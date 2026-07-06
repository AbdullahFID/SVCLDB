// ═══════════════════════════════════════════════════════════════
// subscription.js — Supabase subscription check + HMAC-signed cache.
//
// v4.9 (2026-07-06 — ROOT-CAUSE FIX for HTTP 400 on lifetime users)
//
//   Supabase schema (confirmed via server-side inspection of project
//   rrrpkmzdnaodmvsuxdkw, see docs handoff and CLAUDE.md v4.9 entry):
//
//     subscriptions columns:
//       id, user_id, email, stripe_customer_id, stripe_subscription_id,
//       plan_type, status, current_period_start, current_period_end,
//       is_lifetime, is_manual_grant, granted_by, grant_reason,
//       created_at, updated_at
//
//     subscriptions.status CHECK enum:
//       active | cancelling | past_due | cancelled | expired
//         (NO 'suspended' — never was)
//
//     subscriptions has NO suspension_reason column.
//     user_suspensions table DOES NOT EXIST.
//     banned_users table DOES NOT EXIST (Mac project only).
//
//     manual_grants columns:
//       id, email, plan_type, status, granted_by, expires_at, notes,
//       revoked_at, created_at
//     RLS: `USING (email = (auth.jwt() ->> 'email'))` — keyed by JWT
//     email claim, NOT by user_id.
//     status enum: 'active' | 'revoked' (nothing else).
//
//   Prior v4.6 subscription.js selected `suspension_reason` and filtered
//   `status=in.(active,cancelling,suspended)` — the extra column caused
//   PostgREST to return 42703 (column does not exist) → 400. Lifetime
//   users saw "No active subscription — subscriptions http 400" in the
//   nosub screen (see screenshot 2026-07-06). This file removes both
//   the phantom column and the phantom status value.
//
// Query order:
//   1. manual_grants — lifetime email-whitelist (empty for most users
//      because we migrated grants into subscriptions with is_lifetime=true
//      + is_manual_grant=true).
//   2. subscriptions — active + cancelling. Also picks up lifetime
//      grants (is_lifetime=true) — no need for a separate lifetime
//      query.
//
// Signed cache (unchanged from v4.6):
//   signSubCache(sub, hwid) → HMAC-SHA256(LICENSE_RESPONSE_SECRET,
//                                          JSON(sub) || hwid).
//   verifySubCache(cached, hwid) → timing-safe compare.
// ═══════════════════════════════════════════════════════════════

const crypto = require('crypto');
const {
  SUPABASE_URL, SUPABASE_ANON_KEY, MAX_CLOCK_DRIFT_SECS,
  LICENSE_RESPONSE_SECRET, APP_VERSION,
} = require('./config');

// Statuses we consider "subscription is currently valid". `cancelling`
// means the user hit cancel in Stripe but the current period hasn't
// ended yet — they paid, they get service through the end.
//
// `past_due` intentionally excluded: means Stripe couldn't charge the
// renewal and is retrying — we treat those as inactive until Stripe
// recovers the payment. Matches hooksdll behavior.
const ACTIVE_STATUS_FILTER = 'in.(active,cancelling)';

async function checkSubscription(accessToken) {
  if (!accessToken) throw new Error('No access token');

  const headers = {
    'apikey':        SUPABASE_ANON_KEY,
    'Authorization': `Bearer ${accessToken}`,
    'Accept':        'application/json',
    // hooksdll parity — server-side version enforcement hook.
    'User-Agent':    `CloakGPT/${APP_VERSION}`,
  };
  const requestTime = Math.floor(Date.now() / 1000);
  let lastError = null;
  let serverTime = null;

  // 1. Manual grants (email-keyed lifetime allow-list). Empty for most
  //    users; retained for backward compat with pre-migration grants.
  //    RLS matches by JWT `email` claim, no explicit user_id filter.
  try {
    const url = `${SUPABASE_URL}/rest/v1/manual_grants?select=plan_type,status,expires_at&status=eq.active&revoked_at=is.null`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
    if (resp.ok) {
      serverTime = _serverTime(resp);
      _validateDrift(serverTime, requestTime, 'manual_grants');
      const grants = await resp.json();
      if (Array.isArray(grants) && grants.length > 0) {
        const g = grants[0];
        return {
          active: true,
          plan: g.plan_type || 'lifetime',
          expires_at: g.expires_at,
          is_lifetime: true,
          status: 'active',
          server_time: serverTime || requestTime,
        };
      }
    } else {
      const body = await _readBody(resp);
      lastError = _mkErr(resp.status, 'manual_grants', body);
      console.log(`[subscription] manual_grants http ${resp.status}: ${body.slice(0, 200)}`);
    }
  } catch (e) {
    lastError = _mkNetErr('manual_grants', e);
    console.log('[subscription] manual_grants failed:', e.message);
  }

  // 2. Subscriptions table.
  //    Server schema (confirmed 2026-07-06):
  //      SELECT plan_type, status, current_period_end, is_lifetime
  //      FROM subscriptions
  //      WHERE user_id = auth.uid()        -- via RLS
  //        AND status IN ('active', 'cancelling')
  //
  //    This picks up BOTH normal paying subscribers AND lifetime
  //    grants (which live in subscriptions with is_lifetime=true).
  try {
    const url = `${SUPABASE_URL}/rest/v1/subscriptions?select=plan_type,status,current_period_end,is_lifetime&status=${ACTIVE_STATUS_FILTER}`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
    if (resp.ok) {
      serverTime = _serverTime(resp);
      _validateDrift(serverTime, requestTime, 'subscriptions');
      const subs = await resp.json();
      if (Array.isArray(subs) && subs.length > 0) {
        const s = subs[0];
        return {
          active: true,
          plan: s.plan_type || 'pro',
          expires_at: s.current_period_end,
          is_lifetime: !!s.is_lifetime,
          status: s.status,
          server_time: serverTime || requestTime,
        };
      }
    } else {
      const body = await _readBody(resp);
      lastError = _mkErr(resp.status, 'subscriptions', body);
      console.log(`[subscription] subscriptions http ${resp.status}: ${body.slice(0, 200)}`);
    }
  } catch (e) {
    lastError = _mkNetErr('subscriptions', e);
    console.log('[subscription] subscriptions failed:', e.message);
  }

  return {
    active: false,
    plan: null,
    expires_at: null,
    is_lifetime: false,
    status: 'no_subscription',
    server_time: serverTime || requestTime,
    // Structured error: { kind: 'http'|'network'|'schema', statusCode, endpoint, message, body }.
    // Downstream code (main.js license:load) uses `.kind` and `.statusCode`
    // instead of regex-matching a stringly-typed field.
    error: lastError,
  };
}

// ─── Error shaping ──────────────────────────────────────────────────
//
// Returns an ERROR object, not a string. Downstream (renderer + main
// force-relogin path) inspects fields:
//   .kind        — 'http' | 'network' | 'schema' | 'clock_drift'
//   .statusCode  — HTTP status (present for kind='http'|'schema')
//   .endpoint    — 'manual_grants' | 'subscriptions'
//   .message     — human-readable summary
//   .body        — first 250 bytes of response body (schema hints from PostgREST)
function _mkErr(status, endpoint, body) {
  // PostgREST returns 42703 (column does not exist) as 400 with a
  // JSON body {code, message, hint, details}. Detect + mark as schema
  // so renderer can show the "server misconfig, contact support" copy
  // instead of the misleading "no subscription".
  let kind = 'http';
  if (status === 400 && body && (body.includes('42703') || body.includes('does not exist') || body.includes('PGRST'))) {
    kind = 'schema';
  }
  return {
    kind,
    statusCode: status,
    endpoint,
    message: `${endpoint} http ${status}`,
    body: (body || '').slice(0, 250),
  };
}

function _mkNetErr(endpoint, e) {
  return {
    kind: 'network',
    statusCode: null,
    endpoint,
    message: `${endpoint}: ${e.message || String(e)}`,
    body: '',
  };
}

async function _readBody(resp) {
  try { return await resp.text(); } catch { return ''; }
}

function _serverTime(resp) {
  const d = resp.headers.get('date');
  if (!d) return null;
  const t = new Date(d);
  return isNaN(t.getTime()) ? null : Math.floor(t.getTime() / 1000);
}

// v4.4+ — throw instead of log-only. Documented in CLAUDE.md as
// invariant #30. Was log-only in v4.3 which allowed replay attacks.
function _validateDrift(serverTime, requestTime, ctx) {
  if (!serverTime) return;
  const drift = Math.abs(serverTime - requestTime);
  if (drift > (MAX_CLOCK_DRIFT_SECS || 300)) {
    console.log(`[subscription] ${ctx}: clock drift ${drift}s — reject`);
    const err = new Error(`clock_drift_${drift}s`);
    err.kind = 'clock_drift';
    err.drift = drift;
    throw err;
  }
}

// ─── Signed subscription cache ────────────────────────────────────
//
// The cache stores the entire subscription-check response along with:
//   _cachedAt: unix seconds when it was cached
//   _sig:      base64url HMAC-SHA256(secret, JSON(payload) || hwid)
//
// signSubCache() produces the signature.
// verifySubCache() checks it BEFORE trusting a cached response, so
// a lifted subscription.enc from a different machine (different HWID)
// or a mutated JSON fails.
function signSubCache(sub, hwid) {
  const payload = JSON.stringify({
    active:      sub.active,
    plan:        sub.plan,
    expires_at:  sub.expires_at,
    is_lifetime: sub.is_lifetime,
    status:      sub.status,
    _cachedAt:   sub._cachedAt,
  });
  return crypto
    .createHmac('sha256', LICENSE_RESPONSE_SECRET || 'no-secret')
    .update(payload)
    .update(hwid || '')
    .digest('base64url');
}

// Attach _cachedAt + _sig to a subscription result. Returns the
// mutated `sub` object for caller convenience.
function attachSigToCache(sub, hwid) {
  if (!sub) return sub;
  sub._cachedAt = Math.floor(Date.now() / 1000);
  sub._sig = signSubCache(sub, hwid);
  return sub;
}

// Verify a cached subscription's HMAC signature against `hwid`. Uses
// timingSafeEqual so we don't leak the correct sig via response-time
// side channel.
function verifySubCache(cached, hwid) {
  if (!cached || !cached._sig || !cached._cachedAt) return false;
  try {
    const expected = signSubCache(cached, hwid);
    const a = Buffer.from(cached._sig, 'base64url');
    const b = Buffer.from(expected, 'base64url');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

module.exports = {
  checkSubscription,
  signSubCache, verifySubCache, attachSigToCache,
};
