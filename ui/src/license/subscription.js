// ═══════════════════════════════════════════════════════════════
// subscription.js — Supabase subscription check + HMAC-signed cache.
//
// v6.4 (2026-07-14 — ROOT-CAUSE FIX for silent clock-drift lockout)
//
//   Reported by user jay.perkerson@gmail.com: dashboard showed
//   "No active subscription — Couldn't reach the license server"
//   even though Supabase-side row was active, RLS was fine, and the
//   REST/OAuth queries all returned HTTP 200 (verified via Supabase
//   API logs at 2026-07-14 02:48:53 UTC).
//
//   Root cause: `_validateDrift` throws a special Error with
//   `err.kind='clock_drift'` when the client's wall clock is >
//   MAX_CLOCK_DRIFT_SECS off from Supabase's Date header. But the
//   surrounding catch block called `_mkNetErr(endpoint, e)` which
//   hard-coded `kind: 'network'` regardless of what the caught error
//   actually classified itself as. Result: drift errors were
//   MISCLASSIFIED as network errors → renderer showed the generic
//   "couldn't reach" copy instead of the clock-drift-specific copy
//   that already existed and was never firing.
//
//   Fix:
//     1. `_mkNetErr` now preserves `e.kind` and `e.drift` if the
//        thrown error already classified itself.
//     2. Added exponential-backoff retry loop (3 attempts,
//        600ms → 1200ms → 2400ms + jitter) — but ONLY for kind
//        'network'. http/schema/clock_drift are terminal.
//     3. Per-request timeout bumped 15s → 20s to accommodate slow
//        cold-start Supabase pool connections.
//
//   MAX_CLOCK_DRIFT_SECS also bumped in config.js from 300 → 3600
//   because 5 min was aggressive for real-world Windows w32time
//   drift (30 min is common when Sync has failed silently). 1 h
//   still catches egregious replay while accommodating legit users.
//
// v4.9 (2026-07-06) — first ROOT-CAUSE FIX (still active):
//
//   Supabase schema (confirmed via server-side inspection of project
//   rrrpkmzdnaodmvsuxdkw):
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
//
//     manual_grants columns:
//       id, email, plan_type, status, granted_by, expires_at, notes,
//       revoked_at, created_at
//     RLS: `USING (email = (auth.jwt() ->> 'email'))` — keyed by JWT
//     email claim, NOT by user_id.
//     status enum: 'active' | 'revoked' only.
//
// Query order:
//   1. manual_grants — lifetime email-whitelist (empty for most users
//      because migrated grants live in subscriptions).
//   2. subscriptions — active + cancelling. Picks up lifetime grants
//      via is_lifetime=true — no separate lifetime query needed.
//
// Signed cache (v6 semantics):
//   signSubCache(sub, hwid) → HMAC-SHA256(LICENSE_RESPONSE_SECRET,
//                                          JSON(payload) || hwid).
//   verifySubCache(cached, hwid) → timing-safe compare.
//   v6.4: caller may also pass a fallback HWID list — see
//   verifySubCacheAgainstAny() below.
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
// renewal and is retrying — treat as inactive until Stripe recovers
// the payment. Matches hooksdll behavior.
const ACTIVE_STATUS_FILTER = 'in.(active,cancelling)';

// v6.4: request timeout bumped 15s → 20s. Cold-start PostgREST
// connections during off-peak hours can take ~10-12s to respond;
// 15s was cutting it close for users on slow wifi.
const REQUEST_TIMEOUT_MS = 20_000;

// v6.4: retry policy for TRANSIENT failures (network only).
// Terminal errors (http 4xx, schema mismatch, clock drift) do not
// retry — they won't self-heal by trying again.
const MAX_RETRY_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 600;
const RETRY_JITTER_MS = 300;

async function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Run a single sub-check pass. Returns the full result shape:
//   { active, plan, expires_at, is_lifetime, status, server_time, error? }
// No throws — all errors are captured into `error`. See top-file comment.
async function _checkSubscriptionOnce(accessToken) {
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
  try {
    const url = `${SUPABASE_URL}/rest/v1/manual_grants?select=plan_type,status,expires_at&status=eq.active&revoked_at=is.null`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
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
  //    Picks up BOTH normal paying subscribers AND lifetime grants
  //    (which live in subscriptions with is_lifetime=true).
  try {
    const url = `${SUPABASE_URL}/rest/v1/subscriptions?select=plan_type,status,current_period_end,is_lifetime&status=${ACTIVE_STATUS_FILTER}`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
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
    // Structured error: { kind: 'http'|'network'|'schema'|'clock_drift',
    //                      statusCode, endpoint, message, body, drift? }.
    error: lastError,
  };
}

// v6.4 (2026-07-14): public entry point wraps _checkSubscriptionOnce
// with retry-on-transient-network-failure. Terminal errors (http 4xx,
// schema mismatch, clock drift) return immediately — they won't
// self-heal by trying again.
async function checkSubscription(accessToken) {
  if (!accessToken) throw new Error('No access token');

  let lastResult = null;
  for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
    lastResult = await _checkSubscriptionOnce(accessToken);

    // Success — return immediately.
    if (lastResult && lastResult.active) return lastResult;

    const err = lastResult && lastResult.error;

    // Genuinely no subscription (query succeeded, returned zero rows).
    // Nothing to retry.
    if (!err) return lastResult;

    // Terminal error — client-server mismatch (schema), user clock skew
    // (clock_drift), or non-retryable HTTP status. These won't be fixed
    // by another attempt. See invariant docs in CLAUDE.md.
    if (err.kind !== 'network') return lastResult;

    // Transient network failure — retry with exponential backoff + jitter.
    if (attempt < MAX_RETRY_ATTEMPTS) {
      const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
      const jitter = Math.floor(Math.random() * RETRY_JITTER_MS);
      console.log(`[subscription] transient network failure (attempt ${attempt}/${MAX_RETRY_ATTEMPTS}); retry in ${delay + jitter}ms`);
      await _sleep(delay + jitter);
    }
  }

  console.log(`[subscription] all ${MAX_RETRY_ATTEMPTS} attempts exhausted, giving up`);
  return lastResult;
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
//   .drift       — seconds of clock skew (present only for kind='clock_drift')
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

// v6.4 (2026-07-14): PRESERVE the thrown error's `.kind` if it already
// classified itself. The classic bug pre-v6.4: `_validateDrift` threw
// with `err.kind='clock_drift'` but this function hard-coded 'network',
// clobbering the classification. The renderer's clock-drift-specific
// copy therefore never fired, and every drift user saw the generic
// "Couldn't reach the license server" instead. Fix: sniff `e.kind`
// and `e.drift` from the thrown error.
function _mkNetErr(endpoint, e) {
  const preClassified = e && typeof e.kind === 'string';
  const kind = preClassified ? e.kind : 'network';
  const out = {
    kind,
    statusCode: null,
    endpoint,
    message: `${endpoint}: ${e && e.message ? e.message : String(e)}`,
    body: '',
  };
  if (e && typeof e.drift === 'number') out.drift = e.drift;
  return out;
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

// v4.4+ — throw instead of log-only. Was log-only in v4.3 which
// allowed replay attacks. Downstream MUST preserve err.kind (see
// _mkNetErr) or the drift-specific renderer copy never fires.
function _validateDrift(serverTime, requestTime, ctx) {
  if (!serverTime) return;
  const drift = Math.abs(serverTime - requestTime);
  if (drift > (MAX_CLOCK_DRIFT_SECS || 3600)) {
    console.log(`[subscription] ${ctx}: clock drift ${drift}s — reject (max=${MAX_CLOCK_DRIFT_SECS}s)`);
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
//   _hwid:     (v6.4) the HWID the sig was signed against, so we can
//              recognize a cache that was signed on this machine with
//              a NOW-ROTATED HWID and heal it in place.
//
// signSubCache() produces the signature.
// verifySubCache() checks it BEFORE trusting a cached response, so
// a lifted subscription.enc from a different machine (different HWID)
// or a mutated JSON fails.
// verifySubCacheAgainstAny() (v6.4) tries the cache against a list of
// candidate HWIDs — used to survive HWID rotation on the same machine
// (see device.js Win11 wmic deprecation notes).
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

// Attach _cachedAt + _sig (+ _hwid tag for v6.4 rotation-tolerance)
// to a subscription result. Returns the mutated `sub` object for
// caller convenience.
function attachSigToCache(sub, hwid) {
  if (!sub) return sub;
  sub._cachedAt = Math.floor(Date.now() / 1000);
  sub._sig      = signSubCache(sub, hwid);
  sub._hwid     = hwid || '';
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

// v6.4 (2026-07-14): try to verify a cache against ANY of the provided
// candidate HWIDs. Returns { ok, matchedHwid } — matchedHwid is the
// specific value that verified. Used to survive HWID rotation on the
// same physical machine (e.g. Windows 11 22H2+ where `wmic csproduct
// get uuid` is deprecated and falls through to different sources across
// runs). Caller then re-signs with the current preferred HWID.
//
// Security note: this ONLY helps IF the attacker cannot enumerate the
// HWIDs a machine can produce — but since HWIDs derive from local
// hardware/registry/hostname the "candidate list" IS the machine's
// identity. An attacker who has all those inputs already has the box.
// Using a candidate list widens the accept set trivially compared to
// the actual hardware fingerprint.
function verifySubCacheAgainstAny(cached, hwidCandidates) {
  if (!cached || !cached._sig || !cached._cachedAt) return { ok: false, matchedHwid: null };
  const list = Array.isArray(hwidCandidates) ? hwidCandidates : [hwidCandidates];
  for (const cand of list) {
    if (!cand) continue;
    try {
      if (verifySubCache(cached, cand)) {
        return { ok: true, matchedHwid: cand };
      }
    } catch { /* try next */ }
  }
  return { ok: false, matchedHwid: null };
}

module.exports = {
  checkSubscription,
  signSubCache, verifySubCache, verifySubCacheAgainstAny, attachSigToCache,
  // Exported for main.js's HWID auto-heal path (see v6.4 CLAUDE.md
  // entry). Not part of the renderer contract.
  _validateDrift, _mkNetErr, _mkErr,
};
