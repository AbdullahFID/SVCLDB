// ═══════════════════════════════════════════════════════════════
// subscription.js — Supabase subscription check + HMAC-signed cache.
//
// Order of checks:
//   1. suspensions  — dedicated ban table (if it exists server-side).
//      Row present = user is BANNED (chargeback, TOS violation).
//      Return { active:false, status:'suspended', suspension_reason }.
//   2. manual_grants — lifetime whitelist (plan_type=lifetime rows).
//   3. subscriptions — status IN (active, cancelling, suspended).
//      If we get status=suspended here too, treat as ban.
//
// Returns { active, plan, expires_at, is_lifetime, status,
//           suspension_reason?, server_time?, error? }.
//
// Signed cache:
//   signSubCache(sub, hwid) → HMAC-SHA256(LICENSE_RESPONSE_SECRET,
//                                          JSON(sub) || hwid).
//   loadSignedSubCache(hwid) → verifies signature; rejects stale/wrong-hwid.
// ═══════════════════════════════════════════════════════════════

const crypto = require('crypto');
const {
  SUPABASE_URL, SUPABASE_ANON_KEY, MAX_CLOCK_DRIFT_SECS,
  LICENSE_RESPONSE_SECRET, APP_VERSION,
} = require('./config');
const security = require('./security');

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

  // 0. Suspensions table (if it exists). Silently ignored if the table
  //    isn't set up server-side (404) — we don't want to hard-fail on
  //    a missing table, just log + continue.
  try {
    const url = `${SUPABASE_URL}/rest/v1/user_suspensions?select=reason,suspended_at,active&active=eq.true`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(10_000) });
    if (resp.ok) {
      serverTime = _serverTime(resp);
      _validateDrift(serverTime, requestTime, 'suspensions');
      const rows = await resp.json();
      if (Array.isArray(rows) && rows.length > 0) {
        const s = rows[0];
        console.log('[subscription] SUSPENDED account detected:', s.reason || '(no reason)');
        return {
          active: false,
          plan: null,
          expires_at: null,
          is_lifetime: false,
          status: 'suspended',
          suspension_reason: s.reason || 'account_suspended',
          suspended_at: s.suspended_at || null,
          server_time: serverTime || requestTime,
        };
      }
    } else if (resp.status !== 404) {
      lastError = `user_suspensions http ${resp.status}`;
    }
  } catch (e) {
    // Table missing / RLS denies read for non-admin / offline — treat
    // as "not suspended" and continue with the normal flow.
    console.log('[subscription] user_suspensions query skipped:', e.message);
  }

  // 1. Manual grants (lifetime allow-list).
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
      lastError = `manual_grants http ${resp.status}`;
    }
  } catch (e) {
    lastError = `manual_grants: ${e.message}`;
    console.log('[subscription] manual_grants failed:', e.message);
  }

  // 2. Subscriptions table.
  try {
    const url = `${SUPABASE_URL}/rest/v1/subscriptions?select=plan_type,status,current_period_end,is_lifetime,suspension_reason&status=in.(active,cancelling,suspended)`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
    if (resp.ok) {
      serverTime = _serverTime(resp);
      _validateDrift(serverTime, requestTime, 'subscriptions');
      const subs = await resp.json();
      if (Array.isArray(subs) && subs.length > 0) {
        const s = subs[0];
        // If the ONLY subscription row we found is status=suspended,
        // treat as ban (dedicated screen with the reason).
        if (s.status === 'suspended') {
          console.log('[subscription] SUSPENDED subscription:', s.suspension_reason || '(no reason)');
          return {
            active: false,
            plan: s.plan_type || null,
            expires_at: s.current_period_end || null,
            is_lifetime: false,
            status: 'suspended',
            suspension_reason: s.suspension_reason || 'subscription_suspended',
            server_time: serverTime || requestTime,
          };
        }
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
      lastError = `subscriptions http ${resp.status}`;
    }
  } catch (e) {
    lastError = `subscriptions: ${e.message}`;
    console.log('[subscription] subscriptions failed:', e.message);
  }

  return {
    active: false,
    plan: null,
    expires_at: null,
    is_lifetime: false,
    status: 'no_subscription',
    server_time: serverTime || requestTime,
    error: lastError,
  };
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
    throw new Error(`clock_drift_${drift}s`);
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
    suspension_reason: sub.suspension_reason || null,
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
