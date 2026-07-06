// ═══════════════════════════════════════════════════════════════
// subscription.js — Supabase-direct subscription check.
//
// Mirrors the fetching logic in the C-side launcher/src/license.c
// (license_check_subscription). Order:
//   1. manual_grants (lifetime whitelist)
//   2. subscriptions (active | cancelling)
//
// Response includes { active, plan, expires_at, is_lifetime, status }.
// ═══════════════════════════════════════════════════════════════

const { SUPABASE_URL, SUPABASE_ANON_KEY, MAX_CLOCK_DRIFT_SECS, APP_VERSION } = require('./config');

async function checkSubscription(accessToken) {
  if (!accessToken) throw new Error('No access token');
  const headers = {
    'apikey': SUPABASE_ANON_KEY,
    'Authorization': `Bearer ${accessToken}`,
    /* v4.4: User-Agent so the server can distinguish CloakGPT versions
     * (needed for future downgrade-attack mitigation — server rejects
     * requests from pre-handshake builds). Same pattern hooksdll uses. */
    'User-Agent': `CloakGPT/${APP_VERSION}`,
  };
  const requestTime = Math.floor(Date.now() / 1000);

  // 1. Manual grants — lifetime allow-list.
  try {
    const url = `${SUPABASE_URL}/rest/v1/manual_grants?select=plan_type,status,expires_at&status=eq.active&revoked_at=is.null`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
    if (resp.ok) {
      _validateFreshness(_serverTime(resp), requestTime);
      const grants = await resp.json();
      if (grants && grants.length > 0) {
        const g = grants[0];
        return {
          active: true,
          plan: g.plan_type || 'lifetime',
          expires_at: g.expires_at,
          is_lifetime: true,
          status: 'active',
        };
      }
    }
  } catch (e) {
    console.log('[subscription] manual_grants query error:', e.message);
  }

  // 2. Subscriptions table.
  try {
    const url = `${SUPABASE_URL}/rest/v1/subscriptions?select=plan_type,status,current_period_end,is_lifetime&status=in.(active,cancelling)`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
    if (resp.ok) {
      _validateFreshness(_serverTime(resp), requestTime);
      const subs = await resp.json();
      if (subs && subs.length > 0) {
        const s = subs[0];
        return {
          active: true,
          plan: s.plan_type || 'pro',
          expires_at: s.current_period_end,
          is_lifetime: !!s.is_lifetime,
          status: s.status,
        };
      }
    }
  } catch (e) {
    console.log('[subscription] subscriptions query error:', e.message);
  }

  return {
    active: false, plan: null, expires_at: null,
    is_lifetime: false, status: 'no_subscription',
  };
}

function _serverTime(resp) {
  const d = resp.headers.get('date');
  if (!d) return null;
  const t = new Date(d);
  return isNaN(t.getTime()) ? null : Math.floor(t.getTime() / 1000);
}

function _validateFreshness(serverTime, requestTime) {
  if (!serverTime) return;
  const drift = Math.abs(serverTime - requestTime);
  if (drift > (MAX_CLOCK_DRIFT_SECS || 300)) {
    /* v4.4 hardening: THROW instead of log-only. Prevents replay-attack
     * path where an attacker MITMs a stale "active" response from a
     * previous session (or advances local clock to accept a future one).
     * The revalidation loop's 3-consecutive-failure grace absorbs
     * short-lived server clock hiccups; a real ≥5min drift is a red
     * flag, not a hiccup. */
    throw new Error(`Response timestamp out of range (drift=${drift}s > ${MAX_CLOCK_DRIFT_SECS}s) — possible replay`);
  }
}

module.exports = { checkSubscription };
