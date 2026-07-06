// Supabase subscription status check.
// Order:
//   1. manual_grants  (lifetime whitelist — plan_type=lifetime rows)
//   2. subscriptions  (status IN active | cancelling)
// Returns { active, plan, expires_at, is_lifetime, status, error? }.

const { SUPABASE_URL, SUPABASE_ANON_KEY, MAX_CLOCK_DRIFT_SECS } = require('./config');

async function checkSubscription(accessToken) {
  if (!accessToken) throw new Error('No access token');

  const headers = {
    'apikey':        SUPABASE_ANON_KEY,
    'Authorization': `Bearer ${accessToken}`,
    'Accept':        'application/json',
  };
  const requestTime = Math.floor(Date.now() / 1000);
  let lastError = null;

  // 1. Manual grants (lifetime allow-list). Try/catch so we always
  //    fall through to subscriptions on any error.
  try {
    const url = `${SUPABASE_URL}/rest/v1/manual_grants?select=plan_type,status,expires_at&status=eq.active&revoked_at=is.null`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
    if (resp.ok) {
      const grants = await resp.json();
      _logDrift(_serverTime(resp), requestTime, 'manual_grants');
      if (Array.isArray(grants) && grants.length > 0) {
        const g = grants[0];
        return {
          active: true,
          plan: g.plan_type || 'lifetime',
          expires_at: g.expires_at,
          is_lifetime: true,
          status: 'active',
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
    const url = `${SUPABASE_URL}/rest/v1/subscriptions?select=plan_type,status,current_period_end,is_lifetime&status=in.(active,cancelling)`;
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
    if (resp.ok) {
      const subs = await resp.json();
      _logDrift(_serverTime(resp), requestTime, 'subscriptions');
      if (Array.isArray(subs) && subs.length > 0) {
        const s = subs[0];
        return {
          active: true,
          plan: s.plan_type || 'pro',
          expires_at: s.current_period_end,
          is_lifetime: !!s.is_lifetime,
          status: s.status,
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
    error: lastError,
  };
}

function _serverTime(resp) {
  const d = resp.headers.get('date');
  if (!d) return null;
  const t = new Date(d);
  return isNaN(t.getTime()) ? null : Math.floor(t.getTime() / 1000);
}

// Clock-drift is LOG ONLY, not throw. Rationale: throwing here caused
// users with mild local-clock skew (very common on laptops that
// suspend/resume) to be locked out of legitimate lifetime grants.
// The replay-attack threat is negligible when we don't cache subscription
// state locally — every check hits Supabase live over TLS anyway.
function _logDrift(serverTime, requestTime, ctx) {
  if (!serverTime) return;
  const drift = Math.abs(serverTime - requestTime);
  if (drift > (MAX_CLOCK_DRIFT_SECS || 300)) {
    console.log(`[subscription] ${ctx}: server-clock drift ${drift}s (accepted)`);
  }
}

module.exports = { checkSubscription };
