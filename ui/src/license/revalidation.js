// ═══════════════════════════════════════════════════════════════
// revalidation.js — Runtime subscription re-check + token refresh +
//                    signed-cache offline grace + jitter.
//
// Adapted from hooksdll/lumio/src/license/revalidation.js with two
// upgrades over the v4.2 svcldb version:
//
//   1. Signed subscription cache — if the network fails but we have a
//      valid HMAC-signed cache under GRACE_PERIOD_MS old, keep the user
//      active. Fair on flaky exam-day wifi.
//   2. Jitter on every scheduled tick — ±20% around the base interval.
//      Prevents thundering-herd + makes the poller invisible to server-
//      side rate detection.
//
// v4.9 (2026-07-06): removed SUSPENDED branch — server-side has no
// suspension concept (no user_suspensions table, no 'suspended' in
// subscriptions.status enum). See subscription.js header + CLAUDE.md.
//
// Payload also has its own C-side sub-check (payload/src/sub_check.c)
// so if the Electron app is closed entirely the payload still self-
// unloads within ~30 min of losing subscription. Defense in depth.
// ═══════════════════════════════════════════════════════════════

const {
  GRACE_PERIOD_MS,
} = require('./config');

const BASE_INTERVAL_MS         = 60 * 60 * 1000;   // 1 hour
const JITTER_PCT               = 0.20;              // ±20 % randomness
const TOKEN_REFRESH_BUFFER_S   = 15 * 60;           // refresh if <15 min left
const MAX_CONSECUTIVE_FAILURES = 3;                 // 3 fails before lockout

let timerId             = null;
let consecutiveFailures = 0;
let stopped             = true;

/** Return the next interval in ms with ±JITTER_PCT randomness. */
function nextIntervalMs() {
  const jitter = 1 + ((Math.random() * 2 - 1) * JITTER_PCT);
  return Math.floor(BASE_INTERVAL_MS * jitter);
}

/**
 * Start periodic revalidation.
 *
 * @param {object} deps
 * @param {() => object|null} deps.getSession   returns current session
 * @param {(session) => Promise<object|null>} deps.refreshFn  refresh token if near expiry
 * @param {(token: string) => Promise<object>} deps.subCheckFn call Supabase, return sub result
 * @param {() => string|null} deps.getHwid      returns current HWID (for cache sig)
 * @param {() => object|null} deps.loadSignedCache  reads sub from storage + verifies sig
 * @param {(sub) => void} deps.saveSignedCache  writes sub to storage (signed by caller)
 * @param {(newSession: object) => void} deps.onRefreshed  called with refreshed session
 * @param {(reason: string, extra?: object) => void} deps.onExpired  called when locked out
 */
function start(deps) {
  if (timerId) {
    console.log('[revalidation] already running');
    return;
  }
  stopped = false;
  consecutiveFailures = 0;
  const {
    getSession, refreshFn, subCheckFn,
    getHwid, loadSignedCache, saveSignedCache,
    onRefreshed, onExpired,
  } = deps;

  console.log(`[revalidation] started (base=${BASE_INTERVAL_MS / 60000}m ±${JITTER_PCT * 100}%, ` +
              `max_fail=${MAX_CONSECUTIVE_FAILURES}, grace=${GRACE_PERIOD_MS / 3600000}h)`);

  const tick = async (initial) => {
    if (stopped) return;
    if (!initial) console.log('[revalidation] tick');
    try {
      let session = getSession();
      if (!session) throw new Error('no session');

      // Token refresh if near expiry.
      const now = Math.floor(Date.now() / 1000);
      if (session.expires_at && session.expires_at - now < TOKEN_REFRESH_BUFFER_S && session.refresh_token) {
        console.log(`[revalidation] refreshing token (${session.expires_at - now}s left)`);
        try {
          session = await refreshFn(session);
          onRefreshed(session);
        } catch (rerr) {
          console.log('[revalidation] refresh failed:', rerr.message);
          throw rerr;
        }
      }

      const status = await subCheckFn(session.access_token);
      if (status && status.active) {
        if (consecutiveFailures > 0) {
          console.log('[revalidation] recovered after', consecutiveFailures, 'failures');
        }
        consecutiveFailures = 0;
        // Persist to signed cache so offline-grace can serve later.
        if (saveSignedCache) {
          try { saveSignedCache(status); }
          catch (e) { console.log('[revalidation] signed-cache save failed:', e.message); }
        }
        return;
      }
      // If the sub check returned a SCHEMA error (PostgREST 42703 —
      // "column does not exist"), that's a client/server mismatch that
      // won't self-heal on retry. Treat it as a critical failure so
      // main.js can surface a "contact support" banner instead of
      // silently unloading.
      if (status && status.error && status.error.kind === 'schema') {
        console.log('[revalidation] SCHEMA error — locking out with support-contact reason');
        stop();
        onExpired('license_server_schema_error', { serverError: status.error });
        return;
      }
      // v6.4 (2026-07-14): if sub check returned kind=network or
      // kind=clock_drift, that's TRANSIENT (network) or USER-FIXABLE
      // (clock). Do NOT interpret as "subscription inactive" — the
      // subscription state is UNKNOWN. Feed into the failure counter
      // like a thrown error so offline-grace + backoff kick in
      // instead of an immediate lockout.
      const errKind = status && status.error && status.error.kind;
      if (errKind === 'network' || errKind === 'clock_drift') {
        console.log(`[revalidation] transient error (${errKind}); ` +
                    `routing through failure handler for backoff + grace-cache`);
        // Re-throw so the catch below handles it uniformly with fetch
        // rejects — that block does the offline-grace lookup + failure
        // count + eventual lockout. Do NOT increment counter here —
        // the catch will do it exactly once.
        const e = new Error(status.error.message || errKind);
        e.kind = errKind;
        if (typeof status.error.drift === 'number') e.drift = status.error.drift;
        throw e;
      }
      // Explicit inactive — no rows AND no error → user has no active
      // subscription. Lock out.
      console.log('[revalidation] subscription NOT ACTIVE — locking out');
      stop();
      onExpired('subscription_inactive');
    } catch (e) {
      consecutiveFailures++;
      console.log(`[revalidation] error: ${e.message} (${consecutiveFailures}/${MAX_CONSECUTIVE_FAILURES})`);

      // OFFLINE-GRACE FAST PATH: if we have a signed cache within grace
      // window, treat this failure as "temporary" and keep the user
      // active. Only actually lock out when the cache is stale.
      if (getHwid && loadSignedCache) {
        try {
          const cached = loadSignedCache(getHwid());
          if (cached && cached.active && cached._cachedAt) {
            const cacheAgeMs = Date.now() - cached._cachedAt * 1000;
            if (cacheAgeMs < GRACE_PERIOD_MS) {
              console.log(`[revalidation] offline-grace: cached sub still valid ` +
                          `(${Math.round(cacheAgeMs/1000)}s old, grace=${GRACE_PERIOD_MS/1000}s)`);
              // Don't clear failures counter — a chain of failures still
              // needs to trigger eventual lockout at grace expiry.
              return;
            }
            console.log(`[revalidation] offline-grace: cache stale ` +
                        `(${Math.round(cacheAgeMs/1000)}s > ${GRACE_PERIOD_MS/1000}s grace)`);
          }
        } catch (ge) {
          console.log('[revalidation] grace-cache load failed:', ge.message);
        }
      }

      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        stop();
        onExpired('too_many_failures:' + e.message);
      }
    } finally {
      if (!stopped) {
        // Schedule next tick with fresh jitter.
        timerId = setTimeout(() => tick(false), nextIntervalMs());
      }
    }
  };

  // First tick 30s after start (not immediate — let the app settle after
  // signin/inject). Then every jittered interval.
  timerId = setTimeout(() => tick(true), 30_000);
}

function stop() {
  stopped = true;
  if (timerId) {
    clearTimeout(timerId);
    timerId = null;
    console.log('[revalidation] stopped');
  }
}

function isRunning() {
  return !stopped && timerId !== null;
}

module.exports = {
  start, stop, isRunning,
  BASE_INTERVAL_MS, TOKEN_REFRESH_BUFFER_S, MAX_CONSECUTIVE_FAILURES, JITTER_PCT,
};
