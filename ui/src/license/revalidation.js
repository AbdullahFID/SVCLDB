// ═══════════════════════════════════════════════════════════════
// revalidation.js — Runtime subscription re-check + token refresh.
//
// Adapted from hooksdll/lumio/src/license/revalidation.js. Simpler:
// single interval that both refreshes the access token when close to
// expiry AND polls the Supabase subscription table. First N failures
// are tolerated (network flap, DNS glitch); at MAX_CONSECUTIVE_FAILURES
// the caller's onExpired() fires and the app should:
//   1. Uninject the payload (revoke access immediately).
//   2. Clear the cached session.
//   3. Push the renderer back to the login screen.
//
// Why the payload also has its own C-side sub-check (payload/src/sub_check.c):
// if the user closes the Electron app entirely, the JS timer stops firing.
// The payload's own thread keeps polling from inside dwm.exe so a stolen
// binary that's kept the Electron app quit still self-unloads within an
// hour of losing the subscription. Defense in depth.
// ═══════════════════════════════════════════════════════════════

const REVALIDATION_INTERVAL_MS = 60 * 60 * 1000;   // 1 hour
const TOKEN_REFRESH_BUFFER_S   = 15 * 60;          // refresh if <15 min left
const MAX_CONSECUTIVE_FAILURES = 3;                // 3 hours of soft errors
                                                   // before we lock the user out
let intervalId          = null;
let consecutiveFailures = 0;

/**
 * Start periodic revalidation.
 *
 * @param {object} deps
 * @param {() => object|null} deps.getSession    returns current session
 * @param {(session) => Promise<object|null>} deps.refreshFn  refresh token if near expiry
 * @param {(token: string) => Promise<object>} deps.subCheckFn call Supabase, return {active}
 * @param {(newSession: object) => void} deps.onRefreshed     called with refreshed session
 * @param {(reason: string) => void} deps.onExpired           called when locked out
 */
function start(deps) {
  if (intervalId) {
    console.log('[revalidation] already running');
    return;
  }
  consecutiveFailures = 0;
  const {
    getSession, refreshFn, subCheckFn, onRefreshed, onExpired,
  } = deps;

  console.log(`[revalidation] started (interval=${REVALIDATION_INTERVAL_MS / 60000}m, ` +
              `max_fail=${MAX_CONSECUTIVE_FAILURES})`);

  const tick = async (initial) => {
    if (!initial) console.log('[revalidation] tick');
    try {
      let session = getSession();
      if (!session) throw new Error('no session');

      // Token refresh: if <TOKEN_REFRESH_BUFFER_S left on the access token,
      // hit Supabase refresh_token endpoint pre-emptively. The C-side reads
      // access_token from config.dat — if it's stale, every C-side sub check
      // gets a 401 too. Rewrite config.dat after refresh so the payload
      // picks up the new token on next re-arm (not injected here — just
      // for future Inject clicks).
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
        return;
      }
      // Explicit "sub inactive" — no grace, hard lock immediately. Network
      // failures still get MAX_CONSECUTIVE_FAILURES retries via the catch below.
      console.log('[revalidation] subscription NOT ACTIVE — locking out');
      stop();
      onExpired('subscription_inactive');
    } catch (e) {
      consecutiveFailures++;
      console.log(`[revalidation] error: ${e.message} (${consecutiveFailures}/${MAX_CONSECUTIVE_FAILURES})`);
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        stop();
        onExpired('too_many_failures:' + e.message);
      }
    }
  };

  // First tick 30s after start (not immediate — let the app settle after
  // signin/inject). Then every REVALIDATION_INTERVAL_MS.
  setTimeout(() => { tick(true); }, 30_000);
  intervalId = setInterval(() => { tick(false); }, REVALIDATION_INTERVAL_MS);
}

function stop() {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    console.log('[revalidation] stopped');
  }
}

function isRunning() {
  return intervalId !== null;
}

module.exports = {
  start, stop, isRunning,
  REVALIDATION_INTERVAL_MS, TOKEN_REFRESH_BUFFER_S, MAX_CONSECUTIVE_FAILURES,
};
