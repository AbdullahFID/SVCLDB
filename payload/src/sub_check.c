/* ================================================================== *
 * sub_check.c -- Runtime Supabase subscription poller.                 *
 *                                                                    *
 * See sub_check.h for the security rationale.                        *
 *                                                                    *
 * v4.6 (2026-07-06):                                                  *
 *   - Jittered polling interval (±20 %) so laptops that suspend       *
 *     during a poll cycle don't all resume at the exact same tick     *
 *     (thundering herd on Supabase + suspicious traffic pattern).    *
 *   - Exponential backoff on transport errors (2 min -> 30 min).      *
 *     Better than the old constant 30-min retry when a laptop is on   *
 *     hotel wifi that goes in and out -- we retry fast the first time  *
 *     but back off if the network is genuinely down for a while.     *
 *   - GetSystemTimeAsFileTime seeded PRNG so jitter differs per       *
 *     install (not a fingerprint since it's local + not exposed).    *
 * ================================================================== */

#include "sub_check.h"
#include "config_read.h"
#include "../../shared/common.h"
#include "../../shared/config_types.h"
#include "../../shared/supabase_config.h"
#include "../../shared/winhttp_util.h"
#include "../../shared/json_util.h"
#include "../../shared/log_secure.h"
#include "../../shared/str_enc.h"

#include <stdio.h>
#include <string.h>

/* Base cadence: 30 min ± jitter. First fire delay 2 min so we don't
 * slam the network the instant DWM starts (network stack may still be
 * warming up on wake-from-sleep). Transport backoff schedule: 2, 4, 8,
 * 15, 30 minutes then cap. Explicit `inactive` still fires immediately.
 *
 * v1.6.5 (2026-07-16): SUB_CHECK_MAX_NET_FAILURES removed. Previous
 * value (3) mirrored the Electron-side revalidation.js policy that was
 * ALREADY changed in v1.6 to NOT lockout on kind='network' errors
 * (invariant #103). The C-side sub_check was accidentally left with
 * the pre-v1.6 aggressive-unload logic -- paying subscribers on flaky
 * wifi or during transient Supabase 503s got their overlay silently
 * pulled ~8 min after the first blip (verified via user
 * simplystoragespace173@gmail.com logs 2026-07-16 23:29:13, where 3
 * network fails 6 minutes apart triggered SELF-UNLOAD despite an
 * active weekly subscription).
 *
 * Post-v1.6.5 policy: network failures cause exponential backoff
 * indefinitely (2/4/8/15/30 min capped). ONLY an explicit HTTP-200
 * with empty result OR an explicit 401/403 triggers self-unload. */
#define SUB_CHECK_INTERVAL_MS       (30U * 60U * 1000U)
#define SUB_CHECK_FIRST_DELAY_MS    (2U  * 60U * 1000U)
#define SUB_CHECK_JITTER_PCT        20    /* ±20 % of INTERVAL_MS */

/* v1.9.2 (2026-09-09) -- Bug 2 (session died at ~1h). A Supabase JWT lives
 * ~1h. When it expires, EVERY authenticated REST call returns 401 -- which
 * says nothing about the subscription, only that the token is stale. The
 * pre-fix code treated that 401 as "subscription inactive" and self-unloaded
 * instantly, yanking paying users' overlays at the ~1h mark. Electron's
 * revalidation now refreshes the JWT ~12 min before expiry and pushes it
 * over the token-refresh pipe (token_refresh_server.c) into cfg->access_token,
 * so a healthy session never even reaches a 401 here. As defense-in-depth we
 * give a stale-token 401 a short grace: retry on AUTH_RETRY cadence and only
 * self-unload after MAX_AUTH_FAILS consecutive 401s (covers a slightly-late
 * push, or concludes the session is genuinely dead / Electron closed). */
#define SUB_CHECK_AUTH_RETRY_MS     (3U * 60U * 1000U)  /* retry ~3 min while token looks stale */
#define SUB_CHECK_MAX_AUTH_FAILS    3                    /* ~9 min grace before self-unload */

static HANDLE  g_sc_thread = NULL;
static volatile LONG g_sc_running = 0;

/* Simple xorshift PRNG seeded from wall clock -- no need for BCrypt
 * quality here (this is timing jitter, not a key). */
static unsigned long g_prng_state = 0;
static void sc_prng_seed_once(void) {
    if (g_prng_state != 0) return;
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    g_prng_state =
        ((unsigned long)ft.dwLowDateTime ^ ((unsigned long)ft.dwHighDateTime << 3)) |
        1UL;   /* never zero */
}
static unsigned long sc_prng_next(void) {
    unsigned long x = g_prng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    g_prng_state = x;
    return x;
}

/* Return an interval in ms in [BASE - JITTER%, BASE + JITTER%]. */
static unsigned sc_next_interval_ms(unsigned base_ms) {
    sc_prng_seed_once();
    long delta = (long)((base_ms * SUB_CHECK_JITTER_PCT) / 100U);   /* ±20 % */
    long pick  = (long)(sc_prng_next() % (unsigned long)(2 * delta + 1)) - delta;
    long out   = (long)base_ms + pick;
    if (out < 60000)  out = 60000;    /* never faster than 1 min */
    return (unsigned)out;
}

/* Exponential-backoff schedule for transport errors. Argument = fail
 * count (1-based). Returns interval to wait before RETRY. */
static unsigned sc_backoff_ms(int fail_count) {
    /* 2, 4, 8, 15, 30 min, then cap at 30. */
    static const unsigned schedule_min[] = { 2, 4, 8, 15, 30 };
    const int n = (int)(sizeof(schedule_min) / sizeof(schedule_min[0]));
    int idx = fail_count - 1;
    if (idx < 0)   idx = 0;
    if (idx >= n)  idx = n - 1;
    return schedule_min[idx] * 60U * 1000U;
}

/* Return values:
 *   1  = subscription confirmed ACTIVE
 *   0  = subscription confirmed INACTIVE (HTTP 200 + empty result set)
 *  -1  = network/transport error (undefined; caller should retry)
 *  -2  = auth error (HTTP 401/403). Token expired/invalid -- NOT proof the
 *        subscription is inactive. Caller applies a short grace before any
 *        self-unload (v1.9.2, Bug 2). */
static int query_supabase_active(const char *access_token) {
    if (!access_token || !access_token[0]) return 0;   /* no token = inactive */

    const char *base = sb_url();
    const char *anon = sb_anon_key();
    if (!base || !anon) {
        slog_write("payload.log", "sub_check: sb_url/anon unavailable");
        return -1;
    }

    /* Build headers once -- reused for both queries. Local buffers big enough
     * for JWT (~3KB) + anon key (~200B). */
    static char auth_hdr[8192];
    static char apikey_hdr[512];
    _snprintf(auth_hdr,   sizeof(auth_hdr)   - 1, "Authorization: Bearer %s", access_token);
    _snprintf(apikey_hdr, sizeof(apikey_hdr) - 1, "apikey: %s",              anon);
    auth_hdr[sizeof(auth_hdr) - 1]     = 0;
    apikey_hdr[sizeof(apikey_hdr) - 1] = 0;
    const char *headers[] = { auth_hdr, apikey_hdr, "Accept: application/json", NULL };

    char url[512];

    /* 1. manual_grants -- lifetime whitelist. */
    _snprintf(url, sizeof(url) - 1,
              "%s/rest/v1/manual_grants?select=status&status=eq.active&revoked_at=is.null", base);
    url[sizeof(url) - 1] = 0;
    whreq_result_t rr = {0};
    if (whreq_get(url, headers, &rr)) {
        if (rr.status == 200 && rr.body && json_has_nonempty_array_or_object(rr.body)) {
            whreq_free_result(&rr);
            return 1;   /* lifetime grant present */
        }
        int auth_error = (rr.status == 401 || rr.status == 403);
        /* v2.0.2 (2026-09-10): snapshot status BEFORE free -- reading rr.status
         * after whreq_free_result was a log-only use-after-free that always
         * printed 0 for the actual HTTP status. Cheap fix, correct log now. */
        unsigned int http_status = rr.status;
        whreq_free_result(&rr);
        if (auth_error) {
            /* v1.9.2: 401/403 = expired/invalid token, not "no grant". */
            slog_writef("payload.log", "sub_check: manual_grants %u -> auth error (stale token?)", http_status);
            return -2;
        }
    } else {
        whreq_free_result(&rr);
        return -1;   /* transport error */
    }

    /* 2. subscriptions -- active OR cancelling counts as still-paid.
     * NOTE: intentionally NOT including 'suspended' here. If the user
     * gets suspended, we want the payload to self-unload, not stay
     * armed. The Electron UI has a dedicated suspension screen and
     * fires immediate lockout there; the payload just needs to notice
     * "no active row" and unload. */
    memset(&rr, 0, sizeof(rr));
    _snprintf(url, sizeof(url) - 1,
              "%s/rest/v1/subscriptions?select=status&status=in.(active,cancelling)", base);
    url[sizeof(url) - 1] = 0;
    if (whreq_get(url, headers, &rr)) {
        if (rr.status == 200 && rr.body) {
            int has = json_has_nonempty_array_or_object(rr.body);
            slog_writef("payload.log", "sub_check: subs %u -> %s", rr.status,
                        has ? "ACTIVE" : "empty");
            whreq_free_result(&rr);
            return has ? 1 : 0;
        }
        if (rr.status == 401 || rr.status == 403) {
            /* v1.9.2: 401/403 = expired/invalid token, not "inactive". */
            slog_writef("payload.log", "sub_check: subs %u -> auth error (stale token?)", rr.status);
            whreq_free_result(&rr);
            return -2;
        }
        whreq_free_result(&rr);
        return -1;
    }
    whreq_free_result(&rr);
    return -1;
}

/* Fire the same shutdown event dllmain's init_thread creates + its
 * shutdown_watcher listens on. Clean uninstall of hooks, DWM stays alive.
 * We open by name (not the local HANDLE from dllmain) so this module
 * doesn't have to reach into another translation unit's globals. */
static void trigger_self_unload(const char *reason) {
    slog_writef("payload.log", SS(SVC_STR_SUBCHK_SELF_UNLOAD), reason);
    HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, SS(SVC_STR_SHUTDOWN_EVENT));
    if (ev) {
        SetEvent(ev);
        CloseHandle(ev);
    } else {
        slog_writef("payload.log",
                    "sub_check: OpenEvent(%s) failed gle=%lu -- payload may not unload cleanly",
                    SS(SVC_STR_SHUTDOWN_EVENT), GetLastError());
    }
}

static DWORD WINAPI sub_check_thread(LPVOID param) {
    (void)param;
    slog_write("payload.log", SS(SVC_STR_SUBCHK_THREAD_UP));
    sc_prng_seed_once();

    /* Wait for the shutdown event to exist -- it's created by
     * dllmain::init_thread and takes a few ms. Bound the wait so we
     * never deadlock if event creation fails. */
    HANDLE stop = NULL;
    for (int i = 0; i < 50; i++) {   /* max 5s */
        stop = OpenEventA(SYNCHRONIZE, FALSE, SS(SVC_STR_SHUTDOWN_EVENT));
        if (stop) break;
        Sleep(100);
    }
    if (!stop) {
        slog_write("payload.log", "sub_check: shutdown event never appeared -- thread bailing");
        return 1;
    }

    /* Initial delay so we don't slam the network the instant DWM starts. */
    if (WaitForSingleObject(stop, SUB_CHECK_FIRST_DELAY_MS) == WAIT_OBJECT_0) {
        CloseHandle(stop);
        return 0;
    }

    int consecutive_net_fails = 0;
    int consecutive_auth_fails = 0;   /* v1.9.2: stale-token (401/403) grace */
    for (;;) {
        /* Choose next wait interval:
         *   - token looked stale (401) -> short AUTH_RETRY so we pick up the
         *     fresh JWT Electron pushes over the token-refresh pipe
         *   - transport failing -> exp backoff schedule
         *   - normal path -> base ± jitter
         * Log the picked interval so support has visibility into why a
         * check happened when it did. */
        unsigned wait_ms;
        if (consecutive_auth_fails > 0) {
            wait_ms = SUB_CHECK_AUTH_RETRY_MS;
            slog_writef("payload.log", "sub_check: auth-retry wait=%u ms (auth_fails=%d)",
                        wait_ms, consecutive_auth_fails);
        } else if (consecutive_net_fails > 0) {
            wait_ms = sc_backoff_ms(consecutive_net_fails);
            slog_writef("payload.log", "sub_check: backoff wait=%u ms (net_fails=%d)",
                        wait_ms, consecutive_net_fails);
        } else {
            wait_ms = sc_next_interval_ms(SUB_CHECK_INTERVAL_MS);
            slog_writef("payload.log", "sub_check: jittered wait=%u ms", wait_ms);
        }

        DWORD wr = WaitForSingleObject(stop, wait_ms);
        if (wr == WAIT_OBJECT_0) break;   /* shutdown signalled */
        if (wr != WAIT_TIMEOUT)    break; /* WAIT_FAILED or abandoned */

        const svc_config_t *cfg = cfg_get();
        if (!cfg) {
            slog_write("payload.log", "sub_check: cfg not loaded -- skipping this tick");
            continue;
        }
        /* v2.0.1 (2026-09-10) -- snapshot the JWT under the config CS to
         * avoid a torn read racing with cfg_update_access_token (token-
         * refresh pipe push happens on a separate thread). Pre-fix, a
         * simultaneous push during our memcpy-via-strncpy inside
         * whreq_get header build could produce a malformed Bearer header
         * and a spurious 401 -> auth-fail counter increment. */
        char access_token_local[4200];
        size_t at_len = cfg_copy_access_token(access_token_local, sizeof(access_token_local));
        if (at_len == 0) {
            slog_write("payload.log", "sub_check: no cfg/token -- skipping this tick");
            continue;
        }
        int r = query_supabase_active(access_token_local);
        svc_secure_zero(access_token_local, sizeof(access_token_local));
        if (r == 1) {
            if (consecutive_net_fails > 0 || consecutive_auth_fails > 0) {
                slog_writef("payload.log", "sub_check: recovered (net_fails=%d auth_fails=%d)",
                            consecutive_net_fails, consecutive_auth_fails);
            }
            consecutive_net_fails = 0;
            consecutive_auth_fails = 0;
            continue;
        }
        if (r == 0) {
            /* Explicit inactive -- HTTP 200 + empty result. The subscription
             * genuinely is not active. No grace. Unload now. */
            trigger_self_unload(SS(SVC_STR_SUBCHK_INACTIVE));
            break;
        }
        if (r == -2) {
            /* v1.9.2 (2026-09-09) -- Bug 2. 401/403 = expired/invalid token,
             * NOT proof of an inactive subscription. Electron refreshes the
             * JWT ~12 min pre-expiry and pushes it into cfg->access_token,
             * so a healthy session should never land here. Give it a short
             * grace before pulling the overlay: retry on the AUTH cadence,
             * self-unload only after MAX_AUTH_FAILS consecutive 401s. */
            consecutive_auth_fails++;
            slog_writef("payload.log",
                        "sub_check: auth/expired-token fail %d/%d (grace -- awaiting "
                        "Electron token-refresh push)",
                        consecutive_auth_fails, SUB_CHECK_MAX_AUTH_FAILS);
            if (consecutive_auth_fails >= SUB_CHECK_MAX_AUTH_FAILS) {
                slog_write("payload.log",
                           "sub_check: stale token persisted across grace window -- self-unload");
                trigger_self_unload(SS(SVC_STR_SUBCHK_INACTIVE));
                break;
            }
            continue;
        }
        /* r == -1: transport error. v1.6.5: NO self-unload -- matches
         * Electron-side v1.6 policy (invariant #103). Just count for
         * backoff and log. Cap the counter so backoff stays at 30-min
         * max forever instead of overflowing. */
        consecutive_net_fails++;
        if (consecutive_net_fails > 32) consecutive_net_fails = 32;
        slog_writef("payload.log",
                    "sub_check: net fail %d (backing off, no self-unload; "
                    "matches v1.6 revalidation.js kind=network policy)",
                    consecutive_net_fails);
    }
    CloseHandle(stop);
    slog_write("payload.log", "sub_check: thread exiting");
    return 0;
}

void sub_check_start(void) {
    if (InterlockedCompareExchange(&g_sc_running, 1, 0) != 0) return;
    g_sc_thread = CreateThread(NULL, 0, sub_check_thread, NULL, 0, NULL);
    if (!g_sc_thread) {
        InterlockedExchange(&g_sc_running, 0);
        slog_writef("payload.log", "sub_check: CreateThread failed gle=%lu", GetLastError());
    }
}

void sub_check_stop(void) {
    /* Signaling the shutdown event (from wherever) is what actually stops the
     * thread. Wait for it to exit here, up to 30s (was 1s pre-v14 -- network
     * call in flight can be up to ~20s given Supabase's WinHttp timeout, so
     * 1s guaranteed the thread was STILL RUNNING when FreeLibraryAndExitThread
     * executed -> jump-to-freed-code crash). Called from shutdown_watcher
     * after hooks_uninstall.
     *
     * v14.1 (2026-08-24) -- CancelSynchronousIo on the thread so a
     * pending WinHttpReadData / WinHttpReceiveResponse aborts immediately
     * instead of us waiting up to 20s for its natural timeout. Same fix
     * as token_refresh_stop; without it, the 30s wait was the correct
     * safety margin but made prod uninject feel hung. With cancellation,
     * uninject returns in <100ms typical, 30s only as a hard ceiling. */
    if (g_sc_thread) {
        CancelSynchronousIo(g_sc_thread);
        WaitForSingleObject(g_sc_thread, 30000);
        CloseHandle(g_sc_thread);
        g_sc_thread = NULL;
    }
    InterlockedExchange(&g_sc_running, 0);
}
