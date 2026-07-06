/* ================================================================== *
 * sub_check.c — Runtime Supabase subscription poller.                 *
 *                                                                    *
 * See sub_check.h for the security rationale.                        *
 * ================================================================== */

#include "sub_check.h"
#include "config_read.h"
#include "../../shared/common.h"
#include "../../shared/config_types.h"
#include "../../shared/supabase_config.h"
#include "../../shared/winhttp_util.h"
#include "../../shared/json_util.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <string.h>

/* 30 min between checks. Matches the Electron UI's cadence (1h) but half —
 * defense in depth: whichever fires first wins.
 *
 * Consecutive network-failure tolerance: 3 checks (90 min offline) before
 * we treat it as "network is genuinely gone → be safe, unload". Explicit
 * `active: false` responses trigger unload immediately (no grace). */
#define SUB_CHECK_INTERVAL_MS       (30U * 60U * 1000U)
#define SUB_CHECK_FIRST_DELAY_MS    (2U * 60U * 1000U)   /* wait 2 min after init */
#define SUB_CHECK_MAX_NET_FAILURES  3

static HANDLE  g_sc_thread = NULL;
static volatile LONG g_sc_running = 0;

/* Return values:
 *   1  = subscription confirmed ACTIVE
 *   0  = subscription confirmed INACTIVE (HTTP 200 + empty results, or 401/403)
 *  -1  = network/transport error (undefined; caller should retry)              */
static int query_supabase_active(const char *access_token) {
    if (!access_token || !access_token[0]) return 0;   /* no token = inactive */

    const char *base = sb_url();
    const char *anon = sb_anon_key();
    if (!base || !anon) {
        slog_write("payload.log", "sub_check: sb_url/anon unavailable");
        return -1;
    }

    /* Build headers once — reused for both queries. Local buffers big enough
     * for JWT (~3KB) + anon key (~200B). */
    static char auth_hdr[8192];
    static char apikey_hdr[512];
    _snprintf(auth_hdr,   sizeof(auth_hdr)   - 1, "Authorization: Bearer %s", access_token);
    _snprintf(apikey_hdr, sizeof(apikey_hdr) - 1, "apikey: %s",              anon);
    auth_hdr[sizeof(auth_hdr) - 1]     = 0;
    apikey_hdr[sizeof(apikey_hdr) - 1] = 0;
    const char *headers[] = { auth_hdr, apikey_hdr, "Accept: application/json", NULL };

    char url[512];

    /* 1. manual_grants — lifetime whitelist. */
    _snprintf(url, sizeof(url) - 1,
              "%s/rest/v1/manual_grants?select=status&status=eq.active&revoked_at=is.null", base);
    url[sizeof(url) - 1] = 0;
    whreq_result_t rr = {0};
    if (whreq_get(url, headers, &rr)) {
        if (rr.status == 200 && rr.body && json_has_nonempty_array_or_object(rr.body)) {
            whreq_free_result(&rr);
            return 1;   /* lifetime grant present */
        }
        int explicit_denied = (rr.status == 401 || rr.status == 403);
        whreq_free_result(&rr);
        if (explicit_denied) {
            slog_writef("payload.log", "sub_check: manual_grants %u -> denied", rr.status);
            return 0;
        }
    } else {
        whreq_free_result(&rr);
        return -1;   /* transport error */
    }

    /* 2. subscriptions — active OR cancelling counts as still-paid. */
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
            slog_writef("payload.log", "sub_check: subs %u -> denied", rr.status);
            whreq_free_result(&rr);
            return 0;
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
    slog_writef("payload.log", "sub_check: SELF-UNLOAD trigger (%s)", reason);
    HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, SVC_SHUTDOWN_EVENT_NAME);
    if (ev) {
        SetEvent(ev);
        CloseHandle(ev);
    } else {
        slog_writef("payload.log",
                    "sub_check: OpenEvent(%s) failed gle=%lu — payload may not unload cleanly",
                    SVC_SHUTDOWN_EVENT_NAME, GetLastError());
    }
}

static DWORD WINAPI sub_check_thread(LPVOID param) {
    (void)param;
    slog_write("payload.log", "sub_check: thread up");

    /* Wait for the shutdown event to exist — it's created by
     * dllmain::init_thread and takes a few ms. Bound the wait so we
     * never deadlock if event creation fails. */
    HANDLE stop = NULL;
    for (int i = 0; i < 50; i++) {   /* max 5s */
        stop = OpenEventA(SYNCHRONIZE, FALSE, SVC_SHUTDOWN_EVENT_NAME);
        if (stop) break;
        Sleep(100);
    }
    if (!stop) {
        slog_write("payload.log", "sub_check: shutdown event never appeared — thread bailing");
        return 1;
    }

    /* Initial delay so we don't slam the network the instant DWM starts. */
    if (WaitForSingleObject(stop, SUB_CHECK_FIRST_DELAY_MS) == WAIT_OBJECT_0) {
        CloseHandle(stop);
        return 0;
    }

    int consecutive_net_fails = 0;
    while (WaitForSingleObject(stop, SUB_CHECK_INTERVAL_MS) == WAIT_TIMEOUT) {
        const svc_config_t *cfg = cfg_get();
        if (!cfg || !cfg->access_token[0]) {
            slog_write("payload.log", "sub_check: no cfg/token — skipping this tick");
            continue;
        }
        int r = query_supabase_active(cfg->access_token);
        if (r == 1) {
            if (consecutive_net_fails > 0) {
                slog_writef("payload.log", "sub_check: recovered after %d net fails",
                            consecutive_net_fails);
            }
            consecutive_net_fails = 0;
            continue;
        }
        if (r == 0) {
            /* Explicit inactive — no grace. Unload now. */
            trigger_self_unload("subscription_inactive");
            break;
        }
        /* r == -1: transport error */
        consecutive_net_fails++;
        slog_writef("payload.log", "sub_check: net fail %d/%d",
                    consecutive_net_fails, SUB_CHECK_MAX_NET_FAILURES);
        if (consecutive_net_fails >= SUB_CHECK_MAX_NET_FAILURES) {
            trigger_self_unload("too_many_network_failures");
            break;
        }
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
     * thread. Just wait for it to exit here, up to 1s (network call in flight
     * might delay). Called from shutdown_watcher after hooks_uninstall. */
    if (g_sc_thread) {
        WaitForSingleObject(g_sc_thread, 1000);
        CloseHandle(g_sc_thread);
        g_sc_thread = NULL;
    }
    InterlockedExchange(&g_sc_running, 0);
}
