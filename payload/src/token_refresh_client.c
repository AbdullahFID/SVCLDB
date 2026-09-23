/* ================================================================== *
 * token_refresh_client.c -- v14 (2026-09-19)                          *
 *                                                                    *
 * Payload-side JWT auto-refresh. See token_refresh_client.h for the  *
 * full "why this exists" rationale.                                   *
 *                                                                    *
 * TL;DR of prior three-failed-attempts context:                       *
 *   Pre-v14 the payload could NOT refresh its own JWT -- there was no *
 *   `refresh_token` field in svc_config_t. Only Electron could push   *
 *   fresh JWTs via the named-pipe (token_refresh_server.c). Users     *
 *   who closed svchelper.exe after inject lost the overlay ~1h into  *
 *   their exam because no one refreshed the token. v14 adds the       *
 *   payload autonomy that was missing.                                *
 * ================================================================== */

#include "token_refresh_client.h"
#include "config_read.h"
#include "../../shared/common.h"
#include "../../shared/config_types.h"
#include "../../shared/supabase_config.h"
#include "../../shared/winhttp_util.h"
#include "../../shared/json_util.h"
#include "../../shared/log_secure.h"
#include "../../shared/str_enc.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ─── Tuning ─────────────────────────────────────────────────────── */

/* Refresh lead: attempt refresh when the current token has this many
 * seconds of life left. Set to 6 min so we prefer to lose the race
 * against Electron's 12-min-lead scheduler (see revalidation.js
 * REFRESH_WAKE_LEAD_S) -- Electron wins in the common "svchelper open"
 * case, and we take over silently if it's not running. */
#define TRC_REFRESH_LEAD_S       (6U * 60U)

/* Poll cadence. Cheap wake, do the "is expiry near?" check, sleep
 * again. Small enough that a fresh install with a short-TTL token
 * still gets refreshed in time, big enough that we're not burning CPU
 * inside dwm.exe. */
#define TRC_TICK_MS              (60U * 1000U)     /* 1 min */

/* Retry backoff after a failed refresh (network transient, or lost race
 * to Electron -> 400 invalid_grant). Deliberately short so that if we
 * lost to Electron and the pipe push landed in the interim, our next
 * tick sees the fresh token and skips. Long enough that a genuinely-
 * broken network isn't hammered. */
#define TRC_RETRY_MS             (2U * 60U * 1000U)  /* 2 min */

/* Absolute floor on wait when a refresh JUST succeeded (avoid a
 * failed-immediately-after-succeeded loop if expires_in came back
 * bogus like 0 or negative). */
#define TRC_MIN_WAIT_MS          (30U * 1000U)

/* Max response size we'll accept from the refresh endpoint. Real
 * responses are ~1200-2500 bytes. Anything over 32 KB is a red flag
 * (either Supabase is misbehaving or we're talking to something else) --
 * reject and don't try to parse. */
#define TRC_MAX_RESP_LEN         (32U * 1024U)

/* Startup grace: don't try to refresh in the first N seconds after
 * inject. Gives Electron time to push its own initial refresh if it's
 * running, avoids two racing refreshes at inject time. Aligns with
 * sub_check's SUB_CHECK_FIRST_DELAY_MS (2 min). */
#define TRC_INITIAL_DELAY_MS     (90U * 1000U)

/* ─── Module state ───────────────────────────────────────────────── */

static HANDLE  g_trc_thread  = NULL;
static volatile LONG g_trc_running = 0;
static HANDLE  g_trc_stop_ev = NULL;    /* payload's shutdown event handle (SYNCHRONIZE) */

/* v-next (2026-09-23) -- private wake event, guaranteed openable by our
 * own thread regardless of the shared shutdown event's DACL. Fixes the
 * "will sleep uninterruptibly" fallback that used to leave trc_thread
 * stuck in Sleep(90s) when OpenEventA on the shared shutdown event fails
 * (which happens whenever the shared event's DACL is tightened past
 * DWM-N's implicit access -- our current SYSTEM+Admins DACL does exactly
 * that, so the fallback was firing 100% of the time in practice).
 *
 * Consequence pre-fix: `token_refresh_client_stop`'s WaitForSingleObject
 * on g_trc_thread would block the full 5s ceiling (thread was in
 * Sleep(90s), CancelSynchronousIo is a no-op on Sleep). In the v-next
 * parallel-stops shutdown design, that 5s block was capping the
 * WaitForMultipleObjects window at 2500ms with WAIT_TIMEOUT, aborting
 * cleanup early and abandoning the trc worker.
 *
 * With this private event: token_refresh_client_stop signals it, trc_thread
 * wakes from its next trc_sleep_or_stop call within microseconds, exits
 * cleanly, thread handle is joined, parallel-stops completes cleanly. */
static HANDLE  g_trc_wake_ev = NULL;    /* private, always openable */

/* Tracks the last time we saw a valid refresh_token in cfg. If cfg
 * never has one (upgrade from a pre-v14 install where user hasn't
 * re-injected yet), we log ONCE and then idle so we don't spam the log. */
static int g_idle_logged = 0;

/* ─── Helpers ────────────────────────────────────────────────────── */

/* Return the current wall-clock in unix seconds. Same convention as
 * cfg->token_expires_at. */
static long long trc_now_s(void) {
    return (long long)time(NULL);
}

/* Rough sleep with interruption via the shutdown event OR the private
 * wake event. Returns 1 if either fired (caller should exit), 0 on
 * natural timeout.
 *
 * v-next (2026-09-23) -- wait on BOTH events via WaitForMultipleObjects
 * so token_refresh_client_stop can guarantee wake even when
 * OpenEventA(shared shutdown event) failed at start-up (DACL blocks
 * DWM-N's opener). g_trc_wake_ev is created by token_refresh_client_start
 * with no name / default DACL so it's always openable within this process.
 * Old "uninterruptibly Sleep(wait_ms)" fallback made shutdown_watcher's
 * WaitForSingleObject on g_trc_thread block the full 5s ceiling, which
 * in parallel-stops was aborting the wait at 2500ms with WAIT_TIMEOUT. */
static int trc_sleep_or_stop(unsigned wait_ms) {
    HANDLE waits[2];
    DWORD  count = 0;
    if (g_trc_stop_ev) waits[count++] = g_trc_stop_ev;
    if (g_trc_wake_ev) waits[count++] = g_trc_wake_ev;
    if (count == 0) {
        /* Both events failed to be created. Should never happen post
         * v-next since g_trc_wake_ev creation is unconditional and
         * DACL-immune, but guard defensively so we don't hard-hang. */
        Sleep(wait_ms > 200 ? 200 : wait_ms);   /* cap at 200ms so g_trc_running check happens often */
        return InterlockedCompareExchange(&g_trc_running, 0, 0) == 0;
    }
    DWORD wr = WaitForMultipleObjects(count, waits, FALSE, wait_ms);
    /* WAIT_OBJECT_0 or WAIT_OBJECT_0+1 => shutdown/wake fired. */
    return (wr == WAIT_OBJECT_0) || (wr == (WAIT_OBJECT_0 + 1));
}

/* ─── Core refresh ───────────────────────────────────────────────── *
 *
 * POST {SUPABASE_URL}/auth/v1/token?grant_type=refresh_token
 *   header  apikey: <anon>
 *   header  Content-Type: application/json
 *   body    {"refresh_token":"<rt>"}
 *
 * Success 200:
 *   { "access_token":"eyJ...", "refresh_token":"...", "expires_in":3600, ... }
 *
 * Failure 400 body typically:
 *   { "error":"invalid_grant", "error_description":"Invalid Refresh Token: ..." }
 *   400 invalid_grant means the refresh_token was consumed elsewhere
 *   (Electron beat us to it, or a stale on-disk config.dat's rt got
 *   rotated on the other side). We DON'T self-unload on 400 -- the pipe
 *   push from Electron should land soon and update our cfg.
 *
 * Returns:
 *    1 = success (cfg updated + persisted)
 *    0 = transient failure (network / 5xx) -- retry soon
 *   -1 = permanent-ish failure (400 invalid_grant, or refresh_token gone)
 *        -- back off, defer to Electron pipe push, keep trying at retry
 *        cadence until sub_check's grace window forces a self-unload.  */
static int trc_do_refresh(void) {
    /* Snapshot the current refresh_token + supabase endpoints under CS
     * (no torn reads, and we don't hold the CS across the HTTPS call). */
    char rt[4096];
    size_t rt_len = cfg_copy_refresh_token(rt, sizeof(rt));
    if (rt_len == 0) {
        /* No refresh_token in cfg. Possible reasons:
         *   1) Pre-v14 install upgraded in place; user hasn't re-injected
         *      yet so config.dat still lacks the field. Sam should be
         *      told to sign in again OR just click Inject again.
         *   2) Somehow the field was cleared (shouldn't happen).
         * Log once, don't spam. */
        if (!g_idle_logged) {
            slog_write("payload.log",
                       "token_refresh_client: no refresh_token in cfg "
                       "(pre-v14 install? user needs to re-inject); "
                       "auto-refresh disabled");
            g_idle_logged = 1;
        }
        return -1;
    }

    const char *sb = sb_url();
    const char *anon = sb_anon_key();
    if (!sb || !anon) {
        svc_secure_zero(rt, sizeof(rt));
        slog_write("payload.log",
                   "token_refresh_client: supabase config unavailable");
        return 0;
    }

    /* Build URL. */
    char url[512];
    _snprintf(url, sizeof(url) - 1,
              "%s/auth/v1/token?grant_type=refresh_token", sb);
    url[sizeof(url) - 1] = 0;

    /* Build JSON body: {"refresh_token":"..."} */
    json_builder_t jb;
    if (!jb_init(&jb, 512)) {
        svc_secure_zero(rt, sizeof(rt));
        return 0;
    }
    if (!jb_obj_begin(&jb) ||
        !jb_key(&jb, "refresh_token") || !jb_str(&jb, rt) ||
        !jb_obj_end(&jb)) {
        jb_free(&jb);
        svc_secure_zero(rt, sizeof(rt));
        return 0;
    }
    svc_secure_zero(rt, sizeof(rt));   /* rt is baked into jb.buf now */

    /* Build headers. Content-Type MUST come first (WinHTTP quirk on some
     * builds -- header order shouldn't matter but be defensive). */
    char apikey_hdr[512];
    _snprintf(apikey_hdr, sizeof(apikey_hdr) - 1, "apikey: %s", anon);
    apikey_hdr[sizeof(apikey_hdr) - 1] = 0;
    const char *hdrs[] = {
        "Content-Type: application/json",
        apikey_hdr,
        "Accept: application/json",
        NULL
    };

    whreq_result_t r = {0};
    int ok = whreq_post(url, hdrs, jb.buf, jb.len, &r);
    /* Wipe the body: it contains the plaintext refresh_token. */
    svc_secure_zero(jb.buf, jb.len);
    jb_free(&jb);

    if (!ok) {
        slog_writef("payload.log",
                    "token_refresh_client: transport error (%s)",
                    r.err[0] ? r.err : "unknown");
        whreq_free_result(&r);
        return 0;
    }

    /* Cap response size defensively before parse. */
    if (r.body_len > TRC_MAX_RESP_LEN) {
        slog_writef("payload.log",
                    "token_refresh_client: response too large (%zu bytes) -- reject",
                    r.body_len);
        whreq_free_result(&r);
        return 0;
    }

    if (r.status >= 400 && r.status < 500) {
        /* 400 typically = invalid_grant (rotated by other side).
         * 401/403 = wrong apikey (shouldn't happen -- we use anon).
         * Log the first ~200 chars of the body without exposing tokens. */
        char snip[256] = {0};
        if (r.body && r.body_len > 0) {
            size_t take = r.body_len < sizeof(snip) - 1 ? r.body_len : sizeof(snip) - 1;
            memcpy(snip, r.body, take);
            snip[take] = 0;
        }
        slog_writef("payload.log",
                    "token_refresh_client: refresh %u -- %s "
                    "(likely lost race to Electron pipe push; deferring)",
                    r.status, snip);
        whreq_free_result(&r);
        return -1;
    }

    if (r.status < 200 || r.status >= 300 || !r.body) {
        slog_writef("payload.log",
                    "token_refresh_client: refresh non-2xx %u (%s)",
                    r.status, r.err[0] ? r.err : "no err");
        whreq_free_result(&r);
        return 0;
    }

    /* Parse response. */
    char new_at[4096]  = {0};
    char new_rt[4096]  = {0};
    if (!json_get_str(r.body, "access_token", new_at, sizeof(new_at)) ||
        new_at[0] == 0) {
        slog_write("payload.log",
                   "token_refresh_client: response missing access_token");
        whreq_free_result(&r);
        return 0;
    }
    /* refresh_token SHOULD always be present but tolerate its absence
     * (some Supabase deployments/configs may not rotate). If absent,
     * keep using the current one -- the update helper is a no-op below. */
    (void)json_get_str(r.body, "refresh_token", new_rt, sizeof(new_rt));
    double expires_in = 3600.0;   /* Supabase default */
    (void)json_get_num(r.body, "expires_in", &expires_in);
    if (expires_in < 60.0)     expires_in = 60.0;      /* sanity floor */
    if (expires_in > 24*3600.0) expires_in = 24*3600.0; /* sanity ceiling */

    /* Whole response is no longer needed. Zero-then-free so the body
     * (containing plaintext JWTs) doesn't linger in freed heap. */
    if (r.body && r.body_len > 0) svc_secure_zero(r.body, r.body_len);
    whreq_free_result(&r);

    /* Apply to cfg. */
    size_t at_len = strnlen(new_at, sizeof(new_at));
    if (!cfg_update_access_token(new_at, at_len)) {
        svc_secure_zero(new_at, sizeof(new_at));
        svc_secure_zero(new_rt, sizeof(new_rt));
        slog_write("payload.log",
                   "token_refresh_client: cfg_update_access_token failed");
        return 0;
    }
    if (new_rt[0]) {
        size_t rt2_len = strnlen(new_rt, sizeof(new_rt));
        (void)cfg_update_refresh_token(new_rt, rt2_len);
    }
    long long new_exp = trc_now_s() + (long long)expires_in;
    cfg_update_token_expires_at(new_exp);

    /* Persist so a payload reload / DWM crash / reboot preserves the
     * rotated refresh_token. Supabase's refresh_tokens are one-shot --
     * losing the rotation = losing the ability to refresh forever. */
    int persist_ok = cfg_persist();
    slog_writef("payload.log",
                "token_refresh_client: refreshed access_token (%zu bytes) "
                "expires_in=%.0fs%s persist=%s",
                at_len, expires_in,
                new_rt[0] ? " (refresh_token rotated)" : "",
                persist_ok ? "OK" : "FAIL");

    svc_secure_zero(new_at, sizeof(new_at));
    svc_secure_zero(new_rt, sizeof(new_rt));
    g_idle_logged = 0;   /* re-enable the "no refresh_token" log if it clears */
    return 1;
}

/* ─── Thread body ────────────────────────────────────────────────── */

static DWORD WINAPI trc_thread(LPVOID param) {
    (void)param;
    slog_write("payload.log", "token_refresh_client: thread up");

    /* Grab a SYNCHRONIZE handle on the shared shutdown event so we can
     * wake from Sleep-equivalent instantly on shutdown. Bounded try:
     * event is created early in init_thread; a few 100ms polls covers
     * any startup ordering. */
    for (int i = 0; i < 30 && !g_trc_stop_ev; i++) {
        g_trc_stop_ev = OpenEventA(SYNCHRONIZE, FALSE,
                                   SS(SVC_STR_SHUTDOWN_EVENT));
        if (g_trc_stop_ev) break;
        Sleep(100);
    }
    if (!g_trc_stop_ev) {
        /* v-next (2026-09-23): pre-fix this meant Sleep(wait_ms) with no
         * wake path -- stop() couldn't cancel a mid-tick sleep, so the
         * thread would exit only after up to 90s. Post-fix, trc_sleep_or_stop
         * waits on the private g_trc_wake_ev too (unnamed / DACL-immune),
         * which token_refresh_client_stop signals unconditionally. */
        slog_write("payload.log",
                   "token_refresh_client: shared shutdown event not openable "
                   "(DACL); using private wake event for prompt stop");
    }

    /* Initial grace so Electron's revalidation can do its own first
     * refresh if it's running. Also gives cfg time to be fully loaded
     * (cfg_get is lazy-init on first call). */
    if (trc_sleep_or_stop(TRC_INITIAL_DELAY_MS)) goto done;

    unsigned next_wait_ms = TRC_TICK_MS;

    while (InterlockedCompareExchange(&g_trc_running, 0, 0) == 1) {
        /* Force cfg load if not yet -- cfg_get returns const svc_config_t*
         * or NULL. We only need the loaded state; individual fields are
         * fetched via the copy helpers. */
        const svc_config_t *cfg = cfg_get();
        if (!cfg) {
            slog_write("payload.log",
                       "token_refresh_client: cfg not loaded -- skipping tick");
            if (trc_sleep_or_stop(next_wait_ms)) break;
            continue;
        }

        long long exp   = cfg_get_token_expires_at();
        long long now_s = trc_now_s();
        long long remaining_s = exp - now_s;

        /* If cfg didn't ship with a token_expires_at (0 or unset), we
         * still try -- Supabase will tell us if the token is expired,
         * and we cache the fresh expires_in. Doing so lets us bootstrap
         * on the very first payload load. */
        int need_refresh = (exp <= 0) ||
                           (remaining_s <= (long long)TRC_REFRESH_LEAD_S);

        if (!need_refresh) {
            /* Token is still fresh. Sleep until ~1 min before we'd next
             * need to check (which is: remaining_s - LEAD - a bit). But
             * never sleep less than TICK_MS so we don't tight-loop. */
            long long until_check_s = remaining_s - (long long)TRC_REFRESH_LEAD_S;
            unsigned wait_ms;
            if (until_check_s <= 0)                 wait_ms = TRC_TICK_MS;
            else if (until_check_s > 30 * 60)       wait_ms = 15U * 60U * 1000U;
            else if (until_check_s * 1000LL < TRC_TICK_MS)
                                                    wait_ms = TRC_TICK_MS;
            else                                    wait_ms = (unsigned)(until_check_s * 1000LL);
            if (trc_sleep_or_stop(wait_ms)) break;
            next_wait_ms = TRC_TICK_MS;
            continue;
        }

        /* Attempt the refresh. */
        int r = trc_do_refresh();
        if (r == 1) {
            /* Success -- next tick uses default cadence. */
            next_wait_ms = TRC_TICK_MS;
        } else if (r == 0) {
            /* Transient failure -- back off. */
            next_wait_ms = TRC_RETRY_MS;
        } else {
            /* -1: permanent-ish (400 invalid_grant / no refresh_token).
             * Defer to Electron pipe push -- our next tick just checks
             * cfg_get_token_expires_at again, which will show fresh if
             * the pipe push landed. */
            next_wait_ms = TRC_RETRY_MS;
        }
        if (next_wait_ms < TRC_MIN_WAIT_MS) next_wait_ms = TRC_MIN_WAIT_MS;

        if (trc_sleep_or_stop(next_wait_ms)) break;
    }

done:
    if (g_trc_stop_ev) {
        CloseHandle(g_trc_stop_ev);
        g_trc_stop_ev = NULL;
    }
    slog_write("payload.log", "token_refresh_client: thread exiting");
    return 0;
}

/* ─── Public API ─────────────────────────────────────────────────── */

void token_refresh_client_start(void) {
    if (InterlockedCompareExchange(&g_trc_running, 1, 0) != 0) return;
    /* v-next (2026-09-23) -- pre-create the private wake event so
     * trc_thread can wait on it from tick 0 (avoids the "created after
     * thread started" race). Manual-reset so multiple waiters see the
     * signal + it stays signalled until token_refresh_client_stop
     * completes. */
    if (!g_trc_wake_ev) {
        g_trc_wake_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        /* NULL name = unnamed = process-local = DACL-immune. */
    }
    g_trc_thread = CreateThread(NULL, 0, trc_thread, NULL, 0, NULL);
    if (!g_trc_thread) {
        InterlockedExchange(&g_trc_running, 0);
        slog_writef("payload.log",
                    "token_refresh_client: CreateThread failed gle=%lu",
                    GetLastError());
    }
}

void token_refresh_client_stop(void) {
    InterlockedExchange(&g_trc_running, 0);
    /* v-next (2026-09-23) -- ALWAYS signal our private wake event first.
     * Pre-fix this fn relied on the shared shutdown event being signalled
     * externally + on CancelSynchronousIo to unblock in-flight HTTP; both
     * fail to wake a thread that took the "Sleep(wait_ms) uninterruptibly"
     * fallback path (which happened 100% of the time whenever OpenEventA
     * on the shared shutdown event failed due to DACL). The private event
     * is unnamed / process-local / DACL-immune -- it always wakes. */
    if (g_trc_wake_ev) SetEvent(g_trc_wake_ev);
    /* Signal via the shared shutdown event so any in-flight
     * WaitForSingleObject returns immediately. If our WinHTTP request
     * is in flight, CancelSynchronousIo aborts it (same pattern as
     * sub_check_stop + token_refresh_stop). */
    if (g_trc_thread) {
        CancelSynchronousIo(g_trc_thread);
        WaitForSingleObject(g_trc_thread, 5000);
        CloseHandle(g_trc_thread);
        g_trc_thread = NULL;
    }
    /* Only NOW is it safe to close the wake event -- thread has exited
     * and won't dereference the handle anymore. */
    if (g_trc_wake_ev) {
        CloseHandle(g_trc_wake_ev);
        g_trc_wake_ev = NULL;
    }
}
