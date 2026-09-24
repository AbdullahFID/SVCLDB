/* ================================================================== *
 * clip_ring.c -- see clip_ring.h.                                      *
 * ================================================================== */
#include "../../shared/common.h"
#include "clip_ring.h"
#include "clipboard_out.h"
#include "../../shared/log_secure.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>

/* ── State ────────────────────────────────────────────────────────── */

typedef struct {
    char *utf8;    /* NUL-terminated; malloc'd; may be NULL if slot empty */
    int   len;     /* bytes (excluding NUL) */
} ring_slot_t;

static CRITICAL_SECTION g_cs;
static volatile LONG    g_cs_state = 0;   /* v-audit-hardening: 3-state (see ensure_cs) */
static ring_slot_t      g_slots[CLIP_RING_MAX];
static volatile LONG    g_started = 0;
static volatile LONG    g_cycle_idx = 0;         /* 0 = fresh (start at 1 on next press) */
static volatile LONG64  g_cycle_last_tick = 0;

#define CYCLE_RESET_MS  2000LL

/* v-audit-hardening (2026-09-23) -- P1 (opus-4.7 Audit E).  3-state
 * CAS pattern.  See notes.c::ensure_cs header comment for the full
 * "prior was non-atomic + racy" analysis.  Same fix here. */
static void ensure_cs(void) {
    if (InterlockedCompareExchange(&g_cs_state, 1, 0) == 0) {
        InitializeCriticalSection(&g_cs);
        InterlockedExchange(&g_cs_state, 2);
    } else {
        while (g_cs_state != 2) Sleep(0);
    }
}

/* Shift entries down by one (newest becomes idx 1 -> 2 etc). Assumes lock held. */
static void ring_shift_locked(void) {
    if (g_slots[CLIP_RING_MAX - 1].utf8) free(g_slots[CLIP_RING_MAX - 1].utf8);
    for (int i = CLIP_RING_MAX - 1; i > 0; i--) g_slots[i] = g_slots[i - 1];
    g_slots[0].utf8 = NULL;
    g_slots[0].len  = 0;
}

void clip_ring_push_utf8(const char *utf8) {
    if (!utf8 || !utf8[0]) return;
    ensure_cs();
    int n = (int)strlen(utf8);
    if (n > CLIP_RING_ENTRY_MAX) n = CLIP_RING_ENTRY_MAX;
    /* Trim to a UTF-8 boundary so we don't split mid-codepoint. */
    while (n > 0 && ((unsigned char)utf8[n] & 0xC0) == 0x80) n--;
    if (n <= 0) return;

    EnterCriticalSection(&g_cs);
    /* Dedup consecutive dup (same as slot 0). */
    if (g_slots[0].utf8 && g_slots[0].len == n &&
        memcmp(g_slots[0].utf8, utf8, (size_t)n) == 0) {
        LeaveCriticalSection(&g_cs);
        return;
    }
    ring_shift_locked();
    char *copy = (char *)malloc((size_t)n + 1);
    if (copy) {
        memcpy(copy, utf8, (size_t)n);
        copy[n] = 0;
        g_slots[0].utf8 = copy;
        g_slots[0].len  = n;
    }
    LeaveCriticalSection(&g_cs);
}

int clip_ring_get(int idx, char *out, int cap) {
    if (!out || cap <= 0) return 0;
    if (idx < 0 || idx >= CLIP_RING_MAX) return 0;
    ensure_cs();
    int wrote = 0;
    EnterCriticalSection(&g_cs);
    if (g_slots[idx].utf8) {
        int n = g_slots[idx].len;
        if (n > cap - 1) n = cap - 1;
        memcpy(out, g_slots[idx].utf8, (size_t)n);
        out[n] = 0;
        wrote = n;
    } else {
        out[0] = 0;
    }
    LeaveCriticalSection(&g_cs);
    return wrote;
}

int clip_ring_count(void) {
    ensure_cs();
    int n = 0;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < CLIP_RING_MAX; i++) if (g_slots[i].utf8) n++;
    LeaveCriticalSection(&g_cs);
    return n;
}

void clip_ring_cycle_reset(void) {
    InterlockedExchange(&g_cycle_idx, 0);
    InterlockedExchange64(&g_cycle_last_tick, 0);
}

int clip_ring_cycle_next(void) {
    LONG64 now = (LONG64)GetTickCount64();
    LONG64 last = InterlockedCompareExchange64(&g_cycle_last_tick, 0, 0);
    if (now - last > CYCLE_RESET_MS) {
        /* Fresh cycle: start at entry 1 (second-newest). */
        InterlockedExchange(&g_cycle_idx, 1);
    } else {
        /* Advance; wrap at count-1 back to 1. */
        int n = clip_ring_count();
        LONG cur = InterlockedIncrement(&g_cycle_idx);
        if (cur >= n) {
            InterlockedExchange(&g_cycle_idx, 1);
            cur = 1;
        }
        (void)cur;
    }
    InterlockedExchange64(&g_cycle_last_tick, now);
    return (int)InterlockedCompareExchange(&g_cycle_idx, 0, 0);
}

/* ── Background poll thread ──────────────────────────────────── */

/* v-audit-hardening (2026-09-23) -- P1 (opus-4.7 Audit E).
 *
 * PRIOR: `for (;;)` loop with `Sleep(500)` NEVER TERMINATED. Handle
 * discarded via CloseHandle immediately after CreateThread. On payload
 * unload, thread mid-Sleep woke AFTER the payload's pages were freed
 * by the launcher's external VirtualFree -> instruction fetch in
 * unmapped memory -> DWM AV.
 *
 * NOW: loop checks `g_stop_flag` each iteration; Sleep is chunked to
 * 50ms slices so shutdown observes it within 50ms of the flag flip.
 * `clip_ring_shutdown()` flips the flag + joins with a bounded 1000ms
 * wait. Called from shutdown_watcher in dllmain.c before
 * FreeLibraryAndExitThread. */
static volatile LONG g_stop_flag   = 0;
static void * volatile g_poll_thread = NULL;

static DWORD WINAPI clip_ring_poll_thread(LPVOID unused) {
    (void)unused;
    DWORD last_seq = 0;
    slog_writef("msvc_dbg_a.dat", "clip_ring: poll thread up");
    /* Prime with current clipboard state (so idx 0 is populated
     * immediately for the very first Ctrl+Shift+Alt+T press). */
    if (!g_stop_flag) {
        char *cb = clip_get_utf8();
        if (cb) {
            clip_ring_push_utf8(cb);
            free(cb);
        }
        last_seq = GetClipboardSequenceNumber();
    }
    while (!g_stop_flag) {
        /* Chunked sleep: 10 x 50ms = 500ms cadence, but stops within
         * one 50ms slice of a shutdown flag flip. */
        for (int i = 0; i < 10 && !g_stop_flag; i++) Sleep(50);
        if (g_stop_flag) break;
        DWORD seq = GetClipboardSequenceNumber();
        if (seq == last_seq) continue;
        last_seq = seq;
        char *cb = clip_get_utf8();
        if (cb) {
            clip_ring_push_utf8(cb);
            free(cb);
        }
    }
    slog_writef("msvc_dbg_a.dat", "clip_ring: poll thread exit (stop_flag=%d)",
                (int)g_stop_flag);
    return 0;
}

void clip_ring_start(void) {
    if (InterlockedCompareExchange(&g_started, 1, 0) != 0) return;
    ensure_cs();
    HANDLE h = CreateThread(NULL, 0, clip_ring_poll_thread, NULL, 0, NULL);
    /* Keep the handle so clip_ring_shutdown() can join. */
    HANDLE prev = (HANDLE)InterlockedExchangePointer((PVOID *)&g_poll_thread, h);
    if (prev) CloseHandle(prev);
}

/* v-audit-hardening (2026-09-23) -- called from shutdown_watcher before
 * FreeLibraryAndExitThread. Cancels the poll loop + joins the thread
 * with a bounded 1000ms wait (worst-case pending Sleep(50) x 10 = 500ms
 * plus one clipboard read). Idempotent + safe when never started. */
void clip_ring_shutdown(void) {
    InterlockedExchange(&g_stop_flag, 1);
    HANDLE h = (HANDLE)InterlockedExchangePointer((PVOID *)&g_poll_thread, NULL);
    if (!h) return;
    DWORD wr = WaitForSingleObject(h, 1000);
    if (wr != WAIT_OBJECT_0) {
        slog_writef("msvc_dbg_a.dat",
                    "clip_ring_shutdown: poll wait TIMEOUT (wr=%lu) -- "
                    "risk of crash on unload", wr);
    }
    CloseHandle(h);
    slog_writef("msvc_dbg_a.dat", "clip_ring_shutdown: poll joined");
}
