/* ================================================================== *
 * as_cfg.c -- AutoSolver/Agent settings store (see as_cfg.h).          *
 * ================================================================== */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "as_cfg.h"
#include "../../../shared/json_util.h"
#include "../../../shared/common.h"
#include "../../../shared/config_types.h"

extern void slog_writef(const char *file, const char *fmt, ...);

#define AS_CFG_PATH  SVC_INSTALL_DIR "\\autosolver.json"

static CRITICAL_SECTION g_cs;
static volatile LONG     g_cs_init = 0;
static volatile LONG     g_loaded  = 0;
static FILETIME          g_mtime   = {0};   /* autosolver.json last-write we loaded */
static volatile LONG     g_watch_running = 0;

/* v7.3 (2026-09-24) -- Deferred-persist infrastructure. Setters flip
 * g_dirty; the persister thread flushes once per debounce window
 * (AS_CFG_DEBOUNCE_MS). Prevents:
 *   1. A rapid burst of dot-taps (each toggling ui_state) blocking the
 *      DWM compose thread on 5-20ms file writes per tap.
 *   2. A write-then-immediately-reload storm from the mtime watcher
 *      seeing its own write (we also bump g_mtime after every save
 *      so this can't fire even if the persister races with the watcher).
 * A cancel-and-join in as_cfg_shutdown() (called from shutdown_watcher)
 * flushes any pending dirty writes before the payload unmaps. */
static volatile LONG     g_dirty         = 0;
static volatile LONG     g_persist_running = 0;
static HANDLE            g_persist_thread  = NULL;
#define AS_CFG_DEBOUNCE_MS 250   /* min gap between disk writes */

/* Forward decl -- defined below the setters, called by the persister. */
static void as_cfg_save_locked(void);

static as_settings_t g_as = {
    /* autosolver_enabled */ 1,
    /* auto_click         */ 0,   /* STEALTH DEFAULT: display-only */
    /* humanize           */ 1,
    /* uia_snap           */ 1,
    /* dot_enabled        */ 1,
    /* dot_jump           */ 1,
    /* render_max_edge    */ 1280,
    /* dot_opacity        */ 0.30,   /* v15.1 -- lighter default per LO */
    /* dot_size_px        */ 8,      /* v15.1.4 -- hooksdll-parity default (was 6/9) */
    /* dot_ui_state       */ 0,      /* collapsed */
    /* dot_pos_x          */ -1,     /* auto: top-right */
    /* dot_pos_y          */ -1,
    /* dot_full_w         */ 340,
    /* dot_full_h         */ 210,
    /* dot_show_slider    */ 1,
    /* dot_hold_ms        */ 2000,
    /* dot_hide_when_overlay */ 1,   /* per LO: dot only shows when overlay hidden */
    /* dot_col_idle       */ 0xFF34C759,  /* macOS-spec green */
    /* dot_col_capturing  */ 0xFFF59E0A,  /* amber */
    /* dot_col_analyzing  */ 0xFFFF9500,  /* orange */
    /* dot_col_executing  */ 0xFFAF52DE,  /* purple */
    /* dot_col_done       */ 0xFF34C759,  /* green (same as idle/cooldown) */
    /* dot_col_error      */ 0xFFFF3B30,  /* red */
    /* agent_provider     */ 0,           /* 0=anthropic (default) */
    /* agent_tier         */ SVC_TIER_MEDIUM,
    /* agent_budget_usd   */ 2.0,
    /* agent_max_steps    */ 40,
    /* agent_max_wallclock_ms */ 30 * 60 * 1000,
    /* agent_pace         */ 1,
    /* v17 (2026-09-23) -- Human autotyper defaults. */
    /* typer_wpm          */ 110,
    /* typer_humanize     */ 1,
    /* typer_paste_mode   */ 0,
    /* typer_planning     */ 1,
    /* typer_wait_mods    */ 1,
    /* v7.3 (2026-09-24) -- autotyper cancel key (default VK_ESCAPE=0x1B). */
    /* typer_cancel_vk    */ 0x1B,
    /* v7.4 (2026-09-25) -- multi-turn conversation memory (chat + solver). */
    /* chat_history_turns       */ 5,
    /* autosolver_history_turns */ 5,
};

static void ensure_cs(void) {
    if (InterlockedCompareExchange(&g_cs_init, 1, 0) == 0)
        InitializeCriticalSection(&g_cs);
}

static char *read_file_all(const char *path, DWORD *out_len) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0 || sz > 65536) { CloseHandle(h); return NULL; }
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD rd = 0;
    if (!ReadFile(h, buf, sz, &rd, NULL) || rd != sz) { free(buf); CloseHandle(h); return NULL; }
    buf[sz] = 0;
    CloseHandle(h);
    if (out_len) *out_len = rd;
    return buf;
}

static int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

/* Fetch autosolver.json's last-write time. Returns 1 + fills *ft on success;
 * 0 if the file doesn't exist yet (ft zeroed). */
static int file_mtime(FILETIME *ft) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ZeroMemory(ft, sizeof(*ft));
    if (!GetFileAttributesExA(AS_CFG_PATH, GetFileExInfoStandard, &fad)) return 0;
    *ft = fad.ftLastWriteTime;
    return 1;
}

void as_cfg_load(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    g_loaded = 1;
    DWORD len = 0;
    char *j = read_file_all(AS_CFG_PATH, &len);
    if (j) {
        double d; int b;
        if (json_get_bool(j, "autosolver_enabled", &b)) g_as.autosolver_enabled = b;
        if (json_get_bool(j, "auto_click", &b))         g_as.auto_click = b;
        /* v18 (2026-09-25) -- Sam's UI-simplification pass.  These four
         * booleans (humanize motion, UIA snap-to-element, autotyper
         * humanize, autotyper wait-for-mod-release) are removed from the
         * svchelper dashboard: they are ALL pro-stealth defaults ("too
         * much options for the avg kid"). Forced ON on every load so
         * even hand-edited or legacy configs get the stealthy path.
         * `json_get_bool(j, "humanize", &b)` is intentionally NOT called
         * here -- the field is still WRITTEN by the Electron save path
         * (as `1`, so round-trip stays clean), but the payload no
         * longer trusts an on-disk `0` value. */
        g_as.humanize   = 1;
        g_as.uia_snap   = 1;
        if (json_get_bool(j, "dot_enabled", &b))        g_as.dot_enabled = b;
        if (json_get_bool(j, "dot_jump", &b))           g_as.dot_jump = b;
        if (json_get_num (j, "render_max_edge", &d))    g_as.render_max_edge = clampi((int)d, 640, 4096);
        if (json_get_num (j, "dot_opacity", &d))        g_as.dot_opacity = (d < 0.05 ? 0.05 : (d > 1.0 ? 1.0 : d));
        if (json_get_num (j, "dot_size_px", &d))        g_as.dot_size_px = clampi((int)d, 6, 24);
        if (json_get_num (j, "dot_ui_state", &d))       g_as.dot_ui_state = clampi((int)d, 0, 2);
        if (json_get_num (j, "dot_pos_x", &d))          g_as.dot_pos_x = (int)d;
        if (json_get_num (j, "dot_pos_y", &d))          g_as.dot_pos_y = (int)d;
        if (json_get_num (j, "dot_full_w", &d))         g_as.dot_full_w = clampi((int)d, 180, 900);
        if (json_get_num (j, "dot_full_h", &d))         g_as.dot_full_h = clampi((int)d, 110, 900);
        if (json_get_bool(j, "dot_show_slider", &b))    g_as.dot_show_slider = b;
        if (json_get_num (j, "dot_hold_ms", &d))        g_as.dot_hold_ms = clampi((int)d, 200, 5000);
        if (json_get_bool(j, "dot_hide_when_overlay", &b)) g_as.dot_hide_when_overlay = b;
        if (json_get_num (j, "dot_col_idle", &d))       g_as.dot_col_idle      = (unsigned)(long long)d;
        if (json_get_num (j, "dot_col_capturing", &d))  g_as.dot_col_capturing = (unsigned)(long long)d;
        if (json_get_num (j, "dot_col_analyzing", &d))  g_as.dot_col_analyzing = (unsigned)(long long)d;
        if (json_get_num (j, "dot_col_executing", &d))  g_as.dot_col_executing = (unsigned)(long long)d;
        if (json_get_num (j, "dot_col_done", &d))       g_as.dot_col_done      = (unsigned)(long long)d;
        if (json_get_num (j, "dot_col_error", &d))      g_as.dot_col_error     = (unsigned)(long long)d;
        if (json_get_num (j, "agent_provider", &d))     g_as.agent_provider = clampi((int)d, 0, 2);
        if (json_get_num (j, "agent_tier", &d))         g_as.agent_tier = clampi((int)d, 0, 3);
        if (json_get_num (j, "agent_budget_usd", &d))   g_as.agent_budget_usd = (d < 0.1 ? 0.1 : (d > 100.0 ? 100.0 : d));
        if (json_get_num (j, "agent_max_steps", &d))    g_as.agent_max_steps = clampi((int)d, 1, 400);
        if (json_get_num (j, "agent_max_wallclock_ms", &d)) g_as.agent_max_wallclock_ms = clampi((int)d, 60000, 12*60*60*1000);
        if (json_get_num (j, "agent_pace", &d))         g_as.agent_pace = clampi((int)d, 0, 2);
        /* v17 (2026-09-23) -- Human autotyper fields.
         * v18 (2026-09-25) -- typer_humanize + typer_wait_mods removed
         * from the dashboard UI (see comment on the `humanize` block
         * above). Forced ON regardless of on-disk value.  Only
         * typer_paste_mode + typer_planning + typer_wpm remain
         * user-toggleable. */
        if (json_get_num (j, "typer_wpm", &d))          g_as.typer_wpm = clampi((int)d, 30, 500);
        g_as.typer_humanize = 1;
        if (json_get_bool(j, "typer_paste_mode", &b))   g_as.typer_paste_mode = b;
        if (json_get_bool(j, "typer_planning", &b))     g_as.typer_planning = b;
        g_as.typer_wait_mods = 1;
        /* v7.3 (2026-09-24) -- autotyper cancel key (optional; default
         * VK_ESCAPE == 0x1B).  Range clamp: [0..0xFF]. 0 disables the
         * global cancel entirely so autotyper only stops via the dot's
         * in-overlay stop button. */
        if (json_get_num (j, "typer_cancel_vk", &d))    g_as.typer_cancel_vk = clampi((int)d, 0, 0xFF);
        /* v7.4 (2026-09-25) -- Multi-turn conversation memory. */
        if (json_get_num (j, "chat_history_turns", &d))       g_as.chat_history_turns = clampi((int)d, 1, 24);
        if (json_get_num (j, "autosolver_history_turns", &d)) g_as.autosolver_history_turns = clampi((int)d, 1, 24);
        free(j);
        slog_writef("msvc_dbg_a.dat", "as_cfg loaded (autosolver=%d auto_click=%d humanize=%d uia=%d dot=%d cancel_vk=0x%02X)",
                    g_as.autosolver_enabled, g_as.auto_click, g_as.humanize,
                    g_as.uia_snap, g_as.dot_enabled, g_as.typer_cancel_vk);
    }
    /* Record the on-disk mtime we just consumed so the watcher only reloads
     * on a genuine change (Electron write or a hotkey-save). */
    file_mtime(&g_mtime);
    LeaveCriticalSection(&g_cs);
}

/* v7.3 (2026-09-24) -- Actual on-disk writer; caller MUST hold g_cs.
 * Splits the old as_cfg_save() into `mark dirty` (deferred) and this
 * synchronous flush.  Called from:
 *   - as_cfg_bg_thread   (background debounce + mtime watcher)
 *   - as_cfg_shutdown    (final flush before payload unloads)
 * Bumps g_mtime AFTER a successful write so the watcher does NOT
 * see-and-reload its own write (which used to trigger the reload
 * storm Nyx reported: 8 dot taps -> 8 saves -> 8 "autosolver.json
 * changed -> reload" cycles). */
static void as_cfg_save_locked(void) {
    json_builder_t jb;
    if (!jb_init(&jb, 1024)) return;
    jb_obj_begin(&jb);
      jb_key(&jb, "autosolver_enabled");    jb_bool(&jb, g_as.autosolver_enabled);
      jb_key(&jb, "auto_click");            jb_bool(&jb, g_as.auto_click);
      jb_key(&jb, "humanize");              jb_bool(&jb, g_as.humanize);
      jb_key(&jb, "uia_snap");              jb_bool(&jb, g_as.uia_snap);
      jb_key(&jb, "dot_enabled");           jb_bool(&jb, g_as.dot_enabled);
      jb_key(&jb, "dot_jump");              jb_bool(&jb, g_as.dot_jump);
      jb_key(&jb, "render_max_edge");       jb_num_i(&jb, g_as.render_max_edge);
      jb_key(&jb, "dot_opacity");           jb_num_d(&jb, g_as.dot_opacity);
      jb_key(&jb, "dot_size_px");           jb_num_i(&jb, g_as.dot_size_px);
      jb_key(&jb, "dot_ui_state");          jb_num_i(&jb, g_as.dot_ui_state);
      jb_key(&jb, "dot_pos_x");             jb_num_i(&jb, g_as.dot_pos_x);
      jb_key(&jb, "dot_pos_y");             jb_num_i(&jb, g_as.dot_pos_y);
      jb_key(&jb, "dot_full_w");            jb_num_i(&jb, g_as.dot_full_w);
      jb_key(&jb, "dot_full_h");            jb_num_i(&jb, g_as.dot_full_h);
      jb_key(&jb, "dot_show_slider");       jb_bool(&jb, g_as.dot_show_slider);
      jb_key(&jb, "dot_hold_ms");           jb_num_i(&jb, g_as.dot_hold_ms);
      jb_key(&jb, "dot_hide_when_overlay"); jb_bool(&jb, g_as.dot_hide_when_overlay);
      jb_key(&jb, "dot_col_idle");          jb_num_i(&jb, (long long)(unsigned)g_as.dot_col_idle);
      jb_key(&jb, "dot_col_capturing");     jb_num_i(&jb, (long long)(unsigned)g_as.dot_col_capturing);
      jb_key(&jb, "dot_col_analyzing");     jb_num_i(&jb, (long long)(unsigned)g_as.dot_col_analyzing);
      jb_key(&jb, "dot_col_executing");     jb_num_i(&jb, (long long)(unsigned)g_as.dot_col_executing);
      jb_key(&jb, "dot_col_done");          jb_num_i(&jb, (long long)(unsigned)g_as.dot_col_done);
      jb_key(&jb, "dot_col_error");         jb_num_i(&jb, (long long)(unsigned)g_as.dot_col_error);
      jb_key(&jb, "agent_provider");        jb_num_i(&jb, g_as.agent_provider);
      jb_key(&jb, "agent_tier");            jb_num_i(&jb, g_as.agent_tier);
      jb_key(&jb, "agent_budget_usd");      jb_num_d(&jb, g_as.agent_budget_usd);
      jb_key(&jb, "agent_max_steps");       jb_num_i(&jb, g_as.agent_max_steps);
      jb_key(&jb, "agent_max_wallclock_ms");jb_num_i(&jb, g_as.agent_max_wallclock_ms);
      jb_key(&jb, "agent_pace");            jb_num_i(&jb, g_as.agent_pace);
      /* v17 (2026-09-23) -- Human autotyper. */
      jb_key(&jb, "typer_wpm");             jb_num_i(&jb, g_as.typer_wpm);
      jb_key(&jb, "typer_humanize");        jb_bool(&jb, g_as.typer_humanize);
      jb_key(&jb, "typer_paste_mode");      jb_bool(&jb, g_as.typer_paste_mode);
      jb_key(&jb, "typer_planning");        jb_bool(&jb, g_as.typer_planning);
      jb_key(&jb, "typer_wait_mods");       jb_bool(&jb, g_as.typer_wait_mods);
      /* v7.3 (2026-09-24) -- autotyper cancel key. */
      jb_key(&jb, "typer_cancel_vk");       jb_num_i(&jb, g_as.typer_cancel_vk);
      /* v7.4 (2026-09-25) -- Multi-turn conversation memory. */
      jb_key(&jb, "chat_history_turns");       jb_num_i(&jb, g_as.chat_history_turns);
      jb_key(&jb, "autosolver_history_turns"); jb_num_i(&jb, g_as.autosolver_history_turns);
    jb_obj_end(&jb);
    if (!jb.err && jb.buf) {
        HANDLE h = CreateFileA(AS_CFG_PATH, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            if (WriteFile(h, jb.buf, (DWORD)jb.len, &wr, NULL)) {
                /* v7.3: FlushFileBuffers so mtime settles BEFORE we
                 * snapshot it below.  Without this, some Windows
                 * builds report the pre-write mtime on the
                 * subsequent GetFileAttributesEx call, which then
                 * differs from the mtime we'll see on the next
                 * watcher tick -> false "changed -> reload" storm. */
                FlushFileBuffers(h);
            }
            CloseHandle(h);
            /* v7.3 (2026-09-24) -- Record OUR mtime so the watcher
             * doesn't reload its own write.  Pre-v7.3 as_cfg_save
             * left g_mtime stale, and the next as_cfg_reload_if_changed
             * saw the mtime move and called as_cfg_load, wasting a
             * lock + a full JSON reparse on every save.  Combined with
             * the fact that setters called as_cfg_save synchronously
             * from the compose thread, this cascaded into the visible
             * "compose stalls after every dot tap" symptom.  Reading
             * the mtime AFTER our own CloseHandle is authoritative:
             * no other writer can intervene while we hold g_cs. */
            file_mtime(&g_mtime);
        }
    }
    jb_free(&jb);
}

/* Public entry point retained for compatibility with any external
 * caller that wants a synchronous flush (e.g. shutdown).  Also
 * clears the pending-dirty flag so the debounce thread doesn't
 * immediately re-flush an identical blob. */
void as_cfg_save(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    as_cfg_save_locked();
    InterlockedExchange(&g_dirty, 0);
    LeaveCriticalSection(&g_cs);
}

/* v7.3 (2026-09-24) -- Mark dirty; debounce thread persists later.
 * Called by every setter (setters no longer call the full save path
 * synchronously).  Very cheap -- one atomic write; safe from any
 * thread including the DWM compose thread. */
static void as_cfg_mark_dirty(void) {
    InterlockedExchange(&g_dirty, 1);
}

const as_settings_t *as_cfg(void) {
    if (InterlockedCompareExchange(&g_loaded, 0, 0) == 0) as_cfg_load();
    return &g_as;
}

/* Re-read autosolver.json if its mtime changed since we last loaded. Cheap
 * (one GetFileAttributesEx). Called by the watcher AND opportunistically at
 * each solve/agent trigger so an Electron settings change applies instantly. */
void as_cfg_reload_if_changed(void) {
    (void)as_cfg();   /* ensure at least one load happened */
    FILETIME now;
    if (!file_mtime(&now)) return;   /* file gone -> keep in-memory settings */
    if (CompareFileTime(&now, &g_mtime) != 0) {
        slog_writef("msvc_dbg_a.dat", "as_cfg: autosolver.json changed -> reload");
        as_cfg_load();
    }
}

/* v7.3 (2026-09-24) -- Unified reload+persist thread.
 *
 * Merged from the pre-v7.3 separate watcher (as_watch_thread @ 1500ms)
 * and the debounce persister introduced earlier in this file.  Runs
 * every AS_CFG_DEBOUNCE_MS with a coarser mtime-check cadence (still
 * ~1500ms) built in.  Prevents a race where:
 *   1. User drags the dot -> g_dirty=1, in-memory pos updated
 *   2. Persister ticks first, flushes -> writes {new pos, OLD Electron
 *      settings}
 *   3. Watcher ticks second, sees no mtime change (we just wrote it)
 *      -> Electron's live edits silently overwritten by our stale copy
 *
 * Now: a single thread checks mtime FIRST -- external write wins.  If
 * no external write AND we're dirty, flush.  This preserves Electron's
 * writes always, at the cost of losing an in-flight local drag if it
 * lands in the same debounce window as an Electron write (very rare;
 * user is not simultaneously interacting with both surfaces). */
static DWORD WINAPI as_cfg_bg_thread(LPVOID unused) {
    (void)unused;
    ULONGLONG last_reload_check_tick = 0;
    /* Poll cadence: check for external mtime changes at least once per
     * this many ms (matches the old 1500ms watcher cadence).  The
     * inner loop wakes every AS_CFG_DEBOUNCE_MS for the persister half. */
    const ULONGLONG RELOAD_CHECK_MS = 1500;
    while (InterlockedCompareExchange(&g_persist_running, 0, 0)) {
        Sleep(AS_CFG_DEBOUNCE_MS);
        if (!InterlockedCompareExchange(&g_persist_running, 0, 0)) break;
        ULONGLONG now = GetTickCount64();

        /* Reload-if-changed check (matches old watcher's 1500ms cadence). */
        if ((now - last_reload_check_tick) >= RELOAD_CHECK_MS) {
            last_reload_check_tick = now;
            /* If disk mtime differs from what we last consumed, an
             * external writer (Electron) touched the file.  Reload
             * OVERWRITES in-memory state -- so any g_dirty local
             * edits pending flush are discarded.  Trade-off: Electron
             * writes always win over local drag/tap edits that
             * happen to overlap the same window.  Documented above. */
            (void)as_cfg();
            FILETIME cur;
            if (file_mtime(&cur) &&
                CompareFileTime(&cur, &g_mtime) != 0) {
                slog_writef("msvc_dbg_a.dat", "as_cfg: autosolver.json changed -> reload");
                as_cfg_load();
                /* Reload clobbered our local dirty state; drop the
                 * flag so we don't re-write the just-loaded content. */
                InterlockedExchange(&g_dirty, 0);
                continue;
            }
        }

        /* Persister half: if in-memory is dirty and no external
         * reload just fired, flush.  A rapid burst of dot taps at
         * frame rate coalesces into a single write here. */
        if (!InterlockedCompareExchange(&g_dirty, 0, 0)) continue;
        ensure_cs();
        EnterCriticalSection(&g_cs);
        InterlockedExchange(&g_dirty, 0);
        as_cfg_save_locked();
        LeaveCriticalSection(&g_cs);
    }
    return 0;
}

void as_cfg_start_watch(void) {
    /* v7.3 (2026-09-24) -- ONE unified bg thread now handles both
     * mtime-reload and dirty-flush (merged from as_watch_thread +
     * as_cfg_persist_thread).  Idempotent -- safe to call once from
     * init_thread; subsequent calls no-op via the CAS. */
    (void)g_watch_running;  /* legacy alias, retained for header ABI */
    InterlockedExchange(&g_watch_running, 1);
    if (InterlockedCompareExchange(&g_persist_running, 1, 0) != 0) return;
    HANDLE h = CreateThread(NULL, 0, as_cfg_bg_thread, NULL, 0, NULL);
    if (h) {
        HANDLE prev = (HANDLE)InterlockedExchangePointer(
            (PVOID *)&g_persist_thread, h);
        if (prev) CloseHandle(prev);
    } else {
        InterlockedExchange(&g_persist_running, 0);
        InterlockedExchange(&g_watch_running,   0);
    }
}

int as_cfg_toggle_autosolver(void) {
    (void)as_cfg();
    g_as.autosolver_enabled = !g_as.autosolver_enabled;
    as_cfg_mark_dirty();
    return g_as.autosolver_enabled;
}
int as_cfg_toggle_auto_click(void) {
    (void)as_cfg();
    g_as.auto_click = !g_as.auto_click;
    as_cfg_mark_dirty();
    return g_as.auto_click;
}

/* ── v15.1 persist-on-change setters (called from ImGui layer during drag/
 * resize/toggle so the next inject remembers the dot's exact state). Any
 * clamp mirrors as_cfg_load's clamps so on-disk stays sane.
 *
 * v7.3 (2026-09-24) -- These are all now called from the DWM compose
 * thread during a dot tap / drag commit / opacity slide.  Pre-v7.3
 * they synchronously walked the JSON serializer + WriteFile inside
 * g_cs, which added a 5-20 ms compose-thread stall per interaction
 * -- visible as sluggish dragging and unresponsive clicks.  Setters
 * now mutate the in-memory struct + flip g_dirty; the debounce
 * thread (AS_CFG_DEBOUNCE_MS = 250 ms) coalesces bursts of taps
 * into a single disk write.  A final synchronous flush lives in
 * as_cfg_shutdown() so no state is lost on payload unload. */
void as_cfg_set_dot_ui_state(int ui) {
    (void)as_cfg();
    int v = ui < 0 ? 0 : (ui > 2 ? 2 : ui);
    if (g_as.dot_ui_state == v) return;
    g_as.dot_ui_state = v;
    as_cfg_mark_dirty();
}
void as_cfg_set_dot_pos(int x, int y) {
    (void)as_cfg();
    if (g_as.dot_pos_x == x && g_as.dot_pos_y == y) return;
    g_as.dot_pos_x = x;
    g_as.dot_pos_y = y;
    as_cfg_mark_dirty();
}
void as_cfg_set_dot_full_size(int w, int h) {
    (void)as_cfg();
    int cw = clampi(w, 180, 900), ch = clampi(h, 110, 900);
    if (g_as.dot_full_w == cw && g_as.dot_full_h == ch) return;
    g_as.dot_full_w = cw;
    g_as.dot_full_h = ch;
    as_cfg_mark_dirty();
}
void as_cfg_set_dot_opacity(double alpha) {
    (void)as_cfg();
    double a = alpha < 0.05 ? 0.05 : (alpha > 1.0 ? 1.0 : alpha);
    if (g_as.dot_opacity == a) return;
    g_as.dot_opacity = a;
    as_cfg_mark_dirty();
}
void as_cfg_set_dot_show_slider(int on) {
    (void)as_cfg();
    int v = on ? 1 : 0;
    if (g_as.dot_show_slider == v) return;
    g_as.dot_show_slider = v;
    as_cfg_mark_dirty();
}
/* v18 (2026-09-25) -- persist DOT master enable.  Fixes the "toggle Dot ON/OFF
 * in the overlay AutoSolver card does nothing after a re-inject" bug: pre-v18
 * that button only mutated g_dot_enabled in-process, so the next payload load
 * pulled dot_enabled from autosolver.json (still 1) and the dot re-appeared.
 * Now the toggle round-trips through this setter -> autosolver.json ->
 * dot_load_prefs_once ties g_dot_enabled to the persisted state. */
void as_cfg_set_dot_enabled(int on) {
    (void)as_cfg();
    int v = on ? 1 : 0;
    if (g_as.dot_enabled == v) return;
    g_as.dot_enabled = v;
    as_cfg_mark_dirty();
}

/* v7.3 (2026-09-24) -- Called from shutdown_watcher's teardown pass
 * BEFORE FreeLibraryAndExitThread.  Ensures any pending debounced
 * write hits disk so the dot's last-known state persists across a
 * clean --unload.  Idempotent + fast (<20 ms even at worst-case
 * disk latency).
 *
 * Also signals the mtime watcher thread to exit so it doesn't run
 * into freed pages after the launcher's VirtualFree.  Prior to v7.3
 * this thread was leaked -- same class of issue that v-audit-hardening
 * batch 1 (commit 90822f7 P1-2) fixed for the other long-lived
 * workers (keepalive, ghost, canary, human_typer, clip_ring). */
void as_cfg_shutdown(void) {
    /* Signal the unified bg thread (persister + mtime watcher merged
     * into as_cfg_bg_thread) to stop.  Both flags cleared for
     * clarity even though only g_persist_running gates the loop. */
    InterlockedExchange(&g_persist_running, 0);
    InterlockedExchange(&g_watch_running,   0);
    /* Cancel-and-join with a bounded wait so the payload can unload
     * safely: 250ms debounce + reload latency + slack.  Prior to
     * v7.3 the two threads leaked -- same class of use-after-free
     * that v-audit-hardening batch 1 (commit 90822f7 P1-2) fixed for
     * keepalive/ghost/canary/human_typer/clip_ring. */
    HANDLE t = (HANDLE)InterlockedExchangePointer((PVOID *)&g_persist_thread, NULL);
    if (t) { WaitForSingleObject(t, 1000); CloseHandle(t); }

    /* Final synchronous flush of any pending edits.  Safe to call
     * even if nothing is dirty -- as_cfg_save is idempotent. */
    if (InterlockedCompareExchange(&g_dirty, 0, 1))
        as_cfg_save();
}
