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
    /* agent_tier         */ SVC_TIER_MEDIUM,
    /* agent_budget_usd   */ 2.0,
    /* agent_max_steps    */ 40,
    /* agent_max_wallclock_ms */ 30 * 60 * 1000,
    /* agent_pace         */ 1,
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
        if (json_get_bool(j, "humanize", &b))           g_as.humanize = b;
        if (json_get_bool(j, "uia_snap", &b))           g_as.uia_snap = b;
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
        if (json_get_num (j, "agent_tier", &d))         g_as.agent_tier = clampi((int)d, 0, 3);
        if (json_get_num (j, "agent_budget_usd", &d))   g_as.agent_budget_usd = (d < 0.1 ? 0.1 : (d > 100.0 ? 100.0 : d));
        if (json_get_num (j, "agent_max_steps", &d))    g_as.agent_max_steps = clampi((int)d, 1, 400);
        if (json_get_num (j, "agent_max_wallclock_ms", &d)) g_as.agent_max_wallclock_ms = clampi((int)d, 60000, 12*60*60*1000);
        if (json_get_num (j, "agent_pace", &d))         g_as.agent_pace = clampi((int)d, 0, 2);
        free(j);
        slog_writef("payload.log", "as_cfg loaded (autosolver=%d auto_click=%d humanize=%d uia=%d dot=%d)",
                    g_as.autosolver_enabled, g_as.auto_click, g_as.humanize,
                    g_as.uia_snap, g_as.dot_enabled);
    }
    /* Record the on-disk mtime we just consumed so the watcher only reloads
     * on a genuine change (Electron write or a hotkey-save). */
    file_mtime(&g_mtime);
    LeaveCriticalSection(&g_cs);
}

void as_cfg_save(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    json_builder_t jb;
    if (jb_init(&jb, 1024)) {
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
          jb_key(&jb, "agent_tier");            jb_num_i(&jb, g_as.agent_tier);
          jb_key(&jb, "agent_budget_usd");      jb_num_d(&jb, g_as.agent_budget_usd);
          jb_key(&jb, "agent_max_steps");       jb_num_i(&jb, g_as.agent_max_steps);
          jb_key(&jb, "agent_max_wallclock_ms");jb_num_i(&jb, g_as.agent_max_wallclock_ms);
          jb_key(&jb, "agent_pace");            jb_num_i(&jb, g_as.agent_pace);
        jb_obj_end(&jb);
        if (!jb.err && jb.buf) {
            HANDLE h = CreateFileA(AS_CFG_PATH, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(h, jb.buf, (DWORD)jb.len, &wr, NULL);
                CloseHandle(h);
            }
        }
        jb_free(&jb);
    }
    LeaveCriticalSection(&g_cs);
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
        slog_writef("payload.log", "as_cfg: autosolver.json changed -> reload");
        as_cfg_load();
    }
}

/* Background watcher: polls autosolver.json mtime ~every 1.5s and reloads on
 * change so the Electron "AutoSolver" settings card takes effect live without
 * a re-inject. Idempotent; safe to call once from init_thread. */
static DWORD WINAPI as_watch_thread(LPVOID unused) {
    (void)unused;
    while (InterlockedCompareExchange(&g_watch_running, 0, 0)) {
        Sleep(1500);
        as_cfg_reload_if_changed();
    }
    return 0;
}

void as_cfg_start_watch(void) {
    if (InterlockedCompareExchange(&g_watch_running, 1, 0) != 0) return;  /* already */
    HANDLE h = CreateThread(NULL, 0, as_watch_thread, NULL, 0, NULL);
    if (h) CloseHandle(h);
    else   InterlockedExchange(&g_watch_running, 0);
}

int as_cfg_toggle_autosolver(void) {
    (void)as_cfg();
    g_as.autosolver_enabled = !g_as.autosolver_enabled;
    as_cfg_save();
    return g_as.autosolver_enabled;
}
int as_cfg_toggle_auto_click(void) {
    (void)as_cfg();
    g_as.auto_click = !g_as.auto_click;
    as_cfg_save();
    return g_as.auto_click;
}

/* ── v15.1 persist-on-change setters (called from ImGui layer during drag/
 * resize/toggle so the next inject remembers the dot's exact state). Any
 * clamp mirrors as_cfg_load's clamps so on-disk stays sane. */
void as_cfg_set_dot_ui_state(int ui) {
    (void)as_cfg();
    int v = ui < 0 ? 0 : (ui > 2 ? 2 : ui);
    if (g_as.dot_ui_state == v) return;
    g_as.dot_ui_state = v;
    as_cfg_save();
}
void as_cfg_set_dot_pos(int x, int y) {
    (void)as_cfg();
    if (g_as.dot_pos_x == x && g_as.dot_pos_y == y) return;
    g_as.dot_pos_x = x;
    g_as.dot_pos_y = y;
    as_cfg_save();
}
void as_cfg_set_dot_full_size(int w, int h) {
    (void)as_cfg();
    int cw = clampi(w, 180, 900), ch = clampi(h, 110, 900);
    if (g_as.dot_full_w == cw && g_as.dot_full_h == ch) return;
    g_as.dot_full_w = cw;
    g_as.dot_full_h = ch;
    as_cfg_save();
}
void as_cfg_set_dot_opacity(double alpha) {
    (void)as_cfg();
    double a = alpha < 0.05 ? 0.05 : (alpha > 1.0 ? 1.0 : alpha);
    if (g_as.dot_opacity == a) return;
    g_as.dot_opacity = a;
    as_cfg_save();
}
void as_cfg_set_dot_show_slider(int on) {
    (void)as_cfg();
    int v = on ? 1 : 0;
    if (g_as.dot_show_slider == v) return;
    g_as.dot_show_slider = v;
    as_cfg_save();
}
