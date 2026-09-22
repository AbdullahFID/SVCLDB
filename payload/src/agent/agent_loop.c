/* ================================================================== *
 * agent_loop.c -- Agent Mode long-horizon loop (v2, CU-adapter port).
 *
 * v15.1.13 (2026-09-22): full 1:1 port of hooksdll's agent_mode.js.
 * Now dispatches through the three vendor-native CU (computer-use) tool
 * adapters (Anthropic / OpenAI / Gemini) via cu_common.h. The previous
 * generic vision+JSON path is superseded.
 *
 * Flow per turn:
 *   1. Guards: budget / step / wall-clock
 *   2. Capture the active monitor via ui_capture_screen_png (fall back
 *      to cap_primary_png)
 *   3. imgproc_prepare_png -> downscale to render_max_edge + red grid
 *   4. ground_build_anchor_block for the UIA text (helper-routed on
 *      isolated desktop)
 *   5. Base64-encode the JPEG bytes for the vendor
 *   6. Route to cu_providers[agent_provider].turn(...) with retry+fallback
 *   7. Dispatch each canonical action via input/actions.c humanized stack
 *   8. Progress guard (5 consecutive identical actions -> halt)
 * ================================================================== */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "agent_loop.h"
#include "cu_common.h"
#include "../autosolver/as_cfg.h"
#include "../config_read.h"
#include "../capture.h"
#include "../ai/ai_provider.h"
#include "../ui/imgui_layer.h"
#include "../capture/imgproc.h"
#include "../capture/ground.h"
#include "../input/coords.h"
#include "../input/actions.h"
#include "../input/motion.h"
#include "../../../shared/base64.h"
#include "../../../shared/config_types.h"

extern void slog_writef(const char *file, const char *fmt, ...);

/* Fallback preset -- used when user launches Agent Mode with no task set. */
static const char AGENT_PRESET_TASK[] =
"Read the on-screen form or question set. For each item, determine the "
"best answer and enter it (select the option / type the value). Move "
"through the items to complete the whole set. Do not finalize or turn "
"in the work.";

/* ── State ── */
static volatile LONG g_active = 0;
static volatile LONG g_paused = 0;
static volatile LONG g_cancel = 0;
static HANDLE        g_thread = NULL;
static CRITICAL_SECTION g_task_cs;
static volatile LONG g_task_cs_init = 0;
static char g_task[512] = {0};

static void task_cs_ensure(void) {
    if (InterlockedCompareExchange(&g_task_cs_init, 1, 0) == 0)
        InitializeCriticalSection(&g_task_cs);
}

int agent_is_active(void) { return InterlockedCompareExchange(&g_active, 0, 0) != 0; }

void agent_set_task(const char *utf8) {
    task_cs_ensure();
    EnterCriticalSection(&g_task_cs);
    _snprintf(g_task, sizeof(g_task) - 1, "%s", utf8 ? utf8 : "");
    g_task[sizeof(g_task) - 1] = 0;
    LeaveCriticalSection(&g_task_cs);
}

/* Resolve model for a (provider, tier) pair. as_cfg->agent_tier uses the
 * svc_tier_t enum (0=STRONG, 1=MEDIUM, 2=CHEAP, 3=CUSTOM). */
static const char *resolve_model(int provider, int tier) {
    if (provider < 0 || provider > 2) provider = 0;
    const cu_provider_t *p = &cu_providers[provider];
    switch (tier) {
        case 0: return p->strong;
        case 2: return p->cheap;
        default: return p->medium;
    }
}

/* Map cu_provider_t index -> svc_provider_t for api_key lookup. */
static int agent_provider_to_svc(int agent_provider) {
    if (agent_provider == 0) return SVC_PROVIDER_ANTHROPIC;
    if (agent_provider == 1) return SVC_PROVIDER_OPENAI;
    if (agent_provider == 2) return SVC_PROVIDER_GOOGLE;
    return SVC_PROVIDER_ANTHROPIC;
}

/* No-progress guard: 5 consecutive identical action hashes = halt.
 * Matches hooksdll's _checkNoProgress rewrite (V6.2). */
static unsigned hash_action(const cu_action_t *a) {
    unsigned h = 2166136261u;
    for (const char *s = a->action; *s; s++) { h ^= (unsigned char)*s; h *= 16777619u; }
    h ^= (unsigned)(a->coord_x * 73856093) ^ (unsigned)(a->coord_y * 19349663);
    for (const char *t = a->text; *t && (t - a->text) < 30; t++) { h ^= (unsigned char)*t; h *= 16777619u; }
    return h;
}
static int check_no_progress(unsigned h, unsigned *last, int *consec) {
    if (h == *last) { (*consec)++; }
    else            { *consec = 1; *last = h; }
    return *consec >= 5;
}

/* Push a status line to the overlay (thread-safe). */
static void status(const char *fmt, int turn, const char *extra) {
    char line[256];
    if (extra && extra[0])
        _snprintf(line, sizeof(line) - 1, fmt, turn, extra);
    else
        _snprintf(line, sizeof(line) - 1, fmt, turn);
    line[sizeof(line) - 1] = 0;
    ui_agent_set_status(line, 1);
}

/* Dispatch one canonical action via the humanized input stack. `mon` +
 * `render_scale` are the capture context so image-space coords convert
 * to native screen px. */
static void dispatch_action(const cu_action_t *a, const svc_monitor_t *mon,
                            double render_scale, act_ctx_t *ctx) {
    if (!a || !a->action[0]) return;
    if (mot_cancelled()) return;
    if (!strcmp(a->action, "left_click")) {
        if (a->has_coord) act_click_image(ctx, a->coord_x, a->coord_y, 0, 1);
    } else if (!strcmp(a->action, "right_click")) {
        if (a->has_coord) act_click_image(ctx, a->coord_x, a->coord_y, 1, 1);
    } else if (!strcmp(a->action, "double_click")) {
        if (a->has_coord) act_click_image(ctx, a->coord_x, a->coord_y, 0, 2);
    } else if (!strcmp(a->action, "middle_click")) {
        if (a->has_coord) act_click_image(ctx, a->coord_x, a->coord_y, 2, 1);
    } else if (!strcmp(a->action, "mouse_move")) {
        if (a->has_coord) act_move_image(ctx, a->coord_x, a->coord_y);
    } else if (!strcmp(a->action, "type")) {
        act_type(ctx, a->text);
    } else if (!strcmp(a->action, "key")) {
        act_press(ctx, a->text);
    } else if (!strcmp(a->action, "scroll")) {
        int cx = a->has_coord ? a->coord_x : (int)(mon->width  * render_scale / 2);
        int cy = a->has_coord ? a->coord_y : (int)(mon->height * render_scale / 2);
        act_scroll_image(ctx, cx, cy,
                         a->scroll_dir[0] ? a->scroll_dir : "down",
                         a->scroll_amount > 0 ? a->scroll_amount : 3);
    } else if (!strcmp(a->action, "left_click_drag")) {
        if (a->has_start && a->has_coord)
            act_drag_image(ctx, a->start_x, a->start_y, a->coord_x, a->coord_y);
    } else if (!strcmp(a->action, "wait")) {
        act_wait(a->duration_ms > 0 ? a->duration_ms : 400);
    } else if (!strcmp(a->action, "screenshot")) {
        /* No-op -- loop takes a fresh screenshot next turn anyway. */
    }
    (void)render_scale;
}

/* Read the API key for the chosen provider from svc_config_t. Returns
 * NULL if missing (loop bails out with a friendly error). */
static const char *pick_agent_key(const svc_config_t *cfg, int agent_provider) {
    int sp = agent_provider_to_svc(agent_provider);
    const char *k = ai_pick_provider_key(cfg, sp);
    return (k && *k) ? k : NULL;
}

static DWORD WINAPI agent_thread(LPVOID unused) {
    (void)unused;
    as_cfg_reload_if_changed();
    const as_settings_t *as = as_cfg();
    const svc_config_t  *cfg = cfg_get();
    if (!cfg) {
        InterlockedExchange(&g_active, 0);
        ui_agent_set_status("Agent: no config", 0);
        return 1;
    }

    /* Snapshot task under CS + sanitize. */
    char task[512];
    task_cs_ensure();
    EnterCriticalSection(&g_task_cs);
    if (g_task[0]) _snprintf(task, sizeof(task) - 1, "%s", g_task);
    else           _snprintf(task, sizeof(task) - 1, "%s", AGENT_PRESET_TASK);
    task[sizeof(task) - 1] = 0;
    LeaveCriticalSection(&g_task_cs);
    cu_sanitize_task(task, sizeof(task));

    int provider    = as->agent_provider;
    int tier        = as->agent_tier;
    int max_steps   = as->agent_max_steps;
    int wall_ms     = as->agent_max_wallclock_ms;
    double budget   = as->agent_budget_usd;
    double pace_mult = (as->agent_pace == 0) ? 0.5 : (as->agent_pace == 2 ? 2.0 : 1.0);
    const char *primary_model = resolve_model(provider, tier);
    const cu_provider_t *pvd = &cu_providers[provider < 0 || provider > 2 ? 0 : provider];

    const char *api_key = pick_agent_key(cfg, provider);
    if (!api_key) {
        char msg[128];
        _snprintf(msg, sizeof(msg) - 1, "Agent: no API key for %s", pvd->label);
        ui_agent_set_status(msg, 0);
        slog_writef("payload.log", "agent: bail no-api-key provider=%s", pvd->label);
        InterlockedExchange(&g_active, 0);
        return 1;
    }

    cu_state_t *cst = cu_state_new();
    if (!cst) { ui_agent_set_status("Agent: OOM", 0); InterlockedExchange(&g_active, 0); return 1; }

    DWORD t_start = GetTickCount();
    int steps = 0;
    unsigned last_hash = 0; int consec = 0;

    slog_writef("payload.log",
                "agent: start provider=%s model=%s tier=%d task=\"%.60s\" "
                "steps<=%d wall=%dms budget=$%.2f",
                pvd->label, primary_model, tier, task,
                max_steps, wall_ms, budget);
    ui_agent_set_status("Agent: starting", 1);

    while (InterlockedCompareExchange(&g_active, 0, 0) &&
           !InterlockedCompareExchange(&g_cancel, 0, 0)) {
        while (InterlockedCompareExchange(&g_paused, 0, 0) &&
               InterlockedCompareExchange(&g_active, 0, 0) &&
               !InterlockedCompareExchange(&g_cancel, 0, 0)) {
            ui_agent_set_status("Agent: paused", 1);
            Sleep(200);
        }
        if (!InterlockedCompareExchange(&g_active, 0, 0) ||
            InterlockedCompareExchange(&g_cancel, 0, 0)) break;

        /* Guards */
        if (steps >= max_steps)                        { ui_agent_set_status("Agent: step cap reached", 1); break; }
        if ((int)(GetTickCount() - t_start) > wall_ms) { ui_agent_set_status("Agent: time cap reached", 1); break; }
        if (cst->total_spend_usd >= budget)            { ui_agent_set_status("Agent: budget reached", 1); break; }

        status("Agent turn %d: capturing", steps + 1, NULL);

        /* Capture */
        unsigned char *png = NULL; unsigned int plen = 0; int from_dwm = 0;
        if (ui_capture_screen_png(&png, &plen, 3000)) from_dwm = 1;
        else { uint8_t *gp = NULL; size_t gl = 0;
               if (cap_primary_png(&gp, &gl)) { png = gp; plen = (unsigned)gl; } }
        if (!png || !plen) { ui_agent_set_status("Agent: capture failed", 1); break; }

        /* Downscale + grid */
        uint8_t *gpng = NULL; size_t glen = 0;
        int gw = 0, gh = 0, nw = 0, nh = 0; double scale = 1.0;
        int ok_img = imgproc_prepare_png(png, plen,
                                         as->render_max_edge, as->render_max_edge * 800,
                                         1, &gpng, &glen, &gw, &gh, &nw, &nh, &scale);
        if (from_dwm) ui_capture_free(png); else cap_free_png(png);
        if (!ok_img || !gpng) { ui_agent_set_status("Agent: image prep failed", 1); break; }

        /* Monitor for coord dispatch. */
        svc_monitor_t mon; ZeroMemory(&mon, sizeof(mon));
        coords_make_thread_dpi_aware();
        coords_primary_monitor(&mon);
        double render_scale = (nw > 0) ? (double)gw / (double)nw : scale;

        /* UIA anchors */
        char *anchors = ground_build_anchor_block(&mon, render_scale);

        /* Base64-encode the JPEG for the vendor. */
        size_t b64cap = ((glen + 2) / 3) * 4 + 4;
        char *b64 = (char *)malloc(b64cap);
        if (!b64) { imgproc_free(gpng); if (anchors) ground_free(anchors); ui_agent_set_status("Agent: OOM", 1); break; }
        b64_encode_std(gpng, glen, b64);

        cu_cap_t cap = {
            .b64 = b64, .w = gw, .h = gh,
            .uia_anchor_block = anchors,
        };

        status("Agent turn %d: %s thinking", steps + 1, pvd->label);

        /* CU adapter call w/ 429 retry + fallback SKU. */
        cu_turn_result_t turn;
        memset(&turn, 0, sizeof(turn));
        int ok = pvd->turn(cst, primary_model, api_key, &cap, task, &turn);
        if (!ok && (strstr(turn.err, "HTTP 429") || strstr(turn.err, "HTTP 5"))) {
            slog_writef("payload.log", "agent: %s -- backing off + retry primary", turn.err);
            ui_agent_set_status("Agent: rate-limited, retrying", 1);
            cu_actions_free(&turn);
            Sleep(4000 + (rand() % 3000));
            memset(&turn, 0, sizeof(turn));
            ok = pvd->turn(cst, primary_model, api_key, &cap, task, &turn);
        }
        if (!ok && pvd->fallback && pvd->fallback[0]) {
            slog_writef("payload.log", "agent: primary err -- trying fallback %s", pvd->fallback);
            char sf[128];
            _snprintf(sf, sizeof(sf) - 1, "fallback %.80s", pvd->fallback);
            status("Agent turn %d: %s", steps + 1, sf);
            cu_actions_free(&turn);
            memset(&turn, 0, sizeof(turn));
            ok = pvd->turn(cst, pvd->fallback, api_key, &cap, task, &turn);
        }
        free(b64);
        imgproc_free(gpng);
        if (anchors) ground_free(anchors);

        if (!ok) {
            char msg[128];
            _snprintf(msg, sizeof(msg) - 1, "Agent: %.100s", turn.err);
            ui_agent_set_status(msg, 1);
            slog_writef("payload.log", "agent: FATAL turn err=%s", turn.err);
            cu_actions_free(&turn);
            break;
        }

        /* Terminate on end_turn with no actions. */
        if (turn.n_actions == 0 &&
            (!strcmp(turn.stop_reason, "end_turn") ||
             !strcmp(turn.stop_reason, "stop") ||
             !strcmp(turn.stop_reason, "end"))) {
            ui_agent_set_status("Agent: model finished", 1);
            steps++;
            cu_actions_free(&turn);
            break;
        }

        /* Dispatch each action. */
        act_ctx_t ctx; ZeroMemory(&ctx, sizeof(ctx));
        ctx.mon = mon; ctx.render_scale = render_scale;
        ctx.humanize = as->humanize; ctx.uia_snap = as->uia_snap;
        ctx.secure = 0; ctx.wpm = 220;
        act_begin(&ctx);
        for (int i = 0; i < turn.n_actions &&
                        !InterlockedCompareExchange(&g_cancel, 0, 0); i++) {
            cu_action_t *a = &turn.actions[i];
            unsigned h = hash_action(a);
            if (check_no_progress(h, &last_hash, &consec)) {
                ui_agent_set_status("Agent: no-progress halt", 1);
                slog_writef("payload.log", "agent: no-progress halt (5 identical actions)");
                InterlockedExchange(&g_cancel, 1);
                break;
            }
            char slbl[80];
            _snprintf(slbl, sizeof(slbl) - 1, "%s", a->action[0] ? a->action : "?");
            status("Agent turn %d: %s", steps + 1, slbl);
            dispatch_action(a, &mon, render_scale, &ctx);
            /* Inter-action dwell with pace multiplier. */
            int dwell = (int)((300 + (rand() % 400)) * pace_mult);
            int left = dwell;
            while (left > 0 && InterlockedCompareExchange(&g_active, 0, 0) &&
                   !InterlockedCompareExchange(&g_cancel, 0, 0)) {
                int slice = left < 50 ? left : 50; Sleep(slice); left -= slice;
            }
        }
        act_end(&ctx);

        cu_actions_free(&turn);
        steps++;

        /* Inter-turn dwell with pace multiplier. */
        int dwell = (int)((400 + (rand() % 500)) * pace_mult);
        int left = dwell;
        while (left > 0 && InterlockedCompareExchange(&g_active, 0, 0) &&
               !InterlockedCompareExchange(&g_cancel, 0, 0)) {
            int slice = left < 50 ? left : 50; Sleep(slice); left -= slice;
        }
    }

    slog_writef("payload.log", "agent: end steps=%d spend=$%.4f",
                steps, cst->total_spend_usd);
    Sleep(1200);
    ui_agent_set_status("", 0);
    cu_state_free(cst);
    InterlockedExchange(&g_active, 0);
    InterlockedExchange(&g_paused, 0);
    return 0;
}

void agent_start(void) {
    if (InterlockedCompareExchange(&g_active, 1, 0) != 0) return;
    InterlockedExchange(&g_cancel, 0);
    InterlockedExchange(&g_paused, 0);
    mot_set_cancel(0);
    g_thread = CreateThread(NULL, 0, agent_thread, NULL, 0, NULL);
    if (g_thread) { CloseHandle(g_thread); g_thread = NULL; }
    else { InterlockedExchange(&g_active, 0); ui_agent_set_status("", 0); }
}

void agent_stop(void) {
    if (!InterlockedCompareExchange(&g_active, 0, 0)) return;
    InterlockedExchange(&g_cancel, 1);
    InterlockedExchange(&g_active, 0);
    act_cancel();
    ui_agent_set_status("Agent: stopped", 0);
}

void agent_pause_toggle(void) {
    if (!InterlockedCompareExchange(&g_active, 0, 0)) return;
    LONG now = InterlockedCompareExchange(&g_paused, 0, 0);
    InterlockedExchange(&g_paused, now ? 0 : 1);
}
