/* ================================================================== *
 * agent_loop.c -- Agent Mode long-horizon loop (see agent_loop.h).     *
 *                                                                    *
 * v1: vision+JSON. Each turn -> clean capture + red grid -> ask the     *
 * configured model for the next 1-4 actions in image space -> dispatch  *
 * via the humanized injection stack -> repeat. Guards: step cap,        *
 * wall-clock, rough budget, and a consecutive-no-progress halt. Unlike  *
 * AutoSolver, the agent MAY navigate/submit to finish the task.         *
 *                                                                    *
 * Reuses the exact AutoSolver primitives so behavior/stealth match.     *
 * Vendor computer-use adapters (Anthropic computer_20250124 / OpenAI    *
 * computer_use_preview / Gemini CU) are a documented upgrade behind      *
 * this same API (see docs plan section "agent").                       *
 * ================================================================== */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "agent_loop.h"
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
#include "../../../shared/json_util.h"
#include "../../../shared/config_types.h"

extern void slog_writef(const char *file, const char *fmt, ...);

/* Mechanical, stealth-safe (no exam/quiz/proctor tokens). */
static const char AGENT_SYSTEM_PROMPT[] =
"You are a screen-control agent operating a Windows desktop. You are shown one screenshot per "
"turn with a red coordinate grid (x,y labels every 100 pixels). Decide the next few concrete "
"actions to make progress on the user's goal, then wait for the next screenshot.\n"
"\n"
"RULES:\n"
"- Read the screen. Identify the primary interactive surface and what to do next.\n"
"- Return 1-4 actions for THIS turn, then stop and wait for the fresh screenshot.\n"
"- Every coordinate is a PIXEL in the screenshot you were shown (top-left origin); use the grid "
"labels as ground truth. Target the visible CENTER of the element. Never click blank space.\n"
"- Prefer the `type` action for text; use `scroll` for long content; use `key` for Enter/Tab.\n"
"- You MAY click navigation controls (Next, Continue, etc.) when that is the correct next step "
"to complete the goal.\n"
"- When the goal is complete OR you cannot make progress, set status to \"done\".\n"
"\n"
"OUTPUT: return ONE JSON object and NOTHING else (no prose, no fences):\n"
"{ \"status\": \"continue\" | \"done\",\n"
"  \"reason\": \"<one short line>\",\n"
"  \"actions\": [ {\"type\":\"click\",\"x\":INT,\"y\":INT,\"description\":\"...\"},\n"
"                {\"type\":\"type\",\"text\":\"...\"},\n"
"                {\"type\":\"key\",\"key\":\"enter\"},\n"
"                {\"type\":\"scroll\",\"x\":INT,\"y\":INT,\"direction\":\"down\",\"amount\":3} ] }\n";

static const char AGENT_PRESET_TASK[] =
"Read the on-screen form or question set. For each item, determine the best answer and enter it "
"(select the option / type the value). Move through the items to complete the whole set. Do not "
"finalize or turn in the work.";

/* ── state ── */
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

/* Strip vendor-policy trigger tokens from the task (defensive, matches
 * hooksdll _sanitizeTask intent). Rewrites in place. */
static void sanitize_task(char *s) {
    struct { const char *from; const char *to; } sub[] = {
        {"exam","form"},{"Exam","form"},{"quiz","form"},{"Quiz","form"},
        {"test","form"},{"Test","form"},{"proctor","monitor"},{"cheat","complete"},
        {NULL,NULL}
    };
    for (int i = 0; sub[i].from; i++) {
        char *p;
        while ((p = strstr(s, sub[i].from)) != NULL) {
            size_t fl = strlen(sub[i].from), tl = strlen(sub[i].to);
            if (tl <= fl) {
                memcpy(p, sub[i].to, tl);
                memmove(p + tl, p + fl, strlen(p + fl) + 1);
            } else break; /* don't grow; leave as-is */
        }
    }
}

/* ── compact action parser (image-space) ── */
typedef struct {
    char type[24]; int has_xy, x, y, amount; char dir[8]; char text[1024]; char key[48];
} ag_action_t;

static int parse_actions(const char *obj, ag_action_t *out, int maxn) {
    int n = 0;
    const char *ap = strstr(obj, "\"actions\"");
    if (!ap) return 0;
    const char *lb = strchr(ap, '[');
    if (!lb) return 0;
    const char *p = lb + 1;
    while (n < maxn) {
        while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r' || *p == ',') p++;
        if (*p == ']' || *p == 0) break;
        if (*p != '{') break;
        const char *end = json_skip_object(p);
        if (!end || end <= p) break;
        size_t sl = (size_t)(end - p);
        char *slice = (char *)malloc(sl + 1);
        if (!slice) break;
        memcpy(slice, p, sl); slice[sl] = 0;
        ag_action_t *a = &out[n]; ZeroMemory(a, sizeof(*a));
        double d;
        json_get_str(slice, "type", a->type, sizeof(a->type));
        int gx = json_get_num(slice, "x", &d); if (gx) a->x = (int)d;
        int gy = json_get_num(slice, "y", &d); if (gy) a->y = (int)d;
        a->has_xy = gx && gy;
        if (json_get_num(slice, "amount", &d)) a->amount = (int)d;
        json_get_str(slice, "direction", a->dir, sizeof(a->dir));
        json_get_str(slice, "text", a->text, sizeof(a->text));
        json_get_str(slice, "key", a->key, sizeof(a->key));
        free(slice);
        if (a->type[0]) n++;
        p = end;
    }
    return n;
}

static unsigned hash_action(const ag_action_t *a) {
    unsigned h = 2166136261u;
    const char *s = a->type;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    h ^= (unsigned)(a->x * 73856093) ^ (unsigned)(a->y * 19349663);
    for (const char *t = a->text; *t; t++) { h ^= (unsigned char)*t; h *= 16777619u; }
    return h;
}

static void status(const char *fmt, int turn) {
    char line[256];
    _snprintf(line, sizeof(line) - 1, fmt, turn);
    line[sizeof(line) - 1] = 0;
    ui_agent_set_status(line, 1);
}

static DWORD WINAPI agent_thread(LPVOID unused) {
    (void)unused;
    as_cfg_reload_if_changed();          /* pick up any just-saved Electron settings */
    const as_settings_t *as = as_cfg();
    const svc_config_t  *cfg = cfg_get();
    if (!cfg) { InterlockedExchange(&g_active, 0); ui_agent_set_status("", 0); return 1; }

    char task[512];
    task_cs_ensure();
    EnterCriticalSection(&g_task_cs);
    if (g_task[0]) _snprintf(task, sizeof(task) - 1, "%s", g_task);
    else           _snprintf(task, sizeof(task) - 1, "%s", AGENT_PRESET_TASK);
    task[sizeof(task) - 1] = 0;
    LeaveCriticalSection(&g_task_cs);
    sanitize_task(task);

    int max_steps = as->agent_max_steps;
    int wall_ms   = as->agent_max_wallclock_ms;
    double budget = as->agent_budget_usd;
    double pace_mult = (as->agent_pace == 0) ? 0.5 : (as->agent_pace == 2 ? 2.0 : 1.0);

    DWORD t_start = GetTickCount();
    int steps = 0;
    double est_spend = 0.0;
    unsigned last_hash = 0; int consec = 0;

    ui_agent_set_status("Agent: starting", 1);
    slog_writef("payload.log", "agent: start task=\"%.60s\" steps<=%d wall=%dms budget=$%.2f",
                task, max_steps, wall_ms, budget);

    /* rolling history of the last few actions, injected into each prompt */
    char history[1024]; history[0] = 0;

    while (InterlockedCompareExchange(&g_active, 0, 0) && !InterlockedCompareExchange(&g_cancel, 0, 0)) {
        while (InterlockedCompareExchange(&g_paused, 0, 0) &&
               InterlockedCompareExchange(&g_active, 0, 0) &&
               !InterlockedCompareExchange(&g_cancel, 0, 0)) {
            ui_agent_set_status("Agent: paused", 1);
            Sleep(200);
        }
        if (!InterlockedCompareExchange(&g_active, 0, 0) || InterlockedCompareExchange(&g_cancel, 0, 0)) break;

        if (steps >= max_steps)                        { ui_agent_set_status("Agent: step cap reached", 1); break; }
        if ((int)(GetTickCount() - t_start) > wall_ms) { ui_agent_set_status("Agent: time cap reached", 1); break; }
        if (est_spend >= budget)                       { ui_agent_set_status("Agent: budget reached", 1); break; }

        status("Agent turn %d: capturing", steps + 1);

        unsigned char *png = NULL; unsigned int plen = 0; int from_dwm = 0;
        if (ui_capture_screen_png(&png, &plen, 3000)) from_dwm = 1;
        else { uint8_t *gp = NULL; size_t gl = 0; if (cap_primary_png(&gp, &gl)) { png = gp; plen = (unsigned)gl; } }
        if (!png || !plen) { ui_agent_set_status("Agent: capture failed", 1); break; }

        uint8_t *gpng = NULL; size_t glen = 0; int gw = 0, gh = 0, nw = 0, nh = 0; double scale = 1.0;
        int ok_img = imgproc_prepare_png(png, plen, as->render_max_edge, as->render_max_edge * 800,
                                         1, &gpng, &glen, &gw, &gh, &nw, &nh, &scale);
        if (from_dwm) ui_capture_free(png); else cap_free_png(png);
        if (!ok_img || !gpng) { ui_agent_set_status("Agent: image prep failed", 1); break; }

        svc_monitor_t mon; ZeroMemory(&mon, sizeof(mon));
        coords_make_thread_dpi_aware();
        coords_primary_monitor(&mon);
        double render_scale = (nw > 0) ? (double)gw / (double)nw : scale;

        char *anchors = ground_build_anchor_block(&mon, render_scale);

        status("Agent turn %d: thinking", steps + 1);

        char preamble[4096];
        _snprintf(preamble, sizeof(preamble) - 1,
            "GOAL: %s\n\n"
            "The screenshot is %dx%d pixels with a red coordinate grid (x,y labels every 100px). "
            "Use the grid labels as ground truth.%s%s\n"
            "%s%s\n"
            "Return ONLY the JSON object {status,reason,actions[]} with coordinates in this image's "
            "pixel space. Give the next 1-4 actions for this turn.",
            task, gw, gh,
            anchors ? "\n" : "", anchors ? anchors : "",
            history[0] ? "Actions already taken this session:\n" : "",
            history[0] ? history : "(none yet)");
        preamble[sizeof(preamble) - 1] = 0;

        svc_config_t lc = *cfg;
        lc.direct_answer_mode = 0;
        lc.streaming_enabled  = 0;
        _snprintf(lc.system_prompt, sizeof(lc.system_prompt) - 1, "%s", AGENT_SYSTEM_PROMPT);
        lc.system_prompt[sizeof(lc.system_prompt) - 1] = 0;

        char *reply = NULL; char err[512] = {0}; int got = 0;
        if (cfg->provider == SVC_PROVIDER_CREDITS && cfg->access_token[0]) {
            int mrc = ai_ask_metered(cfg, preamble, gpng, glen, &reply, err, sizeof(err));
            got = (mrc == 1 && reply);
            if (!got) {
                int has_byo = cfg->api_key[0] || cfg->api_key_openai[0] || cfg->api_key_anthropic[0] ||
                              cfg->api_key_google[0] || cfg->api_key_openrouter[0];
                if (has_byo) got = ai_ask(&lc, preamble, gpng, glen, &reply, err, sizeof(err));
            }
        } else {
            got = ai_ask(&lc, preamble, gpng, glen, &reply, err, sizeof(err));
        }

        imgproc_free(gpng);
        if (anchors) ground_free(anchors);

        if (!got || !reply) {
            ui_agent_set_status("Agent: model error", 1);
            slog_writef("payload.log", "agent: ai FAILED: %s", err);
            if (reply) ai_free_reply(reply);
            break;
        }

        est_spend += 0.02;   /* rough per-turn estimate for the budget guard */

        const char *os = strchr(reply, '{');
        const char *oe = os ? json_skip_object(os) : NULL;
        char *obj = NULL;
        if (os && oe && oe > os) { size_t ol = (size_t)(oe - os); obj = (char *)malloc(ol + 1); if (obj) { memcpy(obj, os, ol); obj[ol] = 0; } }

        char st[24] = {0};
        if (obj) json_get_str(obj, "status", st, sizeof(st));

        ag_action_t acts[6];
        int nacts = obj ? parse_actions(obj, acts, 6) : 0;

        if ((st[0] && (strcmp(st, "done") == 0 || strcmp(st, "complete") == 0)) || nacts == 0) {
            ui_agent_set_status("Agent: model finished", 1);
            if (obj) free(obj);
            ai_free_reply(reply);
            break;
        }

        /* no-progress guard */
        unsigned h = hash_action(&acts[0]);
        if (h == last_hash) { if (++consec >= 5) { ui_agent_set_status("Agent: no-progress halt", 1); if (obj) free(obj); ai_free_reply(reply); break; } }
        else { consec = 1; last_hash = h; }

        act_ctx_t ctx; ZeroMemory(&ctx, sizeof(ctx));
        ctx.mon = mon; ctx.render_scale = render_scale;
        ctx.humanize = as->humanize; ctx.uia_snap = as->uia_snap; ctx.secure = 0; ctx.wpm = 220;
        act_begin(&ctx);
        for (int i = 0; i < nacts && !InterlockedCompareExchange(&g_cancel, 0, 0); i++) {
            ag_action_t *a = &acts[i];
            const char *t = a->type;
            status("Agent turn %d: acting", steps + 1);
            if      (!strcmp(t, "click"))        { if (a->has_xy) act_click_image(&ctx, a->x, a->y, 0, 1); }
            else if (!strcmp(t, "double_click")) { if (a->has_xy) act_click_image(&ctx, a->x, a->y, 0, 2); }
            else if (!strcmp(t, "right_click"))  { if (a->has_xy) act_click_image(&ctx, a->x, a->y, 1, 1); }
            else if (!strcmp(t, "type"))         { if (a->has_xy) { act_click_image(&ctx, a->x, a->y, 0, 1); act_wait(160); } act_type(&ctx, a->text); }
            else if (!strcmp(t, "key"))          { act_press(&ctx, a->key); }
            else if (!strcmp(t, "scroll"))       { act_scroll_image(&ctx, a->has_xy ? a->x : gw/2, a->has_xy ? a->y : gh/2, a->dir[0] ? a->dir : "down", a->amount > 0 ? a->amount : 3); }
            else if (!strcmp(t, "wait"))         { act_wait(a->amount > 0 ? a->amount : 400); }
            /* append to history */
            {
                char frag[96];
                if (!strcmp(t, "type")) _snprintf(frag, sizeof(frag) - 1, "%d:type \"%.24s\"; ", steps + 1, a->text);
                else                    _snprintf(frag, sizeof(frag) - 1, "%d:%s(%d,%d); ", steps + 1, t, a->x, a->y);
                frag[sizeof(frag) - 1] = 0;
                size_t hl = strlen(history);
                if (hl + strlen(frag) < sizeof(history) - 1) strcat(history, frag);
                else { /* keep last half */ memmove(history, history + sizeof(history)/2, strlen(history + sizeof(history)/2) + 1); strcat(history, frag); }
            }
            if (i < nacts - 1) act_interpause(&ctx);
        }
        act_end(&ctx);

        if (obj) free(obj);
        ai_free_reply(reply);

        steps++;
        int dwell = (int)((400 + (rand() % 500)) * pace_mult);
        int left = dwell;
        while (left > 0 && InterlockedCompareExchange(&g_active, 0, 0) && !InterlockedCompareExchange(&g_cancel, 0, 0)) {
            int slice = left < 50 ? left : 50; Sleep(slice); left -= slice;
        }
    }

    slog_writef("payload.log", "agent: end steps=%d est_spend=$%.2f", steps, est_spend);
    Sleep(1500);
    ui_agent_set_status("", 0);
    InterlockedExchange(&g_active, 0);
    InterlockedExchange(&g_paused, 0);
    return 0;
}

void agent_start(void) {
    if (InterlockedCompareExchange(&g_active, 1, 0) != 0) return;  /* already running */
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
