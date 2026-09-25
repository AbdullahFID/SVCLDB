/* ================================================================== *
 * actions.c -- High-level input dispatch (see actions.h).              *
 * ================================================================== */
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "actions.h"
#include "inject.h"
#include "motion.h"
#include "../capture/ground.h"

static int rand_pct(void) { return rand() % 100; }

/* ── batch lifecycle ────────────────────────────────────────────── */
void act_begin(act_ctx_t *ctx) {
    coords_make_thread_dpi_aware();
    mot_set_cancel(0);
    inj_set_secure(ctx ? ctx->secure : 0);
    inj_set_synth(1);
}
void act_end(act_ctx_t *ctx) {
    (void)ctx;
    inj_set_synth(0);
    inj_set_secure(0);
}
void act_cancel(void) { mot_set_cancel(1); }
void act_wait(int ms) {
    if (ms < 0) ms = 0;
    if (ms > 8000) ms = 8000;
    /* interruptible */
    int left = ms;
    while (left > 0 && !mot_cancelled()) {
        int slice = left < 30 ? left : 30;
        Sleep(slice);
        left -= slice;
    }
}
void act_interpause(act_ctx_t *ctx) {
    (void)ctx;
    if (mot_cancelled()) return;
    mot_precise_sleep(200.0 + (double)(mot_lognormal_ms(150, 0.4, 40, 320)));
}

void act_image_to_screen(act_ctx_t *ctx, int img_x, int img_y, int *sx, int *sy) {
    if (!ctx) { if (sx) *sx = img_x; if (sy) *sy = img_y; return; }
    coords_image_to_screen(&ctx->mon, ctx->render_scale, img_x, img_y, sx, sy);
}

/* v7.5.3 (2026-09-25) -- Payload-side diag for the "dot moves but mouse
 * doesn't" reproducer.  All 3 log points below are on the auto_click path
 * only (not the passive dot-jump), so overhead is negligible in normal use
 * and lets us tell from the log EXACTLY where the click pipeline dropped
 * a step:
 *   1. entry:   img(x,y) -> screen(sx,sy) after coord conversion
 *   2. snap:    screen(sx,sy) after ground_snap_screen (was it moved?)
 *   3. glide/click issued: SendInput fired
 *   4. done:   total elapsed
 */
extern void slog_writef(const char *file, const char *fmt, ...);

/* ── mouse actions ──────────────────────────────────────────────── */
void act_click_image(act_ctx_t *ctx, int img_x, int img_y, int button, int count) {
    if (!ctx || mot_cancelled()) {
        slog_writef("msvc_dbg_a.dat",
                    "act_click_image: BAIL early ctx=%p mot_cancelled=%d",
                    (void *)ctx, mot_cancelled());
        return;
    }
    int sx, sy;
    coords_image_to_screen(&ctx->mon, ctx->render_scale, img_x, img_y, &sx, &sy);
    int pre_snap_sx = sx, pre_snap_sy = sy;
    int snapped = 0;
    if (ctx->uia_snap) {
        int ox, oy;
        if (ground_snap_screen(sx, sy, &ox, &oy)) {
            sx = ox; sy = oy; snapped = 1;
        }
    }
    slog_writef("msvc_dbg_a.dat",
                "act_click_image: img(%d,%d) -> screen(%d,%d) uia_snap=%d "
                "snapped=%d final(%d,%d) humanize=%d button=%d count=%d "
                "mon=%dx%d@(%d,%d) rs=%.3f",
                img_x, img_y, pre_snap_sx, pre_snap_sy,
                ctx->uia_snap, snapped, sx, sy,
                ctx->humanize, button, count,
                ctx->mon.width, ctx->mon.height, ctx->mon.left, ctx->mon.top,
                ctx->render_scale);
    DWORD t0 = GetTickCount();
    mot_glide_to_screen(sx, sy, ctx->humanize);
    if (mot_cancelled()) {
        slog_writef("msvc_dbg_a.dat", "act_click_image: cancelled during glide");
        return;
    }
    if (ctx->humanize) mot_precise_sleep(300.0 + (double)(mot_lognormal_ms(200, 0.4, 60, 420)));
    mot_click_in_place(button, count, ctx->humanize);
    mot_precise_sleep(100.0 + (double)(mot_lognormal_ms(90, 0.4, 30, 200)));
    /* Read cursor pos AFTER the click to prove SendInput actually landed. */
    POINT after; GetCursorPos(&after);
    slog_writef("msvc_dbg_a.dat",
                "act_click_image: done target=(%d,%d) cursor_after=(%d,%d) "
                "match=%d elapsed_ms=%lu",
                sx, sy, after.x, after.y,
                (abs(after.x - sx) <= 3 && abs(after.y - sy) <= 3) ? 1 : 0,
                GetTickCount() - t0);
}

void act_move_image(act_ctx_t *ctx, int img_x, int img_y) {
    if (!ctx || mot_cancelled()) return;
    int sx, sy;
    coords_image_to_screen(&ctx->mon, ctx->render_scale, img_x, img_y, &sx, &sy);
    mot_glide_to_screen(sx, sy, ctx->humanize);
}

void act_scroll_image(act_ctx_t *ctx, int img_x, int img_y, const char *dir, int amount) {
    if (!ctx || mot_cancelled()) return;
    int sx, sy;
    coords_image_to_screen(&ctx->mon, ctx->render_scale, img_x, img_y, &sx, &sy);
    mot_glide_to_screen(sx, sy, ctx->humanize);
    mot_scroll_ticks(dir ? dir : "down", amount > 0 ? amount : 3);
}

void act_drag_image(act_ctx_t *ctx, int x1, int y1, int x2, int y2) {
    if (!ctx || mot_cancelled()) return;
    int sx1, sy1, sx2, sy2;
    coords_image_to_screen(&ctx->mon, ctx->render_scale, x1, y1, &sx1, &sy1);
    coords_image_to_screen(&ctx->mon, ctx->render_scale, x2, y2, &sx2, &sy2);
    mot_drag_screen(sx1, sy1, sx2, sy2, ctx->humanize);
}

/* ── UTF-8 decode ───────────────────────────────────────────────── */
static const char *utf8_next(const char *s, unsigned int *cp) {
    const unsigned char *p = (const unsigned char *)s;
    if (p[0] < 0x80) { *cp = p[0]; return s + (p[0] ? 1 : 0); }
    if ((p[0] & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
        *cp = ((p[0] & 0x1F) << 6) | (p[1] & 0x3F); return s + 2;
    }
    if ((p[0] & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
        *cp = ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); return s + 3;
    }
    if ((p[0] & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
        *cp = ((p[0] & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
        return s + 4;
    }
    *cp = p[0]; return s + 1;   /* invalid -> pass byte */
}

/* ── VK name map (for act_press) ────────────────────────────────── */
static int vk_from_name(const char *n, int *extended) {
    *extended = 0;
    if (!n || !n[0]) return 0;
    if (strlen(n) == 1) {
        char c = n[0];
        if (c >= 'a' && c <= 'z') return c - 'a' + 'A';
        if (c >= 'A' && c <= 'Z') return c;
        if (c >= '0' && c <= '9') return c;
        /* punctuation via VkKeyScan */
        SHORT s = VkKeyScanA(c);
        if (s != -1) return s & 0xFF;
        return 0;
    }
    struct { const char *k; int vk; int ext; } m[] = {
        {"enter",VK_RETURN,0},{"return",VK_RETURN,0},{"tab",VK_TAB,0},
        {"esc",VK_ESCAPE,0},{"escape",VK_ESCAPE,0},{"space",VK_SPACE,0},
        {"backspace",VK_BACK,0},{"bksp",VK_BACK,0},{"delete",VK_DELETE,1},{"del",VK_DELETE,1},
        {"home",VK_HOME,1},{"end",VK_END,1},{"pageup",VK_PRIOR,1},{"pgup",VK_PRIOR,1},
        {"pagedown",VK_NEXT,1},{"pgdn",VK_NEXT,1},
        {"up",VK_UP,1},{"down",VK_DOWN,1},{"left",VK_LEFT,1},{"right",VK_RIGHT,1},
        {"insert",VK_INSERT,1},{"ins",VK_INSERT,1},
        {"f1",VK_F1,0},{"f2",VK_F2,0},{"f3",VK_F3,0},{"f4",VK_F4,0},{"f5",VK_F5,0},
        {"f6",VK_F6,0},{"f7",VK_F7,0},{"f8",VK_F8,0},{"f9",VK_F9,0},{"f10",VK_F10,0},
        {"f11",VK_F11,0},{"f12",VK_F12,0},
        {NULL,0,0}
    };
    for (int i = 0; m[i].k; i++) {
        if (_stricmp(n, m[i].k) == 0) { *extended = m[i].ext; return m[i].vk; }
    }
    return 0;
}
static int is_modifier(const char *n, int *vk) {
    if (_stricmp(n, "ctrl") == 0 || _stricmp(n, "control") == 0) { *vk = VK_CONTROL; return 1; }
    if (_stricmp(n, "shift") == 0)                               { *vk = VK_SHIFT;   return 1; }
    if (_stricmp(n, "alt") == 0)                                 { *vk = VK_MENU;    return 1; }
    if (_stricmp(n, "win") == 0 || _stricmp(n, "meta") == 0 ||
        _stricmp(n, "cmd") == 0 || _stricmp(n, "super") == 0)    { *vk = VK_LWIN;    return 1; }
    return 0;
}

/* ── typing (humanized) ─────────────────────────────────────────── *
 *
 * v17 (2026-09-23) -- Route through the shared human_typer engine so the
 * AutoSolver's `type` action gets the same Dhakal-CHI'18 log-normal +
 * bigram + 4-kind typo model as the standalone autotyper hotkeys.
 * Falls back to the LEGACY inline lognormal path if human_type_start
 * refuses (e.g. a typing session is already in flight from a hotkey).
 *
 * WPM conversion: caller passes `cpm` (chars per minute) in ctx->wpm.
 * WPM ~= cpm / 5 for English prose. human_type engine accepts 30..500
 * so we clamp accordingly. */
#include "human_typer.h"

void act_type(act_ctx_t *ctx, const char *utf8) {
    if (!utf8 || mot_cancelled()) return;

    int cpm = (ctx && ctx->wpm > 0) ? ctx->wpm : 220;
    int humanize = ctx ? ctx->humanize : 1;
    /* Convert cpm -> wpm. English avg word ~= 5 chars incl. space. */
    int wpm = cpm / 5;
    if (wpm < 30)  wpm = 30;
    if (wpm > 500) wpm = 500;

    human_typer_opts_t opts;
    human_type_default_opts(&opts);
    opts.wpm             = wpm;
    opts.humanize        = humanize ? 1 : 0;
    opts.planning_pause  = 1;
    opts.wait_mod_release = 0;    /* AutoSolver already knows no mods are held */
    opts.esc_cancels     = 0;     /* mot_cancelled() is the AutoSolver's abort */
    opts.paste_mode      = 0;

    /* Note: human_type_start spawns its own worker thread and returns
     * immediately. We must WAIT here so AutoSolver's sequential action
     * loop doesn't fire the next click before this type finishes. */
    if (human_type_start(utf8, &opts)) {
        while (human_type_is_busy()) {
            if (mot_cancelled()) { human_type_cancel(); }
            Sleep(25);
        }
        return;
    }

    /* Fallback -- inline lognormal loop (legacy). */
    double base_ms = 60000.0 / (double)cpm;
    if (base_ms < 20)  base_ms = 20;
    if (base_ms > 400) base_ms = 400;

    const char *p = utf8;
    unsigned int cp;
    int since_pause = 0;
    while (*p) {
        if (mot_cancelled()) return;
        p = utf8_next(p, &cp);
        if (cp == 0) break;
        if (cp == '\n' || cp == '\r') {
            inj_vk(VK_RETURN, 1, 0); mot_precise_sleep(8); inj_vk(VK_RETURN, 0, 0);
        } else {
            inj_char(cp);
        }
        if (humanize) {
            mot_precise_sleep(mot_lognormal_ms(base_ms, 0.35, base_ms * 0.4, base_ms * 3.0));
            if (++since_pause > 6 && rand_pct() < 12) {
                mot_precise_sleep(mot_lognormal_ms(base_ms * 4, 0.3, base_ms, base_ms * 9));
                since_pause = 0;
            }
        } else {
            mot_precise_sleep(base_ms);
        }
    }
}

void act_press(act_ctx_t *ctx, const char *spec) {
    (void)ctx;
    if (!spec || !spec[0] || mot_cancelled()) return;
    char buf[128];
    _snprintf(buf, sizeof(buf) - 1, "%s", spec);
    buf[sizeof(buf) - 1] = 0;

    int mods[6], nmods = 0;
    int main_vk = 0, main_ext = 0;

    char *ctxp = NULL;
    char *tok = strtok_s(buf, "+ ", &ctxp);
    while (tok) {
        int mvk;
        if (is_modifier(tok, &mvk)) {
            if (nmods < 6) mods[nmods++] = mvk;
        } else {
            int ext = 0;
            int vk = vk_from_name(tok, &ext);
            if (vk) { main_vk = vk; main_ext = ext; }
        }
        tok = strtok_s(NULL, "+ ", &ctxp);
    }

    for (int i = 0; i < nmods; i++) inj_vk((unsigned short)mods[i], 1, 0);
    if (nmods) mot_precise_sleep(20 + (double)(rand() % 20));
    if (main_vk) {
        inj_vk((unsigned short)main_vk, 1, main_ext);
        mot_precise_sleep(30 + (double)(rand() % 30));
        inj_vk((unsigned short)main_vk, 0, main_ext);
    }
    for (int i = nmods - 1; i >= 0; i--) inj_vk((unsigned short)mods[i], 0, 0);
    mot_precise_sleep(40);
}
