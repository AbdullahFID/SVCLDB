/* ================================================================== *
 * imgui_layer.h — C-callable interface over the ImGui + D3D11 layer.  *
 *                                                                    *
 * The .cpp compiles ImGui internals (C++). This header exposes the   *
 * C entry points the payload's C code (dllmain.c, dwm_hooks.c) uses. *
 * ================================================================== */
#ifndef SVCLDB_IMGUI_LAYER_H
#define SVCLDB_IMGUI_LAYER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Lazy-init on first fire. Called from Detour_COverlayContextPresent.
 * `pCtx` is COverlayContext this-ptr; `pLayer` is the layer being presented.
 * MUST BE SEH-SAFE — any fault takes down the entire desktop. */
void ui_present_frame(void *pCtx, void *pLayer);

/* Save the CURRENT layer texture directly to a BMP file — no WIC, no COM,
 * no memory allocation beyond a staging texture. Uses raw WriteFile
 * calls to write the BMP header + BGRA pixel data.
 *
 * This is hooksdll's proven-working approach that succeeds from DWM's
 * process context where WIC PNG encoding fails silently. Blocks up to
 * `timeout_ms` waiting for the next Present call to occur. Returns 1
 * on success, 0 on failure (see log for reason).
 *
 * `path_bmp` should be an absolute file path ending in .bmp
 * (e.g. "C:\\Users\\Public\\Desktop\\capture.bmp"). */
int ui_capture_screen_bmp_to_file(const char *path_bmp, unsigned int timeout_ms);

/* Reply text (from AI worker thread). Thread-safe. */
void ui_set_reply(const char *utf8);

/* Visibility. */
void ui_toggle_visible(void);
int  ui_is_visible(void);

/* Reply text ops. */
void ui_clear_reply(void);
void ui_copy_reply_to_clipboard(void);
/* Reply pane scroll — signed pixel delta consumed on next frame.
 * Positive = scroll DOWN (toward end), negative = scroll UP. */
void ui_scroll_reply(int delta_px);
/* TRUE (1) if reply text is empty (home page state). Used by the
 * CLEAR hotkey handler to switch to "quit" behavior on home page. */
int  ui_has_reply(void);

/* Geometry adjustments — called from hotkey callbacks in dllmain.c.
 * All are best-effort; if the requested value goes out of range, we
 * clamp to a sane bound. Persisted-back to disk on next frame (v2). */
void ui_nudge(int dx, int dy);       /* move by (dx, dy) pixels */
void ui_resize(int dw, int dh);      /* grow/shrink by (dw, dh) pixels */
void ui_cycle_corner(void);          /* TL → TR → BR → BL → TL */
void ui_bump_alpha(float delta);     /* + or - to bg alpha [0.20 .. 1.00] */
void ui_bump_font(float delta);      /* + or - to font scale factor */
void ui_reset_geometry(void);        /* back to defaults */

/* Request a DWM-side screen capture. Blocks up to `timeout_ms` for a fresh
 * frame to be grabbed from the compositor's layer backbuffer (the same
 * texture we render into). Returns 1 on success with *png_out / *len_out
 * allocated via malloc (caller frees via ui_capture_free). Returns 0 on
 * timeout or error. Runs from ai worker thread.
 *
 * Why this beats GDI capture inside DWM: GetDC(NULL) from DWM's context
 * returns DWM's own restricted DC, not the interactive user's screen DC.
 * We ALREADY have the fully-composited backbuffer in ui_present_frame —
 * just copy it to a staging texture and encode. Same technique the main
 * hooksdll capture path uses (dwm_payload.c line 1577+). */
int  ui_capture_screen_png(unsigned char **png_out, unsigned int *len_out,
                           unsigned int timeout_ms);
void ui_capture_free(unsigned char *png);

/* Shutdown. */
void ui_shutdown(void);

/* ── Chat input mode ────────────────────────────────────────────── *
 * When active, the overlay shows an input field at the bottom of the
 * chat window. The rawinput low-level keyboard hook feeds characters
 * into the buffer instead of running its normal hotkey matcher, so
 * the user can type freely without other apps seeing the keystrokes.
 * ENTER submits the buffered text to AI (bundled with a fresh
 * screenshot for context). ESCAPE cancels + clears. */
void ui_chat_toggle(void);
int  ui_chat_is_active(void);
void ui_chat_feed_char(unsigned int utf32_codepoint);
void ui_chat_feed_backspace(void);
void ui_chat_feed_delete(void);
/* Cursor navigation — Left/Right step one UTF-8 codepoint;
 * Home/End jump to boundaries. */
void ui_chat_cursor_left(void);
void ui_chat_cursor_right(void);
void ui_chat_cursor_home(void);
void ui_chat_cursor_end(void);
void ui_chat_cancel(void);
/* Return current buffer + clear it + deactivate. Caller frees via free().
 * NULL if buffer empty. */
char *ui_chat_take_and_clear(void);

#ifdef __cplusplus
}
#endif

#endif
