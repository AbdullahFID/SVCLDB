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

/* ── Chat message model (v3, 2026-07-05) ──
 *
 * Overlay renders a chat as a scrolling list of bubbles:
 *   - USER messages: right-aligned, blue accent, ~70% width
 *   - AI   messages: left-aligned, dark bg + border, ~85% width, md_render-formatted
 *   - PENDING flag on an AI message shows the animated "Thinking..." indicator
 *     until the message is finalized (streaming complete / non-stream reply).
 *
 * All API is thread-safe (guarded by g_chat_cs). */
typedef enum { UI_MSG_USER = 0, UI_MSG_AI = 1 } ui_msg_role_t;

/* Append a new message with the given role + text. `text` is copied. */
void ui_chat_append_message(int role, const char *text);

/* Append a placeholder AI message showing "Thinking..." — returns
 * the message id so ui_chat_stream_append / ui_chat_finalize_pending
 * can target it. Returns -1 on failure. */
int  ui_chat_append_pending(void);

/* Append a chunk of text to a specific pending message id (streaming). */
void ui_chat_stream_append(int msg_id, const char *chunk, size_t len);

/* Finalize a pending message — clears the "thinking" flag. */
void ui_chat_finalize_pending(int msg_id);

/* If the last AI message is still pending, replace its full content
 * with `text` and mark it final. Used for non-streaming replies. */
void ui_chat_set_reply_of_pending(int msg_id, const char *text);

/* Total messages in the ring. */
int  ui_chat_message_count(void);

/* Copy the LAST assistant reply to the clipboard (Ctrl+Alt+C).
 * NO-OP if no assistant reply exists. */
void ui_copy_reply_to_clipboard(void);

/* Copy JUST the concatenated fenced-code blocks from the last AI
 * reply (Ctrl+Shift+Alt+C). Blocks joined with "\n\n" between them.
 * NO-OP if no code blocks in the reply. */
void ui_copy_last_ai_code(void);

/* Copy JUST the first non-empty line of the last AI reply
 * (Ctrl+Alt+A). The "direct answer" per our system prompt's
 * "answer first" contract. NO-OP if reply empty. */
void ui_copy_last_ai_answer(void);

/* Legacy setter — kept for compatibility. Appends as a new AI message. */
void ui_set_reply(const char *utf8);

/* Return the text of the last USER message (heap-alloc'd) — used by
 * the REGENERATE hotkey. Returns NULL if none. Caller frees. */
char *ui_chat_last_user_text(void);

/* Clear ENTIRE chat history (Ctrl+Alt+N New Chat). */
void ui_chat_clear_history(void);

/* Legacy alias: clears everything (same as ui_chat_clear_history). */
void ui_clear_reply(void);

/* Visibility. */
void ui_toggle_visible(void);
int  ui_is_visible(void);

/* Reply pane scroll — signed pixel delta consumed on next frame.
 * Positive = scroll DOWN (toward end), negative = scroll UP. */
void ui_scroll_reply(int delta_px);
/* TRUE (1) if there's at least one message (i.e. NOT the empty home
 * page). Used by the CLEAR hotkey handler to switch to "quit" behavior
 * on home page. */
int  ui_has_reply(void);

/* ── Status-bar text (top-right badge) ──
 * Small provider+tier+model indicator so user knows which config
 * they're on right now. Update whenever cfg changes (cycle tier/prov).
 * text is copied; safe to call from any thread. */
void ui_set_status(const char *provider, const char *tier,
                   const char *model, int streaming);

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
