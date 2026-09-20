/* ================================================================== *
 * imgui_layer.h -- C-callable interface over the ImGui + D3D11 layer.  *
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
 * MUST BE SEH-SAFE -- any fault takes down the entire desktop. */
void ui_present_frame(void *pCtx, void *pLayer);

/* Save the CURRENT layer texture directly to a BMP file -- no WIC, no COM,
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

/* Append a placeholder AI message showing "Thinking..." -- returns
 * the message id so ui_chat_stream_append / ui_chat_finalize_pending
 * can target it. Returns -1 on failure. */
int  ui_chat_append_pending(void);

/* Append a chunk of text to a specific pending message id (streaming). */
void ui_chat_stream_append(int msg_id, const char *chunk, size_t len);

/* Finalize a pending message -- clears the "thinking" flag. */
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

/* Legacy setter -- kept for compatibility. Appends as a new AI message. */
void ui_set_reply(const char *utf8);

/* Return the text of the last USER message (heap-alloc'd) -- used by
 * the REGENERATE hotkey. Returns NULL if none. Caller frees. */
char *ui_chat_last_user_text(void);

/* Clear ENTIRE chat history -- wipes all messages (Ctrl+Alt+N New Chat).
 * DESTRUCTIVE -- the messages are gone forever. */
void ui_chat_clear_history(void);

/* Force overlay to show the empty "home" cheat-sheet view even if the
 * chat history isn't empty. Non-destructive -- messages stay in memory
 * and are shown again as soon as a new message arrives (or user hits
 * REGENERATE etc). This is the Ctrl+Alt+X "back" behavior: hide the
 * conversation without deleting it. */
void ui_view_show_home(void);

/* Undo ui_view_show_home() -- allow the chat view to render if there
 * are messages. Called automatically when a new message is appended. */
void ui_view_show_chat(void);

/* TRUE if the chat view is currently VISIBLE (i.e. has messages AND
 * not home-forced). Used by the Ctrl+Alt+X handler to decide between
 * "back" (chat view visible -> hide) and "quit" (home view showing). */
int  ui_is_showing_chat(void);

/* Legacy alias: NON-DESTRUCTIVE -- same as ui_view_show_home().
 * (Kept for API stability with earlier callers; new code should call
 * ui_view_show_home() directly.) */
void ui_clear_reply(void);

/* Visibility. */
void ui_toggle_visible(void);
int  ui_is_visible(void);

/* v1.7.10 (2026-07-24) -- LEAN MODE toggle. When ON, draw_chat_window
 * skips the standard ImGui::Begin/End window and instead renders the
 * overlay via ImDrawList::AddRectFilled + AddText on
 * ImGui::GetForegroundDrawList() -- Bypassify's exact render pattern
 * (verified via RPM: BP's ImGui Windows vector = 1 unnamed entry).
 * Sacrifices chat scrollback, MD/LaTeX rendering, per-bubble buttons,
 * code-block copy, styled chrome. Kept: last AI reply text, background
 * rect, respect for pos/size/alpha/theme. Toggled via Ctrl+Shift+Alt+M
 * or via svchelper UI. */
void ui_toggle_lean(void);
int  ui_is_lean(void);

/* Reply pane scroll -- signed pixel delta consumed on next frame.
 * Positive = scroll DOWN (toward end), negative = scroll UP. */
void ui_scroll_reply(int delta_px);

/* Hit-test: TRUE (1) iff the overlay is currently visible AND the
 * (x, y) screen-coordinate point lies inside the overlay's last-drawn
 * rect. Used by the LL mouse hook to decide whether to consume a
 * mouse-wheel event and forward it to ui_scroll_reply. Cheap; safe
 * from any thread. Returns 0 before the overlay has ever drawn. */
int  ui_point_in_overlay(int x, int y);
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

/* ── Hotkey binding registry ──
 *
 * The UI layer needs to know the current hotkey mappings so it can
 * label buttons dynamically (e.g. "copy [Ctrl+Alt+C]"). dllmain.c
 * calls this once at startup with the packed hotkey table from
 * svc_config_t.hotkeys[]. If the user rebinds hotkeys later (config
 * reload), call again to update.
 *
 * `hks` is an array of packed (mod << 16) | vk values indexed by
 * svc_hotkey_action_t. `n` is the array length (usually SVC_HK_COUNT).
 * Layer copies the values internally; caller retains ownership. */
void ui_set_hotkey_bindings(const unsigned *hks, int n);

/* Format an action's currently-bound hotkey into `out` (e.g.
 * "Ctrl+Alt+C" or "Ctrl+Shift+Alt+C"). If action isn't bound OR out
 * of range, writes an empty string. Returns bytes written excluding
 * NUL. `action` corresponds to a svc_hotkey_action_t index. */
size_t ui_format_hotkey(int action, char *out, size_t out_sz);

/* Geometry adjustments -- called from hotkey callbacks in dllmain.c.
 * All are best-effort; if the requested value goes out of range, we
 * clamp to a sane bound. Persisted-back to disk on next frame (v2). */
void ui_nudge(int dx, int dy);       /* move by (dx, dy) pixels */
void ui_resize(int dw, int dh);      /* grow/shrink by (dw, dh) pixels */
void ui_cycle_corner(void);          /* TL -> TR -> BR -> BL -> TL */
void ui_bump_alpha(float delta);     /* + or - to bg alpha [0.20 .. 1.00] */
void ui_bump_font(float delta);      /* + or - to font scale factor */
void ui_reset_geometry(void);        /* back to defaults */

/* v1.6.2 (2026-07-15): plumb the vtable-slot target RVAs from
 * offsets.blob into the UI layer, so get_backbuffer_texture can
 * discover the correct vtable slot indices at first Present() call
 * (dynamic-preferred, hardcoded-fallback). Called once at init from
 * dllmain, AFTER pl_offsets_load succeeds. Any of the three RVAs
 * being 0 means "no PDB hint -- use hardcoded slot" for that entry.
 * Thread-safe (single-writer at init before any Present detour). */
typedef unsigned long long ui_rva_t;
void ui_set_vtable_slot_hints(ui_rva_t gpb_rva, ui_rva_t gd3d_rva, ui_rva_t acc_rva);

/* v1.6.3 (2026-07-15): populate an RVA-to-name lookup table so the
 * first-success diagnostic in get_backbuffer_texture can identify
 * which known dwmcore method each vtable slot actually invokes on
 * the user's Windows build. Each entry: (rva, name). Zero RVAs are
 * skipped. Called once at init from dllmain with all resolved
 * offsets from pl_offsets_t. Enables log lines like:
 *   "slot=5 rva=0x1DD690 (== getDevice)"
 * instead of just "slot=5 rva=0x1DD690" -- support can identify by
 * method name what each user's slot is actually calling. */
typedef struct {
    ui_rva_t     rva;
    const char  *name;
} ui_rva_symbol_t;
void ui_set_known_rva_table(const ui_rva_symbol_t *table, int count);

/* v8 (2026-07-06): apply the launch-time overlay config that Electron
 * built via cfg->overlay_w/h/alpha + cfg->size_mode. Called ONCE at
 * init from dllmain, AFTER config load + state_load_once. Sets the
 * initial base size + alpha default + clamp range for size_mode.
 *   base_w, base_h : starting box dimensions in DPI-independent pixels.
 *                    Pass 0 to keep hardcoded fallback (600x460).
 *   alpha          : bg alpha [0.20..1.00]; pass -1 to skip apply.
 *   size_mode      : 0 = normal clamps, 1 = ultra (tiny <-> huge).
 * Thread-safe (guarded by g_ui_cs). */
void ui_apply_launch_config(int base_w, int base_h,
                            float alpha, int size_mode);

/* v11 (2026-07-24) -- theme + overlay-flags apply, called from dllmain right
 * after ui_apply_launch_config with the values from cfg->theme + cfg->overlay_flags.
 *   theme         : 0=dark, 1=light, 2=auto (payload polls Windows Personalize
 *                   registry every ~2s and follows AppsUseLightTheme).
 *   overlay_flags : bitfield of SVC_OVFLAG_* -- controls trail-erase (paint
 *                   over prior positions with opaque bg color), smooth-nudge
 *                   (8px @ 60Hz vs 20px @ 20Hz), uniform-alpha, opaque-lock.
 * Thread-safe (guarded by g_ui_cs). */
void ui_apply_theme_and_flags(int theme, unsigned overlay_flags);

/* v11: read-only accessors -- used by rawinput_hook to pick nudge repeat
 * rate based on user's SMOOTH_NUDGE preference. Non-locking, returns
 * the current cached value (Interlocked read). */
unsigned ui_get_overlay_flags(void);
int      ui_get_theme_effective(void);

/* Request a DWM-side screen capture. Blocks up to `timeout_ms` for a fresh
 * frame to be grabbed from the compositor's layer backbuffer (the same
 * texture we render into). Returns 1 on success with *png_out / *len_out
 * allocated via malloc (caller frees via ui_capture_free). Returns 0 on
 * timeout or error. Runs from ai worker thread.
 *
 * Why this beats GDI capture inside DWM: GetDC(NULL) from DWM's context
 * returns DWM's own restricted DC, not the interactive user's screen DC.
 * We ALREADY have the fully-composited backbuffer in ui_present_frame --
 * just copy it to a staging texture and encode. Same technique the main
 * hooksdll capture path uses (dwm_payload.c line 1577+). */
int  ui_capture_screen_png(unsigned char **png_out, unsigned int *len_out,
                           unsigned int timeout_ms);
/* Same as ui_capture_screen_png but INCLUDES the overlay pixels
 * (does NOT hide the overlay for the layer settle). Only for debug
 * / iteration use -- the AI-request path uses the clean-layer
 * variant above. */
int  ui_capture_screen_png_with_overlay(unsigned char **png_out,
                                        unsigned int *len_out,
                                        unsigned int timeout_ms);
void ui_capture_free(unsigned char *png);

/* Shutdown. */
void ui_shutdown(void);

/* v3.2 (P0: overlay dies on explorer/shell restart). In-process render-layer
 * teardown for the soft-reinject worker: tears down the ImGui context + DX11/
 * Win32 backends + RTV cache + resets the layer target, WITHOUT deleting the UI
 * lock, so the next ui_present_frame rebuilds ImGui fresh on the current device
 * -- the render half of a --reinject, done without unloading the DLL. Must be
 * called with draws already stopped (g_stop_draw / hooks uninstalled) so the
 * compose thread is not inside ui_present_frame. */
void ui_reinit(void);

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
/* Cursor navigation -- Left/Right step one UTF-8 codepoint;
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
