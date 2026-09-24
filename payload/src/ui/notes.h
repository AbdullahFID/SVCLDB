/* ================================================================== *
 * notes.h -- User reference-notes storage.                             *
 *                                                                     *
 * v17 (2026-09-23). Small persistent text blob (16 KB cap) that the    *
 * user pastes/edits before an exam; contents are prepended to every    *
 * AI request as context ("=== Reference notes ===...=== End ===").    *
 * Storage: encrypted-at-rest file at SVC_INSTALL_DIR\notes.enc using   *
 * the shared log-secure key derivation (same AES-256-GCM primitive    *
 * that already encrypts payload.log).                                  *
 *                                                                     *
 * UI: multi-line notes-editor panel toggled by SVC_HK_NOTES_TOGGLE     *
 * (Ctrl+Shift+Alt+N). Uses the same composer widget as the chat input  *
 * so the editor is bigger, supports Shift+Enter newlines, Ctrl+V paste,*
 * word cursors etc. Save on Escape or dedicated button.                *
 * ================================================================== */
#ifndef SVCLDB_UI_NOTES_H
#define SVCLDB_UI_NOTES_H

#ifdef __cplusplus
extern "C" {
#endif

#define NOTES_MAX_BYTES  16384   /* 16 KB fits ~2500 English words. */

/* Load on payload init. Silently no-ops if file missing / decrypt
 * fails (notes stay empty). Safe to call multiple times; loads once. */
void notes_load(void);

/* Save whatever is currently in the in-memory buffer to disk (async
 * throttled via a dirty flag + 500 ms coalesce). Actual disk write
 * happens on next notes_flush() or on payload shutdown. */
void notes_mark_dirty(void);
void notes_flush(void);

/* Take a snapshot of current notes into caller's buffer. Returns
 * the number of bytes written (excluding NUL). Zero-length = no notes.
 * Safe from any thread. */
int  notes_snapshot(char *out, int cap);

/* Editor state -- toggled by the hotkey. When open, LL keyboard hook
 * routes input into the notes buffer instead of the chat buffer. */
int  notes_editor_is_open(void);
void notes_editor_toggle(void);
void notes_editor_close_save(void);   /* Escape / outside-click */
void notes_editor_close_no_save(void); /* Ctrl+Alt+X or explicit discard */

/* Editor keystroke sinks -- MIRROR of ui_chat_feed_* semantics.
 * Called from rawinput_hook.c ll_kbd_proc / dispatch_external_key
 * while notes_editor_is_open() is true. */
void notes_feed_char(unsigned int cp);
void notes_feed_backspace(void);
void notes_feed_delete(void);
void notes_feed_newline(void);
void notes_feed_clipboard_paste(void);
void notes_feed_word_backspace(void);
void notes_feed_word_delete(void);
void notes_cursor_left(void);
void notes_cursor_right(void);
void notes_cursor_up(void);
void notes_cursor_down(void);
void notes_cursor_home(void);
void notes_cursor_end(void);
void notes_cursor_word_left(void);
void notes_cursor_word_right(void);

/* Snapshot for renderer. Fills `out` (NUL-terminated), returns byte
 * length. Also returns cursor byte-offset via *cursor_out. */
int  notes_render_snapshot(char *out, int cap, int *cursor_out);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_UI_NOTES_H */
