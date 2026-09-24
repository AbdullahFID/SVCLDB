/* ================================================================== *
 * clipboard_out.h -- Write UTF-8 text to the interactive user's        *
 * clipboard. Best-effort -- falls back to writing to a file the       *
 * launcher's tray helper can pop up.                                 *
 * ================================================================== */
#ifndef SVCLDB_CLIPBOARD_OUT_H
#define SVCLDB_CLIPBOARD_OUT_H

#include <stddef.h>   /* size_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Try to set the clipboard to `utf8` (NUL-terminated).
 * Retries OpenClipboard up to 5 times with backoff (clipboard can be
 * locked by other apps mid-copy). Returns 1 on success, 0 on failure
 * (logged with GLE). Uses CF_UNICODETEXT so non-ASCII text survives. */
int  clip_set_utf8(const char *utf8);

/* Same as clip_set_utf8 but takes an explicit byte length so callers
 * can copy a range slice without an intermediate NUL-terminated dup.
 * len is the number of UTF-8 bytes at `bytes` (NOT including any
 * trailing NUL -- this helper adds one internally). Returns 1/0.
 *
 * v9 (2026-07-06): all imgui_layer copy paths (Ctrl+Alt+C,
 * Ctrl+Shift+Alt+C, Ctrl+Alt+A, per-block copy buttons) route through
 * this so they inherit the retry loop AND CF_UNICODETEXT semantics
 * that clip_set_utf8 already had. Previously each writer did a single
 * OpenClipboard attempt with CF_TEXT -- first-attempt failures silently
 * ate the request, and non-ASCII (Greek/math/emoji) got mangled by
 * the ANSI codepage round-trip. */
int  clip_set_utf8_bytes(const char *bytes, size_t len);

/* v17 (2026-09-23) -- Read whatever text is on the interactive clipboard,
 * as a freshly-allocated NUL-terminated UTF-8 string. Caller owns the
 * pointer (must free()). Returns NULL when the clipboard is empty, has
 * no text formats, or the OpenClipboard retry loop fails after ~150ms
 * of contention. Prefers CF_UNICODETEXT; falls back to CF_TEXT (ANSI). */
char *clip_get_utf8(void);

/* Fallback: write reply to <install-dir>\last_reply.txt (readable for support). */
void clip_dump_to_file(const char *utf8);

#ifdef __cplusplus
}
#endif

#endif
