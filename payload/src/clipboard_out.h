/* ================================================================== *
 * clipboard_out.h — Write UTF-8 text to the interactive user's        *
 * clipboard. Best-effort — falls back to writing to a file the       *
 * launcher's tray helper can pop up.                                 *
 * ================================================================== */
#ifndef SVCLDB_CLIPBOARD_OUT_H
#define SVCLDB_CLIPBOARD_OUT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Try to set the clipboard to `utf8`. Retries up to 5 times with backoff
 * (clipboard can be locked by other apps). Returns 1 on success. */
int  clip_set_utf8(const char *utf8);

/* Fallback: write reply to <install-dir>\last_reply.txt (readable for support). */
void clip_dump_to_file(const char *utf8);

#ifdef __cplusplus
}
#endif

#endif
