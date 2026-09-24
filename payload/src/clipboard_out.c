#include "../../shared/common.h"
#include "clipboard_out.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>   /* malloc/free */
#include <limits.h>   /* INT_MAX */

/* Internal worker used by both clip_set_utf8 and clip_set_utf8_bytes.
 * Takes a UTF-8 byte range (may or may not be NUL-terminated) and
 * publishes it to the interactive clipboard as CF_UNICODETEXT.
 *
 * Design notes:
 *   - CF_UNICODETEXT is what modern Windows apps (Chrome, Word, Notion,
 *     VSCode, Notepad, ...) actually paste from. CF_TEXT round-trips
 *     through the ANSI codepage and mangles anything outside the
 *     current codepage (Greek, math symbols, emoji, CJK). All our
 *     replies contain such characters after LaTeX-to-Unicode
 *     conversion, so CF_TEXT was silently corrupting them.
 *   - OpenClipboard(NULL) attaches to whichever thread owns the DWM
 *     message loop -- usually fast, but contends with any app that's
 *     also mid-write (esp. Explorer's copy status, Chrome's own
 *     clipboard hook, screen recorders). Retries with backoff cover
 *     ~150ms of contention windows before we give up.
 *   - MultiByteToWideChar with cbMultiByte = int(len) converts EXACTLY
 *     `len` bytes; no NUL required in `bytes`. We add the final NUL to
 *     the output buffer ourselves. */
static int clip_publish_utf16_from_bytes(const char *bytes, size_t len) {
    if (!bytes || len == 0) return 0;
    if (len > INT_MAX) len = INT_MAX;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, bytes, (int)len, NULL, 0);
    if (wlen <= 0) return 0;

    /* +1 for our terminating NUL. */
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)(wlen + 1) * sizeof(WCHAR));
    if (!h) return 0;
    LPWSTR p = (LPWSTR)GlobalLock(h);
    if (!p) { GlobalFree(h); return 0; }
    MultiByteToWideChar(CP_UTF8, 0, bytes, (int)len, p, wlen);
    p[wlen] = L'\0';
    GlobalUnlock(h);

    int opened = 0;
    DWORD open_gle = 0;
    for (int attempt = 0; attempt < 5; attempt++) {
        if (OpenClipboard(NULL)) { opened = 1; break; }
        open_gle = GetLastError();
        Sleep(30 * (attempt + 1));
    }
    if (!opened) {
        GlobalFree(h);
        slog_writef("payload.log",
                    "clip: OpenClipboard failed after 5 retries (gle=%lu)",
                    open_gle);
        return 0;
    }
    EmptyClipboard();
    HANDLE set = SetClipboardData(CF_UNICODETEXT, h);
    DWORD set_gle = set ? 0 : GetLastError();
    CloseClipboard();
    if (!set) {
        GlobalFree(h);
        slog_writef("payload.log",
                    "clip: SetClipboardData(CF_UNICODETEXT) failed (gle=%lu wchars=%d)",
                    set_gle, wlen);
        return 0;
    }
    /* SetClipboardData succeeded -> system owns h; don't GlobalFree. */
    slog_writef("payload.log", "clip: set %d wchars (utf8_bytes=%zu)", wlen, len);
    return 1;
}

int clip_set_utf8(const char *utf8) {
    if (!utf8) return 0;
    return clip_publish_utf16_from_bytes(utf8, strlen(utf8));
}

int clip_set_utf8_bytes(const char *bytes, size_t len) {
    return clip_publish_utf16_from_bytes(bytes, len);
}

/* v17 (2026-09-23) -- Read whatever CF_UNICODETEXT (or CF_TEXT fallback) is
 * currently on the interactive clipboard, decoded to a freshly-allocated
 * NUL-terminated UTF-8 buffer. Ownership passes to caller (free() when done).
 *
 * Used by:
 *   1. ui_chat_feed_clipboard_paste() -- Ctrl+V in the composer.
 *   2. hotkey_autotype_clipboard()    -- Ctrl+Alt+T grabs clipboard for the
 *                                        human autotyper.
 *
 * Robustness:
 *   - Same 5-attempt OpenClipboard retry loop as clip_set_utf8 -- the
 *     clipboard is a global shared resource; other apps' clipboard hooks
 *     (Chrome, screen recorders, password managers) can block briefly.
 *   - CF_UNICODETEXT is preferred (survives codepoint round-trips); we fall
 *     back to CF_TEXT via CP_ACP if only ANSI is available (very old apps).
 *   - Returns NULL on any failure (empty clipboard, no text formats, alloc
 *     fail). Callers must NULL-check before dereferencing.
 *   - Caps returned buffer at INT_MAX bytes because WideCharToMultiByte's
 *     size prototype is int. In practice clipboards over ~64 MB behave
 *     poorly in every app, so this ceiling is unreachable. */
char *clip_get_utf8(void) {
    int opened = 0;
    for (int attempt = 0; attempt < 5; attempt++) {
        if (OpenClipboard(NULL)) { opened = 1; break; }
        Sleep(30 * (attempt + 1));
    }
    if (!opened) {
        slog_writef("payload.log", "clip_get: OpenClipboard failed (gle=%lu)",
                    GetLastError());
        return NULL;
    }

    char *out = NULL;

    /* Preferred: CF_UNICODETEXT -> UTF-8. */
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h) {
        LPCWSTR wsrc = (LPCWSTR)GlobalLock(h);
        if (wsrc) {
            int wlen = (int)wcslen(wsrc);
            if (wlen > 0) {
                int u8len = WideCharToMultiByte(CP_UTF8, 0, wsrc, wlen,
                                                NULL, 0, NULL, NULL);
                if (u8len > 0 && u8len < INT_MAX - 1) {
                    out = (char *)malloc((size_t)u8len + 1);
                    if (out) {
                        WideCharToMultiByte(CP_UTF8, 0, wsrc, wlen,
                                            out, u8len, NULL, NULL);
                        out[u8len] = 0;
                    }
                }
            }
            GlobalUnlock(h);
        }
    } else {
        /* Fallback: CF_TEXT (ANSI) -> UTF-8. Rare on Win10+, but some legacy
         * apps still only publish ANSI. */
        HANDLE ha = GetClipboardData(CF_TEXT);
        if (ha) {
            LPCSTR asrc = (LPCSTR)GlobalLock(ha);
            if (asrc) {
                int alen = (int)strlen(asrc);
                if (alen > 0) {
                    int wlen = MultiByteToWideChar(CP_ACP, 0, asrc, alen, NULL, 0);
                    if (wlen > 0) {
                        WCHAR *wbuf = (WCHAR *)malloc((size_t)(wlen + 1) * sizeof(WCHAR));
                        if (wbuf) {
                            MultiByteToWideChar(CP_ACP, 0, asrc, alen, wbuf, wlen);
                            wbuf[wlen] = 0;
                            int u8len = WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen,
                                                            NULL, 0, NULL, NULL);
                            if (u8len > 0 && u8len < INT_MAX - 1) {
                                out = (char *)malloc((size_t)u8len + 1);
                                if (out) {
                                    WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen,
                                                        out, u8len, NULL, NULL);
                                    out[u8len] = 0;
                                }
                            }
                            free(wbuf);
                        }
                    }
                }
                GlobalUnlock(ha);
            }
        }
    }
    CloseClipboard();
    return out;
}

void clip_dump_to_file(const char *utf8) {
    /* v18 (2026-09-23) -- production builds MUST NOT write the AI reply
     * anywhere plaintext. Previous behavior wrote the full reply as UTF-8
     * to <install>\last_reply.txt with CREATE_ALWAYS, so at any moment the
     * file contained the most recent answer verbatim. A forensic sweep of
     * the machine (or any admin with `type "C:\ProgramData\WinAudioSvc\
     * last_reply.txt"`) would surface the last exam answer directly. That's
     * literal receipts of the cheating.
     *
     * The clipboard copy path (clip_set_utf8 in dllmain) still runs
     * independently, so the paste-into-app flow is unaffected. Support can
     * still recover replies from the AES-256-GCM-encrypted ai.log if
     * absolutely needed -- and only the CloakGPT team has that key.
     *
     * Dev builds keep the plaintext file for local iteration. */
#if SVCLDB_PRODUCTION_BUILD
    (void)utf8;
    /* Self-heal: if a stale plaintext last_reply.txt exists (e.g. user
     * upgraded from a dev build, or manually created it), nuke it every
     * time this path is entered. Cheap -- DeleteFileA on a non-existent
     * file just returns 0. Guarantees the file cannot survive across
     * even one AI reply on a production build. */
    {
        char stale[MAX_PATH];
        int n = _snprintf(stale, sizeof(stale) - 1, "%s\\last_reply.txt", SVC_INSTALL_DIR);
        if (n > 0 && n < (int)sizeof(stale)) {
            stale[n] = 0;
            DeleteFileA(stale);
        }
    }
    return;
#else
    if (!utf8) return;
    CreateDirectoryA(SVC_INSTALL_DIR, NULL);
    char path[MAX_PATH];
    _snprintf(path, sizeof(path) - 1, "%s\\last_reply.txt", SVC_INSTALL_DIR);
    path[sizeof(path) - 1] = 0;
    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, utf8, (DWORD)strlen(utf8), &w, NULL);
    CloseHandle(h);
#endif
}
