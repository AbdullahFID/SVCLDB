#include "../../shared/common.h"
#include "clipboard_out.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <string.h>
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

void clip_dump_to_file(const char *utf8) {
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
}
