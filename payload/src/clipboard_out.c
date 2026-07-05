#include "../../shared/common.h"
#include "clipboard_out.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <string.h>

int clip_set_utf8(const char *utf8) {
    if (!utf8) return 0;

    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (wlen <= 0) return 0;

    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)wlen * sizeof(WCHAR));
    if (!h) return 0;
    void *p = GlobalLock(h);
    if (!p) { GlobalFree(h); return 0; }
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, (LPWSTR)p, wlen);
    GlobalUnlock(h);

    /* OpenClipboard(NULL) attaches to whichever thread owns the DWM message
     * loop. Retries with backoff — clipboard is contended by any app that
     * happens to be reading/writing at the same instant. */
    int opened = 0;
    for (int attempt = 0; attempt < 5; attempt++) {
        if (OpenClipboard(NULL)) { opened = 1; break; }
        Sleep(30 * (attempt + 1));
    }
    if (!opened) {
        GlobalFree(h);
        slog_writef("payload.log", "clip: OpenClipboard failed (%lu)", GetLastError());
        return 0;
    }
    EmptyClipboard();
    HANDLE set = SetClipboardData(CF_UNICODETEXT, h);
    CloseClipboard();
    if (!set) {
        GlobalFree(h);
        slog_writef("payload.log", "clip: SetClipboardData failed (%lu)", GetLastError());
        return 0;
    }
    /* When SetClipboardData succeeds, ownership transfers to system;
     * don't GlobalFree(h). */
    slog_writef("payload.log", "clip: set %d wchars", wlen - 1);
    return 1;
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
