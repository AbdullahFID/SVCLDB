#include "../../shared/common.h"
#include "blob_read.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <string.h>

#define BLOB_PATH SVC_INSTALL_DIR "\\" SVC_OFFSETS_BLOB

int pl_offsets_load(pl_offsets_t *out) {
    if (!out) return 0;
    HANDLE h = CreateFileA(BLOB_PATH, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        slog_writef("payload.log", "blob: none at %s (GLE=%lu)", BLOB_PATH, GetLastError());
        return 0;
    }
    DWORD sz = GetFileSize(h, NULL);
    if (sz != sizeof(pl_offsets_t)) {
        slog_writef("payload.log", "blob: bad size %lu (expected %zu)", sz, sizeof(pl_offsets_t));
        CloseHandle(h);
        return 0;
    }
    DWORD r = 0;
    BOOL ok = ReadFile(h, out, sz, &r, NULL);
    CloseHandle(h);
    if (!ok || r != sz) return 0;
    slog_writef("payload.log", "blob: present=0x%llx overlay-prev=0x%llx",
                (unsigned long long)out->cOverlayContextPresent,
                (unsigned long long)out->isOverlayPrevented);
    return 1;
}

HMODULE pl_locate_dwmcore(void) {
    HMODULE m = GetModuleHandleA("dwmcore.dll");
    if (!m) m = LoadLibraryA("dwmcore.dll");   /* dwm.exe always has it loaded */
    return m;
}
