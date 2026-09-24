#include "../../shared/common.h"
#include "blob_read.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#define BLOB_PATH SVC_INSTALL_DIR "\\" SVC_OFFSETS_BLOB

int pl_offsets_load(pl_offsets_t *out) {
    if (!out) return 0;
    /* v1.6.2: zero-init so partial reads (legacy blob without the new
     * slot-target RVAs) leave those fields at 0. Payload's get_backbuffer_
     * texture treats 0 RVA as "no dynamic hint" and falls back to
     * hardcoded slot indices -- same behavior as pre-v1.6.2. */
    memset(out, 0, sizeof(*out));

    HANDLE h = CreateFileA(BLOB_PATH, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        slog_writef("msvc_dbg_a.dat", "blob: none at %s (GLE=%lu)", BLOB_PATH, GetLastError());
        return 0;
    }
    DWORD sz = GetFileSize(h, NULL);
    /* Accept BOTH the new full-size blob AND the legacy 168-byte blob
     * (pre-v1.6.2 resolver output). This lets users upgrade the payload
     * without needing to re-run the resolver first. */
    if (sz != sizeof(pl_offsets_t) && sz != PL_OFFSETS_LEGACY_SIZE) {
        slog_writef("msvc_dbg_a.dat", "blob: bad size %lu (expected %zu or %zu legacy)",
                    sz, sizeof(pl_offsets_t), (size_t)PL_OFFSETS_LEGACY_SIZE);
        CloseHandle(h);
        return 0;
    }
    DWORD to_read = sz;   /* read whatever's on disk into the front of the struct */
    DWORD r = 0;
    BOOL ok = ReadFile(h, out, to_read, &r, NULL);
    CloseHandle(h);
    if (!ok || r != to_read) return 0;
    slog_writef("msvc_dbg_a.dat", "blob: present=0x%llx overlay-prev=0x%llx "
                "gpb=0x%llx gd3d=0x%llx acc=0x%llx (size=%lu)",
                (unsigned long long)out->cOverlayContextPresent,
                (unsigned long long)out->isOverlayPrevented,
                (unsigned long long)out->getPhysicalBackBufferRva,
                (unsigned long long)out->getD3D11ResourceRva,
                (unsigned long long)out->accessorRva,
                sz);
    return 1;
}

HMODULE pl_locate_dwmcore(void) {
    HMODULE m = GetModuleHandleA("dwmcore.dll");
    if (!m) m = LoadLibraryA("dwmcore.dll");   /* dwm.exe always has it loaded */
    return m;
}
