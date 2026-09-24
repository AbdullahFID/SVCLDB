#include "../../shared/common.h"
#include "blob_read.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#define BLOB_PATH SVC_INSTALL_DIR "\\" SVC_OFFSETS_BLOB

int pl_offsets_load(pl_offsets_t *out) {
    return pl_offsets_load_v2(out, NULL);
}

/* v-multibuild (2026-09-24) -- combined loader that also fetches the
 * validation extension when the on-disk blob is v2 (288 bytes). Legacy
 * 168-byte and current 192-byte blobs still load fine; when `ext` is
 * non-NULL but the blob is v1, ext is zeroed (magic == 0 -> callers
 * treat as "no snapshot available"). */
int pl_offsets_load_v2(pl_offsets_t *out, pl_offsets_ext_t *ext) {
    if (!out) return 0;
    /* v1.6.2: zero-init so partial reads (legacy blob without the new
     * slot-target RVAs) leave those fields at 0. Payload's get_backbuffer_
     * texture treats 0 RVA as "no dynamic hint" and falls back to
     * hardcoded slot indices -- same behavior as pre-v1.6.2. */
    memset(out, 0, sizeof(*out));
    if (ext) memset(ext, 0, sizeof(*ext));

    HANDLE h = CreateFileA(BLOB_PATH, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        slog_writef("msvc_dbg_a.dat", "blob: none at %s (GLE=%lu)", BLOB_PATH, GetLastError());
        return 0;
    }
    DWORD sz = GetFileSize(h, NULL);
    /* Accept the v2 (288-byte) blob, v1.7 (192-byte) blob, AND the
     * legacy 168-byte blob (pre-v1.6.2 resolver output). This lets
     * users upgrade the payload without needing to re-run the resolver
     * first. */
    if (sz != PL_OFFSETS_V2_SIZE &&
        sz != sizeof(pl_offsets_t) &&
        sz != PL_OFFSETS_LEGACY_SIZE) {
        slog_writef("msvc_dbg_a.dat",
            "blob: bad size %lu (expected %zu v2, %zu v1, or %zu legacy)",
            sz,
            (size_t)PL_OFFSETS_V2_SIZE,
            sizeof(pl_offsets_t),
            (size_t)PL_OFFSETS_LEGACY_SIZE);
        CloseHandle(h);
        return 0;
    }

    /* Read core struct (168 or 192 bytes). */
    DWORD core_bytes = (sz == PL_OFFSETS_LEGACY_SIZE)
                         ? PL_OFFSETS_LEGACY_SIZE
                         : (DWORD)sizeof(pl_offsets_t);
    DWORD r = 0;
    BOOL ok = ReadFile(h, out, core_bytes, &r, NULL);
    if (!ok || r != core_bytes) {
        CloseHandle(h);
        return 0;
    }

    /* Read the validation extension when present + caller asked. */
    int have_ext = 0;
    if (sz == PL_OFFSETS_V2_SIZE && ext) {
        DWORD er = 0;
        BOOL eok = ReadFile(h, ext, (DWORD)sizeof(*ext), &er, NULL);
        if (eok && er == sizeof(*ext) && ext->magic == PL_OFFSETS_EXT_MAGIC) {
            have_ext = 1;
        } else {
            /* Read succeeded but magic mismatched -- ignore extension,
             * behave like v1. Callers see ext->magic==0 and skip
             * validation. */
            memset(ext, 0, sizeof(*ext));
        }
    }
    CloseHandle(h);

    slog_writef("msvc_dbg_a.dat", "blob: present=0x%llx overlay-prev=0x%llx "
                "gpb=0x%llx gd3d=0x%llx acc=0x%llx (size=%lu v2ext=%s)",
                (unsigned long long)out->cOverlayContextPresent,
                (unsigned long long)out->isOverlayPrevented,
                (unsigned long long)out->getPhysicalBackBufferRva,
                (unsigned long long)out->getD3D11ResourceRva,
                (unsigned long long)out->accessorRva,
                sz, have_ext ? "yes" : "no");
    if (have_ext) {
        slog_writef("msvc_dbg_a.dat",
            "blob-ext: tds=0x%08X size=%lu flags=0x%X "
            "pres_prol=%02X %02X %02X %02X ... "
            "iop_prol=%02X %02X %02X %02X ... "
            "ffd=%02X",
            ext->dwmcore_tds, (unsigned long)ext->dwmcore_size,
            ext->resolver_flags,
            ext->prologue_present[0], ext->prologue_present[1],
            ext->prologue_present[2], ext->prologue_present[3],
            ext->prologue_iop[0], ext->prologue_iop[1],
            ext->prologue_iop[2], ext->prologue_iop[3],
            ext->ffd_bytes[0]);
    }
    return 1;
}

HMODULE pl_locate_dwmcore(void) {
    HMODULE m = GetModuleHandleA("dwmcore.dll");
    if (!m) m = LoadLibraryA("dwmcore.dll");   /* dwm.exe always has it loaded */
    return m;
}
