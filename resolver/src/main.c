/* ================================================================== *
 * resolver -- DWM symbol resolver for the payload.                     *
 *                                                                    *
 * DIRECTLY MODELED on hooksdll/dwm/dwm_resolver.c -- same 17-slot     *
 * blob format so we can reuse the production vtable-walk code from   *
 * the main app's dwm_payload.c verbatim, without offset drift.       *
 * ================================================================== */

#include "../../shared/common.h"
#include "../../shared/log_secure.h"
#include "../../shared/str_enc.h"

#include <stdio.h>
#include <stdarg.h>

#pragma comment(lib, "user32.lib")

/* ── Offsets blob layout -- must match payload's pl_offsets_t exactly */
typedef struct {
    uint64_t renderContent;
    uint64_t isNormal;
    uint64_t isNormalDesktopRender;
    uint64_t wdaDispatch;
    uint64_t wdaValidator;
    uint64_t finalCapture;
    uint64_t scheduleComposition;
    uint64_t cvisualRenderContent;
    uint64_t cOverlayContextPresent;
    uint64_t presentNeeded;
    uint64_t forceFullDirty;
    uint64_t legacyPresentNeeded;
    uint64_t isOverlayPrevented;
    uint64_t getDevice;
    uint64_t overlayConstructor;
    uint64_t isPrimaryMonitor;
    uint64_t getHwnd;
    /* --- svcldb-specific extras for fullscreen-dirty trick --- */
    uint64_t addDirtyRectDisplay;
    uint64_t addDirtyRectLegacy;
    uint64_t presentDisplay;
    uint64_t presentLegacy;
    /* --- v1.6.2 -- vtable-slot target RVAs (payload matches these
     * against the live vtable at first Present() to discover the
     * correct slot indices dynamically, replacing hardcoded 5/24/19). */
    uint64_t getPhysicalBackBufferRva;
    uint64_t getD3D11ResourceRva;
    uint64_t accessorRva;
} OffsetsBlob;

#define BLOB_PATH      SVC_INSTALL_DIR "\\" SVC_OFFSETS_BLOB
#define SYM_CACHE      SVC_INSTALL_DIR "\\symbols"
#define SYM_SERVER     "srv*" SVC_INSTALL_DIR "\\symbols*https://msdl.microsoft.com/download/symbols"
#define DWMCORE_PATH   "C:\\Windows\\System32\\dwmcore.dll"
#define FAKE_BASE      ((uint64_t)0x10000000)

/* v-multibuild (2026-09-24) -- validation extension appended to the
 * legacy 192-byte OffsetsBlob. Payload's pl_offsets_ext_t must match
 * exactly (see payload/src/blob_read.h). Keep both structs in sync
 * or v2 blobs fail the magic check + payload falls back to v1 mode. */
#define BLOB_EXT_MAGIC 0x32435653u   /* 'SVC2' little-endian */
typedef struct {
    uint32_t magic;
    uint32_t dwmcore_tds;
    uint32_t dwmcore_size;
    uint32_t resolver_flags;
    uint8_t  prologue_present[32];
    uint8_t  prologue_iop[32];
    uint8_t  ffd_bytes[16];
    uint8_t  reserved[16];
} OffsetsBlobExt;

typedef struct {
    ULONG    SizeOfStruct;
    ULONG    TypeIndex;
    ULONG64  Reserved[2];
    ULONG    Index;
    ULONG    Size;
    ULONG64  ModBase;
    ULONG    Flags;
    ULONG64  Value;
    ULONG64  Address;
    ULONG    Register;
    ULONG    Scope;
    ULONG    Tag;
    ULONG    NameLen;
    ULONG    MaxNameLen;
    CHAR     Name[2048];
} SYMINFO;

typedef BOOL    (WINAPI *pfnSymInitialize  )(HANDLE, PCSTR, BOOL);
typedef ULONG64 (WINAPI *pfnSymLoadModuleEx)(HANDLE, HANDLE, PCSTR, PCSTR, ULONG64, DWORD, PVOID, DWORD);
typedef BOOL    (WINAPI *pfnSymFromName    )(HANDLE, PCSTR, SYMINFO*);
typedef BOOL    (WINAPI *pfnSymCleanup     )(HANDLE);
typedef DWORD   (WINAPI *pfnSymSetOptions  )(DWORD);
typedef BOOL    (CALLBACK *pfnEnumSymCb    )(SYMINFO*, ULONG, PVOID);
typedef BOOL    (WINAPI *pfnSymEnumSymbols )(HANDLE, ULONG64, PCSTR, pfnEnumSymCb, PVOID);

static pfnSymInitialize   pSymInitialize   = NULL;
static pfnSymLoadModuleEx pSymLoadModuleEx = NULL;
static pfnSymFromName     pSymFromName     = NULL;
static pfnSymCleanup      pSymCleanup      = NULL;
static pfnSymSetOptions   pSymSetOptions   = NULL;
static pfnSymEnumSymbols  pSymEnumSymbols  = NULL;

static HANDLE g_hDbg = NULL;
static HANDLE g_hProc = NULL;

static void log_line(const char *fmt, ...) {
    char buf[1024];
    va_list va; va_start(va, fmt);
    _vsnprintf(buf, sizeof(buf) - 1, fmt, va);
    va_end(va);
    buf[sizeof(buf) - 1] = 0;
    /* Every line goes ONLY to the AES-256-GCM-encrypted resolver.log. The
     * previous unconditional stdout mirror leaked the full symbol RVA table
     * ("COverlayContext::Present -> RVA 0x...", "IsOverlayPrevented -> ...")
     * in plaintext to any terminal that spawned dllhost32.exe directly --
     * trivial treasure map for anyone RE'ing the resolver. Gated to
     * non-production builds so devs can still iterate with tail-on-console. */
    slog_resolver(buf);
#if !SVCLDB_PRODUCTION_BUILD
    printf("%s\n", buf); fflush(stdout);
#endif
}

/* Wildcard resolver -- captures first match. Fallback when SymFromName misses
 * because the class name differs across Windows builds. */
typedef struct { uint64_t rva; char name[512]; int count; } WildCtx;
static BOOL CALLBACK WildCb(SYMINFO *pSym, ULONG size, PVOID ctx) {
    (void)size;
    WildCtx *c = (WildCtx *)ctx;
    c->count++;
    if (c->count == 1) {
        c->rva = pSym->Address - FAKE_BASE;
        strncpy(c->name, pSym->Name, sizeof(c->name) - 1);
    }
    return TRUE;
}
static uint64_t resolve_wild(const char *pattern) {
    if (!pSymEnumSymbols) return 0;
    WildCtx ctx = {0};
    pSymEnumSymbols(g_hProc, FAKE_BASE, pattern, WildCb, &ctx);
    if (ctx.count > 0) {
        log_line("  WILD: %-60s -> %s RVA=0x%llX", pattern, ctx.name,
                 (unsigned long long)ctx.rva);
        return ctx.rva;
    }
    return 0;
}

/* v3.2 (2026-09-24) -- exact-name enum resolver.
 *
 * SymFromName's decorated-name matcher varies across dbghelp versions +
 * PDB toolchain versions. Empirical: shipping our current dbghelp against
 * an older dwmcore.pdb (10.0.26100.7920) MISSES every symbol with GLE=126
 * (ERROR_MOD_NOT_FOUND) even though the symbols exist -- SymEnumSymbols
 * with the same fully-qualified name as its mask finds them all first
 * try. This was confirmed via tools/dwmcore_shape_probe against a mid-2025
 * dwmcore.dll harvested from the sibling hooksdll repo. Same symbols,
 * same PDB, same dbghelp -- but SymFromName specifically miscompares.
 *
 * FIX: use SymEnumSymbols with the exact fully-qualified name as its own
 * pattern (single result expected -- classnames are unique). This is
 * SymFromName's underlying primitive and doesn't rely on the internal
 * name-parser's guess of the decorated form.
 *
 * Kept both paths and log which succeeded so we can spot drift. */
static uint64_t resolve_exact_via_enum(const char *sym) {
    if (!pSymEnumSymbols) return 0;
    WildCtx ctx = {0};
    /* Fully-qualified name is a valid enum mask -- expects <=1 match. */
    pSymEnumSymbols(g_hProc, FAKE_BASE, sym, WildCb, &ctx);
    if (ctx.count > 0) return ctx.rva;
    return 0;
}

/* Primary resolve() -- try enum-exact FIRST, SymFromName SECOND.
 *
 * Enum-exact is more robust across dbghelp/PDB toolchain mismatches
 * (see block-comment above). SymFromName kept as fallback for the rare
 * case where enum fails but SymFromName succeeds (never observed live,
 * kept defensively). Log which path won so we can spot drift over time
 * -- the log line prefix indicates the source. */
static uint64_t resolve(const char *sym) {
    /* Path 1: exact-name enum. */
    uint64_t via_enum = resolve_exact_via_enum(sym);
    if (via_enum) {
        log_line("  HIT : %-60s RVA=0x%llX", sym, (unsigned long long)via_enum);
        return via_enum;
    }

    /* Path 2: SymFromName (legacy path, kept for defensive coverage). */
    char buf[sizeof(SYMINFO)];
    SYMINFO *p = (SYMINFO *)buf;
    ZeroMemory(buf, sizeof(buf));
    p->SizeOfStruct = 88;
    p->MaxNameLen = sizeof(p->Name) - 1;
    if (pSymFromName(g_hProc, sym, p) && p->Address >= FAKE_BASE) {
        uint64_t r = p->Address - FAKE_BASE;
        log_line("  HIT2: %-60s RVA=0x%llX (via SymFromName)",
                 sym, (unsigned long long)r);
        return r;
    }
    log_line("  MISS: %-60s GLE=%lu", sym, GetLastError());
    return 0;
}

int main(void) {
    svc_str_init();   /* decrypt SS() strings once at startup */
    log_line("=== resolver start ===");
    CreateDirectoryA(SVC_INSTALL_DIR, NULL);
    CreateDirectoryA(SYM_CACHE, NULL);

    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);
    char *sl = strrchr(self, '\\');
    if (sl) *sl = 0;
    log_line("dir: %s", self);

    char oldpath[4096] = {0}, newpath[4096] = {0};
    GetEnvironmentVariableA("PATH", oldpath, sizeof(oldpath));
    _snprintf(newpath, sizeof(newpath) - 1, "%s;%s", self, oldpath);
    newpath[sizeof(newpath) - 1] = 0;
    SetEnvironmentVariableA("PATH", newpath);

    char dbg[MAX_PATH];
    _snprintf(dbg, sizeof(dbg) - 1, "%s\\cgpt_dbghelp.dll", self);
    dbg[sizeof(dbg) - 1] = 0;
    g_hDbg = LoadLibraryA(dbg);
    if (!g_hDbg) { log_line("FATAL: %s GLE=%lu", dbg, GetLastError()); return 1; }

    pSymInitialize   = (pfnSymInitialize)  GetProcAddress(g_hDbg, "SymInitialize");
    pSymLoadModuleEx = (pfnSymLoadModuleEx)GetProcAddress(g_hDbg, "SymLoadModuleEx");
    pSymFromName     = (pfnSymFromName)    GetProcAddress(g_hDbg, "SymFromName");
    pSymCleanup      = (pfnSymCleanup)     GetProcAddress(g_hDbg, "SymCleanup");
    pSymSetOptions   = (pfnSymSetOptions)  GetProcAddress(g_hDbg, "SymSetOptions");
    pSymEnumSymbols  = (pfnSymEnumSymbols) GetProcAddress(g_hDbg, "SymEnumSymbols");
    if (!pSymInitialize || !pSymLoadModuleEx || !pSymFromName) {
        log_line("FATAL: missing dbghelp exports"); return 1;
    }
    g_hProc = GetCurrentProcess();
    if (pSymSetOptions) pSymSetOptions(0x80800002);   /* DEBUG|UNDNAME|FAVOR_COMPRESSED */

    log_line("SymInitialize (%s)", SYM_SERVER);
    log_line("NOTE: first run downloads PDB -- 30-90s");
    if (!pSymInitialize(g_hProc, SYM_SERVER, FALSE)) {
        log_line("FATAL: SymInitialize %lu", GetLastError()); return 1;
    }

    log_line("SymLoadModuleEx %s", DWMCORE_PATH);
    ULONG64 mb = pSymLoadModuleEx(g_hProc, NULL, DWMCORE_PATH, NULL,
                                   FAKE_BASE, 0, NULL, 0);
    if (!mb) {
        log_line("FATAL: SymLoadModuleEx %lu", GetLastError());
        if (pSymCleanup) pSymCleanup(g_hProc);
        return 1;
    }

    OffsetsBlob b = {0};
    log_line("Resolving 17 symbols:");

    b.renderContent = resolve(SS(SVC_STR_PDB_CWNODE_RC));

    b.isNormal = resolve("dwmcore!CVisual::IsNormal");
    if (!b.isNormal) b.isNormal = resolve_wild("dwmcore!*::IsNormal");

    b.isNormalDesktopRender = resolve("dwmcore!CDrawingContext::IsNormalDesktopRender");

    b.wdaDispatch = resolve("dwmcore!CVisual::SetWindowDisplayAffinity");
    if (!b.wdaDispatch) b.wdaDispatch = resolve("dwmcore!CDwmWindow::SetWindowDisplayAffinity");
    if (!b.wdaDispatch) b.wdaDispatch = resolve("dwmcore!CWindowNode::SetWindowDisplayAffinity");
    if (!b.wdaDispatch) b.wdaDispatch = resolve_wild("dwmcore!*::SetWindowDisplayAffinity");
    if (!b.wdaDispatch) b.wdaDispatch = resolve_wild("dwmcore!*DisplayAffinity*");

    b.wdaValidator = resolve("dwmcore!CVisual::IsWindowExcludedFromCapture");
    if (!b.wdaValidator) b.wdaValidator = resolve("dwmcore!CWindowNode::IsExcludedFromCapture");
    if (!b.wdaValidator) b.wdaValidator = resolve("dwmcore!CWindowNode::IsExcludedFromDesktopCapture");
    if (!b.wdaValidator) b.wdaValidator = resolve_wild("dwmcore!*::IsExcluded*");
    if (!b.wdaValidator) b.wdaValidator = resolve_wild("dwmcore!*Excluded*Capture*");

    b.finalCapture = resolve("dwmcore!CWindowNode::FinalCapture");
    if (!b.finalCapture) b.finalCapture = resolve("dwmcore!CWindowNode::Capture");
    if (!b.finalCapture) b.finalCapture = resolve_wild("dwmcore!CWindowNode::*apture");

    b.scheduleComposition   = resolve("dwmcore!ScheduleCompositionPass");
    b.cvisualRenderContent  = resolve(SS(SVC_STR_PDB_CVISUAL_RC));
    b.cOverlayContextPresent= resolve("dwmcore!COverlayContext::Present");
    b.presentNeeded         = resolve("dwmcore!CDDisplayRenderTarget::PresentNeeded");
    b.forceFullDirty        = resolve("dwmcore!CCommonRegistryData::ForceFullDirtyRendering");
    b.legacyPresentNeeded   = resolve("dwmcore!CLegacyRenderTarget::PresentNeeded");
    b.isOverlayPrevented    = resolve("dwmcore!CGlobalCompositionSurfaceInfo::IsOverlayPrevented");
    b.getDevice             = resolve("dwmcore!COverlaySwapChain::GetDevice");
    b.overlayConstructor    = resolve("dwmcore!COverlayContext::COverlayContext");

    b.isPrimaryMonitor = resolve("dwmcore!CDDisplayRenderTarget::IsPrimaryMonitor");
    if (!b.isPrimaryMonitor) b.isPrimaryMonitor = resolve("dwmcore!CMonitor::IsPrimaryMonitor");
    if (!b.isPrimaryMonitor) b.isPrimaryMonitor = resolve("dwmcore!CDisplayRenderTarget::IsPrimaryMonitor");

    b.getHwnd = resolve("dwmcore!CWindowNode::GetHwnd");
    if (!b.getHwnd) b.getHwnd = resolve("dwmcore!CWindowNode::get_hwnd");

    /* svcldb-specific: dirty-region trampolines for the fullscreen-dirty
     * trick that solves the "quadrant" bug where DWM only re-composites
     * the region the user just clicked in. Calling these with a
     * fullscreen RECTF on every PN detour fire forces DWM to mark the
     * whole layer dirty each frame -> next composite samples entire
     * texture -> our overlay pixels are always up to date. */
    b.addDirtyRectDisplay = resolve("dwmcore!CDDisplayRenderTarget::AddDirtyRect");
    b.addDirtyRectLegacy  = resolve("dwmcore!CLegacyRenderTarget::AddDirtyRect");

    /* Present RVAs -- hooked to capture the REAL `this` pointer DWM uses
     * for the render target. PN's `this` might be virtual-base-adjusted
     * (crashed AddDirtyRect when used directly); Present's `this` is
     * the top-level object with the complete layout. */
    b.presentDisplay = resolve("dwmcore!CDDisplayRenderTarget::Present");
    b.presentLegacy  = resolve("dwmcore!CLegacyRenderTarget::Present");

    /* v1.6.2 -- vtable-slot target RVAs. Payload walks pLayer's vtable
     * at first Present() call and matches these against the live function
     * pointers to discover the correct slot index for each method,
     * replacing hardcoded GPB_SLOT=5 / GD3D_SLOT=24 / ACC3_SLOT=19.
     *
     * The hardcoded values came from Bypassify's original RE and work
     * for ~800+ Bypassify users, but Windows patch levels can re-order
     * internal vtables (verified on user jay.perkerson@gmail.com's box,
     * 2026-07-15 -- DWM crashed within 1s of inject). Dynamic discovery
     * closes that failure mode.
     *
     * If PDB doesn't expose these symbol names (which happens on some
     * Windows editions), the RVA stays 0 -> payload falls back to
     * hardcoded slots, same behavior as pre-v1.6.2. */
    /* Try known class variants (Windows 10/11 pre-24H2, 24H2, 25H2+).
     * The class that owns GetPhysicalBackBuffer / GetD3D11Resource has
     * been renamed across Windows versions:
     *   - Older Windows 10/11: COverlaySwapChain
     *   - Windows 11 24H2+:    CDDisplaySwapChain (buffer class:
     *                           CDDisplaySwapChainBuffer)
     * We resolve BOTH so payload's dynamic scan has more RVA candidates
     * to match against -- increases coverage when pLayer's actual vtable
     * slot dispatches to whichever variant is live. */
    b.getPhysicalBackBufferRva = resolve("dwmcore!CDDisplaySwapChain::GetPhysicalBackBuffer");
    if (!b.getPhysicalBackBufferRva)
        b.getPhysicalBackBufferRva = resolve("dwmcore!COverlaySwapChain::GetPhysicalBackBuffer");
    if (!b.getPhysicalBackBufferRva)
        b.getPhysicalBackBufferRva = resolve_wild("dwmcore!*SwapChain::GetPhysicalBackBuffer");
    if (!b.getPhysicalBackBufferRva)
        b.getPhysicalBackBufferRva = resolve_wild("dwmcore!*::GetPhysicalBackBuffer");
    if (!b.getPhysicalBackBufferRva)
        b.getPhysicalBackBufferRva = resolve_wild("dwmcore!*PhysicalBackBuffer*");

    b.getD3D11ResourceRva = resolve("dwmcore!CDDisplaySwapChainBuffer::GetD3D11Resource");
    if (!b.getD3D11ResourceRva)
        b.getD3D11ResourceRva = resolve("dwmcore!CDDisplaySwapChain::GetD3D11Resource");
    if (!b.getD3D11ResourceRva)
        b.getD3D11ResourceRva = resolve("dwmcore!COverlaySwapChain::GetD3D11Resource");
    if (!b.getD3D11ResourceRva)
        b.getD3D11ResourceRva = resolve_wild("dwmcore!*::GetD3D11Resource");
    if (!b.getD3D11ResourceRva)
        b.getD3D11ResourceRva = resolve_wild("dwmcore!*GetD3D11Resource*");

    /* Accessor method -- its exact name is class-dependent (defined on
     * whatever D3D11 resource wrapper GetD3D11Resource returns). Try
     * common patterns; if none hit, payload uses hardcoded slot 19. */
    b.accessorRva = resolve("dwmcore!CDeviceTextureTarget::GetTexture2D");
    if (!b.accessorRva)
        b.accessorRva = resolve_wild("dwmcore!*Target::GetTexture2D");
    if (!b.accessorRva)
        b.accessorRva = resolve_wild("dwmcore!*::GetTexture2D");
    if (!b.accessorRva)
        b.accessorRva = resolve_wild("dwmcore!*::AsTexture2D");
    if (!b.accessorRva)
        b.accessorRva = resolve_wild("dwmcore!*::GetResource");

    int n = 0;
    uint64_t *f = (uint64_t *)&b;
    const int total_fields = (int)(sizeof(b) / sizeof(uint64_t));
    for (int i = 0; i < total_fields; i++) if (f[i]) n++;
    log_line("Resolved %d/%d symbols", n, total_fields);
    log_line("Vtable-slot RVA hints: gpb=0x%llX gd3d=0x%llX acc=0x%llX",
             (unsigned long long)b.getPhysicalBackBufferRva,
             (unsigned long long)b.getD3D11ResourceRva,
             (unsigned long long)b.accessorRva);

    /* Payload only NEEDS cOverlayContextPresent + isOverlayPrevented.
     * Everything else is nice-to-have (wda etc. we don't use in svcldb). */
    if (!b.cOverlayContextPresent || !b.isOverlayPrevented) {
        log_line("FATAL: missing core symbols (present + overlay-prevent)");
        if (pSymCleanup) pSymCleanup(g_hProc);
        return 1;
    }

    /* v-multibuild (2026-09-24) -- capture validation snapshot.
     *
     * Read dwmcore.dll from disk, parse the PE headers, snapshot:
     *   - TimeDateStamp (for cross-check that payload's loaded dwmcore
     *     matches what we resolved against -- catches "Windows Update
     *     replaced dwmcore between resolve + inject" edge case).
     *   - SizeOfImage (payload uses to bounds-check RVAs).
     *   - First 32 bytes at cOverlayContextPresent and IsOverlayPrevented
     *     (payload compares to live dwmcore memory before hooking).
     *   - 16 bytes at ForceFullDirty flag (bool-guard input).
     *
     * All of this is optional data -- if capture fails, we still write
     * the 192-byte v1 blob (payload falls back to its existing shape-
     * detection heuristics). */
    OffsetsBlobExt ext = {0};
    ext.magic = BLOB_EXT_MAGIC;
    ext.resolver_flags = 0;
    int ext_ok = 0;
    {
        HANDLE hf_dc = CreateFileA(DWMCORE_PATH, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf_dc != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER li;
            if (GetFileSizeEx(hf_dc, &li) && li.QuadPart > 0 && li.QuadPart < 0x8000000) {
                DWORD fsz = (DWORD)li.QuadPart;
                BYTE *fbuf = (BYTE *)VirtualAlloc(NULL, fsz, MEM_COMMIT, PAGE_READWRITE);
                if (fbuf) {
                    DWORD rd = 0;
                    if (ReadFile(hf_dc, fbuf, fsz, &rd, NULL) && rd == fsz && fsz >= 0x400) {
                        DWORD e_lfanew = *(DWORD *)(fbuf + 0x3C);
                        if (e_lfanew + 0x18 <= fsz &&
                            fbuf[e_lfanew] == 'P' && fbuf[e_lfanew+1] == 'E') {
                            /* IMAGE_FILE_HEADER at e_lfanew+4: TDS at +4. */
                            ext.dwmcore_tds = *(DWORD *)(fbuf + e_lfanew + 4 + 4);
                            /* IMAGE_OPTIONAL_HEADER64.SizeOfImage at offset
                             * IMAGE_FILE_HEADER (20) + optional header field
                             * offset 56 = e_lfanew + 4 + 20 + 56 = +80. */
                            ext.dwmcore_size = *(DWORD *)(fbuf + e_lfanew + 4 + 20 + 56);

                            /* Parse sections. */
                            WORD n_sec = *(WORD *)(fbuf + e_lfanew + 4 + 2);
                            WORD opt_sz = *(WORD *)(fbuf + e_lfanew + 4 + 16);
                            DWORD sec_start = e_lfanew + 4 + 20 + opt_sz;

                            /* Helper: given an RVA, find file offset. */
                            #define FIND_FILEOFF(rva, out_off) do { \
                                (out_off) = 0; \
                                for (WORD si = 0; si < n_sec; si++) { \
                                    DWORD sofs = sec_start + si * 40; \
                                    if (sofs + 40 > fsz) break; \
                                    DWORD s_vsz = *(DWORD *)(fbuf + sofs + 8); \
                                    DWORD s_va  = *(DWORD *)(fbuf + sofs + 12); \
                                    DWORD s_raw = *(DWORD *)(fbuf + sofs + 20); \
                                    if ((rva) >= s_va && (rva) < s_va + s_vsz) { \
                                        (out_off) = s_raw + ((rva) - s_va); \
                                        break; \
                                    } \
                                } \
                            } while (0)

                            /* Capture prologue of Present. */
                            if (b.cOverlayContextPresent) {
                                DWORD off = 0;
                                FIND_FILEOFF((DWORD)b.cOverlayContextPresent, off);
                                if (off && off + 32 <= fsz)
                                    memcpy(ext.prologue_present, fbuf + off, 32);
                            }
                            /* Capture prologue of IsOverlayPrevented. */
                            if (b.isOverlayPrevented) {
                                DWORD off = 0;
                                FIND_FILEOFF((DWORD)b.isOverlayPrevented, off);
                                if (off && off + 32 <= fsz)
                                    memcpy(ext.prologue_iop, fbuf + off, 32);
                            }
                            /* Capture ForceFullDirty bytes (may not exist). */
                            if (b.forceFullDirty) {
                                DWORD off = 0;
                                FIND_FILEOFF((DWORD)b.forceFullDirty, off);
                                if (off && off + 16 <= fsz)
                                    memcpy(ext.ffd_bytes, fbuf + off, 16);
                            }
                            #undef FIND_FILEOFF
                            ext_ok = 1;
                        }
                    }
                    VirtualFree(fbuf, 0, MEM_RELEASE);
                }
            }
            CloseHandle(hf_dc);
        }
    }
    if (ext_ok) {
        log_line("blob-ext: dwmcore TDS=0x%08X size=%lu "
                 "present=%02X %02X %02X %02X ... iop=%02X %02X %02X %02X ... ffd=%02X",
                 ext.dwmcore_tds, (unsigned long)ext.dwmcore_size,
                 ext.prologue_present[0], ext.prologue_present[1],
                 ext.prologue_present[2], ext.prologue_present[3],
                 ext.prologue_iop[0], ext.prologue_iop[1],
                 ext.prologue_iop[2], ext.prologue_iop[3],
                 ext.ffd_bytes[0]);
    } else {
        log_line("blob-ext: capture FAILED -- writing v1 blob (no validation snapshot)");
    }

    HANDLE hf = CreateFileA(BLOB_PATH, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        log_line("FATAL: %s GLE=%lu", BLOB_PATH, GetLastError());
        if (pSymCleanup) pSymCleanup(g_hProc);
        return 1;
    }
    DWORD w = 0, w2 = 0;
    WriteFile(hf, &b, sizeof(b), &w, NULL);
    if (ext_ok) {
        WriteFile(hf, &ext, sizeof(ext), &w2, NULL);
    }
    CloseHandle(hf);
    log_line("Wrote %lu core + %lu ext = %lu bytes to %s",
             w, w2, w + w2, BLOB_PATH);

    if (pSymCleanup) pSymCleanup(g_hProc);
    log_line("=== resolver done ===");
    return 0;
}
