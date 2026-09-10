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
    slog_resolver(buf);
    printf("%s\n", buf); fflush(stdout);
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

static uint64_t resolve(const char *sym) {
    char buf[sizeof(SYMINFO)];
    SYMINFO *p = (SYMINFO *)buf;
    ZeroMemory(buf, sizeof(buf));
    p->SizeOfStruct = 88;
    p->MaxNameLen = sizeof(p->Name) - 1;
    if (!pSymFromName(g_hProc, sym, p)) {
        log_line("  MISS: %-60s GLE=%lu", sym, GetLastError());
        return 0;
    }
    uint64_t r = p->Address - FAKE_BASE;
    log_line("  HIT : %-60s RVA=0x%llX", sym, (unsigned long long)r);
    return r;
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

    HANDLE hf = CreateFileA(BLOB_PATH, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        log_line("FATAL: %s GLE=%lu", BLOB_PATH, GetLastError());
        if (pSymCleanup) pSymCleanup(g_hProc);
        return 1;
    }
    DWORD w = 0;
    WriteFile(hf, &b, sizeof(b), &w, NULL);
    CloseHandle(hf);
    log_line("Wrote %lu bytes to %s", w, BLOB_PATH);

    if (pSymCleanup) pSymCleanup(g_hProc);
    log_line("=== resolver done ===");
    return 0;
}
