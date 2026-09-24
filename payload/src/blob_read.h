/* ================================================================== *
 * blob_read.h -- Mirror of the resolver's offsets_blob_t.              *
 *                                                                    *
 * Layout matches hooksdll/dwm/dwm_resolver.c's OffsetsBlob exactly    *
 * so a well-worn PDB-resolution + fallback path can be reused as-is.  *
 * ================================================================== */
#ifndef SVCLDB_BLOB_READ_H
#define SVCLDB_BLOB_READ_H

#include <stdint.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 19 slots × 8 bytes = 152 bytes total. Same field ordering + semantics as
 * the main app's OffsetsBlob (first 17) so we can reuse its vtable-walk
 * verbatim. Extra 2 slots for our fullscreen-dirty trick -- see comments. */
typedef struct {
    uint64_t renderContent;          /* CWindowNode::RenderContent RVA        */
    uint64_t isNormal;               /* CVisual::IsNormal RVA                 */
    uint64_t isNormalDesktopRender;  /* CDrawingContext::IsNormalDesktopRender*/
    uint64_t wdaDispatch;            /* WDA attribute dispatcher RVA          */
    uint64_t wdaValidator;           /* WDA attribute validator RVA           */
    uint64_t finalCapture;           /* CWindowNode::FinalCapture RVA         */
    uint64_t scheduleComposition;    /* ScheduleCompositionPass RVA           */
    uint64_t cvisualRenderContent;   /* CVisual::RenderContent RVA            */
    uint64_t cOverlayContextPresent; /* COverlayContext::Present RVA          */
    uint64_t presentNeeded;          /* CDDisplayRenderTarget::PresentNeeded  */
    uint64_t forceFullDirty;         /* CCommonRegistryData::ForceFullDirty   */
    uint64_t legacyPresentNeeded;    /* CLegacyRenderTarget::PresentNeeded    */
    uint64_t isOverlayPrevented;     /* CGlobalCompositionSurfaceInfo::IsOverlayPrevented */
    uint64_t getDevice;              /* COverlaySwapChain::GetDevice          */
    uint64_t overlayConstructor;     /* COverlayContext::COverlayContext      */
    uint64_t isPrimaryMonitor;       /* IsPrimaryMonitor                      */
    uint64_t getHwnd;                /* CWindowNode::GetHwnd (body-parsed)    */

    /* --- svcldb-specific extras for fullscreen-dirty trick --- */
    uint64_t addDirtyRectDisplay;    /* CDDisplayRenderTarget::AddDirtyRect   */
    uint64_t addDirtyRectLegacy;     /* CLegacyRenderTarget::AddDirtyRect     */
    uint64_t presentDisplay;         /* CDDisplayRenderTarget::Present RVA    */
    uint64_t presentLegacy;          /* CLegacyRenderTarget::Present RVA      */

    /* --- v1.6.2 (2026-07-15) -- dynamic vtable-slot targets ---
     *
     * RVAs of the three methods whose vtable slot indices used to be
     * hardcoded in payload/src/ui/imgui_layer.cpp (GPB_SLOT=5,
     * GD3D_SLOT=24, ACC3_SLOT=19). At first Present() call, the
     * payload walks pLayer's / pRes's vtable and finds the slot whose
     * function pointer matches these RVAs -- that IS the correct slot
     * on this specific Windows build. Falls back to hardcoded values
     * if the RVAs are 0 (old blob or PDB missed the symbol).
     *
     * Solves the "DWM crashes ~1s after inject on Windows patch levels
     * with re-ordered vtable" bug reported by jay.perkerson@gmail.com
     * 2026-07-15. Hardcoded values match Bypassify's RE (~800+ working
     * users) so on typical Windows builds these RVAs discover the SAME
     * slots the hardcoded ones point to -- the dynamic pass validates
     * the hardcoded assumption every run. */
    uint64_t getPhysicalBackBufferRva; /* COverlaySwapChain::GetPhysicalBackBuffer */
    uint64_t getD3D11ResourceRva;      /* COverlaySwapChain::GetD3D11Resource      */
    uint64_t accessorRva;              /* accessor method on D3D11 resource        */
} pl_offsets_t;

/* Legacy 21-field blob size -- for backwards-compat load of blobs written
 * by the pre-v1.6.2 resolver. Payload accepts both sizes; new fields
 * zero-initialized when reading legacy blob -> dynamic scan falls back
 * to hardcoded, identical behavior to today. */
#define PL_OFFSETS_LEGACY_SIZE   (21 * sizeof(uint64_t))

/* v-multibuild (2026-09-24) -- validation extension.
 *
 * Appended to the 192-byte core `pl_offsets_t` when the resolver
 * captures a validation snapshot of the resolved-against dwmcore.dll.
 * Purpose: let the payload SANITY-CHECK the RVAs before installing
 * hooks / applying byte-patches, so that a mismatched blob (stale,
 * corrupted, from-a-different-Windows-build) produces a controlled
 * "safe-mode" degradation (payload loads, no hooks, DWM alive)
 * instead of the previous "hook the wrong function -> DWM AV" path.
 *
 * Extension is OPTIONAL:
 *   - Resolver v3.2+ writes 192 + sizeof(pl_offsets_ext_t) bytes.
 *   - Payload v3.2+ reads the extension when blob file size matches.
 *   - Older blobs (168 or 192 bytes) load as before -- validation
 *     just gets skipped, existing prologue-shape detection stays
 *     as the primary safety net.
 *
 * Field semantics:
 *   magic          "SVC2" (0x32435653) little-endian. Non-zero
 *                  distinguishes v2 from padding.
 *   dwmcore_tds    PE TimeDateStamp of dwmcore.dll at resolve time.
 *                  Payload compares to the currently-loaded module's
 *                  stamp -- if different, dwmcore was swapped between
 *                  resolve and inject (Windows Update mid-flight) ->
 *                  refuse to hook.
 *   dwmcore_size   PE SizeOfImage.
 *   resolver_flags Bitfield reporting how each critical symbol was
 *                  found (enum-first / SymFromName / sig-scan / miss).
 *   prologue_present  First 32 bytes at COverlayContext::Present RVA.
 *                     Payload compares to live dwmcore memory --
 *                     mismatch means RVA points to wrong function.
 *   prologue_iop      First 32 bytes at IsOverlayPrevented RVA.
 *   ffd_bytes         16 bytes at ForceFullDirty flag RVA.
 */
typedef struct {
    uint32_t magic;                    /* 0x32435653 = "SVC2" LE       */
    uint32_t dwmcore_tds;              /* PE TimeDateStamp             */
    uint32_t dwmcore_size;             /* PE SizeOfImage               */
    uint32_t resolver_flags;           /* bit 0: enum-first hit any
                                        * bit 1: SymFromName fallback used any
                                        * bit 2: sig-scan fallback used
                                        * bit 3: sig-scan used for a CRITICAL sym
                                        * bit 4: reserved              */
    uint8_t  prologue_present[32];     /* first 32 bytes of Present    */
    uint8_t  prologue_iop[32];         /* first 32 bytes of IsOverlay* */
    uint8_t  ffd_bytes[16];            /* 16 bytes at ForceFullDirty   */
    uint8_t  reserved[16];             /* padding for future growth    */
} pl_offsets_ext_t;

/* Magic marker used to distinguish v2 blobs from raw padding zeros. */
#define PL_OFFSETS_EXT_MAGIC   0x32435653u   /* 'SVC2' little-endian    */

/* Total v2 blob size on disk. */
#define PL_OFFSETS_V2_SIZE     (sizeof(pl_offsets_t) + sizeof(pl_offsets_ext_t))

/* Load both parts. `ext` is optional -- callers may pass NULL and get
 * only the core RVAs (legacy path). When non-NULL AND a v2 blob is on
 * disk, ext is populated + `ext->magic` will equal PL_OFFSETS_EXT_MAGIC
 * on success. When ext is populated but blob is v1, ext is zeroed and
 * caller should treat as "no validation snapshot available". */
int  pl_offsets_load(pl_offsets_t *out);
int  pl_offsets_load_v2(pl_offsets_t *out, pl_offsets_ext_t *ext);
HMODULE pl_locate_dwmcore(void);

#ifdef __cplusplus
}
#endif

#endif
