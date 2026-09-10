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

int  pl_offsets_load(pl_offsets_t *out);
HMODULE pl_locate_dwmcore(void);

#ifdef __cplusplus
}
#endif

#endif
