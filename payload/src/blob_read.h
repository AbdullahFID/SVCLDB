/* ================================================================== *
 * blob_read.h — Mirror of the resolver's offsets_blob_t.              *
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
 * verbatim. Extra 2 slots for our fullscreen-dirty trick — see comments. */
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
} pl_offsets_t;

int  pl_offsets_load(pl_offsets_t *out);
HMODULE pl_locate_dwmcore(void);

#ifdef __cplusplus
}
#endif

#endif
