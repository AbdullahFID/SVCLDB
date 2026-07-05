---
name: bypassify-dwm-pdb-technique
description: "Full Bypassify 1:1 parity: PDB resolution, 7 DWM hooks, IsOverlayPrevented patch, PresentNeeded RT capture, ForceCompositionPass, COM GetDevice. V5.2."
metadata: 
  node_type: memory
  type: project
  originSessionId: f1632464-7f61-477c-86fa-78a14984a487
---

## Bypassify 1:1 Parity Status (V5.2, 2026-05-22)

All 8 Bypassify dwmcore symbols + 3 D3D are now resolved or superseded. Every technique Bypassify uses (except hosting the overlay inside DWM, which is architectural — CloakGPT uses Electron) is implemented.

**dwm_resolver.exe resolves 16 symbols:**
Slots 1-9: RenderContent, IsNormal, IsNormalDesktopRender, WdaDispatch, WdaValidator, FinalCapture, ScheduleCompositionPass, CVisual::RenderContent, COverlayContext::Present
Slots 10-12: CDDisplayRenderTarget::PresentNeeded, ForceFullDirtyRendering, CLegacyRenderTarget::PresentNeeded
Slots 13-16: IsOverlayPrevented, COverlaySwapChain::GetDevice, COverlayContext constructor, IsPrimaryMonitor

**offsets.blob**: 16×UINT64 = 128 bytes

**7 active hooks in dwm_payload.dll:**
1. CWindowNode::RenderContent — overlay invisible in captures
2. CVisual::SetWindowDisplayAffinity (WdaDispatch) — block 0x11 for non-overlay
3. WDA validator — fail 0x11 validation
4. CWindowNode::FinalCapture — D3D11 texture grab fallback
5. COverlayContext::Present — GPB screenshot (primary capture path)
6. CDDisplayRenderTarget::PresentNeeded — captures render target `this`, forces present
7. CLegacyRenderTarget::PresentNeeded — captures legacy render target `this`

**Plus permanent patches:**
- IsOverlayPrevented → `xor eax,eax; ret` (blanket WDA compositor bypass)
- WDA byte-patch sites (5 code patches, applied temporarily during capture)

**ForceCompositionPass() chain (4 steps):**
1. ForceFullDirtyRendering — mark all compositor content dirty
2. ScheduleCompositionPass — trigger DWM to compose a frame
3. PresentNeeded on captured CDDisplayRenderTarget — force display present
4. PresentNeeded on captured CLegacyRenderTarget — force legacy present
All SEH-wrapped. Called before GPB capture and during FinalCapture retry loop.

**GPB device acquisition (V5.2 fix):**
Replaced fragile `[CPhysBackBuffer+0x218]` struct offset with standard COM `ID3D11DeviceChild::GetDevice` (vtable[3]). ABI-stable across all Windows builds.

**Remaining Bypassify differences (architectural, not gaps):**
- CloakGPT uses Electron overlay, not DWM-hosted ImGui overlay
- GPB vtable slots 5/24/19 hardcoded (COM ABI-stable, correct approach)
- IsPrimaryMonitor resolved but not yet wired for multi-monitor capture selection

[[v51_dwm_capture_state]] [[screenshot_pipeline_v51]]
