---
name: dwm-hwnd-offset-v57-resolution
description: "HWND offset discovery outcome — what failed, what works, final state after V5.7+ session"
metadata: 
  node_type: memory
  type: project
  originSessionId: 8d345f11-2fe9-40b9-955d-2d2cceaaffb6
---

## Final state: g_hwndOffset = 0x320 works (46 matches/1000). Discovery is a tiebreaker, not a true scan.

**Why:** Three discovery approaches all failed to uniquely identify the CWindowNode HWND offset:
1. `IsWindow` heap scan → many CVisual subclasses share +0x6A flag, wrong class wins
2. Isolated overlay HWND match (±8 neighbor filter) → GPU graphics buffers contain HWND value at stride-16, so ALL even offsets (0x2F0, 0x300, 0x310, 0x320...) tie at 10 isolated hits
3. Score by visibleFlagCorrect → all CVisual share the same +0x6A flag byte, most-numerous subclass wins

**Current implementation:** Picks offset closest to HWND_OFFSET_IN_WINDOWNODE (0x320) as tiebreaker when all candidates tie. Works correctly for build 26100.8457 because 0x320 IS the correct offset. If offset changes to something far from 0x320, tiebreaker will fail.

**The real solution:** `dwm_resolver.exe` downloads dwmcore.pdb via symsrv and writes `offsets.blob` with exact function RVAs. BUT it doesn't resolve HWND struct offset — it only resolves function addresses (same as Bypassify). The HWND offset is not a symbol PDB would expose as `GetHwnd` field; it needs struct member enumeration via DIA SDK. Currently not implemented.

**Hardcoded 0x320** is reliable for build 26100 until a Windows update changes the struct layout. ValidateStructOffsets (Phase 2) detects FAIL:HWND_OFFSET and logs it.

**Bypassify v1.2.3 reference:** Pure PDB — SymFromName for 8 function addresses, no HWND scan. Their capture = COverlayContext::Present → GetPhysicalBackBuffer. They never touch CWindowNode because they don't do per-window hiding.

**Why:** Our overlay-hiding requirement (skip CWindowNode::RenderContent for our window only) is unique to us.
**How to apply:** Keep 0x320 hardcoded as fallback. The discovery machinery stays but is documented as tiebreaker-only.
