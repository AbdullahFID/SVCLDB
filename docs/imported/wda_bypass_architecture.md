---
name: wda-capture-architecture-working
description: WDA_EXCLUDEFROMCAPTURE vulnerability via DWM compositor hooks — fully working end-to-end with Electron
metadata: 
  node_type: memory
  type: project
  originSessionId: bf3fa94e-c9d5-48d0-b8f7-0b0ad7e185e7
---

## WDA Capture via DWM Hooks - Fully Working (2026-03-26)

### Capture Flow (Production)
1. Electron writes "1" to `C:\ProgramData\Lumio\wda_bypass.dat`
2. DWM capture thread reads "1", applies 5 patches, arms FinalCapture
3. FinalCapture hook QIs `pThis+0x20` for ID3D11Texture2D → gets compositor texture (HDR)
4. Converts HDR float16 → BGRA, saves `capture.bmp` (20MB, 2880x1800)
5. DWM waits for Electron to write "0" (ACL: DWM can't write to Electron's files)
6. Patches reverted. Single-shot.

### 5 Patch Sites (signature-scanned, update-resilient)
1-3. Type A: `cmp [rax+48h], 0x11` + JNE → JMP (skip WDA exclusion)
4. Type B anchor: CALL → `xor eax,eax` + NOPs
5. IsNormal: → `mov al,1; ret` (prevents content blackout — CRITICAL)

### 3 MinHook Hooks
- RenderContent: skips overlay HWND during composition
- FinalCapture: grabs DComp texture via candidate 0 (pThis+0x20)
- WdaDispatch/Validator: monitoring

### Key Discoveries
- **win32k.sys enforces WDA independently** — GDI/DXGI from DWM gives BLACK even with patches
- **FinalCapture grabs texture BEFORE win32k** — only way to get actual content
- **DComp wrapper ≠ ID3D11Texture2D** — internal GUID {30961379...}. Real texture at pThis+0x20
- **DWM-N service account** can't write files created by admin. One-way IPC only.
- **IsNormal patch is essential** — without it, windows render as black rectangles

### File IPC Protocol
- Signal: `C:\ProgramData\Lumio\wda_bypass.dat` (Electron writes, DWM reads)
- Capture: `C:\ProgramData\Lumio\capture.bmp` (DWM writes, Electron reads)
- Electron polls for capture.bmp existence (size > 1000 bytes)
