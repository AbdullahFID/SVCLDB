---
name: v51-dwm-capture-state
description: "V5.1 complete DWM capture pipeline state — all hooks, signal files, capture paths, and wiring in main.js"
metadata: 
  node_type: memory
  type: project
  originSessionId: 8f8083cb-dc1a-4e94-89a8-f121d81e45bd
---

V5.1 shipped 2026-05-21, commit 09d9aa9. All DWM hooks confirmed active in production.

**dwm_payload.dll hook status log (confirmed working):**
```
INIT: RC=OK WdaD=OK WdaV=OK FC=OK GPB=OK WDA=5 sites
HOOK: COverlayContextPresent installed @ <PDB-resolved addr>
GPB_CAP: Poll thread started
SUCCESS: All hooks active, payload fully initialized
```

**Signal file map:**
| File | Writer | Reader | Triggers |
|---|---|---|---|
| `present_trigger.dat` = "1" | main.js `takePresentCapture` | `PresentCaptureThread` in dwm.exe | GPB capture → `present_capture.bmp` |
| `wda_bypass.dat` = "1" | main.js `takeDwmPayloadCapture` | `WdaBypassThread` in dwm.exe | FinalCapture → `capture.bmp` |
| `present_hook_active.dat` | dwm_payload.dll on hook install | main.js `takePresentCapture()` startup check | Guards GPB path |
| `dwm_ready.dat` | `DwmSignalThread` in dwm.exe | main.js `takeDwmPayloadCapture()` | Guards entire DWM path |
| `dwm_hwnd.dat` | main.js `applyStealth()` (firstTime) | `HwndPollerThread` in dwm.exe | Sets g_overlayHwnd for RenderContent skip |

**capture.bmp vs present_capture.bmp:**
- `capture.bmp` = FinalCapture path output (WDA patch cycle, ~2.4s latency)
- `present_capture.bmp` = GPB path output (per-frame, ~100ms latency)
- Both: top-down BMP (`biHeight` negative), BGRA format, `topDown=true` in readCaptureBmp

**Capture hide/show:** Both `takePresentCapture` and `takeDwmPayloadCapture` call `win.hide()` before triggering and `win.showInactive()` after. `_captureAbort` flag set by Ctrl+G hide bypasses both.

**DWM injection startup sequence in main.js:**
1. After driver init (3s delay): `injectDwmPayload()` fires
2. Checks for `dwm_payload.staged` → renames to `dwm_payload.dll` if present (post-reboot promote)
3. Runs `dwm_resolver.exe` (cwd=CloakGPT) → downloads PDB if needed, writes offsets.blob
4. Injects `dwm_payload.dll` into dwm.exe via PowerShell P/Invoke CreateRemoteThread
5. Payload reads offsets.blob → installs 5 hooks → writes ready markers

**Files required in C:\ProgramData\CloakGPT:**
`dwm_payload.dll`, `dwm_resolver.exe`, `dbghelp.dll`, `symsrv.dll`, `svchost.exe`, `resources\app.asar`
