---
name: screenshot-pipeline-v51
description: "V5.1 screenshot pipeline fixes — async BMP reading, topDown detection, hide/show, _captureAbort, taskbar icon suppression"
metadata: 
  node_type: memory
  type: project
  originSessionId: 8f8083cb-dc1a-4e94-89a8-f121d81e45bd
---

All fixes shipped in V5.0/V5.1 (2026-05-21).

**BMP orientation (critical):**
`SaveBGRAasBMP` in dwm_payload.c writes `biHeight = -(LONG)height` (negative = top-down BMP).
`readCaptureBmp` in main.js must detect `rawH < 0` → `topDown=true` → read rows `srcY=y` (no flip).
`flipH=false` for DWM captures — D3D11 physical backbuffer is correctly oriented left-to-right.
Old bug: treating top-down as bottom-up caused double-flip = 180° rotation.

**readCaptureBmp is async:** Uses `fs.promises.readFile` to avoid blocking Node.js event loop during 20MB BMP reads. All callers must `await` it. Functions `takeDllPresentCapture`, `takeGdiScreenshot` are also async now.

**_captureAbort flag:** Set by `toggleOverlay()` hide path. `takePresentCapture` and `takeDwmPayloadCapture` check it every 100ms. Gives Ctrl+G absolute priority — capture aborts on next tick, window hides immediately.

**Taskbar icon suppression (multi-layer):**
1. `app.setAppUserModelId('.')` — treats process as background service
2. `applyStealth()` calls `win.setSkipTaskbar(true)` on every invocation (not just firstTime)
3. `win.on('focus')` → `setSkipTaskbar(true)` — kills entry that appears when renderer paste triggers focus
4. Removed all `win.hide()` calls from kernel-capture fallback path (was causing flash)
5. DWM path: `win.hide()` before capture, `win.showInactive()` after (overlay hidden from DWM frame)

**Capture path priority (enhanced/kernel):**
1. `takePresentCapture()` — GPB hook, ~100ms, checks `present_hook_active.dat`
2. `takeDwmPayloadCapture()` FinalCapture — ~2.4s, checks `dwm_ready.dat`
3. `takeDllPresentCapture()` — hooks.dll GDI/Present
4. hooks.dll `kernel_capture_trigger` chain
5. `takeFullScreenshot()` DXGI fallback
