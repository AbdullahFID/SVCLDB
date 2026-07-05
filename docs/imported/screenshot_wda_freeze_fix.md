---
name: screenshot_wda_freeze_fix
description: Two root causes for screenshot freeze + WDA loss after V9.0 teal fix. Both fixed in V4.3.
metadata: 
  node_type: memory
  type: project
  originSessionId: 4dffb0f4-9066-4efe-a44f-14138f0e449c
---

## Root Cause 1 — WDA permanently lost after screenshots

`applyStealth(win)` checks `if (_captureInProgress) return` early. It was called inside `takeFullScreenshot()`'s `finally` block while `_captureInProgress` was still `true` (only cleared in the *outer* `take-screenshot` handler's `finally`, after `takeFullScreenshot` returns). So `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` was silently skipped every time — the window became permanently visible to all capture APIs after the first screenshot.

**Fix:** Call `applyStealth(win)` in the outer `finally` blocks of `take-screenshot` and `startRegionCapture` handlers, *after* `_captureInProgress = false`.

## Root Cause 2 — Renderer freeze after screenshot

V9.0 added `transparent:true + thickFrame:false` to fix DWM teal caption bar. `win.hide()` on a `transparent:true` window triggers Chromium's `NativeWindowOcclusionTracker`, which *pauses* (not just throttles) the renderer process. Renderer JS still ran to completion (confirmed by logs) but GPU compositor stopped sending frames — visual freeze. `disable-background-timer-throttling` (already present) doesn't cover occlusion-based pausing.

**Fix:**
- `app.commandLine.appendSwitch('disable-backgrounding-occluded-windows')`
- `app.commandLine.appendSwitch('disable-renderer-backgrounding')`
- `backgroundThrottling: false` in webPreferences
- `win.on('show')` deferred applyStealth via `setTimeout(150)` — prevents `SetWindowDisplayAffinity` from racing with DWM surface reconstruction on transparent windows

**Why:** `WDA_EXCLUDEFROMCAPTURE` called synchronously inside the 'show' event was changing DWM compositing mode mid-show, breaking input routing on `transparent:true` windows.

## What did NOT work (for reference)
- `win.setOpacity(0)` instead of hide — same GPU compositor stall
- CSS `document.documentElement.style.opacity="0"` — fixed freeze but webviews (OOPIF) didn't hide reliably
- `win.webContents.invalidate()` — no-op on non-OSR windows
- `sendInputEvent({type:'mouseMove'})` after setOpacity — didn't kick compositor
- `setBounds` bounce — coalesced, no effect
- `setBackgroundThrottling(false)` alone — doesn't cover occlusion pausing
- Removing `thickFrame:false` — didn't fix freeze (issue is `transparent:true` alone)

**How to apply:** Any time screenshot capture is modified, ensure `applyStealth(win)` runs in outer finally AFTER `_captureInProgress=false`, not inside `takeFullScreenshot()` directly.

## Root Cause 3 — V5.5.2: WDA flicker on default-mode camera button spam (DWM VSync race)

Every default-mode capture had a ~1 DWM frame (~16ms at 60Hz) where the overlay was **visible + WDA=0**, caught by screen recorders when spamming the button (each press has ~6% hit chance; 20 presses = ~71% cumulative).

Three stacked bugs:
1. `takeFullScreenshot` called `SetWindowDisplayAffinity(h, 0)` on all BrowserWindows before hiding them. WDA persists through hide/show — clearing before hide means the overlay re-appears with WDA=0 on show().
2. `takeFullScreenshot`'s finally called `applyStealth(s.w)` after `show()` but `_captureInProgress` was still true → applyStealth was a no-op → WDA=0 persisted until outer handler ran.
3. `kernel-capture` cleared WDA on all BrowserWindows including the visible overlay, leaving it exposed for the full 30ms capture wait.

**Fix (V5.5.2):**
- Removed `SetWindowDisplayAffinity(h, 0)` from `takeFullScreenshot`'s pre-hide loop entirely.
- Added `SetWindowDisplayAffinity(hwnd, 0x11)` BEFORE `s.w.show()` in `takeFullScreenshot`'s finally (safe — window is hidden, not mid-show transition).
- `kernel-capture` WDA clear loop now skips `win` (main overlay) with `w !== win` guard.
- Same pre-show WDA assertion added to `takeDwmPayloadCapture` and `present-capture` finally blocks.

**Rule:** NEVER call `SetWindowDisplayAffinity` during/after show (breaks DWM routing on transparent windows — V4.3). Always call it BEFORE show while window is hidden, or in the outer finally after `_captureInProgress=false`.
