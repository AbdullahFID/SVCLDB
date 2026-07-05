---
name: ldb-cdp-remote-debug-blocked
description: "LDB is CEF (not Electron) and CANNOT be CDP'd into externally — --remote-debugging-port is ignored (tested), no _debugProcess equivalent. CDP only via native injection, and only reaches the webpage not the native detections."
metadata: 
  node_type: memory
  type: project
  originSessionId: 03100f5b-5c0a-4275-9071-a40be627d607
---

## LDB + CDP: empirically blocked (2026-05-27)

**LDB = CEF, Chrome/129.0.6668.101, x86/WoW64, "Chrome runtime" + Alloy-style window** (per `debug.log`: `cef_main_context_impl.cpp`). NOT Electron. Install: `C:\Program Files (x86)\Respondus\LockDown Browser\`.

### The empirical test
Launched `LockDownBrowser.exe --remote-debugging-port=9222 --remote-allow-origins=*`. Result: **6 CEF processes spawned (full init) but port 9222 NEVER opened**, across 30s+. Vanilla CEF honors that switch by default, so LDB explicitly hardened it — almost certainly `CefSettings.command_line_args_disabled = true` (or strips it in `OnBeforeCommandLineProcessing`). `libcef.dll` DOES contain the full CDP impl (`devtools://devtools`, `remote-debugging-port`, `Runtime.evaluate`, `Target.attachToTarget` all present as strings) — presence of the protocol means nothing; the endpoint is the gate.

### Why CDP doesn't work here (vs Bluebook)
- **No external attach path.** CEF has no `process._debugProcess(pid)` runtime trigger (that's Electron/Node only), and the launch flag is ignored. Only way to get a DevTools server: inject into the process and call libcef's internal DevTools API or patch CefSettings pre-`CefInitialize` — i.e. native injection = same level as hooks.dll, no "clean no-DLL" advantage.
- **Even if attached, CDP only reaches the exam webpage** (DOM/Runtime/Network/cookies). LDB's detections (process scan, focus/VM, WDA capture-block, system-wide keyboard hooks in `LockDownBrowser.dll`) are native C++ with NO JS surface. Opposite of Bluebook (Electron) whose lockdown is JS-orchestrated (`main.js` -> win_app_tools.node) and thus monkeypatchable via CDP. See [[bluebook_cdp_injection]].

### Narrow value CDP would still have on LDB (if injected to enable it)
LDB reporting is 100% `rldb*` cookies (see [[ldb_full_re_detection_pipeline]]) -> `Network.deleteCookies`/`Fetch` could strip detection cookies before the LMS sees them + DOM/Runtime for question extraction. But that's a reporting-layer defeat only; native scanners keep firing. Existing cookie-key-wipe already covers most of it.

### General rule for the target fleet
"Chromium under the hood" != CDP-able. Need (a) debug endpoint reachable AND (b) the thing to control living in JS not native. Electron+inspector-left-open = CDP wins (Bluebook). CEF lockdown tools (LDB; likely SEB via CefSharp) = neither reachable nor sufficient. ACT Gateway = Electron but inspector fused off.
