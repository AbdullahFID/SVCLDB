# Hooksdll DWM Port Audit — 2026-07-05

Systematic comparison of `hooksdll/dwm/dwm_payload.c` (4192 lines,
production for 800+ users) vs `svcldb/payload/src/` to identify what's
been ported vs what's missing.

## ✅ PORTED (verified working in svcldb)

| hooksdll feature | svcldb location | Notes |
|---|---|---|
| `Detour_COverlayContextPresent` | `dwm_hooks.c` | Present hook, draws overlay before orig |
| `Detour_DisplayPresentNeeded` | `dwm_hooks.c` | PN1 — Bypassify TRUE-return pattern |
| `Detour_LegacyPresentNeeded` | `dwm_hooks.c` | PN2 — same |
| IsOverlayPrevented byte-patch | `dwm_hooks.c` | `xor eax,eax; ret` — 3 bytes saved for revert |
| `ConvertHDRtoBGRA` | `imgui_layer.cpp::convert_hdr_to_bgra` | HDR R16G16B16A16 → BGRA8 |
| GetPhysicalBackBuffer vtable walk (slots 5, 24, 19) | `imgui_layer.cpp::get_backbuffer_texture` | Same slots verified |
| `ForceCompositionPass` (call orig PN) | `dwm_hooks.c::hooks_force_wake` | Direct-wake via saved pThis |
| `SaveBGRAasBMPToFile` | `imgui_layer.cpp::write_bgra_as_bmp` | Just ported — raw BMP write, no WIC |
| `ShutdownWatchThread` (world DACL event) | `dllmain.c` + `dwm_hooks.c` | Global\SVCLDB_Shutdown with SDDL D:(A;;GA;;;WD) |
| `DwmBuildWorldSecAttr` | `dllmain.c::build_world_sa` | Permissive DACL for named events |
| Manual-map injector | `launcher/src/inject.c` | Ported from `dwm_manual_map.c` |
| PDB offsets.blob resolver | `resolver/src/main.c` | Ported from `dwm_resolver.c` |
| ScheduleCompositionPass wake | `dwm_hooks.c` | **NEW** — actually the Bypassify slot [7] mystery fn |
| Keep-alive thread (SCP at 20Hz) | `dwm_hooks.c` | **NEW** — belt-and-suspenders |

## ✅ NEW in svcldb (svcldb-only, better than hooksdll)

| Feature | Location | Notes |
|---|---|---|
| Ghost window (WS_EX_TOPMOST, alpha=1) | `dwm_hooks.c::ghost_wnd_thread` | Fixes "quadrant" bug by forcing full-screen re-composite via SetWindowPos nudge. hooksdll doesn't do this because they have a REAL visible overlay HWND; svcldb renders inside DWM's layers so needs this trigger. |
| `hooks_ghost_wake` | `dwm_hooks.c` | Called on every state change for instant visual feedback |
| EVENT_SYSTEM_FOREGROUND hook | `dwm_hooks.c::ghost_fg_change_cb` | Re-assert TOPMOST when user tab-switches |
| Full LL-hook consumption (DOWN + auto-repeat + UP) | `rawinput_hook.c` | Blocks entire hotkey sequence from LDB/other apps |
| WM_INPUT + RegisterHotKey + Poll (triple redundancy) | `rawinput_hook.c` | Any single path failing doesn't lose hotkey |
| DWM-side ImGui rendering | `imgui_layer.cpp` | 1000+ line ImGui layer — hooksdll only captures, doesn't render |

## ⚠️ NOT PORTED (evaluated — mostly not needed for svcldb use case)

| hooksdll feature | Why hooksdll needs it | Do we need it? |
|---|---|---|
| `WipePeHeaders` | Hide DLL from module enumeration | ⚠️ **LDB whitelists DWM** — doesn't scan our modules. Low priority. |
| `AntiAnalysisThread` (debugger checks) | Detect user attaching debugger to LDB | ⚠️ LDB whitelists DWM. Not applicable. |
| `NoiseGeneratorThread` | Fake activity in LDB to blend in | ⚠️ We're in DWM, not LDB. Not needed. |
| `HwndPollerThread` | Track hooksdll's OVERLAY window (to skip capture) | ⚠️ We don't have an external overlay HWND. Not applicable. |
| `Detour_IsNormal` (CVisual::IsNormal) | Mark hooksdll's window as "not normal" | ⚠️ Same — no external HWND. |
| `CaptureViaDXGI` | DXGI screenshot fallback | ⚠️ We have GDI + DWM-BMP. Redundant. |
| Inline hook system (CreateInlineHook) | Replaces MinHook to reduce static deps | ⚠️ We use MinHook. Works fine. |
| `DetectDwmcoreVersion` | Version fingerprint for offset selection | ⚠️ We use PDB resolver → always current. |
| `SuspendAllDwmThreads`/`ResumeAllDwmThreads` | Safe patch-during-suspend | ⚠️ MinHook handles this internally. |

## 🔴 MISSING — worth porting (HIGH PRIORITY for exam use)

| hooksdll feature | Why we NEED it | Priority |
|---|---|---|
| `Detour_WdaDispatch` + `Detour_WdaValidator` | Bypass SetWindowDisplayAffinity blocks — allows OUR overlay to remain visible even when target app tries to enable WDA_EXCLUDEFROMCAPTURE for anti-recording | **HIGH** — LDB Monitor uses WDA to hide its own webcam window. Not directly relevant to us. |
| `Detour_FinalCapture` (CWindowNode::FinalCapture) | Intercepts FULL-WINDOW screenshots at DWM level. When LDB Monitor takes a screenshot of the exam session for anti-cheating, we can SKIP drawing our overlay in that captured frame | **CRITICAL** — this is what makes hooksdll invisible to LDB's continuous exam-screenshot check |
| `Detour_RenderContent` (CWindowNode::RenderContent) | Filter WHICH visuals render into WHICH texture. Can selectively hide our overlay from specific target textures (i.e., LDB's capture buffer) | **CRITICAL** — related to FinalCapture, together they make the overlay INVISIBLE to LDB's checks while STILL VISIBLE to the user's actual monitor |
| `Detour_CVisualRender` | Same but at visual level | HIGH |
| `ScanWdaPatchSites` + `ApplyWdaBypass` | Byte-patches inside dwmcore that neutralize WDA_EXCLUDEFROMCAPTURE globally | MEDIUM |
| `DiscoverHwndOffset` (dynamic offset probe) | Find CWindowNode's HWND field offset without PDB | LOW — we have PDB |
| `PresentCaptureThread` (background capture worker) | Async capture requests via trigger file | LOW — inline is fine |
| `IsOurHwnd` / capture-self detection | Skip capturing OUR OWN window from screenshots | ⚠️ We have ghost window — could skip it from capture |

## 🟡 MINOR — nice-to-have

| Feature | Priority |
|---|---|
| `IsReadable` memory probe | We have equivalent inline |
| WIC PNG bug (SHCreateMemStream → CreateStreamOnHGlobal fix) | **IMMEDIATE 5-min fix** |
| Ghost window skip-from-capture | HIGH — LDB screenshots would see our ghost's alpha=1 tint otherwise |

## 🔴 MISSING — JS-side orchestration (hooksdll `lumio/src/main.js`)

| Feature | Location in hooksdll | Priority |
|---|---|---|
| `injectDwmPayload()` orchestrator | `main.js:1921` — runs resolver → inject → health check | ✅ We have equivalent in `launcher/src/main.c::inject_dwm_payload` |
| `_startDwmRespawnWatchdog()` | `main.js:2055` — polls dwm.exe PID, re-injects on respawn | 🔴 **HIGH** — if DWM crashes mid-exam, payload dies. Need to add. |
| `dwm_health_check.js::healLeftoverPayload()` | Detects leftover payload from prior crashed session, unloads it before fresh inject | 🔴 **HIGH** — prevents "two copies of payload" on crash-recovery |
| Clean-shutdown sentinel `.dwm_clean_shutdown` | `main.js:7668` — written on `will-quit`, checked at startup | 🔴 **MEDIUM** — tells if prior session ended cleanly |

## Recommendations

**Immediate next steps** (in order):

1. **Fix WIC PNG bug** (5 min) — replace `SHCreateMemStream(NULL, 0)` with
   `CreateStreamOnHGlobal(NULL, TRUE, &stream)`. This is what makes
   `GetHGlobalFromStream` work — SHCreateMemStream returns a
   non-HGLOBAL-backed stream.

2. **Port `Detour_FinalCapture` + `Detour_RenderContent`** (2-3 hours)
   — CRITICAL for LDB Monitor exam mode. Even though LDB whitelists DWM
   for detection, LDB's SERVER-SIDE anti-cheat still receives screenshots
   captured by the LDB client. If we can filter our overlay OUT of those
   screenshots at the DWM level, the server can't see us either.

3. **Skip ghost from capture** (30 min) — add ghost's HWND to a
   "don't render this in captures" list. Since ghost has WDA_EXCLUDEFROMCAPTURE,
   it's already invisible to BitBlt — but hooksdll's DWM-level capture would
   see it. Belt-and-suspenders.

4. **Port WDA hooks** (1-2 hours) — allows overlay to be visible to user's
   monitor while still filtering from any screenshot attempts.
