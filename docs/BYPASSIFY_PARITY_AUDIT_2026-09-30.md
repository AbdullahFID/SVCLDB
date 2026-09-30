# Bypassify vs svcldb -- full 1:1 decompiled parity audit (2026-09-30)

Source: `launchhere (3).exe` (Bypassify Windows, 3.75 MB, 2026-09-30 build --
newer than the July builds we RE'd). Payload extracted from RCDATA id=101
(`bp_payload_new.dll`, 937,984 B) + resolver id=102 + bundled `dbghelp.dll`
(id=104) + `symsrv.dll` (id=103). Decompiled in Ghidra (`C:\ghidra_dl\project_bp`,
scripts `BPDump*.java`/`BPDetours.java`/`BPStealth.java`, raw output
`C:\ghidra_dl\bp*.out`). BP's blob confirmed LIVE-resolved on this box
(`C:\WDFRes\offsets.blob`).

## Verdict
**svcldb is at 1:1 parity with Bypassify on every load-bearing subsystem, and a
SUPERSET in several.** The only place BP is ahead is stripped debug strings
(a static-analysis fingerprint). Everything that makes BP "the GOAT" -- the
render acquire, the compose-wake trick, the hooks, the input, the overlay -- we
match exactly, verified by decompile.

## Subsystem-by-subsystem (all decompile-verified)

| Subsystem | Bypassify | svcldb | Verdict |
|---|---|---|---|
| Offset resolution | native resolver + bundled dbghelp+symsrv, PDB from `msdl.microsoft.com`, by-name, writes `C:\WDFRes\offsets.blob`, **re-resolves every launch** | our resolver, same dbghelp+symsrv+PDB+by-name, writes `offsets.blob` | **identical** |
| Resolved RVAs (live, same dwmcore) | Present 0x22C490, PN1 0x1B4998, PN2 0x1B49CC, IOP 0x1E74A0, FFD 0x411A69, SCP 0x11F1CC | **byte-identical** | **identical** |
| Hook engine | MinHook, manual-mapped, **thread-freeze** (Freeze/ProcessThreadIPs: suspend all threads + relocate RIPs on enable/disable) | MinHook (`shared/minhook`), same Freeze/EnumerateThreads/ProcessThreadIPs | **identical** |
| Hook set | **4 MinHooks**: Present, PN1, PN2, IsOverlayPrevented | **4 MinHooks** (v7.9: IOP moved byte-patch -> MinHook); RenderContent/WDA/Present-RT were already stripped v1.7.9/v11.2.2 | **identical (v7.9)** |
| Render acquire | `pLayer.vtbl[5]`=getDevice, `[24]`=GetPhysicalBackBuffer, buffer`[19]`=GetD3D11Resource; `this=pLayer` adj 0; **no MI-walk, no fallback** (skips draw if GPB NULL) | same primary chain **+ legacy-getter-by-name + g_legacy_rt dummy anchor + surface-hunter** | **svcldb superset** |
| Present detour | draw-into-layer BEFORE orig, SEH-guarded, skip on shutdown flag | same | identical |
| PN1/PN2 detour | call orig -> if !shutdown: ScheduleCompositionPass(0,-1) + return TRUE (force continuous compose) | same (`Detour_DisplayPresentNeeded`/`Detour_LegacyPresentNeeded`) | identical |
| IsOverlayPrevented | MinHook detour -> return TRUE while running (skips orig) | **v7.9 MinHook detour -> call orig (preserve init side-effect) THEN force TRUE** | **svcldb parity+ (safer)** |
| ForceFullDirty | byte-patch flag=1 init / 0 shutdown | same byte-patch (bool-guarded) | identical |
| Shutdown | set flag -> revert FFD byte -> CreateThread(sleep 200ms -> MH_Disable -> MH_Uninitialize) | same (`hooks_uninstall` + drain) | identical |
| TDR resilience | `GetDeviceRemovedReason` (slot 39) every frame, skip render if removed | same (v1.7.10.4) | identical |
| Explorer restart | cache Progman HWND via `FindWindowA("Progman",...)`, re-acquire when `!IsWindow` | same | identical |
| Capture-stealth | Present-detour state machine (`defd8` 0->1->2), screenshots into a 6-slot vector | same concept (capture-active gate + debug-capture) | identical |
| Input | **WH_KEYBOARD_LL + WH_MOUSE_LL + RegisterRawInputDevices(RIDEV_INPUTSINK)** into hidden window `"MSDiagEventSink"`, `ToUnicodeEx` | LL keyboard + raw input + hidden window (`rawinput_hook.c`) | **identical mechanism** |
| Secure/isolated desktop | LL hooks on the payload's own desktop only -- **no winlogon helper found in the payload** | **winlogon-hosted `wl_input.c` helper forwards raw input over a pipe on ANY active desktop** | **svcldb superset (SEB/secure-desktop)** |
| Overlay UI | ImGui 1.92.6, **DPI-scaled font** (16 x h/900), arial->msyh->malgun | ImGui, DPI-scaled font (`FontGlobalScale = screen_h/1080`) | parity (divisor differs; BP ~20% larger) |
| Hotkey glide | time-based interpolation (smooth at any refresh) | **v7.9: frame-time-independent integrator (QPC + fixed 1/120s substeps)** -- was fixed-per-frame (the stutter) | **parity (v7.9)** |
| Auto theme | reads `HKCU\...\Personalize\AppsUseLightTheme` | same (auto-theme repoll) | identical |
| Licensing | device-lock on `HKLM\...\Cryptography\MachineGuid`, 14-day switch cooldown, BCrypt device key, WinHttp | HWID (`shared/hwid.c`) + Supabase auth | different impl, same intent |
| Anti-debug | none beyond CRT `__report_gsfailure` (IsDebuggerPresent = GS-failure path) | comparable | parity |
| Crash resilience | (not observed) | **SAFE-MODE blob validation + crash-loop firewall (.dwm_user_panic) + present-fire canary** | **svcldb superset** |
| Debug strings in payload | **STRIPPED** (no `[DWM]` flow logs) | plaintext `get_backbuffer_texture`/`ImGui READY`/`legacy-hunt`/... | **BP ahead (fingerprint)** |

## The one genuine gap (BP ahead): stripped debug strings
Our payload ships plaintext diagnostic format strings that name exactly what we
do (`GetPhysicalBackBuffer`, `dwmcore`, `ImGui READY`, `legacy-hunt`, `SAFE-MODE`).
`strings dwmapiext.dll` reveals the whole technique to any analyst; BP's payload
has none. **Deferred, on purpose:** those strings are the instrument we're using
to debug the 9550-legacy render issue right now -- stripping them mid-investigation
blinds us. Close it after the legacy-render issue is fully resolved (gate the
`diag()` format strings through the existing `str_enc` XOR system, or compile them
out in the shippable build).

## Where svcldb is AHEAD of BP
- **Secure/isolated-desktop input** (winlogon `wl_input.c` helper) -- BP's payload
  only LL-hooks its own desktop; if SEB uses a separate secure desktop, BP's
  hotkeys wouldn't fire there. Confirm on the replica laptop.
- **Dummy-box render fallback** (`g_legacy_rt` anchor + legacy-getter-by-name) --
  BP skips the draw when GetPhysicalBackBuffer NULLs; we try the render target's
  own fullscreen swapchain first.
- **Crash resilience** -- SAFE-MODE blob validation, crash-loop firewall,
  present-fire canary. BP has none observed.

## v7.9 changes (this audit's actions)
1. **Nudge glide -> frame-time-independent** (`imgui_layer.cpp`): QPC-measured real
   dt integrated in fixed 1/120s substeps; kills the frame-time-variance stutter
   LO saw next to BP. Display-validated; smoothness confirmed by LO.
2. **IsOverlayPrevented -> MinHook** (`dwm_hooks.c`): retired the byte-patch +
   prologue-shape detection (behind `g_iop_byte_patch_retired`); added
   `Detour_IsOverlayPrevented` (call orig -> force TRUE while active). Gains
   prologue-agnostic robustness AND MinHook's thread-freeze install safety (the
   byte-patch never had thread-freeze -- this is why it could AV mid-compose).
   Display-validated: `IsOverlayPrevented hooked (MinHook)` -> `LOCKED` ->
   `ImGui READY`, DWM stable.
3. Hook-count audit: svcldb already hooks only 3 (the "9 hooks" was the hooksdll
   project); with v7.9 IOP-MinHook we're at BP's exact 4-hook model.
