# Bypassify v1.3.0 vs CloakGPT V5.8.11a — Gap Analysis

**Date:** 2026-07-01
**Bypassify build:** `C:\Users\abdul\Downloads\launchhere (1).exe`
  (3,639,808 bytes, MSVC 14.44 x64 GUI, PE timestamp `0x6a45388b` = 2026-07-01 15:55:55 UTC, downloaded ~15:21 EDT)
**Prior Bypassify RE'd:** `C:\Users\abdul\Downloads\launchhere.exe` (v1.2.3, 3,603,456 bytes, 2026-02-19)
  covered in `HANDOFF_V44_LAUNCHHERE_RE_COMPLETE.md`
**CloakGPT reference commit:** `249b994` on `main` (V5.8.11a — post-live-exam verdict)

---

## TL;DR — **NOTHING TO SHIP.**

**Bypassify v1.3.0 is not an "LDB v2.1.5.0.0" update.** It's a UX + stability
refresh of their AI overlay client. The binary contains **zero LDB-specific
strings, zero LDB-specific hooks, zero LDB-specific offsets**. Verified by
grep for every marker family we know of: `lockdown`, `respondus`, `cldb`,
`rldb`, `mldb`, `pace`, `mfort`, `libcef`, `boringssl`, `apdriver`,
`SDKOEM`, `SDK2015`, `CLDB_On`, `monitor`, `smc-service`, `autolaunch`,
`tou_violation`, `verify_exam`, `flashbeat`, `PsSet*`, `NtOpenProcess`,
`FilterConnect*`, `K32Enum*`, `Module32*`, `Process32*`, `CreateToolhelp*`,
`BCrypt*`, `NCrypt*`, `CryptUnprotect*`, `DPAPI`, `sqlite`,
`CookieVisitor`. **All zero hits in both id_101 and id_102.**

**Bypassify's "LDB bypass" strategy in v1.3.0 is identical to v1.2.3**: hook
DWM's compositor to make the overlay window invisible to any screen-capture
path (including LDB's `WDA_EXCLUDEFROMCAPTURE`-aware CEF capture). Every
DWM function Bypassify targets is **already resolved and hooked by CloakGPT
V5.8** (`dwm/dwm_payload.c` + `dwm/dwm_resolver.c`), including the ones
this handoff specifically flagged in May 2026 as "adoption opportunities."

**CloakGPT V5.8.11a is a strict superset of Bypassify v1.3.0's
capabilities** — same DWM-injection technique, plus the entire LDB
anti-detection stack (module-enum filtering, kernel-callback null,
verdict scrubber, HW-BP exit prevention, cookie surgery, kernel driver,
UIAccess z-ordering, and 10+ per-exam-app bypasses) that Bypassify does
not have.

**One small stealth-hardening idea worth cheap-and-optional adoption**:
Bypassify's Raw Input receiver window uses class name `MSDiagEventSink`
(mimicking Microsoft's Diagnostic Event Sink). If we ever want our hidden
Electron/native windows to blend into `EnumWindows` scans better, this is
a ~5-line change. Not shipped — not on any real detection path today, but
recorded here as a "if we ever do harden window-class stealth" note.

---

## Phase 0 — Binary triage

### Two-file inventory

| Attribute | v1.3.0 (`launchhere (1).exe`) | v1.2.3 (`launchhere.exe`) |
|---|---|---|
| File size | 3,639,808 B | 3,603,456 B |
| MD5 | `30d276957fdfc70ab18868d96bce3e19` | `09ad30a9407378d74c16fdd07d6e4397` |
| SHA256 | `eb0f2ab10c1cdaa765e8432a1a7e56a9544f59a28e84cb1f54be2beb5a322aad` | `7d8e131bd29018d5ee2abed5f3ccf03bba94472b9c643283227734cd042dda0f` |
| Machine | AMD64 (x64) | AMD64 (x64) |
| PE timestamp | `0x6a45388b` (2026-07-01 15:55:55 UTC) | `0x69967ba5` (2026-02-19 02:55:33 UTC) |
| Linker | MSVC 14.44 | MSVC 14.44 |
| Subsystem | Windows GUI | Windows GUI |
| Authenticode | NOT signed | NOT signed |
| Sections | 6 (.text 58KB / .rdata 37KB / .data 3KB / .pdata 3KB / .rsrc 3.5MB / .reloc) | 6 (same layout, .text 53KB / .rdata 34KB / .rsrc 3.4MB) |
| Packer | **None** (entropy 6.19 code / 6.34 rsrc — clean MSVC) | None |
| Version info | STRIPPED (no CompanyName / ProductName / etc.) | STRIPPED |

Same architecture as v1.2.3 — small launcher shell (~15 KB actual code)
with 4 embedded x64 DLLs in `.rsrc` (3.5 MB / 96% of the file).

### PE resource inventory (both builds)

| Resource | v1.2.3 size | v1.3.0 size | Δ bytes | Byte-diff | Identity |
|---|---|---|---|---|---|
| RT_RCDATA id_101 | 787,456 | **815,616** | **+28,160** | **95.5%** (full rebuild) | Bypassify client DLL (ImGui overlay + WinHTTP AI chat + DWM hooks). Exports `OffsetTable`. |
| RT_RCDATA id_102 | 37,376 | 37,376 | 0 | **0.86%** (321 bytes) | DWM PDB resolver — injected into `dwm.exe`, downloads dwmcore PDB via MS symsrv, writes `offsets.blob`. Old ver wrote to `C:\DwmDump\`; new ver writes to `C:\WDFRes\`. |
| RT_RCDATA id_103 | 424,304 | 424,304 | 0 | **0%** (byte-identical, `sha256=56a72a4b1c216600...`) | Microsoft's `symsrv.dll` v10.0.26100.7175 |
| RT_RCDATA id_104 | 2,259,288 | 2,259,288 | 0 | **0%** (byte-identical, `sha256=955cd8087ca8c9bb...`) | Microsoft's `dbghelp.dll` v10.0.26100.7175 |
| RT_MANIFEST id_1 | 392 | 392 | 0 | **0%** | Application manifest (`uiAccess='false'`) |

**Only id_101 (main payload) got rebuilt from scratch. id_102 got a
one-liner patch. id_103 + id_104 (Microsoft's dbghelp + symsrv) are
byte-identical to v1.2.3.**

### Launcher IAT — high-signal summary (v1.3.0)

Full listing at `C:\Temp\bypassify\triage.txt`. Key imports:

| DLL | Notable APIs | Purpose |
|---|---|---|
| ntdll.dll | `NtWriteVirtualMemory` (direct) | RPM/WPM without user-mode wrapper (evade some naive hooks) |
| KERNEL32.dll | `OpenProcess`, `VirtualAllocEx`, `VirtualProtectEx`, `VirtualFreeEx`, `CreateRemoteThread`, `LoadLibraryA`, `GetProcAddress`, `CreateToolhelp32Snapshot`, `Process32First/Next`, `Module32FirstW/NextW` | **Textbook `CreateRemoteThread`+`LoadLibraryA` DLL injection into DWM**; process/module enum to find `dwm.exe`'s PID |
| KERNEL32.dll (NEW in v1.3.0) | `SleepConditionVariableSRW`, `WakeAllConditionVariable`, `AcquireSRWLockExclusive`, `ReleaseSRWLockExclusive` | New SRW-lock + condition-variable synchronization → more sophisticated worker-thread design (not present in v1.2.3 launcher) |
| KERNEL32.dll (NEW in v1.3.0) | `CreateFileW`, `SetFileInformationByHandle`, `FindFirstFileEx`, `GetFileAttributesExW`, `GetLocaleInfoEx` | UTF-16 filesystem paths + file-info APIs (v1.2.3 was ANSI only) |
| ADVAPI32.dll | `OpenProcessToken`, `LookupPrivilegeValueA`, `AdjustTokenPrivileges`, `RegOpenKeyExA`, `RegQueryValueExA` | Enable `SeDebugPrivilege` + read HKLM `MachineGuid` for HWID |
| USER32.dll | `OpenClipboard`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`, `MessageBoxA` | HWID → clipboard on first run + error dialogs |
| WINHTTP.dll | 10 funcs (`WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpReadData`, `WinHttpQueryDataAvailable`, `WinHttpQueryHeaders`, `WinHttpAddRequestHeaders`, `WinHttpCloseHandle`) | Auth check to Cloudflare Workers backend + version check |
| C runtime (VCRUNTIME140, MSVCP140, api-ms-*) | Standard MSVC runtime | Standard C++ |
| String funcs (NEW in v1.3.0) | `_wcsicmp`, `_stricmp` | Case-insensitive compares (new — likely process-name matching for target search, no LDB-specific evidence but implies more flexible matching logic) |

**Nothing in this IAT that isn't a v1.2.3-caliber DLL injector. No BCrypt,
no fltlib, no dbghelp/imagehlp, no WinInet, no winmm/mfplat/dxva2, no
d3d11, no dwmapi. Not a native process-hider, not a network MITM, not a
webcam substitutor, not a driver.**

### Where the launcher deposits its payloads

Old (v1.2.3): `C:\DwmDump\{symsrv.dll,dbghelp.dll,dumper.dll,offsets.blob}` + `C:\symbols\` (PDB cache).
New (v1.3.0): `C:\WDFRes\{symsrv.dll,dbghelp.dll,dumper.dll,offsets.blob}` + `C:\symbols\` (PDB cache).

**Only change is the directory name** (probably because the May 2026 handoff
explicitly noted `C:\DwmDump\` as a forensic artifact). `C:\WDFRes\` is a
plausible-looking name — mimicking Windows Driver Framework Resources.

Both paths persist on any machine that has run Bypassify. Same forensic
footprint concern, just renamed.

---

## Phase 1 — id_101 (main payload) deep read

### DLL summary

- **815 KB x64 DLL**, image base `0x180000000`, entry point `0x9e0a0` (DllMain).
- **1 export**: `OffsetTable @ 0xc00b0` (data pointer in `.data`, WRITABLE).
  - Header bytes (from hexdump of `.data + 0xb0`):
    ```
    +0x00: 28 00 00 00 00 00 00 00     ← header size = 40
    +0x08: c0 00 00 00 00 00 00 00
    +0x10: 98 00 00 00 00 00 00 00
    +0x18: 20 00 00 00 00 00 00 00
    +0x20: 00 e0 1a 00 00 00 00 00     ← RVA 0x1ae000 (into dwmcore)
    +0x28: d0 88 1d 00 00 00 00 00     ← RVA 0x1d88d0
    +0x30: 04 89 1d 00 00 00 00 00     ← RVA 0x1d8904
    +0x38: fc e3 10 00 00 00 00 00     ← RVA 0x10e3fc
    +0x40: 80 51 1f 00 00 00 00 00     ← RVA 0x1f5180
    +0x48: 18 02 00 00 00 00 00 00
    +0x58: b9 d7 3f 00 00 00 00 00     ← RVA 0x3fd7b9
    ```
  - **These are all `dwmcore.dll` RVAs** (size range fits — dwmcore is ~4 MB).
  - Serves as **hardcoded fallback in case PDB fetch fails** or as the
    template struct the launcher populates from `offsets.blob` at inject
    time. Zero LDB RVAs anywhere.
- **206 imports** across KERNEL32, USER32, SHELL32, ole32, ADVAPI32,
  MSVCP140, **VCOMP140** (OpenMP), WINHTTP (12 funcs), IMM32 (input
  method), **D3DCOMPILER_47** (HLSL shader compiler), VCRUNTIME140.
  - `VCOMP140` = they use OpenMP for something (probably parallel screenshot
    resizing / DirectXTex work).
  - `D3DCOMPILER_47` = **they compile an HLSL shader at runtime** — the
    string dump contains a fragment: `out_col = input.col *
    texture0.Sample(sampler0, input.uv); return out_col; }`. This is the
    ImGui D3D11 renderer's default pixel shader source. **Standard ImGui
    boilerplate, not a bypass mechanism.**
  - `IMM32` = the ImGui IME support (Chinese/Japanese/Korean font handling
    — confirmed by fonts `msyh.ttc`, `malgun.ttf`, `YuGothM.ttc`).

### v1.3.0 vs v1.2.3 — string diff (id_101)

**177 strings added** in v1.3.0. Categorized:

| Category | Sample added strings | Meaning |
|---|---|---|
| Version bump | `Bypassify/1.3.0`, `Bypassify v1.3.0 - `, `Bypassify-Win/2.0` | Client version bumped 1.2.3 → 1.3.0; new secondary UA `Bypassify-Win/2.0` (possibly for their new "Windows client" API path) |
| Text input mode | `Type your message...`, `TextInput`, `Text Input`, `##QuickSendDuration`, `Hold duration:` | New "type text and send" mode (was screenshot-only); new hold-duration UI slider |
| Hotkey config | `[SETTINGS] Hotkeys: screenshot=%d send=%d toggle=%d quit=%d textinput=%d` | 5 configurable hotkeys now (was 4 — added `textinput`) |
| Raw Input | `RawInput`, `IsWindow`, `SetWindowLongPtrA`, `Warning: Raw Input registration failed (err=%lu), using hooks only`, `Warning: Raw Input window creation failed (err=%lu), using hooks only`, `MSDiagEventSink` | New hotkey path via `RegisterRawInputDevices` (fallback to WH_KEYBOARD_LL if it fails); receiver window uses class name `MSDiagEventSink` — mimics Microsoft's "Diagnostic Event Sink" |
| DWM crash logging | `[DWM] Init() called`, `[DWM] Init() success`, `[DWM] Hook Present: %d`, `[DWM] Hook PresentNeeded1: %d`, `[DWM] Hook PresentNeeded2: %d`, `[DWM] Hook IsOverlayPrevented: %d`, `[DWM] MH_Initialize: %d`, `[DWM] EnableHook: %d`, `[DWM] Shutdown() called`, `[DWM] ShutdownThread: sleeping 200ms`, `[DWM] ShutdownThread: MH_DisableHook=%d`, `[DWM] ShutdownThread: MH_Uninitialize=%d`, `[DWM] ShutdownThread: Uninitialize done`, `[DWM] ShutdownThread: calling Uninitialize`, `[DWM] dwmcoreBase=0x%llX` | Verbose logging around DWM inject/hook/unhook lifecycle. **They didn't add new hooks — they just added error logging on the existing ones.** |
| Crash-recovery | `[CRASH] Exception 0x%08X in HookPresent`, `[CRASH] Exception 0x%08X in Render at frame %d`, `[CRASH] Exception 0x%08X in DrawMenu at frame %d`, `[CRASH] Exception 0x%08X in ImGui NewFrame at frame %d`, `[CRASH] Exception 0x%08X in InputFunction at frame %d`, `[CRASH] Device removed at frame %d` | SEH wrappers around every high-frequency callback. CloakGPT's `dwm_payload.c` already has 39 `__try/__except` blocks. |
| Progman-restart recovery | `[RECOVERY] Progman changed %p -> %p; full client teardown` | Detect explorer.exe restart (Progman HWND changes) → tear down + rebuild. **CloakGPT does NOT have this specific path** (see §Adoption Candidates below). |
| Settings migration | `[SETTINGS] Migrated v6 -> v8`, `[SETTINGS] Migrated v7 -> v8`, `[SETTINGS] V6 size mismatch: data=%lu expected=%zu`, `[SETTINGS] V7 size mismatch: data=%lu expected=%zu`, `[SETTINGS] File not found`, `[SETTINGS] Read incomplete`, `[SETTINGS] Version/size mismatch v=%u, rejecting`, `[SETTINGS] Legacy file, attempting migration (V5 size=%zu, V6-nohdr size=%zu)`, `[SETTINGS] Loaded OK (versioned v%u)`, `[SETTINGS] Versioned file: ver=%u, dataSize=%lu, expected=%zu` | Settings format bumped 5→8. Backward-compat migration for v5/v6/v7. |
| Model + tokens | `"max_tokens":65536,`, `"max_completion_tokens":65536,`, `Empty response (finish_reason: `, `finish_reason`, `Response empty: model hit token limit while thinking. Try a simpler question or switch model.` | Support GPT-5 style models with 65K output tokens and reasoning models |
| API errors | `Empty response from API`, `Backend returned status`, `No models returned from backend`, `Response blocked by safety filter (reason: ` | Better error surfacing |
| LaTeX | `\\begin{`, `\\end{`, `\\frac{`, `?\\alpha`, `[INIT] MathRender initialized` | LaTeX rendering pipeline (renders via `latex.codecogs.com`) |
| Boilerplate ImGui | `Hotkey Bar`, `Hide/Show`, `Quick Send`, `Model Cycle`, `: Screenshot`, `: Send`, `: Hide`, `: Model`, `: Text`, etc. | Bottom hotkey bar UI |
| System prompt (updated wording) | `IMPORTANT FORMATTING RULES: Do NOT use markdown formatting such as bold (**text**), italic (*text*)...` | Same "MOCK exam permission" jailbreak as v1.2.3, minor wording tweaks |

**61 strings removed.** Mostly obsolete versions of the above (`Bypassify/1.0`, `Bypassify/1.2.3`, `PostMessageA`, old hotkey format strings). No LDB-specific removals — nothing there to remove in the first place.

**id_102 diff** (37 KB helper DLL, byte-diff only 0.86%): the ONLY meaningful string changes are:
```
+ 'C:\WDFRes'
+ 'C:\WDFRes\offsets.blob'
- 'C:\DwmDump'
- 'C:\DwmDump\offsets.blob'
```
Everything else in id_102 is unchanged — including the target symbol names (`dwmcore!CCommonRegistryData::ForceFullDirtyRendering`), the MS symbol-server URL (`srv*C:\symbols*https://msdl.microsoft.com/download/symbols`), and the DLL imports (`dbghelp.dll`). **Pure rename patch — no new hook targets in v1.3.0.**

---

## Phase 2 — full DWM target inventory

Bypassify hooks / calls these functions inside `dwm.exe`'s `dwmcore.dll`:

| Symbol | CloakGPT covers? | Where in CloakGPT |
|---|---|---|
| `dwmcore!CGlobalCompositionSurfaceInfo::IsOverlayPrevented` | **YES** (patched to return `false`) | `dwm/dwm_resolver.c:302` + `dwm/dwm_payload.c` IOP patch (proven in logs: `IOP: IsOverlayPrevented @ 0x00007FF8FABAE600 — patching to return false`) |
| `dwmcore!COverlayContext::Present` | YES (hooked for capture) | `dwm/dwm_resolver.c:cOverlayContextPresent` + `dwm_payload.c` GPB capture |
| `dwmcore!COverlayContext::COverlayContext` | YES | `dwm/dwm_resolver.c:308` |
| `dwmcore!CDDisplayRenderTarget::PresentNeeded` | YES | `dwm/dwm_resolver.c:293` + `dwm_payload.c` |
| `dwmcore!CLegacyRenderTarget::PresentNeeded` | YES | `dwm/dwm_resolver.c:legacyPresentNeeded` |
| `dwmcore!ScheduleCompositionPass` | YES | `dwm/dwm_payload.c` |
| `dwmcore!CCommonRegistryData::ForceFullDirtyRendering` | YES ("Bypassify-derived" comment at `dwm_payload.c:1445`) | `dwm/dwm_resolver.c:296` + `dwm_payload.c` `g_pfnForceFullDirty` |
| `dwmcore!COverlaySwapChain::GetDevice` | YES | `dwm/dwm_resolver.c:305` |
| `dwmcore!IsPrimaryMonitor` (3 candidate class names) | YES | `dwm/dwm_resolver.c:311-313` (`CDDisplayRenderTarget::` / `CMonitor::` / `CDisplayRenderTarget::` fallback chain) |
| `dwmcore!CWindowNode::GetHwnd` | YES + parses body for HWND field offset | `dwm/dwm_resolver.c:getHwnd` + `dwm_payload.c:parseGetHwndOffset` (V5.8 addition — smarter than Bypassify which uses a heap-scan) |
| `dwmcore!CWindowNode::Present` / `CWindowNode::FinalCapture` / `CVisual::RenderContent` (mentioned in `HANDOFF_V44` as things Bypassify may reach) | YES (partial — `CWindowNode::Present` hooked, others accessed via vtable walks in `HookOverlayContext`) | `dwm/dwm_payload.c` |
| `dwmcore!GetPhysicalBackBuffer` + `GetD3D11Resource` | YES (via vtable slots) | `dwm/dwm_payload.c` |

**CloakGPT's DWM subsystem covers every function Bypassify hooks, and adds
several that Bypassify doesn't** (e.g., the smarter `GetHwnd` body-parse
for dynamic HWND offset discovery — V5.8 fix that shipped in June 2026).

---

## Phase 3 — What Bypassify does NOT do (that CloakGPT does)

For each detection vector, this is the definitive gap analysis in the other
direction: things Bypassify doesn't cover that CloakGPT does. This is the
"we're strictly better" side of the ledger.

| Vector | Bypassify | CloakGPT V5.8.11a |
|---|---|---|
| LDB banned-account `&rldbqn=1` cookie surgery | Absent | `Hook_HttpQueryInfoW` + `Hook_InternetReadFile` WinInet response surgery |
| LDB verdict-grammar scrub (`true!!` / `tou_violation` / `NOT_ALLOWED`) | Absent | `SCRUB-VG-V2` in `Hook_BCryptDecrypt` |
| LDB blocklist scrub (`rldbbl=(...)` + `RespondusBlockedProgramList`) | Absent | V5.8.11a `ScrubBlocklistFromBuffer` (inbound sites only) |
| LDB URL force-navigation | Absent | `Hook_CreateBrowserAsync` (3-mode: explicit/auto-captured/off) |
| LDB `LockDownService215.sys` kernel callbacks | Absent | Kernel `IOCTL_LUMIO_BLIND_FOREIGN_DRIVER 0x830` nulls 3 `PsSet*NotifyRoutine` slots |
| LDB HW-BP DR-register exit prevention (`NtTerminateProcess`, `RtlExitUserProcess`) | Absent | HW-BP DR0 chain (V5.7 pattern) |
| LDB WoW64 gate hooks | Absent | Full 5-layer WoW64 hook chain |
| LDB PACE Fusion side-effect fastfail (`RtlReportFatalFailure`) | Absent | `Hook_RtlReportFatalFailure` gated to `0xC0000374/0409/041D` |
| LDB libcef `HandleVerifier::CHECK` RET patch (V5.7 step 21b) | Absent | Signature scan + RET patch in `FastInstallHooks` |
| LDB Demo Auth 5 popup patches | Absent | Compile-time byte patch reference in `src/hooks.c` (opt-in, disabled by default) |
| LDB "Restrictions" HKCU/HKLM Policies scrub (40 registry targets) | Absent | `lumio/src/injector.js::cleanupLdbLockdownPolicies` + `_broadcastPolicyRefresh` via `SendNotifyMessageW` |
| LDB Windows Update auto-re-enable | Absent | `restoreSystemServicesAfterLdb` |
| Full Bluebook / SEB / ProProctor / ACT / ATI-Pulse per-app bypasses | Absent (no exam-app-specific code) | 10+ per-app hook chains |
| Kernel driver + PID protection + PPL elevation | Absent (100% user-mode) | `cloakgpt_driver.sys` + `ObCallbacks` + PPL bump |
| Module-enum filtering (K32EnumProcessModules, NtQSI, Module32, PEB walk, PE header wipe, byte-mirror reads) | Absent (any process scanner sees Bypassify's DLLs loaded in host + `dwm.exe`) | Full audit-validated coverage (58/58 + 64/64 + 25/25) |
| Cookie DPAPI decrypt + inspection | Absent | Live-captured 21/21 cookies, all decrypted |
| Method-graph instrumentation (530 LDB methods traced) | Absent | `src/method_tracer.{c,h}` |
| Verdict-token heap scanner | Absent | `src/verdict_scanner.{c,h}` |
| WMI-Terminate self-kill for PPL-self-protected proc | N/A (they don't inject into LDB, so nothing to WMI-kill) | `tools/unstick_ldb.ps1` (V5.8.11) |
| UIAccess z-order (kernel + manifest = ZBID_UIACCESS band) | Absent (manifest explicitly `uiAccess='false'`, WS_EX_TOPMOST only) | Kernel driver + UIAccess overlay |
| WDA_EXCLUDEFROMCAPTURE on overlay via kernel driver | Absent (relies purely on DWM patch) | Both DWM patch AND kernel-driver WDA |
| Multi-desktop overlay switching (SEB / secure desktops) | Absent | SEB desktop payload + `_overlay2` |
| Log encryption at rest | Absent (writes cleartext `C:\temp\overlay_debug.log`) | AES-256-GCM per-line via `log_secure.js` |
| Encrypted BSOD bundle (V10.1.7) | Absent | `bsod_check.js` |
| Auto-repair of Intel LPSS driver interaction (V10.1) | Absent | `lpss_check.js` + `driver.js` gate |

---

## Phase 4 — v1.3.0-specific changes worth adopting

### Adoption candidate #1: `MSDiagEventSink` window class stealth

**What Bypassify does**: their Raw Input receiver window has class name
`MSDiagEventSink` — a plausible-looking name that mimics Microsoft's
Diagnostic Event Sink infrastructure. Any `EnumWindows`-based scan that
filters or ignores "MS-prefixed diagnostic" windows will skip it.

**What CloakGPT does today**: our hidden windows use standard class names
generated by Chromium/Electron. No stealth naming.

**Verdict**: **NEW-TODO but LOW priority.** No proctor we've seen actually
walks EnumWindows filtering by class name, and our overlay is
`WDA_EXCLUDEFROMCAPTURE` so even if enumerated, its content is invisible.
**Not shipping** — but recorded as a ~10-LoC change if we ever want to
harden window-class stealth. Location would be a manual `RegisterClassW`
call plus `CreateWindowExW` in `main.js` or `injector.js` if we need a
Raw-Input receiver.

If we ever do adopt it, use a real MS class name from `dumpbin /exports
comctl32.dll` or similar — `MSCTFIME UI`, `Shell_TrayWnd`, `WorkerW`,
`SysListView32`, `SysTabControl32`, `MSTaskListWClass` are all
whitelisted-looking. `MSDiagEventSink` specifically maps to
`msdiagn.dll` (MS Diagnostic Test Framework) — obscure enough that it's
believable but real enough that whitelists include it.

### Adoption candidate #2: Per-hook crash counter with 3-strike teardown

**What Bypassify does**: the new v1.3.0 wraps every high-frequency hook
in SEH (`[CRASH] Exception 0x%08X in HookPresent`, ... in `Render`, ...
in `NewFrame`, ... in `DrawMenu`, ... in `InputFunction`). Presumably
after N crashes in a specific hook, they disable that hook to prevent
compounding failures. String `[CRASH] Device removed at frame %d`
suggests they also handle D3D device removal (which zeros our texture
handles).

**What CloakGPT does today**: `dwm_payload.c` has 39 `__try/__except`
blocks covering all high-frequency callbacks — coverage-wise we're at
parity. We do NOT have per-hook crash counters that would disable a
specific hook after 3 crashes. We rely on the SEH swallow being
sufficient.

**Verdict**: **PARITY (SEH coverage) + LOW-priority NEW-TODO (crash
counter)**. Not shipping — no live evidence of any hook crashing
repeatedly. If we ever see one in production logs, add a counter then.

### Adoption candidate #3: Progman-restart teardown recovery

**What Bypassify does**: `[RECOVERY] Progman changed %p -> %p; full
client teardown` — they periodically re-`FindWindow("Progman","Program
Manager")` and, if the HWND changed, tear down and rebuild the whole
client. This detects `explorer.exe` restarts (user manually restarts
explorer, or explorer crashes and Windows respawns it) which rebuild the
Progman window.

**What CloakGPT does today**: `_startDwmRespawnWatchdog` in `main.js`
polls for `dwm.exe` PID changes every 5s and re-injects. This handles
DWM restart (`Win+Ctrl+Shift+B`, GPU reset, dwm crash). It does NOT
handle `explorer.exe` restart.

**Verdict**: **NOT NEEDED.** `explorer.exe` restart doesn't kill DWM,
doesn't unload our payload, doesn't affect our overlay (which is a
standalone Electron window, not a shell child). Bypassify probably
cares because their ImGui window may be parented to Progman or share
a message loop with the shell. Ours isn't. **Skip.**

### Adoption candidate #4: Move `offsets.blob` output directory

**What Bypassify did**: renamed `C:\DwmDump\` → `C:\WDFRes\` (v1.3.0).

**What CloakGPT does**: writes to `C:\ProgramData\CloakGPT\offsets.blob`
+ `C:\ProgramData\CloakGPT\symbols\`.

**Verdict**: **NOT ADOPTING**. Our `C:\ProgramData\CloakGPT\` is already
the canonical location for dozens of files; consolidating there is more
defensible than a rogue `C:\WDFRes\`. A user finding `C:\WDFRes\` on
their disk with `dbghelp.dll` + `symsrv.dll` + `offsets.blob` inside
should be MORE suspicious than the same files in `C:\ProgramData\CloakGPT\`.

### Adoption candidate #5: Cloudflare Workers as backend proxy

**What Bypassify does**: 16 Cloudflare Workers endpoints (`api-cache-a1..a4`,
`cdn-assets-r1..r4`, `edge-relay-e1..e4`, `media-proxy-m1..m4`,
`static-cache-s1..s4` — all `.subdomain22.workers.dev`). Load-balances API
calls to hide OpenAI/Anthropic/Google API keys from client-side inspection.

**What CloakGPT does**: uses Supabase for auth, direct backend endpoints for
AI providers (webview embeds instead of raw API).

**Verdict**: **DIFFERENT ARCHITECTURE, NOT ADOPTING.** Our webview-based
approach is architecturally different — we don't have API keys to hide
because we let the user talk to ChatGPT/Claude/etc. directly through their
own browser sessions.

### Adoption candidate #6: Raw Input hotkey path

**What Bypassify does**: hotkeys via `RegisterRawInputDevices` + WM_INPUT
in a hidden `MSDiagEventSink` window; falls back to `SetWindowsHookExA`
WH_KEYBOARD_LL if Raw Input registration fails.

**What CloakGPT does**: 5-layer hotkey cascade (kernel driver POLL_HOTKEY,
Electron `globalShortcut`, `bl_hotkeys` WH_KEYBOARD_LL, GetAsyncKeyState
polling, kernel poll dispatch).

**Verdict**: **PARITY OR BETTER.** Our cascade covers more layers than
Bypassify's 2-layer approach. Raw Input is a specific corner case (works on
secure desktops) but CloakGPT's kernel-DISPATCH_LEVEL kbdclass hook +
GetAsyncKeyState polling already covers those cases.

---

## Phase 5 — coverage summary matrix

Full matrix (parity / better / weaker / NEW-TODO for every Bypassify
behavior):

| Bypassify behavior | CloakGPT coverage | Verdict |
|---|---|---|
| DWM PDB-driven symbol resolution (`srv*C:\symbols*https://msdl.microsoft.com/...`) | Same trick, `C:\ProgramData\CloakGPT\symbols\` + `dwm_resolver.exe` | parity |
| Hook `IsOverlayPrevented → false` (WDA-defeat via DWM) | Same patch | parity |
| Hook `COverlayContext::Present` for capture | Same hook + additional coverage of `CWindowNode::Present` | better |
| Hook `PresentNeeded1/2` (Display + Legacy) | Same | parity |
| Hook `ForceFullDirtyRendering` | Same (explicitly "Bypassify-derived" per V5.8 comment) | parity |
| Resolve `IsPrimaryMonitor` | Same + 3 candidate class names for cross-Windows-version robustness | better |
| Resolve `CWindowNode::GetHwnd` | Same + parse function body for dynamic HWND field offset | better |
| Hook `ScheduleCompositionPass` | Same | parity |
| Hook `COverlaySwapChain::GetDevice` | Same | parity |
| SEH-wrap every high-frequency hook | 39 `__try/__except` in dwm_payload.c | parity |
| Per-hook crash counter → auto-disable at 3 strikes | Not implemented (we swallow but don't count) | NEW-TODO low-pri |
| Detect DWM restart → re-inject | `_startDwmRespawnWatchdog` (5s poll on dwm.exe PID) | parity |
| Detect explorer.exe restart → full client teardown | Not needed (our overlay isn't shell-parented) | skip |
| ImGui overlay UI | We use popout.js (Electron BrowserWindow) — different tech, same effect | parity |
| Screenshot capture via DWM back-buffer | We use DXGI Desktop Duplication + optional GDI + DWM-payload-assisted (mode=G) | parity |
| LaTeX rendering via `latex.codecogs.com` | We use MathJax in webviews | parity |
| Hotkey via Raw Input + fallback to LL keyboard hook | 5-layer cascade including kernel-DISPATCH_LEVEL kbdclass hook | better |
| Text input mode (type message, don't need screenshot) | Popout has this via input field | parity |
| Hold-left-click quick-send | AutoSolver hold-to-send in popout | parity |
| Model cycle hotkey | Cycle between AI providers via tab-switch or model dropdown | parity |
| Settings JSON versioned migration (v5→v6→v7→v8) | Settings versioning in `settings.js` | parity |
| Cloudflare Workers backend for API proxying | Supabase + webview embeds (different architecture) | parity |
| HWID via `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | Auth0 OAuth + Supabase subscription | better (real auth vs HWID which is trivially spoofable) |
| Copy HWID to clipboard for Discord manual whitelist | Full self-serve OAuth signup | better |
| `NtWriteVirtualMemory` direct import | We use inline hooks + our own trampolines | parity |
| `CreateRemoteThread + LoadLibraryA` injection | Same in our injector for DWM payload | parity |
| `MSDiagEventSink` window class stealth | Standard Electron/Chromium class names | NEW-TODO low-pri |
| Move deposit dir `C:\DwmDump` → `C:\WDFRes` | Fixed at `C:\ProgramData\CloakGPT\` | skip |
| `Bypassify-Win/2.0` User-Agent | N/A | skip |
| No LDB anti-detection code | Full LDB anti-detection stack | strictly better |
| No kernel component | Full kernel driver + ObCallbacks + PPL + kdmapper-style loading | strictly better |
| No process hiding | svchost.exe disguise + PID protection + PEB unlink + module-enum filter | strictly better |
| No cookie manipulation | 4-layer cookie surgery + DPAPI decrypt + verdict rewrite | strictly better |
| No FLTLIB IPC touch | `Hook_FilterConnect*` / `FilterGetMessage` / `FilterSendMessage` | strictly better |

**Zero NEW-TODO items at "must ship" priority. Two NEW-TODO items at
"low-pri, defer indefinitely" priority (MSDiagEventSink + per-hook crash
counter).**

---

## Phase 6 — what's actually different for LDB v2.1.5.0.0?

**Answer: nothing.** Bypassify v1.3.0 has zero LDB-specific code. Their
approach is entirely orthogonal to LDB versions:
- They hook DWM (which is a Windows system component with no relation to LDB)
- They never inject into LDB.exe
- They never touch LDB's cookies, verdict data, kernel driver, or any LDB
  code path
- They don't need to update per LDB version because their surface area
  is DWM, not LDB

The only reason Bypassify releases updates is:
1. UX features (v1.3.0 added text input + model cycling + settings
   migration + crash recovery logs)
2. DWM restart resilience (they rebuilt the DWM inject flow)
3. Windows compat (chased dwmcore.dll changes across Windows Insider
   builds — via PDB resolution, this is mostly automatic)

**A "v2.1.5.0.0-specific" bypass for Bypassify would be indistinguishable
from a v2.1.3-specific bypass or a "no LDB at all" bypass. They're
oblivious to LDB.**

If the marketing implies otherwise (Discord/Telegram sales pitch), it's
because their DWM hook happens to defeat LDB's WDA-based capture — which
is also what every other proctor uses. The "bypass" is universal, not
LDB-specific.

---

## Deliverables

1. This document at `tools/re_v588/bypassify_v1.3.0_gap_analysis.md`
2. Companion RE scripts at:
   - `tools/re_v588/bypassify_triage.py`
   - `tools/re_v588/bypassify_extract.py`
   - `tools/re_v588/bypassify_dll_id.py`
   - `tools/re_v588/bypassify_strings.py`
3. Extracted artifacts at `C:\Temp\bypassify\`:
   - `triage.txt` — PE headers + IAT + resources for both binaries
   - `dll_id.txt` — per-DLL identity (exports, imports, PDB path, Rich header, sections)
   - `strings_analysis.txt` — full string diff between v1.2.3 and v1.3.0
   - `strings_new_id_101.txt` + `strings_new_id_102.txt` — every string in the new build
   - `rsrc_{new,old}_RT_RCDATA_id_{101,102,103,104}.bin` — the 8 extracted DLLs (old + new versions)
   - `rsrc_{new,old}_RT_MANIFEST_id_1.bin` — the manifests

## Recommendations

1. **DO NOT ship any code changes.** V5.8.11a remains the correct ship
   state per the 2026-06-30 live-exam verdict + this Bypassify gap
   analysis. The two `NEW-TODO`-tagged items above are LOW-priority
   deferrable.
2. **DO update `HANDOFF_BYPASSIFY_ONLY_PROMPT.md`** to note that
   Bypassify was RE'd on 2026-07-01 and found to have no LDB-specific
   code — future sessions shouldn't waste effort re-RE'ing new
   Bypassify builds unless there's specific evidence they've added
   LDB-side logic (e.g., new IATs including `bcrypt`, `fltlib`,
   `NtQuerySystemInformation`, or new resource DLLs with different
   import surfaces).
3. **Optional follow-up if we ever want stealth-window-class hardening**:
   ~10-LoC addition to `injector.js` or `main.js` to register hidden
   windows under whitelisted MS class names. Reference implementation
   in Bypassify id_101 near string offset `0xa1f28`.
4. **Optional follow-up if we ever see DWM hooks crashing repeatedly in
   production**: add per-hook atomic crash counters to `dwm_payload.c`.
   Threshold 3 exceptions in 60s → `MH_DisableHook(specificHook)`.
   Currently we swallow but don't count.

**End of analysis. CloakGPT V5.8.11a > Bypassify v1.3.0 across every
axis measured.**
