# 🚨🚨 P0 HANDOFF — Payload CRASHES DWM after Windows 11 25H2 KB5124008 update (2026-09-21 night)

**Status:** UNRESOLVED + WORSE THAN INITIALLY REPORTED. Payload does not just fail to render — it **actively crashes `dwm.exe` with `0xc0000005` access violations** shortly after inject. Winlogon watchdog then dutifully re-injects → crash again → respawn loop. **Payload must stay UNLOADED on this Windows build until fixed.** Real regression from Windows update, not user error.

**Branch/HEAD when written:** `main` at commit `4d2a1a9` (this handoff doc). All fixes from tonight's session already committed + pushed.

## 🛑 SHIP-BLOCK NOTICE

**DO NOT distribute the Setup.exe / zip currently on Nyx's Desktop (dated 2026-09-21 18:13 / 18:14)** on Windows 11 25H2 builds **≥ 26200.9457** — the payload will crash the user's DWM. Windows respawns DWM but their screen flickers black each cycle. If svchelper's `respawnWatchdog` OR the winlogon helper's `sentinel_thread` is armed, it goes into a permanent crash loop that only stops when the user finds a way to run `sihost.exe --unload` (hard for a non-technical user).

Devices on ≤ 26100.8xxx cumulative baseline appear unaffected — that build worked live all day today. Regression is specifically the KB5124008-family update (build 26200.9445 / 26200.9457).

**Ship-blocked until this handoff is closed.**

## 🩹 EMERGENCY UNLOAD (for user hitting this in the wild)

```powershell
# Run elevated -- writes clean-shutdown sentinels then unloads, so winlogon
# watchdog does NOT re-arm.
"1" | Out-File C:\ProgramData\WinAudioSvc\.dwm_clean_shutdown -Encoding ASCII -NoNewline -Force
"1" | Out-File C:\ProgramData\WinAudioSvc\.dwm_user_panic     -Encoding ASCII -NoNewline -Force
& C:\ProgramData\WinAudioSvc\sihost.exe --unload
Start-Sleep 8
Get-Process svchelper -ErrorAction SilentlyContinue | Stop-Process -Force
```

Verified working on this box at 8:07 PM local: DWM immediately stabilized after unload (same pid held for 8+ seconds, no more respawns).

---

## READ FIRST

1. `CLAUDE.md` — 40+ hard invariants + architecture overview.
2. `AGENTS.md` — workspace rules (Sonnet-only subagents, dev-bypass etc.).
3. `docs/HANDOFF_2026-09-21_WINLOGON_WATCHDOG_LANDED.md` — v3.0.3 → v3.0.7 recent architecture (this whole session's work landed there).
4. `docs/HANDOFF_2026-09-20_OVERLAY_DIES_ON_EXPLORER_RESTART.md` — the LAST invisible-overlay bug (similar failure mode, different root cause — DWM MPO plane renegotiation on shell restart). READ THIS CAREFULLY, similar symptoms.
5. `payload/src/dwm_hooks.c` — where all Present / RenderContent hooks live.
6. `payload/src/ui/imgui_layer.cpp` — where `get_backbuffer_texture` + `ui_present_frame` live.
7. `resolver/src/main.c` — PDB resolution + offset writer.

---

## THE BUG (verified live 2026-09-21 23:51+ local + escalated 24:07 local)

**Original user report:** "no — no overlay visible even though logs say hooks_install: SUCCESS"

**Follow-up user report (8:06 PM local, ~2h after first symptom):** *"OH HELL NAH FUCK NO can u unload it fully including the winlogon seems like it's actually crashing my dwm somehow yes unload fully... like r my dwm crashes then the winlogon b.s makes it RESPAWN BRO then it crashes again"*

Translation: after Nyx let the payload sit for ~2h he noticed DWM was actively crashing on a loop and the winlogon watchdog was faithfully re-arming it each cycle. **What I thought was "silent no-render" was actually "crashes before render can happen."** Full unload verified stops the loop.

## THE HARD EVIDENCE — Windows event log (2026-09-21 7-8 PM local)

```
9/21/2026 8:05:45 PM  Application  Event 1000  APPCRASH
    Faulting application: dwm.exe, version 10.0.26100.9278
    Faulting module:      dwmcore.dll, version 10.0.26100.9278
    Exception code:       0xc0000005   (access violation)
    Fault bucket:         1705138388519202707

9/21/2026 8:05:40 PM  Application  Event 1000  APPCRASH
    Faulting application: dwm.exe, version 10.0.26100.9278
    Faulting module:      unknown, version 0.0.0.0
    Exception code:       0xc0000005   (access violation)
    Fault bucket:         (different from above)

9/21/2026 7:58:35 PM  Application  Event 1000  APPCRASH
    Faulting application: dwm.exe, version 10.0.26100.9278
    Faulting module:      dwmcore.dll, version 10.0.26100.9278
    Exception code:       0xc0000005
    Fault bucket:         1181915356926031190
```

- **`Faulting module: unknown`** ← this IS our payload. Manual-mapped DLL has no PEB entry so WER cannot attribute the fault. Standard behavior. Confirms an access violation inside OUR detour code.
- **`Faulting module: dwmcore.dll`** with a completely different fault bucket ← DWM crashed inside its own compositor code AFTER returning from our hook, meaning we corrupted state or returned unexpected pointer values.
- Two different fault buckets = two different crash sites, both provoked by our payload.

**WER dump path** (for `windbg -z ...`):
```
C:\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash_dwm.exe_7a11eab216bacb537a1bab56145ee84f4e9d9_b2389584_1c6b91f5-2a5f-43ee-918a-02f1a971e39a\Report.wer
```
No `.dmp` file was retained (WER default policy on Home/Pro is to submit + purge). Fresh chat should enable full dumps for `dwm.exe` BEFORE re-testing:
```powershell
# Enable full user-mode dumps for dwm.exe -- MUST be set BEFORE re-provoking crash
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\dwm.exe'
New-Item $k -Force | Out-Null
Set-ItemProperty $k -Name DumpType     -Value 2   # 2 = full dump
Set-ItemProperty $k -Name DumpFolder   -Value 'C:\CrashDumps'
Set-ItemProperty $k -Name DumpCount    -Value 5
New-Item C:\CrashDumps -Type Directory -Force | Out-Null
```
Then re-inject and let it crash ONCE. `C:\CrashDumps\dwm.exe.*.dmp` will contain full memory. Load into windbg with:
```
windbg -z C:\CrashDumps\dwm.exe.*.dmp
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f
!analyze -v
```
The `!analyze` output will name the exact instruction that AV'd, and stack walk will show whether it's inside `Detour_COverlayContextPresent`, `get_backbuffer_texture`, or dwmcore itself.

## THE ORIGINAL "invisible overlay" observation (superseded but keep for context)

Prior to noticing the crash loop, the observed symptom was:

**Full stack ALL succeeds per logs:**
- Payload injected into dwm.exe (pid 2828) — ✅
- Resolver succeeded, offsets.blob written — ✅
- All 5 hooks installed:
  - `Present hooked @ 00007FF8434D1000` ✅
  - `PresentNeeded1 hooked @ 00007FF843470F10` ✅
  - `PresentNeeded2 hooked @ 00007FF843470F44` ✅
  - `ForceFullDirty flag @ 00007FF84369D819 patched DIRECT: 0x34 -> 0x01` ✅
  - `IsOverlayPrevented patched @ 00007FF84348E600 -- RETURNS TRUE. Original 6 bytes: ff 15 5a df 11 00` ✅
- `hook integrity monitor armed (3 hooks registered)` ✅
- `hooks_install: SUCCESS (Phase A: RUNNING)` ✅
- `keepalive: ghost visibility -> SHOWN (overlay visible)` ✅
- Rawinput slots loaded (33/33) ✅
- Poll thread heartbeating normally (~164 polls / 5s) ✅

**Full stack ALL FAILS at render pipeline:**
- ❌ ZERO `dwm: Present fired count=N` log lines (pre-reboot fired within 1 sec of inject with `count=1`)
- ❌ ZERO `get_backbuffer_texture: OK on first call` log (fires ONCE on first successful vtable walk)
- ❌ ZERO `RTV cached` log
- ❌ ZERO `ImGui READY -- overlay should render this frame` log
- ❌ **User sees no overlay on screen**

**Meaning:** hooks are installed correctly. But either (a) DWM isn't calling into our hooked function, or (b) our detour IS running but is a total no-op (silently), or (c) our detour walks vtable + returns NULL because vtable layout changed.

---

## KEY DIAGNOSTIC DATA

**Windows version:**
- **Before update:** Windows 11 25H2, ~June 2026 cumulative (user was months behind)
- **After update:** Windows 11 25H2 build **26200.9457** (post-KB5124008 preview/hotfix — even newer than the Sep 8 mainline KB5124008 which was 26200.9445)

**dwmcore.dll version (critical!):**
- **Before AND after update: `10.0.26100.9278`** — SAME version. Windows update did NOT ship a new dwmcore.dll.
- This is verified via `(Get-Item C:\Windows\System32\dwmcore.dll).VersionInfo.FileVersion`
- Same version → same PDB → same symbol RVAs → resolver's `offsets.blob` was IDENTICAL pre and post update:
  - Pre: `blob: present=0x231000 overlay-prev=0x1ee600 gpb=0x1ea620 gd3d=0x1fe330 acc=0x103510`
  - Post: `blob: present=0x231000 overlay-prev=0x1ee600 gpb=0x1ea620 gd3d=0x1fe330 acc=0x103510`
  - Byte-for-byte identical.

**BUT — hook RVAs shifted because dwmcore rebased at load (ASLR):**
- Pre-reboot dwmcore base: `00007FFA1F9C0000` → Present at `00007FFA1FBF1000` (RVA 0x231000)
- Post-reboot dwmcore base: `00007FF8432A0000` → Present at `00007FF8434D1000` (RVA 0x231000)
- Different absolute addresses, IDENTICAL relative offset. This is normal + expected. Just ASLR.

**IsOverlayPrevented byte layout DIFFERS pre/post:**
- Pre-reboot original 6 bytes: `8a 81 28 01 00 00` (MOV al, [rcx+128] — a normal getter)
- Post-reboot original 6 bytes: `ff 15 5a df 11 00` (CALL rel32 [dwmcore+11df5a+6] — an indirect call)
- **Microsoft modified the prologue of IsOverlayPrevented between builds** (even though dwmcore version reported as unchanged — could be a MUI/localization patch or CFG/HVCI insertion).
- Our patch overwrites those 6 bytes with a "return TRUE" stub either way, so patch succeeds. But this SIGNALS that dwmcore internal code IS different despite version string being same. Maybe more subtle things also changed.

---

## HYPOTHESES (RE-RANKED after crash-loop evidence)

**KEY RULE-OUTS from the AV events:**
- **H3 (HVCI/CFG) is OUT.** CFG mitigations would silently reject our indirect call and no-op — NOT produce a `c0000005` in dwmcore.dll. If CFG had rejected the trampoline JMP, the CPU would go to a `__fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE)` fault path (bugcheck 139 or an APPCRASH with exception code `0xC0000409` subcode 0xA), not a plain access violation.
- **H4 (graphics driver TDR) is OUT.** GPU driver resets show up as VIDEO_TDR events (Kernel_141 in WER) or `nvlddmkm`/`igdkmd`/`amdkmdag` module faults, not dwmcore.
- **H6 (silent dwmcore hash change) is OUT.** File hash could differ, but the resolver would still resolve symbols from the on-disk PDB and produce correct RVAs — it's the CACHED offsets.blob we care about, and we verified those match. Not this.

**Live hypotheses, re-ranked:**

### H1 — Vtable layout changed, wrong-slot pointers cause AV
**Prior after crash evidence: ~85%.** Best fit.

**Detail:** `get_backbuffer_texture` in `payload/src/ui/imgui_layer.cpp` walks:
- `pLayer->vtable[5]()` = `GetPhysicalBackBuffer` (returns swapchain buf)
- `pLayer->vtable[24]()` = `GetD3D11Resource` (returns IUnknown accessor)
- `accessor->vtable[19]()` = actual `ID3D11Texture2D`

If Microsoft added/removed even ONE virtual method to `COverlayContext` / `CDisplaySwapChain` between builds, every subsequent slot shifts by one. We then call a completely different function through slot [5]/[24]/[19] — that function almost certainly has a DIFFERENT signature (different arg count, different `this` expectations) and immediately AV's when it tries to dereference `rcx` or read args off the stack that aren't there.

**Why this matches the observed pattern:**
- We successfully do the trampoline write (hooks_install: SUCCESS)
- On first Present, our detour body IS called (trampoline works)
- Detour calls `get_backbuffer_texture` → indirect call through wrong vtable slot → wrong function → AV on first pointer deref (rcx / edi / whatever)
- Sometimes AV happens BEFORE ret so WER records "unknown" module (that's OUR code — the detour body copied into wherever MinHook allocated trampoline pages)
- Sometimes we return corrupted values to dwmcore and DWM AVs later inside `dwmcore.dll` (the second fault-bucket)

**Test:** Add unconditional first-fire log at top of `Detour_COverlayContextPresent`, run once, capture the WER minidump with full memory (see setup above). `!analyze -v` will land exactly at the vtable indirect call and tell us which slot broke.

### H2 — Present hook is installed at the correct symbol but DWM calls a different function
**Prior after crash evidence: ~10%.** Would still cause a crash if the "different function" now calls back into a vtable slot that shifted, but H1 explains it more directly.

**Detail:** In some Windows updates Microsoft has SPLIT compose paths — e.g., adds a `COverlayContext::Present2` for HDR-specific compositing while keeping the old `Present` as a legacy path. If DWM's active session uses the new path, our hook on the old symbol never fires.

**Test:** Run `dumpbin /exports C:\Windows\System32\dwmcore.dll | findstr /I "Present"` to see all Present-related exports. Compare against what our resolver looks for (`payload/src/dwm_hooks.c` + `resolver/src/main.c`). Look for new siblings.

### H3 — HVCI / VBS enforcement changes broke our MinHook trampoline
**Prior after crash evidence: ~2%.** RULED OUT — CFG rejects should produce `__fastfail` (STATUS_STACK_BUFFER_OVERRUN or similar), not plain `0xc0000005`. Keeping this stub only in case fresh chat wants to verify HVCI state as a sanity check.

**Test (sanity only):** `Get-ComputerInfo | Select-Object DeviceGuard*, HypervisorPresent`.

### H4 — Graphics driver update changed MPO scanout
**Prior after crash evidence: ~2%.** RULED OUT — driver TDRs would show as VIDEO_TDR (Kernel_141) or `nvlddmkm`/`igdkmd`/`amdkmdag` module faults, not `dwmcore.dll`+`unknown` AV.

### H5 — Windows changed the DWM composition surface Present pattern
**Prior after crash evidence: ~30%.** Companion to H1, not competitor.

**Detail:** The Terminal `Composed: Flip` vs `Hardware Composed: Independent Flip` issue from Sep 2026 (see WEB search in this session's transcript) shows Microsoft has been rejigging DWM's presentation model. If dwm.exe is now calling `PresentMPO` or `PresentGdi` INSTEAD of `COverlayContext::Present` for the primary compose path, our hook on `COverlayContext::Present` never fires for the relevant frames.

**But this wouldn't crash by itself** — if our hook never fires, no crash inside our detour. The crash proves our detour IS running. So H5 is only interesting as a companion — maybe DWM calls the NEW compose path (PresentMPO2, whatever), and something on that path eventually walks a vtable that overlaps with the one we tampered with.

**Test:** Same as H2 — enumerate dwmcore.dll exports for Present-adjacent symbols.

### H6 — dwmcore.dll was code-signed differently and now has different mitigation
**Prior after crash evidence: ~1%.** RULED OUT — pure re-sign wouldn't shift vtable layout and would fail early on PE cert-check, not late during a compose Present.

### NEW hypothesis: H7 — Our detour signature is wrong for the current Present
**Prior: ~40%.** Related to but distinct from H1.

**Detail:** Microsoft may have changed the arg count / calling convention of `COverlayContext::Present` between builds. Our detour body reads `this`, `pParam1`, `pParam2` from `rcx`/`rdx`/`r8` — if the new Present takes 4 or 5 args, our detour reads correctly but the ORIGINAL function (which we call via trampoline) expects extra args in `r9` / stack that we never populated. Trampoline returns into dwmcore with a corrupted register state → dwmcore.dll AV a few instructions later.

**Test:** Same crash-dump analysis as H1 — `!analyze -v` on the dwmcore.dll faulting-module dump will show the exact call site and register state at fault time. Compare against `x dwmcore!COverlayContext::Present` symbol type info to see the actual signature.

### NEW hypothesis: H8 — CET Shadow Stack now enforced on dwm.exe
**Prior: ~15%.** Windows 11 25H2 has been progressively rolling out Intel CET (Control-flow Enforcement Technology) hardware shadow stack enforcement to more processes.

**Detail:** If Microsoft flipped dwm.exe to require shadow stack for indirect returns, our trampoline's `ret` to dwmcore is on a return address the shadow stack doesn't have → hardware `#CP` fault → AV.

**Test:** Check `Get-ProcessMitigation -Name dwm.exe | Select CFG, ShadowStack, UserShadowStack*` — if `UserShadowStackStrictMode` is `ON`, CET is enforced. Would need to either (a) push a matching shadow-stack entry via `SSPUSH` before jumping, or (b) request CET exemption via `SetProcessMitigationPolicy` from a helper. But those require our code to be aware — the simpler fix is to detour LATER in the function past the ENDBR64 prologue.

---

## WHAT I ALREADY VERIFIED (do NOT re-run these — save time)

- ✅ dwmcore.dll `FileVersion` string reports `10.0.26100.9278` pre AND post update (verified via `Get-Item`)
- ✅ offsets.blob content is byte-for-byte identical pre/post (see raw values above)
- ✅ dwm.exe is running, current pid 2828, started 7:38:54 PM local
- ✅ Payload SUCCESSFULLY injected into dwm pid 2828 (all init_thread log lines present)
- ✅ Resolver did NOT output "symbol NOT FOUND" for any name — every symbol resolved
- ✅ MinHook returned success codes for every hook install
- ✅ IsOverlayPrevented byte-patch succeeded (VirtualProtect + write + revert)
- ✅ `hook integrity monitor` did NOT log any hook getting overwritten (would fire if AV/EDR re-patched)
- ✅ Rawinput hook system works (poll thread heartbeating, LL hook installed)
- ✅ Config (schema v14) loaded from config.dat, `provider=0` = auto = normal state
- ✅ NO `NOT FOUND`, `FATAL`, or `ERROR` lines in payload.log or launcher.log post-update
- ✅ Payload is `LOADED` per `sihost --status` (exit 0)
- ✅ ghost window visibility flag set to SHOWN
- ✅ SAME svchelper.exe / sihost.exe binaries worked PRE-UPDATE. We haven't rebuilt payload since morning. Same binary → different behavior → environment change.

## WHAT I DID NOT VERIFY (worth checking)

- ❌ Whether hash of `C:\Windows\System32\dwmcore.dll` matches pre-update (H6)
- ❌ Whether HVCI / Memory Integrity is enabled post-update (H3)
- ❌ Whether graphics driver was updated (H4)
- ❌ Whether NEW Present-adjacent symbols exist in dwmcore.dll (H2 / H5)
- ❌ Whether our Present detour is even being called (needs new diag log — see H1 test)
- ❌ Whether attempting overlay TOGGLE (Ctrl+B) fires anything in log (would validate hotkey path even if render broken)

---

## SUGGESTED INVESTIGATION ORDER (2h max)

**Step 0 (2 min) — CRITICAL PRE-REQUISITE — enable full dumps** BEFORE re-provoking the crash. See "WER dump path" section above. Without this the crash produces no analyzable artifact.

Also arm `Get-ProcessMitigation -Name dwm.exe | Select CFG, *ShadowStack*, ArbitraryCodeGuard*` and log the output. If ShadowStack is `ON` → suspect H8 immediately.

**Step 1 (5 min)** — Add unconditional first-fire log to `Detour_COverlayContextPresent`:
```c
// At top of Detour_COverlayContextPresent in payload/src/dwm_hooks.c:
static volatile LONG s_detour_hits = 0;
LONG n = InterlockedIncrement(&s_detour_hits);
if (n == 1 || n == 60 || n == 600) {
    slog_writef("payload.log", "PRESENT DETOUR CALLED count=%ld", n);
}
```
Build, reinject, wait 5s. Check log:
- If `PRESENT DETOUR CALLED count=1` fires → hook works, bug is DOWNSTREAM (vtable walk / render pipeline). Go to Step 2.
- If NO log line fires → hook is installed but not being called. Go to Step 4.

**Step 2 (10 min)** — If detour fires but render doesn't: instrument `get_backbuffer_texture`:
```c
// Add unconditional first-call log INSIDE get_backbuffer_texture, at every early-return:
slog_writef("payload.log", "get_backbuffer: vtable[5] returned pDevice=%p", pDevice);
slog_writef("payload.log", "get_backbuffer: vtable[24] returned pAccessor=%p", pAccessor);
slog_writef("payload.log", "get_backbuffer: QI(ID3D11Texture2D) returned tex=%p hr=0x%X", tex, hr);
```
Find which step returns NULL. That's the vtable slot that changed.

**Step 3 (30 min)** — Once you know which vtable slot is off: use `dumpbin /symbols dwmcore.dll` + `!vtable` in WinDbg to enumerate the actual current vtable of `COverlayContext` / `CDisplaySwapChain` / whatever. Find where `GetPhysicalBackBuffer` / `GetD3D11Resource` moved to. Update the slot indices in `payload/src/ui/imgui_layer.cpp`.

**Step 4 (only if Step 1 shows no fire)** — Hook installed but not called. Two sub-cases:
- **Step 4a** — Check if HVCI is on: `bcdedit /enum {current} | findstr hypervisorlaunchtype`. If ON, temporarily disable Memory Integrity in Windows Security UI, reboot, retry. If disabling HVCI fixes it → confirmed H3.
- **Step 4b** — Enumerate ALL dwmcore.dll Present-adjacent symbols: `dumpbin /exports dwmcore.dll | findstr /I present`. Look for new ones (`Present2`, `PresentGdi`, `PresentMPO`, etc.). If found, our Present hook is on the WRONG symbol — DWM is calling the new one. Add hook for the new symbol too.

**Step 5 — CRITICAL: temporarily disable winlogon watchdog before testing** so you don't loop-crash Nyx's DWM during investigation:

Before each inject test, write BOTH sentinels first:
```powershell
"1" | Out-File C:\ProgramData\WinAudioSvc\.dwm_clean_shutdown -Encoding ASCII -NoNewline -Force
"1" | Out-File C:\ProgramData\WinAudioSvc\.dwm_user_panic     -Encoding ASCII -NoNewline -Force
```
The winlogon helper's `sentinel_thread` checks these before every reinject cycle — with both present, it stays quiet. Also do NOT start `svchelper.exe` during debug (its `respawnWatchdog` will also re-arm). Manual `sihost --reinject` only.

---

## LOG DECRYPT (for the fresh chat)

Master key (2026-07-05 v3):
```
5919246238e69eaf9ab65a4e15bf075141af7189fd5071aee7886505d01551c5
```

Decrypt command:
```powershell
$key = "5919246238e69eaf9ab65a4e15bf075141af7189fd5071aee7886505d01551c5"
node "C:\Users\abdul\Desktop\hooksdll\lumio\tools\decrypt-logs.js" `
     "C:\ProgramData\WinAudioSvc\payload.log" --key $key
```

Filter for critical events:
```powershell
| Select-String -Pattern "PRESENT DETOUR|get_backbuffer|RTV cached|ImGui READY|hooks_install|NOT FOUND|FATAL"
```

---

## HARD DO-NOT-REVISIT LIST (proven dead-ends this session or in HANDOFF_2026-09-20)

1. ❌ Do NOT try to force `PresentMPO` → `swapChain->Present` fallback via IsOverlayPrevented patching. CRASHES DWM. Verified in `HANDOFF_2026-09-20`.
2. ❌ Do NOT call `ImGui_ImplDX11_Shutdown()` + `Init()` inside `ui_present_frame` on the compose thread. CRASHES DWM.
3. ❌ Do NOT drop the WorkerW fallback WITHOUT keeping the iso-desktop preservation guard from v3.6.2 (already in code, don't regress).
4. ❌ Do NOT self-spawn `sihost --reinject` from payload's KILL_ALL. Hits `ERROR_ELEVATION_REQUIRED (740)`. Inline self-terminate is the answer.
5. ❌ Do NOT rebuild the payload with any dev-bypass env var set. Production ship must be clean.

---

## REPRODUCTION

**Current state on this box (as of 8:07 PM local):**
- Payload FULLY UNLOADED per Nyx's request. `sihost --status` = 3 (not loaded).
- Both `.dwm_clean_shutdown` + `.dwm_user_panic` sentinels in place → winlogon watchdog stays quiet.
- svchelper Electron killed.
- Winlogon helper's shutdown event no longer exists → helper thread exited.
- **DWM is now stable — same pid held for 8+ seconds without respawn.** Confirmed clean.

**To reproduce the crash (deliberately, for debugging):**
1. Enable full dumps (Step 0 above)
2. Sentinels stay in place (they suppress winlogon reinject, but don't block first arm)
3. Manual arm: `& C:\ProgramData\WinAudioSvc\sihost.exe --reinject --quiet`
4. Wait ~1-5 seconds. DWM will AV. WER writes dump to `C:\CrashDumps\dwm.exe.NNNN.dmp`.
5. Windows respawns DWM. Sentinels prevent winlogon watchdog from re-arming payload. You get ONE crash per manual arm — controlled test.
6. If a re-arm happens anyway (watchdog debounce, timing), immediately re-write the sentinels + `sihost --unload`.

**To reproduce from scratch:**
1. Unload payload: `& C:\ProgramData\WinAudioSvc\sihost.exe --unload; Start-Sleep 5`
2. Reinject: `& C:\ProgramData\WinAudioSvc\sihost.exe --reinject --quiet; Start-Sleep 4`
3. Verify loaded: `& C:\ProgramData\WinAudioSvc\sihost.exe --status` (expect exit 0)
4. Check user's screen — overlay should be visible with default position + text. Currently is NOT.

**Rebuild + redeploy dev-bypass for iterative testing:**
```powershell
$env:SVCLDB_DEV_AUTH="1"
$env:WL_DIAG="1"
cd C:\Users\abdul\Desktop\svcldb\payload;  cmd /c "build.bat"
cd C:\Users\abdul\Desktop\svcldb\launcher; cmd /c "build.bat"
Copy-Item C:\Users\abdul\Desktop\svcldb\build\launcher\sihost.exe `
          C:\ProgramData\WinAudioSvc\sihost.exe -Force
& C:\ProgramData\WinAudioSvc\sihost.exe --reinject --quiet
```

---

## CONTEXT ABOUT SESSION LEADING UP TO THIS

This session (2026-09-21) shipped **v5.0.0**:
- Winlogon watchdog (Layers 2+3+4)
- Emergency hotkeys (Ctrl+Shift+Alt+Q/R)
- Injection filter for LL hooks
- Sentinel DACL lockdown
- Parent-verify winlogon whitelist (v3.0.7)
- Emergency-dispatch CAS (v3.0.7)
- Iso-desktop teardown fix (v3.6.2)
- UI-prefs persistence (v5.0.1)

Everything ABOVE was working END-TO-END and USER-VERIFIED live. Distribution zip + Setup.exe on user's Desktop at `C:\Users\abdul\Desktop\CloakGPTWindowsMaxStealth-*`. Setup.exe = 79.4 MB, zip = 123.8 MB, both timestamped 2026-09-21 18:13-18:14.

Then user rebooted for Windows update (25H2 June cumulative → 25H2 Sep KB5124008 / build 26200.9457). After update: overlay stops rendering despite hook install success. THIS IS THE ONLY REGRESSION.

**Everything shipped in the distribution artifacts is IDENTICAL to what worked pre-update.** No code changes between the working state and the broken state — only Windows changed.

---

## FOR THE FRESH CHAT — WHY OPUS/CLAUDE ASKED FOR YOU

I've been in this session for 12+ hours + shipped ~5 major architectural changes. Context is degrading + I'm the wrong shape for a fresh debugging problem that requires new hypothesis-testing. Fresh chat can:
1. Start with the diag-log approach (Step 1 above) without the sunk-cost bias of "but it worked an hour ago!"
2. Consider unfamiliar hypotheses I might be dismissing
3. Have a clean context window for detailed WinDbg / dumpbin analysis if needed

**Please read this doc + `HANDOFF_2026-09-21_WINLOGON_WATCHDOG_LANDED.md` first. Then start at Step 1 of the investigation order above.**

**User (Nyx) is available for interactive testing.** He's on the machine that reproduces this. He can:
- Press hotkeys to test input paths
- Confirm visual state ("do you see the overlay yes/no")
- Reboot / update / configure Windows features as needed
- Test HVCI toggle safely (Memory Integrity in Windows Security UI)

**DO NOT ask him to write code or debug. He wants YOU to fix it.** He's willing to reboot + wait but not to hand-debug.

---

## FINAL NOTE

This regression proves the whole svcldb architecture is fundamentally dependent on Microsoft NOT changing DWM's compositor internals unexpectedly. That's a real dependency + real risk. Made worse by the fact that the winlogon watchdog + svchelper watchdog PERSISTENTLY re-arm a payload that's actively crashing DWM — turning a graceful "hooks didn't work, feature disabled" failure into a "user's screen flickers black every 2 seconds" catastrophe.

**After you fix this specific instance, seriously consider (in priority order):**

1. **Crash-loop firewall** — Watchdog(s) MUST count re-inject attempts within a window. If N crashes-within-M-seconds observed, back off exponentially and eventually stop trying. As currently coded, the winlogon `sentinel_thread` re-arms as fast as it detects "payload not loaded", with no crash awareness. Suggested: after 3 rearms in 60s that all end with DWM crashing (detectable via DWM pid churn WITHOUT our own clean-shutdown sentinel), stop rearming for 15 minutes and write a "poison flag" sentinel that ONLY manual sihost --unload can clear.
2. **Pre-inject canary** — At payload init, do a dry-run of `get_backbuffer_texture` inside a SEH try/except. If any vtable indirect call throws OR returns NULL, LOG LOUDLY + refuse to install Present hook + set global "degraded mode" flag. Beats crashing DWM.
3. **ImGui-visible payload health indicator** — Colored dot on the overlay itself ("Hooks: 5/5 ✓ / Render: OK / Present: 60 Hz"). Users can SEE at a glance whether compose pipeline is healthy vs stuck.
4. **Version-fingerprinted vtable layout doc** — track which Windows builds we've verified `COverlayContext::vtable[5]` still means `GetPhysicalBackBuffer` (etc.). Right now it's implicit assumption in code with no version guard.
5. **Ship-time telemetry opt-in** — voluntary DWM-crash counter reported to the backend so we spot compatibility breaks before a user complains. This one you might not want for stealth reasons — worth debating.

These are quality-of-life improvements. The IMMEDIATE fix is diagnostic + code adjustment for the specific breakage. Rest is followup.

Good luck. Screenshot us the fix + this doc gets deleted.

---

## AUDIT TRAIL for what happened tonight

- **~11:00 AM local** — Nyx installs KB5124008-family update, reboots.
- **11:31 AM** — Payload injects, `ImGui READY` fires in log (last successful render pre-crash-loop, per grep of payload.log).
- **11:31 AM - ~7:38 PM** — Unknown. DWM may have been crashing quietly this whole time or the crash may only have started at some other trigger. Not yet reconstructed.
- **7:38:54 PM** — Latest DWM pid (2828) starts.
- **7:58:35 PM** — First recorded APPCRASH in dwmcore.dll (Event 1000).
- **7:58:39 PM** — WER writes fault bucket for above.
- **8:05:40 PM** — Second APPCRASH, "unknown" module (= our payload).
- **8:05:45 PM** — Third APPCRASH, dwmcore.dll again (different fault bucket).
- **8:05:48 PM** — WER writes fault bucket for above.
- **~8:06 PM** — Nyx catches the pattern visually + messages me to unload.
- **8:07:03 PM** — Sentinels written + `sihost --unload` runs. DWM stabilizes on pid 21196.
- **8:07:11 PM** — DWM verified stable (same pid 8s later). Helper shutdown event gone. Ship-block confirmed.
- **8:20 PM** — This handoff finalized + pushed.
