```
# AUDIT REPORT: Installer + Electron UI + Launcher (non-auth)

## Summary
- Files audited: 11 (installer.nsh, install-cloakgpt.ps1, build-distribution.ps1, build-protected.js, package.json, main.js, injector.js, renderer.js, index.html, launcher/main.c, ocr_scanner.cpp) + ~6 supporting (log_secure.h, storage.js, config_types.h, obf-names, preload.js, _rename_log_files.ps1)
- Total findings: 12 (P0: 0, P1: 3, P2: 6, P3: 3)
- Overall verdict: Ship-safe for the installer + launcher surface. No P0 install-breaks, no Explorer-kill regressions, no user-data-loss paths. Two P1s materially degrade support (log export empty) and product-truth (users see the wrong version string). Recommend fixing both P1s before the next public ship; P2s are steady-state hardening.
- Estimated hours to fix all P0/P1: ~1.5h (log-export filter widen + probe rename ~30 min, package.json version bump + smoke test ~15 min, buffer for release verification ~45 min)

---

## P0 (Install fails / kills Explorer / user data loss / bricks system)

_None found. The known-hazard surfaces (path-filtered sihost.exe kill in `installer.nsh` customInit/customUnInstall + `install-cloakgpt.ps1` Stop-OurProcesses + launcher `--kill-all` sibling sweep) all correctly gate by full image path before terminating, so Windows' own `C:\Windows\System32\sihost.exe` is never touched._

---

## P1 (Install glitch / shortcut missing / watchdog loop / upgrade breaks)

### Finding P1-1: `logs:export` ships an EMPTY diagnostic bundle (support blind)
- File:line: `ui/src/main.js:2494` (`isLogLike`) + `ui/src/main.js:2504` (readdir filter) + `ui/src/main.js:1517-1518` (`logProbe` calls)
- Symptom: User hits "Export logs" on the dashboard, gets `cloakgpt-logs-<ts>.zip` on Desktop. Zip contains ONLY `meta.json`. Every C-side log file is silently skipped, so support has nothing to decrypt. The dashboard's "Support" card metadata also reports "0 KB / not present" for the log probes.
- Root cause: v3.3-hardening (2026-09-23) renamed every log to opaque `.dat` names (`payload.log`â†’`msvc_dbg_a.dat`, `launcher.log`â†’`msvc_dbg_b.dat`, plus `_c`/`_d`/`_e`/`_f`/`_g` â€” see `shared/log_secure.h:38-42` + `tools/_rename_log_files.ps1`). The Electron export filter kept its old extension whitelist:

```2494:2495:ui/src/main.js
    const isLogLike = (name) =>
      /\.(log|blob|txt|hex)$/i.test(name) || name === '.dwm_clean_shutdown';
```

`.dat` is not in the set, so `readdir(SVC_INSTALL_DIR)` matches zero real logs. The support-metadata probes at lines 1517-1518 also still point at pre-rename names that will never exist again:

```1517:1518:ui/src/main.js
    logProbe('log A', path.join(SVC_INSTALL_DIR, 'payload.log'));
    logProbe('log B', path.join(SVC_INSTALL_DIR, 'launcher.log'));
```

- Repro: On a v3.3+ deploy after the payload has run at least once, click Export logs on the dashboard. Open the zip: only `meta.json`. Grep the zip for `msvc_dbg`: zero matches. The support-metadata card shows both probes as "not present" despite `dir C:\ProgramData\WinAudioSvc\msvc_dbg_*.dat` returning multiple multi-KB files.
- Fix:
  1. Widen `isLogLike` to include `.dat` for the mangled names, and OPTIONALLY tighten the copy so it only picks `msvc_dbg_*.dat` (not any random `.dat` a future asset might drop):
     ```js
     const isLogLike = (name) =>
       /^msvc_dbg_[a-z]\.dat$/i.test(name)     // v3.3+ renamed logs
       || /\.(log|blob|txt|hex)$/i.test(name)  // legacy + offsets.blob + api_key.txt.hex
       || name === '.dwm_clean_shutdown';
     ```
  2. Rewrite the two `logProbe` calls to the current names:
     ```js
     logProbe('log A (payload)',  path.join(SVC_INSTALL_DIR, 'msvc_dbg_a.dat'));
     logProbe('log B (launcher)', path.join(SVC_INSTALL_DIR, 'msvc_dbg_b.dat'));
     logProbe('log D (ai)',       path.join(SVC_INSTALL_DIR, 'msvc_dbg_d.dat'));
     logProbe('log G (auth)',     path.join(SVC_INSTALL_DIR, 'msvc_dbg_g.dat'));
     ```
- Confidence: HIGH. Renamed logs are the single source of truth (`shared/log_secure.h:38-42` + grep in `payload/`, `launcher/`, `shared/` all use `msvc_dbg_*.dat`). Nothing in the codebase writes the old names anymore.

### Finding P1-2: User-visible version is `v6.7.0.0`, not `v6.9.0.0` â€” v-ctrlb-hardening bump is dead code
- File:line: `ui/package.json:3` (`"version": "6.7.0"`) + `ui/src/renderer.js:200-222` (dynamic-version overwrite) + `ui/src/index.html:23,77` (hardcoded `v6.9.0.0` placeholders)
- Symptom: The audit brief says v-ctrlb-hardening bumped titlebar-ver + login-app-ver from v6.7.0.0 to v6.9.0.0 in `ui/src/index.html`. In a real packaged build the user sees `v6.7.0.0` in both spots â€” the HTML strings render for one paint frame and are then overwritten by the renderer.
- Root cause: The renderer's IIFE at boot reads `app.getVersion()` (which comes from `ui/package.json`) and unconditionally replaces both `#titlebar-ver` and `#login-app-ver`:

```206:222:ui/src/renderer.js
  (async () => {
    try {
      const v = await window.svc.app.getVersion();
      if (!v) return;
      const parts = String(v).split('.');
      const display = (parts.length === 3 && parts.every(p => /^\d+$/.test(p)))
        ? v + '.0' : v;
      const short = 'v' + display;
      const long  = 'CloakGPT v' + display;
      const tb    = document.getElementById('titlebar-ver');
      if (tb)  tb.textContent = short;
      const lv   = document.getElementById('login-app-ver');
      if (lv)  lv.textContent = long;
    } catch { /* preload not ready during dev â€” index.html defaults suffice */ }
  })();
```

Because `package.json.version` is still `"6.7.0"`, the display becomes `v6.7.0.0`. The `v6.9.0.0` bump in `index.html` only shows in dev mode when preload fails.

- Repro: `pnpm build` in `ui/`, run `dist/win-unpacked/svchelper.exe`, look at titlebar and login screen. Both read `v6.7.0.0`. Also `Get-Content ui\package.json | Select-String '"version"'` returns `"version": "6.7.0"`.
- Fix: Bump the SINGLE source of truth. In `ui/package.json`:
  ```json
  "version": "6.9.0",
  ```
  (Electron-builder / npm cap semver at 3 segments â€” the renderer already synthesises the `.0` suffix for display.) Leave the HTML placeholders as `v6.9.0.0` for dev-mode consistency, but nothing else needs to change.
- Confidence: HIGH. Verified by reading both files; the IPC handler at `ui/src/main.js:2217` (`ipcMain.handle('app:get-version', () => app.getVersion())`) confirms the runtime value.

### Finding P1-3: Electron `respawnWatchdog` has NO crash-count back-off â€” depends entirely on winlogon panic sentinel
- File:line: `ui/src/main.js:414-676` (whole `respawnWatchdog` IIFE), specifically the `tick()` body at `ui/src/main.js:492-635`
- Symptom: If the payload's inject succeeds, DWM subsequently crashes (bad dwmcore offset, MPO edge case, third-party graphics driver), and the winlogon-hosted helper is UNABLE to inject (HVCI on, EDR blocks winlogon-DLL-mapping, `arm_helper_best_effort` logged failure and returned void â€” see `launcher/src/main.c:350-357`), the Electron watchdog will detect `probe==='no'`, verify DWM respawned, and blindly re-inject on every 5-second tick forever. The winlogon-side firewall `fw_count_recent_churn`/`fw_trip` (which writes `.dwm_user_panic` after 3 crashes in 90s) never runs because the helper never loaded, so nothing ever writes the panic sentinel and the Electron watchdog never disarms itself.
- Root cause: `tick()` checks (in order): busy, lastArgs, probe status, post-inject grace, confirmedAlive, sentinels, DWM pid diff, in-flight mutex â€” then re-injects. There is NO in-Electron "N crashes within window â†’ trip" logic. All churn suppression is delegated to the winlogon helper. Reading the code confirms:

```599:625:ui/src/main.js
      if (nowPid === baselinePid) {
        /* DWM survived; payload died for another reason (crashed, was
         * killed by AV / EDR, etc). Re-inject anyway ...
         */
      }
      ...
      console.log(`[respawn-watchdog] payload gone (baseline_pid=${baselinePid} now=${nowPid}); ` +
                  `re-injecting with saved args`);
      _injectInFlight = true;
      try {
        const r = await injector.inject(lastArgs);
```

- Repro: Force a scenario where helper injection fails (e.g., HVCI-enabled dev box, or set `SVC_HELPER_RCDATA_ID` to a bogus ID in a test build). Force DWM crashes (kill dwm.exe in a loop from an elevated shell). Observe `main.log`: "[respawn-watchdog] re-inject OK" every ~5s indefinitely with no ceiling, plus CPU + log churn from repeated resolver+manual-map.
- Fix: Add a lightweight ring-buffer inside `respawnWatchdog` â€” mirror the winlogon design at a coarser cadence:
  ```js
  const CRASH_WINDOW_MS = 120_000;   // 2 min
  const CRASH_THRESHOLD = 3;         // 3 respawns in that window trips us
  const crashTimestamps = [];        // sliding window
  ...
  // Inside tick() right after `status === 'no'` + confirmed-alive check:
  const now = Date.now();
  crashTimestamps.push(now);
  while (crashTimestamps.length && now - crashTimestamps[0] > CRASH_WINDOW_MS)
    crashTimestamps.shift();
  if (crashTimestamps.length >= CRASH_THRESHOLD) {
    console.log('[respawn-watchdog] TRIP â€” 3 respawns in 2 min; writing .dwm_user_panic + disarming');
    try {
      require('fs').writeFileSync(
        'C:\\ProgramData\\WinAudioSvc\\.dwm_user_panic',
        'electron_watchdog_trip\n', { mode: 0o644 });
    } catch {}
    lastArgs = null;
    if (timer) { clearInterval(timer); timer = null; }
    sendToRenderer('injector:user-quit', { reason: 'watchdog_trip' });
    return;
  }
  ```
  Reset `crashTimestamps` inside `arm()` so a fresh user-triggered inject starts with a clean budget.
- Confidence: MEDIUM-HIGH. The design intent is documented (winlogon is the authority) but there is no defense-in-depth here for the "winlogon unavailable" case, and HVCI-blocked winlogon injection is a real user story (Windows 11 24H2 defaults + Insiders + Copilot+ PCs).

---

## P2 (Latent bug)

### Finding P2-1: Slot 0/1/2 (ASK/TOGGLE/TYPING) have no unbind lock â€” user can orphan the overlay
- File:line: `ui/src/renderer.js:3373-3378` (recorder-modal Unbind handler) + `ui/src/renderer.js:2774-2846` (editor row build; no per-slot guard)
- Symptom: User opens Settings â†’ Hotkeys, clicks the pencil next to "Screenshot + Ask AI" (slot 0) or "Toggle overlay" (slot 1) or "Chat mode (type)" (slot 2), hits the "Unbind" button in the recorder modal, confirms. Slot is now `_hkState.overrides[slot] = 0` â†’ next inject writes 0 into `cfg->hotkeys[0..2]` â†’ payload treats 0 as inert â†’ user has NO way to summon the overlay (they can still Alt-Tab to svchelper.exe and click Uninject Now, but there is no in-overlay recovery). The only surviving trigger is the fixed `SVC_HK_QUICK_ASK` mouse-multi (middle-triple-click) at slot 33.
- Root cause: The recorder's Unbind handler blindly writes 0:

```3373:3378:ui/src/renderer.js
  document.getElementById('rec-unbind').addEventListener('click', async () => {
    _hkState.overrides[slot] = 0;
    await window.svc.hotkeys.save(_hkState.overrides);
    _closeRecorder(true);
    toast(`Unbound ${HK_LABELS[slot]}.`, 'ok');
  });
```

There is no allow-list check, no confirm dialog, no reset-to-default fallback. `HK_LABELS[0..2]` are `'Screenshot + Ask AI'`, `'Toggle overlay'`, `'Chat mode (type)'` (`ui/src/renderer.js:2298-2300`).
- Repro: Fresh dashboard â†’ Hotkeys â†’ pencil next to Toggle overlay â†’ Unbind â†’ Save. Close app, relaunch, inject. Hit `Ctrl+B` (default TOGGLE binding) â€” nothing. Hit any other binding â€” same overlay behavior as normal. The only way to recover is Settings â†’ Hotkeys â†’ Reset all.
- Fix: In the recorder's Unbind handler (and the mode-toggle chip's `newPacked = 0` fallback), guard slots 0/1/2:
  ```js
  const CRITICAL_SLOTS = new Set([0, 1, 2]);   // SVC_HK_ASK, TOGGLE, TYPING
  document.getElementById('rec-unbind').addEventListener('click', async () => {
    if (CRITICAL_SLOTS.has(slot)) {
      toast(`${HK_LABELS[slot]} is a core action and can't be unbound. Choose a different key or hit Cancel.`, 'err');
      return;
    }
    _hkState.overrides[slot] = 0;
    ...
  });
  ```
  Optionally hide the Unbind button entirely for critical slots via `if (CRITICAL_SLOTS.has(slot)) { document.getElementById('rec-unbind').style.display = 'none'; }` when the modal opens.
- Confidence: HIGH.

### Finding P2-2: NSIS installer Defender-exclusion failures are swallowed silently (no user surface)
- File:line: `ui/build/installer.nsh:118` (customInstall PS one-liner)
- Symptom: On boxes where Defender is GPO-managed (school-issued laptops, corporate MDM, `Set-MpPreference -MAPSReporting Disabled`-locked-out systems), `Add-MpPreference` fails silently. The NSIS installer's `try { â€¦ } catch { Write-Output ('DEFENDER_SKIP: ' + $$_.Exception.Message) }` swallows the exception and the installer proceeds to "Install complete." No user-facing message. User launches, sihost.exe gets quarantined within minutes, then hits `LAUNCHER_MISSING` errors on next inject. `install-cloakgpt.ps1` handles this case correctly (increments `$exErrors`, prints a `[WARN]` line with manual instructions at `install-cloakgpt.ps1:477-482`), but Setup.exe does not.
- Root cause: `nsExec::ExecToLog` captures the PS output into the DetailPrint log window only. Users on the one-click install path never see DetailPrint (it flashes past). The `DEFENDER_SKIP` message never becomes a `MessageBox` or a `SetErrorLevel + MessageBox` gate.
- Repro: On a machine with `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions` locked by GPO, run `CloakGPTWindowsMaxStealth-Setup.exe`. Installer says "Install complete." Inspect exclusions: `Get-MpPreference | Select ExclusionPath, ExclusionProcess` â†’ CloakGPT paths not present.
- Fix: Capture the exit output into a var, MessageBox on skip:
  ```
  nsExec::ExecToStack 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "... Write-Output ''DEFENDER_OK'' ... catch { Write-Output (''DEFENDER_SKIP: '' + $$_.Exception.Message) }"'
  Pop $0   ; exit code
  Pop $1   ; stdout
  ${If} $1 S<> "DEFENDER_OK*"
    MessageBox MB_OK|MB_ICONEXCLAMATION "Windows Defender exclusions could not be added (details: $1). CloakGPT will still install, but Defender may quarantine binaries after install. Manually add C:\ProgramData\WinAudioSvc to Defender exclusions if that happens."
  ${EndIf}
  ```
  Or at minimum, log the skip to a file the user can grep (`$INSTDIR\install.log`) so support can diagnose.
- Confidence: MEDIUM. GPO-managed Defender is common in the target user segment (students on school-issued laptops). Silent failure is a known field-issue trigger.

### Finding P2-3: `arm_helper_best_effort` returns void â€” Electron never learns winlogon inject failed
- File:line: `launcher/src/main.c:323-358`
- Symptom: When winlogon-helper injection fails (HVCI blocks, EDR intervention, resource 102 missing, winlogon token acquire denied) the launcher logs the failure to `msvc_dbg_b.dat` and continues silently. `--reinject` and `--json-config` both `ExitProcess(0)`. Electron's `injector.inject()` reads exit code 0 â†’ arms the respawn watchdog â†’ dashboard shows "Payload injected". User later uses LDB or another isolated-desktop app, notices keyboard input is dead there, has no diagnostic pointer.
- Root cause:

```349:358:launcher/src/main.c
    if (ok) {
        slog_writef("msvc_dbg_b.dat", "%s: helper (winlogon) inject OK", ctx);
    } else {
        slog_writef("msvc_dbg_b.dat",
                    "%s: helper inject FAILED (%s) -- isolated-desktop input degraded, "
                    "Default overlay + input remain fully functional",
                    ctx, err);
    }
}
```

Return type is `static void`; caller has no way to know. Combined with P1-3, this means the "no back-off" watchdog + no helper = infinite Electron reinject loop, and the user only learns about it from the log.
- Fix: (a) Return an `int` from `arm_helper_best_effort` and propagate a distinct non-fatal exit-code diagnostic through `--json-config` / `--reinject` (e.g. `ExitProcess(0)` on full success, `ExitProcess(20)` on payload-OK-but-helper-failed). (b) In Electron `injector.inject()`, treat 20 the same as 0 for the "was payload injected" question but surface a soft banner: "Overlay live. Isolated-desktop input (e.g. LDB fullscreen) may be degraded â€” see support if you see keyboard freeze during exams."
- Confidence: MEDIUM. Documented "graceful degradation" in the source, but zero diagnostic path for the user.

### Finding P2-4: `--kill-all` writes `.dwm_user_panic` AFTER Sleep(300) + Terminate + sweep â€” 5s race with in-flight `--reinject`
- File:line: `launcher/src/main.c:1187-1276` (kill-all flow)
- Symptom: User presses `Ctrl+Shift+Alt+K` (KILL_ALL hotkey; payload spawns `sihost --kill-all` via `secure_inject.c`). At the same moment, the Electron respawn watchdog's 5s tick fires and detects `probe==='no'` because the payload just signaled shutdown. Watchdog's sentinel check runs FIRST (checks for `.dwm_user_panic`), sees no file yet (it hasn't been written â€” the launcher is still on Sleep(300) or mid-sweep), then re-injects. `--kill-all` then writes the panic sentinel a few hundred ms later â€” too late; the fresh payload is already re-injecting.
- Root cause: In `--kill-all`, the sentinel is written LAST (`launcher/src/main.c:1247-1272`), after signal(300ms) + DWM terminate + sibling sihost sweep. The Electron watchdog checks the sentinel at the top of `tick()` (`ui/src/main.js:562-591`) but has no way of knowing a kill-all is in flight. The `_injectInFlight` mutex is local to `respawnWatchdog` and doesn't cross the launcher process boundary.
- Repro: Instrument `--kill-all` to add `Sleep(6000)` before the sentinel write. Trigger the KILL_ALL hotkey. In ~5-10s the Electron watchdog re-injects the payload before the sentinel is written, defeating the emergency stop. In production this is much rarer (Sleep 300 + terminate + sweep â‰ˆ 500-1500ms, usually below the next watchdog tick) but not unreachable â€” a slow snapshot enumeration in `Process32First/Next` on a heavily-loaded box can push past 5s.
- Fix: Write the panic sentinel FIRST, before any Sleep/Terminate/Sweep:
  ```c
  if (kill_all_mode) {
      DWORD self_pid = GetCurrentProcessId();
      slog_writef("msvc_dbg_b.dat", "--kill-all: begin (self=%lu)", self_pid);

      /* v-audit: write sentinel FIRST so any concurrent watchdog tick
       * disarms before we finish sweeping. */
      (void)svc_write_locked_sentinel(SVC_INSTALL_DIR "\\.dwm_user_panic",
                                      "panic\n", 6);
      DeleteFileA(SVC_INSTALL_DIR "\\.dwm_clean_shutdown");

      int signaled = inject_signal_unload();
      ...
  }
  ```
  Mirror in the payload-inline KILL_ALL path (`payload/src/dllmain.c` where SVC_HK_KILL_ALL fires â€” see `dllmain.c` handler for the hotkey) so both entry points sentinel-first.
- Confidence: MEDIUM. Reproducible on synthetic delay; naturally rare in the wild but the whole point of KILL_ALL is that it must be reliable when the user hits it.

### Finding P2-5: `ensureCBinariesInstalled` upgrade-detection blind to same-size/newer-mtime rebuilds (rare) AND to backwards-clock installs
- File:line: `ui/src/main.js:148-158` (upgrade detection) + `ui/src/main.js:182-193` (per-file copy)
- Symptom: Two edge cases.
  1. **Same-size rebuild**: `upgradeDetected = s.mtimeMs > d.mtimeMs && s.size !== d.size` (AND, not OR). If the bundled `sihost.exe` has a different mtime but coincidentally the same byte size (patch-only rebuild, deterministic build, negligible source delta), `upgradeDetected` stays false â†’ **no uninject before overwrite** â€” but the per-file `needCopy` at line 187 uses OR (`s.mtimeMs > d.mtimeMs || s.size !== d.size`), so the file IS still copied. On Windows this could produce a sharing-violation error because the manual-mapped payload still references the on-disk copy for its RCDATA re-read fallback.
  2. **Backwards clock**: If the user rolls back their system clock (or the bundled binaries were copied via robocopy with `/COPY:DAT` preserving old mtimes), `s.mtimeMs > d.mtimeMs` is false. If size ALSO happens to match, `needCopy` is false â†’ user runs indefinitely with the stale binary.
- Root cause: mtime comparison across systems is unreliable. Content hash (SHA-256 of `sihost.exe` bytes) would be authoritative but is heavier.
- Fix: Two low-cost improvements:
  1. Change the upgrade detection to OR: `if (s.mtimeMs !== d.mtimeMs || s.size !== d.size) { upgradeDetected = true; ... }` â€” any difference triggers the uninject.
  2. On first Electron launch of a new package (detected by a version-stamp file in ProgramData holding the last-installed `app.getVersion()`), force-copy all bundled bins regardless of mtime/size. Cheap belt-and-suspenders.
- Confidence: LOW-MEDIUM. Case 1 is real but rare in practice (release rebuilds change size); case 2 requires an aggressively broken user state. Left as P2 rather than P3 because the ProgramData binary mirror is load-bearing and a stale copy = subtle post-Windows-update failure.

### Finding P2-6: Zip installer PS execution-policy dependency undocumented â€” can silently fail before the self-elevate block runs
- File:line: `ui/tools/install-cloakgpt.ps1:1-33` (self-elevate) + `ui/src/index.html`/user-facing instructions (implied user flow)
- Symptom: User right-clicks `install-cloakgpt.ps1` inside the extracted zip â†’ chooses "Run with PowerShell". On a machine where GPO sets `MachinePolicy` `ExecutionPolicy=Restricted` (common in AD-joined domains), the shell integration invokes `powershell.exe -File install-cloakgpt.ps1` WITHOUT `-ExecutionPolicy Bypass`, so PS refuses to run the script at the parse stage. The self-elevate block at line 11 never executes. User sees a red "cannot be loaded because running scripts is disabled" flash then nothing.
- Root cause: The `-Verb RunAs` re-launch inside the self-elevate block does pass `-ExecutionPolicy Bypass`, but that block itself can't run under Restricted MachinePolicy. The zip's docs (`docs/INSTRUCTIONS.md` / on-Desktop `CloakGPT Setup Instructions.md`) tell users the "right-click â†’ Run with PowerShell" recipe as if it were universal.
- Repro: In a VM, set `Group Policy Editor â†’ Computer Configuration â†’ Administrative Templates â†’ Windows Components â†’ Windows PowerShell â†’ Turn on Script Execution: Disabled`, apply. Extract zip. Right-click â†’ Run with PowerShell. Nothing installs.
- Fix: Ship a `install-cloakgpt.cmd` sibling shim inside the zip:
  ```bat
  @echo off
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-cloakgpt.ps1" %*
  ```
  Update the zip-flow instructions ("CloakGPT Setup Instructions.md") to say "Right-click `install-cloakgpt.cmd` â†’ Run as administrator" (which is universal). Keep the `.ps1` for power users. Bundle the `.cmd` in `ui/tools/build-distribution.ps1` right beside `install-cloakgpt.ps1` at zip staging.
- Confidence: MEDIUM. This is a well-known corp-managed Windows failure mode. Setup.exe path doesn't have this bug (NSIS bypass PS entirely); the zip fallback matters for the exact user segment (school-managed devices) most likely to have it locked.

---

## P3 (Nit / hygiene)

### Finding P3-1: `ui/build/installer.nsh` contains 423 non-ASCII bytes (â• box-drawing chars in comment banners)
- File:line: `ui/build/installer.nsh:1-7` (comment banner uses `â•` throughout)
- Symptom: Cosmetic only â€” NSIS ignores all `;`-prefixed comment content, so the â• characters never reach the installer runtime. But per AGENTS.md invariant #34 ("Both scripts MUST stay ASCII-only"), this is a documented violation. If the file is ever re-saved by an editor that mangles the UTF-8 BOM or re-encodes, the byte pattern could shift and confuse `makensis`.
- Fix: Replace the â• box-drawing lines with ASCII `=` runs. Nothing else in the file needs to change:
  ```
  ; ===============================================================
  ; installer.nsh -- Custom NSIS macros for CloakGPTWindowsMaxStealth-Setup.exe.
  ; ===============================================================
  ```
- Confidence: HIGH (verified via a byte scanner).

### Finding P3-2: `build-protected.js` bytecode driver file leaks under abnormal exit
- File:line: `ui/build-protected.js:369-423` (`_bytecode_compile.js` temp write + finally cleanup)
- Symptom: The bytecode compilation step writes `ui/_bytecode_compile.js` to the workspace root, invokes Electron on it, then deletes it in a `finally` block. If the outer Node process is SIGKILL'd (build server hard-kill, power loss, Ctrl+Break outside the trap), the file lingers. Next `pnpm build` re-writes it fine (overwrite), but a stray commit could ship the driver into `dist/` â€” actually no, it lives at ROOT not `src/`, and `files: ["src/**/*", "node_modules/**/*"]` in `ui/package.json:71-73` excludes it. So NOT a ship risk, but IS a git-status noise risk.
- Fix: Rename the driver to a hidden-file location like `path.join(os.tmpdir(), '_svc_bc_' + Date.now() + '.js')` so it never lives in the workspace, and add `ui/_bytecode_compile.js` to `.gitignore` as belt-and-suspenders.
- Confidence: HIGH.

### Finding P3-3: OCR daemon supervisor race â€” `ocr:set-enabled` waits up to 6s for winlogon's 5s poll
- File:line: `ui/src/main.js:3231-3255` (`ocr:set-enabled` IPC)
- Symptom: When user toggles OCR redactor ON, `ocrWaitForPipe(6000)` polls the pipe. The winlogon supervisor polls the enabled flag every 5s (per the comment at line 3239-3241). If the user's toggle-on lands 4900ms into a supervisor tick, the daemon spawn happens at T=5000ms, sihost boots + OCR engine inits (~1-2s), pipe appears at Tâ‰ˆ7000ms â€” which is > `ocrWaitForPipe`'s 6s deadline. User sees the "Daemon did not come up within 6s â€” winlogon supervisor may be rate-limited; try again in a minute" toast even though it's just slow, not rate-limited. Cosmetic.
- Fix: Bump `ocrWaitForPipe` deadline to 9000ms (matches worst-case 5s + 3s init + 1s slack), OR call the supervisor's "force poll" pipe if one exists (currently doesn't â€” this would be a wl_input.c addition).
- Confidence: HIGH.

---

## Files audited
- `ui/build/installer.nsh` (customInit/customInstall/customUnInstall â€” path-filtered kill, Defender exclusion add/remove, ProgramData mirror, silent-upgrade preserves data, cooperative unload)
- `ui/tools/install-cloakgpt.ps1` (self-elevate, hardened shortcut writer, Public Desktop fallback, over-the-shoulder-UAC detection, uninstall flow)
- `ui/tools/build-distribution.ps1` (OneDrive-safe Desktop resolution, Setup.exe copy, zip staging, Compress-Archive, .lnk admin-flag byte-patch)
- `ui/build-protected.js` (integrity stamp, obfuscation tiers, bytenode compile, srcâ†”src-build swap + restore, asar extract, second-pass NSIS wrap)
- `ui/package.json` (nsis block, extraResources manifest, files glob, requestedExecutionLevel)
- `ui/src/main.js` (`ensureCBinariesInstalled`, `ensureDefenderExclusions`, single-instance, `respawnWatchdog`, OCR settings + IPC, `logs:export`, install-secret write path)
- `ui/src/injector/injector.js` (`_guardLauncher`, `ensureBinariesPresent`, `probePayload` tri-state, `buildJson`, `inject`/`uninject`/`killAll` promises + timers)
- `ui/src/renderer.js` (tier chip persistence, hotkey editor row build, recorder modal Unbind path, mode-toggle chips, stealth-preset modal)
- `ui/src/index.html` (titlebar-ver + login-app-ver strings, Support card, provider-row markup)
- `launcher/src/main.c` (`--status`/`--unload`/`--kill`/`--kill-all`/`--reinject`/`--json-config`/`--ocr-daemon` dispatch, `heal_log_dacls_all`, `dwmcore_time_date_stamp` + `auto_refresh_offsets_if_stale`, `verify_svchelper_parent`, `arm_helper_best_effort`, IL/elevation gate)
- `launcher/src/inject.c` (via cross-references â€” signal/verify helpers)
- `launcher/src/ocr/ocr_scanner.cpp` (header + first ~200 lines â€” WinRT init, defaults, log_line macro)
- Supporting: `shared/log_secure.h`, `shared/config_types.h` (SVC_HK_PACK / kind bits), `ui/src/license/storage.js` (uiPrefs + hotkey overrides), `ui/src/preload.js` (IPC surface), `tools/_rename_log_files.ps1`

## Non-issues investigated
1. **Path-filtered `sihost` kill (installer.nsh customInit AND customUnInstall)** â€” PowerShell `Get-Process sihost â€¦ Where-Object Path -like 'C:\ProgramData\WinAudioSvc\*' -or 'C:\Program Files\svchelper\*'` correctly filters by full image path. Windows' own `C:\Windows\System32\sihost.exe` cannot match either wildcard. **No bug.**
2. **`--kill-all` sibling sweep in launcher** (`launcher/src/main.c:1213-1246`) uses `_strnicmp(image, SVC_INSTALL_DIR, strlen(SVC_INSTALL_DIR))` â€” full-path prefix check, same discipline. **No bug.**
3. **`.lnk` admin-flag byte-patch** (both `build-distribution.ps1:145` and `install-cloakgpt.ps1:282-296`) â€” offset 0x15, bit 0x20 = `HasExpString`/`RunAsAdmin` per MS-SHLLINK Â§2.1. Both call sites verify persistence with `Test-Path` after Save() AND after byte-patch. `install-cloakgpt.ps1` returns structured result and warns if admin-flag failed. **No bug.**
4. **`heal_log_dacls_all` scope** â€” checked against `shared/log_secure.h` helpers. Included: msvc_dbg_a (payload), _c (http), _d (ai), _e (wl_input dev), config.dat, config.dat.tmp. Missing: msvc_dbg_b/f/g â€” verified via grep those are written only by launcher/resolver processes (elevated â†’ creator DACL is Admins-writable). Heal not needed for launcher-only logs. **No bug.**
5. **`heal_log_dacls_all` config.dat entries** â€” v14.2 note explicitly requires `config.dat` + `config.dat.tmp` for the DWM-N virtual-account write path. Both present at `launcher/src/main.c:300-301`. **No bug.**
6. **`SVC_HK_PACK` cross-language parity** â€” JS `pack(mod, vk)` at `ui/src/injector/injector.js:332` = `((mod & 0xFF) << 16) | (vk & 0xFFFF)`, matches C `SVC_HK_PACK` at `shared/config_types.h:507` = `((unsigned)(mod) << 16) | (unsigned)(vk)`. JS masks defensively; C trusts caller. Kind bits (24-27) and adaptive/watch flags (bits 28-29) also match across `packLongpress`, `packMultitap`, `packMouseHold`, `packMouseMulti`. **No bug.**
7. **v3.0.7 parent-verify winlogon whitelist** â€” `launcher/src/main.c:171-177` accepts both `svchelper.exe` and `winlogon.exe` as parents for `--json-config`/`--reinject`/`--ocr-daemon`. Rationale documented (injection into winlogon requires SeDebugPrivilege bypass = attacker already owns box). **No bug.**
8. **v3.2 medium-IL kill-proof** â€” `is_high_integrity()` at `launcher/src/main.c:216-232` reads the mandatory-label SID directly (not the ElevationType metadata that SAFER-derived tokens spoof). Gate at line 999 rejects `--unload`/`--kill`/`--kill-all` at Medium IL with silent exit 24. **No bug.**
9. **OCR daemon lifecycle in v6.7.0.0** â€” grep for `spawn.*ocr-daemon` in `ui/src/*.js` returns ZERO hits. Only `tools/redteam/probes/wl_input.c` (the winlogon supervisor) spawns it. `main.js:3271-3293` explicitly documents "winlogon owns the daemon lifecycle now. Nothing to auto-respawn from Electron." The `will-quit` handler correctly does NOT touch the daemon. **No stale svchelper spawn path â€” no bug.**
10. **Provider chip persistence (v5.0.1 fix regression check)** â€” `state.chosen_provider` is loaded on boot (line 254) and saved when the tier chip clicks (line 1061). The provider chip UI was REMOVED in v4.4 (comment at line 1041: "Provider chips removed in v4.4 â€” provider is auto-picked from"), so `state.chosen_provider` stays at `null` (auto). Dead-code plumbing but not a bug. **No regression.**
11. **`.dwm_clean_shutdown` / `.dwm_user_panic` sentinel honoring** â€” Electron watchdog checks BOTH at `ui/src/main.js:563-590` (delete on find + disarm). Launcher `--unload` writes clean-shutdown with parent-verify gate (`launcher/src/main.c:1132-1136`). Launcher `--kill-all` writes user_panic (`launcher/src/main.c:1262-1265`) â€” but see P2-4 for the ordering race. Both use `svc_write_locked_sentinel` for tamper-resistance. **No bug for the honoring path itself.**
12. **Cooperative unload race in installer.nsh customInit** â€” sihost `--unload` internally does `Sleep(500)` after signaling (`launcher/src/main.c:1079`); installer adds `Sleep 1500` for a total ~2000ms grace. Even for a wedged payload this exceeds the 200ms hooks-drain + 50ms MinHook-down budget the payload targets. The subsequent taskkill/PowerShell path-filter kill is the belt-and-suspenders backstop. **No bug.**
13. **Setup.exe UAC-cancel rollback** â€” NSIS oneClick + perMachine + `requestedExecutionLevel: requireAdministrator` shows UAC BEFORE any customInit runs. If user hits No, installer never gets past the UAC layer â†’ no partial state. **No bug.**
14. **`ensureCBinariesInstalled` uninject-before-overwrite (upgrade path)** â€” `main.js:161-177` correctly `spawnSync(sihost, ['--unload'])` with 4s timeout before the per-bin copy loop overwrites files. Config.dat / session / api_keys are NOT in the `bins` list so they survive. **No bug.** (Same-size edge case captured under P2-5.)
15. **NSIS second-pass shipping pre-processing artifacts** â€” build-protected.js Step 6 extracts asar â†’ `resources/app/` and deletes `app.asar`. Step 7 wraps the ALREADY-processed `dist/win-unpacked/` via `--prepackaged` â€” no re-obfuscation, no re-fuse-flip, no re-asar-pack. The `_bytecode_compile.js` driver lives at ROOT (not in `src/**/*`) and package.json's `files` glob excludes it. **No bug** (P3-2 covers the workspace-noise hygiene aspect.)
16. **Public Desktop fallback readability** â€” `[Environment]::GetFolderPath('CommonDesktopDirectory')` resolves to `C:\Users\Public\Desktop`, which Explorer merges into every logged-in user's Desktop view by default. Over-the-shoulder-UAC detection at `install-cloakgpt.ps1:207-231` compares interactive-Explorer-owner SID vs current-process SID, correctly triggers the Public copy on mismatch. **No bug.**
```
