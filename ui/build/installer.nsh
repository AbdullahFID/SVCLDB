; ═══════════════════════════════════════════════════════════════
; installer.nsh — Custom NSIS macros for CloakGPTWindowsMaxStealth-Setup.exe.
;
; Referenced from ui\package.json's `build.nsis.include`. electron-builder
; injects these macros into the generated installer script at the standard
; extension points (customInit / customInstall / customUnInstall).
;
; All shell / PowerShell invocations run ELEVATED because the installer
; declares `requestedExecutionLevel: requireAdministrator` via the manifest
; and NSIS `perMachine: true` mode auto-invokes UAC.
;
; What we do beyond the electron-builder defaults:
;
;   customInit
;     - Detect an existing install (svchelper.exe present at INSTDIR OR
;       C:\ProgramData\WinAudioSvc\sihost.exe present).
;     - If detected: cooperatively unload the running payload via
;       `sihost.exe --unload`, then kill lingering processes so we can
;       overwrite locked files. Same pattern as install-cloakgpt.ps1.
;
;   customInstall
;     - Add Windows Defender exclusions (path + processes). Same set the
;       Electron main.js `ensureDefenderExclusions()` registers on every
;       launch — doing it here means the deploy is clean before the user
;       ever opens the app for the first time.
;     - Copy the bundled C binaries from $INSTDIR\resources\ into
;       C:\ProgramData\WinAudioSvc\ so `sihost --json-config` and
;       `dllhost32.exe` are reachable at the paths hardcoded on the C
;       side. Electron's ensureCBinariesInstalled() also does this as a
;       safety net on first launch — the install-time copy is belt +
;       suspenders.
;
;   customUnInstall
;     - Cooperatively uninject the payload (sihost --unload) BEFORE
;       deleting binaries. Otherwise DWM holds the DLL and we get "file in
;       use" errors during the wipe sweep.
;     - Kill svchelper/sihost/dllhost32 (belt-and-suspenders after unload).
;     - Sleep 2s to give Windows time to release file handles from the
;       just-killed processes — WITHOUT this pause, the subsequent wipe
;       silently skips locked files. Learned the hard way: NSIS `RMDir /r`
;       does not surface locked-file errors, it just no-ops on them.
;     - Remove Defender exclusions (both bare and full-path variants —
;       legacy install-cloakgpt.ps1 uses full paths, NSIS customInstall
;       uses bare names, upgrade path may have both).
;     - Wipe C:\ProgramData\WinAudioSvc\ ONLY if this is a real user-
;       initiated uninstall (IfSilent is false). Upgrade-triggered
;       silent uninstalls preserve config.dat + session + api_keys so
;       users don't have to sign in again after every Setup.exe update.
;       Uses PowerShell Remove-Item -Recurse -Force which is more
;       forgiving of stale handles than NSIS RMDir /r; falls back to
;       RMDir /r on PowerShell failure.
;     - Wipe %APPDATA%\svchelper\ under the same condition.
; ═══════════════════════════════════════════════════════════════

; ---- customInit ---------------------------------------------------
; Fires once at installer startup, BEFORE the file overlay is written.
; Perfect place to detect + clean up prior installs so the fresh copy
; can overwrite locked binaries.
!macro customInit
  DetailPrint "Checking for existing CloakGPT install..."

  ; Detect prior install two ways: the app install dir OR the shared
  ; ProgramData dir. Either one triggers the pre-clean flow.
  StrCpy $R0 "0"
  IfFileExists "$INSTDIR\svchelper.exe" 0 +2
    StrCpy $R0 "1"
  IfFileExists "C:\ProgramData\WinAudioSvc\sihost.exe" 0 +2
    StrCpy $R0 "1"

  StrCmp $R0 "0" upgrade_skip

  DetailPrint "Existing install detected -- turning off overlay before upgrade..."
  ; Cooperative unload — signals the shutdown watcher inside DWM so
  ; the payload cleanly removes its hooks. Takes ~500 ms in the happy
  ; path, up to 5 s worst case. The `taskkill` fallbacks below cover
  ; the case where --unload hangs or the payload is already dead.
  IfFileExists "C:\ProgramData\WinAudioSvc\sihost.exe" 0 skip_unload
    nsExec::ExecToLog '"C:\ProgramData\WinAudioSvc\sihost.exe" --unload'
    Pop $0
    Sleep 1500
  skip_unload:

  DetailPrint "Stopping lingering CloakGPT processes..."
  ; svchelper.exe + dllhost32.exe are unique names to our project — safe to
  ; taskkill by image name. sihost.exe COLLIDES with Windows' Shell Infra-
  ; structure Host (C:\Windows\system32\sihost.exe) — killing that by image
  ; name causes an Explorer respawn cycle. Filter by path via PowerShell so
  ; we only touch OUR sihost.exe (deployed under C:\ProgramData\WinAudioSvc\
  ; OR bundled inside C:\Program Files\svchelper\resources\).
  nsExec::Exec 'taskkill /F /IM svchelper.exe /T'
  Pop $0
  nsExec::Exec 'taskkill /F /IM dllhost32.exe /T'
  Pop $0
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-Process sihost -ErrorAction SilentlyContinue | Where-Object { $$_.Path -and ($$_.Path -like ''C:\ProgramData\WinAudioSvc\*'' -or $$_.Path -like ''C:\Program Files\svchelper\*'') } | Stop-Process -Force -ErrorAction SilentlyContinue"'
  Pop $0

  Sleep 500

  upgrade_skip:
!macroend

; ---- customInstall ------------------------------------------------
; Fires AFTER electron-builder has written every packaged file to
; $INSTDIR. Perfect place to do post-copy setup (Defender exclusions +
; ProgramData binary mirror).
!macro customInstall
  DetailPrint "Registering Windows Defender exclusions..."
  ; Add-MpPreference is a no-op on machines where Defender is disabled,
  ; replaced by a third-party AV, or Tamper Protection blocks the call.
  ; We swallow errors — the app still works without exclusions, users
  ; just have to hit the manual Defender-settings dance from the Setup
  ; Guide. Same forgiving pattern as main.js::ensureDefenderExclusions.
  ; NOTE: `$$` escapes the literal `$` so NSIS doesn't try to interpolate
  ; PowerShell's `$exe` / `$_` / `$ErrorActionPreference` as NSIS variables.
  ; Anywhere PowerShell code needs a `$` inside these single-quoted NSIS
  ; strings, it must be written as `$$`.
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference = ''SilentlyContinue''; try { Add-MpPreference -ExclusionPath ''C:\ProgramData\WinAudioSvc'' -ErrorAction Stop; foreach ($$exe in @(''svchelper.exe'',''sihost.exe'',''dllhost32.exe'',''dwmapiext.dll'',''dwm.exe'')) { Add-MpPreference -ExclusionProcess $$exe -ErrorAction Stop }; Write-Output ''DEFENDER_OK'' } catch { Write-Output (''DEFENDER_SKIP: '' + $$_.Exception.Message) }"'
  Pop $0

  DetailPrint "Deploying runtime binaries to C:\ProgramData\WinAudioSvc\..."
  CreateDirectory "C:\ProgramData\WinAudioSvc"
  ; extraResources in package.json places these under resources/ next to
  ; svchelper.exe. We mirror them to the ProgramData install dir so the
  ; C-side paths (sihost.exe --json-config, dllhost32.exe) work before
  ; the user ever opens the Electron app for the first time. Electron's
  ; ensureCBinariesInstalled() also does this on every launch, so this
  ; step is idempotent and stays consistent if the user later runs a
  ; portable-mode copy of svchelper.exe outside the installed location.
  CopyFiles /SILENT "$INSTDIR\resources\sihost.exe"        "C:\ProgramData\WinAudioSvc\sihost.exe"
  CopyFiles /SILENT "$INSTDIR\resources\dllhost32.exe"     "C:\ProgramData\WinAudioSvc\dllhost32.exe"
  CopyFiles /SILENT "$INSTDIR\resources\dwmapiext.dll"     "C:\ProgramData\WinAudioSvc\dwmapiext.dll"
  CopyFiles /SILENT "$INSTDIR\resources\cgpt_dbghelp.dll"  "C:\ProgramData\WinAudioSvc\cgpt_dbghelp.dll"
  CopyFiles /SILENT "$INSTDIR\resources\symsrv.dll"        "C:\ProgramData\WinAudioSvc\symsrv.dll"
  ; cg_icons.ttf — Lucide icon font the DWM overlay loads by absolute path.
  ; Without it the overlay silently falls back to hand-drawn vector icons
  ; ("buns"). Bundled via package.json extraResources (shared/fonts/lucide.ttf
  ; -> cg_icons.ttf). main.js::ensureCBinariesInstalled also copies it on
  ; first launch — this install-time copy means correct icons on the very
  ; first overlay draw, before the Electron app has run.
  CopyFiles /SILENT "$INSTDIR\resources\cg_icons.ttf"      "C:\ProgramData\WinAudioSvc\cg_icons.ttf"
  ; v17 (2026-09-22) -- Geist.ttf is the CloakGPT UI typeface loaded by
  ; the DWM payload via AddFontFromFileTTF("C:\ProgramData\WinAudioSvc\
  ; Geist.ttf", ...). Bundled via package.json extraResources
  ; (shared/fonts/Geist.ttf -> Geist.ttf). main.js::ensureCBinariesInstalled
  ; also copies it on every launch as a self-heal.
  CopyFiles /SILENT "$INSTDIR\resources\Geist.ttf"         "C:\ProgramData\WinAudioSvc\Geist.ttf"

  ; ────────────────────────────────────────────────────────────
  ; v8.1 (2026-10-03) — Silent-launch scheduled task.
  ;
  ; Replaces the per-launch UAC prompt with a pre-authorized task.
  ; The user already clicked YES on this Setup.exe (NSIS requires
  ; admin to write Program Files + ProgramData + Defender exclusions),
  ; so we spend that one existing UAC consent on registering a
  ; Task Scheduler task with RunLevel=Highest. Every future launch
  ; of svchelper.exe triggers that task silently via `schtasks /run`
  ; (see ui/src/main.js self-elevation block). Result: ONE UAC prompt
  ; at install time, ZERO prompts on every subsequent launch forever.
  ;
  ; Task Scheduler is a SYSTEM-privileged service that pre-authorizes
  ; the elevated token at registration time. No HKCU hijacks, no auto-
  ; elevate manifest abuse — this is the Microsoft-documented pattern
  ; (same one OneDrive Standalone Update Task, Windows Defender
  ; Scheduled Scan, WindowsUpdate Scheduled Start all use). Defender-
  ; clean (no AMSI/behavior/VirTool signatures fire on it).
  ;
  ; Settings:
  ;   /SC ONCE /ST 00:00 /SD 01/01/2099 — far-future dormant trigger;
  ;     the task is only ever started by `schtasks /Run`, never by
  ;     an automatic schedule.
  ;   /RL HIGHEST                      — "Run with highest privileges"
  ;     grants the task the user's full elevated token (same token
  ;     UAC would have given — just via Task Scheduler Service instead
  ;     of a consent prompt).
  ;   /IT                              — Interactive token; task runs
  ;     on the user's visible desktop so the Electron window is
  ;     visible (RunOnlyIfLoggedOn=true).
  ;   (no /RU)                         — schtasks defaults the task's
  ;     Run As identity to the invoker (NSIS, running as the user who
  ;     clicked Setup.exe + consented to UAC = their SID). We used to
  ;     have /RU "%USERNAME%" here but nsExec::ExecToLog invokes
  ;     CreateProcess directly WITHOUT a cmd.exe wrapper → %USERNAME%
  ;     is NOT expanded and schtasks sees it as a literal invalid
  ;     username string, silently failing registration. Dropping /RU
  ;     entirely gets us the right identity cleanly. For over-the-
  ;     shoulder-UAC installs, the task runs for the elevating admin
  ;     only; the actual interactive user falls back to main.js's
  ;     UAC `runas` fallback — rare, documented in install-cloakgpt.ps1.
  ;
  ; Task action: svchelper.exe with --via-task argument so the self-
  ; elevation block in main.js knows it's the task-spawned instance
  ; and doesn't infinite-loop re-triggering itself if elevation
  ; somehow didn't take effect (non-admin user corner case).
  ;
  ; Idempotency: /F forces overwrite — upgrade installs re-register
  ; cleanly even if the task was manually modified.
  ; v8.1.2 (2026-10-03): task registration via shipped .ps1 file.
  ;
  ; Previous attempts to inline the full PowerShell command in an NSIS
  ; single-quoted string got burned by the escape layering hell:
  ;   NSIS single-quote → cmd arg parsing → PowerShell -Command parsing
  ; Three layers of quoting rules compounding; `''` means something
  ; different at each layer (NSIS: literal single-quote; PowerShell
  ; within a single-quoted string: escaped single-quote; PowerShell
  ; within a double-quoted string via -Command: literal empty string).
  ; With $INSTDIR containing a space (`C:\Program Files\svchelper`),
  ; the final command PowerShell received was mal-parsed and no task
  ; got registered — same TASK_OK output as success, but nothing
  ; actually persisted.
  ;
  ; Fix: ship `register-cloakgpt-task.ps1` via extraResources (see
  ; ui/package.json) and invoke it with powershell -File. Zero escape
  ; layering, zero quoting ambiguity. The .ps1 takes the exe path as
  ; a parameter so there's no $INSTDIR substitution inside the quoted
  ; command body either.
  DetailPrint "Registering silent-launch scheduled task (CloakGPT)..."
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\register-cloakgpt-task.ps1" -ExePath "$INSTDIR\svchelper.exe"'
  Pop $0
  StrCmp $0 "0" sched_ok sched_fail
  sched_ok:
    DetailPrint "  Task registered - launches will be silent (no UAC prompt)."
    Goto sched_done
  sched_fail:
    DetailPrint "  WARNING: Task registration failed (code $0) - app falls back to UAC prompts."
  sched_done:

  ; ────────────────────────────────────────────────────────────
  ; v8.2 (2026-10-03) — MAX-STEALTH REGISTRY + FILESYSTEM HIDING.
  ;
  ; Sam's ask: "whats the maximum amount of hiding for svchelper we
  ; can do with admin or system". These are the admin-at-install-time
  ; wins. All reversible on uninstall (NSIS auto-deletes the Uninstall
  ; key entire; we clear +H +S explicitly in customUnInstall below).
  ;
  ; (1) SystemComponent=1 under the Uninstall registry key -> hides
  ;     the CloakGPT entry from BOTH legacy Control Panel "Programs
  ;     and Features" AND the modern Settings > Apps > Installed Apps
  ;     list. The entry still exists in the registry (so our own
  ;     uninstall.exe is still reachable via its full path), but every
  ;     user-facing enumeration surface skips it. This is the exact
  ;     mechanism Windows uses to hide KB updates, driver packages,
  ;     and WOW64 subsystem stubs from the "Installed" view.
  ;
  ;     IMPORTANT -- electron-builder's NSIS wrapper does NOT use the
  ;     literal appId as the Uninstall subkey name. It derives a name-
  ;     based GUID (empirically a UUIDv5-ish transformation of appId;
  ;     verified live 2026-10-03 as "d6731b52-1c1c-5afd-80ce-9c2719e6fb94"
  ;     for appId "com.microsoft.svchelper"). The GUID is stable across
  ;     machines + installs (same appId -> same GUID always), but
  ;     hardcoding it here is brittle. INSTEAD we iterate every
  ;     Uninstall\* subkey (both 32-bit WOW6432Node + 64-bit view) and
  ;     flag any whose DisplayName matches our `uninstallDisplayName`
  ;     from package.json. Robust to future electron-builder bumps that
  ;     might shift the GUID transform. Belt-and-suspenders: also match
  ;     on UninstallString containing our INSTDIR, so a stale pre-v8.2
  ;     install with a different DisplayName still gets hidden.
  ;
  ; (2) +H +S attributes on $INSTDIR -> C:\Program Files\svchelper\
  ;     becomes hidden+system in default Explorer view. Won't show in
  ;     Programs' directory listing without "Show hidden files" AND
  ;     "Show protected OS files" both enabled (two options nested in
  ;     different Explorer dialogs, almost nobody has both on). CMD
  ;     `dir` likewise skips it without `/a:h`. The directory is still
  ;     fully accessible by absolute path (our own uninstall.exe +
  ;     schtasks /Run invocations keep working).
  ;
  ; (3) Legacy task cleanup (safety net for pre-v8.2 installs that
  ;     upgrade): the new nested-path task "\Microsoft\Windows\
  ;     Multimedia\AudioServiceSupport" is registered by the
  ;     register-cloakgpt-task.ps1 above; it also drops any stale
  ;     tree-root "\CloakGPT". If that script failed for any reason
  ;     (PowerShell policy, timeout), we belt-and-suspenders delete
  ;     the legacy task directly via schtasks here so a proctor never
  ;     sees "CloakGPT" at the Task Scheduler root.
  ; ────────────────────────────────────────────────────────────
  DetailPrint "Applying max-stealth registry + filesystem hiding..."

  ; (1) SystemComponent=1 on the Uninstall key -- find by DisplayName /
  ; UninstallString match since electron-builder derives a GUID subkey
  ; from appId (see rationale block above). PowerShell handles both
  ; 32-bit (WOW6432Node) + 64-bit views in a single call via
  ; Get-ChildItem on both paths.
  ;
  ; $$INSTDIR_ESC pre-escapes backslashes for the PowerShell -like
  ; pattern (which treats backslashes literally but the quoted path
  ; needs to roundtrip through NSIS -> cmd -> PowerShell cleanly).
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference = ''SilentlyContinue''; $$pattern = ''*'' + ''$INSTDIR'' + ''*''; $$flagged = 0; foreach ($$root in @(''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'',''HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'')) { if (-not (Test-Path $$root)) { continue }; Get-ChildItem $$root | ForEach-Object { $$dn = $$_.GetValue(''DisplayName''); $$us = $$_.GetValue(''UninstallString''); if (($$dn -eq ''Windows Audio Service Helper'') -or ($$dn -eq ''CloakGPT (Max Stealth)'') -or ($$dn -eq ''svchelper'') -or ($$us -like $$pattern)) { Set-ItemProperty -Path $$_.PSPath -Name ''SystemComponent'' -Value 1 -Type DWord -ErrorAction SilentlyContinue; $$flagged++ } } }; Write-Output (''SYSCOMP_FLAGGED='' + $$flagged)"'
  Pop $0

  ; (2) +H +S on the install directory. PowerShell's Set-ItemProperty
  ; -Name Attributes handles the attribute flag OR cleanly without
  ; needing attrib.exe's crusty syntax. Belt-and-suspenders attrib
  ; call as fallback for machines where PowerShell is restricted.
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference = ''SilentlyContinue''; try { $$it = Get-Item -LiteralPath ''$INSTDIR'' -Force; $$it.Attributes = $$it.Attributes -bor ''Hidden'' -bor ''System''; Write-Output ''ATTR_OK'' } catch { Write-Output (''ATTR_ERR: '' + $$_.Exception.Message) }"'
  Pop $0
  nsExec::Exec 'attrib.exe +H +S "$INSTDIR"'
  Pop $0

  ; (3) Belt-and-suspenders removal of the pre-v8.2 "\CloakGPT" root
  ; task. The new nested task is already registered by the ps1 above.
  nsExec::Exec 'schtasks.exe /Delete /TN "CloakGPT" /F'
  Pop $0

  DetailPrint "Install complete. Launching CloakGPT..."
!macroend

; ---- customUnInstall ---------------------------------------------
; Fires from the auto-generated uninstaller.
;
; ${Silent} is set to 1 by electron-builder's NSIS wrapper when the
; uninstaller is invoked BY THE INSTALLER during an upgrade (i.e. the
; new Setup.exe is running the old uninstaller to clear the way for
; the new install). We detect that state to preserve user data
; (config.dat, session, api_keys) across upgrades.
!macro customUnInstall
  DetailPrint "Turning off overlay and stopping CloakGPT processes..."
  IfFileExists "C:\ProgramData\WinAudioSvc\sihost.exe" 0 unst_skip_unload
    nsExec::ExecToLog '"C:\ProgramData\WinAudioSvc\sihost.exe" --unload'
    Pop $0
    Sleep 1500
  unst_skip_unload:

  ; v6.1 (2026-09-21) - restore Windows Winlogon AutoRestartShell to
  ; default enabled state as an unconditional safety net. svchelper's
  ; will-quit handler + all uninject IPC paths call restore() to put
  ; the reg key back to the user's saved value, but if svchelper was
  ; force-killed dirty (Task Manager end-process, machine crash, etc)
  ; the reg key would be stuck at 0. Uninstalling should ALWAYS return
  ; the machine to normal Windows behavior. Also deletes the
  ; .autorestart_saved sidecar so a subsequent reinstall starts fresh.
  DetailPrint "Restoring Windows shell defaults..."
  nsExec::ExecToLog 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoRestartShell /t REG_DWORD /d 1 /f'
  Pop $0
  Delete "C:\ProgramData\WinAudioSvc\.autorestart_saved"

  ; Same path-filter as customInit — sihost.exe collides with Windows'
  ; own C:\Windows\system32\sihost.exe (Shell Infrastructure Host). Kill by
  ; image name would take Explorer down with it. See customInit for detail.
  nsExec::Exec 'taskkill /F /IM svchelper.exe /T'
  Pop $0
  nsExec::Exec 'taskkill /F /IM dllhost32.exe /T'
  Pop $0
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-Process sihost -ErrorAction SilentlyContinue | Where-Object { $$_.Path -and ($$_.Path -like ''C:\ProgramData\WinAudioSvc\*'' -or $$_.Path -like ''C:\Program Files\svchelper\*'') } | Stop-Process -Force -ErrorAction SilentlyContinue"'
  Pop $0

  ; Critical: give Windows 2 seconds to release file handles from the
  ; just-killed processes. Without this pause, NSIS RMDir /r + PowerShell
  ; Remove-Item both silently skip locked files, leaving stale state at
  ; C:\ProgramData\WinAudioSvc\ that a subsequent fresh install re-reads
  ; (defeating the point of "uninstall then reinstall clean").
  Sleep 2000

  ; v8.1.2 (2026-10-03) — Remove silent-launch scheduled task.
  ; v8.2 (2026-10-03) — delete BOTH the new nested task AND the legacy
  ; "\CloakGPT" root name so upgrades + pre-v8.2 uninstalls both end up
  ; clean. The ps1 helper handles both internally; the schtasks /Delete
  ; fallback has to make two explicit calls. Failure of any is non-fatal.
  DetailPrint "Removing silent-launch scheduled task..."
  IfFileExists "$INSTDIR\resources\register-cloakgpt-task.ps1" use_ps1 use_schtasks
  use_ps1:
    nsExec::Exec 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\register-cloakgpt-task.ps1" -ExePath "$INSTDIR\svchelper.exe" -Action unregister'
    Pop $0
    Goto unreg_done
  use_schtasks:
    nsExec::Exec 'schtasks.exe /Delete /TN "\Microsoft\Windows\Multimedia\AudioServiceSupport" /F'
    Pop $0
    nsExec::Exec 'schtasks.exe /Delete /TN "CloakGPT" /F'
    Pop $0
  unreg_done:

  ; v8.2 (2026-10-03) — reverse the +H +S attributes applied in
  ; customInstall so RMDir / Remove-Item below can see + wipe the
  ; install directory. Hidden+System attribs don't block delete, but
  ; some AV tooling + enterprise MDM Explorer views refuse to touch
  ; marked-OS folders; stripping cleanly first avoids edge cases.
  nsExec::Exec 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference = ''SilentlyContinue''; try { $$it = Get-Item -LiteralPath ''$INSTDIR'' -Force; $$it.Attributes = ''Normal'' } catch { }"'
  Pop $0
  nsExec::Exec 'attrib.exe -H -S "$INSTDIR"'
  Pop $0

  DetailPrint "Removing Windows Defender exclusions..."
  ; See customInstall for the `$$` escape rationale — same pattern here.
  ; Expanded from customInstall's set to ALSO remove full-path exclusions
  ; from a legacy install-cloakgpt.ps1 install (that script adds full-path
  ; exclusions; NSIS customInstall adds bare names; users mid-migration
  ; may have BOTH).
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference = ''SilentlyContinue''; try { Remove-MpPreference -ExclusionPath ''C:\ProgramData\WinAudioSvc'' -ErrorAction SilentlyContinue; foreach ($$exe in @(''svchelper.exe'',''sihost.exe'',''dllhost32.exe'',''dwmapiext.dll'',''dwm.exe'')) { Remove-MpPreference -ExclusionProcess $$exe -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess (''C:\ProgramData\WinAudioSvc\'' + $$exe) -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess (''C:\Program Files\svchelper\resources\'' + $$exe) -ErrorAction SilentlyContinue }; Write-Output ''DEFENDER_CLEANUP_OK'' } catch { Write-Output ''DEFENDER_CLEANUP_ERR'' }"'
  Pop $0

  ; If this uninstall was fired silently by the new Setup.exe during
  ; an upgrade, DO NOT nuke user data. We want config.dat + session
  ; + api_keys to survive so the user doesn't have to sign in / repaste
  ; API keys after every version bump.
  ;
  ; Use bare `IfSilent` (NSIS builtin) rather than `${IfNot} ${Silent}`
  ; (LogicLib macro) — the macro form has been observed to expand
  ; unexpectedly under electron-builder's auto-generated uninstall.nsi
  ; scoping. Bare IfSilent is unambiguous.
  IfSilent unst_silent_skip 0

  DetailPrint "Full uninstall - removing all CloakGPT data..."
  ; Primary: PowerShell Remove-Item -Recurse -Force. More forgiving of
  ; stale file handles than NSIS RMDir /r, and Get-ChildItem lets us
  ; also strip read-only attributes that would block RMDir /r.
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "try { Get-ChildItem ''C:\ProgramData\WinAudioSvc'' -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { $$_.Attributes = ''Normal'' }; Remove-Item ''C:\ProgramData\WinAudioSvc'' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item ''$APPDATA\svchelper'' -Recurse -Force -ErrorAction SilentlyContinue; Write-Output ''WIPE_OK'' } catch { Write-Output (''WIPE_ERR: '' + $$_.Exception.Message) }"'
  Pop $0
  ; Belt + suspenders: NSIS RMDir /r as fallback in case PowerShell was
  ; unavailable OR blocked by execution policy. Either flow succeeding is
  ; enough — this second pass is a no-op if PowerShell already cleaned.
  RMDir /r "C:\ProgramData\WinAudioSvc"
  RMDir /r "$APPDATA\svchelper"
  Goto unst_wipe_done

  unst_silent_skip:
    DetailPrint "Silent (upgrade) uninstall - preserving user data at C:\ProgramData\WinAudioSvc\"

  unst_wipe_done:
!macroend
