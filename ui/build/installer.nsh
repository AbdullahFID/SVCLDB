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

  DetailPrint "Existing install detected — cooperatively uninjecting overlay..."
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
  DetailPrint "Uninjecting overlay and stopping CloakGPT processes..."
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
  DetailPrint "Restoring Windows AutoRestartShell to default..."
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
