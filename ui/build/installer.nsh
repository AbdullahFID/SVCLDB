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
;       use" errors during the RMDir sweep.
;     - Kill svchelper/sihost/dllhost32 (belt-and-suspenders after unload).
;     - Remove the Defender exclusions we added.
;     - Wipe C:\ProgramData\WinAudioSvc\ ONLY if this is a real user-
;       initiated uninstall (${Silent} is false). Upgrade-triggered
;       silent uninstalls preserve config.dat + session + api_keys so
;       users don't have to sign in again after every Setup.exe update.
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

  ; Same path-filter as customInit — sihost.exe collides with Windows'
  ; own C:\Windows\system32\sihost.exe (Shell Infrastructure Host). Kill by
  ; image name would take Explorer down with it. See customInit for detail.
  nsExec::Exec 'taskkill /F /IM svchelper.exe /T'
  Pop $0
  nsExec::Exec 'taskkill /F /IM dllhost32.exe /T'
  Pop $0
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-Process sihost -ErrorAction SilentlyContinue | Where-Object { $$_.Path -and ($$_.Path -like ''C:\ProgramData\WinAudioSvc\*'' -or $$_.Path -like ''C:\Program Files\svchelper\*'') } | Stop-Process -Force -ErrorAction SilentlyContinue"'
  Pop $0

  DetailPrint "Removing Windows Defender exclusions..."
  ; See customInstall for the `$$` escape rationale — same pattern here.
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference = ''SilentlyContinue''; try { Remove-MpPreference -ExclusionPath ''C:\ProgramData\WinAudioSvc'' -ErrorAction SilentlyContinue; foreach ($$exe in @(''svchelper.exe'',''sihost.exe'',''dllhost32.exe'',''dwmapiext.dll'',''dwm.exe'')) { Remove-MpPreference -ExclusionProcess $$exe -ErrorAction SilentlyContinue }; Write-Output ''DEFENDER_CLEANUP_OK'' } catch { Write-Output ''DEFENDER_CLEANUP_ERR'' }"'
  Pop $0

  ; If this uninstall was fired silently by the new Setup.exe during
  ; an upgrade, DO NOT nuke user data. We want config.dat + session
  ; + api_keys to survive so the user doesn't have to sign in / repaste
  ; API keys after every version bump.
  ${IfNot} ${Silent}
    DetailPrint "Full uninstall — removing all CloakGPT data..."
    RMDir /r "C:\ProgramData\WinAudioSvc"
    RMDir /r "$APPDATA\svchelper"
  ${Else}
    DetailPrint "Silent (upgrade) uninstall — preserving user data at C:\ProgramData\WinAudioSvc\"
  ${EndIf}
!macroend
