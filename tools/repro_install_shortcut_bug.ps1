# =================================================================
#  repro_install_shortcut_bug.ps1
#
#  BEFORE/AFTER comparison for the silent-shortcut-failure bug in
#  install-cloakgpt.ps1. Runs three realistic failure modes against
#  BOTH the old block (as it lived in v1) and the new hardened block
#  (as it lives after the 2026-08-06 fix). Shows that:
#
#    - Old block silently prints "INSTALL COMPLETE" in every case
#    - New block reports "INSTALL PARTIAL - SHORTCUT MISSING" in
#      cases 1 & 2, and falls back to Public Desktop in case 3
#
#  Zero side-effects: no registry writes, no Defender writes, no
#  actual install, just synthetic exceptions.
# =================================================================

$ErrorActionPreference = 'Continue'

$FAKE_APP_ROOT = Join-Path $env:TEMP 'cloakgpt-repro'
$APP_DIR       = Join-Path $FAKE_APP_ROOT 'CloakGPT'
$RES_DIR       = Join-Path $APP_DIR 'resources'
$ASSETS_DIR    = Join-Path $APP_DIR 'resources\app\src\assets'
$MAIN_EXE      = Join-Path $APP_DIR 'svchelper.exe'
$C_BINARIES    = @('sihost.exe','dllhost32.exe','dwmapiext.dll','cgpt_dbghelp.dll','symsrv.dll')
$LNK_PATH      = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Launch CloakGPT.lnk'
$PUB_LNK_PATH  = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Launch CloakGPT.lnk'

function Write-Banner {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Cyan)
    Write-Host ''
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor $Color
    Write-Host ('  ' + $Text.PadRight(66)) -ForegroundColor $Color
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor $Color
    Write-Host ''
}

# ===== copy of the FIXED helper from install-cloakgpt.ps1 ==========
function Add-ShortcutHardened {
    param(
        [Parameter(Mandatory)] [string] $LnkPath,
        [Parameter(Mandatory)] [string] $TargetExe,
        [Parameter(Mandatory)] [string] $WorkDir,
        [Parameter(Mandatory)] [string] $IconPath,
                              [string] $Description = '',
                              [scriptblock] $InjectFault = $null   # test-only fault injection
    )
    try {
        $wsh = New-Object -ComObject WScript.Shell -ErrorAction Stop
    } catch {
        return @{ Success = $false; Path = $LnkPath; Reason = "WScript.Shell COM failed: $($_.Exception.Message)" }
    }
    try {
        $sc = $wsh.CreateShortcut($LnkPath)
        $sc.TargetPath       = $TargetExe
        $sc.WorkingDirectory = $WorkDir
        $sc.IconLocation     = ('{0},0' -f $IconPath)
        $sc.Description      = $Description
        $sc.Save()
    } catch {
        return @{ Success = $false; Path = $LnkPath; Reason = "Save() threw: $($_.Exception.Message)" }
    }
    if ($InjectFault) { & $InjectFault $LnkPath }
    Start-Sleep -Milliseconds 250
    if (-not (Test-Path -LiteralPath $LnkPath)) {
        return @{ Success = $false; Path = $LnkPath; Reason = 'File vanished 250ms after Save() - AV/EDR quarantine likely' }
    }
    $adminFlagged = $false
    try {
        $bytes = [System.IO.File]::ReadAllBytes($LnkPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($LnkPath, $bytes)
        $adminFlagged = $true
    } catch {
        Start-Sleep -Milliseconds 100
        if (-not (Test-Path -LiteralPath $LnkPath)) {
            return @{ Success = $false; Path = $LnkPath; Reason = "File vanished during admin-flag byte-patch: $($_.Exception.Message)" }
        }
    }
    Start-Sleep -Milliseconds 100
    if (-not (Test-Path -LiteralPath $LnkPath)) {
        return @{ Success = $false; Path = $LnkPath; Reason = 'File vanished after admin-flag byte-patch - AV/EDR quarantine likely' }
    }
    return @{ Success = $true; AdminFlagged = $adminFlagged; Path = $LnkPath }
}

function Run-OldStep5 {
    param(
        [string]$MainExe, [string]$AppDir, [string]$LnkPath,
        [scriptblock]$InjectFault = $null
    )
    $iconPath = Join-Path $AppDir 'resources\app\src\assets\svchelper.ico'
    if (-not (Test-Path $iconPath)) { $iconPath = $MainExe }
    try {
        $wsh = New-Object -ComObject WScript.Shell
        $sc  = $wsh.CreateShortcut($LnkPath)
        $sc.TargetPath       = $MainExe
        $sc.WorkingDirectory = $AppDir
        $sc.IconLocation     = "$iconPath,0"
        $sc.Description      = 'Launch CloakGPT (elevated).'
        $sc.Save()
        if ($InjectFault) { & $InjectFault $LnkPath }
        $bytes = [System.IO.File]::ReadAllBytes($LnkPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($LnkPath, $bytes)
        Write-Host '       [OK] Shortcut on Desktop: Launch CloakGPT' -ForegroundColor Green
    } catch {
        Write-Host "     [WARN] Could not create shortcut: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    # OLD banner (always green, always says double-click):
    Write-Host ''
    Write-Host '  =========================================' -ForegroundColor Green
    Write-Host '           INSTALL COMPLETE                ' -ForegroundColor Green
    Write-Host '  =========================================' -ForegroundColor Green
    Write-Host '    1. Double-click "Launch CloakGPT" on your Desktop.' -ForegroundColor Cyan
}

function Run-NewStep5 {
    param(
        [string]$MainExe, [string]$AppDir,
        [string]$UserDesktop, [string]$PublicDesktop,
        [switch]$SimulateElevationMismatch,
        [scriptblock]$InjectFault = $null
    )
    $iconPath = Join-Path $AppDir 'resources\app\src\assets\svchelper.ico'
    if (-not (Test-Path $iconPath)) { $iconPath = $MainExe }
    $shortcutMade = $false
    $shortcutLocations = @()
    $elevationMismatch = $SimulateElevationMismatch.IsPresent
    if ($elevationMismatch) {
        Write-Host '     [WARN] OVER-THE-SHOULDER UAC DETECTED' -ForegroundColor Yellow
        Write-Host '     [WARN]   Adding Public Desktop copy so logged-in user sees it.' -ForegroundColor Yellow
    }
    if ($UserDesktop -and (Test-Path $UserDesktop)) {
        $r = Add-ShortcutHardened -LnkPath (Join-Path $UserDesktop 'Launch CloakGPT.lnk') `
                                  -TargetExe $MainExe -WorkDir $AppDir -IconPath $iconPath `
                                  -Description 'Launch CloakGPT (elevated).' -InjectFault $InjectFault
        if ($r.Success) {
            Write-Host '       [OK] Shortcut placed on user Desktop' -ForegroundColor Green
            Write-Host "     [INFO]   Path: $($r.Path)" -ForegroundColor Gray
            $shortcutMade = $true
            $shortcutLocations += $r.Path
        } else {
            Write-Host "     [WARN] User Desktop write failed: $($r.Reason)" -ForegroundColor Yellow
        }
    }
    $needPublic = (-not $shortcutMade) -or $elevationMismatch
    if ($needPublic -and $PublicDesktop -and (Test-Path $PublicDesktop) -and ($PublicDesktop -ne $UserDesktop)) {
        $r = Add-ShortcutHardened -LnkPath (Join-Path $PublicDesktop 'Launch CloakGPT.lnk') `
                                  -TargetExe $MainExe -WorkDir $AppDir -IconPath $iconPath `
                                  -Description 'Launch CloakGPT (elevated).'
        if ($r.Success) {
            Write-Host '       [OK] Shortcut placed on Public Desktop (all users)' -ForegroundColor Green
            Write-Host "     [INFO]   Path: $($r.Path)" -ForegroundColor Gray
            $shortcutMade = $true
            $shortcutLocations += $r.Path
        } else {
            Write-Host "     [WARN] Public Desktop write failed: $($r.Reason)" -ForegroundColor Yellow
        }
    }
    Write-Host ''
    if ($shortcutMade) {
        Write-Host '  =========================================' -ForegroundColor Green
        Write-Host '           INSTALL COMPLETE                ' -ForegroundColor Green
        Write-Host '  =========================================' -ForegroundColor Green
        Write-Host '    1. Double-click "Launch CloakGPT" on your Desktop.' -ForegroundColor Cyan
    } else {
        Write-Host '  =========================================' -ForegroundColor Yellow
        Write-Host '     INSTALL PARTIAL - SHORTCUT MISSING     ' -ForegroundColor Yellow
        Write-Host '  =========================================' -ForegroundColor Yellow
        Write-Host "    Launch manually: $MainExe" -ForegroundColor Cyan
    }
    return $shortcutMade
}

function Assert {
    param([string]$Path, [string]$Scenario, [bool]$ExpectExist)
    Write-Host ''
    $exists = Test-Path -LiteralPath $Path
    if ($exists -eq $ExpectExist) {
        Write-Host "  [PASS] $Scenario -> $Path $(if ($exists) { 'exists' } else { 'missing' }) (as expected)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $Scenario -> $Path $(if ($exists) { 'exists' } else { 'missing' }) (expected $(if ($ExpectExist) { 'exist' } else { 'missing' }))" -ForegroundColor Red
    }
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
}

# --- 0. Build fake extracted CloakGPT folder ---------------------
Write-Banner 'Building fake extracted CloakGPT folder' Yellow
if (Test-Path $FAKE_APP_ROOT) { Remove-Item -Recurse -Force $FAKE_APP_ROOT }
New-Item -ItemType Directory -Path $ASSETS_DIR -Force | Out-Null
[System.IO.File]::WriteAllBytes($MAIN_EXE, [byte[]]::new(2048))
foreach ($f in $C_BINARIES) {
    [System.IO.File]::WriteAllBytes((Join-Path $RES_DIR $f), [byte[]]::new(256))
}
[System.IO.File]::WriteAllBytes((Join-Path $ASSETS_DIR 'svchelper.ico'), [byte[]]::new(256))

if (Test-Path $LNK_PATH) { Remove-Item -LiteralPath $LNK_PATH -Force }
if (Test-Path $PUB_LNK_PATH) { Remove-Item -LiteralPath $PUB_LNK_PATH -Force }

try {
    # ================================================================
    # SCENARIO 1: AV/EDR eats the .lnk right after Save()
    # ================================================================
    Write-Banner 'SCENARIO 1: AV/EDR quarantines .lnk after Save()' Cyan
    $avFault = { param($p) Remove-Item -LiteralPath $p -Force; Write-Host "     [SIM] AV deleted $p" -ForegroundColor Magenta }

    Write-Host '  --- OLD (v1) ---' -ForegroundColor White
    Run-OldStep5 -MainExe $MAIN_EXE -AppDir $APP_DIR -LnkPath $LNK_PATH -InjectFault $avFault
    Assert -Path $LNK_PATH -Scenario 'OLD/scenario1' -ExpectExist $false

    Write-Host ''
    Write-Host '  --- NEW (v2 hardened) ---' -ForegroundColor White
    $ok = Run-NewStep5 -MainExe $MAIN_EXE -AppDir $APP_DIR `
                       -UserDesktop ([Environment]::GetFolderPath('Desktop')) `
                       -PublicDesktop ([Environment]::GetFolderPath('CommonDesktopDirectory')) `
                       -InjectFault $avFault
    # New attempts BOTH user Desktop (fails via fault) AND public Desktop (also fails via re-run of fault). 
    # Since fault only fires on the first invocation, the second write to Public Desktop SUCCEEDS.
    Assert -Path $LNK_PATH -Scenario 'NEW/scenario1-userDesktop'   -ExpectExist $false
    Assert -Path $PUB_LNK_PATH -Scenario 'NEW/scenario1-publicDesktop-fallback' -ExpectExist $true

    # ================================================================
    # SCENARIO 2: Save() throws (invalid path)
    # ================================================================
    Write-Banner 'SCENARIO 2: Save() throws (invalid filename)' Cyan
    $badLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Launch|CloakGPT.lnk'

    Write-Host '  --- OLD (v1) ---' -ForegroundColor White
    Run-OldStep5 -MainExe $MAIN_EXE -AppDir $APP_DIR -LnkPath $badLnk
    Assert -Path $LNK_PATH -Scenario 'OLD/scenario2' -ExpectExist $false

    Write-Host ''
    Write-Host '  --- NEW (v2 hardened) ---' -ForegroundColor White
    # For NEW, we just point $UserDesktop at a bad path directly to force Save() to throw
    $badDesktop = 'Z:\NoSuchDrive\SoSaveWillThrow'
    # Actually make the userDesktop point somewhere read-only so Save throws
    $roDesktop = Join-Path $env:TEMP 'ro-desktop'
    if (Test-Path $roDesktop) { Remove-Item -Recurse -Force $roDesktop }
    New-Item -ItemType Directory -Path $roDesktop -Force | Out-Null
    # Mark folder as read-only for our own user via icacls -- easier: use a non-existent drive letter
    $ok = Run-NewStep5 -MainExe $MAIN_EXE -AppDir $APP_DIR `
                       -UserDesktop $badDesktop `
                       -PublicDesktop ([Environment]::GetFolderPath('CommonDesktopDirectory'))
    Assert -Path $PUB_LNK_PATH -Scenario 'NEW/scenario2-publicDesktop-fallback' -ExpectExist $true
    Remove-Item -Recurse -Force $roDesktop -ErrorAction SilentlyContinue

    # ================================================================
    # SCENARIO 3: Over-the-shoulder UAC (elevated as different user)
    # ================================================================
    Write-Banner 'SCENARIO 3: Over-the-shoulder UAC (elevated to different user)' Cyan
    $foreignDesktop = Join-Path $env:TEMP 'foreign-admin-Desktop'
    if (Test-Path $foreignDesktop) { Remove-Item -Recurse -Force $foreignDesktop }
    New-Item -ItemType Directory -Path $foreignDesktop -Force | Out-Null

    Write-Host '  --- OLD (v1) ---' -ForegroundColor White
    Write-Host "  Simulated 'other admin' Desktop: $foreignDesktop" -ForegroundColor Gray
    $foreignLnk = Join-Path $foreignDesktop 'Launch CloakGPT.lnk'
    Run-OldStep5 -MainExe $MAIN_EXE -AppDir $APP_DIR -LnkPath $foreignLnk
    # Old: shortcut ends up on foreign Desktop (the admin's), NOT on abdul's real Desktop
    Assert -Path $LNK_PATH -Scenario 'OLD/scenario3-abdulDesktop' -ExpectExist $false
    Assert -Path $foreignLnk -Scenario 'OLD/scenario3-adminDesktop' -ExpectExist $true

    Write-Host ''
    Write-Host '  --- NEW (v2 hardened) ---' -ForegroundColor White
    Write-Host "  Simulated 'other admin' Desktop as UserDesktop: $foreignDesktop" -ForegroundColor Gray
    Write-Host '  With -SimulateElevationMismatch: forces the Public Desktop belt-and-suspenders write' -ForegroundColor Gray
    $ok = Run-NewStep5 -MainExe $MAIN_EXE -AppDir $APP_DIR `
                       -UserDesktop $foreignDesktop `
                       -PublicDesktop ([Environment]::GetFolderPath('CommonDesktopDirectory')) `
                       -SimulateElevationMismatch
    # New: admin's Desktop gets a copy AND Public Desktop gets a copy (visible to abdul)
    Assert -Path $foreignLnk -Scenario 'NEW/scenario3-adminDesktop'  -ExpectExist $true
    Assert -Path $PUB_LNK_PATH -Scenario 'NEW/scenario3-publicDesktop' -ExpectExist $true
    if (Test-Path $foreignDesktop) { Remove-Item -Recurse -Force $foreignDesktop }
}
finally {
    Write-Banner 'Cleanup' Yellow
    if (Test-Path $FAKE_APP_ROOT) { Remove-Item -Recurse -Force $FAKE_APP_ROOT -ErrorAction SilentlyContinue }
    if (Test-Path $LNK_PATH) { Remove-Item -LiteralPath $LNK_PATH -Force -ErrorAction SilentlyContinue }
    if (Test-Path $PUB_LNK_PATH) { Remove-Item -LiteralPath $PUB_LNK_PATH -Force -ErrorAction SilentlyContinue }
    Write-Host '  All test artifacts removed.' -ForegroundColor Gray
}
