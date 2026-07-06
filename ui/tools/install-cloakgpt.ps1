# ===========================================================
#  CLOAKGPT INSTALLER v4.5 - Run as Administrator
# ===========================================================
#
#  End-user installer shipped INSIDE CloakGPTWindowsMaxStealth.zip.
#  Handles first install AND upgrades AND uninstall from the same file.
#
#  Compatibility target: Windows 10 20H2+ with PowerShell 5.1+ (the
#  Windows 10 default). Uses ONLY PS 5.1 features (no PS 7 syntax,
#  no ternaries, no ?? operator, no ?.).
#
#  Invoke:
#      Install:    powershell -ExecutionPolicy Bypass -File install-cloakgpt.ps1
#      Uninstall:  powershell -ExecutionPolicy Bypass -File install-cloakgpt.ps1 -Uninstall
#
#  ASCII-ONLY - no smart quotes, no em-dashes, no box-drawing chars.
#  Non-ASCII bytes get mojibaked when PowerShell reads without a BOM
#  hint on some systems (verified 2026-07-06).
# ===========================================================

param(
    [switch]$Uninstall
)

$ErrorActionPreference = 'Continue'

$INSTALL_DIR      = 'C:\ProgramData\WinAudioSvc'
$APP_FOLDER_NAME  = 'CloakGPT'
$MAIN_EXE         = 'svchelper.exe'
$C_BINARIES       = @(
    'sihost.exe',
    'dllhost32.exe',
    'dwmapiext.dll',
    'cgpt_dbghelp.dll',
    'symsrv.dll'
)
$OUR_EXES         = @('svchelper.exe', 'sihost.exe', 'dllhost32.exe')

# =====================================================================
#  Helpers - UX + safe I/O
# =====================================================================

function Write-Banner {
    Clear-Host
    Write-Host ''
    Write-Host '  =========================================' -ForegroundColor Cyan
    Write-Host '           CLOAKGPT INSTALLER  v4.5        ' -ForegroundColor Cyan
    Write-Host '  =========================================' -ForegroundColor Cyan
    Write-Host ''
}

function Write-Step  { param($n,$t,$msg) Write-Host "  [$n/$t] $msg" -ForegroundColor Yellow }
function Write-Ok    { param($msg)       Write-Host "       [OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg)       Write-Host "     [WARN] $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg)       Write-Host "    [FAIL] $msg" -ForegroundColor Red }
function Write-Info  { param($msg)       Write-Host "     [INFO] $msg" -ForegroundColor Gray }

function Ask-Choice {
    param([string]$Prompt, [string[]]$Options)
    Write-Host ''
    Write-Host "  $Prompt" -ForegroundColor White
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host ("    [{0}] {1}" -f ($i + 1), $Options[$i]) -ForegroundColor Cyan
    }
    Write-Host ''
    do {
        $key = Read-Host "  Enter choice (1-$($Options.Count))"
        $idx = 0
        $valid = [int]::TryParse($key, [ref]$idx) -and $idx -ge 1 -and $idx -le $Options.Count
        if (-not $valid) { Write-Host '  Invalid choice. Try again.' -ForegroundColor Red }
    } while (-not $valid)
    return $idx
}

function Get-DesktopPath {
    # Prefer the KFM-aware value. Falls back to USERPROFILE for edge cases
    # where GetFolderPath returns empty (very rare, corrupted profile).
    $d = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
    if (-not $d -or -not (Test-Path $d)) { $d = Join-Path $env:USERPROFILE 'Desktop' }
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

function Schedule-RebootDelete {
    # MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT - the ONLY reliable way
    # to remove a file currently held open by another process (e.g., DLL
    # loaded into DWM). No PSCore dependency.
    param([string]$FilePath)
    $sig = @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
    try {
        $type = Add-Type -MemberDefinition $sig -Name 'MoveFileExUtil' -Namespace 'CG' -PassThru -ErrorAction Stop
    } catch {
        $type = [CG.MoveFileExUtil]
    }
    $MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
    return $type::MoveFileEx($FilePath, $null, $MOVEFILE_DELAY_UNTIL_REBOOT)
}

# =====================================================================
#  Admin check - always required, even for uninstall
# =====================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Banner
    Write-Host '  ERROR: This installer must be run as Administrator.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  How to fix:' -ForegroundColor White
    Write-Host '    1. Right-click install-cloakgpt.ps1' -ForegroundColor Gray
    Write-Host '    2. Choose "Run with PowerShell" and accept UAC' -ForegroundColor Gray
    Write-Host '  OR' -ForegroundColor Gray
    Write-Host '    1. Press Win + X' -ForegroundColor Gray
    Write-Host '    2. Click "Terminal (Admin)" or "PowerShell (Admin)"' -ForegroundColor Gray
    Write-Host "    3. cd to this folder, then run:" -ForegroundColor Gray
    Write-Host '       powershell -ExecutionPolicy Bypass -File .\install-cloakgpt.ps1' -ForegroundColor Cyan
    Write-Host ''
    pause; exit 1
}

# =====================================================================
#  Path-filtered process kill - critical safety
#
#  Windows ships its own svchost.exe / sihost.exe / dllhost.exe in
#  System32 that we MUST NEVER touch. We only kill processes whose
#  Path starts with our INSTALL_DIR or the source folder passed in.
# =====================================================================
function Stop-OurProcesses {
    param([string[]]$AllowedRoots)
    $killed = 0
    foreach ($exe in $OUR_EXES) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($exe)
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $path = $null
            try { $path = $p.Path } catch {}
            if (-not $path) { continue }
            $isOurs = $false
            foreach ($root in $AllowedRoots) {
                if ($root -and $path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $isOurs = $true; break
                }
            }
            if ($isOurs) {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                Write-Info "Stopped $name (PID $($p.Id))  path=$path"
                $killed++
            }
        }
    }
    if ($killed -gt 0) { Start-Sleep -Seconds 1 }
    return $killed
}

# =====================================================================
#  Source folder detection - handles all extraction permutations
# =====================================================================
function Find-CloakGPTSource {
    $scriptDir = $null
    if ($PSScriptRoot) { $scriptDir = $PSScriptRoot }
    elseif ($MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

    # Handle nested-extraction edge cases: user extracts the zip with
    # WinRAR/7-Zip's "Extract Here" which may or may not create an outer
    # folder. Also handle drag-into-existing-folder cases.
    if ($scriptDir) {
        $checks = @(
            (Join-Path $scriptDir $APP_FOLDER_NAME),
            (Join-Path $scriptDir "$APP_FOLDER_NAME\$APP_FOLDER_NAME"),
            (Join-Path $scriptDir "CloakGPTWindowsMaxStealth\$APP_FOLDER_NAME"),
            $scriptDir
        )
        foreach ($try in $checks) {
            if (Test-Path (Join-Path $try $MAIN_EXE)) { return $try }
        }
    }

    # Scan common extraction locations - Desktop (all variants), Downloads.
    # OneDrive corporate accounts create folders like "OneDrive - Contoso"
    # so we enumerate the userprofile for any OneDrive* directory.
    $desktopPaths = New-Object System.Collections.Generic.List[string]
    $desktopPaths.Add([Environment]::GetFolderPath('Desktop'))
    $desktopPaths.Add((Join-Path $env:USERPROFILE 'Desktop'))
    $desktopPaths.Add((Join-Path $env:USERPROFILE 'OneDrive\Desktop'))
    try {
        $odDirs = Get-ChildItem -Path $env:USERPROFILE -Directory -Filter 'OneDrive*' -ErrorAction SilentlyContinue
        foreach ($od in $odDirs) { $desktopPaths.Add((Join-Path $od.FullName 'Desktop')) }
    } catch {}

    $unique = $desktopPaths | Where-Object { $_ } | Select-Object -Unique
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($d in $unique) {
        $candidates.Add((Join-Path $d "CloakGPTWindowsMaxStealth\$APP_FOLDER_NAME"))
        $candidates.Add((Join-Path $d "CloakGPTWindowsMaxStealth\CloakGPTWindowsMaxStealth\$APP_FOLDER_NAME"))
        $candidates.Add((Join-Path $d 'CloakGPTWindowsMaxStealth'))
        $candidates.Add((Join-Path $d $APP_FOLDER_NAME))
    }
    $candidates.Add((Join-Path $env:USERPROFILE "Downloads\CloakGPTWindowsMaxStealth\$APP_FOLDER_NAME"))
    $candidates.Add((Join-Path $env:USERPROFILE "Downloads\$APP_FOLDER_NAME"))
    $candidates.Add((Join-Path $env:USERPROFILE 'Downloads\CloakGPTWindowsMaxStealth'))

    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c $MAIN_EXE)) { return $c }
    }
    return $null
}

# =====================================================================
#  Defender helpers
# =====================================================================
function Get-DefenderPref {
    try { return Get-MpPreference -ErrorAction Stop } catch { return $null }
}
function Test-TamperProtection {
    try { return (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected -eq $true } catch { return $false }
}
function Add-DefenderExclusionSet {
    # Belt-and-suspenders: use both Add-MpPreference AND the registry.
    # Registry survives if Set-MpPreference gets blocked by Tamper
    # Protection but the process is elevated so we can still write to
    # HKLM directly.
    $err = 0
    try {
        Add-MpPreference -ExclusionPath $INSTALL_DIR -Force -ErrorAction Stop
        Write-Info "Path exclusion: $INSTALL_DIR"
    } catch { Write-Warn "Could not add folder exclusion via cmdlet."; $err++ }

    foreach ($exe in @('svchelper.exe','sihost.exe','dllhost32.exe','dwmapiext.dll','dwm.exe')) {
        try {
            Add-MpPreference -ExclusionProcess "$INSTALL_DIR\$exe" -Force -ErrorAction Stop
            Write-Info "Process exclusion: $exe"
        } catch { $err++ }
    }
    # Also exclude the app folder wherever the user extracted it (svchelper.exe
    # lives there, not in ProgramData).
    if ($script:APP_DIR) {
        try {
            Add-MpPreference -ExclusionPath $script:APP_DIR -Force -ErrorAction Stop
            Write-Info "Path exclusion: $script:APP_DIR"
        } catch { $err++ }
    }

    # Registry backup - one entry per path
    try {
        $regPathRoot = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
        if (Test-Path $regPathRoot) {
            New-ItemProperty -Path $regPathRoot -Name $INSTALL_DIR -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            if ($script:APP_DIR) {
                New-ItemProperty -Path $regPathRoot -Name $script:APP_DIR -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            }
            Write-Info "Registry exclusion backup added"
        }
    } catch { Write-Info "Registry exclusion backup skipped (Tamper Protection?)" }

    # Optional: disable cloud-delivered protection + auto sample submission.
    # Cloud verdicts OVERRIDE local exclusions - if this is enabled and
    # Microsoft's cloud engine flags our binaries, they get quarantined
    # anyway. Fine to leave on for most users - just print info.
    try {
        $mp = Get-DefenderPref
        if ($mp -and $mp.MAPSReporting -ne 0) {
            Write-Info "(Cloud-delivered protection is ON; if quarantines happen despite exclusions, disable it in Windows Security)"
        }
    } catch {}

    return $err
}

# =====================================================================
#  UNINSTALL PATH
# =====================================================================
if ($Uninstall) {
    Write-Banner
    Write-Host '  MODE: Uninstall' -ForegroundColor Magenta
    Write-Host ''

    $confirm = Ask-Choice 'Are you sure you want to uninstall CloakGPT?' @('Yes, uninstall', 'No, cancel')
    if ($confirm -eq 2) { Write-Host "`n  Cancelled.`n" -ForegroundColor Gray; pause; exit 0 }

    $totalSteps = 5
    Write-Host ''

    # 1. Stop our processes (path-filtered to our binaries only)
    Write-Step 1 $totalSteps 'Stopping CloakGPT processes...'
    $roots = @($INSTALL_DIR)
    # Best-effort: include the app dir if we can locate it
    $src = Find-CloakGPTSource
    if ($src) { $roots += $src }
    $killed = Stop-OurProcesses -AllowedRoots $roots
    Write-Ok "$killed process(es) stopped."

    # 2. Uninject the payload cleanly if it's loaded
    Write-Step 2 $totalSteps 'Uninjecting payload from DWM (if loaded)...'
    $sihostPath = Join-Path $INSTALL_DIR 'sihost.exe'
    if (Test-Path $sihostPath) {
        try {
            $p = Start-Process -FilePath $sihostPath -ArgumentList '--unload' -PassThru -WindowStyle Hidden
            $p | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
            Write-Ok 'sihost --unload complete.'
        } catch {
            Write-Warn "sihost --unload failed: $($_.Exception.Message)"
        }
    } else {
        Write-Info 'sihost.exe not present; nothing to uninject.'
    }

    # 3. Remove Defender exclusions
    Write-Step 3 $totalSteps 'Removing Defender exclusions...'
    try { Remove-MpPreference -ExclusionPath $INSTALL_DIR -Force -ErrorAction Stop; Write-Info "Removed path exclusion: $INSTALL_DIR" }
    catch { Write-Info 'Path exclusion was not set / could not remove.' }
    foreach ($exe in @('svchelper.exe','sihost.exe','dllhost32.exe','dwmapiext.dll','dwm.exe')) {
        try { Remove-MpPreference -ExclusionProcess "$INSTALL_DIR\$exe" -Force -ErrorAction Stop } catch {}
    }
    try {
        $regPathRoot = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
        if (Test-Path $regPathRoot) {
            Remove-ItemProperty -Path $regPathRoot -Name $INSTALL_DIR -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    Write-Ok 'Defender cleanup done.'

    # 4. Delete install directory (with reboot-scheduling for locked files)
    Write-Step 4 $totalSteps "Deleting $INSTALL_DIR..."
    $needsReboot = $false
    if (Test-Path $INSTALL_DIR) {
        Get-ChildItem $INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_.Attributes = 'Normal' } catch {}
        }
        Remove-Item $INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $INSTALL_DIR) {
            $remaining = @(Get-ChildItem $INSTALL_DIR -Recurse -File -ErrorAction SilentlyContinue)
            if ($remaining.Count -gt 0) {
                Write-Warn "$($remaining.Count) file(s) locked. Scheduling for reboot deletion..."
                foreach ($f in $remaining) { Schedule-RebootDelete $f.FullName | Out-Null }
                Schedule-RebootDelete $INSTALL_DIR | Out-Null
                $needsReboot = $true
            }
        } else {
            Write-Ok 'Directory removed.'
        }
    } else {
        Write-Info 'Already removed.'
    }

    # 5. Remove Desktop shortcut
    Write-Step 5 $totalSteps 'Removing Desktop shortcut...'
    $lnk = Join-Path (Get-DesktopPath) 'Launch CloakGPT.lnk'
    if (Test-Path $lnk) {
        Remove-Item $lnk -Force -ErrorAction SilentlyContinue
        Write-Ok 'Shortcut removed.'
    } else {
        Write-Info 'No shortcut to remove.'
    }

    Write-Host ''
    Write-Host '  =========================================' -ForegroundColor Green
    Write-Host '           UNINSTALL COMPLETE              ' -ForegroundColor Green
    Write-Host '  =========================================' -ForegroundColor Green
    Write-Host ''
    if ($needsReboot) {
        Write-Host '  Some files were held open (payload injected into DWM).' -ForegroundColor Yellow
        Write-Host '  They are scheduled for deletion on next reboot.' -ForegroundColor Yellow
        Write-Host ''
        $doReboot = Ask-Choice 'Restart now to complete cleanup?' @('Yes, restart now', 'No, I will restart later')
        if ($doReboot -eq 1) {
            Write-Host "`n  Restarting in 10 seconds... (Ctrl+C to cancel)`n" -ForegroundColor Yellow
            Start-Sleep 10
            Restart-Computer -Force
        }
    }
    Write-Host '  Note: your extracted CloakGPT folder was NOT deleted. Remove it manually.' -ForegroundColor Gray
    Write-Host ''
    pause; exit 0
}

# =====================================================================
#  INSTALL PATH
# =====================================================================
Write-Banner
Write-Host '  MODE: Install / Upgrade' -ForegroundColor Magenta
Write-Host ''
$totalSteps = 6

# --- Step 1: Locate the extracted CloakGPT folder --------------------
Write-Step 1 $totalSteps 'Locating extracted CloakGPT files...'
$APP_DIR = Find-CloakGPTSource
$script:APP_DIR = $APP_DIR

if (-not $APP_DIR) {
    Write-Host ''
    Write-Warn 'Could not find the extracted CloakGPT folder.'
    Write-Host ''
    Write-Host '  Make sure you extracted CloakGPTWindowsMaxStealth.zip.' -ForegroundColor White
    Write-Host '    Right-click the .zip in Explorer -> Extract All -> Extract' -ForegroundColor Gray
    Write-Host ''
    $action = Ask-Choice 'What next?' @(
        'Enter the folder path manually (or drag it into this window)',
        'Cancel'
    )
    if ($action -eq 2) { Write-Host "`n  Cancelled.`n" -ForegroundColor Gray; pause; exit 1 }
    Write-Host ''
    Write-Host '  Drag the CloakGPT folder into this window, or type the full path:' -ForegroundColor Cyan
    $manual = Read-Host '  Path'
    $manual = $manual.Trim('"').Trim("'").Trim()
    if ($manual -and (Test-Path (Join-Path $manual $MAIN_EXE))) {
        $APP_DIR = $manual
        $script:APP_DIR = $APP_DIR
    } else {
        Write-Err "svchelper.exe not found at that path. Exiting."
        pause; exit 1
    }
}
Write-Ok "Found: $APP_DIR"

# --- Step 2: Detect prior install + stop everything gracefully -------
Write-Step 2 $totalSteps 'Cleaning up any prior installation...'
$roots = @($INSTALL_DIR, $APP_DIR)
$killed = Stop-OurProcesses -AllowedRoots $roots
if ($killed -gt 0) { Write-Info "Stopped $killed running process(es) from previous session." }

# Uninject old payload if injected. Best-effort - if sihost isn't there
# or the payload isn't loaded, this returns quickly.
$existingSihost = Join-Path $INSTALL_DIR 'sihost.exe'
if (Test-Path $existingSihost) {
    try {
        $p = Start-Process -FilePath $existingSihost -ArgumentList '--unload' -PassThru -WindowStyle Hidden
        $p | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
        Write-Info 'Old payload uninjected (belt-and-suspenders before overwrite).'
    } catch {
        Write-Info 'Old sihost --unload skipped (probably not needed).'
    }
}

# Delete the 5 stale C binaries. Preserve config.dat, session, api_keys,
# logs so the user does not have to re-authenticate.
if (Test-Path $INSTALL_DIR) {
    foreach ($f in $C_BINARIES) {
        $p = Join-Path $INSTALL_DIR $f
        if (Test-Path $p) {
            try { Remove-Item $p -Force -ErrorAction Stop } catch {
                Write-Warn "Could not delete stale $f (locked). Scheduling for reboot..."
                Schedule-RebootDelete $p | Out-Null
            }
        }
    }
    Write-Ok 'Old C binaries removed. Config/session/API keys preserved.'
} else {
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    Write-Ok "Created fresh $INSTALL_DIR"
}

# --- Step 3: Windows Defender exclusions -----------------------------
Write-Step 3 $totalSteps 'Adding Windows Defender exclusions...'

$tamperOn = Test-TamperProtection
if ($tamperOn) {
    Write-Warn 'Tamper Protection is ON. Some exclusions may fail.'
    Write-Host '           To fix: Windows Security -> Virus & Threat Protection ->' -ForegroundColor Gray
    Write-Host '                  Manage Settings -> Tamper Protection: OFF' -ForegroundColor Gray
    Write-Host '           Then re-run this installer.' -ForegroundColor Gray
} else {
    Write-Info 'Tamper Protection: off (good)'
}

$exErrors = Add-DefenderExclusionSet
if ($exErrors -gt 0) {
    Write-Warn "$exErrors exclusion(s) failed. If Defender quarantines a binary,"
    Write-Host '           add the exclusion manually (Windows Security -> Exclusions -> Add Folder)' -ForegroundColor Gray
    Write-Host "           and add:  $INSTALL_DIR" -ForegroundColor Cyan
    Write-Host "           and add:  $APP_DIR" -ForegroundColor Cyan
} else {
    Write-Ok 'All exclusions added.'
}

# --- Step 4: Verify all critical files are present -------------------
Write-Step 4 $totalSteps 'Verifying extracted files...'

$mainExe = Join-Path $APP_DIR $MAIN_EXE
if (-not (Test-Path $mainExe)) {
    Write-Err "$MAIN_EXE missing at $mainExe"
    Write-Host '  Re-extract CloakGPTWindowsMaxStealth.zip and re-run.' -ForegroundColor Yellow
    pause; exit 1
}
$mainSize = [math]::Round((Get-Item $mainExe).Length / 1MB, 1)
Write-Ok "$MAIN_EXE present ($mainSize MB)"

# The 5 C binaries live inside resources/ next to svchelper.exe.
$resDir = Join-Path $APP_DIR 'resources'
$missing = @()
foreach ($f in $C_BINARIES) {
    if (-not (Test-Path (Join-Path $resDir $f))) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Err 'Missing bundled C binaries in resources/:'
    foreach ($m in $missing) { Write-Err "  - $m" }
    Write-Host ''
    Write-Host '  Likely cause: Windows Defender quarantined them during extraction.' -ForegroundColor Yellow
    Write-Host '  Open Windows Security -> Protection History -> Restore all,' -ForegroundColor Yellow
    Write-Host '  then re-extract the zip and re-run this installer.' -ForegroundColor Yellow
    pause; exit 1
}
Write-Ok "All $($C_BINARIES.Count) bundled C binaries present."

# --- Step 5: Desktop shortcut with Run-as-Admin flag -----------------
Write-Step 5 $totalSteps 'Creating Desktop shortcut...'

$desktop  = Get-DesktopPath
$lnkPath  = Join-Path $desktop 'Launch CloakGPT.lnk'
$iconPath = Join-Path $APP_DIR 'resources\app\src\assets\svchelper.ico'
if (-not (Test-Path $iconPath)) { $iconPath = $mainExe }

try {
    $wsh = New-Object -ComObject WScript.Shell
    $sc  = $wsh.CreateShortcut($lnkPath)
    $sc.TargetPath       = $mainExe
    $sc.WorkingDirectory = $APP_DIR
    $sc.IconLocation     = "$iconPath,0"
    $sc.Description      = 'Launch CloakGPT (elevated). AI overlay for LockDown Browser.'
    $sc.Save()

    # Set the Run-as-Administrator flag by flipping byte 0x15 bit 0x20.
    # Per MS-SHLLINK section 2.1 LinkFlags. Doing this in the .lnk binary
    # is the only reliable way - the COM API does not expose it.
    $bytes = [System.IO.File]::ReadAllBytes($lnkPath)
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes($lnkPath, $bytes)
    Write-Ok "Shortcut on Desktop: Launch CloakGPT (elevated)"
    Write-Info "Points at: $mainExe"
} catch {
    Write-Warn "Could not create shortcut: $($_.Exception.Message)"
    Write-Info "You can still launch by double-clicking $mainExe directly."
}

# --- Step 6: Final summary + next steps ------------------------------
Write-Step 6 $totalSteps 'Done.'

Write-Host ''
Write-Host '  =========================================' -ForegroundColor Green
Write-Host '           INSTALL COMPLETE                ' -ForegroundColor Green
Write-Host '  =========================================' -ForegroundColor Green
Write-Host ''
Write-Host '  Next steps:' -ForegroundColor White
Write-Host '    1. Double-click "Launch CloakGPT" on your Desktop.' -ForegroundColor Cyan
Write-Host '    2. Accept the UAC prompt.' -ForegroundColor Gray
Write-Host '    3. Sign in with Google.' -ForegroundColor Gray
Write-Host '    4. Paste your AI API keys (test each with the Test button).' -ForegroundColor Gray
Write-Host '    5. Click "Inject Now".' -ForegroundColor Gray
Write-Host '    6. Launch LockDown Browser.' -ForegroundColor Gray
Write-Host ''
Write-Host '  Full setup guide + Defender troubleshooting: see INSTRUCTIONS.md' -ForegroundColor Gray
Write-Host '  To uninstall later: powershell -File install-cloakgpt.ps1 -Uninstall' -ForegroundColor Gray
Write-Host ''
pause
