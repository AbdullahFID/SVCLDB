param([switch]$Uninstall)

$ErrorActionPreference = 'Continue'

# --- Self-elevate ------------------------------------------------
# Relaunch elevated if not already an admin. This makes "right-click
# -> Run with PowerShell" work end-to-end (the docs tell users to do
# exactly that, but bare .ps1 files don't auto-elevate on Win10/11,
# so we UAC-prompt ourselves here). Child runs in a fresh elevated
# window; parent exits immediately.
$__isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $__isAdmin) {
    $__selfPath = $MyInvocation.MyCommand.Path
    if (-not $__selfPath) { $__selfPath = $PSCommandPath }
    if (-not $__selfPath -or -not (Test-Path $__selfPath)) {
        Write-Host ''
        Write-Host '  ERROR: Cannot self-elevate - own script path is unknown.' -ForegroundColor Red
        Write-Host '  Re-run manually from an elevated PowerShell:' -ForegroundColor Yellow
        Write-Host '      powershell -ExecutionPolicy Bypass -File .\install-cloakgpt.ps1' -ForegroundColor Cyan
        pause; exit 1
    }
    $__argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $__selfPath + '"'))
    if ($Uninstall) { $__argsList += '-Uninstall' }
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $__argsList -Verb RunAs -ErrorAction Stop | Out-Null
        exit 0
    } catch {
        Write-Host ''
        Write-Host '  ERROR: UAC prompt was declined or elevation is not available.' -ForegroundColor Red
        Write-Host '  This installer needs admin rights to write to C:\ProgramData\.' -ForegroundColor Yellow
        Write-Host '  Try again and click Yes on the UAC prompt.' -ForegroundColor Yellow
        pause; exit 1
    }
}

$INSTALL_DIR     = 'C:\ProgramData\WinAudioSvc'
$APP_FOLDER_NAME = 'CloakGPT'
$MAIN_EXE        = 'svchelper.exe'
$C_BINARIES      = @('sihost.exe','dllhost32.exe','dwmapiext.dll','cgpt_dbghelp.dll','symsrv.dll')
$OUR_EXES        = @('svchelper.exe','sihost.exe','dllhost32.exe')

function Write-Banner {
    Clear-Host
    Write-Host ''
    Write-Host '  =========================================' -ForegroundColor Cyan
    Write-Host '           CLOAKGPT INSTALLER              ' -ForegroundColor Cyan
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
    $d = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
    if (-not $d -or -not (Test-Path $d)) { $d = Join-Path $env:USERPROFILE 'Desktop' }
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

function Schedule-RebootDelete {
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

# Elevation is guaranteed by the self-elevate block at the top of the
# file. If we reach this point without admin rights (e.g. the top block
# was tampered with) fail loudly rather than silently.
if (-not (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host '  ERROR: Not elevated. Self-elevation block was skipped or failed.' -ForegroundColor Red
    pause; exit 1
}

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
                Write-Info "Stopped $name (PID $($p.Id))"
                $killed++
            }
        }
    }
    if ($killed -gt 0) { Start-Sleep -Seconds 1 }
    return $killed
}

function Find-CloakGPTSource {
    $scriptDir = $null
    if ($PSScriptRoot) { $scriptDir = $PSScriptRoot }
    elseif ($MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
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

function Get-DefenderPref {
    try { return Get-MpPreference -ErrorAction Stop } catch { return $null }
}
function Test-TamperProtection {
    try { return (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected -eq $true } catch { return $false }
}
function Add-DefenderExclusionSet {
    $err = 0
    try {
        Add-MpPreference -ExclusionPath $INSTALL_DIR -Force -ErrorAction Stop
        Write-Info "Path exclusion: $INSTALL_DIR"
    } catch { Write-Warn 'Could not add folder exclusion via cmdlet.'; $err++ }
    foreach ($exe in @('svchelper.exe','sihost.exe','dllhost32.exe','dwmapiext.dll','dwm.exe')) {
        try {
            Add-MpPreference -ExclusionProcess "$INSTALL_DIR\$exe" -Force -ErrorAction Stop
            Write-Info "Process exclusion: $exe"
        } catch { $err++ }
    }
    if ($script:APP_DIR) {
        try {
            Add-MpPreference -ExclusionPath $script:APP_DIR -Force -ErrorAction Stop
            Write-Info "Path exclusion: $script:APP_DIR"
        } catch { $err++ }
    }
    try {
        $regPathRoot = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
        if (Test-Path $regPathRoot) {
            New-ItemProperty -Path $regPathRoot -Name $INSTALL_DIR -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            if ($script:APP_DIR) {
                New-ItemProperty -Path $regPathRoot -Name $script:APP_DIR -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            }
            Write-Info 'Registry exclusion backup added'
        }
    } catch { Write-Info 'Registry exclusion backup skipped (Tamper Protection?)' }
    return $err
}

function Get-InteractiveUserSid {
    <#
    Returns the SID of the user who owns the interactive Explorer shell
    on the current console. Used to detect over-the-shoulder UAC where
    an admin's credentials were used to elevate a non-admin user's
    installer -- in that case our own SpecialFolder.Desktop resolves to
    the admin's Desktop, not the actual logged-in user's Desktop.
    Returns $null if we can't determine it (e.g. no interactive session,
    RDP-only, or WMI unavailable).
    #>
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop
        foreach ($p in $procs) {
            $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction SilentlyContinue
            if ($owner -and $owner.Sid) { return $owner.Sid }
        }
    } catch {}
    try {
        $procs = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop
        foreach ($p in $procs) {
            $owner = $p.GetOwnerSid()
            if ($owner -and $owner.Sid) { return $owner.Sid }
        }
    } catch {}
    return $null
}

function Add-ShortcutHardened {
    <#
    Creates a .lnk with the RunAsAdmin flag set, verifying persistence
    after every step to catch AV/EDR races and silent Save() failures.

    Returns a hashtable:
      @{ Success=$true;  AdminFlagged=$bool; Path=$LnkPath }
      @{ Success=$false; Reason=$string;     Path=$LnkPath }

    Failure modes covered:
      - WScript.Shell COM instantiation blocked (WSH disabled hard)
      - CreateShortcut throws (invalid path chars, denied)
      - Save() throws (denied, network target down, disk full)
      - .lnk vanished 250ms after Save() (AV/EDR quarantine race)
      - Byte-patch throws (file locked / gone during patch)
      - .lnk vanished after byte-patch (AV/EDR quarantine race, 2nd try)
    #>
    param(
        [Parameter(Mandatory)] [string] $LnkPath,
        [Parameter(Mandatory)] [string] $TargetExe,
        [Parameter(Mandatory)] [string] $WorkDir,
        [Parameter(Mandatory)] [string] $IconPath,
                              [string] $Description = ''
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

if ($Uninstall) {
    Write-Banner
    Write-Host '  MODE: Uninstall' -ForegroundColor Magenta
    Write-Host ''
    $confirm = Ask-Choice 'Are you sure you want to uninstall CloakGPT?' @('Yes, uninstall', 'No, cancel')
    if ($confirm -eq 2) { Write-Host "`n  Cancelled.`n" -ForegroundColor Gray; pause; exit 0 }

    $totalSteps = 5
    Write-Host ''

    Write-Step 1 $totalSteps 'Stopping CloakGPT processes...'
    $roots = @($INSTALL_DIR)
    $src = Find-CloakGPTSource
    if ($src) { $roots += $src }
    $killed = Stop-OurProcesses -AllowedRoots $roots
    Write-Ok "$killed process(es) stopped."

    Write-Step 2 $totalSteps 'Uninjecting overlay from DWM (if loaded)...'
    $sihostPath = Join-Path $INSTALL_DIR 'sihost.exe'
    if (Test-Path $sihostPath) {
        try {
            $p = Start-Process -FilePath $sihostPath -ArgumentList '--unload' -PassThru -WindowStyle Hidden
            $p | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
            Write-Ok 'Cooperative unload complete.'
        } catch {
            Write-Warn "Unload command failed: $($_.Exception.Message)"
        }
    } else {
        Write-Info 'Nothing to uninject.'
    }

    Write-Step 3 $totalSteps 'Removing Defender exclusions...'
    try { Remove-MpPreference -ExclusionPath $INSTALL_DIR -Force -ErrorAction Stop; Write-Info "Removed: $INSTALL_DIR" }
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
        Write-Host '  Some files were held open. They are scheduled' -ForegroundColor Yellow
        Write-Host '  for deletion on next reboot.' -ForegroundColor Yellow
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

Write-Banner
Write-Host '  MODE: Install / Upgrade' -ForegroundColor Magenta
Write-Host ''
$totalSteps = 6

Write-Step 1 $totalSteps 'Locating extracted CloakGPT files...'
$APP_DIR = Find-CloakGPTSource
$script:APP_DIR = $APP_DIR

if (-not $APP_DIR) {
    Write-Host ''
    Write-Warn 'Could not find the extracted CloakGPT folder.'
    Write-Host ''
    Write-Host '  Make sure you extracted CloakGPTWindowsMaxStealth.zip.' -ForegroundColor White
    Write-Host '    Right-click the zip in Explorer, choose Extract All, then Extract.' -ForegroundColor Gray
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
        Write-Err "$MAIN_EXE not found at that path. Exiting."
        pause; exit 1
    }
}
Write-Ok "Found: $APP_DIR"

Write-Step 2 $totalSteps 'Cleaning up any prior installation...'
$roots = @($INSTALL_DIR, $APP_DIR)
$killed = Stop-OurProcesses -AllowedRoots $roots
if ($killed -gt 0) { Write-Info "Stopped $killed running process(es)." }

$existingSihost = Join-Path $INSTALL_DIR 'sihost.exe'
if (Test-Path $existingSihost) {
    try {
        $p = Start-Process -FilePath $existingSihost -ArgumentList '--unload' -PassThru -WindowStyle Hidden
        $p | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
        Write-Info 'Uninjected previous overlay.'
    } catch {
        Write-Info 'Unload skipped (probably not needed).'
    }
}

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
    Write-Ok 'Old runtime binaries removed. Your login and settings are preserved.'
} else {
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    Write-Ok "Created fresh $INSTALL_DIR"
}

Write-Step 3 $totalSteps 'Adding Windows Defender exclusions...'
$tamperOn = Test-TamperProtection
if ($tamperOn) {
    Write-Warn 'Tamper Protection is ON. Some exclusions may not stick.'
    Write-Host '           To fix: Windows Security > Virus & threat protection >' -ForegroundColor Gray
    Write-Host '                  Manage settings > Tamper Protection: Off,' -ForegroundColor Gray
    Write-Host '                  then re-run this installer.' -ForegroundColor Gray
} else {
    Write-Info 'Tamper Protection: off (good)'
}
$exErrors = Add-DefenderExclusionSet
if ($exErrors -gt 0) {
    Write-Warn "$exErrors exclusion(s) failed. If Defender quarantines a binary,"
    Write-Host '           add exclusions manually: Windows Security > Exclusions > Add folder:' -ForegroundColor Gray
    Write-Host "             $INSTALL_DIR" -ForegroundColor Cyan
    Write-Host "             $APP_DIR" -ForegroundColor Cyan
} else {
    Write-Ok 'All exclusions added.'
}

Write-Step 4 $totalSteps 'Verifying extracted files...'
$mainExe = Join-Path $APP_DIR $MAIN_EXE
if (-not (Test-Path $mainExe)) {
    Write-Err "$MAIN_EXE missing at $mainExe"
    Write-Host '  Re-extract CloakGPTWindowsMaxStealth.zip and re-run.' -ForegroundColor Yellow
    pause; exit 1
}
$mainSize = [math]::Round((Get-Item $mainExe).Length / 1MB, 1)
Write-Ok "$MAIN_EXE present ($mainSize MB)"

$resDir = Join-Path $APP_DIR 'resources'
$missing = @()
foreach ($f in $C_BINARIES) {
    if (-not (Test-Path (Join-Path $resDir $f))) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Err 'Some bundled files are missing from resources/:'
    foreach ($m in $missing) { Write-Err "  - $m" }
    Write-Host ''
    Write-Host '  Likely cause: Windows Defender quarantined them during extraction.' -ForegroundColor Yellow
    Write-Host '  Open Windows Security > Protection history > Restore all,' -ForegroundColor Yellow
    Write-Host '  then re-extract the zip and re-run this installer.' -ForegroundColor Yellow
    pause; exit 1
}
Write-Ok "All $($C_BINARIES.Count) bundled files present."

Write-Step 5 $totalSteps 'Creating Desktop shortcut...'
$iconPath = Join-Path $APP_DIR 'resources\app\src\assets\svchelper.ico'
if (-not (Test-Path $iconPath)) { $iconPath = $mainExe }

$userDesktop   = [Environment]::GetFolderPath('Desktop')
$publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$currentSid    = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$interactiveSid = Get-InteractiveUserSid

# Over-the-shoulder-UAC detection: if the interactive Explorer session
# is owned by a different SID than the one this elevated pwsh is running
# as, our SpecialFolder.Desktop points at the WRONG user's Desktop and
# they'll never see the shortcut. Always drop a Public Desktop copy in
# that case (Public Desktop is visible to every user, so both accounts
# get the icon).
$elevationMismatch = $interactiveSid -and ($interactiveSid -ne $currentSid)
if ($elevationMismatch) {
    Write-Warn '  OVER-THE-SHOULDER UAC DETECTED'
    Write-Warn "    Elevated SID:    $currentSid"
    Write-Warn "    Interactive SID: $interactiveSid"
    Write-Warn '    Adding Public Desktop copy so the logged-in user can see it.'
}

$script:shortcutMade      = $false
$script:shortcutLocations = @()

# Attempt 1: current user's Desktop (normal case).
if ($userDesktop -and (Test-Path $userDesktop)) {
    $r = Add-ShortcutHardened -LnkPath (Join-Path $userDesktop 'Launch CloakGPT.lnk') `
                              -TargetExe $mainExe `
                              -WorkDir $APP_DIR `
                              -IconPath $iconPath `
                              -Description 'Launch CloakGPT (elevated).'
    if ($r.Success) {
        Write-Ok 'Shortcut placed on user Desktop'
        Write-Info "  Path: $($r.Path)"
        if (-not $r.AdminFlagged) {
            Write-Warn '  Admin-flag byte-patch failed - UAC will not auto-prompt on launch.'
            Write-Warn '  Right-click the shortcut > Properties > Advanced > Run as administrator to fix.'
        }
        $script:shortcutMade = $true
        $script:shortcutLocations += $r.Path
    } else {
        Write-Warn "User Desktop write failed: $($r.Reason)"
    }
} else {
    Write-Warn "User Desktop path is invalid: '$userDesktop'"
}

# Attempt 2: Public Desktop, if user Desktop failed OR elevation mismatch.
$needPublic = (-not $script:shortcutMade) -or $elevationMismatch
if ($needPublic -and $publicDesktop -and (Test-Path $publicDesktop) -and ($publicDesktop -ne $userDesktop)) {
    $r = Add-ShortcutHardened -LnkPath (Join-Path $publicDesktop 'Launch CloakGPT.lnk') `
                              -TargetExe $mainExe `
                              -WorkDir $APP_DIR `
                              -IconPath $iconPath `
                              -Description 'Launch CloakGPT (elevated).'
    if ($r.Success) {
        Write-Ok 'Shortcut placed on Public Desktop (visible to all users)'
        Write-Info "  Path: $($r.Path)"
        if (-not $r.AdminFlagged) {
            Write-Warn '  Admin-flag byte-patch failed on Public Desktop copy.'
        }
        $script:shortcutMade = $true
        $script:shortcutLocations += $r.Path
    } else {
        Write-Warn "Public Desktop write failed: $($r.Reason)"
    }
}

if (-not $script:shortcutMade) {
    Write-Err 'Could NOT create the shortcut on either user or Public Desktop.'
    Write-Err "You will need to launch manually: $mainExe"
}

Write-Step 6 $totalSteps 'Done.'
Write-Host ''
if ($script:shortcutMade) {
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
    if ($script:shortcutLocations.Count -gt 1) {
        Write-Host ''
        Write-Host "  (Shortcut placed in $($script:shortcutLocations.Count) locations for reliability)" -ForegroundColor Gray
    }
} else {
    Write-Host '  =========================================' -ForegroundColor Yellow
    Write-Host '     INSTALL PARTIAL - SHORTCUT MISSING     ' -ForegroundColor Yellow
    Write-Host '  =========================================' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Everything installed EXCEPT the Desktop shortcut. Scroll up' -ForegroundColor Yellow
    Write-Host '  to see the WARN lines with the exact failure reason.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Launch CloakGPT manually:' -ForegroundColor White
    Write-Host ''
    Write-Host "    Right-click this file, choose 'Run as administrator':" -ForegroundColor Cyan
    Write-Host "        $mainExe" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Common causes of shortcut-write failure:' -ForegroundColor White
    Write-Host '    - Anti-virus / EDR (Bitdefender, SentinelOne, Kaspersky) quarantines .lnk' -ForegroundColor Gray
    Write-Host '    - Group Policy blocks Desktop writes for elevated processes' -ForegroundColor Gray
    Write-Host '    - Windows Script Host gutted / wshom.ocx unregistered' -ForegroundColor Gray
    Write-Host '    - Desktop is a network share that is offline' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Manual shortcut recipe:' -ForegroundColor White
    Write-Host "    1. Open the folder above" -ForegroundColor Gray
    Write-Host '    2. Right-click svchelper.exe -> Send to -> Desktop (create shortcut)' -ForegroundColor Gray
    Write-Host '    3. Right-click the new Desktop shortcut -> Properties -> Advanced' -ForegroundColor Gray
    Write-Host '    4. Check "Run as administrator" -> OK -> OK' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Re-run this installer after fixing the underlying cause and' -ForegroundColor Gray
    Write-Host '  the shortcut will land automatically.' -ForegroundColor Gray
}
Write-Host ''
Write-Host '  Subscription: cloakgpt.ca/dashboard' -ForegroundColor Gray
Write-Host '  Support:      email us the zip from the "Export logs" button on the dashboard' -ForegroundColor Gray
Write-Host ''
Write-Host '  To uninstall later:' -ForegroundColor Gray
Write-Host '    powershell -ExecutionPolicy Bypass -File install-cloakgpt.ps1 -Uninstall' -ForegroundColor Cyan
Write-Host ''
pause
