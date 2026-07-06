# ══════════════════════════════════════════════════════════════════
#  install-cloakgpt.ps1 — Auto-install/upgrade helper packaged inside
#  CloakGPTWindowsMaxStealth.zip.
#
#  Recipients run this to:
#    1. Extract CloakGPT/ next to itself if not already extracted
#    2. Kill any running svchelper.exe (safe — it just closes the UI,
#       the injected payload lives inside dwm.exe and is unaffected)
#    3. Wipe any prior install of the C binaries in
#       C:\ProgramData\WinAudioSvc (safe — svchelper re-copies on next
#       launch; only strips stale bins from an older version)
#    4. Add a `Launch CloakGPT.lnk` to their real Desktop
#       (OneDrive-safe) pointing at the extracted svchelper.exe with
#       the "Run as administrator" bit set
#    5. Print next steps
#
#  Idempotent — safe to re-run for upgrades.
#
#  Invoke (right-click → Run with PowerShell, OR from admin terminal):
#      pwsh -File install-cloakgpt.ps1
# ══════════════════════════════════════════════════════════════════

$ErrorActionPreference = 'Stop'

Write-Host ''
Write-Host '  CloakGPT installer'
Write-Host '  =================='
Write-Host ''

$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# ── 1. Locate the CloakGPT/ folder (either next to this script or one level down) ──
$candidates = @(
  (Join-Path $here 'CloakGPT'),
  (Join-Path $here 'CloakGPTWindowsMaxStealth\CloakGPT'),
  $here
) | Where-Object { Test-Path (Join-Path $_ 'svchelper.exe') }

if ($candidates.Count -eq 0) {
  Write-Host '[!] Could not find svchelper.exe. Extract CloakGPTWindowsMaxStealth.zip'
  Write-Host '    to a folder, then run this script from inside that folder.'
  Read-Host '    Press Enter to close'
  exit 1
}
$appDir  = $candidates[0]
$appExe  = Join-Path $appDir 'svchelper.exe'
Write-Host "  Found svchelper.exe at: $appExe"

# ── 2. Kill any running svchelper (previous version, if upgrading) ──
$existing = Get-Process svchelper -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "  Stopping $($existing.Count) running svchelper process(es)..."
  $existing | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

# ── 3. Wipe old C binaries so first-run install copies fresh ones ──
# svchelper.exe on next launch calls ensureCBinariesInstalled() which
# does size+mtime comparison, so this step is technically redundant.
# But it's belt-and-suspenders against edge cases (mtime not updated,
# same size but different content, corrupted install).
$svcDir = 'C:\ProgramData\WinAudioSvc'
if (Test-Path $svcDir) {
  Write-Host '  Cleaning old C binaries from ProgramData (config + logs preserved)...'
  foreach ($f in @('sihost.exe','dllhost32.exe','dwmapiext.dll','cgpt_dbghelp.dll','symsrv.dll')) {
    $p = Join-Path $svcDir $f
    if (Test-Path $p) { Remove-Item -Force -ErrorAction SilentlyContinue $p }
  }
  Write-Host '    Kept: config.dat, session.dat, api_keys.enc, launcher.log, payload.log'
}

# ── 4. Desktop shortcut (OneDrive-safe) ──
$desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
if (!$desktop -or !(Test-Path $desktop)) {
  $desktop = Join-Path $env:USERPROFILE 'Desktop'
}
Write-Host "  Desktop resolved to: $desktop"
if ($desktop -match 'OneDrive') { Write-Host '    (OneDrive-synced Desktop detected)' }

$lnkPath  = Join-Path $desktop 'Launch CloakGPT.lnk'
$iconPath = Join-Path $appDir 'resources\app\assets\svchelper.ico'
if (!(Test-Path $iconPath)) { $iconPath = $appExe }

$wsh = New-Object -ComObject WScript.Shell
$sc  = $wsh.CreateShortcut($lnkPath)
$sc.TargetPath       = $appExe
$sc.WorkingDirectory = $appDir
$sc.IconLocation     = "$iconPath,0"
$sc.Description      = 'Launch CloakGPT (elevated). AI overlay for LockDown Browser.'
$sc.Save()

# Flip the Run-as-admin bit in the .lnk binary
$bytes = [System.IO.File]::ReadAllBytes($lnkPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($lnkPath, $bytes)
Write-Host "  Wrote Launch CloakGPT.lnk (admin-flagged)"

# ── 5. Print next steps ──
Write-Host ''
Write-Host '  ============================================================'
Write-Host '  Install complete.'
Write-Host '  ============================================================'
Write-Host ''
Write-Host '  Next steps:'
Write-Host '    1. Double-click "Launch CloakGPT" on your Desktop.'
Write-Host '    2. Accept the UAC prompt.'
Write-Host '    3. Sign in with Google.'
Write-Host '    4. Paste your AI API keys and click "Inject Now".'
Write-Host '    5. Launch LockDown Browser.'
Write-Host ''
Write-Host '  Full setup guide + Defender exclusion steps:'
Write-Host '    See INSTRUCTIONS.md in the same folder as this script.'
Write-Host ''
Read-Host 'Press Enter to close'
