# =================================================================
#  build-distribution.ps1 - Package everything for end-user download.
#
#  Produces up to FOUR artifacts on the current user's REAL Desktop
#  (OneDrive Known-Folder-Move safe - uses [Environment]::GetFolderPath
#  so it resolves to `C:\Users\<u>\OneDrive\Desktop` when KFM is on):
#
#    1. CloakGPTWindowsMaxStealth-Setup.exe  - one-click NSIS installer
#                                              (primary download path)
#    2. CloakGPTWindowsMaxStealth.zip        - manual-install fallback
#                                              (unchanged from prior)
#    3. CloakGPT Setup Instructions.md       - user setup guide (Defender,
#                                              admin, install, troubleshoot)
#    4. Launch CloakGPT.lnk                  - elevation-flagged shortcut
#                                              (only useful AFTER user
#                                              extracts the zip; the
#                                              NSIS Setup.exe creates its
#                                              own shortcut natively)
#
#  The Setup.exe path is preferred. The zip stays around for:
#    - Users mid-upgrade from a pre-NSIS install
#    - Corporate MDM boxes where Setup.exe elevation is blocked and
#      manual per-user install is the only path
#    - Debug / support scenarios where an admin wants to inspect the
#      unpacked layout before running the app
#
#  Run this AFTER `pnpm build` completes. `pnpm build` produces both
#  `dist\win-unpacked\` and `dist\CloakGPTWindowsMaxStealth-Setup.exe`
#  in one shot (see ui\build-protected.js Step 7 for the NSIS second-
#  pass invocation).
#
#  Invoke:
#      powershell -File ui\tools\build-distribution.ps1
# =================================================================

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$distDir  = Join-Path $repoRoot 'ui\dist\win-unpacked'
$setupExe = Join-Path $repoRoot 'ui\dist\CloakGPTWindowsMaxStealth-Setup.exe'
$docsDir  = Join-Path $repoRoot 'docs'

if (!(Test-Path $distDir)) {
  Write-Error "dist folder missing: $distDir - run 'pnpm build' first"
  exit 1
}

# --- OneDrive-safe Desktop resolution ---------------------------
# .NET's Environment.GetFolderPath honors KFM (Known Folder Move) so
# if the user's Desktop is redirected into OneDrive we drop artifacts
# in the OneDrive-synced location automatically. That's actually
# desired behavior - user gets a cross-device synced copy of both the
# zip and the shortcut for free.
$desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
if (!$desktop -or !(Test-Path $desktop)) {
  # Extremely rare fallback: no desktop folder at all. Try USERPROFILE.
  $desktop = Join-Path $env:USERPROFILE 'Desktop'
  if (!(Test-Path $desktop)) { New-Item -ItemType Directory -Path $desktop | Out-Null }
}
Write-Host "Target Desktop: $desktop"
if ($desktop -match 'OneDrive') { Write-Host "  (OneDrive-synced - that's fine)" }
Write-Host ""

# --- 1a. Copy the NSIS Setup.exe to the Desktop (primary download) --
# Produced by ui\build-protected.js Step 7 (second-pass electron-builder
# with the nsis target, using dist\win-unpacked\ as prepackaged input).
# Missing Setup.exe is NOT fatal - the zip flow below still ships, users
# just fall back to the manual install path documented in the Setup Guide.
$setupOutName = 'CloakGPTWindowsMaxStealth-Setup.exe'
$setupOutPath = Join-Path $desktop $setupOutName
if (Test-Path $setupExe) {
  if (Test-Path $setupOutPath) {
    Write-Host "Removing existing $setupOutName ..."
    Remove-Item -Force $setupOutPath
  }
  Copy-Item -Path $setupExe -Destination $setupOutPath -Force
  $setupSize = '{0:N1} MB' -f ((Get-Item $setupOutPath).Length / 1MB)
  Write-Host "  Copied $setupOutName ($setupSize) [primary one-click installer]"
} else {
  Write-Host "  WARNING: $setupExe missing - one-click Setup.exe skipped" -ForegroundColor Yellow
  Write-Host "           (was electron-builder's NSIS second pass skipped or did it fail?)" -ForegroundColor Yellow
  Write-Host "           The zip below still ships; users can install manually via install-cloakgpt.ps1." -ForegroundColor Yellow
}

# --- 1b. Zip the dist folder (manual-install fallback) ---------------
$zipName = 'CloakGPTWindowsMaxStealth.zip'
$zipPath = Join-Path $desktop $zipName
if (Test-Path $zipPath) {
  Write-Host "Removing existing $zipName ..."
  Remove-Item -Force $zipPath
}
$stagingRoot = Join-Path $env:TEMP ('cloakgpt-dist-' + [guid]::NewGuid().ToString('N').Substring(0,8))
$stagingApp  = Join-Path $stagingRoot 'CloakGPT'
Write-Host "Staging in $stagingApp ..."
New-Item -ItemType Directory -Path $stagingApp | Out-Null

# Copy the entire Electron dist folder into staging/CloakGPT/
Copy-Item -Path (Join-Path $distDir '*') -Destination $stagingApp -Recurse -Force

# INSTRUCTIONS.md is NOT bundled into the zip anymore - the standalone
# "CloakGPT Setup Instructions.md" on the Desktop is enough and keeping
# a copy in the zip clutters what recipients see when they preview it.
# Only ship install-cloakgpt.ps1 alongside the CloakGPT/ folder.
Copy-Item -Path (Join-Path $repoRoot 'ui\tools\install-cloakgpt.ps1') `
          -Destination (Join-Path $stagingRoot 'install-cloakgpt.ps1') -Force

Write-Host "Zipping ..."
Compress-Archive -Path (Join-Path $stagingRoot '*') `
                 -DestinationPath $zipPath `
                 -CompressionLevel Optimal -Force

Remove-Item -Recurse -Force $stagingRoot
$zipSize = '{0:N1} MB' -f ((Get-Item $zipPath).Length / 1MB)
Write-Host "  Zipped $zipName ($zipSize)"

# --- 2. INSTRUCTIONS.md - drop a top-level copy on Desktop too --
Copy-Item -Path (Join-Path $docsDir 'INSTRUCTIONS.md') `
          -Destination (Join-Path $desktop 'CloakGPT Setup Instructions.md') -Force
Write-Host "  Wrote CloakGPT Setup Instructions.md"

# --- 3. 'Launch CloakGPT.lnk' shortcut --------------------------
# The shortcut points to wherever the user EXTRACTED the zip - we don't
# know that path until they extract it. Convention: extract to Desktop
# so it becomes `<Desktop>\CloakGPT\svchelper.exe`. If they extract
# elsewhere, the shortcut will show a "target not found" error and they
# can re-run install-cloakgpt.ps1 (packaged in the zip) which regenerates
# the shortcut to point wherever they extracted.
$targetPath = Join-Path $desktop 'CloakGPT\svchelper.exe'
$lnkPath    = Join-Path $desktop 'Launch CloakGPT.lnk'
$iconPath   = Join-Path $distDir 'resources\app\src\assets\svchelper.ico'
if (!(Test-Path $iconPath)) { $iconPath = $targetPath }

$wsh = New-Object -ComObject WScript.Shell
$sc  = $wsh.CreateShortcut($lnkPath)
$sc.TargetPath       = $targetPath
$sc.WorkingDirectory = Split-Path $targetPath -Parent
$sc.IconLocation     = "$iconPath,0"
$sc.Description      = 'Launch CloakGPT (elevated). AI overlay for LockDown Browser.'
$sc.Save()

# Flip the "Run as administrator" bit in the .lnk binary.
# Byte 0x15, bit 0x20. Per MS-SHLLINK spec section 2.1 LinkFlags.
$bytes = [System.IO.File]::ReadAllBytes($lnkPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($lnkPath, $bytes)
Write-Host "  Wrote Launch CloakGPT.lnk (admin-flagged)"

Write-Host ''
Write-Host '=================================================================='
Write-Host '  Distribution build complete.'
if (Test-Path $setupOutPath) {
  Write-Host '  Setup.exe:    ' $setupOutPath ' [primary one-click installer]'
} else {
  Write-Host '  Setup.exe:     (not produced this run)'                    -ForegroundColor Yellow
}
Write-Host '  Zip:          ' $zipPath                        ' [manual-install fallback]'
Write-Host '  Instructions: ' (Join-Path $desktop 'CloakGPT Setup Instructions.md')
Write-Host '  Shortcut:     ' $lnkPath
Write-Host '=================================================================='
