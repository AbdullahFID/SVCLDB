$ErrorActionPreference='Continue'
$env:SVCLDB_DEV_AUTH='1'

Write-Host "=== stop sihost (any) ==="
Get-Process -Name sihost -EA SilentlyContinue | Where-Object { $_.Path -like '*WinAudioSvc*' } | ForEach-Object {
    Write-Host "  stopping sihost pid=$($_.Id)"
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
}
Start-Sleep -Milliseconds 500

Write-Host "=== delete stale _bind.bin (regenerated with new DACL on next arm) ==="
if (Test-Path 'C:\ProgramData\WinAudioSvc\_bind.bin') {
    Remove-Item 'C:\ProgramData\WinAudioSvc\_bind.bin' -Force
    Write-Host "  deleted"
}

$src = 'C:\Users\abdul\Desktop\svcldb\build\launcher\sihost.exe'
$dst = 'C:\ProgramData\WinAudioSvc\sihost.exe'
$stash = 'C:\ProgramData\WinAudioSvc\sihost.exe.oldv' + (Get-Date -Format 'HHmmss')
if (Test-Path $dst) {
    try {
        Rename-Item -Path $dst -NewName (Split-Path -Leaf $stash) -Force -EA Stop
        Write-Host "  renamed old -> $stash"
    } catch {}
}

Push-Location C:\Users\abdul\Desktop\svcldb\payload
Write-Host "=== payload build ==="
cmd /c "build.bat" 2>&1 | Select-Object -Last 6
$pbuild = $LASTEXITCODE
Pop-Location
if ($pbuild -ne 0) { Write-Host "[FAIL] payload build"; exit 1 }

# Force helper rebuild (build_helper.bat is skipped by launcher/build.bat if
# wl_input.dll exists -- delete so launcher picks up any wl_input.c changes)
Remove-Item 'C:\Users\abdul\Desktop\svcldb\build\helper\wl_input.dll' -Force -EA SilentlyContinue

Push-Location C:\Users\abdul\Desktop\svcldb\launcher
Write-Host "=== launcher build (rebuilds helper too) ==="
cmd /c "build.bat" 2>&1 | Select-Object -Last 6
$lbuild = $LASTEXITCODE
Pop-Location
if ($lbuild -ne 0) { Write-Host "[FAIL] launcher build"; exit 1 }

Write-Host "=== deploy ==="
Copy-Item $src $dst -Force
Write-Host "  deployed: $((Get-Item $dst).Length) bytes"

# Kill DWM so stale in-DWM payload state clears; winlogon auto-respawns
Write-Host "=== killing dwm.exe (winlogon respawns) ==="
$oldDwm = (Get-Process dwm -EA SilentlyContinue).Id
Stop-Process -Name dwm -Force -EA SilentlyContinue
Write-Host "  old dwm pid=$oldDwm"

# Wait for dwm respawn
Start-Sleep -Seconds 4
$newDwm = (Get-Process dwm -EA SilentlyContinue).Id
Write-Host "  new dwm pid=$newDwm"

Write-Host "=== reinject ==="
& $dst --reinject --quiet
Write-Host "  reinject exit=$LASTEXITCODE"
Start-Sleep -Seconds 3
& $dst --status
Write-Host "  status exit=$LASTEXITCODE"

Write-Host "=== _bind.bin state ==="
Get-Item 'C:\ProgramData\WinAudioSvc\_bind.bin' -Force -EA SilentlyContinue | Format-List Name, Length, Attributes
