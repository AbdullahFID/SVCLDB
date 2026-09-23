$ErrorActionPreference='Continue'
$env:SVCLDB_DEV_AUTH = "1"

Write-Host "=== stop residual sihost + svchelper so we can overwrite the .exe ==="
Get-Process -Name sihost -EA SilentlyContinue | Where-Object { $_.Path -like '*WinAudioSvc*' -or $_.Path -like '*svchelper*' } | ForEach-Object {
    Write-Host "  stopping sihost pid=$($_.Id) path=$($_.Path)"
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
}
Get-Process -Name svchelper -EA SilentlyContinue | ForEach-Object {
    Write-Host "  stopping svchelper pid=$($_.Id)"
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
}
Start-Sleep -Milliseconds 800

# Also drop any file handle by trying a rename dance
$src = 'C:\Users\abdul\Desktop\svcldb\build\launcher\sihost.exe'
$dst = 'C:\ProgramData\WinAudioSvc\sihost.exe'
$stash = 'C:\ProgramData\WinAudioSvc\sihost.exe.oldv' + (Get-Date -Format 'HHmmss')
if (Test-Path $dst) {
    try {
        Rename-Item -Path $dst -NewName (Split-Path -Leaf $stash) -Force -EA Stop
        Write-Host "  renamed old -> $stash"
    } catch {
        Write-Host "  rename failed: $($_.Exception.Message)"
    }
}
Push-Location C:\Users\abdul\Desktop\svcldb\payload
Write-Host "=== payload build ==="
cmd /c "build.bat" 2>&1 | Select-Object -Last 8
$pbuild = $LASTEXITCODE
Pop-Location
if ($pbuild -ne 0) { Write-Host "[FAIL] payload build exit=$pbuild"; exit 1 }

Push-Location C:\Users\abdul\Desktop\svcldb\launcher
Write-Host "=== launcher build ==="
cmd /c "build.bat" 2>&1 | Select-Object -Last 8
$lbuild = $LASTEXITCODE
Pop-Location
if ($lbuild -ne 0) { Write-Host "[FAIL] launcher build exit=$lbuild"; exit 1 }

Write-Host "=== deploy sihost.exe ==="
Copy-Item $src $dst -Force
Write-Host "  deployed: $((Get-Item $dst).Length) bytes"

Write-Host "=== reinject ==="
& $dst --reinject --quiet
Write-Host "reinject exit=$LASTEXITCODE"
Start-Sleep -Seconds 2
& $dst --status
Write-Host "status exit=$LASTEXITCODE"
