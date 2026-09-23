$ErrorActionPreference='Continue'
Get-Process -Name sihost -EA SilentlyContinue | Where-Object { $_.Path -like '*WinAudioSvc*' } | ForEach-Object {
    Write-Host "killing residual sihost pid=$($_.Id)"
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
}
Start-Sleep -Milliseconds 500
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --reinject --quiet
Write-Host "reinject exit=$LASTEXITCODE"
Start-Sleep -Seconds 2
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --status
Write-Host "status exit=$LASTEXITCODE"
