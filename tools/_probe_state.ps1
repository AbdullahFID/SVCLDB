$ErrorActionPreference='Continue'
$dwm = Get-Process dwm -EA SilentlyContinue
$winlog = Get-Process winlogon -EA SilentlyContinue
$sihost = Get-Process sihost -EA SilentlyContinue
Write-Host "=== DWM ==="
$dwm | Format-Table Id, ProcessName, StartTime -AutoSize
Write-Host "=== WINLOGON ==="
$winlog | Format-Table Id, ProcessName, SessionId, StartTime -AutoSize
Write-Host "=== SIHOST (any process named sihost) ==="
$sihost | Format-Table Id, ProcessName, Path -AutoSize
Write-Host "=== dwmapiext.dll in dwm module list? ==="
foreach ($p in $dwm) {
  try {
    $mods = $p.Modules
    $found = $mods | Where-Object { $_.ModuleName -like '*dwmapi*' -or $_.ModuleName -like '*wl_input*' }
    Write-Host ("  dwm pid={0} modules={1}" -f $p.Id, $mods.Count)
    foreach ($m in $found) { Write-Host ("    -> {0}   ({1})" -f $m.ModuleName, $m.FileName) }
  } catch {
    Write-Host ("  dwm pid={0} <access denied enumerating modules>" -f $p.Id)
  }
}
Write-Host "=== wl_input in winlogon? ==="
foreach ($p in $winlog) {
  try {
    $mods = $p.Modules
    $found = $mods | Where-Object { $_.ModuleName -like '*wl_input*' -or $_.ModuleName -like '*svcldb*' -or $_.ModuleName -like '*cloak*' }
    Write-Host ("  winlogon pid={0} sess={1} modules={2}" -f $p.Id, $p.SessionId, $mods.Count)
    foreach ($m in $found) { Write-Host ("    -> {0}   ({1})" -f $m.ModuleName, $m.FileName) }
  } catch {
    Write-Host ("  winlogon pid={0} <access denied>" -f $p.Id)
  }
}
Write-Host "=== sihost --status ==="
$statusExe = 'C:\ProgramData\WinAudioSvc\sihost.exe'
if (Test-Path $statusExe) {
    & $statusExe --status
    Write-Host "sihost --status exit=$LASTEXITCODE"
}
