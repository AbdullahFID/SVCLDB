$ErrorActionPreference = 'Continue'

Write-Host "=== DWM process + modules ==="
$dwm = Get-Process dwm -ErrorAction SilentlyContinue | Select-Object -First 1
if ($dwm) {
    "$($dwm.Name) pid=$($dwm.Id) started=$($dwm.StartTime)"
    $dwm.Modules |
        Where-Object { $_.ModuleName -match 'dwmapi|dwmcore|dwmapiext|WinAudio|dwmredir' } |
        Select-Object ModuleName, FileName, ModuleMemorySize |
        Format-Table -AutoSize
} else {
    Write-Host "no dwm process visible (need elevation)"
}

Write-Host "=== svchelper / sihost / winlogon ==="
Get-Process sihost, svchelper, winlogon -ErrorAction SilentlyContinue |
    Select-Object Name, Id, StartTime, Path |
    Format-Table -AutoSize

Write-Host "=== dwmcore.dll PE TimeDateStamp on disk ==="
$dcPath = "$env:SystemRoot\System32\dwmcore.dll"
if (Test-Path $dcPath) {
    $fs = [System.IO.File]::OpenRead($dcPath)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek(0x3C, 'Begin') | Out-Null
        $peOff = $br.ReadInt32()
        $fs.Seek($peOff + 4 + 4, 'Begin') | Out-Null   # skip 'PE\0\0' + Machine(2)+NumSections(2) -> wait, layout: PE\0\0 (4) then FileHeader begins with Machine(2)+NumSections(2)+TimeDateStamp(4)
        # Correct offset: PE signature (4) then Machine(2) + NumSections(2) = 4, then TimeDateStamp(4)
        $fs.Seek($peOff + 4 + 4, 'Begin') | Out-Null
        $tds = $br.ReadUInt32()
        "{0}: version={1} TimeDateStamp=0x{2:X8} ({3})" -f $dcPath, ((Get-Item $dcPath).VersionInfo.FileVersion), $tds, ([DateTimeOffset]::FromUnixTimeSeconds($tds).ToString('yyyy-MM-dd HH:mm:ss UTC'))
    } finally { $fs.Close() }
} else { Write-Host "dwmcore.dll not found at $dcPath" }

Write-Host "=== cached offsets.blob.sig (from launcher's last resolve) ==="
$sigPath = 'C:\ProgramData\WinAudioSvc\offsets.blob.sig'
if (Test-Path $sigPath) {
    $sigBytes = [System.IO.File]::ReadAllBytes($sigPath)
    if ($sigBytes.Length -ge 4) {
        $cachedStamp = [BitConverter]::ToUInt32($sigBytes, 0)
        "cached sig = 0x{0:X8} ({1})" -f $cachedStamp, ([DateTimeOffset]::FromUnixTimeSeconds($cachedStamp).ToString('yyyy-MM-dd HH:mm:ss UTC'))
    } else {
        "sig file too short ({0} bytes)" -f $sigBytes.Length
    }
} else { Write-Host "offsets.blob.sig not found" }

Write-Host "=== sentinels ==="
Get-ChildItem 'C:\ProgramData\WinAudioSvc\.dwm_*', 'C:\ProgramData\WinAudioSvc\.svchelper_*' -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
