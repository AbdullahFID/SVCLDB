param([string[]]$Paths = @(
    'C:\Windows\System32\dwmcore.dll',
    'C:\Users\abdul\Desktop\hooksdll\dwm\dwmcore_clean.dll',
    'C:\Users\abdul\Desktop\hooksdll\dwm\dwmcore_copy.dll'
))
foreach ($p in $Paths) {
    if (-not (Test-Path $p)) { "MISSING: $p"; continue }
    $vi = (Get-Item $p).VersionInfo
    $fs = [IO.File]::OpenRead($p)
    try {
        $br = New-Object IO.BinaryReader($fs)
        $fs.Seek(0x3C, 'Begin') | Out-Null
        $pe = $br.ReadInt32()
        $fs.Seek($pe + 4 + 4, 'Begin') | Out-Null
        $tds = $br.ReadUInt32()
    } finally { $fs.Close() }
    "{0}`n  FileVersion={1}  size={2}  TDS=0x{3:X8}" -f $p, $vi.FileVersion, (Get-Item $p).Length, $tds
}
