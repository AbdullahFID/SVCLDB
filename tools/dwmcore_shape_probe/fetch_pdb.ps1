param(
    [Parameter(Mandatory)][string]$Key,
    [string]$PdbName = 'dwmcore.pdb',
    [string]$Cache = 'C:\ProgramData\WinAudioSvc\symbols'
)
$url = "https://msdl.microsoft.com/download/symbols/$PdbName/$Key/$PdbName"
$outDir = Join-Path $Cache "$PdbName\$Key"
$out = Join-Path $outDir $PdbName
New-Item -Force -ItemType Directory $outDir | Out-Null
Write-Host "GET $url"
try {
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing `
        -Headers @{'User-Agent' = 'Microsoft-Symbol-Server/10.0.10036.206'}
    $sz = (Get-Item $out).Length
    Write-Host "downloaded $sz bytes -> $out"
} catch {
    Write-Host "FAILED: $($_.Exception.Message)"
    if (Test-Path $out) { Remove-Item $out -Force }
}
