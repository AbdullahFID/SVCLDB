# Downloads each sample listed in samples.json from Microsoft's public
# symbol server (msdl.microsoft.com). URL format:
#   https://msdl.microsoft.com/download/symbols/dwmcore.dll/
#     <8-hex-TDS><hex-SizeOfImage>/dwmcore.dll
# Files land in `_dwmcore_samples/<winTag>_<version>.dll` for later probing.
param(
    [string]$SamplesJson = "$PSScriptRoot\samples.json",
    [string]$OutDir      = "$PSScriptRoot\_dwmcore_samples"
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

if (-not (Test-Path $OutDir)) { New-Item $OutDir -ItemType Directory -Force | Out-Null }

$samples = Get-Content $SamplesJson -Raw | ConvertFrom-Json
Write-Host "downloading $($samples.Count) samples to $OutDir`n"

$ok = 0; $fail = 0
foreach ($s in $samples) {
    # Build safe filename: <winTag>_<version-numeric>.dll
    $verNum = ($s.version -split ' ')[0]   # "10.0.22621.6060 (WinBuild.160101.0800)" -> "10.0.22621.6060"
    $safeTag = $s.winTag -replace '[^0-9A-Za-z-]', '_'
    $fname = "${safeTag}_${verNum}.dll"
    $dst = Join-Path $OutDir $fname

    if (Test-Path $dst) {
        $sz = (Get-Item $dst).Length
        if ($sz -eq $s.virtualSize -or $sz -eq $s.size) {
            Write-Host "  [SKIP] $fname (already $sz bytes)"
            $ok++
            continue
        } else {
            Remove-Item $dst -Force
        }
    }

    # symsrv URL. VSIZE hex is NOT zero-padded (Microsoft's own indexing).
    $tds = $s.tdsHex.ToUpper()
    $vsize = $s.vsizeHex.ToUpper()
    $key = "$tds$vsize"
    $url = "https://msdl.microsoft.com/download/symbols/dwmcore.dll/$key/dwmcore.dll"

    Write-Host "  [GET] $fname  ($($s.winTag) $verNum, tds=0x$tds, vsize=0x$vsize)"
    try {
        Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing -TimeoutSec 60 -Headers @{
            'User-Agent' = 'Microsoft-Symbol-Server/10.0.0.0'
        }
        $sz = (Get-Item $dst).Length
        Write-Host "        -> $sz bytes"
        $ok++
    } catch {
        Write-Host "        FAILED: $($_.Exception.Message)"
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
        $fail++
    }
    Start-Sleep -Milliseconds 200   # be nice to MS CDN
}

Write-Host "`n== summary ==  ok=$ok  fail=$fail  total=$($samples.Count)"
Write-Host "$OutDir contents:"
Get-ChildItem $OutDir -Filter '*.dll' | Select-Object Name, Length | Sort-Object Name | Format-Table -AutoSize
