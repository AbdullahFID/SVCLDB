# Runs probe.exe against every .dll in _dwmcore_samples/ and saves
# per-sample output to _probe_out/<sample>.txt. Rerunnable -- skips
# samples that already have a saved output.
param(
    [string]$SamplesDir = "$PSScriptRoot\_dwmcore_samples",
    [string]$OutDir     = "$PSScriptRoot\_probe_out",
    [string]$Probe      = "$PSScriptRoot\..\dwmcore_shape_probe\probe.exe"
)

$ErrorActionPreference = 'Continue'
if (-not (Test-Path $Probe))     { throw "probe.exe missing: $Probe" }
if (-not (Test-Path $OutDir))    { New-Item $OutDir -ItemType Directory -Force | Out-Null }

$samples = Get-ChildItem $SamplesDir -Filter '*.dll' | Sort-Object Name
Write-Host "running probe against $($samples.Count) samples`n"

$total = 0; $done = 0; $started = Get-Date
foreach ($s in $samples) {
    $total++
    $outFile = Join-Path $OutDir ($s.BaseName + '.txt')
    if (Test-Path $outFile) {
        $sz = (Get-Item $outFile).Length
        if ($sz -gt 500) {   # non-trivial output already present
            Write-Host "  [SKIP] $($s.Name)  (output cached, $sz bytes)"
            $done++
            continue
        }
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    Write-Host -NoNewline "  [$total/$($samples.Count)] $($s.Name) ... "
    & $Probe $s.FullName 2>&1 | Out-File $outFile -Encoding utf8
    $sw.Stop()
    $ex = $LASTEXITCODE
    $sz = (Get-Item $outFile).Length
    Write-Host "$($sw.ElapsedMilliseconds)ms exit=$ex out=$sz bytes"
    $done++
}

$elapsed = ((Get-Date) - $started).TotalSeconds
Write-Host "`ndone: $done/$total in $([int]$elapsed)s -- outputs in $OutDir"
