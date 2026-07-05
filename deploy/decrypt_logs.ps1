# Decrypt all svcldb *.log files in the install dir + print latest lines.
# Uses the SVCLDB_LOG_KEY compiled into log_key.c (32 bytes, hardcoded dev key).
#
# Usage:
#   .\decrypt_logs.ps1            # decrypt all *.log files
#   .\decrypt_logs.ps1 -File payload.log -Tail 40
#   .\decrypt_logs.ps1 -Follow    # tail -f style (poll + decrypt new lines)

param(
    [string]$InstallDir = 'C:\ProgramData\Microsoft\WSMonitoring',
    [string]$File       = '',
    [int]$Tail          = 100,
    [switch]$Follow
)

$ErrorActionPreference = 'Continue'

# ── SVCLDB_LOG_KEY (bytes match svcldb/shared/log_key.c) ──
$key = [byte[]](0x7a,0x9e,0x14,0x3b,0x62,0x8c,0xd1,0x05,
                0xf7,0x2a,0x4b,0x91,0xc6,0x08,0x5d,0xea,
                0x33,0x71,0xbf,0x02,0x88,0x4e,0xd3,0x1a,
                0x66,0xa9,0x0c,0xf5,0x27,0xb0,0x9d,0x48)

Add-Type -AssemblyName System.Security

function Decrypt-Line([string]$line, [byte[]]$k) {
    if ($line -notmatch '^v1\.(.+)$') { return $line }  # legacy plaintext passes through
    try {
        $blob = [Convert]::FromBase64String($matches[1])
        if ($blob.Length -lt 29) { return "[SHORT] $line" }
        $iv  = $blob[0..11]
        $tag = $blob[12..27]
        $ct  = $blob[28..($blob.Length - 1)]
        $aes = [System.Security.Cryptography.AesGcm]::new($k)
        $pt  = New-Object byte[] $ct.Length
        $aes.Decrypt($iv, $ct, $tag, $pt)
        $aes.Dispose()
        return [System.Text.Encoding]::UTF8.GetString($pt)
    } catch {
        return "[BAD/WRONG-KEY] $line"
    }
}

function Decrypt-File([string]$path, [int]$tail) {
    if (-not (Test-Path $path)) { Write-Host "  (missing) $path" -ForegroundColor DarkGray; return }
    $lines = Get-Content $path -Tail $tail -Encoding UTF8
    Write-Host ""
    Write-Host "── $(Split-Path -Leaf $path)  (last $tail lines) ──" -ForegroundColor Cyan
    foreach ($ln in $lines) {
        $pt = Decrypt-Line $ln $key
        # Color-code by tag.
        if     ($pt -match '\[cap-x?\]|\[dwm-') { Write-Host $pt -ForegroundColor Yellow }
        elseif ($pt -match 'FAIL|ERROR|err=|failed') { Write-Host $pt -ForegroundColor Red }
        elseif ($pt -match 'ok|OK|armed|Ready')  { Write-Host $pt -ForegroundColor Green }
        else   { Write-Host $pt -ForegroundColor Gray }
    }
}

if ($Follow) {
    $target = if ($File) { Join-Path $InstallDir $File } else { $null }
    if (-not $target) { Write-Host "-Follow needs -File" -ForegroundColor Red; exit 1 }
    Write-Host "Following $target  (Ctrl+C to stop)" -ForegroundColor Yellow
    $seen = 0
    while ($true) {
        if (Test-Path $target) {
            $all = Get-Content $target -Encoding UTF8
            if ($all.Count -gt $seen) {
                foreach ($ln in $all[$seen..($all.Count - 1)]) {
                    $pt = Decrypt-Line $ln $key
                    Write-Host $pt
                }
                $seen = $all.Count
            }
        }
        Start-Sleep -Milliseconds 500
    }
} elseif ($File) {
    Decrypt-File (Join-Path $InstallDir $File) $Tail
} else {
    $logs = @('launcher.log','payload.log','resolver.log','ai.log','auth.log')
    foreach ($f in $logs) { Decrypt-File (Join-Path $InstallDir $f) $Tail }
}
