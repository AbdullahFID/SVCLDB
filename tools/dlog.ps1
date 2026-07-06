#Requires -Version 7
# Decrypt svcldb .log files (AES-256-GCM per-line, v1.<base64>).
# Usage: pwsh -File tools/dlog.ps1 <path/to/logfile> [-Tail N]
param(
    [Parameter(Mandatory)] [string]$Path,
    [int]$Tail = 0,
    [string]$KeyHex = "5919246238e69eaf9ab65a4e15bf075141af7189fd5071aee7886505d01551c5"
)

if (-not (Test-Path $Path)) { Write-Error "File not found: $Path"; exit 1 }

$key = [byte[]]::new($KeyHex.Length / 2)
for ($i = 0; $i -lt $key.Length; $i++) {
    $key[$i] = [Convert]::ToByte($KeyHex.Substring($i*2, 2), 16)
}
$gcm = [System.Security.Cryptography.AesGcm]::new($key)

$lines = if ($Tail -gt 0) {
    Get-Content -Path $Path -Tail $Tail -ErrorAction Stop
} else {
    Get-Content -Path $Path -ErrorAction Stop
}

$decrypted = 0
$errors = 0
foreach ($line in $lines) {
    $line = $line.Trim()
    if (-not $line.StartsWith("v1.")) { continue }
    $b64 = $line.Substring(3)
    try {
        $blob = [Convert]::FromBase64String($b64)
        if ($blob.Length -lt (12 + 16 + 1)) { Write-Host "[short] $line"; $errors++; continue }
        $iv = $blob[0..11]
        $tag = $blob[12..27]
        $ct = $blob[28..($blob.Length - 1)]
        $pt = [byte[]]::new($ct.Length)
        $gcm.Decrypt($iv, $ct, $tag, $pt)
        Write-Host ([Text.Encoding]::UTF8.GetString($pt))
        $decrypted++
    } catch {
        Write-Host "[decrypt-fail] $($_.Exception.Message) — line: $($line.Substring(0, [Math]::Min(80, $line.Length)))..."
        $errors++
    }
}

Write-Host ""
Write-Host "--- Decrypted $decrypted lines, $errors errors ---"
