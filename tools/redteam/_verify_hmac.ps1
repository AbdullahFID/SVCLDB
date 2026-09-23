# Check whether payload+helper are actually using HMAC derivation now.
# From admin, enumerate all pipes matching GUID pattern. If we see the
# SHA256-derived names still present, HMAC didn't take effect.

$machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid.Trim().ToLower()
Write-Host "MachineGuid: $machineGuid"

# Read _bind.bin (admin can read regardless of DACL)
$bindPath = 'C:\ProgramData\WinAudioSvc\_bind.bin'
if (Test-Path $bindPath) {
    $bind = [System.IO.File]::ReadAllBytes($bindPath)
    Write-Host "_bind.bin length: $($bind.Length)"
    Write-Host "_bind.bin hex first 8: $(($bind[0..7] | ForEach-Object { $_.ToString('x2') }) -join '')"
} else {
    Write-Host "_bind.bin MISSING"
    exit 1
}

function Get-Sha256Guid($salt) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt + ':' + $machineGuid))
    $sha.Dispose()
    $hex = -join ($h[0..15] | ForEach-Object { $_.ToString('x2') })
    return ('{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(12,4), $hex.Substring(16,4), $hex.Substring(20,12))
}
function Get-HmacGuid($salt) {
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$bind)
    $h = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt + ':' + $machineGuid))
    $hmac.Dispose()
    $hex = -join ($h[0..15] | ForEach-Object { $_.ToString('x2') })
    return ('{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(12,4), $hex.Substring(16,4), $hex.Substring(20,12))
}

$salts = @('wasvc.pipe.token.1','wasvc.pipe.ocr.1','wasvc.mtx.init.1','wasvc.mtx.ocrd.1','wasvc.evt.shut.1',
           'wasvc.pipe.iso.1','wasvc.evt.iso.halt.1','wasvc.evt.iso.chat.1','wasvc.pipe.iso.cmd.1','wasvc.mtx.sentinel.1','wasvc.mtx.emerg.hk.1')
Write-Host ""
Write-Host ("{0,-30} {1,-38} {2,-38}" -f 'salt', 'SHA256(salt:guid)', 'HMAC(bind, salt:guid)')
Write-Host ("-" * 108)
foreach ($s in $salts) {
    Write-Host ("{0,-30} {1,-38} {2,-38}" -f $s, (Get-Sha256Guid $s), (Get-HmacGuid $s))
}

# Enum all named pipes and match
$pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_ -replace '^\\\\\.\\pipe\\','' }
Write-Host ""
Write-Host "=== which pipes ACTUALLY EXIST? ==="
$found_sha = @()
$found_hmac = @()
foreach ($s in @('wasvc.pipe.token.1','wasvc.pipe.ocr.1','wasvc.pipe.iso.1','wasvc.pipe.iso.cmd.1')) {
    $sha = Get-Sha256Guid $s
    $hmac = Get-HmacGuid $s
    $shaHit = $pipes -contains $sha
    $hmacHit = $pipes -contains $hmac
    Write-Host ("  {0}" -f $s)
    Write-Host ("    SHA256 name  {0}  present={1}" -f $sha, $shaHit)
    Write-Host ("    HMAC name    {0}  present={1}" -f $hmac, $hmacHit)
    if ($shaHit) { $found_sha += $s }
    if ($hmacHit) { $found_hmac += $s }
}
Write-Host ""
Write-Host "SUMMARY: SHA256-name pipes present: $($found_sha.Count) / HMAC-name pipes present: $($found_hmac.Count)"
if ($found_sha.Count -gt 0) {
    Write-Host "  ==> HMAC derivation NOT active on payload/helper. Investigate build." -ForegroundColor Red
} elseif ($found_hmac.Count -gt 0) {
    Write-Host "  ==> HMAC derivation active. GOOD." -ForegroundColor Green
}
