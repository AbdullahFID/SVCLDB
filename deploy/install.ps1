#requires -RunAsAdministrator
# =============================================================
#  install.ps1 — Stage binaries + dbghelp/symsrv to runtime dir.
# =============================================================

$ErrorActionPreference = 'Stop'

$Root       = Split-Path -Parent $PSScriptRoot
$Build      = Join-Path $Root 'build'
$InstallDir = 'C:\ProgramData\WinAudioSvc'   # match SVC_INSTALL_DIR in common.h

Write-Host "=== svcldb: install to $InstallDir ==="

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "  Created $InstallDir"
}

$binaries = @(
    @{ src = "$Build\launcher\sihost.exe";    dst = "$InstallDir\sihost.exe"    }
    @{ src = "$Build\payload\dwmapiext.dll";  dst = "$InstallDir\dwmapiext.dll" }
    @{ src = "$Build\resolver\dllhost32.exe"; dst = "$InstallDir\dllhost32.exe" }
)
foreach ($b in $binaries) {
    if (-not (Test-Path $b.src)) {
        Write-Warning ("MISSING: {0} - run build_all.bat first" -f $b.src)
        exit 1
    }
    Copy-Item -Path $b.src -Destination $b.dst -Force
    $sz = (Get-Item $b.dst).Length
    $nm = Split-Path -Leaf $b.dst
    Write-Host ("  {0} ({1} bytes)" -f $nm, $sz)
}

# ── dbghelp + symsrv from Windows Kits ──
$kitDir  = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64'
$dbghelp = Join-Path $kitDir 'dbghelp.dll'
$symsrv  = Join-Path $kitDir 'symsrv.dll'
if ((Test-Path $dbghelp) -and (Test-Path $symsrv)) {
    Copy-Item -Path $dbghelp -Destination (Join-Path $InstallDir 'cgpt_dbghelp.dll') -Force
    Copy-Item -Path $symsrv  -Destination (Join-Path $InstallDir 'symsrv.dll')      -Force
    Write-Host "  Staged dbghelp + symsrv for PDB resolver"
} else {
    Write-Warning ("Windows Debugging Tools not at {0}" -f $kitDir)
    Write-Warning "Resolver will fail; payload will fall back to no-blob mode."
}

# ── ACL — permissive so dwm.exe (SYSTEM) can write payload.log/config.dat.
#    Prior "SYSTEM+Admin only" ACL blocked dwm's writes despite SYSTEM having
#    an explicit FullControl rule (unclear which OS layer intercepts).
#    Reverting to ProgramData default inherited perms (SYSTEM+Admin+Users
#    with SYSTEM+Admin full and Users read/execute).
$acl = Get-Acl $InstallDir
$acl.SetAccessRuleProtection($false, $true)   # allow inheritance + copy existing
Set-Acl -Path $InstallDir -AclObject $acl
Write-Host "  ACL: default ProgramData inherit (SYSTEM can write)"

Write-Host ""
Write-Host "Install complete."
Write-Host ""
Write-Host "Next:"
Write-Host "  Set env vars: SVCLDB_API_KEY, SVCLDB_PROVIDER, SVCLDB_MODEL"
Write-Host "  Then launch: Start-Process (Join-Path '$InstallDir' 'sihost.exe') -Verb RunAs"
