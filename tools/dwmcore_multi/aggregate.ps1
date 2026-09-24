# Parses every _probe_out/*.txt and produces a compatibility matrix
# (Markdown + JSON) covering every downloaded dwmcore.dll sample.
param(
    [string]$ProbeOutDir = "$PSScriptRoot\_probe_out",
    [string]$MdPath      = "$PSScriptRoot\compat_matrix.md",
    [string]$JsonPath    = "$PSScriptRoot\compat_matrix.json"
)

$ErrorActionPreference = 'Continue'

# v2 probe emits one line per "logical" symbol using friendly labels.
# These MUST match the `label` field in probe.c's g_syms[] array.
$SYM_PRESENT   = 'COverlayContext::Present'
$SYM_IOP       = 'CGlobalCompositionSurfaceInfo::IsOverlayPrevented'
$SYM_FFD       = 'CCommonRegistryData::ForceFullDirtyRendering'
$SYM_PN1       = 'CDDisplayRenderTarget::PresentNeeded'
$SYM_PN2       = 'CLegacyRenderTarget::PresentNeeded'
$SYM_SCP       = 'ScheduleCompositionPass'
$SYM_GPB       = 'GetPhysicalBackBuffer'
$SYM_GD3D      = 'GetD3D11Resource'
$SYM_ACC       = 'Accessor (GetTexture2D)'

function Classify-IopShape {
    param([string]$hexBytes)
    if (-not $hexBytes) { return 'unknown' }
    $b = $hexBytes -split '\s+' | Where-Object { $_ }
    if ($b.Count -lt 4) { return 'unknown' }
    if     ($b[0] -eq 'FF' -and $b[1] -eq '15') { return 'NEW-CFG-CALL' }
    elseif ($b[0] -eq 'F3' -and $b[1] -eq '0F' -and $b[2] -eq '1E' -and $b[3] -eq 'FA') { return 'CET-ENDBR64' }
    elseif ($b[0] -eq '8A' -or $b[0] -eq '0F' -or $b[0] -eq '8B') { return 'OLD-GETTER' }
    return "unknown ($($b[0..3] -join ' '))"
}

function Classify-PresentPrologue {
    param([string]$hexBytes)
    if (-not $hexBytes) { return 'unknown' }
    $b = $hexBytes -split '\s+' | Where-Object { $_ }
    if ($b.Count -lt 5) { return 'unknown' }
    # Known-good prologues MinHook can safely detour (must be >= 5 bytes
    # of relocatable instructions before any branch/call).
    if ($b[0] -eq 'F3' -and $b[1] -eq '0F' -and $b[2] -eq '1E' -and $b[3] -eq 'FA') { return 'CET-ENDBR64+prologue' }
    if ($b[0] -eq '40' -and $b[1] -eq '55')                                          { return 'REX push rbp (large fn)' }
    if ($b[0] -eq '40' -and $b[1] -eq '53')                                          { return 'REX push rbx (medium fn)' }
    if ($b[0] -eq '48' -and $b[1] -eq '89' -and $b[2] -eq '5C' -and $b[3] -eq '24')  { return 'mov [rsp+X],rbx' }
    if ($b[0] -eq '4C' -and $b[1] -eq '89')                                          { return 'mov [rsp+X],r*' }
    if ($b[0] -eq '4C' -and $b[1] -eq '8B' -and $b[2] -eq 'DC')                      { return 'mov r11,rsp (frame stub)' }
    if ($b[0] -eq 'FF' -and $b[1] -eq '15')                                          { return 'call [rip+X] (CFG-first)' }
    return "unknown ($($b[0..4] -join ' '))"
}

function Parse-ProbeFile {
    param([string]$path)
    $lines = Get-Content $path
    $syms = @{}
    foreach ($line in $lines) {
        # New v2 format:
        #   build=<ver> tds=<tds> sym=dwmcore!<label> rva=<val> [via=<v> matched=<pat>] [section=<sec>] [b32=<hex bytes>]
        # <label> can have spaces + parens (e.g., "Accessor (GetTexture2D)").
        # We capture up to " rva=".
        if ($line -match 'build=(?<v>\S+)\s+tds=(?<tds>\S+)\s+sym=dwmcore!(?<sym>.+?)\s+rva=(?<rva>MISS|0x[0-9A-Fa-f]+)') {
            $rec = @{
                version = $Matches['v']
                tds     = $Matches['tds']
                sym     = $Matches['sym'].Trim()
                rva     = $Matches['rva']
                bytes   = $null
                via     = $null
                matched = $null
            }
            if ($line -match ' via=(?<via>\S+)')      { $rec.via = $Matches['via'] }
            if ($line -match ' matched=(?<m>\S+)')    { $rec.matched = $Matches['m'] }
            if ($line -match 'b32=(?<b>(?:[0-9A-Fa-f]{2} )+[0-9A-Fa-f]{2})') {
                $rec.bytes = $Matches['b'].Trim()
            }
            $syms[$rec.sym] = $rec
        }
    }
    return $syms
}

$files = Get-ChildItem $ProbeOutDir -Filter '*.txt' | Sort-Object Name
Write-Host "aggregating $($files.Count) probe outputs`n"

$rows = New-Object System.Collections.ArrayList

foreach ($f in $files) {
    $syms = Parse-ProbeFile -path $f.FullName

    # Extract build metadata from filename: <winTag>_<version>.txt
    $tag = $f.BaseName -replace '_.*$', ''
    $ver = ($f.BaseName -replace '^[^_]+_', '')
    $tds = if ($syms.Count -gt 0) { ($syms.Values | Select-Object -First 1).tds } else { '?' }

    # Look up a symbol; returns $null if missing or MISS.
    function Get-Sym {
        param($map, [string]$name)
        if (-not $map.ContainsKey($name)) { return $null }
        $r = $map[$name]
        if ($r.rva -eq 'MISS') { return $null }
        return $r
    }
    function Get-AnySym {
        param($map, [string[]]$names)
        foreach ($n in $names) {
            $r = Get-Sym -map $map -name $n
            if ($r) { return $r }
        }
        return $null
    }

    $present = Get-Sym -map $syms -name $SYM_PRESENT
    $iop     = Get-Sym -map $syms -name $SYM_IOP
    $pn1     = Get-Sym -map $syms -name $SYM_PN1
    $pn2     = Get-Sym -map $syms -name $SYM_PN2
    $scp     = Get-Sym -map $syms -name $SYM_SCP
    $ffd     = Get-Sym -map $syms -name $SYM_FFD
    $gpb     = Get-Sym -map $syms -name $SYM_GPB
    $gd3d    = Get-Sym -map $syms -name $SYM_GD3D
    $acc     = Get-Sym -map $syms -name $SYM_ACC

    $iopShape = if ($iop)     { Classify-IopShape       $iop.bytes }     else { 'MISS' }
    $preShape = if ($present) { Classify-PresentPrologue $present.bytes } else { 'MISS' }

    # Verdict: matches payload's validation logic exactly.
    $recognized_iop = $iopShape -in @('OLD-GETTER','NEW-CFG-CALL','CET-ENDBR64')
    $recognized_pre = ($preShape -notmatch '^unknown') -and ($preShape -ne 'MISS')

    $verdict = ''
    if (-not $present -or -not $iop) {
        $verdict = 'SAFE-MODE (critical MISS)'
    } elseif (-not $recognized_iop) {
        $verdict = 'SAFE-MODE (IOP shape unknown)'
    } elseif (-not $recognized_pre) {
        $verdict = 'SAFE-MODE (Present prologue unknown)'
    } elseif (-not $pn1 -and -not $pn2) {
        $verdict = 'DEGRADED (no PN wake path)'
    } elseif ((-not $gpb) -or (-not $gd3d) -or (-not $acc)) {
        $verdict = 'DEGRADED (no backbuffer chain)'
    } elseif (-not $pn1 -or -not $pn2 -or -not $scp) {
        $verdict = 'DEGRADED (wake partial)'
    } else {
        $verdict = 'FULL SUPPORT'
    }

    [void]$rows.Add([pscustomobject]@{
        winTag    = $tag
        version   = $ver
        tds       = $tds
        Present   = if ($present) { $present.rva } else { 'MISS' }
        PreShape  = $preShape
        IOP       = if ($iop) { $iop.rva } else { 'MISS' }
        IopShape  = $iopShape
        PN1       = if ($pn1) { $pn1.rva } else { 'MISS' }
        PN2       = if ($pn2) { $pn2.rva } else { 'MISS' }
        SCP       = if ($scp) { $scp.rva } else { 'MISS' }
        FFD       = if ($ffd) { $ffd.rva } else { 'MISS' }
        GPB       = if ($gpb) { $gpb.rva } else { 'MISS' }
        GD3D      = if ($gd3d) { $gd3d.rva } else { 'MISS' }
        ACC       = if ($acc) { $acc.rva } else { 'MISS' }
        Verdict   = $verdict
    })
}

$rows = $rows | Sort-Object winTag, version

# --- Emit markdown (using Out-File to preserve newlines cleanly) ---
$mdLines = @()
$mdLines += '# dwmcore.dll multi-build compatibility matrix'
$mdLines += ''
$mdLines += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
$mdLines += "Samples:   $($rows.Count)"
$mdLines += "Tool:      ``tools/dwmcore_multi/`` (pick + download + probe + aggregate)"
$mdLines += ''
$mdLines += '| WinTag  | Version         | TDS         | Present   | Prologue                | IOP       | Shape       | PN1       | PN2       | SCP       | FFD       | GPB       | GD3D      | ACC       | Verdict |'
$mdLines += '|---------|-----------------|-------------|-----------|-------------------------|-----------|-------------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|---------|'
foreach ($r in $rows) {
    $mdLines += "| $($r.winTag) | $($r.version) | $($r.tds) | $($r.Present) | $($r.PreShape) | $($r.IOP) | $($r.IopShape) | $($r.PN1) | $($r.PN2) | $($r.SCP) | $($r.FFD) | $($r.GPB) | $($r.GD3D) | $($r.ACC) | $($r.Verdict) |"
}
$mdLines += ''
$mdLines += '## Verdict summary'
$mdLines += ''
$rows | Group-Object Verdict | Sort-Object Count -Descending | ForEach-Object {
    $mdLines += "- **$($_.Name)** &mdash; $($_.Count) build(s)"
}
$mdLines += ''
$mdLines += '## IsOverlayPrevented prologue distribution'
$mdLines += ''
$rows | Group-Object IopShape | Sort-Object Count -Descending | ForEach-Object {
    $mdLines += "- **$($_.Name)** &mdash; $($_.Count) build(s)"
}
$mdLines += ''
$mdLines += '## Present prologue distribution'
$mdLines += ''
$rows | Group-Object PreShape | Sort-Object Count -Descending | ForEach-Object {
    $mdLines += "- **$($_.Name)** &mdash; $($_.Count) build(s)"
}

$mdLines | Out-File -FilePath $MdPath -Encoding utf8
$rows | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonPath -Encoding utf8

Write-Host "wrote $MdPath"
Write-Host "wrote $JsonPath"
Write-Host ""
Write-Host "=== VERDICT SUMMARY ==="
$rows | Group-Object Verdict | Sort-Object Count -Descending | ForEach-Object {
    "  {0,-45} {1,3}" -f $_.Name, $_.Count | Write-Host
}
Write-Host ""
Write-Host "=== IOP prologue shapes ==="
$rows | Group-Object IopShape | Sort-Object Count -Descending | ForEach-Object {
    "  {0,-30} {1,3}" -f $_.Name, $_.Count | Write-Host
}
Write-Host ""
Write-Host "=== Present prologue shapes ==="
$rows | Group-Object PreShape | Sort-Object Count -Descending | ForEach-Object {
    "  {0,-35} {1,3}" -f $_.Name, $_.Count | Write-Host
}
