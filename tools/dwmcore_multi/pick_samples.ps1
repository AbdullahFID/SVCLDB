# Reads the winbindex dwmcore.dll JSON and picks a diverse sample set
# covering Win11 21H2/22H2/23H2/24H2/25H2 (+ a couple Win10 for reach).
# Emits `samples.json` listing each pick's SHA-256, TDS hex, vsize hex,
# version, and the winbindex-observed Windows tag.
param(
    [string]$WinbindexJson = "$env:TEMP\dwmcore_winbindex.json",
    [string]$OutJson = "$PSScriptRoot\samples.json"
)

$ErrorActionPreference = 'Stop'

$data = Get-Content $WinbindexJson -Raw | ConvertFrom-Json

# Flatten into a list of { sha, ver, tds, vsize, arch, sign, winTag, kb, releaseDate }.
$rows = New-Object System.Collections.ArrayList
foreach ($p in $data.PSObject.Properties) {
    $sha = $p.Name
    $fi = $p.Value.fileInfo
    if (-not $fi) { continue }
    if ($fi.machineType -ne 34404) { continue }   # AMD64 only for now
    # NOTE: not filtering on signingStatus -- winbindex reports many
    # legit binaries as 'Unsigned' when its own sig validator can't
    # follow the WU cert chain. All msdl.microsoft.com-hosted binaries
    # are legit MS binaries regardless of what winbindex says.
    $ver = $fi.version
    if (-not $ver) { continue }

    # Extract every (winTag, KB, releaseVersion, releaseDate) tuple this
    # binary appears in. Each becomes a separate row so we can pick
    # per-branch.
    $wvs = $p.Value.windowsVersions
    if (-not $wvs) { continue }
    foreach ($wp in $wvs.PSObject.Properties) {
        $winTag = $wp.Name
        foreach ($kbp in $wp.Value.PSObject.Properties) {
            $ui = $kbp.Value.updateInfo
            [void]$rows.Add([pscustomobject]@{
                sha256      = $sha
                version     = $ver
                tdsHex      = ('{0:X8}' -f [uint32]$fi.timestamp)
                vsizeHex    = ('{0:X}'   -f [uint32]$fi.virtualSize)
                size        = $fi.size
                virtualSize = $fi.virtualSize
                arch        = 'amd64'
                winTag      = $winTag
                kb          = $kbp.Name
                relVer      = $ui.releaseVersion
                relDate     = $ui.releaseDate
            })
        }
    }
}

Write-Host "candidate rows (amd64 signed x Windows-tag): $($rows.Count)"

# Group by winTag; within each pick a spread of builds by releaseDate.
$targetTags = @(
    # Windows 11 (build 22000+ / 26100+)
    '11-21H2', '11-22H2', '11-23H2', '11-24H2', '11-25H2', '11-26H1',
    # Windows 10 (build 19041.x) -- reach test
    '22H2', '21H2', '20H2'
)
$picks = New-Object System.Collections.ArrayList

foreach ($tag in $targetTags) {
    # Get all rows for this Windows tag, then dedupe by version
    # (multiple KBs can share a version).
    $bucket = @($rows | Where-Object { $_.winTag -eq $tag } |
                Group-Object version |
                ForEach-Object { $_.Group | Select-Object -First 1 } |
                Sort-Object relDate)

    if ($bucket.Count -eq 0) {
        Write-Host "  [$tag] no rows"
        continue
    }
    # Pick 3 samples: first, middle, latest.
    $n = $bucket.Count
    $idxs = @(0)
    if ($n -ge 3) { $idxs += [int]($n / 2) }
    if ($n -ge 2) { $idxs += ($n - 1) }
    $idxs = @($idxs | Sort-Object -Unique)

    Write-Host "  [$tag] $n unique versions -- picking indices $($idxs -join ',')"
    foreach ($i in $idxs) {
        [void]$picks.Add($bucket[$i])
    }
}

# Dedupe by sha256 (some tags share binaries).
$uniquePicks = $picks | Sort-Object sha256 -Unique

Write-Host "`nfinal picks: $($uniquePicks.Count)"
foreach ($p in $uniquePicks) {
    "  $($p.winTag) $($p.relVer)  ver=$($p.version)  tds=0x$($p.tdsHex)  vsize=0x$($p.vsizeHex)  $($p.relDate)" | Write-Host
}

$uniquePicks | ConvertTo-Json -Depth 4 | Set-Content $OutJson -Encoding UTF8
Write-Host "`nsaved to $OutJson"
