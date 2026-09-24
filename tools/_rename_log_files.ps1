# Rename svc-fingerprint .log filenames to innocuous .dat names in
# all C/C++/H source files. Attacker greps sihost.exe for "payload.log"
# now returns 0 hits.
#
# Renames:
#   payload.log  -> msvc_dbg_a.dat
#   launcher.log -> msvc_dbg_b.dat
#   http.log     -> msvc_dbg_c.dat
#   ai.log       -> msvc_dbg_d.dat
#   wl_input.log -> msvc_dbg_e.dat
#   resolver.log -> msvc_dbg_f.dat
#   auth.log     -> msvc_dbg_g.dat
#
# Also renames the debug_capture dcaux-{d|g}-*.png/bmp prefix so the
# "dcaux-" literal doesn't fingerprint us in dwmapiext.dll strings:
#   dcaux-d-     -> dbgcap_    (path stays under our install dir)
#   dcaux-g-     -> dbgcap_g_
#
# Match strategy: bracket-quoted literal only. `"payload.log"` matches;
# `payload.log` (unquoted, e.g. in comments) does not.
#
# Files touched: source under launcher/, payload/, shared/, tools/redteam/probes/wl_input.c

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\abdul\Desktop\svcldb'

$renames = @{
    '"payload.log"'  = '"msvc_dbg_a.dat"'
    '"launcher.log"' = '"msvc_dbg_b.dat"'
    '"http.log"'     = '"msvc_dbg_c.dat"'
    '"ai.log"'       = '"msvc_dbg_d.dat"'
    '"wl_input.log"' = '"msvc_dbg_e.dat"'
    '"resolver.log"' = '"msvc_dbg_f.dat"'
    '"auth.log"'     = '"msvc_dbg_g.dat"'
    '"dcaux-d-'      = '"dbgcap_d_'
    '"dcaux-g-'      = '"dbgcap_g_'
}

$patterns = @('*.c', '*.cpp', '*.h', '*.hpp')
$roots = @(
    (Join-Path $root 'launcher\src'),
    (Join-Path $root 'payload\src'),
    (Join-Path $root 'shared'),
    (Join-Path $root 'tools\redteam\probes')
)

$totalHits = 0
$fileHits = 0
foreach ($r in $roots) {
    foreach ($p in $patterns) {
        Get-ChildItem -Path $r -Recurse -Filter $p -EA SilentlyContinue | ForEach-Object {
            $f = $_.FullName
            $content = [System.IO.File]::ReadAllText($f)
            $orig = $content
            $localHits = 0
            foreach ($k in $renames.Keys) {
                if ($content.Contains($k)) {
                    $c = ([regex]::Matches($content, [regex]::Escape($k))).Count
                    $content = $content.Replace($k, $renames[$k])
                    $localHits += $c
                }
            }
            if ($content -ne $orig) {
                [System.IO.File]::WriteAllText($f, $content)
                $totalHits += $localHits
                $fileHits++
                Write-Host ("  [{0} hits] {1}" -f $localHits, ($f -replace [regex]::Escape($root), '.'))
            }
        }
    }
}
Write-Host ""
Write-Host "Rename complete: $totalHits literal occurrences in $fileHits files"
