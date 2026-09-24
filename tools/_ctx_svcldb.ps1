$bytes = [System.IO.File]::ReadAllBytes('C:\ProgramData\WinAudioSvc\sihost.exe')
$text = [System.Text.Encoding]::ASCII.GetString($bytes)
$m = [regex]::Matches($text, 'svcldb')
Write-Host "total svcldb ASCII hits: $($m.Count)"
foreach ($h in $m) {
    $s = [Math]::Max(0, $h.Index - 35)
    $e = [Math]::Min($text.Length, $h.Index + 45)
    $snip = $text.Substring($s, $e - $s) -replace '[\x00-\x1F\x7F-\xFF]', '.'
    Write-Host "  [$($h.Index)] $snip"
}

Write-Host ""
Write-Host "--- also checking .log filenames ---"
foreach ($fn in @('payload.log', 'launcher.log', 'resolver.log', 'wl_input.log', 'http.log', 'ai.log')) {
    $mm = [regex]::Matches($text, [regex]::Escape($fn))
    Write-Host "  $fn : $($mm.Count) hits"
}

# Also do dwmapiext
$dw = [regex]::Matches($text, 'dwmapiext')
foreach ($h in $dw) {
    $s = [Math]::Max(0, $h.Index - 40)
    $e = [Math]::Min($text.Length, $h.Index + 40)
    $snip = $text.Substring($s, $e - $s) -replace '[\x00-\x1F\x7F-\xFF]', '.'
    Write-Host ""
    Write-Host "dwmapiext [$($h.Index)]: $snip"
}
