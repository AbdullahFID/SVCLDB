$bytes = [System.IO.File]::ReadAllBytes('C:\ProgramData\WinAudioSvc\sihost.exe')
$text  = [System.Text.Encoding]::ASCII.GetString($bytes)
$patterns = 'CloakGPT|cloakgpt|svcldb|dwmapiext|SysCompositorSink|NetSvcCoord|HANDSHAKE SKIPPED'
$m = [regex]::Matches($text, $patterns)
$m | Group-Object Value | Sort-Object Count -Descending | Format-Table Count, Name -AutoSize
Write-Host ''
Write-Host '=== context snippets (up to 3 hits per pattern) ==='
foreach ($v in ($m | Group-Object Value)) {
    Write-Host ''
    Write-Host "--- $($v.Name) ---"
    $v.Group | Select-Object -First 3 | ForEach-Object {
        $s = [Math]::Max(0, $_.Index - 30)
        $e = [Math]::Min($text.Length, $_.Index + $_.Length + 30)
        $snip = $text.Substring($s, $e - $s) -replace '[\x00-\x1F\x7F-\xFF]', '.'
        Write-Host "  [$($_.Index)] '$snip'"
    }
}

# Also do UTF-16 pass
$textU = [System.Text.Encoding]::Unicode.GetString($bytes)
$mU = [regex]::Matches($textU, $patterns)
Write-Host ''
Write-Host '=== UTF-16 hits ==='
$mU | Group-Object Value | Format-Table Count, Name -AutoSize
foreach ($v in ($mU | Group-Object Value)) {
    Write-Host ""
    Write-Host "--- UTF-16 $($v.Name) ---"
    $v.Group | Select-Object -First 3 | ForEach-Object {
        $s = [Math]::Max(0, $_.Index - 40)
        $e = [Math]::Min($textU.Length, $_.Index + $_.Length + 40)
        $snip = $textU.Substring($s, $e - $s) -replace '[\x00-\x1F\x7F-\xFF]', '.'
        Write-Host "  [$($_.Index)] '$snip'"
    }
}
