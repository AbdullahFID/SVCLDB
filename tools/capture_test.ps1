#Requires -Version 5
# Capture the primary screen via System.Drawing.Bitmap.CopyFromScreen.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$bounds  = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
Write-Host "Primary bounds: $($bounds.Width)x$($bounds.Height)"
$bmp     = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$gfx     = [System.Drawing.Graphics]::FromImage($bmp)

Write-Host "Capturing screen 5 times (~250ms apart) via CopyFromScreen..."
for ($i = 1; $i -le 5; $i++) {
    $gfx.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    Start-Sleep -Milliseconds 250
    Write-Host "  capture #$i done"
}
$gfx.Dispose()

$outPath = "$env:TEMP\svcldb_captest.png"
$bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()

$size = (Get-Item $outPath).Length
Write-Host ""
Write-Host "Capture saved: $outPath ($size bytes)"
