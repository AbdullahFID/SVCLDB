# ================================================================
# test_ocr_probe.ps1 - End-to-end probe for the OCR redactor daemon.
#
# What it does:
#   1. Spawns sihost.exe --ocr-daemon (dev-bypass build required -
#      skips the svchelper-parent verify gate).
#   2. Waits up to 5s for the named pipe to appear.
#   3. Renders a synthetic BGRA bitmap with text known to hit the
#      built-in default blacklist ("Respondus", "proctored", "12:34").
#   4. Sends the BGRA to the daemon via \\.\pipe\svcldb_ocr_v1.
#   5. Parses the response, verifies rect_count > 0.
#   6. Saves the original + redacted BGRA as .bmp files to the
#      scratchpad so a human can eyeball the black rects.
#   7. Sends the opcode-2 shutdown so the daemon exits cleanly.
#
# Requires: elevated PowerShell (sihost is admin-only) and a build
# of sihost.exe made with SVCLDB_DEV_AUTH=1.
# ================================================================

param(
  [string]$SihostPath = "$PSScriptRoot\..\build\launcher\sihost.exe",
  [string]$OutDir     = $(if ($env:CLAUDE_SCRATCHPAD) { $env:CLAUDE_SCRATCHPAD } else { "$env:TEMP\svcldb_ocr_probe" })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Header($msg) {
  Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}
function Write-OK($msg)   { Write-Host "[OK]   $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "[i]    $msg" -ForegroundColor Gray }

Write-Header "test_ocr_probe - svcldb OCR redactor E2E"

# ── Preflight ─────────────────────────────────────────────────
if (-not (Test-Path $SihostPath)) {
  Write-Fail "sihost.exe not found at $SihostPath"
  Write-Info "Build first: cd launcher && SVCLDB_DEV_AUTH=1 cmd /c build.bat"
  exit 2
}
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
Write-Info "sihost path : $SihostPath"
Write-Info "output dir  : $OutDir"

# Elevation check
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal       = New-Object Security.Principal.WindowsPrincipal $currentIdentity
$isAdmin         = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Fail "This probe must run elevated (sihost.exe refuses non-admin)."
  exit 3
}

# ── Render synthetic BGRA with blacklisted words ─────────────
Write-Header "Rendering synthetic BGRA (640x120, BGRA8)"

Add-Type -AssemblyName System.Drawing

$W = 640
$H = 120
$bmp    = New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g      = [System.Drawing.Graphics]::FromImage($bmp)
$g.Clear([System.Drawing.Color]::White)
$font   = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold)
$black  = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::Black)
# Text contains three default-blacklist hits:
#   "Respondus"  → words[]
#   "proctored"  → words[]
#   "12:34"      → NOT a default (timer regex not shipped in MVP defaults)
# We EXPECT at least 2 rects painted.
$text = "Respondus 12:34 proctored exam"
$g.DrawString($text, $font, $black, 20, 40)
$g.Dispose(); $font.Dispose(); $black.Dispose()

# Snapshot the original bmp for eyeball comparison
$origPath = Join-Path $OutDir "ocr_probe_original.bmp"
$bmp.Save($origPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
Write-OK "Wrote original: $origPath"

# Extract BGRA bytes from the bmp
$rect = New-Object System.Drawing.Rectangle 0, 0, $W, $H
$data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
                      [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$stride = [Math]::Abs($data.Stride)
$byteLen = $stride * $H
$bgra = New-Object byte[] $byteLen
[System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bgra, 0, $byteLen)
$bmp.UnlockBits($data)

# ARGB LockBits gives us BGRA on Windows (little-endian). If stride > W*4,
# we need to pack. In practice for 32bpp GDI+ = W*4 exact, but be safe.
if ($stride -ne ($W * 4)) {
  $packed = New-Object byte[] ($W * $H * 4)
  for ($y = 0; $y -lt $H; $y++) {
    [Array]::Copy($bgra, $y * $stride, $packed, $y * $W * 4, $W * 4)
  }
  $bgra = $packed
  $byteLen = $bgra.Length
}
Write-OK "Extracted $byteLen bytes of BGRA (stride was $stride)"

# ── Spawn daemon ──────────────────────────────────────────────
Write-Header "Spawning sihost.exe --ocr-daemon"
$si = Start-Process -FilePath $SihostPath -ArgumentList "--ocr-daemon" `
                    -PassThru -WindowStyle Hidden
Write-Info "daemon pid=$($si.Id)"

# ── Wait for pipe ─────────────────────────────────────────────
Write-Info "Waiting for \\.\pipe\svcldb_ocr_v1..."
$pipeReady = $false
for ($i = 0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 100
  $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') 2>$null
  if ($pipes -and ($pipes -contains '\\.\pipe\svcldb_ocr_v1')) {
    $pipeReady = $true; break
  }
}
if (-not $pipeReady) {
  Write-Fail "pipe never appeared within 5s"
  Write-Info "check C:\ProgramData\WinAudioSvc\launcher.log for --ocr-daemon errors"
  try { $si.Kill() } catch {}
  exit 4
}
Write-OK "pipe is listening"

# ── Send request ──────────────────────────────────────────────
Write-Header "Sending scan+paint request ($W x $H, $byteLen bytes)"
$OCR_WIRE_MAGIC = 0x4F435231  # 'OCR1'
$client = New-Object System.IO.Pipes.NamedPipeClientStream `
             '.', 'svcldb_ocr_v1',
             ([System.IO.Pipes.PipeDirection]::InOut)
$client.Connect(2000)   # 2s open timeout

# Header: 5 x uint32 LE = 20 bytes
$hdr = New-Object byte[] 20
[BitConverter]::GetBytes([uint32]$OCR_WIRE_MAGIC).CopyTo($hdr, 0)
[BitConverter]::GetBytes([uint32]1).CopyTo($hdr, 4)          # opcode = scan+paint
[BitConverter]::GetBytes([uint32]$W).CopyTo($hdr, 8)
[BitConverter]::GetBytes([uint32]$H).CopyTo($hdr, 12)
[BitConverter]::GetBytes([uint32]$byteLen).CopyTo($hdr, 16)

$t0 = Get-Date
$client.Write($hdr, 0, $hdr.Length)
$client.Write($bgra, 0, $bgra.Length)
$client.Flush()

# Response header: 4 x (u32, i32, u32, u32) = 16 bytes
$respHdr = New-Object byte[] 16
$got = 0
while ($got -lt 16) {
  $chunk = $client.Read($respHdr, $got, 16 - $got)
  if ($chunk -le 0) { break }
  $got += $chunk
}
$dt = ((Get-Date) - $t0).TotalMilliseconds
if ($got -ne 16) {
  Write-Fail "short response header ($got bytes)"
  $client.Dispose(); try { $si.Kill() } catch {}
  exit 5
}
$respMagic  = [BitConverter]::ToUInt32($respHdr, 0)
$respStatus = [BitConverter]::ToInt32($respHdr, 4)
$respLen    = [BitConverter]::ToUInt32($respHdr, 8)
$respRects  = [BitConverter]::ToUInt32($respHdr, 12)
Write-Info ("resp magic=0x{0:X}  status={1}  byte_len={2}  rects={3}  rtt={4:N0}ms" `
              -f $respMagic, $respStatus, $respLen, $respRects, $dt)

if ($respMagic -ne $OCR_WIRE_MAGIC) {
  Write-Fail "bad response magic"
  $client.Dispose(); try { $si.Kill() } catch {}
  exit 6
}
if ($respStatus -ne 0) {
  Write-Fail "daemon returned status=$respStatus (see launcher.log)"
  $client.Dispose(); try { $si.Kill() } catch {}
  exit 7
}

# Read the redacted BGRA
$redacted = New-Object byte[] $respLen
$got = 0
while ($got -lt $respLen) {
  $chunk = $client.Read($redacted, $got, $respLen - $got)
  if ($chunk -le 0) { break }
  $got += $chunk
}
if ($got -ne $respLen) {
  Write-Fail "short BGRA body ($got of $respLen bytes)"
  $client.Dispose(); try { $si.Kill() } catch {}
  exit 8
}
$client.Dispose()

# ── Verify redaction ──────────────────────────────────────────
Write-Header "Verifying redaction"
if ($respRects -lt 1) {
  Write-Fail "no rects painted - did OCR fail to recognize the text? " +
             "check that Language.OCR~~~en-US FoD is installed"
} else {
  Write-OK "daemon painted $respRects rect(s)"
}

# Count how many pixels are pure black (0,0,0,255) vs the original.
$origBlacks = 0
$redBlacks  = 0
for ($i = 0; $i -lt $bgra.Length; $i += 4) {
  if ($bgra[$i]     -eq 0 -and $bgra[$i+1] -eq 0 -and
      $bgra[$i+2]   -eq 0 -and $bgra[$i+3] -eq 255) { $origBlacks++ }
  if ($redacted[$i] -eq 0 -and $redacted[$i+1] -eq 0 -and
      $redacted[$i+2] -eq 0 -and $redacted[$i+3] -eq 255) { $redBlacks++ }
}
$delta = $redBlacks - $origBlacks
Write-Info ("black pixels: original={0}  redacted={1}  delta={2}" `
             -f $origBlacks, $redBlacks, $delta)
if ($delta -lt 500) {
  Write-Fail "black-pixel delta only $delta - expected >500 for a real redaction"
} else {
  Write-OK "black-pixel delta = $delta (blackout applied)"
}

# ── Save the redacted BGRA as BMP for eyeball ────────────────
$redBmp = New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$data2  = $redBmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly,
                            [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
[System.Runtime.InteropServices.Marshal]::Copy($redacted, 0, $data2.Scan0, $redacted.Length)
$redBmp.UnlockBits($data2)
$redPath = Join-Path $OutDir "ocr_probe_redacted.bmp"
$redBmp.Save($redPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
$redBmp.Dispose(); $bmp.Dispose()
Write-OK "Wrote redacted: $redPath"

# ── Cooperative shutdown ──────────────────────────────────────
Write-Header "Sending opcode-2 shutdown"
try {
  $c2 = New-Object System.IO.Pipes.NamedPipeClientStream `
           '.', 'svcldb_ocr_v1', ([System.IO.Pipes.PipeDirection]::InOut)
  $c2.Connect(1000)
  $shut = New-Object byte[] 20
  [BitConverter]::GetBytes([uint32]$OCR_WIRE_MAGIC).CopyTo($shut, 0)
  [BitConverter]::GetBytes([uint32]2).CopyTo($shut, 4)      # opcode = shutdown
  $c2.Write($shut, 0, 20)
  $c2.Flush()
  # Read the tiny ack + close
  $ack = New-Object byte[] 16
  $c2.Read($ack, 0, 16) | Out-Null
  $c2.Dispose()
  Write-OK "shutdown message sent"
} catch {
  Write-Info "shutdown send failed ($($_.Exception.Message)) - falling back to kill"
  try { $si.Kill() } catch {}
}
# Give the daemon 2s to exit
$exited = $si.WaitForExit(2000)
if (-not $exited) {
  Write-Info "daemon didn't exit in 2s - killing"
  try { $si.Kill() } catch {}
} else {
  Write-OK "daemon exited (code=$($si.ExitCode))"
}

Write-Header "Probe complete"
Write-Host "Compare visually:" -ForegroundColor Yellow
Write-Host "  Original : $origPath"
Write-Host "  Redacted : $redPath"
