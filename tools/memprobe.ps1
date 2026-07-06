#Requires -Version 7
# Enumerate DWM's committed memory and count MEM_PRIVATE executable regions
# by their protection flag. Verifies our RWX-downgrade + shellcode-cleanup.
param(
    [string]$ProcessName = "dwm"
)

Add-Type -Namespace WinApi -Name MemProbe -MemberDefinition @'
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern System.IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(System.IntPtr h);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(System.IntPtr h, System.IntPtr addr,
        out MEMORY_BASIC_INFORMATION mbi, uint len);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public System.IntPtr BaseAddress;
        public System.IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public ushort Reserved;
        public System.UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
'@

# PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
$PROCESS_QUERY_INFO = 0x0400
$PROCESS_VM_READ    = 0x0010
$access = $PROCESS_QUERY_INFO -bor $PROCESS_VM_READ

$dwm = Get-Process -Name $ProcessName -EA 0 | Select-Object -First 1
if (-not $dwm) { Write-Error "$ProcessName not running"; exit 1 }
Write-Host "Probing pid=$($dwm.Id) ($ProcessName)"

$h = [WinApi.MemProbe]::OpenProcess($access, $false, [uint32]$dwm.Id)
if ($h -eq [System.IntPtr]::Zero) {
    Write-Error "OpenProcess failed. Are you elevated? GLE=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    exit 1
}

$MEM_COMMIT   = 0x1000
$MEM_IMAGE    = 0x1000000
$MEM_MAPPED   = 0x40000
$MEM_PRIVATE  = 0x20000

# Protection classes we care about
$PAGE_EXECUTE           = 0x10
$PAGE_EXECUTE_READ      = 0x20
$PAGE_EXECUTE_READWRITE = 0x40
$PAGE_EXECUTE_WRITECOPY = 0x80
$PAGE_READONLY          = 0x02
$PAGE_READWRITE         = 0x04
$PAGE_WRITECOPY         = 0x08

$EXEC_MASK = $PAGE_EXECUTE -bor $PAGE_EXECUTE_READ -bor $PAGE_EXECUTE_READWRITE -bor $PAGE_EXECUTE_WRITECOPY

$mbi = New-Object WinApi.MemProbe+MEMORY_BASIC_INFORMATION
$addr = [System.IntPtr]::Zero
$scanned = 0

$stats = @{
    PrivateExecRegions = 0
    PrivateRWXRegions  = 0
    PrivateRXRegions   = 0
    PrivateROBigRegs   = 0
    PrivateRWBigRegs   = 0
    TotalCommittedMB   = 0
    PrivateCommittedMB = 0
    ImageMB            = 0
    MappedMB           = 0
}

$suspicious = @()

while ([WinApi.MemProbe]::VirtualQueryEx($h, $addr, [ref]$mbi, [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($mbi))) {
    $scanned++
    $sz = [uint64]$mbi.RegionSize
    if ($mbi.State -eq $MEM_COMMIT) {
        $stats.TotalCommittedMB += ($sz / 1MB)
        if     ($mbi.Type -eq $MEM_IMAGE)   { $stats.ImageMB   += ($sz / 1MB) }
        elseif ($mbi.Type -eq $MEM_MAPPED)  { $stats.MappedMB  += ($sz / 1MB) }
        elseif ($mbi.Type -eq $MEM_PRIVATE) {
            $stats.PrivateCommittedMB += ($sz / 1MB)
            if ($mbi.Protect -band $EXEC_MASK) {
                $stats.PrivateExecRegions++
                if ($mbi.Protect -eq $PAGE_EXECUTE_READWRITE) { $stats.PrivateRWXRegions++ }
                if ($mbi.Protect -eq $PAGE_EXECUTE_READ)      { $stats.PrivateRXRegions++ }

                # Regions ≥ 100 KB are candidates for our injected payload
                if ($sz -ge (100 * 1024)) {
                    $suspicious += [PSCustomObject]@{
                        Base       = ("0x{0:X}" -f [uint64]$mbi.BaseAddress.ToInt64())
                        AllocBase  = ("0x{0:X}" -f [uint64]$mbi.AllocationBase.ToInt64())
                        SizeKB     = [math]::Round($sz / 1KB)
                        Protect    = ("0x{0:X}" -f $mbi.Protect)
                        ProtectStr = switch ($mbi.Protect) {
                            $PAGE_EXECUTE_READWRITE { "RWX" }
                            $PAGE_EXECUTE_READ      { "RX" }
                            $PAGE_EXECUTE           { "X" }
                            $PAGE_EXECUTE_WRITECOPY { "WCX" }
                            default                 { "0x$($mbi.Protect.ToString('X'))" }
                        }
                    }
                }
            } elseif ($mbi.Protect -eq $PAGE_READONLY -and $sz -ge (100 * 1024)) {
                $stats.PrivateROBigRegs++
            } elseif ($mbi.Protect -eq $PAGE_READWRITE -and $sz -ge (100 * 1024)) {
                $stats.PrivateRWBigRegs++
            }
        }
    }
    $next = [System.IntPtr]([uint64]$mbi.BaseAddress.ToInt64() + $sz)
    if ($next -le $addr) { break }  # overflow guard
    $addr = $next
}

[WinApi.MemProbe]::CloseHandle($h) | Out-Null

Write-Host ""
Write-Host "=== Memory scan summary (dwm.exe pid=$($dwm.Id)) ==="
Write-Host ("Regions scanned: {0}" -f $scanned)
Write-Host ("Committed total:      {0,10:N1} MB" -f $stats.TotalCommittedMB)
Write-Host ("  Image (MEM_IMAGE):  {0,10:N1} MB" -f $stats.ImageMB)
Write-Host ("  Mapped (MEM_MAPPED):{0,10:N1} MB" -f $stats.MappedMB)
Write-Host ("  Private (MEM_PRIV): {0,10:N1} MB" -f $stats.PrivateCommittedMB)
Write-Host ""
Write-Host "=== Private+Executable region counts (the fingerprint) ==="
Write-Host ("  ALL exec private: {0}" -f $stats.PrivateExecRegions)
Write-Host ("  RWX  (biggest IOC): {0}" -f $stats.PrivateRWXRegions)
Write-Host ("  RX   (post-downgrade): {0}" -f $stats.PrivateRXRegions)
Write-Host ""
Write-Host "=== Suspicious private-exec regions >= 100 KB ==="
if ($suspicious.Count -eq 0) {
    Write-Host "  (none)"
} else {
    $suspicious | Sort-Object SizeKB -Descending | Format-Table -AutoSize
}
