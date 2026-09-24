param([string[]]$Paths = @(
    'C:\Windows\System32\dwmcore.dll',
    'C:\Users\abdul\Desktop\hooksdll\dwm\dwmcore_clean.dll'
))

# Parse a PE file's debug directory entry -> extract the CV_INFO_PDB70 record.
foreach ($p in $Paths) {
    if (-not (Test-Path $p)) { "MISSING: $p"; continue }
    $bytes = [IO.File]::ReadAllBytes($p)
    $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
    # OptionalHeader offset:
    #   e_lfanew + 4 (PE\0\0) + 20 (IMAGE_FILE_HEADER) = start of OptionalHeader
    $opt = $e_lfanew + 4 + 20
    $magic = [BitConverter]::ToUInt16($bytes, $opt)  # should be 0x20B for PE32+
    if ($magic -ne 0x20B) { "$p : not PE32+ (magic=0x$('{0:X}' -f $magic))"; continue }
    # For PE32+, the DataDirectory array starts at OptionalHeader+112. Debug is dir[6].
    # Each dir entry is 8 bytes (VA + Size).
    $ddDebug = $opt + 112 + 6 * 8
    $debugRva = [BitConverter]::ToUInt32($bytes, $ddDebug)
    $debugSize = [BitConverter]::ToUInt32($bytes, $ddDebug + 4)

    # Convert RVA -> file offset by walking section headers.
    $numSecs = [BitConverter]::ToUInt16($bytes, $e_lfanew + 4 + 2)
    $optHdrSize = [BitConverter]::ToUInt16($bytes, $e_lfanew + 4 + 16)
    $secStart = $e_lfanew + 4 + 20 + $optHdrSize

    function Rva2Off($rva) {
        for ($i = 0; $i -lt $numSecs; $i++) {
            $s = $secStart + $i * 40
            $va = [BitConverter]::ToUInt32($bytes, $s + 12)
            $vsz = [BitConverter]::ToUInt32($bytes, $s + 8)
            $raw = [BitConverter]::ToUInt32($bytes, $s + 20)
            if ($rva -ge $va -and $rva -lt ($va + $vsz)) {
                return $raw + ($rva - $va)
            }
        }
        return 0
    }

    $debugOff = Rva2Off $debugRva
    if ($debugOff -eq 0) { "$p : no debug dir entry"; continue }

    # IMAGE_DEBUG_DIRECTORY layout (28 bytes):
    #   Characteristics(4) TimeDateStamp(4) MajorVersion(2) MinorVersion(2)
    #   Type(4) SizeOfData(4) AddressOfRawData(4) PointerToRawData(4)
    $numEntries = [int]($debugSize / 28)
    "=== $p ==="
    for ($i = 0; $i -lt $numEntries; $i++) {
        $de = $debugOff + $i * 28
        $type = [BitConverter]::ToUInt32($bytes, $de + 12)
        $rawPtr = [BitConverter]::ToUInt32($bytes, $de + 24)
        $rawSize = [BitConverter]::ToUInt32($bytes, $de + 16)
        if ($type -ne 2) { continue }   # 2 = IMAGE_DEBUG_TYPE_CODEVIEW
        # CV_INFO_PDB70: "RSDS" (4) + GUID(16) + Age(4) + Path(NUL-terminated)
        $sig = [Text.Encoding]::ASCII.GetString($bytes, $rawPtr, 4)
        if ($sig -ne 'RSDS') { "  non-RSDS codeview"; continue }
        $g = New-Object byte[] 16
        [Array]::Copy($bytes, $rawPtr + 4, $g, 0, 16)
        # GUID byte order: first 3 fields little-endian, last 8 bytes big-endian.
        $guid = New-Object Guid @(,$g)
        $age = [BitConverter]::ToUInt32($bytes, $rawPtr + 20)
        $pathLen = 0
        while ($rawPtr + 24 + $pathLen -lt $bytes.Length -and $bytes[$rawPtr + 24 + $pathLen] -ne 0) { $pathLen++ }
        $pdbPath = [Text.Encoding]::ASCII.GetString($bytes, $rawPtr + 24, $pathLen)
        # dbghelp's cache key: GUID (no dashes, uppercase) + Age (single hex digit).
        $g2 = $guid.ToString('N').ToUpper()
        $key = "{0}{1:X}" -f $g2, $age
        "  PDB: $pdbPath"
        "  GUID: $guid  Age: $age"
        "  symcache key: $key"
    }
}
