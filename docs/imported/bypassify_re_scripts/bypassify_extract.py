"""Extract all RT_RCDATA resources from both Bypassify binaries + identify their file types."""
import hashlib
from pathlib import Path

import pefile

NEW = r"C:\Users\abdul\Downloads\launchhere (1).exe"
OLD = r"C:\Users\abdul\Downloads\launchhere.exe"
OUT = Path(r"C:\Temp\bypassify")
OUT.mkdir(parents=True, exist_ok=True)


def identify(data: bytes) -> str:
    if data[:2] == b"MZ":
        try:
            sub = pefile.PE(data=data, fast_load=True)
            machine = {0x8664: "x64", 0x14c: "x86", 0xaa64: "arm64"}.get(sub.FILE_HEADER.Machine, hex(sub.FILE_HEADER.Machine))
            is_dll = bool(sub.FILE_HEADER.Characteristics & 0x2000)
            ep = sub.OPTIONAL_HEADER.AddressOfEntryPoint
            tds = sub.FILE_HEADER.TimeDateStamp
            import datetime as _dt
            when = _dt.datetime.utcfromtimestamp(tds).isoformat() if 0 < tds < 0x80000000 else "?"
            return f"PE {machine} {'DLL' if is_dll else 'EXE'} EP=0x{ep:x} TDS=0x{tds:x} ({when})"
        except Exception as ex:
            return f"MZ-header but PE parse failed: {ex}"
    if data[:4] == b"PK\x03\x04":
        return "ZIP archive"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:3] == b"\x1f\x8b\x08":
        return "gzip"
    if data[:4] == b"Rar!":
        return "RAR"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:4] == b"BZh0":
        return "bzip2"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if data[:2] == b"\xff\xd8":
        return "JPEG"
    if data[:4] in (b"RIFF",):
        return f"RIFF ({data[8:12]!r})"
    if data[:4] == b"OggS":
        return "Ogg"
    # Base64?
    printable = sum(32 <= b < 127 for b in data[:200])
    if printable > 190:
        head = data[:80].decode("latin-1", "replace").replace("\r", "\\r").replace("\n", "\\n")
        return f"TEXT-LIKE printable_head={head!r}"
    # Encrypted / compressed / dll?  Check entropy
    import math
    counts = [0] * 256
    for b in data[:65536]:
        counts[b] += 1
    ln = min(65536, len(data))
    ent = 0.0
    for c in counts:
        if c:
            p = c / ln
            ent -= p * math.log2(p)
    return f"unknown magic={data[:16].hex()} entropy_head={ent:.3f}"


def extract(binpath: str, suffix: str):
    pe = pefile.PE(binpath, fast_load=False)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return
    for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        rtn = rt.name.decode() if rt.name else pefile.RESOURCE_TYPE.get(rt.struct.Id, f"type_{rt.struct.Id}")
        if not hasattr(rt, "directory"):
            continue
        for ent in rt.directory.entries:
            entn = ent.name.decode() if ent.name else f"id_{ent.struct.Id}"
            if not hasattr(ent, "directory"):
                continue
            for lang in ent.directory.entries:
                data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                fname = OUT / f"rsrc_{suffix}_{rtn}_{entn}.bin"
                fname.write_bytes(data)
                h = hashlib.sha256(data).hexdigest()
                ident = identify(data)
                print(f"  {fname.name:40s} size={len(data):>8d} sha256={h[:16]}... {ident}")


print("=== NEW binary resources ===")
extract(NEW, "new")
print("\n=== OLD binary resources ===")
extract(OLD, "old")
