"""Bypassify triage — dump PE metadata for both new + old binaries.

Usage: python bypassify_triage.py
Prints PE headers, sections, imports, resources, entropy per section.
Compares new vs old to highlight what changed for the 2.1.5 update.
"""
import hashlib
import math
import sys
from pathlib import Path

import pefile


NEW = r"C:\Users\abdul\Downloads\launchhere (1).exe"
OLD = r"C:\Users\abdul\Downloads\launchhere.exe"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ln = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / ln
            e -= p * math.log2(p)
    return e


def analyze(path: str, label: str):
    print(f"\n{'=' * 78}\n{label}: {path}\n{'=' * 78}")
    data = Path(path).read_bytes()
    print(f"file size: {len(data):,} bytes")
    print(f"MD5:    {hashlib.md5(data).hexdigest()}")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")

    pe = pefile.PE(path, fast_load=False)

    print(
        f"\nmachine=0x{pe.FILE_HEADER.Machine:04x} "
        f"({pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, '?')})"
    )
    print(f"time_date_stamp={pe.FILE_HEADER.TimeDateStamp:#x}")
    import datetime as _dt
    print(f"    compiled: {_dt.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)} UTC")
    print(f"image_base=0x{pe.OPTIONAL_HEADER.ImageBase:x}")
    print(f"entry_point=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x} "
          f"(VA=0x{pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint:x})")
    print(f"subsystem={pe.OPTIONAL_HEADER.Subsystem} (2=GUI, 3=console)")
    print(f"dll_characteristics=0x{pe.OPTIONAL_HEADER.DllCharacteristics:x}")
    print(f"size_of_image=0x{pe.OPTIONAL_HEADER.SizeOfImage:x}")
    print(f"linker=v{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}")

    print(f"\nsections ({len(pe.sections)}):")
    print(f"  {'name':10s} {'vsize':>10s} {'rsize':>10s} {'flags':>10s} {'entropy':>7s}  meaning")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        raw = s.get_data()
        e = entropy(raw)
        flags = s.Characteristics
        access = ""
        if flags & 0x20000000:
            access += "X"
        if flags & 0x80000000:
            access += "W"
        if flags & 0x40000000:
            access += "R"
        print(f"  {name:10s} {s.Misc_VirtualSize:10x} {s.SizeOfRawData:10x} "
              f"{flags:10x} {e:7.3f}  {access}")

    # Imports
    print(f"\nimports:")
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('latin-1', 'replace')
                print(f"  {dll}  ({len(entry.imports)} funcs)")
                for imp in entry.imports:
                    name = imp.name.decode('latin-1', 'replace') if imp.name else f"ord_{imp.ordinal}"
                    print(f"    {name}")
        else:
            print("  (no import table)")
    except Exception as ex:
        print(f"  parse error: {ex}")

    # Delay-load imports (Nuitka / MSVC 2022 default for many DLLs)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']])
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            print(f"\ndelay imports:")
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll = entry.dll.decode('latin-1', 'replace')
                print(f"  [delay] {dll}  ({len(entry.imports)} funcs)")
                for imp in entry.imports:
                    name = imp.name.decode('latin-1', 'replace') if imp.name else f"ord_{imp.ordinal}"
                    print(f"    {name}")
    except Exception:
        pass

    # Resources — top-level structure
    print(f"\nresources:")
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                rtn = rt.name.decode() if rt.name else pefile.RESOURCE_TYPE.get(rt.struct.Id, f"type_{rt.struct.Id}")
                if not hasattr(rt, 'directory'):
                    continue
                for ent in rt.directory.entries:
                    entn = ent.name.decode() if ent.name else f"id_{ent.struct.Id}"
                    if not hasattr(ent, 'directory'):
                        continue
                    for lang in ent.directory.entries:
                        lang_id = lang.data.struct.CodePage if hasattr(lang.data, 'struct') else 0
                        size = lang.data.struct.Size if hasattr(lang.data, 'struct') else 0
                        rva = lang.data.struct.OffsetToData if hasattr(lang.data, 'struct') else 0
                        print(f"  type={rtn!s:15s} name={entn!s:10s} "
                              f"lang=0x{lang.struct.Id:04x} size=0x{size:x} "
                              f"rva=0x{rva:x}")
        else:
            print("  (no resource table)")
    except Exception as ex:
        print(f"  parse error: {ex}")


def main():
    if not Path(NEW).exists() or not Path(OLD).exists():
        print(f"missing: {NEW=} {OLD=}")
        sys.exit(1)
    analyze(NEW, "NEW (2026-07-01)")
    analyze(OLD, "OLD (2026-05-20)")


if __name__ == "__main__":
    main()
