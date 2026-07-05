"""Identify each embedded DLL — dump exports, imports, PDB path, RichHeader."""
import sys
from pathlib import Path

import pefile

OUT = Path(r"C:\Temp\bypassify")


def report(path: Path):
    print(f"\n{'=' * 78}\n{path.name}\n{'=' * 78}")
    pe = pefile.PE(str(path), fast_load=False)
    print(f"machine=0x{pe.FILE_HEADER.Machine:04x}  is_dll={bool(pe.FILE_HEADER.Characteristics & 0x2000)}")
    print(f"image_base=0x{pe.OPTIONAL_HEADER.ImageBase:x}  size_of_image=0x{pe.OPTIONAL_HEADER.SizeOfImage:x}")
    print(f"entry_point=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    print(f"time_date_stamp=0x{pe.FILE_HEADER.TimeDateStamp:x}")
    print(f"linker=v{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}")
    print(f"dll_characteristics=0x{pe.OPTIONAL_HEADER.DllCharacteristics:x}")

    # PDB path via CodeView debug directory
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            try:
                if dbg.entry:
                    for attr in dir(dbg.entry):
                        if attr.startswith("PdbFileName"):
                            v = getattr(dbg.entry, attr)
                            if v:
                                print(f"pdb: {v.decode('latin-1', 'replace')}")
            except Exception:
                pass
            # dump raw debug entry too
            rva = dbg.struct.AddressOfRawData
            size = dbg.struct.SizeOfData
            raw = pe.get_data(rva, size) if rva else b""
            if raw[:4] == b"RSDS":
                # 4 magic + 16 GUID + 4 age + PDB path
                gg = raw[4:20]
                age = int.from_bytes(raw[20:24], "little")
                pdb = raw[24:].split(b"\x00")[0].decode("latin-1", "replace")
                print(f"pdb-RSDS: guid={gg.hex()} age={age} pdb={pdb}")

    # RichHeader tells us MSVC compiler versions in play
    try:
        rich = pe.parse_rich_header()
        if rich:
            print(f"rich header entries (compiler+tool set):")
            for r in rich.get("values", [])[::2]:
                pass  # already covered by clear_data
            # Actually print the mapping properly
            values = rich.get("values", [])
            for i in range(0, len(values), 2):
                comp_id = values[i]
                count = values[i + 1] if i + 1 < len(values) else 0
                pid = (comp_id >> 16) & 0xffff
                min_ver = comp_id & 0xffff
                print(f"  prodID=0x{pid:04x} minorVer={min_ver:5d} count={count}")
    except Exception as ex:
        print(f"rich header: parse failed ({ex})")

    # Exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print(f"\nexports ({len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}):")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:100]:
            name = exp.name.decode("latin-1", "replace") if exp.name else f"@ord_{exp.ordinal}"
            print(f"  ord={exp.ordinal:4d} rva=0x{exp.address:08x}  {name}")
        if len(pe.DIRECTORY_ENTRY_EXPORT.symbols) > 100:
            print(f"  ... {len(pe.DIRECTORY_ENTRY_EXPORT.symbols) - 100} more")

    # Imports summary
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print(f"\nimports ({sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)} total):")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1", "replace")
            print(f"  {dll}  ({len(entry.imports)} funcs)")

    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        print(f"\ndelay imports:")
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll = entry.dll.decode("latin-1", "replace")
            print(f"  [delay] {dll}  ({len(entry.imports)} funcs)")

    # Sections
    print(f"\nsections:")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        print(f"  {name:10s} vsize=0x{s.Misc_VirtualSize:08x} rsize=0x{s.SizeOfRawData:08x} char=0x{s.Characteristics:08x}")


for f in sorted(OUT.glob("rsrc_new_*.bin")):
    if b"MZ" == f.read_bytes()[:2]:
        report(f)
print("\n" + "=" * 78)
print("=== OLD versions of each (for comparison) ===")
print("=" * 78)
for f in sorted(OUT.glob("rsrc_old_*.bin")):
    if b"MZ" == f.read_bytes()[:2]:
        report(f)
