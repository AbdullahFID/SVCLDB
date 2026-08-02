#!/usr/bin/env python3
"""
Extract a PyInstaller PYZ archive into individual .pyc modules.

Usage: pyz_extract.py <PYZ-00.pyz> <out_dir>

PyInstaller PYZ format (v3.x):
    magic:  "PYZ\0"                     4 bytes
    pymagic: python magic (little-endian short + 0x0D0A + 0000)  8 bytes
    toc_offset: uint32 big-endian       4 bytes
    (pad zeros to 16 bytes total header)
    then zlib-deflated pickled entries
    at toc_offset:
        pickled (Python 3) or marshalled TOC dict:
            {module_name: (typ, entry_offset, entry_length)}
        typ: 0=module (marshal-encoded code + zlib), 1=package, 2=data
"""
import struct, sys, os, zlib, marshal, pickle, pathlib

def extract(pyz_path, out_dir):
    data = pathlib.Path(pyz_path).read_bytes()
    if data[:4] != b"PYZ\0":
        raise SystemExit(f"not a PYZ (got {data[:4]!r})")
    py_magic = data[4:8]
    toc_offset = struct.unpack(">I", data[8:12])[0]
    print(f"[+] size={len(data)} py_magic={py_magic.hex()} toc_offset=0x{toc_offset:x}")

    toc_bytes = data[toc_offset:]
    toc = None
    for loader, name in ((pickle.loads, "pickle"), (marshal.loads, "marshal")):
        try:
            toc = loader(toc_bytes)
            print(f"[+] TOC decoded via {name}, entries={len(toc)}")
            break
        except Exception as e:
            print(f"[-] {name} failed: {e}")
    if toc is None:
        raise SystemExit("TOC decode failed")

    out = pathlib.Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    manifest = []
    if isinstance(toc, dict):
        items = list(toc.items())
    else:
        items = list(toc)
    for entry in items:
        if len(entry) == 2:
            key, val = entry
            try:
                typ, off, ln = val
            except (TypeError, ValueError):
                print(f"[-] {key}: bad inner tuple {val}")
                continue
        elif len(entry) == 4:
            key, typ, off, ln = entry
        else:
            print(f"[-] bad entry shape ({len(entry)}): {entry}")
            continue
        raw = data[off:off+ln]
        try:
            decompressed = zlib.decompress(raw)
        except Exception as e:
            manifest.append((key, typ, off, ln, f"zlib-fail:{e}"))
            continue
        name = key.decode() if isinstance(key, bytes) else key
        safe = name.replace(".", "/").replace(":", "_")
        target = out / f"{safe}.pyc"
        target.parent.mkdir(parents=True, exist_ok=True)
        # PYZ entries store just the marshalled code object, no .pyc header.
        # Prepend a synthetic .pyc header (16 bytes for Python 3.7+) so external tools can read.
        header = py_magic + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"
        target.write_bytes(header + decompressed)
        manifest.append((name, typ, off, ln, "ok"))

    with (out / "MANIFEST.txt").open("w", encoding="utf-8") as f:
        for row in manifest:
            f.write("\t".join(str(x) for x in row) + "\n")
    ok = sum(1 for r in manifest if r[4] == "ok")
    print(f"[+] extracted {ok}/{len(manifest)} entries to {out}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: pyz_extract.py <PYZ> <out_dir>")
    extract(sys.argv[1], sys.argv[2])
