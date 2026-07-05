"""Extract useful strings from Bypassify payload DLLs + diff old vs new.

Prints:
  - Interesting strings (URLs, LDB refs, API names, file paths, cookies)
  - Strings ADDED in new build vs old build
  - Strings REMOVED in new build vs old build
"""
import re
import sys
from pathlib import Path

OUT = Path(r"C:\Temp\bypassify")

# ASCII + UTF-16LE extractors
ASCII_RE = re.compile(rb"[\x20-\x7e]{6,300}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,300}")


def extract_strings(path: Path) -> set[str]:
    data = path.read_bytes()
    out = set()
    for m in ASCII_RE.finditer(data):
        try:
            out.add(m.group(0).decode("ascii"))
        except UnicodeDecodeError:
            pass
    for m in UTF16_RE.finditer(data):
        try:
            out.add(m.group(0).decode("utf-16le"))
        except UnicodeDecodeError:
            pass
    return out


INTERESTING = re.compile(
    r"lockdown|respondus|LDB|cldb|apdriver|pace|mfort|libcef|boringssl|"
    r"rldb|mldb|monitor|smc-service|autolaunch|pendo|"
    r"bypassify|bypass|hooker|inject|"
    r"http[s]?://|\.com|\.net|\.org|\.io|\.dev|discord|telegram|"
    r"NtOpen|NtQuery|NtCreate|NtProtect|NtWrite|NtRead|NtMap|NtUnmap|"
    r"OpenProcess|VirtualAlloc|WriteProcessMemory|ReadProcessMemory|"
    r"CreateRemoteThread|LoadLibrary|GetProcAddress|"
    r"BCrypt|NCrypt|CryptUnprotect|"
    r"WinInet|WinHttp|urlmon|WSA|socket|connect|recv|send|"
    r"PsLookup|PsSet|PsGet|KeStack|IoCreate|Zw|"
    r"D:\\|C:\\|/Volumes/|\.exe|\.dll|\.sys|\.pdb|\.pak|\.dat|\.pfx|\.cer|"
    r"Program Files|VS12|LockDownChrome|MONServer|"
    r"jmp |call |mov |xor eax|ret|"
    r"Restrictions|Policies|Explorer|CurrentVersion|"
    r"OffsetTable|Fusion|SDKOEM|SDK2015|CLDB_On|CefBrowser|Cef[A-Z][a-z]+|"
    r"tou_violation|verify_exam|examstart|Flash|flashbeat|"
    r"AppData|ProgramData|Temp\\|APPDATA|"
    r"DiscordWebhook|webhook|token|api_key|api key|"
    r"assemble|shellcode|manual map|reflective|"
    r"anti_debug|antidbg|SetHandleInformation|DebugActive",
    re.IGNORECASE,
)


def dump_interesting(label: str, strs: set[str], outpath: Path):
    print(f"\n=== {label} ===")
    interesting = sorted({s for s in strs if INTERESTING.search(s)}, key=lambda s: (len(s), s))
    outpath.write_text("\n".join(sorted(strs)), encoding="utf-8")
    for s in interesting[:200]:
        print(f"  {s!r}")
    if len(interesting) > 200:
        print(f"  ... {len(interesting) - 200} more")
    print(f"\ntotal strings: {len(strs)}  interesting: {len(interesting)}  written to {outpath}")


def diff(new: set[str], old: set[str], label: str):
    added = sorted(new - old, key=lambda s: (len(s), s))
    removed = sorted(old - new, key=lambda s: (len(s), s))
    print(f"\n\n{'#' * 78}\n# STRING DIFF: {label}\n{'#' * 78}")
    print(f"\n--- ADDED (in new but not old) ({len(added)}) ---")
    for s in added:
        print(f"  + {s!r}")
    print(f"\n--- REMOVED (in old but not new) ({len(removed)}) ---")
    for s in removed[:100]:
        print(f"  - {s!r}")
    if len(removed) > 100:
        print(f"  ... {len(removed) - 100} more")


for name in ["id_101", "id_102"]:
    npath = OUT / f"rsrc_new_RT_RCDATA_{name}.bin"
    opath = OUT / f"rsrc_old_RT_RCDATA_{name}.bin"
    ns = extract_strings(npath)
    os_ = extract_strings(opath)
    dump_interesting(f"NEW {name} interesting strings", ns, OUT / f"strings_new_{name}.txt")
    diff(ns, os_, name)
