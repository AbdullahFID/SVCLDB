/* ==================================================================
 * dwmcore_shape_probe -- Dump the first-N bytes of critical dwmcore
 * symbols across arbitrary dwmcore.dll builds. RE data feeds the
 * shape-detector expansion in payload/src/dwm_hooks.c to support
 * more Windows 11 versions universally.
 *
 * USAGE: probe.exe <path-to-dwmcore.dll>
 * OUTPUT: one line per resolved symbol, machine-parseable:
 *   build=<FileVersion> tds=0x<TDS> sym=<name> rva=0x<RVA>
 *   section=<.text|.rdata|...> file_off=0x<off>
 *   b16=<XX XX ... XX>
 *
 * Loads cgpt_dbghelp.dll from beside the .exe (like the resolver does).
 * ================================================================== */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Minimal dbghelp typedefs (copied from resolver/src/main.c) */
typedef struct {
    ULONG    SizeOfStruct;
    ULONG    TypeIndex;
    ULONG64  Reserved[2];
    ULONG    Index;
    ULONG    Size;
    ULONG64  ModBase;
    ULONG    Flags;
    ULONG64  Value;
    ULONG64  Address;
    ULONG    Register;
    ULONG    Scope;
    ULONG    Tag;
    ULONG    NameLen;
    ULONG    MaxNameLen;
    CHAR     Name[2048];
} SYMINFO;

typedef BOOL    (WINAPI *pfnSymInitialize  )(HANDLE, PCSTR, BOOL);
typedef ULONG64 (WINAPI *pfnSymLoadModuleEx)(HANDLE, HANDLE, PCSTR, PCSTR, ULONG64, DWORD, PVOID, DWORD);
typedef BOOL    (WINAPI *pfnSymFromName    )(HANDLE, PCSTR, SYMINFO*);
typedef BOOL    (WINAPI *pfnSymCleanup     )(HANDLE);
typedef DWORD   (WINAPI *pfnSymSetOptions  )(DWORD);

/* IMAGEHLP_MODULE64 (subset needed). */
typedef enum { SymNone2=0, SymCoff2, SymCv2, SymPdb2, SymExport2, SymDeferred2, SymSym2, SymDia2, SymVirtual2 } SYM_TYPE2;
typedef struct {
    DWORD    SizeOfStruct;
    DWORD64  BaseOfImage;
    DWORD    ImageSize;
    DWORD    TimeDateStamp;
    DWORD    CheckSum;
    DWORD    NumSyms;
    SYM_TYPE2 SymType;
    CHAR     ModuleName[32];
    CHAR     ImageName[256];
    CHAR     LoadedImageName[256];
    CHAR     LoadedPdbName[256];
    DWORD    CVSig;
    CHAR     CVData[MAX_PATH * 3];
    DWORD    PdbSig;
    GUID     PdbSig70;
    DWORD    PdbAge;
    BOOL     PdbUnmatched;
    BOOL     DbgUnmatched;
    BOOL     LineNumbers;
    BOOL     GlobalSymbols;
    BOOL     TypeInfo;
    BOOL     SourceIndexed;
    BOOL     Publics;
    DWORD    MachineType;
    DWORD    Reserved;
} IMAGEHLP_MODULE64_LOCAL;
typedef BOOL (WINAPI *pfnSymGetModuleInfo64)(HANDLE, DWORD64, IMAGEHLP_MODULE64_LOCAL*);
typedef BOOL (WINAPI *pfnSymSetSearchPath)(HANDLE, PCSTR);
typedef BOOL (CALLBACK *pfnEnumSymCb)(SYMINFO*, ULONG, PVOID);
typedef BOOL (WINAPI *pfnSymEnumSymbols)(HANDLE, ULONG64, PCSTR, pfnEnumSymCb, PVOID);

#define FAKE_BASE ((ULONG64)0x10000000)

typedef struct { int max; int count; FILE *fp; const char *tag; } EnumCtx;
static BOOL CALLBACK enum_cb(SYMINFO *pSym, ULONG size, PVOID ctx) {
    (void)size;
    EnumCtx *c = (EnumCtx *)ctx;
    if (c->count >= c->max) return FALSE;
    c->count++;
    fprintf(c->fp, "[%s] %s @ 0x%llX\n", c->tag, pSym->Name,
            (unsigned long long)(pSym->Address - FAKE_BASE));
    return TRUE;
}

/* Single-match callback used by the SymFromName fallback path. Captures
 * the first matching symbol's Address and stops. */
typedef struct EnumCtx2_t { int max; int count; FILE *fp; uint64_t rva; } EnumCtx2;
BOOL CALLBACK single_hit_cb(SYMINFO *pSym, ULONG size, PVOID ctx) {
    (void)size;
    EnumCtx2 *c = (EnumCtx2 *)ctx;
    if (c->count >= c->max) return FALSE;
    c->count++;
    c->rva = pSym->Address;   /* absolute FAKE_BASE+rva */
    return FALSE;             /* stop after first */
}

typedef struct {
    char     section[16];  /* .text / .rdata / etc */
    DWORD    va;           /* virtual address (RVA) start of section */
    DWORD    vsz;          /* virtual size */
    DWORD    raw;          /* file offset */
    DWORD    rsz;          /* raw data size */
} SectionInfo;

static int parse_pe_sections(const BYTE *buf, DWORD n, SectionInfo *out, int max) {
    if (n < 0x40) return 0;
    DWORD e_lfanew = *(DWORD*)(buf + 0x3C);
    if (e_lfanew + 0x18 > n) return 0;
    if (buf[e_lfanew] != 'P' || buf[e_lfanew+1] != 'E') return 0;
    /* IMAGE_FILE_HEADER at e_lfanew+4 -- has NumberOfSections (WORD) at +2,
     * SizeOfOptionalHeader (WORD) at +16. */
    WORD num_sections = *(WORD*)(buf + e_lfanew + 4 + 2);
    WORD opt_hdr_size = *(WORD*)(buf + e_lfanew + 4 + 16);
    DWORD sec_start = e_lfanew + 4 + 20 + opt_hdr_size;   /* 20 = sizeof IMAGE_FILE_HEADER */

    int wrote = 0;
    for (WORD i = 0; i < num_sections && wrote < max; i++) {
        DWORD s = sec_start + i * 40;
        if (s + 40 > n) break;
        SectionInfo *si = &out[wrote++];
        memset(si->section, 0, sizeof(si->section));
        memcpy(si->section, buf + s, 8);   /* Name[8] */
        si->vsz = *(DWORD*)(buf + s + 8);
        si->va  = *(DWORD*)(buf + s + 12);
        si->rsz = *(DWORD*)(buf + s + 16);
        si->raw = *(DWORD*)(buf + s + 20);
    }
    return wrote;
}

static const SectionInfo *find_section_for_rva(const SectionInfo *secs, int n, DWORD rva) {
    for (int i = 0; i < n; i++) {
        if (rva >= secs[i].va && rva < secs[i].va + secs[i].vsz)
            return &secs[i];
    }
    return NULL;
}

/* Read the entire dwmcore.dll file into a heap buffer. */
static BYTE *read_file(const char *path, DWORD *out_sz) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER li;
    if (!GetFileSizeEx(h, &li) || li.QuadPart > 0x10000000) {
        CloseHandle(h); return NULL;
    }
    DWORD sz = (DWORD)li.QuadPart;
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD r = 0;
    if (!ReadFile(h, buf, sz, &r, NULL) || r != sz) {
        VirtualFree(buf, 0, MEM_RELEASE); CloseHandle(h); return NULL;
    }
    CloseHandle(h);
    *out_sz = sz;
    return buf;
}

/* Read the FileVersion resource from a DLL (short form). */
static void read_file_version(const char *path, char *out, size_t out_sz) {
    out[0] = 0;
    DWORD dummy = 0;
    DWORD info_sz = GetFileVersionInfoSizeA(path, &dummy);
    if (info_sz == 0) return;
    BYTE *info = (BYTE *)malloc(info_sz);
    if (!info) return;
    if (GetFileVersionInfoA(path, 0, info_sz, info)) {
        VS_FIXEDFILEINFO *ffi = NULL;
        UINT ffi_sz = 0;
        if (VerQueryValueA(info, "\\", (LPVOID*)&ffi, &ffi_sz) && ffi_sz) {
            _snprintf(out, out_sz - 1, "%u.%u.%u.%u",
                (unsigned)(HIWORD(ffi->dwFileVersionMS)),
                (unsigned)(LOWORD(ffi->dwFileVersionMS)),
                (unsigned)(HIWORD(ffi->dwFileVersionLS)),
                (unsigned)(LOWORD(ffi->dwFileVersionLS)));
            out[out_sz - 1] = 0;
        }
    }
    free(info);
}

/* Symbol table -- ordered by priority. Each entry is a NULL-terminated
 * list of candidate patterns; probe emits ONE result line per entry
 * (first pattern that resolves wins). This mirrors the resolver's
 * fallback chain in resolver/src/main.c so the compat matrix truly
 * reflects what our shipping resolver would find. Wildcards use '*'. */
typedef struct {
    const char *label;
    const char *candidates[8];   /* NULL-terminated */
} SymEntry;

static const SymEntry g_syms[] = {
    { "COverlayContext::Present",
      { "dwmcore!COverlayContext::Present", NULL } },
    { "CGlobalCompositionSurfaceInfo::IsOverlayPrevented",
      { "dwmcore!CGlobalCompositionSurfaceInfo::IsOverlayPrevented", NULL } },
    { "CCommonRegistryData::ForceFullDirtyRendering",
      { "dwmcore!CCommonRegistryData::ForceFullDirtyRendering", NULL } },
    { "CDDisplayRenderTarget::PresentNeeded",
      { "dwmcore!CDDisplayRenderTarget::PresentNeeded",
        "dwmcore!*RenderTarget::PresentNeeded",
        "dwmcore!*::PresentNeeded", NULL } },
    { "CLegacyRenderTarget::PresentNeeded",
      { "dwmcore!CLegacyRenderTarget::PresentNeeded",
        "dwmcore!*Legacy*::PresentNeeded", NULL } },
    { "ScheduleCompositionPass",
      { "dwmcore!ScheduleCompositionPass", NULL } },
    { "CVisual::RenderContent",
      { "dwmcore!CVisual::RenderContent", NULL } },
    { "CWindowNode::RenderContent",
      { "dwmcore!CWindowNode::RenderContent", NULL } },
    /* backbuffer chain -- multiple class variants across builds */
    { "GetPhysicalBackBuffer",
      { "dwmcore!CDDisplaySwapChain::GetPhysicalBackBuffer",
        "dwmcore!COverlaySwapChain::GetPhysicalBackBuffer",
        "dwmcore!*SwapChain::GetPhysicalBackBuffer",
        "dwmcore!*::GetPhysicalBackBuffer",
        "dwmcore!*PhysicalBackBuffer*", NULL } },
    { "GetD3D11Resource",
      { "dwmcore!CDDisplaySwapChainBuffer::GetD3D11Resource",
        "dwmcore!CDDisplaySwapChain::GetD3D11Resource",
        "dwmcore!COverlaySwapChain::GetD3D11Resource",
        "dwmcore!*::GetD3D11Resource",
        "dwmcore!*GetD3D11Resource*", NULL } },
    { "Accessor (GetTexture2D)",
      { "dwmcore!CDeviceTextureTarget::GetTexture2D",
        "dwmcore!*Target::GetTexture2D",
        "dwmcore!*::GetTexture2D",
        "dwmcore!*::AsTexture2D",
        "dwmcore!*::GetResource", NULL } },
    { NULL, { NULL } }   /* terminator */
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: probe.exe <path-to-dwmcore.dll>\n");
        return 2;
    }
    const char *dwmcore_path = argv[1];

    /* Locate cgpt_dbghelp.dll beside probe.exe */
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);
    char *sl = strrchr(self, '\\');
    if (sl) *sl = 0;

    char oldpath[4096] = {0}, newpath[4096] = {0};
    GetEnvironmentVariableA("PATH", oldpath, sizeof(oldpath));
    _snprintf(newpath, sizeof(newpath) - 1, "%s;%s", self, oldpath);
    newpath[sizeof(newpath) - 1] = 0;
    SetEnvironmentVariableA("PATH", newpath);

    char dbg_path[MAX_PATH];
    _snprintf(dbg_path, sizeof(dbg_path) - 1, "%s\\cgpt_dbghelp.dll", self);
    dbg_path[sizeof(dbg_path) - 1] = 0;

    HMODULE hDbg = LoadLibraryA(dbg_path);
    if (!hDbg) {
        fprintf(stderr, "FATAL: LoadLibrary %s failed GLE=%lu\n",
                dbg_path, GetLastError());
        return 1;
    }
    pfnSymInitialize      pSymInit    = (pfnSymInitialize)     GetProcAddress(hDbg, "SymInitialize");
    pfnSymLoadModuleEx    pSymLoadEx  = (pfnSymLoadModuleEx)   GetProcAddress(hDbg, "SymLoadModuleEx");
    pfnSymFromName        pSymFrom    = (pfnSymFromName)       GetProcAddress(hDbg, "SymFromName");
    pfnSymCleanup         pSymCleanup = (pfnSymCleanup)        GetProcAddress(hDbg, "SymCleanup");
    pfnSymSetOptions      pSymSetOpts = (pfnSymSetOptions)     GetProcAddress(hDbg, "SymSetOptions");
    pfnSymGetModuleInfo64 pSymModInfo = (pfnSymGetModuleInfo64)GetProcAddress(hDbg, "SymGetModuleInfo64");
    pfnSymSetSearchPath   pSymSearch  = (pfnSymSetSearchPath)  GetProcAddress(hDbg, "SymSetSearchPath");
    pfnSymEnumSymbols     pSymEnum    = (pfnSymEnumSymbols)    GetProcAddress(hDbg, "SymEnumSymbols");
    if (!pSymInit || !pSymLoadEx || !pSymFrom) {
        fprintf(stderr, "FATAL: missing dbghelp exports\n");
        return 1;
    }

    HANDLE hProc = GetCurrentProcess();
    /* Use liberal options: UNDNAME + LOAD_ANYTHING + LOAD_LINES + FAVOR_COMPRESSED + DEBUG. */
    if (pSymSetOpts) pSymSetOpts(0x80800052);

    /* Point symsrv at our shared cache + msdl fallback */
    const char *sym_path = "srv*C:\\ProgramData\\WinAudioSvc\\symbols*https://msdl.microsoft.com/download/symbols";
    if (!pSymInit(hProc, sym_path, FALSE)) {
        fprintf(stderr, "FATAL: SymInitialize %lu\n", GetLastError());
        return 1;
    }

    ULONG64 mb = pSymLoadEx(hProc, NULL, dwmcore_path, NULL, FAKE_BASE, 0, NULL, 0);
    if (!mb) {
        fprintf(stderr, "FATAL: SymLoadModuleEx %s -> %lu\n",
                dwmcore_path, GetLastError());
        if (pSymCleanup) pSymCleanup(hProc);
        return 1;
    }

    /* Diagnostics: verify PDB actually loaded. */
    if (pSymModInfo) {
        IMAGEHLP_MODULE64_LOCAL mi = {0};
        mi.SizeOfStruct = sizeof(mi);
        if (pSymModInfo(hProc, mb, &mi)) {
            const char *st = "?";
            switch (mi.SymType) {
                case SymNone2: st = "None"; break;
                case SymCoff2: st = "Coff"; break;
                case SymCv2:   st = "Cv";   break;
                case SymPdb2:  st = "Pdb";  break;
                case SymExport2:st = "Export"; break;
                case SymDeferred2: st = "Deferred"; break;
                case SymSym2:  st = "Sym";  break;
                case SymDia2:  st = "Dia";  break;
                case SymVirtual2: st = "Virtual"; break;
            }
            printf("# SymGetModuleInfo64: SymType=%s NumSyms=%lu LoadedPdb=%s "
                   "PdbUnmatched=%d DbgUnmatched=%d\n",
                   st, (unsigned long)mi.NumSyms,
                   mi.LoadedPdbName[0] ? mi.LoadedPdbName : "<none>",
                   mi.PdbUnmatched, mi.DbgUnmatched);
        } else {
            printf("# SymGetModuleInfo64 FAILED gle=%lu\n", GetLastError());
        }
    }

    /* Read the raw PE file so we can dump bytes at each resolved RVA. */
    DWORD file_sz = 0;
    BYTE *file = read_file(dwmcore_path, &file_sz);
    if (!file) {
        fprintf(stderr, "FATAL: read_file %s\n", dwmcore_path);
        return 1;
    }

    /* Parse sections once. */
    SectionInfo secs[24];
    int n_secs = parse_pe_sections(file, file_sz, secs, 24);

    /* PE TimeDateStamp (from what we just parsed) */
    DWORD e_lfanew = *(DWORD*)(file + 0x3C);
    DWORD tds = *(DWORD*)(file + e_lfanew + 4 + 4);

    char fv[64] = {0};
    read_file_version(dwmcore_path, fv, sizeof(fv));

    /* Header line */
    printf("# probe: file=%s size=%lu FileVersion=%s TDS=0x%08lX sections=%d\n",
           dwmcore_path, (unsigned long)file_sz, fv, (unsigned long)tds, n_secs);
    for (int i = 0; i < n_secs; i++) {
        printf("#   sec[%d] name=%-8.8s va=0x%08lX vsz=0x%08lX raw=0x%08lX rsz=0x%08lX\n",
               i, secs[i].section,
               (unsigned long)secs[i].va, (unsigned long)secs[i].vsz,
               (unsigned long)secs[i].raw, (unsigned long)secs[i].rsz);
    }

    /* For each symbol entry, try candidates in order (exact first,
     * wildcards last). Mirrors resolver's fallback chain so the
     * compat matrix reflects what the shipping resolver would find.
     * Records which candidate index won (1..N or 99=SymFromName). */
    for (int i = 0; g_syms[i].label; i++) {
        DWORD rva = 0;
        int hit_via = 0;
        const char *matched_pat = NULL;

        int c;
        for (c = 0; g_syms[i].candidates[c] && !rva; c++) {
            const char *pat = g_syms[i].candidates[c];
            if (!pSymEnum) break;
            FILE *fnul = fopen("NUL", "w");
            EnumCtx2 ec2;
            ec2.max = 1; ec2.count = 0;
            ec2.fp = fnul ? fnul : stdout;
            ec2.rva = 0;
            pSymEnum(hProc, mb, pat, single_hit_cb, &ec2);
            if (ec2.count > 0 && ec2.rva >= FAKE_BASE) {
                rva = (DWORD)(ec2.rva - FAKE_BASE);
                hit_via = c + 1;
                matched_pat = pat;
            }
            if (fnul) fclose(fnul);
        }
        /* Last resort: SymFromName with the primary (index 0) candidate. */
        if (!rva) {
            char buf[sizeof(SYMINFO)];
            SYMINFO *p = (SYMINFO*)buf;
            ZeroMemory(buf, sizeof(buf));
            p->SizeOfStruct = 88;
            p->MaxNameLen = sizeof(p->Name) - 1;
            if (pSymFrom(hProc, g_syms[i].candidates[0], p) && p->Address >= FAKE_BASE) {
                rva = (DWORD)(p->Address - FAKE_BASE);
                hit_via = 99;
                matched_pat = g_syms[i].candidates[0];
            }
        }

        if (!rva) {
            printf("build=%s tds=0x%08lX sym=dwmcore!%s rva=MISS gle=%lu\n",
                   fv, (unsigned long)tds, g_syms[i].label, GetLastError());
            continue;
        }
        const SectionInfo *si = find_section_for_rva(secs, n_secs, rva);
        DWORD file_off = 0;
        if (si) file_off = si->raw + (rva - si->va);

        char bytes[128] = {0};
        char *bp = bytes;
        int max_bytes = 32;
        if (file_off && file_off + max_bytes <= file_sz) {
            int b;
            for (b = 0; b < max_bytes; b++) {
                bp += sprintf(bp, "%02X ", file[file_off + b]);
            }
            if (bp > bytes) bp[-1] = 0;
        } else {
            strcpy(bytes, "<unmapped>");
        }
        {
            char via_lbl[32];
            if (hit_via == 99) strcpy(via_lbl, "SymFromName");
            else               sprintf(via_lbl, "cand%d", hit_via);
            printf("build=%s tds=0x%08lX sym=dwmcore!%s rva=0x%lX via=%s "
                   "matched=%s section=%-8.8s file_off=0x%lX b32=%s\n",
                   fv, (unsigned long)tds, g_syms[i].label,
                   (unsigned long)rva, via_lbl,
                   matched_pat ? matched_pat : "?",
                   si ? si->section : "<none>",
                   (unsigned long)file_off,
                   bytes);
        }
    }

    /* If nothing resolved, dump a sample of what IS in the PDB so we can
     * see if class names differ. */
    if (pSymEnum) {
        printf("\n# === Sampling symbols matching common patterns ===\n");
        const char *patterns[] = {
            "dwmcore!COverlayContext::*",
            "dwmcore!*::Present",
            "dwmcore!*::PresentNeeded",
            "dwmcore!*OverlayPrevented*",
            "dwmcore!*IsPrevented*",
            "dwmcore!*OverlayPlane*",
            "dwmcore!*OverlayInhibit*",
            "dwmcore!*CanUseOverlay*",
            "dwmcore!ScheduleCompositionPass",
            "dwmcore!*ScheduleComposition*",
            "dwmcore!CGlobalCompositionSurfaceInfo::*",
            NULL,
        };
        for (int pi = 0; patterns[pi]; pi++) {
            EnumCtx ctx = { 60, 0, stdout, patterns[pi] };
            pSymEnum(hProc, mb, patterns[pi], enum_cb, &ctx);
            printf("# pattern %-45s -> %d hits\n", patterns[pi], ctx.count);
        }
    }

    if (pSymCleanup) pSymCleanup(hProc);
    VirtualFree(file, 0, MEM_RELEASE);
    return 0;
}
