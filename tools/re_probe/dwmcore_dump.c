/* ================================================================== *
 * dwmcore_dump.c — RE probe: dump dwmcore.dll vtable layouts from PDB.
 *
 * Purpose:
 *   Definitively answer: for a specific dwmcore.dll build, which vtable
 *   slot on which class contains which method? svcldb's hardcoded
 *   GPB_SLOT=5, GD3D_SLOT=24, ACC3_SLOT=19 assume ONE specific vtable
 *   layout. When Windows updates re-order the vtable, we crash. This
 *   tool answers: what SHOULD those slots be per-build?
 *
 * Method:
 *   1. LoadLibraryEx(dwmcore.dll, DONT_RESOLVE_DLL_REFERENCES) — maps
 *      the DLL at some base, gives us access to its .rdata contents.
 *   2. SymInitialize + SymLoadModuleEx on dwmcore.dll at that same
 *      base — dbghelp downloads/loads the PDB.
 *   3. For each class of interest:
 *        - SymFromName on "dwmcore!??_7ClassName@@6B@" (the vtable
 *          symbol) to get the vtable's VA.
 *        - Read up to 80 * sizeof(void*) bytes at that VA — those are
 *          function pointers.
 *        - For each function pointer, SymFromAddr to name the method.
 *        - Print: "  slot[N] = 0x{RVA} == ClassName::MethodName"
 *   4. Also enumerate ALL methods on each class of interest and dump
 *      (Name, RVA) tuples so we can see what's available.
 *
 * Usage:
 *   cl /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS dwmcore_dump.c
 *   dwmcore_dump.exe > dump.txt
 *
 * Output: text dump. Prod code stays untouched.
 * ================================================================== */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Statically link against dbghelp.dll shipped with the OS. Sufficient for
 * SymFromName/SymFromAddr but NOT for PDB downloads from a symbol server.
 * For PDB download we bring the cached dbghelp+symsrv from ProgramData. */
typedef struct _SYMBOL_INFO {
    ULONG   SizeOfStruct;
    ULONG   TypeIndex;
    ULONG64 Reserved[2];
    ULONG   Index;
    ULONG   Size;
    ULONG64 ModBase;
    ULONG   Flags;
    ULONG64 Value;
    ULONG64 Address;
    ULONG   Register;
    ULONG   Scope;
    ULONG   Tag;
    ULONG   NameLen;
    ULONG   MaxNameLen;
    CHAR    Name[2048];
} SYMBOL_INFO;

typedef BOOL    (WINAPI *pfnSymInitialize)(HANDLE, PCSTR, BOOL);
typedef DWORD   (WINAPI *pfnSymSetOptions)(DWORD);
typedef ULONG64 (WINAPI *pfnSymLoadModuleEx)(HANDLE, HANDLE, PCSTR, PCSTR, ULONG64, DWORD, PVOID, DWORD);
typedef BOOL    (WINAPI *pfnSymFromName)(HANDLE, PCSTR, SYMBOL_INFO *);
typedef BOOL    (WINAPI *pfnSymFromAddr)(HANDLE, DWORD64, DWORD64 *, SYMBOL_INFO *);
typedef BOOL    (WINAPI *pfnSymCleanup)(HANDLE);
typedef BOOL    (CALLBACK *pfnEnumSymCb)(SYMBOL_INFO *, ULONG, PVOID);
typedef BOOL    (WINAPI *pfnSymEnumSymbols)(HANDLE, ULONG64, PCSTR, pfnEnumSymCb, PVOID);

static pfnSymInitialize   pSymInitialize;
static pfnSymSetOptions   pSymSetOptions;
static pfnSymLoadModuleEx pSymLoadModuleEx;
static pfnSymFromName     pSymFromName;
static pfnSymFromAddr     pSymFromAddr;
static pfnSymCleanup      pSymCleanup;
static pfnSymEnumSymbols  pSymEnumSymbols;

#define DWMCORE_PATH "C:\\Windows\\System32\\dwmcore.dll"
#define SYM_SERVER   "srv*C:\\ProgramData\\WinAudioSvc\\symbols*https://msdl.microsoft.com/download/symbols"
#define MAX_VTABLE_SLOTS 80

static HANDLE g_proc;
static ULONG64 g_dll_base;
static uintptr_t g_mapped_base;
static SIZE_T   g_mapped_size;

/* Get name of symbol at given VA (address in DLL). Returns "?" on miss. */
static void name_at_va(DWORD64 va, char *out, size_t out_sz, DWORD64 *disp) {
    char buf[sizeof(SYMBOL_INFO)];
    SYMBOL_INFO *p = (SYMBOL_INFO *)buf;
    memset(buf, 0, sizeof(buf));
    p->SizeOfStruct = 88;
    p->MaxNameLen = sizeof(p->Name) - 1;
    DWORD64 d = 0;
    if (pSymFromAddr(g_proc, va, &d, p)) {
        _snprintf(out, out_sz - 1, "%s", p->Name);
        out[out_sz - 1] = 0;
        if (disp) *disp = d;
    } else {
        strncpy(out, "?", out_sz - 1);
        out[out_sz - 1] = 0;
        if (disp) *disp = 0;
    }
}

/* Read pointer from mapped DLL at given RVA. Returns 0 on out-of-bounds. */
static uintptr_t read_ptr_at_rva(uintptr_t rva) {
    if (rva + sizeof(uintptr_t) > g_mapped_size) return 0;
    return *(uintptr_t *)(g_mapped_base + rva);
}

static void dump_vtable_at_rva(const char *label, uintptr_t vtable_rva) {
    printf("\n=== vtable[%s] @ RVA 0x%llX ===\n", label, (unsigned long long)vtable_rva);
    for (int i = 0; i < MAX_VTABLE_SLOTS; i++) {
        uintptr_t fn_va = read_ptr_at_rva(vtable_rva + i * sizeof(uintptr_t));
        if (!fn_va) { printf("  slot[%2d] = 0x0 (end)\n", i); break; }
        uintptr_t rva = fn_va - g_mapped_base;
        DWORD64 sym_va = g_dll_base + rva;
        DWORD64 disp = 0;
        char name[512];
        name_at_va(sym_va, name, sizeof(name), &disp);
        if (disp) {
            printf("  slot[%2d] = 0x%llX (+0x%llX in %s)\n", i,
                   (unsigned long long)rva, (unsigned long long)disp, name);
        } else {
            printf("  slot[%2d] = 0x%llX == %s\n", i,
                   (unsigned long long)rva, name);
        }
        if (fn_va < g_mapped_base || fn_va >= g_mapped_base + g_mapped_size) {
            printf("  (slot points outside dwmcore — end)\n");
            break;
        }
    }
}

/* Legacy path — tries mangled-name lookup. Rarely works because vftable
 * symbols have quirky mangling. Prefer the enum → dump_vtable_at_rva flow. */
static void dump_vtable(const char *class_name) {
    char sym[512];
    _snprintf(sym, sizeof(sym) - 1, "dwmcore!??_7%s@@6B@", class_name);
    sym[sizeof(sym) - 1] = 0;

    char buf[sizeof(SYMBOL_INFO)];
    SYMBOL_INFO *p = (SYMBOL_INFO *)buf;
    memset(buf, 0, sizeof(buf));
    p->SizeOfStruct = 88;
    p->MaxNameLen = sizeof(p->Name) - 1;
    if (!pSymFromName(g_proc, sym, p)) {
        printf("[vtable] %-40s NOT FOUND (GLE=%lu)\n", class_name, GetLastError());
        return;
    }
    uintptr_t vtable_rva = (uintptr_t)(p->Address - g_dll_base);
    dump_vtable_at_rva(class_name, vtable_rva);
}

/* Enumerator that collects vftable RVAs by name pattern, then dumps each. */
typedef struct { uintptr_t rvas[16]; int n; } VfCtx;
static BOOL CALLBACK VfEnumCb(SYMBOL_INFO *pSym, ULONG size, PVOID ctx) {
    (void)size;
    VfCtx *c = (VfCtx *)ctx;
    if (c->n >= 16) return TRUE;
    /* Address is the vtable's location in the DLL. */
    c->rvas[c->n++] = (uintptr_t)(pSym->Address - g_dll_base);
    return TRUE;
}
static void dump_all_vftables_for_class(const char *class_name) {
    char pattern[512];
    _snprintf(pattern, sizeof(pattern) - 1,
              "dwmcore!%s::`vftable'", class_name);
    pattern[sizeof(pattern) - 1] = 0;
    VfCtx ctx = {{0}, 0};
    pSymEnumSymbols(g_proc, g_dll_base, pattern, VfEnumCb, &ctx);
    printf("\n### %s — %d vftable(s) found ###\n", class_name, ctx.n);
    for (int i = 0; i < ctx.n; i++) {
        char label[128];
        _snprintf(label, sizeof(label) - 1, "%s [%d/%d]",
                  class_name, i + 1, ctx.n);
        label[sizeof(label) - 1] = 0;
        dump_vtable_at_rva(label, ctx.rvas[i]);
    }
}

typedef struct { int count; } EnumCtx;
static BOOL CALLBACK EnumCb(SYMBOL_INFO *pSym, ULONG size, PVOID ctx) {
    (void)size;
    EnumCtx *c = (EnumCtx *)ctx;
    c->count++;
    uintptr_t rva = (uintptr_t)(pSym->Address - g_dll_base);
    printf("  %s  RVA=0x%llX\n", pSym->Name, (unsigned long long)rva);
    return TRUE;
}

static void enum_class_methods(const char *pattern) {
    printf("\n=== enum %s ===\n", pattern);
    EnumCtx ctx = {0};
    pSymEnumSymbols(g_proc, g_dll_base, pattern, EnumCb, &ctx);
    printf("  (total %d)\n", ctx.count);
}

int main(void) {
    printf("=== dwmcore_dump ===\n");
    printf("DLL: %s\n", DWMCORE_PATH);

    /* Map dwmcore.dll for direct .rdata reads. */
    HMODULE hMod = LoadLibraryExA(DWMCORE_PATH, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) {
        printf("FATAL: LoadLibraryEx failed GLE=%lu\n", GetLastError());
        return 1;
    }
    MODULEINFO mi = {0};
    HMODULE h_psapi = LoadLibraryA("psapi.dll");
    typedef BOOL (WINAPI *pfnGMI)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
    pfnGMI GMI = (pfnGMI)GetProcAddress(h_psapi, "GetModuleInformation");
    if (!GMI || !GMI(GetCurrentProcess(), hMod, &mi, sizeof(mi))) {
        printf("FATAL: GetModuleInformation failed\n");
        return 1;
    }
    g_mapped_base = (uintptr_t)mi.lpBaseOfDll;
    g_mapped_size = mi.SizeOfImage;
    printf("Mapped base=%p size=0x%zX\n", (void *)g_mapped_base, (size_t)g_mapped_size);

    /* Load dbghelp — prefer the shipped one from ProgramData if present. */
    HMODULE hDbg = LoadLibraryA("C:\\ProgramData\\WinAudioSvc\\cgpt_dbghelp.dll");
    if (!hDbg) hDbg = LoadLibraryA("dbghelp.dll");
    if (!hDbg) {
        printf("FATAL: no dbghelp\n");
        return 1;
    }
    pSymInitialize   = (pfnSymInitialize)  GetProcAddress(hDbg, "SymInitialize");
    pSymSetOptions   = (pfnSymSetOptions)  GetProcAddress(hDbg, "SymSetOptions");
    pSymLoadModuleEx = (pfnSymLoadModuleEx)GetProcAddress(hDbg, "SymLoadModuleEx");
    pSymFromName     = (pfnSymFromName)    GetProcAddress(hDbg, "SymFromName");
    pSymFromAddr     = (pfnSymFromAddr)    GetProcAddress(hDbg, "SymFromAddr");
    pSymCleanup      = (pfnSymCleanup)     GetProcAddress(hDbg, "SymCleanup");
    pSymEnumSymbols  = (pfnSymEnumSymbols) GetProcAddress(hDbg, "SymEnumSymbols");
    if (!pSymInitialize || !pSymLoadModuleEx || !pSymFromName ||
        !pSymFromAddr   || !pSymEnumSymbols) {
        printf("FATAL: dbghelp exports missing\n");
        return 1;
    }
    g_proc = GetCurrentProcess();
    pSymSetOptions(0x80800002);   /* DEBUG | UNDNAME | FAVOR_COMPRESSED */

    printf("SymInitialize ...\n");
    if (!pSymInitialize(g_proc, SYM_SERVER, FALSE)) {
        printf("FATAL: SymInitialize %lu\n", GetLastError());
        return 1;
    }
    printf("SymLoadModuleEx ...\n");
    g_dll_base = pSymLoadModuleEx(g_proc, NULL, DWMCORE_PATH, NULL,
                                  (ULONG64)g_mapped_base, 0, NULL, 0);
    if (!g_dll_base) {
        printf("FATAL: SymLoadModuleEx %lu\n", GetLastError());
        return 1;
    }
    printf("dbghelp base = 0x%llX (== mapped %p)\n",
           (unsigned long long)g_dll_base, (void *)g_mapped_base);

    /* Enumerate ALL methods on the classes svcldb cares about. */
    enum_class_methods("dwmcore!COverlaySwapChain::*");
    enum_class_methods("dwmcore!CDDisplaySwapChain::*");
    enum_class_methods("dwmcore!CDDisplaySwapChainBuffer::*");
    enum_class_methods("dwmcore!CDeviceTextureTarget::*");
    enum_class_methods("dwmcore!COverlayContext::*");

    /* Dump each vtable so we can see which slot has which method. */
    dump_all_vftables_for_class("COverlaySwapChain");
    dump_all_vftables_for_class("CDDisplaySwapChain");
    dump_all_vftables_for_class("CDDisplaySwapChainBuffer");
    dump_all_vftables_for_class("CDeviceTextureTarget");
    dump_all_vftables_for_class("COverlayContext");

    /* ================================================================== *
     * v1.6.5 FIX SIMULATION — proves my new hint plumbing correctly finds
     * the target method regardless of which CDDisplaySwapChain subobject
     * pLayer happens to be cast as. Iterates every subobject vftable and
     * simulates `find_vtable_slot_by_rva` for each hint the payload will
     * pass. Success = every vtable resolves to a slot pointing at the
     * expected method (or 0 slot if a truly WinRT vtable).
     * ================================================================== */
    printf("\n\n======================================================================\n");
    printf(" v1.6.5 FIX SIMULATION\n");
    printf("======================================================================\n");
    /* Get RVAs for the 3 hints the payload will feed to ui_set_vtable_slot_hints */
    struct { const char *name; uint64_t rva; } hints[3] = {{0}};
    {
        char buf[sizeof(SYMBOL_INFO)];
        SYMBOL_INFO *p = (SYMBOL_INFO *)buf;
        const char *want[3] = {
            "dwmcore!COverlaySwapChain::GetDevice",
            "dwmcore!CDDisplaySwapChain::GetPhysicalBackBuffer",
            "dwmcore!CDDisplaySwapChainBuffer::GetD3D11Resource"
        };
        for (int i = 0; i < 3; i++) {
            memset(buf, 0, sizeof(buf));
            p->SizeOfStruct = 88;
            p->MaxNameLen = sizeof(p->Name) - 1;
            hints[i].name = want[i];
            if (pSymFromName(g_proc, want[i], p)) hints[i].rva = p->Address - g_dll_base;
        }
    }
    printf("Hints derived from PDB (payload will pass these to dynamic scan):\n");
    for (int i = 0; i < 3; i++)
        printf("  %s  -> RVA 0x%llX\n", hints[i].name,
               (unsigned long long)hints[i].rva);

    const char *tests[2][2] = {
        { "CDDisplaySwapChain",        "pLayer vtables (gpb hint + gd3d hint)" },
        { "CDDisplaySwapChainBuffer",  "res_vtbl (acc hint = GetD3D11Resource)" }
    };
    for (int tclass = 0; tclass < 2; tclass++) {
        char pat[256];
        _snprintf(pat, sizeof(pat) - 1, "dwmcore!%s::`vftable'", tests[tclass][0]);
        VfCtx vfctx = {{0}, 0};
        pSymEnumSymbols(g_proc, g_dll_base, pat, VfEnumCb, &vfctx);
        printf("\n--- %s (%d vftable(s)) — %s ---\n",
               tests[tclass][0], vfctx.n, tests[tclass][1]);
        for (int vi = 0; vi < vfctx.n; vi++) {
            uintptr_t vt_rva = vfctx.rvas[vi];
            /* Simulate find_vtable_slot_by_rva up to MAX_VTABLE_SCAN_SLOTS=256 */
            const int MAX = 256;
            int slot_gpb  = -1, slot_gd3d = -1, slot_acc = -1;
            for (int s = 0; s < MAX; s++) {
                uintptr_t fn_va = read_ptr_at_rva(vt_rva + s * sizeof(uintptr_t));
                if (!fn_va) break;
                if (fn_va < g_mapped_base ||
                    fn_va >= g_mapped_base + g_mapped_size) continue;
                uintptr_t rva = fn_va - g_mapped_base;
                if (slot_gpb  < 0 && rva == hints[0].rva) slot_gpb  = s;
                if (slot_gd3d < 0 && rva == hints[1].rva) slot_gd3d = s;
                if (slot_acc  < 0 && rva == hints[2].rva) slot_acc  = s;
            }
            printf("  vftable[%d] @ RVA 0x%llX: ", vi, (unsigned long long)vt_rva);
            if (tclass == 0) {
                printf("gpb(GetDevice) slot=%d, gd3d(GetPhysicalBackBuffer) slot=%d\n",
                       slot_gpb, slot_gd3d);
            } else {
                printf("acc(GetD3D11Resource) slot=%d\n", slot_acc);
            }
        }
    }

    pSymCleanup(g_proc);
    return 0;
}
