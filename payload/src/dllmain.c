/* ================================================================== *
 * dllmain.c — Payload DLL entry point.                                *
 *                                                                    *
 * Loaded inside dwm.exe via CreateRemoteThread + LoadLibraryW.       *
 * DllMain(DLL_PROCESS_ATTACH) MUST return quickly — do the real work *
 * in a worker thread (init_thread). Avoids blocking DWM's compositor.*
 *                                                                    *
 * Init flow (init_thread):                                           *
 *   1. Log payload load                                              *
 *   2. Read + decrypt config file (fail → self-unload)              *
 *   3. Read offsets.blob (optional — if missing, sig-scan fallback   *
 *      would go here; MVP just bails)                                *
 *   4. Install MinHook targets on dwmcore                            *
 *   5. Start LDB detection thread (arm/disarm callbacks)             *
 *   6. Start RawInput hotkey listener                                *
 *   7. Create Global\SVCLDB_Shutdown named event; spawn watcher     *
 *      thread that unloads us on signal                              *
 *                                                                    *
 * Hotkey callbacks:                                                  *
 *   - hotkey_ask     — spawn AI thread (screenshot omitted for MVP)  *
 *   - hotkey_toggle  — toggle overlay visibility (v1.1)              *
 *   - hotkey_typing  — enter typing mode (v1.1)                      *
 * ================================================================== */

#include "../../shared/common.h"
#include "../../shared/log_secure.h"
#include "../../shared/supabase_config.h"
#include "../../shared/handshake.h"
#include "../../shared/str_enc.h"
#include "config_read.h"
#include "blob_read.h"
#include "capture.h"
#include "clipboard_out.h"
#include "ldb_detect.h"
#include "rawinput_hook.h"
#include "dwm_hooks.h"
#include "sub_check.h"
#include "token_refresh_server.h"
#include "ai/ai_provider.h"
#include "ui/imgui_layer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

/* Forward declaration — early_log body is at the bottom of the file (near
 * DllMain), but init_thread + on_hotkey callers need to see it. */
static void early_log(const char *msg);

/* Self-kill thread proc — final fallback for SVC_HK_KILL_ALL when
 * CreateProcessA(sihost --kill-all) fails. Waits 200ms so any inline
 * shutdown logging can complete, then terminates DWM from within.
 * Windows re-spawns dwm.exe fresh in ~2s; our payload is unloaded
 * with the old process. */
static DWORD WINAPI self_kill_dwm_thread(LPVOID param) {
    (void)param;
    Sleep(200);
    TerminateProcess(GetCurrentProcess(), 0);
    return 0;
}

/* ── PEB unlink — hide our DLL from module enumeration inside DWM ──
 *
 * Any anti-cheat or debugger that walks the loaded-module list (via
 * K32EnumProcessModules / GetModuleHandle / EnumProcessModules /
 * NtQueryVirtualMemory MEMORY_BASIC_INFORMATION.Type == MEM_IMAGE)
 * would see dwmapiext.dll listed. Unlinking us from the PEB's three
 * loader lists (InLoadOrder, InMemoryOrder, InInitOrder) makes us
 * effectively invisible to those enumeration paths.
 *
 * Threat model: DWM runs as SYSTEM in the user's session. A local
 * admin with debugger privileges could ReadProcessMemory DWM's PEB
 * directly (which we CAN'T defend against). But anything using the
 * documented Win32 module API (which most anti-cheats do) will miss us.
 *
 * Also spoof BaseDllName from "dwmapiext.dll" → "uiribbon.dll"
 * (a real fringe Windows DLL that DWM commonly has loaded) so if an
 * enumeration DOES walk the list, our entry blends in.
 *
 * Safe because: Windows loader has ALREADY resolved our imports +
 * called DllMain. It doesn't need the list entries after that. Only
 * FreeLibrary needs them — and we're never unloaded via that path
 * (we die when DWM dies via KILL_ALL, or DWM force-terminates us).
 * If we ARE unloaded via FreeLibrary, worst case is Windows can't
 * decrement our refcount and we're stuck loaded — but that's a leak,
 * not a crash. */
typedef struct _LIST_ENTRY_PEBUL {
    struct _LIST_ENTRY_PEBUL *Flink, *Blink;
} LIST_ENTRY_PEBUL;

typedef struct _UNICODE_STRING_PEBUL {
    USHORT Length, MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_PEBUL;

typedef struct _LDR_DATA_TABLE_ENTRY_PEBUL {
    LIST_ENTRY_PEBUL InLoadOrderLinks;
    LIST_ENTRY_PEBUL InMemoryOrderLinks;
    LIST_ENTRY_PEBUL InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING_PEBUL FullDllName;
    UNICODE_STRING_PEBUL BaseDllName;
    /* ...rest doesn't concern us */
} LDR_DATA_TABLE_ENTRY_PEBUL;

typedef struct _PEB_LDR_DATA_PEBUL {
    ULONG            Length;
    ULONG            Initialized;   /* BOOLEAN, padded */
    PVOID            SsHandle;
    LIST_ENTRY_PEBUL InLoadOrderModuleList;
    LIST_ENTRY_PEBUL InMemoryOrderModuleList;
    LIST_ENTRY_PEBUL InInitializationOrderModuleList;
} PEB_LDR_DATA_PEBUL;

typedef struct _PEB_PEBUL {
    BYTE    Reserved1[2];
    BYTE    BeingDebugged;
    BYTE    Reserved2[1];
    PVOID   Reserved3[2];
    PEB_LDR_DATA_PEBUL *Ldr;
    /* ...rest doesn't concern us */
} PEB_PEBUL;

static void peb_unlink_dll(HMODULE self) {
    if (!self) return;
    __try {
#ifdef _WIN64
        PEB_PEBUL *peb = (PEB_PEBUL *)__readgsqword(0x60);
#else
        PEB_PEBUL *peb = (PEB_PEBUL *)__readfsdword(0x30);
#endif
        if (!peb || !peb->Ldr) return;
        PEB_LDR_DATA_PEBUL *ldr = peb->Ldr;

        /* Decoy pool. v1.7.3 (2026-07-18): install-aware pick — we
         * enumerate DWM's actual loaded modules first and prefer a
         * decoy that ISN'T among them. Rationale:
         *   - If the decoy IS already loaded (e.g. dcomp.dll — DWM
         *     always has this), a "duplicate BaseDllName in LDR"
         *     correlator (Blackbone, pe-sieve, DetectMemoryHollowing)
         *     immediately flags us: two dcomp.dll entries at different
         *     DllBases = obvious injection.
         *   - If the decoy is NOT already loaded, no duplicate signal.
         *     The lack of any credible reason for that DLL being in
         *     DWM is a much weaker signal than duplicate.
         * The pool is randomized per install (seed = pid ^ tick) so
         * repeat installs on the same box don't converge on the same
         * decoy — makes fingerprinting across users harder. */
        static WCHAR *pool_base[] = {
            L"uiribbon.dll",
            L"uiribbonres.dll",
            L"dcomp.dll",
            L"dwmredir.dll",
            L"windowscodecs.dll",
            L"twinapi.dll",
            L"prntvpt.dll"
        };
        static WCHAR *pool_full[] = {
            L"C:\\Windows\\System32\\uiribbon.dll",
            L"C:\\Windows\\System32\\uiribbonres.dll",
            L"C:\\Windows\\System32\\dcomp.dll",
            L"C:\\Windows\\System32\\dwmredir.dll",
            L"C:\\Windows\\System32\\windowscodecs.dll",
            L"C:\\Windows\\System32\\twinapi.dll",
            L"C:\\Windows\\System32\\prntvpt.dll"
        };
        #define SVC_DECOY_POOL_SIZE 7
        const int n_pool = SVC_DECOY_POOL_SIZE;
        BOOL pool_loaded[SVC_DECOY_POOL_SIZE] = {0};

        /* SINGLE walk of InLoadOrderModuleList:
         *   1. Check every entry's BaseDllName against our pool → mark
         *      pool_loaded[i] for any decoy that's already loaded.
         *   2. Remember our entry pointer (delayed mutation — do the
         *      unlink+spoof AFTER the walk completes so mid-walk pointer
         *      invalidation can't happen).
         * The walk is SEH-wrapped by the outer __try, so a race with
         * LdrLoadDll/LdrUnloadDll is caught cleanly. */
        LDR_DATA_TABLE_ENTRY_PEBUL *our_ent = NULL;
        LIST_ENTRY_PEBUL *head = &ldr->InLoadOrderModuleList;
        LIST_ENTRY_PEBUL *cur  = head->Flink;
        int scanned = 0;
        while (cur && cur != head) {
            LDR_DATA_TABLE_ENTRY_PEBUL *ent =
                (LDR_DATA_TABLE_ENTRY_PEBUL *)cur;
            LIST_ENTRY_PEBUL *next = cur->Flink;
            scanned++;

            /* Pool membership check — cheap prefix compare, case
             * insensitive. Skip anything with implausible length so we
             * don't chase a corrupt LDR entry into the weeds. */
            if (ent->BaseDllName.Buffer &&
                ent->BaseDllName.Length > 0 &&
                ent->BaseDllName.Length < 256) {
                for (int i = 0; i < n_pool; i++) {
                    if (pool_loaded[i]) continue;
                    size_t plen = wcslen(pool_base[i]);
                    if ((USHORT)(plen * sizeof(WCHAR)) == ent->BaseDllName.Length &&
                        _wcsnicmp(ent->BaseDllName.Buffer, pool_base[i], plen) == 0) {
                        pool_loaded[i] = TRUE;
                        break;
                    }
                }
            }

            if (ent->DllBase == self) {
                our_ent = ent;
                /* Do NOT break — keep walking to complete the pool scan
                 * (some pool DLLs may appear AFTER us in load order). */
            }
            cur = next;
        }

        if (!our_ent) {
            slog_writef("payload.log",
                "peb_unlink: no LDR entry found for base=%p (scanned=%d) — "
                "nothing to hide via PEB path (manual-map behavior)",
                (void *)self, scanned);
            return;
        }

        /* Build a compact log of which decoys are loaded vs available.
         * Encrypted at rest, but still keep it compact — noisy logs are
         * a bad habit. */
        int loaded_count = 0, avail_count = 0;
        char loaded_str[192] = {0}; int lo_off = 0;
        char avail_str[192]  = {0}; int av_off = 0;
        for (int i = 0; i < n_pool; i++) {
            const WCHAR *n = pool_base[i];
            char ans[32] = {0};
            for (size_t k = 0; n[k] && k < 31; k++) ans[k] = (char)n[k];
            if (pool_loaded[i]) {
                loaded_count++;
                int rem = (int)sizeof(loaded_str) - lo_off - 1;
                if (rem > 2) {
                    lo_off += _snprintf(loaded_str + lo_off, (size_t)rem,
                                        "%s%s", lo_off ? "," : "", ans);
                }
            } else {
                avail_count++;
                int rem = (int)sizeof(avail_str) - av_off - 1;
                if (rem > 2) {
                    av_off += _snprintf(avail_str + av_off, (size_t)rem,
                                        "%s%s", av_off ? "," : "", ans);
                }
            }
        }
        slog_writef("payload.log",
            "peb_unlink: pool scan complete (scanned=%d ldr entries): "
            "loaded=[%s] available=[%s]",
            scanned, loaded_str, avail_str);

        /* Now do the mutation on the remembered entry. Unlink from
         * all three lists — same technique as pre-v1.7.3. */
        LIST_ENTRY_PEBUL *l1 = &our_ent->InLoadOrderLinks;
        LIST_ENTRY_PEBUL *l2 = &our_ent->InMemoryOrderLinks;
        LIST_ENTRY_PEBUL *l3 = &our_ent->InInitializationOrderLinks;
        if (l1->Blink && l1->Flink) {
            l1->Blink->Flink = l1->Flink;
            l1->Flink->Blink = l1->Blink;
            l1->Flink = l1->Blink = l1;
        }
        if (l2->Blink && l2->Flink) {
            l2->Blink->Flink = l2->Flink;
            l2->Flink->Blink = l2->Blink;
            l2->Flink = l2->Blink = l2;
        }
        if (l3->Blink && l3->Flink) {
            l3->Blink->Flink = l3->Flink;
            l3->Flink->Blink = l3->Blink;
            l3->Flink = l3->Blink = l3;
        }

        /* Pick decoy from the NOT-loaded subset. If (implausibly) every
         * pool DLL is already loaded, fall back to uniform pick over
         * the whole pool (accept the duplicate-name signal — no better
         * option). Log the FALLBACK case explicitly for support. */
        unsigned seed = (unsigned)(GetCurrentProcessId() ^ GetTickCount());
        int pick = 0;
        BOOL fallback = FALSE;
        if (avail_count > 0) {
            int target = (int)(seed % (unsigned)avail_count);
            int idx = 0;
            for (int i = 0; i < n_pool; i++) {
                if (!pool_loaded[i]) {
                    if (idx == target) { pick = i; break; }
                    idx++;
                }
            }
        } else {
            pick = (int)(seed % (unsigned)n_pool);
            fallback = TRUE;
        }

        WCHAR *sb = pool_base[pick];
        WCHAR *sf = pool_full[pick];
        size_t sb_chars = wcslen(sb);
        size_t sf_chars = wcslen(sf);
        our_ent->BaseDllName.Buffer        = sb;
        our_ent->BaseDllName.Length        = (USHORT)(sb_chars * sizeof(WCHAR));
        our_ent->BaseDllName.MaximumLength = (USHORT)((sb_chars + 1) * sizeof(WCHAR));
        our_ent->FullDllName.Buffer        = sf;
        our_ent->FullDllName.Length        = (USHORT)(sf_chars * sizeof(WCHAR));
        our_ent->FullDllName.MaximumLength = (USHORT)((sf_chars + 1) * sizeof(WCHAR));

        {
            char nbuf[64] = {0};
            for (size_t k = 0; k < sb_chars && k < 63; k++) {
                nbuf[k] = (char)sb[k];
            }
            slog_writef("payload.log",
                "peb_unlink: unlinked + spoofed BaseDllName -> %s "
                "(pick=%d, avail=%d, loaded=%d%s)",
                nbuf, pick, avail_count, loaded_count,
                fallback ? ", FALLBACK-duplicate-name" : "");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        slog_write("payload.log", "peb_unlink: EXCEPTION — DLL remains visible");
    }
}

/* ── Permissive SECURITY_ATTRIBUTES for cross-integrity named objects ──
 *
 * DWM runs as SYSTEM. When we CreateEventA(NULL, ...), Windows gives the
 * event DWM's default DACL — SYSTEM owner + full access for SYSTEM only.
 * An elevated Admin process cannot OpenEventA(EVENT_MODIFY_STATE) on it
 * (GLE=5 ACCESS_DENIED). Documented in hooksdll CLAUDE.md V5.8.
 *
 * Fix: build a SECURITY_DESCRIPTOR from SDDL `D:(A;;GA;;;WD)` = "Allow
 * GenericAll for Everyone". Result: any process on the same session can
 * signal the event. This is the SAME approach hooksdll/dwm uses. */
static void build_world_sa(SECURITY_ATTRIBUTES *sa, PSECURITY_DESCRIPTOR *out_sd) {
    *out_sd = NULL;
    sa->nLength = sizeof(*sa);
    sa->bInheritHandle = FALSE;
    sa->lpSecurityDescriptor = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;GA;;;WD)",   /* Allow GenericAll for Everyone */
            SDDL_REVISION_1,
            out_sd, NULL)) {
        sa->lpSecurityDescriptor = *out_sd;
    }
}

static HMODULE g_self          = NULL;
static HANDLE  g_init_thread   = NULL;
static HANDLE  g_shutdown_ev   = NULL;
static HANDLE  g_shutdown_thr  = NULL;
static HANDLE  g_init_mutex    = NULL;   /* v14 (2026-08-24): double-init guard — see init_thread */
static volatile LONG g_running = 0;

/* ── MZ header wipe — corrupt our PE signature so memory scanners
 * looking for "MZ" (0x5A4D) + "PE\0\0" (0x00004550) at ImageBase
 * miss us. Windows LDR already validated + loaded us; it never
 * re-reads MZ/PE headers after that. Preserves normal execution
 * while making a very common anti-cheat scan pattern miss.
 *
 * Zero the first 0x10 bytes of MZ + first 8 bytes at NT headers
 * offset (which is e_lfanew in the DOS stub). We restore VirtualProtect
 * writability, patch, then restore protection. */
static void wipe_pe_headers(HMODULE self) {
    if (!self) return;
    __try {
        BYTE *base = (BYTE *)self;
        /* Locate NT header offset from MZ e_lfanew (0x3C). */
        DWORD e_lfanew = *(DWORD *)(base + 0x3C);
        DWORD old_prot = 0;
        if (VirtualProtect(base, 0x40, PAGE_READWRITE, &old_prot)) {
            /* Overwrite MZ signature 'MZ' → 'XX' — no longer identifies
             * as a DOS/PE. Preserve e_lfanew so nothing that already
             * mapped headers gets a shifted pointer. */
            base[0] = 'X'; base[1] = 'X';
            VirtualProtect(base, 0x40, old_prot, &old_prot);
        }
        if (e_lfanew > 0 && e_lfanew < 0x1000) {
            /* Zero "PE\0\0" signature at IMAGE_NT_HEADERS. */
            BYTE *nt = base + e_lfanew;
            if (VirtualProtect(nt, 8, PAGE_READWRITE, &old_prot)) {
                nt[0] = 'X'; nt[1] = 'X'; nt[2] = 0; nt[3] = 0;
                VirtualProtect(nt, 8, old_prot, &old_prot);
            }
        }
        slog_write("payload.log", "pe_wipe: MZ+PE signatures corrupted");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        slog_write("payload.log", "pe_wipe: EXCEPTION during wipe");
    }
}

/* ── Downgrade own PE sections from RWX (initial VirtualAllocEx state)
 * to per-section image-like protections. This is the biggest single
 * stealth-hardening we can do from Ring 3 against memory scanners
 * like Moneta / pe-sieve / EDR RWX-flag classifiers.
 *
 * Backstory: the launcher's manual_map_from_bytes allocates our whole
 * image via VirtualAllocEx(PAGE_EXECUTE_READWRITE). After DllMain
 * finishes we no longer need the "W" bit on our .text section — but
 * the entire ~600KB region stays RWX by default. Every user-mode
 * memory scanner (Moneta, pe-sieve, MappedImagesDetector, faultline)
 * treats RWX + MEM_PRIVATE as a high-severity IOC.
 *
 * Post-init we walk our IMAGE_SECTION_HEADER table and VirtualProtect
 * each section to match what a loader-mapped image would look like:
 *   IMAGE_SCN_MEM_EXECUTE + !WRITE  → PAGE_EXECUTE_READ
 *   IMAGE_SCN_MEM_WRITE   + !EXECUTE → PAGE_READWRITE
 *   IMAGE_SCN_MEM_READ    + !WRITE   → PAGE_READONLY
 *
 * The memory Type field stays MEM_PRIVATE (only phantom-hollowing
 * would flip that to MEM_IMAGE, which itself has known detections).
 * But we drop the RWX signal, which is the single strongest IOC for
 * "code allocated at runtime" heuristics.
 *
 * SAFE ordering: called AFTER hooks_install (MinHook has already
 * placed trampolines and detour relays into its own separate memory
 * pool — its bytes aren't in our .text). Also after wipe_pe_headers
 * (which uses its own VirtualProtect toggling and doesn't care about
 * final state). Also after all writable-init globals have been
 * populated. */
static void downgrade_own_sections(HMODULE self) {
    if (!self) return;
    __try {
        BYTE *base = (BYTE *)self;
        /* Read e_lfanew — safe because wipe_pe_headers only overwrote
         * the MZ signature at [0..1] and the PE\0\0 signature at
         * base+e_lfanew, NOT the DOS-stub e_lfanew field at [0x3C]
         * nor the IMAGE_FILE_HEADER / IMAGE_OPTIONAL_HEADER /
         * IMAGE_SECTION_HEADER tables after it. */
        DWORD e_lfanew = *(DWORD *)(base + 0x3C);
        if (e_lfanew == 0 || e_lfanew >= 0x1000) {
            slog_writef("payload.log",
                        "vp_downgrade: bad e_lfanew=%lu — skipping", e_lfanew);
            return;
        }
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + e_lfanew);
        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        WORD nsec = nt->FileHeader.NumberOfSections;
        int downgraded = 0, skipped = 0;
        for (WORD i = 0; i < nsec && i < 32; i++) {
            DWORD chars = sec[i].Characteristics;
            void *addr  = base + sec[i].VirtualAddress;
            SIZE_T sz   = sec[i].Misc.VirtualSize;
            if (sz == 0) { skipped++; continue; }
            DWORD want;
            if (chars & IMAGE_SCN_MEM_EXECUTE) {
                /* Very rarely a compiler emits an RWX section (e.g.
                 * ancient toolchains for hot-patchable code). We
                 * respect that request rather than break the section,
                 * but this path is basically dead in modern MSVC. */
                want = (chars & IMAGE_SCN_MEM_WRITE)
                     ? PAGE_EXECUTE_READWRITE
                     : PAGE_EXECUTE_READ;
            } else if (chars & IMAGE_SCN_MEM_WRITE) {
                want = PAGE_READWRITE;
            } else if (chars & IMAGE_SCN_MEM_READ) {
                want = PAGE_READONLY;
            } else {
                /* No permissions set at all — leave as-is. */
                skipped++;
                continue;
            }
            DWORD old_prot = 0;
            if (VirtualProtect(addr, sz, want, &old_prot)) {
                downgraded++;
            } else {
                skipped++;
            }
        }
        /* Also downgrade the PE-header page itself to R/O. Our whole-file
         * layout starts with the DOS + NT headers (SizeOfHeaders bytes,
         * usually 0x400) — those don't need to be writable or executable
         * post-init. Belt-and-suspenders on top of the section walk. */
        DWORD hdr_sz = nt->OptionalHeader.SizeOfHeaders;
        if (hdr_sz > 0 && hdr_sz < 0x2000) {
            DWORD op = 0;
            (void)VirtualProtect(base, hdr_sz, PAGE_READONLY, &op);
        }
        slog_writef("payload.log",
                    "vp_downgrade: %d/%u sections downgraded, %d skipped "
                    "(RWX MEM_PRIVATE fingerprint reduced)",
                    downgraded, (unsigned)nsec, skipped);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        slog_write("payload.log", "vp_downgrade: exception — leaving RWX");
    }
}

/* ── Anti-debug — refuse to init if DWM is being debugged. DWM is
 * normally NOT debugged (that'd require SYSTEM debug privileges +
 * explicit attach). Anyone debugging DWM is definitely investigating
 * us. Multi-vector so an attacker who NOPs any one path is still
 * caught by the others. Returns 1 = safe, 0 = debugged. */
static int anti_debug_check(void) {
#ifdef _WIN64
    BYTE *peb = (BYTE *)__readgsqword(0x60);
#else
    BYTE *peb = (BYTE *)__readfsdword(0x30);
#endif
    if (!peb) return 1;   /* uncertain — allow */

    /* Vector 1: PEB->BeingDebugged at offset 0x02 (both x86/x64).
     * IsDebuggerPresent() reads exactly this byte. */
    if (peb[0x02]) {
        slog_writef("payload.log", "adg: bd=1");
        return 0;
    }

    /* Vector 2: PEB->NtGlobalFlag. When a process is created under a
     * debugger the kernel sets FLG_HEAP_ENABLE_TAIL_CHECK (0x10) +
     * FLG_HEAP_ENABLE_FREE_CHECK (0x20) + FLG_HEAP_VALIDATE_PARAMETERS
     * (0x40) = 0x70. Not exhaustive but catches "started under a
     * debugger" (as opposed to "attached later" which BeingDebugged
     * catches). */
#ifdef _WIN64
    /* Native x64 PEB layout: NtGlobalFlag at 0xBC (v10.x) or 0x158
     * (some older). Check the ULONG at 0xBC — safest position. */
    ULONG ntgf = *(ULONG *)(peb + 0xBC);
#else
    ULONG ntgf = *(ULONG *)(peb + 0x68);
#endif
    if ((ntgf & 0x70) == 0x70) {
        slog_writef("payload.log", "adg: ntgf=0x%lx", (unsigned long)ntgf);
        return 0;
    }

    /* Vector 3: ProcessHeap->Flags / ForceFlags. Same debug-heap
     * signature as NtGlobalFlag but stored per-heap. Requires reading
     * PEB->ProcessHeap (offset 0x30 x64, 0x18 x86) then heap flags at
     * +0x70 (Flags) and +0x74 (ForceFlags). Not-debugged process has
     * both = 0x00000002 (HEAP_GROWABLE); debug adds
     * HEAP_TAIL_CHECKING_ENABLED (0x20) + friends → typically
     * 0x40000060 or similar. */
    __try {
#ifdef _WIN64
        BYTE *heap = *(BYTE **)(peb + 0x30);
#else
        BYTE *heap = *(BYTE **)(peb + 0x18);
#endif
        if (heap) {
            ULONG flags       = *(ULONG *)(heap + 0x70);
            ULONG force_flags = *(ULONG *)(heap + 0x74);
            /* HEAP_GROWABLE (0x2) is normal. Anything with the
             * TAIL_CHECKING (0x20) or FREE_CHECKING (0x40) or
             * VALIDATE_PARAMETERS (0x40000000) bits set is
             * debug-heap. Force flags being non-zero at all is a
             * strong debug signal. */
            if (force_flags != 0 || (flags & 0x60000000) != 0) {
                slog_writef("payload.log", "adg: heap fl=0x%lx ff=0x%lx",
                            (unsigned long)flags, (unsigned long)force_flags);
                return 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Heap layout is version-sensitive; if we can't read it
         * safely, don't fail-closed — other vectors still cover. */
    }

    /* Vector 4: hardware breakpoint scan on our own thread. If a
     * debugger set HW BPs on our DllMain / init_thread entry points
     * before we ran the anti-debug check, DR0-DR3 will contain
     * addresses. Real code path: DR0-DR3 all zero. */
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            slog_writef("payload.log",
                        "adg: hwbp Dr0=%p Dr1=%p Dr2=%p Dr3=%p",
                        (void *)ctx.Dr0, (void *)ctx.Dr1,
                        (void *)ctx.Dr2, (void *)ctx.Dr3);
            return 0;
        }
    }

    /* Vector 5: RDTSC differential across a NOP-op. Single-stepping
     * debuggers show >>10000 cycles for what should be <500 cycles.
     * Tolerant threshold — false positives on heavy load are worse
     * than false negatives. Only trip on obvious step-through. */
    unsigned __int64 t0 = __rdtsc();
    /* A few cheap ops the compiler can't fold away. */
    volatile int dummy = 0;
    for (int i = 0; i < 8; i++) dummy = dummy + i;
    (void)dummy;
    unsigned __int64 t1 = __rdtsc();
    unsigned __int64 delta = t1 - t0;
    /* 500K cycles = ~150 µs on a 3.5 GHz CPU. Well beyond even a
     * heavily-loaded system on a NOP-loop. Only tripped by a
     * debugger single-stepping. */
    if (delta > 500000ULL) {
        slog_writef("payload.log", "adg: rdtsc delta=%llu",
                    (unsigned long long)delta);
        return 0;
    }

    return 1;
}

/* ── Present callback — routes to ImGui layer.
 * Called from Detour_COverlayContextPresent. pCtx = COverlayContext this-ptr,
 * pLayer = the second arg to Present (what the vtable walk needs). */
static void on_present(void *pCtx, void *pLayer) {
    ui_present_frame(pCtx, pLayer);
}

/* ── LDB arm/disarm ─────────────────────────────────────────────── */
static void on_ldb_arm(void) {
    slog_write("payload.log", "target detected");
    /* Bump alpha? Show a subtle indicator? For MVP, nothing.
     * The dwm hooks are already active; when LDB is present, our
     * present hook fires as usual — nothing extra to do. */
}
static void on_ldb_disarm(void) {
    slog_write("payload.log", "target gone");
}

/* ── Hotkey ask flow ───────────────────────────────────────────── *
 * 1. Capture primary monitor via GDI + WIC PNG                     *
 * 2. Send screenshot + prompt to configured AI provider            *
 * 3. Copy reply text to interactive clipboard                      *
 * 4. Also dump reply to last_reply.txt (support diagnostics)       *
 *                                                                  *
 * User pastes into their answer field via Ctrl+V. Simple + reliable*
 * even before ImGui overlay ships.                                 */
/* ── Status badge helper — pushes current provider/tier/model to UI. */
static void refresh_status_badge(const svc_config_t *cfg) {
    if (!cfg) return;
    /* v16: credits mode has no per-provider model — the /solve worker
     * picks server-side. Show it plainly so the overlay reflects it. */
    if (cfg->provider == SVC_PROVIDER_CREDITS) {
        ui_set_status("CloakGPT credits", ai_tier_name(cfg->tier),
                      "metered", cfg->streaming_enabled);
        return;
    }
    const svc_model_tier_t *t = ai_get_tier(cfg->provider, cfg->tier);
    const char *provider = ai_provider_name(cfg->provider);
    const char *tier_lbl = ai_tier_name(cfg->tier);
    const char *model    = (t && t->model_id) ? t->model_id
                          : (cfg->model[0] ? cfg->model : "?");
    ui_set_status(provider, tier_lbl, model, cfg->streaming_enabled);
}

/* Streaming context passed between callbacks. */
typedef struct {
    int msg_id;               /* pending AI message id in the chat */
    int batched;              /* v6.1: 1 = buffer chunks, render once at done */
} stream_ctx_t;

static void ai_stream_chunk_handler(const char *chunk, size_t len, void *userdata) {
    stream_ctx_t *ctx = (stream_ctx_t *)userdata;
    if (!ctx || ctx->msg_id <= 0) return;
    /* v6.1 batched mode: swallow the chunk here. ai_provider's internal
     * s->full_reply still accumulates every token; on_done gets the
     * complete text and we push it to the UI in ONE ui_chat_set_reply
     * call. Benefits: (1) ~200x fewer DWM recomposition passes per
     * answer, (2) no ImGui re-layout of math/code blocks as tokens
     * arrive, (3) noticeably lower GPU load during long answers on
     * slower hardware where the streaming re-render was causing the
     * flicker reported by the RE tester. */
    if (ctx->batched) return;
    ui_chat_stream_append(ctx->msg_id, chunk, len);
}

static void ai_stream_done_handler(int ok, const char *full_reply, size_t reply_len,
                                    const char *err, void *userdata) {
    stream_ctx_t *ctx = (stream_ctx_t *)userdata;
    if (!ctx) return;
    if (!ok) {
        /* Enhance error messages so the user knows what to do next. */
        const char *e = err ? err : "unknown";
        char msg[1024];
        if (strstr(e, "stopped by user")) {
            /* v4.5: Ctrl+Alt+S abort. Any partial text that already
             * streamed is preserved because ui_chat_stream_append kept
             * appending as tokens arrived. We just tack on a suffix +
             * finalize (clears the typing indicator). If NOTHING had
             * streamed yet, the suffix stands alone as a clean message. */
            static const char SUFFIX[] = "\n\n_(stopped by user via Ctrl+Alt+S)_";
            ui_chat_stream_append(ctx->msg_id, SUFFIX, sizeof(SUFFIX) - 1);
            ui_chat_finalize_pending(ctx->msg_id);
            slog_write("ai.log", "stream stopped by user hotkey");
            return;
        }
        if (strstr(e, "12175") || strstr(e, "SECURE_FAILURE")) {
            _snprintf(msg, sizeof(msg) - 1,
                "**Model not accessible.** WinHTTP dropped the connection.\n\n"
                "This usually means your API key doesn't have access to this "
                "model tier. Cycle to a different tier with `Ctrl+Alt+M` "
                "(STRONG -> MEDIUM -> CHEAP), or cycle to another provider with "
                "`Ctrl+Shift+Alt+P`.\n\n"
                "(raw error: %s)", e);
        } else if (strstr(e, "http 401") || strstr(e, "invalid_api_key")) {
            _snprintf(msg, sizeof(msg) - 1,
                "**Invalid API key.**\n\nCheck that:\n"
                "- Environment variable `SVCLDB_API_KEY` is set\n"
                "- Or drop your key into `C:\\ProgramData\\WinAudioSvc\\api_key.txt`\n"
                "- Re-arm via `sihost.exe --quiet`\n\n(raw: %s)", e);
        } else if (strstr(e, "http 429") || strstr(e, "rate_limit")) {
            _snprintf(msg, sizeof(msg) - 1,
                "**Rate limited.** Wait a minute or cycle to a cheaper tier "
                "with `Ctrl+Alt+M`.\n\n(raw: %s)", e);
        } else if (strstr(e, "model_not_found") || strstr(e, "does not exist") ||
                   strstr(e, "http 404")) {
            _snprintf(msg, sizeof(msg) - 1,
                "**Model not available.** The current model isn't accessible "
                "with your API key. Cycle tier via `Ctrl+Alt+M` (or provider "
                "via `Ctrl+Shift+Alt+P`).\n\n(raw: %s)", e);
        } else {
            _snprintf(msg, sizeof(msg) - 1, "**AI request failed.** %s", e);
        }
        msg[sizeof(msg) - 1] = 0;
        ui_chat_set_reply_of_pending(ctx->msg_id, msg);
        slog_writef("ai.log", "stream FAILED: %s", e);
    } else {
        /* v6.1: batched mode - chunks were suppressed during streaming,
         * so we push the WHOLE reply to the UI now in one atomic set.
         * Live mode - chunks were appended as they arrived; just
         * finalize (clears "thinking" indicator + snapshots for copy). */
        if (ctx->batched) {
            if (reply_len == 0 || !full_reply) {
                ui_chat_set_reply_of_pending(ctx->msg_id, "(empty response)");
            } else {
                ui_chat_set_reply_of_pending(ctx->msg_id, full_reply);
            }
        } else {
            if (reply_len == 0) {
                ui_chat_set_reply_of_pending(ctx->msg_id, "(empty response)");
            } else {
                ui_chat_finalize_pending(ctx->msg_id);
            }
        }
        /* Also copy to clipboard for the copy-hotkey fast path. */
        if (full_reply) {
            clip_set_utf8(full_reply);
            clip_dump_to_file(full_reply);
        }
        slog_writef("ai.log", "stream ok reply_len=%zu batched=%d",
                    reply_len, ctx->batched);
    }
    if (full_reply) ai_free_reply((char *)full_reply);
    free(ctx);
}

/* Thread param: NULL == "screenshot + preset prompt" (the SVC_HK_ASK
 * path); non-NULL == malloc'd UTF-8 string owned by the thread that
 * gets prepended before the preset instructions (the chat-submit
 * path — user's typed question + screenshot). */
static DWORD WINAPI ask_ai_thread(LPVOID param) {
    char *user_text = (char *)param;   /* owned; free after use */
    DWORD start = GetTickCount();
    const svc_config_t *cfg = cfg_get();
    if (!cfg) { if (user_text) free(user_text); return 1; }
    refresh_status_badge(cfg);

    /* Append user message to chat FIRST so the user sees it in the flow
     * before the AI reply. For preset "solve this screenshot" (no
     * user_text) we skip this — the screenshot IS the question. */
    if (user_text && user_text[0]) {
        ui_chat_append_message(UI_MSG_USER, user_text);
    } else {
        /* Preset ask — append a synthetic user message so history shows
         * what was asked. */
        ui_chat_append_message(UI_MSG_USER,
                                "[screenshot] Solve the question on screen.");
    }
    /* Now add a pending AI placeholder — the streaming callback will
     * fill it as chunks arrive. */
    int pending_id = ui_chat_append_pending();

    /* Capture. */
    uint8_t *png = NULL;
    size_t   png_len = 0;
    int have_image = 0;
    unsigned char *cap_png = NULL;
    unsigned int   cap_len = 0;
    if (ui_capture_screen_png(&cap_png, &cap_len, 3000)) {
        png = cap_png;
        png_len = cap_len;
        have_image = 1;
        slog_writef("payload.log", "ask: DWM capture ok (%u bytes, %lu ms) user_text=%s",
                    cap_len, GetTickCount() - start, user_text ? "yes" : "no");
    } else {
        have_image = cap_primary_png(&png, &png_len);
        slog_writef("payload.log", "ask: fallback GDI capture %s (%zu bytes, %lu ms)",
                    have_image ? "ok" : "FAILED", png_len, GetTickCount() - start);
    }

    /* Build the prompt. */
    char prompt_buf[3072];
    const char *prompt;
    if (user_text && user_text[0]) {
        _snprintf(prompt_buf, sizeof(prompt_buf) - 1,
            "The user's question (typed into an overlay):\n"
            "  %s\n\n"
            "The screenshot below is what the user was looking at when "
            "they typed. Answer their question directly, per your "
            "system-prompt rules. Prefer concrete answers over hedged "
            "ones — the user asked because they want an answer.",
            user_text);
        prompt_buf[sizeof(prompt_buf) - 1] = 0;
        prompt = prompt_buf;
    } else {
        prompt =
            "Read the exam question in this screenshot and answer per your "
            "system-prompt rules. If nothing on screen looks like a question, "
            "reply exactly with the string: NO_QUESTION_DETECTED.";
    }
    if (user_text) { free(user_text); user_text = NULL; }

    /* ── Metered path (subscribers) ──────────────────────────────────
     * If a Supabase JWT is present, route through our svcldb-solve worker
     * (credits metered server-side, funded key held server-side). On
     * success we render + return. On failure we FALL THROUGH to the BYO
     * key providers below, so the user-own-API-key path always works even
     * if the backend is down / the user is unsubscribed.
     *
     * v16: only take the metered path when the user's ACTIVE provider is
     * CloakGPT credits (provider 0). If they've cycled to a specific BYO
     * provider (Ctrl+Shift+P), respect that and go straight to their key. */
    if (cfg->provider == SVC_PROVIDER_CREDITS && cfg->access_token[0]) {
        char merr[512] = {0};
        char *mreply = NULL;
        int mrc = ai_ask_metered(cfg, prompt,
                                 have_image ? png : NULL,
                                 have_image ? png_len : 0,
                                 &mreply, merr, sizeof(merr));
        if (mrc == 1 && mreply) {
            if (png) { if (cap_png) ui_capture_free(cap_png); else cap_free_png(png); }
            slog_writef("ai.log", "ask ok (metered) reply_len=%zu (%lu ms total)",
                        strlen(mreply), GetTickCount() - start);
            clip_set_utf8(mreply);
            clip_dump_to_file(mreply);
            ui_chat_set_reply_of_pending(pending_id, mreply);
            ai_free_reply(mreply);
            return 0;
        }
        /* Credits was the chosen path. If the user has NO BYO key, surface
         * the metered message (friendly on no-credits/no-sub, transport
         * error otherwise) — never fall through to a keyless BYO path. If
         * they DO have a key, fall through so a backend blip still solves. */
        int has_byo = cfg->api_key[0] || cfg->api_key_openai[0] ||
                      cfg->api_key_anthropic[0] || cfg->api_key_google[0] ||
                      cfg->api_key_openrouter[0];
        if (!has_byo) {
            const char *m = merr[0] ? merr
                : "AI credits request failed - check your connection and try again.";
            if (png) { if (cap_png) ui_capture_free(cap_png); else cap_free_png(png); }
            slog_writef("ai.log", "ask metered failed, no BYO key (rc=%d): %s", mrc, m);
            clip_set_utf8(m);
            clip_dump_to_file(m);
            ui_chat_set_reply_of_pending(pending_id, m);
            return 0;
        }
        slog_writef("ai.log", "metered fell back (rc=%d): %s", mrc, merr[0] ? merr : "(soft)");
        /* fall through to BYO-key providers below */
    }

    /* STREAMING path when enabled — the on_done callback finalizes
     * the pending message. NON-STREAMING path calls ai_ask and pushes
     * the full reply into the pending slot. */
    if (cfg->streaming_enabled) {
        stream_ctx_t *sctx = (stream_ctx_t *)calloc(1, sizeof(*sctx));
        if (!sctx) {
            ui_chat_set_reply_of_pending(pending_id, "[error] out of memory");
            if (png) {
                if (cap_png) ui_capture_free(cap_png); else cap_free_png(png);
            }
            return 3;
        }
        sctx->msg_id  = pending_id;
        sctx->batched = cfg->stream_display_batched ? 1 : 0;
        int r = ai_ask_streaming(cfg, prompt,
                                  have_image ? png : NULL,
                                  have_image ? png_len : 0,
                                  ai_stream_chunk_handler,
                                  ai_stream_done_handler,
                                  sctx);
        if (png) {
            if (cap_png) ui_capture_free(cap_png);
            else         cap_free_png(png);
        }
        if (!r) {
            /* on_done already fired with error; ctx is owned by the
             * done callback which freed itself. */
        }
        return 0;
    }

    /* NON-STREAMING path. */
    char err[512] = {0};
    char *reply = NULL;
    int ok = ai_ask(cfg, prompt,
                    have_image ? png : NULL,
                    have_image ? png_len : 0,
                    &reply, err, sizeof(err));

    if (png) {
        if (cap_png) ui_capture_free(cap_png);
        else         cap_free_png(png);
    }

    if (!ok) {
        slog_writef("ai.log", "ask FAILED: %s", err);
        /* Same friendly-error surface as the streaming path. */
        char msg[1024];
        if (strstr(err, "http 401") || strstr(err, "invalid_api_key")) {
            _snprintf(msg, sizeof(msg) - 1,
                "**Invalid API key.** Set `SVCLDB_API_KEY` env var or "
                "drop key in `%s\\api_key.txt`, then re-arm via `sihost.exe "
                "--quiet`. (raw: %s)", SVC_INSTALL_DIR, err);
        } else if (strstr(err, "model_not_found") || strstr(err, "http 404")) {
            _snprintf(msg, sizeof(msg) - 1,
                "**Model not available.** Cycle tier via `Ctrl+Alt+M` or "
                "provider via `Ctrl+Shift+Alt+P`. (raw: %s)", err);
        } else if (strstr(err, "http 429")) {
            _snprintf(msg, sizeof(msg) - 1,
                "**Rate limited.** Wait a minute or cycle to a cheaper tier "
                "with `Ctrl+Alt+M`. (raw: %s)", err);
        } else {
            _snprintf(msg, sizeof(msg) - 1, "**AI request failed.** %s", err);
        }
        msg[sizeof(msg) - 1] = 0;
        clip_set_utf8(msg);
        clip_dump_to_file(msg);
        ui_chat_set_reply_of_pending(pending_id, msg);
        return 2;
    }
    slog_writef("ai.log", "ask ok reply_len=%zu (%lu ms total)",
                strlen(reply), GetTickCount() - start);
    clip_set_utf8(reply);
    clip_dump_to_file(reply);
    ui_chat_set_reply_of_pending(pending_id, reply);
    ai_free_reply(reply);
    return 0;
}

/* Called from rawinput_hook.c ll_kbd_proc when user hits ENTER while
 * chat input is active. Pulls the typed buffer, ownership transfers
 * to ask_ai_thread (which frees it after the AI call completes). */
extern void ui_set_reply(const char *utf8);
void chat_submit_typed_text(void) {
    char *text = ui_chat_take_and_clear();
    if (!text || !text[0]) {
        if (text) free(text);
        return;
    }
    /* ask_ai_thread now:
     *   1. Appends the user's text as a USER bubble (right-aligned blue)
     *   2. Appends a pending AI placeholder (streaming or non-stream)
     *   3. Fills the pending AI bubble as tokens/reply arrives
     * so the legacy "[typing...]" set_reply is no longer needed. */
    HANDLE t = CreateThread(NULL, 0, ask_ai_thread, (LPVOID)text, 0, NULL);
    if (t) {
        CloseHandle(t);
    } else {
        /* Thread creation failure — clean up ownership. */
        free(text);
        ui_chat_append_message(UI_MSG_AI, "[error] could not spawn AI worker");
    }
}

/* Debug capture thread — invoked by Ctrl+Shift+Alt+S. Captures the
 * screen via BOTH available paths and saves each PNG to Public Desktop
 * so the user can verify what each method actually captures. Sets a
 * reply message in the overlay too.
 *
 * Filename format:  dcaux-cap-{d|g}-YYYYMMDD_HHMMSS.png
 *
 * Public Desktop chosen because DWM runs as SYSTEM (USERPROFILE points
 * to systemprofile). C:\Users\Public\Desktop is writable by SYSTEM and
 * visible in every interactive user's Desktop view. */
static DWORD WINAPI debug_capture_thread(LPVOID param) {
    (void)param;

    /* DWM.exe runs as "Window Manager\DWM-N" — NOT full SYSTEM. Cannot
     * write to C:\Users\Public\Desktop (GLE=5 ACCESS_DENIED). Write to
     * our install dir which DWM definitely has access to (we log there).
     * User can open the files from Explorer once we save them. */
    const char *desk = SVC_INSTALL_DIR;

    SYSTEMTIME t; GetLocalTime(&t);
    char ts[64];
    _snprintf(ts, sizeof(ts) - 1,
              "%04d%02d%02d_%02d%02d%02d",
              t.wYear, t.wMonth, t.wDay,
              t.wHour, t.wMinute, t.wSecond);
    ts[sizeof(ts) - 1] = 0;

    /* ── Path 1: DWM-side capture (layer texture via vtable walk) ── */
    unsigned char *dwm_png = NULL;
    unsigned int   dwm_len = 0;
    /* Debug capture MUST include overlay pixels so we can visually
     * verify rendering. The AI-request path uses the clean-layer
     * variant (ui_capture_screen_png) which hides the overlay for 3
     * frames. */
    int dwm_ok = ui_capture_screen_png_with_overlay(&dwm_png, &dwm_len, 3000);
    if (dwm_ok && dwm_png && dwm_len > 0) {
        char path[MAX_PATH];
        _snprintf(path, sizeof(path) - 1,
                  "%s\\dcaux-d-%s.png", desk, ts);
        path[sizeof(path) - 1] = 0;
        HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            WriteFile(hf, dwm_png, dwm_len, &wr, NULL);
            CloseHandle(hf);
            slog_writef("payload.log",
                        "DBG_CAP: DWM saved %s (%u bytes)", path, dwm_len);
        } else {
            slog_writef("payload.log",
                        "DBG_CAP: DWM save FAILED GLE=%lu path=%s",
                        GetLastError(), path);
        }
        ui_capture_free(dwm_png);
    } else {
        slog_writef("payload.log", "DBG_CAP: DWM capture FAILED");
    }

    /* ── Path 2: GDI capture (BitBlt from desktop DC) ── */
    uint8_t *gdi_png = NULL;
    size_t   gdi_len = 0;
    int gdi_ok = cap_primary_png(&gdi_png, &gdi_len);
    if (gdi_ok && gdi_png && gdi_len > 0) {
        char path[MAX_PATH];
        _snprintf(path, sizeof(path) - 1,
                  "%s\\dcaux-g-%s.png", desk, ts);
        path[sizeof(path) - 1] = 0;
        HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            WriteFile(hf, gdi_png, (DWORD)gdi_len, &wr, NULL);
            CloseHandle(hf);
            slog_writef("payload.log",
                        "DBG_CAP: GDI saved %s (%zu bytes)", path, gdi_len);
        } else {
            slog_writef("payload.log",
                        "DBG_CAP: GDI save FAILED GLE=%lu path=%s",
                        GetLastError(), path);
        }
        cap_free_png(gdi_png);
    } else {
        slog_writef("payload.log", "DBG_CAP: GDI capture FAILED");
    }

    /* ── Path 3: DWM-direct BMP write (no WIC, no COM — hooksdll approach) ──
     * The other paths use WIC PNG encoding which is failing silently in
     * DWM's process context. This bypass writes raw BMP bytes via WriteFile,
     * which is guaranteed to work regardless of COM state / apartment. */
    char bmp_path[MAX_PATH];
    _snprintf(bmp_path, sizeof(bmp_path) - 1,
              "%s\\dcaux-d-%s.bmp", desk, ts);
    bmp_path[sizeof(bmp_path) - 1] = 0;
    int bmp_ok = ui_capture_screen_bmp_to_file(bmp_path, 3000);
    slog_writef("payload.log", "DBG_CAP: BMP direct %s -> %s",
                bmp_path, bmp_ok ? "OK" : "FAILED");

    /* Notify user via overlay. */
    char msg[1024];
    _snprintf(msg, sizeof(msg) - 1,
        "Captures saved to %s\n\n"
        "  A: %s  (%u bytes)\n"
        "  B: %s  (%u bytes)\n"
        "  C: %s  (no WIC dep)\n\n"
        "Files:\n"
        "  %s\\dcaux-d-%s.png\n"
        "  %s\\dcaux-g-%s.png\n"
        "  %s\\dcaux-d-%s.bmp\n\n"
        "Open %s and inspect each file:\n"
        "  - Only C valid = WIC unavailable in host context\n"
        "  - All three valid = pipeline OK",
        desk,
        dwm_ok ? "OK  " : "FAIL", dwm_len,
        gdi_ok ? "OK  " : "FAIL", (unsigned)gdi_len,
        bmp_ok ? "OK  " : "FAIL",
        desk, ts, desk, ts, desk, ts, desk);
    msg[sizeof(msg) - 1] = 0;
    ui_set_reply(msg);
    return 0;
}

/* Callback fired by rawin_start's poll+WM_INPUT threads.
 * `action` is a svc_hotkey_action_t (0=ASK, 1=TOGGLE, ..., 19=DEBUG_CAP). */
static void on_hotkey(int action);

/* v14 (2026-08-11): UI ACTION BRIDGE. The redesigned overlay's on-screen
 * controls (HOME hub buttons, Auto-Solve, model/tier cyclers, etc.) fire
 * the SAME code path as hotkeys by calling this with a svc_hotkey_action_t.
 * on_hotkey owns all the cfg_get, ai_provider, and refresh_status_badge
 * logic, so the UI layer stays decoupled from AI internals. Only SAFE actions are
 * wired to buttons in imgui_layer (never SVC_HK_CLEAR/KILL_ALL). */
void ui_action_fire(int action) { on_hotkey(action); }

static void on_hotkey(int action) {
    char buf[64];
    _snprintf(buf, sizeof(buf) - 1, "hk: %d", action);
    early_log(buf);
    slog_writef("payload.log", "hk: %d", action);

    switch (action) {
        case SVC_HK_ASK:
        case SVC_HK_QUICK_ASK: {
            /* v1.7.4.17: SVC_HK_QUICK_ASK is a SECOND binding slot
             * that shares SVC_HK_ASK's handler. Lets the user wire a
             * mouse-hold gesture (e.g. hold LMB 2000ms) to screenshot+
             * ask WITHOUT any keyboard footprint — matches Bypassify's
             * "quick-send" feature that markets zero-keyboard-signature
             * AI queries for maximum proctor-tool safety. */
            HANDLE t = CreateThread(NULL, 0, ask_ai_thread, NULL, 0, NULL);
            if (t) CloseHandle(t);
            break;
        }
        case SVC_HK_TOGGLE:
            ui_toggle_visible();
            break;
        case SVC_HK_TYPING:
            /* Chat input mode — toggles a typing field at the bottom of
             * the overlay. All non-hotkey keystrokes get diverted into
             * the buffer (invisible to LDB / any other app in the LL
             * hook chain). Enter submits with a fresh screenshot;
             * Escape cancels. See ui_chat_* in imgui_layer.cpp. */
            ui_chat_toggle();
            break;
        case SVC_HK_COPY_REPLY:
            ui_copy_reply_to_clipboard();
            break;
        case SVC_HK_CLEAR:
            /* Context-aware: if a reply is showing, CLEAR the reply
             * (back to home page). If we're on the home page, this
             * hotkey becomes QUIT — signals our own shutdown event
             * DIRECTLY (no launcher spawn — that fails with
             * ERROR_ELEVATION_REQUIRED since sihost has an admin
             * manifest and DWM's SYSTEM context can't satisfy UAC). */
            if (ui_has_reply()) {
                ui_clear_reply();
            } else {
                /* Inline soft-quit: signal our own shutdown event.
                 * The shutdown_watcher thread will call hooks_uninstall
                 * which drains ~200ms of clean frames + disables all
                 * hooks + reverts byte patches — same as if user ran
                 * sihost --unload manually. Overlay disappears cleanly;
                 * DWM stays alive; user re-arms via launcher when
                 * ready. Sentinel gets written to indicate clean quit. */
                HANDLE hf = CreateFileA(SVC_INSTALL_DIR "\\.dwm_clean_shutdown",
                                         GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                         FILE_ATTRIBUTE_NORMAL, NULL);
                if (hf != INVALID_HANDLE_VALUE) {
                    DWORD w = 0;
                    WriteFile(hf, "clean\n", 6, &w, NULL);
                    CloseHandle(hf);
                }
                if (g_shutdown_ev) SetEvent(g_shutdown_ev);
                slog_writef("payload.log", "hotkey QUIT: signalled inline shutdown");
            }
            break;
        /* v13 (2026-08-10) — nudge step is USER-CONFIGURABLE via
         * cfg->nudge_step_px (dashboard "Nudge step" slider). LO: the arrow-
         * key move was "mediocre fast ... wanna be able to do micro
         * adjustments". A small value (2-4 px) gives precise per-tap micro-
         * adjustment AND a slow controllable slide when held (step ×
         * repeat-rate); a large value keeps the old fast hops. Default 48
         * preserves the pre-v13 "~1cm per press" feel. Range 1-200 clamped
         * defensively against a corrupt/unmigrated config. */
        case SVC_HK_MOVE_LEFT:
        case SVC_HK_MOVE_RIGHT:
        case SVC_HK_MOVE_UP:
        case SVC_HK_MOVE_DOWN: {
            const svc_config_t *ncfg = cfg_get();
            int nstep = (ncfg && ncfg->nudge_step_px >= 1 && ncfg->nudge_step_px <= 200)
                        ? ncfg->nudge_step_px : 48;
            if      (action == SVC_HK_MOVE_LEFT)  ui_nudge(-nstep, 0);
            else if (action == SVC_HK_MOVE_RIGHT) ui_nudge( nstep, 0);
            else if (action == SVC_HK_MOVE_UP)    ui_nudge( 0, -nstep);
            else                                  ui_nudge( 0,  nstep);
            break;
        }
        case SVC_HK_RESIZE_WIDER:  ui_resize(30,   0); break;
        case SVC_HK_RESIZE_NARROW: ui_resize(-30,  0); break;
        case SVC_HK_RESIZE_TALLER: ui_resize( 0,  30); break;
        case SVC_HK_RESIZE_SHORT:  ui_resize( 0, -30); break;
        case SVC_HK_CYCLE_CORNER:  ui_cycle_corner();  break;
        case SVC_HK_ALPHA_UP:      ui_bump_alpha(+0.05f); break;  /* small step — held key repeats @20Hz */
        case SVC_HK_ALPHA_DOWN:    ui_bump_alpha(-0.05f); break;
        case SVC_HK_FONT_UP:       ui_bump_font(+0.10f);  break;  /* smaller step — held key repeats @20Hz */
        case SVC_HK_FONT_DOWN:     ui_bump_font(-0.10f);  break;
        case SVC_HK_RESET:         ui_reset_geometry();   break;
        case SVC_HK_SCROLL_UP: {
            /* v1.7.11.18 (2026-07-25): user-configurable scroll granularity.
             * scroll_step_px defaults 80 (same as pre-v12), range 20-400 via
             * dashboard slider. Clamp defensively against corrupt config. */
            const svc_config_t *scfg = cfg_get();
            int step = (scfg && scfg->scroll_step_px >= 20 && scfg->scroll_step_px <= 400)
                       ? scfg->scroll_step_px : 80;
            ui_scroll_reply(-step);
            break;
        }
        case SVC_HK_SCROLL_DOWN: {
            const svc_config_t *scfg = cfg_get();
            int step = (scfg && scfg->scroll_step_px >= 20 && scfg->scroll_step_px <= 400)
                       ? scfg->scroll_step_px : 80;
            ui_scroll_reply(+step);
            break;
        }
        case SVC_HK_DEBUG_CAP: {
            HANDLE t = CreateThread(NULL, 0, debug_capture_thread, NULL, 0, NULL);
            if (t) CloseHandle(t);
            break;
        }
        case SVC_HK_NEW_CHAT: {
            /* Wipe entire chat history. Fresh conversation. */
            ui_chat_clear_history();
            slog_write("payload.log", "hotkey NEW_CHAT: history cleared");
            break;
        }
        case SVC_HK_CYCLE_TIER: {
            /* Cycle STRONG -> MEDIUM -> CHEAP -> STRONG (skip CUSTOM). */
            svc_config_t *mcfg = (svc_config_t *)cfg_get();
            if (!mcfg) break;
            int next = mcfg->tier + 1;
            if (next >= SVC_TIER_CUSTOM) next = SVC_TIER_STRONG;
            mcfg->tier = next;
            refresh_status_badge(mcfg);
            const svc_model_tier_t *t = ai_get_tier(mcfg->provider, mcfg->tier);
            char msg[256];
            _snprintf(msg, sizeof(msg) - 1, "[tier changed] %s | %s | %s",
                      ai_provider_name(mcfg->provider),
                      ai_tier_name(mcfg->tier),
                      t && t->model_id ? t->model_id : "?");
            msg[sizeof(msg) - 1] = 0;
            ui_chat_append_message(UI_MSG_AI, msg);
            slog_writef("payload.log", "hotkey CYCLE_TIER: %s", msg);
            break;
        }
        case SVC_HK_CYCLE_PROVIDER: {
            /* v16: cycle through ONLY the options the user actually has:
             * CloakGPT credits (if signed in) + each provider with a key.
             * Order: credits -> OpenAI -> Anthropic -> Google -> OpenRouter
             * -> back to credits, skipping any provider you have no key for. */
            svc_config_t *mcfg = (svc_config_t *)cfg_get();
            if (!mcfg) break;
            int opts[5]; int n = 0;
            if (mcfg->access_token[0]) opts[n++] = SVC_PROVIDER_CREDITS;
            if (mcfg->api_key_openai[0])     opts[n++] = SVC_PROVIDER_OPENAI;
            if (mcfg->api_key_anthropic[0])  opts[n++] = SVC_PROVIDER_ANTHROPIC;
            if (mcfg->api_key_google[0])     opts[n++] = SVC_PROVIDER_GOOGLE;
            if (mcfg->api_key_openrouter[0]) opts[n++] = SVC_PROVIDER_OPENROUTER;
            if (n <= 1) {
                ui_chat_append_message(UI_MSG_AI,
                    n == 1 ? "[provider] only one option available (no other API keys set)."
                           : "[provider] no credits session and no API keys configured.");
                slog_writef("payload.log", "CYCLE_PROVIDER: nothing to cycle (n=%d)", n);
                break;
            }
            int cur = 0;
            for (int i = 0; i < n; i++) if (opts[i] == mcfg->provider) { cur = i; break; }
            int nx = opts[(cur + 1) % n];
            mcfg->provider = nx;
            refresh_status_badge(mcfg);
            char msg[256];
            if (nx == SVC_PROVIDER_CREDITS) {
                _snprintf(msg, sizeof(msg) - 1, "[provider] CloakGPT credits (managed AI)");
            } else {
                const svc_model_tier_t *t = ai_get_tier(nx, mcfg->tier);
                _snprintf(msg, sizeof(msg) - 1, "[provider] %s | %s | %s",
                          ai_provider_name(nx), ai_tier_name(mcfg->tier),
                          t && t->model_id ? t->model_id : "?");
            }
            msg[sizeof(msg) - 1] = 0;
            ui_chat_append_message(UI_MSG_AI, msg);
            slog_writef("payload.log", "hotkey CYCLE_PROVIDER: %s", msg);
            break;
        }
        case SVC_HK_REGENERATE: {
            /* Re-ask the last user turn. If there's a pending AI msg,
             * we'll still spawn a new ask — the new one appears below. */
            char *last = ui_chat_last_user_text();
            if (!last) {
                ui_chat_append_message(UI_MSG_AI,
                    "[nothing to regenerate — no prior question]");
                break;
            }
            /* Strip the "[screenshot] " prefix for preset asks so the
             * regen doesn't look weird — call the preset path. */
            const char *user_prefix = "[screenshot] ";
            char *param = NULL;
            if (strncmp(last, user_prefix, strlen(user_prefix)) == 0) {
                free(last);
                param = NULL;
            } else {
                param = last;   /* transfer ownership to thread */
            }
            HANDLE t = CreateThread(NULL, 0, ask_ai_thread, (LPVOID)param, 0, NULL);
            if (t) CloseHandle(t);
            else if (param) free(param);
            break;
        }
        case SVC_HK_STREAM_TOGGLE: {
            svc_config_t *mcfg = (svc_config_t *)cfg_get();
            if (!mcfg) break;
            mcfg->streaming_enabled = !mcfg->streaming_enabled;
            refresh_status_badge(mcfg);
            char msg[128];
            _snprintf(msg, sizeof(msg) - 1, "[streaming %s]",
                      mcfg->streaming_enabled ? "ON" : "OFF");
            msg[sizeof(msg) - 1] = 0;
            ui_chat_append_message(UI_MSG_AI, msg);
            slog_writef("payload.log", "hotkey STREAM_TOGGLE: %s", msg);
            break;
        }
        case SVC_HK_COPY_CODE: {
            /* Extract + copy JUST fenced code blocks from last AI reply. */
            ui_copy_last_ai_code();
            break;
        }
        case SVC_HK_COPY_ANSWER: {
            /* Copy JUST the first-line "direct answer" (e.g. "x = 4"
             * or "B) Photosynthesis") — per SYSTEM_PROMPT contract. */
            ui_copy_last_ai_answer();
            break;
        }
        case SVC_HK_STOP_GEN: {
            /* v4.5: user-requested abort of an in-flight AI stream.
             * Sets a process-wide flag ai_provider polls per SSE chunk.
             * Safe to press even when no request is running (no-op). */
            ai_request_abort();
            ui_chat_append_message(UI_MSG_AI,
                "[STOP] Aborting in-flight response. If a partial reply "
                "was already streamed it will be finalized; otherwise the "
                "AI bubble will show 'stopped by user'.");
            slog_writef("payload.log", "hotkey STOP_GEN: abort requested");
            break;
        }
        case SVC_HK_LATEX_TOGGLE: {
            svc_config_t *mcfg = (svc_config_t *)cfg_get();
            if (!mcfg) break;
            mcfg->latex_disabled = !mcfg->latex_disabled;
            char msg[256];
            if (mcfg->latex_disabled) {
                _snprintf(msg, sizeof(msg) - 1,
                    "[LaTeX **DISABLED**] Next AI reply will use plain "
                    "Unicode / keyboard math (`x^2`, `sqrt(x)`, `pi`, "
                    "`sum from i=1 to n of`, etc.) instead of `\\frac`, "
                    "`\\int`, `\\sum`.");
            } else {
                _snprintf(msg, sizeof(msg) - 1,
                    "[LaTeX **ENABLED**] Next AI reply may use LaTeX "
                    "commands (`$..$` inline, `\\[..\\]` display, "
                    "`\\frac{}{}`, `\\int`, etc.) rendered as raw text "
                    "in the overlay.");
            }
            msg[sizeof(msg) - 1] = 0;
            ui_chat_append_message(UI_MSG_AI, msg);
            slog_writef("payload.log", "hotkey LATEX_TOGGLE: %s",
                        mcfg->latex_disabled ? "DISABLED" : "ENABLED");
            break;
        }
        case SVC_HK_DIRECT_TOGGLE: {
            /* v6: toggle DIRECT ANSWER mode. When ON, AI replies with
             * ONLY the direct factual answer (or 'ERROR' if uncertain).
             * See materialize_default_system in ai_provider.c for the
             * exact system prompt override. */
            svc_config_t *mcfg = (svc_config_t *)cfg_get();
            if (!mcfg) break;
            mcfg->direct_answer_mode = !mcfg->direct_answer_mode;
            char msg[512];
            if (mcfg->direct_answer_mode) {
                _snprintf(msg, sizeof(msg) - 1,
                    "[Direct-answer mode **ON**] Next AI reply will contain "
                    "ONLY the factual answer - no explanation, no reasoning, "
                    "no framing. If the AI is uncertain it will reply "
                    "'ERROR' instead of guessing.\n\n"
                    "Shape rules: MCQ -> just the letter (`B`). Numeric -> "
                    "value + units (`9.81 m/s^2`). True/False -> just the "
                    "word. Toggle back off with `Ctrl+Shift+Alt+D`.");
            } else {
                _snprintf(msg, sizeof(msg) - 1,
                    "[Direct-answer mode **OFF**] Next AI reply will use "
                    "the normal detailed format (answer + reasoning + "
                    "sanity check per the system prompt).");
            }
            msg[sizeof(msg) - 1] = 0;
            ui_chat_append_message(UI_MSG_AI, msg);
            slog_writef("payload.log", "hotkey DIRECT_TOGGLE: %s",
                        mcfg->direct_answer_mode ? "ON" : "OFF");
            break;
        }
        case SVC_HK_LEAN_TOGGLE: {
            /* v1.7.10: toggle LEAN MODE. Overlay switches between full
             * ImGui Begin/End render (chat bubbles, MD, scrollback, buttons)
             * and BP-parity draw-list-only render (raw AddRectFilled +
             * AddText on GetForegroundDrawList — much lighter per-frame
             * workload = smoother nudge feel). See ui_toggle_lean() in
             * imgui_layer.cpp for the exact implementation. */
            ui_toggle_lean();
            int now_lean = ui_is_lean();
            char msg[512];
            if (now_lean) {
                _snprintf(msg, sizeof(msg) - 1,
                    "[LEAN mode **ON**] Overlay now renders via raw draw "
                    "list (Bypassify parity). Chat scrollback / MD / bubbles "
                    "hidden. Shows LAST AI reply as plain wrapped text. "
                    "Smoother nudge feel. Toggle off: `Ctrl+Shift+Alt+M`.");
            } else {
                _snprintf(msg, sizeof(msg) - 1,
                    "[LEAN mode **OFF**] Full overlay restored — chat "
                    "scrollback, markdown, code blocks, buttons all back.");
            }
            msg[sizeof(msg) - 1] = 0;
            ui_chat_append_message(UI_MSG_AI, msg);
            slog_writef("payload.log", "hotkey LEAN_TOGGLE: %s",
                        now_lean ? "ON" : "OFF");
            break;
        }
        case SVC_HK_KILL_ALL: {
            /* Emergency stop — DIRECT self-kill of DWM from inside DWM.
             *
             * The old design tried to spawn sihost.exe --kill-all from
             * DWM but sihost has a requireAdministrator manifest and
             * DWM's SYSTEM-in-user-session context returns
             * ERROR_ELEVATION_REQUIRED (740) on CreateProcess for such
             * binaries — no interactive UAC to satisfy the manifest.
             *
             * Inline approach:
             *   1. Write .dwm_user_panic sentinel — Electron's
             *      respawn watchdog checks BOTH .dwm_clean_shutdown
             *      (Ctrl+Q soft-quit) and .dwm_user_panic (this hotkey)
             *      and disarms on either. Without this, watchdog would
             *      auto-reinject seconds after panic (the whole point
             *      of KILL_ALL was "GET OFF MY SCREEN NOW" — silently
             *      re-injecting is a catastrophic UX regression). See
             *      ui/src/main.js respawnWatchdog::tick sentinel logic.
             *   2. Delete .dwm_clean_shutdown so launcher's cold-start
             *      dirty-detect logs prior=DIRTY (this was NOT a clean
             *      hooks_uninstall — we're about to TerminateProcess).
             *   3. TerminateProcess(GetCurrentProcess()) in a helper
             *      thread after a short delay. Windows respawns
             *      dwm.exe fresh in ~2s; our payload dies with it.
             *
             * Bug fix 2026-08-24 (Sam's user report — teacher walking up
             * scenario): panic hotkey used to cause overlay to POP UP a
             * few seconds later because the watchdog had no way to
             * distinguish "user hit panic" from "DWM crashed". The new
             * sentinel is that signal.
             *
             * We DON'T sweep sibling sihost.exe instances — launcher is
             * a one-shot that exits after arming so there's normally
             * nothing to sweep. If the user has a stuck sihost they
             * can kill it via Task Manager. */
            {
                HANDLE hpanic = CreateFileA(SVC_INSTALL_DIR "\\.dwm_user_panic",
                                             GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                             FILE_ATTRIBUTE_NORMAL, NULL);
                if (hpanic != INVALID_HANDLE_VALUE) {
                    DWORD w = 0;
                    WriteFile(hpanic, "panic\n", 6, &w, NULL);
                    FlushFileBuffers(hpanic);
                    CloseHandle(hpanic);
                } else {
                    /* Best-effort — if sentinel write fails, watchdog
                     * MIGHT still re-inject. Rare (ProgramData is
                     * writable to SYSTEM). Logged so post-mortem can
                     * spot it. */
                    slog_writef("payload.log",
                                "hotkey KILL_ALL: .dwm_user_panic write FAILED gle=%lu — "
                                "watchdog may re-inject!", GetLastError());
                }
            }
            DeleteFileA(SVC_INSTALL_DIR "\\.dwm_clean_shutdown");
            slog_writef("payload.log",
                        "hotkey KILL_ALL: user_panic sentinel written, "
                        "inline self-kill in 200ms");
            HANDLE t = CreateThread(NULL, 0, self_kill_dwm_thread,
                                    NULL, 0, NULL);
            if (t) CloseHandle(t);
            break;
        }
        default:
            slog_writef("payload.log", "unknown hotkey action %d", action);
            break;
    }
}

/* ── Cooperative shutdown watcher ────────────────────────────────
 * Global\SVCLDB_Shutdown named event. Launcher --unload sets it.
 * On signal: uninstall hooks, stop threads, FreeLibraryAndExitThread. */
static DWORD WINAPI shutdown_watcher(LPVOID param) {
    (void)param;
    if (!g_shutdown_ev) return 0;
    WaitForSingleObject(g_shutdown_ev, INFINITE);
    slog_write("payload.log", "shutdown signal received");

    InterlockedExchange(&g_running, 0);
    rawin_stop();
    ldb_detect_stop();
    sub_check_stop();
    /* v14 (2026-08-24): stop the token-refresh pipe server BEFORE
     * hooks_uninstall + cfg_cleanup. Prevents an in-flight
     * handle_one_client from touching hooks or dereferencing cfg
     * mid-teardown. token_refresh_stop closes the pending pipe handle
     * to unblock ConnectNamedPipe and waits up to 5s for the thread. */
    token_refresh_stop();
    hooks_uninstall();
    ui_shutdown();
    cfg_cleanup();
    sb_cleanup();

    if (g_shutdown_ev) { CloseHandle(g_shutdown_ev); g_shutdown_ev = NULL; }
    /* v14 (2026-08-24): release the double-init guard mutex so a
     * subsequent --reinject can acquire it cleanly. Kernel would
     * clean this up when DWM terminates anyway, but explicit release
     * matters for the graceful --unload path where DWM stays alive. */
    if (g_init_mutex) { CloseHandle(g_init_mutex); g_init_mutex = NULL; }

    /* Free ourselves. This kills our thread; DLL is unloaded. */
    FreeLibraryAndExitThread(g_self, 0);
    return 0;
}

/* ── Init worker (runs off DllMain thread). ──────────────────────── */
/* Log rotation — payload.log can grow unbounded over long sessions.
 * On each init, if it exceeds 2MB, truncate to zero and start fresh.
 * Loses old encrypted diag but prevents disk-fill DoS. Keeps 2MB
 * of history which is ~10K encrypted lines — plenty for post-mortem. */
static void rotate_payload_log(void) {
    const char *path = SVC_INSTALL_DIR "\\payload.log";
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return;
    ULARGE_INTEGER sz;
    sz.LowPart  = fad.nFileSizeLow;
    sz.HighPart = fad.nFileSizeHigh;
    if (sz.QuadPart > (2ULL * 1024 * 1024)) {
        HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
}

#if SVCLDB_DEV_BYPASS_AUTH
/* v1.7.10.2 — Dev-only automated hotkey self-test. Programmatically
 * fires each ui_* action after 5s startup delay. Logs pass/fail per
 * action so we can diagnose broken hotkeys without needing LO to
 * physically test each one. Only compiled into dev-bypass builds.
 * Grep decrypted log for "selftest:" to see results. */
static DWORD WINAPI selftest_thread_dev(LPVOID param) {
    (void)param;
    Sleep(5000);   /* Let payload init settle fully. */
    slog_write("payload.log", "selftest: === BEGIN AUTOMATED HOTKEY TEST ===");

    /* Each test is: log intent -> fire action -> log side effect.
     * We can't observe visual behavior programmatically, but we log
     * enough state changes that a diff of before/after tells us if
     * the action reached its implementation. */

    /* Geometry / visual actions */
    slog_write("payload.log", "selftest: [1/16] ui_nudge(+48,0)");
    ui_nudge(48, 0);
    Sleep(150);
    slog_write("payload.log", "selftest: [2/16] ui_nudge(-48,0)");
    ui_nudge(-48, 0);
    Sleep(150);
    slog_write("payload.log", "selftest: [3/16] ui_nudge(0,+48)");
    ui_nudge(0, 48);
    Sleep(150);
    slog_write("payload.log", "selftest: [4/16] ui_nudge(0,-48)");
    ui_nudge(0, -48);
    Sleep(150);

    slog_write("payload.log", "selftest: [5/16] ui_resize(+30,0)");
    ui_resize(30, 0);
    Sleep(150);
    slog_write("payload.log", "selftest: [6/16] ui_resize(-30,0)");
    ui_resize(-30, 0);
    Sleep(150);

    slog_write("payload.log", "selftest: [7/16] ui_cycle_corner");
    ui_cycle_corner();
    Sleep(150);
    ui_cycle_corner(); ui_cycle_corner(); ui_cycle_corner();  /* back to 0 */

    slog_write("payload.log", "selftest: [8/16] ui_bump_alpha(-0.1)");
    ui_bump_alpha(-0.1f);
    Sleep(150);
    ui_bump_alpha(0.1f);

    slog_write("payload.log", "selftest: [9/16] ui_bump_font(+0.1)");
    ui_bump_font(0.1f);
    Sleep(150);
    ui_bump_font(-0.1f);

    /* Scroll — MUST pump some visible chat first so we can tell if
     * the underlying scroll region is empty (nothing to scroll) vs
     * the scroll handler itself is buggy. Adds one fake AI msg with
     * enough text to overflow the chat area on any normal geometry. */
    slog_write("payload.log", "selftest: [10/16] pumping fake AI msg + ui_scroll_reply(-160)");
    ui_chat_append_message(1 /* AI */,
        "SELFTEST: this is a synthetic AI reply used to give the "
        "scroll test something to scroll. Line 1.\n\n"
        "Line 2 with more filler text so the chat region grows past "
        "one viewport height for the scroll hotkey to have effect.\n\n"
        "Line 3. Line 4. Line 5.\n\n"
        "Line 6 with even more filler content padding for the vertical "
        "extent required to make scroll register.\n\n"
        "Line 7. Line 8. Line 9. Line 10.\n\n"
        "Line 11. Line 12. Line 13. Line 14. Line 15.\n\n"
        "END OF SELFTEST FILLER");
    Sleep(200);   /* let the chat window render once + build up ScrollMaxY */
    ui_scroll_reply(-160);
    Sleep(150);
    slog_write("payload.log", "selftest: [11/16] ui_scroll_reply(+160)");
    ui_scroll_reply(160);
    Sleep(150);

    /* Visibility + lean */
    slog_write("payload.log", "selftest: [12/16] ui_toggle_visible");
    ui_toggle_visible();
    Sleep(200);
    ui_toggle_visible();   /* restore */

    slog_write("payload.log", "selftest: [13/16] ui_toggle_lean");
    ui_toggle_lean();
    Sleep(200);
    ui_toggle_lean();   /* restore */

    /* Chat mode toggle */
    slog_write("payload.log", "selftest: [14/16] ui_chat_toggle");
    ui_chat_toggle();
    Sleep(200);
    ui_chat_toggle();

    /* Copy hotkeys */
    slog_write("payload.log", "selftest: [15/28] ui_copy_reply_to_clipboard");
    ui_copy_reply_to_clipboard();
    Sleep(150);

    slog_write("payload.log", "selftest: [16/28] ui_reset_geometry");
    ui_reset_geometry();
    Sleep(150);

    /* ── v1.7.11.15+ expanded coverage. ──────────────────────────── */

    /* Copy variants — need the fake AI msg from [10] to still be there.
     * These should silently succeed even if clipboard access is briefly
     * denied (5-retry OpenClipboard loop inside clip_set_utf8_bytes). */
    slog_write("payload.log", "selftest: [17/28] ui_copy_last_ai_answer");
    ui_copy_last_ai_answer();
    Sleep(150);
    slog_write("payload.log", "selftest: [18/28] ui_copy_last_ai_code");
    ui_copy_last_ai_code();
    Sleep(150);

    /* Config mutations — cycle tier / provider / stream / latex / direct. */
    svc_config_t *mcfg = (svc_config_t *)cfg_get();
    if (mcfg) {
        int t0 = mcfg->tier;
        slog_writef("payload.log", "selftest: [19/28] cycle_tier from=%d", t0);
        int t = t0;
        for (int i = 0; i < 3; i++) t = (t + 1) % 3;
        mcfg->tier = t;
        slog_writef("payload.log", "selftest: cycle_tier settled at=%d (should match start)", mcfg->tier);
        Sleep(50);

        int p0 = mcfg->provider;
        slog_writef("payload.log", "selftest: [20/28] cycle_provider from=%d", p0);
        int p = p0;
        for (int i = 0; i < 4; i++) p = (p >= 4) ? 1 : (p + 1);
        mcfg->provider = p;
        slog_writef("payload.log", "selftest: cycle_provider settled at=%d", mcfg->provider);
        Sleep(50);

        int se = mcfg->streaming_enabled;
        mcfg->streaming_enabled = !se;
        slog_writef("payload.log", "selftest: [21/28] stream_toggle %d->%d", se, mcfg->streaming_enabled);
        mcfg->streaming_enabled = se;   /* restore */
        Sleep(50);

        int ld = mcfg->latex_disabled;
        mcfg->latex_disabled = !ld;
        slog_writef("payload.log", "selftest: [22/28] latex_toggle %d->%d", ld, mcfg->latex_disabled);
        mcfg->latex_disabled = ld;   /* restore */
        Sleep(50);

        int da = mcfg->direct_answer_mode;
        mcfg->direct_answer_mode = !da;
        slog_writef("payload.log", "selftest: [23/28] direct_toggle %d->%d", da, mcfg->direct_answer_mode);
        mcfg->direct_answer_mode = da;   /* restore */
        Sleep(50);

        /* Verify scroll_step_px is read from cfg (v12 new field). */
        slog_writef("payload.log", "selftest: [24/28] cfg->scroll_step_px = %d (expect 20-400 range)",
                    mcfg->scroll_step_px);
    }

    /* Stop-gen abort — safe to call even with no in-flight request. */
    slog_write("payload.log", "selftest: [25/28] ai_request_abort");
    ai_request_abort();
    Sleep(50);
    ai_clear_abort();  /* clean state for LO's real use */

    /* v1.7.11.15 BURST HYSTERESIS TEST — fire ui_toggle_visible 5x in
     * ~50ms. Should see exactly ONE "visible toggled -> N" line and
     * FOUR "visible toggle IGNORED (burst hysteresis:...)" lines. If
     * any consecutive toggles slip through, the hysteresis regressed. */
    slog_write("payload.log", "selftest: [26/28] burst hysteresis (5 rapid toggles, expect 1 fire + 4 ignored)");
    for (int i = 0; i < 5; i++) {
        ui_toggle_visible();
        Sleep(20);   /* well under the 300ms window */
    }
    Sleep(400);   /* wait past hysteresis */
    ui_toggle_visible();   /* restore to original visible state (net 2 flips = 0 change if starting visible) */

    /* Chat mode round-trip with a synthetic char — feeds through the
     * feed_char path so we exercise the buffer growth logic. */
    slog_write("payload.log", "selftest: [27/28] chat toggle + feed 'a' + backspace + cancel");
    ui_chat_toggle();
    Sleep(50);
    if (ui_chat_is_active()) {
        ui_chat_feed_char('t');
        ui_chat_feed_char('e');
        ui_chat_feed_char('s');
        ui_chat_feed_char('t');
        ui_chat_feed_backspace();
        ui_chat_cancel();
        slog_write("payload.log", "selftest: chat feed cycle complete");
    } else {
        slog_write("payload.log", "selftest: WARN chat_toggle didn't enable chat_active");
    }
    Sleep(50);

    /* NEW_CHAT clears all messages including the selftest filler. */
    slog_write("payload.log", "selftest: [28/28] ui_chat_clear_history");
    ui_chat_clear_history();

    slog_write("payload.log", "selftest: === END (28 actions fired). Grep 'selftest' + verify each [N/28] has a matching side-effect log line. Look specifically for: nudge/resize/cycle_corner/alpha/font/scroll/visible toggled/visible toggle IGNORED/lean toggled/chat toggled/copy_reply/reset. ===");
    return 0;
}
#endif

static DWORD WINAPI init_thread(LPVOID param) {
    (void)param;
    /* Decrypt the smoking-gun string blob BEFORE any logging code runs.
     * Idempotent + thread-safe — safe to call at DllMain-thread start.
     * After this, SS(SVC_STR_XXX) returns plaintext pointers to strings
     * that live encrypted-at-rest inside .rdata. See shared/str_enc.h. */
    svc_str_init();

    rotate_payload_log();
    early_log("init_thread: entered");
    slog_write("payload.log", SS(SVC_STR_PAYLOAD_INIT));

    /* v14 (2026-08-24) — Double-init guard. Manual-map does NOT go
     * through the Windows loader → LoadLibrary's ref-count dedup that
     * would normally block a second load doesn't apply. If sihost
     * --reinject fires while the first payload is still alive (e.g.
     * respawnWatchdog racing a user's manual click, two sihost.exe
     * launched concurrently, or the launcher's leftover-heal path
     * timing out) — both DllMain chains run init_thread, both call
     * hooks_install() which RE-WRITES MinHook's byte patches.
     *
     * MinHook internally dedups by target but the second install
     * still rewrites the JMP bytes (from JMP-trampoline-A to
     * JMP-trampoline-B), silently invalidating the FIRST payload's
     * trampoline pointers. First payload's long-lived threads
     * (sub_check, keepalive, integrity monitor) then MH_CALL_ORIGINAL
     * through stale trampolines → jump to garbage → __fastfail → DWM
     * crash → screen goes black. This is a documented crasher
     * (CLAUDE_REFERENCE_OLD.md:2664-2668, session 2026-07-06).
     *
     * Fix: named mutex scoped to this DWM session (Local\ namespace,
     * one guard per user session — multi-user hosts don't false-
     * conflict). First mapper wins + keeps the handle. Second mapper
     * gets ERROR_ALREADY_EXISTS → bails BEFORE touching hooks.
     * The second DLL image leaks ~850 KB in DWM's address space
     * (can't FreeLibrary a manual-mapped copy — no LDR entry),
     * but that's a one-shot cost vs a DWM crash.
     *
     * Name blends with legit DWM object naming ("DwmCompositor*"
     * matches the existing SVC_SHUTDOWN_EVENT_NAME pattern). Not
     * encrypted here — the string is innocuous + adding str_enc
     * bloat for one guard call site isn't worth it. */
    g_init_mutex = CreateMutexA(NULL, FALSE, "Local\\DwmCompositorGuardRelease");
    DWORD init_mutex_gle = GetLastError();
    if (init_mutex_gle == ERROR_ALREADY_EXISTS) {
        slog_write("payload.log",
                   "init_thread: DOUBLE-INIT DETECTED — another payload copy already "
                   "loaded in this DWM session. Bailing WITHOUT touching hooks to avoid "
                   "MinHook double-patch crash.");
        if (g_init_mutex) { CloseHandle(g_init_mutex); g_init_mutex = NULL; }
        return 42;   /* Leak our DLL image; safer than double-init crash. */
    }
    if (!g_init_mutex) {
        /* Very unusual — CreateMutex failed for a reason other than
         * ALREADY_EXISTS (OOM, DACL denial, exhausted handle table).
         * Log + continue optimistically; this is a defense-in-depth
         * guard, not the primary flow. First-map behavior is still
         * safe without the mutex, only re-inject race is unprotected. */
        slog_writef("payload.log",
                    "init_thread: init-guard CreateMutex failed gle=%lu (continuing)",
                    init_mutex_gle);
    } else {
        slog_write("payload.log", "init_thread: init-guard mutex acquired");
    }

    early_log("init_thread: past slog_write test");

    /* Anti-debug — refuse to init if DWM is being debugged. Someone
     * attached a debugger to SYSTEM's DWM = they're investigating us. */
    if (!anti_debug_check()) {
        early_log("init_thread: debugged — aborting init");
        return 4;
    }

    /* Read config — MUST succeed. If not, payload is inert (safe). */
    const svc_config_t *cfg = cfg_get();
    if (!cfg) {
        early_log("init_thread: config unavailable");
        slog_write("payload.log", SS(SVC_STR_CONFIG_UNAVAIL));
        return 1;
    }
    early_log("init_thread: config loaded");

    /* ── Handshake gate (v4 schema) ────────────────────────────────────
     * Verify the Electron UI produced a valid HMAC token for THIS box +
     * a recent day. Prevents CLI-only bypass of the login flow: sihost
     * or any custom loader that ships config.dat without a valid token
     * (or with a stale one) is refused injection here. See
     * shared/handshake.h for the derivation contract.
     *
     * Dev bypass: `SVCLDB_DEV_BYPASS_AUTH=1` at compile time skips this
     * gate for iteration convenience. See common.h — MUST be 0 before
     * shipping. */
#if SVCLDB_DEV_BYPASS_AUTH
    early_log("init_thread: HANDSHAKE SKIPPED (SVCLDB_DEV_BYPASS_AUTH=1)");
#else
    if (cfg->magic != SVC_CONFIG_MAGIC ||
        cfg->schema_version != SVC_CONFIG_SCHEMA_VERSION) {
        slog_writef("payload.log", SS(SVC_STR_HANDSHAKE_BAD_HEADER),
                    (unsigned)cfg->magic, (unsigned)cfg->schema_version,
                    (unsigned)SVC_CONFIG_MAGIC, (unsigned)SVC_CONFIG_SCHEMA_VERSION);
        early_log("init_thread: config header rejected");
        return 5;
    }
    if (!handshake_verify(cfg->access_token, cfg->handshake_hwid,
                          cfg->handshake_token)) {
        slog_write("payload.log", SS(SVC_STR_HANDSHAKE_TOKEN_INVALID));
        early_log("init_thread: HANDSHAKE FAILED");
        return 5;
    }
    early_log(SS(SVC_STR_HANDSHAKE_OK));
#endif

    /* Read offsets.blob — try, fall back to signature scan later. */
    pl_offsets_t off = {0};
    if (!pl_offsets_load(&off)) {
        early_log("init_thread: offsets.blob missing");
        return 2;
    }
    early_log("init_thread: offsets loaded");

    /* v1.6.5 (2026-07-16) — HINT SEMANTICS CORRECTED via PDB RE.
     *
     * The three vtable slots and their ACTUAL method identities per
     * PDB verification (see tools/re_probe/dwmcore_dump.c output):
     *   GPB_SLOT   =  5  on pLayer   → COverlaySwapChain::GetDevice
     *   GD3D_SLOT  = 24  on pLayer   → CDDisplaySwapChain::GetPhysicalBackBuffer
     *   ACC3_SLOT  = 19  on res_vtbl → CDDisplaySwapChainBuffer::GetD3D11Resource
     *
     * PRE-v1.6.5 BUG: hints were plumbed as
     *   gpb_hint = getPhysicalBackBufferRva  (WRONG — slot 5 is GetDevice)
     *   gd3d_hint = getD3D11ResourceRva      (WRONG — slot 24 is GetPhysicalBackBuffer)
     *   acc_hint = accessorRva               (WRONG — slot 19 is GetD3D11Resource,
     *                                         and accessorRva is GetTexture2D
     *                                         which is on a DIFFERENT class)
     *
     * Result: every dynamic-scan MISSED because it searched for the
     * wrong RVAs. Fell back to hardcoded slots. On dev-box vtable[1/6]
     * layout the hardcoded slots happen to be correct. On user builds
     * where pLayer's cast lands on vtable[2..5]/6 (multi-inherit
     * subobjects), hardcoded slot 24 points at a completely different
     * method → wrong chain → silent __fastfail via CFG/CET.
     *
     * v1.6.5 fix: hint each slot with the RVA of what that slot ACTUALLY
     * invokes. Dynamic scan now MATCHES on typical builds (zero
     * regression) and DRIFTS to the correct slot on user builds where
     * the method has moved to slots 28/43/44/45 (still within the
     * v1.6.5 MAX_VTABLE_SCAN_SLOTS=256 window). */
    ui_set_vtable_slot_hints(off.getDevice,                 /* slot 5 → GetDevice */
                             off.getPhysicalBackBufferRva,  /* slot 24 → GetPhysicalBackBuffer */
                             off.getD3D11ResourceRva);      /* slot 19 → GetD3D11Resource */

    /* v1.6.3: populate the known-RVA lookup table so the first-success
     * diag in get_backbuffer_texture can NAME which dwmcore method each
     * vtable slot actually invokes on this Windows build. Enables log
     * lines like "slot=5 rva=0x1DD690 (== getDevice)" — support can
     * identify by method name what each user's slot resolves to,
     * WITHOUT needing to run the resolver on their box. */
    {
        static ui_rva_symbol_t known[] = {
            /* Populated in-place from `off` below — the pointers here
             * are compile-time; the RVAs are runtime. */
            { 0, "cOverlayContextPresent"  },
            { 0, "isOverlayPrevented"      },
            { 0, "scheduleComposition"     },
            { 0, "renderContent"           },
            { 0, "cvisualRenderContent"    },
            { 0, "isNormalDesktopRender"   },
            { 0, "finalCapture"            },
            { 0, "presentNeeded"           },
            { 0, "legacyPresentNeeded"     },
            { 0, "forceFullDirty"          },
            { 0, "getDevice"               },
            { 0, "overlayConstructor"      },
            { 0, "isPrimaryMonitor"        },
            { 0, "getHwnd"                 },
            { 0, "addDirtyRectDisplay"     },
            { 0, "addDirtyRectLegacy"      },
            { 0, "presentDisplay"          },
            { 0, "presentLegacy"           },
            { 0, "getPhysicalBackBuffer"   },
            { 0, "getD3D11Resource"        },
            { 0, "accessor"                },
        };
        known[0].rva  = off.cOverlayContextPresent;
        known[1].rva  = off.isOverlayPrevented;
        known[2].rva  = off.scheduleComposition;
        known[3].rva  = off.renderContent;
        known[4].rva  = off.cvisualRenderContent;
        known[5].rva  = off.isNormalDesktopRender;
        known[6].rva  = off.finalCapture;
        known[7].rva  = off.presentNeeded;
        known[8].rva  = off.legacyPresentNeeded;
        known[9].rva  = off.forceFullDirty;
        known[10].rva = off.getDevice;
        known[11].rva = off.overlayConstructor;
        known[12].rva = off.isPrimaryMonitor;
        known[13].rva = off.getHwnd;
        known[14].rva = off.addDirtyRectDisplay;
        known[15].rva = off.addDirtyRectLegacy;
        known[16].rva = off.presentDisplay;
        known[17].rva = off.presentLegacy;
        known[18].rva = off.getPhysicalBackBufferRva;
        known[19].rva = off.getD3D11ResourceRva;
        known[20].rva = off.accessorRva;
        ui_set_known_rva_table(known, (int)(sizeof(known) / sizeof(known[0])));
    }

    if (!hooks_install(&off, on_present)) {
        early_log("init_thread: hooks_install FAILED");
        return 3;
    }
    early_log("init_thread: hooks installed");

    /* Hide our DLL from PEB module lists. Anti-cheat / debugger that
     * walks the loader lists (K32EnumProcessModules et al.) no longer
     * sees us. Spoofs BaseDllName to `uiribbon.dll` as a decoy. */
    peb_unlink_dll(g_self);
    early_log("init_thread: peb_unlink done");

    /* Corrupt PE headers so memory scanners searching for "MZ" /
     * "PE\0\0" at page boundaries can't identify our image as a
     * valid PE. Belt-and-suspenders on top of the PEB unlink. */
    wipe_pe_headers(g_self);
    early_log("init_thread: pe_wipe done");

    /* Downgrade our whole image from initial RWX to per-section image-
     * like protections (.text→RX, .data→RW, .rdata→RO). Removes the
     * single strongest IOC used by user-mode memory scanners against
     * manually-mapped code. See downgrade_own_sections() docstring. */
    downgrade_own_sections(g_self);
    early_log("init_thread: sections downgraded");

    /* Start background workers. */
    ldb_detect_start(on_ldb_arm, on_ldb_disarm);
    rawin_start(cfg->hotkeys, on_hotkey);

    /* Push hotkey bindings to UI so buttons show mapped hotkeys
     * (e.g. "Copy full [Ctrl+Alt+C]"). Fires once at arm; if user
     * later rebinds via config edit, they need to re-arm anyway. */
    ui_set_hotkey_bindings(cfg->hotkeys,
                           sizeof(cfg->hotkeys) / sizeof(cfg->hotkeys[0]));

    /* v8: apply Electron-configured overlay geometry + size mode.
     * User picks these in the "Overlay appearance" dashboard card.
     * Runs AFTER hotkey bindings so any status log line about launch
     * geometry has the full context available. State file was already
     * consumed by the first ensure_cs() during ui_set_hotkey_bindings
     * so persisted user tweaks (extras from prior Ctrl+Alt+= sessions)
     * are respected. */
    ui_apply_launch_config(cfg->overlay_w, cfg->overlay_h,
                           cfg->overlay_alpha, cfg->size_mode);
    /* v11 (2026-07-24): theme + overlay behavior flags — Bypassify parity.
     * Reads cfg->theme + cfg->overlay_flags from the config that svchelper
     * wrote. Stale v10 configs pass 0 for both which auto-migrates to
     * AUTO theme + SVC_OVFLAG_DEFAULTS. */
    ui_apply_theme_and_flags(cfg->theme, cfg->overlay_flags);

    /* Shutdown watcher — event must be openable from elevated Admin
     * launcher process, so we build a world-writable DACL via SDDL. */
    SECURITY_ATTRIBUTES sa = {0};
    PSECURITY_DESCRIPTOR sd = NULL;
    build_world_sa(&sa, &sd);
    g_shutdown_ev = CreateEventA(sa.lpSecurityDescriptor ? &sa : NULL,
                                  TRUE, FALSE, SS(SVC_STR_SHUTDOWN_EVENT));
    if (sd) LocalFree(sd);   /* CreateEvent duplicates the descriptor */
    if (g_shutdown_ev) {
        DWORD gle = GetLastError();
        slog_writef("payload.log", "shutdown event created (gle=%lu already_exists=%d)",
                    gle, gle == ERROR_ALREADY_EXISTS);
        g_shutdown_thr = CreateThread(NULL, 0, shutdown_watcher, NULL, 0, NULL);
        if (g_shutdown_thr) CloseHandle(g_shutdown_thr);
    } else {
        slog_writef("payload.log", "shutdown event create FAILED gle=%lu", GetLastError());
    }

    /* Push status badge (provider/tier/model + streaming flag) so it
     * shows in the overlay's top strip right on first frame. */
    refresh_status_badge(cfg);

    /* Runtime subscription re-check. Independent of Electron UI —
     * self-unloads within ~30 min of the sub going inactive even if
     * the UI is closed. See payload/src/sub_check.h.
     *
     * Dev bypass: `SVCLDB_DEV_BYPASS_AUTH=1` at compile time skips this
     * poller so dev-mode builds don't self-unload when the tester's
     * config.dat doesn't correspond to a real Supabase account. */
#if SVCLDB_DEV_BYPASS_AUTH
    early_log("init_thread: SUB_CHECK SKIPPED (SVCLDB_DEV_BYPASS_AUTH=1)");
#else
    sub_check_start();
#endif

    /* v14 (2026-08-24) — Start the token-refresh pipe server so Electron
     * can push a refreshed JWT into cfg->access_token before sub_check's
     * next tick. Fixes the "1 hour → overlay silently disappears" bug
     * (Bug 2). Under dev-bypass this is a no-op cost (server thread
     * still runs but no client will ever connect since sub_check itself
     * is skipped). Cheap enough to always leave enabled. */
    token_refresh_start();

    InterlockedExchange(&g_running, 1);
    early_log("init_thread: PAYLOAD READY");
    slog_write("payload.log", SS(SVC_STR_PAYLOAD_READY));

#if SVCLDB_DEV_BYPASS_AUTH
    /* v1.7.10.2 (2026-07-24) — DEV-ONLY AUTO-SELFTEST.
     * Spawns a thread that waits 5s for init to settle, then
     * programmatically fires every hotkey action + logs pass/fail
     * per action. Result decodable via tools/dlog.ps1 grep of
     * "selftest:" lines. Only compiled in when SVCLDB_DEV_BYPASS_AUTH=1
     * so prod builds NEVER run this. */
    HANDLE hSelftest = CreateThread(NULL, 0, selftest_thread_dev, NULL, 0, NULL);
    if (hSelftest) CloseHandle(hSelftest);
    early_log("init_thread: selftest thread spawned (dev bypass build)");
#endif

    return 0;
}

/* ── EARLY plaintext diagnostic — no TLS, no BCrypt, no CRT.        *
 * When manual-mapped, __declspec(thread) TLS is broken (loader-only *
 * init step skipped). slog_write relies on TLS reentry guard, so a  *
 * crashing slog_write would silently swallow all logging.           *
 * This bypasses slog entirely — proves DllMain ran + gives us a    *
 * bootstrap trace no matter what fails later. */
/* early_log — routes through slog (encrypted) so feature-name signature
 * strings ("init_thread: hooks installed" etc.) don't leak in plaintext
 * on disk. Falls back to payload_early.txt when DWM_EXT_TRACE=1
 * for iteration debug. See hook_diag_raw in dwm_hooks.c for the same
 * pattern. */
static int g_early_plaintext = -1;
static void early_log(const char *msg) {
    if (g_early_plaintext < 0) {
#if SVCLDB_PRODUCTION_BUILD
        /* Production: NEVER emit plaintext, regardless of env vars.
         * Any leakage would let an admin grep the logs for features. */
        g_early_plaintext = 0;
#else
        char buf[8];
        DWORD n = GetEnvironmentVariableA("DWM_EXT_TRACE",
                                          buf, sizeof(buf));
        g_early_plaintext = (n > 0 && buf[0] != '0') ? 1 : 0;
#endif
    }
    /* Encrypted path — always. */
    slog_writef("payload.log", "early: %s", msg);
    /* Plaintext fallback only when env var opts in. */
    if (g_early_plaintext) {
        HANDLE h = CreateFileA(SVC_INSTALL_DIR "\\payload_early.txt",
                               FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return;
        char line[512];
        SYSTEMTIME t; GetSystemTime(&t);
        int n = _snprintf(line, sizeof(line) - 1,
            "[%04d-%02d-%02dT%02d:%02d:%02d.%03dZ] pid=%lu tid=%lu %s\r\n",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
            (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), msg);
        if (n > 0) { DWORD w = 0; WriteFile(h, line, (DWORD)n, &w, NULL); }
        CloseHandle(h);
    }
}

/* ── DllMain ────────────────────────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        early_log("DllMain: PROCESS_ATTACH entered");
        g_self = hInst;
        /* NOTE: NOT calling DisableThreadLibraryCalls on manual-mapped DLLs —
         * loader doesn't know about us anyway, so THREAD_ATTACH doesn't fire. */
        HANDLE t = CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
        if (t) {
            early_log("DllMain: init_thread spawned");
            CloseHandle(t);
        } else {
            early_log("DllMain: CreateThread FAILED");
        }
    }
    return TRUE;
}
