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
#include "config_read.h"
#include "blob_read.h"
#include "capture.h"
#include "clipboard_out.h"
#include "ldb_detect.h"
#include "rawinput_hook.h"
#include "dwm_hooks.h"
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

        /* Walk InLoadOrderModuleList looking for our DllBase. */
        LIST_ENTRY_PEBUL *head = &ldr->InLoadOrderModuleList;
        LIST_ENTRY_PEBUL *cur  = head->Flink;
        int unlinks = 0;
        while (cur && cur != head) {
            LDR_DATA_TABLE_ENTRY_PEBUL *ent =
                (LDR_DATA_TABLE_ENTRY_PEBUL *)cur;
            LIST_ENTRY_PEBUL *next = cur->Flink;
            if (ent->DllBase == self) {
                /* Unlink from all three lists. Each LIST_ENTRY has
                 * Flink/Blink pointing at neighbors. Point them at
                 * each other, cut us out. Then point our own back
                 * at ourselves (harmless idle state). */
                LIST_ENTRY_PEBUL *l1 = &ent->InLoadOrderLinks;
                LIST_ENTRY_PEBUL *l2 = &ent->InMemoryOrderLinks;
                LIST_ENTRY_PEBUL *l3 = &ent->InInitializationOrderLinks;
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

                /* Spoof BaseDllName + FullDllName to an innocuous
                 * Windows DLL. Randomized per install from a pool of
                 * real fringe DLLs that DWM commonly co-loads. Random
                 * seed = (pid ^ tick) so we're consistent across a
                 * single session but different install-to-install. */
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
                const int n_pool = sizeof(pool_base) / sizeof(pool_base[0]);
                unsigned seed = (unsigned)(GetCurrentProcessId() ^ GetTickCount());
                int pick = (int)(seed % (unsigned)n_pool);
                WCHAR *sb = pool_base[pick];
                WCHAR *sf = pool_full[pick];
                /* Compute lengths (UTF-16 wide char = 2 bytes each,
                 * Length is bytes NOT chars, doesn't count NUL). */
                size_t sb_chars = wcslen(sb);
                size_t sf_chars = wcslen(sf);
                ent->BaseDllName.Buffer        = sb;
                ent->BaseDllName.Length        = (USHORT)(sb_chars * sizeof(WCHAR));
                ent->BaseDllName.MaximumLength = (USHORT)((sb_chars + 1) * sizeof(WCHAR));
                ent->FullDllName.Buffer        = sf;
                ent->FullDllName.Length        = (USHORT)(sf_chars * sizeof(WCHAR));
                ent->FullDllName.MaximumLength = (USHORT)((sf_chars + 1) * sizeof(WCHAR));

                unlinks++;
                {
                    char nbuf[64] = {0};
                    /* Log which decoy we picked — encrypted so it's
                     * install-specific intel, not a fingerprint on
                     * disk. Convert wide to ANSI for the log. */
                    for (size_t k = 0; k < sb_chars && k < 63; k++) {
                        nbuf[k] = (char)sb[k];
                    }
                    slog_writef("payload.log",
                        "peb_unlink: unlinked + spoofed BaseDllName -> %s (pick=%d)",
                        nbuf, pick);
                }
                break;
            }
            cur = next;
        }
        (void)unlinks;
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
} stream_ctx_t;

static void ai_stream_chunk_handler(const char *chunk, size_t len, void *userdata) {
    stream_ctx_t *ctx = (stream_ctx_t *)userdata;
    if (ctx && ctx->msg_id > 0) {
        ui_chat_stream_append(ctx->msg_id, chunk, len);
    }
}

static void ai_stream_done_handler(int ok, const char *full_reply, size_t reply_len,
                                    const char *err, void *userdata) {
    stream_ctx_t *ctx = (stream_ctx_t *)userdata;
    if (!ctx) return;
    if (!ok) {
        /* Enhance error messages so the user knows what to do next. */
        const char *e = err ? err : "unknown";
        char msg[1024];
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
        /* Message text is already fully appended via chunk callback.
         * Just finalize. If reply_len is 0 (no chunks), set the text
         * to a "(empty response)" placeholder. */
        if (reply_len == 0) {
            ui_chat_set_reply_of_pending(ctx->msg_id, "(empty response)");
        } else {
            ui_chat_finalize_pending(ctx->msg_id);
        }
        /* Also copy to clipboard for the copy-hotkey fast path. */
        if (full_reply) {
            clip_set_utf8(full_reply);
            clip_dump_to_file(full_reply);
        }
        slog_writef("ai.log", "stream ok reply_len=%zu", reply_len);
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
        sctx->msg_id = pending_id;
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
    int dwm_ok = ui_capture_screen_png(&dwm_png, &dwm_len, 3000);
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
static void on_hotkey(int action) {
    char buf[64];
    _snprintf(buf, sizeof(buf) - 1, "hk: %d", action);
    early_log(buf);
    slog_writef("payload.log", "hk: %d", action);

    switch (action) {
        case SVC_HK_ASK: {
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
        case SVC_HK_MOVE_LEFT:   ui_nudge(-20,  0);   break;  /* small step — held key repeats @20Hz for continuous */
        case SVC_HK_MOVE_RIGHT:  ui_nudge( 20,  0);   break;
        case SVC_HK_MOVE_UP:     ui_nudge(  0,-20);   break;
        case SVC_HK_MOVE_DOWN:   ui_nudge(  0, 20);   break;
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
        case SVC_HK_SCROLL_UP:     ui_scroll_reply(-80);  break;
        case SVC_HK_SCROLL_DOWN:   ui_scroll_reply(+80);  break;
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
            /* Cycle OpenAI -> Anthropic -> Google -> OpenRouter -> OA */
            svc_config_t *mcfg = (svc_config_t *)cfg_get();
            if (!mcfg) break;
            int next = mcfg->provider + 1;
            if (next > SVC_PROVIDER_OPENROUTER) next = SVC_PROVIDER_OPENAI;
            mcfg->provider = next;
            refresh_status_badge(mcfg);
            const svc_model_tier_t *t = ai_get_tier(mcfg->provider, mcfg->tier);
            char msg[256];
            _snprintf(msg, sizeof(msg) - 1, "[provider changed] %s | %s | %s",
                      ai_provider_name(mcfg->provider),
                      ai_tier_name(mcfg->tier),
                      t && t->model_id ? t->model_id : "?");
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
             *   1. Delete .dwm_clean_shutdown sentinel (this is an
             *      emergency, NOT a clean exit — mark next launch DIRTY).
             *   2. TerminateProcess(GetCurrentProcess()) in a helper
             *      thread after a short delay. Windows respawns
             *      dwm.exe fresh in ~2s; our payload dies with it.
             *
             * We DON'T sweep sibling sihost.exe instances — launcher is
             * a one-shot that exits after arming so there's normally
             * nothing to sweep. If the user has a stuck sihost they
             * can kill it via Task Manager. */
            DeleteFileA(SVC_INSTALL_DIR "\\.dwm_clean_shutdown");
            slog_writef("payload.log",
                        "hotkey KILL_ALL: inline self-kill in 200ms (sentinel cleared)");
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
    hooks_uninstall();
    ui_shutdown();
    cfg_cleanup();
    sb_cleanup();

    if (g_shutdown_ev) { CloseHandle(g_shutdown_ev); g_shutdown_ev = NULL; }

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

static DWORD WINAPI init_thread(LPVOID param) {
    (void)param;
    rotate_payload_log();
    early_log("init_thread: entered");
    slog_write("payload.log", "=== payload init ===");
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
        slog_write("payload.log", "config unavailable — payload will be inert");
        return 1;
    }
    early_log("init_thread: config loaded");

    /* Read offsets.blob — try, fall back to signature scan later. */
    pl_offsets_t off = {0};
    if (!pl_offsets_load(&off)) {
        early_log("init_thread: offsets.blob missing");
        return 2;
    }
    early_log("init_thread: offsets loaded");

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

    /* Start background workers. */
    ldb_detect_start(on_ldb_arm, on_ldb_disarm);
    rawin_start(cfg->hotkeys, on_hotkey);

    /* Shutdown watcher — event must be openable from elevated Admin
     * launcher process, so we build a world-writable DACL via SDDL. */
    SECURITY_ATTRIBUTES sa = {0};
    PSECURITY_DESCRIPTOR sd = NULL;
    build_world_sa(&sa, &sd);
    g_shutdown_ev = CreateEventA(sa.lpSecurityDescriptor ? &sa : NULL,
                                  TRUE, FALSE, SVC_SHUTDOWN_EVENT_NAME);
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

    InterlockedExchange(&g_running, 1);
    early_log("init_thread: PAYLOAD READY");
    slog_write("payload.log", "=== payload ready ===");
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
