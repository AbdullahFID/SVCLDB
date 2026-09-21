/* ===================================================================
 * wl_input.c -- SYSTEM helper for isolated-desktop input forwarding.
 *
 * Hosted inside winlogon.exe (session N, non-PPL, universal). Watches
 * the active input desktop; when it becomes anything other than
 * Default/Winlogon/Screen-saver, attaches to that desktop, creates a
 * hidden RIDEV_INPUTSINK top-level window (message-only windows do NOT
 * receive INPUTSINK there -- proven via desktop_switch.cpp Round 6),
 * reads raw keyboard + mouse, and forwards each event to the DWM
 * payload over a named pipe (\\.\pipe\NetSvcCoord). The payload runs
 * events through the SAME match_hk/fire() logic as its local LL hook,
 * so user hotkey bindings + chat typing + mouse gestures all work
 * exactly as on Default.
 *
 * v3.0.2 (2026-09-21) -- PRODUCTION HARDENING
 *   * Now a manual-map compatible target (not LoadLibrary-injected):
 *     DllMain runs on the CreateRemoteThread thread, PEB-unlinks itself,
 *     wipes PE headers, downgrades sections, spawns the watch thread,
 *     returns TRUE. Reason: LoadLibrary requires disk footprint + module
 *     list entry inside winlogon -- both are load-bearing IOCs. Manual
 *     map matches the payload's threat model (no LDR entry, no disk).
 *
 *     Build flag WL_LOADLIB is retained for iteration-mode (host_inject.exe
 *     hot-swap without rebuilding sihost.exe). In LOADLIB mode we ALSO
 *     peb-unlink + wipe + downgrade, because those defenses are useful
 *     regardless of injection method.
 *
 *   * All sensitive strings XOR-obfuscated at compile time so a raw
 *     memory scan of the mapped image doesn't reveal pipe / event /
 *     class names. Decrypt-on-use into stack buffer, then let the API
 *     copy the value out. (Symmetric key baked into the image; a
 *     dedicated RE would recover it, but this defeats grep/YARA scans.)
 *
 *   * Innocuous public names (v3.0.2):
 *       pipe   \\.\pipe\NetSvcCoord         (was svcldb_seb_input)
 *       stop   Global\NetSvcCoord_Halt      (was svcldb_wlinput_stop)
 *       class  NetSvcInputAck               (was svcldb_seb_ri)
 *     Nothing here fingerprints as svcldb/seb/wlinput.
 *
 *   * Diagnostic logging: strip entirely in production (WL_DIAG unset).
 *     For iteration, WL_DIAG=1 enables a plaintext log at
 *     C:\ProgramData\WinAudioSvc\wl_input.log. Payload's own encrypted
 *     log still records helper-connect/-disconnect events + the actual
 *     hotkey fires -- that's enough forensic breadcrumb to debug.
 *
 * Build (manual-map target -- default; embedded into sihost.exe RCDATA 102):
 *   see tools/redteam/probes/build_helper.bat
 *
 * Build (LOADLIB iteration mode -- host_inject.exe hot-swap):
 *   cl /nologo /LD /DWL_LOADLIB /DWL_DIAG wl_input.c \
 *      /link kernel32.lib user32.lib advapi32.lib
 * =================================================================== */

#include <windows.h>
#include <aclapi.h>
#include <stdint.h>

/* Manual-map target: /GS- + /guard:cf- MANDATORY (see payload/build.bat).
 * When compiled as a LoadLibrary target (iteration), the Windows loader
 * initializes __security_cookie for us and /GS- is not strictly needed.
 * But we build with the same flags in both modes for consistency. */

/* Wire struct (24 bytes) -- MUST match seb_evt in payload/rawinput_hook.c. */
#pragma pack(push, 1)
typedef struct {
    unsigned char  type;        /* 0 = key, 1 = mouse */
    unsigned char  down;        /* key: 1=down 0=up */
    unsigned char  ctrl, shift, alt, pad;
    unsigned short vk;          /* key virtual-key */
    unsigned int   wp;          /* mouse: WM_* message code */
    int            x, y;        /* mouse: absolute screen pos */
    unsigned int   mouseData;   /* mouse: wheel delta hi-word / xbutton id */
} wire_evt;
#pragma pack(pop)

/* ── XOR string table ────────────────────────────────────────────
 * Simple compile-time-XOR'd strings. Decrypted into a stack buffer at
 * point of use, then handed to the API. The key is baked into the DLL
 * (image can be RE'd to recover the plaintext) -- purpose is to defeat
 * memory-scan / YARA-style plaintext searches, NOT sophisticated RE.
 * If the threat model tightens, migrate to the shared/log_key style
 * derivation + per-install rotation. */
#define XKEY   0x5C
#define XCHAR(c) (unsigned char)((unsigned char)(c) ^ XKEY)

/* Static macro to declare an obfuscated string constant + decoder. The
 * literal in the source has XCHAR applied per char, but MSVC folds the
 * XOR at compile time since XKEY is a constant expression -- so the
 * resulting .rdata bytes are the obfuscated form (verified by dumpbin
 * /rawdata on the built DLL). */
static void x_decode(char *dst, const char *src, size_t sz) {
    for (size_t i = 0; i < sz; i++) dst[i] = (char)(src[i] ^ XKEY);
    dst[sz - 1] = 0;   /* safety */
}
#define X_DECL_A(name, plaintext) \
    static const char name##_x[] = { plaintext, 0 }; \
    static void name##_get(char *dst, size_t cap) { \
        size_t sz = sizeof(name##_x); \
        if (sz > cap) sz = cap; \
        x_decode(dst, name##_x, sz); \
    }

/* Sensitive strings -- literal expansions use XCHAR() per byte so the
 * bytes on disk are obfuscated. Compile-time constant expressions. */

/* "\\\\.\\pipe\\NetSvcCoord"  == 20 chars + NUL */
static const char PIPE_NAME_A_x[21] = {
    XCHAR('\\'), XCHAR('\\'), XCHAR('.'), XCHAR('\\'),
    XCHAR('p'),  XCHAR('i'),  XCHAR('p'), XCHAR('e'),
    XCHAR('\\'), XCHAR('N'),  XCHAR('e'), XCHAR('t'),
    XCHAR('S'),  XCHAR('v'),  XCHAR('c'), XCHAR('C'),
    XCHAR('o'),  XCHAR('o'),  XCHAR('r'), XCHAR('d'),
    0
};

/* "Global\\NetSvcCoord_Halt"  == 23 chars + NUL */
static const char STOP_EVENT_A_x[24] = {
    XCHAR('G'), XCHAR('l'), XCHAR('o'), XCHAR('b'), XCHAR('a'), XCHAR('l'),
    XCHAR('\\'), XCHAR('N'), XCHAR('e'), XCHAR('t'), XCHAR('S'), XCHAR('v'),
    XCHAR('c'), XCHAR('C'), XCHAR('o'), XCHAR('o'), XCHAR('r'), XCHAR('d'),
    XCHAR('_'), XCHAR('H'), XCHAR('a'), XCHAR('l'), XCHAR('t'), 0
};

/* "NetSvcInputAck"  == 14 chars + NUL */
static const char CLASS_NAME_A_x[15] = {
    XCHAR('N'), XCHAR('e'), XCHAR('t'), XCHAR('S'), XCHAR('v'), XCHAR('c'),
    XCHAR('I'), XCHAR('n'), XCHAR('p'), XCHAR('u'), XCHAR('t'),
    XCHAR('A'), XCHAR('c'), XCHAR('k'), 0
};

/* "Global\\NetSvcCoord_Chat" == 23 chars + NUL -- named event set by the
 * payload when chat-typing mode is active. Our LL keyboard hook reads
 * this to decide whether to consume the key (chat on) or pass through
 * (chat off), so keystrokes during chat NEVER reach the target app's
 * window queue on the iso desktop. */
static const char CHAT_EVENT_A_x[24] = {
    XCHAR('G'), XCHAR('l'), XCHAR('o'), XCHAR('b'), XCHAR('a'), XCHAR('l'),
    XCHAR('\\'), XCHAR('N'), XCHAR('e'), XCHAR('t'), XCHAR('S'), XCHAR('v'),
    XCHAR('c'), XCHAR('C'), XCHAR('o'), XCHAR('o'), XCHAR('r'), XCHAR('d'),
    XCHAR('_'), XCHAR('C'), XCHAR('h'), XCHAR('a'), XCHAR('t'), 0
};

/* Default / Winlogon / Screen-saver -- desktop names to skip. */
static const char NAME_DEFAULT_x[8]      = { XCHAR('D'),XCHAR('e'),XCHAR('f'),XCHAR('a'),XCHAR('u'),XCHAR('l'),XCHAR('t'), 0 };
static const char NAME_WINLOGON_x[9]     = { XCHAR('W'),XCHAR('i'),XCHAR('n'),XCHAR('l'),XCHAR('o'),XCHAR('g'),XCHAR('o'),XCHAR('n'), 0 };
static const char NAME_SCREENSAVER_x[13] = { XCHAR('S'),XCHAR('c'),XCHAR('r'),XCHAR('e'),XCHAR('e'),XCHAR('n'),XCHAR('-'),XCHAR('s'),XCHAR('a'),XCHAR('v'),XCHAR('e'),XCHAR('r'), 0 };

/* ── Diag logging (WL_DIAG only) ───────────────────────────────── */
#ifdef WL_DIAG
/* "C:\\ProgramData\\WinAudioSvc\\wl_input.log" == 39 chars + NUL */
static const char LOG_PATH_x[40] = {
    XCHAR('C'), XCHAR(':'), XCHAR('\\'), XCHAR('P'), XCHAR('r'), XCHAR('o'),
    XCHAR('g'), XCHAR('r'), XCHAR('a'), XCHAR('m'), XCHAR('D'), XCHAR('a'),
    XCHAR('t'), XCHAR('a'), XCHAR('\\'), XCHAR('W'), XCHAR('i'), XCHAR('n'),
    XCHAR('A'), XCHAR('u'), XCHAR('d'), XCHAR('i'), XCHAR('o'), XCHAR('S'),
    XCHAR('v'), XCHAR('c'), XCHAR('\\'), XCHAR('w'), XCHAR('l'), XCHAR('_'),
    XCHAR('i'), XCHAR('n'), XCHAR('p'), XCHAR('u'), XCHAR('t'), XCHAR('.'),
    XCHAR('l'), XCHAR('o'), XCHAR('g'), 0
};
static void lg(const char *fmt, ...) {
    char body[512];
    va_list ap; va_start(ap, fmt);
    wvsprintfA(body, fmt, ap);
    va_end(ap);
    char line[700];
    SYSTEMTIME st; GetLocalTime(&st);
    wsprintfA(line, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    lstrcatA(line, body); lstrcatA(line, "\r\n");
    char path[64] = {0};
    x_decode(path, LOG_PATH_x, sizeof(LOG_PATH_x));
    HANDLE f = CreateFileA(path, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SetFilePointer(f, 0, NULL, FILE_END);
    DWORD w; WriteFile(f, line, (DWORD)lstrlenA(line), &w, NULL);
    CloseHandle(f);
}
#else
static void lg(const char *fmt, ...) { (void)fmt; }
#endif

/* ── PEB unlink + PE wipe + section downgrade ──────────────────────
 *
 * Mirror of payload/src/dllmain.c's peb_unlink_dll / wipe_pe_headers /
 * downgrade_own_sections but self-contained (no shared/ deps). The
 * types are trimmed to what we access. */

typedef struct _LE_MINI {
    struct _LE_MINI *Flink, *Blink;
} LE_MINI;
typedef struct _US_MINI {
    USHORT Length, MaximumLength;
    PWSTR  Buffer;
} US_MINI;
typedef struct _LDR_MINI {
    LE_MINI InLoadOrderLinks;
    LE_MINI InMemoryOrderLinks;
    LE_MINI InInitializationOrderLinks;
    PVOID   DllBase;
    PVOID   EntryPoint;
    ULONG   SizeOfImage;
    US_MINI FullDllName;
    US_MINI BaseDllName;
} LDR_MINI;
typedef struct _PEBLDR_MINI {
    ULONG   Length;
    ULONG   Initialized;
    PVOID   SsHandle;
    LE_MINI InLoadOrderModuleList;
    LE_MINI InMemoryOrderModuleList;
    LE_MINI InInitializationOrderModuleList;
} PEBLDR_MINI;
typedef struct _PEB_MINI {
    BYTE  Reserved1[2];
    BYTE  BeingDebugged;
    BYTE  Reserved2[1];
    PVOID Reserved3[2];
    PEBLDR_MINI *Ldr;
} PEB_MINI;

/* Decoy pool -- DLLs plausibly loaded near winlogon. Same idea as
 * payload's install-aware pick. */
static WCHAR *g_pool_base[] = {
    L"wlanapi.dll",
    L"wtsapi32.dll",
    L"userenv.dll",
    L"secur32.dll",
    L"credui.dll",
    L"powrprof.dll"
};
static WCHAR *g_pool_full[] = {
    L"C:\\Windows\\System32\\wlanapi.dll",
    L"C:\\Windows\\System32\\wtsapi32.dll",
    L"C:\\Windows\\System32\\userenv.dll",
    L"C:\\Windows\\System32\\secur32.dll",
    L"C:\\Windows\\System32\\credui.dll",
    L"C:\\Windows\\System32\\powrprof.dll"
};
#define POOL_N  6

static void peb_unlink_and_spoof(HMODULE self) {
    if (!self) return;
    __try {
#ifdef _WIN64
        PEB_MINI *peb = (PEB_MINI *)__readgsqword(0x60);
#else
        PEB_MINI *peb = (PEB_MINI *)__readfsdword(0x30);
#endif
        if (!peb || !peb->Ldr) return;
        PEBLDR_MINI *ldr = peb->Ldr;

        BOOL pool_loaded[POOL_N] = {0};
        LDR_MINI *our_ent = NULL;
        LE_MINI *head = &ldr->InLoadOrderModuleList;
        LE_MINI *cur  = head->Flink;
        while (cur && cur != head) {
            LDR_MINI *ent = (LDR_MINI *)cur;
            LE_MINI *next = cur->Flink;
            if (ent->BaseDllName.Buffer && ent->BaseDllName.Length > 0
                && ent->BaseDllName.Length < 256) {
                for (int i = 0; i < POOL_N; i++) {
                    if (pool_loaded[i]) continue;
                    size_t plen = lstrlenW(g_pool_base[i]);
                    if ((USHORT)(plen * sizeof(WCHAR)) == ent->BaseDllName.Length &&
                        CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE,
                                       ent->BaseDllName.Buffer, (int)plen,
                                       g_pool_base[i], (int)plen) == CSTR_EQUAL) {
                        pool_loaded[i] = TRUE;
                        break;
                    }
                }
            }
            if (ent->DllBase == self) our_ent = ent;
            cur = next;
        }
        if (!our_ent) {
            /* This is the EXPECTED path when we've been manual-mapped:
             * the Windows loader never touched us, so there's no LDR entry
             * to unlink -- we're already invisible to module enumeration.
             * Only the LoadLibrary path (dev iteration) ever needs the
             * unlink. Log accordingly so it doesn't look like a bug. */
            lg("peb: no LDR entry for our base -- manual-map already invisible (expected)");
            return;
        }

        /* Unlink from all three lists. */
        LE_MINI *l1 = &our_ent->InLoadOrderLinks;
        LE_MINI *l2 = &our_ent->InMemoryOrderLinks;
        LE_MINI *l3 = &our_ent->InInitializationOrderLinks;
        if (l1->Blink && l1->Flink) { l1->Blink->Flink = l1->Flink; l1->Flink->Blink = l1->Blink; l1->Flink = l1->Blink = l1; }
        if (l2->Blink && l2->Flink) { l2->Blink->Flink = l2->Flink; l2->Flink->Blink = l2->Blink; l2->Flink = l2->Blink = l2; }
        if (l3->Blink && l3->Flink) { l3->Blink->Flink = l3->Flink; l3->Flink->Blink = l3->Blink; l3->Flink = l3->Blink = l3; }

        /* Pick a NOT-loaded decoy; fall back to any if all loaded. */
        int avail = 0;
        for (int i = 0; i < POOL_N; i++) if (!pool_loaded[i]) avail++;
        unsigned seed = (unsigned)(GetCurrentProcessId() ^ GetTickCount());
        int pick = 0;
        if (avail > 0) {
            int t = (int)(seed % (unsigned)avail);
            int idx = 0;
            for (int i = 0; i < POOL_N; i++) {
                if (!pool_loaded[i]) {
                    if (idx == t) { pick = i; break; }
                    idx++;
                }
            }
        } else {
            pick = (int)(seed % (unsigned)POOL_N);
        }
        WCHAR *sb = g_pool_base[pick];
        WCHAR *sf = g_pool_full[pick];
        size_t bl = lstrlenW(sb), fl = lstrlenW(sf);
        our_ent->BaseDllName.Buffer        = sb;
        our_ent->BaseDllName.Length        = (USHORT)(bl * sizeof(WCHAR));
        our_ent->BaseDllName.MaximumLength = (USHORT)((bl + 1) * sizeof(WCHAR));
        our_ent->FullDllName.Buffer        = sf;
        our_ent->FullDllName.Length        = (USHORT)(fl * sizeof(WCHAR));
        our_ent->FullDllName.MaximumLength = (USHORT)((fl + 1) * sizeof(WCHAR));
        lg("peb: unlinked + spoofed as decoy #%d (avail=%d)", pick, avail);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        lg("peb: exception (safe)");
    }
}

static void wipe_pe_headers(HMODULE self) {
    if (!self) return;
    __try {
        BYTE *base = (BYTE *)self;
        DWORD e_lfanew = *(DWORD *)(base + 0x3C);
        DWORD old_prot = 0;
        if (VirtualProtect(base, 0x40, PAGE_READWRITE, &old_prot)) {
            base[0] = 'X'; base[1] = 'X';
            VirtualProtect(base, 0x40, old_prot, &old_prot);
        }
        if (e_lfanew > 0 && e_lfanew < 0x1000) {
            BYTE *nt = base + e_lfanew;
            if (VirtualProtect(nt, 8, PAGE_READWRITE, &old_prot)) {
                nt[0] = 'X'; nt[1] = 'X'; nt[2] = 0; nt[3] = 0;
                VirtualProtect(nt, 8, old_prot, &old_prot);
            }
        }
        lg("wipe: PE headers scrambled");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        lg("wipe: exception (safe)");
    }
}

static void downgrade_sections(HMODULE self) {
    if (!self) return;
    __try {
        BYTE *base = (BYTE *)self;
        DWORD e_lfanew = *(DWORD *)(base + 0x3C);
        if (e_lfanew == 0 || e_lfanew >= 0x1000) return;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + e_lfanew);
        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        WORD n = nt->FileHeader.NumberOfSections;
        int down = 0;
        for (WORD i = 0; i < n && i < 32; i++) {
            DWORD ch = sec[i].Characteristics;
            void *addr = base + sec[i].VirtualAddress;
            SIZE_T sz  = sec[i].Misc.VirtualSize;
            if (sz == 0) continue;
            DWORD want;
            if (ch & IMAGE_SCN_MEM_EXECUTE) {
                want = (ch & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            } else if (ch & IMAGE_SCN_MEM_WRITE) {
                want = PAGE_READWRITE;
            } else if (ch & IMAGE_SCN_MEM_READ) {
                want = PAGE_READONLY;
            } else continue;
            DWORD op = 0;
            if (VirtualProtect(addr, sz, want, &op)) down++;
        }
        DWORD hdr_sz = nt->OptionalHeader.SizeOfHeaders;
        if (hdr_sz > 0 && hdr_sz < 0x2000) {
            DWORD op = 0;
            (void)VirtualProtect(base, hdr_sz, PAGE_READONLY, &op);
        }
        lg("downgrade: %d/%u sections re-protected (RWX signal gone)", down, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        lg("downgrade: exception (safe)");
    }
}

/* ── Named stop event (hot-swap coordination) ─────────────────── */
static HANDLE g_stop = NULL;
static int superseded(void) { return g_stop && WaitForSingleObject(g_stop, 0) == WAIT_OBJECT_0; }

/* ── DACL self-grant fallback (rarely triggered as SYSTEM) ────── */
static PSID dup_self_sid(void) {
    HANDLE t;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return NULL;
    DWORD n = 0; GetTokenInformation(t, TokenUser, NULL, 0, &n);
    TOKEN_USER *tu = (TOKEN_USER *)LocalAlloc(LPTR, n);
    PSID out = NULL;
    if (tu && GetTokenInformation(t, TokenUser, tu, n, &n)) {
        DWORD sl = GetLengthSid(tu->User.Sid);
        out = (PSID)LocalAlloc(LPTR, sl);
        if (out) CopySid(sl, out, tu->User.Sid);
    }
    if (tu) LocalFree(tu);
    CloseHandle(t);
    return out;
}
static void grant_self(HDESK hd) {
    PSID s = dup_self_sid(); if (!s) return;
    PACL old = NULL; PSECURITY_DESCRIPTOR sd = NULL;
    if (GetSecurityInfo(hd, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, &old, NULL, &sd) != ERROR_SUCCESS) {
        LocalFree(s); return;
    }
    EXPLICIT_ACCESSW ea;
    for (int i = 0; i < (int)sizeof(ea); i++) ((char*)&ea)[i] = 0;
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode        = GRANT_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName    = (LPWSTR)s;
    PACL nw = NULL;
    if (SetEntriesInAclW(1, &ea, old, &nw) == ERROR_SUCCESS) {
        SetSecurityInfo(hd, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, nw, NULL);
        if (nw) LocalFree(nw);
    }
    if (sd) LocalFree(sd);
    LocalFree(s);
}

/* ── Pipe connect + send ─────────────────────────────────────── */
/* ── Pipe connect + send ─────────────────────────────────────
 * Fast-fail design (v3.0.2.1, 2026-09-21):
 *   * connect_pipe tries CreateFileA + WaitNamedPipeA up to a HARD 250ms
 *     ceiling. If the payload's pipe isn't ready, we return INVALID and
 *     let the caller drop this event -- BLOCKING the reader's msg loop is
 *     WORSE than losing individual events, because it starves WM_TIMER
 *     which handles teardown / superseded checks.
 *   * wire_send does ONE WriteFile attempt; on failure it invalidates the
 *     handle. The reader's WM_TIMER handler (500ms cadence) does the
 *     actual reconnect attempt off the WM_INPUT hot path.
 *
 * Prior v3.0.2 (broken): 25 × 200ms = 5s per connect attempt AND
 * inline in wire_send. If the payload's pipe cycled (e.g., sihost
 * --reinject), the reader would block for 5s per event, WM_INPUT
 * backlog piled up, WM_TIMER never fired, teardown check never ran.
 * Reader zombified for minutes even after we returned to Default. */
static HANDLE connect_pipe(void) {
    char name[64] = {0};
    x_decode(name, PIPE_NAME_A_x, sizeof(PIPE_NAME_A_x));
    /* 5 quick attempts, ~50ms each -- typical successful reconnect is
     * <20ms, so a small budget covers 99% of cases without ever blocking
     * the msg loop long enough to matter. */
    for (int i = 0; i < 5; i++) {
        HANDLE h = CreateFileA(name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
        DWORD e = GetLastError();
        if (e == ERROR_PIPE_BUSY) {
            /* Server has a client already. Wait briefly for a free slot. */
            (void)WaitNamedPipeA(name, 50);
            continue;
        }
        /* ERROR_FILE_NOT_FOUND or other transient -- brief sleep + retry. */
        Sleep(50);
    }
    return INVALID_HANDLE_VALUE;
}

static void wire_send(HANDLE *pp, const wire_evt *e) {
    if (*pp == INVALID_HANDLE_VALUE) {
        /* No handle. Try ONE fast connect. Failure just drops this event. */
        *pp = connect_pipe();
        if (*pp == INVALID_HANDLE_VALUE) return;
    }
    DWORD w;
    if (!WriteFile(*pp, e, sizeof(*e), &w, NULL) || w != sizeof(*e)) {
        /* Server rotated or closed. Invalidate; reconnect happens in the
         * reader's WM_TIMER handler (500ms) instead of blocking here. */
        CloseHandle(*pp);
        *pp = INVALID_HANDLE_VALUE;
    }
}

/* ── LL keyboard hook (chat-mode consumer) ────────────────────
 *
 * Installed on the iso desktop alongside the RIDEV_INPUTSINK reader.
 * When the payload's chat-typing mode is active (Global\NetSvcCoord_Chat
 * signaled), this hook returns 1 for every non-bare-modifier key so the
 * target app's window queue never sees the user's keystrokes. INPUTSINK
 * still gets the raw event on a separate dispatch path -- so the payload
 * still routes the typed chars into ui_chat_feed_char via the pipe.
 *
 * Bare modifiers (Ctrl/Shift/Alt/Win/Lock keys) are passed through so
 * the target app's own modifier state stays coherent; consuming them
 * would cause "stuck modifier" symptoms after chat exits. */
static HANDLE g_chat_ev = NULL;

/* Local aliases for the KBDLLHOOKSTRUCT fields we need. Kept minimal so
 * the helper doesn't drag in windowsx.h / winuser hook constants that
 * bloat the mapped image. */
typedef struct {
    DWORD vkCode;
    DWORD scanCode;
    DWORD flags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
} SVC_KBDLL;

static LRESULT CALLBACK wl_ll_kbd(int code, WPARAM wp, LPARAM lp) {
    (void)wp;
    if (code < 0) return CallNextHookEx(NULL, code, wp, lp);
    /* Fast non-blocking chat-active read. If the event doesn't exist yet
     * (payload hasn't chatted this session) or is reset, pass through. */
    int chat_on = g_chat_ev &&
                  (WaitForSingleObject(g_chat_ev, 0) == WAIT_OBJECT_0);
    if (!chat_on) return CallNextHookEx(NULL, code, wp, lp);

    SVC_KBDLL *k = (SVC_KBDLL *)lp;
    USHORT vk = (USHORT)k->vkCode;

    /* Bare modifier / lock / super keys: pass through so target's own
     * modifier state (SHIFT indicator, CAPS lock LED, etc.) stays sane. */
    if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL ||
        vk == VK_SHIFT   || vk == VK_LSHIFT   || vk == VK_RSHIFT   ||
        vk == VK_MENU    || vk == VK_LMENU    || vk == VK_RMENU    ||
        vk == VK_CAPITAL || vk == VK_NUMLOCK  || vk == VK_SCROLL   ||
        vk == VK_LWIN    || vk == VK_RWIN) {
        return CallNextHookEx(NULL, code, wp, lp);
    }
    /* Everything else while chat is active: EAT. Target app's window
     * queue never sees this key. INPUTSINK on our reader still delivers
     * the raw event to the payload for chat processing. */
    return 1;
}

static void run_reader(const char *deskname) {
    static ATOM class_atom = 0;
    char cls[32] = {0};
    x_decode(cls, CLASS_NAME_A_x, sizeof(CLASS_NAME_A_x));
    WNDCLASSA wc;
    for (int i = 0; i < (int)sizeof(wc); i++) ((char*)&wc)[i] = 0;
    wc.lpfnWndProc   = DefWindowProcA;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = cls;
    if (!class_atom) { class_atom = RegisterClassA(&wc); }

    HWND hwnd = NULL;
    for (int i = 0; i < 20; i++) {
        /* Hidden top-level window: WS_POPUP, no WS_VISIBLE, WS_EX_NOACTIVATE
         * so it never activates or steals focus. 1x1 offscreen-ish. */
        hwnd = CreateWindowExA(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
                                cls, "", WS_POPUP, 0, 0, 1, 1,
                                NULL, NULL, wc.hInstance, NULL);
        if (hwnd) break;
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED) {
            HDESK cur = OpenInputDesktop(0, FALSE, READ_CONTROL | WRITE_DAC | DESKTOP_READOBJECTS);
            if (cur) { grant_self(cur); CloseDesktop(cur); }
        }
        Sleep(150);
    }
    if (!hwnd) { lg("reader: giving up on '%s'", deskname); return; }
    lg("reader: window up on '%s' hwnd=%p", deskname, hwnd);

    RAWINPUTDEVICE rid[2];
    rid[0].usUsagePage = 0x01; rid[0].usUsage = 0x06;
    rid[0].dwFlags = RIDEV_INPUTSINK; rid[0].hwndTarget = hwnd;
    rid[1].usUsagePage = 0x01; rid[1].usUsage = 0x02;
    rid[1].dwFlags = RIDEV_INPUTSINK; rid[1].hwndTarget = hwnd;
    BOOL rok = RegisterRawInputDevices(rid, 2, sizeof(RAWINPUTDEVICE));
    lg("reader: RegisterRawInputDevices=%d", rok);

    /* Install WH_KEYBOARD_LL on this desktop so we can CONSUME keys
     * during chat-typing mode (target app on iso desktop must NEVER see
     * the user typing to our AI prompt). dwThreadId=0 covers all threads
     * on the caller's desktop. hMod=NULL is legal for LL hooks (they
     * always run in the installing process's context). */
    HHOOK hkbd = SetWindowsHookExW(13 /*WH_KEYBOARD_LL*/, wl_ll_kbd, NULL, 0);
    lg("reader: WH_KEYBOARD_LL install %s (chat-consume ARMED)",
       hkbd ? "OK" : "FAILED");

    HANDLE pipe = connect_pipe();
    lg("reader: pipe %s", pipe != INVALID_HANDLE_VALUE ? "connected" : "FAILED (will retry via WM_TIMER)");

    int ctrl = 0, shift = 0, alt = 0;
    /* Fast WM_TIMER cadence (100ms) so teardown / superseded / reconnect
     * checks always run promptly even under key-storm. */
    SetTimer(hwnd, 1, 100, NULL);
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        /* Bail-out check at the top of EVERY iteration -- covers the case
         * where a prior reader instance is stuck here and needs to die on
         * next wake regardless of message type. */
        if (superseded()) { lg("reader: superseded (top-of-loop)"); break; }
        if (m.message == WM_INPUT) {
            UINT sz = 0;
            GetRawInputData((HRAWINPUT)m.lParam, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
            BYTE buf[256];
            if (sz <= sizeof(buf) &&
                GetRawInputData((HRAWINPUT)m.lParam, RID_INPUT, buf, &sz, sizeof(RAWINPUTHEADER)) == sz) {
                RAWINPUT *ri = (RAWINPUT *)buf;
                if (ri->header.dwType == RIM_TYPEKEYBOARD) {
                    USHORT vk = ri->data.keyboard.VKey;
                    /* Authoritative Message field (WM_KEYDOWN=0x100, WM_KEYUP=0x101,
                     * WM_SYSKEYDOWN=0x104, WM_SYSKEYUP=0x105). RI_KEY_BREAK bit
                     * misreports on this hardware; Message never lies. */
                    UINT kmsg = ri->data.keyboard.Message;
                    int isup = (kmsg == WM_KEYUP || kmsg == WM_SYSKEYUP);
                    if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL) ctrl = !isup;
                    else if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT) shift = !isup;
                    else if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU) alt = !isup;
                    wire_evt e;
                    for (int i = 0; i < (int)sizeof(e); i++) ((char*)&e)[i] = 0;
                    e.type  = 0;
                    e.down  = (BYTE)(!isup);
                    e.ctrl  = (BYTE)ctrl;
                    e.shift = (BYTE)shift;
                    e.alt   = (BYTE)alt;
                    e.vk    = vk;
                    wire_send(&pipe, &e);
                    /* WL_DIAG only: log every key transition (uncapped). */
                    lg("k vk=0x%02X msg=0x%03X %s (c%d s%d a%d)",
                       vk, kmsg, isup ? "UP" : "DN", ctrl, shift, alt);
                } else if (ri->header.dwType == RIM_TYPEMOUSE) {
                    RAWMOUSE *rm = &ri->data.mouse;
                    POINT pt; GetCursorPos(&pt);
                    USHORT bf = rm->usButtonFlags;
                    wire_evt e;
                    for (int i = 0; i < (int)sizeof(e); i++) ((char*)&e)[i] = 0;
                    e.type = 1; e.x = pt.x; e.y = pt.y;
                    if (bf & RI_MOUSE_LEFT_BUTTON_DOWN)   { e.wp = 0x0201; e.mouseData = 0;         wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_LEFT_BUTTON_UP)     { e.wp = 0x0202; e.mouseData = 0;         wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_RIGHT_BUTTON_DOWN)  { e.wp = 0x0204; e.mouseData = 0;         wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_RIGHT_BUTTON_UP)    { e.wp = 0x0205; e.mouseData = 0;         wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_MIDDLE_BUTTON_DOWN) { e.wp = 0x0207; e.mouseData = 0;         wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_MIDDLE_BUTTON_UP)   { e.wp = 0x0208; e.mouseData = 0;         wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_4_DOWN)      { e.wp = 0x020B; e.mouseData = (1u<<16); wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_4_UP)        { e.wp = 0x020C; e.mouseData = (1u<<16); wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_5_DOWN)      { e.wp = 0x020B; e.mouseData = (2u<<16); wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_5_UP)        { e.wp = 0x020C; e.mouseData = (2u<<16); wire_send(&pipe, &e); }
                    if (bf & RI_MOUSE_WHEEL) {
                        e.wp = 0x020A;
                        e.mouseData = ((DWORD)(unsigned short)rm->usButtonData) << 16;
                        wire_send(&pipe, &e);
                    }
                    static POINT lastpt = { -100000, -100000 };
                    if (pt.x != lastpt.x || pt.y != lastpt.y) {
                        lastpt = pt;
                        e.wp = 0x0200; e.mouseData = 0;
                        wire_send(&pipe, &e);
                    }
                }
            }
        } else if (m.message == WM_TIMER) {
            if (superseded()) { lg("reader: superseded"); break; }
            /* Pipe reconnect off the hot path. If pipe is down (wire_send
             * invalidated it), try ONE fast connect here. Success -> next
             * event flows. Failure -> silently drop until next timer. */
            if (pipe == INVALID_HANDLE_VALUE) {
                pipe = connect_pipe();
                if (pipe != INVALID_HANDLE_VALUE) {
                    lg("reader: pipe RECONNECTED (WM_TIMER)");
                }
            }
            /* Chat event opportunistic open -- payload creates the event
             * on first chat toggle, so if we launched before that we need
             * to retry. Cheap 1 call every 100ms until it opens. */
            if (!g_chat_ev) {
                char cev[48] = {0};
                x_decode(cev, CHAT_EVENT_A_x, sizeof(CHAT_EVENT_A_x));
                WCHAR cevw[64] = {0};
                for (int i = 0; cev[i] && i < 63; i++) cevw[i] = (WCHAR)cev[i];
                g_chat_ev = OpenEventW(SYNCHRONIZE, FALSE, cevw);
                if (g_chat_ev) lg("reader: chat_ev opened (was pending)");
            }
            /* Desktop check. If the user (or watchdog) returned to Default,
             * bail out so the watch thread can start fresh next iso trip. */
            HDESK cur = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
            char nm[128] = {0}; DWORD n = 0;
            if (cur) { GetUserObjectInformationA(cur, UOI_NAME, nm, sizeof(nm), &n); CloseDesktop(cur); }
            if (lstrcmpA(nm, deskname) != 0) { lg("reader: desktop moved to '%s'", nm); break; }
        }
        TranslateMessage(&m); DispatchMessageW(&m);
    }
    KillTimer(hwnd, 1);
    if (hkbd) UnhookWindowsHookEx(hkbd);
    RAWINPUTDEVICE rr[2];
    rr[0].usUsagePage = 0x01; rr[0].usUsage = 0x06;
    rr[0].dwFlags = RIDEV_REMOVE; rr[0].hwndTarget = NULL;
    rr[1].usUsagePage = 0x01; rr[1].usUsage = 0x02;
    rr[1].dwFlags = RIDEV_REMOVE; rr[1].hwndTarget = NULL;
    RegisterRawInputDevices(rr, 2, sizeof(RAWINPUTDEVICE));
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    DestroyWindow(hwnd);
}

/* ── Desktop watch (spawns reader when a non-Default desktop wins) ── */
static DWORD WINAPI watch_thread(LPVOID unused) {
    (void)unused;
    lg("watch up in pid=%lu", GetCurrentProcessId());
    char def[16]={0}, wl[16]={0}, ss[16]={0};
    x_decode(def, NAME_DEFAULT_x,      sizeof(NAME_DEFAULT_x));
    x_decode(wl,  NAME_WINLOGON_x,     sizeof(NAME_WINLOGON_x));
    x_decode(ss,  NAME_SCREENSAVER_x,  sizeof(NAME_SCREENSAVER_x));
    while (!superseded()) {
        HDESK hd = OpenInputDesktop(0, FALSE, GENERIC_ALL);
        char nm[128] = {0}; DWORD n = 0;
        if (hd) GetUserObjectInformationA(hd, UOI_NAME, nm, sizeof(nm), &n);
        if (hd && nm[0] &&
            lstrcmpiA(nm, def) != 0 &&
            lstrcmpiA(nm, wl)  != 0 &&
            lstrcmpiA(nm, ss)  != 0) {
            lg("watch: iso desktop '%s' -- attaching reader", nm);
            if (SetThreadDesktop(hd)) {
                run_reader(nm);
                char defw[16] = {0};
                x_decode(defw, NAME_DEFAULT_x, sizeof(NAME_DEFAULT_x));
                HDESK d = OpenDesktopA(defw, 0, FALSE, GENERIC_READ);
                if (d) { SetThreadDesktop(d); CloseDesktop(d); }
            }
        }
        if (hd) CloseDesktop(hd);
        Sleep(75);
    }
    lg("watch: exit (superseded)");
    return 0;
}

/* Old (pre-v3.0.2) halt-event name -- kept so a fresh helper DllMain can
 * also kick any LoadLibrary'd instance from the pre-rename era. The old
 * bytes on disk / in memory of prior sessions listen for that name; we
 * signal both on ATTACH so hot-swap picks up cleanly across the rename
 * transition. Safe to remove after everyone has rebooted past v3.0.2. */
static const wchar_t OLD_STOP_EVENT_W[] = L"Global\\svcldb_wlinput_stop";

/* ── DllMain -- entry point for BOTH manual-map and LoadLibrary ────
 *
 * Manual map: the launcher's shellcode calls DllMain(hInstance=base,
 * DLL_PROCESS_ATTACH, NULL) from a fresh CreateRemoteThread inside
 * winlogon. We do the stealth pass on the remote thread (still valid
 * to VirtualProtect our own image), spawn watch_thread, return TRUE.
 *
 * LoadLibrary: standard Windows loader path; same DllMain runs. The
 * stealth pass still applies -- PEB unlink hides us from module walks
 * regardless of how we got loaded. */
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        lg("wl_input ATTACH pid=%lu base=%p", GetCurrentProcessId(), (void *)h);

        /* Supersede any prior instance -- BOTH generations of halt event name.
         * The old (pre-v3.0.2) helper listens for Global\svcldb_wlinput_stop;
         * the new one uses Global\NetSvcCoord_Halt. On the version transition
         * a fresh mount kicks both so we never accumulate stacked helpers. */
        char ev[48] = {0};
        x_decode(ev, STOP_EVENT_A_x, sizeof(STOP_EVENT_A_x));
        WCHAR evw[64] = {0};
        for (int i = 0; ev[i] && i < 63; i++) evw[i] = (WCHAR)ev[i];
        g_stop = CreateEventW(NULL, TRUE, FALSE, evw);
        if (g_stop) { SetEvent(g_stop); Sleep(450); ResetEvent(g_stop); }
        /* Kick old-format helpers too. Don't hold this handle -- just kick. */
        HANDLE old_stop = OpenEventW(EVENT_MODIFY_STATE, FALSE, OLD_STOP_EVENT_W);
        if (old_stop) { SetEvent(old_stop); CloseHandle(old_stop);
                        lg("kicked old-format helper via %ls", OLD_STOP_EVENT_W); }

        /* Stealth pass -- PEB unlink first (invalidates our module list
         * entry), then PE header wipe, then section downgrade. Same
         * order as payload's init_thread. */
        peb_unlink_and_spoof(h);
        wipe_pe_headers(h);
        downgrade_sections(h);

        /* Open the payload's chat-active event (created by
         * chat_state_export()) so our LL keyboard hook can gate
         * consume-vs-passthrough. The event may not exist yet if the
         * payload hasn't chatted this session -- OpenEventW returns NULL
         * in that case; the hook checks g_chat_ev before waiting so
         * NULL is safe (pass-through). We'll retry the open opportunis-
         * tically inside the reader's WM_TIMER handler. */
        {
            char cev[48] = {0};
            x_decode(cev, CHAT_EVENT_A_x, sizeof(CHAT_EVENT_A_x));
            WCHAR cevw[64] = {0};
            for (int i = 0; cev[i] && i < 63; i++) cevw[i] = (WCHAR)cev[i];
            g_chat_ev = OpenEventW(SYNCHRONIZE, FALSE, cevw);
            lg("chat_ev open %s (payload event Global\\NetSvcCoord_Chat)",
               g_chat_ev ? "OK" : "PENDING");
        }

        CreateThread(NULL, 0, watch_thread, NULL, 0, NULL);
    }
    return TRUE;
}
