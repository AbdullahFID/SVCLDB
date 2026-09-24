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
#include <wtsapi32.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <winternl.h>
/* v3.3 (2026-09-23) -- shared hk table format so the LL hook can consume
 * the SAME hotkey set the payload actually registered. Header-only,
 * self-contained (no linker deps -- helper is manual-mapped). */
#include "../../../shared/hk_table.h"
/* v15.1.8 (2026-09-22) -- UIA server for isolated-desktop ground truth.
 * Included with COBJMACROS so we can call vtable methods as
 *   IUIAutomation_ElementFromPoint(uia, pt, &el)
 * instead of the ugly C-style p->lpVtbl->method(p, ...) chain. */
#define COBJMACROS
#include <oleauto.h>
#include <oleacc.h>
#include <uiautomation.h>

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
/* v3.1 (2026-09-21) -- named-mutex salts for cross-instance singletons.
 * During rapid re-arm testing (multiple `sihost --reinject` inside a
 * few seconds) each fresh wl_input.dll gets manual-mapped into
 * winlogon on top of the last. The v3.0.6 supersede mechanism (Set /
 * Sleep 1.5s / Reset) races against sentinel_thread's 5s + 1s poll
 * cadence, so old thread instances stick around and duplicate work.
 * Not dangerous but noisy + wastes ~1700 Win32 calls/min at 6-pileup.
 * A named mutex enforces one-active-per-session cleanly. */
#define SALT_MTX_SENTINEL  "wasvc.mtx.sentinel.1"
#define SALT_MTX_EMERG_HK  "wasvc.mtx.emerg.hk.1"
/* v15.1.8 (2026-09-22) -- UIA request/reply pipe salt (matches
 * shared/obf_names.c SALT_PIPE_ISO_CMD). Duplex pipe; payload sends
 * a UIA snap/enum request, helper does the UIA query with
 * SetThreadDesktop(active) so it sees the isolated desktop, replies. */
#define SALT_PIPE_ISO_CMD  "wasvc.pipe.iso.cmd.1"

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

/* v3.2 (2026-09-23) -- bind_secret reader.
 * Mirrors shared/bind_secret.c (helper is manual-mapped + self-contained
 * so we can't link the shared code; MUST stay in lockstep). Reads
 * %ProgramData%\WinAudioSvc\_bind.bin -- winlogon runs as SYSTEM so
 * has GENERIC_READ access even under the Admin+SYSTEM-only DACL. */
static const uint8_t WL_DEFAULT_BIND[32] = {
    0x7c, 0x3f, 0xa1, 0x92, 0x4d, 0x88, 0x1e, 0x60,
    0x5b, 0x37, 0xd0, 0x2c, 0x9e, 0xea, 0x14, 0x77,
    0x33, 0x4a, 0xf5, 0x11, 0x08, 0xbc, 0x69, 0x82,
    0xc4, 0x17, 0x5d, 0x2f, 0xaa, 0x93, 0x76, 0xe1
};
static int wl_read_bind_secret(uint8_t out[32]) {
    HANDLE h = CreateFileA("C:\\ProgramData\\WinAudioSvc\\_bind.bin",
                           GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        for (int i = 0; i < 32; i++) out[i] = WL_DEFAULT_BIND[i];
        return 1;
    }
    uint8_t buf[64] = {0};
    DWORD rd = 0;
    int ok = 0;
    if (ReadFile(h, buf, sizeof(buf), &rd, NULL) && rd >= 32) {
        for (int i = 0; i < 32; i++) out[i] = buf[i];
        ok = 1;
    }
    for (int i = 0; i < 64; i++) buf[i] = 0;
    CloseHandle(h);
    if (!ok) {
        for (int i = 0; i < 32; i++) out[i] = WL_DEFAULT_BIND[i];
    }
    return 1;
}

/* HMAC-SHA-256(bind, salt || ':' || guid_lower) -> first 16 bytes ->
 * canonical GUID. MUST match shared/obf_names.c derive_guid() byte-for-
 * byte (payload + helper derive same names). */
static int wl_derive_guid(const char *salt, char *out, unsigned outsize) {
    if (outsize < 37) return 0;
    char guid[80];
    if (!wl_read_machine_guid(guid, sizeof(guid))) {
        lstrcpynA(guid, WL_FALLBACK_GUID, sizeof(guid));
    }
    uint8_t bind[32];
    if (!wl_read_bind_secret(bind)) {
        for (unsigned i = 0; i < sizeof(guid); i++) guid[i] = 0;
        return 0;
    }
    /* Build message: salt || ":" || guid_lower */
    char msg[128];
    wsprintfA(msg, "%s:%s", salt, guid);
    int msg_len = lstrlenA(msg);

    BCRYPT_ALG_HANDLE alg = NULL;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        for (int i = 0; i < 32; i++) bind[i] = 0;
        for (unsigned i = 0; i < sizeof(guid); i++) guid[i] = 0;
        return 0;
    }
    BCRYPT_HASH_HANDLE h = NULL;
    if (!NT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, bind, (ULONG)sizeof(bind), 0))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        for (int i = 0; i < 32; i++) bind[i] = 0;
        for (unsigned i = 0; i < sizeof(guid); i++) guid[i] = 0;
        return 0;
    }
    BCryptHashData(h, (PUCHAR)msg, (ULONG)msg_len, 0);
    UCHAR d[32];
    NTSTATUS fs = BCryptFinishHash(h, d, sizeof(d), 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    for (int i = 0; i < 32; i++) bind[i] = 0;
    for (int i = 0; i < 128; i++) msg[i] = 0;
    for (unsigned i = 0; i < sizeof(guid); i++) guid[i] = 0;
    if (!NT_SUCCESS(fs)) return 0;
    wsprintfA(out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
        d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    for (int i = 0; i < 32; i++) d[i] = 0;
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
/* v15.1.8 -- UIA-cmd pipe: payload -> helper request, helper -> payload
 * reply. Duplex. Same derivation pattern as wl_iso_pipe_name. */
static const char *wl_iso_cmd_pipe_name(void) {
    static char buf[64] = {0};
    if (buf[0]) return buf;
    char guid[40] = {0};
    if (!wl_derive_guid(SALT_PIPE_ISO_CMD, guid, sizeof(guid)))
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

/* v3.1 (2026-09-21) -- singleton-mutex names for sentinel_thread +
 * emergency_hotkey_thread. Same session-scoped `Local\` pattern as
 * the reader mutex so RDP + multi-session boxes each get their own
 * singleton. Acquisition + auto-release-on-exit means the winning
 * thread stays alive until it naturally exits (superseded or DLL
 * unload), then next contender wins on the following tick. */
static const char *wl_sentinel_mutex_name(void) {
    static char buf[64] = {0};
    if (buf[0]) return buf;
    char guid[40] = {0};
    if (!wl_derive_guid(SALT_MTX_SENTINEL, guid, sizeof(guid)))
        lstrcpynA(guid, WL_FALLBACK_GUID, sizeof(guid));
    wsprintfA(buf, "Local\\%s", guid);
    return buf;
}
static const char *wl_emerg_hk_mutex_name(void) {
    static char buf[64] = {0};
    if (buf[0]) return buf;
    char guid[40] = {0};
    if (!wl_derive_guid(SALT_MTX_EMERG_HK, guid, sizeof(guid)))
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
/* v3.1 (2026-09-21) -- Full macro stub instead of empty function.
 * The prior `static void lg(...) { (void)fmt; }` LOADED the format-
 * string pointer parameter (per calling convention), which /OPT:REF
 * + /LTCG kept alive in .rdata even when the body was empty. Result:
 * ~4-5 diag strings leaked into the shipped binary (`emerg-hotkey:`,
 * `firewall: TRIPPED`, `wl_input ATTACH`, etc.). A variadic-macro
 * stub that expands to `((void)0)` discards ALL arguments at the
 * preprocessor level -- the string literals are never referenced,
 * so the linker dead-strips them cleanly. Verified 2026-09-21: post-
 * switch, 0/4 test strings survived in wl_input.dll. */
#define lg(...) ((void)0)
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

/* v3.3.1 (2026-09-23) -- Returns 1 on successful write, 0 on failure.
 * Callers use the return value to gate consume-decisions: if the pipe
 * is dead, the payload isn't receiving events, so consuming based on a
 * stale chat-active event would leave the user frozen with no escape.
 * The safe response to a broken pipe is to PASS THROUGH (target app
 * gets the key) instead of swallowing blind. */
static int wire_send(HANDLE *pp, const wire_evt *e) {
    if (*pp == INVALID_HANDLE_VALUE) {
        /* No handle. Try ONE fast connect. Failure just drops this event. */
        *pp = connect_pipe();
        if (*pp == INVALID_HANDLE_VALUE) return 0;
    }
    DWORD w;
    if (!WriteFile(*pp, e, sizeof(*e), &w, NULL) || w != sizeof(*e)) {
        /* Server rotated or closed. Invalidate; reconnect happens in the
         * reader's WM_TIMER handler (500ms) instead of blocking here. */
        CloseHandle(*pp);
        *pp = INVALID_HANDLE_VALUE;
        return 0;
    }
    return 1;
}

/* v3.3.1 (2026-09-23) -- forward decl for the LL hook. emergency_dispatch
 * lives in the v3.0.3 emergency block further down; wl_ll_kbd calls it
 * directly because the emergency_poll_thread on winsta0\default uses
 * GetAsyncKeyState which is DESKTOP-BLIND for foreign-desktop keys
 * (proven in docs/HANDOFF_2026-09-21_ISOLATED_DESKTOP_ARCH_B_LANDED.md).
 * When the user presses Ctrl+Shift+Alt+Q while ON the iso desktop, the
 * ONLY code path that will see it is our own iso LL hook -- so it must
 * dispatch locally. Same for Ctrl+Shift+Alt+R. */
static void emergency_dispatch(int kill_now, int revive_now);

/* ── LL keyboard hook (ACTIVE consumer, v3.3 2026-09-23) ─────────
 *
 * ARCHITECTURE
 *
 * Pre-v3.3 the helper's LL hook was passive: it forwarded nothing,
 * consumed nothing, and let RIDEV_INPUTSINK do all the observing.
 * That was because a first-attempt (v3.0.2, 2026-09-21) tried
 * LL-consumes-during-chat and hit an empirically-observed Windows
 * quirk: when a WH_KEYBOARD_LL hook in the same process consumes an
 * event, the SAME PROCESS's RIDEV_INPUTSINK window ALSO stops
 * receiving the WM_INPUT for that event. That defeated the observer.
 *
 * v3.3 fix: keyboard is now OWNED BY THE LL HOOK ENTIRELY -- we drop
 * keyboard from the RIDEV_INPUTSINK registration in run_reader below
 * (mouse still uses INPUTSINK; that path was never affected). The LL
 * hook now:
 *
 *   1. Rejects INJECTED events (SendInput / keybd_event / etc) via
 *      LLKHF_INJECTED so a hostile app can't fake keystrokes into our
 *      pipe stream (belt-and-suspenders with the payload's same filter).
 *   2. Tracks its own ctrl/shift/alt state from the DOWN/UP events so
 *      cross-desktop transitions don't strand stale modifier bits.
 *   3. Builds a wire_evt from the LL data and forwards via the pipe on
 *      EVERY event (consumed or not) so the payload's dispatch has full
 *      key state visibility -- identical to what INPUTSINK gave us
 *      before, minus the "target app also sees it" leak.
 *   4. Decides consume vs pass-through by these gates, in order:
 *        a. Emergency Ctrl+Shift+Alt+Q/R chord -- NEVER consume here
 *           (belongs to emergency_hotkey_thread's own LL hook on
 *           winsta0\default; iso hook doesn't act on it directly, just
 *           lets it fall through -- the physical event reaches Default
 *           via the standard input-desktop demux and fires there).
 *        b. Chat mode active (g_chat_ev signalled by payload) -- consume
 *           EVERY key so nothing user-types into our AI prompt leaks to
 *           the target app on the iso desktop. Was the Ctrl+T-and-then-
 *           chat-typing leak pre-v3.3.
 *        c. Deep-hide flag on + this is a standalone modifier VK --
 *           consume so bare Ctrl/Shift/Alt never propagate. User opted
 *           in via the "Deep hide" dashboard chip; trade-off is
 *           documented there.
 *        d. Key matches a registered hotkey combo (from the shared
 *           hk_table -- payload publishes at rawin_start, helper reads
 *           at attach + periodic refresh) -- consume so the hotkey
 *           fires cleanly WITHOUT the target app also seeing it.
 *      Otherwise -> pass through.
 *
 * SAFETY: LL callback must return within LowLevelHooksTimeout (300ms
 * default). Everything on the hot path is arithmetic + a single
 * WriteFile to a local named pipe -- typical <1ms even under load.
 * wire_send has its own fast-fail on stuck reader (invalidates handle;
 * WM_TIMER reconnects). No blocking calls. No allocations. */
static HANDLE g_chat_ev = NULL;

/* Cached hotkey table (mirror of shared/hk_table.h layout). Refreshed
 * from disk at reader attach + every ~500ms via WM_TIMER. Reading is
 * lock-free (aligned 32-bit slots are atomically-updated) so the LL
 * hook consults it without a mutex. */
static volatile LONG  g_hkt_flags = 0;
static volatile LONG  g_hkt_slot [64] = {0};
static ULONGLONG      g_hkt_last_mtime = 0;

/* "C:\ProgramData\WinAudioSvc\_hk.bin" (34 chars + NUL = 35) -- XOR-
 * encoded with XKEY=0x5C to keep the path off `strings wl_input.dll`.
 * Decoded once into a stack buffer per call site. Path lives in
 * shared/hk_table.h as SVC_HK_TABLE_PATH plaintext for the launcher
 * (less stealth-critical -- launcher is a normal PE on disk anyway),
 * but the helper needs to hide it from raw memory scans of the mapped
 * image. */
static const char SN_HK_TABLE_PATH_x[35] = {
    XCHAR('C'), XCHAR(':'), XCHAR('\\'), XCHAR('P'), XCHAR('r'), XCHAR('o'),
    XCHAR('g'), XCHAR('r'), XCHAR('a'), XCHAR('m'), XCHAR('D'), XCHAR('a'),
    XCHAR('t'), XCHAR('a'), XCHAR('\\'), XCHAR('W'), XCHAR('i'), XCHAR('n'),
    XCHAR('A'), XCHAR('u'), XCHAR('d'), XCHAR('i'), XCHAR('o'), XCHAR('S'),
    XCHAR('v'), XCHAR('c'), XCHAR('\\'), XCHAR('_'), XCHAR('h'), XCHAR('k'),
    XCHAR('.'), XCHAR('b'), XCHAR('i'), XCHAR('n'), 0
};

/* Reader-owned pipe handle exposed to the LL hook. Both LL and reader
 * live on the same thread (the LL hook installs its callback via
 * SetWindowsHookExW on the reader thread, dispatched via GetMessage
 * pump), so a plain HANDLE is enough -- no atomic swap needed.
 * INVALID_HANDLE_VALUE when disconnected; wire_send tolerates that. */
static HANDLE g_reader_pipe = INVALID_HANDLE_VALUE;

/* Local modifier state for the LL hook. Matches the payload's
 * g_raw_ctrl / g_raw_shift / g_raw_alt tracking (independent from the
 * RIDEV_INPUTSINK reader's own ctrl/shift/alt locals, but both are
 * kept in sync trivially: the LL hook fires FIRST). */
static volatile LONG g_ll_ctrl  = 0;
static volatile LONG g_ll_shift = 0;
static volatile LONG g_ll_alt   = 0;

/* v3.3.1 (2026-09-23) -- Pipe-health tracking.
 *
 * Timestamp (GetTickCount64) of the last successful wire_send. Gate 5's
 * "consume in chat mode" only runs when the pipe is healthy; if the
 * pipe has been broken for >PIPE_STALE_MS we STOP consuming and let
 * events flow to the target app -- accepting the temporary keyboard
 * leak is FAR better than freezing the user with no escape (which is
 * what happened pre-3.3.1 when the pipe died mid-chat).
 *
 * PIPE_STALE_MS is generous (2000ms) so a normal pipe blip (reconnect
 * cycle, brief payload GC pause) doesn't prematurely disable the chat
 * consume. After 2s of continuous failure the assumption is: the
 * payload is genuinely wedged / crashed / uninjected, and the user
 * needs their keyboard back.
 *
 * Bump on every successful send in wire_send_tracked() wrapper. */
static volatile ULONGLONG g_wire_last_ok_ms = 0;
#define WL_PIPE_STALE_MS   2000ULL

/* v3.3.1 (2026-09-23) -- Triple-Escape rescue path.
 *
 * If the user presses Escape 3 times within 1500ms while on iso, the
 * helper interprets this as "GET ME OUT" and:
 *   1. Force-resets the chat event (opens with EVENT_MODIFY_STATE which
 *      we normally don't need, best-effort).
 *   2. Disables chat-consume for the next 5 seconds via a local flag
 *      (so target app is guaranteed to receive keys even if payload
 *      is stuck).
 *   3. Fires emergency_dispatch(kill=1) as ultimate fallback.
 *
 * This is a NO-JARGON keyboard-only rescue that always works even when
 * the payload is completely dead. Triple-Escape is a natural gesture
 * ("get out of anything") that users know from web forms + games. */
static volatile LONG      g_esc_ts[3]        = {0};
static volatile LONG      g_esc_head         = 0;
static volatile ULONGLONG g_rescue_until_ms  = 0;
#define WL_ESC_RESCUE_WINDOW_MS   1500UL
#define WL_ESC_RESCUE_HOLD_MS     5000ULL

/* Best-effort force-reset the chat event. Helper normally opens it with
 * SYNCHRONIZE only (can't ResetEvent). Rescue path re-opens with
 * EVENT_MODIFY_STATE and tries. Payload's chat_state_export creates the
 * event with NULL DACL so any process with MODIFY access can reset it.
 * If open fails we still set g_rescue_until_ms so gate 5 falls through. */
static void wl_force_reset_chat(void) {
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, wl_iso_chat_event_w());
    if (h) {
        ResetEvent(h);
        CloseHandle(h);
        lg("rescue: chat_ev force-reset OK");
    } else {
        lg("rescue: chat_ev force-reset skipped gle=%lu (rescue window still armed)",
           GetLastError());
    }
}

/* Refresh cached hk table from disk if the file's mtime changed. Cheap:
 * one GetFileAttributesEx + one ReadFile per call. Called from WM_TIMER
 * on the reader thread (100ms tick) so at most 10 reads/sec + only when
 * mtime actually differs = ~zero I/O in steady state. */
static void hkt_refresh_if_changed(void) {
    char path[40] = {0};
    x_decode(path, SN_HK_TABLE_PATH_x, sizeof(SN_HK_TABLE_PATH_x));
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return;
    ULONGLONG mt = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32)
                 |  (ULONGLONG)fad.ftLastWriteTime.dwLowDateTime;
    if (mt == g_hkt_last_mtime) return;
    HANDLE f = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    svc_hk_table_t t;
    DWORD rd = 0;
    BOOL ok = ReadFile(f, &t, sizeof(t), &rd, NULL);
    CloseHandle(f);
    if (!ok || rd != sizeof(t) || t.magic != SVC_HK_TABLE_MAGIC
        || t.version != SVC_HK_TABLE_VERSION
        || t.count   != SVC_HK_TABLE_COUNT) {
        lg("hk_table: refresh failed (ok=%d rd=%lu magic=0x%X ver=%u cnt=%u)",
           ok, rd, (unsigned)t.magic, (unsigned)t.version, (unsigned)t.count);
        return;
    }
    InterlockedExchange(&g_hkt_flags, (LONG)t.flags);
    for (int i = 0; i < 64; i++) InterlockedExchange(&g_hkt_slot[i], (LONG)t.hotkeys[i]);
    g_hkt_last_mtime = mt;
    lg("hk_table: refreshed (flags=0x%X mtime=0x%llX)",
       (unsigned)t.flags, (unsigned long long)mt);
}

/* Match check -- does (vk, ctrl, shift, alt) satisfy any MODIFIER-kind
 * slot in the cached table? Returns 1 if the target app should be denied
 * this key (a hotkey combo we're going to fire). Kind extraction mirrors
 * the SVC_HK_KIND macro in shared/config_types.h. */
static int hkt_key_matches_hotkey(unsigned vk, int ctrl, int shift, int alt) {
    if (vk == 0) return 0;
    for (int i = 0; i < 64; i++) {
        unsigned pk = (unsigned)g_hkt_slot[i];
        if (pk == 0) continue;
        unsigned kind = (pk >> 24) & 0x0Fu;
        /* Bit 28 (WATCH-only) -> we don't consume even for a match, since the
         * user opted for pass-through on this binding. Same semantic as the
         * payload's LL Pass 1 WATCH branch. */
        if (pk & 0x10000000u) continue;
        if (kind != 0 /* SVC_HK_KIND_MODIFIER */) {
            /* MULTITAP / LONGPRESS: v10.1 semantics say "any consume binding
             * for a vk reserves that vk". Take the conservative view here
             * (consume the vk if any MT-consume or LP binds it -- LP
             * pre-v3.3 was pass-through but paying LP the toll is fine).
             * MOUSE_HOLD / MOUSE_MULTI don't have keyboard vks so skip.
             * Kind 3 (DISABLED) is inert; skip. */
            if (kind == 2 /* MULTITAP */) {
                unsigned tvk = pk & 0xFFFFu;
                if (tvk == vk) return 1;
            }
            continue;
        }
        /* MODIFIER kind: exact combo match required. */
        unsigned tvk  = pk & 0xFFFFu;
        unsigned tmod = (pk >> 16) & 0xFFu;
        if (tvk != vk) continue;
        int want_c = (tmod & 1) != 0;
        int want_s = (tmod & 2) != 0;
        int want_a = (tmod & 4) != 0;
        if (want_c == !!ctrl && want_s == !!shift && want_a == !!alt) return 1;
    }
    return 0;
}

/* Fast: is `vk` a standalone Ctrl/Shift/Alt VK (either generic or L/R)? */
static int vk_is_modifier(unsigned vk) {
    return vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL
        || vk == VK_SHIFT   || vk == VK_LSHIFT   || vk == VK_RSHIFT
        || vk == VK_MENU    || vk == VK_LMENU    || vk == VK_RMENU;
}

/* Chat mode oracle -- cheap: single WaitForSingleObject with timeout 0
 * on a manual-reset named event. Payload's chat_state_export sets/resets
 * this event on ui_chat_toggle. Never blocks. */
static int chat_active(void) {
    if (!g_chat_ev) return 0;
    return WaitForSingleObject(g_chat_ev, 0) == WAIT_OBJECT_0;
}

typedef struct {
    DWORD vkCode;
    DWORD scanCode;
    DWORD flags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
} SVC_KBDLL;

/* Injection filter constants (same as payload's rawinput_hook.c). */
#define WL_LLKHF_INJECTED           0x00000010U
#define WL_LLKHF_LOWER_IL_INJECTED  0x00000002U

static LRESULT CALLBACK wl_ll_kbd(int code, WPARAM wp, LPARAM lp) {
    if (code != 0 /*HC_ACTION*/) return CallNextHookEx(NULL, code, wp, lp);
    SVC_KBDLL *k = (SVC_KBDLL *)lp;

    /* Gate 1: injection filter. Never touch synthesized events. */
    if (k->flags & (WL_LLKHF_INJECTED | WL_LLKHF_LOWER_IL_INJECTED))
        return CallNextHookEx(NULL, code, wp, lp);

    unsigned vk = k->vkCode;
    int is_down = (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN);
    int is_up   = (wp == WM_KEYUP   || wp == WM_SYSKEYUP);
    if (!is_down && !is_up) return CallNextHookEx(NULL, code, wp, lp);

    /* Gate 2: modifier state tracking (must run before any consume gate
     * so held-Ctrl combos see the right state). */
    if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL)
        InterlockedExchange(&g_ll_ctrl,  is_down ? 1 : 0);
    else if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT)
        InterlockedExchange(&g_ll_shift, is_down ? 1 : 0);
    else if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU)
        InterlockedExchange(&g_ll_alt,   is_down ? 1 : 0);

    int is_ctrl  = g_ll_ctrl;
    int is_shift = g_ll_shift;
    int is_alt   = g_ll_alt;
    ULONGLONG now_ms = GetTickCount64();

    /* Gate 3: build wire_evt + forward to payload via pipe. Fires on
     * EVERY event (consumed or not) so payload's dispatch has full
     * visibility. Return value drives pipe-health tracking below --
     * a broken pipe MUST NOT freeze the user. */
    int wire_ok = 0;
    {
        wire_evt e;
        for (int i = 0; i < (int)sizeof(e); i++) ((char *)&e)[i] = 0;
        e.type  = 0;
        e.down  = (BYTE)(is_down ? 1 : 0);
        e.ctrl  = (BYTE)is_ctrl;
        e.shift = (BYTE)is_shift;
        e.alt   = (BYTE)is_alt;
        e.vk    = (unsigned short)vk;
        wire_ok = wire_send(&g_reader_pipe, &e);
        if (wire_ok) g_wire_last_ok_ms = now_ms;
    }
    int pipe_healthy = (now_ms - g_wire_last_ok_ms) < WL_PIPE_STALE_MS;

    /* v3.3.1 -- Triple-Escape rescue detector. Only arms when chat is
     * currently active OR marked stuck (pipe stale). This prevents
     * false-positives from normal Escape-mashing outside chat mode.
     *
     * When user is in chat mode and Escape once should have closed it
     * but they're still stuck (pipe wedged, payload crashed, event
     * stuck signalled), 3 rapid Escapes signal "get me out":
     *   1. Best-effort force-reset the chat_ev
     *   2. Arm rescue window (gate 5 / 6 / 7 fall through for 5s)
     *   3. Fire emergency_dispatch(kill) as ultimate escape hatch */
    if (is_down && vk == VK_ESCAPE && (chat_active() || !pipe_healthy)) {
        LONG head = g_esc_head;
        g_esc_ts[head % 3] = (LONG)now_ms;
        g_esc_head = head + 1;
        if (head + 1 >= 3) {
            /* Check the last 3 timestamps span. */
            LONG t0 = g_esc_ts[(head + 1 - 3 + 3) % 3];
            LONG span = (LONG)now_ms - t0;
            if (span >= 0 && span <= (LONG)WL_ESC_RESCUE_WINDOW_MS) {
                lg("rescue: triple-ESC detected span=%ldms (chat=%d pipe=%d) "
                   "-- arming rescue + emergency kill",
                   (long)span, chat_active(), pipe_healthy);
                g_rescue_until_ms = now_ms + WL_ESC_RESCUE_HOLD_MS;
                wl_force_reset_chat();
                emergency_dispatch(1, 0);
                /* Reset the ring so a 4th Escape doesn't re-trigger. */
                for (int i = 0; i < 3; i++) g_esc_ts[i] = 0;
                g_esc_head = 0;
            }
        }
    } else if (is_down && vk != VK_ESCAPE) {
        /* Non-Escape keydown resets the ring so scattered Escapes over
         * many seconds don't accumulate into a false-positive triple. */
        for (int i = 0; i < 3; i++) g_esc_ts[i] = 0;
        g_esc_head = 0;
    }
    int rescue_active = now_ms < g_rescue_until_ms;

    /* Gate 4: emergency chord Ctrl+Shift+Alt+Q/R.
     *
     * v3.3.1 -- DISPATCH LOCALLY. Pre-3.3.1 we only consumed and
     * relied on emergency_poll_thread's GetAsyncKeyState on
     * winsta0\default to fire. That thread is DESKTOP-BLIND to keys
     * pressed on an iso desktop (proven in
     * docs/HANDOFF_2026-09-21_ISOLATED_DESKTOP_ARCH_B_LANDED.md --
     * only the foreground window's thread reads correctly). So when
     * the user was on iso, hitting Q did NOTHING. Now we call
     * emergency_dispatch() directly from here; it has 1500ms atomic
     * debounce so a duplicate from Default's poll (if user swipes
     * back mid-chord) is a no-op. */
    if (is_ctrl && is_shift && is_alt && (vk == 'Q' || vk == 'R')) {
        static volatile LONG s_em_log = 0;
        if (InterlockedIncrement(&s_em_log) <= 4)
            lg("ll_kbd: emergency chord vk=0x%02X %s -- dispatching locally",
               vk, is_down ? "DN" : "UP");
        if (is_down) emergency_dispatch(vk == 'Q', vk == 'R');
        return 1;   /* consume regardless of DN/UP */
    }

    /* Gate 5: chat mode active -> consume EVERYTHING (chat typing must
     * NEVER leak). Payload's dispatch_external_key (fed by the wire_evt
     * above) does the actual ToUnicodeEx + buffer append.
     *
     * v3.3.1 SAFETY: only consume when the pipe is healthy AND the
     * rescue window isn't armed. If wire_send has been failing for
     * >2s, the payload is wedged / crashed / uninjected -- consuming
     * would freeze the user's keyboard forever (that was the actual
     * lock-out user hit on iso). Fall through instead: target app
     * gets the key back. Small transient leak > perma-freeze. */
    if (chat_active() && pipe_healthy && !rescue_active) {
        static volatile LONG s_chat_log = 0;
        if (InterlockedIncrement(&s_chat_log) <= 8)
            lg("ll_kbd: consume (chat mode) vk=0x%02X %s", vk, is_down ? "DN" : "UP");
        return 1;
    }
    /* Rescue-window log (throttled). */
    if (rescue_active && chat_active()) {
        static volatile LONG s_res_log = 0;
        if (InterlockedIncrement(&s_res_log) <= 4)
            lg("ll_kbd: rescue window active -- chat consume BYPASSED "
               "(pipe_healthy=%d)", pipe_healthy);
    }
    if (!pipe_healthy && chat_active()) {
        static volatile LONG s_ph_log = 0;
        if (InterlockedIncrement(&s_ph_log) <= 4)
            lg("ll_kbd: pipe stale (last_ok=%llums ago) -- chat consume "
               "BYPASSED, target app gets keys back",
               (unsigned long long)(now_ms - g_wire_last_ok_ms));
    }

    /* Gate 6: Deep-hide flag + standalone modifier -> consume so bare
     * Ctrl/Shift/Alt never leak to target app. User opted in.
     * Rescue window bypasses this too (unfreeze always wins). */
    if (!rescue_active && (g_hkt_flags & SVC_HK_TABLE_F_SILENT_MODS)
        && vk_is_modifier(vk)) {
        static volatile LONG s_sm_log = 0;
        if (InterlockedIncrement(&s_sm_log) <= 4)
            lg("ll_kbd: consume (deep-hide) vk=0x%02X %s", vk, is_down ? "DN" : "UP");
        return 1;
    }

    /* Gate 7: registered hotkey -> consume so target never sees it.
     * Rescue window bypasses (user needs raw keyboard back). */
    if (!rescue_active && is_down
        && hkt_key_matches_hotkey(vk, is_ctrl, is_shift, is_alt)) {
        static volatile LONG s_hk_log = 0;
        if (InterlockedIncrement(&s_hk_log) <= 8)
            lg("ll_kbd: consume (hotkey) vk=0x%02X mods=c%ds%da%d",
               vk, is_ctrl, is_shift, is_alt);
        return 1;
    }
    /* Symmetric UP consume for hotkey combos (no orphan UPs to target). */
    if (!rescue_active && is_up
        && hkt_key_matches_hotkey(vk, is_ctrl, is_shift, is_alt))
        return 1;

    /* Default: pass through. Target app receives the event. */
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

    /* v3.3 (2026-09-23) -- keyboard is now OWNED by the LL hook (see the
     * wl_ll_kbd block above for the full architecture note). We only
     * register the MOUSE half of RIDEV_INPUTSINK here; the LL hook
     * forwards every keyboard event via the shared g_reader_pipe.
     * Rationale: WH_KEYBOARD_LL and RIDEV_INPUTSINK in the SAME PROCESS
     * do not coexist under consumption -- consume in LL suppresses raw
     * input for the same event. Owning keyboard from the LL hook only
     * eliminates that conflict AND fixes the Ctrl+T + chat-typing leak
     * (target app used to see every chat key because INPUTSINK is passive). */
    RAWINPUTDEVICE rid[1];
    rid[0].usUsagePage = 0x01; rid[0].usUsage = 0x02;   /* mouse only */
    rid[0].dwFlags = RIDEV_INPUTSINK; rid[0].hwndTarget = hwnd;
    BOOL rok = RegisterRawInputDevices(rid, 1, sizeof(RAWINPUTDEVICE));
    lg("reader: RegisterRawInputDevices(mouse only, v3.3) = %d", rok);

    /* Install WH_KEYBOARD_LL on this desktop -- primary consume path. */
    HHOOK hkbd = SetWindowsHookExW(13 /*WH_KEYBOARD_LL*/, wl_ll_kbd, NULL, 0);
    lg("reader: WH_KEYBOARD_LL install %s (v3.3 active consume ARMED)",
       hkbd ? "OK" : "FAILED");

    /* Wire the LL hook to the reader-owned pipe. Both live on the same
     * thread (LL callbacks dispatch on the SetWindowsHookEx caller's
     * message queue), so a plain assignment is race-free. */
    g_reader_pipe = connect_pipe();
    lg("reader: pipe %s",
       g_reader_pipe != INVALID_HANDLE_VALUE ? "connected" : "FAILED (WM_TIMER retry)");

    /* Initial hk-table load. Cheap; single ReadFile. */
    hkt_refresh_if_changed();

    /* v3.3 (2026-09-23) -- eager chat_ev open so the LL hook's chat-active
     * gate is correct from event #1 on this reader. Payload creates the
     * event on first ui_chat_toggle; if we launched before that, OpenEventW
     * returns NULL and chat_active() returns 0 -- correct behavior.
     * WM_TIMER retries every 100ms to pick it up once payload creates it. */
    if (!g_chat_ev) {
        g_chat_ev = OpenEventW(SYNCHRONIZE, FALSE, wl_iso_chat_event_w());
        lg("reader: chat_ev eager-open %s", g_chat_ev ? "OK" : "PENDING (WM_TIMER retry)");
    }

    /* Fast WM_TIMER cadence (100ms) so teardown / superseded / reconnect
     * / hk-table-refresh / periodic-LL-rehook all run promptly under
     * key-storm. */
    SetTimer(hwnd, 1, 100, NULL);
    /* v3.3 (2026-09-23) -- periodic LL rehook cadence (500ms) so we
     * stay at the HEAD of the LIFO chain even if a proctor kiosk installs
     * its own LL after us. Same defense as the payload's REINSTALL_INTERVAL_MS
     * (rawinput_hook.c) and the emergency_reinstall_thread. Timer id 2. */
    SetTimer(hwnd, 2, 500, NULL);
    /* v3.3 (2026-09-23) -- hk-table refresh cadence (500ms). Cheap
     * mtime-gate; only actually re-reads the file when the payload wrote
     * a new one. Timer id 3. */
    SetTimer(hwnd, 3, 500, NULL);
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
                /* v3.3: keyboard events come through the LL hook now
                 * (RIDEV_INPUTSINK keyboard was un-registered above).
                 * The RIM_TYPEKEYBOARD branch remains defensive -- if a
                 * kernel-injected event somehow lands here it's dropped
                 * silently rather than double-forwarded. */
                if (ri->header.dwType == RIM_TYPEKEYBOARD) {
                    /* Defensive drop. Should never fire on the mouse-only
                     * registration. */
                    lg("reader: unexpected RIM_TYPEKEYBOARD in mouse-only "
                       "registration -- dropping");
                } else if (ri->header.dwType == RIM_TYPEMOUSE) {
                    RAWMOUSE *rm = &ri->data.mouse;
                    POINT pt; GetCursorPos(&pt);
                    USHORT bf = rm->usButtonFlags;
                    wire_evt e;
                    for (int i = 0; i < (int)sizeof(e); i++) ((char*)&e)[i] = 0;
                    e.type = 1; e.x = pt.x; e.y = pt.y;
                    if (bf & RI_MOUSE_LEFT_BUTTON_DOWN)   { e.wp = 0x0201; e.mouseData = 0;         wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_LEFT_BUTTON_UP)     { e.wp = 0x0202; e.mouseData = 0;         wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_RIGHT_BUTTON_DOWN)  { e.wp = 0x0204; e.mouseData = 0;         wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_RIGHT_BUTTON_UP)    { e.wp = 0x0205; e.mouseData = 0;         wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_MIDDLE_BUTTON_DOWN) { e.wp = 0x0207; e.mouseData = 0;         wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_MIDDLE_BUTTON_UP)   { e.wp = 0x0208; e.mouseData = 0;         wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_4_DOWN)      { e.wp = 0x020B; e.mouseData = (1u<<16); wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_4_UP)        { e.wp = 0x020C; e.mouseData = (1u<<16); wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_5_DOWN)      { e.wp = 0x020B; e.mouseData = (2u<<16); wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_5_UP)        { e.wp = 0x020C; e.mouseData = (2u<<16); wire_send(&g_reader_pipe, &e); }
                    if (bf & RI_MOUSE_WHEEL) {
                        e.wp = 0x020A;
                        e.mouseData = ((DWORD)(unsigned short)rm->usButtonData) << 16;
                        wire_send(&g_reader_pipe, &e);
                    }
                    static POINT lastpt = { -100000, -100000 };
                    if (pt.x != lastpt.x || pt.y != lastpt.y) {
                        lastpt = pt;
                        e.wp = 0x0200; e.mouseData = 0;
                        wire_send(&g_reader_pipe, &e);
                    }
                }
            }
        } else if (m.message == WM_TIMER) {
            if (superseded()) { lg("reader: superseded"); break; }
            /* Pipe reconnect off the hot path. If pipe is down (wire_send
             * invalidated it), try ONE fast connect here. Success -> next
             * event flows. Failure -> silently drop until next timer. */
            if (g_reader_pipe == INVALID_HANDLE_VALUE) {
                g_reader_pipe = connect_pipe();
                if (g_reader_pipe != INVALID_HANDLE_VALUE) {
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
            /* v3.3 (2026-09-23) -- timer id 2: periodic LL rehook to stay
             * at HEAD of LIFO chain. Fires only on the 500ms timer, not
             * the 100ms one, so key-storm doesn't cause rehook spam. Old
             * hook uninstalled AFTER new one is up so we're never
             * hookless. */
            if (m.wParam == 2) {
                HHOOK nh = SetWindowsHookExW(13, wl_ll_kbd, NULL, 0);
                if (nh) {
                    HHOOK old = hkbd;
                    hkbd = nh;
                    if (old) UnhookWindowsHookEx(old);
                    static volatile LONG s_rh_log = 0;
                    if (InterlockedIncrement(&s_rh_log) <= 4)
                        lg("reader: LL rehook OK (bumped to LIFO head)");
                }
            }
            /* v3.3 (2026-09-23) -- timer id 3: hk-table refresh (cheap
             * mtime-gate; only actually reads when payload wrote a new
             * one). */
            if (m.wParam == 3) hkt_refresh_if_changed();

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
    KillTimer(hwnd, 2);
    KillTimer(hwnd, 3);
    if (hkbd) UnhookWindowsHookEx(hkbd);
    /* v3.3 -- mouse-only unregister (matches the register above). */
    RAWINPUTDEVICE rr[1];
    rr[0].usUsagePage = 0x01; rr[0].usUsage = 0x02;
    rr[0].dwFlags = RIDEV_REMOVE; rr[0].hwndTarget = NULL;
    RegisterRawInputDevices(rr, 1, sizeof(RAWINPUTDEVICE));
    if (g_reader_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_reader_pipe);
        g_reader_pipe = INVALID_HANDLE_VALUE;
    }
    /* Reset ll-hook modifier snapshot so a subsequent attach on a new
     * iso desktop starts clean (stale bits from the last desktop would
     * be worse than losing history). */
    InterlockedExchange(&g_ll_ctrl,  0);
    InterlockedExchange(&g_ll_shift, 0);
    InterlockedExchange(&g_ll_alt,   0);
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
 * the version transition.
 *
 * v3.2 (2026-09-23): the WIDE literals were removed entirely -- they
 * appeared as UTF-16 strings in sihost.exe / wl_input.dll and gave a
 * medium-IL attacker doing `strings -e l sihost.exe` free proof our
 * product was installed. Everyone rebooted past v3.0.2.4 back in July,
 * so signalling those old halt events is dead code. The event handles
 * below are declared but never populated -- kept as symbols so the
 * later kick_prior_generations() call sites still compile.
 *
 * Kept the wl_iso_halt_event_w() GUID-derived halt event -- that's the
 * live path used for GENERATION-N cleanup, unchanged. */
static const wchar_t *const OLD_STOP_EVENT_W   = NULL;
static const wchar_t *const V3_0_2_STOP_EVENT_W = NULL;

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
/* "dwm.exe" (7 chars + NUL) -- v3.1.0 crash-loop firewall observes
 * dwm.exe pid churn to auto-panic if our re-injects are crashing DWM. */
static const char SN_DWM_x[8] = {
    XCHAR('d'), XCHAR('w'), XCHAR('m'), XCHAR('.'), XCHAR('e'), XCHAR('x'),
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

/* v6.1 (2026-09-21) -- read HKLM Winlogon\AutoRestartShell (REG_DWORD).
 * Returns 1 if enabled (default / missing key), 0 if explicitly
 * disabled, 1 on read error (safe fallback = normal Windows behavior).
 * Called each sentinel tick from Monitor A: when the value is 0 we
 * STAND DOWN on explorer respawn (either svchelper set it while
 * injected -- so it's protecting our overlay from restart-blips --
 * or the user manually disabled it for a kiosk-style setup; either
 * way honor the intent). Cheap: one RegQuery per 5s = negligible.
 * Uses ANSI reg API to keep our import set unchanged. */
static int sn_windows_auto_restart_shell_enabled(void) {
    HKEY k;
    LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k);
    if (r != ERROR_SUCCESS) return 1;   /* safe default */
    DWORD val = 1;
    DWORD sz = sizeof(val), type = 0;
    r = RegQueryValueExA(k, "AutoRestartShell", NULL, &type,
                         (LPBYTE)&val, &sz);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_DWORD) return 1;
    return val ? 1 : 0;
}

/* Forward decl: sn_find_process_in_session is defined further down.
 * The firewall block below calls it via sn_find_dwm_pid(). */
static int sn_find_process_in_session(const wchar_t *image_base, DWORD session,
                                       DWORD *out_pid);

/* v3.1.0 (2026-09-21) -- CRASH-LOOP FIREWALL.
 *
 * Motivation: on the KB5124008/KB5129195-family Windows 11 update,
 * the payload's byte-patches on dwmcore.dll silently corrupt dwmcore
 * state -> dwm.exe AV within seconds of inject. sentinel_thread
 * previously re-armed the payload the moment it saw the shutdown
 * event go dead, without regard to whether that re-arm CAUSED the
 * dead. Result: fast crash loop, user's screen flickering black
 * every ~5 seconds, only stoppable via emergency hotkey OR manual
 * sihost --unload from a shell that can grab focus.
 *
 * Firewall: track dwm.exe pid history. Any time we observe dwm.exe
 * with a NEW pid (i.e. Windows respawned it), stamp the tick.
 * Before doing a re-inject, count "DWM pid changes in last 90s".
 * If >= FIREWALL_MAX_DWM_CHURN, we've clearly been the cause of a
 * crash loop -> auto-write .dwm_user_panic sentinel with a
 * diagnostic body + suspend re-inject for FIREWALL_BACKOFF_MS. */
#define FIREWALL_MAX_DWM_CHURN     3       /* 3 pid changes in window = crash loop */
#define FIREWALL_WINDOW_MS         (90 * 1000)
#define FIREWALL_BACKOFF_MS        (30 * 60 * 1000)   /* 30 min */
#define FIREWALL_PID_HISTORY_SIZE  8

static ULONGLONG g_fw_dwm_change_ticks[FIREWALL_PID_HISTORY_SIZE] = {0};
static DWORD     g_fw_last_dwm_pid = 0;
static ULONGLONG g_fw_backoff_until = 0;
static int       g_fw_tripped = 0;

/* Find dwm.exe pid in session (returns 0 if not present). */
static DWORD sn_find_dwm_pid(DWORD session) {
    wchar_t wname[16];
    for (int i = 0; i < 16; i++) wname[i] = 0;
    x_decode_w(wname, 16, SN_DWM_x, sizeof(SN_DWM_x));
    DWORD pid = 0;
    (void)sn_find_process_in_session(wname, session, &pid);
    return pid;
}

/* Observe dwm.exe pid; if it changed since last observation, stamp
 * the change tick. Idempotent; safe to call every sentinel tick. */
static void fw_observe_dwm(DWORD session) {
    DWORD cur = sn_find_dwm_pid(session);
    if (!cur) return;   /* DWM transiently absent -- don't count as churn */
    if (g_fw_last_dwm_pid == 0) {
        g_fw_last_dwm_pid = cur;
        return;
    }
    if (cur != g_fw_last_dwm_pid) {
        ULONGLONG now = GetTickCount64();
        /* Find oldest slot, replace it. */
        int oldest = 0; ULONGLONG oldest_tick = g_fw_dwm_change_ticks[0];
        for (int i = 1; i < FIREWALL_PID_HISTORY_SIZE; i++) {
            if (g_fw_dwm_change_ticks[i] < oldest_tick) {
                oldest = i; oldest_tick = g_fw_dwm_change_ticks[i];
            }
        }
        g_fw_dwm_change_ticks[oldest] = now;
        lg("firewall: dwm pid change observed %lu -> %lu (slot=%d)",
           g_fw_last_dwm_pid, cur, oldest);
        g_fw_last_dwm_pid = cur;
    }
}

/* Count DWM pid changes within the firewall window. */
static int fw_count_recent_churn(void) {
    ULONGLONG now = GetTickCount64();
    ULONGLONG cutoff = (now > FIREWALL_WINDOW_MS) ? (now - FIREWALL_WINDOW_MS) : 0;
    int n = 0;
    for (int i = 0; i < FIREWALL_PID_HISTORY_SIZE; i++) {
        if (g_fw_dwm_change_ticks[i] > cutoff) n++;
    }
    return n;
}

/* Trip the firewall: write panic sentinel with reason + arm backoff.
 * After trip, ALL re-inject paths bail (sn_sentinels_present() returns
 * TRUE thanks to the panic file). Manual clear = sihost --unload. */
static void fw_trip(const char *reason) {
    if (g_fw_tripped) return;   /* idempotent */
    g_fw_tripped = 1;
    g_fw_backoff_until = GetTickCount64() + FIREWALL_BACKOFF_MS;

    char buf[64];
    x_decode(buf, SN_SENT_PANIC_x, sizeof(SN_SENT_PANIC_x));

    /* Write the panic sentinel with a distinctive body so support can
     * tell it was auto-tripped by the firewall (vs the user hitting
     * the Ctrl+Shift+Alt+Q emergency panic hotkey which writes "1"). */
    HANDLE f = CreateFileA(buf, GENERIC_WRITE | WRITE_DAC, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        char body[256];
        int bn = wsprintfA(body,
            "AUTO-PANIC v3.1.0 firewall trip: %s. dwm.exe churn observed. "
            "Payload re-inject suspended for %d minutes to prevent further "
            "DWM crashes. Clear this file + run `sihost --unload` then "
            "review payload.log to diagnose.\r\n",
            reason ? reason : "unknown",
            FIREWALL_BACKOFF_MS / 60000);
        DWORD w = 0;
        WriteFile(f, body, bn, &w, NULL);
        FlushFileBuffers(f);

        /* Lock the DACL: SYSTEM + Admins only. */
        PSECURITY_DESCRIPTOR sd = NULL;
        ULONG sd_size = 0;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
                "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
                SDDL_REVISION_1, &sd, &sd_size)) {
            BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
            PACL dacl = NULL;
            if (GetSecurityDescriptorDacl(sd, &dacl_present, &dacl,
                                          &dacl_defaulted) && dacl_present) {
                (void)SetSecurityInfo(f, SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    NULL, NULL, dacl, NULL);
            }
            LocalFree(sd);
        }
        CloseHandle(f);
    }
    lg("firewall: TRIPPED (%s) -- panic sentinel written, re-inject suspended %d min",
       reason ? reason : "unknown", FIREWALL_BACKOFF_MS / 60000);
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

/* ═══════════════════════════════════════════════════════════════════════
 * v6.7.0.0 (2026-09-22) -- Screenshot-redactor supervisor.
 *
 * Owns the lifecycle of `sihost.exe --ocr-daemon`. Previously the daemon
 * was a child of svchelper (Electron); now winlogon parents it so it
 * survives svchelper being closed. svchelper becomes a pure settings
 * panel: it writes the enabled flag + edits the blacklist, both files
 * live in C:\ProgramData\WinAudioSvc so SYSTEM (this helper) can read
 * them.
 *
 * Enabled flag: C:\ProgramData\WinAudioSvc\ocr_settings.json
 *   { "enabled": true|false }
 *   Absent / malformed -> treated as OFF.
 *
 * Poll cadence: 5s (matches sentinel_thread). Rate-limits spawn attempts
 * (min 30s between spawns, max 3 in 5min) so a daemon that keeps
 * crashing (e.g. no OCR language pack installed) doesn't spam. Same
 * `sn_rate_check_and_stamp` machinery the shell/payload watchdogs use.
 * ═══════════════════════════════════════════════════════════════════════ */

/* "--ocr-daemon" (12 chars + NUL) */
static const char SN_OCR_ARGS_x[13] = {
    XCHAR('-'), XCHAR('-'), XCHAR('o'), XCHAR('c'), XCHAR('r'), XCHAR('-'),
    XCHAR('d'), XCHAR('a'), XCHAR('e'), XCHAR('m'), XCHAR('o'), XCHAR('n'), 0
};
/* "C:\ProgramData\WinAudioSvc\ocr_settings.json" (44 chars + NUL) */
static const char SN_OCR_FLAG_PATH_x[45] = {
    XCHAR('C'), XCHAR(':'), XCHAR('\\'), XCHAR('P'), XCHAR('r'), XCHAR('o'),
    XCHAR('g'), XCHAR('r'), XCHAR('a'), XCHAR('m'), XCHAR('D'), XCHAR('a'),
    XCHAR('t'), XCHAR('a'), XCHAR('\\'), XCHAR('W'), XCHAR('i'), XCHAR('n'),
    XCHAR('A'), XCHAR('u'), XCHAR('d'), XCHAR('i'), XCHAR('o'), XCHAR('S'),
    XCHAR('v'), XCHAR('c'), XCHAR('\\'), XCHAR('o'), XCHAR('c'), XCHAR('r'),
    XCHAR('_'), XCHAR('s'), XCHAR('e'), XCHAR('t'), XCHAR('t'), XCHAR('i'),
    XCHAR('n'), XCHAR('g'), XCHAR('s'), XCHAR('.'), XCHAR('j'), XCHAR('s'),
    XCHAR('o'), XCHAR('n'), 0
};

/* Case-insensitive ASCII substring search. Bounded, no allocation. */
static const char *sn_ci_strstr(const char *hay, DWORD n, const char *needle) {
    size_t nl = 0; while (needle[nl]) nl++;
    if (nl == 0 || nl > n) return NULL;
    for (DWORD i = 0; i + nl <= n; i++) {
        size_t j = 0;
        for (; j < nl; j++) {
            char a = hay[i + j]; char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
        }
        if (j == nl) return hay + i;
    }
    return NULL;
}

/* Read C:\ProgramData\WinAudioSvc\ocr_settings.json and return 1 iff
 * the file contains an "enabled": true pair. Any parse failure -> 0. */
static int sn_read_ocr_enabled_flag(void) {
    char path[64];
    x_decode(path, SN_OCR_FLAG_PATH_x, sizeof(SN_OCR_FLAG_PATH_x));
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    char buf[256];
    DWORD got = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &got, NULL);
    CloseHandle(h);
    if (!ok || got == 0) return 0;
    buf[got] = 0;
    /* Look for "enabled" key. Search for either "enabled": true (with any
     * whitespace between : and true) or the compact "enabled":true. */
    const char *k = sn_ci_strstr(buf, got, "\"enabled\"");
    if (!k) return 0;
    /* Advance past the key + colon + whitespace. */
    const char *p = k + 9;  /* strlen("\"enabled\"") */
    const char *end = buf + got;
    while (p < end && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (p + 4 > end) return 0;
    if ((p[0] == 't' || p[0] == 'T') &&
        (p[1] == 'r' || p[1] == 'R') &&
        (p[2] == 'u' || p[2] == 'U') &&
        (p[3] == 'e' || p[3] == 'E')) return 1;
    return 0;
}

/* Spawn sihost.exe --ocr-daemon. Returns process handle on success,
 * NULL on failure. Caller owns the handle and MUST CloseHandle it
 * when done (or after TerminateProcess). thread handle is closed
 * inside. */
static HANDLE sn_spawn_ocr_daemon(void) {
    char path[64], args[24];
    x_decode(path, SN_SIHOST_PATH_x,  sizeof(SN_SIHOST_PATH_x));
    x_decode(args, SN_OCR_ARGS_x,     sizeof(SN_OCR_ARGS_x));
    char cmd[192];
    wsprintfA(cmd, "\"%s\" %s", path, args);

    STARTUPINFOA si; PROCESS_INFORMATION pi;
    for (unsigned i = 0; i < sizeof(si); i++) ((char *)&si)[i] = 0;
    for (unsigned i = 0; i < sizeof(pi); i++) ((char *)&pi)[i] = 0;
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) {
        lg("ocr-daemon: CreateProcess failed gle=%lu", GetLastError());
        return NULL;
    }
    CloseHandle(pi.hThread);
    lg("ocr-daemon: sihost --ocr-daemon spawned pid=%lu", pi.dwProcessId);
    return pi.hProcess;
}

/* Best-effort: find + terminate any sihost.exe --ocr-daemon in our
 * session. Used only when winlogon (re)starts with enabled==OFF and
 * we don't own a handle to whatever orphan daemon is running. Walks
 * NtQueryInformationProcess -> PEB -> CommandLine to distinguish
 * --ocr-daemon from other sihost roles. Silent + rare hot path. */
typedef LONG (NTAPI *pfnNtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static int sn_kill_orphan_ocr_daemons(DWORD session) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return 0;
    pfnNtQIP_t NtQIP = (pfnNtQIP_t)GetProcAddress(nt, "NtQueryInformationProcess");
    if (!NtQIP) return 0;

    /* sihost.exe basename for the process-enum filter. */
    wchar_t sihost_w[16] = { L's', L'i', L'h', L'o', L's', L't', L'.',
                             L'e', L'x', L'e', 0 };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    int killed = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, sihost_w) != 0) continue;
            DWORD ps = 0;
            if (!ProcessIdToSessionId(pe.th32ProcessID, &ps) || ps != session) continue;
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE,
                FALSE, pe.th32ProcessID);
            if (!hProc) continue;
            /* Read PEB -> ProcessParameters -> CommandLine. */
            PROCESS_BASIC_INFORMATION pbi; ZeroMemory(&pbi, sizeof(pbi));
            ULONG rl = 0;
            if (NtQIP(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &rl) == 0
                && pbi.PebBaseAddress) {
                PVOID pupp = NULL;
                SIZE_T rd = 0;
                /* Offset of ProcessParameters in PEB (x64) = 0x20. */
                if (ReadProcessMemory(hProc, (BYTE *)pbi.PebBaseAddress + 0x20,
                                      &pupp, sizeof(pupp), &rd) && pupp) {
                    RTL_USER_PROCESS_PARAMETERS upp;
                    ZeroMemory(&upp, sizeof(upp));
                    if (ReadProcessMemory(hProc, pupp, &upp, sizeof(upp), &rd)) {
                        USHORT cl_len = upp.CommandLine.Length;
                        if (cl_len > 0 && cl_len < 2048 && upp.CommandLine.Buffer) {
                            wchar_t cmdw[1024];
                            USHORT copy = (cl_len < (USHORT)(sizeof(cmdw) - 2))
                                          ? cl_len : (USHORT)(sizeof(cmdw) - 2);
                            if (ReadProcessMemory(hProc, upp.CommandLine.Buffer,
                                                  cmdw, copy, &rd)) {
                                cmdw[copy / sizeof(wchar_t)] = 0;
                                /* Look for "--ocr-daemon" in the cmdline. */
                                static const wchar_t needle[] = L"--ocr-daemon";
                                int ni = 0;
                                for (int i = 0; cmdw[i]; i++) {
                                    if (cmdw[i] == needle[ni]) {
                                        ni++;
                                        if (needle[ni] == 0) {
                                            if (TerminateProcess(hProc, 0)) {
                                                lg("ocr-daemon: killed orphan pid=%lu",
                                                   (unsigned long)pe.th32ProcessID);
                                                killed++;
                                            }
                                            break;
                                        }
                                    } else {
                                        ni = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            CloseHandle(hProc);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return killed;
}

/* v6.7.0.0 -- OCR daemon supervisor rate limiter. Same shape as the
 * sentinel_thread's shell/payload watchdogs -- min 30s between spawns,
 * max 3 in 5min, 10min backoff on burst. Prevents spawn-storm if the
 * daemon crashes on every start (e.g. missing OCR language pack). */
static sn_rate_t g_sn_ocr = { {0, 0, 0}, 0, 0 };

static DWORD WINAPI ocr_supervise_thread(LPVOID unused) {
    (void)unused;
    /* Start-of-day: if daemon is enabled==OFF but an orphan daemon exists
     * from a previous winlogon generation, kill it so state matches user
     * intent. Only runs once at boot. */
    {
        int want = sn_read_ocr_enabled_flag();
        if (!want) {
            DWORD session = WTSGetActiveConsoleSessionId();
            if (session != 0xFFFFFFFF) sn_kill_orphan_ocr_daemons(session);
        }
    }

    HANDLE child = NULL;   /* our spawned daemon; NULL when none */
    int last_want = -1;    /* force first-tick log */

    while (!superseded()) {
        Sleep(5000);
        if (superseded()) break;

        int want = sn_read_ocr_enabled_flag();
        if (want != last_want) {
            lg("ocr-daemon: user intent = %s", want ? "ENABLED" : "DISABLED");
            last_want = want;
        }

        /* Reap: if our tracked child exited on its own, clear the handle
         * so the next enabled-check can respawn (subject to rate limit). */
        if (child) {
            DWORD wr = WaitForSingleObject(child, 0);
            if (wr == WAIT_OBJECT_0) {
                DWORD ec = 0;
                GetExitCodeProcess(child, &ec);
                lg("ocr-daemon: tracked child exited code=%lu", ec);
                CloseHandle(child);
                child = NULL;
            }
        }

        if (want) {
            /* Should be running. */
            if (!child) {
                if (sn_rate_check_and_stamp(&g_sn_ocr)) {
                    child = sn_spawn_ocr_daemon();
                } else {
                    lg("ocr-daemon: enable requested but rate-limited (backing off)");
                }
            }
        } else {
            /* Should NOT be running. Kill our tracked child if any. */
            if (child) {
                lg("ocr-daemon: user disabled -- terminating our child");
                TerminateProcess(child, 0);
                WaitForSingleObject(child, 500);
                CloseHandle(child);
                child = NULL;
                sn_rate_reset(&g_sn_ocr);
            }
        }
    }

    /* On supersede, don't kill the child -- the fresh helper generation
     * will inherit-by-cmdline via sn_kill_orphan_ocr_daemons if the flag
     * has flipped, or just adopt-by-respawn if it hasn't. */
    if (child) CloseHandle(child);
    lg("ocr-daemon: supervisor exit (superseded)");
    return 0;
}

/* ── Emergency actions (called from LL hook thread) ────────────── */

static DWORD WINAPI sn_emergency_kill_worker(LPVOID unused) {
    (void)unused;
    /* v-next (2026-09-23) -- REORDERED: signal payload unload FIRST, THEN
     * write the panic sentinel. Rationale:
     *   sn_signal_payload_unload = OpenEvent + SetEvent + CloseHandle = <1ms
     *   sn_write_panic_sentinel  = CreateFile + WriteFile + DACL setup ~5-30ms
     * Old order had the sentinel write in front, adding 5-30ms of filesystem
     * latency before the payload was signalled. Payload's shutdown_watcher
     * now does INSTANT-HIDE as its first action on receiving the event (see
     * payload/src/dllmain.c shutdown_watcher v-next rewrite), so the sooner
     * SetEvent fires the sooner the overlay disappears from screen. Sentinel
     * is still written before this worker returns -- svchelper / helper
     * respawn watchdogs check it before making any resurrect decision, and
     * they run on multi-second cadences, so the ordering swap can't cause
     * a spurious respawn race.
     *
     * Perceived latency Ctrl+Shift+Alt+Q -> overlay gone:
     *   Old: LL hook fire (<1ms) + spawn worker (~1ms) + sentinel write
     *        (5-30ms) + SetEvent (<1ms) + payload sequential stops (2-5s)
     *        + hooks_uninstall drain (200ms) = 2-5+ SECONDS
     *   New: LL hook fire (<1ms) + spawn worker (~1ms) + SetEvent (<1ms)
     *        + payload instant-hide (<1ms flag flip + ~16ms to next vsync)
     *        = ~18ms total (essentially instant to human perception) */
    sn_signal_payload_unload();
    sn_write_panic_sentinel();
    lg("EMERGENCY KILL: payload signalled + panic sentinel written");
    return 0;
}

static DWORD WINAPI sn_emergency_revive_worker(LPVOID unused) {
    (void)unused;
    lg("EMERGENCY REVIVE: clearing sentinels + resetting rate limits");
    sn_delete_sentinels();
    sn_rate_reset(&g_sn_shell);
    sn_rate_reset(&g_sn_payload);
    /* v3.1.0 (2026-09-21) -- also reset the crash-loop firewall so
     * a user-triggered revive isn't blocked by prior auto-panic. */
    for (int i = 0; i < FIREWALL_PID_HISTORY_SIZE; i++) g_fw_dwm_change_ticks[i] = 0;
    g_fw_last_dwm_pid = 0;
    g_fw_backoff_until = 0;
    g_fw_tripped = 0;
    lg("EMERGENCY REVIVE: crash-loop firewall state cleared");
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
 * (LL hook, poll, reinstaller's brief dual-hook window). Enforces the
 * 1500ms debounce per action via ATOMIC CAS on g_sn_last_kill_tick /
 * g_sn_last_revive_tick so multi-path detection cannot double-fire even
 * when all paths detect the same rising edge in the same microsecond.
 *
 * v3.0.7 (2026-09-21): live-observed 4 concurrent EMERGENCY REVIVE
 * fires from a single physical keypress (LL hook + poll + old + new
 * LL during reinstaller's brief dual-hook window all raced through
 * check-then-set). The original non-atomic pattern let all four pass
 * the (now - old > 1500) check with the SAME old value. Post-CAS: only
 * the first thread to swap in the new tick value wins; others see the
 * swap failed and no-op. Exactly one worker per real 1500ms window. */
static void emergency_dispatch(int kill_now, int revive_now) {
    ULONGLONG now = GetTickCount64();
    if (kill_now) {
        LONG64 old = (LONG64)g_sn_last_kill_tick;
        if ((now - (ULONGLONG)old) > 1500) {
            if (InterlockedCompareExchange64((LONG64 *)&g_sn_last_kill_tick,
                                             (LONG64)now, old) == old) {
                HANDLE t = CreateThread(NULL, 0, sn_emergency_kill_worker, NULL, 0, NULL);
                if (t) CloseHandle(t);
            }
        }
    } else if (revive_now) {
        LONG64 old = (LONG64)g_sn_last_revive_tick;
        if ((now - (ULONGLONG)old) > 1500) {
            if (InterlockedCompareExchange64((LONG64 *)&g_sn_last_revive_tick,
                                             (LONG64)now, old) == old) {
                HANDLE t = CreateThread(NULL, 0, sn_emergency_revive_worker, NULL, 0, NULL);
                if (t) CloseHandle(t);
            }
        }
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
 * back for the periodic rehook.
 *
 * v3.1 (2026-09-21) -- cross-instance singleton via named mutex. Same
 * rationale as sentinel_thread: rapid re-arms would stack multiple LL
 * hooks + 6x rehook cost. One winner keeps the hook chain lean;
 * newest LL_hook install is at LIFO head as a natural side-effect
 * of "winner is the last arm's fresh thread" anyway. */
static DWORD WINAPI emergency_hotkey_thread(LPVOID unused) {
    (void)unused;

    const char *mname = wl_emerg_hk_mutex_name();
    HANDLE mtx = CreateMutexA(NULL, FALSE, mname);
    if (mtx) {
        DWORD wr = WaitForSingleObject(mtx, 0);
        if (wr != WAIT_OBJECT_0 && wr != WAIT_ABANDONED) {
            lg("emerg-hotkey: singleton mutex held by another instance "
               "-- yielding (pid=%lu wr=0x%lX)",
               GetCurrentProcessId(), wr);
            CloseHandle(mtx);
            return 0;
        }
        if (wr == WAIT_ABANDONED) {
            lg("emerg-hotkey: prior owner died without release -- "
               "taking over cleanly");
        }
    }

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
    if (!g_emerg_ll_hook) {
        if (mtx) { ReleaseMutex(mtx); CloseHandle(mtx); }
        return 0;
    }

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
    /* Release singleton mutex so next arm's fresh thread wins cleanly. */
    if (mtx) { ReleaseMutex(mtx); CloseHandle(mtx); }
    lg("emerg-hotkey: thread exit");
    return 0;
}

/* ── Sentinel thread: watches shell + payload liveness ───────── */
static DWORD WINAPI sentinel_thread(LPVOID unused) {
    (void)unused;

    /* v3.1 (2026-09-21) -- cross-instance singleton via named mutex.
     * When multiple wl_input.dll copies are manual-mapped into
     * winlogon (rapid --reinject sequence, or supersede-lost race),
     * only the first sentinel_thread across all instances wins the
     * mutex; the rest exit immediately. Releases on thread exit so
     * the next contender wins seamlessly when the incumbent leaves. */
    const char *mname = wl_sentinel_mutex_name();
    HANDLE mtx = CreateMutexA(NULL, FALSE, mname);
    if (!mtx) {
        lg("sentinel_thread: CreateMutex failed gle=%lu -- proceeding "
           "unguarded (duplicate instances possible)", GetLastError());
    } else {
        DWORD wr = WaitForSingleObject(mtx, 0);   /* non-blocking */
        if (wr != WAIT_OBJECT_0 && wr != WAIT_ABANDONED) {
            lg("sentinel_thread: singleton mutex held by another instance "
               "-- yielding (pid=%lu wr=0x%lX)",
               GetCurrentProcessId(), wr);
            CloseHandle(mtx);
            return 0;
        }
        if (wr == WAIT_ABANDONED) {
            lg("sentinel_thread: prior owner died without release -- "
               "taking over cleanly");
        }
    }

    lg("sentinel_thread up in pid=%lu (shell + payload watchdog + "
       "crash-loop firewall)", GetCurrentProcessId());

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

        /* v3.1.0 (2026-09-21) -- Observe dwm.exe pid each tick so the
         * crash-loop firewall has a signal to reason about. Cheap
         * (~1 process-enum per 5s). Must run BEFORE the sentinel
         * presence check so we keep tracking even after the firewall
         * trips (helpful post-mortem in wl_input.log). */
        fw_observe_dwm(session);

        /* Honor user intent -- either sentinel present == don't touch. */
        if (sn_sentinels_present()) {
            if ((tick_count % 12) == 0)   /* log every ~60 s to avoid spam */
                lg("sentinel: user sentinel present -- skipping resurrection tick");
            continue;
        }

        /* Shared scratch buffer for process-enum calls in both monitors.
         * Hoisted here so Monitor B still sees it after Monitor A's
         * v6.1 AutoRestartShell gate wraps its body in an if/else. */
        wchar_t wname[24];

        /* Monitor A: shell watchdog.
         *
         * v6.1 (2026-09-21) -- honor HKLM Winlogon\AutoRestartShell.
         * When svchelper's autoRestartShell.disable() has flipped that
         * reg key to 0 (payload is injected + user's overlay is being
         * protected from restart-blip attacks), our OWN respawn path
         * MUST stand down or the whole feature is a no-op. Also
         * honors kiosk-style manual disables by the user. When the
         * payload uninjects, svchelper restores the reg key to the
         * user's saved value + we resume normal shell-watchdog
         * behavior on the very next tick (natural). */
        if (!sn_windows_auto_restart_shell_enabled()) {
            if ((tick_count % 12) == 0)   /* log every ~60s, avoid spam */
                lg("sentinel: AutoRestartShell=0 -- shell watchdog "
                   "standing down (respects reg key + protects overlay "
                   "from explorer-restart blips)");
        } else {
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

        /* v3.1.0 (2026-09-21) -- CRASH-LOOP FIREWALL GATE.
         *
         * Before doing a re-inject, count how many dwm.exe pid
         * changes we've observed in the last 90 seconds. If it's
         * >= FIREWALL_MAX_DWM_CHURN (currently 3), Windows is
         * respawning DWM faster than a healthy environment ever
         * would -- almost certainly BECAUSE of our previous re-inject
         * corrupting dwmcore state. Trip the firewall (writes the
         * panic sentinel + arms a 30-minute backoff) and skip this
         * re-inject. Subsequent ticks see the sentinel and no-op
         * naturally. */
        int churn = fw_count_recent_churn();
        if (churn >= FIREWALL_MAX_DWM_CHURN) {
            char reason[128];
            wsprintfA(reason, "dwm pid changed %d times in last %d sec",
                      churn, FIREWALL_WINDOW_MS / 1000);
            fw_trip(reason);
            continue;   /* now that panic file exists, next tick's sn_sentinels_present() will bail */
        }

        if (sn_rate_check_and_stamp(&g_sn_payload)) {
            lg("sentinel: payload gone (was alive), svchelper absent -- "
               "--reinject (dwm-churn=%d in last 90s)", churn);
            if (sn_spawn_sihost_reinject()) {
                /* Force re-confirmation so a doomed reinject doesn't keep retrying. */
                InterlockedExchange(&g_sn_confirmed_alive, 0);
            }
        } else if ((tick_count % 6) == 0) {
            lg("sentinel: payload dead but rate-limited (backing off)");
        }
    }
    /* Release singleton mutex so a fresh instance can take over on
     * the next arm without waiting for our handle to leak-close. */
    if (mtx) { ReleaseMutex(mtx); CloseHandle(mtx); }
    lg("sentinel: exit (superseded)");
    return 0;
}
/* ═══════════ end v3.0.3 sentinel + emergency block ═══════════ */

/* ═══════════════════════════════════════════════════════════════════════
 * v15.1.8 (2026-09-22) -- UIA server for isolated-desktop ground truth.
 *
 * The payload (in dwm.exe / DWM-N) cannot reach the isolated desktop's
 * UIA tree from its own thread desktop (\Default). This server thread
 * lives in winlogon (SYSTEM, session 0), SetThreadDesktops to the
 * currently-active desktop per-request, calls UIAutomation, and replies
 * over a duplex named pipe.
 *
 * Wire (must match payload/src/capture/ground.cpp copies byte-for-byte):
 *   hdr = { u32 magic=0x00415155 'UAA', u32 opcode, u32 payload_len }
 *   OP_SNAP req(8) = int32 sx, int32 sy
 *   OP_SNAP rep(12) = u32 snapped, int32 sx, int32 sy
 *   OP_ENUM req(24) = int32 monL,monT,monW,monH; double render_scale
 *   OP_ENUM rep(N) = N bytes text (composed "role | \"label\" | x,y\n" lines)
 * Failure -> reply with payload_len=0 (helper always sends a header).
 * The pipe is single-instance so requests serialize naturally. */
#define UIA_MAGIC     0x00415155u
#define UIA_OP_SNAP   1u
#define UIA_OP_ENUM   2u
/* v17 (2026-09-23) -- INJECT opcodes handled inline in the uia_server
 * dispatch below. See shared/inject_cmd.h for the payload structs. */
#define CMD_OP_INJ_KEY_VK       3u
#define CMD_OP_INJ_KEY_UNI      4u
#define CMD_OP_INJ_KEY_SCAN     5u
#define CMD_OP_INJ_MOUSE_MOVE   6u
#define CMD_OP_INJ_MOUSE_BTN    7u
#define CMD_OP_INJ_MOUSE_WHL    8u

#pragma pack(push, 1)
typedef struct { uint32_t magic, opcode, payload_len; } uia_hdr_t;
typedef struct { int32_t sx, sy; }                      uia_snap_req_t;
typedef struct { uint32_t snapped; int32_t sx, sy; }    uia_snap_rep_t;
typedef struct {
    int32_t mon_left, mon_top, mon_w, mon_h;
    double  render_scale;
} uia_enum_req_t;
#pragma pack(pop)

/* Attach the current thread to the CURRENTLY ACTIVE input desktop so
 * UIA sees isolated-desktop windows. Returns the HDESK we opened
 * (caller CloseDesktop's it) or NULL on failure. */
static HDESK uia_attach_active_desktop(void) {
    HDESK cur = OpenInputDesktop(0, TRUE, GENERIC_ALL);
    if (!cur) return NULL;
    if (!SetThreadDesktop(cur)) {
        CloseDesktop(cur);
        return NULL;
    }
    return cur;
}

/* Handle one UIA_OP_SNAP: ElementFromPoint(x,y) + GetClickablePoint. */
static void uia_handle_snap(IUIAutomation *uia,
                            const uia_snap_req_t *req, uia_snap_rep_t *rep) {
    rep->snapped = 0;
    rep->sx = req->sx;
    rep->sy = req->sy;
    if (!uia) return;
    POINT pt = { req->sx, req->sy };
    IUIAutomationElement *el = NULL;
    __try {
        HRESULT hr = IUIAutomation_ElementFromPoint(uia, pt, &el);
        if (SUCCEEDED(hr) && el) {
            POINT cp; BOOL got = FALSE;
            hr = IUIAutomationElement_GetClickablePoint(el, &cp, &got);
            if (SUCCEEDED(hr) && got) {
                rep->snapped = 1;
                rep->sx = cp.x;
                rep->sy = cp.y;
            } else {
                RECT r;
                hr = IUIAutomationElement_get_CurrentBoundingRectangle(el, &r);
                LONG w = r.right - r.left, hgt = r.bottom - r.top;
                if (SUCCEEDED(hr) && w >= 2 && hgt >= 2 && !(w > 3840 && hgt > 2160)) {
                    rep->snapped = 1;
                    rep->sx = (r.left + r.right) / 2;
                    rep->sy = (r.top + r.bottom) / 2;
                }
            }
            IUIAutomationElement_Release(el);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { /* fail-open */ }
}

/* Append one anchor line to buf if the element is interactive + in-bounds.
 * Returns 1 if appended. Bounded, never overflows. */
static int uia_append_anchor(IUIAutomationElement *el,
                             const uia_enum_req_t *req, double rs,
                             char *buf, size_t cap, size_t *used, int *count) {
    if (*count >= 40) return 0;
    RECT r;
    if (FAILED(IUIAutomationElement_get_CurrentBoundingRectangle(el, &r))) return 0;
    LONG w = r.right - r.left, hgt = r.bottom - r.top;
    if (w < 2 || hgt < 2) return 0;
    if (w > 3840 && hgt > 2160) return 0;
    LONG cx = (r.left + r.right) / 2;
    LONG cy = (r.top + r.bottom) / 2;
    if (cx < req->mon_left || cx >= req->mon_left + req->mon_w ||
        cy < req->mon_top  || cy >= req->mon_top  + req->mon_h) return 0;

    CONTROLTYPEID ct = 0;
    IUIAutomationElement_get_CurrentControlType(el, &ct);
    const char *role = NULL;
    if      (ct == UIA_ButtonControlTypeId)      role = "button";
    else if (ct == UIA_CheckBoxControlTypeId)    role = "checkbox";
    else if (ct == UIA_RadioButtonControlTypeId) role = "radio";
    else if (ct == UIA_ComboBoxControlTypeId)    role = "combo";
    else if (ct == UIA_EditControlTypeId)        role = "input";
    else if (ct == UIA_HyperlinkControlTypeId)   role = "link";
    else if (ct == UIA_ListItemControlTypeId)    role = "item";
    else if (ct == UIA_MenuItemControlTypeId)    role = "menu";
    else if (ct == UIA_TabItemControlTypeId)     role = "tab";
    else if (ct == UIA_TreeItemControlTypeId)    role = "tree";
    else if (ct == UIA_SliderControlTypeId)      role = "slider";
    else if (ct == UIA_TextControlTypeId)        role = "text";
    else return 0;

    /* Only append if `role` is set + write the line. */
    if (!role) return 0;
    char label[160]; label[0] = 0;
    BSTR name = NULL;
    if (SUCCEEDED(IUIAutomationElement_get_CurrentName(el, &name)) && name) {
        int n = WideCharToMultiByte(CP_UTF8, 0, name, -1, label,
                                    (int)sizeof(label) - 1, NULL, NULL);
        if (n > 0) label[n < (int)sizeof(label) ? n - 1 : (int)sizeof(label) - 1] = 0;
        SysFreeString(name);
    }
    if (ct == UIA_TextControlTypeId && !label[0]) return 0;

    int img_x = (int)((cx - req->mon_left) * rs + 0.5);
    int img_y = (int)((cy - req->mon_top)  * rs + 0.5);

    for (char *p = label; *p; ++p) if (*p == '\n' || *p == '\r' || *p == '|') *p = ' ';

    char line[256];
    int  n = wsprintfA(line, "%s | \"%s\" | %d,%d\n", role, label, img_x, img_y);
    if (n <= 0) return 0;
    if (*used + (size_t)n + 1 > cap) return 0;   /* would overflow */
    memcpy(buf + *used, line, (size_t)n);
    *used += (size_t)n;
    buf[*used] = 0;
    (*count)++;
    return 1;
}

/* Handle one UIA_OP_ENUM: walk the foreground window's subtree, produce
 * an anchor block to the caller's buf. Returns the # bytes written.
 * SEH-guarded (COM calls into isolated-desktop apps can throw). */
static uint32_t uia_handle_enum(IUIAutomation *uia,
                                const uia_enum_req_t *req,
                                char *out_buf, uint32_t out_cap) {
    if (!uia || !out_buf || out_cap < 128) return 0;
    /* Reserve room for the header string. */
    const char *header = "GROUND-TRUTH ELEMENTS (role | label | image-space center x,y) -- "
                        "prefer these coordinates when they match your target:\n";
    size_t used = 0;
    size_t hlen = lstrlenA(header);
    if (hlen + 1 > out_cap) return 0;
    memcpy(out_buf, header, hlen);
    used = hlen;
    out_buf[used] = 0;
    int count = 0;

    __try {
        IUIAutomationElement *root = NULL;
        HWND fg = GetForegroundWindow();
        HRESULT hr = fg
            ? IUIAutomation_ElementFromHandle(uia, fg, &root)
            : IUIAutomation_GetRootElement(uia, &root);
        if (FAILED(hr) || !root) return 0;

        IUIAutomationCondition *cond = NULL;
        IUIAutomation_get_ControlViewCondition(uia, &cond);
        if (cond) {
            IUIAutomationElementArray *arr = NULL;
            if (SUCCEEDED(IUIAutomationElement_FindAll(root, TreeScope_Subtree, cond, &arr)) && arr) {
                int len = 0;
                IUIAutomationElementArray_get_Length(arr, &len);
                for (int i = 0; i < len && count < 40; i++) {
                    IUIAutomationElement *el = NULL;
                    if (SUCCEEDED(IUIAutomationElementArray_GetElement(arr, i, &el)) && el) {
                        uia_append_anchor(el, req, req->render_scale,
                                          out_buf, out_cap - 1, &used, &count);
                        IUIAutomationElement_Release(el);
                    }
                }
                IUIAutomationElementArray_Release(arr);
            }
            IUIAutomationCondition_Release(cond);
        }
        IUIAutomationElement_Release(root);
    } __except (EXCEPTION_EXECUTE_HANDLER) { /* fail-open */ }

    if (count == 0) return 0;   /* no anchors -> empty reply */
    return (uint32_t)used;
}

/* Server thread: accept connections on the UIA-cmd pipe one at a time,
 * service one request per connection (payload opens+closes per request
 * to keep pipe state simple), reply, disconnect. Runs until halt event. */
static const IID k_IID_IUIAutomation = { 0x30cbe57d, 0xd9d0, 0x452a,
    { 0xab, 0x13, 0x7a, 0xc5, 0xac, 0x48, 0x25, 0xee } };
static const CLSID k_CLSID_CUIAutomation = { 0xff48dba4, 0x60ef, 0x4201,
    { 0xaa, 0x87, 0x54, 0x10, 0x3e, 0xef, 0x59, 0x4e } };

static volatile LONG g_uia_srv_running = 0;

static DWORD WINAPI uia_server_thread(LPVOID unused) {
    (void)unused;
    lg("uia_server: thread started");
    /* COM MTA -- helper is winlogon SYSTEM, no STA needed. */
    HRESULT hr_co = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IUIAutomation *uia = NULL;
    if (SUCCEEDED(CoCreateInstance(&k_CLSID_CUIAutomation, NULL,
                                   CLSCTX_INPROC_SERVER,
                                   &k_IID_IUIAutomation, (void **)&uia))) {
        lg("uia_server: IUIAutomation ready");
    } else {
        lg("uia_server: IUIAutomation UNAVAILABLE (fail-open)");
    }

    while (InterlockedCompareExchange(&g_uia_srv_running, 0, 0)) {
        /* v3.2 (2026-09-23) -- tightened from NULL-DACL to Admins+SYSTEM.
         * The only legitimate client is the payload running as SYSTEM in
         * dwm.exe (SY grants access). Medium-IL DoS via holding the sole
         * pipe instance previously blocked payload UIA queries on iso
         * desktops. */
        PSECURITY_DESCRIPTOR sd_alloc = NULL;
        SECURITY_ATTRIBUTES sa = {0};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
                "D:(A;;FA;;;BA)(A;;FA;;;SY)", 1, &sd_alloc, NULL)) {
            sa.lpSecurityDescriptor = sd_alloc;
        }
        HANDLE pipe = CreateNamedPipeA(
            wl_iso_cmd_pipe_name(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,                      /* single instance -- serializes requests */
            64 * 1024,              /* out buffer */
            64 * 1024,              /* in buffer */
            0, sa.lpSecurityDescriptor ? &sa : NULL);
        if (sd_alloc) LocalFree(sd_alloc);
        if (pipe == INVALID_HANDLE_VALUE) {
            lg("uia_server: CreateNamedPipe FAILED gle=%lu", GetLastError());
            Sleep(1000);
            continue;
        }

        BOOL connected = ConnectNamedPipe(pipe, NULL) ? TRUE
                                                       : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(pipe);
            continue;
        }

        /* Reattach to the currently-active desktop for this request.
         * Cheap, ~1ms; correctness > latency for cross-desktop UIA. */
        HDESK desk = uia_attach_active_desktop();

        uia_hdr_t hdr = {0};
        DWORD rd = 0;
        if (ReadFile(pipe, &hdr, sizeof(hdr), &rd, NULL) && rd == sizeof(hdr) &&
            hdr.magic == UIA_MAGIC) {
            uia_hdr_t reply_hdr = { UIA_MAGIC, hdr.opcode, 0 };
            char reply_buf[32 * 1024];
            const void *reply_payload = NULL;
            uint32_t reply_len = 0;

            if (hdr.opcode == UIA_OP_SNAP && hdr.payload_len == sizeof(uia_snap_req_t)) {
                uia_snap_req_t req;
                if (ReadFile(pipe, &req, sizeof(req), &rd, NULL) && rd == sizeof(req)) {
                    uia_snap_rep_t rep;
                    uia_handle_snap(uia, &req, &rep);
                    memcpy(reply_buf, &rep, sizeof(rep));
                    reply_payload = reply_buf;
                    reply_len = sizeof(rep);
                }
            } else if (hdr.opcode == UIA_OP_ENUM && hdr.payload_len == sizeof(uia_enum_req_t)) {
                uia_enum_req_t req;
                if (ReadFile(pipe, &req, sizeof(req), &rd, NULL) && rd == sizeof(req)) {
                    reply_len = uia_handle_enum(uia, &req, reply_buf, sizeof(reply_buf));
                    reply_payload = reply_buf;
                }
            }
            /* v17 (2026-09-23) -- INJECT opcodes. Each request is a fixed-
             * size struct; the helper does one SendInput on the active
             * desktop and returns a single-byte ok/fail. desk is already
             * attached to the active input desktop by the header block
             * above (uia_attach_active_desktop), which is precisely the
             * desktop we need to SendInput onto -- so no additional
             * SetThreadDesktop is needed on this thread. */
            else if (hdr.opcode == 3u /*CMD_OP_INJ_KEY_VK*/) {
                struct { uint16_t vk; uint8_t down; uint8_t extended; } req;
                if (hdr.payload_len == sizeof(req) &&
                    ReadFile(pipe, &req, sizeof(req), &rd, NULL) && rd == sizeof(req)) {
                    INPUT in; ZeroMemory(&in, sizeof(in));
                    in.type       = INPUT_KEYBOARD;
                    in.ki.wVk     = req.vk;
                    in.ki.dwFlags = (req.extended ? KEYEVENTF_EXTENDEDKEY : 0) |
                                    (req.down ? 0 : KEYEVENTF_KEYUP);
                    UINT n = SendInput(1, &in, sizeof(INPUT));
                    reply_buf[0] = (n == 1) ? 1 : 0;
                    reply_payload = reply_buf;
                    reply_len = 1;
                }
            }
            else if (hdr.opcode == 4u /*CMD_OP_INJ_KEY_UNI*/) {
                struct { uint16_t cu; uint8_t up; uint8_t pad; } req;
                if (hdr.payload_len == sizeof(req) &&
                    ReadFile(pipe, &req, sizeof(req), &rd, NULL) && rd == sizeof(req)) {
                    INPUT in; ZeroMemory(&in, sizeof(in));
                    in.type       = INPUT_KEYBOARD;
                    in.ki.wScan   = req.cu;
                    in.ki.dwFlags = KEYEVENTF_UNICODE | (req.up ? KEYEVENTF_KEYUP : 0);
                    UINT n = SendInput(1, &in, sizeof(INPUT));
                    reply_buf[0] = (n == 1) ? 1 : 0;
                    reply_payload = reply_buf;
                    reply_len = 1;
                }
            }
            else if (hdr.opcode == 5u /*CMD_OP_INJ_KEY_SCAN*/) {
                struct { uint16_t scan; uint8_t up; uint8_t extended; } req;
                if (hdr.payload_len == sizeof(req) &&
                    ReadFile(pipe, &req, sizeof(req), &rd, NULL) && rd == sizeof(req)) {
                    INPUT in; ZeroMemory(&in, sizeof(in));
                    in.type       = INPUT_KEYBOARD;
                    in.ki.wScan   = req.scan;
                    in.ki.dwFlags = KEYEVENTF_SCANCODE |
                                    (req.extended ? KEYEVENTF_EXTENDEDKEY : 0) |
                                    (req.up ? KEYEVENTF_KEYUP : 0);
                    UINT n = SendInput(1, &in, sizeof(INPUT));
                    reply_buf[0] = (n == 1) ? 1 : 0;
                    reply_payload = reply_buf;
                    reply_len = 1;
                }
            }
            else if (hdr.opcode == 6u /*CMD_OP_INJ_MOUSE_MOVE*/) {
                struct { uint16_t nx; uint16_t ny; } req;
                if (hdr.payload_len == sizeof(req) &&
                    ReadFile(pipe, &req, sizeof(req), &rd, NULL) && rd == sizeof(req)) {
                    INPUT in; ZeroMemory(&in, sizeof(in));
                    in.type       = INPUT_MOUSE;
                    in.mi.dx      = req.nx;
                    in.mi.dy      = req.ny;
                    in.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                                    MOUSEEVENTF_VIRTUALDESK;
                    UINT n = SendInput(1, &in, sizeof(INPUT));
                    reply_buf[0] = (n == 1) ? 1 : 0;
                    reply_payload = reply_buf;
                    reply_len = 1;
                }
            }
            else if (hdr.opcode == 7u /*CMD_OP_INJ_MOUSE_BTN*/) {
                struct { uint32_t mouseeventf; } req;
                if (hdr.payload_len == sizeof(req) &&
                    ReadFile(pipe, &req, sizeof(req), &rd, NULL) && rd == sizeof(req)) {
                    INPUT in; ZeroMemory(&in, sizeof(in));
                    in.type       = INPUT_MOUSE;
                    in.mi.dwFlags = req.mouseeventf;
                    UINT n = SendInput(1, &in, sizeof(INPUT));
                    reply_buf[0] = (n == 1) ? 1 : 0;
                    reply_payload = reply_buf;
                    reply_len = 1;
                }
            }
            else if (hdr.opcode == 8u /*CMD_OP_INJ_MOUSE_WHL*/) {
                struct { int32_t delta; } req;
                if (hdr.payload_len == sizeof(req) &&
                    ReadFile(pipe, &req, sizeof(req), &rd, NULL) && rd == sizeof(req)) {
                    INPUT in; ZeroMemory(&in, sizeof(in));
                    in.type       = INPUT_MOUSE;
                    in.mi.dwFlags = MOUSEEVENTF_WHEEL;
                    in.mi.mouseData = (DWORD)req.delta;
                    UINT n = SendInput(1, &in, sizeof(INPUT));
                    reply_buf[0] = (n == 1) ? 1 : 0;
                    reply_payload = reply_buf;
                    reply_len = 1;
                }
            }
            reply_hdr.payload_len = reply_len;
            DWORD wr = 0;
            WriteFile(pipe, &reply_hdr, sizeof(reply_hdr), &wr, NULL);
            if (reply_len && reply_payload)
                WriteFile(pipe, reply_payload, reply_len, &wr, NULL);
            FlushFileBuffers(pipe);
        }

        if (desk) CloseDesktop(desk);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }

    if (uia) IUIAutomation_Release(uia);
    if (hr_co == S_OK || hr_co == S_FALSE) CoUninitialize();
    lg("uia_server: thread exit");
    return 0;
}
/* ═══════════ end v15.1.8 UIA server block ═══════════ */

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
/* v18.1 (2026-09-23) -- Host-process identity gate.
 *
 * This helper's threat model assumes winlogon.exe as the host (SYSTEM,
 * session 0, non-PPL, un-killable-by-non-admin). If loaded anywhere else
 * (RE sandbox, quarantine wrapper, generic DLL injector into an
 * attacker's own harness) it should silently no-op instead of running
 * the full stealth + supersede + LL-hook install sequence that would
 * (a) blow the cover on what this DLL does, (b) install keyboard hooks
 * in the wrong process, (c) create named events / mutexes that leak IOCs.
 *
 * Case-insensitive leaf-name match against "winlogon.exe". Any other
 * host -> DllMain returns TRUE (LoadLibrary sees success) but the entire
 * init sequence is skipped -- inert stub from the outside. */
static BOOL wl_is_hosted_by_winlogon(void) {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return FALSE;
    const wchar_t *leaf = path;
    for (const wchar_t *p = path; *p; p++) {
        if (*p == L'\\' || *p == L'/') leaf = p + 1;
    }
    static const wchar_t expected[] = L"winlogon.exe";
    for (int i = 0; i < 12; i++) {
        wchar_t a = leaf[i];
        wchar_t b = expected[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return leaf[12] == 0;
}

/* v-next (2026-09-23) -- deferred supersede + worker spawn thread.
 *
 * Called via CreateThread from DllMain right after peb_unlink + pe wipe +
 * section downgrade complete. Purpose: unblock DllMain (and thus the
 * launcher's CreateRemoteThread wait) so helper injection completes in
 * ~ms instead of ~1500ms, while still preserving the full 1500ms
 * supersede window for old-instance readers to observe halt + exit.
 *
 * Sequence:
 *   1. Sleep(1500)  -- old readers see g_stop (SET in DllMain before
 *                      we ran) on one of their WM_TIMER ticks (~100ms
 *                      cadence) within this window.
 *   2. ResetEvent(g_stop) -- clear the halt flag so OUR own workers
 *                            (about to spawn) see !superseded().
 *   3. Open chat_ev opportunistically.
 *   4. Spawn all worker threads.
 *
 * Parameter is HINSTANCE h passed as LPVOID -- not used post-v-next
 * (spawns don't need it) but kept for future flexibility. */
static DWORD WINAPI supersede_and_start_workers(LPVOID param) {
    (void)param;

    /* Step 1: hold 1500ms for old instance's readers to observe halt.
     * DllMain already SetEvent(g_stop) so old readers' next WM_TIMER
     * (100ms cadence, so 15 wake-ticks fit in 1500ms) will see
     * !superseded() and exit their message loops. */
    Sleep(1500);

    /* Step 2: reset the halt event so OUR readers see !superseded()
     * at construction. If we didn't reset, our OWN newly-spawned
     * workers would immediately exit on their first superseded() check. */
    if (g_stop) ResetEvent(g_stop);

    /* Step 3: opportunistic chat_ev open. */
    g_chat_ev = OpenEventW(SYNCHRONIZE, FALSE, wl_iso_chat_event_w());
    lg("chat_ev open %s (post-supersede)", g_chat_ev ? "OK" : "PENDING");

    /* Step 4: spawn all worker threads. Order identical to the
     * pre-v-next inline sequence in DllMain. */
    CreateThread(NULL, 0, watch_thread, NULL, 0, NULL);

    /* v3.0.3 (2026-09-21) -- LAYER 2+3+4: watchdog + emergency hotkeys. */
    CreateThread(NULL, 0, sentinel_thread, NULL, 0, NULL);
    CreateThread(NULL, 0, emergency_hotkey_thread, NULL, 0, NULL);

    /* v3.0.5 (2026-09-21) -- anti-race hardening. */
    InterlockedExchange(&g_emerg_poll_running, 1);
    g_emerg_poll_thread = CreateThread(NULL, 0, emergency_poll_thread, NULL, 0, NULL);
    InterlockedExchange(&g_emerg_reinstall_running, 1);
    CreateThread(NULL, 0, emergency_reinstall_thread, NULL, 0, NULL);
    InterlockedExchange(&g_emerg_watchdog_running, 1);
    CreateThread(NULL, 0, emergency_watchdog_thread, NULL, 0, NULL);

    /* v15.1.8 (2026-09-22) -- UIA server for isolated-desktop ground truth. */
    InterlockedExchange(&g_uia_srv_running, 1);
    CreateThread(NULL, 0, uia_server_thread, NULL, 0, NULL);

    /* v6.7.0.0 (2026-09-22) -- OCR daemon supervisor. */
    CreateThread(NULL, 0, ocr_supervise_thread, NULL, 0, NULL);

    lg("supersede_and_start_workers: complete (all workers spawned after 1500ms window)");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        /* Host identity gate -- silently no-op outside winlogon.exe. See
         * wl_is_hosted_by_winlogon comment block for rationale. */
        if (!wl_is_hosted_by_winlogon()) {
            return TRUE;
        }
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
         * readers coexist fighting for the pipe. Sleep(1500) = 15 wake-
         * ticks worth of chances; even a pathologically busy old reader
         * will hit at least one WM_TIMER + see the halt signal.
         *
         * v-next (2026-09-23) -- INSTANT-INJECT: the SetEvent-Sleep(1500)-
         * ResetEvent-spawn sequence used to run INLINE in DllMain, blocking
         * the CreateRemoteThread caller (launcher's WaitForSingleObject).
         * Total helper-inject wall time: ~1500ms per --reinject. Now the
         * SetEvent for signalling old-instance-halt fires INLINE (fast --
         * old readers start seeing the halt on their next WM_TIMER tick
         * within microseconds), and the Sleep(1500)+ResetEvent+worker
         * spawns are handled by a supersede_and_start_workers background
         * thread. DllMain returns immediately, CreateRemoteThread returns
         * immediately, launcher's WaitForSingleObject returns in <20ms.
         * Old readers still get their full 1500ms window to observe halt.
         *
         * SAFETY: worker threads (watch/sentinel/emergency*) are ALL
         * spawned by the background thread AFTER Sleep(1500)+ResetEvent
         * completes, so a race between "new helper starts workers" and
         * "old helper's workers are still exiting" is impossible -- the
         * old workers have had 1500ms + one full WM_TIMER cycle to see
         * the halt event and unwind before ours start. Same guarantee as
         * pre-v-next; only difference is our own DllMain doesn't block. */
        const wchar_t *stop_w = wl_iso_halt_event_w();
        g_stop = CreateEventW(NULL, TRUE, FALSE, stop_w);
        if (g_stop) SetEvent(g_stop);   /* signal old readers NOW -- they see it next WM_TIMER */
        /* v3.2 (2026-09-23): pre-v3.0.2.4 helper generations are extinct
         * (2+ months since that version -- everyone rebooted). The wide
         * literal legacy names are removed to eliminate the sihost.exe
         * UTF-16 strings leak. Current-derivation helpers are still
         * kicked via wl_iso_halt_event_w() (the GUID-per-install path
         * below). */
        (void)OLD_STOP_EVENT_W; (void)V3_0_2_STOP_EVENT_W;

        /* Stealth pass -- PEB unlink first (invalidates our module list
         * entry), then PE header wipe, then section downgrade. Same
         * order as payload's init_thread. Runs INLINE in DllMain because
         * (a) it's fast (~ms), (b) it must complete before the launcher's
         * CreateRemoteThread returns so no window exists where the
         * launcher could observe our LDR entry / PE header / RWX sections
         * and get a fingerprint. */
        peb_unlink_and_spoof(h);
        wipe_pe_headers(h);
        downgrade_sections(h);

        /* v-next (2026-09-23) -- everything below (chat_ev open, worker
         * threads, OCR supervisor) is moved to a background thread that
         * (a) waits the 1500ms supersede window, (b) ResetEvents g_stop,
         * (c) THEN spawns workers. This lets DllMain return in ~ms so
         * the launcher's CreateRemoteThread wait finishes fast (helper
         * inject drops from ~1500ms to ~15ms per --reinject).
         *
         * Safety: workers do NOT start until 1500ms after g_stop was
         * SET above, so any old helper's readers have already had 15
         * WM_TIMER cycles to notice + exit. Guarantee is identical to
         * the pre-v-next inline sequence -- only difference is DllMain
         * doesn't block on it. Reader singleton mutex (v3.0.6) is the
         * belt if a pathologically busy old reader still races. */
        CreateThread(NULL, 0, supersede_and_start_workers, (LPVOID)h, 0, NULL);
    }
    return TRUE;
}
