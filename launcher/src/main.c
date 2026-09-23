/* ================================================================== *
 * main.c -- Launcher entry point.                                     *
 *                                                                    *
 * Flow:                                                              *
 *   1. Elevation check + SeDebugPrivilege                            *
 *   2. OAuth login (or reload valid session)                         *
 *   3. Subscription check                                            *
 *   4. Settings UI (config editor -- placeholder for MVP)             *
 *   5. On "Arm":                                                     *
 *        - Write encrypted config file                               *
 *        - Run resolver to produce offsets.blob                      *
 *        - Inject payload into dwm.exe                               *
 *   6. Exit (payload persists inside dwm.exe)                        *
 *                                                                    *
 * MVP UI: MessageBox-based flow. Full ImGui-native settings UI       *
 * lives in a follow-up. This is enough to prove the auth + inject   *
 * pipeline end-to-end.                                               *
 * ================================================================== */

#include "../../shared/common.h"
#include "../../shared/hwid.h"
#include "../../shared/log_secure.h"
#include "../../shared/supabase_config.h"
#include "../../shared/handshake.h"
#include "../../shared/crypto_util.h"
#include "../../shared/json_util.h"
#include "../../shared/str_enc.h"
#include "../../shared/lazy_api.h"
#include "../../shared/obf_names.h"
#include "../../shared/sec_attr.h"
#include "../../shared/bind_secret.h"
#include "config_write.h"
#include "inject.h"
#include "license.h"
#include "oauth.h"
#include "ocr/ocr_scanner.h"

#include <shellapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

/* Lazy-resolve OpenProcess so it doesn't appear in the IAT. Same
 * technique as inject.c but scoped locally here since main.c has its
 * own kill/kill-all paths that call OpenProcess with different flags. */
typedef HANDLE (WINAPI *PFN_OpenProcessML)(DWORD, BOOL, DWORD);
static PFN_OpenProcessML g_pOpenProcessML = NULL;
#define OpenProcess(desired, inherit, pid) \
    ((g_pOpenProcessML ? g_pOpenProcessML : \
      (g_pOpenProcessML = LAZY_API(PFN_OpenProcessML, L"kernel32.dll", "OpenProcess"))) \
     ((desired), (inherit), (pid)))

/* ── v1.6.5 (2026-07-17): parent-process verification ─────────────────
 *
 * Sihost only exists to serve the Electron UI (svchelper.exe). Any
 * OTHER caller is either:
 *   (a) an attacker attempting to lift a valid session by dropping a
 *       crafted api_key.txt and running sihost --quiet
 *   (b) a legitimate power-user who edited settings via CLI (rare;
 *       we now require the Electron path)
 *
 * verify_svchelper_parent() reads the InheritedFromUniqueProcessId
 * field of our own PROCESS_BASIC_INFORMATION via NtQueryInformationProcess,
 * opens the parent with PROCESS_QUERY_LIMITED_INFORMATION (least
 * privilege -- works even if parent is high-integrity), reads the
 * parent's full image path via QueryFullProcessImageNameW, and verifies
 * the basename is svchelper.exe.
 *
 * Weaknesses (acknowledged):
 *   - Parent PID CAN be spoofed via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
 *     by an attacker with SeAssignPrimaryTokenPrivilege (typically
 *     admin). Combining with SVC_STR_DIR path-prefix check makes this
 *     harder -- attacker needs their spoofed parent to sit in our
 *     install directory too. Still not cryptographic.
 *   - For a real cryptographic bind (attacker-with-admin threat model),
 *     add an HMAC launch-token via registry + env var. Deferred to a
 *     future revision -- parent-check + install-path-check covers the
 *     casual-lift attack we care about today.
 *
 * Returns 1 if parent is svchelper.exe from our install dir, 0 otherwise.
 * On probe failure (dbghelp missing / OpenProcess denied), returns 0 --
 * fail closed. */
typedef LONG (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef struct {
    LONG  ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG  BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} SVC_PROCESS_BASIC_INFORMATION;

static int str_ends_with_icase(const wchar_t *s, const wchar_t *suffix) {
    if (!s || !suffix) return 0;
    size_t ls = wcslen(s), lx = wcslen(suffix);
    if (lx > ls) return 0;
    const wchar_t *p = s + (ls - lx);
    for (size_t i = 0; i < lx; i++) {
        wchar_t a = p[i], b = suffix[i];
        if (a >= L'A' && a <= L'Z') a = (wchar_t)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = (wchar_t)(b - L'A' + L'a');
        if (a != b) return 0;
    }
    return 1;
}

static int verify_svchelper_parent(char *err, size_t err_sz) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        _snprintf(err, err_sz - 1, "ntdll.dll not loaded (impossible)");
        return 0;
    }
    pfnNtQueryInformationProcess NtQIP =
        (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQIP) {
        _snprintf(err, err_sz - 1, "NtQueryInformationProcess missing");
        return 0;
    }
    SVC_PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG ret = 0;
    LONG st = NtQIP(GetCurrentProcess(), 0 /* ProcessBasicInformation */,
                    &pbi, sizeof(pbi), &ret);
    if (st != 0 || pbi.InheritedFromUniqueProcessId == 0) {
        _snprintf(err, err_sz - 1, "NtQIP failed st=0x%lX", (unsigned long)st);
        return 0;
    }
    DWORD parent_pid = (DWORD)pbi.InheritedFromUniqueProcessId;
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent_pid);
    if (!hp) {
        _snprintf(err, err_sz - 1, "OpenProcess(parent=%lu) failed gle=%lu",
                  parent_pid, GetLastError());
        return 0;
    }
    wchar_t path[MAX_PATH * 2] = {0};
    DWORD plen = (DWORD)(sizeof(path) / sizeof(path[0]));
    BOOL ok = QueryFullProcessImageNameW(hp, 0, path, &plen);
    CloseHandle(hp);
    if (!ok) {
        _snprintf(err, err_sz - 1, "QueryFullProcessImageName failed gle=%lu",
                  GetLastError());
        return 0;
    }
    /* Basename must be svchelper.exe OR winlogon.exe (case-insensitive).
     *
     * v3.0.7 (2026-09-21): added winlogon.exe as an accepted parent so
     * the winlogon-hosted helper (see tools/redteam/probes/wl_input.c)
     * can spawn `sihost --reinject` for Layer 3 payload-respawn +
     * Layer 4 emergency-revive hotkey. Previously the parent-verify
     * gate rejected these spawns because parent showed as winlogon,
     * silently defeating the entire winlogon-watchdog auto-recovery
     * architecture. Live-reproduced 2026-09-21 07:26: emergency-revive
     * hotkey fired 4x cleanly, each spawn hit REJECT + ExitProcess(23).
     *
     * SECURITY: winlogon is a whitelist safe target because injecting
     * INTO winlogon requires SeDebugPrivilege (admin-only) + successfully
     * bypassing PPL on newer Windows. A hostile process at any tier
     * capable of injecting into winlogon has already-total control of
     * the system -- the parent-verify gate can't stop them and doesn't
     * need to (they'd bypass every other check too). Only our own
     * helper (manual-mapped by our own elevated launcher) legitimately
     * runs code inside winlogon on this box. */
    if (!str_ends_with_icase(path, L"\\svchelper.exe") &&
        !str_ends_with_icase(path, L"\\winlogon.exe")) {
        char pathA[MAX_PATH * 2] = {0};
        WideCharToMultiByte(CP_UTF8, 0, path, -1, pathA, sizeof(pathA) - 1, NULL, NULL);
        _snprintf(err, err_sz - 1, "parent is not svchelper.exe or winlogon.exe: %.200s", pathA);
        return 0;
    }
    /* Log which whitelisted parent triggered acceptance so post-mortem
     * can tell the manual-launch flow (svchelper) from the helper
     * auto-recovery flow (winlogon). */
    const wchar_t *parent_kind = str_ends_with_icase(path, L"\\winlogon.exe")
        ? L"winlogon.exe (helper auto-recovery)" : L"svchelper.exe";
    char parent_kind_a[80] = {0};
    WideCharToMultiByte(CP_UTF8, 0, parent_kind, -1, parent_kind_a, sizeof(parent_kind_a) - 1, NULL, NULL);
    slog_writef("launcher.log",
                "parent-verify: OK (pid=%lu is %s)", parent_pid, parent_kind_a);
    return 1;
}

/* ── Elevation check ──────────────────────────────────────────────── */
static int is_elevated(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    TOKEN_ELEVATION te;
    DWORD sz = sizeof(te);
    int elevated = 0;
    if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &sz))
        elevated = te.TokenIsElevated != 0;
    CloseHandle(tok);
    return elevated;
}

/* ── v3.2 (2026-09-23) High-integrity check ─────────────────────────
 * is_elevated() alone is insufficient at the destructive-verb gate:
 * SAFER-derived tokens (SaferComputeTokenFromLevel(NORMALUSER)) keep
 * TokenElevationType=Full even after admin group is stripped + integrity
 * dropped, so a malicious process running with a SAFER-derived token
 * would pass is_elevated() while actually being at Medium IL with no
 * real admin power. is_high_integrity() reads the mandatory label SID
 * directly (S-1-16-8192 == Medium, 12288 == High, 16384 == System).
 * We require >= HIGH (12288) to run --unload / --kill / --kill-all
 * (which signal + potentially terminate DWM). Combined with the DACL on
 * the shutdown event this closes the medium-IL destructive-verb window
 * even if the caller's token has weird ElevationType metadata. */
static int is_high_integrity(void) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    DWORD needed = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &needed);
    if (needed == 0) { CloseHandle(tok); return 0; }
    PTOKEN_MANDATORY_LABEL tml = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!tml) { CloseHandle(tok); return 0; }
    int high = 0;
    if (GetTokenInformation(tok, TokenIntegrityLevel, tml, needed, &needed)) {
        DWORD *sub = GetSidSubAuthority(tml->Label.Sid,
                                        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
        if (sub && *sub >= 0x3000 /* SECURITY_MANDATORY_HIGH_RID */) high = 1;
    }
    HeapFree(GetProcessHeap(), 0, tml);
    CloseHandle(tok);
    return high;
}

static void die(const char *title, const char *msg) {
    MessageBoxA(NULL, msg, title, MB_ICONERROR | MB_OK);
    slog_writef("launcher.log", "die: %s: %s", title, msg);
    ExitProcess(1);
}

/* ── v3.0.2 (2026-09-21) -- Best-effort helper injection ──────────────
 *
 * The wl_input helper is the SYSTEM-hosted input forwarder for isolated
 * / secure desktops. It's optional -- the payload works fully on Default
 * without it. So if the helper injection fails (e.g., no winlogon in
 * our session, resource missing on this build, helper binary corrupt),
 * we log the failure and continue. Only isolated-desktop input is
 * degraded, and that's a well-defined graceful degradation.
 *
 * Called from every arm path (--reinject, --json-config, full arm)
 * AFTER the payload is confirmed injected. The helper needs the
 * payload's named pipe (\\.\pipe\NetSvcCoord) to exist to be useful,
 * and the payload creates that pipe in its init_thread. */
static void arm_helper_best_effort(HMODULE self, const char *ctx) {
    /* v3.0.6 (2026-09-21): pre-signal helper unload BEFORE injecting a
     * new one, so any prior helper generations start their halt-event
     * exit path with a head start. Prevents the multi-generation
     * accumulation regression observed live 2026-09-21 06:07 where
     * rapid re-injects during dev testing left 2+ helper generations
     * running in winlogon, both spawning readers on iso desktops, both
     * fighting for the NetSvcCoord pipe.
     *
     * Sleep 300ms after signalling so old helpers' WM_TIMER poll (100ms
     * cadence) has 3 wake-ticks to see the halt event and start exiting
     * BEFORE the new helper's DllMain runs its own 1500ms supersede.
     * Combined budget: 1800ms across two layers of kill-old-instance
     * signalling. If a helper is STILL alive after that, the reader
     * singleton mutex (v3.0.6) prevents its reader from grabbing the
     * pipe -- iso input works via whichever reader won the mutex. */
    int prior = inject_helper_signal_unload();
    if (prior) {
        slog_writef("launcher.log",
                    "%s: pre-signalled prior helper halt (giving 300ms head start)",
                    ctx);
        Sleep(300);
    }

    char err[512] = {0};
    int ok = inject_helper_from_resource(self, SVC_HELPER_RCDATA_ID,
                                         err, sizeof(err));
    if (ok) {
        slog_writef("launcher.log", "%s: helper (winlogon) inject OK", ctx);
    } else {
        slog_writef("launcher.log",
                    "%s: helper inject FAILED (%s) -- isolated-desktop input degraded, "
                    "Default overlay + input remain fully functional",
                    ctx, err);
    }
}

/* ── Handshake stamp ─────────────────────────────────────────────── *
 * Populate the v4 magic / schema / handshake fields on a config struct
 * about to be written. Used by BOTH the legacy env-var arm path (so
 * `sihost --quiet` iteration keeps working for devs) and by the
 * `--json-config` path when Electron didn't precompute a token itself.
 *
 * Idempotent: safe to call multiple times.
 * Returns 1 iff handshake_compute succeeded. */
static int stamp_handshake_and_magic(svc_config_t *cfg,
                                     const char *access_token,
                                     const char *hwid) {
    cfg->magic          = SVC_CONFIG_MAGIC;
    cfg->schema_version = SVC_CONFIG_SCHEMA_VERSION;
    cfg->handshake_epoch_day = handshake_current_epoch_day();
    _snprintf(cfg->handshake_hwid, sizeof(cfg->handshake_hwid) - 1, "%s", hwid ? hwid : "");
    cfg->handshake_hwid[sizeof(cfg->handshake_hwid) - 1] = 0;
    memset(cfg->handshake_token, 0, sizeof(cfg->handshake_token));
    if (!access_token || !access_token[0] || !hwid || !hwid[0]) {
        slog_writef("launcher.log",
                    "handshake stamp: skipped -- missing access_token or hwid "
                    "(len at=%zu hwid=%zu)",
                    access_token ? strlen(access_token) : 0,
                    hwid ? strlen(hwid) : 0);
        return 0;
    }
    int ok = handshake_compute(access_token, cfg->handshake_hwid,
                               cfg->handshake_epoch_day,
                               cfg->handshake_token);
    if (!ok) {
        slog_writef("launcher.log", "handshake stamp: compute FAILED");
        return 0;
    }
    slog_writef("launcher.log",
                "handshake stamp: ok day=%lld hwid=%.8s...",
                (long long)cfg->handshake_epoch_day, cfg->handshake_hwid);
    return 1;
}

/* ── Read entire file into a malloc'd buffer (NUL-terminated). ── */
static char *slurp_file(const char *path, size_t *out_len) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz = {0};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 8 * 1024 * 1024) {
        CloseHandle(h); return NULL;
    }
    char *buf = (char *)malloc((size_t)sz.QuadPart + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD r = 0;
    BOOL ok = ReadFile(h, buf, (DWORD)sz.QuadPart, &r, NULL);
    CloseHandle(h);
    if (!ok || r != (DWORD)sz.QuadPart) { free(buf); return NULL; }
    buf[r] = 0;
    if (out_len) *out_len = r;
    return buf;
}

/* ── Parse a JSON handoff file from Electron into svc_config_t.
 * The Electron UI writes a temporary JSON to disk (deleted immediately
 * after read) containing:
 *
 *   {
 *     "access_token": "eyJ...",
 *     "token_expires_at": 1672531200,
 *     "hwid": "SMBIOS-UUID",
 *     "handshake_epoch_day": 19541,
 *     "handshake_token_hex": "abc...deadbeef",   // 64 hex chars
 *     "provider": 1,           // 1=OA 2=AN 3=GG 4=OR
 *     "tier":     1,           // 0=STRONG 1=MED 2=CHEAP 3=CUSTOM
 *     "api_key":  "sk-...",
 *     "model":    "",
 *     "reasoning_effort":  4,
 *     "streaming_enabled": 1,
 *     "latex_disabled":    0,
 *     "system_prompt":     "",
 *     "overlay_x":40, "overlay_y":40, "overlay_w":560, "overlay_h":420,
 *     "overlay_alpha": 0.94,
 *     "hotkeys_packed_csv": "196640,262215,..."   // 32 uints comma-sep
 *   }
 *
 * On success: cfg is fully populated (including magic + handshake). We
 * additionally VERIFY the handshake token before returning success, so a
 * corrupt/tampered JSON is rejected here rather than at payload init.
 *
 * Returns 1 iff the JSON was well-formed AND the handshake verifies. */
static int assemble_config_from_json(const char *json,
                                     svc_config_t *cfg,
                                     char *err, size_t err_sz) {
    if (!json || !cfg) return 0;
    memset(cfg, 0, sizeof(*cfg));

    /* ── Required fields ────────────────────────────────────── */
    if (!json_get_str(json, "access_token", cfg->access_token, sizeof(cfg->access_token))) {
        _snprintf(err, err_sz - 1, "missing access_token"); return 0;
    }
    /* v14 (2026-09-19) -- refresh_token is OPTIONAL for backwards compat
     * (older Electron builds don't send it; the payload just won't be
     * able to self-refresh in that case and falls back to Electron's
     * pipe push exclusively -- see token_refresh_client.c). New Electron
     * builds populate it so the payload can survive svchelper.exe being
     * closed post-inject. Missing -> zeroed cfg->refresh_token, which
     * token_refresh_client.c handles gracefully (single log line, then
     * idle). */
    json_get_str(json, "refresh_token", cfg->refresh_token, sizeof(cfg->refresh_token));
    if (!json_get_str(json, "hwid", cfg->handshake_hwid, sizeof(cfg->handshake_hwid))) {
        _snprintf(err, err_sz - 1, "missing hwid"); return 0;
    }
    char hex[80] = {0};
    if (!json_get_str(json, "handshake_token_hex", hex, sizeof(hex))) {
        _snprintf(err, err_sz - 1, "missing handshake_token_hex"); return 0;
    }
    if (cu_from_hex(hex, cfg->handshake_token, sizeof(cfg->handshake_token))
            != (int)sizeof(cfg->handshake_token)) {
        _snprintf(err, err_sz - 1, "handshake_token_hex wrong length (need 64 chars)");
        return 0;
    }
    double n = 0;
    if (!json_get_num(json, "handshake_epoch_day", &n)) {
        _snprintf(err, err_sz - 1, "missing handshake_epoch_day"); return 0;
    }
    cfg->handshake_epoch_day = (long long)n;
    if (json_get_num(json, "token_expires_at", &n)) cfg->token_expires_at = (long long)n;

    /* v5 per-provider keys -- populated by Electron from the 4-input
     * settings card. At least ONE must be non-empty; the legacy
     * cfg->api_key (single-key backward compat) is optional. */
    json_get_str(json, "api_key_openai",     cfg->api_key_openai,     sizeof(cfg->api_key_openai));
    json_get_str(json, "api_key_anthropic",  cfg->api_key_anthropic,  sizeof(cfg->api_key_anthropic));
    json_get_str(json, "api_key_google",     cfg->api_key_google,     sizeof(cfg->api_key_google));
    json_get_str(json, "api_key_openrouter", cfg->api_key_openrouter, sizeof(cfg->api_key_openrouter));
    /* Legacy shared field -- if UI sends it, prefer it. Otherwise fall
     * through to per-provider keys inside ai_provider.c. */
    json_get_str(json, "api_key", cfg->api_key, sizeof(cfg->api_key));

    if (!cfg->api_key[0] && !cfg->api_key_openai[0] && !cfg->api_key_anthropic[0]
        && !cfg->api_key_google[0] && !cfg->api_key_openrouter[0]) {
        /* No BYO key is OK: the payload routes solves through the metered
         * CloakGPT-credits worker (svcldb-solve) using cfg->access_token
         * (validated present above). Only reject if there is ALSO no
         * session token -- then there is neither a credits path nor a key. */
        if (!cfg->access_token[0]) {
            _snprintf(err, err_sz - 1, "no api key and no session token");
            return 0;
        }
        /* else: credits mode -- allow injection with no BYO key. */
    }
    if (json_get_num(json, "provider", &n)) cfg->provider = (int)n;
    if (json_get_num(json, "tier",     &n)) cfg->tier     = (int)n;
    json_get_str(json, "model", cfg->model, sizeof(cfg->model));
    if (json_get_num(json, "reasoning_effort",  &n)) cfg->reasoning_effort  = (int)n;
    if (json_get_num(json, "streaming_enabled", &n)) cfg->streaming_enabled = (int)n;
    if (json_get_num(json, "latex_disabled",    &n)) cfg->latex_disabled    = (int)n;
    /* v6: direct-answer mode. See config_types.h + ai_provider.c
     * materialize_default_system for the exact system-prompt override. */
    if (json_get_num(json, "direct_answer_mode", &n)) cfg->direct_answer_mode = (int)n;
    /* v6.1: batched-display streaming (buffer chunks, render once). */
    if (json_get_num(json, "stream_display_batched", &n)) cfg->stream_display_batched = (int)n;

    /* system_prompt: allow empty (payload falls back to built-in).
     * v6 semantics for non-empty values:
     *   - "DEFAULT"        -> use built-in prompt
     *   - "APPEND:\n<text>" -> built-in + user tail
     *   - anything else    -> user's text verbatim (power user override) */
    json_get_str(json, "system_prompt", cfg->system_prompt, sizeof(cfg->system_prompt));

    /* overlay geometry (all optional -- sensible defaults for missing fields) */
    if (json_get_num(json, "overlay_x",     &n)) cfg->overlay_x = (int)n; else cfg->overlay_x = 40;
    if (json_get_num(json, "overlay_y",     &n)) cfg->overlay_y = (int)n; else cfg->overlay_y = 40;
    if (json_get_num(json, "overlay_w",     &n)) cfg->overlay_w = (int)n; else cfg->overlay_w = 560;
    if (json_get_num(json, "overlay_h",     &n)) cfg->overlay_h = (int)n; else cfg->overlay_h = 420;
    if (json_get_num(json, "overlay_alpha", &n)) cfg->overlay_alpha = (float)n; else cfg->overlay_alpha = 1.00f;   /* v11: default OPAQUE for zero trailing */
    /* v8: size_mode (0=normal, 1=ultra). Default normal. */
    if (json_get_num(json, "size_mode",     &n)) cfg->size_mode = (int)n; else cfg->size_mode = 0;
    /* v11 (2026-07-24): theme (0=dark, 1=light, 2=auto). Default AUTO (payload
     * polls Windows Personalize registry every ~2s and follows the system). */
    if (json_get_num(json, "theme",         &n)) cfg->theme = (int)n; else cfg->theme = 2;
    /* v11: overlay behavior flags. Default: TRAIL_ERASE + SMOOTH_NUDGE + UNIFORM_ALPHA on. */
    if (json_get_num(json, "overlay_flags", &n)) cfg->overlay_flags = (unsigned)n; else cfg->overlay_flags = SVC_OVFLAG_DEFAULTS;
    /* v12 (2026-07-25): scroll_step_px -- user-configurable pixels per scroll
     * hotkey / mouse wheel notch. Default 80 mirrors pre-v12 hardcoded value. */
    if (json_get_num(json, "scroll_step_px", &n)) cfg->scroll_step_px = (int)n; else cfg->scroll_step_px = 80;
    if (cfg->scroll_step_px < 20 || cfg->scroll_step_px > 400) cfg->scroll_step_px = 80;
    /* v13 (2026-08-10): nudge_step_px -- user-configurable pixels per arrow-key
     * nudge (micro-adjust). Default 48 mirrors the pre-v13 hardcoded value. */
    if (json_get_num(json, "nudge_step_px", &n)) cfg->nudge_step_px = (int)n; else cfg->nudge_step_px = 48;
    if (cfg->nudge_step_px < 1 || cfg->nudge_step_px > 200) cfg->nudge_step_px = 48;

    /* Hotkeys: CSV of packed uints. Missing / short -> zeroed slots.
     *
     * v9 (2026-07-06): loop now iterates the FULL array capacity
     * (previously hardcoded 32, cutting off SVC_HK_DIRECT_TOGGLE = 32
     * and any future slots -- see the OOB bug notes in config_types.h).
     * Using the sizeof-derived cap keeps this in sync with any future
     * array-size bumps automatically. */
    const int hk_cap = (int)(sizeof(cfg->hotkeys) / sizeof(cfg->hotkeys[0]));
    char csv[4096] = {0};
    if (json_get_str(json, "hotkeys_packed_csv", csv, sizeof(csv))) {
        char *tok = csv;
        for (int i = 0; i < hk_cap && *tok; i++) {
            char *comma = strchr(tok, ',');
            if (comma) *comma = 0;
            cfg->hotkeys[i] = (unsigned)strtoul(tok, NULL, 10);
            if (!comma) break;
            tok = comma + 1;
        }
    }

    /* Header + handshake sanity -- MUST verify against the token we
     * just decoded before we hand this to config_write. */
    cfg->magic          = SVC_CONFIG_MAGIC;
    cfg->schema_version = SVC_CONFIG_SCHEMA_VERSION;
    if (!handshake_verify(cfg->access_token, cfg->handshake_hwid,
                          cfg->handshake_token)) {
        _snprintf(err, err_sz - 1,
                  "handshake_token mismatch (day=%lld, hwid=%.8s..., "
                  "did Electron/sihost use the same access_token?)",
                  (long long)cfg->handshake_epoch_day, cfg->handshake_hwid);
        return 0;
    }
    return 1;
}

/* Auto-detect provider from an API key's prefix. Returns provider enum
 * or 0 if no match. Extracted for reuse between --json-config path
 * and legacy env-var path. */
static int detect_provider_from_key(const char *api_key) {
    if (!api_key || !*api_key) return 0;
    if (strncmp(api_key, "sk-ant-", 7) == 0) return SVC_PROVIDER_ANTHROPIC;
    if (strncmp(api_key, "sk-or-",  6) == 0) return SVC_PROVIDER_OPENROUTER;
    if (strncmp(api_key, "sk-",     3) == 0) return SVC_PROVIDER_OPENAI;
    if (strncmp(api_key, "AIza",    4) == 0) return SVC_PROVIDER_GOOGLE;
    return SVC_PROVIDER_OPENROUTER;   /* safe catch-all */
}

/* ── MVP settings flow: prompt via MessageBox / simple InputBox ─── *
 * Replaced by native ImGui settings in v2 -- for now, use environment
 * variables + default config so we can prove the pipeline works.
 * User exports SVCLDB_API_KEY + SVCLDB_PROVIDER before running.
 */
static void load_env_config(svc_config_t *cfg, const oauth_session_t *sess) {
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->access_token, sess->access_token, sizeof(cfg->access_token) - 1);
    cfg->token_expires_at = sess->expires_at;

    /* Provider select -- env var wins if set. */
    char provider[32] = {0};
    GetEnvironmentVariableA("SVCLDB_PROVIDER", provider, sizeof(provider));

    GetEnvironmentVariableA("SVCLDB_API_KEY", cfg->api_key, sizeof(cfg->api_key));

    if      (_stricmp(provider, "openai")     == 0) cfg->provider = SVC_PROVIDER_OPENAI;
    else if (_stricmp(provider, "anthropic")  == 0) cfg->provider = SVC_PROVIDER_ANTHROPIC;
    else if (_stricmp(provider, "google")     == 0) cfg->provider = SVC_PROVIDER_GOOGLE;
    else if (_stricmp(provider, "openrouter") == 0) cfg->provider = SVC_PROVIDER_OPENROUTER;
    else cfg->provider = 0;   /* auto-detect below once we have the key */
    GetEnvironmentVariableA("SVCLDB_MODEL",   cfg->model,   sizeof(cfg->model));
    if (cfg->model[0] == 0) {
        switch (cfg->provider) {
            case SVC_PROVIDER_OPENAI:     strncpy(cfg->model, SS(SVC_STR_MODEL_OPENAI_GPT55),   sizeof(cfg->model) - 1); break;
            case SVC_PROVIDER_ANTHROPIC:  strncpy(cfg->model, SS(SVC_STR_MODEL_ANTHROPIC_OPUS),sizeof(cfg->model) - 1); break;
            case SVC_PROVIDER_GOOGLE:     strncpy(cfg->model, "gemini-2.5-pro",       sizeof(cfg->model) - 1); break;
            case SVC_PROVIDER_OPENROUTER: strncpy(cfg->model, "anthropic/claude-opus-4.8", sizeof(cfg->model) - 1); break;
        }
    }
    cfg->reasoning_effort = 4;  /* high */

    /* Leave system_prompt empty (or literally "DEFAULT") so ai_ask()
     * uses the built-in SVCLDB_DEFAULT_SYSTEM_PROMPT in
     * payload/src/ai/ai_provider.c -- ~10 KB of subject-matter rules
     * ported from hooksdll/lumio/src/autosolver.js (math/physics/chem/
     * bio/eng/CS/nursing/humanities/business + verify loop + common
     * pitfalls + response humanization).
     *
     * Power users can drop their own prompt into config.dat post-arm
     * if they want to override. */
    cfg->system_prompt[0] = 0;

    /* Hotkey defaults -- chosen to survive LL-hook interception by other apps.
     * Empirically 2026-07-05: Ctrl+G / Ctrl+Shift+G / Ctrl+P are consumed by
     * Cursor IDE's LL keyboard hook (Find/CommandPalette). Ctrl+Alt+* combos
     * are almost never intercepted since no common app uses them by default.
     * Ctrl+Shift+letter combos ARE seen when the letter isn't in the OS-wide
     * accessibility set (F/K/S are safe; G/P/T are risky). */
    #define MOD_C    SVC_HK_MOD_CTRL
    #define MOD_S    SVC_HK_MOD_SHIFT
    #define MOD_A    SVC_HK_MOD_ALT
    #define MOD_CS   (SVC_HK_MOD_CTRL | SVC_HK_MOD_SHIFT)
    #define MOD_CA   (SVC_HK_MOD_CTRL | SVC_HK_MOD_ALT)
    #define MOD_CSA  (SVC_HK_MOD_CTRL | SVC_HK_MOD_SHIFT | SVC_HK_MOD_ALT)
    memset(cfg->hotkeys, 0, sizeof(cfg->hotkeys));
    /* v1.7.5.1 (2026-07-24) -- Bypassify-1:1 PARITY defaults in the launcher
     * fallback path (mirror of ui/src/injector/injector.js DEFAULT_HOTKEYS).
     * The launcher's env-var --quiet fallback used to install the old
     * multitap-triple-tap map for every slot; that made "Ctrl+Left nudge"
     * require THREE Ctrl+Left presses which is (a) not BP-parity, (b) the
     * root cause of the "jaggy nudge" LO reported (each 3-tap window = one
     * step). Now single Ctrl+key just like BP. Electron UI still overrides
     * per-user via hotkey editor; this is only the launcher-only fallback
     * used by dev-bypass and the initial-install --json-config write. */
    cfg->hotkeys[SVC_HK_ASK]           = SVC_HK_PACK(MOD_C,   'U');       /*  0 Ctrl+U   Take Screenshot     */
    cfg->hotkeys[SVC_HK_TOGGLE]        = SVC_HK_PACK(MOD_C,   'B');       /*  1 Ctrl+B   Hide/Show Overlay   */
    cfg->hotkeys[SVC_HK_TYPING]        = SVC_HK_PACK(MOD_C,   'T');       /*  2 Ctrl+T   Text Input Mode     */
    cfg->hotkeys[SVC_HK_COPY_REPLY]    = SVC_HK_PACK(MOD_C,   'C');       /*  3 Ctrl+C   (LO ask 2026-07-25 -- user prefers Ctrl+C binding; clipboard-write bug is separate) */
    cfg->hotkeys[SVC_HK_CLEAR]         = SVC_HK_PACK(MOD_C,   'Q');       /*  4 Ctrl+Q   Quit                */
    cfg->hotkeys[SVC_HK_MOVE_LEFT]     = SVC_HK_PACK(MOD_C,   0x25);      /*  5 Ctrl+Left                    */
    cfg->hotkeys[SVC_HK_MOVE_RIGHT]    = SVC_HK_PACK(MOD_C,   0x27);      /*  6 Ctrl+Right                   */
    cfg->hotkeys[SVC_HK_MOVE_UP]       = SVC_HK_PACK(MOD_C,   0x26);      /*  7 Ctrl+Up                      */
    cfg->hotkeys[SVC_HK_MOVE_DOWN]     = SVC_HK_PACK(MOD_C,   0x28);      /*  8 Ctrl+Down                    */
    cfg->hotkeys[SVC_HK_RESIZE_WIDER]  = SVC_HK_PACK(MOD_CA,  0xBB);      /*  9 Ctrl+Alt+=                   */
    cfg->hotkeys[SVC_HK_RESIZE_NARROW] = SVC_HK_PACK(MOD_CA,  0xBD);      /* 10 Ctrl+Alt+-                   */
    cfg->hotkeys[SVC_HK_RESIZE_TALLER] = SVC_HK_PACK(MOD_CA,  0xDD);      /* 11 Ctrl+Alt+]                   */
    cfg->hotkeys[SVC_HK_RESIZE_SHORT]  = SVC_HK_PACK(MOD_CA,  0xDB);      /* 12 Ctrl+Alt+[                   */
    cfg->hotkeys[SVC_HK_CYCLE_CORNER]  = SVC_HK_PACK(MOD_CA,  'Q');       /* 13 Ctrl+Alt+Q                   */
    cfg->hotkeys[SVC_HK_ALPHA_UP]      = SVC_HK_PACK(MOD_CA,  0xBE);      /* 14 Ctrl+Alt+.                   */
    cfg->hotkeys[SVC_HK_ALPHA_DOWN]    = SVC_HK_PACK(MOD_CA,  0xBC);      /* 15 Ctrl+Alt+,                   */
    cfg->hotkeys[SVC_HK_FONT_UP]       = SVC_HK_PACK(MOD_CA,  0xDE);      /* 16 Ctrl+Alt+'                   */
    cfg->hotkeys[SVC_HK_FONT_DOWN]     = SVC_HK_PACK(MOD_CA,  0xBA);      /* 17 Ctrl+Alt+;                   */
    cfg->hotkeys[SVC_HK_RESET]         = SVC_HK_PACK(MOD_CA,  'R');       /* 18 Ctrl+Alt+R                   */
    cfg->hotkeys[SVC_HK_DEBUG_CAP]     = SVC_HK_PACK(MOD_CSA, 0x7B);      /* 19 Ctrl+Shift+Alt+F12           */
    cfg->hotkeys[SVC_HK_KILL_ALL]      = SVC_HK_PACK(MOD_CSA, 'K');       /* 20 Ctrl+Shift+Alt+K             */
    cfg->hotkeys[SVC_HK_SCROLL_UP]     = SVC_HK_PACK(MOD_C,   0xDB);      /* 21 Ctrl+[   Scroll Chat Up      */
    cfg->hotkeys[SVC_HK_SCROLL_DOWN]   = SVC_HK_PACK(MOD_C,   0xDD);      /* 22 Ctrl+]   Scroll Chat Down    */
    cfg->hotkeys[SVC_HK_NEW_CHAT]      = SVC_HK_PACK(MOD_C,   'N');       /* 23 Ctrl+N                       */
    cfg->hotkeys[SVC_HK_CYCLE_TIER]    = SVC_HK_PACK(MOD_C,   'M');       /* 24 Ctrl+M   Cycle AI Model      */
    cfg->hotkeys[SVC_HK_CYCLE_PROVIDER]= SVC_HK_PACK(MOD_CS,  'P');       /* 25 Ctrl+Shift+P                 */
    cfg->hotkeys[SVC_HK_REGENERATE]    = SVC_HK_PACK(MOD_C,   0x0D);      /* 26 Ctrl+Enter  Send to AI       */
    cfg->hotkeys[SVC_HK_STREAM_TOGGLE] = SVC_HK_PACK(MOD_CS,  'T');       /* 27 Ctrl+Shift+T                 */
    cfg->hotkeys[SVC_HK_COPY_CODE]     = SVC_HK_PACK(MOD_C,   'K');       /* 28 Ctrl+K                       */
    cfg->hotkeys[SVC_HK_COPY_ANSWER]   = SVC_HK_PACK(MOD_C,   'A');       /* 29 Ctrl+A                       */
    cfg->hotkeys[SVC_HK_LATEX_TOGGLE]  = SVC_HK_PACK(MOD_CS,  'L');       /* 30 Ctrl+Shift+L                 */
    cfg->hotkeys[SVC_HK_STOP_GEN]      = SVC_HK_PACK(MOD_CS,  'S');       /* 31 Ctrl+Shift+S  Settings       */
    cfg->hotkeys[SVC_HK_DIRECT_TOGGLE] = SVC_HK_PACK(MOD_CS,  'D');       /* 32 Ctrl+Shift+D                 */
    /* 33 SVC_HK_QUICK_ASK: v3 (2026-09-19) -- default triple-middle-click
     * within 400ms fires screenshot+ask. Mirrors ui/src/injector/injector.js
     * (JS side already ships this; C fallback matches so a CLI-only inject
     * without svchelper gets the same out-of-box mouse-only control).
     * VK_MBUTTON = 4. Middle-triple-click is virtually never a normal
     * gesture, so this hijacks nothing. Rebind via the hotkey editor. */
    cfg->hotkeys[SVC_HK_QUICK_ASK]     = SVC_HK_PACK_MOUSE_MULTI(3, 400, 4);
    cfg->hotkeys[SVC_HK_LEAN_TOGGLE]   = SVC_HK_PACK(MOD_CSA, 'M');       /* 34 Ctrl+Shift+Alt+M  Lean mode  */

    cfg->overlay_x = 40; cfg->overlay_y = 40;
    cfg->overlay_w = 560; cfg->overlay_h = 420;
    cfg->overlay_alpha = 1.00f;   /* v11: OPAQUE default -- Bypassify-parity, zero trailing */
    cfg->size_mode = 0;   /* v8: normal size clamps by default */
    cfg->theme = 2;                            /* v11: AUTO -- follow Windows theme */
    cfg->overlay_flags = SVC_OVFLAG_DEFAULTS;  /* v11: smooth-nudge + uniform-alpha ON (v13: OPAQUE_LOCK dropped) */
    cfg->scroll_step_px = 80;                  /* v12: default scroll granularity */
    cfg->nudge_step_px = 48;                   /* v13: default arrow-key nudge step */

    /* Defaults for the AI-config fields.
     *   tier=MEDIUM -- balanced default; user rotates live via Ctrl+Alt+M
     *   reasoning_effort=high -- best answers at cost of ~2x tokens
     *   streaming_enabled=1 -- live-typing feel
     *   latex_disabled=0 -- LaTeX ON by default (readable + copyable) */
    if (cfg->tier == 0 && cfg->model[0] == 0) {
        cfg->tier = 1;   /* SVC_TIER_MEDIUM */
    }
    if (cfg->reasoning_effort == 0) cfg->reasoning_effort = 4;   /* high */
    cfg->streaming_enabled = 1;
    cfg->latex_disabled    = 0;
}

/* ── Locate resolver + payload beside our exe ───────────────────── */
static void resolve_beside_me(const char *name, char *out, size_t outsize) {
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);
    char *slash = strrchr(self, '\\');
    if (slash) *(slash + 1) = 0;
    _snprintf(out, outsize - 1, "%s%s", self, name);
    out[outsize - 1] = 0;
}

/* v3.1 (2026-09-21) -- dwmcore.dll fingerprint for offsets.blob
 * staleness detection. Reads PE header IMAGE_FILE_HEADER.TimeDateStamp
 * (4 bytes) which changes any time Microsoft rebuilds the DLL.
 * Cheap: opens dwmcore, reads first 4KB, extracts the 4-byte stamp.
 * Returns 0 on failure. */
static DWORD dwmcore_time_date_stamp(void) {
    HANDLE h = CreateFileA("C:\\Windows\\System32\\dwmcore.dll",
                           GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    BYTE buf[4096];
    DWORD n = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf), &n, NULL);
    CloseHandle(h);
    if (!ok || n < 512) return 0;
    /* IMAGE_DOS_HEADER.e_lfanew at 0x3C */
    DWORD nt_off = *(DWORD *)(buf + 0x3C);
    if (nt_off + 8 > n) return 0;
    /* NT sig 'PE\0\0' (4 bytes), then IMAGE_FILE_HEADER whose
     * TimeDateStamp is at offset 4. */
    if (buf[nt_off] != 'P' || buf[nt_off + 1] != 'E') return 0;
    if (nt_off + 4 + 4 + 4 > n) return 0;
    return *(DWORD *)(buf + nt_off + 4 + 4);
}

/* Path of the sidecar file storing the dwmcore signature the current
 * offsets.blob was resolved against. */
static void offsets_sig_path(char *out, size_t out_sz) {
    _snprintf(out, out_sz - 1, "%s\\%s.sig",
              SVC_INSTALL_DIR, SVC_OFFSETS_BLOB);
    out[out_sz - 1] = 0;
}

static DWORD offsets_sig_read(void) {
    char path[MAX_PATH];
    offsets_sig_path(path, sizeof(path));
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD sig = 0, n = 0;
    ReadFile(h, &sig, sizeof(sig), &n, NULL);
    CloseHandle(h);
    return (n == sizeof(sig)) ? sig : 0;
}

static void offsets_sig_write(DWORD sig) {
    char path[MAX_PATH];
    offsets_sig_path(path, sizeof(path));
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, &sig, sizeof(sig), &w, NULL);
    CloseHandle(h);
}

/* Returns 1 if offsets.blob is stale (dwmcore has been rebuilt since
 * last resolve), 0 if fresh, -1 if we can't determine. */
static int offsets_blob_needs_refresh(void) {
    DWORD cur = dwmcore_time_date_stamp();
    if (cur == 0) return -1;   /* couldn't read dwmcore header */
    DWORD saved = offsets_sig_read();
    if (saved == 0) return 1;  /* no cached sig -> definitely refresh */
    return (cur != saved) ? 1 : 0;
}

static int run_resolver(char *err, size_t err_sz) {
    char resolver[MAX_PATH];
    resolve_beside_me(SVC_RESOLVER_EXE, resolver, sizeof(resolver));
    if (GetFileAttributesA(resolver) == INVALID_FILE_ATTRIBUTES) {
        _snprintf(err, err_sz - 1, "resolver missing: %s", resolver); err[err_sz - 1] = 0;
        return 0;
    }
    /* Delete any stale offsets.blob first. */
    char blob[MAX_PATH];
    _snprintf(blob, sizeof(blob) - 1, "%s\\%s", SVC_INSTALL_DIR, SVC_OFFSETS_BLOB);
    blob[sizeof(blob) - 1] = 0;
    DeleteFileA(blob);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(resolver, NULL, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        _snprintf(err, err_sz - 1, "spawn resolver: %lu", GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 180000);   /* 3 min (PDB download can be slow) */
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (GetFileAttributesA(blob) == INVALID_FILE_ATTRIBUTES) {
        _snprintf(err, err_sz - 1, "resolver produced no offsets.blob (exit=%lu). "
                                   "Payload will fall back to sig scanning.", exit_code);
        err[err_sz - 1] = 0;
        return 0;
    }
    /* v3.1 (2026-09-21) -- stamp the dwmcore signature next to the blob
     * so future arms know if it needs re-running. */
    DWORD stamp = dwmcore_time_date_stamp();
    if (stamp) offsets_sig_write(stamp);
    slog_writef("launcher.log",
                "resolver ok (exit=%lu, dwmcore-stamp=0x%08lx)",
                exit_code, (unsigned long)stamp);
    return 1;
}

/* Auto-refresh offsets.blob if dwmcore has been rebuilt since last
 * resolve. Called from every arm path (--reinject, --json-config,
 * full arm). Safe to skip on failure -- the payload has a sig-scan
 * fallback for the essentials. */
static void auto_refresh_offsets_if_stale(const char *caller) {
    int stale = offsets_blob_needs_refresh();
    if (stale != 1) {
        if (stale == 0) {
            slog_writef("launcher.log",
                        "%s: offsets.blob fresh (dwmcore unchanged)", caller);
        }
        return;
    }
    slog_writef("launcher.log",
                "%s: dwmcore signature CHANGED (Windows update?) -- "
                "auto-re-running resolver to refresh offsets.blob",
                caller);
    char rerr[512] = {0};
    if (!run_resolver(rerr, sizeof(rerr))) {
        slog_writef("launcher.log",
                    "%s: auto-resolver FAILED: %s (continuing; payload will "
                    "use stale RVAs -- overlay may not render this session)",
                    caller, rerr);
    } else {
        slog_writef("launcher.log",
                    "%s: offsets.blob refreshed successfully", caller);
    }
}

int main(int argc, char *argv[]) {
    /* --quiet   suppress MessageBox dialogs (iteration mode).
     * --unload  signal payload to cooperatively unload from dwm.exe
     *           (Bypassify-style: sets shutdown flag, sleeps 200ms so
     *           clean frames composite over our overlay pixels, then
     *           disables hooks). Overlay is off-screen in ~250ms total.
     * --kill    force-terminate dwm.exe. Windows respawns it fresh in
     *           ~2s, guaranteed to clear the overlay. Use ONLY if
     *           --unload doesn't work (e.g., payload hung). */
    int quiet_mode = 0;
    int unload_mode = 0;
    int kill_mode = 0;
    int kill_all_mode = 0;
    int reinject_mode = 0;   /* skip config regen; use existing config.dat */
    int json_config_mode = 0;
    int ocr_daemon_mode = 0; /* stay resident, serve OCR redaction over pipe */
    int status_mode = 0;     /* read-only "is payload injected?" probe */
    const char *json_config_path = NULL;
#if SVCLDB_DEV_BYPASS_AUTH
    /* v1.7.4.10 (2026-07-24): --custom-dll <path> -- dev-only. Manual-
     * maps an ARBITRARY DLL from disk into dwm.exe using our existing
     * inject path. For RE observation of third-party payloads
     * (e.g. Bypassify's dumper.dll) without going through their
     * proprietary launcher. Available ONLY in dev-bypass builds. */
    int custom_dll_mode = 0;
    const char *custom_dll_path = NULL;
#endif
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            quiet_mode = 1;
        } else if (strcmp(argv[i], "--unload") == 0 || strcmp(argv[i], "-u") == 0) {
            unload_mode = 1;
            quiet_mode = 1;  /* --unload implies --quiet */
        } else if (strcmp(argv[i], "--kill") == 0) {
            kill_mode = 1;
            quiet_mode = 1;
        } else if (strcmp(argv[i], "--kill-all") == 0) {
            kill_all_mode = 1;
            quiet_mode = 1;
        } else if (strcmp(argv[i], "--status") == 0) {
            /* Read-only injected-state probe for the Electron status poll.
             * Handled EARLY (below), before the elevation gate and before
             * any arm path -- pure OpenEvent, zero side effects. */
            status_mode = 1;
            quiet_mode = 1;
#if SVCLDB_DEV_BYPASS_AUTH
        } else if (strcmp(argv[i], "--custom-dll") == 0 && i + 1 < argc) {
            custom_dll_mode = 1;
            custom_dll_path = argv[i + 1];
            quiet_mode = 1;
            i++;
#endif
        } else if (strcmp(argv[i], "--reinject") == 0 ||
                   strcmp(argv[i], "-r") == 0) {
            /* Fast re-injection using the existing config.dat + offsets.blob.
             * Skips OAuth, subscription check, api_key.txt, resolver, config
             * regen. Just: verify config.dat exists -> inject payload from
             * embedded resource -> done. Used after --kill-all or DWM crash
             * when the user wants to arm again without going through the
             * full 3-minute cold-start. */
            reinject_mode = 1;
            quiet_mode = 1;
        } else if (strcmp(argv[i], "--ocr-daemon") == 0) {
            /* Screenshot-redactor daemon. Stays resident, listens on a
             * named pipe, redacts BGRA frames sent by the payload before
             * they leave the machine as vision-LLM requests. Spawned by
             * the Electron toggle; terminated by opcode-2 shutdown or
             * process kill from Electron. See ocr_scanner.h + the
             * HANDOFF_OCR_BLACKOUT_PORTABLE_REFERENCE doc. */
            ocr_daemon_mode = 1;
            quiet_mode = 1;
        } else if (strcmp(argv[i], "--json-config") == 0 && i + 1 < argc) {
            /* Electron UI hand-off: read a temp JSON with the session +
             * settings + handshake, write encrypted config.dat, run
             * resolver, inject. Skips OAuth entirely (Electron did it).
             * Path arg is consumed + should be deleted by Electron after
             * we exit successfully. */
            json_config_mode = 1;
            json_config_path = argv[i + 1];
            quiet_mode = 1;
            i++;   /* consume the path arg */
        }
    }

    /* Decrypt smoking-gun string blob before any logging. Idempotent. */
    svc_str_init();

    slog_launcher("=== launcher start ===");

    /* ── --status: read-only injected-state probe (Electron status poll) ──
     * Existence of the payload's Global\ shutdown event == overlay alive.
     * Exit 0 == loaded, 3 == not loaded. Handled here, BEFORE the elevation
     * gate, the production launch-lockdown gate, and every arm path, so a
     * status poll can NEVER trigger OAuth / subscription-check / inject and
     * needs no elevation -- it is a pure OpenEvent(SYNCHRONIZE). This is the
     * robust, PowerShell-free probe the Electron injector prefers; see
     * ui/src/injector/injector.js probePayload(). */
    if (status_mode) {
        int loaded = inject_is_loaded();
        slog_writef("launcher.log", "--status: loaded=%d", loaded);
        ExitProcess(loaded ? 0 : 3);
    }

    /* ── v3.2 (2026-09-23) High-integrity gate for destructive verbs ──
     *
     * --unload / --kill / --kill-all are documented as "safe from any
     * parent" because the shutdown event's DACL (Admins+SYSTEM only,
     * see payload/src/dllmain.c build_shutdown_event_sa) already blocks
     * medium-IL SetEvent. But we add an explicit integrity gate here
     * as defense-in-depth: even if some future refactor accidentally
     * loosens the DACL, this second check catches it. Reject with
     * silent exit 24 so a probing attacker learns nothing (same shape
     * as the parent-verify silent reject at line ExitProcess(23)).
     *
     * Only High/System IL callers get through; SAFER-derived tokens at
     * Medium fail is_high_integrity() even when their ElevationType
     * metadata is Full (verified live 2026-09-23 with the medium-IL
     * attacker at tools/redteam/attacker_medium_il.ps1). */
    if ((unload_mode || kill_mode || kill_all_mode) && !is_high_integrity()) {
        slog_writef("launcher.log",
                    "REJECT: destructive verb (%s) at low integrity",
                    unload_mode ? "--unload" :
                    kill_mode   ? "--kill"   : "--kill-all");
        ExitProcess(24);
    }

    if (!is_elevated()) {
        if (quiet_mode) {
            slog_writef("launcher.log", "die: elevation required (quiet)");
            ExitProcess(2);
        }
        die("Elevation required",
            SVC_PRODUCT_NAME " must run as Administrator.\n\n"
            "Right-click the executable and choose 'Run as administrator'.");
    }

#if !SVCLDB_DEV_BYPASS_AUTH
    /* ── v1.6.5 (2026-07-17) LAUNCH LOCKDOWN -- production only ──
     *
     * sihost.exe is an internal helper spawned by svchelper.exe. Any
     * direct-launch attempt (attacker with admin drops crafted args)
     * gets rejected here. Only exceptions: --unload / --kill / --kill-all
     * (destructive-only, safe to allow from anywhere -- worst case an
     * attacker disables their own overlay).
     *
     * Two-layer gate:
     *   1. Legacy CLI-arm modes (--quiet or bare no-args) are DEAD in
     *      production. They existed as pre-Electron dev iteration paths;
     *      Electron's --json-config supersedes them. Attacker who drops
     *      api_key.txt + runs `sihost.exe` no longer arms -- hard exit.
     *
     *   2. --json-config and --reinject (the two Electron-driven arm
     *      paths) require our parent process to be svchelper.exe from
     *      the install directory. Blocks attacker from crafting their
     *      own JSON handoff and spawning sihost with it.
     *
     * Dev-bypass build (SVCLDB_DEV_AUTH=1) skips BOTH -- iterating via
     * `sihost --quiet` or `sihost --reinject` works as always. */
    if (quiet_mode && !unload_mode && !kill_mode && !kill_all_mode &&
        !reinject_mode && !json_config_mode && !ocr_daemon_mode) {
        /* Encrypted log line only -- no user-facing hint about internal
         * layout, no plaintext MessageBox that ships strings to
         * attackers. Silent non-zero exit. */
        slog_writef("launcher.log", "REJECT: unsupported CLI mode");
        ExitProcess(22);
    }
    if (argc == 1) {
        /* Bare `sihost.exe` with no args -- same silent reject. */
        slog_writef("launcher.log", "REJECT: bare launch");
        ExitProcess(22);
    }
    if (json_config_mode || reinject_mode || ocr_daemon_mode) {
        char verify_err[512] = {0};
        if (!verify_svchelper_parent(verify_err, sizeof(verify_err))) {
            slog_writef("launcher.log",
                        "REJECT: parent-verify failed (%s) -- not spawned by "
                        "svchelper.exe", verify_err);
            /* Silent exit -- don't tip off attacker with a MessageBox. */
            ExitProcess(23);
        }
    }
#endif

    /* ── --unload: cooperative unload ── *
     * Signal the named event; payload's shutdown_watcher wakes,
     * calls hooks_uninstall() -> sleeps 200ms -> MinHook down.
     * We wait ~500ms then exit so the caller sees a synchronous "done".
     * If the payload is NOT loaded, signal fails silently and we exit 0. */
    if (unload_mode) {
        int signaled = inject_signal_unload();
        /* v3.0.2 (2026-09-21) -- also signal the helper in winlogon so its
         * watch + reader threads exit. Helper is optional; ignore failure. */
        int helper_signaled = inject_helper_signal_unload();
        slog_writef("launcher.log", "--unload signal=%d helper_signal=%d",
                    signaled, helper_signaled);
        if (signaled) {
            /* Give the payload time to drain 200ms of clean frames + 50ms
             * MinHook disable + safety margin. */
            Sleep(500);

            /* CLEAN-SHUTDOWN SENTINEL -- write a marker file so the NEXT
             * launch knows the prior session shut down cleanly. Absence
             * on next launch = prior session was killed (crash, taskmgr,
             * force-close). Support can grep launcher.log for
             * "prior=clean" vs "prior=DIRTY" to diagnose. */
            /* v3.0.3 (2026-09-21): locked-DACL sentinel writer -- see
             * shared/common.h svc_write_locked_sentinel + the sentinel
             * DoS gap doc in HANDOFF_2026-09-21_WINLOGON_WATCHDOG_LANDED.md.
             * Prevents any non-admin process from forging this sentinel
             * to disarm the resurrection watchdogs. Launcher runs
             * elevated so it can always lock down its own writes.
             *
             * v3.2 (2026-09-23) -- PARENT-VERIFY GATE ON SENTINEL WRITE.
             * A hostile admin process can invoke `sihost.exe --unload`
             * directly and previously that would (a) signal the payload
             * to unload gracefully AND (b) write .dwm_clean_shutdown --
             * which then made the winlogon-hosted sentinel_thread stand
             * down for the entire session. Net: non-destructive kill
             * that survived, violating the "only destructive methods
             * win" mandate. Fix: only write the sentinel when parent
             * IS svchelper.exe (the legit user-driven path). Hostile
             * admin's --unload still signals (payload dies briefly)
             * but the watchdog auto-reinjects within ~5s because the
             * "user wanted a clean shutdown" hint is absent. Dev-bypass
             * builds keep the old behavior so dev iteration isn't
             * disrupted (dev tester wants payload to stay unloaded
             * between manual --unload / --reinject cycles). */
            int _trusted_unload;
            char _pv_err[256] = {0};
            int _pv_ok = verify_svchelper_parent(_pv_err, sizeof(_pv_err));
#if SVCLDB_DEV_BYPASS_AUTH
            /* Dev-bypass: default is to keep old behavior so dev iteration
             * (manual `sihost --unload` from a PowerShell) isn't disrupted.
             * Set SVCLDB_STRICT_UNLOAD=1 to enable prod semantics for
             * red-team testing without a full prod rebuild. */
            _trusted_unload = _pv_ok ? 1 : (GetEnvironmentVariableA("SVCLDB_STRICT_UNLOAD", NULL, 0) > 0 ? 0 : 1);
            if (!_pv_ok && _trusted_unload) {
                slog_writef("launcher.log",
                            "--unload: dev-bypass allowing untrusted parent (%s) -- "
                            "set SVCLDB_STRICT_UNLOAD=1 to enforce prod behavior",
                            _pv_err);
            }
#else
            _trusted_unload = _pv_ok;
#endif
            if (!_trusted_unload) {
                slog_writef("launcher.log",
                            "--unload: UNTRUSTED parent (%s) -- payload signalled but "
                            ".dwm_clean_shutdown sentinel NOT written; watchdog will "
                            "auto-reinject", _pv_err);
            }
            if (_trusted_unload && svc_write_locked_sentinel(
                    SVC_INSTALL_DIR "\\.dwm_clean_shutdown",
                    "clean\n", 6)) {
                slog_writef("launcher.log", "clean-shutdown sentinel written (locked DACL)");
            }

            /* Verify: if the payload actually unloaded, dwm.exe should
             * no longer have dwmapiext.dll loaded. Not fatal if still
             * loaded (some AV/perf plugins can slow FreeLibrary) -- just
             * a diagnostic. */
            if (inject_is_loaded()) {
                slog_writef("launcher.log", "--unload: payload still loaded after 500ms");
            } else {
                slog_writef("launcher.log", "--unload: payload gone");
            }
        }
        ExitProcess(0);
    }

    /* ── --kill: force-terminate DWM ── *
     * Nuclear option. Sends kill signal to dwm.exe. Windows respawns it
     * in ~2s, guaranteed to clear ANY leftover overlay pixels (fresh
     * process = fresh compositor state = fresh backing textures). */
    if (kill_mode) {
        unsigned long pid = inject_find_dwm_pid();
        slog_writef("launcher.log", "--kill: dwm.exe pid=%lu", pid);
        if (pid) {
            /* Try cooperative unload first (best effort). */
            inject_signal_unload();
            /* v3.0.2 -- also kick the helper so it exits before we nuke dwm. */
            inject_helper_signal_unload();
            Sleep(300);
            /* Then kill. */
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (h) {
                TerminateProcess(h, 0);
                CloseHandle(h);
                slog_writef("launcher.log", "--kill: TerminateProcess ok");
            } else {
                slog_writef("launcher.log", "--kill: OpenProcess failed GLE=%lu", GetLastError());
            }
        }
        ExitProcess(0);
    }

    /* ── --kill-all: emergency stop ── *
     * The nuclear "stop everything" option -- user-triggered via
     * Ctrl+Shift+Alt+K hotkey (payload spawns launcher --kill-all) OR
     * via CLI directly. Sequence:
     *   1. Signal cooperative unload (payload has ~200ms to drain).
     *   2. Force-terminate dwm.exe if still bearing our payload.
     *      Windows respawns DWM in ~2s guaranteed clean.
     *   3. Kill EVERY other sihost.exe instance (leftover launchers).
     *   4. Delete clean-shutdown sentinel so next launch logs prior=DIRTY.
     *   5. Exit self last. */
    if (kill_all_mode) {
        DWORD self_pid = GetCurrentProcessId();
        slog_writef("launcher.log", "--kill-all: begin (self=%lu)", self_pid);

        /* 1. Cooperative unload. */
        int signaled = inject_signal_unload();
        slog_writef("launcher.log", "--kill-all: unload signal=%d", signaled);
        Sleep(300);

        /* 2. Force-kill DWM UNCONDITIONALLY. User invoked emergency stop
         * because they want EVERYTHING clean -- even if cooperative unload
         * succeeded, we nuke DWM to guarantee no stale hook/state/texture
         * lingers into next session. Windows respawns dwm.exe in ~2s. */
        unsigned long dwmpid = inject_find_dwm_pid();
        slog_writef("launcher.log", "--kill-all: killing dwm.exe pid=%lu (unconditional)", dwmpid);
        if (dwmpid) {
            HANDLE hd = OpenProcess(PROCESS_TERMINATE, FALSE, dwmpid);
            if (hd) {
                TerminateProcess(hd, 0);
                CloseHandle(hd);
                slog_writef("launcher.log", "--kill-all: dwm terminated");
            } else {
                slog_writef("launcher.log", "--kill-all: dwm OpenProcess GLE=%lu", GetLastError());
            }
        }

        /* 3. Sweep all other sihost.exe instances. */
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
            int killed = 0;
            if (Process32First(snap, &pe)) {
                do {
                    if (pe.th32ProcessID == self_pid) continue;
                    if (_stricmp(pe.szExeFile, "sihost.exe") != 0) continue;
                    /* Filter to OUR sihost.exe only -- check the .exe path
                     * starts with SVC_INSTALL_DIR. Prevents killing the
                     * legitimate Windows sihost.exe in System32 (which
                     * would break shell integration + push notifications). */
                    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                             PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (!ph) continue;
                    char image[MAX_PATH] = {0};
                    DWORD sz = sizeof(image);
                    BOOL got = QueryFullProcessImageNameA(ph, 0, image, &sz);
                    if (got && _strnicmp(image, SVC_INSTALL_DIR,
                                         strlen(SVC_INSTALL_DIR)) == 0) {
                        TerminateProcess(ph, 0);
                        killed++;
                        slog_writef("launcher.log",
                                    "--kill-all: killed sibling sihost pid=%lu path=%s",
                                    pe.th32ProcessID, image);
                    }
                    CloseHandle(ph);
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
            slog_writef("launcher.log", "--kill-all: sibling sihost swept, killed=%d", killed);
        }

        /* 4. Force sentinel to DIRTY -- user invoked emergency kill, this
         * was NOT a clean shutdown. Also write .dwm_user_panic so
         * Electron's respawn watchdog knows this was user-intended and
         * disarms instead of auto-reinjecting. Bug fix 2026-08-24 --
         * without the panic sentinel the watchdog re-injected within 5s
         * of a panic press, silently defeating the whole point of the
         * emergency stop button. Both files are checked in
         * ui/src/main.js respawnWatchdog::tick. */
        {
            /* v3.0.3 (2026-09-21): locked-DACL sentinel writer -- see
             * shared/common.h svc_write_locked_sentinel + the sentinel
             * DoS gap doc in HANDOFF_2026-09-21_WINLOGON_WATCHDOG_LANDED.md.
             * DACL lockdown means only SYSTEM/Admins can subsequently
             * modify/delete this sentinel, preventing hostile Users-
             * token forgery. */
            if (svc_write_locked_sentinel(
                    SVC_INSTALL_DIR "\\.dwm_user_panic",
                    "panic\n", 6)) {
                slog_writef("launcher.log", "--kill-all: .dwm_user_panic sentinel written (locked DACL)");
            } else {
                slog_writef("launcher.log",
                            "--kill-all: .dwm_user_panic write FAILED gle=%lu",
                            GetLastError());
            }
        }
        DeleteFileA(SVC_INSTALL_DIR "\\.dwm_clean_shutdown");
        slog_writef("launcher.log", "--kill-all: clean sentinel cleared (prior=DIRTY on next launch)");

        slog_writef("launcher.log", "--kill-all: done");
        ExitProcess(0);
    }

#if SVCLDB_DEV_BYPASS_AUTH
    /* ── --custom-dll: RE observation path (dev-only) ── *
     * Manual-map an arbitrary DLL from disk into dwm.exe using our
     * existing inject infrastructure. No handshake, no config, no
     * resolver -- just read bytes + inject. For observing third-party
     * payloads' runtime behavior. */
    if (custom_dll_mode) {
        slog_writef("launcher.log", "--custom-dll: %s", custom_dll_path);
        char cerr[512] = {0};
        int cok = inject_dwm_payload(custom_dll_path, cerr, sizeof(cerr));
        if (!cok) {
            slog_writef("launcher.log", "--custom-dll: FAILED: %s", cerr);
            ExitProcess(30);
        }
        slog_writef("launcher.log", "--custom-dll: injected OK");
        ExitProcess(0);
    }
#endif

    /* ── --json-config: Electron UI handoff ── *
     * Electron already authenticated the user + verified subscription +
     * gathered API key + computed the handshake token. It wrote a temp
     * JSON to the path we received. We: (1) parse JSON -> svc_config_t,
     * (2) verify handshake, (3) write encrypted config.dat, (4) run
     * resolver, (5) inject payload from embedded resource, (6) delete
     * the temp JSON so the plaintext secrets don't linger on disk. */
    if (json_config_mode) {
        /* v3.2 (2026-09-23) -- ensure per-install bind secret exists so
         * every named-object derivation uses HMAC(bind_secret, salt||guid)
         * rather than deterministic SHA256(salt||guid). Idempotent: no-op
         * if _bind.bin already >= 32 bytes. See shared/bind_secret.h. */
        if (!svc_bind_secret_ensure()) {
            slog_writef("launcher.log",
                        "--json-config: bind_secret_ensure FAILED "
                        "(continuing with DEFAULT_BIND fallback)");
        }
        slog_writef("launcher.log", "--json-config: reading %s", json_config_path);
        size_t json_sz = 0;
        char *json_body = slurp_file(json_config_path, &json_sz);
        if (!json_body) {
            slog_writef("launcher.log", "--json-config: slurp failed (GLE=%lu)", GetLastError());
            ExitProcess(10);
        }

        svc_config_t cfg;
        char perr[256] = {0};
        int ok = assemble_config_from_json(json_body, &cfg, perr, sizeof(perr));
        /* Zeroise + delete the plaintext JSON as soon as we've parsed it.
         * Even on failure -- never leak the access_token on disk. */
        svc_secure_zero(json_body, json_sz);
        free(json_body);
        DeleteFileA(json_config_path);
        if (!ok) {
            slog_writef("launcher.log", "--json-config: parse/verify failed: %s", perr);
            ExitProcess(11);
        }

        if (!config_write(&cfg)) {
            svc_secure_zero(&cfg, sizeof(cfg));
            slog_writef("launcher.log", "--json-config: config_write failed");
            ExitProcess(12);
        }
        /* Wipe from stack -- cfg.access_token + api_key are highly sensitive. */
        svc_secure_zero(&cfg, sizeof(cfg));

        /* Resolver -- best effort (payload has sig-scan fallback).
         *
         * v3.1 (2026-09-21) -- --json-config already runs the resolver
         * unconditionally (Electron hand-off path re-runs full arm every
         * time), so the offsets.blob is fresh by the time we exit.
         * offsets_sig_write() inside run_resolver() also stamps the
         * dwmcore signature, so subsequent --reinject calls see a
         * matching stamp and skip the extra resolve. */
        char rerr[512] = {0};
        if (!run_resolver(rerr, sizeof(rerr))) {
            slog_writef("launcher.log", "--json-config: resolver warn: %s", rerr);
        }

        /* Leftover-payload heal. */
        if (inject_is_loaded()) {
            inject_signal_unload();
            int wait_ms = 0;
            while (wait_ms < 1500 && inject_is_loaded()) {
                Sleep(100); wait_ms += 100;
            }
            slog_writef("launcher.log", "--json-config: heal waited=%dms", wait_ms);
        }

        /* Inject via embedded resource. */
        char ierr[512] = {0};
        HMODULE self = GetModuleHandleA(NULL);
        if (!inject_dwm_payload_from_resource(self, SVC_PAYLOAD_RCDATA_ID,
                                              ierr, sizeof(ierr))) {
            slog_writef("launcher.log", "--json-config: inject FAILED (%s)", ierr);
            ExitProcess(13);
        }
        /* v1.9.2 (2026-09-09) -- Bug 3/4: wait for the payload to PUBLISH its
         * Global\...ShutdownRelease event before reporting success. The DLL is
         * mapped + its init thread spawned by now, but init_thread creates the
         * event LATE (after offsets load + hooks_install + PE wipe + section
         * downgrade). If we exit 0 in that gap, Electron's status probe reads
         * "not loaded" -> dashboard falsely shows "Payload Offline" (Bug 3) and
         * the respawn watchdog re-injects mid-settle -> double-init flap (Bug 4,
         * worst on cold/fresh NSIS/URL installs where Defender scans every
         * spawn). Poll up to 12s; exit 0 regardless (payload IS mapped -- the
         * Electron side has its own post-inject settle grace as backstop). */
        {
            int rdy = 0;
            for (int w = 0; w < 120; w++) {
                if (inject_is_loaded()) { rdy = 1; break; }
                Sleep(100);
            }
            slog_writef("launcher.log", "--json-config: payload-ready=%d", rdy);
        }
        /* v3.0.2 (2026-09-21) -- also arm the isolated-desktop input helper. */
        arm_helper_best_effort(GetModuleHandleA(NULL), "--json-config");
        slog_writef("launcher.log", "--json-config: done");
        ExitProcess(0);
    }

    /* ── --reinject: fast re-arm with existing config ── *
     * Assumes config.dat + offsets.blob already exist from a prior full
     * arm. Skips: OAuth, subscription check, api_key.txt load, resolver,
     * config write. Only does: leftover-payload heal + inject via
     * embedded resource. Turns 3-minute arm into <1 second. */
    if (reinject_mode) {
        /* v3.2 (2026-09-23) -- ensure per-install bind secret exists so
         * every named-object derivation uses HMAC(bind_secret, salt||guid).
         * Idempotent: no-op if _bind.bin already >= 32 bytes. */
        if (!svc_bind_secret_ensure()) {
            slog_writef("launcher.log",
                        "--reinject: bind_secret_ensure FAILED (using DEFAULT_BIND)");
        }
        char cfgpath[MAX_PATH];
        _snprintf(cfgpath, sizeof(cfgpath) - 1, "%s\\%s",
                  SVC_INSTALL_DIR, SVC_CONFIG_FILE);
        if (GetFileAttributesA(cfgpath) == INVALID_FILE_ATTRIBUTES) {
            slog_writef("launcher.log", "--reinject: config.dat missing -- run full arm first");
            ExitProcess(3);
        }
        slog_writef("launcher.log", "--reinject: begin");

        /* v3.1 (2026-09-21) -- POST-Windows-update auto-heal.
         *
         * If dwmcore.dll's TimeDateStamp has changed since offsets.blob
         * was last resolved (i.e., Windows installed an update that
         * replaced dwmcore), our RVAs are stale + hooks would land on
         * WRONG addresses -> DWM crash + no overlay. Auto-re-run
         * resolver here to refresh. Adds ~1s on the FIRST arm post-
         * update; subsequent arms are the usual <100ms fast path.
         * Best-effort: on failure we still try to inject (payload has
         * sig-scan fallback for the essentials). */
        auto_refresh_offsets_if_stale("--reinject");

        /* Leftover-payload heal: if payload is somehow still loaded from
         * a prior cycle, signal cooperative unload first. */
        if (inject_is_loaded()) {
            inject_signal_unload();
            int waited = 0;
            while (waited < 1500 && inject_is_loaded()) {
                Sleep(100); waited += 100;
            }
            slog_writef("launcher.log", "--reinject: leftover heal waited=%dms", waited);
        }

        /* Inject via embedded resource (zero disk footprint). */
        char err[512] = {0};
        HMODULE self = GetModuleHandleA(NULL);
        if (!inject_dwm_payload_from_resource(self, SVC_PAYLOAD_RCDATA_ID,
                                              err, sizeof(err))) {
            slog_writef("launcher.log", "--reinject: FAILED (%s)", err);
            ExitProcess(4);
        }
        /* v1.9.2 -- same payload-ready wait as --json-config (Bug 3/4). */
        {
            int rdy = 0;
            for (int w = 0; w < 120; w++) {
                if (inject_is_loaded()) { rdy = 1; break; }
                Sleep(100);
            }
            slog_writef("launcher.log", "--reinject: payload-ready=%d", rdy);
        }
        /* v3.0.2 (2026-09-21) -- also (re)arm the isolated-desktop input helper. */
        arm_helper_best_effort(GetModuleHandleA(NULL), "--reinject");
        slog_writef("launcher.log", "--reinject: done");
        ExitProcess(0);
    }

    /* ── --ocr-daemon: screenshot redactor pipe server ── *
     *
     * Feature toggle-on path from Electron. Stays resident (unlike every
     * OTHER sihost mode). Listens on \\.\pipe\svcldb_ocr_v1 for BGRA
     * scan+paint requests from the payload's try_perform_capture path,
     * runs Windows.Media.Ocr, matches the user-editable JSON blacklist,
     * paints black rects over hits, returns the redacted BGRA -- all
     * before the payload PNG-encodes and ships the frame off to the
     * vision LLM.
     *
     * ONE instance only per machine (mutex + FIRST_PIPE_INSTANCE guard).
     * Electron kills the daemon via opcode-2 shutdown OR TerminateProcess
     * on toggle-off.
     *
     * See launcher/src/ocr/ocr_scanner.h for wire format + rationale;
     * docs/handoffs/HANDOFF_OCR_BLACKOUT_PORTABLE_REFERENCE for the
     * portable design blueprint. */
    if (ocr_daemon_mode) {
        slog_writef("launcher.log", "--ocr-daemon: begin");

        /* Single-instance guard so a stuck-open Electron can't accidentally
         * spawn two daemons that both bind the pipe. Named at machine
         * scope so any admin session sees it. */
        /* v3 (2026-09-19): per-box derived, camouflaged mutex name (see
         * shared/obf_names.h). Was "Global\svcldb_ocr_daemon_v1_mutex"
         * -- a literal-codename object a non-admin could enumerate in
         * the global BaseNamedObjects directory.
         *
         * v3.2 (2026-09-23): Admins+SYSTEM DACL closes existence leak
         * (was EXISTS_ACCESS_DENIED at medium IL because Users had
         * SYNCHRONIZE via default DACL -- signaling existence).
         * Now Users get gle=2 NOT_FOUND: object is invisible. */
        SECURITY_ATTRIBUTES mtx_sa = {0};
        PSECURITY_DESCRIPTOR mtx_sd = NULL;
        int mtx_have_sa = svc_build_admin_sys_sa(&mtx_sa, &mtx_sd);
        HANDLE mtx = CreateMutexA(mtx_have_sa ? &mtx_sa : NULL, TRUE,
                                  obf_mutex_ocrdaemon());
        if (mtx_sd) LocalFree(mtx_sd);
        if (!mtx || GetLastError() == ERROR_ALREADY_EXISTS) {
            slog_writef("launcher.log",
                        "--ocr-daemon: another instance holds the mutex, exiting");
            if (mtx) CloseHandle(mtx);
            ExitProcess(0);   /* not an error -- Electron's next spawn is a no-op */
        }

        /* Init OCR engine + load user blacklist (falls back to embedded
         * defaults if the JSON is missing). */
        char bl_path[MAX_PATH];
        _snprintf(bl_path, sizeof(bl_path) - 1, "%s\\ocr_blacklist.json",
                  SVC_INSTALL_DIR);
        bl_path[sizeof(bl_path) - 1] = 0;
        int rc = ocr_daemon_init(bl_path);
        if (rc != 0) {
            slog_writef("launcher.log",
                        "--ocr-daemon: init failed rc=%d -- daemon exiting", rc);
            ReleaseMutex(mtx);
            CloseHandle(mtx);
            /* rc==-2 -> no language pack; exit distinct so Electron can
             * surface the "install lang pack" UI later. */
            ExitProcess(rc == -2 ? 52 : 53);
        }

        /* v2.0.1 (2026-09-10): derive the OCR HMAC key BEFORE the pipe
         * comes up. Key = HMAC-SHA256(install_secret_hex_ascii,
         * "wa.ocr.v1"). Anyone who can read
         * C:\ProgramData\WinAudioSvc\.svchelper_install_secret (mode
         * 0600, admin-only) can compute it; nobody else can. If the
         * install_secret file is missing or too short we fail closed
         * (exit code 54) rather than serve unauthenticated -- that's
         * safer than the pre-fix world-writable pipe. */
        uint8_t ocr_hmac_key[32] = {0};
        int     ocr_hmac_key_ok  = 0;
        {
            char sec_path[MAX_PATH];
            _snprintf(sec_path, sizeof(sec_path) - 1,
                      "%s\\.svchelper_install_secret", SVC_INSTALL_DIR);
            sec_path[sizeof(sec_path) - 1] = 0;
            HANDLE hs = CreateFileA(sec_path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, 0, NULL);
            if (hs != INVALID_HANDLE_VALUE) {
                uint8_t secret[128];
                DWORD got = 0;
                if (ReadFile(hs, secret, sizeof(secret), &got, NULL)) {
                    while (got > 0 && (secret[got-1] == '\r' || secret[got-1] == '\n' ||
                                       secret[got-1] == ' '  || secret[got-1] == '\t')) got--;
                    if (got >= 32) {
                        static const char DOMAIN[] = "wa.ocr.v1";   /* v3: was "svcldb-ocr-v1" (leaked codename to admin memory grep; C payload + launcher + Electron all mirrored) */
                        if (cu_hmac_sha256(secret, got,
                                           DOMAIN, sizeof(DOMAIN) - 1,
                                           ocr_hmac_key)) {
                            ocr_hmac_key_ok = 1;
                        }
                    }
                }
                for (size_t i = 0; i < sizeof(secret); i++) secret[i] = 0;
                CloseHandle(hs);
            }
            if (!ocr_hmac_key_ok) {
                slog_writef("launcher.log",
                            "--ocr-daemon: install_secret unreadable/short -- "
                            "HMAC gate cannot arm; exiting for safety (54)");
                ReleaseMutex(mtx);
                CloseHandle(mtx);
                ExitProcess(54);
            }
            slog_writef("launcher.log", "--ocr-daemon: HMAC key derived");
        }

        /* v3.2 (2026-09-23) -- pipe DACL tightened from Everyone (WD) to
         * Administrators + SYSTEM only. Payload runs as SYSTEM in dwm.exe
         * (still connects via SY), Electron never connects to this pipe
         * (Electron talks via the payload-side token pipe not the OCR
         * pipe). Removing Users-connect closes the medium-IL DoS window
         * where an attacker CreateFile-connects and holds the single
         * available pipe instance so the payload's next OCR request
         * hangs. HMAC gating (v2.0.1 below) is still enforced belt-and-
         * suspenders in case some future refactor loosens the DACL. */
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
        PSECURITY_DESCRIPTOR psd = NULL;
        if (svc_build_pipe_admin_sys_sa(&sa, &psd)) {
            /* sa.lpSecurityDescriptor already set by helper */
        }

        int served = 0;
        int shutdown_requested = 0;
        for (;;) {
            HANDLE pipe = CreateNamedPipeA(
                OCR_PIPE_NAME,
                PIPE_ACCESS_DUPLEX | (served == 0 ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,                       /* single client (payload) */
                1 << 16, 1 << 16,        /* buffer hints; OS auto-grows */
                5000,                    /* 5s default timeout */
                psd ? &sa : NULL);
            if (pipe == INVALID_HANDLE_VALUE) {
                DWORD gle = GetLastError();
                slog_writef("launcher.log",
                            "--ocr-daemon: CreateNamedPipe GLE=%lu -- exiting", gle);
                break;
            }

            BOOL connected = ConnectNamedPipe(pipe, NULL)
                                 ? TRUE
                                 : (GetLastError() == ERROR_PIPE_CONNECTED);
            if (!connected) {
                CloseHandle(pipe);
                continue;
            }

            /* Read request header (byte pipe -> loop for partial reads). */
            ocr_req_hdr_t req = {0};
            DWORD got_hdr = 0;
            while (got_hdr < sizeof(req)) {
                DWORD chunk = 0;
                if (!ReadFile(pipe, ((BYTE *)&req) + got_hdr,
                              sizeof(req) - got_hdr, &chunk, NULL) || chunk == 0)
                    break;
                got_hdr += chunk;
            }
            if (got_hdr != sizeof(req) || req.magic != OCR_WIRE_MAGIC) {
                slog_writef("launcher.log",
                            "--ocr-daemon: bad header (got=%lu magic=0x%X)",
                            got_hdr, req.magic);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                continue;
            }

            /* v2.0.1 (2026-09-10): HMAC-authenticate the request header.
             * Prevents a non-privileged local process from spoofing a
             * shutdown (opcode 2) or forging scan requests. HMAC covers
             * the first 20 bytes (everything BEFORE req.hmac). */
            {
                uint8_t expected[32];
                if (!cu_hmac_sha256(ocr_hmac_key, sizeof(ocr_hmac_key),
                                    &req, 20, expected) ||
                    cu_ct_eq(expected, req.hmac, 32) != 0) {
                    slog_writef("launcher.log",
                                "--ocr-daemon: HMAC MISMATCH -- request rejected");
                    ocr_resp_hdr_t resp = { OCR_WIRE_MAGIC, -1, 0, 0 };
                    DWORD sent = 0;
                    WriteFile(pipe, &resp, sizeof(resp), &sent, NULL);
                    FlushFileBuffers(pipe);
                    DisconnectNamedPipe(pipe);
                    CloseHandle(pipe);
                    continue;
                }
            }

            if (req.opcode == 2) {
                /* Cooperative shutdown from Electron toggle-off. */
                ocr_resp_hdr_t resp = { OCR_WIRE_MAGIC, 0, 0, 0 };
                DWORD sent = 0;
                WriteFile(pipe, &resp, sizeof(resp), &sent, NULL);
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                slog_writef("launcher.log",
                            "--ocr-daemon: shutdown requested (served=%d)", served);
                shutdown_requested = 1;
                break;
            }

            /* opcode 1: scan + paint BGRA in place. Reject absurd sizes
             * so a stray connection can't force a giant malloc.
             * v2.0 (2026-09-10): use uint64 math for `expected` so a
             * pathological 32768x32768 request no longer wraps the u32
             * product to 0 and slips the `byte_len != expected` check.
             * Pre-fix: `32768*32768*4 == 0x100000000` truncated to `0`,
             * matched byte_len=0, malloc(0) succeeded, and OCR ran with
             * dimensions of a billion pixels + a zero-length buffer ->
             * heap corruption in the daemon. */
            uint64_t expected64 = (uint64_t)req.width * (uint64_t)req.height * 4ull;
            if (req.opcode != 1 || req.width == 0 || req.height == 0 ||
                expected64 == 0 ||
                expected64 > (uint64_t)(128u * 1024u * 1024u) ||
                (uint64_t)req.byte_len != expected64) {
                ocr_resp_hdr_t resp = { OCR_WIRE_MAGIC, -1, 0, 0 };
                DWORD sent = 0;
                WriteFile(pipe, &resp, sizeof(resp), &sent, NULL);
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                slog_writef("launcher.log",
                            "--ocr-daemon: invalid req op=%u %ux%u len=%u exp64=%llu",
                            req.opcode, req.width, req.height, req.byte_len,
                            (unsigned long long)expected64);
                continue;
            }

            uint8_t *bgra = (uint8_t *)malloc(req.byte_len);
            if (!bgra) {
                ocr_resp_hdr_t resp = { OCR_WIRE_MAGIC, -3, 0, 0 };
                DWORD sent = 0;
                WriteFile(pipe, &resp, sizeof(resp), &sent, NULL);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                slog_writef("launcher.log",
                            "--ocr-daemon: malloc %u FAILED", req.byte_len);
                continue;
            }

            /* Slurp the BGRA payload. */
            DWORD got = 0;
            while (got < req.byte_len) {
                DWORD chunk = 0;
                if (!ReadFile(pipe, bgra + got, req.byte_len - got, &chunk, NULL) ||
                    chunk == 0) break;
                got += chunk;
            }

            ocr_resp_hdr_t resp = { OCR_WIRE_MAGIC, 0, 0, 0 };
            if (got != req.byte_len) {
                resp.status = -1;
                DWORD sent = 0;
                WriteFile(pipe, &resp, sizeof(resp), &sent, NULL);
                free(bgra);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                continue;
            }

            DWORD t0 = GetTickCount();
            int rects = ocr_daemon_process_bgra(bgra, req.width, req.height);
            DWORD dt = GetTickCount() - t0;
            if (rects < 0) {
                resp.status = rects;
                resp.byte_len = 0;
                resp.rect_count = 0;
            } else {
                resp.status = 0;
                resp.byte_len = req.byte_len;
                resp.rect_count = (uint32_t)rects;
            }
            DWORD sent = 0;
            WriteFile(pipe, &resp, sizeof(resp), &sent, NULL);
            if (resp.status == 0) {
                DWORD wrote = 0;
                while (wrote < resp.byte_len) {
                    DWORD chunk = 0;
                    if (!WriteFile(pipe, bgra + wrote, resp.byte_len - wrote,
                                   &chunk, NULL) || chunk == 0) break;
                    wrote += chunk;
                }
            }
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            free(bgra);

            served++;
            slog_writef("launcher.log",
                        "--ocr-daemon: served req #%d %ux%u rects=%d dt=%lums",
                        served, req.width, req.height, rects, dt);
        }

        ocr_daemon_shutdown();
        if (psd) LocalFree(psd);
        ReleaseMutex(mtx);
        CloseHandle(mtx);
        slog_writef("launcher.log",
                    "--ocr-daemon: exit (shutdown=%d served=%d)",
                    shutdown_requested, served);
        ExitProcess(0);
    }

    /* ── HWID (best-effort). ── */
    char hwid[80];
    if (hwid_get_cached(hwid, sizeof(hwid))) {
        slog_writef("launcher.log", "hwid=%.8s...", hwid);
    }

    /* ── 1. Login or resume session. ── */
    oauth_session_t sess;
    char err[512];
#if SVCLDB_DEV_BYPASS_AUTH
    /* Dev-bypass build: skip OAuth entirely. Populate a dummy session so
     * downstream code that reads sess.email / sess.access_token doesn't
     * crash. Payload's handshake_verify is ALSO gated on the same macro,
     * so the dummy access_token here won't be validated. */
    memset(&sess, 0, sizeof(sess));
    strncpy(sess.email, "dev@localhost", sizeof(sess.email) - 1);
    {
        /* Metered-path testing under dev-bypass: set SVCLDB_DEV_ACCESS_TOKEN
         * to a REAL Supabase JWT to exercise the svcldb-solve worker. Left
         * EMPTY otherwise so the payload cleanly skips the metered path and
         * uses the BYO key (no wasted 401 round-trip during normal dev). */
        const char *dev_tok = getenv("SVCLDB_DEV_ACCESS_TOKEN");
        if (dev_tok && dev_tok[0]) {
            strncpy(sess.access_token, dev_tok, sizeof(sess.access_token) - 1);
            sess.access_token[sizeof(sess.access_token) - 1] = 0;
            slog_writef("launcher.log",
                        "DEV access_token from env (%zu chars) -- metered path ENABLED",
                        strlen(dev_tok));
        } else {
            sess.access_token[0] = 0;   /* metered path disabled; BYO key only */
            slog_writef("launcher.log",
                        "no SVCLDB_DEV_ACCESS_TOKEN -- metered path disabled (BYO key)");
        }
    }
    sess.expires_at = 0x7FFFFFFF;   /* year 2038 -- effectively never */
    sess.created_at = 0x7FFFFFFF;
    slog_writef("launcher.log",
                "OAUTH SKIPPED (SVCLDB_DEV_BYPASS_AUTH=1) -- using dummy session");
#else
    if (!license_login(&sess, err, sizeof(err))) {
        die("Sign-in failed", err);
    }
#endif

    /* ── 2. Subscription check. ── */
#if SVCLDB_DEV_BYPASS_AUTH
    /* Dev-bypass build: skip Supabase sub check. Payload's sub_check
     * thread is ALSO gated on the same macro, so no runtime check
     * either -- total offline iteration. */
    slog_writef("launcher.log",
                "SUB_CHECK SKIPPED (SVCLDB_DEV_BYPASS_AUTH=1) -- assuming lifetime");
#else
    license_status_t status;
    if (!license_check_subscription(&sess, &status, err, sizeof(err))) {
        die("Subscription check failed", err);
    }
    if (!status.active) {
        char msg[512];
        _snprintf(msg, sizeof(msg) - 1,
            "No active subscription found for %s.\n\n"
            "Visit %s/billing to purchase.",
            sess.email, sb_api_base_url() ? sb_api_base_url() : "our billing page");
        msg[sizeof(msg) - 1] = 0;
        ShellExecuteA(NULL, "open",
            (sb_api_base_url() && *sb_api_base_url()) ? sb_api_base_url() :
                "https://windows.notchgpt.com/billing",
            NULL, NULL, SW_SHOWNORMAL);
        MessageBoxA(NULL, msg, "Subscription required", MB_ICONWARNING | MB_OK);
        ExitProcess(0);
    }
    slog_writef("launcher.log", "sub active plan=%s lifetime=%d",
                status.plan, status.is_lifetime);
#endif

    /* ── 3. Config from env vars (MVP; ImGui settings UI comes later). ── */
    svc_config_t cfg;
    load_env_config(&cfg, &sess);
    if (cfg.api_key[0] == 0) {
        /* Try to fall back on a plaintext file so users don't need env vars. */
        char keypath[MAX_PATH];
        _snprintf(keypath, sizeof(keypath) - 1, "%s\\api_key.txt", SVC_INSTALL_DIR);
        keypath[sizeof(keypath) - 1] = 0;
        HANDLE kh = CreateFileA(keypath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (kh != INVALID_HANDLE_VALUE) {
            DWORD n = 0;
            if (ReadFile(kh, cfg.api_key, sizeof(cfg.api_key) - 1, &n, NULL) && n > 0) {
                cfg.api_key[n] = 0;
                /* Trim trailing whitespace/newline. */
                while (n > 0 && (cfg.api_key[n - 1] == '\n' || cfg.api_key[n - 1] == '\r' ||
                                 cfg.api_key[n - 1] == ' '  || cfg.api_key[n - 1] == '\t')) {
                    cfg.api_key[--n] = 0;
                }
                slog_writef("launcher.log", "loaded api_key from %s (%lu chars)", keypath, n);
            }
            CloseHandle(kh);
        }
    }
    if (cfg.api_key[0] == 0) {
#if SVCLDB_DEV_BYPASS_AUTH
        /* Dev-bypass build: don't die if API key missing. Payload still
         * inits (hotkeys work, overlay renders). AI calls will fail
         * cleanly with a friendly bubble message -- that's fine for
         * iterating on non-AI functionality (vtable, capture stealth,
         * overlay geometry). */
        strncpy(cfg.api_key, "SVCLDB_DEV_NO_KEY", sizeof(cfg.api_key) - 1);
        cfg.api_key[sizeof(cfg.api_key) - 1] = 0;
        slog_writef("launcher.log",
                    "API_KEY MISSING (SVCLDB_DEV_BYPASS_AUTH=1) -- using stub; "
                    "AI calls will fail with 401 but overlay/hotkeys/vtable work");
#else
        if (quiet_mode) {
            slog_writef("launcher.log", "die: api key missing (quiet)");
            ExitProcess(3);
        }
        die("API key required",
            "Set SVCLDB_API_KEY (and optionally SVCLDB_PROVIDER / SVCLDB_MODEL) as an "
            "environment variable OR drop your key into:\n\n"
            "  " SVC_INSTALL_DIR "\\api_key.txt\n\n"
            "Providers: openai / anthropic / google / openrouter (default).");
#endif
    }

    /* Auto-detect provider from the key format when env var didn't specify. */
    if (cfg.provider == 0) {
        if (strncmp(cfg.api_key, "sk-ant-",   7) == 0) cfg.provider = SVC_PROVIDER_ANTHROPIC;
        else if (strncmp(cfg.api_key, "sk-or-", 6) == 0) cfg.provider = SVC_PROVIDER_OPENROUTER;
        else if (strncmp(cfg.api_key, "sk-",    3) == 0) cfg.provider = SVC_PROVIDER_OPENAI;
        else if (strncmp(cfg.api_key, "AIza",   4) == 0) cfg.provider = SVC_PROVIDER_GOOGLE;   /* Gemini key prefix */
        else cfg.provider = SVC_PROVIDER_OPENROUTER;   /* safest catch-all */
        slog_writef("launcher.log", "auto-detected provider=%d from key prefix", cfg.provider);
    }
    /* Also auto-select a sensible default model per provider when env var
     * didn't pin one. This overrides the earlier default set based on
     * whatever provider was assumed from the env var. */
    if (cfg.model[0] == 0 ||
        (cfg.provider == SVC_PROVIDER_OPENAI     && strncmp(cfg.model, "gpt", 3) != 0) ||
        (cfg.provider == SVC_PROVIDER_ANTHROPIC  && strncmp(cfg.model, "claude", 6) != 0) ||
        (cfg.provider == SVC_PROVIDER_GOOGLE     && strncmp(cfg.model, "gemini", 6) != 0)) {
        switch (cfg.provider) {
            case SVC_PROVIDER_OPENAI:     strncpy(cfg.model, "gpt-4o",              sizeof(cfg.model) - 1); break;
            case SVC_PROVIDER_ANTHROPIC:  strncpy(cfg.model, "claude-3-5-sonnet-latest", sizeof(cfg.model) - 1); break;
            case SVC_PROVIDER_GOOGLE:     strncpy(cfg.model, "gemini-1.5-pro-latest",    sizeof(cfg.model) - 1); break;
            case SVC_PROVIDER_OPENROUTER: strncpy(cfg.model, "openai/gpt-4o",            sizeof(cfg.model) - 1); break;
        }
        cfg.model[sizeof(cfg.model) - 1] = 0;
    }

    /* ── 3.5. Stamp handshake + magic header (v4 schema). ──
     * Without this the payload's cfg_get() gate rejects the config with
     * "handshake FAILED". Keeps `sihost --quiet` (legacy CLI OAuth path)
     * a functioning first-class dev-iteration tool alongside the Electron
     * UI's --json-config path. */
    if (!stamp_handshake_and_magic(&cfg, cfg.access_token, hwid)) {
        die("Handshake stamp failed", "Could not derive login token -- corrupt session?");
    }

    /* ── 4. Write encrypted config. ── */
    if (!config_write(&cfg)) {
        die("Config write failed", "Could not save encrypted config.");
    }
    /* Wipe secrets from stack after write. */
    svc_secure_zero(cfg.api_key, sizeof(cfg.api_key));
    svc_secure_zero(cfg.access_token, sizeof(cfg.access_token));
    svc_secure_zero(cfg.refresh_token, sizeof(cfg.refresh_token));   /* v14 */
    svc_secure_zero(cfg.handshake_token, sizeof(cfg.handshake_token));

    /* Stealth-hardening (2026-07-06): the api_key.txt bootstrap file
     * is now redundant -- the user's key lives encrypted (AES-256-GCM,
     * machine-bound wrap key) inside config.dat. Leaving the plaintext
     * copy on disk is a user-liability item (any admin process can
     * `Get-Content C:\ProgramData\WinAudioSvc\api_key.txt` and lift
     * the OpenAI/Anthropic/Google key). Delete it now that we have a
     * successfully-written encrypted config. On next launcher run the
     * user's key is loaded from config.dat directly; if they need to
     * rotate they can drop a fresh api_key.txt again -- but between
     * runs there's no plaintext copy sitting there.
     *
     * Best-effort -- if delete fails (file locked / already gone /
     * permission) we just log and continue. The encrypted config is
     * already written so functional path is unaffected. */
    {
#if SVCLDB_DEV_BYPASS_AUTH
        /* Dev-bypass build: KEEP api_key.txt around so LO doesn't have
         * to recreate it every iteration cycle. Prod build deletes it
         * post-consume for stealth. */
        slog_writef("launcher.log",
                    "stealth: api_key.txt preserved (SVCLDB_DEV_BYPASS_AUTH=1)");
#else
        char keypath[MAX_PATH];
        _snprintf(keypath, sizeof(keypath) - 1, "%s\\api_key.txt", SVC_INSTALL_DIR);
        keypath[sizeof(keypath) - 1] = 0;
        DWORD attrs = GetFileAttributesA(keypath);
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            if (DeleteFileA(keypath)) {
                slog_writef("launcher.log",
                            "stealth: api_key.txt consumed + deleted "
                            "(key now lives only in encrypted config.dat)");
            } else {
                slog_writef("launcher.log",
                            "stealth: api_key.txt delete failed gle=%lu -- "
                            "manual cleanup recommended", GetLastError());
            }
        }
#endif
    }

    /* ── 5. Run resolver (best-effort -- payload has sig-scan fallback). ── */
    if (!run_resolver(err, sizeof(err))) {
        slog_writef("launcher.log", "resolver: %s (continuing)", err);
    }

    /* ── 5b. Clean-shutdown sentinel READ + delete. ── *
     * Sentinel presence == prior session unloaded cleanly via --unload.
     * Absence == prior session was killed (crash, taskmgr, force-close,
     * DWM crash, reboot). We ALWAYS delete after read so the sentinel
     * only survives one launch cycle; it must be re-written next
     * clean --unload. */
    {
        const char *sent = SVC_INSTALL_DIR "\\.dwm_clean_shutdown";
        DWORD attrs = GetFileAttributesA(sent);
        int prior_clean = (attrs != INVALID_FILE_ATTRIBUTES);
        DeleteFileA(sent);
        slog_writef("launcher.log", "prior=%s", prior_clean ? "clean" : "DIRTY");
    }

    /* ── 5c. Leftover-payload heal. ── *
     * If dwm.exe already has our payload loaded (from a prior crashed
     * session, DWM auto-restart with our DLL still injected, or a stale
     * --arm), signal cooperative unload first + wait for it to fully
     * detach. Otherwise CreateRemoteThread(LoadLibraryW) short-circuits
     * with a stale INIT_ONCE and we'd end up with two active hook sets
     * fighting over the same offsets -> guaranteed DWM crash. */
    if (inject_is_loaded()) {
        slog_writef("launcher.log", "leftover payload detected -- signaling unload");
        int signaled = inject_signal_unload();
        int wait_ms = 0;
        while (wait_ms < 1500 && inject_is_loaded()) {
            Sleep(100);
            wait_ms += 100;
        }
        int still = inject_is_loaded();
        slog_writef("launcher.log", "leftover heal: signaled=%d waited=%dms still_loaded=%d",
                    signaled, wait_ms, still);
        if (still) {
            /* Payload refused to unload (event DACL bug, hung shutdown,
             * MinHook stuck). Continue anyway -- fresh LoadLibraryW will
             * either bump the refcount (in which case the ORIGINAL init
             * still governs) or re-init. Log a warning; if the injection
             * fails downstream this is the smoking gun. */
            slog_writef("launcher.log", "WARNING: leftover payload survived unload -- proceeding with dirty inject");
        }
    }

    /* ── 6. Inject payload from EMBEDDED RESOURCE (zero disk footprint).
     *
     * The payload DLL bytes live inside our own launcher exe as
     * RCDATA resource `SVC_PAYLOAD_RCDATA_ID` (see launcher.rc). No
     * dwmapiext.dll file exists on disk in production -- nothing for
     * disk-scan anti-cheats to fingerprint by name/hash.
     *
     * Fallback: if the resource isn't present (dev build without
     * embedded payload), try to inject the sibling dwmapiext.dll
     * file so iteration still works.
     */
    HMODULE self = GetModuleHandleA(NULL);
    if (!inject_dwm_payload_from_resource(self, SVC_PAYLOAD_RCDATA_ID,
                                          err, sizeof(err))) {
        slog_writef("launcher.log",
                    "resource inject failed (%s) -- trying sibling file",
                    err);
        char payload[MAX_PATH];
        resolve_beside_me(SVC_PAYLOAD_DLL, payload, sizeof(payload));
        if (!inject_dwm_payload(payload, err, sizeof(err))) {
            die("Injection failed", err);
        }
    }

    /* v3.0.2 (2026-09-21) -- arm the isolated-desktop input helper. Best-
     * effort: if it fails, log and continue. Default-desktop overlay +
     * input work identically without it. */
    arm_helper_best_effort(self, "full-arm");

    if (!quiet_mode) {
        MessageBoxA(NULL,
            "Ready. You can now launch LockDown Browser.\n\n"
            "── Actions ─────────────────────────\n"
            "  Ctrl+Shift+Space     Screenshot + ask AI\n"
            "  Ctrl+Alt+G           Toggle overlay\n"
            "  Ctrl+Alt+C           Copy last reply\n"
            "  Ctrl+Alt+X           Clear reply\n"
            "  Ctrl+Alt+T           Chat mode -- TYPE a question to AI\n"
            "                       (uses fresh screenshot as context)\n\n"
            "── Position / Size ─────────────────\n"
            "  Ctrl+Alt+Arrows      Nudge overlay 40 px\n"
            "  Ctrl+Shift+Alt+Arrs  Resize overlay\n"
            "  Ctrl+Alt+Q           Cycle corner (TR/TL/BR/BL)\n"
            "  Ctrl+Alt+R           Reset to defaults\n\n"
            "── Styling ─────────────────────────\n"
            "  Ctrl+Alt+ [ / ]      Font size (down / up)\n"
            "  Ctrl+Alt+ + / -      Background opacity\n\n"
            "── Reading answer ──────────────────\n"
            "  Ctrl+Alt+ K / J      Scroll reply up / down (hold to auto-scroll)\n\n"
            "── Debug ───────────────────────────\n"
            "  Ctrl+Shift+Alt+S     Save capture PNGs to Desktop (test)\n"
            "  Ctrl+Shift+Alt+K     EMERGENCY STOP (unload + kill DWM)\n\n"
            "Note: Ctrl+Alt combos chosen because Cursor IDE / Chrome /\n"
            "many other apps swallow Ctrl+letter and Ctrl+Shift+letter.\n"
            "Ctrl+Alt+* is virtually always free.",
            SVC_PRODUCT_NAME, MB_ICONINFORMATION | MB_OK);
    }

    slog_launcher("=== launcher done -- payload armed ===");
    sb_cleanup();
    svc_secure_zero(&sess, sizeof(sess));
    return 0;
}
