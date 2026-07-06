/* ================================================================== *
 * main.c — Launcher entry point.                                     *
 *                                                                    *
 * Flow:                                                              *
 *   1. Elevation check + SeDebugPrivilege                            *
 *   2. OAuth login (or reload valid session)                         *
 *   3. Subscription check                                            *
 *   4. Settings UI (config editor — placeholder for MVP)             *
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
#include "config_write.h"
#include "inject.h"
#include "license.h"
#include "oauth.h"

#include <shellapi.h>
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

static void die(const char *title, const char *msg) {
    MessageBoxA(NULL, msg, title, MB_ICONERROR | MB_OK);
    slog_writef("launcher.log", "die: %s: %s", title, msg);
    ExitProcess(1);
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
                    "handshake stamp: skipped — missing access_token or hwid "
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

    /* v5 per-provider keys — populated by Electron from the 4-input
     * settings card. At least ONE must be non-empty; the legacy
     * cfg->api_key (single-key backward compat) is optional. */
    json_get_str(json, "api_key_openai",     cfg->api_key_openai,     sizeof(cfg->api_key_openai));
    json_get_str(json, "api_key_anthropic",  cfg->api_key_anthropic,  sizeof(cfg->api_key_anthropic));
    json_get_str(json, "api_key_google",     cfg->api_key_google,     sizeof(cfg->api_key_google));
    json_get_str(json, "api_key_openrouter", cfg->api_key_openrouter, sizeof(cfg->api_key_openrouter));
    /* Legacy shared field — if UI sends it, prefer it. Otherwise fall
     * through to per-provider keys inside ai_provider.c. */
    json_get_str(json, "api_key", cfg->api_key, sizeof(cfg->api_key));

    if (!cfg->api_key[0] && !cfg->api_key_openai[0] && !cfg->api_key_anthropic[0]
        && !cfg->api_key_google[0] && !cfg->api_key_openrouter[0]) {
        _snprintf(err, err_sz - 1, "no api key for any provider");
        return 0;
    }
    if (json_get_num(json, "provider", &n)) cfg->provider = (int)n;
    if (json_get_num(json, "tier",     &n)) cfg->tier     = (int)n;
    json_get_str(json, "model", cfg->model, sizeof(cfg->model));
    if (json_get_num(json, "reasoning_effort",  &n)) cfg->reasoning_effort  = (int)n;
    if (json_get_num(json, "streaming_enabled", &n)) cfg->streaming_enabled = (int)n;
    if (json_get_num(json, "latex_disabled",    &n)) cfg->latex_disabled    = (int)n;

    /* system_prompt: allow empty (payload falls back to built-in). */
    json_get_str(json, "system_prompt", cfg->system_prompt, sizeof(cfg->system_prompt));

    /* overlay geometry (all optional — sensible defaults for missing fields) */
    if (json_get_num(json, "overlay_x",     &n)) cfg->overlay_x = (int)n; else cfg->overlay_x = 40;
    if (json_get_num(json, "overlay_y",     &n)) cfg->overlay_y = (int)n; else cfg->overlay_y = 40;
    if (json_get_num(json, "overlay_w",     &n)) cfg->overlay_w = (int)n; else cfg->overlay_w = 560;
    if (json_get_num(json, "overlay_h",     &n)) cfg->overlay_h = (int)n; else cfg->overlay_h = 420;
    if (json_get_num(json, "overlay_alpha", &n)) cfg->overlay_alpha = (float)n; else cfg->overlay_alpha = 0.94f;

    /* Hotkeys: CSV of packed uints. Missing / short → zeroed slots. */
    char csv[2048] = {0};
    if (json_get_str(json, "hotkeys_packed_csv", csv, sizeof(csv))) {
        char *tok = csv;
        for (int i = 0; i < 32 && *tok; i++) {
            char *comma = strchr(tok, ',');
            if (comma) *comma = 0;
            cfg->hotkeys[i] = (unsigned)strtoul(tok, NULL, 10);
            if (!comma) break;
            tok = comma + 1;
        }
    }

    /* Header + handshake sanity — MUST verify against the token we
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
 * Replaced by native ImGui settings in v2 — for now, use environment
 * variables + default config so we can prove the pipeline works.
 * User exports SVCLDB_API_KEY + SVCLDB_PROVIDER before running.
 */
static void load_env_config(svc_config_t *cfg, const oauth_session_t *sess) {
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->access_token, sess->access_token, sizeof(cfg->access_token) - 1);
    cfg->token_expires_at = sess->expires_at;

    /* Provider select — env var wins if set. */
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
     * payload/src/ai/ai_provider.c — ~10 KB of subject-matter rules
     * ported from hooksdll/lumio/src/autosolver.js (math/physics/chem/
     * bio/eng/CS/nursing/humanities/business + verify loop + common
     * pitfalls + response humanization).
     *
     * Power users can drop their own prompt into config.dat post-arm
     * if they want to override. */
    cfg->system_prompt[0] = 0;

    /* Hotkey defaults — chosen to survive LL-hook interception by other apps.
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
    cfg->hotkeys[SVC_HK_ASK]           = SVC_HK_PACK(MOD_CS, ' ');   /* Ctrl+Shift+Space (works)      */
    cfg->hotkeys[SVC_HK_TOGGLE]        = SVC_HK_PACK(MOD_CA, 'G');   /* Ctrl+Alt+G                    */
    cfg->hotkeys[SVC_HK_TYPING]        = SVC_HK_PACK(MOD_CA, 'T');   /* Ctrl+Alt+T                    */
    cfg->hotkeys[SVC_HK_COPY_REPLY]    = SVC_HK_PACK(MOD_CA, 'C');   /* Ctrl+Alt+C                    */
    cfg->hotkeys[SVC_HK_CLEAR]         = SVC_HK_PACK(MOD_CA, 'X');   /* Ctrl+Alt+X                    */
    cfg->hotkeys[SVC_HK_MOVE_LEFT]     = SVC_HK_PACK(MOD_CA, 0x25);  /* Ctrl+Alt+Left                 */
    cfg->hotkeys[SVC_HK_MOVE_RIGHT]    = SVC_HK_PACK(MOD_CA, 0x27);  /* Ctrl+Alt+Right                */
    cfg->hotkeys[SVC_HK_MOVE_UP]       = SVC_HK_PACK(MOD_CA, 0x26);  /* Ctrl+Alt+Up                   */
    cfg->hotkeys[SVC_HK_MOVE_DOWN]     = SVC_HK_PACK(MOD_CA, 0x28);  /* Ctrl+Alt+Down                 */
    cfg->hotkeys[SVC_HK_RESIZE_WIDER]  = SVC_HK_PACK(MOD_CSA, 0x27); /* Ctrl+Shift+Alt+Right          */
    cfg->hotkeys[SVC_HK_RESIZE_NARROW] = SVC_HK_PACK(MOD_CSA, 0x25); /* Ctrl+Shift+Alt+Left           */
    cfg->hotkeys[SVC_HK_RESIZE_TALLER] = SVC_HK_PACK(MOD_CSA, 0x28); /* Ctrl+Shift+Alt+Down           */
    cfg->hotkeys[SVC_HK_RESIZE_SHORT]  = SVC_HK_PACK(MOD_CSA, 0x26); /* Ctrl+Shift+Alt+Up             */
    cfg->hotkeys[SVC_HK_CYCLE_CORNER]  = SVC_HK_PACK(MOD_CA, 'Q');   /* Ctrl+Alt+Q (Q for "quadrant") */
    cfg->hotkeys[SVC_HK_ALPHA_UP]      = SVC_HK_PACK(MOD_CA, 0xBB);  /* Ctrl+Alt++                    */
    cfg->hotkeys[SVC_HK_ALPHA_DOWN]    = SVC_HK_PACK(MOD_CA, 0xBD);  /* Ctrl+Alt+-                    */
    cfg->hotkeys[SVC_HK_FONT_UP]       = SVC_HK_PACK(MOD_CA, 0xDD);  /* Ctrl+Alt+] (bracket right) — laptop-friendly (no PgUp needed) */
    cfg->hotkeys[SVC_HK_FONT_DOWN]     = SVC_HK_PACK(MOD_CA, 0xDB);  /* Ctrl+Alt+[ (bracket left)                     */
    cfg->hotkeys[SVC_HK_RESET]         = SVC_HK_PACK(MOD_CA, 'R');   /* Ctrl+Alt+R                    */
    cfg->hotkeys[SVC_HK_DEBUG_CAP]     = SVC_HK_PACK(MOD_CSA, 'S');  /* Ctrl+Shift+Alt+S — debug capture-to-Desktop */
    cfg->hotkeys[SVC_HK_KILL_ALL]      = SVC_HK_PACK(MOD_CSA, 'K');  /* Ctrl+Shift+Alt+K — emergency stop (unload+kill DWM+kill launcher) */
    cfg->hotkeys[SVC_HK_SCROLL_UP]     = SVC_HK_PACK(MOD_CA, 'K');   /* Ctrl+Alt+K — scroll reply UP (vi convention)   */
    cfg->hotkeys[SVC_HK_SCROLL_DOWN]   = SVC_HK_PACK(MOD_CA, 'J');   /* Ctrl+Alt+J — scroll reply DOWN                 */
    /* Chat / config controls (v3 additions 2026-07-05). */
    cfg->hotkeys[SVC_HK_NEW_CHAT]      = SVC_HK_PACK(MOD_CA, 'N');   /* Ctrl+Alt+N — new chat (wipe all messages)      */
    cfg->hotkeys[SVC_HK_CYCLE_TIER]    = SVC_HK_PACK(MOD_CA, 'M');   /* Ctrl+Alt+M — cycle STRONG/MED/CHEAP            */
    cfg->hotkeys[SVC_HK_CYCLE_PROVIDER]= SVC_HK_PACK(MOD_CSA, 'P');  /* Ctrl+Shift+Alt+P — cycle provider              */
    cfg->hotkeys[SVC_HK_REGENERATE]    = SVC_HK_PACK(MOD_CA, 0x0D);  /* Ctrl+Alt+Enter — regenerate last turn          */
    cfg->hotkeys[SVC_HK_STREAM_TOGGLE] = SVC_HK_PACK(MOD_CSA, 'T');  /* Ctrl+Shift+Alt+T — toggle SSE streaming        */
    /* v3.1 additions. */
    cfg->hotkeys[SVC_HK_COPY_CODE]     = SVC_HK_PACK(MOD_CSA, 'C');  /* Ctrl+Shift+Alt+C — copy JUST fenced code blocks */
    cfg->hotkeys[SVC_HK_COPY_ANSWER]   = SVC_HK_PACK(MOD_CA,  'A');  /* Ctrl+Alt+A — copy JUST first-line answer        */
    cfg->hotkeys[SVC_HK_LATEX_TOGGLE]  = SVC_HK_PACK(MOD_CSA, 'L');  /* Ctrl+Shift+Alt+L — LaTeX <-> Unicode/keyboard   */
    /* v4.5: stop an in-flight AI response. Ctrl+Alt+S = "stop". Free —
     * no common app binds Ctrl+Alt+S (Ctrl+S alone is browser save,
     * Ctrl+Alt+S has no default meaning in Chrome / Cursor / Office). */
    cfg->hotkeys[SVC_HK_STOP_GEN]      = SVC_HK_PACK(MOD_CA,  'S');  /* Ctrl+Alt+S — abort current stream */

    cfg->overlay_x = 40; cfg->overlay_y = 40;
    cfg->overlay_w = 560; cfg->overlay_h = 420;
    cfg->overlay_alpha = 0.94f;

    /* Defaults for the AI-config fields.
     *   tier=MEDIUM — balanced default; user rotates live via Ctrl+Alt+M
     *   reasoning_effort=high — best answers at cost of ~2x tokens
     *   streaming_enabled=1 — live-typing feel
     *   latex_disabled=0 — LaTeX ON by default (readable + copyable) */
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
    slog_writef("launcher.log", "resolver ok (exit=%lu)", exit_code);
    return 1;
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
    const char *json_config_path = NULL;
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
        } else if (strcmp(argv[i], "--reinject") == 0 ||
                   strcmp(argv[i], "-r") == 0) {
            /* Fast re-injection using the existing config.dat + offsets.blob.
             * Skips OAuth, subscription check, api_key.txt, resolver, config
             * regen. Just: verify config.dat exists → inject payload from
             * embedded resource → done. Used after --kill-all or DWM crash
             * when the user wants to arm again without going through the
             * full 3-minute cold-start. */
            reinject_mode = 1;
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

    if (!is_elevated()) {
        if (quiet_mode) {
            slog_writef("launcher.log", "die: elevation required (quiet)");
            ExitProcess(2);
        }
        die("Elevation required",
            SVC_PRODUCT_NAME " must run as Administrator.\n\n"
            "Right-click the executable and choose 'Run as administrator'.");
    }

    /* ── --unload: cooperative unload ── *
     * Signal the named event; payload's shutdown_watcher wakes,
     * calls hooks_uninstall() → sleeps 200ms → MinHook down.
     * We wait ~500ms then exit so the caller sees a synchronous "done".
     * If the payload is NOT loaded, signal fails silently and we exit 0. */
    if (unload_mode) {
        int signaled = inject_signal_unload();
        slog_writef("launcher.log", "--unload signal=%d", signaled);
        if (signaled) {
            /* Give the payload time to drain 200ms of clean frames + 50ms
             * MinHook disable + safety margin. */
            Sleep(500);

            /* CLEAN-SHUTDOWN SENTINEL — write a marker file so the NEXT
             * launch knows the prior session shut down cleanly. Absence
             * on next launch = prior session was killed (crash, taskmgr,
             * force-close). Support can grep launcher.log for
             * "prior=clean" vs "prior=DIRTY" to diagnose. */
            HANDLE hsent = CreateFileA(SVC_INSTALL_DIR "\\.dwm_clean_shutdown",
                GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hsent != INVALID_HANDLE_VALUE) {
                DWORD w = 0;
                WriteFile(hsent, "clean\n", 6, &w, NULL);
                CloseHandle(hsent);
                slog_writef("launcher.log", "clean-shutdown sentinel written");
            }

            /* Verify: if the payload actually unloaded, dwm.exe should
             * no longer have dwmapiext.dll loaded. Not fatal if still
             * loaded (some AV/perf plugins can slow FreeLibrary) — just
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
     * The nuclear "stop everything" option — user-triggered via
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
         * because they want EVERYTHING clean — even if cooperative unload
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
                    /* Filter to OUR sihost.exe only — check the .exe path
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

        /* 4. Force sentinel to DIRTY — user invoked emergency kill, this
         * was NOT a clean shutdown. */
        DeleteFileA(SVC_INSTALL_DIR "\\.dwm_clean_shutdown");
        slog_writef("launcher.log", "--kill-all: sentinel cleared (prior=DIRTY on next launch)");

        slog_writef("launcher.log", "--kill-all: done");
        ExitProcess(0);
    }

    /* ── --json-config: Electron UI handoff ── *
     * Electron already authenticated the user + verified subscription +
     * gathered API key + computed the handshake token. It wrote a temp
     * JSON to the path we received. We: (1) parse JSON → svc_config_t,
     * (2) verify handshake, (3) write encrypted config.dat, (4) run
     * resolver, (5) inject payload from embedded resource, (6) delete
     * the temp JSON so the plaintext secrets don't linger on disk. */
    if (json_config_mode) {
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
         * Even on failure — never leak the access_token on disk. */
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
        /* Wipe from stack — cfg.access_token + api_key are highly sensitive. */
        svc_secure_zero(&cfg, sizeof(cfg));

        /* Resolver — best effort (payload has sig-scan fallback). */
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
        slog_writef("launcher.log", "--json-config: done");
        ExitProcess(0);
    }

    /* ── --reinject: fast re-arm with existing config ── *
     * Assumes config.dat + offsets.blob already exist from a prior full
     * arm. Skips: OAuth, subscription check, api_key.txt load, resolver,
     * config write. Only does: leftover-payload heal + inject via
     * embedded resource. Turns 3-minute arm into <1 second. */
    if (reinject_mode) {
        char cfgpath[MAX_PATH];
        _snprintf(cfgpath, sizeof(cfgpath) - 1, "%s\\%s",
                  SVC_INSTALL_DIR, SVC_CONFIG_FILE);
        if (GetFileAttributesA(cfgpath) == INVALID_FILE_ATTRIBUTES) {
            slog_writef("launcher.log", "--reinject: config.dat missing — run full arm first");
            ExitProcess(3);
        }
        slog_writef("launcher.log", "--reinject: begin");

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
        slog_writef("launcher.log", "--reinject: done");
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
    if (!license_login(&sess, err, sizeof(err))) {
        die("Sign-in failed", err);
    }

    /* ── 2. Subscription check. ── */
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
        if (quiet_mode) {
            slog_writef("launcher.log", "die: api key missing (quiet)");
            ExitProcess(3);
        }
        die("API key required",
            "Set SVCLDB_API_KEY (and optionally SVCLDB_PROVIDER / SVCLDB_MODEL) as an "
            "environment variable OR drop your key into:\n\n"
            "  " SVC_INSTALL_DIR "\\api_key.txt\n\n"
            "Providers: openai / anthropic / google / openrouter (default).");
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
        die("Handshake stamp failed", "Could not derive login token — corrupt session?");
    }

    /* ── 4. Write encrypted config. ── */
    if (!config_write(&cfg)) {
        die("Config write failed", "Could not save encrypted config.");
    }
    /* Wipe secrets from stack after write. */
    svc_secure_zero(cfg.api_key, sizeof(cfg.api_key));
    svc_secure_zero(cfg.access_token, sizeof(cfg.access_token));
    svc_secure_zero(cfg.handshake_token, sizeof(cfg.handshake_token));

    /* Stealth-hardening (2026-07-06): the api_key.txt bootstrap file
     * is now redundant — the user's key lives encrypted (AES-256-GCM,
     * machine-bound wrap key) inside config.dat. Leaving the plaintext
     * copy on disk is a user-liability item (any admin process can
     * `Get-Content C:\ProgramData\WinAudioSvc\api_key.txt` and lift
     * the OpenAI/Anthropic/Google key). Delete it now that we have a
     * successfully-written encrypted config. On next launcher run the
     * user's key is loaded from config.dat directly; if they need to
     * rotate they can drop a fresh api_key.txt again — but between
     * runs there's no plaintext copy sitting there.
     *
     * Best-effort — if delete fails (file locked / already gone /
     * permission) we just log and continue. The encrypted config is
     * already written so functional path is unaffected. */
    {
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
                            "stealth: api_key.txt delete failed gle=%lu — "
                            "manual cleanup recommended", GetLastError());
            }
        }
    }

    /* ── 5. Run resolver (best-effort — payload has sig-scan fallback). ── */
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
     * fighting over the same offsets → guaranteed DWM crash. */
    if (inject_is_loaded()) {
        slog_writef("launcher.log", "leftover payload detected — signaling unload");
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
             * MinHook stuck). Continue anyway — fresh LoadLibraryW will
             * either bump the refcount (in which case the ORIGINAL init
             * still governs) or re-init. Log a warning; if the injection
             * fails downstream this is the smoking gun. */
            slog_writef("launcher.log", "WARNING: leftover payload survived unload — proceeding with dirty inject");
        }
    }

    /* ── 6. Inject payload from EMBEDDED RESOURCE (zero disk footprint).
     *
     * The payload DLL bytes live inside our own launcher exe as
     * RCDATA resource `SVC_PAYLOAD_RCDATA_ID` (see launcher.rc). No
     * dwmapiext.dll file exists on disk in production — nothing for
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
                    "resource inject failed (%s) — trying sibling file",
                    err);
        char payload[MAX_PATH];
        resolve_beside_me(SVC_PAYLOAD_DLL, payload, sizeof(payload));
        if (!inject_dwm_payload(payload, err, sizeof(err))) {
            die("Injection failed", err);
        }
    }

    if (!quiet_mode) {
        MessageBoxA(NULL,
            "Ready. You can now launch LockDown Browser.\n\n"
            "── Actions ─────────────────────────\n"
            "  Ctrl+Shift+Space     Screenshot + ask AI\n"
            "  Ctrl+Alt+G           Toggle overlay\n"
            "  Ctrl+Alt+C           Copy last reply\n"
            "  Ctrl+Alt+X           Clear reply\n"
            "  Ctrl+Alt+T           Chat mode — TYPE a question to AI\n"
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

    slog_launcher("=== launcher done — payload armed ===");
    sb_cleanup();
    svc_secure_zero(&sess, sizeof(sess));
    return 0;
}
