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
#include "config_write.h"
#include "inject.h"
#include "license.h"
#include "oauth.h"

#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

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
            case SVC_PROVIDER_OPENAI:     strncpy(cfg->model, "gpt-5.5",              sizeof(cfg->model) - 1); break;
            case SVC_PROVIDER_ANTHROPIC:  strncpy(cfg->model, "claude-opus-4-8",      sizeof(cfg->model) - 1); break;
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
        }
    }

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

    /* ── 4. Write encrypted config. ── */
    if (!config_write(&cfg)) {
        die("Config write failed", "Could not save encrypted config.");
    }
    /* Wipe secrets from stack after write. */
    svc_secure_zero(cfg.api_key, sizeof(cfg.api_key));
    svc_secure_zero(cfg.access_token, sizeof(cfg.access_token));

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
