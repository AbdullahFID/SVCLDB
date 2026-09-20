/* ================================================================== *
 * token_refresh_server.c -- v14 (2026-08-24)                          *
 *                                                                    *
 * Payload-side named-pipe SERVER that lets Electron push a refreshed *
 * Supabase JWT into `cfg->access_token` while the payload is running. *
 *                                                                    *
 * ── Root problem (Bug 2, user-reported "1 hour into session, app    *
 *    crashed then overlay popped up") ───────────────────────────────  *
 *                                                                    *
 *   * Payload's `cfg->access_token` is set once at inject time (from *
 *     `sihost --json-config`) and cached forever in `config_read.c`  *
 *     via `cfg_get()`.                                                *
 *   * Supabase JWTs have a ~1-hour lifetime.                         *
 *   * `sub_check.c` polls Supabase every ~30 min with the cached      *
 *     token. At ~1h in, the token is expired, Supabase returns 401,  *
 *     `sub_check` interprets that as "denied" -> `trigger_self_unload` *
 *     -> overlay silently vanishes.                                    *
 *   * Electron's `revalidation.js` DOES refresh the JWT (~15 min      *
 *     before expiry) and saves it to `session.enc` on disk -- but      *
 *     nothing propagated the fresh token into the running payload's  *
 *     in-memory cfg. Fixed here by pushing the new token over a       *
 *     named pipe, HMAC-authenticated by a shared install secret.     *
 *                                                                    *
 * ── Wire protocol (little-endian) ───────────────────────────────────  *
 *                                                                    *
 *   Request  (Electron -> payload, 44 + token_len bytes):              *
 *     uint32_t  magic         = 0x544F4B31   ('TOK1')                 *
 *     uint32_t  reserved      = 0                                     *
 *     uint8_t   hmac[32]      = HMAC-SHA256(k, token_bytes) where     *
 *                                k = HMAC-SHA256(install_secret_hex,  *
 *                                                cfg->handshake_hwid) *
 *     uint32_t  token_len     = strlen(new_access_token) [1..4095]    *
 *     char      token[token_len] = ASCII JWT (no NUL)                 *
 *                                                                    *
 *   Response (payload -> Electron, 8 bytes):                          *
 *     uint32_t  magic         = 0x544F4B31                            *
 *     int32_t   status        =  0 accepted                           *
 *                                -1 bad HMAC / generic reject         *
 *                                -2 token too long                    *
 *                                -3 install secret unreadable         *
 *                                -4 io error                          *
 *                                                                    *
 * ── Threat model ─────────────────────────────────────────────────────  *
 *                                                                    *
 *   The HMAC key = HMAC(install_secret_hex_ASCII, HWID).              *
 *   * install_secret is a 64-char hex string at                       *
 *     `C:\ProgramData\WinAudioSvc\.svchelper_install_secret` written  *
 *     with mode 0o600 by Electron's auth.js. Local admin CAN read.    *
 *     Non-admin cannot.                                               *
 *   * HWID is `cfg->handshake_hwid` -- Electron's device fingerprint    *
 *     used at inject time. Bound to this machine.                     *
 *                                                                    *
 *   Defends against: non-admin process that enumerates named pipes    *
 *     and tries to spoof a token push. They can't read the secret.    *
 *   Does NOT defend against: malicious admin process. But an admin    *
 *     process could just read `config.dat`'s wrap-key and read the    *
 *     token directly -- this is the same trust boundary as our         *
 *     encrypted config storage.                                       *
 *                                                                    *
 * ── Lifecycle ────────────────────────────────────────────────────────  *
 *                                                                    *
 *   * `token_refresh_start()` -- called from `dllmain.c::init_thread`  *
 *     after `hooks_install` + `cfg_get` + `sub_check_start`.          *
 *   * `token_refresh_stop()`  -- called from `shutdown_watcher`        *
 *     between `sub_check_stop` and `hooks_uninstall`. Closes the      *
 *     pending pipe handle to unblock `ConnectNamedPipe`, waits up to  *
 *     5s for the thread to exit. Must run BEFORE `cfg_cleanup` so an  *
 *     in-flight `handle_one_client` doesn't dereference NULL cfg.     *
 *                                                                    *
 *   Single-instance pipe (only Electron connects). Reuses one         *
 *   PIPE_ACCESS_DUPLEX handle per client cycle: create -> wait for     *
 *   connect -> read+verify+update -> write response -> disconnect ->      *
 *   loop. `PIPE_REJECT_REMOTE_CLIENTS` blocks over-network access.   *
 * ================================================================== */

#include "token_refresh_server.h"
#include "config_read.h"
#include "../../shared/common.h"
#include "../../shared/log_secure.h"
#include "../../shared/crypto_util.h"
#include "../../shared/config_types.h"
#include "../../shared/obf_names.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ─── Wire constants ─────────────────────────────────────────────── */
/* v3 (2026-09-19): per-box derived, camouflaged pipe name -- see
 * shared/obf_names.h. Was the fixed literal "\\.\pipe\svcldb_token_v1",
 * a zero-effort IOC for any non-admin `\\.\pipe\*` enumeration. Now a
 * per-machine GUID indistinguishable from legit COM/RPC/mojo pipes.
 * (Function call, not a string literal -- only ever used as a runtime
 * pipe-name argument, cached after first derivation.) */
#define TOKEN_PIPE_NAME     obf_pipe_token()
#define TOKEN_PIPE_MAGIC    0x544F4B31u    /* 'TOK1' */
#define TOKEN_HMAC_LEN      32u
#define TOKEN_REQ_HDR_LEN   (4u + 4u + 32u + 4u)   /* magic+reserved+hmac+token_len */
#define TOKEN_RESP_LEN      8u                      /* magic+status */

/* Max JWT length. Supabase JWTs are typically ~1200-2000 chars; cap
 * at 4095 to match cfg->access_token[4096]-1 NUL. Anything larger
 * rejects with status -2 (protects against DoS via giant reads). */
#define TOKEN_MAX_LEN       4095u

#define INSTALL_SECRET_PATH SVC_INSTALL_DIR "\\.svchelper_install_secret"

/* ─── Module state ───────────────────────────────────────────────── */
static HANDLE g_tr_thread   = NULL;
/* Current pipe handle exposed to token_refresh_stop() so it can close
 * out from under ConnectNamedPipe. Atomically swapped to NULL after
 * DisconnectNamedPipe + CloseHandle to avoid double-close. */
static HANDLE g_tr_pipe     = NULL;
static volatile LONG g_tr_running = 0;

/* ─── Utility ────────────────────────────────────────────────────── */

static BOOL read_all(HANDLE h, void *buf, DWORD n) {
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        DWORD r = 0;
        if (!ReadFile(h, p, n, &r, NULL) || r == 0) return FALSE;
        p += r; n -= r;
    }
    return TRUE;
}

static BOOL write_all(HANDLE h, const void *buf, DWORD n) {
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        DWORD w = 0;
        if (!WriteFile(h, p, n, &w, NULL) || w == 0) return FALSE;
        p += w; n -= w;
    }
    return TRUE;
}

static void write_response(HANDLE pipe, int32_t status) {
    uint8_t resp[TOKEN_RESP_LEN];
    uint32_t rmagic = TOKEN_PIPE_MAGIC;
    memcpy(resp + 0, &rmagic, 4);
    memcpy(resp + 4, &status, 4);
    (void)write_all(pipe, resp, TOKEN_RESP_LEN);
}

/* ─── Install secret + key derivation ────────────────────────────── */

/* Read the install secret file into `out`. Returns bytes read (after
 * trimming trailing whitespace). 0 on failure. `outmax` should be
 * >= 64 to hold the standard 64-char hex string; we also accept
 * a slightly-longer read to absorb possible line endings. */
static size_t read_install_secret(uint8_t *out, size_t outmax) {
    HANDLE h = CreateFileA(INSTALL_SECRET_PATH, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD r = 0;
    BOOL ok = ReadFile(h, out, (DWORD)outmax, &r, NULL);
    CloseHandle(h);
    if (!ok) return 0;
    /* Trim trailing whitespace/newlines -- auth.js writes without a
     * trailing NL but a hand-edit or Notepad save could inject one. */
    while (r > 0 && (out[r - 1] == '\r' || out[r - 1] == '\n' ||
                     out[r - 1] == ' '  || out[r - 1] == '\t')) {
        out[r - 1] = 0;
        r--;
    }
    return (size_t)r;
}

/* Derive verify key = HMAC-SHA256(install_secret_hex_string, HWID).
 * Matches Electron's auth.js:_deriveSigningKey pattern:
 *   crypto.createHmac('sha256', _installSecretCached())
 *     .update(hwid || 'no-hwid')
 *     .digest()
 *
 * Note: Node's `createHmac(algo, key)` treats a string key as its UTF-8
 * byte representation. Since the secret is 64 ASCII hex chars, the
 * effective key is those 64 raw ASCII bytes -- NOT the decoded 32 raw
 * bytes. We must match that here. */
static int derive_verify_key(uint8_t out[32]) {
    uint8_t secret[128];
    size_t secret_len = read_install_secret(secret, sizeof(secret));
    if (secret_len < 32) {
        slog_writef("payload.log",
                    "token_refresh: install_secret unreadable/short (%zu)",
                    secret_len);
        return 0;
    }
    const svc_config_t *cfg = cfg_get();
    if (!cfg) {
        svc_secure_zero(secret, sizeof(secret));
        return 0;
    }
    /* HWID string as-is (matches auth.js `.update(hwid || 'no-hwid')`).
     * If handshake_hwid is empty (very rare -- cfg was written pre-v4
     * schema?), fall back to the literal "no-hwid" to match JS side. */
    const char *hwid = cfg->handshake_hwid;
    const char *nohwid_fallback = "no-hwid";
    if (!hwid || !hwid[0]) hwid = nohwid_fallback;
    size_t hwid_len = strnlen(hwid, sizeof(cfg->handshake_hwid));

    int ok = cu_hmac_sha256(secret, secret_len,
                            hwid, hwid_len,
                            out);
    svc_secure_zero(secret, sizeof(secret));
    return ok;
}

/* ─── One-shot handler ───────────────────────────────────────────── */

/* Read one full request off `pipe`, validate, apply if valid, send
 * response. Returns 0 on success, negative on any error (response is
 * always sent best-effort, even on error paths, so Electron can log
 * a specific status). */
static int handle_one_client(HANDLE pipe) {
    uint8_t hdr[TOKEN_REQ_HDR_LEN];
    if (!read_all(pipe, hdr, TOKEN_REQ_HDR_LEN)) {
        slog_write("payload.log", "token_refresh: read header failed");
        write_response(pipe, -4);
        return -4;
    }
    uint32_t magic;
    memcpy(&magic, hdr + 0, 4);
    if (magic != TOKEN_PIPE_MAGIC) {
        slog_writef("payload.log", "token_refresh: bad magic 0x%08x", magic);
        write_response(pipe, -1);
        return -1;
    }
    /* hdr[4..8]: reserved, ignored */
    uint8_t incoming_hmac[32];
    memcpy(incoming_hmac, hdr + 8, 32);
    uint32_t token_len;
    memcpy(&token_len, hdr + 40, 4);
    if (token_len == 0 || token_len > TOKEN_MAX_LEN) {
        slog_writef("payload.log", "token_refresh: bad token_len %u", token_len);
        write_response(pipe, -2);
        return -2;
    }

    char *token = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)token_len + 1);
    if (!token) {
        slog_write("payload.log", "token_refresh: HeapAlloc failed");
        write_response(pipe, -4);
        return -4;
    }
    if (!read_all(pipe, token, token_len)) {
        HeapFree(GetProcessHeap(), 0, token);
        slog_write("payload.log", "token_refresh: read token payload failed");
        write_response(pipe, -4);
        return -4;
    }
    token[token_len] = 0;

    uint8_t key[32];
    if (!derive_verify_key(key)) {
        HeapFree(GetProcessHeap(), 0, token);
        write_response(pipe, -3);
        return -3;
    }
    uint8_t expected[32];
    if (!cu_hmac_sha256(key, 32, token, token_len, expected)) {
        svc_secure_zero(key, sizeof(key));
        HeapFree(GetProcessHeap(), 0, token);
        write_response(pipe, -1);
        return -1;
    }
    svc_secure_zero(key, sizeof(key));
    if (cu_ct_eq(expected, incoming_hmac, 32) != 0) {
        slog_write("payload.log", "token_refresh: HMAC MISMATCH -- rejecting");
        HeapFree(GetProcessHeap(), 0, token);
        write_response(pipe, -1);
        return -1;
    }

    if (!cfg_update_access_token(token, (size_t)token_len)) {
        svc_secure_zero(token, (size_t)token_len);
        HeapFree(GetProcessHeap(), 0, token);
        slog_write("payload.log", "token_refresh: cfg_update_access_token FAILED");
        write_response(pipe, -1);
        return -1;
    }
    slog_writef("payload.log",
                "token_refresh: cfg->access_token updated (%u bytes)", token_len);
    svc_secure_zero(token, (size_t)token_len);
    HeapFree(GetProcessHeap(), 0, token);

    write_response(pipe, 0);
    return 0;
}

/* ─── Thread body ────────────────────────────────────────────────── */

static DWORD WINAPI token_refresh_thread(LPVOID param) {
    (void)param;
    slog_write("payload.log", "token_refresh: server thread up");

    /* Small settle delay so cfg_get() is guaranteed primed by
     * init_thread by the time a real client connects. */
    Sleep(200);

    while (InterlockedCompareExchange(&g_tr_running, 0, 0) == 1) {
        /* Create a fresh single-instance pipe for the next client.
         *
         * FIRST_PIPE_INSTANCE: enforced by our single-listener design
         *   -- if two payloads race, only the first-created pipe wins
         *   and the second gets ERROR_ACCESS_DENIED (belt-and-suspenders
         *   next to init-guard mutex).
         * REJECT_REMOTE_CLIENTS: blocks anyone reaching us via UNC
         *   (\\host\pipe\...). Local admin only.
         * PIPE_TYPE_BYTE + READMODE_BYTE + PIPE_WAIT: matches
         *   redact_client.c's byte-stream convention. */
        HANDLE pipe = CreateNamedPipeA(
            TOKEN_PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,        /* max instances -- single-client */
            256,      /* out buffer size (just the 8-byte resp) */
            8192,     /* in buffer size -- max header 44 + token 4095 */
            0,        /* default timeout */
            NULL);    /* default DACL -- pipe owned by SYSTEM (DWM's context) */
        if (pipe == INVALID_HANDLE_VALUE) {
            DWORD gle = GetLastError();
            slog_writef("payload.log",
                        "token_refresh: CreateNamedPipe failed gle=%lu -- retrying in 5s",
                        gle);
            /* Interruptible sleep so stop() cancels us fast. */
            for (int i = 0; i < 50 &&
                            InterlockedCompareExchange(&g_tr_running, 0, 0) == 1; i++) {
                Sleep(100);
            }
            continue;
        }

        InterlockedExchangePointer((PVOID volatile *)&g_tr_pipe, pipe);

        BOOL connected = ConnectNamedPipe(pipe, NULL);
        DWORD cnp_gle = GetLastError();
        /* PIPE_WAIT + no OVERLAPPED: ConnectNamedPipe blocks until a
         * client connects, returns TRUE on success. Some Windows
         * versions return FALSE + ERROR_PIPE_CONNECTED when the client
         * connected just before we called it -> also treat as success. */
        if (!connected && cnp_gle != ERROR_PIPE_CONNECTED) {
            /* Shutdown path: stop() closed the handle -> ConnectNamedPipe
             * returns FALSE with ERROR_BROKEN_PIPE or ERROR_INVALID_HANDLE. */
            HANDLE closed = (HANDLE)InterlockedExchangePointer(
                (PVOID volatile *)&g_tr_pipe, NULL);
            if (closed != NULL && closed != INVALID_HANDLE_VALUE) {
                CloseHandle(closed);
            }
            if (InterlockedCompareExchange(&g_tr_running, 0, 0) != 1) break;
            slog_writef("payload.log",
                        "token_refresh: ConnectNamedPipe failed gle=%lu",
                        cnp_gle);
            continue;
        }

        (void)handle_one_client(pipe);

        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        HANDLE closed = (HANDLE)InterlockedExchangePointer(
            (PVOID volatile *)&g_tr_pipe, NULL);
        if (closed != NULL && closed != INVALID_HANDLE_VALUE) {
            CloseHandle(closed);
        }
    }

    slog_write("payload.log", "token_refresh: server thread exiting");
    return 0;
}

/* ─── Public API ─────────────────────────────────────────────────── */

void token_refresh_start(void) {
    if (InterlockedCompareExchange(&g_tr_running, 1, 0) != 0) return;
    g_tr_thread = CreateThread(NULL, 0, token_refresh_thread, NULL, 0, NULL);
    if (!g_tr_thread) {
        InterlockedExchange(&g_tr_running, 0);
        slog_writef("payload.log",
                    "token_refresh: CreateThread failed gle=%lu", GetLastError());
    }
}

void token_refresh_stop(void) {
    InterlockedExchange(&g_tr_running, 0);
    /* v14.1 (2026-08-24) -- CRITICAL FIX: CancelSynchronousIo on the
     * server thread to unblock its ConnectNamedPipe. Just closing the
     * pipe handle from another thread does NOT reliably abort a blocking
     * synchronous ConnectNamedPipe (documented UB) -- this was causing
     * shutdown_watcher to stall inside token_refresh_stop for the full
     * 5s WaitForSingleObject budget -> launcher --unload polls for 500ms
     * then gives up + reports "payload still loaded" -> svchelper's
     * Uninject button appears broken, and worse: hooks_uninstall +
     * FreeLibraryAndExitThread eventually run WHILE the pipe thread is
     * still in ConnectNamedPipe inside freed code -> DWM crash. Bug
     * reported by Sam 2026-08-24 (v14 -> v14.1 same-day).
     *
     * CancelSynchronousIo is Vista+. Cancels any pending sync I/O on
     * the target thread -- includes ConnectNamedPipe, ReadFile,
     * WriteFile. Thread's error path checks g_tr_running == 0 and
     * exits. Same-process thread handle has SYNCHRONIZE by default. */
    if (g_tr_thread) {
        CancelSynchronousIo(g_tr_thread);
        WaitForSingleObject(g_tr_thread, 5000);
        CloseHandle(g_tr_thread);
        g_tr_thread = NULL;
    }
    /* Best-effort: reap any leftover pipe handle. The thread's own
     * cleanup path should have handled this on its way out; this is
     * defense in depth. */
    HANDLE p = (HANDLE)InterlockedExchangePointer(
        (PVOID volatile *)&g_tr_pipe, NULL);
    if (p != NULL && p != INVALID_HANDLE_VALUE) {
        CloseHandle(p);
    }
}
