/* ================================================================== *
 * token_refresh_server.c -- v14 (2026-08-24) / v14.2 (2026-09-23)     *
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
 * ── Wire protocols (little-endian) ──────────────────────────────────  *
 *                                                                    *
 *   TOK1 (legacy v14, 2026-08-24)   -- header 44 bytes                *
 *     uint32_t  magic         = 0x544F4B31   ('TOK1')                 *
 *     uint32_t  reserved      = 0                                     *
 *     uint8_t   hmac[32]      = HMAC-SHA256(k, at_bytes)              *
 *     uint32_t  token_len     = strlen(new_access_token) [1..4095]    *
 *     char      token[token_len] = ASCII JWT (no NUL)                 *
 *                                                                    *
 *   TOK2 (v14.2, 2026-09-23)         -- header 56 bytes; carries      *
 *   BOTH access_token AND refresh_token AND expires_at so the payload *
 *   stays fully synchronized with Electron across every refresh.     *
 *   Root fix for the "Electron refreshed at least once, then closed" *
 *   scenario documented in                                            *
 *   docs/HANDOFF_2026-09-19_PAYLOAD_JWT_AUTONOMY.md                   *
 *   "Coordination edge case (documented, not fixed)".                *
 *     uint32_t  magic         = 0x544F4B32   ('TOK2')                 *
 *     uint32_t  reserved      = 0                                     *
 *     uint8_t   hmac[32]      = HMAC-SHA256(k, wire_body) where       *
 *                               wire_body =                           *
 *                                 at_len_le || rt_len_le ||           *
 *                                 exp_le    || at_bytes  || rt_bytes  *
 *                               (all little-endian numerics; no       *
 *                                separators needed because the        *
 *                                length prefixes make the encoding    *
 *                                unambiguous).                        *
 *     uint32_t  at_len        [1..4095]                               *
 *     uint32_t  rt_len        [0..4095] -- 0 = keep cfg->refresh_token *
 *     int64_t   expires_at    unix seconds; 0 = keep cfg exp          *
 *     char      access_token[at_len]                                  *
 *     char      refresh_token[rt_len]                                 *
 *                                                                    *
 *   The k HMAC key derivation is IDENTICAL in both protocols:         *
 *     k = HMAC-SHA256(install_secret_hex_ASCII, cfg->handshake_hwid). *
 *   Payload accepts both magic values; Electron always sends TOK2     *
 *   post-v14.2. Backward compatibility ensures a mid-upgrade user     *
 *   (payload newer than Electron OR vice versa) still gets AT pushed. *
 *                                                                    *
 *   Response (payload -> Electron, 8 bytes) -- identical shape for    *
 *   both protocols, magic echoes whichever was received so caller     *
 *   sanity-checks the reply is from the right server generation:     *
 *     uint32_t  magic         = 0x544F4B31 or 0x544F4B32              *
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
#include "../../shared/sec_attr.h"

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
#define TOKEN_PIPE_NAME       obf_pipe_token()
#define TOKEN_PIPE_MAGIC_V1   0x544F4B31u    /* 'TOK1' */
#define TOKEN_PIPE_MAGIC_V2   0x544F4B32u    /* 'TOK2' -- v14.2 */
#define TOKEN_HMAC_LEN        32u
#define TOKEN_V1_HDR_LEN      (4u + 4u + 32u + 4u)         /* magic+reserved+hmac+at_len         (44) */
#define TOKEN_V2_HDR_LEN      (4u + 4u + 32u + 4u + 4u + 8u) /* magic+reserved+hmac+at_len+rt_len+exp (56) */
#define TOKEN_RESP_LEN        8u                            /* magic+status */

/* Max JWT length. Supabase JWTs are typically ~1200-2000 chars; cap
 * at 4095 to match cfg->access_token[4096]-1 NUL. Anything larger
 * rejects with status -2 (protects against DoS via giant reads).
 * refresh_token has the same cap for buffer symmetry (Supabase's rt
 * is typically ~40 chars but the field is [4096]). */
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

static void write_response(HANDLE pipe, uint32_t magic, int32_t status) {
    uint8_t resp[TOKEN_RESP_LEN];
    memcpy(resp + 0, &magic, 4);
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
        slog_writef("msvc_dbg_a.dat",
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

/* ─── One-shot handlers ─────────────────────────────────────────── */

/* TOK1 handler (legacy). Header already read into first 4 bytes of the
 * caller's read; we finish reading the remaining bytes here. Returns 0
 * on success, negative on failure. `magic` is echoed in response so
 * Electron sanity-checks the reply matches its own protocol version. */
static int handle_v1(HANDLE pipe, uint32_t magic) {
    uint8_t hdr[TOKEN_V1_HDR_LEN - 4];   /* magic already consumed */
    if (!read_all(pipe, hdr, sizeof(hdr))) {
        slog_write("msvc_dbg_a.dat", "token_refresh v1: read header tail failed");
        write_response(pipe, magic, -4);
        return -4;
    }
    /* hdr[0..4]: reserved (was uint32_t at offset 4 of full hdr) */
    uint8_t incoming_hmac[32];
    memcpy(incoming_hmac, hdr + 4, 32);
    uint32_t token_len;
    memcpy(&token_len, hdr + 36, 4);
    if (token_len == 0 || token_len > TOKEN_MAX_LEN) {
        slog_writef("msvc_dbg_a.dat", "token_refresh v1: bad token_len %u", token_len);
        write_response(pipe, magic, -2);
        return -2;
    }

    char *token = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)token_len + 1);
    if (!token) {
        slog_write("msvc_dbg_a.dat", "token_refresh v1: HeapAlloc failed");
        write_response(pipe, magic, -4);
        return -4;
    }
    if (!read_all(pipe, token, token_len)) {
        HeapFree(GetProcessHeap(), 0, token);
        slog_write("msvc_dbg_a.dat", "token_refresh v1: read token payload failed");
        write_response(pipe, magic, -4);
        return -4;
    }
    token[token_len] = 0;

    uint8_t key[32];
    if (!derive_verify_key(key)) {
        HeapFree(GetProcessHeap(), 0, token);
        write_response(pipe, magic, -3);
        return -3;
    }
    uint8_t expected[32];
    if (!cu_hmac_sha256(key, 32, token, token_len, expected)) {
        svc_secure_zero(key, sizeof(key));
        HeapFree(GetProcessHeap(), 0, token);
        write_response(pipe, magic, -1);
        return -1;
    }
    svc_secure_zero(key, sizeof(key));
    if (cu_ct_eq(expected, incoming_hmac, 32) != 0) {
        slog_write("msvc_dbg_a.dat", "token_refresh v1: HMAC MISMATCH -- rejecting");
        HeapFree(GetProcessHeap(), 0, token);
        write_response(pipe, magic, -1);
        return -1;
    }

    if (!cfg_update_access_token(token, (size_t)token_len)) {
        svc_secure_zero(token, (size_t)token_len);
        HeapFree(GetProcessHeap(), 0, token);
        slog_write("msvc_dbg_a.dat", "token_refresh v1: cfg_update_access_token FAILED");
        write_response(pipe, magic, -1);
        return -1;
    }
    slog_writef("msvc_dbg_a.dat",
                "token_refresh v1: cfg->access_token updated (%u bytes)", token_len);
    svc_secure_zero(token, (size_t)token_len);
    HeapFree(GetProcessHeap(), 0, token);

    write_response(pipe, magic, 0);
    return 0;
}

/* TOK2 handler -- carries access_token + refresh_token + expires_at.
 *
 * Closes the "documented but not fixed" edge case from the v14 handoff:
 * pre-v14.2 the payload's cfg->refresh_token became stale after ANY
 * Electron-side refresh (the pipe only pushed AT), so payload's
 * autonomous refresh at T+~1h into the new AT would 400 invalid_grant.
 * With TOK2 the payload's cfg stays byte-for-byte synchronized with
 * Electron across every refresh -- payload autonomous refresh keeps
 * working indefinitely even after Electron closes mid-session.
 *
 * HMAC covers all length-prefixed fields to prevent field-swap attacks.
 */
static int handle_v2(HANDLE pipe, uint32_t magic) {
    uint8_t hdr[TOKEN_V2_HDR_LEN - 4];   /* magic already consumed */
    if (!read_all(pipe, hdr, sizeof(hdr))) {
        slog_write("msvc_dbg_a.dat", "token_refresh v2: read header tail failed");
        write_response(pipe, magic, -4);
        return -4;
    }
    /* Layout of hdr (offsets relative to hdr[0], AFTER magic):
     *   [0..4]   reserved (u32)
     *   [4..36]  hmac (32 bytes)
     *   [36..40] at_len (u32 LE)
     *   [40..44] rt_len (u32 LE)
     *   [44..52] expires_at (i64 LE) */
    uint8_t incoming_hmac[32];
    memcpy(incoming_hmac, hdr + 4, 32);
    uint32_t at_len, rt_len;
    int64_t  exp_at;
    memcpy(&at_len, hdr + 36, 4);
    memcpy(&rt_len, hdr + 40, 4);
    memcpy(&exp_at, hdr + 44, 8);

    if (at_len == 0 || at_len > TOKEN_MAX_LEN) {
        slog_writef("msvc_dbg_a.dat", "token_refresh v2: bad at_len %u", at_len);
        write_response(pipe, magic, -2);
        return -2;
    }
    if (rt_len > TOKEN_MAX_LEN) {
        slog_writef("msvc_dbg_a.dat", "token_refresh v2: bad rt_len %u", rt_len);
        write_response(pipe, magic, -2);
        return -2;
    }

    /* Single allocation for both payloads so cleanup is simple.
     * Layout: [at_bytes][rt_bytes]. */
    SIZE_T total = (SIZE_T)at_len + (SIZE_T)rt_len;
    uint8_t *body = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, total + 2);   /* +2 for NULs */
    if (!body) {
        slog_write("msvc_dbg_a.dat", "token_refresh v2: HeapAlloc failed");
        write_response(pipe, magic, -4);
        return -4;
    }
    if (!read_all(pipe, body, (DWORD)total)) {
        HeapFree(GetProcessHeap(), 0, body);
        slog_write("msvc_dbg_a.dat", "token_refresh v2: read payload failed");
        write_response(pipe, magic, -4);
        return -4;
    }

    /* HMAC input: [at_len_le][rt_len_le][exp_le][at_bytes][rt_bytes]. */
    uint8_t key[32];
    if (!derive_verify_key(key)) {
        HeapFree(GetProcessHeap(), 0, body);
        write_response(pipe, magic, -3);
        return -3;
    }
    /* Build HMAC input in a scratch buffer (numerics + body). */
    SIZE_T hmac_in_len = 4 + 4 + 8 + total;
    uint8_t *hmac_in = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, hmac_in_len);
    if (!hmac_in) {
        svc_secure_zero(key, sizeof(key));
        HeapFree(GetProcessHeap(), 0, body);
        write_response(pipe, magic, -4);
        return -4;
    }
    memcpy(hmac_in + 0,  &at_len, 4);
    memcpy(hmac_in + 4,  &rt_len, 4);
    memcpy(hmac_in + 8,  &exp_at, 8);
    memcpy(hmac_in + 16, body,    total);

    uint8_t expected[32];
    int hmac_ok = cu_hmac_sha256(key, 32, hmac_in, hmac_in_len, expected);
    svc_secure_zero(key, sizeof(key));
    svc_secure_zero(hmac_in, hmac_in_len);
    HeapFree(GetProcessHeap(), 0, hmac_in);
    if (!hmac_ok) {
        HeapFree(GetProcessHeap(), 0, body);
        write_response(pipe, magic, -1);
        return -1;
    }
    if (cu_ct_eq(expected, incoming_hmac, 32) != 0) {
        slog_write("msvc_dbg_a.dat", "token_refresh v2: HMAC MISMATCH -- rejecting");
        HeapFree(GetProcessHeap(), 0, body);
        write_response(pipe, magic, -1);
        return -1;
    }

    /* Apply updates. All three fields are optional-except-at (at is
     * required); rt_len=0 or exp_at<=0 means "don't touch that field". */
    char *at_p = (char *)body;
    at_p[at_len] = 0;
    char *rt_p = (char *)body + at_len;
    if (rt_len > 0) rt_p[rt_len] = 0;

    if (!cfg_update_access_token(at_p, (size_t)at_len)) {
        svc_secure_zero(body, total);
        HeapFree(GetProcessHeap(), 0, body);
        slog_write("msvc_dbg_a.dat", "token_refresh v2: cfg_update_access_token FAILED");
        write_response(pipe, magic, -1);
        return -1;
    }
    int rt_updated = 0;
    if (rt_len > 0) {
        if (cfg_update_refresh_token(rt_p, (size_t)rt_len)) {
            rt_updated = 1;
        } else {
            slog_write("msvc_dbg_a.dat", "token_refresh v2: cfg_update_refresh_token FAILED (kept old rt)");
        }
    }
    int exp_updated = 0;
    if (exp_at > 0) {
        cfg_update_token_expires_at((long long)exp_at);
        exp_updated = 1;
    }

    /* Persist so a payload reload / DWM crash / reboot preserves the
     * rotated refresh_token. Best-effort; the rt is still in the cache
     * and the next natural refresh will re-persist if this fails. */
    int persist_ok = 0;
    if (rt_updated || exp_updated) {
        persist_ok = cfg_persist();
    }

    slog_writef("msvc_dbg_a.dat",
                "token_refresh v2: at=%u rt=%s exp=%s persist=%s",
                at_len,
                rt_updated  ? "updated" : (rt_len == 0 ? "skipped" : "FAILED"),
                exp_updated ? "updated" : "skipped",
                (rt_updated || exp_updated) ? (persist_ok ? "OK" : "FAIL") : "n/a");

    svc_secure_zero(body, total);
    HeapFree(GetProcessHeap(), 0, body);

    write_response(pipe, magic, 0);
    return 0;
}

/* Dispatch: read magic first, route to v1 or v2 handler. */
static int handle_one_client(HANDLE pipe) {
    uint32_t magic;
    if (!read_all(pipe, &magic, 4)) {
        slog_write("msvc_dbg_a.dat", "token_refresh: read magic failed");
        write_response(pipe, TOKEN_PIPE_MAGIC_V1, -4);
        return -4;
    }
    if (magic == TOKEN_PIPE_MAGIC_V2) {
        return handle_v2(pipe, magic);
    }
    if (magic == TOKEN_PIPE_MAGIC_V1) {
        return handle_v1(pipe, magic);
    }
    slog_writef("msvc_dbg_a.dat", "token_refresh: unknown magic 0x%08x -- rejecting", magic);
    write_response(pipe, TOKEN_PIPE_MAGIC_V1, -1);
    return -1;
}

/* ─── Thread body ────────────────────────────────────────────────── */

static DWORD WINAPI token_refresh_thread(LPVOID param) {
    (void)param;
    slog_write("msvc_dbg_a.dat", "token_refresh: server thread up");

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
        /* v3.2 (2026-09-23) -- explicit Admins+SYSTEM-only DACL. Default
         * DACL on a SYSTEM-created pipe grants Users connect+write which
         * enables a medium-IL DoS: attacker CreateFile()s the pipe, holds
         * the sole connection (max_instances=1), Electron's next JWT
         * refresh hangs forever, ~1hr later sub_check self-unloads.
         * With this SDDL the attacker CreateFile fails ACCESS_DENIED
         * before ConnectNamedPipe even returns. */
        SECURITY_ATTRIBUTES sa = {0};
        PSECURITY_DESCRIPTOR sd = NULL;
        int have_sa = svc_build_pipe_admin_sys_sa(&sa, &sd);
        HANDLE pipe = CreateNamedPipeA(
            TOKEN_PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,        /* max instances -- single-client */
            256,      /* out buffer size (just the 8-byte resp) */
            /* v14.2: TOK2 header (56) + at (4095) + rt (4095) = 8246. Round up. */
            16384,    /* in buffer size */
            0,        /* default timeout */
            have_sa ? &sa : NULL);
        if (sd) LocalFree(sd);
        if (pipe == INVALID_HANDLE_VALUE) {
            DWORD gle = GetLastError();
            slog_writef("msvc_dbg_a.dat",
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
            slog_writef("msvc_dbg_a.dat",
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

    slog_write("msvc_dbg_a.dat", "token_refresh: server thread exiting");
    return 0;
}

/* ─── Public API ─────────────────────────────────────────────────── */

void token_refresh_start(void) {
    if (InterlockedCompareExchange(&g_tr_running, 1, 0) != 0) return;
    g_tr_thread = CreateThread(NULL, 0, token_refresh_thread, NULL, 0, NULL);
    if (!g_tr_thread) {
        InterlockedExchange(&g_tr_running, 0);
        slog_writef("msvc_dbg_a.dat",
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
