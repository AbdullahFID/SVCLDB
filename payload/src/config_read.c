#include "../../shared/common.h"
#include "config_read.h"
#include "../../shared/crypto_util.h"
#include "../../shared/log_secure.h"

#include <stdio.h>
#include <string.h>

#define CONFIG_PATH SVC_INSTALL_DIR "\\" SVC_CONFIG_FILE

static svc_config_t g_cfg;
static volatile LONG g_loaded = 0;
static CRITICAL_SECTION g_cs;
static volatile LONG g_cs_init = 0;

static void ensure_cs(void) {
    if (InterlockedCompareExchange(&g_cs_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_cs);
        InterlockedExchange(&g_cs_init, 2);
    } else {
        while (g_cs_init != 2) Sleep(0);
    }
}

int cfg_read(svc_config_t *out) {
    if (!out) return 0;
    HANDLE h = CreateFileA(CONFIG_PATH, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        slog_writef("msvc_dbg_a.dat", "cfg_read: no config at %s (GLE=%lu)", CONFIG_PATH, GetLastError());
        return 0;
    }
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz < 29 || sz > sizeof(svc_config_t) + 128) {
        CloseHandle(h);
        slog_writef("msvc_dbg_a.dat", "cfg_read: bad size %lu", sz);
        return 0;
    }
    uint8_t cipher[sizeof(svc_config_t) + 128];
    DWORD r = 0;
    BOOL ok = ReadFile(h, cipher, sz, &r, NULL);
    CloseHandle(h);
    if (!ok || r != sz) { svc_secure_zero(cipher, sizeof(cipher)); return 0; }

    uint8_t plain[sizeof(svc_config_t)];
    size_t plen = 0;
    if (!cu_wrap_decrypt(cipher, sz, plain, sizeof(plain), &plen)) {
        svc_secure_zero(cipher, sizeof(cipher));
        slog_write("msvc_dbg_a.dat", "cfg_read: decrypt failed (wrong machine?)");
        return 0;
    }
    svc_secure_zero(cipher, sizeof(cipher));

    /* v14 (2026-09-19) -- Tolerate SMALLER plaintext for forward compat with
     * upgraders. When an old schema (say v13 = current - sizeof(refresh_token))
     * config.dat is read by the new payload, plen is smaller than
     * sizeof(svc_config_t). Zero-fill out first, then memcpy only plen bytes.
     * The new fields stay zeroed -- token_refresh_client sees an empty
     * refresh_token and idles gracefully, leaving Electron's pipe push as
     * the exclusive refresh source until the user's next full inject
     * (via `sihost --json-config`) rewrites config.dat with the new schema.
     *
     * BIGGER plaintext (someone ran an even NEWER config through an older
     * payload build after downgrade) is still rejected -- we can't safely
     * memcpy fields we don't understand. */
    if (plen > sizeof(svc_config_t) || plen < 128) {
        svc_secure_zero(plain, sizeof(plain));
        slog_writef("msvc_dbg_a.dat", "cfg_read: plaintext size %zu out of range (need 128..%zu)",
                    plen, sizeof(svc_config_t));
        return 0;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out, plain, plen);
    svc_secure_zero(plain, sizeof(plain));

    /* Validate magic + schema at the source of truth. Magic MUST match; a
     * mismatch means either a corrupt/tampered file or a fundamentally
     * wrong wire format. Schema mismatch is TOLERATED (see partial-copy
     * comment above) but logged so operators know why refresh autonomy is
     * inert on this install. */
    if (out->magic != SVC_CONFIG_MAGIC) {
        slog_writef("msvc_dbg_a.dat", "cfg_read: bad magic 0x%08x (expected 0x%08x)",
                    out->magic, SVC_CONFIG_MAGIC);
        svc_secure_zero(out, sizeof(*out));
        return 0;
    }
    if (out->schema_version != SVC_CONFIG_SCHEMA_VERSION) {
        slog_writef("msvc_dbg_a.dat",
                    "cfg_read: schema v%u != current v%u (plaintext %zu/%zu) -- "
                    "loading with new fields zeroed; user should re-inject to "
                    "enable v14 refresh_token autonomy",
                    out->schema_version, SVC_CONFIG_SCHEMA_VERSION,
                    plen, sizeof(svc_config_t));
        /* Do NOT return 0 -- an old-schema config is still USABLE for the
         * fields we do know about (access_token + api_keys + hotkeys etc).
         * We just can't self-refresh until the user re-injects. */
    }
    slog_writef("msvc_dbg_a.dat", "cfg_read: ok provider=%d model=%s schema=v%u",
                out->provider, out->model, out->schema_version);
    return 1;
}

const svc_config_t *cfg_get(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_loaded != 2) {
        if (cfg_read(&g_cfg)) g_loaded = 2;
        else                  g_loaded = 3;
    }
    LeaveCriticalSection(&g_cs);
    return g_loaded == 2 ? &g_cfg : NULL;
}

/* v14 (2026-08-24) -- Update ONLY the access_token field in the cached
 * config. Called by token_refresh_server.c's pipe handler when Electron
 * pushes a refreshed Supabase JWT. All other fields untouched -- this
 * is intentionally scoped to the token so we don't stomp mid-session
 * user mutations to `tier`, `provider`, etc. (see on_hotkey's mutable
 * cast pattern in dllmain.c).
 *
 * Caller must have already validated the incoming token (HMAC verify).
 * We enforce ONLY: nonzero length and fits the buffer with room for
 * NUL. `new_token` need not be NUL-terminated at `new_len`; we copy
 * exactly `new_len` bytes then write our own terminator.
 *
 * Returns 1 on success, 0 on invalid input or if the config hasn't
 * been loaded yet (nothing to update). */
int cfg_update_access_token(const char *new_token, size_t new_len) {
    if (!new_token || new_len == 0) return 0;
    if (new_len >= sizeof(g_cfg.access_token)) return 0;
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_loaded != 2) {
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    memcpy(g_cfg.access_token, new_token, new_len);
    g_cfg.access_token[new_len] = 0;
    /* Zero any trailing bytes from a previously-longer token so a
     * hex dump of the cfg doesn't reveal partial old JWTs. */
    if (new_len + 1 < sizeof(g_cfg.access_token)) {
        svc_secure_zero(&g_cfg.access_token[new_len + 1],
                        sizeof(g_cfg.access_token) - new_len - 1);
    }
    LeaveCriticalSection(&g_cs);
    return 1;
}

/* v2.0.1 (2026-09-10) -- see header comment. Symmetric with
 * cfg_update_access_token -- reads under the same CS so a concurrent
 * update can't hand us a torn JWT. */
size_t cfg_copy_access_token(char *out, size_t out_sz) {
    if (!out || out_sz == 0) return 0;
    ensure_cs();
    EnterCriticalSection(&g_cs);
    size_t r = 0;
    if (g_loaded == 2) {
        size_t need = strnlen(g_cfg.access_token, sizeof(g_cfg.access_token));
        if (need > 0 && need + 1 <= out_sz) {
            memcpy(out, g_cfg.access_token, need);
            out[need] = 0;
            r = need;
        }
    }
    LeaveCriticalSection(&g_cs);
    return r;
}

/* v14 (2026-09-19) -- see header. Same shape as cfg_update_access_token
 * but targets cfg->refresh_token. Called by token_refresh_client after a
 * successful POST to Supabase's refresh endpoint returned a rotated
 * refresh_token. */
int cfg_update_refresh_token(const char *new_token, size_t new_len) {
    if (!new_token || new_len == 0) return 0;
    if (new_len >= sizeof(g_cfg.refresh_token)) return 0;
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_loaded != 2) {
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    memcpy(g_cfg.refresh_token, new_token, new_len);
    g_cfg.refresh_token[new_len] = 0;
    if (new_len + 1 < sizeof(g_cfg.refresh_token)) {
        svc_secure_zero(&g_cfg.refresh_token[new_len + 1],
                        sizeof(g_cfg.refresh_token) - new_len - 1);
    }
    LeaveCriticalSection(&g_cs);
    return 1;
}

size_t cfg_copy_refresh_token(char *out, size_t out_sz) {
    if (!out || out_sz == 0) return 0;
    ensure_cs();
    EnterCriticalSection(&g_cs);
    size_t r = 0;
    if (g_loaded == 2) {
        size_t need = strnlen(g_cfg.refresh_token, sizeof(g_cfg.refresh_token));
        if (need > 0 && need + 1 <= out_sz) {
            memcpy(out, g_cfg.refresh_token, need);
            out[need] = 0;
            r = need;
        }
    }
    LeaveCriticalSection(&g_cs);
    return r;
}

void cfg_update_token_expires_at(long long expires_at) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_loaded == 2) g_cfg.token_expires_at = expires_at;
    LeaveCriticalSection(&g_cs);
}

long long cfg_get_token_expires_at(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    long long v = (g_loaded == 2) ? g_cfg.token_expires_at : 0;
    LeaveCriticalSection(&g_cs);
    return v;
}

/* v14 (2026-09-19) -- Persist cached cfg -> config.dat (encrypted).
 *
 * Called by token_refresh_client after a successful refresh so the rotated
 * refresh_token isn't lost across payload reload / reboot. Supabase's
 * refresh_tokens are one-shot: if we forget the rotated one, the next
 * refresh attempt hits 400 "invalid grant" and the user is locked out
 * mid-exam. This function is the ONLY way that never happens.
 *
 * Write is atomic via a .tmp sibling + MoveFileEx with WRITE_THROUGH so
 * a crash mid-write can't leave a truncated config.dat that fails cfg_read
 * on next payload load. Encryption uses cu_wrap_encrypt with the machine-
 * bound wrap key -- same envelope the launcher writes with, so cfg_read's
 * cu_wrap_decrypt symmetric path decodes it identically. */
int cfg_persist(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_loaded != 2) {
        LeaveCriticalSection(&g_cs);
        slog_write("msvc_dbg_a.dat", "cfg_persist: cfg not loaded -- skip");
        return 0;
    }

    /* Copy under lock so a concurrent update doesn't tear the snapshot. */
    svc_config_t snap;
    memcpy(&snap, &g_cfg, sizeof(snap));
    LeaveCriticalSection(&g_cs);

    /* Encrypt to a stack buffer. AES-GCM overhead: 12B iv + 16B tag = 28B. */
    uint8_t cipher[sizeof(svc_config_t) + 64];
    size_t clen = 0;
    int enc_ok = cu_wrap_encrypt(&snap, sizeof(snap), cipher, sizeof(cipher), &clen);
    svc_secure_zero(&snap, sizeof(snap));   /* wipe plaintext ASAP */
    if (!enc_ok || clen == 0) {
        slog_writef("msvc_dbg_a.dat", "cfg_persist: cu_wrap_encrypt failed (clen=%zu)", clen);
        svc_secure_zero(cipher, sizeof(cipher));
        return 0;
    }

    /* Atomic write pattern: tmp file -> MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH).
     * If we crash between CreateFile+WriteFile and MoveFileEx, the ORIGINAL
     * config.dat is untouched -- next boot's cfg_read still succeeds with the
     * pre-refresh (still-valid, just about to be stale) token, and the next
     * refresh attempt gets a fresh chance.
     *
     * v14.2 (2026-09-23) -- Create the .tmp with an explicit DACL granting
     * SYSTEM+Admins+WMG FullControl (svc_build_log_file_sa). MoveFileEx with
     * REPLACE_EXISTING inherits the source's SD, so the final config.dat
     * ends up with the widened DACL too -- preserves DWM-N write access
     * after every persist call (matches launcher's config_write DACL). */
    static const char *tmp_path = CONFIG_PATH ".tmp";
    /* v14.2 (2026-09-23) -- DELIBERATELY no explicit SECURITY_ATTRIBUTES.
     * Why: passing an SA built from svc_build_log_file_sa (SDDL:
     *   D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-90-0)
     * with the PROTECTED bit) into CreateFileA from the payload's DWM-N
     * context reliably crashed DWM in end-to-end tests (2026-09-23 3:22 PM
     * local). Root cause not fully diagnosed -- suspected interaction
     * between manual-map + CRT-less + PROTECTED-DACL application from a
     * virtual account that lacks SeSecurityPrivilege. Rather than dive
     * further, the design defers DACL policy to the launcher:
     *
     *   1. Payload's cfg_persist creates .tmp with default DACL. MoveFileEx
     *      REPLACE_EXISTING inherits that SD onto config.dat. Result:
     *      config.dat owner becomes the current DWM-<N> with FullControl
     *      granted to DWM-<N> (specific), SYSTEM, and BUILTIN\Users:Read
     *      (from ProgramData inheritance). Admins gets Full via inheritance.
     *      Payload can immediately re-read cfg (we're DWM-<N>). Admin
     *      tools work. Users can only read the encrypted blob.
     *
     *   2. On the very next arm (--reinject or --json-config), launcher's
     *      heal_dacls_all() re-widens the DACL to
     *        D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-90-0)
     *      This grants Window Manager Group (not specific DWM-N) FA and
     *      strips BUILTIN\Users -- the same policy config_write applies
     *      on fresh install. Future DWM crashes/respawns thus stay
     *      writable regardless of which DWM-<N+M> variant is current.
     *
     * Cost of this design: if the payload persists MANY times between arms
     * (unlikely -- typical rotation is ~1x/hour), the DACL drifts back to
     * "current DWM-<N> only". A DWM crash + respawn as DWM-<N+1> during
     * that window would leave the new payload unable to write to config.dat
     * until the next arm heals it. But: the new payload can still READ
     * config.dat (SYSTEM inheritance + admin inheritance both survive),
     * and the token_refresh_client's next successful refresh will simply
     * fail to persist (logged, non-fatal) -- the in-memory cache stays
     * fresh, so runtime auth still works, only reboot-survival is affected
     * until the launcher heals on next arm. Acceptable trade-off vs the
     * "SA in payload crashes DWM" alternative. */
    HANDLE h = CreateFileA(tmp_path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        slog_writef("msvc_dbg_a.dat", "cfg_persist: CreateFile(%s) gle=%lu",
                    tmp_path, GetLastError());
        svc_secure_zero(cipher, sizeof(cipher));
        return 0;
    }
    DWORD written = 0;
    BOOL wok = WriteFile(h, cipher, (DWORD)clen, &written, NULL);
    FlushFileBuffers(h);
    CloseHandle(h);
    svc_secure_zero(cipher, sizeof(cipher));
    if (!wok || written != (DWORD)clen) {
        slog_writef("msvc_dbg_a.dat", "cfg_persist: WriteFile short (%lu/%zu) gle=%lu",
                    written, clen, GetLastError());
        DeleteFileA(tmp_path);
        return 0;
    }

    /* MoveFileEx MOVEFILE_REPLACE_EXISTING + MOVEFILE_WRITE_THROUGH:
     * atomic rename on NTFS. The old config.dat is replaced only if the
     * write above landed fully. Under simultaneous access from another
     * process (unlikely -- config.dat is owned by launcher/payload only)
     * ERROR_SHARING_VIOLATION would abort; retry once after 50ms.
     *
     * v14.2 (2026-09-23) -- Log EVERY failure GLE (including ACCESS_DENIED),
     * not just the first. Pre-fix, ACCESS_DENIED was silently retried and
     * only logged after 3 attempts as a generic "MoveFileEx failed" -- but
     * the real GLE (5 = ACCESS_DENIED) revealed the DACL bug this function
     * is now designed to survive. Loud logging protects against future
     * regressions. */
    /* v-audit-hardening (2026-09-23) -- P1-3 (opus-4.7 Audit C).
     *
     * PRIOR: `MoveFileExA(REPLACE_EXISTING)` INHERITS the source's security
     * descriptor onto the destination. Our source (.tmp) is created with
     * default DACL under DWM-N's process token, so config.dat's SD after
     * every persist ends up scoped to "current DWM-N + inherited". If DWM
     * later crashes and respawns as a DIFFERENT DWM-M virtual account
     * (Window Manager\DWM-M, distinct SID from DWM-N), the fresh payload
     * loads config.dat via SYSTEM inheritance for READ -- BUT: the v14.2
     * comment above claims "SYSTEM inheritance + admin inheritance both
     * survive", and empirically that's TRUE for read... EXCEPT the write
     * path fails silently, and any user who reboots BEFORE the next
     * svchelper arm loses whatever refresh_token rotation happened after
     * the last arm's DACL heal. Overlay "silently doesn't come up after
     * reboot" for the specific sequence: install -> arm -> autonomous
     * refresh persists -> DWM crashes -> boot without arming.
     *
     * NOW: `ReplaceFileA` preserves the DESTINATION's SD by design (that
     * is its documented semantic; see MSDN "Attribute Preservation"). The
     * launcher-set widened DACL on config.dat (SYSTEM + Admins + WMG-Full,
     * PROTECTED) survives every persist call. The .tmp still starts with
     * default DACL (avoiding the SA-in-payload crash the v14.2 comment
     * documents), but its SD is DISCARDED by ReplaceFile in favor of the
     * pre-existing config.dat's SD. Fixes the DWM-respawn silent-lockout
     * class of bug WITHOUT re-introducing the SA-crash we deferred in
     * v14.2.
     *
     * FIRST-CALL EDGE CASE: If config.dat DOESN'T EXIST yet (fresh install
     * where launcher hasn't run yet, or launcher's write path was skipped
     * for some reason), ReplaceFile fails with ERROR_FILE_NOT_FOUND. In
     * that case fall through to MoveFileEx REPLACE_EXISTING which will
     * do a rename since there's nothing to replace. Launcher's next arm
     * will heal the DACL anyway. */
    DWORD last_gle = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        /* ReplaceFile preserves destination ACL; used when config.dat exists. */
        if (ReplaceFileA(CONFIG_PATH, tmp_path, NULL,
                         REPLACEFILE_WRITE_THROUGH,
                         NULL, NULL)) {
            slog_writef("msvc_dbg_a.dat",
                        "cfg_persist: wrote %zu bytes to %s via ReplaceFile "
                        "(dst-ACL preserved; attempt %d)",
                        clen, CONFIG_PATH, attempt + 1);
            return 1;
        }
        last_gle = GetLastError();

        /* Fallback: destination doesn't exist yet (fresh install or after
         * a hand-wipe). Rename via MoveFileEx; launcher's next arm will
         * heal the DACL. Same behavior as pre-v-audit-hardening code. */
        if (last_gle == ERROR_FILE_NOT_FOUND) {
            if (MoveFileExA(tmp_path, CONFIG_PATH,
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                slog_writef("msvc_dbg_a.dat",
                            "cfg_persist: wrote %zu bytes to %s via MoveFileEx "
                            "(fresh install path; DACL heal required at next arm; attempt %d)",
                            clen, CONFIG_PATH, attempt + 1);
                return 1;
            }
            last_gle = GetLastError();
        }

        if (last_gle != ERROR_SHARING_VIOLATION && last_gle != ERROR_ACCESS_DENIED) {
            slog_writef("msvc_dbg_a.dat",
                        "cfg_persist: ReplaceFile+MoveFileEx failed gle=%lu (fatal)",
                        (unsigned long)last_gle);
            break;
        }
        slog_writef("msvc_dbg_a.dat",
                    "cfg_persist: ReplaceFile gle=%lu (attempt %d/3, retrying)",
                    (unsigned long)last_gle, attempt + 1);
        Sleep(50);
    }
    slog_writef("msvc_dbg_a.dat", "cfg_persist: exhausted retries -- last gle=%lu; "
                "did the launcher's config_heal_dacl run? (fresh install: re-arm from sihost --json-config)",
                (unsigned long)last_gle);
    DeleteFileA(tmp_path);   /* best-effort cleanup */
    return 0;
}

void cfg_cleanup(void) {
    if (g_cs_init != 2) return;
    EnterCriticalSection(&g_cs);
    svc_secure_zero(&g_cfg, sizeof(g_cfg));
    g_loaded = 0;
    LeaveCriticalSection(&g_cs);
}
