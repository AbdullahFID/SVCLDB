/* ================================================================== *
 * bind_secret.h -- per-install 32-byte HMAC secret.                   *
 *                                                                    *
 * v3.2 (2026-09-23) after medium-IL red-team pass.                   *
 *                                                                    *
 * WHY:                                                                *
 *   Prior obf_names.c derivation was:                                *
 *     guid = SHA256(salt_string || ":" || machine_guid)[0..15]       *
 *   All three inputs are readable by any local user:                 *
 *     - salt_string:   ASCII inside sihost.exe / dwmapiext.dll       *
 *     - machine_guid:  HKLM\SOFTWARE\Microsoft\Cryptography\...      *
 *   So a medium-IL attacker could derive every named-object name we  *
 *   use, then probe them to detect the payload is loaded (proven     *
 *   live 2026-09-23 in tools/redteam/runtime/attack_medium_*.json).  *
 *                                                                    *
 * NEW derivation:                                                     *
 *   guid = HMAC-SHA256(bind_secret, salt || ":" || machine_guid)[0..15] *
 *                                                                    *
 * bind_secret is 32 random bytes generated at first install and     *
 * stored in %ProgramData%\WinAudioSvc\_bind.bin with DACL restricted *
 * to BUILTIN\Administrators and NT AUTHORITY\SYSTEM only. Medium-IL *
 * Users get ACCESS_DENIED reading the file, so they cannot compute  *
 * the HMAC and every derived name becomes unpredictable to them.    *
 *                                                                    *
 * Elevated svchelper (Electron) can read (Administrators).           *
 * Payload in dwm.exe (SYSTEM) can read.                              *
 * Winlogon-hosted helper (SYSTEM) can read.                          *
 * That's every legitimate consumer.                                  *
 *                                                                    *
 * Backward compat during upgrade: if _bind.bin doesn't exist yet or  *
 * can't be read (rare -- read failure would be a DACL misconfig), we *
 * fall back to a fixed compile-time DEFAULT_BIND. The payload always *
 * creates objects using whatever derivation succeeds first, and all  *
 * clients (launcher + Electron + helper) do the same. So mismatched  *
 * clients (one has _bind.bin, one doesn't) simply can't talk -- that *
 * is safer than the old world-derivable names.                       *
 * ================================================================== */
#ifndef SVCLDB_BIND_SECRET_H
#define SVCLDB_BIND_SECRET_H

#include <windows.h>
#include <stdint.h>

/* Read the current bind secret (32 bytes). Returns 1 on success, 0 on
 * failure. Cached: first successful read is memoized process-wide, so
 * subsequent calls return the cached bytes without touching disk. */
int svc_bind_secret_read(uint8_t out[32]);

/* Ensure %ProgramData%\WinAudioSvc\_bind.bin exists with 32 random
 * bytes and a DACL granting FullControl to Administrators+SYSTEM only.
 * Called by the launcher at every arm path (--json-config, --reinject).
 * Idempotent: existing file with >= 32 bytes is left alone (rotating
 * the secret would rename every named object, breaking every currently-
 * connected pipe/event -- destructive to running payload; only regen
 * during install / upgrade).
 * Returns 1 on success (file exists after call), 0 on failure. */
int svc_bind_secret_ensure(void);

/* Test hook: force cache invalidation so a subsequent svc_bind_secret_read
 * re-reads from disk. Not intended for production use. */
void svc_bind_secret_reset_cache(void);

#endif /* SVCLDB_BIND_SECRET_H */
