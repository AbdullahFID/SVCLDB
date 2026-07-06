/* ================================================================== *
 * handshake.h — Electron<->launcher<->payload handshake token.        *
 *                                                                    *
 * Purpose: prevent bypass of the Electron login flow. Only a caller  *
 * that holds a REAL Supabase access token AND runs on the same       *
 * machine (HWID match) can produce a token the payload accepts.      *
 *                                                                    *
 * Derivation:                                                        *
 *   sig_key = SHA-256(access_token || "svcldb-handshake-v1")         *
 *   msg     = hwid || ":" || epoch_day_decimal                       *
 *   token   = HMAC-SHA-256(sig_key, msg)   -> 32 bytes               *
 *                                                                    *
 * The Electron UI generates the token and writes it into config.dat  *
 * alongside the access token, HWID, and epoch_day. The payload       *
 * recomputes on init and refuses to install hooks if the token is    *
 * missing, invalid, or the epoch_day is outside {today, yesterday}.  *
 *                                                                    *
 * Attack surface:                                                    *
 *   1. Stealing config.dat: bound to HWID via wrap_encrypt AND via   *
 *      the handshake HWID field. Both must match the current box.    *
 *   2. Crafting a fake token: requires the access_token, which is    *
 *      only issued after a real Google OAuth via Supabase.           *
 *   3. Replaying a stale token: valid for at most 48 hours (today +  *
 *      yesterday grace) — after that user must re-authenticate.      *
 *                                                                    *
 * NOT a replacement for network verification (subscription check     *
 * still runs against Supabase on every login) — but it stops all     *
 * offline CLI paths from injecting without an active session.        *
 * ================================================================== */
#ifndef SVCLDB_HANDSHAKE_H
#define SVCLDB_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wire-format constants — MUST match the JS implementation in
 * ui/src/license/handshake.js. Change either side and the payload
 * will reject every token until both sides are rebuilt. */
#define SVCLDB_HANDSHAKE_TOKEN_LEN   32
#define SVCLDB_HANDSHAKE_SALT        "svcldb-handshake-v1"
#define SVCLDB_HANDSHAKE_GRACE_DAYS  1   /* accept today OR yesterday */

/* Compute the 32-byte handshake token for a given (access_token, hwid,
 * epoch_day) triple. Returns 1 on success, 0 on parameter/crypto error.
 *
 * access_token: NUL-terminated Supabase JWT (up to 4095 bytes).
 * hwid:         NUL-terminated HWID string (typically SMBIOS UUID).
 * epoch_day:    floor(unix_time / 86400) at generation time.
 * out_token:    receives 32 raw bytes. */
int handshake_compute(const char *access_token,
                      const char *hwid,
                      int64_t     epoch_day,
                      uint8_t     out_token[SVCLDB_HANDSHAKE_TOKEN_LEN]);

/* Verify a token against today and yesterday. Returns 1 iff the token
 * matches either recomputation (timing-safe compare). Returns 0 if
 * either input is empty, if the crypto fails, or if the token doesn't
 * match either day.
 *
 * This is what the payload calls in init_thread. Do NOT log the token
 * on failure — a hostile debugger reading the log could correlate. */
int handshake_verify(const char *access_token,
                     const char *hwid,
                     const uint8_t token[SVCLDB_HANDSHAKE_TOKEN_LEN]);

/* Current UNIX epoch day. Deterministic across processes with the
 * same system clock. Both sides of the handshake must call this to
 * agree on which day the token belongs to. */
int64_t handshake_current_epoch_day(void);

#ifdef __cplusplus
}
#endif

#endif  /* SVCLDB_HANDSHAKE_H */
