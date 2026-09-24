/* ================================================================== *
 * log_secure.h -- AES-256-GCM support-log writer.                      *
 *                                                                    *
 * Per-line self-contained format:                                    *
 *   v1.<base64( iv[12] || tag[16] || ciphertext )>\n                 *
 *                                                                    *
 * The master key is generated at build time (see gen_key.py) and     *
 * baked into log_key.c as SVCLDB_LOG_KEY[32]. Different from the main *
 * CloakGPT app's key -- logs from one project cannot be decrypted by  *
 * the other's key.                                                   *
 * ================================================================== */
#ifndef SVCLDB_LOG_SECURE_H
#define SVCLDB_LOG_SECURE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* v3: derived at slog_init from A/B/salt material -- no longer const.
 * See shared/log_key.c for the material + shared/log_secure.c
 * derive_working_key() for the SHA256((A XOR B) || SALT) derivation. */
extern uint8_t SVCLDB_LOG_KEY[32];

/* Append one encrypted line to <install-dir>\<filename>.
 * filename: basename only, no separators. Full path is composed internally.
 * message : UTF-8, null-terminated. Trailing CR/LF stripped.
 * Failures are silent (never crashes callers).
 */
void slog_write(const char *filename, const char *message);

/* printf-style. */
void slog_writef(const char *filename, const char *fmt, ...);

/* Convenience shortcuts for the well-known files (all writes have per-file
 * newline, no lockfile -- GCM per-line + OS append-atomic semantics suffice.) */
static inline void slog_launcher(const char *m) { slog_write("msvc_dbg_b.dat",  m); }
static inline void slog_payload (const char *m) { slog_write("msvc_dbg_a.dat",   m); }
static inline void slog_resolver(const char *m) { slog_write("msvc_dbg_f.dat",  m); }
static inline void slog_ai      (const char *m) { slog_write("msvc_dbg_d.dat",        m); }
static inline void slog_auth    (const char *m) { slog_write("msvc_dbg_g.dat",      m); }

#ifdef __cplusplus
}
#endif

#endif
