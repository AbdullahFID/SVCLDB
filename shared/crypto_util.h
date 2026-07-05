/* ================================================================== *
 * crypto_util.h — HMAC-SHA256, PKCE, random bytes, machine-bound     *
 * config encryption (BCrypt).                                        *
 * ================================================================== */
#ifndef SVCLDB_CRYPTO_UTIL_H
#define SVCLDB_CRYPTO_UTIL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fill buf with cryptographically strong random bytes. Returns 1/0. */
int  cu_random(uint8_t *buf, size_t len);

/* SHA-256. out must be 32 bytes. Returns 1/0. */
int  cu_sha256(const void *data, size_t len, uint8_t out[32]);

/* HMAC-SHA-256. out must be 32 bytes. Returns 1/0. */
int  cu_hmac_sha256(const uint8_t *key, size_t key_len,
                    const void *data, size_t data_len,
                    uint8_t out[32]);

/* Timing-safe byte compare (0 = equal). */
int  cu_ct_eq(const void *a, const void *b, size_t len);

/* Hex encode. out must be len*2+1 bytes; NUL-terminated. */
void cu_to_hex(const uint8_t *bytes, size_t len, char *out);

/* Hex decode. Returns bytes written or -1 on invalid input. */
int  cu_from_hex(const char *hex, uint8_t *out, size_t outmax);

/* ── PKCE helpers ── */
/* Generate a 32-byte verifier + emit base64url of it in out_verifier (44 chars).
 * out_verifier must be >= 44 chars. Returns 1/0. */
int  cu_pkce_verifier(char out_verifier[64]);
/* Compute PKCE challenge (base64url of SHA-256(verifier)) from verifier string.
 * out_challenge must be >= 44 chars. Returns 1/0. */
int  cu_pkce_challenge(const char *verifier, char out_challenge[64]);

/* ── Machine-bound AES-256-GCM (DPAPI-equivalent) ── */
/* Wrap key = SHA-256("svcldb-config-wrap-v2" || MachineGuid || HostName || UserName).
 * Deterministic per machine+user; stealing the ciphertext to another machine
 * yields decrypt failure. Wraps opaque bytes (like the license session token). */
int  cu_wrap_encrypt(const void *plain, size_t plain_len,
                     uint8_t *out, size_t outmax, size_t *out_len);
int  cu_wrap_decrypt(const uint8_t *cipher, size_t cipher_len,
                     uint8_t *out, size_t outmax, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
