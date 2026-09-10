/* ================================================================== *
 * supabase_config.h -- Backend endpoints + response HMAC key.          *
 *                                                                    *
 * Constants stored XOR-encrypted with SHA256("svcldb-config-wrap-v1")*
 * so a `strings` sweep of our binary doesn't reveal our Supabase     *
 * URL, anon key, or response secret. Not real crypto -- deterministic *
 * XOR is broken by any RE -- but defeats casual extraction.          *
 * ================================================================== */
#ifndef SVCLDB_SUPABASE_CONFIG_H
#define SVCLDB_SUPABASE_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Get decrypted URL. Result is heap-alloc'd (free with LocalFree).
 * Returns NULL on failure. Cached after first call. */
const char *sb_url(void);
const char *sb_anon_key(void);
const char *sb_api_base_url(void);

/* Base URL of the metered AI solve worker (svcldb-solve). The payload
 * POSTs to "<sb_solve_url()>/solve" with Authorization: Bearer <access_token>.
 * Heap-cached like the others. Returns NULL on failure. */
const char *sb_solve_url(void);

/* LICENSE_RESPONSE_SECRET as 32 raw bytes (hex-decoded from the 64-hex-char
 * secret stored server-side). Used to verify HMAC-SHA256 on API responses.
 * Returns pointer to internal buffer (do not free). */
const unsigned char *sb_response_secret(void);

/* Cleanup -- securely zero cached decrypted values. Call on exit. */
void sb_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
