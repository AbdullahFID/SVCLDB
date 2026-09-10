/* ================================================================== *
 * winhttp_util.h -- HTTPS request wrapper (WinHTTP).                   *
 *                                                                    *
 * Simple synchronous request layer used by:                          *
 *  - OAuth token exchange                                            *
 *  - Supabase REST subscription check                                *
 *  - AI provider requests (OpenAI / Anthropic / Google / Openrouter) *
 *                                                                    *
 * Streaming callback variant for AI SSE responses.                   *
 * ================================================================== */
#ifndef SVCLDB_WINHTTP_UTIL_H
#define SVCLDB_WINHTTP_UTIL_H

#include "common.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned status;       /* HTTP status; 0 on transport failure */
    char    *body;         /* malloc'd; caller must whreq_free_result */
    size_t   body_len;
    char    *header_signature; /* value of x-response-signature header if present, or NULL */
    char     err[256];     /* human-readable error on failure */
} whreq_result_t;

/* Free a whreq_result_t's owned buffers (does not free r itself). */
void whreq_free_result(whreq_result_t *r);

/* Simple synchronous GET.
 * url    : full https URL (must be https, http is rejected)
 * headers: array of "Header-Name: value" strings, terminated with NULL. May be NULL.
 * out    : filled with status + body. On error status=0, err populated.
 * Returns 1 if the HTTP roundtrip completed (status may still be 4xx/5xx),
 * 0 on transport-level failure (out->err populated).
 */
int whreq_get(const char *url, const char **headers, whreq_result_t *out);

/* Simple synchronous POST.
 * body    : request body (may be NULL if body_len==0)
 * body_len: length in bytes
 * headers : "Content-Type: ..." should be included by caller
 */
int whreq_post(const char *url, const char **headers,
               const void *body, size_t body_len,
               whreq_result_t *out);

/* Streaming POST for SSE (OpenAI stream mode, etc.).
 * on_chunk fires for every read of data; return 0 to keep streaming,
 * non-zero to abort. userdata is passed through.
 */
typedef int (*whreq_chunk_cb)(const uint8_t *data, size_t len, void *userdata);

int whreq_post_stream(const char *url, const char **headers,
                      const void *body, size_t body_len,
                      whreq_chunk_cb cb, void *userdata,
                      unsigned *out_status, char *out_err, size_t err_size);

/* Same as whreq_post_stream but lets the caller override the per-chunk
 * WinHTTP receive timeout. Use this for reasoning-model responses that
 * can go long minutes between SSE tokens (o3, gpt-5.5-pro, opus, gemini-3.1-pro).
 *
 * receive_timeout_ms is passed to WinHttpSetTimeouts's dwReceiveTimeout
 * parameter which applies PER WinHttpReadData call -- i.e. "no data for
 * this long between chunks kills the stream". Pass 0 to inherit the
 * default (20_000 ms). Recommended: 900_000 (15 min) for reasoning models,
 * 60_000 (1 min) for fast models.
 *
 * Also fills out_headers (heap-alloc'd raw header block, caller frees with
 * LocalFree) so the caller can inspect Retry-After on 429 responses.
 * Pass NULL if the header block isn't needed. */
int whreq_post_stream_ex(const char *url, const char **headers,
                         const void *body, size_t body_len,
                         DWORD receive_timeout_ms,
                         whreq_chunk_cb cb, void *userdata,
                         unsigned *out_status,
                         char **out_headers,
                         char *out_err, size_t err_size);

/* Same idea for non-streaming POST/GET -- receive_timeout_ms overrides
 * dwReceiveTimeout. out_headers same contract as above. */
int whreq_post_ex(const char *url, const char **headers,
                  const void *body, size_t body_len,
                  DWORD receive_timeout_ms,
                  whreq_result_t *out);

int whreq_get_ex(const char *url, const char **headers,
                 DWORD receive_timeout_ms,
                 whreq_result_t *out);

/* Parse the Retry-After header value returned by 429s. Returns the
 * suggested wait in milliseconds, or 0 if the header is missing or
 * unparseable. Handles OpenAI's `retry-after-ms` (raw ms) and the RFC
 * standard `retry-after` (seconds, integer OR HTTP-date). Anthropic +
 * Google use seconds. */
DWORD whreq_parse_retry_after_ms(const char *headers_raw);

/* Parse a "Header-Name" from a raw header block.
 * Case-insensitive name match.
 * value_out is a heap-alloc'd string (must free with LocalFree) or NULL if not found. */
char *whreq_find_header(const char *headers_raw, const char *name);

#ifdef __cplusplus
}
#endif

#endif
