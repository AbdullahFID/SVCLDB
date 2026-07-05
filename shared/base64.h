/* base64 encode/decode — standard alphabet + URL-safe variant. */
#ifndef SVCLDB_BASE64_H
#define SVCLDB_BASE64_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* out must have at least ((inlen+2)/3)*4 + 1 bytes.
 * Writes NUL terminator. Returns bytes written (excluding NUL). */
size_t b64_encode_std (const uint8_t *in, size_t inlen, char *out);
size_t b64_encode_url (const uint8_t *in, size_t inlen, char *out);

/* Decode returns bytes written or -1 on invalid input.
 * out must have at least ((inlen+3)/4)*3 bytes.
 * Accepts both '+/' and '-_' alphabets; ignores whitespace + trailing '='. */
int    b64_decode_any (const char *in, size_t inlen, uint8_t *out, size_t outmax);

#ifdef __cplusplus
}
#endif

#endif
