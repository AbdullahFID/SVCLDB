/* ================================================================== *
 * json_util.h — Minimal JSON parse + build.                           *
 *                                                                    *
 * Not a full JSON library — just enough for:                         *
 *   - reading Supabase token responses (access_token, refresh_token) *
 *   - reading subscription arrays                                    *
 *   - building AI request bodies (messages, model, max_tokens)       *
 *                                                                    *
 * Zero deps. Handles UTF-8 (pass-through). Numbers are treated as    *
 * strings for simplicity.                                            *
 * ================================================================== */
#ifndef SVCLDB_JSON_UTIL_H
#define SVCLDB_JSON_UTIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Find a string value for a top-level JSON object key.
 * Handles: escaped quotes (\"), backslash escapes (\\, \n, \t, \r, \/),
 * unicode escapes (\uXXXX — decoded to UTF-8 in out).
 *
 * json    : must be a JSON object (or contain one)
 * key     : bare key, no quotes
 * out     : receives unescaped UTF-8 value (NUL-terminated)
 * outsize : capacity of out
 *
 * Returns 1 if found + written, 0 otherwise (out untouched on 0).
 * Ignores nesting: matches the FIRST top-level occurrence of key. */
int json_get_str(const char *json, const char *key, char *out, size_t outsize);

/* Find a numeric value; returns 1 if found + parsed to double.
 * Handles ints, floats, exponents. */
int json_get_num(const char *json, const char *key, double *out);

/* Find a bool value; returns 1 if found. Sets *out to 1 or 0. */
int json_get_bool(const char *json, const char *key, int *out);

/* Test whether an array key exists AND has at least one element.
 * Useful for Supabase REST responses which return arrays of matching rows. */
int json_has_nonempty_array_or_object(const char *json);

/* Find the first object inside an array at the top level; sets *object_start/end
 * to the [start, end) byte range of "{ ... }" including braces.
 * Returns 1 if found. */
int json_first_array_object(const char *json,
                            const char **object_start, const char **object_end);

/* ── JSON builder ─────────────────────────────────────────────────── */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    int    err;
    int    depth;
    int    needs_comma;
} json_builder_t;

int   jb_init  (json_builder_t *b, size_t initial_cap);
void  jb_free  (json_builder_t *b);

int   jb_obj_begin(json_builder_t *b);
int   jb_obj_end  (json_builder_t *b);
int   jb_arr_begin(json_builder_t *b);
int   jb_arr_end  (json_builder_t *b);

int   jb_key      (json_builder_t *b, const char *key);
int   jb_str      (json_builder_t *b, const char *value);
int   jb_num_i    (json_builder_t *b, long long value);
int   jb_num_d    (json_builder_t *b, double value);
int   jb_bool     (json_builder_t *b, int value);
int   jb_null     (json_builder_t *b);

/* Raw JSON literal (caller-verified). Use for pre-serialized fragments. */
int   jb_raw      (json_builder_t *b, const char *raw);

#ifdef __cplusplus
}
#endif

#endif
