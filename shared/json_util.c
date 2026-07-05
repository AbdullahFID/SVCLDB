/* ================================================================== *
 * json_util.c — Minimal JSON parse + build.                           *
 * ================================================================== */

#include "json_util.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

/* ─── Parser ─────────────────────────────────────────────────────── */

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

/* Skip a JSON string starting at *p (which must point at the opening '"').
 * Advances past the closing '"'. Handles \" and other escapes.
 * Returns new position or NULL on syntax error. */
static const char *skip_str(const char *p) {
    if (*p != '"') return NULL;
    p++;
    while (*p) {
        if (*p == '\\' && p[1]) { p += 2; continue; }
        if (*p == '"') return p + 1;
        p++;
    }
    return NULL;
}

/* Skip any JSON value starting at *p (whitespace already skipped).
 * Returns new position (immediately after the value) or NULL. */
static const char *skip_value(const char *p) {
    p = skip_ws(p);
    if (*p == '"') return skip_str(p);
    if (*p == '{' || *p == '[') {
        char open = *p, close = (open == '{' ? '}' : ']');
        int depth = 1;
        p++;
        while (*p && depth > 0) {
            p = skip_ws(p);
            if (*p == '"') { p = skip_str(p); if (!p) return NULL; continue; }
            if (*p == open)  { depth++; p++; continue; }
            if (*p == close) { depth--; p++; continue; }
            p++;
        }
        return depth == 0 ? p : NULL;
    }
    /* Number / true / false / null — consume until delimiter. */
    while (*p && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
    return p;
}

/* Find the value of `key` in a top-level object. Returns pointer to first char
 * of the value (after ':' + ws), or NULL. */
static const char *find_key(const char *json, const char *key) {
    if (!json || !key) return NULL;
    size_t klen = strlen(key);
    const char *p = json;

    /* Advance to the top-level '{'. */
    p = skip_ws(p);
    if (*p != '{') return NULL;
    p++;

    while (*p) {
        p = skip_ws(p);
        if (*p == '}') return NULL;
        if (*p != '"') return NULL;
        const char *k_start = p + 1;
        const char *k_end   = skip_str(p);
        if (!k_end) return NULL;

        int match = ((size_t)(k_end - 1 - k_start) == klen) &&
                    (memcmp(k_start, key, klen) == 0);

        p = skip_ws(k_end);
        if (*p != ':') return NULL;
        p++;
        p = skip_ws(p);
        if (match) return p;

        const char *v_end = skip_value(p);
        if (!v_end) return NULL;
        p = skip_ws(v_end);
        if (*p == ',') p++;
        else if (*p == '}') return NULL;
    }
    return NULL;
}

/* Copy a JSON string starting at p (which must point at the opening '"'),
 * unescaping into out. */
static int copy_str(const char *p, char *out, size_t outsize) {
    if (*p != '"') return 0;
    p++;
    size_t o = 0;
    while (*p) {
        if (*p == '"') { if (o < outsize) out[o] = 0; else out[outsize - 1] = 0; return 1; }
        if (*p == '\\' && p[1]) {
            char c = p[1];
            char emit = 0;
            int  emit_len = 1;
            char emitbuf[4] = {0};
            switch (c) {
                case '"': emit = '"'; break;
                case '\\': emit = '\\'; break;
                case '/':  emit = '/'; break;
                case 'n':  emit = '\n'; break;
                case 't':  emit = '\t'; break;
                case 'r':  emit = '\r'; break;
                case 'b':  emit = '\b'; break;
                case 'f':  emit = '\f'; break;
                case 'u': {
                    /* \uXXXX — decode BMP char. Skip surrogate pairs (rare in
                     * our use case). Encode as UTF-8 into emitbuf. */
                    if (!p[2] || !p[3] || !p[4] || !p[5]) return 0;
                    unsigned int cp;
                    char hexb[5] = { p[2], p[3], p[4], p[5], 0 };
                    if (sscanf(hexb, "%04x", &cp) != 1) return 0;
                    if (cp < 0x80) { emitbuf[0] = (char)cp; emit_len = 1; }
                    else if (cp < 0x800) {
                        emitbuf[0] = (char)(0xC0 | (cp >> 6));
                        emitbuf[1] = (char)(0x80 | (cp & 0x3F));
                        emit_len = 2;
                    } else {
                        emitbuf[0] = (char)(0xE0 | (cp >> 12));
                        emitbuf[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        emitbuf[2] = (char)(0x80 | (cp & 0x3F));
                        emit_len = 3;
                    }
                    for (int i = 0; i < emit_len; i++) {
                        if (o + 1 >= outsize) { out[outsize - 1] = 0; return 1; }
                        out[o++] = emitbuf[i];
                    }
                    p += 6;
                    continue;
                }
                default: emit = c; break;
            }
            if (o + 1 >= outsize) { out[outsize - 1] = 0; return 1; }
            out[o++] = emit;
            p += 2;
            continue;
        }
        if (o + 1 >= outsize) { out[outsize - 1] = 0; return 1; }
        out[o++] = *p++;
    }
    return 0;
}

int json_get_str(const char *json, const char *key, char *out, size_t outsize) {
    if (!out || outsize == 0) return 0;
    const char *v = find_key(json, key);
    if (!v) return 0;
    if (*v != '"') return 0;
    return copy_str(v, out, outsize);
}

int json_get_num(const char *json, const char *key, double *out) {
    const char *v = find_key(json, key);
    if (!v) return 0;
    /* Handle bare numeric or numeric-inside-string. */
    char buf[64] = {0};
    if (*v == '"') {
        if (!copy_str(v, buf, sizeof(buf))) return 0;
        *out = atof(buf);
        return 1;
    }
    *out = atof(v);
    return 1;
}

int json_get_bool(const char *json, const char *key, int *out) {
    const char *v = find_key(json, key);
    if (!v) return 0;
    if (strncmp(v, "true", 4) == 0)  { *out = 1; return 1; }
    if (strncmp(v, "false", 5) == 0) { *out = 0; return 1; }
    return 0;
}

int json_has_nonempty_array_or_object(const char *json) {
    if (!json) return 0;
    const char *p = skip_ws(json);
    if (*p == '[') {
        p = skip_ws(p + 1);
        return *p && *p != ']';
    }
    if (*p == '{') {
        p = skip_ws(p + 1);
        return *p && *p != '}';
    }
    return 0;
}

int json_first_array_object(const char *json,
                            const char **object_start, const char **object_end) {
    if (!json) return 0;
    const char *p = skip_ws(json);
    if (*p != '[') return 0;
    p = skip_ws(p + 1);
    if (*p != '{') return 0;
    const char *e = skip_value(p);
    if (!e) return 0;
    *object_start = p;
    *object_end   = e;
    return 1;
}

/* ─── Builder ────────────────────────────────────────────────────── */

static int jb_ensure(json_builder_t *b, size_t extra) {
    if (b->err) return 0;
    if (b->len + extra + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 128;
        while (nc < b->len + extra + 1) nc *= 2;
        char *nb = (char *)realloc(b->buf, nc);
        if (!nb) { b->err = 1; return 0; }
        b->buf = nb;
        b->cap = nc;
    }
    return 1;
}

static int jb_maybe_comma(json_builder_t *b) {
    if (b->needs_comma) {
        if (!jb_ensure(b, 1)) return 0;
        b->buf[b->len++] = ',';
        b->needs_comma = 0;
    }
    return 1;
}

int jb_init(json_builder_t *b, size_t initial_cap) {
    memset(b, 0, sizeof(*b));
    b->cap = initial_cap > 128 ? initial_cap : 128;
    b->buf = (char *)malloc(b->cap);
    if (!b->buf) return 0;
    b->buf[0] = 0;
    return 1;
}

void jb_free(json_builder_t *b) {
    if (b->buf) free(b->buf);
    memset(b, 0, sizeof(*b));
}

int jb_obj_begin(json_builder_t *b) {
    if (!jb_maybe_comma(b) || !jb_ensure(b, 1)) return 0;
    b->buf[b->len++] = '{';
    b->depth++;
    b->needs_comma = 0;
    return 1;
}
int jb_obj_end(json_builder_t *b) {
    if (!jb_ensure(b, 1)) return 0;
    b->buf[b->len++] = '}';
    b->depth--;
    b->needs_comma = 1;
    return 1;
}
int jb_arr_begin(json_builder_t *b) {
    if (!jb_maybe_comma(b) || !jb_ensure(b, 1)) return 0;
    b->buf[b->len++] = '[';
    b->depth++;
    b->needs_comma = 0;
    return 1;
}
int jb_arr_end(json_builder_t *b) {
    if (!jb_ensure(b, 1)) return 0;
    b->buf[b->len++] = ']';
    b->depth--;
    b->needs_comma = 1;
    return 1;
}

/* Emit a JSON-escaped string literal (with surrounding quotes). */
static int emit_qstr(json_builder_t *b, const char *s) {
    size_t sl = s ? strlen(s) : 0;
    if (!jb_ensure(b, sl * 6 + 2)) return 0;
    b->buf[b->len++] = '"';
    for (size_t i = 0; i < sl; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  b->buf[b->len++] = '\\'; b->buf[b->len++] = '"'; break;
            case '\\': b->buf[b->len++] = '\\'; b->buf[b->len++] = '\\'; break;
            case '\n': b->buf[b->len++] = '\\'; b->buf[b->len++] = 'n'; break;
            case '\r': b->buf[b->len++] = '\\'; b->buf[b->len++] = 'r'; break;
            case '\t': b->buf[b->len++] = '\\'; b->buf[b->len++] = 't'; break;
            case '\b': b->buf[b->len++] = '\\'; b->buf[b->len++] = 'b'; break;
            case '\f': b->buf[b->len++] = '\\'; b->buf[b->len++] = 'f'; break;
            default:
                if (c < 0x20) {
                    b->buf[b->len++] = '\\'; b->buf[b->len++] = 'u';
                    b->buf[b->len++] = '0'; b->buf[b->len++] = '0';
                    static const char H[] = "0123456789ABCDEF";
                    b->buf[b->len++] = H[(c >> 4) & 0xF];
                    b->buf[b->len++] = H[c & 0xF];
                } else {
                    b->buf[b->len++] = (char)c;
                }
        }
    }
    b->buf[b->len++] = '"';
    return 1;
}

int jb_key(json_builder_t *b, const char *key) {
    if (!jb_maybe_comma(b)) return 0;
    if (!emit_qstr(b, key)) return 0;
    if (!jb_ensure(b, 1)) return 0;
    b->buf[b->len++] = ':';
    b->needs_comma = 0;
    return 1;
}

int jb_str(json_builder_t *b, const char *value) {
    if (!jb_maybe_comma(b)) return 0;
    int r = emit_qstr(b, value);
    b->needs_comma = 1;
    return r;
}

int jb_num_i(json_builder_t *b, long long value) {
    if (!jb_maybe_comma(b) || !jb_ensure(b, 32)) return 0;
    int n = _snprintf(b->buf + b->len, b->cap - b->len - 1, "%lld", value);
    if (n <= 0) return 0;
    b->len += n;
    b->needs_comma = 1;
    return 1;
}

int jb_num_d(json_builder_t *b, double value) {
    if (!jb_maybe_comma(b) || !jb_ensure(b, 64)) return 0;
    int n = _snprintf(b->buf + b->len, b->cap - b->len - 1, "%.17g", value);
    if (n <= 0) return 0;
    b->len += n;
    b->needs_comma = 1;
    return 1;
}

int jb_bool(json_builder_t *b, int value) {
    if (!jb_maybe_comma(b)) return 0;
    const char *s = value ? "true" : "false";
    size_t sl = strlen(s);
    if (!jb_ensure(b, sl)) return 0;
    memcpy(b->buf + b->len, s, sl);
    b->len += sl;
    b->needs_comma = 1;
    return 1;
}

int jb_null(json_builder_t *b) {
    if (!jb_maybe_comma(b) || !jb_ensure(b, 4)) return 0;
    memcpy(b->buf + b->len, "null", 4);
    b->len += 4;
    b->needs_comma = 1;
    return 1;
}

int jb_raw(json_builder_t *b, const char *raw) {
    if (!jb_maybe_comma(b)) return 0;
    size_t rl = strlen(raw);
    if (!jb_ensure(b, rl)) return 0;
    memcpy(b->buf + b->len, raw, rl);
    b->len += rl;
    b->needs_comma = 1;
    return 1;
}
