#include "base64.h"

static const char A_STD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char A_URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t enc_with(const char *alph, int pad, const uint8_t *in, size_t inlen, char *out) {
    size_t i = 0, o = 0;
    while (i + 3 <= inlen) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[o++] = alph[(v >> 18) & 63];
        out[o++] = alph[(v >> 12) & 63];
        out[o++] = alph[(v >>  6) & 63];
        out[o++] = alph[ v        & 63];
        i += 3;
    }
    size_t rem = inlen - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = alph[(v >> 18) & 63];
        out[o++] = alph[(v >> 12) & 63];
        if (pad) { out[o++] = '='; out[o++] = '='; }
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
        out[o++] = alph[(v >> 18) & 63];
        out[o++] = alph[(v >> 12) & 63];
        out[o++] = alph[(v >>  6) & 63];
        if (pad) out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

size_t b64_encode_std(const uint8_t *in, size_t inlen, char *out) {
    return enc_with(A_STD, 1, in, inlen, out);
}
size_t b64_encode_url(const uint8_t *in, size_t inlen, char *out) {
    return enc_with(A_URL, 0, in, inlen, out);
}

static int decv(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

int b64_decode_any(const char *in, size_t inlen, uint8_t *out, size_t outmax) {
    uint32_t v = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        char c = in[i];
        if (c == '=' || c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        int d = decv(c);
        if (d < 0) return -1;
        v = (v << 6) | (uint32_t)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outmax) return -1;
            out[o++] = (uint8_t)((v >> bits) & 0xFF);
        }
    }
    return (int)o;
}
