/* ================================================================== *
 * supabase_config.c — XOR-obfuscated Supabase constants.              *
 *                                                                    *
 * Values encrypted with SHA256("svcldb-config-wrap-v1") and stored   *
 * as base64 blobs. Decrypted at runtime into heap-alloc'd cached     *
 * strings. Never printed. Cleaned via sb_cleanup on shutdown.        *
 * ================================================================== */

#include "common.h"
#include "supabase_config.h"
#include "base64.h"

#include <bcrypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "bcrypt.lib")

/* ── Ciphertext (base64, XOR'd with SHA256("svcldb-config-wrap-v1")) ── */
static const char C_URL[]           = "lQIajrMjL55196kpvsGyu7bi0SjmwD3MGS73cMb1b2OcFA+NpTdj3g==";
static const char C_API[]           = "lQIajrMjL55w7LU9utu78bbsyi/j0T7NTynzag==";
/* svcldb-solve worker base (https://svcldb-solve.c-viperdevelopment.workers.dev) */
static const char C_SOLVE[]         = "lQIajrMjL55087g1sc7lrLfvyCml1WPPCDr5dYzjbHaRGR6TpXd0n3DqqTKw3rvxvObI";
static const char C_ANON_KEY[]      = "mA8klqJeY9hI7JEQgNaB7pbq9z/C2ByMAgnVMaHtakurNSTH7nx5+3fm6BS846GVoufmDuPvI/8bEM9Om890WZEsB7f2UG77fua1G6fOkK+z4dMK/ewJiFMpr1Hc3F1nzj8Hial6bYh034gQ4+Wlma3hjHji+g3zERPEVoHJcFbOOASd8lZE5H7LoT6m5aWJ7OD9Bb37JPhVB+ZO2stOWs45Js7uUzTaY8G6K5bonrWz944Bst4s6gkt1ma+sVgizyFbyItGaORWxIsKj53lvA==";
static const char C_RESP_SECRET[]   = "nEQIx/QrOYI2tr5q5pj+uu6323no1XbYBSz/Zo6weCvIEgjL9i00g2a3vjuxm/Du6bKMdLOAL4sHKKs00b58Iw==";

static char *g_url         = NULL;
static char *g_anon        = NULL;
static char *g_api_base    = NULL;
static char *g_solve       = NULL;
static unsigned char *g_secret = NULL;   /* 32 raw bytes */
static CRITICAL_SECTION g_cs;
static volatile LONG    g_cs_init = 0;

static void ensure_cs(void) {
    if (InterlockedCompareExchange(&g_cs_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_cs);
        InterlockedExchange(&g_cs_init, 2);
    } else {
        while (g_cs_init != 2) Sleep(0);
    }
}

/* Wrap key = SHA-256("svcldb-config-wrap-v1"). Computed once. */
static const unsigned char *wrap_key(void) {
    static unsigned char k[32];
    static volatile LONG done = 0;
    if (done == 2) return k;
    if (InterlockedCompareExchange(&done, 1, 0) == 0) {
        static const char seed[] = "svcldb-config-wrap-v1";
        BCRYPT_ALG_HANDLE alg;
        if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
            BCRYPT_HASH_HANDLE h;
            if (NT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0))) {
                BCryptHashData(h, (PUCHAR)seed, sizeof(seed) - 1, 0);
                BCryptFinishHash(h, k, 32, 0);
                BCryptDestroyHash(h);
            }
            BCryptCloseAlgorithmProvider(alg, 0);
        }
        InterlockedExchange(&done, 2);
    } else {
        while (done != 2) Sleep(0);
    }
    return k;
}

/* Decode + XOR-decrypt a compile-time constant. Returned buffer is heap. */
static char *decrypt_str(const char *b64) {
    size_t clen = strlen(b64);
    unsigned char *tmp = (unsigned char *)malloc(clen);
    if (!tmp) return NULL;
    int n = b64_decode_any(b64, clen, tmp, clen);
    if (n <= 0) { free(tmp); return NULL; }

    const unsigned char *k = wrap_key();
    for (int i = 0; i < n; i++) tmp[i] ^= k[i % 32];

    char *out = (char *)malloc(n + 1);
    if (!out) { free(tmp); return NULL; }
    memcpy(out, tmp, n);
    out[n] = 0;
    svc_secure_zero(tmp, n);
    free(tmp);
    return out;
}

/* Decode 64-hex-char secret to 32 raw bytes. */
static unsigned char *decrypt_secret(const char *b64) {
    char *hex = decrypt_str(b64);
    if (!hex) return NULL;
    size_t hex_len = strlen(hex);
    if (hex_len != 64) { free(hex); return NULL; }
    unsigned char *out = (unsigned char *)malloc(32);
    if (!out) { free(hex); return NULL; }
    for (int i = 0; i < 32; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%02x", &b) != 1) {
            svc_secure_zero(hex, hex_len); free(hex);
            svc_secure_zero(out, 32);      free(out);
            return NULL;
        }
        out[i] = (unsigned char)b;
    }
    svc_secure_zero(hex, hex_len);
    free(hex);
    return out;
}

const char *sb_url(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (!g_url) g_url = decrypt_str(C_URL);
    LeaveCriticalSection(&g_cs);
    return g_url;
}

const char *sb_anon_key(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (!g_anon) g_anon = decrypt_str(C_ANON_KEY);
    LeaveCriticalSection(&g_cs);
    return g_anon;
}

const char *sb_api_base_url(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (!g_api_base) g_api_base = decrypt_str(C_API);
    LeaveCriticalSection(&g_cs);
    return g_api_base;
}

const char *sb_solve_url(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (!g_solve) g_solve = decrypt_str(C_SOLVE);
    LeaveCriticalSection(&g_cs);
    return g_solve;
}

const unsigned char *sb_response_secret(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (!g_secret) g_secret = decrypt_secret(C_RESP_SECRET);
    LeaveCriticalSection(&g_cs);
    return g_secret;
}

void sb_cleanup(void) {
    if (g_cs_init != 2) return;
    EnterCriticalSection(&g_cs);
    if (g_url)      { svc_secure_zero(g_url,      strlen(g_url));      free(g_url);      g_url = NULL; }
    if (g_anon)     { svc_secure_zero(g_anon,     strlen(g_anon));     free(g_anon);     g_anon = NULL; }
    if (g_api_base) { svc_secure_zero(g_api_base, strlen(g_api_base)); free(g_api_base); g_api_base = NULL; }
    if (g_solve)    { svc_secure_zero(g_solve,    strlen(g_solve));    free(g_solve);    g_solve = NULL; }
    if (g_secret)   { svc_secure_zero(g_secret,   32);                 free(g_secret);   g_secret = NULL; }
    LeaveCriticalSection(&g_cs);
}
