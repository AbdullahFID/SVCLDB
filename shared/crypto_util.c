/* ================================================================== *
 * crypto_util.c — BCrypt wrapper for the primitives we need.          *
 * ================================================================== */

#include "common.h"
#include "crypto_util.h"
#include "base64.h"

#include <bcrypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif

int cu_random(uint8_t *buf, size_t len) {
    if (!buf || !len) return 0;
    return NT_SUCCESS(BCryptGenRandom(NULL, buf, (ULONG)len,
                                       BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

int cu_sha256(const void *data, size_t len, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return 0;
    BCRYPT_HASH_HANDLE h;
    int ok = 0;
    if (NT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0))) {
        if (NT_SUCCESS(BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0)) &&
            NT_SUCCESS(BCryptFinishHash(h, out, 32, 0))) {
            ok = 1;
        }
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

int cu_hmac_sha256(const uint8_t *key, size_t key_len,
                   const void *data, size_t data_len,
                   uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                                 BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        return 0;
    BCRYPT_HASH_HANDLE h;
    int ok = 0;
    if (NT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0))) {
        if (NT_SUCCESS(BCryptHashData(h, (PUCHAR)data, (ULONG)data_len, 0)) &&
            NT_SUCCESS(BCryptFinishHash(h, out, 32, 0))) {
            ok = 1;
        }
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

int cu_ct_eq(const void *a, const void *b, size_t len) {
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t d = 0;
    for (size_t i = 0; i < len; i++) d |= x[i] ^ y[i];
    return d;
}

void cu_to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = H[bytes[i] >> 4];
        out[i * 2 + 1] = H[bytes[i] & 15];
    }
    out[len * 2] = 0;
}

int cu_from_hex(const char *hex, uint8_t *out, size_t outmax) {
    if (!hex || !out) return -1;
    size_t hlen = strlen(hex);
    if (hlen % 2) return -1;
    size_t bytes = hlen / 2;
    if (bytes > outmax) return -1;
    for (size_t i = 0; i < bytes; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%02x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return (int)bytes;
}

int cu_pkce_verifier(char out_verifier[64]) {
    uint8_t bytes[32];
    if (!cu_random(bytes, 32)) return 0;
    b64_encode_url(bytes, 32, out_verifier);
    svc_secure_zero(bytes, sizeof(bytes));
    return 1;
}

int cu_pkce_challenge(const char *verifier, char out_challenge[64]) {
    if (!verifier) return 0;
    uint8_t h[32];
    if (!cu_sha256(verifier, strlen(verifier), h)) return 0;
    b64_encode_url(h, 32, out_challenge);
    return 1;
}

/* ── Machine-bound wrap key derivation ────────────────────────────── */
/* SHA-256("svcldb-config-wrap-v2" || MachineGuid || Computer || User).
 * Deterministic per host. Cache after first compute. */
static uint8_t g_wrap[32];
static volatile LONG g_wrap_ready = 0;

static int build_wrap_key(void) {
    if (g_wrap_ready == 2) return 1;
    if (InterlockedCompareExchange(&g_wrap_ready, 1, 0) != 0) {
        while (g_wrap_ready == 1) Sleep(1);
        return g_wrap_ready == 2;
    }

    /* MachineGuid. */
    char mg[128] = {0};
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography", 0,
        KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        DWORD sz = sizeof(mg), type = 0;
        RegQueryValueExA(k, "MachineGuid", NULL, &type, (LPBYTE)mg, &sz);
        RegCloseKey(k);
    }

    /* Hostname only — MUST NOT use GetUserNameA because launcher runs
     * as interactive user but payload runs as SYSTEM (inside dwm.exe).
     * Including username would make the wrap keys differ between the two
     * → payload can't decrypt config written by launcher. */
    char host[128] = {0};
    DWORD hlen = sizeof(host);
    GetComputerNameA(host, &hlen);

    BCRYPT_ALG_HANDLE alg;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        InterlockedExchange(&g_wrap_ready, 3);
        return 0;
    }
    BCRYPT_HASH_HANDLE h;
    int ok = 0;
    if (NT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0))) {
        static const char seed[] = "svcldb-config-wrap-v3|";  /* v3: no username */
        BCryptHashData(h, (PUCHAR)seed, sizeof(seed) - 1, 0);
        BCryptHashData(h, (PUCHAR)mg,   (ULONG)strlen(mg), 0);
        BCryptHashData(h, (PUCHAR)"|",  1, 0);
        BCryptHashData(h, (PUCHAR)host, (ULONG)strlen(host), 0);
        if (NT_SUCCESS(BCryptFinishHash(h, g_wrap, 32, 0))) ok = 1;
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    InterlockedExchange(&g_wrap_ready, ok ? 2 : 3);
    return ok;
}

/* AES-256-GCM encrypt plain → out. Layout: iv[12] || tag[16] || ct[N].
 * Returns 1 + fills *out_len on success. */
int cu_wrap_encrypt(const void *plain, size_t plain_len,
                    uint8_t *out, size_t outmax, size_t *out_len) {
    if (!plain || !out || plain_len == 0 || outmax < plain_len + 28) return 0;
    if (!build_wrap_key()) return 0;

    BCRYPT_ALG_HANDLE alg;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return 0;
    int ok = 0;
    BCRYPT_KEY_HANDLE key = NULL;

    NTSTATUS s = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)), 0);
    if (!NT_SUCCESS(s)) goto done;

    s = BCryptGenerateSymmetricKey(alg, &key, NULL, 0, g_wrap, 32, 0);
    if (!NT_SUCCESS(s)) goto done;

    uint8_t iv[12];
    if (!cu_random(iv, 12)) goto done;
    memcpy(out, iv, 12);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv; info.cbNonce = 12;
    info.pbTag   = out + 12; info.cbTag = 16;   /* tag written in-place */

    ULONG written = 0;
    s = BCryptEncrypt(key, (PUCHAR)plain, (ULONG)plain_len, &info,
                      NULL, 0, out + 28, (ULONG)(outmax - 28), &written, 0);
    if (!NT_SUCCESS(s)) goto done;

    *out_len = 28 + written;
    ok = 1;

done:
    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

int cu_wrap_decrypt(const uint8_t *cipher, size_t cipher_len,
                    uint8_t *out, size_t outmax, size_t *out_len) {
    if (!cipher || !out || cipher_len < 29) return 0;
    if (!build_wrap_key()) return 0;

    BCRYPT_ALG_HANDLE alg;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return 0;
    int ok = 0;
    BCRYPT_KEY_HANDLE key = NULL;

    NTSTATUS s = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)), 0);
    if (!NT_SUCCESS(s)) goto done;

    s = BCryptGenerateSymmetricKey(alg, &key, NULL, 0, g_wrap, 32, 0);
    if (!NT_SUCCESS(s)) goto done;

    uint8_t iv[12], tag[16];
    memcpy(iv,  cipher,      12);
    memcpy(tag, cipher + 12, 16);
    size_t ct_len = cipher_len - 28;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv; info.cbNonce = 12;
    info.pbTag   = tag; info.cbTag  = 16;

    ULONG written = 0;
    s = BCryptDecrypt(key, (PUCHAR)(cipher + 28), (ULONG)ct_len, &info,
                      NULL, 0, out, (ULONG)outmax, &written, 0);
    if (!NT_SUCCESS(s)) goto done;

    *out_len = written;
    ok = 1;

done:
    if (key) BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}
