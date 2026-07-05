/* ================================================================== *
 * log_secure.c — AES-256-GCM support-log writer.                      *
 *                                                                    *
 * Derived from hooksdll/src/log_secure.c. Adapted to svcldb install  *
 * dir + own SVCLDB_LOG_KEY. Kept identical wire format so a single   *
 * decrypt tool can read logs from both projects.                     *
 * ================================================================== */

#include "common.h"
#include "log_secure.h"

#include <bcrypt.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif

/* ── base64 (standard alphabet) ─────────────────────────────────── */
static const char B64_A[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const uint8_t *in, size_t inlen, char *out) {
    size_t i = 0, o = 0;
    while (i + 3 <= inlen) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[o++] = B64_A[(v >> 18) & 63];
        out[o++] = B64_A[(v >> 12) & 63];
        out[o++] = B64_A[(v >>  6) & 63];
        out[o++] = B64_A[ v        & 63];
        i += 3;
    }
    size_t rem = inlen - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64_A[(v >> 18) & 63];
        out[o++] = B64_A[(v >> 12) & 63];
        out[o++] = '='; out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
        out[o++] = B64_A[(v >> 18) & 63];
        out[o++] = B64_A[(v >> 12) & 63];
        out[o++] = B64_A[(v >>  6) & 63];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

/* ── BCrypt init (lazy + memoized) ──────────────────────────────── */
static BCRYPT_ALG_HANDLE g_alg = NULL;
static BCRYPT_KEY_HANDLE g_key = NULL;
static volatile LONG     g_init_state = 0;   /* 0=unset 1=initing 2=ok 3=fail */
static CRITICAL_SECTION  g_lock;
static volatile LONG     g_lock_init = 0;

/* Per-thread reentry guard.
 * NOTE: We CANNOT use __declspec(thread) here — this code runs under a
 * manual-mapped DLL where the OS loader is unaware of us, so the
 * __tls_index / TLS callbacks are never wired up. Reading a TLS variable
 * dereferences a garbage TIB slot and either returns junk or crashes.
 * Instead: a tiny lock-free per-thread-ID table. Worst-case: at capacity
 * with all slots busy, we skip logging (no crash). Fine for MVP.
 * (Confirmed empirically 2026-07-04: under manual map, __declspec(thread)
 * reads succeeded but returned pseudo-random values from unrelated TLS
 * indexes, silently swallowing >99% of slog_write calls.) */
#define REENTRY_SLOTS 64
static volatile DWORD g_reentry_tids[REENTRY_SLOTS] = {0};

static int reentry_enter(void) {
    DWORD me = GetCurrentThreadId();
    /* Scan for our TID first — if already present, we're re-entering. */
    for (int i = 0; i < REENTRY_SLOTS; i++) {
        if (g_reentry_tids[i] == me) return 0;
    }
    /* Claim an empty slot. */
    for (int i = 0; i < REENTRY_SLOTS; i++) {
        if (g_reentry_tids[i] == 0 &&
            InterlockedCompareExchange((LONG*)&g_reentry_tids[i], (LONG)me, 0) == 0) {
            return 1;
        }
    }
    return 0;   /* table full — skip this write */
}

static void reentry_exit(void) {
    DWORD me = GetCurrentThreadId();
    for (int i = 0; i < REENTRY_SLOTS; i++) {
        if (g_reentry_tids[i] == me) {
            InterlockedExchange((LONG*)&g_reentry_tids[i], 0);
            return;
        }
    }
}

static void ensure_lock(void) {
    if (InterlockedCompareExchange(&g_lock_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_lock);
        InterlockedExchange(&g_lock_init, 2);
    } else {
        while (g_lock_init != 2) Sleep(0);
    }
}

/* Master material — 2 halves + salt, defined in log_key.c. Working
 * key derived at init: SHA256((MA XOR MB) || SALT). This means:
 *  (1) The 32-byte AES-256 key never appears as a contiguous byte
 *      run in the binary — bytesearch tools have to find A + B + salt
 *      separately and then reproduce the derivation.
 *  (2) Rotating either material or the salt invalidates all prior
 *      logs — full-forward-secrecy on rebuild.
 *  (3) An attacker needs the compiled binary AND to reverse this
 *      code to get the working key.
 * The derived hex is written to `.log_master_key.hex` (gitignored)
 * at build time so the decrypt tool consumes it directly. */
extern const uint8_t SVCLDB_KEY_MATERIAL_A[32];
extern const uint8_t SVCLDB_KEY_MATERIAL_B[32];
extern const uint8_t SVCLDB_KEY_SALT[32];
/* SVCLDB_LOG_KEY declared in log_secure.h as non-const; defined in
 * log_key.c as writable storage; populated here at slog_init. */

static BOOL derive_working_key(uint8_t out_key[32]) {
    /* seed = (A XOR B) || SALT — 64 bytes. */
    uint8_t seed[64];
    for (int i = 0; i < 32; i++) {
        seed[i] = SVCLDB_KEY_MATERIAL_A[i] ^ SVCLDB_KEY_MATERIAL_B[i];
    }
    memcpy(seed + 32, SVCLDB_KEY_SALT, 32);

    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_HASH_HANDLE h_hash = NULL;
    BOOL ok = FALSE;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto done;
    if (!NT_SUCCESS(BCryptCreateHash(h_alg, &h_hash, NULL, 0, NULL, 0, 0)))
        goto done;
    if (!NT_SUCCESS(BCryptHashData(h_hash, seed, sizeof(seed), 0)))
        goto done;
    if (!NT_SUCCESS(BCryptFinishHash(h_hash, out_key, 32, 0)))
        goto done;
    ok = TRUE;
done:
    if (h_hash) BCryptDestroyHash(h_hash);
    if (h_alg)  BCryptCloseAlgorithmProvider(h_alg, 0);
    /* Wipe seed. */
    SecureZeroMemory(seed, sizeof(seed));
    return ok;
}

static BOOL slog_init(void) {
    LONG s = g_init_state;
    if (s == 2) return TRUE;
    if (s == 3) return FALSE;
    if (InterlockedCompareExchange(&g_init_state, 1, 0) != 0) {
        for (int i = 0; i < 200 && g_init_state == 1; i++) Sleep(2);
        return g_init_state == 2;
    }
    /* Derive the working key from A/B/salt. */
    if (!derive_working_key(SVCLDB_LOG_KEY)) goto fail;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&g_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) goto fail;
    st = BCryptSetProperty(g_alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)), 0);
    if (!NT_SUCCESS(st)) goto fail;
    st = BCryptGenerateSymmetricKey(g_alg, &g_key, NULL, 0,
        (PUCHAR)SVCLDB_LOG_KEY, 32, 0);
    if (!NT_SUCCESS(st)) goto fail;
    ensure_lock();
    InterlockedExchange(&g_init_state, 2);
    return TRUE;
fail:
    if (g_alg) { BCryptCloseAlgorithmProvider(g_alg, 0); g_alg = NULL; }
    InterlockedExchange(&g_init_state, 3);
    return FALSE;
}

/* ── public API ─────────────────────────────────────────────────── */

void slog_write(const char *filename, const char *message) {
    if (!filename || !message) return;
    if (!reentry_enter()) return;
    if (!slog_init()) goto out;

    char plaintext[2048];
    SYSTEMTIME t;
    GetSystemTime(&t);
    int n = _snprintf(plaintext, sizeof(plaintext) - 1,
        "[%04d-%02d-%02dT%02d:%02d:%02d.%03dZ] pid=%lu %s",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
        (unsigned long)GetCurrentProcessId(), message);
    if (n <= 0) goto out;
    if (n >= (int)sizeof(plaintext)) n = (int)sizeof(plaintext) - 1;
    while (n > 0 && (plaintext[n-1] == '\n' || plaintext[n-1] == '\r')) n--;
    plaintext[n] = '\0';
    if (n == 0) goto out;

    uint8_t iv[12];
    if (!NT_SUCCESS(BCryptGenRandom(NULL, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        goto out;

    uint8_t ct[2048];
    uint8_t tag[16];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv;  info.cbNonce = sizeof(iv);
    info.pbTag   = tag; info.cbTag   = sizeof(tag);

    ULONG written = 0;
    NTSTATUS enc = BCryptEncrypt(g_key, (PUCHAR)plaintext, (ULONG)n, &info,
                                 NULL, 0, ct, sizeof(ct), &written, 0);
    if (!NT_SUCCESS(enc) || written == 0) goto out;

    uint8_t blob[12 + 16 + sizeof(ct)];
    memcpy(blob,      iv,  12);
    memcpy(blob + 12, tag, 16);
    memcpy(blob + 28, ct,  written);

    char encoded[3 + ((12 + 16 + sizeof(ct)) * 4 / 3) + 8];
    encoded[0] = 'v'; encoded[1] = '1'; encoded[2] = '.';
    size_t b64len = b64_encode(blob, 12 + 16 + written, encoded + 3);
    encoded[3 + b64len]     = '\n';
    encoded[3 + b64len + 1] = '\0';
    DWORD total = (DWORD)(3 + b64len + 1);

    char fname[160] = {0};
    size_t fi = 0;
    for (const char *p = filename; *p && fi < sizeof(fname) - 1; p++) {
        char c = *p;
        if (c == '\\' || c == '/' || c == ':' || c == '*' ||
            c == '?'  || c == '"' || c == '<' || c == '>' || c == '|') continue;
        fname[fi++] = c;
    }
    fname[fi] = '\0';
    if (fi == 0) goto out;

    char fullpath[MAX_PATH];
    int pn = _snprintf(fullpath, sizeof(fullpath) - 1,
                       "%s\\%s", SVC_INSTALL_DIR, fname);
    if (pn <= 0 || pn >= (int)sizeof(fullpath)) goto out;
    fullpath[pn] = '\0';

    CreateDirectoryA(SVC_INSTALL_DIR, NULL);

    EnterCriticalSection(&g_lock);
    HANDLE h = CreateFileA(fullpath, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, encoded, total, &w, NULL);
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_lock);

out:
    reentry_exit();
}

void slog_writef(const char *filename, const char *fmt, ...) {
    if (!filename || !fmt) return;
    char buf[1900];
    va_list args;
    va_start(args, fmt);
    int n = _vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    va_end(args);
    if (n <= 0) return;
    if (n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
    buf[n] = '\0';
    slog_write(filename, buf);
}
