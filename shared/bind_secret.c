/* ================================================================== *
 * bind_secret.c -- see bind_secret.h.                                 *
 * ================================================================== */
#include "common.h"
#include "bind_secret.h"
#include "sec_attr.h"

#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

/* Path where we store the secret. Same directory as config.dat, offsets.blob,
 * etc. -- everything payload/launcher use. */
#define BIND_FILE_PATH "C:\\ProgramData\\WinAudioSvc\\_bind.bin"

/* Fallback secret when the real file can't be read. Compile-time constant.
 * NOT SECRET (present in every binary) so a medium-IL attacker who reaches
 * the fallback path can also derive the names. The fallback exists ONLY
 * to keep IPC alive on badly-configured boxes -- production installs
 * MUST have a proper _bind.bin. */
static const uint8_t DEFAULT_BIND[32] = {
    0x7c, 0x3f, 0xa1, 0x92, 0x4d, 0x88, 0x1e, 0x60,
    0x5b, 0x37, 0xd0, 0x2c, 0x9e, 0xea, 0x14, 0x77,
    0x33, 0x4a, 0xf5, 0x11, 0x08, 0xbc, 0x69, 0x82,
    0xc4, 0x17, 0x5d, 0x2f, 0xaa, 0x93, 0x76, 0xe1
};

static CRITICAL_SECTION g_lock;
static LONG             g_lock_inited = 0;
static uint8_t          g_cache[32];
static int              g_cache_valid = 0;

static void ensure_lock(void) {
    if (InterlockedCompareExchange(&g_lock_inited, 1, 0) == 0) {
        InitializeCriticalSection(&g_lock);
    }
}

/* Best-effort mkdir. Ignores "already exists". */
static void ensure_dir(const char *path) {
    CreateDirectoryA(path, NULL);
}

int svc_bind_secret_read(uint8_t out[32]) {
    if (!out) return 0;
    ensure_lock();
    EnterCriticalSection(&g_lock);
    if (g_cache_valid) {
        memcpy(out, g_cache, 32);
        LeaveCriticalSection(&g_lock);
        return 1;
    }

    int ok = 0;
    HANDLE h = CreateFileA(BIND_FILE_PATH, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        uint8_t buf[64] = {0};
        DWORD rd = 0;
        if (ReadFile(h, buf, sizeof(buf), &rd, NULL) && rd >= 32) {
            memcpy(g_cache, buf, 32);
            g_cache_valid = 1;
            memcpy(out, g_cache, 32);
            ok = 1;
        }
        /* Wipe temp buffer immediately. */
        svc_secure_zero(buf, sizeof(buf));
        CloseHandle(h);
    }

    if (!ok) {
        /* Fallback: use compile-time DEFAULT_BIND. Log-worthy but not fatal. */
        memcpy(g_cache, DEFAULT_BIND, 32);
        g_cache_valid = 1;
        memcpy(out, DEFAULT_BIND, 32);
        ok = 1;
    }
    LeaveCriticalSection(&g_lock);
    return ok;
}

int svc_bind_secret_ensure(void) {
    ensure_dir("C:\\ProgramData\\WinAudioSvc");

    /* If file already exists AND has >= 32 bytes, treat as good; don't
     * regenerate (that would rename all named objects mid-flight). */
    HANDLE h = CreateFileA(BIND_FILE_PATH, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz;
        if (GetFileSizeEx(h, &sz) && sz.QuadPart >= 32) {
            CloseHandle(h);
            return 1;
        }
        CloseHandle(h);
    }

    /* Generate 32 random bytes. */
    uint8_t rnd[32];
    if (!NT_SUCCESS(BCryptGenRandom(NULL, rnd, sizeof(rnd),
                                     BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return 0;
    }

    /* Build DACL: SYSTEM + Administrators + Window Manager Group READ.
     * Excludes Users so medium-IL cannot compute HMAC-derived names.
     * WMG required so dwm.exe (running under Window Manager\DWM-<n>
     * virtual account -- neither SYSTEM nor Administrators) can also
     * read the secret. */
    SECURITY_ATTRIBUTES sa = {0};
    PSECURITY_DESCRIPTOR sd = NULL;
    int have_sa = svc_build_bind_secret_sa(&sa, &sd);

    /* CREATE_ALWAYS: overwrite a partial/corrupt file if present. */
    HANDLE wh = CreateFileA(BIND_FILE_PATH, GENERIC_WRITE, 0,
                            have_sa ? &sa : NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (sd) LocalFree(sd);
    if (wh == INVALID_HANDLE_VALUE) {
        svc_secure_zero(rnd, sizeof(rnd));
        return 0;
    }
    DWORD wr = 0;
    BOOL ok = WriteFile(wh, rnd, sizeof(rnd), &wr, NULL) && wr == sizeof(rnd);
    /* Flush before releasing handle so a subsequent read from another
     * process is guaranteed to see the bytes. */
    if (ok) FlushFileBuffers(wh);
    CloseHandle(wh);
    svc_secure_zero(rnd, sizeof(rnd));

    /* Invalidate any prior cached fallback so the next read picks up the
     * real bytes. */
    if (ok) svc_bind_secret_reset_cache();
    return ok ? 1 : 0;
}

void svc_bind_secret_reset_cache(void) {
    ensure_lock();
    EnterCriticalSection(&g_lock);
    svc_secure_zero(g_cache, sizeof(g_cache));
    g_cache_valid = 0;
    LeaveCriticalSection(&g_lock);
}
