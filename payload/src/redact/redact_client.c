/* ================================================================== *
 * redact_client.c -- payload-side pipe client for the OCR redactor.    *
 *                                                                    *
 * See redact_client.h for the API contract. This TU stays intention-  *
 * ally tiny + dependency-free so it can slot into the manual-mapped   *
 * payload without any of the WinRT/C++/CRT drama that put us into    *
 * a helper-process design in the first place.                        *
 * ================================================================== */

#include "redact_client.h"

#include <windows.h>
#include <stddef.h>
#include <string.h>

#include "../../shared/common.h"
#include "../../shared/crypto_util.h"

/* Kept in sync with launcher/src/ocr/ocr_scanner.h. Duplicated here
 * to avoid a cross-project include; if you change one, change both.
 * v2.0.1 (2026-09-10): bumped magic OCR1 -> OCR2, added HMAC field. */
#define REDACT_PIPE_NAME  "\\\\.\\pipe\\svcldb_ocr_v1"
#define REDACT_WIRE_MAGIC 0x4F435232u   /* 'OCR2' little-endian */
#define REDACT_HMAC_LEN   32u

typedef struct {
    uint32_t magic;
    uint32_t opcode;   /* 1 = scan+paint, 2 = shutdown */
    uint32_t width;
    uint32_t height;
    uint32_t byte_len;
    uint8_t  hmac[REDACT_HMAC_LEN];   /* v2.0.1: HMAC over the first 20 bytes */
} redact_req_hdr_t;

typedef struct {
    uint32_t magic;
    int32_t  status;
    uint32_t byte_len;
    uint32_t rect_count;
} redact_resp_hdr_t;

/* ── v2.0.1 (2026-09-10) HMAC key derivation ──────────────────────
 * Key = HMAC-SHA256(install_secret_hex_ascii_bytes, "svcldb-ocr-v1").
 * Cached process-lifetime after first successful derive -- install_secret
 * doesn't change while the payload is loaded, so no invalidation. Mirrors
 * launcher/src/main.c --ocr-daemon path bit-for-bit. If derivation fails
 * (secret file missing/short), redact_bgra_via_pipe returns -1 (same as
 * the "daemon isn't running" sentinel) -- payload silently falls back to
 * unredacted capture, which is the pre-fix behaviour when OCR was OFF. */
static volatile LONG g_ocr_key_state = 0;   /* 0=unset 1=deriving 2=ok 3=fail */
static uint8_t       g_ocr_key[32]    = {0};

static int derive_ocr_key_once(void) {
    LONG s = InterlockedCompareExchange(&g_ocr_key_state, 0, 0);
    if (s == 2) return 1;
    if (s == 3) return 0;
    /* CAS 0 -> 1 to serialize; losers spin briefly then re-check. */
    if (InterlockedCompareExchange(&g_ocr_key_state, 1, 0) != 0) {
        for (int i = 0; i < 20; i++) {
            Sleep(10);
            s = InterlockedCompareExchange(&g_ocr_key_state, 0, 0);
            if (s == 2) return 1;
            if (s == 3) return 0;
        }
        return 0;
    }
    /* We're the deriver. */
    char sec_path[MAX_PATH];
    wsprintfA(sec_path, "%s\\.svchelper_install_secret", SVC_INSTALL_DIR);
    HANDLE hs = CreateFileA(sec_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    int ok = 0;
    if (hs != INVALID_HANDLE_VALUE) {
        uint8_t secret[128];
        DWORD got = 0;
        if (ReadFile(hs, secret, sizeof(secret), &got, NULL)) {
            while (got > 0 && (secret[got-1] == '\r' || secret[got-1] == '\n' ||
                               secret[got-1] == ' '  || secret[got-1] == '\t')) got--;
            if (got >= 32) {
                static const char DOMAIN[] = "svcldb-ocr-v1";
                ok = cu_hmac_sha256(secret, got,
                                    DOMAIN, sizeof(DOMAIN) - 1,
                                    g_ocr_key);
            }
        }
        svc_secure_zero(secret, sizeof(secret));
        CloseHandle(hs);
    }
    InterlockedExchange(&g_ocr_key_state, ok ? 2 : 3);
    return ok;
}

/* ── Utility: full-blocking pipe reads/writes ──────────────────── */

static int write_all(HANDLE h, const void *buf, DWORD len) {
    const BYTE *p = (const BYTE *)buf;
    DWORD sent = 0;
    while (sent < len) {
        DWORD chunk = 0;
        if (!WriteFile(h, p + sent, len - sent, &chunk, NULL) || chunk == 0)
            return 0;
        sent += chunk;
    }
    return 1;
}

static int read_all(HANDLE h, void *buf, DWORD len) {
    BYTE *p = (BYTE *)buf;
    DWORD got = 0;
    while (got < len) {
        DWORD chunk = 0;
        if (!ReadFile(h, p + got, len - got, &chunk, NULL) || chunk == 0)
            return 0;
        got += chunk;
    }
    return 1;
}

/* ── Cheap availability probe ──────────────────────────────────── */

int redact_daemon_available(void) {
    /* WaitNamedPipeA with 0 timeout returns immediately.
     * Returns nonzero if a pipe is available. */
    return WaitNamedPipeA(REDACT_PIPE_NAME, 0) != FALSE;
}

/* ── Main entry ────────────────────────────────────────────────── */

int redact_bgra_via_pipe(uint8_t *bgra, uint32_t width, uint32_t height) {
    if (!bgra || width == 0 || height == 0) return -1;

    /* Try to open the pipe with a short wait (200ms) -- daemon may be
     * busy servicing a prior request. WaitNamedPipe + CreateFile is the
     * documented pattern (see MSDN Named Pipes). */
    if (!WaitNamedPipeA(REDACT_PIPE_NAME, 200)) {
        /* No pipe advertised -> daemon isn't running -> feature is OFF.
         * Return the "not-available" sentinel silently. */
        return -1;
    }

    HANDLE pipe = CreateFileA(
        REDACT_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,                    /* no sharing */
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (pipe == INVALID_HANDLE_VALUE) return -1;

    /* Switch to byte mode (matches server); harmless if already byte. */
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(pipe, &mode, NULL, NULL);

    uint32_t byte_len = width * height * 4u;
    redact_req_hdr_t req;
    req.magic    = REDACT_WIRE_MAGIC;
    req.opcode   = 1;
    req.width    = width;
    req.height   = height;
    req.byte_len = byte_len;
    memset(req.hmac, 0, sizeof(req.hmac));

    /* v2.0.1 (2026-09-10): compute HMAC over the first 20 bytes of the
     * header (everything BEFORE req.hmac). If key derivation fails
     * (install_secret unreadable -- should never happen for the payload
     * since it runs inside dwm.exe which the ProgramData ACL permits),
     * bail with the "unavailable" sentinel -- the payload's caller
     * silently falls back to unredacted capture, matching OCR-OFF UX. */
    if (!derive_ocr_key_once()) {
        return -1;
    }
    if (!cu_hmac_sha256(g_ocr_key, sizeof(g_ocr_key),
                        &req, 20, req.hmac)) {
        return -1;
    }

    int rc = -3;   /* default: protocol/IO error */

    if (!write_all(pipe, &req, (DWORD)sizeof(req))) goto done;
    if (!write_all(pipe, bgra,  byte_len))          goto done;

    redact_resp_hdr_t resp = { 0, 0, 0, 0 };
    if (!read_all(pipe, &resp, (DWORD)sizeof(resp))) goto done;
    if (resp.magic != REDACT_WIRE_MAGIC)             goto done;

    if (resp.status != 0) {
        rc = -2;   /* daemon reported an error -- buffer stays untouched */
        goto done;
    }
    if (resp.byte_len != byte_len) {
        /* server sent unexpected size -- refuse the response */
        goto done;
    }

    /* Overwrite our buffer with the redacted BGRA. */
    if (!read_all(pipe, bgra, byte_len)) goto done;

    rc = (int)resp.rect_count;

done:
    /* Ensure the server sees end-of-transmission before we vanish. */
    FlushFileBuffers(pipe);
    CloseHandle(pipe);
    return rc;
}
