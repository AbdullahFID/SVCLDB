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
#include "../../shared/obf_names.h"

/* Kept in sync with launcher/src/ocr/ocr_scanner.h. Duplicated here
 * to avoid a cross-project include; if you change one, change both.
 * v2.0.1 (2026-09-10): bumped magic OCR1 -> OCR2, added HMAC field.
 * v3 (2026-09-19): pipe name is now the per-box derived GUID from
 * obf_pipe_ocr() (same value the launcher daemon + Electron use) --
 * kills the "svcldb_ocr_v1" literal that leaked the codename to any
 * unprivileged pipe enumeration. */
#define REDACT_PIPE_NAME  obf_pipe_ocr()
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
 * Key = HMAC-SHA256(install_secret_hex_ascii_bytes, "wa.ocr.v1").
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
                static const char DOMAIN[] = "wa.ocr.v1";   /* v3: was "svcldb-ocr-v1" (leaked codename to admin memory grep) */
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

/* ── Utility: overlapped, timeout-bounded pipe reads/writes ────
 *
 * v-audit-hardening (2026-09-23) -- P0 fix from opus-4.7 Audit D.
 *
 * PRIOR:
 *   Pipe was opened without FILE_FLAG_OVERLAPPED and read/write helpers
 *   used blocking WriteFile/ReadFile with NO TIMEOUT. `redact_bgra_via_pipe`
 *   is called from `try_perform_capture` in `imgui_layer.cpp`, which runs
 *   ON DWM's compose thread inside `ui_present_frame`. If the OCR daemon
 *   (`sihost.exe --ocr-daemon` in winlogon) accepts the pipe but then
 *   hangs (deadlock in `Windows.Media.Ocr`, GPU stall, LDB-suspended
 *   child), WriteFile / ReadFile blocked FOREVER. DWM's compose thread
 *   stopped -> whole desktop stopped compositing until the daemon was
 *   forcibly killed. Ship-blocking P0.
 *
 * NOW:
 *   Pipe opened with FILE_FLAG_OVERLAPPED. Each read/write submits with
 *   an OVERLAPPED struct + auto-reset event and WaitForSingleObject
 *   with a hard 2000ms timeout. On timeout, we CancelIoEx and return
 *   failure -> caller (`redact_bgra_via_pipe`) returns -3 -> caller of
 *   THAT (`try_perform_capture` around imgui_layer.cpp:1810-1927)
 *   treats it as "daemon failed" and falls through to unredacted
 *   capture. Matches OCR-OFF UX. DWM stays alive no matter what the
 *   daemon does.
 *
 * Total worst-case blocking on the compose thread: ~2s per round-trip.
 * A full 4K BGRA (~33 MB) at ~100 MB/s pipe bandwidth = ~330 ms real
 * transfer, well inside the 2s cap. OCR itself typically 100-200 ms
 * per screen -- also inside the cap. Legit slow paths (dictionary
 * reload, first-frame OCR init) may occasionally graze the cap; treat
 * that as a one-frame skipped-redaction, not a compose-thread freeze. */

#ifndef REDACT_PIPE_IO_TIMEOUT_MS
#define REDACT_PIPE_IO_TIMEOUT_MS 2000u
#endif

static int overlapped_wait(HANDLE h, OVERLAPPED *ov, HANDLE ev, DWORD *out_bytes) {
    /* Wait for the overlapped op to complete, bounded by timeout.
     * On timeout: cancel the pending IO so the OS releases the handle
     * for the CloseHandle path we're about to run. Never let a
     * pending overlapped op outlive this function on the compose
     * thread -- it would hold the handle + the buffer alive past our
     * return. */
    DWORD wait = WaitForSingleObject(ev, REDACT_PIPE_IO_TIMEOUT_MS);
    if (wait == WAIT_OBJECT_0) {
        DWORD n = 0;
        if (!GetOverlappedResult(h, ov, &n, FALSE)) return 0;
        if (out_bytes) *out_bytes = n;
        return 1;
    }
    /* Timeout or wait failed -- cancel any pending IO on this handle,
     * then drain the completion so the OS doesn't touch our OVERLAPPED
     * after we return. */
    CancelIoEx(h, ov);
    DWORD dummy = 0;
    GetOverlappedResult(h, ov, &dummy, TRUE);   /* bWait=TRUE: wait for cancel to actually complete */
    return 0;
}

static int write_all(HANDLE h, const void *buf, DWORD len) {
    const BYTE *p = (const BYTE *)buf;
    DWORD sent = 0;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    if (!ev) return 0;
    int rc = 1;
    while (sent < len) {
        OVERLAPPED ov = {0};
        ov.hEvent = ev;
        ResetEvent(ev);
        DWORD chunk = 0;
        BOOL ok = WriteFile(h, p + sent, len - sent, &chunk, &ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING) { rc = 0; break; }
        if (!overlapped_wait(h, &ov, ev, &chunk))        { rc = 0; break; }
        if (chunk == 0)                                  { rc = 0; break; }
        sent += chunk;
    }
    CloseHandle(ev);
    return rc;
}

static int read_all(HANDLE h, void *buf, DWORD len) {
    BYTE *p = (BYTE *)buf;
    DWORD got = 0;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ev) return 0;
    int rc = 1;
    while (got < len) {
        OVERLAPPED ov = {0};
        ov.hEvent = ev;
        ResetEvent(ev);
        DWORD chunk = 0;
        BOOL ok = ReadFile(h, p + got, len - got, &chunk, &ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING) { rc = 0; break; }
        if (!overlapped_wait(h, &ov, ev, &chunk))        { rc = 0; break; }
        if (chunk == 0)                                  { rc = 0; break; }
        got += chunk;
    }
    CloseHandle(ev);
    return rc;
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
        FILE_FLAG_OVERLAPPED,  /* v-audit-hardening: required for
                                 * timeout-bounded read/write helpers
                                 * above. See their block comment for
                                 * the P0 rationale. */
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
