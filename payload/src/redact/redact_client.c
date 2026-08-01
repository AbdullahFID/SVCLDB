/* ================================================================== *
 * redact_client.c — payload-side pipe client for the OCR redactor.    *
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

/* Kept in sync with launcher/src/ocr/ocr_scanner.h. Duplicated here
 * to avoid a cross-project include; if you change one, change both. */
#define REDACT_PIPE_NAME  "\\\\.\\pipe\\svcldb_ocr_v1"
#define REDACT_WIRE_MAGIC 0x4F435231u   /* 'OCR1' little-endian */

typedef struct {
    uint32_t magic;
    uint32_t opcode;   /* 1 = scan+paint, 2 = shutdown */
    uint32_t width;
    uint32_t height;
    uint32_t byte_len;
} redact_req_hdr_t;

typedef struct {
    uint32_t magic;
    int32_t  status;
    uint32_t byte_len;
    uint32_t rect_count;
} redact_resp_hdr_t;

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

    /* Try to open the pipe with a short wait (200ms) — daemon may be
     * busy servicing a prior request. WaitNamedPipe + CreateFile is the
     * documented pattern (see MSDN Named Pipes). */
    if (!WaitNamedPipeA(REDACT_PIPE_NAME, 200)) {
        /* No pipe advertised → daemon isn't running → feature is OFF.
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

    int rc = -3;   /* default: protocol/IO error */

    if (!write_all(pipe, &req, (DWORD)sizeof(req))) goto done;
    if (!write_all(pipe, bgra,  byte_len))          goto done;

    redact_resp_hdr_t resp = { 0, 0, 0, 0 };
    if (!read_all(pipe, &resp, (DWORD)sizeof(resp))) goto done;
    if (resp.magic != REDACT_WIRE_MAGIC)             goto done;

    if (resp.status != 0) {
        rc = -2;   /* daemon reported an error — buffer stays untouched */
        goto done;
    }
    if (resp.byte_len != byte_len) {
        /* server sent unexpected size — refuse the response */
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
