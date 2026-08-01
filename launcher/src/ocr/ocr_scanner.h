/* ================================================================== *
 * ocr_scanner.h — C-callable interface to the OCR redactor pipeline.  *
 *                                                                    *
 * All work happens in-process in sihost's --ocr-daemon mode:         *
 * WinRT Windows.Media.Ocr → match user blacklist → paint black       *
 * rects on the BGRA in place. Payload sends BGRA in, gets            *
 * redacted BGRA back over a named pipe.                              *
 *                                                                    *
 * See docs/ handoff HANDOFF_OCR_BLACKOUT_PORTABLE_REFERENCE for      *
 * the design rationale (portable across projects).                   *
 * ================================================================== */
#ifndef SVCLDB_OCR_SCANNER_H
#define SVCLDB_OCR_SCANNER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Named-pipe endpoint used by payload ↔ sihost daemon.
 * Local machine, single client (payload) at a time. */
#define OCR_PIPE_NAME "\\\\.\\pipe\\svcldb_ocr_v1"

/* Wire-format magic (4 bytes) — validates the peer is actually a
 * payload-side pipe client and not a stray connection. */
#define OCR_WIRE_MAGIC 0x4F435231u   /* 'OCR1' little-endian */

/* Request header sent by payload → sihost daemon. Followed by
 * (width * height * 4) BGRA8 bytes tightly packed. */
typedef struct {
    uint32_t magic;      /* MUST == OCR_WIRE_MAGIC */
    uint32_t opcode;     /* 1 = scan+paint BGRA in place; 2 = shutdown daemon */
    uint32_t width;
    uint32_t height;
    uint32_t byte_len;   /* == width*height*4 for opcode 1; 0 for opcode 2 */
} ocr_req_hdr_t;

/* Response header. For opcode 1: followed by (byte_len) painted BGRA
 * bytes. For opcode 2: no body, daemon exits after send. */
typedef struct {
    uint32_t magic;         /* == OCR_WIRE_MAGIC */
    int32_t  status;        /* 0 = ok, -1 = invalid req, -2 = OCR unavailable,
                             *   -3 = internal error */
    uint32_t byte_len;      /* == request width*height*4 on success, else 0 */
    uint32_t rect_count;    /* number of rects painted (informational) */
} ocr_resp_hdr_t;

/* ── Public C API (called from main.c --ocr-daemon path) ────────── */

/* Initialize the OCR engine + load blacklist JSON. `blacklist_path` is
 * NUL-terminated ANSI path to ocr_blacklist.json; NULL falls back to
 * embedded defaults (all 6 tiers baked in).
 *
 * Returns:
 *   0 on success (engine ready).
 *  -1 on invalid args.
 *  -2 if no OCR recognizer language is installed (daemon should exit
 *     and let launcher-side DISM install path handle the FoD; not
 *     implemented in MVP — we just log and refuse to start).
 *  -3 on any other WinRT / init failure. */
int ocr_daemon_init(const char *blacklist_path);

/* Process one BGRA8 frame in place: OCR → match → paint black rects
 * over matching words/phrases. Buffer must be tightly-packed
 * width*height*4 bytes; the same buffer is mutated on success.
 *
 * Returns:
 *   >= 0 on success (number of rects painted).
 *  -1 on invalid args.
 *  -3 on OCR failure — buffer is left untouched. */
int ocr_daemon_process_bgra(uint8_t *bgra, uint32_t width, uint32_t height);

/* Re-read blacklist JSON if the file's mtime changed since last load.
 * Cheap when unchanged. Called before every request. */
void ocr_daemon_maybe_reload_blacklist(void);

/* Free engine + blacklist. Idempotent. */
void ocr_daemon_shutdown(void);

/* ── Diagnostics — for the daemon's launcher.log lines. ─────────── */
int  ocr_daemon_language_count(void);  /* # recognizer langs available */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SVCLDB_OCR_SCANNER_H */
