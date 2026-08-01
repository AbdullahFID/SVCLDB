/* ================================================================== *
 * redact_client.h — payload-side pipe client for the OCR redactor.    *
 *                                                                    *
 * Sits between the payload's BGRA staging-texture Map and the WIC    *
 * PNG encode. When the sihost --ocr-daemon is running (Electron      *
 * toggle ON), pipes the BGRA out, gets a redacted BGRA back, mutates *
 * the caller's buffer in place. When the daemon is NOT running       *
 * (toggle OFF, default), returns immediately without touching the    *
 * buffer — zero-cost passthrough.                                    *
 *                                                                    *
 * MUST fail silently on every error path. A redactor that breaks     *
 * screenshots is worse than no redactor.                             *
 * ================================================================== */
#ifndef SVCLDB_REDACT_CLIENT_H
#define SVCLDB_REDACT_CLIENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Attempt to redact `bgra` (tightly-packed BGRA8, w*h*4 bytes) in place
 * via the sihost --ocr-daemon on \\.\pipe\svcldb_ocr_v1. The buffer is
 * mutated in place on success.
 *
 * Returns:
 *    >= 0  rects painted (0 == daemon ran OCR but found no matches)
 *    -1    daemon not running (feature OFF) or pipe unreachable — buffer
 *          left untouched, caller should treat as "no redaction happened"
 *    -2    daemon reachable but returned an error — buffer left untouched
 *    -3    protocol / IO error — buffer left untouched
 *
 * Total blocking time on caller thread is bounded — pipe open + rtt +
 * whatever OCR takes (typ. 100-200 ms at 1080p). Safe to call from the
 * DWM render thread since we never hold DWM's device/context. */
int redact_bgra_via_pipe(uint8_t *bgra, uint32_t width, uint32_t height);

/* Cheap probe — is the daemon reachable right now? Uses WaitNamedPipeA
 * with 0ms timeout (never blocks). Useful for a warm-path check that
 * skips even the pipe-open overhead when we know the daemon is down. */
int redact_daemon_available(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SVCLDB_REDACT_CLIENT_H */
