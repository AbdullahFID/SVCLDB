/* ================================================================== *
 * capture.h — Full-screen capture via GDI BitBlt + WIC PNG encode.    *
 *                                                                    *
 * From inside dwm.exe, GetDC(NULL) returns the composed desktop      *
 * surface. Since LDB doesn't WDA-protect itself, we capture LDB's    *
 * exam content just like the main app's autosolver does — except     *
 * we're already inside DWM (which is whitelisted by LDS215) so no    *
 * external process is needed.                                        *
 *                                                                    *
 * Output PNG bytes go straight into the AI request body (base64      *
 * inline for OpenAI, /Anthropic, /Google, /Openrouter).              *
 * ================================================================== */
#ifndef SVCLDB_CAPTURE_H
#define SVCLDB_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Capture the primary monitor → PNG bytes.
 * On success: sets *out_png (malloc'd) + *out_len; return 1.
 * On failure: return 0.
 * Caller must free *out_png. */
int  cap_primary_png(uint8_t **out_png, size_t *out_len);

/* Free PNG bytes from cap_primary_png. */
void cap_free_png(uint8_t *png);

#ifdef __cplusplus
}
#endif

#endif
