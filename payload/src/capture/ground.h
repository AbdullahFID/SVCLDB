/* ================================================================== *
 * ground.h -- Click grounding: snap coordinates to real UI elements +  *
 * build a ground-truth element anchor block for the LLM prompt.        *
 *                                                                    *
 * Strategy (see docs plan "ground"):                                  *
 *   PRIMARY : UIAutomation COM (ElementFromPoint / GetClickablePoint / *
 *             tree enumerate). Biggest click-accuracy lever besides    *
 *             the grid.                                                *
 *   FALLBACK (apps that block MSAA/UIAutomation -- MUST be just as     *
 *             good): grid + vision + zoom re-inspect (solve.c), plus    *
 *             optional OCR text anchors. Computer-use models don't need *
 *             UIA at all (pixel-trained), so agent mode degrades least. *
 *                                                                    *
 * Everything fails OPEN: any error returns "no grounding" and the      *
 * solve proceeds on raw model coordinates.                            *
 * ================================================================== */
#ifndef SVCLDB_CAPTURE_GROUND_H
#define SVCLDB_CAPTURE_GROUND_H

#include "../input/coords.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Snap a screen point (physical px) to the center of the actionable
 * element under it. Returns 1 and fills out_* if it snapped to a real
 * element center, 0 to keep the original point. */
int ground_snap_screen(int sx, int sy, int *out_sx, int *out_sy);

/* Build the element anchor block for the LLM user message: lines of
 * `role | "label" | cx,cy` where cx,cy are IMAGE-SPACE centers (already
 * scaled by render_scale, clamped to the shot). Returns a heap string
 * (free with ground_free) or NULL if no grounding is available. */
char *ground_build_anchor_block(const svc_monitor_t *mon, double render_scale);

void ground_free(char *s);

/* Diagnostics: bit0 = UIA available, bit1 = OCR anchors available. */
int  ground_capabilities(void);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_CAPTURE_GROUND_H */
