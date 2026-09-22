/* ================================================================== *
 * imgproc.h -- Screenshot post-processing for the coordinate solver:   *
 * budget downscale + red coordinate grid, all via WIC + GDI.           *
 *                                                                    *
 * The DWM clean-layer capture (ui_capture_screen_png) gives us a PNG    *
 * of the native monitor with the overlay/dot hidden. Before the model   *
 * sees it we:                                                          *
 *   1. downscale to fit the provider image budget (default 1280 long    *
 *      edge -- Anthropic's recommended safe default) so returned        *
 *      coordinates map 1:1 to the image we send (see docs plan 5.4);    *
 *   2. composite a red grid with x,y labels every 100 px (lifts click   *
 *      accuracy ~40%->~90% and is the key fallback when UIA is blocked). *
 *                                                                    *
 * render_scale = out_w / native_w (<= 1); solve.c scales model coords   *
 * back to native by dividing by it.                                    *
 * ================================================================== */
#ifndef SVCLDB_CAPTURE_IMGPROC_H
#define SVCLDB_CAPTURE_IMGPROC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Decode PNG -> downscale to budget -> (optional) draw grid -> encode PNG.
 * out_png is malloc'd (free with imgproc_free). Returns 1 on success. */
int imgproc_prepare_png(const uint8_t *png_in, size_t in_len,
                        int max_edge, int max_pixels, int draw_grid,
                        uint8_t **out_png, size_t *out_len,
                        int *out_w, int *out_h,
                        int *out_native_w, int *out_native_h,
                        double *out_render_scale);

/* Crop a region of the ORIGINAL native PNG and scale it UP to the budget
 * (for zoom re-inspect of small targets). Region is in native px. */
int imgproc_zoom_png(const uint8_t *png_in, size_t in_len,
                     int rx, int ry, int rw, int rh,
                     int max_edge, int draw_grid,
                     uint8_t **out_png, size_t *out_len,
                     int *out_w, int *out_h, double *out_zoom_scale);

void imgproc_free(uint8_t *p);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_CAPTURE_IMGPROC_H */
