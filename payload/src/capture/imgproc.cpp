/* ================================================================== *
 * imgproc.cpp -- WIC downscale + GDI coordinate grid (see imgproc.h).   *
 * Compiled as C++ for clean WIC/COM usage; exports extern "C".          *
 * ================================================================== */
#include <windows.h>
#include <objbase.h>
#include <wincodec.h>
#include <math.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "imgproc.h"

extern "C" void slog_writef(const char *file, const char *fmt, ...);

/* ── WIC factory (lazy, per-process) ────────────────────────────── */
static IWICImagingFactory *g_wic = nullptr;
static CRITICAL_SECTION    g_wic_cs;
static volatile LONG       g_wic_cs_init = 0;

static IWICImagingFactory *wic(void) {
    if (InterlockedCompareExchange(&g_wic_cs_init, 1, 0) == 0)
        InitializeCriticalSection(&g_wic_cs);
    EnterCriticalSection(&g_wic_cs);
    if (!g_wic) {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                         IID_PPV_ARGS(&g_wic));
    }
    IWICImagingFactory *f = g_wic;
    LeaveCriticalSection(&g_wic_cs);
    return f;
}

static void compute_render_size(int nw, int nh, int max_edge, int max_pixels,
                                int *rw, int *rh, double *scale) {
    if (nw <= 0 || nh <= 0) { *rw = nw; *rh = nh; *scale = 1.0; return; }
    double aspect = (double)nw / (double)nh;
    double w, h;
    double hFromPx = sqrt((double)max_pixels / aspect);
    double wFromPx = hFromPx * aspect;
    if (nw >= nh) { w = wFromPx < max_edge ? wFromPx : max_edge; h = w / aspect; }
    else          { h = hFromPx < max_edge ? hFromPx : max_edge; w = h * aspect; }
    if (w > nw) w = nw;
    if (h > nh) h = nh;
    int iw = (int)(w + 0.5), ih = (int)(h + 0.5);
    if (iw < 1) iw = 1;
    if (ih < 1) ih = 1;
    *rw = iw; *rh = ih; *scale = (double)iw / (double)nw;
}

/* Draw a red coordinate grid + axis labels every 100 px onto a top-down
 * 32bpp BGRA buffer via GDI. */
static void draw_grid(void *bits, int w, int h) {
    BITMAPINFO bi; ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize     = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth    = w;
    bi.bmiHeader.biHeight   = -h;   /* top-down */
    bi.bmiHeader.biPlanes   = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    HDC screen = GetDC(NULL);
    HDC mem = CreateCompatibleDC(screen);
    void *dibbits = nullptr;
    HBITMAP dib = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &dibbits, NULL, 0);
    if (dib && dibbits) {
        memcpy(dibbits, bits, (size_t)w * h * 4);
        HGDIOBJ old = SelectObject(mem, dib);

        HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 40, 40));
        HGDIOBJ oldpen = SelectObject(mem, pen);
        for (int x = 100; x < w; x += 100) { MoveToEx(mem, x, 0, NULL); LineTo(mem, x, h); }
        for (int y = 100; y < h; y += 100) { MoveToEx(mem, 0, y, NULL); LineTo(mem, w, y); }

        HFONT font = CreateFontA(-11, 0, 0, 0, FW_BOLD, 0, 0, 0, ANSI_CHARSET,
                                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        HGDIOBJ oldfont = SelectObject(mem, font);
        SetBkMode(mem, TRANSPARENT);
        SetTextColor(mem, RGB(255, 40, 40));
        char lbl[16];
        for (int x = 100; x < w; x += 100) {
            _snprintf(lbl, sizeof(lbl) - 1, "%d", x); lbl[sizeof(lbl) - 1] = 0;
            TextOutA(mem, x + 2, 1, lbl, (int)strlen(lbl));
        }
        for (int y = 100; y < h; y += 100) {
            _snprintf(lbl, sizeof(lbl) - 1, "%d", y); lbl[sizeof(lbl) - 1] = 0;
            TextOutA(mem, 1, y + 1, lbl, (int)strlen(lbl));
        }

        GdiFlush();
        memcpy(bits, dibbits, (size_t)w * h * 4);

        SelectObject(mem, oldfont); DeleteObject(font);
        SelectObject(mem, oldpen);  DeleteObject(pen);
        SelectObject(mem, old);
    }
    if (dib) DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(NULL, screen);
}

/* Encode a top-down 32bpp BGRA buffer to PNG bytes (malloc'd). */
static int encode_png_bgra(IWICImagingFactory *f, void *bits, int w, int h,
                           uint8_t **out_png, size_t *out_len) {
    int ok = 0;
    IStream *stream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(NULL, TRUE, &stream))) return 0;

    IWICBitmapEncoder *enc = nullptr;
    IWICBitmapFrameEncode *frame = nullptr;
    if (SUCCEEDED(f->CreateEncoder(GUID_ContainerFormatPng, nullptr, &enc)) && enc &&
        SUCCEEDED(enc->Initialize(stream, WICBitmapEncoderNoCache)) &&
        SUCCEEDED(enc->CreateNewFrame(&frame, nullptr)) && frame &&
        SUCCEEDED(frame->Initialize(nullptr))) {
        frame->SetSize(w, h);
        WICPixelFormatGUID fmt = GUID_WICPixelFormat32bppBGRA;
        frame->SetPixelFormat(&fmt);
        UINT stride = (UINT)w * 4;
        UINT bufsz  = stride * (UINT)h;
        if (SUCCEEDED(frame->WritePixels((UINT)h, stride, bufsz, (BYTE *)bits)) &&
            SUCCEEDED(frame->Commit()) && SUCCEEDED(enc->Commit())) {
            /* pull bytes back out of the HGLOBAL stream */
            HGLOBAL hg = NULL;
            if (SUCCEEDED(GetHGlobalFromStream(stream, &hg)) && hg) {
                SIZE_T sz = GlobalSize(hg);
                void *src = GlobalLock(hg);
                if (src && sz) {
                    uint8_t *b = (uint8_t *)malloc(sz);
                    if (b) { memcpy(b, src, sz); *out_png = b; *out_len = sz; ok = 1; }
                }
                if (src) GlobalUnlock(hg);
            }
        }
    }
    if (frame)  frame->Release();
    if (enc)    enc->Release();
    if (stream) stream->Release();
    return ok;
}

/* Decode PNG -> IWICBitmapSource (+ native size). */
static IWICBitmapSource *decode_png(IWICImagingFactory *f, const uint8_t *in,
                                    size_t len, UINT *nw, UINT *nh) {
    IWICStream *stm = nullptr;
    if (FAILED(f->CreateStream(&stm)) || !stm) return nullptr;
    if (FAILED(stm->InitializeFromMemory((BYTE *)in, (DWORD)len))) { stm->Release(); return nullptr; }
    IWICBitmapDecoder *dec = nullptr;
    if (FAILED(f->CreateDecoderFromStream(stm, nullptr, WICDecodeMetadataCacheOnLoad, &dec)) || !dec) {
        stm->Release(); return nullptr;
    }
    IWICBitmapFrameDecode *frame = nullptr;
    IWICBitmapSource *src = nullptr;
    if (SUCCEEDED(dec->GetFrame(0, &frame)) && frame) {
        frame->GetSize(nw, nh);
        frame->QueryInterface(IID_PPV_ARGS(&src));
        frame->Release();
    }
    dec->Release();
    stm->Release();
    return src;
}

/* Scale (or pass through) a source to (rw,rh) as 32bpp BGRA into a malloc'd
 * buffer. */
static void *source_to_bgra(IWICImagingFactory *f, IWICBitmapSource *src,
                            int rw, int rh) {
    IWICBitmapScaler *scaler = nullptr;
    IWICBitmapSource *use = src;
    if (SUCCEEDED(f->CreateBitmapScaler(&scaler)) && scaler &&
        SUCCEEDED(scaler->Initialize(src, rw, rh, WICBitmapInterpolationModeFant))) {
        use = scaler;
    }
    IWICFormatConverter *conv = nullptr;
    IWICBitmapSource *bgra = use;
    if (SUCCEEDED(f->CreateFormatConverter(&conv)) && conv &&
        SUCCEEDED(conv->Initialize(use, GUID_WICPixelFormat32bppBGRA,
                                   WICBitmapDitherTypeNone, nullptr, 0.0,
                                   WICBitmapPaletteTypeCustom))) {
        bgra = conv;
    }
    void *buf = malloc((size_t)rw * rh * 4);
    if (buf) {
        UINT stride = (UINT)rw * 4;
        if (FAILED(bgra->CopyPixels(nullptr, stride, stride * (UINT)rh, (BYTE *)buf))) {
            free(buf); buf = nullptr;
        }
    }
    if (conv)   conv->Release();
    if (scaler) scaler->Release();
    return buf;
}

extern "C" int imgproc_prepare_png(const uint8_t *png_in, size_t in_len,
                                   int max_edge, int max_pixels, int draw_grid_flag,
                                   uint8_t **out_png, size_t *out_len,
                                   int *out_w, int *out_h,
                                   int *out_native_w, int *out_native_h,
                                   double *out_render_scale) {
    if (!png_in || !in_len || !out_png || !out_len) return 0;
    IWICImagingFactory *f = wic();
    if (!f) return 0;
    if (max_edge <= 0)   max_edge   = 1280;
    if (max_pixels <= 0) max_pixels = 1280 * 800;

    UINT nw = 0, nh = 0;
    IWICBitmapSource *src = decode_png(f, png_in, in_len, &nw, &nh);
    if (!src || nw == 0 || nh == 0) { if (src) src->Release(); return 0; }

    int rw, rh; double scale;
    compute_render_size((int)nw, (int)nh, max_edge, max_pixels, &rw, &rh, &scale);

    void *buf = source_to_bgra(f, src, rw, rh);
    src->Release();
    if (!buf) return 0;

    if (draw_grid_flag) draw_grid(buf, rw, rh);

    int ok = encode_png_bgra(f, buf, rw, rh, out_png, out_len);
    free(buf);
    if (!ok) return 0;

    if (out_w) *out_w = rw;
    if (out_h) *out_h = rh;
    if (out_native_w) *out_native_w = (int)nw;
    if (out_native_h) *out_native_h = (int)nh;
    if (out_render_scale) *out_render_scale = scale;
    slog_writef("msvc_dbg_a.dat", "imgproc: native=%ux%u render=%dx%d scale=%.4f grid=%d",
                nw, nh, rw, rh, scale, draw_grid_flag);
    return 1;
}

extern "C" int imgproc_zoom_png(const uint8_t *png_in, size_t in_len,
                                int rx, int ry, int rw_in, int rh_in,
                                int max_edge, int draw_grid_flag,
                                uint8_t **out_png, size_t *out_len,
                                int *out_w, int *out_h, double *out_zoom_scale) {
    if (!png_in || !in_len || !out_png || !out_len || rw_in <= 0 || rh_in <= 0) return 0;
    IWICImagingFactory *f = wic();
    if (!f) return 0;
    if (max_edge <= 0) max_edge = 1280;

    UINT nw = 0, nh = 0;
    IWICBitmapSource *src = decode_png(f, png_in, in_len, &nw, &nh);
    if (!src || nw == 0 || nh == 0) { if (src) src->Release(); return 0; }

    /* clamp crop rect to native bounds */
    if (rx < 0) rx = 0; if (ry < 0) ry = 0;
    if (rx + rw_in > (int)nw) rw_in = (int)nw - rx;
    if (ry + rh_in > (int)nh) rh_in = (int)nh - ry;
    if (rw_in <= 0 || rh_in <= 0) { src->Release(); return 0; }

    IWICBitmapClipper *clip = nullptr;
    IWICBitmapSource *cropped = src;
    WICRect wr = { rx, ry, rw_in, rh_in };
    if (SUCCEEDED(f->CreateBitmapClipper(&clip)) && clip &&
        SUCCEEDED(clip->Initialize(src, &wr))) {
        cropped = clip;
    }

    /* scale the crop UP to the budget (preserve aspect) */
    double aspect = (double)rw_in / (double)rh_in;
    int ow, oh;
    if (rw_in >= rh_in) { ow = max_edge; oh = (int)(max_edge / aspect + 0.5); }
    else                { oh = max_edge; ow = (int)(max_edge * aspect + 0.5); }
    if (ow < 1) ow = 1; if (oh < 1) oh = 1;

    void *buf = source_to_bgra(f, cropped, ow, oh);
    if (clip) clip->Release();
    src->Release();
    if (!buf) return 0;

    if (draw_grid_flag) draw_grid(buf, ow, oh);
    int ok = encode_png_bgra(f, buf, ow, oh, out_png, out_len);
    free(buf);
    if (!ok) return 0;

    if (out_w) *out_w = ow;
    if (out_h) *out_h = oh;
    if (out_zoom_scale) *out_zoom_scale = (double)ow / (double)rw_in;
    return 1;
}

extern "C" void imgproc_free(uint8_t *p) { if (p) free(p); }
