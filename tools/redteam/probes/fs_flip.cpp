// fs_flip.cpp -- NON-ADMIN fullscreen independent-flip reproducer.
// Models what OnVUE's fullscreen secure browser does to DWM: a borderless
// window exactly covering the monitor with a flip-model swapchain presenting
// every vsync. Windows promotes this to independent flip / MPO -> the GPU
// scans out THIS swapchain directly, bypassing DWM composition -> a DWM-
// composited overlay (svcldb) stops being drawn because DWM stops calling
// its compositor present path. If the overlay vanishes while this runs, the
// mechanism is confirmed.
//   cl /nologo /EHsc fs_flip.cpp /link d3d11.lib dxgi.lib
//   fs_flip.exe 15      (fullscreen for 15 seconds)
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <cstdio>
#include <cstdlib>
#pragma comment(lib,"d3d11.lib")
#pragma comment(lib,"dxgi.lib")

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProc(h, m, w, l);
}

int main(int argc, char** argv) {
    int secs = argc > 1 ? atoi(argv[1]) : 15;
    bool excl = (argc > 2 && (!strcmp(argv[2], "excl") || !strcmp(argv[2], "exclusive")));
    SetProcessDPIAware();   // so GetSystemMetrics returns PHYSICAL pixels -> window covers the whole monitor -> DWM promotes to independent flip
    int W = GetSystemMetrics(SM_CXSCREEN), H = GetSystemMetrics(SM_CYSCREEN);
    WNDCLASSA wc = {}; wc.lpfnWndProc = WndProc; wc.hInstance = GetModuleHandleA(0); wc.lpszClassName = "fsflip";
    RegisterClassA(&wc);
    HWND hwnd = CreateWindowExA(WS_EX_TOPMOST, "fsflip", "fsflip",
        WS_POPUP | WS_VISIBLE, 0, 0, W, H, 0, 0, wc.hInstance, 0);
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, W, H, SWP_SHOWWINDOW);
    ShowWindow(hwnd, SW_SHOW);

    D3D_FEATURE_LEVEL fl; ID3D11Device* dev = 0; ID3D11DeviceContext* ctx = 0;
    HRESULT hr = D3D11CreateDevice(0, D3D_DRIVER_TYPE_HARDWARE, 0, 0, 0, 0, D3D11_SDK_VERSION, &dev, &fl, &ctx);
    if (FAILED(hr)) { printf("D3D11CreateDevice=0x%08lx\n", (unsigned long)hr); return 1; }
    IDXGIDevice* dxd = 0; dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxd);
    IDXGIAdapter* ad = 0; dxd->GetAdapter(&ad);
    IDXGIFactory2* f = 0; ad->GetParent(__uuidof(IDXGIFactory2), (void**)&f);
    DXGI_SWAP_CHAIN_DESC1 sd = {};
    sd.Width = W; sd.Height = H; sd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.SampleDesc.Count = 1; sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2; sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD; sd.Scaling = DXGI_SCALING_NONE;
    IDXGISwapChain1* sc = 0;
    hr = f->CreateSwapChainForHwnd(dev, hwnd, &sd, 0, 0, &sc);
    if (FAILED(hr)) { printf("CreateSwapChainForHwnd=0x%08lx\n", (unsigned long)hr); return 2; }
    if (excl) {
        HRESULT fhr = sc->SetFullscreenState(TRUE, NULL);
        printf("fs_flip: SetFullscreenState(TRUE) hr=0x%08lx\n", (unsigned long)fhr);
        sc->ResizeBuffers(2, W, H, DXGI_FORMAT_R8G8B8A8_UNORM, 0);
    }
    ID3D11Texture2D* bb = 0; sc->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&bb);
    ID3D11RenderTargetView* rtv = 0; dev->CreateRenderTargetView(bb, 0, &rtv);

    printf("fs_flip: %s %dx%d flip swapchain for %ds (present every vsync)\n",
           excl ? "EXCLUSIVE-fullscreen" : "borderless-fullscreen", W, H, secs);
    fflush(stdout);
    DWORD t0 = GetTickCount(); int frame = 0;
    while (GetTickCount() - t0 < (DWORD)secs * 1000) {
        MSG msg; while (PeekMessage(&msg, 0, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessage(&msg); }
        float c = (frame % 180) / 180.0f; float col[4] = { c * 0.2f, 0.05f, 0.15f, 1.0f };
        ctx->ClearRenderTargetView(rtv, col);
        sc->Present(1, 0);   // vsync present -> drives independent flip
        frame++;
    }
    if (excl) sc->SetFullscreenState(FALSE, NULL);   // restore desktop composition
    printf("fs_flip: done, %d frames presented\n", frame);
    return 0;
}
