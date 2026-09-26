/* rehook_throttle_probe.c -- does Windows throttle rapid WH_KEYBOARD_LL
 * (un)install? The payload's REINSTALL_INTERVAL_MS comment claims "do NOT
 * lower below 500ms -- Windows may throttle rapid hook installations as
 * anti-abuse." Measure it: install+unhook N times as fast as possible and
 * report the per-iteration cost + whether any call ever fails.
 *
 * Build: cl /nologo /EHsc rehook_throttle_probe.c /link user32.lib
 */
#include <windows.h>
#include <stdio.h>

static LRESULT CALLBACK proc(int c, WPARAM w, LPARAM l) { return CallNextHookEx(NULL, c, w, l); }

int main(void) {
    const int N = 2000;
    LARGE_INTEGER f, a, b; QueryPerformanceFrequency(&f);
    int fails = 0; DWORD firstFailGle = 0;
    QueryPerformanceCounter(&a);
    for (int i = 0; i < N; i++) {
        HHOOK h = SetWindowsHookExW(WH_KEYBOARD_LL, proc, GetModuleHandleW(NULL), 0);
        if (!h) { if (!fails) firstFailGle = GetLastError(); fails++; continue; }
        UnhookWindowsHookEx(h);
    }
    QueryPerformanceCounter(&b);
    double total_ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)f.QuadPart;
    printf("iterations=%d  total=%.2f ms  per-iter=%.4f ms  install_fails=%d firstFailGle=%lu\n",
           N, total_ms, total_ms / N, fails, firstFailGle);
    printf("=> rapid re-hook throttled: %s\n", fails ? "YES (some installs failed)" : "NO (all installs OK)");
    return 0;
}
