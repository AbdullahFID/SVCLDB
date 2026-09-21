// host_testdll.c -- svcldb SYSTEM-host load-beacon (SEB secure-desktop research).
//
// The MINIMAL possible payload: DllMain writes ONE line to a log on
// DLL_PROCESS_ATTACH and returns TRUE. No threads, no hooks, no imports beyond
// kernel32/user32 -- so loading it into a critical process (winlogon) cannot
// destabilize it. Purpose: prove we can land a DLL in a SYSTEM session-4 host
// and that the host survives, before we put any real logic in.
//
// Build:  cl /nologo /LD host_testdll.c /link kernel32.lib user32.lib
#include <windows.h>

static void beacon(const char *tag) {
    HANDLE f = CreateFileA("C:\\ProgramData\\WinAudioSvc\\host_test.log",
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    char buf[256];
    SYSTEMTIME st; GetLocalTime(&st);
    int n = wsprintfA(buf, "%02d:%02d:%02d.%03d  %s  pid=%lu\r\n",
                      st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                      tag, GetCurrentProcessId());
    SetFilePointer(f, 0, NULL, FILE_END);
    DWORD w; WriteFile(f, buf, (DWORD)n, &w, NULL);
    CloseHandle(f);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        beacon("host_testdll ATTACH");
    }
    return TRUE;
}
