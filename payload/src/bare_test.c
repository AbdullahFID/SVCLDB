/* Bulletproof bare DLL — writes to THREE places + OutputDebugString.
 * If NONE of these fire, DllMain literally isn't running. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void try_write(const char *path, const char *msg, DWORD len) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, msg, len, &w, NULL);
        CloseHandle(h);
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID res) {
    (void)h; (void)res;
    if (r == DLL_PROCESS_ATTACH) {
        /* Big visible marker in the debugger stream. */
        OutputDebugStringA("SVCLDB_BARE_TEST_DLLMAIN_ATTACH");
        /* Try three different paths in case one has ACL issues. */
        const char *msg = "HELLO FROM DLLMAIN\r\n";
        try_write("C:\\Windows\\Temp\\svcldb_bare.txt", msg, 20);
        try_write("C:\\ProgramData\\svcldb_bare.txt",   msg, 20);
        try_write("C:\\ProgramData\\Microsoft\\WSMonitoring\\bare_test.txt", msg, 20);
    }
    return TRUE;
}
