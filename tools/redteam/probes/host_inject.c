// host_inject.c -- minimal LoadLibrary injector for the SYSTEM-host load test.
//
// Enables SeDebugPrivilege, opens the target, writes the DLL path, and fires a
// remote LoadLibraryW. Standard, well-worn injection -- deliberately simple so
// the test's only variable is "does the host tolerate our DLL." (The real thing
// will manual-map + PEB-unlink for stealth; this is just the go/no-go probe.)
//
// Build:  cl /nologo host_inject.c /link advapi32.lib
// Usage:  host_inject <pid> <full\path\to\dll>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static void enable_debug(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    LUID luid;
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(tok);
}

int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: host_inject <pid> <dllpath>\n"); return 1; }
    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    wchar_t wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, argv[2], -1, wpath, MAX_PATH);

    enable_debug();
    HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
                           | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!p) { printf("OpenProcess(%lu) failed %lu\n", pid, GetLastError()); return 2; }

    SIZE_T sz = (wcslen(wpath) + 1) * sizeof(wchar_t);
    void *rem = VirtualAllocEx(p, NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { printf("VirtualAllocEx failed %lu\n", GetLastError()); CloseHandle(p); return 3; }
    if (!WriteProcessMemory(p, rem, wpath, sz, NULL)) {
        printf("WriteProcessMemory failed %lu\n", GetLastError()); CloseHandle(p); return 4;
    }
    FARPROC ll = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE th = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)ll, rem, 0, NULL);
    if (!th) { printf("CreateRemoteThread failed %lu\n", GetLastError()); CloseHandle(p); return 5; }
    WaitForSingleObject(th, 8000);
    DWORD mod = 0; GetExitCodeThread(th, &mod);
    printf("injected pid=%lu: remote LoadLibraryW returned 0x%lX (%s)\n",
           pid, mod, mod ? "module loaded" : "LOAD FAILED");
    CloseHandle(th); CloseHandle(p);
    return mod ? 0 : 6;
}
