/*
 * deint.c -- de-elevate to Medium IL and spawn the given command.
 *
 * Uses SaferCreateLevel(SAFER_LEVELID_NORMALUSER) + SaferComputeTokenFromLevel
 * to build a restricted token, then CreateProcessAsUserW (or the WithToken
 * fallback) to spawn the child. The token is forced to Medium integrity
 * regardless of what Safer picks, since SAFER's integrity choice varies by
 * Windows build.
 *
 * Usage:  deint.exe <exe> [args...]
 * The child inherits our stdio via inheritance (NOT STARTF_USESTDHANDLES,
 * which crashed on some Win11 builds when the caller was itself a redirected
 * shell child).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsafer.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

static BOOL set_medium_integrity(HANDLE tok) {
    PSID psid = NULL;
    if (!ConvertStringSidToSidA("S-1-16-8192", &psid)) return FALSE;
    TOKEN_MANDATORY_LABEL tml;
    tml.Label.Sid = psid;
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    DWORD sz = (DWORD)(sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(psid));
    BOOL ok = SetTokenInformation(tok, TokenIntegrityLevel, &tml, sz);
    LocalFree(psid);
    return ok;
}

/* Quote arg for CommandLineToArgvW round-trip; caller ensures buf has room. */
static void append_quoted(wchar_t *cmdline, size_t cap, const wchar_t *arg) {
    wcscat_s(cmdline, cap, L"\"");
    /* Escape embedded backslashes+quotes per Microsoft's argv rules --
     * safe simple version: escape only " with \". Good enough for our
     * probe payloads (they don't contain literal quotes). */
    size_t len = wcslen(arg);
    for (size_t i = 0; i < len; i++) {
        wchar_t c = arg[i];
        if (c == L'"') wcscat_s(cmdline, cap, L"\\\"");
        else { wchar_t s[2] = { c, 0 }; wcscat_s(cmdline, cap, s); }
    }
    wcscat_s(cmdline, cap, L"\"");
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        fwprintf(stderr, L"usage: deint.exe <exe> [args...]\n");
        return 2;
    }

    /* Resolve exe to full path via SearchPathW -- CreateProcessAsUserW is
     * stricter than CreateProcessW about relative names. */
    wchar_t exePath[MAX_PATH * 2] = {0};
    if (!SearchPathW(NULL, argv[1], L".exe", MAX_PATH * 2, exePath, NULL)) {
        /* Fall back to whatever the user passed -- maybe already a full path. */
        wcsncpy_s(exePath, MAX_PATH * 2, argv[1], _TRUNCATE);
    }

    /* Build a fully quoted command line. First token is the exe path. */
    size_t cap = 32768;
    wchar_t *cmdline = (wchar_t *)calloc(cap, sizeof(wchar_t));
    if (!cmdline) return 3;
    append_quoted(cmdline, cap, exePath);
    for (int i = 2; i < argc; i++) {
        wcscat_s(cmdline, cap, L" ");
        append_quoted(cmdline, cap, argv[i]);
    }

    SAFER_LEVEL_HANDLE lvl = NULL;
    if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER,
                          SAFER_LEVEL_OPEN, &lvl, NULL)) {
        fwprintf(stderr, L"SaferCreateLevel failed gle=%lu\n", GetLastError());
        free(cmdline);
        return 4;
    }
    HANDLE restrictedTok = NULL;
    if (!SaferComputeTokenFromLevel(lvl, NULL, &restrictedTok,
                                     SAFER_TOKEN_NULL_IF_EQUAL, NULL)) {
        DWORD gle = GetLastError();
        SaferCloseLevel(lvl);
        fwprintf(stderr, L"SaferComputeTokenFromLevel failed gle=%lu\n", gle);
        free(cmdline);
        return 5;
    }
    SaferCloseLevel(lvl);

    if (restrictedTok == NULL) {
        /* We were already at NormalUser -- clone our own token. */
        HANDLE self = NULL;
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
                              TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                              &self)) {
            fwprintf(stderr, L"OpenProcessToken fallback failed gle=%lu\n", GetLastError());
            free(cmdline);
            return 6;
        }
        if (!DuplicateTokenEx(self, MAXIMUM_ALLOWED, NULL,
                              SecurityImpersonation, TokenPrimary,
                              &restrictedTok)) {
            CloseHandle(self);
            fwprintf(stderr, L"DuplicateTokenEx failed gle=%lu\n", GetLastError());
            free(cmdline);
            return 6;
        }
        CloseHandle(self);
    }

    /* Force integrity to Medium. */
    if (!set_medium_integrity(restrictedTok)) {
        fwprintf(stderr, L"set_medium_integrity failed gle=%lu (continuing)\n",
                 GetLastError());
    }

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    /* Deliberately DO NOT set STARTF_USESTDHANDLES -- with a restricted
     * token that path can AV inside CSRSS on Win11 24H2 when the caller's
     * stdio handles have restricted DACLs. Handle inheritance via
     * bInheritHandles=TRUE + default STARTUPINFO is enough for a console
     * child that shares our stdio. */
    PROCESS_INFORMATION pi = {0};

    BOOL ok = CreateProcessAsUserW(restrictedTok, exePath, cmdline,
                                    NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (!ok) {
        DWORD gle = GetLastError();
        fwprintf(stderr, L"CreateProcessAsUserW failed gle=%lu — trying CreateProcessWithTokenW\n", gle);
        ok = CreateProcessWithTokenW(restrictedTok, 0, exePath, cmdline,
                                     0, NULL, NULL, &si, &pi);
        if (!ok) {
            fwprintf(stderr, L"CreateProcessWithTokenW also failed gle=%lu\n", GetLastError());
            CloseHandle(restrictedTok);
            free(cmdline);
            return 7;
        }
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 1;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(restrictedTok);
    free(cmdline);
    return (int)ec;
}
