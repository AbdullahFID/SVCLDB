// wl_grant.c -- svcldb SEB secure-desktop DACL-grant helper (SYSTEM host).
//
// Rides inside a SYSTEM session-N process (winlogon for universality). A worker
// thread polls the active input desktop; when it lands on a NON-Default desktop
// (SEB's secure desktop, or our simulator's), it rewrites that desktop's DACL to
// grant access, so our DWM-4-hosted payload can finally CreateWindow +
// RegisterRawInputDevices there. This is the piece DWM-4 itself can't do
// (it got ERROR_ACCESS_DENIED reading/writing the DACL) -- SYSTEM can.
//
// TEST BUILD: grants the WORLD (Everyone) SID GENERIC_ALL -- broadest, so DWM-4
// is guaranteed included; proves the mechanism. Production will narrow this to
// exactly dwm.exe's token SID and manual-map instead of LoadLibrary.
//
// Build:  cl /nologo /LD wl_grant.c /link kernel32.lib user32.lib advapi32.lib
#include <windows.h>
#include <aclapi.h>
#include <tlhelp32.h>

static void lg(const char *fmt, ...) {
    char body[512];
    va_list ap; va_start(ap, fmt);
    wvsprintfA(body, fmt, ap);   /* NOTE: wsprintf family has NO %.*s support */
    va_end(ap);
    char line[700];
    SYSTEMTIME st; GetLocalTime(&st);
    wsprintfA(line, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    lstrcatA(line, body);
    lstrcatA(line, "\r\n");
    HANDLE f = CreateFileA("C:\\ProgramData\\WinAudioSvc\\wl_grant.log",
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SetFilePointer(f, 0, NULL, FILE_END);
    DWORD w; WriteFile(f, line, (DWORD)lstrlenA(line), &w, NULL);
    CloseHandle(f);
}

/* Find dwm.exe in our session and return a copy of its token user SID
 * (Window Manager\DWM-N). Caller LocalFree's it. That exact SID is what our
 * payload's CreateWindow is checked against -- "Everyone" does NOT include the
 * DWM virtual account, which is why the first grant didn't take. */
static PSID get_dwm_sid(void) {
    DWORD mysess = 0; ProcessIdToSessionId(GetCurrentProcessId(), &mysess);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    PSID out = NULL;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, L"dwm.exe") == 0) {
                DWORD s = 0; ProcessIdToSessionId(pe.th32ProcessID, &s);
                if (s != mysess) continue;
                HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (p) {
                    HANDLE t;
                    if (OpenProcessToken(p, TOKEN_QUERY, &t)) {
                        DWORD n = 0; GetTokenInformation(t, TokenUser, NULL, 0, &n);
                        TOKEN_USER *tu = (TOKEN_USER *)LocalAlloc(LPTR, n);
                        if (tu && GetTokenInformation(t, TokenUser, tu, n, &n)) {
                            DWORD sl = GetLengthSid(tu->User.Sid);
                            out = (PSID)LocalAlloc(LPTR, sl);
                            if (out) CopySid(sl, out, tu->User.Sid);
                        }
                        if (tu) LocalFree(tu);
                        CloseHandle(t);
                    }
                    CloseHandle(p);
                }
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

static int grant_desktop(HDESK hd) {
    PACL old = NULL; PSECURITY_DESCRIPTOR sd = NULL;
    DWORD rc = GetSecurityInfo(hd, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                               NULL, NULL, &old, NULL, &sd);
    if (rc != ERROR_SUCCESS) { lg("GetSecurityInfo failed %lu", rc); return 0; }

    /* ACE 1: DWM's exact token SID (the one that matters).  ACE 2: Everyone
     * (belt-and-suspenders / covers non-DWM readers). */
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    PSID ev = NULL;
    AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &ev);
    PSID dwm = get_dwm_sid();
    lg("get_dwm_sid => %s", dwm ? "OK" : "NULL");

    EXPLICIT_ACCESSW ea[2]; memset(ea, 0, sizeof(ea));
    int nea = 0;
    if (dwm) {
        ea[nea].grfAccessPermissions = GENERIC_ALL;
        ea[nea].grfAccessMode = GRANT_ACCESS;
        ea[nea].grfInheritance = NO_INHERITANCE;
        ea[nea].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[nea].Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea[nea].Trustee.ptstrName = (LPWSTR)dwm;
        nea++;
    }
    if (ev) {
        ea[nea].grfAccessPermissions = GENERIC_ALL;
        ea[nea].grfAccessMode = GRANT_ACCESS;
        ea[nea].grfInheritance = NO_INHERITANCE;
        ea[nea].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[nea].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[nea].Trustee.ptstrName = (LPWSTR)ev;
        nea++;
    }
    PACL neww = NULL;
    rc = SetEntriesInAclW(nea, ea, old, &neww);
    if (rc != ERROR_SUCCESS) { lg("SetEntriesInAcl failed %lu", rc); if (sd) LocalFree(sd); if (ev) FreeSid(ev); if (dwm) LocalFree(dwm); return 0; }
    rc = SetSecurityInfo(hd, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, neww, NULL);
    lg("SetSecurityInfo => %lu (0=OK; granted DWM SID%s + Everyone)", rc, dwm ? "" : "(MISSING)");
    if (neww) LocalFree(neww);
    if (sd) LocalFree(sd);
    if (ev) FreeSid(ev);
    if (dwm) LocalFree(dwm);
    return rc == ERROR_SUCCESS;
}

static DWORD WINAPI watch(LPVOID unused) {
    (void)unused;
    char last[128] = {0};
    lg("watch thread up in pid=%lu", GetCurrentProcessId());
    for (;;) {
        HDESK hd = OpenInputDesktop(0, FALSE, READ_CONTROL | WRITE_DAC | DESKTOP_READOBJECTS);
        if (hd) {
            char nm[128] = {0}; DWORD n = 0;
            GetUserObjectInformationA(hd, UOI_NAME, nm, sizeof(nm), &n);
            if (nm[0] && lstrcmpiA(nm, "Default") != 0 && lstrcmpiA(nm, "Winlogon") != 0
                && lstrcmpiA(nm, "Screen-saver") != 0 && lstrcmpA(nm, last) != 0) {
                lg("non-Default input desktop '%s' -- granting", nm);
                if (grant_desktop(hd)) lstrcpynA(last, nm, sizeof(last));
            } else if (lstrcmpiA(nm, "Default") == 0 && last[0]) {
                last[0] = 0;   /* back on Default -- re-arm for next switch */
            }
            CloseDesktop(hd);
        } else {
            /* Couldn't even open the input desktop for DACL rights. */
            static int once = 0;
            if (!once) { lg("OpenInputDesktop(WRITE_DAC) denied err=%lu", GetLastError()); once = 1; }
        }
        Sleep(150);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        lg("wl_grant ATTACH pid=%lu", GetCurrentProcessId());
        CreateThread(NULL, 0, watch, NULL, 0, NULL);
    }
    return TRUE;
}
