// wl_input.c -- svcldb SEB secure-desktop INPUT helper (SYSTEM host, e.g. winlogon).
//
// Architecture B. DWM-4 (our overlay's host) is walled out of a foreign secure
// desktop even after its SID is granted the DACL. This helper rides inside a
// SYSTEM session process (winlogon = universal) and does what DWM-4 can't:
//   * watch the active input desktop; when it becomes a NON-Default (SEB) desktop,
//   * SetThreadDesktop onto it, create a hidden RIDEV_INPUTSINK window there
//     (SYSTEM has the access; self-grants the DACL as a fallback if needed),
//   * read raw keyboard input focus-free, and
//   * forward each key event (vk + Ctrl/Shift/Alt) to the DWM payload over the
//     named pipe \\.\pipe\svcldb_seb_input, where the payload matches it against
//     the user's real hotkey bindings and fires -> overlay reacts on SEB's desktop.
// When the desktop switches back, it tears the window down and re-arms.
//
// TEST BUILD: LoadLibrary-injected + logs to wl_input.log. Production will
// manual-map (no module-list trace). Keyboard only for now; mouse gestures TBD.
//
// Build:  cl /nologo /LD wl_input.c /link kernel32.lib user32.lib advapi32.lib
#include <windows.h>
#include <aclapi.h>

#pragma pack(push, 1)
typedef struct {
    unsigned char  type;        /* 0 = key, 1 = mouse */
    unsigned char  down;        /* key: 1=down 0=up */
    unsigned char  ctrl, shift, alt, pad;
    unsigned short vk;          /* key virtual-key */
    unsigned int   wp;          /* mouse: WM_* message code */
    int            x, y;        /* mouse: absolute screen pos */
    unsigned int   mouseData;   /* mouse: wheel delta hi-word / xbutton id */
} seb_evt;
#pragma pack(pop)

/* Named stop-event: a freshly-injected instance signals it so any prior
 * instance's watch/reader threads exit -> hot-swap during iteration without a
 * reboot (no more accumulating competing readers in winlogon). */
static HANDLE g_stop = NULL;
static int superseded(void) { return g_stop && WaitForSingleObject(g_stop, 0) == WAIT_OBJECT_0; }

static void lg(const char *fmt, ...) {
    char body[512];
    va_list ap; va_start(ap, fmt);
    wvsprintfA(body, fmt, ap);
    va_end(ap);
    char line[700];
    SYSTEMTIME st; GetLocalTime(&st);
    wsprintfA(line, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    lstrcatA(line, body); lstrcatA(line, "\r\n");
    HANDLE f = CreateFileA("C:\\ProgramData\\WinAudioSvc\\wl_input.log", FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SetFilePointer(f, 0, NULL, FILE_END);
    DWORD w; WriteFile(f, line, (DWORD)lstrlenA(line), &w, NULL);
    CloseHandle(f);
}

static PSID dup_self_sid(void) {
    HANDLE t; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return NULL;
    DWORD n = 0; GetTokenInformation(t, TokenUser, NULL, 0, &n);
    TOKEN_USER *tu = (TOKEN_USER *)LocalAlloc(LPTR, n);
    PSID out = NULL;
    if (tu && GetTokenInformation(t, TokenUser, tu, n, &n)) {
        DWORD sl = GetLengthSid(tu->User.Sid);
        out = (PSID)LocalAlloc(LPTR, sl);
        if (out) CopySid(sl, out, tu->User.Sid);
    }
    if (tu) LocalFree(tu);
    CloseHandle(t);
    return out;
}

static void grant_self(HDESK hd) {
    PSID s = dup_self_sid();
    if (!s) return;
    PACL old = NULL; PSECURITY_DESCRIPTOR sd = NULL;
    if (GetSecurityInfo(hd, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &old, NULL, &sd) != ERROR_SUCCESS) {
        lg("grant_self: GetSecurityInfo failed %lu", GetLastError()); LocalFree(s); return;
    }
    EXPLICIT_ACCESSW ea; memset(&ea, 0, sizeof(ea));
    ea.grfAccessPermissions = GENERIC_ALL; ea.grfAccessMode = GRANT_ACCESS; ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID; ea.Trustee.TrusteeType = TRUSTEE_IS_USER; ea.Trustee.ptstrName = (LPWSTR)s;
    PACL nw = NULL;
    if (SetEntriesInAclW(1, &ea, old, &nw) == ERROR_SUCCESS) {
        DWORD rc = SetSecurityInfo(hd, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, nw, NULL);
        lg("grant_self: SetSecurityInfo => %lu", rc);
        if (nw) LocalFree(nw);
    }
    if (sd) LocalFree(sd);
    LocalFree(s);
}

static HANDLE connect_pipe(void) {
    for (int i = 0; i < 25; i++) {
        HANDLE h = CreateFileW(L"\\\\.\\pipe\\svcldb_seb_input", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
        Sleep(200);
    }
    return INVALID_HANDLE_VALUE;
}

/* Write one event; on failure, transparently reconnect (SEB may recreate the
 * pipe between desktop entries). *pp is updated in place. */
static void seb_send(HANDLE *pp, const seb_evt *e) {
    if (*pp == INVALID_HANDLE_VALUE) { *pp = connect_pipe(); if (*pp == INVALID_HANDLE_VALUE) return; }
    DWORD w;
    if (!WriteFile(*pp, e, sizeof(*e), &w, NULL)) {
        CloseHandle(*pp);
        *pp = connect_pipe();
    }
}

// We are already SetThreadDesktop'd onto `deskname`. Create the INPUTSINK window,
// read raw keyboard, forward to the pipe, until the input desktop changes away.
static void run_reader(const char *deskname) {
    static int class_done = 0;
    WNDCLASSW wc; memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = DefWindowProcW; wc.hInstance = GetModuleHandleW(NULL); wc.lpszClassName = L"svcldb_seb_ri";
    if (!class_done) { RegisterClassW(&wc); class_done = 1; }

    HWND hwnd = NULL;
    for (int i = 0; i < 20; i++) {
        hwnd = CreateWindowExW(WS_EX_NOACTIVATE, L"svcldb_seb_ri", L"", WS_POPUP, 0, 0, 1, 1, NULL, NULL, wc.hInstance, NULL);
        if (hwnd) break;
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED) {
            if (i == 0) lg("reader: CreateWindow ACCESS_DENIED -- self-granting + retry");
            HDESK cur = OpenInputDesktop(0, FALSE, READ_CONTROL | WRITE_DAC | DESKTOP_READOBJECTS);
            if (cur) { grant_self(cur); CloseDesktop(cur); }
        } else { lg("reader: CreateWindow failed %lu", e); }
        Sleep(150);
    }
    if (!hwnd) { lg("reader: could not create window on '%s' -- giving up", deskname); return; }
    lg("reader: INPUTSINK window up hwnd=%p on '%s'", hwnd, deskname);

    RAWINPUTDEVICE rid[2];
    rid[0].usUsagePage = 0x01; rid[0].usUsage = 0x06; rid[0].dwFlags = RIDEV_INPUTSINK; rid[0].hwndTarget = hwnd;
    rid[1].usUsagePage = 0x01; rid[1].usUsage = 0x02; rid[1].dwFlags = RIDEV_INPUTSINK; rid[1].hwndTarget = hwnd;
    BOOL rok = RegisterRawInputDevices(rid, 2, sizeof(RAWINPUTDEVICE));
    lg("reader: RegisterRawInputDevices=%d err=%lu", rok, rok ? 0 : GetLastError());

    HANDLE pipe = connect_pipe();
    lg("reader: pipe %s", pipe != INVALID_HANDLE_VALUE ? "connected" : "FAILED");

    int ctrl = 0, shift = 0, alt = 0;
    unsigned fwd = 0;
    /* Zero-latency: GetMessage sleeps until a message arrives and wakes the
     * instant WM_INPUT is posted. A 200ms WM_TIMER handles the teardown check
     * without a busy poll. */
    SetTimer(hwnd, 1, 200, NULL);
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (m.message == WM_INPUT) {
            UINT sz = 0;
            GetRawInputData((HRAWINPUT)m.lParam, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
            BYTE buf[256];
            if (sz <= sizeof(buf) && GetRawInputData((HRAWINPUT)m.lParam, RID_INPUT, buf, &sz, sizeof(RAWINPUTHEADER)) == sz) {
                RAWINPUT *ri = (RAWINPUT *)buf;
                if (ri->header.dwType == RIM_TYPEKEYBOARD) {
                    USHORT vk = ri->data.keyboard.VKey;
                    /* Use the authoritative Message field (WM_KEYDOWN=0x100,
                     * WM_KEYUP=0x101, WM_SYSKEYDOWN=0x104, WM_SYSKEYUP=0x105).
                     * The Flags & RI_KEY_BREAK bit was misreporting every event
                     * as UP on this hardware -- Message never lies. */
                    UINT kmsg = ri->data.keyboard.Message;
                    int isup = (kmsg == WM_KEYUP || kmsg == WM_SYSKEYUP);
                    if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL) ctrl = !isup;
                    else if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT) shift = !isup;
                    else if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU) alt = !isup;
                    seb_evt e; memset(&e, 0, sizeof(e));
                    e.type = 0; e.down = (BYTE)(!isup); e.ctrl = (BYTE)ctrl; e.shift = (BYTE)shift; e.alt = (BYTE)alt; e.vk = vk;
                    seb_send(&pipe, &e);
                    /* v3.0.1 DIAG: log EVERY key transition (uncapped) so we can trace
                     * modifier + arrow sequencing during hotkey debugging. Strip before ship. */
                    lg("reader: k vk=0x%02X msg=0x%03X flags=0x%X %s (c%d s%d a%d)",
                       vk, kmsg, ri->data.keyboard.Flags, isup ? "UP" : "DN", ctrl, shift, alt);
                    (void)fwd;
                } else if (ri->header.dwType == RIM_TYPEMOUSE) {
                    RAWMOUSE *rm = &ri->data.mouse;
                    POINT pt; GetCursorPos(&pt);
                    USHORT bf = rm->usButtonFlags;
                    seb_evt e; memset(&e, 0, sizeof(e)); e.type = 1; e.x = pt.x; e.y = pt.y;
                    if (bf & RI_MOUSE_LEFT_BUTTON_DOWN)   { e.wp = 0x0201; e.mouseData = 0; seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_LEFT_BUTTON_UP)     { e.wp = 0x0202; e.mouseData = 0; seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_RIGHT_BUTTON_DOWN)  { e.wp = 0x0204; e.mouseData = 0; seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_RIGHT_BUTTON_UP)    { e.wp = 0x0205; e.mouseData = 0; seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_MIDDLE_BUTTON_DOWN) { e.wp = 0x0207; e.mouseData = 0; seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_MIDDLE_BUTTON_UP)   { e.wp = 0x0208; e.mouseData = 0; seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_4_DOWN)      { e.wp = 0x020B; e.mouseData = (1u << 16); seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_4_UP)        { e.wp = 0x020C; e.mouseData = (1u << 16); seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_5_DOWN)      { e.wp = 0x020B; e.mouseData = (2u << 16); seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_BUTTON_5_UP)        { e.wp = 0x020C; e.mouseData = (2u << 16); seb_send(&pipe, &e); }
                    if (bf & RI_MOUSE_WHEEL)              { e.wp = 0x020A; e.mouseData = ((DWORD)(unsigned short)rm->usButtonData) << 16; seb_send(&pipe, &e); }
                    /* movement: forward MOUSEMOVE when the cursor actually moved */
                    static POINT lastpt = { -100000, -100000 };
                    if (pt.x != lastpt.x || pt.y != lastpt.y) { lastpt = pt; e.wp = 0x0200; e.mouseData = 0; seb_send(&pipe, &e); }
                }
            }
        } else if (m.message == WM_TIMER) {
            if (superseded()) { lg("reader: superseded by newer instance -- tearing down"); break; }
            HDESK cur = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
            char nm[128] = {0}; DWORD n = 0;
            if (cur) { GetUserObjectInformationA(cur, UOI_NAME, nm, sizeof(nm), &n); CloseDesktop(cur); }
            if (lstrcmpA(nm, deskname) != 0) { lg("reader: input desktop moved to '%s' -- tearing down", nm); break; }
        }
        TranslateMessage(&m); DispatchMessageW(&m);
    }
    KillTimer(hwnd, 1);

    RAWINPUTDEVICE rr[2];
    rr[0].usUsagePage = 0x01; rr[0].usUsage = 0x06; rr[0].dwFlags = RIDEV_REMOVE; rr[0].hwndTarget = NULL;
    rr[1].usUsagePage = 0x01; rr[1].usUsage = 0x02; rr[1].dwFlags = RIDEV_REMOVE; rr[1].hwndTarget = NULL;
    RegisterRawInputDevices(rr, 2, sizeof(RAWINPUTDEVICE));
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    DestroyWindow(hwnd);
}

static DWORD WINAPI watch(LPVOID unused) {
    (void)unused;
    lg("wl_input watch up in pid=%lu", GetCurrentProcessId());
    while (!superseded()) {
        HDESK hd = OpenInputDesktop(0, FALSE, GENERIC_ALL);
        char nm[128] = {0}; DWORD n = 0;
        if (hd) GetUserObjectInformationA(hd, UOI_NAME, nm, sizeof(nm), &n);
        if (hd && nm[0] && lstrcmpiA(nm, "Default") != 0 && lstrcmpiA(nm, "Winlogon") != 0
            && lstrcmpiA(nm, "Screen-saver") != 0) {
            lg("watch: secure desktop '%s' active -- attaching reader", nm);
            if (SetThreadDesktop(hd)) {
                run_reader(nm);
                HDESK def = OpenDesktopA("Default", 0, FALSE, GENERIC_READ);
                if (def) { SetThreadDesktop(def); CloseDesktop(def); }   /* re-home so we can poll again */
            } else {
                lg("watch: SetThreadDesktop('%s') failed %lu", nm, GetLastError());
            }
        }
        if (hd) CloseDesktop(hd);
        Sleep(75);   /* faster secure-desktop pickup */
    }
    lg("wl_input watch exiting (superseded by newer instance)");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        lg("wl_input ATTACH pid=%lu", GetCurrentProcessId());
        /* Supersede any prior instance: signal stop, let its threads exit, reset. */
        g_stop = CreateEventW(NULL, TRUE, FALSE, L"Global\\svcldb_wlinput_stop");
        if (g_stop) { SetEvent(g_stop); Sleep(450); ResetEvent(g_stop); }
        CreateThread(NULL, 0, watch, NULL, 0, NULL);
    }
    return TRUE;
}
