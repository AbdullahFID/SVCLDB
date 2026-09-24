#include "../../shared/common.h"
#include "ldb_detect.h"
#include "../../shared/log_secure.h"

#include <tlhelp32.h>
#include <string.h>

static HANDLE       g_thread   = NULL;
static HANDLE       g_stop_ev  = NULL;
static ldb_state_cb g_on_arm   = NULL;
static ldb_state_cb g_on_disarm= NULL;
static volatile LONG g_active  = 0;

/* Look for a process name (case-insensitive, wide). */
static int find_proc(const wchar_t *want) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    int found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, want) == 0) { found = 1; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static int ldb_present(void) {
    if (find_proc(L"LockDownBrowser.exe"))    return 1;
    if (find_proc(L"LockDownBrowserOEM.exe")) return 1;
    return 0;
}

static DWORD WINAPI detect_thread(LPVOID param) {
    (void)param;
    int prev = 0;
    slog_write("msvc_dbg_a.dat", "ldb detect thread started");
    while (WaitForSingleObject(g_stop_ev, 2000) == WAIT_TIMEOUT) {
        int cur = ldb_present();
        if (cur != prev) {
            InterlockedExchange(&g_active, cur);
            slog_writef("msvc_dbg_a.dat", "ldb state: %s", cur ? "ARMED" : "IDLE");
            if (cur && g_on_arm)      g_on_arm();
            if (!cur && g_on_disarm)  g_on_disarm();
            prev = cur;
        }
    }
    slog_write("msvc_dbg_a.dat", "ldb detect thread exit");
    return 0;
}

int ldb_detect_start(ldb_state_cb on_arm, ldb_state_cb on_disarm) {
    if (g_thread) return 1;
    g_on_arm    = on_arm;
    g_on_disarm = on_disarm;
    g_stop_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_stop_ev) return 0;
    g_thread = CreateThread(NULL, 0, detect_thread, NULL, 0, NULL);
    return g_thread != NULL;
}

void ldb_detect_stop(void) {
    if (g_stop_ev) SetEvent(g_stop_ev);
    if (g_thread) {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    if (g_stop_ev) { CloseHandle(g_stop_ev); g_stop_ev = NULL; }
}

int ldb_detect_active(void) { return g_active != 0; }
