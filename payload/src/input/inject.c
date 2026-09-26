/* ================================================================== *
 * inject.c -- Low-level input injection (see inject.h).                *
 * ================================================================== */
#include <windows.h>
#include "inject.h"
#include "coords.h"
#include "secure_inject.h"

static volatile LONG g_synth  = 0;
static volatile LONG g_secure = 0;

void inj_set_synth(int on) { InterlockedExchange(&g_synth, on ? 1 : 0); }
int  inj_is_synth(void)    { return InterlockedCompareExchange(&g_synth, 0, 0) != 0; }
void inj_set_secure(int on){ InterlockedExchange(&g_secure, on ? 1 : 0); }
int  inj_secure(void)      { return InterlockedCompareExchange(&g_secure, 0, 0) != 0; }

/* ── local SendInput helpers ───────────────────────────────────── */
static void send_mouse(DWORD flags, LONG dx, LONG dy, DWORD data) {
    INPUT in;
    ZeroMemory(&in, sizeof(in));
    in.type       = INPUT_MOUSE;
    in.mi.dx      = dx;
    in.mi.dy      = dy;
    in.mi.mouseData = data;
    in.mi.dwFlags = flags;
    SendInput(1, &in, sizeof(INPUT));
}

static void send_key_unicode_unit(WORD unit, int up) {
    INPUT in;
    ZeroMemory(&in, sizeof(in));
    in.type       = INPUT_KEYBOARD;
    in.ki.wScan   = unit;
    in.ki.dwFlags = KEYEVENTF_UNICODE | (up ? KEYEVENTF_KEYUP : 0);
    SendInput(1, &in, sizeof(INPUT));
}

/* v7.5.12 (2026-09-26): emit a real hardware scancode (KEYEVENTF_SCANCODE).
 * Unlike KEYEVENTF_UNICODE this produces a normal VK event, NOT VK_PACKET
 * (0xE7) -- see inj_char for the Bluebook rationale. */
static void send_key_scancode(WORD scan, int up) {
    INPUT in;
    ZeroMemory(&in, sizeof(in));
    in.type       = INPUT_KEYBOARD;
    in.ki.wScan   = scan;
    in.ki.dwFlags = KEYEVENTF_SCANCODE | (up ? KEYEVENTF_KEYUP : 0);
    SendInput(1, &in, sizeof(INPUT));
}

/* ── public primitives ─────────────────────────────────────────── */
void inj_move_abs(int nx, int ny) {
    if (inj_secure() && sec_inject_available()) {
        if (sec_inject_move_abs(nx, ny)) return;
    }
    send_mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
               nx, ny, 0);
}

void inj_move_screen(int screen_x, int screen_y) {
    int nx, ny;
    coords_screen_to_abs(screen_x, screen_y, &nx, &ny);
    inj_move_abs(nx, ny);
}

static void button(DWORD flag) {
    if (inj_secure() && sec_inject_available()) {
        if (sec_inject_button(flag)) return;
    }
    send_mouse(flag, 0, 0, 0);
}

void inj_lbtn(int down) { button(down ? MOUSEEVENTF_LEFTDOWN   : MOUSEEVENTF_LEFTUP);   }
void inj_rbtn(int down) { button(down ? MOUSEEVENTF_RIGHTDOWN  : MOUSEEVENTF_RIGHTUP);  }
void inj_mbtn(int down) { button(down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP); }

void inj_wheel(int delta) {
    if (inj_secure() && sec_inject_available()) {
        if (sec_inject_wheel(delta)) return;
    }
    send_mouse(MOUSEEVENTF_WHEEL, 0, 0, (DWORD)delta);
}

void inj_char(unsigned int cp) {
    /* v7.5.12 (2026-09-26): LOCAL path emits real SCANCODES instead of
     * KEYEVENTF_UNICODE. Unicode injection synthesizes VK_PACKET (0xE7),
     * which Bluebook's WH_KEYBOARD_LL denylist flags as injected input
     * (RE-confirmed); a real keyboard emits a scancode -> real VK. We map the
     * codepoint through the FOREGROUND window's keyboard layout so the typed
     * char is correct for whatever layout the exam app uses (not dwm's thread
     * default), and fall back to unicode for any char that can't be produced
     * with a plain-or-Shift chord on that layout (AltGr/Ctrl/dead-key/accent,
     * or non-BMP). Those are rare in exam text, and typing the CORRECT char
     * matters more than stealth for them. Proven VK_PACKET-clean via
     * tools/redteam/probes/scancode_type_probe.c (23 chars, 0 VK_PACKET, 0
     * fallbacks).
     *
     * SEB/secure path is intentionally left on unicode: it routes through the
     * winlogon helper and there is no RE evidence SEB (or exams hosted in it)
     * runs a VK_PACKET check -- that denylist belongs to Bluebook/ACT, which
     * live on the normal desktop and hit THIS local path. If that changes, add
     * a scancode opcode to the helper protocol (secure_inject + wl_input). */
    if (!inj_secure() && cp <= 0xFFFF) {
        HWND  fg   = GetForegroundWindow();
        DWORD ftid = fg ? GetWindowThreadProcessId(fg, NULL) : 0;
        HKL   hkl  = GetKeyboardLayout(ftid);   /* ftid==0 -> our thread layout */
        SHORT s    = VkKeyScanExW((WCHAR)cp, hkl);
        if (s != -1) {
            BYTE vk          = LOBYTE(s);
            BYTE shift_state = HIBYTE(s);
            /* bit0=Shift, bit1=Ctrl, bit2=Alt. Only plain or Shift is a clean
             * physical chord; Ctrl/AltGr combos fall back to unicode. */
            if (vk != 0 && !(shift_state & 6)) {
                WORD scan = (WORD)MapVirtualKeyExW(vk, MAPVK_VK_TO_VSC, hkl);
                if (scan != 0) {
                    int  need_shift = (shift_state & 1) != 0;
                    WORD sh = (WORD)MapVirtualKeyExW(VK_SHIFT, MAPVK_VK_TO_VSC, hkl);
                    if (need_shift && sh) send_key_scancode(sh, 0);
                    send_key_scancode(scan, 0);
                    send_key_scancode(scan, 1);
                    if (need_shift && sh) send_key_scancode(sh, 1);
                    return;
                }
            }
        }
    }
    if (inj_secure() && sec_inject_available()) {
        /* helper handles BMP; surrogate pairs handled here for the local
         * path only -- CU/AutoSolver text is overwhelmingly BMP. */
        if (cp <= 0xFFFF) {
            if (sec_inject_key_unicode((unsigned short)cp, 0) &&
                sec_inject_key_unicode((unsigned short)cp, 1)) return;
        }
    }
    if (cp <= 0xFFFF) {
        send_key_unicode_unit((WORD)cp, 0);
        send_key_unicode_unit((WORD)cp, 1);
    } else {
        /* UTF-16 surrogate pair */
        unsigned int v = cp - 0x10000;
        WORD hi = (WORD)(0xD800 + (v >> 10));
        WORD lo = (WORD)(0xDC00 + (v & 0x3FF));
        send_key_unicode_unit(hi, 0);
        send_key_unicode_unit(lo, 0);
        send_key_unicode_unit(hi, 1);
        send_key_unicode_unit(lo, 1);
    }
}

void inj_vk(unsigned short vk, int down, int extended) {
    if (inj_secure() && sec_inject_available()) {
        if (sec_inject_key_vk(vk, down ? 0 : 1, extended)) return;
    }
    INPUT in;
    ZeroMemory(&in, sizeof(in));
    in.type       = INPUT_KEYBOARD;
    in.ki.wVk     = vk;
    in.ki.dwFlags = (extended ? KEYEVENTF_EXTENDEDKEY : 0) | (down ? 0 : KEYEVENTF_KEYUP);
    SendInput(1, &in, sizeof(INPUT));
}
