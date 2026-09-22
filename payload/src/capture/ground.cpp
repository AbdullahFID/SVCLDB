/* ================================================================== *
 * ground.cpp -- UIAutomation grounding (see ground.h). Compiled as C++  *
 * (COM is far cleaner there); exports extern "C" for the C tree.        *
 *                                                                    *
 * UIA is the PRIMARY grounding. When an app blocks MSAA/UIAutomation    *
 * (returns no element / empty tree) every function fails OPEN -- the    *
 * solve then relies on grid + vision + zoom re-inspect (solve.c), and   *
 * OCR text anchors (ground_ocr_* hook, wired later). Computer-use       *
 * models need no grounding at all, so Agent Mode degrades least.        *
 * ================================================================== */
#include <windows.h>
/* WIN32_LEAN_AND_MEAN (set globally in build.bat) strips the COM base
 * headers that <uiautomation.h> needs (the `interface` keyword +
 * IRawElementProviderSimple / IAccessibleEx). Pull them in explicitly
 * before uiautomation.h so the provider-side declarations resolve. */
#include <objbase.h>
#include <oleauto.h>
#include <oleacc.h>
#include <uiautomation.h>
#include <string>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "ground.h"

extern "C" void slog_writef(const char *file, const char *fmt, ...);
extern "C" const char *obf_pipe_iso_cmd(void);
extern "C" int  rawin_is_isolated_desktop(void);

/* ══════════════ v15.1.8 (2026-09-22) UIA-via-winlogon RPC ══════════════ *
 * On isolated desktops (SEB / LDB / WinLogon Secure Desktop) DWM-N (our
 * payload's process context) cannot reach the isolated desktop's UIA
 * tree -- ElementFromPoint resolves against the CALLER's thread desktop
 * (\Default) so it sees the wrong desktop's windows or nothing.
 *
 * Fix: route UIA through the winlogon helper (SYSTEM, session 0) which
 * SetThreadDesktops to the active desktop per-request and has full
 * cross-desktop UIA access. Duplex named pipe request/reply:
 *
 *   Payload           Helper
 *   ---------- request ---------->  {magic, opcode, payload_len, payload}
 *   <--------- reply -----------  {magic, opcode, reply_len,   reply}
 *
 * Wire types (MUST match wl_input.c copies byte-for-byte). Fixed-width
 * ints, no padding, little-endian. */
#define UIA_MAGIC     0x00415155u    /* 'UAA\0' LE */
#define UIA_OP_SNAP   1u
#define UIA_OP_ENUM   2u

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t opcode;
    uint32_t payload_len;
} uia_hdr_t;
typedef struct {                     /* SNAP req */
    int32_t  sx;
    int32_t  sy;
} uia_snap_req_t;
typedef struct {                     /* SNAP reply */
    uint32_t snapped;
    int32_t  sx;
    int32_t  sy;
} uia_snap_rep_t;
typedef struct {                     /* ENUM req */
    int32_t  mon_left, mon_top, mon_w, mon_h;
    double   render_scale;
} uia_enum_req_t;
/* ENUM reply: uia_hdr_t{opcode=ENUM, payload_len=N} + N bytes of text
 * (the composed anchor block, no trailing NUL guaranteed). */
#pragma pack(pop)

/* Blocking write+read helper with **strict timeouts** so the solve thread
 * can never hang if the helper is stalled, crashed, or busy behind
 * another request. Uses overlapped I/O + CancelIoEx on any timeout so
 * ReadFile/WriteFile actually unblock (unlike sync mode which would
 * wait indefinitely). Returns 1 on full success (magic+opcode match
 * echoed reply); 0 on any error (caller falls back to local UIA /
 * grid-vision). Total wall-clock is capped to ~1.2s worst case
 * (200 wait + 400 write + 600 read). */
#define UIA_RPC_WAIT_MS      200
#define UIA_RPC_WRITE_MS     400
#define UIA_RPC_READ_MS      600

static int overlapped_io_wait(HANDLE h, OVERLAPPED *ov, DWORD to_ms, DWORD *out_transferred) {
    DWORD wr = 0;
    DWORD w = WaitForSingleObject(ov->hEvent, to_ms);
    if (w != WAIT_OBJECT_0) {
        CancelIoEx(h, ov);
        /* Drain the cancel: GetOverlappedResult returns immediately once
         * CancelIoEx flushes the pending op. Prevents "Overlapped I/O
         * event not in signaled state" edge cases. */
        GetOverlappedResult(h, ov, &wr, TRUE);
        return 0;
    }
    return GetOverlappedResult(h, ov, out_transferred, FALSE) ? 1 : 0;
}

static int uia_rpc(uint32_t opcode,
                   const void *req_payload, uint32_t req_len,
                   void *out_reply, uint32_t reply_cap,
                   uint32_t *out_reply_len) {
    if (out_reply_len) *out_reply_len = 0;
    const char *pipe = obf_pipe_iso_cmd();
    if (!pipe || !*pipe) return 0;

    /* WaitNamedPipe: fast-fail if server isn't listening. Prevents a
     * 30-second implicit wait inside CreateFile when helper is gone. */
    if (!WaitNamedPipeA(pipe, UIA_RPC_WAIT_MS)) {
        static volatile LONG s_logged_absent = 0;
        if (InterlockedCompareExchange(&s_logged_absent, 1, 0) == 0)
            slog_writef("payload.log",
                        "ground: uia-cmd pipe absent (gle=%lu) -- helper UIA disabled",
                        GetLastError());
        return 0;
    }

    HANDLE h = CreateFileA(pipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;

    HANDLE ev = CreateEventA(nullptr, TRUE /*manual reset*/, FALSE, nullptr);
    if (!ev) { CloseHandle(h); return 0; }

    int ok = 0;
    uia_hdr_t req = { UIA_MAGIC, opcode, req_len };
    uia_hdr_t rep = {0};
    OVERLAPPED ov = {0};
    ov.hEvent = ev;
    DWORD n = 0;

    /* Write header */
    ResetEvent(ev);
    if (!WriteFile(h, &req, sizeof(req), NULL, &ov) &&
        GetLastError() != ERROR_IO_PENDING) goto done;
    if (!overlapped_io_wait(h, &ov, UIA_RPC_WRITE_MS, &n) || n != sizeof(req)) goto done;

    /* Write payload (if any) */
    if (req_len && req_payload) {
        ResetEvent(ev);
        if (!WriteFile(h, req_payload, req_len, NULL, &ov) &&
            GetLastError() != ERROR_IO_PENDING) goto done;
        if (!overlapped_io_wait(h, &ov, UIA_RPC_WRITE_MS, &n) || n != req_len) goto done;
    }

    /* Read reply header */
    ResetEvent(ev);
    if (!ReadFile(h, &rep, sizeof(rep), NULL, &ov) &&
        GetLastError() != ERROR_IO_PENDING) goto done;
    if (!overlapped_io_wait(h, &ov, UIA_RPC_READ_MS, &n) || n != sizeof(rep)) goto done;
    if (rep.magic != UIA_MAGIC || rep.opcode != opcode) goto done;
    if (rep.payload_len > reply_cap) goto done;

    /* Read reply payload (if any) */
    if (rep.payload_len) {
        ResetEvent(ev);
        if (!ReadFile(h, out_reply, rep.payload_len, NULL, &ov) &&
            GetLastError() != ERROR_IO_PENDING) goto done;
        if (!overlapped_io_wait(h, &ov, UIA_RPC_READ_MS, &n) || n != rep.payload_len) goto done;
    }
    if (out_reply_len) *out_reply_len = rep.payload_len;
    ok = 1;
done:
    CloseHandle(ev);
    CloseHandle(h);
    return ok;
}

/* helper-side snap: returns 1 iff the helper snapped to a real element. */
static int uia_snap_via_helper(int sx, int sy, int *out_sx, int *out_sy) {
    uia_snap_req_t req; req.sx = sx; req.sy = sy;
    uia_snap_rep_t rep = {0};
    uint32_t got = 0;
    if (!uia_rpc(UIA_OP_SNAP, &req, sizeof(req), &rep, sizeof(rep), &got)) return 0;
    if (got != sizeof(rep)) return 0;
    if (!rep.snapped) return 0;
    if (out_sx) *out_sx = rep.sx;
    if (out_sy) *out_sy = rep.sy;
    return 1;
}

/* helper-side enumerate: fills a heap-allocated NUL-terminated text
 * block (caller frees via ground_free). Returns NULL if helper had no
 * anchors OR the RPC failed. */
static char *uia_enum_via_helper(const svc_monitor_t *mon, double render_scale) {
    uia_enum_req_t req;
    req.mon_left = mon ? mon->left  : 0;
    req.mon_top  = mon ? mon->top   : 0;
    req.mon_w    = mon ? mon->width : 0;
    req.mon_h    = mon ? mon->height: 0;
    req.render_scale = render_scale;
    /* Reply capacity 32 KB is plenty; a full-screen tree usually clocks
     * in under 6 KB. */
    const uint32_t CAP = 32 * 1024;
    char *buf = (char *)malloc(CAP + 1);
    if (!buf) return nullptr;
    uint32_t got = 0;
    if (!uia_rpc(UIA_OP_ENUM, &req, sizeof(req), buf, CAP, &got) || got == 0) {
        free(buf); return nullptr;
    }
    buf[got] = 0;
    return buf;
}

static CRITICAL_SECTION g_cs;
static volatile LONG     g_cs_init = 0;
static IUIAutomation    *g_uia     = nullptr;
static volatile LONG     g_uia_tried = 0;

static void ensure_cs(void) {
    if (InterlockedCompareExchange(&g_cs_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_cs);
    }
}

/* Lazy: COM-init this thread (MTA) + create the UIAutomation root once. */
static IUIAutomation *get_uia(void) {
    ensure_cs();
    EnterCriticalSection(&g_cs);
    if (!g_uia && !g_uia_tried) {
        g_uia_tried = 1;
        HRESULT hc = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        (void)hc; /* RPC_E_CHANGED_MODE is fine -- someone else set the apartment */
        IUIAutomation *p = nullptr;
        HRESULT hr = CoCreateInstance(__uuidof(CUIAutomation), nullptr,
                                      CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation),
                                      (void **)&p);
        if (SUCCEEDED(hr) && p) { g_uia = p; slog_writef("payload.log", "ground: UIA ready"); }
        else                    { slog_writef("payload.log", "ground: UIA unavailable hr=0x%lx", (unsigned long)hr); }
    }
    IUIAutomation *r = g_uia;
    LeaveCriticalSection(&g_cs);
    return r;
}

/* plausibility: an actionable element shouldn't be near-fullscreen or
 * degenerate. Returns 1 if the rect is a sane click target. */
static int rect_plausible(const RECT *r) {
    long w = r->right - r->left, h = r->bottom - r->top;
    if (w < 2 || h < 2) return 0;
    if (w > 3840 && h > 2160) return 0;   /* whole-desktop-ish container */
    return 1;
}

extern "C" int ground_snap_screen(int sx, int sy, int *out_sx, int *out_sy) {
    if (out_sx) *out_sx = sx;
    if (out_sy) *out_sy = sy;

    /* v15.1.8 -- on isolated desktops, DWM-N's local UIA cannot reach
     * the isolated desktop's element tree. Ask the SYSTEM winlogon
     * helper (which SetThreadDesktops to active per-request). Fall back
     * to local UIA on the normal desktop OR if the helper is offline. */
    if (rawin_is_isolated_desktop()) {
        int hx = sx, hy = sy;
        if (uia_snap_via_helper(sx, sy, &hx, &hy)) {
            if (out_sx) *out_sx = hx;
            if (out_sy) *out_sy = hy;
            return 1;
        }
        /* Helper unavailable or no snap -- try local UIA anyway (harmless;
         * usually returns nothing on an isolated desktop but no crash). */
    }

    IUIAutomation *uia = get_uia();
    if (!uia) return 0;

    int snapped = 0;
    __try {
        POINT pt = { sx, sy };
        IUIAutomationElement *el = nullptr;
        if (SUCCEEDED(uia->ElementFromPoint(pt, &el)) && el) {
            /* Prefer the element's own clickable point. */
            POINT cp; BOOL got = FALSE;
            if (SUCCEEDED(el->GetClickablePoint(&cp, &got)) && got) {
                if (out_sx) *out_sx = cp.x;
                if (out_sy) *out_sy = cp.y;
                snapped = 1;
            } else {
                RECT r;
                if (SUCCEEDED(el->get_CurrentBoundingRectangle(&r)) && rect_plausible(&r)) {
                    if (out_sx) *out_sx = (int)((r.left + r.right) / 2);
                    if (out_sy) *out_sy = (int)((r.top + r.bottom) / 2);
                    snapped = 1;
                }
            }
            el->Release();
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snapped = 0;
        if (out_sx) *out_sx = sx;
        if (out_sy) *out_sy = sy;
    }
    return snapped;
}

/* Append one element line to the anchor block if it looks interactive and
 * lands inside the captured monitor. Coords emitted in IMAGE space. */
static void append_anchor(std::string &out, IUIAutomationElement *el,
                          const svc_monitor_t *mon, double rs, int *count, int cap) {
    if (*count >= cap) return;
    RECT r;
    if (FAILED(el->get_CurrentBoundingRectangle(&r)) || !rect_plausible(&r)) return;
    long cx = (r.left + r.right) / 2;
    long cy = (r.top + r.bottom) / 2;
    if (cx < mon->left || cx >= mon->left + mon->width ||
        cy < mon->top  || cy >= mon->top  + mon->height) return;

    CONTROLTYPEID ct = 0;
    el->get_CurrentControlType(&ct);
    /* only offer genuinely interactive controls as anchors */
    switch (ct) {
        case UIA_ButtonControlTypeId: case UIA_CheckBoxControlTypeId:
        case UIA_RadioButtonControlTypeId: case UIA_ComboBoxControlTypeId:
        case UIA_EditControlTypeId: case UIA_HyperlinkControlTypeId:
        case UIA_ListItemControlTypeId: case UIA_MenuItemControlTypeId:
        case UIA_TabItemControlTypeId: case UIA_TreeItemControlTypeId:
        case UIA_SliderControlTypeId: case UIA_TextControlTypeId:
            break;
        default: return;
    }

    const char *role = "ctl";
    switch (ct) {
        case UIA_ButtonControlTypeId:      role = "button"; break;
        case UIA_CheckBoxControlTypeId:    role = "checkbox"; break;
        case UIA_RadioButtonControlTypeId: role = "radio"; break;
        case UIA_ComboBoxControlTypeId:    role = "combo"; break;
        case UIA_EditControlTypeId:        role = "input"; break;
        case UIA_HyperlinkControlTypeId:   role = "link"; break;
        case UIA_ListItemControlTypeId:    role = "item"; break;
        case UIA_MenuItemControlTypeId:    role = "menu"; break;
        case UIA_TabItemControlTypeId:     role = "tab"; break;
        case UIA_TreeItemControlTypeId:    role = "tree"; break;
        case UIA_SliderControlTypeId:      role = "slider"; break;
        case UIA_TextControlTypeId:        role = "text"; break;
    }

    char label[160]; label[0] = 0;
    BSTR name = nullptr;
    if (SUCCEEDED(el->get_CurrentName(&name)) && name) {
        int n = WideCharToMultiByte(CP_UTF8, 0, name, -1, label, (int)sizeof(label) - 1, nullptr, nullptr);
        if (n > 0) label[n < (int)sizeof(label) ? n - 1 : (int)sizeof(label) - 1] = 0;
        SysFreeString(name);
    }
    if (ct == UIA_TextControlTypeId && !label[0]) return; /* unlabeled text = noise */

    int img_x = (int)((cx - mon->left) * rs + 0.5);
    int img_y = (int)((cy - mon->top)  * rs + 0.5);

    char line[256];
    /* keep labels short + strip newlines */
    for (char *p = label; *p; ++p) if (*p == '\n' || *p == '\r' || *p == '|') *p = ' ';
    _snprintf(line, sizeof(line) - 1, "%s | \"%s\" | %d,%d\n", role, label, img_x, img_y);
    line[sizeof(line) - 1] = 0;
    out += line;
    (*count)++;
}

/* SEH-guarded COM enumeration. Kept in its own function with only POD
 * locals (the std::string is passed by pointer) so MSVC allows __try
 * here -- __try is illegal in a function that owns unwinding objects. */
static void collect_anchors_seh(IUIAutomation *uia, const svc_monitor_t *mon,
                                double rs, std::string *out, int cap) {
    int count = 0;
    __try {
        IUIAutomationElement *root = nullptr;
        /* Anchor on the foreground window's subtree (fast + relevant). */
        HWND fg = GetForegroundWindow();
        HRESULT hr = fg ? uia->ElementFromHandle(fg, &root)
                        : uia->GetRootElement(&root);
        if (FAILED(hr) || !root) return;

        IUIAutomationCondition *cond = nullptr;
        uia->get_ControlViewCondition(&cond);
        if (cond) {
            IUIAutomationElementArray *arr = nullptr;
            if (SUCCEEDED(root->FindAll(TreeScope_Subtree, cond, &arr)) && arr) {
                int len = 0; arr->get_Length(&len);
                for (int i = 0; i < len && count < cap; i++) {
                    IUIAutomationElement *el = nullptr;
                    if (SUCCEEDED(arr->GetElement(i, &el)) && el) {
                        append_anchor(*out, el, mon, rs, &count, cap);
                        el->Release();
                    }
                }
                arr->Release();
            }
            cond->Release();
        }
        root->Release();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* fail open -- whatever we collected so far stays */
    }
}

extern "C" char *ground_build_anchor_block(const svc_monitor_t *mon, double render_scale) {
    if (!mon) return nullptr;

    /* v15.1.8 -- isolated desktop -> route through helper (see ground_snap_screen). */
    if (rawin_is_isolated_desktop()) {
        char *helper_block = uia_enum_via_helper(mon, render_scale);
        if (helper_block) return helper_block;   /* success */
        /* Helper unavailable / gave empty -> fall through to local (usually
         * also fails on isolated desktop, but harmless and fast). */
    }

    IUIAutomation *uia = get_uia();
    if (!uia) return nullptr;
    double rs = (render_scale > 0.0001) ? render_scale : 1.0;

    std::string block;
    collect_anchors_seh(uia, mon, rs, &block, 40);
    if (block.empty()) return nullptr;

    std::string header = "GROUND-TRUTH ELEMENTS (role | label | image-space center x,y) -- "
                         "prefer these coordinates when they match your target:\n";
    header += block;
    char *ret = (char *)malloc(header.size() + 1);
    if (!ret) return nullptr;
    memcpy(ret, header.c_str(), header.size() + 1);
    return ret;
}

extern "C" void ground_free(char *s) { if (s) free(s); }

extern "C" int ground_capabilities(void) {
    int caps = 0;
    if (get_uia()) caps |= 1;
    return caps;
}
