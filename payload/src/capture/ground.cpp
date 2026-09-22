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
