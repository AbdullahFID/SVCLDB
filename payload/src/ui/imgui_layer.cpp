/* ================================================================== *
 * imgui_layer.cpp — ImGui + D3D11 inside DWM's compositor pass.       *
 *                                                                    *
 * Design:                                                            *
 *  - Hook `COverlayContext::Present(pCtx, pLayer, ...)` in dwmcore.  *
 *  - Walk pLayer's vtable to obtain the ID3D11Texture2D that DWM      *
 *    just presented to the compositor for THIS specific layer.       *
 *  - Get the D3D device via COM ID3D11DeviceChild::GetDevice slot 3. *
 *  - Only render into the FULLSCREEN layer (>= 800x600). DWM Present *
 *    is per-layer — cursor overlay is 32x32, tooltips are small.     *
 *  - HDR-aware: if the texture is R16G16B16A16_FLOAT, we create the  *
 *    RTV with the SAME format (ImGui outputs scRGB-compatible sRGB   *
 *    values → 1.0 in float = SDR white on both SDR and HDR monitors).*
 *  - Complete D3D11 state save/restore around ImGui render (ImGui's  *
 *    internal backup handles the shader/IA/RS/BS/DS/PS-SRV state; we *
 *    additionally back up OM RTVs + viewport + scissor since ImGui   *
 *    doesn't touch OM's target binding).                             *
 *                                                                    *
 * Diagnostics: uses plaintext CreateFileA writes to `payload_early`  *
 * (not slog) because slog uses __declspec(thread) internally, and    *
 * TLS is broken under manual map (loader-only init step skipped).    *
 *                                                                    *
 * Vtable slots — verified via production hooksdll/dwm/dwm_payload.c  *
 * capture path (25/25 audit; used in production for 800+ users):     *
 *   pLayer.vtable[5] () = GetPhysicalBackBuffer                      *
 *   pLayer.vtable[24]() = GetD3D11Resource                           *
 *   resource.vtable[19]() = accessor (IUnknown for the D3D texture)  *
 *   QueryInterface(accessor, IID_ID3D11Texture2D)                    *
 *   texture->GetDevice(&device) via standard COM slot 3              *
 * ================================================================== */

#include "../../../shared/common.h"

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <wincodec.h>
#include <shlwapi.h>
#include <stdio.h>

#include "../../../shared/imgui/imgui.h"
#include "../../../shared/imgui/backends/imgui_impl_dx11.h"

#include "imgui_layer.h"

extern "C" {
#include "../../../shared/log_secure.h"
#include "../dwm_hooks.h"
#include "../clipboard_out.h"   /* v9: unified retry+UNICODETEXT copy helper */
}

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "shlwapi.lib")

/* ---------- Vtable slots (production-verified in hooksdll) ---------- */
#define GPB_SLOT     5    /* pLayer->GetPhysicalBackBuffer */
#define GD3D_SLOT    24   /* pLayer->GetD3D11Resource      */
#define ACC3_SLOT    19   /* resource->accessor            */
#define VTBL_QI      0    /* IUnknown::QueryInterface      */
#define VTBL_RELEASE 2    /* IUnknown::Release             */

static const GUID IID_ID3D11Texture2D_LOCAL = {
    0x6f15aaf2, 0xd208, 0x4e89, {0x9a,0xb4,0x48,0x95,0x35,0xd3,0x4f,0x9c}
};

typedef HRESULT (__stdcall *pfnQI)(void *, const GUID *, void **);
typedef ULONG   (__stdcall *pfnRelease)(void *);
typedef void   *(__fastcall *pfnVGet)(void *);

/* ---------- Diagnostic writer (bypasses slog TLS issue entirely) ----------
 * Every important line ALSO goes to payload_early.txt as plaintext. The
 * TLS-in-manual-map problem swallowed all slog_write calls before this
 * commit — plaintext bypass is unaffected and always works. */
static CRITICAL_SECTION g_diag_cs;
static volatile LONG    g_diag_cs_init = 0;

static void diag_init_lock(void) {
    if (InterlockedCompareExchange(&g_diag_cs_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_diag_cs);
        InterlockedExchange(&g_diag_cs_init, 2);
    } else {
        while (g_diag_cs_init != 2) Sleep(0);
    }
}

/* Route UI-layer diag through encrypted slog. Enable plaintext mirror
 * with DWM_EXT_TRACE=1 env var. Anti-strings-scan pattern —
 * see dllmain.c early_log for the same shape. */
static int g_ui_diag_plaintext = -1;
static void diag(const char *fmt, ...) {
    diag_init_lock();

    char body[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf(body, sizeof(body) - 1, fmt, ap);
    va_end(ap);
    body[sizeof(body) - 1] = 0;
    slog_writef("payload.log", "ui: %s", body);

    if (g_ui_diag_plaintext < 0) {
#if SVCLDB_PRODUCTION_BUILD
        g_ui_diag_plaintext = 0;
#else
        char buf[8];
        DWORD n = GetEnvironmentVariableA("DWM_EXT_TRACE",
                                          buf, sizeof(buf));
        g_ui_diag_plaintext = (n > 0 && buf[0] != '0') ? 1 : 0;
#endif
    }
    if (!g_ui_diag_plaintext) return;

    EnterCriticalSection(&g_diag_cs);
    HANDLE h = CreateFileA(SVC_INSTALL_DIR "\\payload_early.txt",
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char line[600];
        SYSTEMTIME t; GetSystemTime(&t);
        int lp = _snprintf(line, sizeof(line) - 1,
            "[%02d:%02d:%02d.%03d] ui: %s\r\n",
            t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, body);
        if (lp > 0) { DWORD w = 0; WriteFile(h, line, (DWORD)lp, &w, NULL); }
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_diag_cs);
}

/* Forward decl — used by ui_toggle_visible / ui_nudge / etc. below.
 * Definition is further down alongside the capture path. */
static void wake_dwm_composition(void);

/* ---------- Readability probe ---------- */
static bool is_readable(const void *addr, size_t bytes) {
    if (!addr) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    if ((BYTE *)addr + bytes > (BYTE *)mbi.BaseAddress + mbi.RegionSize) return false;
    return true;
}

/* ---------- RTV cache ---------- */
struct RtvCacheEntry {
    ID3D11Texture2D        *tex;
    ID3D11RenderTargetView *rtv;
    UINT                    w, h;
    DXGI_FORMAT             fmt;
};
static const int RTV_CACHE_MAX = 8;
static RtvCacheEntry g_cache[RTV_CACHE_MAX] = {};
static ID3D11Device *g_last_device = nullptr;

/* ---------- Public state ---------- */
static CRITICAL_SECTION g_ui_cs;
static bool             g_ui_cs_init  = false;
static bool             g_visible     = true;
static bool             g_imgui_inited= false;
static ULONGLONG        g_frame_count = 0;

/* ── Chat message ring buffer (v3) ────────────────────────────── *
 *
 * Circular buffer of the last N messages. When full, oldest gets
 * evicted. Each message owns its `text` heap-alloc. `pending` = 1
 * for AI messages still being streamed (renderer shows animated
 * "Thinking..." indicator + inline chunk-append text).
 *
 * IDs are monotonically-increasing to survive eviction (streaming
 * callback references a message by id, not slot). */
#define CHAT_MAX_MSGS 64
struct chat_msg_t {
    int         id;            /* -1 = empty slot */
    int         role;          /* UI_MSG_USER or UI_MSG_AI */
    int         pending;       /* AI only: 1 while streaming */
    ULONGLONG   ts_ms;         /* GetTickCount64() when created */
    char       *text;          /* heap-alloc; NULL = empty */
    size_t      text_len;
    size_t      text_cap;
};
static CRITICAL_SECTION g_chat_msgs_cs;
static bool             g_chat_msgs_cs_init = false;
static struct chat_msg_t g_chat_msgs[CHAT_MAX_MSGS] = {0};
static int              g_chat_msg_head = 0;   /* next-write index */
static int              g_chat_msg_count = 0;   /* current populated count */
static volatile LONG    g_chat_next_id  = 1;

/* Non-destructive "back to home view" flag. When 1, draw_chat_window
 * shows the empty home cheat-sheet even if messages exist. Any new
 * message appended flips this back to 0 so the user sees new activity
 * immediately. Toggled by:
 *   - Ctrl+Alt+X on chat view → set to 1 (hide messages, preserve them)
 *   - ui_chat_append_* → set to 0 (new activity, show chat again)
 *   - Ctrl+Alt+N → also implicitly resets (messages gone entirely) */
static volatile LONG    g_home_view_forced = 0;

/* Status badge (provider/tier/model shown top-right). */
static CRITICAL_SECTION g_status_cs;
static bool             g_status_cs_init = false;
static char             g_status_provider[32] = {0};
static char             g_status_tier    [32] = {0};
static char             g_status_model   [64] = {0};
static int              g_status_streaming = 0;

/* ── Hotkey binding registry ──
 *
 * Snapshot of svc_config_t.hotkeys[] provided by dllmain via
 * ui_set_hotkey_bindings. Used by UI buttons that show the mapped
 * hotkey (e.g. "copy full [Ctrl+Alt+C]"). Read-mostly after init;
 * no locking needed for simple reads since writes are rare + atomic
 * on x64 for aligned 32-bit ints. */
#define UI_HK_MAX 32
static unsigned         g_hk_bindings[UI_HK_MAX] = {0};
static int              g_hk_bindings_n = 0;
static volatile LONG    g_hk_bindings_ver = 0;   /* bumps on update */

/* Snapshot of last-set reply for the legacy ui_copy_reply_to_clipboard
 * fast path (avoid walking messages under g_chat_msgs_cs while it's
 * being appended). Updated each time an AI message finalizes. */
static CRITICAL_SECTION g_last_reply_cs;
static bool             g_last_reply_cs_init = false;
static char            *g_last_reply_snapshot = NULL;

static void ensure_chat_msgs_cs(void) {
    if (!g_chat_msgs_cs_init) {
        InitializeCriticalSection(&g_chat_msgs_cs);
        g_chat_msgs_cs_init = true;
        for (int i = 0; i < CHAT_MAX_MSGS; i++) g_chat_msgs[i].id = -1;
    }
}
static void ensure_status_cs(void) {
    if (!g_status_cs_init) {
        InitializeCriticalSection(&g_status_cs);
        g_status_cs_init = true;
    }
}
static void ensure_last_reply_cs(void) {
    if (!g_last_reply_cs_init) {
        InitializeCriticalSection(&g_last_reply_cs);
        g_last_reply_cs_init = true;
    }
}

/* Slot in the ring for the next-write index (head). */
static struct chat_msg_t *chat_msg_slot_at_head(void) {
    return &g_chat_msgs[g_chat_msg_head];
}

/* Slot at position i (0 = oldest). Caller holds g_chat_msgs_cs. */
static struct chat_msg_t *chat_msg_at(int i) {
    if (i < 0 || i >= g_chat_msg_count) return NULL;
    int start = (g_chat_msg_head - g_chat_msg_count + CHAT_MAX_MSGS) % CHAT_MAX_MSGS;
    return &g_chat_msgs[(start + i) % CHAT_MAX_MSGS];
}

/* Find slot by id. Caller holds g_chat_msgs_cs. */
static struct chat_msg_t *chat_msg_by_id(int id) {
    for (int i = 0; i < g_chat_msg_count; i++) {
        struct chat_msg_t *m = chat_msg_at(i);
        if (m && m->id == id) return m;
    }
    return NULL;
}

/* Free a slot's owned text + reset. Caller holds g_chat_msgs_cs. */
static void chat_msg_free_slot(struct chat_msg_t *m) {
    if (!m) return;
    if (m->text) { free(m->text); m->text = NULL; }
    m->text_len = 0;
    m->text_cap = 0;
    m->id = -1;
    m->pending = 0;
}

/* Append raw bytes to a message's text (auto-grow buffer). */
static void chat_msg_append_bytes(struct chat_msg_t *m,
                                  const char *bytes, size_t len) {
    if (!m || !bytes || len == 0) return;
    size_t need = m->text_len + len + 1;
    if (need > m->text_cap) {
        size_t new_cap = (m->text_cap ? m->text_cap * 2 : 512);
        while (new_cap < need) new_cap *= 2;
        char *nb = (char *)realloc(m->text, new_cap);
        if (!nb) return;
        m->text = nb;
        m->text_cap = new_cap;
    }
    memcpy(m->text + m->text_len, bytes, len);
    m->text_len += len;
    m->text[m->text_len] = 0;
}

/* Fonts. Loaded in ImGui init path. g_font_ui = Segoe UI (sans-serif,
 * matches Win11 UI), g_font_mono = Cascadia Mono / Consolas (fenced-
 * code + math blocks). Both fall back to ImGui default (Proggy Clean)
 * if loading fails — everything still renders, just smaller / uglier.
 *
 * Base size 16px @ 1x DPI. Runtime scaling happens via
 * ImGuiIO::FontGlobalScale in draw_chat_window (screen_h/1080 factor
 * × user font-size hotkey multiplier). */
static ImFont *g_font_ui   = NULL;
static ImFont *g_font_mono = NULL;
#define UI_FONT_SIZE_PX    18.0f
#define MONO_FONT_SIZE_PX  17.0f

/* ---------- Geometry & style state (user-adjustable via hotkeys) ---------- *
 * `g_corner` cycles: 0=top-right (default), 1=top-left, 2=bottom-right,
 * 3=bottom-left. `g_offset_{x,y}` are user nudges from the corner anchor. */
static int   g_corner   = 0;
static int   g_offset_x = 0;
static int   g_offset_y = 0;
static int   g_extra_w  = 0;
static int   g_extra_h  = 0;
static float g_alpha    = 0.94f;
static float g_font     = 1.00f;   /* multiplicative on top of DPI-derived scale */

/* v8 (2026-07-06): user-configurable LAUNCH base size (from config.dat,
 * set in the Electron dashboard's "Overlay appearance" card). Zero =
 * fall through to the historical 600x460 hardcoded defaults, preserving
 * behavior for stale configs that never set these fields.
 *
 * These are the RAW DPI-independent target dimensions in pixels. The
 * draw_chat_window path multiplies by scale (screen_h / 1080) so a
 * "560 wide" launch on a 4K screen actually renders ~1120px, matching
 * the previous 600*scale behavior for defaults. */
static int   g_base_w_cfg = 0;   /* 0 = use fallback 600 */
static int   g_base_h_cfg = 0;   /* 0 = use fallback 460 */

/* v8: size_mode toggle from cfg->size_mode. 0 = normal, 1 = ultra.
 * Controls the RUNTIME clamp range for both the launch base + user's
 * live resize hotkeys. Ultra allows tiny 80x60 pip AND near-fullscreen. */
static volatile LONG g_size_mode = 0;   /* 0 normal, 1 ultra */

/* v1.3 (2026-07-07): per-frame alpha multiplier — snapshotted from
 * g_alpha at the top of draw_chat_window and used by nested
 * renderers (draw_chat_bubble, md_render_tinted_block, code/math
 * block wrappers) to scale their INTERIOR background + border alphas.
 *
 * BUG WE'RE FIXING: before this global, bubble bg was hardcoded to
 * alpha=0.95, code-block bg was 0.98, math-block bg was 0.98. The
 * outer ImGui window's WindowBg respected g_alpha but everything
 * INSIDE was near-opaque. User set alpha=0.20 and got a very
 * transparent frame with almost-opaque chat bubbles inside — the
 * "transparency only applies to the edges, not the chat box" report.
 *
 * Threading model: draw_chat_window is called from the DWM Present
 * detour on the compositor thread. Every downstream call chain
 * (draw_chat_bubble, md_render, md_render_code_block,
 * md_render_math_display, md_render_tinted_block) runs synchronously
 * on that same thread. No concurrent access — a plain static
 * suffices, no atomic needed.
 *
 * Contract: draw_chat_window MUST set g_frame_alpha_mul at the top
 * of every frame. Downstream renderers read it via with_alpha_mul().
 * If a future call site is added that renders bubbles/blocks OUTSIDE
 * draw_chat_window, it MUST set g_frame_alpha_mul too. */
static float g_frame_alpha_mul = 1.0f;

/* Return `c` with its alpha channel multiplied by g_frame_alpha_mul.
 * Applied to bubble bg + border, code/math block bg + border, and
 * button colors — everything that visually constitutes the "chat
 * box container" so the whole container respects user transparency
 * uniformly. Body TEXT is deliberately NOT scaled — text alpha
 * scaling below ~0.5 makes prose unreadable, which is worse UX than
 * having text render at full opacity against a partially-transparent
 * background. */
static inline ImVec4 with_alpha_mul(ImVec4 c) {
    c.w *= g_frame_alpha_mul;
    return c;
}

/* ---------- Fullscreen-layer discovery ---------- *
 * DWM's COverlayContext::Present fires many times per frame — once per
 * layer. Cursor overlay is 32x32, tooltips are ~100x30, etc. We only
 * want to render into the layer that represents the physical display
 * output (which for a single-monitor 1920x1080 setup is the 1920x1080
 * layer). We track the largest layer we've seen and only render there. */
static UINT g_target_w = 0;   /* Largest layer dimensions we've seen. */
static UINT g_target_h = 0;
static ID3D11Texture2D *g_target_tex = nullptr;  /* Last texture matching target. */

/* Frame dedup — Present is called PER LAYER by DWM. Even after size gate
 * multiple ~fullscreen layers can pass through in the same compose cycle
 * (LDB main + LDB modal + full-screen overlay window). We must draw the
 * chat overlay ONCE per frame or the user sees duplicates ghosting into
 * each other. Track last draw tick; skip if <FRAME_DEDUP_MS since.
 *
 * Threshold: 3ms. Detailed rationale + refresh-rate table lives in the
 * v1.3 TRANSPARENCY FLICKER FIX comment below (right above the tick
 * comparison in ui_present_frame). Do not restore 12ms — that broke
 * every monitor >= 90Hz. */
#define FRAME_DEDUP_MS 3
static ULONGLONG g_last_draw_tick = 0;

/* Reply-pane scroll accumulator — hotkey handler adds delta, next
 * draw_chat_window frame calls ImGui::SetScrollY with the accumulated
 * amount then resets. Positive = scroll down toward end, negative =
 * scroll up toward top. Auto-repeat produces continuous scroll. */
static volatile LONG g_reply_scroll_pending = 0;

/* Chat input state — user types via WH_KEYBOARD_LL feeding into
 * ui_chat_feed_char. When g_chat_active, the LL hook diverts EVERY
 * non-hotkey key into this buffer instead of passing it through.
 * Buffer is UTF-8 to survive non-ASCII input on the way to the AI. */
#define CHAT_BUF_SIZE 2048
static volatile LONG    g_chat_active   = 0;
static CRITICAL_SECTION g_chat_cs;
static bool             g_chat_cs_init  = false;
static char             g_chat_buf[CHAT_BUF_SIZE] = {0};
static int              g_chat_len      = 0;   /* bytes used */
static int              g_chat_cursor   = 0;   /* insert position (byte offset) */

static void ensure_chat_cs() {
    if (!g_chat_cs_init) {
        InitializeCriticalSection(&g_chat_cs);
        g_chat_cs_init = true;
    }
}

/* ================================================================== *
 * Persistent overlay state — save/restore across sessions.            *
 * ================================================================== *
 *                                                                    *
 * User's tuning (corner + nudge + size + alpha + font) survives DWM   *
 * crash / --unload / reboot. Persistence file lives beside the        *
 * payload DLL under the writable install dir.                        *
 *                                                                    *
 * File format (v1, 40 bytes fixed):                                   *
 *   0..3   magic 'SVOL' (svcldb overlay)                              *
 *   4..7   version (1)                                                *
 *   8..11  visible flag (int32)                                       *
 *   12..15 corner                                                     *
 *   16..19 offset_x                                                   *
 *   20..23 offset_y                                                   *
 *   24..27 extra_w                                                    *
 *   28..31 extra_h                                                    *
 *   32..35 alpha (float)                                              *
 *   36..39 font (float)                                               *
 * A future v2 can extend by appending; reader tolerates trailing bytes.
 * Save is throttled to STATE_SAVE_THROTTLE_MS to survive rapid nudges
 * without hammering disk. */
#define STATE_MAGIC              0x4C4F5653  /* 'SVOL' */
#define STATE_VERSION            1
#define STATE_FILE               "overlay_state.bin"
#define STATE_SAVE_THROTTLE_MS   250
static ULONGLONG g_last_save_tick = 0;
static volatile LONG g_state_dirty = 0;

/* Full path to persistence file. Writable location — SVC_INSTALL_DIR
 * (typically C:\ProgramData\WinAudioSvc) is already carved out for us. */
static void state_file_path(char *out, size_t out_sz) {
    _snprintf(out, out_sz - 1, "%s\\%s", SVC_INSTALL_DIR, STATE_FILE);
    out[out_sz - 1] = 0;
}

/* Serialize state into a fixed 40-byte record. */
static void state_pack(unsigned char buf[40]) {
    unsigned int   u_magic   = STATE_MAGIC;
    unsigned int   u_version = STATE_VERSION;
    int   i_visible  = g_visible ? 1 : 0;
    int   i_corner   = g_corner;
    int   i_off_x    = g_offset_x;
    int   i_off_y    = g_offset_y;
    int   i_extra_w  = g_extra_w;
    int   i_extra_h  = g_extra_h;
    float f_alpha    = g_alpha;
    float f_font     = g_font;
    memcpy(buf +  0, &u_magic,   4);
    memcpy(buf +  4, &u_version, 4);
    memcpy(buf +  8, &i_visible, 4);
    memcpy(buf + 12, &i_corner,  4);
    memcpy(buf + 16, &i_off_x,   4);
    memcpy(buf + 20, &i_off_y,   4);
    memcpy(buf + 24, &i_extra_w, 4);
    memcpy(buf + 28, &i_extra_h, 4);
    memcpy(buf + 32, &f_alpha,   4);
    memcpy(buf + 36, &f_font,    4);
}

/* Write buffered state to disk. Caller MUST hold g_ui_cs. */
static void state_persist_locked(void) {
    unsigned char buf[40];
    state_pack(buf);
    char path[MAX_PATH];
    state_file_path(path, sizeof(path));
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, buf, (DWORD)sizeof(buf), &w, NULL);
    CloseHandle(h);
}

/* Mark state as dirty. Actual disk write happens on next call to
 * state_flush_if_due(). Callers holding g_ui_cs can call directly. */
static void state_mark_dirty(void) {
    InterlockedExchange(&g_state_dirty, 1);
}

/* Throttled flush — called from ui_present_frame every N frames. */
static void state_flush_if_due(void) {
    if (!InterlockedCompareExchange(&g_state_dirty, 0, 1)) return;
    ULONGLONG now = GetTickCount64();
    if ((now - g_last_save_tick) < STATE_SAVE_THROTTLE_MS) {
        /* Re-arm and try later. */
        InterlockedExchange(&g_state_dirty, 1);
        return;
    }
    g_last_save_tick = now;
    EnterCriticalSection(&g_ui_cs);
    state_persist_locked();
    LeaveCriticalSection(&g_ui_cs);
}

/* Restore saved state from disk if the file exists + is well-formed.
 * Called ONCE during ensure_cs(). Silently no-op on any error.
 *
 * Version-tolerant reader (Bypassify parity — they carry v5→v8
 * migration; we start with v1 and grow forward). Rules:
 *  - Magic MUST match (else file is corrupt or from a different tool)
 *  - version MUST be >= 1 (0 is invalid)
 *  - version > STATE_VERSION: reject entirely (file is newer than us,
 *    reading it risks misinterpreting trailing fields as ours)
 *  - version == STATE_VERSION: full read (fast path today)
 *  - version < STATE_VERSION: read only the fields that existed at
 *    THAT version; leave newer fields at their defaults. Requires
 *    a version-size table so we know how many bytes to trust.
 *
 * All future struct extensions should append AFTER the last field
 * and bump STATE_VERSION. Never rearrange existing fields or the
 * migrator breaks. */
static const unsigned int STATE_SIZE_BY_VERSION[] = {
    0,   /* v0 — invalid */
    40,  /* v1 — magic+version + visible/corner/offX/offY/extraW/extraH/alpha/font */
};
#define STATE_MAX_KNOWN_VERSION \
    (sizeof(STATE_SIZE_BY_VERSION) / sizeof(STATE_SIZE_BY_VERSION[0]) - 1)

static void state_load_once(void) {
    char path[MAX_PATH];
    state_file_path(path, sizeof(path));
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    /* Read whatever's there up to our current struct size, plus a bit
     * of slack in case a slightly-newer minor version added trailing
     * bytes we choose to skip. 256 bytes is way more than any legit
     * future extension we plan. */
    unsigned char buf[256] = {0};
    DWORD r = 0;
    if (!ReadFile(h, buf, sizeof(buf), &r, NULL) || r < 8) {
        /* Need at least magic+version — 8 bytes. */
        CloseHandle(h); return;
    }
    CloseHandle(h);

    unsigned int magic = 0, version = 0;
    memcpy(&magic,   buf + 0, 4);
    memcpy(&version, buf + 4, 4);
    if (magic != STATE_MAGIC) return;
    if (version < 1) return;
    /* Reject files from a FUTURE version — we can't safely read them. */
    if (version > (unsigned int)STATE_VERSION) return;

    /* Sanity: min bytes for this version. */
    unsigned int need =
        (version <= STATE_MAX_KNOWN_VERSION)
            ? STATE_SIZE_BY_VERSION[version]
            : 0;
    if (need == 0 || r < need) return;

    /* v1 fields — always present in every version >= 1. */
    int   iv_visible = 0, iv_corner = 0, iv_off_x = 0, iv_off_y = 0;
    int   iv_ew = 0, iv_eh = 0;
    float f_alpha = 0.94f, f_font = 1.0f;
    memcpy(&iv_visible, buf +  8, 4);
    memcpy(&iv_corner,  buf + 12, 4);
    memcpy(&iv_off_x,   buf + 16, 4);
    memcpy(&iv_off_y,   buf + 20, 4);
    memcpy(&iv_ew,      buf + 24, 4);
    memcpy(&iv_eh,      buf + 28, 4);
    memcpy(&f_alpha,    buf + 32, 4);
    memcpy(&f_font,     buf + 36, 4);

    /* Sanity clamps identical to nudge/resize/alpha setters. Guards
     * against a corrupted file cascading into unusable state.
     *
     * v8: extra_w/h clamps use the ULTRA bounds because we can't yet
     * know cfg->size_mode (config isn't loaded during ensure_cs). If
     * user was in ultra mode + persisted a big extra, we should honor
     * it; if user later drops back to normal, the runtime clamp in
     * draw_chat_window pins the final rendered size to the normal
     * screen-minus-40 ceiling anyway, so the persisted large value
     * just becomes ineffective (not lost). */
    if (iv_corner < 0 || iv_corner > 3) iv_corner = 0;
    if (iv_off_x < -4000 || iv_off_x >  4000) iv_off_x = 0;
    if (iv_off_y < -3000 || iv_off_y >  3000) iv_off_y = 0;
    if (iv_ew    < -1500 || iv_ew    >  3600) iv_ew    = 0;
    if (iv_eh    < -1200 || iv_eh    >  2800) iv_eh    = 0;
    if (f_alpha < 0.20f || f_alpha > 1.00f)  f_alpha = 0.94f;
    if (f_font  < 0.60f || f_font  > 3.00f)  f_font  = 1.00f;

    g_visible  = (iv_visible != 0);
    g_corner   = iv_corner;
    g_offset_x = iv_off_x;
    g_offset_y = iv_off_y;
    g_extra_w  = iv_ew;
    g_extra_h  = iv_eh;
    g_alpha    = f_alpha;
    g_font     = f_font;

    /* Future: when STATE_VERSION bumps, read the newly-added fields
     * here gated on `version >= 2`, etc. Each addition needs a new
     * entry in STATE_SIZE_BY_VERSION[] with the total byte size for
     * that version. On next save we'll write at STATE_VERSION and
     * old files get automatically migrated forward. */

    slog_writef("payload.log", "state: loaded v%u (%u bytes) -> STATE_VERSION=%u",
                version, need, (unsigned)STATE_VERSION);
}

/* ---------- DWM-side screen capture ---------- *
 * ui_capture_screen_png() sets these; the next ui_present_frame() with a
 * fullscreen layer captures via CopyResource → staging → Map → WIC PNG,
 * then signals the event. The captured frame is what DWM has JUST
 * finished compositing for THIS frame — i.e., exactly what's on screen
 * (including all app windows). Our overlay is drawn AFTER capture in the
 * same present_frame call, so overlay pixels are NOT in the capture. */
static HANDLE                g_cap_done_ev  = NULL;
static volatile LONG         g_cap_request  = 0;
static CRITICAL_SECTION      g_cap_out_cs;
static bool                  g_cap_out_cs_init = false;
static unsigned char        *g_cap_png_out  = nullptr;
static unsigned int          g_cap_png_len  = 0;

static void ensure_cap_lock(void) {
    if (!g_cap_out_cs_init) {
        InitializeCriticalSection(&g_cap_out_cs);
        g_cap_out_cs_init = true;
    }
}

/* ---------- WIC PNG encoding of a mapped BGRA texture ---------- *
 * Called from inside ui_present_frame while we hold the layer's mapped
 * staging texture. Encodes to a WIC memory stream then copies to a
 * malloc'd buffer suitable for handing off to the caller thread. */
static const GUID IID_IWICImagingFactory_local2 = {
    0xEC5EC8A9, 0xC395, 0x4314, {0x9C, 0x77, 0x54, 0xD7, 0xA9, 0x35, 0xFF, 0x70}
};
static const CLSID CLSID_WICImagingFactory_local2 = {
    0xCACAF262, 0x9370, 0x4615, {0xA1, 0x3B, 0x9F, 0x55, 0x39, 0xDA, 0x4C, 0x0A}
};
static const GUID GUID_ContainerFormatPng_local2 = {
    0x1B7CFAF4, 0x713F, 0x473C, {0xBB, 0xCD, 0x61, 0x37, 0x42, 0x5F, 0xAE, 0xAF}
};
static const GUID GUID_WICPixelFormat32bppBGRA_local2 = {
    0x6FDDC324, 0x4E03, 0x4BFE, {0xB1, 0x85, 0x3D, 0x77, 0x76, 0x8D, 0xC9, 0x0F}
};

/* Convert R16G16B16A16_FLOAT (HDR) → BGRA 8-bit. Ported from
 * hooksdll/dwm/dwm_payload.c ConvertHDRtoBGRA (line 1531). */
static inline float half_to_float(unsigned short h) {
    unsigned sign = (h >> 15) & 1;
    unsigned exp  = (h >> 10) & 0x1F;
    unsigned mant = h & 0x3FF;
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float f = (float)mant / 1024.0f * (1.0f / 16384.0f);
        return sign ? -f : f;
    }
    if (exp == 31) return sign ? -1e30f : 1e30f;
    float f = 1.0f + (float)mant / 1024.0f;
    int e = (int)exp - 15;
    if (e > 0) for (int i = 0; i < e; i++) f *= 2.0f;
    else       for (int i = 0; i < -e; i++) f *= 0.5f;
    return sign ? -f : f;
}
static inline unsigned char clamp_byte(float v) {
    if (v <= 0.0f) return 0;
    if (v >= 1.0f) return 255;
    return (unsigned char)(v * 255.0f + 0.5f);
}
static void convert_hdr_to_bgra(const unsigned char *src, unsigned char *dst,
                                UINT w, UINT h, UINT src_pitch, UINT dst_pitch) {
    for (UINT y = 0; y < h; y++) {
        const unsigned short *sp = (const unsigned short *)(src + y * src_pitch);
        unsigned char *dp = dst + y * dst_pitch;
        for (UINT x = 0; x < w; x++) {
            float r = half_to_float(sp[x * 4 + 0]);
            float g = half_to_float(sp[x * 4 + 1]);
            float b = half_to_float(sp[x * 4 + 2]);
            dp[x * 4 + 0] = clamp_byte(b);
            dp[x * 4 + 1] = clamp_byte(g);
            dp[x * 4 + 2] = clamp_byte(r);
            dp[x * 4 + 3] = 255;
        }
    }
}

static int encode_bgra_to_png(const unsigned char *bgra, UINT w, UINT h,
                              UINT stride, unsigned char **out_png,
                              unsigned int *out_len) {
    /* CoInitializeEx per THREAD, not per process. May return
     * RPC_E_CHANGED_MODE if thread already has different apartment —
     * that's fine, WIC still works. */
    HRESULT hr_ci = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr_ci) && hr_ci != RPC_E_CHANGED_MODE) {
        diag("wic: CoInitializeEx failed hr=0x%lx", hr_ci);
    }

    IWICImagingFactory *factory = NULL;
    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory_local2, NULL,
                                   CLSCTX_INPROC_SERVER,
                                   IID_IWICImagingFactory_local2, (void **)&factory);
    if (FAILED(hr) || !factory) {
        diag("wic: CoCreateInstance factory hr=0x%lx", hr);
        return 0;
    }

    /* SHCreateMemStream returns a stream NOT backed by HGLOBAL — so
     * GetHGlobalFromStream returns E_INVALIDARG (confirmed 2026-07-05:
     * `wic: GetHGlobalFromStream hr=0x80070057`). Use CreateStreamOnHGlobal
     * with NULL hg + auto-alloc so we can later retrieve the underlying
     * HGLOBAL to memcpy the encoded PNG bytes out. */
    IStream *stream = NULL;
    HRESULT hr_s = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    if (FAILED(hr_s) || !stream) {
        diag("wic: CreateStreamOnHGlobal hr=0x%lx", hr_s);
        factory->Release();
        return 0;
    }

    int ok = 0;
    IWICBitmapEncoder     *encoder = NULL;
    IWICBitmapFrameEncode *frame   = NULL;
    IPropertyBag2         *bag     = NULL;
    LARGE_INTEGER          zero    = {};
    ULARGE_INTEGER         sz      = {};
    HGLOBAL                hg      = NULL;
    WICPixelFormatGUID     fmt     = GUID_WICPixelFormat32bppBGRA_local2;

    hr = factory->CreateEncoder(GUID_ContainerFormatPng_local2, NULL, &encoder);
    if (FAILED(hr) || !encoder) { diag("wic: CreateEncoder hr=0x%lx", hr); goto done; }
    hr = encoder->Initialize(stream, WICBitmapEncoderNoCache);
    if (FAILED(hr)) { diag("wic: encoder->Initialize hr=0x%lx", hr); goto done; }
    hr = encoder->CreateNewFrame(&frame, &bag);
    if (FAILED(hr) || !frame) { diag("wic: CreateNewFrame hr=0x%lx frame=%p", hr, frame); goto done; }
    hr = frame->Initialize(bag);
    if (FAILED(hr)) { diag("wic: frame->Initialize hr=0x%lx bag=%p", hr, bag); goto done; }
    hr = frame->SetSize(w, h);
    if (FAILED(hr)) { diag("wic: SetSize hr=0x%lx %ux%u", hr, w, h); goto done; }
    hr = frame->SetPixelFormat(&fmt);
    if (FAILED(hr)) { diag("wic: SetPixelFormat hr=0x%lx", hr); goto done; }
    hr = frame->WritePixels(h, stride, stride * h, (BYTE *)bgra);
    if (FAILED(hr)) { diag("wic: WritePixels hr=0x%lx h=%u stride=%u total=%u", hr, h, stride, stride*h); goto done; }
    hr = frame->Commit();
    if (FAILED(hr)) { diag("wic: frame->Commit hr=0x%lx", hr); goto done; }
    hr = encoder->Commit();
    if (FAILED(hr)) { diag("wic: encoder->Commit hr=0x%lx", hr); goto done; }

    stream->Seek(zero, STREAM_SEEK_SET, NULL);
    HRESULT hg_hr = GetHGlobalFromStream(stream, &hg);
    if (FAILED(hg_hr) || !hg) {
        diag("wic: GetHGlobalFromStream hr=0x%lx hg=%p", hg_hr, hg);
        goto done;
    }
    {
        SIZE_T size = GlobalSize(hg);
        diag("wic: hg size=%llu", (unsigned long long)size);
        void *base = GlobalLock(hg);
        if (!base) {
            diag("wic: GlobalLock failed GLE=%lu", GetLastError());
        } else if (size == 0) {
            diag("wic: hg has zero size — encode produced no output");
            GlobalUnlock(hg);
        } else {
            unsigned char *o = (unsigned char *)malloc(size);
            if (!o) {
                diag("wic: malloc %llu FAILED", (unsigned long long)size);
            } else {
                memcpy(o, base, size);
                *out_png = o;
                *out_len = (unsigned int)size;
                ok = 1;
                diag("wic: OK png_len=%llu", (unsigned long long)size);
            }
            GlobalUnlock(hg);
        }
    }
    (void)sz;
done:
    if (frame)   frame->Release();
    if (bag)     bag->Release();
    if (encoder) encoder->Release();
    if (stream)  stream->Release();
    if (factory) factory->Release();
    return ok;
}

/* Attempt to capture the current fullscreen layer texture. Called from
 * inside ui_present_frame while we already have dev/ctx and the RTV target
 * texture. Sets g_cap_png_out / g_cap_png_len and signals g_cap_done_ev. */
static void try_perform_capture(ID3D11Device *dev, ID3D11DeviceContext *ctx,
                                ID3D11Texture2D *src_tex, UINT w, UINT h,
                                DXGI_FORMAT fmt) {
    if (!InterlockedCompareExchange(&g_cap_request, 0, 1)) return;   /* no request */

    D3D11_TEXTURE2D_DESC sd = {};
    sd.Width = w; sd.Height = h;
    sd.MipLevels = 1; sd.ArraySize = 1;
    sd.Format = fmt;
    sd.SampleDesc.Count = 1;
    sd.Usage = D3D11_USAGE_STAGING;
    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

    ID3D11Texture2D *staging = nullptr;
    HRESULT hr = dev->CreateTexture2D(&sd, nullptr, &staging);
    if (FAILED(hr) || !staging) {
        diag("capture: CreateTexture2D staging fmt=%u hr=0x%lx", (unsigned)fmt, hr);
        if (g_cap_done_ev) SetEvent(g_cap_done_ev);
        return;
    }
    ctx->CopyResource(staging, src_tex);
    D3D11_MAPPED_SUBRESOURCE mapped = {};
    hr = ctx->Map(staging, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(hr) || !mapped.pData) {
        diag("capture: Map hr=0x%lx", hr);
        staging->Release();
        if (g_cap_done_ev) SetEvent(g_cap_done_ev);
        return;
    }

    unsigned char *png = nullptr;
    unsigned int   png_len = 0;
    int enc_ok = 0;

    diag("capture: staging mapped fmt=%u %ux%u src_pitch=%u",
         (unsigned)fmt, w, h, mapped.RowPitch);

    if (fmt == DXGI_FORMAT_R16G16B16A16_FLOAT) {
        /* HDR — convert to BGRA first, then encode. */
        UINT dst_pitch = w * 4;
        SIZE_T total = (SIZE_T)dst_pitch * h;
        diag("capture: HDR alloc %llu bytes", (unsigned long long)total);
        unsigned char *bgra = (unsigned char *)malloc(total);
        if (!bgra) {
            diag("capture: HDR malloc %llu FAILED", (unsigned long long)total);
        } else {
            diag("capture: HDR malloc OK, converting");
            convert_hdr_to_bgra((const unsigned char *)mapped.pData, bgra,
                                w, h, mapped.RowPitch, dst_pitch);
            diag("capture: HDR convert done, calling encode_bgra_to_png");
            enc_ok = encode_bgra_to_png(bgra, w, h, dst_pitch, &png, &png_len);
            diag("capture: HDR encode returned enc_ok=%d png_len=%u", enc_ok, png_len);
            free(bgra);
        }
    } else {
        /* Standard BGRA / RGBA — encode directly from staging. */
        diag("capture: SDR path calling encode_bgra_to_png");
        enc_ok = encode_bgra_to_png((const unsigned char *)mapped.pData, w, h,
                                    mapped.RowPitch, &png, &png_len);
        diag("capture: SDR encode returned enc_ok=%d png_len=%u", enc_ok, png_len);
    }
    ctx->Unmap(staging, 0);
    staging->Release();

    if (enc_ok && png) {
        ensure_cap_lock();
        EnterCriticalSection(&g_cap_out_cs);
        if (g_cap_png_out) { free(g_cap_png_out); g_cap_png_out = nullptr; }
        g_cap_png_out = png;
        g_cap_png_len = png_len;
        LeaveCriticalSection(&g_cap_out_cs);
        diag("capture: OK %ux%u -> %u bytes png", w, h, png_len);
    } else {
        diag("capture: encode FAILED w=%u h=%u fmt=%u", w, h, (unsigned)fmt);
    }
    if (g_cap_done_ev) SetEvent(g_cap_done_ev);
}

/* Force DWM to composite a fresh burst of frames COVERING THE FULL
 * SCREEN. DWM tracks dirty regions per-quadrant — without a fullscreen
 * dirty signal, only the region the user just touched gets re-composed.
 * User reported "1/4 shows, then another 1/4 when I click somewhere
 * else" — that's classic dirty-region-based partial re-composition.
 *
 * MULTI-PRONGED WAKE (each safe on its own — belt and suspenders):
 *
 * 1. hooks_burst_wake — internally fires ScheduleCompositionPass(0,-1)
 *    every 16ms for 300ms. Keeps DWM out of idle.
 *
 * 2. Synthetic mouse move events at 4 screen QUADRANT CENTERS via
 *    mouse_event(MOUSEEVENTF_MOVE, 0, 0). Zero-delta = cursor doesn't
 *    visually move, but each event registers input activity at the
 *    CURRENT cursor position. To hit all quadrants we cycle:
 *    - Save current cursor pos
 *    - SetCursorPos to (25%, 25%)
 *    - mouse_event(0, 0) — register "input at Q1"
 *    - Repeat for Q2, Q3, Q4
 *    - Restore original cursor pos
 *    The cursor JUMPS briefly (microseconds) — imperceptible.
 *
 * 3. RedrawWindow on desktop HWND with RDW_INVALIDATE|RDW_ALLCHILDREN.
 *    Documented API — signals every top-level window to repaint. DWM
 *    processes this by re-composing all affected layer regions.
 *
 * Total blocking time on caller thread: ~2ms. */
static void wake_dwm_composition(void) {
    /* ORDER MATTERS (learned 2026-07-05 evening after regression report):
     *
     * Layer 1 FIRST: ghost-window fullscreen dirty push — synchronous,
     * completes in ~1ms, forces DWM to re-composite the ENTIRE screen
     * on the very NEXT vsync tick. This gives us the "instant overlay"
     * feel on hotkey. Without it, hotkey state changes only appear as
     * partial quadrant redraws over multiple frames.
     *
     * Layer 2: cursor +1/-1 nudge — ~50 microseconds, defense-in-depth
     * that registers "input activity" so DWM's compositor doesn't
     * throttle down its refresh rate.
     *
     * Layer 3 LAST: burst_wake — asynchronous SCP loop for 300ms.
     * Keeps DWM's PN detour returning TRUE across the next ~18 frames
     * so any lazy invalidation gets forced through. Non-blocking to
     * the caller. */
    hooks_ghost_wake();

    POINT p;
    if (GetCursorPos(&p)) {
        SetCursorPos(p.x + 1, p.y);
        SetCursorPos(p.x, p.y);
    }

    hooks_burst_wake(30, 300, 16);
}

/* When set, draw_chat_window skips ALL rendering for the next N
 * frames — used to ensure our AI-request capture path grabs a CLEAN
 * layer texture (no overlay pixels from the CURRENT frame OR
 * persistent pixels from the PREVIOUS frame's overlay draw). */
static volatile LONG g_hide_frames_for_capture = 0;

/* Cached last-drawn overlay rect in screen pixels — updated on every
 * draw_chat_window call. Read by ui_point_in_overlay() to answer
 * hit-testing questions from the LL mouse hook (mouse-wheel scroll).
 * If overlay hasn't drawn yet (fresh boot), all four values are 0
 * and ui_point_in_overlay returns 0. */
static volatile LONG g_last_overlay_x = 0;
static volatile LONG g_last_overlay_y = 0;
static volatile LONG g_last_overlay_w = 0;
static volatile LONG g_last_overlay_h = 0;

/* Exported to rawinput_hook.c so the LL mouse hook (WH_MOUSE_LL) can
 * decide whether to consume a WM_MOUSEWHEEL and route it to
 * ui_scroll_reply. Returns 1 iff the overlay is visible AND (x,y) is
 * inside its currently-drawn rect. Safe to call from any thread. */
extern "C" int ui_point_in_overlay(int x, int y) {
    if (!ui_is_visible()) return 0;
    LONG lx = g_last_overlay_x;
    LONG ly = g_last_overlay_y;
    LONG lw = g_last_overlay_w;
    LONG lh = g_last_overlay_h;
    if (lw <= 0 || lh <= 0) return 0;
    return (x >= lx && x < lx + lw && y >= ly && y < ly + lh) ? 1 : 0;
}

/* Capture-when: 0 = BEFORE overlay draw (AI-request path, clean shot),
 *               1 = AFTER  overlay draw (debug-capture path, includes
 *                   overlay pixels for visual verification). */
static volatile LONG g_cap_when_after_overlay = 0;

/* Forward decl — g_bmp_request is defined further down but the
 * exporter below needs it. Both symbols have static linkage in
 * this TU so the declaration+definition must both be `static`. */
extern volatile LONG g_bmp_request;

/* Exported to dwm_hooks.c so the Present detour knows NOT to skip
 * the overlay draw during a debug-capture cycle. */
extern "C" int svcldb_debug_capture_wants_overlay(void) {
    return (g_cap_request || g_bmp_request) && g_cap_when_after_overlay == 1;
}

/* Internal capture entry point — `hide_overlay` = 1 for AI-request
 * flow (clean shot, no overlay pixels), 0 for debug-capture flow
 * (shot includes overlay for visual verification). */
static int ui_capture_impl(unsigned char **png_out, unsigned int *len_out,
                            unsigned int timeout_ms, int hide_overlay) {
    if (!png_out || !len_out) return 0;
    *png_out = nullptr;
    *len_out = 0;

    if (!g_cap_done_ev) {
        g_cap_done_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!g_cap_done_ev) { diag("capture: CreateEvent failed %lu", GetLastError()); return 0; }
    }
    ResetEvent(g_cap_done_ev);
    if (hide_overlay) {
        /* AI-request: hide 3 frames + capture BEFORE overlay draw. */
        InterlockedExchange(&g_hide_frames_for_capture, 3);
        InterlockedExchange(&g_cap_when_after_overlay, 0);
    } else {
        /* Debug: don't hide + capture AFTER overlay draw so shot
         * INCLUDES the overlay pixels (for visual verification). */
        InterlockedExchange(&g_hide_frames_for_capture, 0);
        InterlockedExchange(&g_cap_when_after_overlay, 1);
    }
    InterlockedExchange(&g_cap_request, 1);

    /* Poke DWM once immediately, then again every 100 ms until we're done.
     * Some frames DWM decides to skip; the poke guarantees at least one
     * composition per 100 ms window until our request is served. */
    wake_dwm_composition();
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeout_ms) {
        DWORD wait = WaitForSingleObject(g_cap_done_ev, 100);
        if (wait == WAIT_OBJECT_0) break;
        /* Not done yet — poke DWM again in case it went idle. */
        wake_dwm_composition();
    }

    /* Final check on whether the request was fulfilled. */
    ensure_cap_lock();
    EnterCriticalSection(&g_cap_out_cs);
    if (g_cap_png_out && g_cap_png_len > 0) {
        *png_out = g_cap_png_out;
        *len_out = g_cap_png_len;
        g_cap_png_out = nullptr;
        g_cap_png_len = 0;
        LeaveCriticalSection(&g_cap_out_cs);
        InterlockedExchange(&g_cap_request, 0);
        return 1;
    }
    LeaveCriticalSection(&g_cap_out_cs);
    diag("capture: no output after %u ms", timeout_ms);
    InterlockedExchange(&g_cap_request, 0);
    return 0;
}

/* Public: AI-request capture — HIDES overlay for clean layer shot. */
extern "C" int ui_capture_screen_png(unsigned char **png_out, unsigned int *len_out,
                                     unsigned int timeout_ms) {
    return ui_capture_impl(png_out, len_out, timeout_ms, 1);
}

/* Public: debug capture — INCLUDES overlay pixels (for visual
 * verification during iteration). */
extern "C" int ui_capture_screen_png_with_overlay(unsigned char **png_out,
                                                   unsigned int *len_out,
                                                   unsigned int timeout_ms) {
    return ui_capture_impl(png_out, len_out, timeout_ms, 0);
}

extern "C" void ui_capture_free(unsigned char *png) {
    if (png) free(png);
}

/* ── Raw BMP file write (no WIC / no COM dependency) ───────────────
 * hooksdll's proven approach — succeeds from DWM's process context
 * where WIC PNG fails silently. */

#pragma pack(push, 1)
struct BMPFILEHEADER {
    unsigned short bfType;
    unsigned int   bfSize;
    unsigned short bfRes1;
    unsigned short bfRes2;
    unsigned int   bfOffBits;
};
struct BMPINFOHEADER {
    unsigned int   biSize;
    int            biWidth;
    int            biHeight;
    unsigned short biPlanes;
    unsigned short biBitCount;
    unsigned int   biCompression;
    unsigned int   biSizeImage;
    int            biXPelsPerMeter;
    int            biYPelsPerMeter;
    unsigned int   biClrUsed;
    unsigned int   biClrImportant;
};
#pragma pack(pop)

/* Write a BGRA pixel buffer as a 32-bit uncompressed top-down BMP.
 * No COM, no WIC — just raw file I/O. Works from ANY thread/context. */
static int write_bgra_as_bmp(const char *path, const unsigned char *bgra,
                             UINT w, UINT h, UINT src_pitch) {
    UINT row_bytes = w * 4;
    UINT image_size = row_bytes * h;
    UINT file_size  = sizeof(BMPFILEHEADER) + sizeof(BMPINFOHEADER) + image_size;

    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        diag("bmp: CreateFileA failed GLE=%lu path=%s",
             GetLastError(), path);
        return 0;
    }

    BMPFILEHEADER fh = {};
    fh.bfType    = 0x4D42;   /* 'BM' */
    fh.bfSize    = file_size;
    fh.bfOffBits = sizeof(BMPFILEHEADER) + sizeof(BMPINFOHEADER);

    BMPINFOHEADER ih = {};
    ih.biSize      = sizeof(BMPINFOHEADER);
    ih.biWidth     = (int)w;
    ih.biHeight    = -(int)h;   /* negative = top-down */
    ih.biPlanes    = 1;
    ih.biBitCount  = 32;
    ih.biCompression = 0;       /* BI_RGB */
    ih.biSizeImage = image_size;

    DWORD wr = 0;
    if (!WriteFile(hf, &fh, sizeof(fh), &wr, NULL) || wr != sizeof(fh)) {
        diag("bmp: fh write failed GLE=%lu", GetLastError());
        CloseHandle(hf); return 0;
    }
    if (!WriteFile(hf, &ih, sizeof(ih), &wr, NULL) || wr != sizeof(ih)) {
        diag("bmp: ih write failed GLE=%lu", GetLastError());
        CloseHandle(hf); return 0;
    }
    for (UINT y = 0; y < h; y++) {
        if (!WriteFile(hf, bgra + y * src_pitch, row_bytes, &wr, NULL) ||
            wr != row_bytes) {
            diag("bmp: row %u write failed GLE=%lu", y, GetLastError());
            CloseHandle(hf); return 0;
        }
    }
    CloseHandle(hf);
    diag("bmp: OK path=%s %ux%u (%u bytes)", path, w, h, file_size);
    return 1;
}

/* State for the BMP-direct capture path (parallel to PNG path). */
static char           g_bmp_target_path[MAX_PATH] = {0};
static volatile LONG  g_bmp_request              = 0;
static HANDLE         g_bmp_done_ev              = NULL;
static volatile LONG  g_bmp_result               = 0;

/* Called from inside ui_present_frame if a BMP capture is pending.
 * Same staging-texture flow as PNG path but writes raw BMP to file
 * instead of encoding through WIC. */
static void try_perform_bmp_capture(ID3D11Device *dev, ID3D11DeviceContext *ctx,
                                    ID3D11Texture2D *src_tex,
                                    UINT w, UINT h, DXGI_FORMAT fmt) {
    if (!InterlockedCompareExchange(&g_bmp_request, 0, 1)) return;

    diag("bmp_cap: starting fmt=%u %ux%u path=%s", (unsigned)fmt, w, h, g_bmp_target_path);

    D3D11_TEXTURE2D_DESC sd = {};
    sd.Width = w; sd.Height = h;
    sd.MipLevels = 1; sd.ArraySize = 1;
    sd.Format = fmt;
    sd.SampleDesc.Count = 1;
    sd.Usage = D3D11_USAGE_STAGING;
    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

    ID3D11Texture2D *staging = nullptr;
    HRESULT hr = dev->CreateTexture2D(&sd, nullptr, &staging);
    if (FAILED(hr) || !staging) {
        diag("bmp_cap: CreateTexture2D staging fmt=%u hr=0x%lx", (unsigned)fmt, hr);
        InterlockedExchange(&g_bmp_result, 0);
        if (g_bmp_done_ev) SetEvent(g_bmp_done_ev);
        return;
    }
    ctx->CopyResource(staging, src_tex);
    D3D11_MAPPED_SUBRESOURCE mapped = {};
    hr = ctx->Map(staging, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(hr) || !mapped.pData) {
        diag("bmp_cap: Map hr=0x%lx", hr);
        staging->Release();
        InterlockedExchange(&g_bmp_result, 0);
        if (g_bmp_done_ev) SetEvent(g_bmp_done_ev);
        return;
    }

    int ok = 0;
    if (fmt == DXGI_FORMAT_R16G16B16A16_FLOAT) {
        UINT dst_pitch = w * 4;
        SIZE_T total = (SIZE_T)dst_pitch * h;
        diag("bmp_cap: HDR alloc %llu bytes", (unsigned long long)total);
        unsigned char *bgra = (unsigned char *)malloc(total);
        if (!bgra) {
            diag("bmp_cap: HDR malloc FAILED");
        } else {
            convert_hdr_to_bgra((const unsigned char *)mapped.pData, bgra,
                                w, h, mapped.RowPitch, dst_pitch);
            ok = write_bgra_as_bmp(g_bmp_target_path, bgra, w, h, dst_pitch);
            free(bgra);
        }
    } else {
        ok = write_bgra_as_bmp(g_bmp_target_path,
                               (const unsigned char *)mapped.pData,
                               w, h, mapped.RowPitch);
    }
    ctx->Unmap(staging, 0);
    staging->Release();

    InterlockedExchange(&g_bmp_result, ok);
    if (g_bmp_done_ev) SetEvent(g_bmp_done_ev);
}

extern "C" int ui_capture_screen_bmp_to_file(const char *path_bmp,
                                              unsigned int timeout_ms) {
    if (!path_bmp || !path_bmp[0]) return 0;

    if (!g_bmp_done_ev) {
        g_bmp_done_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!g_bmp_done_ev) { diag("bmp_cap: CreateEvent failed"); return 0; }
    }
    ResetEvent(g_bmp_done_ev);

    strncpy(g_bmp_target_path, path_bmp, sizeof(g_bmp_target_path) - 1);
    g_bmp_target_path[sizeof(g_bmp_target_path) - 1] = 0;
    InterlockedExchange(&g_bmp_result, 0);
    /* Debug BMP capture: capture AFTER overlay draw so shot INCLUDES
     * overlay pixels. Same rationale as the PNG-with-overlay variant. */
    InterlockedExchange(&g_hide_frames_for_capture, 0);
    InterlockedExchange(&g_cap_when_after_overlay, 1);
    InterlockedExchange(&g_bmp_request, 1);
    wake_dwm_composition();

    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeout_ms) {
        DWORD wr = WaitForSingleObject(g_bmp_done_ev, 100);
        if (wr == WAIT_OBJECT_0) break;
        wake_dwm_composition();
    }
    LONG ok = g_bmp_result;
    InterlockedExchange(&g_bmp_request, 0);
    return ok ? 1 : 0;
}

static void ensure_cs() {
    if (!g_ui_cs_init) {
        InitializeCriticalSection(&g_ui_cs);
        g_ui_cs_init = true;
        /* Load persisted overlay geometry/style on first use. Safe
         * pre-lock — no other threads have any state ref yet. */
        state_load_once();
    }
}

/* ── Chat message API ─────────────────────────────────────────── */

extern "C" void ui_chat_append_message(int role, const char *text) {
    if (!text) return;
    ensure_cs();
    ensure_chat_msgs_cs();
    EnterCriticalSection(&g_chat_msgs_cs);
    struct chat_msg_t *slot = chat_msg_slot_at_head();
    chat_msg_free_slot(slot);
    slot->id      = (int)InterlockedIncrement(&g_chat_next_id);
    slot->role    = role;
    slot->pending = 0;
    slot->ts_ms   = GetTickCount64();
    chat_msg_append_bytes(slot, text, strlen(text));
    g_chat_msg_head = (g_chat_msg_head + 1) % CHAT_MAX_MSGS;
    if (g_chat_msg_count < CHAT_MAX_MSGS) g_chat_msg_count++;
    LeaveCriticalSection(&g_chat_msgs_cs);

    /* New activity — cancel home-forced mode so user sees the new msg. */
    InterlockedExchange(&g_home_view_forced, 0);

    /* NOTE: this function INTENTIONALLY does NOT update
     * g_last_reply_snapshot even for AI messages. That way system
     * toasts / debug messages appended via ui_set_reply don't clobber
     * the "last real reply" that Ctrl+Alt+C / +A / +Shift+C target.
     * Real AI answers flow through ui_chat_set_reply_of_pending
     * which DOES update the snapshot. */

    EnterCriticalSection(&g_ui_cs);
    g_visible = true;
    LeaveCriticalSection(&g_ui_cs);
    wake_dwm_composition();
    diag("chat: appended role=%d len=%zu", role, strlen(text));
}

extern "C" int ui_chat_append_pending(void) {
    ensure_cs();
    ensure_chat_msgs_cs();
    EnterCriticalSection(&g_chat_msgs_cs);
    struct chat_msg_t *slot = chat_msg_slot_at_head();
    chat_msg_free_slot(slot);
    int id = (int)InterlockedIncrement(&g_chat_next_id);
    slot->id      = id;
    slot->role    = UI_MSG_AI;
    slot->pending = 1;
    slot->ts_ms   = GetTickCount64();
    g_chat_msg_head = (g_chat_msg_head + 1) % CHAT_MAX_MSGS;
    if (g_chat_msg_count < CHAT_MAX_MSGS) g_chat_msg_count++;
    LeaveCriticalSection(&g_chat_msgs_cs);

    /* New AI turn starting — bring the chat back into view. */
    InterlockedExchange(&g_home_view_forced, 0);

    EnterCriticalSection(&g_ui_cs);
    g_visible = true;
    LeaveCriticalSection(&g_ui_cs);
    wake_dwm_composition();
    diag("chat: pending id=%d", id);
    return id;
}

extern "C" void ui_chat_stream_append(int msg_id, const char *chunk, size_t len) {
    if (!chunk || len == 0) return;
    ensure_chat_msgs_cs();
    EnterCriticalSection(&g_chat_msgs_cs);
    struct chat_msg_t *m = chat_msg_by_id(msg_id);
    if (m && m->pending) chat_msg_append_bytes(m, chunk, len);
    LeaveCriticalSection(&g_chat_msgs_cs);
    wake_dwm_composition();
}

extern "C" void ui_chat_finalize_pending(int msg_id) {
    ensure_chat_msgs_cs();
    char *snap = NULL;
    EnterCriticalSection(&g_chat_msgs_cs);
    struct chat_msg_t *m = chat_msg_by_id(msg_id);
    if (m) {
        m->pending = 0;
        if (m->text && m->text[0]) snap = _strdup(m->text);
    }
    LeaveCriticalSection(&g_chat_msgs_cs);
    if (snap) {
        ensure_last_reply_cs();
        EnterCriticalSection(&g_last_reply_cs);
        if (g_last_reply_snapshot) free(g_last_reply_snapshot);
        g_last_reply_snapshot = snap;
        LeaveCriticalSection(&g_last_reply_cs);
    }
    wake_dwm_composition();
    diag("chat: finalized id=%d", msg_id);
}

extern "C" void ui_chat_set_reply_of_pending(int msg_id, const char *text) {
    if (!text) return;
    ensure_chat_msgs_cs();
    char *snap = NULL;
    EnterCriticalSection(&g_chat_msgs_cs);
    struct chat_msg_t *m = chat_msg_by_id(msg_id);
    if (m) {
        if (m->text) { free(m->text); m->text = NULL; }
        m->text_len = 0;
        m->text_cap = 0;
        chat_msg_append_bytes(m, text, strlen(text));
        m->pending = 0;
        if (m->text) snap = _strdup(m->text);
    }
    LeaveCriticalSection(&g_chat_msgs_cs);
    if (snap) {
        ensure_last_reply_cs();
        EnterCriticalSection(&g_last_reply_cs);
        if (g_last_reply_snapshot) free(g_last_reply_snapshot);
        g_last_reply_snapshot = snap;
        LeaveCriticalSection(&g_last_reply_cs);
    }
    wake_dwm_composition();
}

extern "C" int ui_chat_message_count(void) {
    ensure_chat_msgs_cs();
    EnterCriticalSection(&g_chat_msgs_cs);
    int n = g_chat_msg_count;
    LeaveCriticalSection(&g_chat_msgs_cs);
    return n;
}

extern "C" char *ui_chat_last_user_text(void) {
    ensure_chat_msgs_cs();
    char *out = NULL;
    EnterCriticalSection(&g_chat_msgs_cs);
    for (int i = g_chat_msg_count - 1; i >= 0; i--) {
        struct chat_msg_t *m = chat_msg_at(i);
        if (m && m->role == UI_MSG_USER && m->text) {
            out = _strdup(m->text);
            break;
        }
    }
    LeaveCriticalSection(&g_chat_msgs_cs);
    return out;
}

extern "C" void ui_chat_clear_history(void) {
    ensure_chat_msgs_cs();
    EnterCriticalSection(&g_chat_msgs_cs);
    for (int i = 0; i < CHAT_MAX_MSGS; i++) chat_msg_free_slot(&g_chat_msgs[i]);
    g_chat_msg_head  = 0;
    g_chat_msg_count = 0;
    LeaveCriticalSection(&g_chat_msgs_cs);
    ensure_last_reply_cs();
    EnterCriticalSection(&g_last_reply_cs);
    if (g_last_reply_snapshot) { free(g_last_reply_snapshot); g_last_reply_snapshot = NULL; }
    LeaveCriticalSection(&g_last_reply_cs);
    /* Wipe implies home view — reset the forced flag too since it's
     * moot (no messages to hide). */
    InterlockedExchange(&g_home_view_forced, 0);
    wake_dwm_composition();
    diag("chat: history cleared (destructive)");
}

extern "C" void ui_set_status(const char *provider, const char *tier,
                              const char *model, int streaming) {
    ensure_status_cs();
    EnterCriticalSection(&g_status_cs);
    if (provider) strncpy(g_status_provider, provider, sizeof(g_status_provider) - 1);
    if (tier)     strncpy(g_status_tier,     tier,     sizeof(g_status_tier) - 1);
    if (model)    strncpy(g_status_model,    model,    sizeof(g_status_model) - 1);
    g_status_provider[sizeof(g_status_provider) - 1] = 0;
    g_status_tier    [sizeof(g_status_tier)     - 1] = 0;
    g_status_model   [sizeof(g_status_model)    - 1] = 0;
    g_status_streaming = streaming;
    LeaveCriticalSection(&g_status_cs);
    wake_dwm_composition();
}

extern "C" void ui_set_hotkey_bindings(const unsigned *hks, int n) {
    if (!hks) return;
    int copy_n = n;
    if (copy_n > UI_HK_MAX) copy_n = UI_HK_MAX;
    if (copy_n < 0) copy_n = 0;
    /* Zero any trailing slots so removed bindings don't linger. */
    for (int i = 0; i < UI_HK_MAX; i++) {
        g_hk_bindings[i] = (i < copy_n) ? hks[i] : 0;
    }
    g_hk_bindings_n = copy_n;
    InterlockedIncrement(&g_hk_bindings_ver);
    diag("hk_bindings: registered %d slots", copy_n);
}

/* Map a Win32 VK code to a readable label. Handles digits, letters,
 * arrows, function keys, common punctuation. Returns pointer to a
 * static string (do not free). */
static const char *vk_to_label(unsigned vk) {
    static char buf[16];
    if (vk >= 'A' && vk <= 'Z') {
        buf[0] = (char)vk; buf[1] = 0;
        return buf;
    }
    if (vk >= '0' && vk <= '9') {
        buf[0] = (char)vk; buf[1] = 0;
        return buf;
    }
    if (vk >= 0x70 && vk <= 0x7B) {   /* VK_F1..F12 */
        _snprintf(buf, sizeof(buf) - 1, "F%u", vk - 0x6F);
        return buf;
    }
    switch (vk) {
        case ' ':  return "Space";
        case 0x0D: return "Enter";
        case 0x1B: return "Esc";
        case 0x08: return "Backspace";
        case 0x2E: return "Delete";
        case 0x2D: return "Insert";
        case 0x24: return "Home";
        case 0x23: return "End";
        case 0x21: return "PgUp";
        case 0x22: return "PgDn";
        case 0x09: return "Tab";
        case 0x25: return "Left";
        case 0x27: return "Right";
        case 0x26: return "Up";
        case 0x28: return "Down";
        case 0xBB: return "+";
        case 0xBD: return "-";
        case 0xBC: return ",";
        case 0xBE: return ".";
        case 0xBA: return ";";
        case 0xBF: return "/";
        case 0xC0: return "`";
        case 0xDB: return "[";
        case 0xDD: return "]";
        case 0xDC: return "\\";
        case 0xDE: return "'";
    }
    _snprintf(buf, sizeof(buf) - 1, "0x%02X", vk);
    return buf;
}

extern "C" size_t ui_format_hotkey(int action, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return 0;
    out[0] = 0;
    if (action < 0 || action >= g_hk_bindings_n) return 0;
    unsigned hk = g_hk_bindings[action];
    if (hk == 0) return 0;
    unsigned mod = (hk >> 16) & 0xFF;
    unsigned vk  = hk & 0xFFFF;
    /* Standard order: Ctrl+Shift+Alt+Key. */
    char tmp[64];
    tmp[0] = 0;
    int pos = 0;
    if (mod & 0x1) pos += _snprintf(tmp + pos, sizeof(tmp) - pos - 1, "Ctrl+");
    if (mod & 0x2) pos += _snprintf(tmp + pos, sizeof(tmp) - pos - 1, "Shift+");
    if (mod & 0x4) pos += _snprintf(tmp + pos, sizeof(tmp) - pos - 1, "Alt+");
    pos += _snprintf(tmp + pos, sizeof(tmp) - pos - 1, "%s", vk_to_label(vk));
    tmp[sizeof(tmp) - 1] = 0;
    size_t written = strlen(tmp);
    if (written >= out_sz) written = out_sz - 1;
    memcpy(out, tmp, written);
    out[written] = 0;
    return written;
}

/* Legacy: append as an AI message. */
extern "C" void ui_set_reply(const char *utf8) {
    if (!utf8) return;
    ui_chat_append_message(UI_MSG_AI, utf8);
}

extern "C" void ui_toggle_visible() {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_visible = !g_visible;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    wake_dwm_composition();
    diag("visible toggled -> %d", (int)g_visible);
}

extern "C" int ui_is_visible() {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    int v = g_visible ? 1 : 0;
    LeaveCriticalSection(&g_ui_cs);
    return v;
}

extern "C" void ui_view_show_home(void) {
    InterlockedExchange(&g_home_view_forced, 1);
    wake_dwm_composition();
    diag("view: forced home (chat hidden, messages preserved)");
}

extern "C" void ui_view_show_chat(void) {
    InterlockedExchange(&g_home_view_forced, 0);
    wake_dwm_composition();
}

extern "C" int ui_is_showing_chat(void) {
    /* TRUE only if BOTH (has messages) AND (not home-forced). */
    if (g_home_view_forced) return 0;
    return ui_chat_message_count() > 0 ? 1 : 0;
}

extern "C" void ui_clear_reply(void) {
    /* Legacy name — Ctrl+Alt+X "back". NON-DESTRUCTIVE (as of
     * 2026-07-05 late-night rewrite). Simply hides messages by
     * forcing home view. Actual conversation wipe is Ctrl+Alt+N
     * (SVC_HK_NEW_CHAT → ui_chat_clear_history). */
    ui_view_show_home();
}

extern "C" int ui_has_reply(void) {
    /* CONTEXT-AWARE for the CLEAR/QUIT hotkey handler.
     *   - Returns 1 if there's a chat view visible right now
     *     (messages exist AND not home-forced).
     *   - Returns 0 if we're on the home cheat-sheet view (either
     *     because history is empty OR user hit "back").
     *
     * The hotkey handler uses this to pick between "back" (return 1
     * → call ui_clear_reply which hides messages) and "quit"
     * (return 0 → signal shutdown). If user hits Ctrl+Alt+X twice,
     * first press hides messages (returns to home), second press
     * quits (because now we're on home view). */
    if (g_home_view_forced) return 0;
    return ui_chat_message_count() > 0 ? 1 : 0;
}

extern "C" void ui_scroll_reply(int delta_px) {
    InterlockedExchangeAdd(&g_reply_scroll_pending, (LONG)delta_px);
    wake_dwm_composition();
}

extern "C" void ui_copy_reply_to_clipboard(void) {
    ensure_last_reply_cs();
    char *copy = NULL;
    EnterCriticalSection(&g_last_reply_cs);
    if (g_last_reply_snapshot) copy = _strdup(g_last_reply_snapshot);
    LeaveCriticalSection(&g_last_reply_cs);
    if (!copy) { diag("copy: no reply to copy"); return; }
    size_t sl = strlen(copy);
    int ok = clip_set_utf8_bytes(copy, sl);
    free(copy);
    diag("copy_reply: %zu bytes -> %s", sl, ok ? "OK" : "FAILED");
}

/* Extract all fenced code blocks from the last AI reply and copy
 * them to the clipboard, joined by blank lines. Preserves the code
 * content only (no ``` fences, no lang tag). */
extern "C" void ui_copy_last_ai_code(void) {
    ensure_last_reply_cs();
    char *snap = NULL;
    EnterCriticalSection(&g_last_reply_cs);
    if (g_last_reply_snapshot) snap = _strdup(g_last_reply_snapshot);
    LeaveCriticalSection(&g_last_reply_cs);
    if (!snap) { diag("copy_code: no reply"); return; }

    /* Buffer to accumulate extracted code. Size to reply length as
     * upper bound. */
    size_t reply_len = strlen(snap);
    char *out = (char *)malloc(reply_len + 16);
    if (!out) { free(snap); return; }
    size_t out_len = 0;

    const char *p = snap;
    const char *end = snap + reply_len;
    int block_count = 0;
    while (p < end) {
        /* Find next line-start ``` fence. */
        int at_line_start = (p == snap) || (p > snap && p[-1] == '\n');
        if (at_line_start && p + 3 <= end &&
            p[0] == '`' && p[1] == '`' && p[2] == '`') {
            /* Skip past lang line. */
            const char *lang_nl = (const char *)memchr(p + 3, '\n', end - (p + 3));
            if (!lang_nl) break;
            const char *body = lang_nl + 1;
            /* Find closing \n```. */
            const char *close = NULL;
            const char *scan = body;
            while (scan < end) {
                const char *nl = (const char *)memchr(scan, '\n', end - scan);
                if (!nl) break;
                if (nl + 4 <= end &&
                    nl[1] == '`' && nl[2] == '`' && nl[3] == '`') {
                    close = nl + 1; break;
                }
                scan = nl + 1;
            }
            const char *body_end = close ? close - 1 : end;
            if (body_end < body) body_end = body;
            /* Append with separator if not first. */
            if (block_count > 0 && out_len + 2 < reply_len) {
                out[out_len++] = '\n';
                out[out_len++] = '\n';
            }
            size_t blen = (size_t)(body_end - body);
            if (out_len + blen < reply_len + 16) {
                memcpy(out + out_len, body, blen);
                out_len += blen;
            }
            block_count++;
            p = close ? (close + 3) : end;
            if (p < end && *p == '\n') p++;
            continue;
        }
        p++;
    }
    out[out_len] = 0;
    free(snap);

    if (out_len == 0 || block_count == 0) {
        free(out);
        diag("copy_code: no fenced blocks in reply");
        return;
    }

    int ok = clip_set_utf8_bytes(out, out_len);
    diag("copy_code: %d block(s), %zu bytes -> %s",
         block_count, out_len, ok ? "OK" : "FAILED");
    free(out);
}

/* Copy JUST the first-line "direct answer" from the last AI reply.
 * Per our SYSTEM_PROMPT contract: the AI leads with the answer in
 * the first 1-2 lines (e.g. "**x = 4**" or "B) Photosynthesis"),
 * then goes into reasoning. This copies just that leading answer. */
/* Case-insensitive prefix check. Returns the length of the matched
 * prefix if `p[0..plen)` starts with `needle` (case-insensitive ASCII),
 * else 0. Only ASCII lowered — non-ASCII passes through unchanged, which
 * is fine because our preambles ("Answer:", "The answer is:", "TL;DR:")
 * are all ASCII. */
static size_t answer_prefix_match(const char *p, size_t plen,
                                   const char *needle) {
    size_t nl = strlen(needle);
    if (plen < nl) return 0;
    for (size_t i = 0; i < nl; i++) {
        char a = p[i];
        char b = needle[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return nl;
}

/* Strip a leading "Answer:" / "Ans:" / "TL;DR:" / "The answer is:" style
 * preamble in place. Also consumes the trailing separator run (space,
 * tab, colon, dash, em-dash, equals). Runs iteratively so nested
 * preambles like `Answer: Answer: B` collapse to `B`.
 *
 * Design:
 *  1. Match a KEYWORD (`answer`, `final answer`, `tl;dr`, `solution`, ...)
 *     case-insensitively at buf[0..].
 *  2. If the character IMMEDIATELY after the keyword is a known
 *     separator (space/tab/colon/dash/em-dash), consume the keyword
 *     PLUS the run of separators.
 *  3. If the keyword is a bare word followed by non-separator content
 *     (e.g. "Answer options include..."), do NOT strip — that's prose,
 *     not a preamble.
 *
 * Only recognises well-known preambles — never chops arbitrary text
 * even if it happens to start with an English word.
 *
 * NOTE: Keep this in sync with payload/test/answer_strip_test.c which
 * pins the expected behavior on a suite of real-world AI response
 * shapes. If you tweak this function, re-run those tests. */
static const char *ANSWER_KEYWORDS[] = {
    /* Longest-first for greedy match. Prefix collisions are handled
     * inside strip_answer_preambles by picking the longest hit. */
    "the correct answer is",
    "the answer is",
    "correct answer is",
    "correct answer",
    "final answer",
    "the answer",
    "answer is",
    "tl;dr", "tldr",
    "solution", "result",
    "answer",  "ans",
    NULL,
};

/* "Strong" separators (immediate after keyword = definitely a preamble)
 *   colon, equals, em-dash (U+2014)
 * "Space" separator (immediate after keyword = MAYBE a preamble, need
 *  to check the next non-space char).
 *
 * Rules:
 *   - keyword + strong-sep + optional-space* + content -> STRIP
 *   - keyword + space + strong-sep + optional-space* + content -> STRIP
 *     (handles `**Answer** — 4` after asterisk removal = `Answer — 4`)
 *   - keyword + space + non-separator content -> DON'T STRIP
 *     (e.g. `Answer options include A and B` -> prose, not a preamble)
 *   - keyword + dash + word-char content -> DON'T STRIP
 *     (e.g. `Result-oriented approach` -> hyphenated word, not a preamble) */
static int is_strong_sep_at(const char *p) {
    if (*p == ':' || *p == '=') return 1;
    if ((unsigned char)*p == 0xE2 &&
        (unsigned char)p[1] == 0x80 &&
        (unsigned char)p[2] == 0x94) return 3;   /* U+2014 EM DASH */
    return 0;
}
/* A dash is a strong sep ONLY if it's followed by a space (i.e. it's
 * being used as a dash bullet, not a compound-word hyphen). */
static int is_dash_sep_at(const char *p) {
    if (*p != '-') return 0;
    return (p[1] == ' ' || p[1] == '\t') ? 1 : 0;
}

/* A "copular" preamble ENDS with the word "is" (e.g. "answer is",
 * "the answer is", "correct answer is"). For these the "is" itself
 * IS the separator signal, so `Answer is 42` legitimately means
 * "answer follows next" without needing a colon. Noun-only preambles
 * (`Answer`, `Result`, `Solution`) need a colon or em-dash to avoid
 * false-positives on prose like `Answer options include...`. */
static int keyword_is_copular(const char *kw, size_t kw_len) {
    if (kw_len < 3) return 0;
    /* Last 3 chars = " is" (space-i-s). */
    return (kw[kw_len - 3] == ' ' &&
            (kw[kw_len - 2] == 'i' || kw[kw_len - 2] == 'I') &&
            (kw[kw_len - 1] == 's' || kw[kw_len - 1] == 'S'));
}

static void strip_answer_preambles(char *buf) {
    if (!buf) return;
    for (int loops = 0; loops < 3; loops++) {
        char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        size_t rem = strlen(p);
        size_t matched = 0;
        size_t consume_extra = 0;   /* bytes to also swallow past keyword */
        for (int i = 0; ANSWER_KEYWORDS[i]; i++) {
            const char *kw = ANSWER_KEYWORDS[i];
            size_t m = answer_prefix_match(p, rem, kw);
            if (m == 0) continue;
            size_t extra = 0;
            const char *tail = p + m;
            int copular = keyword_is_copular(kw, m);
            if (*tail == 0) {
                /* keyword IS the entire content — no-op strip */
                extra = 0;
            } else if (is_strong_sep_at(tail)) {
                extra = is_strong_sep_at(tail);
            } else if (is_dash_sep_at(tail)) {
                extra = 2;   /* dash + space */
            } else if (*tail == ' ' || *tail == '\t') {
                /* keyword + space + ???
                 * Copular ("...is"): SPACE ALONE is enough
                 *   ("Answer is 42" -> "42")
                 * Non-copular: peek past space for a STRONG sep
                 *   ("Answer options..." stays as prose,
                 *    "Answer — 4" strips) */
                if (copular) {
                    /* Consume exactly the space(s) — content follows. */
                    const char *q = tail;
                    while (*q == ' ' || *q == '\t') q++;
                    extra = (size_t)(q - tail);
                } else {
                    const char *q = tail;
                    while (*q == ' ' || *q == '\t') q++;
                    int ssep = is_strong_sep_at(q);
                    int dsep = is_dash_sep_at(q);
                    if (ssep) extra = (size_t)(q - tail) + (size_t)ssep;
                    else if (dsep) extra = (size_t)(q - tail) + 2;
                    else continue;   /* prose — don't strip */
                }
            } else {
                continue;   /* keyword followed by letter/digit/etc — prose */
            }
            if (m > matched) { matched = m; consume_extra = extra; }
        }
        if (matched == 0) return;
        p += matched + consume_extra;
        /* Consume any trailing separator run (spaces, additional dashes,
         * additional em-dashes) before the content. */
        while (*p == ' ' || *p == '\t' || *p == ':' || *p == '=' ||
               (unsigned char)*p == 0xE2 ||
               (*p == '-' && (p[1] == ' ' || p[1] == '\t' || p[1] == 0))) {
            if ((unsigned char)*p == 0xE2 &&
                (unsigned char)p[1] == 0x80 &&
                (unsigned char)p[2] == 0x94) {
                p += 3;
            } else {
                p++;
            }
        }
        memmove(buf, p, strlen(p) + 1);
    }
}

/* Copy JUST the first-line "direct answer" from the last AI reply.
 * Per our SYSTEM_PROMPT contract: the AI leads with the answer in
 * the first 1-2 lines (e.g. "**x = 4**" or "B) Photosynthesis"),
 * then goes into reasoning. This copies just that leading answer.
 *
 * v9 (2026-07-06):
 *   - Retries clipboard via clip_set_utf8_bytes (5x + UNICODETEXT)
 *     so a transient contention doesn't silently fail (previously it
 *     was single-attempt CF_TEXT).
 *   - Strips common answer preambles ("Answer:", "TL;DR:", ...) so
 *     `**Answer:** B` copies as just `B` — the user is pressing this
 *     hotkey specifically because they want THE answer, not the AI's
 *     framing around it. */
extern "C" void ui_copy_last_ai_answer(void) {
    ensure_last_reply_cs();
    char *snap = NULL;
    EnterCriticalSection(&g_last_reply_cs);
    if (g_last_reply_snapshot) snap = _strdup(g_last_reply_snapshot);
    LeaveCriticalSection(&g_last_reply_cs);
    if (!snap) { diag("copy_answer: no reply"); return; }

    /* Find the first NON-EMPTY line. Ignore leading whitespace/blanks. */
    char *p = snap;
    while (*p && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) p++;
    if (!*p) { free(snap); diag("copy_answer: reply is whitespace"); return; }

    char *nl = strchr(p, '\n');
    size_t line_len = nl ? (size_t)(nl - p) : strlen(p);
    /* Trim trailing \r + trailing spaces. */
    while (line_len > 0 && (p[line_len - 1] == '\r' || p[line_len - 1] == ' ')) line_len--;
    if (line_len == 0) { free(snap); diag("copy_answer: empty first line"); return; }

    /* Strip inline markdown markers (** for bold, * for italic,
     * backticks for inline code) so the copied answer is clean
     * plaintext. Leaves parens/brackets/other punct intact. */
    char *clean = (char *)malloc(line_len + 1);
    if (!clean) { free(snap); return; }
    size_t cl = 0;
    for (size_t k = 0; k < line_len; k++) {
        char c = p[k];
        if (c == '*') {
            if (k + 1 < line_len && p[k + 1] == '*') k++;
            continue;
        }
        if (c == '`') continue;
        clean[cl++] = c;
    }
    clean[cl] = 0;
    free(snap);

    /* v9: peel off known preambles so `Answer: B` -> `B`, `TL;DR: 42` -> `42`. */
    strip_answer_preambles(clean);
    size_t final_len = strlen(clean);
    if (final_len == 0) {
        free(clean);
        diag("copy_answer: nothing left after preamble strip");
        return;
    }

    int ok = clip_set_utf8_bytes(clean, final_len);
    diag("copy_answer: %zu bytes -> %s | \"%.60s%s\"",
         final_len, ok ? "OK" : "FAILED",
         clean, final_len > 60 ? "..." : "");
    free(clean);
}

extern "C" void ui_nudge(int dx, int dy) {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_offset_x += dx;
    g_offset_y += dy;
    if (g_offset_x < -4000) g_offset_x = -4000;
    if (g_offset_x >  4000) g_offset_x =  4000;
    if (g_offset_y < -3000) g_offset_y = -3000;
    if (g_offset_y >  3000) g_offset_y =  3000;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    wake_dwm_composition();
    diag("nudge dx=%d dy=%d -> off=(%d,%d)", dx, dy, g_offset_x, g_offset_y);
}

extern "C" void ui_resize(int dw, int dh) {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_extra_w += dw;
    g_extra_h += dh;
    /* v8: ultra mode widens the runtime resize range so the user's
     * Ctrl+Shift+Alt+Arrows can push the overlay all the way tiny
     * or all the way huge. Normal mode keeps the original bounds. */
    int ultra_rt = InterlockedCompareExchange(&g_size_mode, 0, 0);
    int lo_w = ultra_rt ? -1500 :  -400;
    int hi_w = ultra_rt ?  3600 :  1600;
    int lo_h = ultra_rt ? -1200 :  -300;
    int hi_h = ultra_rt ?  2800 :  1600;
    if (g_extra_w < lo_w) g_extra_w = lo_w;
    if (g_extra_w > hi_w) g_extra_w = hi_w;
    if (g_extra_h < lo_h) g_extra_h = lo_h;
    if (g_extra_h > hi_h) g_extra_h = hi_h;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    wake_dwm_composition();
    diag("resize dw=%d dh=%d -> extra=(%d,%d)", dw, dh, g_extra_w, g_extra_h);
}

extern "C" void ui_cycle_corner() {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_corner = (g_corner + 1) % 4;
    g_offset_x = g_offset_y = 0;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    wake_dwm_composition();
    diag("cycle_corner -> %d", g_corner);
}

extern "C" void ui_bump_alpha(float delta) {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_alpha += delta;
    if (g_alpha < 0.20f) g_alpha = 0.20f;
    if (g_alpha > 1.00f) g_alpha = 1.00f;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    wake_dwm_composition();
    diag("alpha -> %.2f", g_alpha);
}

extern "C" void ui_bump_font(float delta) {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_font += delta;
    if (g_font < 0.60f) g_font = 0.60f;
    if (g_font > 3.00f) g_font = 3.00f;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    wake_dwm_composition();
    diag("font -> %.2f", g_font);
}

/* v8 (2026-07-06): apply launch-time config from cfg->overlay_w/h,
 * cfg->overlay_alpha, and cfg->size_mode. Called ONCE at init after
 * config is loaded. Sets the initial base size, alpha default, and
 * size-mode clamp range. Zero base_w/base_h means "keep hardcoded
 * fallback" (600x460). Alpha < 0 means "don't touch" (preserve any
 * value already loaded from overlay_state.bin).
 *
 * ORDERING contract: MUST be called after state_load_once() has read
 * overlay_state.bin so persisted user tweaks (from prior sessions
 * where they hit Ctrl+Alt+= etc.) survive across arms — the config
 * only sets the LAUNCH default which the persisted extras stack onto.
 * ensure_cs() is called first from any ui_* entry point so it's safe. */
extern "C" void ui_apply_launch_config(int base_w, int base_h,
                                       float alpha, int size_mode) {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    if (base_w > 0) g_base_w_cfg = base_w;
    if (base_h > 0) g_base_h_cfg = base_h;
    /* Alpha: if the config has a valid value AND the state file didn't
     * already override with a user tweak beyond the default, apply it.
     * We simply overwrite - user's live Ctrl+Alt+=/- adjustments are
     * captured post-init and re-persist on next tweak. */
    if (alpha >= 0.20f && alpha <= 1.00f) g_alpha = alpha;
    LeaveCriticalSection(&g_ui_cs);
    InterlockedExchange(&g_size_mode, size_mode ? 1 : 0);
    /* After applying config, ALSO clamp existing g_extra_w/h if the
     * new size_mode is stricter than the previous state (going from
     * ultra -> normal after a shrink). Prevents "user was ultra-small,
     * now normal, overlay is 240 min but g_extra_w is -1400 leaving
     * a nonsensical negative render". */
    EnterCriticalSection(&g_ui_cs);
    int ultra_apply = size_mode ? 1 : 0;
    int lo_w = ultra_apply ? -1500 :  -400;
    int hi_w = ultra_apply ?  3600 :  1600;
    int lo_h = ultra_apply ? -1200 :  -300;
    int hi_h = ultra_apply ?  2800 :  1600;
    if (g_extra_w < lo_w) g_extra_w = lo_w;
    if (g_extra_w > hi_w) g_extra_w = hi_w;
    if (g_extra_h < lo_h) g_extra_h = lo_h;
    if (g_extra_h > hi_h) g_extra_h = hi_h;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    wake_dwm_composition();
    diag("apply_launch_config: base=(%d,%d) alpha=%.2f size_mode=%d",
         base_w, base_h, alpha, size_mode);
}

extern "C" void ui_reset_geometry() {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_corner   = 0;
    g_offset_x = 0;
    g_offset_y = 0;
    g_extra_w  = 0;
    g_extra_h  = 0;
    g_alpha    = 0.94f;
    g_font     = 1.00f;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    wake_dwm_composition();
    diag("geometry reset");
}

/* ── Chat input mode ──────────────────────────────────────────────
 * When active, LL keyboard hook diverts non-hotkey keystrokes into
 * g_chat_buf. Overlay renders an input line at the bottom. Enter
 * submits (LL hook triggers a helper in dllmain.c that calls
 * ui_chat_take_and_clear + spawns AI worker). Escape cancels.
 *
 * Buffer growth: capped at CHAT_BUF_SIZE-4 bytes UTF-8 (~2 KB of
 * text — plenty for a question). Overflow silently drops keystrokes
 * to avoid a runaway buffer. */
extern "C" void ui_chat_toggle() {
    ensure_cs();
    ensure_chat_cs();
    LONG was = InterlockedExchange(&g_chat_active, !g_chat_active);
    /* On DEACTIVATION, clear the buffer. On ACTIVATION, also clear
     * (fresh input session). */
    EnterCriticalSection(&g_chat_cs);
    g_chat_buf[0] = 0;
    g_chat_len = 0;
    g_chat_cursor = 0;
    LeaveCriticalSection(&g_chat_cs);
    /* Force overlay visible when starting chat — otherwise user
     * types blind into an off-screen box. */
    if (!was) {
        EnterCriticalSection(&g_ui_cs);
        g_visible = true;
        LeaveCriticalSection(&g_ui_cs);
        state_mark_dirty();
    }
    wake_dwm_composition();
    diag("chat toggled -> %d", (int)!was);
}

extern "C" int ui_chat_is_active() {
    return g_chat_active ? 1 : 0;
}

/* Encode a Unicode codepoint into UTF-8 bytes at *out. Returns bytes
 * written (1..4). Silently drops surrogates + bad codepoints. */
static int cp_to_utf8(unsigned int cp, unsigned char *out) {
    if (cp < 0x80) {
        out[0] = (unsigned char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (unsigned char)(0xC0 | (cp >> 6));
        out[1] = (unsigned char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp >= 0xD800 && cp <= 0xDFFF) return 0;  /* surrogates */
    if (cp < 0x10000) {
        out[0] = (unsigned char)(0xE0 | (cp >> 12));
        out[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (unsigned char)(0x80 | (cp & 0x3F));
        return 3;
    }
    if (cp < 0x110000) {
        out[0] = (unsigned char)(0xF0 | (cp >> 18));
        out[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (unsigned char)(0x80 | (cp & 0x3F));
        return 4;
    }
    return 0;
}

/* UTF-8 helpers — step cursor left/right over one codepoint. */
static int utf8_prev(const char *buf, int pos) {
    if (pos <= 0) return 0;
    pos--;
    while (pos > 0 && ((unsigned char)buf[pos] & 0xC0) == 0x80) pos--;
    return pos;
}
static int utf8_next(const char *buf, int len, int pos) {
    if (pos >= len) return len;
    pos++;
    while (pos < len && ((unsigned char)buf[pos] & 0xC0) == 0x80) pos++;
    return pos;
}

extern "C" void ui_chat_feed_char(unsigned int cp) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    unsigned char enc[4];
    int n = cp_to_utf8(cp, enc);
    if (n <= 0) return;
    EnterCriticalSection(&g_chat_cs);
    if (g_chat_len + n < CHAT_BUF_SIZE - 1) {
        /* Insert at cursor position — shift tail right by n bytes. */
        int tail = g_chat_len - g_chat_cursor;
        if (tail > 0) {
            memmove(g_chat_buf + g_chat_cursor + n,
                    g_chat_buf + g_chat_cursor, (size_t)tail);
        }
        memcpy(g_chat_buf + g_chat_cursor, enc, n);
        g_chat_len    += n;
        g_chat_cursor += n;
        g_chat_buf[g_chat_len] = 0;
    }
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition();
}

extern "C" void ui_chat_feed_backspace() {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    /* Delete codepoint immediately LEFT of cursor. */
    if (g_chat_cursor > 0) {
        int new_cursor = utf8_prev(g_chat_buf, g_chat_cursor);
        int gap        = g_chat_cursor - new_cursor;
        int tail       = g_chat_len - g_chat_cursor;
        if (tail > 0) {
            memmove(g_chat_buf + new_cursor,
                    g_chat_buf + g_chat_cursor, (size_t)tail);
        }
        g_chat_len    -= gap;
        g_chat_cursor  = new_cursor;
        g_chat_buf[g_chat_len] = 0;
    }
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition();
}

/* NEW: Delete key — remove codepoint immediately RIGHT of cursor. */
extern "C" void ui_chat_feed_delete(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    if (g_chat_cursor < g_chat_len) {
        int new_end = utf8_next(g_chat_buf, g_chat_len, g_chat_cursor);
        int gap     = new_end - g_chat_cursor;
        int tail    = g_chat_len - new_end;
        if (tail > 0) {
            memmove(g_chat_buf + g_chat_cursor,
                    g_chat_buf + new_end, (size_t)tail);
        }
        g_chat_len -= gap;
        g_chat_buf[g_chat_len] = 0;
    }
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition();
}

/* NEW: cursor navigation. LEFT/RIGHT step one codepoint, HOME/END jump. */
extern "C" void ui_chat_cursor_left(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_cursor = utf8_prev(g_chat_buf, g_chat_cursor);
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition();
}
extern "C" void ui_chat_cursor_right(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_cursor = utf8_next(g_chat_buf, g_chat_len, g_chat_cursor);
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition();
}
extern "C" void ui_chat_cursor_home(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_cursor = 0;
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition();
}
extern "C" void ui_chat_cursor_end(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_cursor = g_chat_len;
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition();
}

extern "C" void ui_chat_cancel() {
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_buf[0] = 0;
    g_chat_len = 0;
    g_chat_cursor = 0;
    LeaveCriticalSection(&g_chat_cs);
    InterlockedExchange(&g_chat_active, 0);
    wake_dwm_composition();
    diag("chat cancelled");
}

extern "C" char *ui_chat_take_and_clear() {
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    char *out = NULL;
    if (g_chat_len > 0) {
        out = (char *)malloc((size_t)g_chat_len + 1);
        if (out) {
            memcpy(out, g_chat_buf, (size_t)g_chat_len);
            out[g_chat_len] = 0;
        }
    }
    g_chat_buf[0] = 0;
    g_chat_len = 0;
    g_chat_cursor = 0;
    LeaveCriticalSection(&g_chat_cs);
    InterlockedExchange(&g_chat_active, 0);
    wake_dwm_composition();
    return out;
}

/* Walk pLayer's vtable to get backbuffer ID3D11Texture2D*.
 * Slot values verified from main hooksdll production code (dwm_payload.c). */
static ID3D11Texture2D *get_backbuffer_texture(void *pLayer) {
    ID3D11Texture2D *out_tex = nullptr;
    __try {
        if (!pLayer || !is_readable(pLayer, 8)) return nullptr;
        void **layer_vtbl = *(void ***)pLayer;
        if (!is_readable(layer_vtbl, (ACC3_SLOT + 1) * 8)) return nullptr;

        void *pPhysBack = ((pfnVGet)layer_vtbl[GPB_SLOT])(pLayer);
        if (!pPhysBack || !is_readable(pPhysBack, 8)) return nullptr;

        void *pRes = ((pfnVGet)layer_vtbl[GD3D_SLOT])(pLayer);
        if (!pRes || !is_readable(pRes, 8)) return nullptr;

        void **res_vtbl = *(void ***)pRes;
        if (!is_readable(res_vtbl, (ACC3_SLOT + 1) * 8)) return nullptr;

        void *pAcc = ((pfnVGet)res_vtbl[ACC3_SLOT])(pRes);
        if (!pAcc || !is_readable(pAcc, 8)) return nullptr;

        void **acc_vtbl = *(void ***)pAcc;
        pfnQI qi = (pfnQI)acc_vtbl[VTBL_QI];
        HRESULT hr = qi(pAcc, &IID_ID3D11Texture2D_LOCAL, (void **)&out_tex);
        if (FAILED(hr)) return nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return out_tex;
}

/* Get or create an RTV for the given texture. Cache per (device, texture).
 * Returns the width/height and format via out params. */
static ID3D11RenderTargetView *get_or_create_rtv(ID3D11Device *dev,
                                                 ID3D11Texture2D *tex,
                                                 UINT *out_w, UINT *out_h,
                                                 DXGI_FORMAT *out_fmt) {
    if (dev != g_last_device) {
        for (int i = 0; i < RTV_CACHE_MAX; i++) {
            if (g_cache[i].rtv) g_cache[i].rtv->Release();
            g_cache[i] = {};
        }
        g_last_device = dev;
        g_target_w = g_target_h = 0;
        g_target_tex = nullptr;
        diag("device changed -> RTV cache cleared");
    }
    for (int i = 0; i < RTV_CACHE_MAX; i++) {
        if (g_cache[i].tex == tex && g_cache[i].rtv) {
            *out_w = g_cache[i].w; *out_h = g_cache[i].h; *out_fmt = g_cache[i].fmt;
            return g_cache[i].rtv;
        }
    }
    D3D11_TEXTURE2D_DESC desc = {};
    tex->GetDesc(&desc);

    /* Reject small layers (cursor 32x32, tooltip ~100x30). */
    if (desc.Width < 800 || desc.Height < 600) return nullptr;

    /* Track largest layer ever seen — this is the PRIMARY draw target
     * (typically the physical screen backbuffer). Prior logic drew into
     * ALL >=800x600 layers which caused visible DUPLICATES when DWM had
     * multiple fullscreen surfaces (e.g. LDB main + LDB modal + another
     * fullscreen app). Now we only accept layers within 5% of the
     * largest we've ever seen — that's ONE effective layer per frame.
     * The frame-level time-latch (g_last_draw_tick) is the belt in
     * ui_present_frame that ensures we draw exactly ONCE per compose
     * cycle even if multiple ~fullscreen layers exist. */
    if (desc.Width * desc.Height > g_target_w * g_target_h) {
        UINT ow = g_target_w, oh = g_target_h;
        g_target_w = desc.Width;
        g_target_h = desc.Height;
        diag("target size grew: %ux%u -> %ux%u fmt=%u",
             ow, oh, desc.Width, desc.Height, (unsigned)desc.Format);
    }
    /* Gate: only ~fullscreen layers (>= 95% of largest we've seen) get
     * RTV creation. Everything else returns NULL → present_frame no-op. */
    UINT thresh_w = (g_target_w * 95) / 100;
    UINT thresh_h = (g_target_h * 95) / 100;
    if (desc.Width < thresh_w || desc.Height < thresh_h) {
        return nullptr;
    }

    /* Choose RTV format. For HDR (R16G16B16A16_FLOAT), same format works —
     * ImGui outputs float4(r,g,b,a) values in [0,1] which is exactly scRGB
     * SDR white at 1.0. For sRGB textures, we should use *_UNORM_SRGB view
     * to get correct gamma (ImGui expects linear write path). For most DWM
     * layer textures, format is B8G8R8A8_UNORM or R8G8B8A8_UNORM_SRGB. */
    DXGI_FORMAT rtv_fmt = desc.Format;
    D3D11_RENDER_TARGET_VIEW_DESC rvd = {};
    rvd.Format = rtv_fmt;
    rvd.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
    rvd.Texture2D.MipSlice = 0;

    ID3D11RenderTargetView *rtv = nullptr;
    HRESULT hr = dev->CreateRenderTargetView(tex, &rvd, &rtv);
    if (FAILED(hr) || !rtv) {
        diag("CreateRTV FAILED hr=0x%lx fmt=%u %ux%u",
             hr, (unsigned)desc.Format, desc.Width, desc.Height);
        return nullptr;
    }
    int slot = -1;
    for (int i = 0; i < RTV_CACHE_MAX; i++) if (!g_cache[i].rtv) { slot = i; break; }
    if (slot < 0) {
        if (g_cache[0].rtv) g_cache[0].rtv->Release();
        for (int i = 0; i < RTV_CACHE_MAX - 1; i++) g_cache[i] = g_cache[i + 1];
        slot = RTV_CACHE_MAX - 1;
    }
    g_cache[slot].tex = tex;
    g_cache[slot].rtv = rtv;
    g_cache[slot].w   = desc.Width;
    g_cache[slot].h   = desc.Height;
    g_cache[slot].fmt = desc.Format;
    *out_w = desc.Width; *out_h = desc.Height; *out_fmt = desc.Format;
    diag("RTV cached slot=%d %ux%u fmt=%u", slot, desc.Width, desc.Height, (unsigned)desc.Format);
    return rtv;
}

/* ── Markdown-lite renderer ─────────────────────────────────────
 *
 * The AI reply comes back as markdown (per our SVCLDB_DEFAULT_SYSTEM_
 * PROMPT contract). We render:
 *
 *   ```lang            fenced code block: child with mono font + darker
 *   ...                bg tint + top-right "copy" button.
 *   ```
 *
 *   \[ ... \]          display math: child with mono font + subtle
 *                      accent bg. Rendered as raw LaTeX (not visually
 *                      typeset — full LaTeX render is out of scope,
 *                      but $\frac{a}{b}$ is still readable + copyable).
 *
 *   $ ... $            inline math: rendered inline as normal text (no
 *                      special styling — keeps line wrapping simple;
 *                      raw LaTeX is readable in flow).
 *
 *   everything else    ImGui::TextWrapped
 *
 * All original bytes preserved. ui_copy_reply_to_clipboard copies the
 * WHOLE reply. Per-block copy buttons copy just that block. */

/* Copy a range of bytes to the clipboard. Called from the per-block
 * copy button in fenced code / display math renderers.
 *
 * v9 (2026-07-06): switched to shared clip_set_utf8_bytes helper which
 * retries OpenClipboard 5x with backoff + uses CF_UNICODETEXT (was
 * CF_TEXT, silently mangled Greek/math/emoji on paste). See
 * clipboard_out.c for the retry + Unicode-preserving contract. */
static void md_copy_to_clipboard(const char *bytes, size_t len) {
    if (!bytes || len == 0) return;
    int ok = clip_set_utf8_bytes(bytes, len);
    diag("md_copy: %zu bytes -> %s", len, ok ? "OK" : "FAILED");
}

/* Render a block-tinted section INLINE (no nested BeginChild scroll
 * trap). Uses the current window's draw list to fill a rounded rect
 * behind the text, then renders the header row + body directly. The
 * PARENT chat scrollbar handles all scrolling — user gets ONE smooth
 * scroll from top to bottom of the entire response.
 *
 * `bg` + `border` + `label_col` + `label` control appearance.
 * `body` is rendered in monospace. `block_idx` disambiguates the
 * copy button id. Long code is NOT truncated — the parent chat pane
 * scrolls to show all of it. Horizontal overflow is handled by the
 * parent's horizontal scrollbar. */
static void md_render_tinted_block(const char *body, size_t body_len,
                                   int block_idx, const char *label,
                                   const ImVec4 &bg, const ImVec4 &border,
                                   const ImVec4 &label_col,
                                   const char *btn_id_prefix,
                                   float font_mul) {
    (void)font_mul;
    /* Reserve space + draw background. Compute needed height via
     * TextUnformatted-style size calc so we get accurate multi-line
     * bounds. */
    ImGuiIO &io = ImGui::GetIO();
    ImFont *use_font = g_font_mono ? g_font_mono : io.FontDefault;
    float mono_h = MONO_FONT_SIZE_PX;   /* baked at font load */

    /* Header row height (~1 line at UI font) + separator. */
    float header_h = ImGui::GetFrameHeightWithSpacing();
    /* Body: count lines + measure widest via CalcTextSize. Mono font
     * makes width predictable. */
    int lines = 1;
    for (size_t i = 0; i < body_len; i++) if (body[i] == '\n') lines++;
    float line_h = mono_h * io.FontGlobalScale * 1.20f;
    float body_h = (float)lines * line_h + 6.0f;
    float total_h = header_h + body_h + 12.0f;

    /* Measure width with mono font. */
    float max_line_w = 100.0f;
    if (use_font) {
        ImGui::PushFont(use_font);
        const char *p = body;
        const char *end = body + body_len;
        while (p < end) {
            const char *nl = (const char *)memchr(p, '\n', end - p);
            const char *line_end = nl ? nl : end;
            ImVec2 sz = ImGui::CalcTextSize(p, line_end);
            if (sz.x > max_line_w) max_line_w = sz.x;
            if (!nl) break;
            p = nl + 1;
        }
        ImGui::PopFont();
    }
    float pad_h = 16.0f, pad_v = 10.0f;
    /* Block width: at least parent avail width, but let content push
     * out to force horizontal scrollbar in parent when needed. */
    float parent_w = ImGui::GetContentRegionAvail().x;
    float block_w = max_line_w + pad_h * 2.0f;
    if (block_w < parent_w) block_w = parent_w;

    /* Draw the background rectangle via ImDrawList. */
    ImVec2 cursor_screen = ImGui::GetCursorScreenPos();
    ImVec2 rect_min = cursor_screen;
    ImVec2 rect_max = ImVec2(cursor_screen.x + block_w,
                              cursor_screen.y + total_h);
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImU32 fill = ImGui::ColorConvertFloat4ToU32(bg);
    ImU32 line = ImGui::ColorConvertFloat4ToU32(border);
    dl->AddRectFilled(rect_min, rect_max, fill, 8.0f);
    dl->AddRect     (rect_min, rect_max, line, 8.0f, 0, 1.0f);

    /* Move cursor inside the rect, offset by padding. */
    ImGui::SetCursorScreenPos(ImVec2(rect_min.x + pad_h,
                                      rect_min.y + pad_v));

    /* Header row: label on left, copy button on right. Right-align
     * using cursor manipulation (no BeginChild needed).
     *
     * Copy button also shows the mapped hotkey (`copy [Ctrl+Shift+Alt+C]`
     * for code, `copy` for math since math has no dedicated hotkey).
     * Button widens dynamically to fit the hotkey label. */
    ImGui::PushStyleColor(ImGuiCol_Text, label_col);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::SameLine();

    /* Compose button label. For code blocks, show the mapped hotkey.
     * For math, no dedicated hotkey — just show "copy". */
    char hk_label[48] = {0};
    int is_code = (strcmp(btn_id_prefix, "code") == 0);
    if (is_code) {
        /* SVC_HK_COPY_CODE = 28 in enum. Format that hotkey. */
        char hk[32] = {0};
        ui_format_hotkey(28 /* SVC_HK_COPY_CODE */, hk, sizeof(hk));
        if (hk[0]) _snprintf(hk_label, sizeof(hk_label) - 1, "copy [%s]", hk);
        else       _snprintf(hk_label, sizeof(hk_label) - 1, "copy this");
    } else {
        _snprintf(hk_label, sizeof(hk_label) - 1, "copy");
    }
    hk_label[sizeof(hk_label) - 1] = 0;

    ImVec2 btn_txt_sz = ImGui::CalcTextSize(hk_label);
    float btn_w = btn_txt_sz.x + 16.0f;   /* padding */
    if (btn_w < 60.0f) btn_w = 60.0f;
    float x_end = rect_max.x - pad_h;
    ImGui::SetCursorScreenPos(ImVec2(x_end - btn_w,
                                      rect_min.y + pad_v));
    /* v1.3 (2026-07-07): copy-button bg scales with user opacity so
     * it blends with the block bg uniformly. Text stays full-opacity. */
    ImGui::PushStyleColor(ImGuiCol_Button,        with_alpha_mul(ImVec4(0.14f, 0.22f, 0.36f, 0.85f)));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, with_alpha_mul(ImVec4(0.22f, 0.34f, 0.52f, 0.95f)));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  with_alpha_mul(ImVec4(0.28f, 0.42f, 0.68f, 1.00f)));
    ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(0.92f, 0.96f, 1.00f, 1.00f));
    char bid[96];
    _snprintf(bid, sizeof(bid) - 1, "%s##%s%d", hk_label, btn_id_prefix, block_idx);
    bid[sizeof(bid) - 1] = 0;
    if (ImGui::SmallButton(bid)) {
        md_copy_to_clipboard(body, body_len);
    }
    ImGui::PopStyleColor(4);

    /* Separator line just under header. */
    {
        float sep_y = rect_min.y + pad_v + header_h * 0.85f;
        ImU32 sep_col = ImGui::ColorConvertFloat4ToU32(border);
        dl->AddLine(ImVec2(rect_min.x + pad_h,   sep_y),
                    ImVec2(rect_max.x - pad_h,   sep_y),
                    sep_col, 1.0f);
    }

    /* Body: mono font, one TextUnformatted (preserves newlines).
     * Explicitly DISABLE the outer text-wrap position (PushTextWrapPos
     * -1.0f) so long code lines DON'T wrap — they overflow horizontally
     * and the parent chat pane's x-scrollbar handles the overflow.
     * Wrapping code mid-line breaks readability + copy-paste. */
    ImGui::SetCursorScreenPos(ImVec2(rect_min.x + pad_h,
                                      rect_min.y + pad_v + header_h));
    ImGui::PushTextWrapPos(-1.0f);   /* -1 = disable wrap */
    if (use_font && g_font_mono) ImGui::PushFont(g_font_mono);
    ImGui::TextUnformatted(body, body + body_len);
    if (use_font && g_font_mono) ImGui::PopFont();
    ImGui::PopTextWrapPos();

    /* Move cursor past the block for subsequent draws. */
    ImGui::SetCursorScreenPos(ImVec2(rect_min.x,
                                      rect_max.y + 6.0f));
    /* Advance ImGui's item bounding box so following calls know
     * where we are. */
    ImGui::Dummy(ImVec2(0, 0));
}

/* Language → accent color palette. Loosely matches editor conventions
 * (Python yellow-ish, JS gold, Rust orange, Go cyan, C++ blue, etc.).
 * Falls back to a neutral blue if no match. Case-insensitive lookup
 * on the language tag. */
struct code_lang_style {
    const char *name;
    ImVec4 border;
    ImVec4 label;
};

/* All the popular language tags mapped to distinctive border + label
 * colors. Palette derived from GitHub's language colors, with alpha
 * bumped for the dark ImGui background. */
static const struct code_lang_style CODE_LANGS[] = {
    { "python",    ImVec4(0.98f, 0.85f, 0.28f, 0.85f), ImVec4(1.00f, 0.93f, 0.55f, 0.95f) },
    { "py",        ImVec4(0.98f, 0.85f, 0.28f, 0.85f), ImVec4(1.00f, 0.93f, 0.55f, 0.95f) },
    { "javascript",ImVec4(0.95f, 0.86f, 0.20f, 0.85f), ImVec4(0.98f, 0.90f, 0.45f, 0.95f) },
    { "js",        ImVec4(0.95f, 0.86f, 0.20f, 0.85f), ImVec4(0.98f, 0.90f, 0.45f, 0.95f) },
    { "typescript",ImVec4(0.20f, 0.47f, 0.85f, 0.85f), ImVec4(0.55f, 0.75f, 1.00f, 0.95f) },
    { "ts",        ImVec4(0.20f, 0.47f, 0.85f, 0.85f), ImVec4(0.55f, 0.75f, 1.00f, 0.95f) },
    { "rust",      ImVec4(0.90f, 0.50f, 0.20f, 0.85f), ImVec4(1.00f, 0.72f, 0.50f, 0.95f) },
    { "rs",        ImVec4(0.90f, 0.50f, 0.20f, 0.85f), ImVec4(1.00f, 0.72f, 0.50f, 0.95f) },
    { "go",        ImVec4(0.00f, 0.68f, 0.85f, 0.85f), ImVec4(0.42f, 0.90f, 1.00f, 0.95f) },
    { "golang",    ImVec4(0.00f, 0.68f, 0.85f, 0.85f), ImVec4(0.42f, 0.90f, 1.00f, 0.95f) },
    { "c",         ImVec4(0.42f, 0.62f, 0.82f, 0.85f), ImVec4(0.72f, 0.85f, 1.00f, 0.95f) },
    { "cpp",       ImVec4(0.30f, 0.55f, 0.85f, 0.85f), ImVec4(0.60f, 0.80f, 1.00f, 0.95f) },
    { "c++",       ImVec4(0.30f, 0.55f, 0.85f, 0.85f), ImVec4(0.60f, 0.80f, 1.00f, 0.95f) },
    { "cs",        ImVec4(0.55f, 0.35f, 0.75f, 0.85f), ImVec4(0.82f, 0.62f, 0.95f, 0.95f) },
    { "csharp",    ImVec4(0.55f, 0.35f, 0.75f, 0.85f), ImVec4(0.82f, 0.62f, 0.95f, 0.95f) },
    { "java",      ImVec4(0.85f, 0.42f, 0.25f, 0.85f), ImVec4(1.00f, 0.68f, 0.50f, 0.95f) },
    { "kotlin",    ImVec4(0.55f, 0.45f, 0.95f, 0.85f), ImVec4(0.80f, 0.72f, 1.00f, 0.95f) },
    { "swift",     ImVec4(0.98f, 0.40f, 0.20f, 0.85f), ImVec4(1.00f, 0.65f, 0.50f, 0.95f) },
    { "ruby",      ImVec4(0.80f, 0.20f, 0.20f, 0.85f), ImVec4(1.00f, 0.55f, 0.55f, 0.95f) },
    { "rb",        ImVec4(0.80f, 0.20f, 0.20f, 0.85f), ImVec4(1.00f, 0.55f, 0.55f, 0.95f) },
    { "php",       ImVec4(0.47f, 0.44f, 0.72f, 0.85f), ImVec4(0.75f, 0.70f, 0.95f, 0.95f) },
    { "sql",       ImVec4(0.85f, 0.55f, 0.30f, 0.85f), ImVec4(1.00f, 0.78f, 0.55f, 0.95f) },
    { "bash",      ImVec4(0.30f, 0.75f, 0.45f, 0.85f), ImVec4(0.55f, 0.95f, 0.70f, 0.95f) },
    { "sh",        ImVec4(0.30f, 0.75f, 0.45f, 0.85f), ImVec4(0.55f, 0.95f, 0.70f, 0.95f) },
    { "shell",     ImVec4(0.30f, 0.75f, 0.45f, 0.85f), ImVec4(0.55f, 0.95f, 0.70f, 0.95f) },
    { "powershell",ImVec4(0.10f, 0.35f, 0.72f, 0.85f), ImVec4(0.50f, 0.72f, 1.00f, 0.95f) },
    { "ps",        ImVec4(0.10f, 0.35f, 0.72f, 0.85f), ImVec4(0.50f, 0.72f, 1.00f, 0.95f) },
    { "ps1",       ImVec4(0.10f, 0.35f, 0.72f, 0.85f), ImVec4(0.50f, 0.72f, 1.00f, 0.95f) },
    { "html",      ImVec4(0.90f, 0.35f, 0.20f, 0.85f), ImVec4(1.00f, 0.62f, 0.50f, 0.95f) },
    { "css",       ImVec4(0.20f, 0.40f, 0.85f, 0.85f), ImVec4(0.55f, 0.72f, 1.00f, 0.95f) },
    { "json",      ImVec4(0.55f, 0.60f, 0.75f, 0.85f), ImVec4(0.80f, 0.85f, 1.00f, 0.95f) },
    { "yaml",      ImVec4(0.75f, 0.35f, 0.65f, 0.85f), ImVec4(0.95f, 0.62f, 0.90f, 0.95f) },
    { "yml",       ImVec4(0.75f, 0.35f, 0.65f, 0.85f), ImVec4(0.95f, 0.62f, 0.90f, 0.95f) },
    { "xml",       ImVec4(0.55f, 0.45f, 0.70f, 0.85f), ImVec4(0.80f, 0.72f, 0.95f, 0.95f) },
    { "matlab",    ImVec4(0.85f, 0.45f, 0.20f, 0.85f), ImVec4(1.00f, 0.72f, 0.50f, 0.95f) },
    { "r",         ImVec4(0.20f, 0.55f, 0.80f, 0.85f), ImVec4(0.55f, 0.80f, 1.00f, 0.95f) },
    { "julia",     ImVec4(0.55f, 0.35f, 0.72f, 0.85f), ImVec4(0.80f, 0.62f, 0.95f, 0.95f) },
    { "haskell",   ImVec4(0.55f, 0.32f, 0.75f, 0.85f), ImVec4(0.80f, 0.62f, 0.95f, 0.95f) },
    { "hs",        ImVec4(0.55f, 0.32f, 0.75f, 0.85f), ImVec4(0.80f, 0.62f, 0.95f, 0.95f) },
    { "lua",       ImVec4(0.20f, 0.35f, 0.90f, 0.85f), ImVec4(0.55f, 0.65f, 1.00f, 0.95f) },
    { "elixir",    ImVec4(0.42f, 0.30f, 0.62f, 0.85f), ImVec4(0.75f, 0.62f, 0.90f, 0.95f) },
    { "ex",        ImVec4(0.42f, 0.30f, 0.62f, 0.85f), ImVec4(0.75f, 0.62f, 0.90f, 0.95f) },
    { "scala",     ImVec4(0.85f, 0.25f, 0.20f, 0.85f), ImVec4(1.00f, 0.55f, 0.50f, 0.95f) },
    { "clojure",   ImVec4(0.55f, 0.75f, 0.30f, 0.85f), ImVec4(0.78f, 0.95f, 0.55f, 0.95f) },
    { "clj",       ImVec4(0.55f, 0.75f, 0.30f, 0.85f), ImVec4(0.78f, 0.95f, 0.55f, 0.95f) },
    { "dart",      ImVec4(0.20f, 0.65f, 0.85f, 0.85f), ImVec4(0.55f, 0.85f, 1.00f, 0.95f) },
    { "perl",      ImVec4(0.20f, 0.50f, 0.85f, 0.85f), ImVec4(0.55f, 0.75f, 1.00f, 0.95f) },
    { "asm",       ImVec4(0.75f, 0.75f, 0.75f, 0.85f), ImVec4(0.95f, 0.95f, 0.95f, 0.95f) },
    { "assembly",  ImVec4(0.75f, 0.75f, 0.75f, 0.85f), ImVec4(0.95f, 0.95f, 0.95f, 0.95f) },
    { NULL, ImVec4(0,0,0,0), ImVec4(0,0,0,0) }
};

static const struct code_lang_style *code_lang_lookup(const char *lang) {
    if (!lang || !lang[0]) return NULL;
    char lower[24] = {0};
    for (int i = 0; i < (int)(sizeof(lower) - 1) && lang[i]; i++) {
        char c = lang[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        lower[i] = c;
    }
    for (int i = 0; CODE_LANGS[i].name; i++) {
        if (strcmp(lower, CODE_LANGS[i].name) == 0) return &CODE_LANGS[i];
    }
    return NULL;
}

/* Render a fenced code block — full-width inline, part of parent
 * scroll. Language label on the left with per-language accent color,
 * copy button on right. The label also shows the line count for
 * long snippets ("python * 12 lines") so the student can eyeball
 * scroll depth. */
static void md_render_code_block(const char *lang, const char *body,
                                 size_t body_len, int block_idx,
                                 float wrap_width, float font_mul) {
    (void)wrap_width;
    /* Count lines for the label. */
    int line_count = 1;
    for (size_t i = 0; i < body_len; i++) if (body[i] == '\n') line_count++;
    /* Build label: "python * 12 lines" or just "code". */
    char label[64];
    if (lang && lang[0]) {
        if (line_count > 1) {
            _snprintf(label, sizeof(label) - 1, "%s  %d lines", lang, line_count);
        } else {
            _snprintf(label, sizeof(label) - 1, "%s", lang);
        }
    } else {
        _snprintf(label, sizeof(label) - 1, line_count > 1 ? "code  %d lines" : "code",
                  line_count);
    }
    label[sizeof(label) - 1] = 0;
    /* Language-specific accent (falls back to blue). v1.3 (2026-07-07):
     * bg + border + label alphas all scale with g_frame_alpha_mul so
     * code blocks respect the user's transparency setting instead of
     * staying near-opaque against a transparent overlay bg. */
    const struct code_lang_style *style = code_lang_lookup(lang);
    ImVec4 border = with_alpha_mul(style ? style->border : ImVec4(0.24f, 0.38f, 0.58f, 0.85f));
    ImVec4 lbl    = with_alpha_mul(style ? style->label  : ImVec4(0.55f, 0.75f, 1.00f, 0.90f));
    md_render_tinted_block(body, body_len, block_idx, label,
        with_alpha_mul(ImVec4(0.02f, 0.04f, 0.08f, 0.98f)),   /* bg: near-black (universal) */
        border, lbl, "code", font_mul);
}

/* latex_to_unicode is defined in the included latex_convert.h below.
 * md_render_math_display uses it — but the include site is FURTHER
 * down (right after md_render_list_item to keep the ordering readable).
 * Forward-declare it here so md_render_math_display can call it. The
 * `static` matches the header's linkage. */
#include "latex_convert.h"

/* Render a display-math block (\[..\] / $$..$$) — same pattern as
 * code block but with violet accent so the eye knows "math not code".
 * Body is converted from LaTeX to Unicode for readability. */
static void md_render_math_display(const char *body, size_t body_len,
                                   int block_idx, float font_mul) {
    char uni_buf[8192];
    size_t ulen = latex_to_unicode(body, body_len, uni_buf, sizeof(uni_buf) - 1);
    uni_buf[ulen] = 0;
    /* v1.3 (2026-07-07): bg + border + label alphas all scale with
     * g_frame_alpha_mul so math blocks respect user transparency
     * uniformly with the rest of the overlay. */
    md_render_tinted_block(uni_buf, ulen, block_idx, "math",
        with_alpha_mul(ImVec4(0.08f, 0.05f, 0.14f, 0.98f)),   /* bg: dark violet */
        with_alpha_mul(ImVec4(0.50f, 0.35f, 0.72f, 0.85f)),   /* border: violet */
        with_alpha_mul(ImVec4(0.85f, 0.72f, 1.00f, 0.90f)),   /* label: light violet */
        "math", font_mul);
}

/* Render a heading (# / ## / ###) line — larger font + accent color.
 * `line` is one full logical line (no trailing newline). `level` is
 * the number of `#` chars (1..3). */
static void md_render_heading(const char *line, size_t line_len, int level) {
    /* Skip the # chars + space. */
    size_t start = 0;
    while (start < line_len && line[start] == '#') start++;
    while (start < line_len && line[start] == ' ') start++;
    const char *body = line + start;
    size_t blen = line_len - start;
    if (blen == 0) return;

    /* Level → size + color mapping. */
    float scale = (level == 1) ? 1.5f : (level == 2) ? 1.3f : 1.15f;
    ImVec4 col = (level == 1) ? ImVec4(0.85f, 0.90f, 1.00f, 1.0f)
               : (level == 2) ? ImVec4(0.70f, 0.85f, 1.00f, 1.0f)
                              : ImVec4(0.62f, 0.78f, 0.95f, 1.0f);

    ImGuiIO &io = ImGui::GetIO();
    float old_scale = io.FontGlobalScale;
    io.FontGlobalScale = old_scale * scale;
    ImGui::PushStyleColor(ImGuiCol_Text, col);
    ImGui::TextUnformatted(body, body + blen);
    ImGui::PopStyleColor();
    io.FontGlobalScale = old_scale;
    ImGui::Spacing();
}

/* Render a bullet-list item. `line` is body without the `- ` / `* ` /
 * `• ` marker. */
static void md_render_list_item(const char *line, size_t line_len,
                                int is_numbered, int number) {
    /* Bullet or number, then indented body. */
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.75f, 0.95f, 1.0f));
    if (is_numbered) {
        ImGui::Text("%d.", number);
    } else {
        ImGui::Text("\xE2\x80\xA2");   /* • U+2022 BULLET */
    }
    ImGui::PopStyleColor();
    ImGui::SameLine(0, 8.0f);
    ImGui::TextUnformatted(line, line + line_len);
}

/* LaTeX-to-Unicode simplifier: already included above (right before
 * md_render_math_display) so its definitions are visible where used.
 * Kept a comment here as a visual reminder of where the block used
 * to live pre-refactor. */


/* Render a plain-text run. Splits on newlines and detects per-line
 * markdown structure: headings, list items. Non-structured lines
 * render as TextWrapped. */
static void md_render_plain(const char *body, size_t body_len) {
    if (body_len == 0) return;
    /* Skip if all whitespace but keep a spacing hint for blank lines. */
    int all_ws = 1;
    for (size_t i = 0; i < body_len; i++) {
        if (body[i] != ' ' && body[i] != '\t' && body[i] != '\n' &&
            body[i] != '\r') { all_ws = 0; break; }
    }
    if (all_ws) {
        int newlines = 0;
        for (size_t i = 0; i < body_len; i++)
            if (body[i] == '\n') newlines++;
        if (newlines > 0) ImGui::Spacing();
        return;
    }

    /* Walk line by line. For each line, detect structure at line
     * start; else render as wrapped text with adjacent lines merged
     * into a paragraph. */
    const char *p = body;
    const char *end = body + body_len;
    /* Paragraph buffer — accumulates consecutive non-structural lines. */
    char para[8192];
    size_t para_len = 0;

    /* Convert any LaTeX ($..$ / \(..\) / \frac / \pi / etc.) to
     * Unicode at render time. Keeps chat_msg.text as the original
     * LaTeX (so copy hotkeys give raw LaTeX for pasting to Overleaf)
     * while display shows readable Unicode. */
    char para_uni[10240];
    auto flush_para = [&]() {
        if (para_len == 0) return;
        size_t ulen = latex_to_unicode(para, para_len, para_uni, sizeof(para_uni) - 1);
        para_uni[ulen] = 0;
        ImGui::TextUnformatted(para_uni, para_uni + ulen);
        para_len = 0;
    };

    while (p < end) {
        const char *nl = (const char *)memchr(p, '\n', end - p);
        size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);
        /* Strip trailing \r. */
        size_t effective_len = line_len;
        while (effective_len > 0 && p[effective_len - 1] == '\r') effective_len--;

        /* Skip leading spaces to detect structural markers. */
        size_t indent = 0;
        while (indent < effective_len && (p[indent] == ' ' || p[indent] == '\t')) indent++;
        const char *ls = p + indent;
        size_t ls_len = effective_len - indent;

        int handled = 0;

        /* Blank line → paragraph break. */
        if (ls_len == 0) {
            flush_para();
            ImGui::Spacing();
            handled = 1;
        }

        /* Headings: ### / ## / # . */
        if (!handled && ls_len >= 2 && ls[0] == '#') {
            int level = 0;
            while (level < 6 && (size_t)level < ls_len && ls[level] == '#') level++;
            if (level >= 1 && level <= 6 && (size_t)level < ls_len && ls[level] == ' ') {
                flush_para();
                md_render_heading(ls, ls_len, level);
                handled = 1;
            }
        }

        /* Bullet lists: - item, * item, • item */
        if (!handled && ls_len >= 2 &&
            (ls[0] == '-' || ls[0] == '*') && ls[1] == ' ') {
            flush_para();
            md_render_list_item(ls + 2, ls_len - 2, 0, 0);
            handled = 1;
        }
        if (!handled && ls_len >= 4 &&
            (unsigned char)ls[0] == 0xE2 && (unsigned char)ls[1] == 0x80 &&
            (unsigned char)ls[2] == 0xA2 && ls[3] == ' ') {
            flush_para();
            md_render_list_item(ls + 4, ls_len - 4, 0, 0);
            handled = 1;
        }

        /* Numbered lists: `1. `, `12. `, etc. up to 4 digits. */
        if (!handled && ls_len >= 3 && ls[0] >= '0' && ls[0] <= '9') {
            int digit_end = 1;
            while (digit_end < 4 && (size_t)digit_end < ls_len &&
                   ls[digit_end] >= '0' && ls[digit_end] <= '9') digit_end++;
            if ((size_t)(digit_end + 1) < ls_len &&
                ls[digit_end] == '.' && ls[digit_end + 1] == ' ') {
                int number = 0;
                for (int k = 0; k < digit_end; k++) number = number * 10 + (ls[k] - '0');
                flush_para();
                md_render_list_item(ls + digit_end + 2, ls_len - digit_end - 2,
                                    1, number);
                handled = 1;
            }
        }

        if (!handled) {
            /* Accumulate into paragraph buffer with a space separator
             * (markdown wrapping: consecutive non-blank lines are one
             * paragraph). Strip inline markers (**, *, `) for cleaner
             * display — bold/italic/inline-code markers passthrough
             * makes prose look junky in an ImGui rendered view. */
            if (effective_len > 0) {
                if (para_len > 0 && para_len + 1 < sizeof(para)) {
                    para[para_len++] = ' ';
                }
                /* Walk source, skipping ** and * and ` markers. */
                for (size_t k = 0; k < effective_len; k++) {
                    unsigned char c = (unsigned char)p[k];
                    if (c == '*') {
                        /* Skip ** or single *. */
                        if (k + 1 < effective_len && p[k + 1] == '*') k++;
                        continue;
                    }
                    if (c == '`') {
                        /* Skip inline-code backtick. */
                        continue;
                    }
                    if (para_len + 1 >= sizeof(para) - 1) break;
                    para[para_len++] = (char)c;
                }
                para[para_len] = 0;
            }
        }

        if (!nl) break;
        p = nl + 1;
    }
    flush_para();
}

/* Top-level markdown renderer. See file-level comment for the
 * supported subset. */
static void md_render(const char *text, float font_mul) {
    if (!text || !text[0]) return;
    const char *p = text;
    const char *end = text + strlen(text);
    int block_idx = 0;
    while (p < end) {
        /* Fenced code — MUST be at line start (after \n or at text
         * head). Prevents accidental matches in prose that mentions
         * triple-backtick. */
        int at_line_start = (p == text) || (p > text && p[-1] == '\n');
        if (at_line_start && p + 3 <= end &&
            p[0] == '`' && p[1] == '`' && p[2] == '`') {
            /* Extract optional language from the line after ``` */
            const char *lang_start = p + 3;
            const char *lang_nl = (const char *)memchr(lang_start, '\n',
                                                        end - lang_start);
            if (!lang_nl) {
                /* No newline after fence — treat whole rest as code */
                md_render_code_block("", lang_start, end - lang_start,
                                     block_idx++, 0.0f, font_mul);
                return;
            }
            /* Language token — trim whitespace. */
            char lang[24] = {0};
            size_t lang_raw_len = lang_nl - lang_start;
            /* Strip leading + trailing whitespace. */
            const char *ls = lang_start;
            while (ls < lang_nl && (*ls == ' ' || *ls == '\t')) ls++;
            const char *le = lang_nl;
            while (le > ls && (le[-1] == ' ' || le[-1] == '\t' ||
                               le[-1] == '\r')) le--;
            size_t use = (size_t)(le - ls);
            if (use > 23) use = 23;
            if (use > 0) memcpy(lang, ls, use);
            lang[use] = 0;
            /* Reject languages > 20 chars — false-positive fence in
             * prose (very rare but defensive). Fall through to plain. */
            if (lang_raw_len > 20) {
                /* Not a real fence — advance one char + continue. */
                md_render_plain(p, 1);
                p++;
                continue;
            }
            /* Body starts after the \n after language. */
            const char *body = lang_nl + 1;
            /* Find closing ``` on its own line ("\n```"). */
            const char *close = NULL;
            const char *scan = body;
            while (scan < end) {
                const char *nl = (const char *)memchr(scan, '\n', end - scan);
                if (!nl) break;
                if (nl + 4 <= end &&
                    nl[1] == '`' && nl[2] == '`' && nl[3] == '`') {
                    close = nl + 1;   /* points at the first ` */
                    break;
                }
                scan = nl + 1;
            }
            const char *body_end = close ? close - 1 : end;   /* -1 = don't include trailing \n */
            if (body_end < body) body_end = body;
            md_render_code_block(lang, body, body_end - body,
                                 block_idx++, 0.0f, font_mul);
            if (close) {
                p = close + 3;   /* past the closing ``` */
                if (p < end && *p == '\n') p++;
            } else {
                p = end;
            }
            continue;
        }
        /* Display math \[ ... \] */
        if (p + 2 <= end && p[0] == '\\' && p[1] == '[') {
            const char *body = p + 2;
            /* Find matching \] */
            const char *close = NULL;
            for (const char *s = body; s + 2 <= end; s++) {
                if (s[0] == '\\' && s[1] == ']') { close = s; break; }
            }
            if (close) {
                md_render_math_display(body, close - body, block_idx++,
                                       font_mul);
                p = close + 2;
                continue;
            }
            /* No closer — fall through to plain */
        }
        /* Display math $$...$$ (common MathJax dialect) */
        if (p + 2 <= end && p[0] == '$' && p[1] == '$') {
            const char *body = p + 2;
            /* Find matching $$ */
            const char *close = NULL;
            for (const char *s = body; s + 2 <= end; s++) {
                if (s[0] == '$' && s[1] == '$') { close = s; break; }
            }
            if (close) {
                md_render_math_display(body, close - body, block_idx++,
                                       font_mul);
                p = close + 2;
                continue;
            }
            /* No closer — fall through to plain */
        }
        /* Consume plain text until next special marker. */
        const char *pt_end = p + 1;   /* at least 1 char forward */
        while (pt_end < end) {
            int at_ls = (pt_end > text && pt_end[-1] == '\n');
            if (at_ls && pt_end + 3 <= end &&
                pt_end[0] == '`' && pt_end[1] == '`' && pt_end[2] == '`') {
                break;
            }
            if (pt_end + 2 <= end &&
                pt_end[0] == '\\' && pt_end[1] == '[') {
                break;
            }
            if (pt_end + 2 <= end &&
                pt_end[0] == '$' && pt_end[1] == '$') {
                break;
            }
            pt_end++;
        }
        md_render_plain(p, pt_end - p);
        p = pt_end;
    }
}

/* ---------- Draw the chat overlay ---------- *
 * Polished dark chat panel. Position anchored to one of 4 corners (cycled
 * via Ctrl+Shift+P). User can nudge with Ctrl+arrow, resize with
 * Ctrl+Shift+arrow. Full 12+ hotkey coverage — see g_hk table in
 * launcher/src/main.c. */
/* Render a single chat message.
 *
 * Architecture: NO nested BeginChild — the bubble is drawn as a
 * tinted background via ImDrawList (like md_render_tinted_block) so
 * ALL scrolling flows through the parent "chat" pane.
 *
 * Distinct visual:
 *   USER: right-aligned, ~70% width, bright blue bg + "You" label
 *   AI:   left-aligned, FULL-WIDTH (per user request), dark bg + "AI" label
 *
 * Prose wraps at bubble body width. Code / math blocks respect that
 * width for the label + copy button but the code content itself does
 * NOT wrap (parent x-scroll handles overflow). */
static void draw_chat_bubble(int msg_idx, int role, const char *text,
                             int pending, float region_w, float font_mul) {
    (void)msg_idx;
    /* Bubble sizing:
     *   USER  = right-aligned ~70% (chat-app style)
     *   AI    = FULL width (per user's "cover the full screen width")
     *           minus a 4-px right gutter so we don't touch the scrollbar */
    float bubble_max_w = role == UI_MSG_USER
        ? region_w * 0.70f
        : region_w - 4.0f;
    if (bubble_max_w < 240.0f) bubble_max_w = 240.0f;

    /* Palette. v1.3 (2026-07-07): bg + border alpha scale with the
     * user's opacity setting (g_frame_alpha_mul) so the whole overlay
     * respects transparency uniformly instead of only the outer edges.
     * Label alpha also scales (labels are part of the "container"
     * visual, not the body content). Body text stays at full opacity
     * for readability — text alpha scaling at low overall opacity
     * makes prose unreadable in a way that's worse than the visual
     * inconsistency of opaque text over a semi-transparent bubble. */
    ImVec4 bg    = with_alpha_mul(role == UI_MSG_USER
        ? ImVec4(0.22f, 0.42f, 0.75f, 0.95f)
        : ImVec4(0.06f, 0.09f, 0.14f, 0.95f));
    ImVec4 border = with_alpha_mul(role == UI_MSG_USER
        ? ImVec4(0.45f, 0.68f, 1.00f, 0.95f)
        : ImVec4(0.24f, 0.38f, 0.58f, 0.85f));
    ImVec4 label_col = with_alpha_mul(role == UI_MSG_USER
        ? ImVec4(0.80f, 0.90f, 1.00f, 0.95f)
        : ImVec4(0.55f, 0.75f, 1.00f, 0.90f));
    ImVec4 text_col = ImVec4(0.96f, 0.97f, 1.0f, 1.0f);   /* full opacity */

    /* Right-align USER bubbles. */
    if (role == UI_MSG_USER) {
        float indent = region_w - bubble_max_w - 4.0f;
        if (indent < 0) indent = 0;
        ImGui::Dummy(ImVec2(indent, 0));
        ImGui::SameLine();
    }

    /* ── Bubble draw phase 1: capture starting cursor + reserve area ── *
     *
     * We can't compute the exact height ahead of time (md_render's
     * output is dynamic — bold-strip, list rendering, fenced-code
     * insertion all vary). Instead we use a two-pass approach:
     *  1. Save cursor pos.
     *  2. Render everything (label + md_render'd body).
     *  3. Compute rect from saved pos to current pos.
     *  4. Backfill the rounded background via a channel-splitter so
     *     the bg appears BEHIND the already-emitted text.
     *
     * ImGui's ImDrawListSplitter is the correct tool for this — it
     * lets us switch to channel 0 (bg) after rendering to channel 1
     * (fg), then merge. */
    ImDrawList *dl = ImGui::GetWindowDrawList();
    static ImDrawListSplitter s_split;   /* reused across bubbles */
    s_split.Split(dl, 2);
    s_split.SetCurrentChannel(dl, 1);    /* draw text on channel 1 (fg) */

    ImVec2 start = ImGui::GetCursorScreenPos();
    /* Padding: 20px horizontal so text has breathing room from the
     * bubble edges (was 14px — user reported "hugging the [edge]"). */
    float pad_h = 20.0f, pad_v = 12.0f;

    /* Constrain body to bubble width. Push cursor inward for padding
     * and push text-wrap so prose wraps within bubble width. */
    ImGui::SetCursorScreenPos(ImVec2(start.x + pad_h, start.y + pad_v));

    /* Label row. */
    ImGui::PushStyleColor(ImGuiCol_Text, label_col);
    if (role == UI_MSG_USER) {
        /* Right-align "You" label inside bubble. */
        float body_w = bubble_max_w - pad_h * 2.0f;
        const char *lbl = "You";
        ImVec2 tsz = ImGui::CalcTextSize(lbl);
        float x = start.x + pad_h + body_w - tsz.x;
        ImGui::SetCursorScreenPos(ImVec2(x, start.y + pad_v));
        ImGui::TextUnformatted(lbl);
    } else {
        ImGui::TextUnformatted(pending ? "AI (streaming)" : "AI");
    }
    ImGui::PopStyleColor();

    /* Separator drawn manually. */
    float sep_y = ImGui::GetCursorScreenPos().y + 2.0f;
    dl->AddLine(ImVec2(start.x + pad_h,                          sep_y),
                ImVec2(start.x + bubble_max_w - pad_h,           sep_y),
                ImGui::ColorConvertFloat4ToU32(border), 1.0f);
    ImGui::SetCursorScreenPos(ImVec2(start.x + pad_h, sep_y + 6.0f));

    /* Body — text wraps at bubble body width.
     *
     * CRITICAL: PushTextWrapPos takes a WINDOW-LOCAL x coord (per
     * ImGui docs), NOT a screen coord. Passing `start.x + ...` was
     * a bug — screen coordinates on multi-monitor setups can be
     * thousands of pixels off, which effectively disabled wrapping
     * and caused long AI streams (single-line paragraphs) to overflow
     * the bubble bounds.
     *
     * The correct value: current cursor local X + body inner width.
     * ImGui will wrap any TextUnformatted/TextWrapped call that
     * crosses that boundary. */
    ImGui::PushStyleColor(ImGuiCol_Text, text_col);
    float body_inner_w = bubble_max_w - pad_h * 2.0f;
    float wrap_local_x = ImGui::GetCursorPosX() + body_inner_w;
    ImGui::PushTextWrapPos(wrap_local_x);
    if (pending && (!text || !text[0])) {
        unsigned tick = GetTickCount();
        int phase = (tick / 400) % 3;
        const char *dots[3] = { "• Thinking",
                                "• • Thinking",
                                "• • • Thinking" };
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.60f, 0.82f, 1.0f, 0.90f));
        if (g_font_mono) ImGui::PushFont(g_font_mono);
        ImGui::TextUnformatted(dots[phase]);
        if (g_font_mono) ImGui::PopFont();
        ImGui::PopStyleColor();
    } else if (text && text[0]) {
        if (role == UI_MSG_USER) {
            ImGui::TextUnformatted(text);
        } else {
            md_render(text, font_mul);
            if (pending) {
                unsigned tick = GetTickCount();
                if ((tick / 400) % 2 == 0) {
                    ImGui::PushStyleColor(ImGuiCol_Text,
                        ImVec4(0.55f, 0.85f, 1.0f, 0.85f));
                    ImGui::TextUnformatted("\xE2\x96\x8A");
                    ImGui::PopStyleColor();
                }
            }
        }
    }
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();

    /* ── AI bubble footer: copy-full + copy-answer buttons ─────────
     *
     * Only shown on FINALIZED (non-pending) AI messages with actual
     * content. Buttons are labeled with their mapped hotkeys pulled
     * from the registry so they stay in sync if user rebinds. */
    if (role == UI_MSG_AI && !pending && text && text[0]) {
        /* Small separator line under content. */
        float sep_y2 = ImGui::GetCursorScreenPos().y + 4.0f;
        dl->AddLine(ImVec2(start.x + pad_h,               sep_y2),
                    ImVec2(start.x + bubble_max_w - pad_h, sep_y2),
                    ImGui::ColorConvertFloat4ToU32(border), 1.0f);
        ImGui::SetCursorScreenPos(ImVec2(start.x + pad_h, sep_y2 + 6.0f));

        /* Snapshot text for the copy handlers (button click fires
         * out-of-band; we need a stable copy). Snapshot only if the
         * button is pressed — cheaper than snapshotting every frame.
         *
         * v1.3 (2026-07-07): button bg alphas scale with the frame
         * multiplier so they blend uniformly with the bubble bg.
         * Button TEXT stays at full opacity so labels remain
         * readable at low transparency. */
        ImGui::PushStyleColor(ImGuiCol_Button,        with_alpha_mul(ImVec4(0.14f, 0.22f, 0.36f, 0.85f)));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, with_alpha_mul(ImVec4(0.22f, 0.34f, 0.52f, 0.95f)));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  with_alpha_mul(ImVec4(0.28f, 0.42f, 0.68f, 1.00f)));
        ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(0.92f, 0.96f, 1.00f, 1.00f));

        char hk_full[32] = {0}, hk_ans[32] = {0};
        ui_format_hotkey(3 /* SVC_HK_COPY_REPLY  */, hk_full, sizeof(hk_full));
        ui_format_hotkey(29 /* SVC_HK_COPY_ANSWER */, hk_ans,  sizeof(hk_ans));
        char label_full[64], label_ans[64];
        if (hk_full[0]) _snprintf(label_full, sizeof(label_full) - 1, "Copy full [%s]##full_%d", hk_full, msg_idx);
        else            _snprintf(label_full, sizeof(label_full) - 1, "Copy full##full_%d", msg_idx);
        if (hk_ans[0])  _snprintf(label_ans,  sizeof(label_ans)  - 1, "Copy answer [%s]##ans_%d", hk_ans, msg_idx);
        else            _snprintf(label_ans,  sizeof(label_ans)  - 1, "Copy answer##ans_%d", msg_idx);
        label_full[sizeof(label_full) - 1] = 0;
        label_ans [sizeof(label_ans)  - 1] = 0;

        if (ImGui::SmallButton(label_full)) {
            md_copy_to_clipboard(text, strlen(text));
        }
        ImGui::SameLine();
        if (ImGui::SmallButton(label_ans)) {
            /* Emit first-line only (matches ui_copy_last_ai_answer). */
            const char *first_nl = strchr(text, '\n');
            size_t first_len = first_nl ? (size_t)(first_nl - text) : strlen(text);
            /* Strip leading whitespace + trailing \r. */
            const char *p = text;
            while (first_len > 0 && (*p == ' ' || *p == '\t')) { p++; first_len--; }
            while (first_len > 0 && (p[first_len - 1] == ' ' ||
                                      p[first_len - 1] == '\t' ||
                                      p[first_len - 1] == '\r')) first_len--;
            if (first_len > 0) md_copy_to_clipboard(p, first_len);
        }
        ImGui::PopStyleColor(4);
        ImGui::Spacing();
    }

    /* Capture end cursor and compute rect. */
    ImVec2 end = ImGui::GetCursorScreenPos();
    float rect_h = (end.y + pad_v) - start.y;
    if (rect_h < 40.0f) rect_h = 40.0f;
    ImVec2 rect_max = ImVec2(start.x + bubble_max_w, start.y + rect_h);

    /* ── Bubble draw phase 2: backfill background on channel 0 ── */
    s_split.SetCurrentChannel(dl, 0);
    dl->AddRectFilled(start, rect_max,
        ImGui::ColorConvertFloat4ToU32(bg), 12.0f);
    dl->AddRect(start, rect_max,
        ImGui::ColorConvertFloat4ToU32(border), 12.0f, 0, 1.5f);
    s_split.Merge(dl);

    /* Ensure ImGui knows the item consumed this space so subsequent
     * calls advance below the bubble. Reserve a Dummy at the bottom
     * with the full rect width. */
    ImGui::SetCursorScreenPos(ImVec2(start.x, rect_max.y + 8.0f));
    ImGui::Dummy(ImVec2(bubble_max_w, 0));
}

static void draw_chat_window(UINT screen_w, UINT screen_h) {
    /* If a capture is pending, skip drawing so the layer texture stays
     * app-only. The capture path in ui_present_frame ALSO defers the
     * capture until g_hide_frames_for_capture reaches 0 — by then
     * multiple frames have composed without our overlay and prior
     * overlay pixels have been overwritten by the underlying app. */
    if (g_hide_frames_for_capture > 0) return;
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    bool visible = g_visible;
    int   corner   = g_corner;
    int   off_x    = g_offset_x;
    int   off_y    = g_offset_y;
    int   extra_w  = g_extra_w;
    int   extra_h  = g_extra_h;
    float alpha    = g_alpha;
    float font_mul = g_font;
    LeaveCriticalSection(&g_ui_cs);

    if (!visible) return;

    /* v1.3 (2026-07-07): publish alpha to the file-scope multiplier
     * BEFORE any nested renderer runs. draw_chat_bubble +
     * md_render_tinted_block read this via with_alpha_mul() so their
     * hardcoded bg/border alphas scale uniformly with user opacity.
     * See the g_frame_alpha_mul definition near the top of this
     * file for the full contract + rationale. */
    g_frame_alpha_mul = alpha;

    /* Snapshot chat messages under lock to avoid renderer-vs-append tear. */
    ensure_chat_msgs_cs();
    struct msg_snap_t {
        int   role;
        int   pending;
        char *text;   /* strdup'd; must free after render */
    };
    msg_snap_t msgs[CHAT_MAX_MSGS];
    int msg_n = 0;
    EnterCriticalSection(&g_chat_msgs_cs);
    for (int i = 0; i < g_chat_msg_count && msg_n < CHAT_MAX_MSGS; i++) {
        struct chat_msg_t *m = chat_msg_at(i);
        if (!m || m->id < 0) continue;
        msgs[msg_n].role    = m->role;
        msgs[msg_n].pending = m->pending;
        msgs[msg_n].text    = m->text ? _strdup(m->text) : NULL;
        msg_n++;
    }
    LeaveCriticalSection(&g_chat_msgs_cs);

    /* Status snapshot. */
    ensure_status_cs();
    char stat_provider[32], stat_tier[32], stat_model[64];
    int stat_streaming = 0;
    EnterCriticalSection(&g_status_cs);
    strncpy(stat_provider, g_status_provider, sizeof(stat_provider));
    strncpy(stat_tier,     g_status_tier,     sizeof(stat_tier));
    strncpy(stat_model,    g_status_model,    sizeof(stat_model));
    stat_streaming = g_status_streaming;
    LeaveCriticalSection(&g_status_cs);
    stat_provider[sizeof(stat_provider) - 1] = 0;
    stat_tier[sizeof(stat_tier) - 1] = 0;
    stat_model[sizeof(stat_model) - 1] = 0;
    /* have_msgs = messages exist AND we're not on home-forced view.
     * If user hit Ctrl+Alt+X (back), messages stay in memory but the
     * chat view is hidden and cheat-sheet home is shown instead. */
    int have_msgs = (msg_n > 0) && (g_home_view_forced == 0);
    size_t sl = have_msgs ? 1 : 0;

    /* DPI-derived base scale. Baseline 1080p → scale=1.0; 4K → scale ~2.0. */
    float scale = (float)screen_h / 1080.0f;
    if (scale < 0.6f) scale = 0.6f;
    if (scale > 3.0f) scale = 3.0f;

    /* v8: honor cfg->overlay_w/h as the LAUNCH base (was hardcoded 600x460).
     * Falls back to legacy 600/460 when config field is zero (stale configs
     * or in-payload-first-launch before Electron writes v8). Then adds the
     * user's LIVE resize deltas (g_extra_w/h from Ctrl+Shift+Alt+Arrows +
     * persisted in overlay_state.bin). */
    float cfg_bw = (g_base_w_cfg > 0) ? (float)g_base_w_cfg : 600.0f;
    float cfg_bh = (g_base_h_cfg > 0) ? (float)g_base_h_cfg : 460.0f;
    float base_w = cfg_bw * scale + (float)extra_w;
    float base_h = cfg_bh * scale + (float)extra_h;

    /* v8: min-size floor + max-size ceiling depend on size_mode.
     *   Normal : 240 x 180 min, screen - 40 max     (unchanged from v7)
     *   Ultra  :  80 x  60 min, screen - 8  max     (tiny pip <-> ~fullscreen)
     * These are RENDERED pixel bounds (post-scale) so they're consistent
     * across resolutions. */
    int ultra = InterlockedCompareExchange(&g_size_mode, 0, 0);
    float min_w = ultra ?  80.0f : 240.0f;
    float min_h = ultra ?  60.0f : 180.0f;
    float pad   = ultra ?   8.0f :  40.0f;
    if (base_w < min_w) base_w = min_w;
    if (base_h < min_h) base_h = min_h;
    if (base_w > (float)screen_w - pad) base_w = (float)screen_w - pad;
    if (base_h > (float)screen_h - pad) base_h = (float)screen_h - pad;

    float margin = 32.0f * scale;
    float pos_x = 0.0f, pos_y = 0.0f;
    switch (corner) {
        case 0:  /* top-right */
            pos_x = (float)screen_w - base_w - margin + off_x;
            pos_y = margin + off_y;
            break;
        case 1:  /* top-left */
            pos_x = margin + off_x;
            pos_y = margin + off_y;
            break;
        case 2:  /* bottom-right */
            pos_x = (float)screen_w - base_w - margin + off_x;
            pos_y = (float)screen_h - base_h - margin + off_y;
            break;
        case 3:  /* bottom-left */
            pos_x = margin + off_x;
            pos_y = (float)screen_h - base_h - margin + off_y;
            break;
    }
    /* Keep at least partly on-screen. */
    if (pos_x < -base_w + 60.0f) pos_x = -base_w + 60.0f;
    if (pos_y < -base_h + 30.0f) pos_y = -base_h + 30.0f;
    if (pos_x > (float)screen_w - 60.0f) pos_x = (float)screen_w - 60.0f;
    if (pos_y > (float)screen_h - 30.0f) pos_y = (float)screen_h - 30.0f;

    /* v6: cache the drawn rect for the LL mouse hook so mouse-wheel
     * scrolling can hit-test the cursor against the overlay. */
    InterlockedExchange(&g_last_overlay_x, (LONG)pos_x);
    InterlockedExchange(&g_last_overlay_y, (LONG)pos_y);
    InterlockedExchange(&g_last_overlay_w, (LONG)base_w);
    InterlockedExchange(&g_last_overlay_h, (LONG)base_h);

    ImGui::SetNextWindowPos(ImVec2(pos_x, pos_y), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(base_w, base_h), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(alpha);

    /* Font: baseline scale + user multiplier. */
    ImGui::GetIO().FontGlobalScale = scale * font_mul;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  14.0f * scale);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.5f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(20.0f * scale, 16.0f * scale));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,     ImVec2(10.0f * scale, 8.0f * scale));

    /* v1.3 (2026-07-07): all chrome elements (title/border/separator/
     * scrollbar) scale with the user's opacity setting via
     * with_alpha_mul so the whole overlay looks uniformly transparent
     * instead of "transparent frame with opaque titlebar + scrollbar".
     * TEXT alone stays at full opacity to preserve readability. */
    ImGui::PushStyleColor(ImGuiCol_WindowBg,      ImVec4(0.04f, 0.05f, 0.09f, alpha));
    ImGui::PushStyleColor(ImGuiCol_TitleBg,       with_alpha_mul(ImVec4(0.07f, 0.09f, 0.14f, 0.98f)));
    ImGui::PushStyleColor(ImGuiCol_TitleBgActive, with_alpha_mul(ImVec4(0.10f, 0.14f, 0.22f, 0.98f)));
    ImGui::PushStyleColor(ImGuiCol_Border,        with_alpha_mul(ImVec4(0.28f, 0.42f, 0.68f, 0.85f)));
    ImGui::PushStyleColor(ImGuiCol_Text,          ImVec4(0.94f, 0.96f, 0.99f, 1.0f));  /* full opacity */
    ImGui::PushStyleColor(ImGuiCol_Separator,     with_alpha_mul(ImVec4(0.20f, 0.28f, 0.42f, 0.80f)));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarBg,   with_alpha_mul(ImVec4(0.06f, 0.08f, 0.12f, 0.60f)));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrab, with_alpha_mul(ImVec4(0.28f, 0.42f, 0.68f, 0.85f)));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrabHovered, with_alpha_mul(ImVec4(0.38f, 0.52f, 0.80f, 0.90f)));

    if (ImGui::Begin("AI overlay", nullptr,
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {

        /* Reserve space at the bottom for the persistent footer (2 lines +
         * spacing). Content area = total - footer_height. */
        float footer_height = ImGui::GetFrameHeightWithSpacing() * 1.5f;

        /* ── Status bar (top strip) ───────────────────────────────── */
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.72f, 0.95f, 0.90f));
            if (stat_provider[0]) {
                if (stat_streaming)
                    ImGui::Text("%s | %s | %s | STREAM", stat_provider, stat_tier, stat_model);
                else
                    ImGui::Text("%s | %s | %s",         stat_provider, stat_tier, stat_model);
            } else {
                ImGui::Text("svcldb ready");
            }
            ImGui::PopStyleColor();
            ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.20f, 0.32f, 0.50f, 0.55f));
            ImGui::Separator();
            ImGui::PopStyleColor();
        }

        if (!have_msgs) {
            /* ── Empty state: full hotkey cheat sheet ─────────────────── *
             *
             * Two sub-cases:
             *   (a) Truly empty history (msg_n == 0) → show cheat sheet.
             *   (b) home-forced with messages preserved → show cheat
             *       sheet + "return to chat" hint.
             *
             * Case (b) means user hit Ctrl+Alt+X to hide messages. They
             * can return via any message-appending hotkey (ASK, TYPING,
             * REGENERATE) or by hitting Ctrl+Alt+X again which now
             * signals quit (since have_msgs is 0). */
            int home_forced_with_msgs = (msg_n > 0) && (g_home_view_forced != 0);

            ImGui::BeginChild("body", ImVec2(0, -footer_height), false, 0);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.72f, 0.86f, 1.0f, 1.0f));
            if (home_forced_with_msgs) {
                ImGui::TextWrapped("Chat hidden. %d message%s preserved. "
                                   "Ask/type/regenerate to bring it back.",
                                   msg_n, msg_n == 1 ? "" : "s");
            } else {
                ImGui::TextWrapped("Overlay ready. Rendering at %ux%u.",
                                   screen_w, screen_h);
            }
            ImGui::PopStyleColor();
            ImGui::Spacing();
            /* NOTE 2026-07-06: switched from `──` (U+2500 box-drawing) to
             * ASCII hyphens. The default ImGui font atlas covers only ASCII
             * + Latin-1, so U+2500 rendered as `?` fallbacks — the
             * "?? Ask AI ??" bug reported by the user. Plain ASCII fixes it
             * without touching the font atlas (which would inflate the
             * DLL by ~1MB for one glyph). */
            ImGui::TextDisabled("--- Ask AI ---");
            ImGui::TextDisabled("  Ctrl+Shift+Space    Screenshot + ask AI");
            ImGui::TextDisabled("  Ctrl+Alt+T          Type a question (chat mode)");
            ImGui::TextDisabled("  Ctrl+Alt+Enter      Regenerate last answer");
            ImGui::TextDisabled("  Ctrl+Alt+S          STOP the in-flight AI response");
            ImGui::TextDisabled("  Ctrl+Alt+J / K      Scroll chat down / up");
            ImGui::TextDisabled("  Ctrl+Alt+N          New chat (clear all msgs - DESTRUCTIVE)");
            ImGui::TextDisabled("  Ctrl+Alt+X          Back to home (preserves msgs) / Quit on home");
            ImGui::Spacing();
            ImGui::TextDisabled("--- Copy ---");
            ImGui::TextDisabled("  Ctrl+Alt+C          Copy full last reply");
            ImGui::TextDisabled("  Ctrl+Alt+A          Copy just the direct answer (first line)");
            ImGui::TextDisabled("  Ctrl+Shift+Alt+C    Copy just code blocks (all concatenated)");
            ImGui::TextDisabled("  (Buttons under each AI reply also do this)");
            ImGui::Spacing();
            ImGui::TextDisabled("--- Config (live rotation) ---");
            ImGui::TextDisabled("  Ctrl+Alt+M          Cycle STRONG -> MEDIUM -> CHEAP");
            ImGui::TextDisabled("  Ctrl+Shift+Alt+P    Cycle OpenAI / Anthropic / Google / OpenRouter");
            ImGui::TextDisabled("  Ctrl+Shift+Alt+T    Toggle streaming (SSE)");
            ImGui::TextDisabled("  Ctrl+Shift+Alt+L    Toggle LaTeX (on = LaTeX, off = Unicode/keyboard)");
            ImGui::Spacing();
            ImGui::TextDisabled("--- Layout (hold for continuous) ---");
            ImGui::TextDisabled("  Ctrl+Alt+G          Toggle overlay");
            ImGui::TextDisabled("  Ctrl+Alt+Arrows     Nudge position");
            ImGui::TextDisabled("  Ctrl+Shift+Alt+Arrs Resize");
            ImGui::TextDisabled("  Ctrl+Alt+Q          Cycle corner (quadrant)");
            ImGui::TextDisabled("  Ctrl+Alt+ [ / ]     Font size (smaller / bigger)");
            ImGui::TextDisabled("  Ctrl+Alt+ = / -     Opacity (more / less)");
            ImGui::TextDisabled("  Ctrl+Alt+R          Reset");
            ImGui::TextDisabled("  Ctrl+Shift+Alt+K    Emergency stop (kill DWM)");
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::TextDisabled("Frames %llu   Corner %d   Alpha %.2f   Font %.2f",
                                (unsigned long long)g_frame_count, corner, alpha, font_mul);
            ImGui::EndChild();
        } else {
            /* ── Chat state: bubble list ──────────────────────────────── *
             * Parent-level scroll: BOTH y (vertical scroll through
             * message history) AND x (horizontal for long code lines /
             * long math expressions). No per-bubble child scrollbars. */
            ImGui::BeginChild("chat", ImVec2(0, -footer_height), false,
                              ImGuiWindowFlags_HorizontalScrollbar |
                              ImGuiWindowFlags_AlwaysVerticalScrollbar);
            float region_w = ImGui::GetContentRegionAvail().x;
            for (int i = 0; i < msg_n; i++) {
                draw_chat_bubble(i, msgs[i].role, msgs[i].text,
                                 msgs[i].pending, region_w, font_mul);
            }
            /* Free snapshots. */
            for (int i = 0; i < msg_n; i++) if (msgs[i].text) free(msgs[i].text);

            /* Scroll handling. */
            LONG scroll_delta = InterlockedExchange(&g_reply_scroll_pending, 0);
            if (scroll_delta != 0) {
                float cur = ImGui::GetScrollY();
                float mx  = ImGui::GetScrollMaxY();
                float tgt = cur + (float)scroll_delta;
                if (tgt < 0.0f) tgt = 0.0f;
                if (tgt > mx)   tgt = mx;
                ImGui::SetScrollY(tgt);
            } else {
                if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                    ImGui::SetScrollHereY(1.0f);
            }
            ImGui::EndChild();
        }

        /* ── Persistent footer — visible in BOTH states. Two variants:
         *    - CHAT INPUT ACTIVE: show the current text buffer with
         *      blinking cursor + "Enter to send / Esc to cancel" hint.
         *      This is the killer feature — user types freely and the
         *      LL keyboard hook diverts keys into the buffer instead of
         *      matching hotkeys, so ANY app receives no keystrokes
         *      during input.
         *    - CHAT INPUT INACTIVE: normal hotkey cheat-sheet strip. */
        ImGui::Separator();
        int chat_on = g_chat_active;
        if (chat_on) {
            /* Snapshot buffer + cursor under lock so we don't tear
             * mid-utf8 while rendering. */
            char cbuf[CHAT_BUF_SIZE];
            int  cbuf_len, ccur;
            ensure_chat_cs();
            EnterCriticalSection(&g_chat_cs);
            memcpy(cbuf, g_chat_buf, (size_t)g_chat_len);
            cbuf[g_chat_len] = 0;
            cbuf_len = g_chat_len;
            ccur     = g_chat_cursor;
            LeaveCriticalSection(&g_chat_cs);

            /* Bounds sanity for tearing edge case. */
            if (ccur < 0) ccur = 0;
            if (ccur > cbuf_len) ccur = cbuf_len;

            /* Blink cursor — 500ms on / 500ms off. */
            bool cursor_on = ((GetTickCount() / 500) & 1) == 0;
            int  chars_shown = cbuf_len;   /* for char counter */

            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.85f, 1.0f, 0.95f));
            ImGui::Text("Ask AI (with screenshot):");
            ImGui::PopStyleColor();

            /* Frame the input area so it looks like a text box.
             * v1.3 (2026-07-07): ChildBg alpha scales with user
             * opacity via with_alpha_mul — the chat input box is a
             * container element, not body content. */
            ImGui::PushStyleColor(ImGuiCol_ChildBg, with_alpha_mul(ImVec4(0.08f, 0.12f, 0.20f, 0.70f)));
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.0f * scale, 6.0f * scale));
            ImGui::BeginChild("chat_input_frame",
                              ImVec2(0, ImGui::GetFrameHeightWithSpacing() * 1.4f),
                              true, ImGuiWindowFlags_NoScrollbar);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.94f, 0.98f, 1.0f, 1.0f));
            if (cbuf_len > 0) {
                /* Render text_before + cursor block + text_after so the
                 * cursor visually sits at ccur (arrow-key navigation UX). */
                char before[CHAT_BUF_SIZE], after[CHAT_BUF_SIZE];
                memcpy(before, cbuf, (size_t)ccur);       before[ccur] = 0;
                int tail = cbuf_len - ccur;
                memcpy(after,  cbuf + ccur, (size_t)tail); after[tail] = 0;
                /* U+258A LEFT FIVE EIGHTHS BLOCK = solid narrow bar. */
                ImGui::TextWrapped("%s%s%s",
                    before,
                    cursor_on ? "\xE2\x96\x8A" : " ",
                    after);
            } else {
                if (cursor_on) {
                    ImGui::TextWrapped("\xE2\x96\x8A");
                } else {
                    ImGui::TextDisabled("Type your question...");
                }
            }
            ImGui::PopStyleColor();
            ImGui::EndChild();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor();

            /* Hint line + char counter (buffer max 2048 bytes). */
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.68f, 0.85f, 0.75f));
            ImGui::Text("Enter send | Esc cancel | Backspace/Delete | Arrows/Home/End nav   [%d/%d]",
                        chars_shown, CHAT_BUF_SIZE - 4);
            ImGui::PopStyleColor();
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.68f, 0.85f, 0.75f));
            if (sl == 0) {
                /* Home view (either empty history OR user hit back).
                 * Ctrl+Alt+X here QUITS since there's no chat to hide. */
                ImGui::Text("Ctrl+Shift+Space  ask   |   Ctrl+Alt+T  type   |   Ctrl+Alt+G  toggle   |   Ctrl+Alt+X  quit");
            } else {
                /* Chat visible.
                 *  - Ctrl+Alt+X = BACK (hide chat, preserve msgs)
                 *  - Ctrl+Alt+N = CLEAR (wipe all msgs entirely)
                 *  - Copy hotkeys handy for the current reply. */
                ImGui::Text("Ctrl+Alt+X  back   |   Ctrl+Alt+N  clear   |   Ctrl+Alt+C  copy   |   Ctrl+Alt+J/K  scroll");
            }
            ImGui::PopStyleColor();
        }
    }
    ImGui::End();

    ImGui::PopStyleColor(9);
    ImGui::PopStyleVar(4);
}

/* ---------- OM state backup for the RTV binding ---------- *
 * ImGui's internal backup covers IA/RS/BS/DS/PS/VS/GS/samplers/topology/etc.
 * It does NOT restore OMSetRenderTargets — because it EXPECTS the caller to
 * have set the target before calling RenderDrawData. So we must save+restore
 * that ourselves. */
struct OMBackup {
    ID3D11RenderTargetView *rtvs[8];
    ID3D11DepthStencilView *dsv;
    UINT                    vp_count;
    D3D11_VIEWPORT          vps[16];
    UINT                    sc_count;
    D3D11_RECT              scs[16];
};

static void om_backup(ID3D11DeviceContext *ctx, OMBackup *b) {
    for (int i = 0; i < 8; i++) b->rtvs[i] = nullptr;
    b->dsv = nullptr;
    ctx->OMGetRenderTargets(8, b->rtvs, &b->dsv);
    b->vp_count = 16;
    ctx->RSGetViewports(&b->vp_count, b->vps);
    b->sc_count = 16;
    ctx->RSGetScissorRects(&b->sc_count, b->scs);
}

static void om_restore(ID3D11DeviceContext *ctx, OMBackup *b) {
    ctx->OMSetRenderTargets(8, b->rtvs, b->dsv);
    for (int i = 0; i < 8; i++) if (b->rtvs[i]) b->rtvs[i]->Release();
    if (b->dsv) b->dsv->Release();
    if (b->vp_count > 0) ctx->RSSetViewports(b->vp_count, b->vps);
    if (b->sc_count > 0) ctx->RSSetScissorRects(b->sc_count, b->scs);
}

/* ---------- Main frame entry ---------- */
extern "C" void ui_present_frame(void *pCtx, void *pLayer) {
    (void)pCtx;
    if (!pLayer) return;
    g_frame_count++;
    /* Throttled state persistence — no-op fast path if !g_state_dirty. */
    state_flush_if_due();

    /* First-time markers so we can see the pipeline is executing. */
    static volatile LONG s_first_call = 0;
    if (InterlockedCompareExchange(&s_first_call, 1, 0) == 0) {
        diag("present_frame entered (first frame)");
    }

    __try {
        ID3D11Texture2D *tex = get_backbuffer_texture(pLayer);
        if (!tex) {
            static volatile LONG s_first_no_tex = 0;
            if (InterlockedCompareExchange(&s_first_no_tex, 1, 0) == 0)
                diag("get_backbuffer_texture returned NULL (first miss)");
            return;
        }
        static volatile LONG s_first_tex = 0;
        if (InterlockedCompareExchange(&s_first_tex, 1, 0) == 0)
            diag("got backbuffer tex (first)");

        ID3D11Device *dev = nullptr;
        tex->GetDevice(&dev);
        if (!dev) { tex->Release(); return; }

        UINT w = 0, h = 0;
        DXGI_FORMAT fmt = DXGI_FORMAT_UNKNOWN;
        ID3D11RenderTargetView *rtv = get_or_create_rtv(dev, tex, &w, &h, &fmt);
        tex->Release();     /* RTV holds its own ref. */
        if (!rtv || w == 0 || h == 0) { dev->Release(); return; }

/* Frame dedup — if another ~fullscreen layer already drew this
 * frame, skip. Otherwise we'd render the ImGui window multiple
 * times into different layer textures = visible duplicate overlays
 * that ghost through each other.
 *
 * v1.3 (2026-07-07) THRESHOLD DROPPED 12ms -> 3ms — TRANSPARENCY
 * FLICKER FIX.
 *
 * The old 12ms threshold was safe for 60Hz (16.67ms/frame) but
 * unintentionally clamped high-refresh-rate monitors:
 *   120Hz -> 8.33ms/frame  < 12ms -> skip every other frame
 *   144Hz -> 6.94ms/frame  < 12ms -> skip most frames
 *   165Hz -> 6.06ms/frame  < 12ms -> skip most frames
 *   240Hz -> 4.17ms/frame  < 12ms -> skip most frames
 * On any skipped frame the layer texture goes back to raw app
 * content (no overlay pixels blended in), which the user perceives
 * as OVERLAY FLICKER — especially visible with transparency < 100%
 * because the semi-transparent overlay makes any per-frame
 * on/off flip trivially noticeable (whereas an opaque overlay
 * blocks the underlying app content, masking the flip's visual
 * impact somewhat).
 *
 * 3ms threshold rationale:
 *   - Within-cycle multi-layer draws happen microseconds apart
 *     (DWM calls Present sequentially for LDB main + LDB modal +
 *     other fullscreen surfaces within one compose cycle). 3ms is
 *     plenty to catch them.
 *   - Real vsync frames on 60/120/144/165/200/240/300Hz monitors
 *     all have frame periods >= 3.33ms so the threshold never
 *     wrongly rejects a legitimate frame.
 *   - 360Hz+ monitors (2.77ms/frame) would still hit a partial skip
 *     but those are cutting-edge esports panels; if svcldb ever
 *     ships to that user, revisit.
 *
 * Belt-and-suspenders: the layer-size gate in get_or_create_rtv
 * (only accept layers within 95% of the largest seen) ALSO
 * eliminates duplicates from smaller-but-still-fullscreen layers.
 * So even if this threshold underfires, we won't get duplicate
 * overlays from smaller fullscreen surfaces. */
        ULONGLONG now = GetTickCount64();
        if ((now - g_last_draw_tick) < FRAME_DEDUP_MS) {
            dev->Release();
            return;
        }
        g_last_draw_tick = now;

        ID3D11DeviceContext *ctx = nullptr;
        dev->GetImmediateContext(&ctx);
        if (!ctx) { dev->Release(); return; }

        /* PRE-OVERLAY CAPTURE (AI-request path).
         *
         * When ui_capture_screen_png is called for an AI request:
         *   - g_hide_frames_for_capture = 3
         *   - g_cap_when_after_overlay = 0
         * We skip capture + overlay draw for 3 frames so DWM
         * re-composites the layer with pure app content, then on
         * frame 4 (hide=0) we capture BEFORE our overlay draw runs
         * this frame. Result: AI receives a clean app-only shot. */
        if (g_cap_request && g_hide_frames_for_capture == 0 &&
            g_cap_when_after_overlay == 0) {
            ID3D11Texture2D *cap_tex = get_backbuffer_texture(pLayer);
            if (cap_tex) {
                try_perform_capture(dev, ctx, cap_tex, w, h, fmt);
                cap_tex->Release();
            }
        }
        if (g_bmp_request && g_hide_frames_for_capture == 0 &&
            g_cap_when_after_overlay == 0) {
            ID3D11Texture2D *cap_tex = get_backbuffer_texture(pLayer);
            if (cap_tex) {
                try_perform_bmp_capture(dev, ctx, cap_tex, w, h, fmt);
                cap_tex->Release();
            }
        }
        if (g_hide_frames_for_capture > 0) {
            InterlockedDecrement(&g_hide_frames_for_capture);
        }

        if (!g_imgui_inited) {
            diag("initializing ImGui with %ux%u fmt=%u", w, h, (unsigned)fmt);
            IMGUI_CHECKVERSION();
            ImGui::CreateContext();
            ImGuiIO &io = ImGui::GetIO();
            io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
            io.IniFilename  = nullptr;
            io.LogFilename  = nullptr;
            /* Use a big display size initially; will be overridden per-frame. */
            io.DisplaySize = ImVec2((float)w, (float)h);

            /* Load fonts BEFORE ImGui_ImplDX11_Init — the backend
             * builds the GPU font texture from IO.Fonts on first
             * frame. Loading after that causes a missing-glyph texture.
             *
             * v6.3 (2026-07-06) - MAJOR RANGE FIX:
             *
             * Previous ranges were BROKEN in two ways:
             *   1. OUT OF ORDER: 0x2500 (box drawing) came before 0x2190
             *      (arrows). ImGui requires ranges in ASCENDING order.
             *      Any range after an out-of-order entry could be silently
             *      dropped. This is why arrows / some symbols rendered
             *      as '??' in AI answers.
             *   2. MISSING critical ranges for LaTeX rendering:
             *      - Superscripts (U+2070-209F): ² ³ ⁻ ⁺ ⁿ — emitted by
             *        our sup_of() helper for x^2, x^{ab}, etc.
             *      - Subscripts (U+2080-209F): ₀ ₁ ₂ ᵢ — emitted by
             *        sub_of() for H_2O, x_i, etc.
             *      - Number Forms (U+2150-218F): ½ ⅓ ⅔ ¼ ¾ — emitted
             *        by our VULGAR_FRACS table for \frac{1}{2}.
             *      - Letterlike (U+2100-214F): ℝ ℂ ℕ ℚ ℤ — sometimes
             *        emitted for AI's blackboard-bold set names.
             *      - Combining marks (U+0300-036F, U+20D0-20FF): the
             *        \vec, \hat, \bar, \dot commands emit these to add
             *        marks over the previous letter (e.g. \vec{v} → v⃗).
             *
             * Fix: use ONE contiguous range that covers everything from
             * 0x0020 to 0x2BFF. Font atlas grows by a few MB but that's
             * fine (we're inside DWM which has plenty of GPU memory).
             * ImGui only allocates atlas slots for glyphs the font
             * actually HAS, so no penalty for over-requesting.
             *
             * Also v6.3: MERGE Segoe UI Symbol on top so any math /
             * symbol glyph Segoe UI itself lacks gets filled from the
             * symbol font. Segoe UI Symbol is a dedicated Microsoft
             * font shipped with every Win7+ install that covers 100%
             * of the math / arrow / geometric-shape Unicode blocks.
             *
             * CJK is DELIBERATELY not loaded (adds 200+ MB to atlas). */
            static const ImWchar RANGES_UI[] = {
                0x0020, 0x007F,   /* Basic Latin */
                0x00A0, 0x024F,   /* Latin-1 Supplement + Latin Extended-A/B */
                0x0300, 0x036F,   /* Combining Diacritical Marks (accents) */
                0x0370, 0x03FF,   /* Greek (α β π θ ε λ Σ Δ etc.) */
                0x2000, 0x209F,   /* Punctuation + Superscripts + Subscripts */
                0x20A0, 0x20CF,   /* Currency symbols */
                0x20D0, 0x20FF,   /* Combining marks for symbols (\vec arrow etc.) */
                0x2100, 0x214F,   /* Letterlike (ℝ ℂ ℕ ℚ ℤ ℵ) */
                0x2150, 0x218F,   /* Number Forms (½ ⅓ ⅔ ¼ ¾ ⅕ ⅖ ...) */
                0x2190, 0x21FF,   /* Arrows (→ ← ↑ ↓ ⇌ ↦ ⇒ ⇔) */
                0x2200, 0x22FF,   /* Mathematical Operators (∀ ∃ ∈ ∫ ∑ √ ∂ ∇ ≠ ≤) */
                0x2300, 0x23FF,   /* Misc Technical (⌈ ⌉ ⌊ ⌋ ⌜ ⌝) */
                0x2500, 0x257F,   /* Box drawing */
                0x2580, 0x259F,   /* Block elements */
                0x25A0, 0x25FF,   /* Geometric shapes (■ ● ▲ ◆) */
                0x2600, 0x26FF,   /* Misc symbols (☆ ★ ⚠) */
                0x2700, 0x27BF,   /* Dingbats (✓ ✗) */
                0x27C0, 0x27EF,   /* Misc Math A */
                0x27F0, 0x27FF,   /* Supplemental Arrows-A */
                0x2900, 0x297F,   /* Supplemental Arrows-B */
                0x2980, 0x29FF,   /* Misc Math B */
                0x2A00, 0x2AFF,   /* Supplemental Math Operators */
                0x2B00, 0x2BFF,   /* Misc Symbols and Arrows */
                0, 0
            };
            g_font_ui = io.Fonts->AddFontFromFileTTF(
                "C:\\Windows\\Fonts\\segoeui.ttf", UI_FONT_SIZE_PX,
                nullptr, RANGES_UI);
            if (!g_font_ui) {
                g_font_ui = io.Fonts->AddFontDefault();
                diag("font: segoeui.ttf load FAILED, using default");
            } else {
                diag("font: UI = Segoe UI @ %.0fpx", UI_FONT_SIZE_PX);
            }
            /* v6.3: MERGE Segoe UI Symbol on top of Segoe UI so any
             * math/symbol glyph Segoe UI itself lacks (rare - it covers
             * most, but Cambria Math coverage is broader) gets filled
             * from the symbol font. seguisym.ttf ships with Win7+. */
            {
                ImFontConfig mcfg;
                mcfg.MergeMode = true;
                mcfg.PixelSnapH = true;
                ImFont *sym = io.Fonts->AddFontFromFileTTF(
                    "C:\\Windows\\Fonts\\seguisym.ttf", UI_FONT_SIZE_PX,
                    &mcfg, RANGES_UI);
                if (sym) diag("font: Segoe UI Symbol merged for math coverage");
                else     diag("font: seguisym.ttf load FAILED - math glyphs may render as ?");
            }
            /* Mono font — try Cascadia Mono, then Consolas. */
            g_font_mono = io.Fonts->AddFontFromFileTTF(
                "C:\\Windows\\Fonts\\CascadiaMono.ttf", MONO_FONT_SIZE_PX,
                nullptr, RANGES_UI);
            if (!g_font_mono) {
                g_font_mono = io.Fonts->AddFontFromFileTTF(
                    "C:\\Windows\\Fonts\\consola.ttf", MONO_FONT_SIZE_PX,
                    nullptr, RANGES_UI);
            }
            if (!g_font_mono) {
                g_font_mono = g_font_ui;   /* fall back to UI font */
                diag("font: mono load FAILED, using UI font");
            } else {
                diag("font: mono OK @ %.0fpx", MONO_FONT_SIZE_PX);
                /* v6.3: also merge Segoe UI Symbol into mono for the
                 * same math coverage. Cascadia Mono has decent math
                 * coverage already but Consolas is sparse. */
                ImFontConfig mcfg;
                mcfg.MergeMode = true;
                mcfg.PixelSnapH = true;
                io.Fonts->AddFontFromFileTTF(
                    "C:\\Windows\\Fonts\\seguisym.ttf", MONO_FONT_SIZE_PX,
                    &mcfg, RANGES_UI);
            }

            ImGui::StyleColorsDark();

            if (!ImGui_ImplDX11_Init(dev, ctx)) {
                diag("ImGui_ImplDX11_Init FAILED");
                ImGui::DestroyContext();
                ctx->Release(); dev->Release();
                return;
            }
            /* Build fonts explicitly so first-frame flicker is avoided. */
            ImGui_ImplDX11_NewFrame();  /* needed so backend allocates GPU font */
            g_imgui_inited = true;
            diag("ImGui READY — overlay should render this frame");
        }

        /* Save OM state before we clobber it. */
        OMBackup om = {};
        om_backup(ctx, &om);

        /* Bind our RTV + viewport (full RT). No depth, no scissor initially. */
        ID3D11RenderTargetView *bind[1] = { rtv };
        ctx->OMSetRenderTargets(1, bind, nullptr);
        D3D11_VIEWPORT vp = {};
        vp.Width = (float)w; vp.Height = (float)h;
        vp.MinDepth = 0.0f; vp.MaxDepth = 1.0f;
        vp.TopLeftX = 0.0f; vp.TopLeftY = 0.0f;
        ctx->RSSetViewports(1, &vp);
        /* No scissor — RSGetScissorRects with count=0 disables scissor test. */
        ctx->RSSetScissorRects(0, nullptr);

        /* -------- ImGui frame -------- */
        ImGuiIO &io = ImGui::GetIO();
        io.DisplaySize = ImVec2((float)w, (float)h);
        io.DeltaTime   = 1.0f / 60.0f;

        ImGui_ImplDX11_NewFrame();
        ImGui::NewFrame();
        draw_chat_window(w, h);
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        static volatile LONG s_first_render = 0;
        if (InterlockedCompareExchange(&s_first_render, 1, 0) == 0)
            diag("RenderDrawData completed (first frame) — pixels should be on screen");

        /* POST-OVERLAY CAPTURE (debug-capture path).
         *
         * When ui_capture_screen_png_with_overlay is called for debug:
         *   - g_hide_frames_for_capture = 0
         *   - g_cap_when_after_overlay = 1
         * Capture runs HERE (after our overlay draw completed) so the
         * shot INCLUDES the overlay pixels — useful for verifying
         * that bubble rendering + code blocks + math blocks look
         * right without needing a physical monitor screenshot. */
        if (g_cap_request && g_cap_when_after_overlay == 1) {
            ID3D11Texture2D *cap_tex = get_backbuffer_texture(pLayer);
            if (cap_tex) {
                try_perform_capture(dev, ctx, cap_tex, w, h, fmt);
                cap_tex->Release();
            }
        }
        if (g_bmp_request && g_cap_when_after_overlay == 1) {
            ID3D11Texture2D *cap_tex = get_backbuffer_texture(pLayer);
            if (cap_tex) {
                try_perform_bmp_capture(dev, ctx, cap_tex, w, h, fmt);
                cap_tex->Release();
            }
        }

        /* Restore DWM's state. */
        om_restore(ctx, &om);

        ctx->Release();
        dev->Release();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        static volatile LONG s_first_exc = 0;
        if (InterlockedCompareExchange(&s_first_exc, 1, 0) == 0)
            diag("EXCEPTION in ui_present_frame (silently swallowed to avoid DWM crash)");
    }
}

extern "C" void ui_shutdown() {
    if (g_imgui_inited) {
        ImGui_ImplDX11_Shutdown();
        ImGui::DestroyContext();
        g_imgui_inited = false;
    }
    for (int i = 0; i < RTV_CACHE_MAX; i++) {
        if (g_cache[i].rtv) g_cache[i].rtv->Release();
        g_cache[i] = {};
    }
    g_last_device = nullptr;
    if (g_ui_cs_init) {
        DeleteCriticalSection(&g_ui_cs);
        g_ui_cs_init = false;
    }
    diag("shutdown done");
}
