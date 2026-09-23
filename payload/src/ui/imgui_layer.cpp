/* ================================================================== *
 * imgui_layer.cpp -- ImGui + D3D11 inside DWM's compositor pass.       *
 *                                                                    *
 * Design:                                                            *
 *  - Hook `COverlayContext::Present(pCtx, pLayer, ...)` in dwmcore.  *
 *  - Walk pLayer's vtable to obtain the ID3D11Texture2D that DWM      *
 *    just presented to the compositor for THIS specific layer.       *
 *  - Get the D3D device via COM ID3D11DeviceChild::GetDevice slot 3. *
 *  - Only render into the FULLSCREEN layer (>= 800x600). DWM Present *
 *    is per-layer -- cursor overlay is 32x32, tooltips are small.     *
 *  - HDR-aware: if the texture is R16G16B16A16_FLOAT, we create the  *
 *    RTV with the SAME format (ImGui outputs scRGB-compatible sRGB   *
 *    values -> 1.0 in float = SDR white on both SDR and HDR monitors).*
 *  - Complete D3D11 state save/restore around ImGui render (ImGui's  *
 *    internal backup handles the shader/IA/RS/BS/DS/PS-SRV state; we *
 *    additionally back up OM RTVs + viewport + scissor since ImGui   *
 *    doesn't touch OM's target binding).                             *
 *                                                                    *
 * Diagnostics: uses plaintext CreateFileA writes to `payload_early`  *
 * (not slog) because slog uses __declspec(thread) internally, and    *
 * TLS is broken under manual map (loader-only init step skipped).    *
 *                                                                    *
 * Vtable slots -- verified via production hooksdll/dwm/dwm_payload.c  *
 * capture path (25/25 audit; used in production for 800+ users):     *
 *   pLayer.vtable[5] () = GetPhysicalBackBuffer                      *
 *   pLayer.vtable[24]() = GetD3D11Resource                           *
 *   resource.vtable[19]() = accessor (IUnknown for the D3D texture)  *
 *   QueryInterface(accessor, IID_ID3D11Texture2D)                    *
 *   texture->GetDevice(&device) via standard COM slot 3              *
 * ================================================================== */

#include "../../../shared/common.h"
#include "../../../shared/config_types.h"   /* v1.7.4: SVC_HK_KIND_* + accessors for label formatter */

#include <windows.h>
#include <d3d11.h>
#include <d3d11_1.h>   /* ID3D11DeviceContext1::ClearView (v1.7.4.15) */
#include <dxgi.h>
#include <wincodec.h>
#include <shlwapi.h>
#include <psapi.h>
#include <stdio.h>
#include <ctype.h>

#include "../../../shared/imgui/imgui.h"
#include "../../../shared/imgui/backends/imgui_impl_dx11.h"
#include "../../../shared/imgui/backends/imgui_impl_win32.h"

#include "imgui_layer.h"

extern "C" {
#include "../../../shared/log_secure.h"
#include "../../../shared/obf_names.h"   /* v3.0.2.4: GUID-per-install names */
#include "../dwm_hooks.h"
#include "../clipboard_out.h"   /* v9: unified retry+UNICODETEXT copy helper */
#include "../redact/redact_client.h"   /* screenshot-redactor pipe client */
/* v3.0.2.3 (2026-09-21) -- extern for the Cancel/Send buttons in the
 * chat footer (defined in dllmain.c). */
void chat_submit_typed_text(void);
}

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

/* ---------- Vtable slots (production-verified via PDB dump 2026-07-16) ----------
 *
 * IMPORTANT NAMING NOTE (v1.6.5 -- corrected via RE):
 *
 * The names GPB_SLOT / GD3D_SLOT / ACC3_SLOT are HISTORICAL -- they
 * pre-date the actual RE of dwmcore.dll. Actual method identity at
 * each slot on a REFERENCE build (Win11 26100.8115, PDB-verified):
 *
 *   GPB_SLOT   =  5  -> COverlaySwapChain::GetDevice
 *                       (result THROWN AWAY -- sanity probe only, kept
 *                        because removing it would change behavior on
 *                        obscure builds where slot 24 depends on the
 *                        object state after GetDevice runs)
 *   GD3D_SLOT  = 24  -> CDDisplaySwapChain::GetPhysicalBackBuffer
 *                       (THIS returns pBuffer used downstream)
 *   ACC3_SLOT  = 19  -> CDDisplaySwapChainBuffer::GetD3D11Resource
 *                       (called on pBuffer, returns pResource)
 *   VTBL_QI    =  0  -> IUnknown::QueryInterface (COM-standard)
 *
 * CDDisplaySwapChain has 6 vftables (multi-inheritance). GetPhysicalBackBuffer
 * lives at slot 24 on vftable[1/6], slot 45 on [2/6], 44 on [3/6],
 * 43 on [4/6], 28 on [5/6]. When DWM passes pLayer cast as a
 * non-primary subobject on older Windows builds, hardcoded slot 24
 * points at a completely different function -> wrong-object chain ->
 * garbage QI target -> __fastfail. Dynamic RVA-based scan handles this.
 *
 * See tools/re_probe/dwmcore_dump.c for the tool used to produce
 * the definitive per-build slot mapping. */
#define GPB_SLOT     5    /* really: COverlaySwapChain::GetDevice   */
#define GD3D_SLOT    24   /* really: CDDisplaySwapChain::GetPhysicalBackBuffer */
#define ACC3_SLOT    19   /* really: CDDisplaySwapChainBuffer::GetD3D11Resource */
#define VTBL_QI      0    /* IUnknown::QueryInterface      */
#define VTBL_RELEASE 2    /* IUnknown::Release             */

static const GUID IID_ID3D11Texture2D_LOCAL = {
    0x6f15aaf2, 0xd208, 0x4e89, {0x9a,0xb4,0x48,0x95,0x35,0xd3,0x4f,0x9c}
};

/* v1.7.11.2 (2026-07-25) -- BP-parity Device1 QI for DiscardView.
 * BP RE (bp_decomp.c line 65-77 + bp_decomp2.c FUN_18000c390) confirms
 * BP QIs the underlying pDevice to ID3D11Device1, then uses
 * GetImmediateContext1 to get ID3D11DeviceContext1. That unlocks
 * DiscardView / DiscardResource -- the D3D11.1 compositor-hint APIs
 * that tell DWM "these pixels are discardable, feel free to fully
 * repaint on the next compose". Likely the missing piece for BP's
 * glide + no-trails behavior on Chrome/DirectComposition apps. */
static const GUID IID_ID3D11Device1_LOCAL = {
    0xa04bfb29, 0x08ef, 0x43d6, {0xa4,0x9c,0xa9,0xbd,0xbd,0xcb,0xe6,0x86}
};
static const GUID IID_ID3D11DeviceContext1_LOCAL = {
    0xbb2c6faa, 0xb5fb, 0x4082, {0x8e,0x6b,0x38,0x8b,0x8c,0xfa,0x90,0xe1}
};

typedef HRESULT (__stdcall *pfnQI)(void *, const GUID *, void **);
typedef ULONG   (__stdcall *pfnRelease)(void *);
typedef void   *(__fastcall *pfnVGet)(void *);

/* ---------- Diagnostic writer (bypasses slog TLS issue entirely) ----------
 * Every important line ALSO goes to payload_early.txt as plaintext. The
 * TLS-in-manual-map problem swallowed all slog_write calls before this
 * commit -- plaintext bypass is unaffected and always works. */
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
 * with DWM_EXT_TRACE=1 env var. Anti-strings-scan pattern --
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

/* Forward decl -- used by ui_toggle_visible / ui_nudge / etc. below.
 * Definition is further down alongside the capture path. */
static void wake_dwm_composition(void);
/* v1.6.5: lightweight variant for visibility toggles -- one composition
 * pass, no cursor jitter, no 300ms SCP burst. See ui_toggle_visible. */
static void wake_dwm_composition_lite(void);
/* v1.7.2: throttled typing wake -- used per-keystroke to avoid strobing. */
static void wake_dwm_composition_typing(void);

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

/* v1.6.1 (2026-07-15) -- Executability probe for vtable-slot validation.
 *
 * The hardcoded vtable slots in get_backbuffer_texture (GPB_SLOT=5,
 * GD3D_SLOT=24, ACC3_SLOT=19) were reverse-engineered from a specific
 * dwmcore build. When Windows updates re-order the vtable (different
 * patch levels, ARM64 vs x64, N vs full SKU), our slot indices point
 * to the WRONG function pointer for that build. Calling the wrong
 * pointer either:
 *   - Lands in valid code that happens to have a different signature
 *     -> stack corruption -> later __fastfail
 *   - Lands in NON-code (heap, .data, unmapped) -> __fastfail via CFG
 *     or CET Shadow Stack (BYPASSES __try/__except entirely)
 *
 * Reported by jay.perkerson@gmail.com 2026-07-15: DWM crashed within
 * ~1s of every inject. Payload log stopped exactly at first-frame
 * BEFORE any ImGui init line, which is where get_backbuffer_texture
 * runs. His resolver hit 11/21 symbols vs 17/21 on the dev box --
 * confirming different dwmcore build.
 *
 * Fix: validate each vtable slot fetch returns a pointer INSIDE
 * dwmcore.dll's executable memory before calling. If not, log and
 * bail -- overlay doesn't render (returns NULL from
 * get_backbuffer_texture) but DWM STAYS ALIVE, hotkeys still work,
 * and payload emits diagnostic that tells support what happened. */
static HMODULE g_dwmcore_mod  = NULL;
static BYTE   *g_dwmcore_base = NULL;
static SIZE_T  g_dwmcore_size = 0;
static void ensure_dwmcore_bounds_cached(void) {
    if (g_dwmcore_mod) return;
    HMODULE m = GetModuleHandleW(L"dwmcore.dll");
    if (!m) return;
    MODULEINFO mi = {0};
    if (!GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof(mi))) return;
    g_dwmcore_mod  = m;
    g_dwmcore_base = (BYTE *)mi.lpBaseOfDll;
    g_dwmcore_size = (SIZE_T)mi.SizeOfImage;
}
static bool is_ptr_in_dwmcore(const void *p) {
    if (!p) return false;
    ensure_dwmcore_bounds_cached();
    if (!g_dwmcore_base || !g_dwmcore_size) return false;
    const BYTE *pb = (const BYTE *)p;
    return pb >= g_dwmcore_base && pb < (g_dwmcore_base + g_dwmcore_size);
}

/* v1.6.1: Any executable memory owned by an IMAGE-mapped section (i.e.
 * inside a legitimately-loaded DLL/EXE). Used for looser slot validation
 * on COM-standard vtable positions (e.g. IUnknown::QueryInterface at
 * slot 0) which legitimately dispatch across module boundaries -- the
 * accessor's QI might point into d3d11.dll or dxgi.dll, not dwmcore.
 *
 * MEM_IMAGE + PAGE_EXECUTE_* is the correct signature for loaded-DLL
 * code -- excludes heap/stack/manual-map regions where a corrupted vtable
 * pointer might otherwise land. */
static bool is_ptr_in_loaded_module_code(const void *p) {
    if (!p) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Type  != MEM_IMAGE)  return false;
    DWORD exec_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & exec_mask) != 0;
}

/* ── v1.6.2 (2026-07-15) -- dynamic vtable-slot discovery ──
 *
 * dllmain plumbs the resolver-discovered RVAs of the vtable target
 * methods into the UI layer via ui_set_vtable_slot_hints(). Any RVA
 * being 0 means "no PDB hint -- fall back to hardcoded slot" for
 * that entry.
 *
 * At first Present() call, get_backbuffer_texture walks pLayer's
 * (and pRes's) vtable up to MAX_VTABLE_SCAN_SLOTS, finds the slot
 * whose function pointer's (addr - dwmcore_base) matches the hint
 * RVA, and caches the discovered slot index for the process lifetime.
 * If no match, falls back to the hardcoded GPB_SLOT / GD3D_SLOT /
 * ACC3_SLOT constants (which work for ~800+ Bypassify users).
 *
 * Solves the "DWM crashes ~1s after inject on Windows patches with
 * re-ordered vtable" bug (jay.perkerson@gmail.com 2026-07-15).
 * Zero regression risk for users where hardcoded works -- dynamic
 * discovers the SAME slot the hardcoded constant points to, uses
 * it, no user-visible change.
 *
 * v1.6.5 (2026-07-16): raised from 64 -> 256 after user log analysis.
 * CDDisplaySwapChain has 6 vftables in modern dwmcore (multi-inherit).
 * On subobjects other than vtable[1/6], GetPhysicalBackBuffer lives at
 * slot 28/43/44/45. 64 caught the primary vtable but MISSed all others.
 * 256 gives comfortable headroom vs the largest observed dwmcore vtable
 * (COverlayContext has ~80 methods) while staying well below the class-
 * range boundaries where adjacent .rdata could false-positive. */
#define MAX_VTABLE_SCAN_SLOTS 256

static volatile ui_rva_t g_rva_gpb  = 0;   /* GetPhysicalBackBuffer RVA hint */
static volatile ui_rva_t g_rva_gd3d = 0;   /* GetD3D11Resource RVA hint      */
static volatile ui_rva_t g_rva_acc  = 0;   /* accessor RVA hint              */

/* Discovered slot indices (cached across calls). -1 = not yet resolved
 * or dynamic scan failed -> falls back to hardcoded constant. */
static volatile int g_dyn_slot_gpb  = -1;
static volatile int g_dyn_slot_gd3d = -1;
static volatile int g_dyn_slot_acc  = -1;

extern "C" void ui_set_vtable_slot_hints(ui_rva_t gpb_rva, ui_rva_t gd3d_rva, ui_rva_t acc_rva) {
    g_rva_gpb  = gpb_rva;
    g_rva_gd3d = gd3d_rva;
    g_rva_acc  = acc_rva;
    /* Note: don't log here -- this runs before slog is fully set up in
     * some code paths. Discovery attempts log their own diagnostics. */
}

/* v1.6.3: known-RVA lookup table. Populated once at init by
 * ui_set_known_rva_table(); read (lock-free) at first Present() to
 * name each vtable slot's actual function in the diag log. Small
 * bounded copy (MAX_KNOWN_RVA = 32) -- plenty for offsets.blob's ~20
 * meaningful entries. */
#define MAX_KNOWN_RVA 32
static ui_rva_symbol_t g_known_rva[MAX_KNOWN_RVA];
static int             g_known_rva_count = 0;

extern "C" void ui_set_known_rva_table(const ui_rva_symbol_t *table, int count) {
    if (!table || count <= 0) return;
    int n = count > MAX_KNOWN_RVA ? MAX_KNOWN_RVA : count;
    int written = 0;
    for (int i = 0; i < n; i++) {
        if (table[i].rva == 0 || !table[i].name) continue;
        g_known_rva[written] = table[i];
        written++;
    }
    g_known_rva_count = written;
}

/* O(N) linear search -- N is tiny (~20). Called at most 3 times per
 * DWM lifetime (once per slot on first Present success). Returns
 * name of the symbol whose RVA matches, or "?" if unknown. */
static const char *lookup_rva_name(ui_rva_t rva) {
    if (rva == 0) return "?";
    for (int i = 0; i < g_known_rva_count; i++) {
        if (g_known_rva[i].rva == rva) return g_known_rva[i].name;
    }
    return "?";
}

/* v1.6.5: On dynamic-scan MISS, dump the FULL vtable-slot-to-known-symbol
 * mapping so support can see what's at each slot on this user's Windows
 * build. Enables identifying which slot GetPhysicalBackBuffer actually
 * lives at without needing to run RE tools on the user's machine.
 *
 * Only logs slots where the fn's RVA matches something in the known-RVA
 * table (~20 entries from offsets.blob) -- the vast majority of the ~50
 * scanned slots point to methods we don't have RVAs for, so listing them
 * would just be noise. */
static void dump_known_slots_in_vtable(const char *vtbl_label, void **vtbl) {
    if (!vtbl) return;
    ensure_dwmcore_bounds_cached();
    if (!g_dwmcore_base) return;
    diag("vtable[%s] known-symbol map (slot -> known method):", vtbl_label);
    int found_any = 0;
    __try {
        for (int i = 0; i < MAX_VTABLE_SCAN_SLOTS; i++) {
            if (!is_readable(&vtbl[i], sizeof(void *))) break;
            void *fn = vtbl[i];
            if (!fn) continue;
            const BYTE *pb = (const BYTE *)fn;
            if (pb < g_dwmcore_base || pb >= (g_dwmcore_base + g_dwmcore_size)) continue;
            ui_rva_t rva = (ui_rva_t)(pb - g_dwmcore_base);
            const char *nm = lookup_rva_name(rva);
            if (nm[0] != '?') {
                diag("  slot[%3d] rva=0x%llx == %s", i,
                     (unsigned long long)rva, nm);
                found_any = 1;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        diag("  (SEH during vtable walk -- vtable ended early)");
    }
    if (!found_any) {
        diag("  (no slots matched any known-RVA -- pLayer type is unknown "
             "OR resolver missed too many symbols)");
    }
}

/* Walk a vtable up to MAX_VTABLE_SCAN_SLOTS looking for a slot whose
 * function pointer, when compared as an offset from dwmcore's base,
 * equals `target_rva`. Returns the matching slot index or -1.
 *
 * SEH-wrapped because vtable might be shorter than we scan; a bad
 * page-read is caught + returns -1 (falls back to hardcoded). */
static int find_vtable_slot_by_rva(void **vtbl, ui_rva_t target_rva) {
    if (!vtbl || target_rva == 0) return -1;
    ensure_dwmcore_bounds_cached();
    if (!g_dwmcore_base) return -1;

    int found = -1;
    __try {
        for (int i = 0; i < MAX_VTABLE_SCAN_SLOTS; i++) {
            /* Bounds-check the pointer read itself -- vtable might end
             * before slot MAX_VTABLE_SCAN_SLOTS. */
            if (!is_readable(&vtbl[i], sizeof(void *))) break;
            void *fn = vtbl[i];
            if (!fn) continue;
            /* Fast-path: dwmcore-only check (99% of methods). */
            const BYTE *pb = (const BYTE *)fn;
            if (pb < g_dwmcore_base || pb >= (g_dwmcore_base + g_dwmcore_size)) continue;
            ui_rva_t rva = (ui_rva_t)(pb - g_dwmcore_base);
            if (rva == target_rva) {
                found = i;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Vtable turned out shorter than we scanned or unmapped -- bail. */
    }
    return found;
}

/* One-shot dynamic slot discovery. Called from get_backbuffer_texture
 * on first successful call. Logs the result so we can see per-user
 * whether dynamic matched hardcoded (validation) or found a different
 * slot (drift on that Windows build). */
static void discover_gpb_slot_once(void **layer_vtbl, int hardcoded) {
    static volatile LONG s_done = 0;
    if (InterlockedCompareExchange(&s_done, 1, 0) != 0) return;
    int dyn = find_vtable_slot_by_rva(layer_vtbl, g_rva_gpb);
    if (dyn >= 0) {
        g_dyn_slot_gpb = dyn;
        if (dyn == hardcoded) {
            diag("vtable: gpb_slot dynamic=%d hardcoded=%d MATCH", dyn, hardcoded);
        } else {
            diag("vtable: gpb_slot dynamic=%d hardcoded=%d DRIFT -- using dynamic",
                 dyn, hardcoded);
        }
    } else {
        diag("vtable: gpb_slot dynamic-scan MISS (rva_hint=0x%llx) -- falling back to hardcoded %d",
             (unsigned long long)g_rva_gpb, hardcoded);
        /* v1.6.5: dump full known-symbol map for pLayer so support can
         * see what's ACTUALLY at each slot on this Windows build. */
        dump_known_slots_in_vtable("pLayer(gpb)", layer_vtbl);
    }
}
static void discover_gd3d_slot_once(void **layer_vtbl, int hardcoded) {
    static volatile LONG s_done = 0;
    if (InterlockedCompareExchange(&s_done, 1, 0) != 0) return;
    int dyn = find_vtable_slot_by_rva(layer_vtbl, g_rva_gd3d);
    if (dyn >= 0) {
        g_dyn_slot_gd3d = dyn;
        if (dyn == hardcoded) {
            diag("vtable: gd3d_slot dynamic=%d hardcoded=%d MATCH", dyn, hardcoded);
        } else {
            diag("vtable: gd3d_slot dynamic=%d hardcoded=%d DRIFT -- using dynamic",
                 dyn, hardcoded);
        }
    } else {
        diag("vtable: gd3d_slot dynamic-scan MISS (rva_hint=0x%llx) -- falling back to hardcoded %d",
             (unsigned long long)g_rva_gd3d, hardcoded);
        /* v1.6.5: dump layer_vtbl once -- same vtable as gpb, but the gpb
         * dump already fired on its MISS. Only dump here if gpb HIT
         * (rare -- both hints would then be plausibly present). Cheap. */
        if (g_dyn_slot_gpb >= 0) {
            dump_known_slots_in_vtable("pLayer(gd3d)", layer_vtbl);
        }
    }
}
static void discover_acc_slot_once(void **res_vtbl, int hardcoded) {
    static volatile LONG s_done = 0;
    if (InterlockedCompareExchange(&s_done, 1, 0) != 0) return;
    int dyn = find_vtable_slot_by_rva(res_vtbl, g_rva_acc);
    if (dyn >= 0) {
        g_dyn_slot_acc = dyn;
        if (dyn == hardcoded) {
            diag("vtable: acc_slot dynamic=%d hardcoded=%d MATCH", dyn, hardcoded);
        } else {
            diag("vtable: acc_slot dynamic=%d hardcoded=%d DRIFT -- using dynamic",
                 dyn, hardcoded);
        }
    } else {
        diag("vtable: acc_slot dynamic-scan MISS (rva_hint=0x%llx) -- falling back to hardcoded %d",
             (unsigned long long)g_rva_acc, hardcoded);
        /* v1.6.5: res_vtbl is a DIFFERENT vtable than layer_vtbl (belongs
         * to the buffer object returned by GetPhysicalBackBuffer). Dump it
         * so support can see if slot 19 really has GetD3D11Resource or not. */
        dump_known_slots_in_vtable("res_vtbl(acc)", res_vtbl);
    }
}

/* Convenience -- returns the slot to USE (dynamic if discovered, else hardcoded). */
static inline int effective_gpb_slot(void)  { int d = g_dyn_slot_gpb;  return d >= 0 ? d : GPB_SLOT;  }
static inline int effective_gd3d_slot(void) { int d = g_dyn_slot_gd3d; return d >= 0 ? d : GD3D_SLOT; }
static inline int effective_acc_slot(void)  { int d = g_dyn_slot_acc;  return d >= 0 ? d : ACC3_SLOT; }

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
/* v1.7.2 (2026-07-17): default HIDDEN on fresh inject.
 *
 * Root cause of the "app flickers like HELL when I type" report:
 * dwm_hooks.c's PN detour forces PN=TRUE + fires ScheduleCompositionPass
 * whenever `ui_is_visible()`. That keeps DWM in composition mode, which
 * BLOCKS DirectComposition apps (Chrome, Cursor, Electron, Slack,
 * Discord, VS Code) from taking their direct-flip fast path. Every
 * keystroke redraw of the typed-into app falls back to the composited
 * swapchain -> visible strobe on each key.
 *
 * v6.3 documented this trade-off: "when overlay IS visible we NEED
 * composition (that's how our pixels get on screen) so the trade-off
 * is inherent". Only fix path is to keep the overlay HIDDEN by default
 * so DirectComp apps direct-flip. User presses TOGGLE (hold Right-Shift
 * in stealth, or Ctrl+Alt+G) to peek at answers, then hides again.
 *
 * ASK / stream / copy still work silently while hidden -- invariant #120
 * ensures the chat append + pending handlers DON'T force-show. The
 * whole stealth workflow: triple-tap ` -> ASK fires invisibly -> wait
 * a beat -> triple-tap A -> answer in clipboard -> paste. Zero pixels
 * on screen. */
static bool             g_visible     = true;   /* v11.2.4 (2026-07-24) -- LO ask: show overlay immediately on inject (was default HIDDEN -- required Ctrl+B toggle). Bypassify parity. */
static bool             g_imgui_inited= false;

/* v1.7.10 (2026-07-24) -- LEAN MODE.
 *
 * When ON, draw_chat_window skips ImGui::Begin/End and renders the
 * overlay via ImGui::GetForegroundDrawList()->AddRectFilled + AddText.
 * Matches Bypassify's exact render pattern (RPM-verified: BP's
 * ImGuiContext::Windows.Size = 1, single unnamed entry -- proving they
 * bypass the Begin/End window system entirely).
 *
 * Trade-offs given up:
 *   - Chat scrollback (only last AI reply shown)
 *   - MD / LaTeX rendering (raw text only)
 *   - Per-bubble copy buttons
 *   - Code block chrome
 *   - Styled title bar / borders
 *
 * Kept:
 *   - Overlay position / size / alpha (respects hotkey nudges)
 *   - Theme colors (dark or light)
 *   - Show/hide via Ctrl+B
 *
 * Toggled at runtime via SVC_HK_LEAN_TOGGLE (Ctrl+Shift+Alt+M) or
 * via svchelper UI at inject time. */
static volatile LONG    g_lean_mode   = 0;

/* v12 (2026-07-24) -- ARCHITECTURAL REFACTOR TO BP PARITY.
 *
 * Deep Ghidra decomp of Bypassify (bp-architecture-full-picture.md
 * memory note) proved BP uses PROGMAN's HWND as a fake parent Win32
 * window + standard ImGui-Win32 backend. That's why their input works
 * per-frame + why DWM's dirty-region tracker knows about them + why
 * they don't ghost-trail. Our custom no-HWND setup was architecturally
 * different -- every surface tweak (trail-erase, hide-grace, RTV swap,
 * opaque-lock, message pump) was fighting this gap and losing.
 *
 * v12 architectural change:
 *   1. Find Progman's HWND at first render (matches BP exactly).
 *   2. ImGui_ImplWin32_Init(g_fake_hwnd) alongside ImGui_ImplDX11_Init.
 *   3. Per-frame: ImGui_ImplWin32_NewFrame() BEFORE ImGui::NewFrame()
 *      updates io.DisplaySize + cursor + kbd from Win32 API.
 *   4. Progman-recovery: every frame check IsWindow(g_fake_hwnd); if
 *      invalid, teardown + refind + reinit (matches BP FUN_180008AC0's
 *      "[RECOVERY] Progman changed" branch).
 *   5. Message pump per-frame is now SAFE because ImGui_ImplWin32
 *      installs its own WndProc handler that routes events cleanly.
 *
 * WHY THIS IS RIGHT: DWM's compositor treats Progman as a real window
 * with a rect it tracks. Rendering into DWM's layer texture at
 * coordinates INSIDE that rect means DWM's next dirty-tracking pass
 * knows to re-composite the area from source apps. Old-position
 * pixels get naturally overwritten. Same reason BP has zero ghost. */
static HWND             g_fake_hwnd            = NULL;
static bool             g_win32_backend_inited = false;
static ULONGLONG        g_last_progman_check   = 0;
static DWORD            g_progman_pid          = 0;   /* owning explorer PID of g_fake_hwnd */
/* v3.4 (P0 explorer-restart fix, BP-1:1). Set by ensure_fake_hwnd_valid when
 * Progman changes (shell restart). Consumed at the TOP of ui_present_frame (on
 * the DWM compose thread) to do a FULL client teardown + fresh re-acquire --
 * exactly Bypassify's Uninitialize->Initialize recovery. Doing it on the compose
 * thread (not a worker) is why BP is reliable and our old worker-thread rearm
 * was flaky (it raced the compose thread). */
static volatile LONG    g_needs_client_reinit  = 0;

/* v3.6.1 (P0 explorer-stays-dead fix, 2026-09-21):
 * Query the image basename of `pid`. Returns:
 *   +1  == definitively IS explorer.exe (proof)
 *   -1  == definitively is NOT explorer.exe (proof)
 *    0  == indeterminate (OpenProcess failed / query failed / freshly-
 *          spawned process before its DACL settles)
 *
 * The caller (ensure_fake_hwnd_valid) rejects ONLY on -1. Rejecting on
 * indeterminate (0) is a false-negative trap that permanently rejects
 * legitimate fresh explorer.exe pids -- observed live 2026-09-21 when
 * a freshly-spawned explorer at pid 9544 got rejected 1.5s after start
 * because PROCESS_QUERY_LIMITED_INFORMATION transiently failed on it.
 *
 * Empirical repro of the +1/-1 win case (2026-09-21 with
 * AutoRestartShell=0 held): killing explorer.exe left a RuntimeBroker.exe
 * (pid 15636) with a WorkerW-class window that FindWindowA("WorkerW",
 * NULL) matched. Old code accepted it, ran the full teardown+reinit
 * against RuntimeBroker's HWND, fired the canonical "ImGui READY --
 * overlay should render this frame" log line, but pixels went to a
 * surface DWM wasn't scanning out. Overlay silently invisible while
 * every diag marker screamed "recovered". Fix: reject on definitive -1
 * only, so RuntimeBroker is caught but a fresh explorer isn't.
 *
 * PROCESS_QUERY_LIMITED_INFORMATION is *usually* granted on user-session
 * processes from DWM's SYSTEM-adjacent context, but the handle-table
 * DACL settles a few 100ms after CreateProcess -- until then OpenProcess
 * can fail spuriously. Fresh-boot explorer + first-time-launch explorer
 * both hit this. */
static int is_process_explorer_ternary(DWORD pid) {
    if (pid == 0) return -1;   /* NULL owner: definitely not a shell */
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return 0;         /* indeterminate: transient DACL race */
    wchar_t path[MAX_PATH]; DWORD sz = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(hp, 0, path, &sz);
    CloseHandle(hp);
    if (!ok || sz == 0) return 0;   /* indeterminate: query failed */
    /* Extract basename (last component after '\' or '/'). */
    const wchar_t *base = path;
    for (DWORD i = 0; i < sz; i++) {
        if (path[i] == L'\\' || path[i] == L'/') base = &path[i + 1];
    }
    /* Case-insensitive compare to L"explorer.exe". */
    static const wchar_t kExplorer[] = L"explorer.exe";
    int i = 0;
    while (base[i] && kExplorer[i]) {
        wchar_t a = base[i], b = kExplorer[i];
        if (a >= L'A' && a <= L'Z') a = (wchar_t)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = (wchar_t)(b - L'A' + L'a');
        if (a != b) return -1;
        i++;
    }
    return (base[i] == 0 && kExplorer[i] == 0) ? +1 : -1;
}

/* Progman-recovery: fired every frame from ui_present_frame. If our
 * fake HWND is null or destroyed, teardown ImGui-Win32 backend, refind
 * Progman, reinit. Throttled to once per ~500ms so we're not calling
 * IsWindow every vsync. */
static bool ensure_fake_hwnd_valid(void) {
    ULONGLONG now = GetTickCount64();
    /* v3.5 (P0 reliability): the old fast-path `if (IsWindow(g_fake_hwnd)) return`
     * MISSED explorer restarts whenever the new Progman reused the OLD HWND value
     * -- Windows recycles HWNDs (observed 0x1D040A reused across restarts), so
     * the 2nd/3rd explorer-kill never tripped the reinit and the overlay stayed
     * dead. BP-1:1 fix: poll FindWindow("Progman") on a ~200ms cadence and treat
     * a change in EITHER the HWND *or its owning process id* (explorer's PID) as
     * a shell restart. The PID change reliably catches the HWND-reuse case. */
    if ((now - g_last_progman_check) < 200) {
        return g_fake_hwnd != NULL;   /* between polls -- cheap */
    }
    g_last_progman_check = now;
    HWND newh = FindWindowA("Progman", "Program Manager");
    /* v3.6.1 (2026-09-21): dropped the FindWindowA("WorkerW", NULL)
     * fallback. Empirically it was the phantom-leak source -- UWP
     * broker processes (RuntimeBroker.exe, ShellExperienceHost) carry
     * WorkerW-class windows that satisfied the fallback probe after
     * the real shell died. Progman + "Program Manager" title is
     * uniquely explorer's shell window (registered by the explorer
     * runtime; no other process is documented to use that class+title
     * pair). If Progman is gone, the shell is gone -- wait 200ms for
     * the next poll rather than falling back to a class that's not
     * uniquely ours. The ternary owner-check below is defense-in-depth
     * for the pathological case where something DOES spoof Progman. */
    DWORD newpid = 0;
    if (newh) GetWindowThreadProcessId(newh, &newpid);
    /* v3.6.1: reject ONLY on definitive proof (-1) that the owner is
     * not explorer.exe. Indeterminate (0) = transient OpenProcess race
     * on freshly-spawned explorer whose handle DACL hasn't settled;
     * observed live 2026-09-21 when new explorer at pid 9544 got
     * false-rejected 1.5s after start. Treating indeterminate as
     * "trust the HWND" keeps recovery from stalling forever on that
     * transient. */
    if (newh) {
        int owner_check = is_process_explorer_ternary(newpid);
        if (owner_check == -1) {
            static DWORD s_last_rejected_pid = 0;
            if (newpid != s_last_rejected_pid) {
                diag("[RECOVERY] rejecting phantom Progman hwnd=%p owner_pid=%lu "
                     "(definitively NOT explorer.exe) -- waiting for real shell",
                     newh, (unsigned long)newpid);
                s_last_rejected_pid = newpid;
            }
            newh = NULL;
            newpid = 0;
        }
    }

    /* v3.6.2 (2026-09-21) -- ISO-DESKTOP TEARDOWN REGRESSION FIX.
     *
     * If Progman is missing AND the active input desktop is NOT Default,
     * we're on an isolated/secure desktop (SEB, custom proctor desktop,
     * our test probe, etc.) where there LEGITIMATELY is no Progman.
     * Don't treat that as a shell restart -- tearing down the ImGui-Win32
     * backend + calling ui_reinit() + rawin_restart() mid-iso-session drops
     * pipe events in flight, resets overlay position (visible to the user
     * as "snap backwards" during drag), and can miss hotkeys during the
     * ~350ms rebuild window.
     *
     * REGRESSION SOURCE: v3.6.1 (this file) dropped the
     * FindWindowA("WorkerW", NULL) fallback. Pre-v3.6.1, that fallback
     * accidentally papered over this bug because iso desktops usually
     * have SOME WorkerW-class window that satisfied the probe, so newh
     * ended up non-NULL and the reinit branch didn't fire. Post-v3.6.1,
     * newh is genuinely NULL on iso, and my code triggered the full
     * teardown+reinit every time the user switched to iso.
     *
     * Live-observed 2026-09-21 06:22 via desktop_switch.cpp probe:
     * slot table redump mid-iso-session, Ctrl+arrow hotkeys broken,
     * overlay drag position snapped back periodically. SEB happened to
     * work only because SEB's secure desktop has more windows around
     * that satisfied the pre-fix WorkerW fallback -- but that was luck,
     * not correctness.
     *
     * FIX: preserve current state (return cached HWND value) when Progman
     * is gone AND we're on a non-Default input desktop. When the user
     * returns to Default, either the real Progman reappears (normal
     * path handles it) or we transition to actual "shell dead" cleanly.
     * Only add the OpenInputDesktop query on the newh==NULL slow path
     * so hot-path (Progman found) is unchanged. */
    if (!newh) {
        HDESK cur = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
        if (cur) {
            char dname[64] = {0}; DWORD need = 0;
            BOOL got = GetUserObjectInformationA(cur, UOI_NAME,
                                                  dname, sizeof(dname), &need);
            CloseDesktop(cur);
            if (got && lstrcmpiA(dname, "Default") != 0) {
                static char s_last_iso_desk[64] = {0};
                if (lstrcmpiA(dname, s_last_iso_desk) != 0) {
                    lstrcpynA(s_last_iso_desk, dname, sizeof(s_last_iso_desk));
                    diag("[RECOVERY] input desktop '%s' (non-Default) + Progman absent "
                         "(expected on iso) -- preserving state, no teardown",
                         dname);
                }
                /* Keep g_fake_hwnd + g_progman_pid unchanged. Backend stays
                 * initialized. On return to Default, either the real Progman
                 * comes back (accepted by the normal path above) or newh is
                 * still NULL on Default (real shell death) and the reinit
                 * fires correctly. */
                return g_fake_hwnd != NULL;
            }
        }
    }

    /* Shell restart if the HWND changed, OR the owning explorer PID changed
     * (HWND reuse), OR our cached HWND went invalid. */
    BOOL restarted = (newh != g_fake_hwnd) || (newpid != g_progman_pid) ||
                     (g_fake_hwnd && !IsWindow(g_fake_hwnd));
    if (!restarted) {
        return g_fake_hwnd != NULL;   /* nothing changed */
    }

    /* v6.1.0 (2026-09-21) -- BLIP-DoS DEBOUNCE.
     *
     * A medium-IL attacker can taskkill+restart explorer.exe in a tight
     * loop. Each Progman change here triggers teardown + client_reinit,
     * which BP's proven recovery path costs ~3 frames of visible blip.
     * At 30Hz attacker rate (each kill+restart cycle ~30ms), we'd
     * blip ~5x/sec (capped by our 200ms poll cadence) = sustained
     * visible flicker = practical DoS of overlay visibility.
     *
     * v6.1.0 (AutoRestartShell=0 + sentinel Monitor-A gate) blocks the
     * KILL-ONLY attack (Windows won't respawn, so kills don't produce
     * fresh Progman = no reinit). But an attacker who ALSO explicitly
     * `CreateProcess`es explorer each cycle still triggers churn.
     *
     * Fix: rate-limit teardown itself. Between the first change and
     * `SHELL_TEARDOWN_COOLDOWN_MS` later, ignore further Progman flaps
     * completely. Attacker at 30Hz churn -> max 1 blip per 2s = 0.5Hz
     * blips. During the cooldown, backend retains stale HWND state; if
     * torn down, subsequent frames don't call ImGui_ImplWin32_NewFrame
     * (backend flag is false) so io.DisplaySize retains last-good
     * value -> overlay stays VISIBLE with stale-but-plausible layout,
     * just no mouse-coord tracking. When attacker stops for > cooldown,
     * next real Progman change gets processed cleanly (single blip,
     * back to healthy).
     *
     * Legitimate one-shot explorer restart: eats ~2s of stale state
     * before the ONE reinit fires. Acceptable tradeoff -- users rarely
     * restart explorer on purpose, and when they do a 2s recovery
     * delay is invisible next to explorer's own respawn latency. */
    static ULONGLONG g_last_shell_teardown_tick = 0;
    const ULONGLONG SHELL_TEARDOWN_COOLDOWN_MS = 2000;
    if (g_last_shell_teardown_tick != 0) {
        ULONGLONG since = now - g_last_shell_teardown_tick;
        if (since < SHELL_TEARDOWN_COOLDOWN_MS) {
            static ULONGLONG s_last_rl_log = 0;
            if (now - s_last_rl_log > 5000) {
                diag("[RECOVERY-RL] Progman flapped %p(pid %lu) -> %p(pid %lu) "
                     "but only %llu ms since last teardown (cooldown %llu ms) -- "
                     "deferring reinit to defeat blip-DoS. Overlay stays visible "
                     "with stale backend state during cooldown.",
                     g_fake_hwnd, (unsigned long)g_progman_pid,
                     newh, (unsigned long)newpid,
                     since, (ULONGLONG)SHELL_TEARDOWN_COOLDOWN_MS);
                s_last_rl_log = now;
            }
            return g_fake_hwnd != NULL;   /* keep current state unchanged */
        }
    }
    g_last_shell_teardown_tick = now;

    /* Progman changed (explorer restart, session switch, etc.) --
     * teardown Win32 backend, swap HWND, re-init on next frame. */
    if (g_win32_backend_inited) {
        diag("[RECOVERY] shell restart: Progman %p(pid %lu) -> %p(pid %lu); teardown Win32 backend",
             g_fake_hwnd, (unsigned long)g_progman_pid, newh, (unsigned long)newpid);
        ImGui_ImplWin32_Shutdown();
        g_win32_backend_inited = false;
        /* v3.4 (P0 fix, BP-1:1): a Progman swap while we already had a backend
         * means the shell (explorer) restarted and rebuilt the desktop's visual
         * tree, which silently drops our overlay from the scanned-out MPO plane
         * set. Flag a FULL client teardown + fresh re-acquire -- consumed at the
         * top of ui_present_frame ON THIS (compose) THREAD next frame. This is
         * exactly what Bypassify does (Uninitialize -> Initialize on Progman
         * change): release device/RTV/ImGui, then re-acquire the device +
         * swapchain fresh from the CURRENT layer + rebuild ImGui. Fully
         * in-process, no worker thread, no process spawn (OnVUE-safe). */
        InterlockedExchange(&g_needs_client_reinit, 1);
    } else if (!g_fake_hwnd && newh) {
        /* v3.6.1 (2026-09-21): silent-recovery diag. Backend was already
         * torn down (we transitioned to "no shell" earlier), and now a
         * fresh Progman appears. The main render body's
         * `!g_win32_backend_inited` branch will re-init ImGui-Win32 on the
         * next frame. Log so the recovery is traceable -- without this,
         * "shell came back" is silent and it looks like the payload
         * stayed dead in the tail. */
        diag("[RECOVERY] shell resumed: fresh Progman %p(pid %lu) -- backend rebuild next frame",
             newh, (unsigned long)newpid);
    }
    g_fake_hwnd   = newh;
    g_progman_pid = newpid;
    if (!g_fake_hwnd) return false;
    return true;
}
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
 *   - Ctrl+Alt+X on chat view -> set to 1 (hide messages, preserve them)
 *   - ui_chat_append_* -> set to 0 (new activity, show chat again)
 *   - Ctrl+Alt+N -> also implicitly resets (messages gone entirely) */
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
 * if loading fails -- everything still renders, just smaller / uglier.
 *
 * Base size 16px @ 1x DPI. Runtime scaling happens via
 * ImGuiIO::FontGlobalScale in draw_chat_window (screen_h/1080 factor
 * × user font-size hotkey multiplier). */
static ImFont *g_font_ui   = NULL;
static ImFont *g_font_mono = NULL;
/* v14c (2026-08-11): real icon font (Font Awesome 6 Solid), loaded
 * standalone so draw_icon can stamp crisp glyphs at any size. NULL =>
 * draw_icon falls back to hand-drawn vector icons. */
static ImFont *g_font_icons = NULL;
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
static float g_alpha    = 1.00f;   /* v11: default OPAQUE (was 0.94f) -- Bypassify-parity, zero trailing */
static float g_font     = 1.00f;   /* multiplicative on top of DPI-derived scale */

/* v1.7.8 (2026-07-24) -- TRAIL FIX via UNDERLYING-APP INVALIDATE.
 *
 * LO reported: overlay OVER the foreground-at-inject-time app = no
 * trails (that app repaints every frame -> DWM re-composites -> old
 * overlay pixels overwritten). Overlay OVER any static background
 * app = trails (no app invalidation -> DWM never re-composes those
 * pixels -> our old-position overlay pixels sit in the layer forever).
 *
 * Fix: track the LAST drawn overlay rect (screen coords). On any
 * geometry change (nudge / resize / cycle_corner / reset / toggle_
 * visible / hide) OR on ui_shutdown, call RedrawWindow(NULL, &rect,
 * NULL, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW) which
 * cascades a repaint through every top-level window overlapping the
 * old rect. That forces DWM to invalidate its layer compose at that
 * region -> underlying apps' fresh pixels overwrite our stale overlay
 * pixels -> trails gone.
 *
 * Rect is padded 32px on each side to cover ImGui window shadows
 * and any ~1-frame anti-aliased fringe. */
static RECT  g_last_overlay_rect = {0, 0, 0, 0};
static void invalidate_last_overlay_region(const char *why);   /* forward decl for callers above the def */

/* v1.7.8c (2026-07-24) -- GLIDE ANIMATION (Bypassify-parity, LO ask).
 *
 * BP's overlay glides across the screen; ours snapped instantly per
 * nudge. Fix: interpolate the DISPLAYED position toward the TARGET
 * position (g_offset_x/y) each frame with exponential ease-out.
 *
 * At 60Hz + 0.30 approach factor:
 *   frame 0: 0%  progress
 *   frame 1: 30%
 *   frame 2: 51%
 *   frame 3: 66%
 *   frame 4: 76%   (halfway feel around frame 2)
 *   frame ~8: ~95% (visually settled)
 * -> ~130ms total settling for a single 48px nudge, feels smooth without
 * being sluggish. Rapid Ctrl+arrow bursts extend the target smoothly;
 * displayed position tracks with a slight lag = the butter feel.
 *
 * Snap to target when within 0.5px so we don't float infinitely at
 * subpixel. -0.0f init lets first-render at fresh position without
 * a phantom glide from (0,0). */
static float g_disp_off_x = 0.0f;
static float g_disp_off_y = 0.0f;
static bool  g_disp_off_primed = false;

/* v1.7.4 (2026-07-23) -- GHOST FRAME / WINDOW MOVE FIX.
 *
 * User bug reports:
 *   1. "AI overlay" title bar renders 7-8 times horizontally stacked
 *      (screenshot showed "AI AI AI AI AI AI AI AI overlay") after
 *      the user nudged the overlay via Ctrl+Alt+Right several times.
 *   2. "Moving the window won't register until I hide it and open it
 *      again to see his new position" -- user moves overlay via nudge
 *      hotkey but the visible position doesn't update on-screen.
 *
 * Root cause: DWM's overlay-layer texture is NOT cleared between
 * frames. Every Present call:
 *   - Renders ImGui overlay AT CURRENT position INTO the layer texture
 *   - DWM composites the layer over the desktop
 *   - Next frame, layer texture STILL has the previous overlay pixels
 *   - We render at NEW position -> both old + new pixels visible
 *
 * Fix: track the "geometry generation" (bump every time position/size/
 * corner/alpha changes) + snapshot it in the Present path. When the
 * generation changed since the last successful draw, force a
 * ClearRenderTargetView(rtv, {0,0,0,0}) BEFORE ImGui renders. This
 * wipes the entire overlay layer to fully transparent, so only the
 * new frame's ImGui draws contribute -- no ghost from prior positions.
 *
 * SAFE because: DWM's overlay layer holds ONLY our overlay pixels
 * (verified by RE -- pLayer's backbuffer is dedicated to overlay
 * content, NOT desktop composite). Clearing to (0,0,0,0) is
 * semantically "no overlay pixels this frame" which DWM handles
 * correctly. If for some Windows build the layer were shared with
 * desktop content, we'd see the desktop flash -- but empirically the
 * layer is exclusive.
 *
 * NON-CHANGES-CLEAR: we ALSO clear on the first-ever draw and after
 * a visibility toggle so no stale pixels leak from a prior session
 * or a prior "hidden overlay" state. */
static volatile LONG g_geom_generation = 1;   /* bumped on every geometry change */
static void geom_bump(void) { InterlockedIncrement(&g_geom_generation); }

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

/* v11 (2026-07-24) -- Bypassify-parity theme + behavior flags.
 *   g_theme_pref: 0=dark, 1=light, 2=auto (poll AppsUseLightTheme every 2s)
 *   g_theme_effective: 0=dark, 1=light -- the CURRENT rendering theme after
 *                      auto-resolution. Consulted every frame by
 *                      draw_chat_window to pick color palette.
 *   g_overlay_flags: bitfield of SVC_OVFLAG_* (see shared/config_types.h).
 *                    Default SVC_OVFLAG_DEFAULTS on until launch config
 *                    overrides.
 *   g_trail_hist:    ring buffer of last N overlay rects, each with age
 *                    counter. On each frame we paint each entry with our
 *                    opaque WindowBg color via ImGui::GetBackgroundDrawList()
 *                    to overwrite trailing pixels from prior positions.
 *                    Entries age out after TRAIL_ERASE_FRAMES frames -- long
 *                    enough for DWM natural compose to catch up, short
 *                    enough to not leave a visible "solid navy tail".
 *
 * All accesses via Interlocked* -- read-hot from Present thread,
 * write-cold from ui_* handlers and the theme poll thread. */
static volatile LONG g_theme_pref      = 2;                       /* 0=dark, 1=light, 2=auto */
static volatile LONG g_theme_effective = 0;                       /* 0=dark, 1=light         */
static volatile LONG g_overlay_flags   = (LONG)SVC_OVFLAG_DEFAULTS;

/* v11.2 (2026-07-24) -- TRAIL_HIST_MAX 6->48 slots but FRAMES 12->3.
 * v11.2-a live test with 12 frames left a visible dark-navy "afterglow"
 * rectangle where the trail-erase rects hung around too long, forming
 * a solid opaque block behind the moving overlay. FRAMES=3 keeps the
 * erase paint alive for ~50ms @60Hz -- long enough to catch DWM's compose
 * lag but short enough that the user reads it as instant-invisible.
 * 48 slots still covers a rapid 12-nudge sequence without wrap. */
#define TRAIL_HIST_MAX      48
#define TRAIL_ERASE_FRAMES  3

struct trail_rect_t {
    float x, y, w, h;      /* rect in DWM layer coords (same as ImGui overlay coords) */
    LONG  frames_left;     /* atomic counter; 0 = slot empty                          */
};
static struct trail_rect_t g_trail_hist[TRAIL_HIST_MAX] = {};
static CRITICAL_SECTION    g_trail_cs;
static volatile LONG       g_trail_cs_inited = 0;
static float               g_last_pushed_x = -99999.0f;
static float               g_last_pushed_y = -99999.0f;
static float               g_last_pushed_w = 0.0f;
static float               g_last_pushed_h = 0.0f;

/* v11.2 (2026-07-24) -- HIDE GRACE for instant Ctrl+B hide.
 *
 * ROOT CAUSE OF v11.1 "hide takes too long" BUG: draw_chat_window
 * returns early on !g_visible, so nothing paints our region. But the
 * layer texture still holds the last-drawn overlay pixels until DWM's
 * next natural refresh (which may take many frames). User sees the
 * overlay "hang around" or "partially hide" for 100-500ms.
 *
 * FIX: on visibility -> hidden transition, seed the trail history with
 * the last overlay rect, and force draw_chat_window to CONTINUE
 * rendering the erase-paint pass (only the trail-erase rects, no
 * overlay content) for HIDE_GRACE_FRAMES. That forcibly wipes the
 * ghost pixels with opaque bg color. After grace expires, the
 * standard !visible early return kicks in and we stop entirely.
 * DWM's natural refresh handles the final visual cleanup from the
 * erase-paint's opaque bg back to app content. */
#define HIDE_GRACE_FRAMES  5
static volatile LONG g_hide_grace_frames = 0;

static void ensure_trail_cs(void) {
    if (InterlockedCompareExchange(&g_trail_cs_inited, 1, 0) == 0) {
        InitializeCriticalSection(&g_trail_cs);
    }
}

/* Push a trail-erase rect. Called from draw_chat_window when the rendered
 * rect differs from the previous frame's rect (i.e. overlay moved/resized).
 * Cheap: linear scan of TRAIL_HIST_MAX small slots + one CS. */
static void trail_push_rect(float x, float y, float w, float h) {
    if (!(InterlockedCompareExchange(&g_overlay_flags, 0, 0) & SVC_OVFLAG_TRAIL_ERASE))
        return;   /* feature disabled */
    ensure_trail_cs();
    EnterCriticalSection(&g_trail_cs);
    /* Find empty slot OR oldest slot (min frames_left). */
    int   victim = 0;
    LONG  min_left = 0x7FFFFFFF;
    for (int i = 0; i < TRAIL_HIST_MAX; i++) {
        if (g_trail_hist[i].frames_left <= 0) { victim = i; break; }
        if (g_trail_hist[i].frames_left < min_left) {
            min_left = g_trail_hist[i].frames_left;
            victim = i;
        }
    }
    g_trail_hist[victim].x = x;
    g_trail_hist[victim].y = y;
    g_trail_hist[victim].w = w;
    g_trail_hist[victim].h = h;
    g_trail_hist[victim].frames_left = TRAIL_ERASE_FRAMES;
    LeaveCriticalSection(&g_trail_cs);
}

/* Windows registry polling for auto theme (called ~every 2s from the
 * DWM Present hook; cost = single RegQueryValue, sub-microsecond). */
static int query_windows_apps_use_light_theme(void) {
    HKEY hk = NULL;
    DWORD val = 0, sz = sizeof(val);
    /* Personalize is under HKCU -- but payload runs in DWM's session which
     * is SYSTEM. DWM impersonates the interactive user for Personalize
     * reads via HKEY_CURRENT_USER but that may not always work from
     * an arbitrary thread. We try HKCU first, then fall back to reading
     * the interactive user's hive under HKU\<active-sid>. Failure -> 0
     * (dark theme) which matches the pre-v11 rendering. */
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hk, L"AppsUseLightTheme", NULL, NULL,
                             (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
            RegCloseKey(hk);
            return val ? 1 : 0;
        }
        RegCloseKey(hk);
    }
    return 0;   /* dark theme default when we can't read */
}

/* v1.3 (2026-07-07): per-frame alpha multiplier -- snapshotted from
 * g_alpha at the top of draw_chat_window and used by nested
 * renderers (draw_chat_bubble, md_render_tinted_block, code/math
 * block wrappers) to scale their INTERIOR background + border alphas.
 *
 * BUG WE'RE FIXING: before this global, bubble bg was hardcoded to
 * alpha=0.95, code-block bg was 0.98, math-block bg was 0.98. The
 * outer ImGui window's WindowBg respected g_alpha but everything
 * INSIDE was near-opaque. User set alpha=0.20 and got a very
 * transparent frame with almost-opaque chat bubbles inside -- the
 * "transparency only applies to the edges, not the chat box" report.
 *
 * Threading model: draw_chat_window is called from the DWM Present
 * detour on the compositor thread. Every downstream call chain
 * (draw_chat_bubble, md_render, md_render_code_block,
 * md_render_math_display, md_render_tinted_block) runs synchronously
 * on that same thread. No concurrent access -- a plain static
 * suffices, no atomic needed.
 *
 * Contract: draw_chat_window MUST set g_frame_alpha_mul at the top
 * of every frame. Downstream renderers read it via with_alpha_mul().
 * If a future call site is added that renders bubbles/blocks OUTSIDE
 * draw_chat_window, it MUST set g_frame_alpha_mul too. */
static float g_frame_alpha_mul = 1.0f;

/* Return `c` with its alpha channel multiplied by g_frame_alpha_mul.
 * Applied to bubble bg + border, code/math block bg + border, and
 * button colors -- everything that visually constitutes the "chat
 * box container" so the whole container respects user transparency
 * uniformly. Body TEXT is deliberately NOT scaled -- text alpha
 * scaling below ~0.5 makes prose unreadable, which is worse UX than
 * having text render at full opacity against a partially-transparent
 * background. */
static inline ImVec4 with_alpha_mul(ImVec4 c) {
    /* v11.2.1 (2026-07-24) -- kept snap-to-opaque semantics: at user's
     * 100% opacity slider position, force all bg/border/chrome colors
     * to alpha=1.0 so bubble/code/math bgs (designed at 0.85/0.98/etc)
     * don't stay visibly translucent inside an otherwise-opaque overlay.
     * This mirrors Bypassify's opaque solid look. Below 0.99 we scale
     * proportionally so translucent modes still work as before. */
    if (g_frame_alpha_mul >= 0.99f) c.w = 1.0f;
    else                            c.w *= g_frame_alpha_mul;
    return c;
}

/* ---------- Fullscreen-layer discovery ---------- *
 * DWM's COverlayContext::Present fires many times per frame -- once per
 * layer. Cursor overlay is 32x32, tooltips are ~100x30, etc. We only
 * want to render into the layer that represents the physical display
 * output (which for a single-monitor 1920x1080 setup is the 1920x1080
 * layer). We track the largest layer we've seen and only render there. */
static UINT g_target_w = 0;   /* Largest layer dimensions we've seen. */
static UINT g_target_h = 0;
static ID3D11Texture2D *g_target_tex = nullptr;  /* Last texture matching target. */

/* Frame dedup -- Present is called PER LAYER by DWM. Even after size gate
 * multiple ~fullscreen layers can pass through in the same compose cycle
 * (LDB main + LDB modal + full-screen overlay window). We must draw the
 * chat overlay ONCE per frame or the user sees duplicates ghosting into
 * each other. Track last draw tick; skip if <FRAME_DEDUP_MS since.
 *
 * Threshold: 3ms. Detailed rationale + refresh-rate table lives in the
 * v1.3 TRANSPARENCY FLICKER FIX comment below (right above the tick
 * comparison in ui_present_frame). Do not restore 12ms -- that broke
 * every monitor >= 90Hz. */
#define FRAME_DEDUP_MS 3
static ULONGLONG g_last_draw_tick = 0;

/* Reply-pane scroll accumulator -- hotkey handler adds delta, next
 * draw_chat_window frame calls ImGui::SetScrollY with the accumulated
 * amount then resets. Positive = scroll down toward end, negative =
 * scroll up toward top. Auto-repeat produces continuous scroll. */
static volatile LONG g_reply_scroll_pending = 0;

/* Chat input state -- user types via WH_KEYBOARD_LL feeding into
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

/* ── Cross-process chat-state export (v3.0.2, 2026-09-21) ──────────
 *
 * On the isolated desktop the payload can't consume events via its LL
 * keyboard hook (we're not running on that desktop). The winlogon-hosted
 * wl_input helper installs its OWN WH_KEYBOARD_LL on the iso desktop
 * and needs to know when to swallow keys (during chat-typing mode).
 *
 * Cross-process signal: a NULL-DACL named event named via obf_event_iso_chat()
 * (GUID-per-install, statistically indistinguishable from Windows/COM
 * events). Set when g_chat_active flips to 1; reset when it flips to 0.
 * Helper's LL hook does a fast WaitForSingleObject(ev, 0) per key event
 * to decide consume vs pass-through -- no IPC / no allocation, safe
 * from the LL callback's fast-return constraint. */
static HANDLE g_chat_state_event = NULL;
static void chat_state_export(void) {
    if (!g_chat_state_event) {
        SECURITY_DESCRIPTOR sd;
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);   /* NULL DACL */
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa); sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = &sd;
        /* Convert obf_event_iso_chat()'s ANSI name to wide for CreateEventW. */
        const char *nm_a = obf_event_iso_chat();
        wchar_t nm_w[128] = {0};
        for (int i = 0; nm_a[i] && i < 127; i++) nm_w[i] = (wchar_t)nm_a[i];
        g_chat_state_event = CreateEventW(&sa, TRUE /*manual reset*/,
                                          FALSE /*initial*/, nm_w);
    }
    if (g_chat_state_event) {
        if (g_chat_active) SetEvent(g_chat_state_event);
        else               ResetEvent(g_chat_state_event);
    }
}

/* ================================================================== *
 * Persistent overlay state -- save/restore across sessions.            *
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

/* Full path to persistence file. Writable location -- SVC_INSTALL_DIR
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

/* Throttled flush -- called from ui_present_frame every N frames. */
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
 * Version-tolerant reader (Bypassify parity -- they carry v5->v8
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
    0,   /* v0 -- invalid */
    40,  /* v1 -- magic+version + visible/corner/offX/offY/extraW/extraH/alpha/font */
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
        /* Need at least magic+version -- 8 bytes. */
        CloseHandle(h); return;
    }
    CloseHandle(h);

    unsigned int magic = 0, version = 0;
    memcpy(&magic,   buf + 0, 4);
    memcpy(&version, buf + 4, 4);
    if (magic != STATE_MAGIC) return;
    if (version < 1) return;
    /* Reject files from a FUTURE version -- we can't safely read them. */
    if (version > (unsigned int)STATE_VERSION) return;

    /* Sanity: min bytes for this version. */
    unsigned int need =
        (version <= STATE_MAX_KNOWN_VERSION)
            ? STATE_SIZE_BY_VERSION[version]
            : 0;
    if (need == 0 || r < need) return;

    /* v1 fields -- always present in every version >= 1. */
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
    /* v13 (2026-08-10): alpha floor 0.20 -> 0.05 so persisted near-invisible
     * transparency survives across sessions (LO's "it doesnt stick" fix). */
    if (f_alpha < 0.05f || f_alpha > 1.00f)  f_alpha = 0.94f;
    if (f_font  < 0.60f || f_font  > 3.00f)  f_font  = 1.00f;

    /* v1.7.2 (2026-07-17): DELIBERATELY IGNORE persisted visibility.
     * Fresh inject ALWAYS starts hidden. Rationale documented at
     * g_visible default declaration -- DirectComp apps (Chrome/Cursor/
     * Electron) can't direct-flip while overlay is visible, which
     * makes every typed keystroke strobe the app the user is in.
     * Silently ignore `iv_visible` -- position/alpha/font/corner
     * still persist normally, only the visibility bit resets. User
     * hits TOGGLE to peek at answers when they want. */
    (void)iv_visible;
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
 * fullscreen layer captures via CopyResource -> staging -> Map -> WIC PNG,
 * then signals the event. The captured frame is what DWM has JUST
 * finished compositing for THIS frame -- i.e., exactly what's on screen
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

/* Convert R16G16B16A16_FLOAT (HDR) -> BGRA 8-bit. Ported from
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
     * RPC_E_CHANGED_MODE if thread already has different apartment --
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

    /* SHCreateMemStream returns a stream NOT backed by HGLOBAL -- so
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
            diag("wic: hg has zero size -- encode produced no output");
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

    /* Unified BGRA path: alloc a tightly-packed BGRA buffer so we can
     * (a) run the screenshot redactor over it in place and (b) feed WIC
     * a stable stride. HDR converts through convert_hdr_to_bgra; SDR
     * copies row-by-row from the GPU-owned pitched map. */
    UINT dst_pitch = w * 4;
    SIZE_T total = (SIZE_T)dst_pitch * h;
    unsigned char *bgra = (unsigned char *)malloc(total);
    if (!bgra) {
        diag("capture: BGRA malloc %llu FAILED", (unsigned long long)total);
        ctx->Unmap(staging, 0);
        staging->Release();
        if (g_cap_done_ev) SetEvent(g_cap_done_ev);
        return;
    }

    if (fmt == DXGI_FORMAT_R16G16B16A16_FLOAT) {
        diag("capture: HDR converting to BGRA (%llu bytes)",
             (unsigned long long)total);
        convert_hdr_to_bgra((const unsigned char *)mapped.pData, bgra,
                            w, h, mapped.RowPitch, dst_pitch);
    } else {
        for (UINT y = 0; y < h; y++) {
            memcpy(bgra + (SIZE_T)y * dst_pitch,
                   (const unsigned char *)mapped.pData + (SIZE_T)y * mapped.RowPitch,
                   dst_pitch);
        }
    }

    /* Release GPU staging BEFORE the (potentially slow) redactor call --
     * OCR pass can take ~100-200 ms and there's no reason to keep the
     * texture map alive during that window. */
    ctx->Unmap(staging, 0);
    staging->Release();
    staging = nullptr;

    /* ── Screenshot redactor (opt-in via Electron toggle) ────────────
     *
     * When the user has flipped "Screenshot redactor" ON in svchelper's
     * settings, Electron spawns `sihost.exe --ocr-daemon`. That daemon
     * listens on \\.\pipe\svcldb_ocr_v1 and runs Windows.Media.Ocr ->
     * blacklist match -> paint black rects on the BGRA in place. Here
     * we simply pipe our BGRA through; the daemon returns painted
     * pixels which we then hand to the WIC PNG encoder as usual.
     *
     * When the toggle is OFF (default), the daemon isn't running and
     * `redact_bgra_via_pipe` returns -1 within milliseconds without
     * touching the buffer -- zero-cost passthrough.
     *
     * On any error (daemon crash, protocol mismatch, IO) the buffer
     * is guaranteed untouched -- a redactor that breaks screenshots
     * is worse than no redactor. */
    {
        DWORD t_rd0 = GetTickCount();
        int rd = redact_bgra_via_pipe(bgra, w, h);
        DWORD t_rd = GetTickCount() - t_rd0;
        if (rd >= 0) {
            diag("capture: redactor painted %d rects in %lums", rd, t_rd);
        } else if (rd != -1) {
            /* rd == -1 = daemon not running = feature off (silent) */
            diag("capture: redactor error rc=%d (buffer unchanged)", rd);
        }
    }

    enc_ok = encode_bgra_to_png(bgra, w, h, dst_pitch, &png, &png_len);
    diag("capture: encode returned enc_ok=%d png_len=%u", enc_ok, png_len);
    free(bgra);

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
 * SCREEN. DWM tracks dirty regions per-quadrant -- without a fullscreen
 * dirty signal, only the region the user just touched gets re-composed.
 * User reported "1/4 shows, then another 1/4 when I click somewhere
 * else" -- that's classic dirty-region-based partial re-composition.
 *
 * MULTI-PRONGED WAKE (each safe on its own -- belt and suspenders):
 *
 * 1. hooks_burst_wake -- internally fires ScheduleCompositionPass(0,-1)
 *    every 16ms for 300ms. Keeps DWM out of idle.
 *
 * 2. Synthetic mouse move events at 4 screen QUADRANT CENTERS via
 *    mouse_event(MOUSEEVENTF_MOVE, 0, 0). Zero-delta = cursor doesn't
 *    visually move, but each event registers input activity at the
 *    CURRENT cursor position. To hit all quadrants we cycle:
 *    - Save current cursor pos
 *    - SetCursorPos to (25%, 25%)
 *    - mouse_event(0, 0) -- register "input at Q1"
 *    - Repeat for Q2, Q3, Q4
 *    - Restore original cursor pos
 *    The cursor JUMPS briefly (microseconds) -- imperceptible.
 *
 * 3. RedrawWindow on desktop HWND with RDW_INVALIDATE|RDW_ALLCHILDREN.
 *    Documented API -- signals every top-level window to repaint. DWM
 *    processes this by re-composing all affected layer regions.
 *
 * Total blocking time on caller thread: ~2ms. */
static void wake_dwm_composition(void) {
    /* ORDER MATTERS (learned 2026-07-05 evening after regression report):
     *
     * Layer 1 FIRST: ghost-window fullscreen dirty push -- synchronous,
     * completes in ~1ms, forces DWM to re-composite the ENTIRE screen
     * on the very NEXT vsync tick. This gives us the "instant overlay"
     * feel on hotkey. Without it, hotkey state changes only appear as
     * partial quadrant redraws over multiple frames.
     *
     * Layer 2 (REMOVED v1.7.2 2026-07-17): cursor +1/-1 nudge.
     *   Originally added as ~50us defense-in-depth to register "input
     *   activity" so DWM's compositor wouldn't throttle refresh rate.
     *   BUT: SetCursorPos physically moves the mouse pointer, and this
     *   wake fires from ~15 different sites (chat append, finalize,
     *   status set, scroll, geometry ops). Any burst of them made the
     *   OS cursor visibly wiggle -- LO reported "the app flickering like
     *   HELL" every time an AI reply finalized OR he scrolled the
     *   overlay. hooks_ghost_wake + burst_wake already keep DWM out of
     *   idle without touching the cursor. The nudge was cosmetic
     *   belt-and-suspenders; the belt is enough.
     *
     * Layer 3 LAST: burst_wake -- asynchronous SCP loop for 300ms.
     * Keeps DWM's PN detour returning TRUE across the next ~18 frames
     * so any lazy invalidation gets forced through. Non-blocking to
     * the caller. */
    hooks_ghost_wake();
    /* v1.7.4.4 (2026-07-23) -- FLICKER MITIGATION.
     *
     * User reported "screen flickering black like a horror movie". Log
     * showed 500-1000 capture-render events per second under load,
     * combined with our 30-pump-over-300ms SCP forcing at every hotkey
     * fire = extreme GPU pressure on lower-end machines. The compositor
     * fell behind + presented intermediate BLACK frames during device-
     * state churn.
     *
     * Fix: reduce burst from 30/300ms -> 6/100ms. PN=TRUE + a single
     * SCP already keeps DWM composing every native vsync (Bypassify's
     * approach per RE); the extra 24 pumps per hotkey were pure
     * pressure with no visible benefit. Chat/AI/screenshot paths
     * that legitimately need long compose windows use their own
     * multi-fire scheme (ui_chat_stream_append throttles wakes to
     * 30Hz via wake_dwm_composition_typing already).
     *
     * Trade-off: on GPU-idle systems, hotkey-triggered state changes
     * take AT MOST one extra vsync (~16ms at 60Hz) to be visible.
     * Imperceptible. */
    hooks_burst_wake(6, 100, 16);
}

/* v1.6.5 (2026-07-17): light wake -- used exclusively for visibility
 * toggles (ui_toggle_visible). Skips the cursor-jitter (SetCursorPos
 * jump) and reduces burst_wake from 30/300ms -> 4/60ms. Rationale:
 * a visibility flip is a SINGLE-frame state change; Present hook
 * dispatches ui_present_frame every native vsync; 4 forced composites
 * within 60ms guarantees at least 3 natural Present fires bracket the
 * toggle. No fullscreen re-composite storm, no visible strobing.
 *
 * NOT used by chat/AI/screenshot paths -- those legitimately need the
 * heavy 300ms burst to render streaming content responsively. */
static void wake_dwm_composition_lite(void) {
    hooks_ghost_wake();               /* throttled to 10Hz internally */
    hooks_burst_wake(4, 60, 16);      /* light: 4 pumps over 60ms */
}

/* v1.7.2 (2026-07-17): typing-path wake. Chat feed handlers used to
 * call the heavy 30-pump/300ms wake per keystroke -- at even a modest
 * typing speed (5 keys/sec) the bursts overlapped and the overlay
 * strobed visibly ("flickers like HELL" -- user report).
 *
 * The typing wake throttles calls to at most one every 33ms (~30Hz)
 * and, when it fires, uses the LITE variant (4 pumps/60ms). DWM's
 * PN=TRUE hook already keeps the compositor running every native
 * vsync so a single lite pump per keystroke is enough -- we just need
 * to nudge composition to pick up the new chat buffer content on the
 * next natural Present, not force-drive it. */
static void wake_dwm_composition_typing(void) {
    static volatile LONG64 s_last_typing_wake_tick = 0;
    LONG64 now = (LONG64)GetTickCount64();
    LONG64 prev = InterlockedCompareExchange64(&s_last_typing_wake_tick, now, 0);
    /* First-call short-circuit: publish now, always wake. */
    if (prev != 0 && (now - prev) < 33) return;   /* throttle */
    InterlockedExchange64(&s_last_typing_wake_tick, now);
    wake_dwm_composition_lite();
}

/* When set, draw_chat_window skips ALL rendering for the next N
 * frames -- used to ensure our AI-request capture path grabs a CLEAN
 * layer texture (no overlay pixels from the CURRENT frame OR
 * persistent pixels from the PREVIOUS frame's overlay draw). */
static volatile LONG g_hide_frames_for_capture = 0;

/* Cached last-drawn overlay rect in screen pixels -- updated on every
 * draw_chat_window call. Read by ui_point_in_overlay() to answer
 * hit-testing questions from the LL mouse hook (mouse-wheel scroll).
 * If overlay hasn't drawn yet (fresh boot), all four values are 0
 * and ui_point_in_overlay returns 0. */
static volatile LONG g_last_overlay_x = 0;
static volatile LONG g_last_overlay_y = 0;
static volatile LONG g_last_overlay_w = 0;
static volatile LONG g_last_overlay_h = 0;
/* v14b: DPI-scaled resize-grip size (px), published each frame from
 * draw_chat_window and read by ui_point_in_resize_grip in the LL hook. */
static volatile LONG g_resize_grip_px = 30;
/* v14d: overlay corner-anchor margin (px), published each frame so
 * ui_resize_begin can convert to a top-left anchor without moving. */
static volatile LONG g_overlay_margin_px = 32;
/* v16: chrome-collapse (focus mode). 1 = hide header + footer so only the
 * chat shows; a chevron toggles it. Render-thread only. */
static volatile LONG g_chrome_collapsed = 0;

/* Exported to rawinput_hook.c so the LL mouse hook (WH_MOUSE_LL) can
 * decide whether to consume a WM_MOUSEWHEEL and route it to
 * ui_scroll_reply. Returns 1 iff the overlay is visible AND (x,y) is
 * inside its currently-drawn rect. Safe to call from any thread.
 *
 * v15.1 -- also returns 1 when the OVERLAY IS HIDDEN and (x,y) is
 * inside the AutoSolver dot's currently-drawn rect. This lets the LL
 * hook eat clicks on the dot so our drag/resize/tap state machine in
 * draw_answer_dot can respond, without needing rawinput_hook.c to
 * learn about a second hit-test surface. (Overlay and dot are mutually
 * exclusive by design -- see draw_answer_dot's dot_hide_when_overlay
 * gate -- so overloading one hit-test is safe.) */
extern "C" int ui_point_in_dot(int x, int y);
extern "C" int ui_point_in_overlay(int x, int y) {
    if (ui_is_visible()) {
        LONG lx = g_last_overlay_x;
        LONG ly = g_last_overlay_y;
        LONG lw = g_last_overlay_w;
        LONG lh = g_last_overlay_h;
        if (lw <= 0 || lh <= 0) return 0;
        return (x >= lx && x < lx + lw && y >= ly && y < ly + lh) ? 1 : 0;
    }
    /* Overlay hidden -> the AutoSolver dot may be showing instead. */
    return ui_point_in_dot(x, y);
}

/* v14 (2026-08-11): overlay MOUSE-INTERACTIVITY plumbing.
 *
 * g_ui_mouse_left_down -- authoritative left-button LEVEL, published by
 *   the LL mouse hook (rawinput_hook.c). Fed into ImGui io.MouseDown[0]
 *   every frame in ui_present_frame so widgets (slider/buttons/combo)
 *   are actually clickable. The DX11/Win32 backend feeds cursor POSITION
 *   (from the Progman hwnd) but NEVER sees button events -- clicks route
 *   to whatever app owns the window under the cursor, not our overlay --
 *   so without this the widgets would be hover-only.
 *
 * g_mouse_over_widget -- set each frame to (IsAnyItemHovered ||
 *   IsAnyItemActive); read by the LL hook so a press that lands on a
 *   widget is handed to ImGui instead of starting a window-drag. */
static volatile LONG g_ui_mouse_left_down = 0;
static volatile LONG g_mouse_over_widget  = 0;

/* v3.0.1 (SEB Arch B): forced cursor position. On a secure (SEB) desktop the
 * compose thread's GetCursorPos is wrong for that desktop, so the winlogon
 * input helper feeds the real position here (via rawinput_hook's pipe handler)
 * and the compose thread uses it instead of GetCursorPos when active. */
static volatile LONG g_forced_mouse_active = 0;
static volatile LONG g_forced_mouse_x = 0;
static volatile LONG g_forced_mouse_y = 0;
extern "C" void ui_set_forced_mouse(int active, int x, int y) {
    InterlockedExchange(&g_forced_mouse_x, x);
    InterlockedExchange(&g_forced_mouse_y, y);
    InterlockedExchange(&g_forced_mouse_active, active ? 1 : 0);
}

extern "C" void ui_set_mouse_left_down(int down) {
    InterlockedExchange(&g_ui_mouse_left_down, down ? 1 : 0);
}
/* v15.1.11 -- accessor for the poll thread's stuck-latch unstick. */
extern "C" int ui_mouse_left_down_get(void) {
    return InterlockedCompareExchange(&g_ui_mouse_left_down, 0, 0) != 0;
}
extern "C" int ui_mouse_over_widget(void) {
    return (int)InterlockedCompareExchange(&g_mouse_over_widget, 0, 0);
}

/* v14 (2026-08-11): expose theme preference (0=dark 1=light 2=auto) so the
 * HOME hub's theme toggle can cycle from the current value. */
extern "C" int ui_get_theme_pref(void) {
    return (int)InterlockedCompareExchange(&g_theme_pref, 0, 0);
}

/* v14d (2026-08-11): ANY-corner RESIZE GRIP hit-test. Returns which grip
 * the point (screen px) is in: 0 none, 1 TL, 2 TR, 3 BL, 4 BR. Each grip
 * is a ~grip-px square at a corner with a little slack OUTSIDE the edge so
 * grabbing the very corner works. Read by the LL mouse hook. */
extern "C" int ui_point_in_resize_grip(int x, int y) {
    if (!ui_is_visible()) return 0;
    LONG lx = g_last_overlay_x, ly = g_last_overlay_y;
    LONG lw = g_last_overlay_w, lh = g_last_overlay_h;
    if (lw <= 0 || lh <= 0) return 0;
    int grip = (int)InterlockedCompareExchange(&g_resize_grip_px, 0, 0);
    if (grip < 18) grip = 18;
    int tol = grip / 3;
    int L = (int)lx, R = (int)(lx + lw), Tp = (int)ly, B = (int)(ly + lh);
    int inL = (x >= L - tol && x <= L + grip);
    int inR = (x >= R - grip && x <= R + tol);
    int inT = (y >= Tp - tol && y <= Tp + grip);
    int inB = (y >= B - grip && y <= B + tol);
    if (inR && inB) return 4;   /* bottom-right */
    if (inL && inB) return 3;   /* bottom-left  */
    if (inR && inT) return 2;   /* top-right    */
    if (inL && inT) return 1;   /* top-left     */
    return 0;
}

/* v14d: called once when a resize grip is grabbed. Snaps the overlay to a
 * TOP-LEFT anchor WITHOUT moving it (offset chosen so the recomputed pos
 * equals the current pos), which makes the per-corner resize math trivial
 * and identical regardless of the previous corner anchor. */
extern "C" void ui_resize_begin(void) {
    LONG px = InterlockedCompareExchange(&g_last_overlay_x, 0, 0);
    LONG py = InterlockedCompareExchange(&g_last_overlay_y, 0, 0);
    LONG mg = InterlockedCompareExchange(&g_overlay_margin_px, 0, 0);
    /* g_ui_cs is already initialized: a resize can only start after the
     * overlay has drawn (grip hit-test needs g_last_overlay_*), and draw
     * calls ensure_cs() every frame. */
    EnterCriticalSection(&g_ui_cs);
    g_corner   = 1;                  /* top-left anchor: pos = margin + off */
    g_offset_x = (int)(px - mg);
    g_offset_y = (int)(py - mg);
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    geom_bump();
    wake_dwm_composition();
}

/* v14d: per-corner drag resize (assumes ui_resize_begin snapped us to a
 * top-left anchor). Keeps the OPPOSITE corner visually fixed:
 *   BR: grow by (dx,dy), TL fixed.   TL: shrink, BR fixed (move origin).
 *   TR: width+/height-, BL fixed.    BL: width-/height+, TR fixed. */
extern "C" void ui_resize_drag_corner(int corner, int dx, int dy) {
    switch (corner) {
    case 4: ui_resize( dx,  dy);                       break;  /* BR */
    case 1: ui_resize(-dx, -dy); ui_nudge(dx, dy);     break;  /* TL */
    case 2: ui_resize( dx, -dy); ui_nudge(0,  dy);     break;  /* TR */
    case 3: ui_resize(-dx,  dy); ui_nudge(dx, 0);      break;  /* BL */
    default: break;
    }
}

/* v14: fire a hotkey action from an on-screen control (bridge in dllmain.c). */
extern "C" void ui_action_fire(int action);

/* Capture-when: 0 = BEFORE overlay draw (AI-request path, clean shot),
 *               1 = AFTER  overlay draw (debug-capture path, includes
 *                   overlay pixels for visual verification). */
static volatile LONG g_cap_when_after_overlay = 0;

/* Forward decl -- g_bmp_request is defined further down but the
 * exporter below needs it. Both symbols have static linkage in
 * this TU so the declaration+definition must both be `static`. */
extern volatile LONG g_bmp_request;

/* Exported to dwm_hooks.c so the Present detour knows NOT to skip
 * the overlay draw during a debug-capture cycle. */
extern "C" int svcldb_debug_capture_wants_overlay(void) {
    return (g_cap_request || g_bmp_request) && g_cap_when_after_overlay == 1;
}

/* Internal capture entry point -- `hide_overlay` = 1 for AI-request
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
        /* Not done yet -- poke DWM again in case it went idle. */
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

/* Public: AI-request capture -- HIDES overlay for clean layer shot. */
extern "C" int ui_capture_screen_png(unsigned char **png_out, unsigned int *len_out,
                                     unsigned int timeout_ms) {
    return ui_capture_impl(png_out, len_out, timeout_ms, 1);
}

/* Public: debug capture -- INCLUDES overlay pixels (for visual
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
 * hooksdll's proven approach -- succeeds from DWM's process context
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
 * No COM, no WIC -- just raw file I/O. Works from ANY thread/context. */
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
         * pre-lock -- no other threads have any state ref yet. */
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

    /* New activity -- cancel home-forced mode so if user opens the
     * overlay later they land on the chat view (not the empty cheat-
     * sheet). Only meaningful WHILE the overlay is visible; harmless
     * otherwise. */
    InterlockedExchange(&g_home_view_forced, 0);

    /* NOTE: this function INTENTIONALLY does NOT update
     * g_last_reply_snapshot even for AI messages. That way system
     * toasts / debug messages appended via ui_set_reply don't clobber
     * the "last real reply" that Ctrl+Alt+C / +A / +Shift+C target.
     * Real AI answers flow through ui_chat_set_reply_of_pending
     * which DOES update the snapshot. */

    /* v1.6.4 (2026-07-15): DO NOT auto-show the overlay on new
     * message. Preserve current g_visible state.
     *
     * User feedback (2026-07-15): "keep the overlay hidden even if
     * you clicked the shortcut to answer and the students them self
     * can show/hide it. Because at his current state its kinda nerves
     * rocking if someone passing saw it lol"
     *
     * Rationale: users hiding the overlay for stealth expect it to
     * STAY hidden. Auto-showing on Ctrl+Shift+Space (Ask) defeats the
     * purpose -- someone walking by mid-exam sees the overlay flash
     * on-screen. New behavior: message appends silently; user hits
     * Ctrl+Alt+G to view OR Ctrl+Alt+C to copy answer to clipboard
     * without ever showing the overlay. If overlay was ALREADY
     * visible when the message arrived, it stays visible and the
     * message renders normally in-view (backwards-compat for users
     * who prefer the running-conversation flow). */
    wake_dwm_composition();
    diag("chat: appended role=%d len=%zu (visibility preserved: %d)",
         role, strlen(text), (int)g_visible);
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

    /* New AI turn starting -- cancel home-forced so IF the user opens
     * the overlay they land on the chat view. Only matters when the
     * overlay becomes visible. */
    InterlockedExchange(&g_home_view_forced, 0);

    /* v1.6.4: DO NOT auto-show (see ui_chat_append_message for full
     * rationale). Preserve current visibility. Stream flows silently
     * if overlay was hidden. User hits Ctrl+Alt+G to view OR
     * Ctrl+Alt+C to copy answer to clipboard. */
    wake_dwm_composition();
    diag("chat: pending id=%d (visibility preserved: %d)",
         id, (int)g_visible);
    return id;
}

extern "C" void ui_chat_stream_append(int msg_id, const char *chunk, size_t len) {
    if (!chunk || len == 0) return;
    ensure_chat_msgs_cs();
    EnterCriticalSection(&g_chat_msgs_cs);
    struct chat_msg_t *m = chat_msg_by_id(msg_id);
    if (m && m->pending) chat_msg_append_bytes(m, chunk, len);
    LeaveCriticalSection(&g_chat_msgs_cs);
    /* v1.7.2 (2026-07-17): per-chunk wake used to fire the FULL
     * 30-frame/300ms burst. High-throughput providers deliver 20+
     * chunks/sec -- burst worker end time kept getting pushed forward,
     * so the compositor was force-driven at 250-1800 SCPs/sec CONTINUOUS
     * during streaming. That's what LO reported as "the app flickering
     * so much" during ASK. Typing wake throttles to 30Hz + uses the
     * lite (4-pump/60ms) burst -- plenty for smooth streaming without
     * the overlap storm. */
    wake_dwm_composition_typing();
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
    /* Wipe implies home view -- reset the forced flag too since it's
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

/* v17 (2026-09-22) -- Transient toast overlay. Written from any thread
 * (setting-toggle hotkey handlers in dllmain.c call this instead of clobbering
 * the chat with "[streaming ON]" style messages). Rendered from draw_chat_window
 * as a top-center pill that fades over the last 350ms of its lifetime. */
static CRITICAL_SECTION g_toast_cs;
static volatile LONG    g_toast_cs_init = 0;
static char             g_toast_text[192] = {0};
static volatile LONGLONG g_toast_expire_tick = 0;
static volatile LONGLONG g_toast_show_tick   = 0;

static void ensure_toast_cs(void) {
    if (InterlockedCompareExchange(&g_toast_cs_init, 1, 0) == 0)
        InitializeCriticalSection(&g_toast_cs);
}

extern "C" void ui_show_toast(const char *text, unsigned ms) {
    if (!text || !text[0]) return;
    if (ms == 0) ms = 1800;
    if (ms > 8000) ms = 8000;
    ensure_toast_cs();
    EnterCriticalSection(&g_toast_cs);
    strncpy(g_toast_text, text, sizeof(g_toast_text) - 1);
    g_toast_text[sizeof(g_toast_text) - 1] = 0;
    LONGLONG now = (LONGLONG)GetTickCount64();
    InterlockedExchange64(&g_toast_show_tick,   now);
    InterlockedExchange64(&g_toast_expire_tick, now + (LONGLONG)ms);
    LeaveCriticalSection(&g_toast_cs);
    wake_dwm_composition();
}

/* Draw the toast pill (if any) top-centered inside the overlay window.
 * Called from inside draw_chat_window (after topbar / body / composer,
 * before the resize grip). Colors keyed off g_theme_effective so we don't
 * need to forward-declare ui_theme_t here (its definition lives ~2000
 * lines later in the "GORGEOUS custom UI toolkit" block). */
static void draw_toast_maybe(float scale) {
    LONGLONG expire = InterlockedCompareExchange64(&g_toast_expire_tick, 0, 0);
    if (expire == 0) return;
    LONGLONG now = (LONGLONG)GetTickCount64();
    if (now >= expire) return;
    /* Snapshot text under lock. */
    char msg[192];
    ensure_toast_cs();
    EnterCriticalSection(&g_toast_cs);
    strncpy(msg, g_toast_text, sizeof(msg) - 1);
    msg[sizeof(msg) - 1] = 0;
    LeaveCriticalSection(&g_toast_cs);
    if (!msg[0]) return;

    /* Fade curve: full opacity for most of the lifetime, ease out over the
     * final 350ms. */
    float remain = (float)(expire - now);
    float fade = remain < 350.0f ? (remain / 350.0f) : 1.0f;
    if (fade < 0.0f) fade = 0.0f;

    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 ws = ImGui::GetWindowSize();
    float fh = ImGui::GetFontSize();
    ImVec2 ts = ImGui::CalcTextSize(msg);
    float padx = 14.0f * scale, pady = 8.0f * scale;
    float w = ts.x + padx * 2.0f;
    float h = fh + pady * 2.0f;
    float cx = wp.x + ws.x * 0.5f;
    float x0 = cx - w * 0.5f;
    float y0 = wp.y + 44.0f * scale;   /* just below the topbar */
    /* Slight ease-in slide from -4px. */
    float slide = (1.0f - fade) * 4.0f;
    y0 -= slide;

    /* Theme-aware palette (NL card surface + softened border/text). */
    int th_eff = (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
    int bg_r = 17, bg_g = 17, bg_b = 17;
    int tx_r = 245, tx_g = 245, tx_b = 247;
    if (th_eff == 1) {   /* LIGHT */
        bg_r = 245; bg_g = 245; bg_b = 247;
        tx_r = 20;  tx_g = 20;  tx_b = 24;
    }
    int a_bg     = (int)(230.0f * fade);
    int a_border = (int)(120.0f * fade);
    int a_text   = (int)(255.0f * fade);
    ImU32 bg  = IM_COL32(bg_r, bg_g, bg_b, a_bg);
    ImU32 bd  = IM_COL32(255, 255, 255, a_border);
    if (th_eff == 1) bd = IM_COL32(0, 0, 0, a_border / 2);
    ImU32 txt = IM_COL32(tx_r, tx_g, tx_b, a_text);
    /* Soft shadow. */
    dl->AddRectFilled(ImVec2(x0 + 1, y0 + 2), ImVec2(x0 + w + 1, y0 + h + 2),
                      IM_COL32(0, 0, 0, (int)(70 * fade)), 6.0f * scale);
    dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + w, y0 + h), bg, 6.0f * scale);
    dl->AddRect      (ImVec2(x0, y0), ImVec2(x0 + w, y0 + h), bd, 6.0f * scale, 0, 1.0f);
    dl->AddText(ImVec2(x0 + padx, y0 + pady), txt, msg);
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
        /* v1.7.4: modifier VK names -- used by LONGPRESS labels
         * ("Hold RShift 700ms") and mouse-hold labels. */
        case 0xA0: return "LShift";
        case 0xA1: return "RShift";
        case 0xA2: return "LCtrl";
        case 0xA3: return "RCtrl";
        case 0xA4: return "LAlt";
        case 0xA5: return "RAlt";
        case 0x5B: return "LWin";
        case 0x5C: return "RWin";
        case 0x14: return "CapsLock";
        case 0x90: return "NumLock";
        case 0x91: return "ScrollLock";
        case 0x13: return "Pause";
    }
    _snprintf(buf, sizeof(buf) - 1, "0x%02X", vk);
    return buf;
}

/* v1.7.4 (2026-07-23): format any binding kind (MODIFIER / LONGPRESS /
 * MULTITAP / MOUSE_HOLD / MOUSE_MULTI) into a human-readable label.
 *
 * Was mis-interpreting the "extra" byte as modifier bits for non-
 * MODIFIER kinds -- the extra byte's format depends on kind (mod bits
 * vs hold_ms/10 vs count+gap). Result: overlay buttons showed
 * misleading labels like "Copy full [Ctrl+Shift+C]" when the actual
 * default was "triple-C". Now emits proper kind-aware labels. */
static const char *mouse_vk_label(unsigned mvk) {
    switch (mvk) {
        case 1: return "LMB";
        case 2: return "RMB";
        case 4: return "MMB";
        case 5: return "MX1";
        case 6: return "MX2";
    }
    return "M?";
}

extern "C" size_t ui_format_hotkey(int action, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return 0;
    out[0] = 0;
    if (action < 0 || action >= g_hk_bindings_n) return 0;
    unsigned hk = g_hk_bindings[action];
    if (hk == 0) return 0;
    unsigned kind  = SVC_HK_KIND(hk);
    unsigned vk    = SVC_HK_VK(hk);
    unsigned extra = SVC_HK_EXTRA(hk);
    char tmp[80];
    tmp[0] = 0;

    if (kind == SVC_HK_KIND_MODIFIER) {
        int pos = 0;
        if (extra & 0x1) pos += _snprintf(tmp + pos, sizeof(tmp) - pos - 1, "Ctrl+");
        if (extra & 0x2) pos += _snprintf(tmp + pos, sizeof(tmp) - pos - 1, "Shift+");
        if (extra & 0x4) pos += _snprintf(tmp + pos, sizeof(tmp) - pos - 1, "Alt+");
        _snprintf(tmp + pos, sizeof(tmp) - pos - 1, "%s", vk_to_label(vk));
    } else if (kind == SVC_HK_KIND_LONGPRESS) {
        unsigned hold_ms = SVC_HK_LONGPRESS_MS(hk);
        _snprintf(tmp, sizeof(tmp) - 1, "Hold %s %ums",
                  vk_to_label(vk), hold_ms);
    } else if (kind == SVC_HK_KIND_MULTITAP) {
        unsigned count = SVC_HK_MULTITAP_COUNT(hk);
        int watch = SVC_HK_WATCH(hk) ? 1 : 0;
        (void)watch;   /* label stays compact; UI docs explain WATCH-ONLY */
        _snprintf(tmp, sizeof(tmp) - 1, "%s x%u",
                  vk_to_label(vk), count);
    } else if (kind == SVC_HK_KIND_MOUSE_HOLD) {
        unsigned hold_ms = SVC_HK_LONGPRESS_MS(hk);
        _snprintf(tmp, sizeof(tmp) - 1, "Hold %s %ums",
                  mouse_vk_label(vk), hold_ms);
    } else if (kind == SVC_HK_KIND_MOUSE_MULTI) {
        unsigned count = SVC_HK_MULTITAP_COUNT(hk);
        _snprintf(tmp, sizeof(tmp) - 1, "%s x%u",
                  mouse_vk_label(vk), count);
    } else {
        _snprintf(tmp, sizeof(tmp) - 1, "unbound");
    }
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
    /* v1.7.11.15 (2026-07-25) -- BURST HYSTERESIS.
     *
     * User 1 report: "spamming toggle overlay only works half of the
     * time -- it wouldnt hide it but if i press it 4-6 more times then
     * it does eventually hide it."
     *
     * Root cause: TOGGLE is a stateful FLIP. Each fire flips visible
     * -> invisible -> visible. Rapid spam produces even/odd end state
     * depending on tap count, which the user perceives as ~50%
     * unreliable when they want a specific direction (usually HIDE).
     *
     * Fix: after a flip, ignore subsequent flips for 300ms. A spam
     * burst produces exactly ONE deterministic state change -- the
     * first press ALWAYS wins, subsequent taps within 300ms are
     * treated as "already handled". User taps once -> hides. User
     * spam-taps 6 times -> hides once (all 6 within 300ms) -> deterministic.
     * Legitimate re-toggle after 300ms still works normally.
     *
     * Debounce inside rin_fire() stays at 30ms for responsiveness on
     * SINGLE presses; this hysteresis lives at the state-change layer
     * where the parity problem actually is. */
    static ULONGLONG s_last_toggle_tick = 0;
    ULONGLONG now = GetTickCount64();
    if (now - s_last_toggle_tick < 300ULL) {
        diag("visible toggle IGNORED (burst hysteresis: %llums since last flip)",
             now - s_last_toggle_tick);
        return;
    }
    s_last_toggle_tick = now;

    /* v1.7.8: if we're HIDING, invalidate the old rect so underlying
     * apps repaint over our stale pixels (otherwise the overlay
     * silhouette lingers until an app naturally repaints). */
    invalidate_last_overlay_region("toggle_visible");
    EnterCriticalSection(&g_ui_cs);
    g_visible = !g_visible;
    int now_visible = g_visible ? 1 : 0;
    LeaveCriticalSection(&g_ui_cs);
    /* v11.2.1 (2026-07-24) -- HIDE GRACE REMOVED. See draw_chat_window's
     * !visible branch: we now return instantly on hide like Bypassify. */
    state_mark_dirty();
    geom_bump();                     /* v1.7.4: visibility change ⇒ layer must clear */
    /* v1.6.5 FLICKER FIX (2026-07-17): visibility toggles only need a
     * short compose kick (one composition cycle is enough -- DWM will
     * pick up g_visible on the next Present hook fire). The full
     * wake_dwm_composition path fires 30 SCPs over 300ms which was
     * causing visible strobing on toggle-show. wake_dwm_composition_lite
     * fires a single SCP + skips the cursor-jitter, then relies on the
     * ghost redraw + our natural Present hook to land the overlay.
     * Full path stays reserved for content-changing ops (chat append,
     * stream chunks, screenshot) where >1 frame of forced re-compose
     * genuinely helps visibility. */
    wake_dwm_composition_lite();
    diag("visible toggled -> %d", now_visible);
}

extern "C" void ui_toggle_lean() {
    LONG old = InterlockedExchange(&g_lean_mode, InterlockedCompareExchange(&g_lean_mode, 0, 0) ? 0 : 1);
    /* Invalidate old rect + bump geom so next frame clears any lingering
     * ImGui window chrome pixels that lean mode won't redraw. */
    invalidate_last_overlay_region("lean_toggle");
    geom_bump();
    wake_dwm_composition_lite();
    diag("lean_mode toggled: %d -> %d", (int)old, 1 - (int)old);
}

extern "C" int ui_is_lean() {
    return (int)InterlockedCompareExchange(&g_lean_mode, 0, 0);
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
    /* Legacy name -- Ctrl+Alt+X "back". NON-DESTRUCTIVE (as of
     * 2026-07-05 late-night rewrite). Simply hides messages by
     * forcing home view. Actual conversation wipe is Ctrl+Alt+N
     * (SVC_HK_NEW_CHAT -> ui_chat_clear_history). */
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
     * -> call ui_clear_reply which hides messages) and "quit"
     * (return 0 -> signal shutdown). If user hits Ctrl+Alt+X twice,
     * first press hides messages (returns to home), second press
     * quits (because now we're on home view). */
    if (g_home_view_forced) return 0;
    return ui_chat_message_count() > 0 ? 1 : 0;
}

extern "C" void ui_scroll_reply(int delta_px) {
    InterlockedExchangeAdd(&g_reply_scroll_pending, (LONG)delta_px);
    wake_dwm_composition_typing();   /* v1.7.2: mouse-wheel scroll can fire fast */
}

extern "C" void ui_copy_reply_to_clipboard(void) {
    ensure_last_reply_cs();
    char *copy = NULL;
    EnterCriticalSection(&g_last_reply_cs);
    if (g_last_reply_snapshot) copy = _strdup(g_last_reply_snapshot);
    LeaveCriticalSection(&g_last_reply_cs);

    /* v1.6.5 (2026-07-17): FALLBACK -- if snapshot is NULL (no reply has
     * finalized yet), walk the chat ring buffer backward for the most
     * recent AI message that has ANY text. Covers:
     *   - User hits Ctrl+Alt+C mid-stream (partial text is copyable)
     *   - User hits Ctrl+Alt+C after a Ctrl+Alt+S abort (stopped stream
     *     never fires finalize with non-empty text -- snapshot stays NULL)
     *   - User hits Ctrl+Alt+C after Ctrl+Alt+N (clears snapshot) but
     *     Chat had streaming pending -- same path via ring buffer scan
     * Report from LO 2026-07-17: "some users said when they hit hotkey
     * to copy it wouldnt work" -- silent no-snapshot was the failure. */
    if (!copy) {
        ensure_chat_msgs_cs();
        EnterCriticalSection(&g_chat_msgs_cs);
        for (int i = g_chat_msg_count - 1; i >= 0; i--) {
            struct chat_msg_t *m = chat_msg_at(i);
            if (m && m->role == UI_MSG_AI && m->text && m->text[0]) {
                copy = _strdup(m->text);
                break;
            }
        }
        LeaveCriticalSection(&g_chat_msgs_cs);
        if (copy) diag("copy_reply: snapshot NULL, fell back to ring buffer AI msg");
    }

    if (!copy) {
        diag("copy: no AI reply anywhere (empty conversation OR only user msgs)");
        return;
    }
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
    /* v1.6.5 ring-buffer fallback (see ui_copy_reply_to_clipboard). */
    if (!snap) {
        ensure_chat_msgs_cs();
        EnterCriticalSection(&g_chat_msgs_cs);
        for (int i = g_chat_msg_count - 1; i >= 0; i--) {
            struct chat_msg_t *m = chat_msg_at(i);
            if (m && m->role == UI_MSG_AI && m->text && m->text[0]) {
                snap = _strdup(m->text);
                break;
            }
        }
        LeaveCriticalSection(&g_chat_msgs_cs);
    }
    if (!snap) { diag("copy_code: no AI reply anywhere"); return; }

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
 * else 0. Only ASCII lowered -- non-ASCII passes through unchanged, which
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
 *     (e.g. "Answer options include..."), do NOT strip -- that's prose,
 *     not a preamble.
 *
 * Only recognises well-known preambles -- never chops arbitrary text
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
 *     (handles `**Answer** -- 4` after asterisk removal = `Answer -- 4`)
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
                /* keyword IS the entire content -- no-op strip */
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
                 *    "Answer -- 4" strips) */
                if (copular) {
                    /* Consume exactly the space(s) -- content follows. */
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
                    else continue;   /* prose -- don't strip */
                }
            } else {
                continue;   /* keyword followed by letter/digit/etc -- prose */
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
 *     `**Answer:** B` copies as just `B` -- the user is pressing this
 *     hotkey specifically because they want THE answer, not the AI's
 *     framing around it. */
extern "C" void ui_copy_last_ai_answer(void) {
    ensure_last_reply_cs();
    char *snap = NULL;
    EnterCriticalSection(&g_last_reply_cs);
    if (g_last_reply_snapshot) snap = _strdup(g_last_reply_snapshot);
    LeaveCriticalSection(&g_last_reply_cs);
    /* v1.6.5 ring-buffer fallback (see ui_copy_reply_to_clipboard). */
    if (!snap) {
        ensure_chat_msgs_cs();
        EnterCriticalSection(&g_chat_msgs_cs);
        for (int i = g_chat_msg_count - 1; i >= 0; i--) {
            struct chat_msg_t *m = chat_msg_at(i);
            if (m && m->role == UI_MSG_AI && m->text && m->text[0]) {
                snap = _strdup(m->text);
                break;
            }
        }
        LeaveCriticalSection(&g_chat_msgs_cs);
    }
    if (!snap) { diag("copy_answer: no AI reply anywhere"); return; }

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

/* v1.7.8: invalidate the region the overlay was drawn at LAST frame,
 * so underlying apps repaint + DWM re-composes that region + old
 * overlay pixels get overwritten. Cheap (~50µs). SEH-guarded because
 * we're in DWM's process and any exception in RedrawWindow's cascade
 * would take down DWM. Rect is padded 32px to cover ImGui window
 * shadows. Safe to call from any thread. */
static void invalidate_last_overlay_region(const char *why) {
    /* v1.7.8d: FULL-DESKTOP async invalidate (NULL rect = whole
     * desktop). Per-region invalidate was leaving trails at very-top/
     * very-side edges because those areas contain title-bar / non-
     * client / taskbar chrome that either (a) doesn't respond to
     * RDW_INVALIDATE alone, or (b) has coord-clipping that eats a
     * partial-edge invalidate. Full desktop cascade guarantees EVERY
     * top-level window emits WM_PAINT/WM_NCPAINT on its next tick ->
     * DWM re-composes every region -> all trails cleared. */
    __try {
        RedrawWindow(NULL, NULL, NULL,
                     RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Silent -- never let a repaint cascade kill DWM. */
    }

    /* v1.7.10.5: bump the DirectComposition compose-grace window.
     * WM_PAINT invalidation alone doesn't clear pixels in Chrome /
     * Slack / Cursor / Discord / video players -- those use swap-chain
     * direct-flip that bypasses WM_PAINT entirely. Their cached DWM
     * compose tiles keep our stale overlay pixels until they naturally
     * present new content over those tiles (Chrome's "kid eating a
     * cookie" hide LO reported). Fix: hold DWM in composite mode for
     * 500ms so DWM composes ~30 frames back-to-back, forcing DC apps
     * to yield direct-flip and letting DWM re-composite fresh content
     * over our stale tile regions. */
    hooks_bump_compose_grace(500);

    diag("invalidate: (%s) FULL-DESKTOP + compose-grace 500ms", why ? why : "?");
}

/* v1.7.11.19 (2026-07-25) -- GLIDE JITTER FIX.
 *
 * LO observation: BP's overlay glides perfectly smooth across screen.
 * Ours glides too but occasionally jitters/stutters mid-glide. Last
 * known "our-only" regression.
 *
 * Root cause: every ui_nudge() called invalidate_last_overlay_region()
 * which fires RedrawWindow(NULL, ..., RDW_INVALIDATE | RDW_FRAME |
 * RDW_ALLCHILDREN) -- a FULL-desktop paint cascade to every visible
 * window. Cost varies wildly:
 *   - Idle desktop: ~50µs
 *   - Chrome + Slack + Discord in foreground with pending compose work:
 *     5-20ms of blocking wall time in DWM's process
 *
 * At 60Hz continuous nudge (16ms period), a single ~15ms cascade
 * blows the frame budget -> next Present catches up two nudges at once
 * -> visible stutter. That's the "sometimes jitters then keeps gliding"
 * LO reported.
 *
 * ALSO: the trail-clear is REDUNDANT during a burst -- consecutive nudge
 * positions overlap naturally, so old pixels are covered by new overlay
 * within one frame. Trail pixels only surface when the overlay STOPS
 * moving (chrome edges the new position doesn't cover).
 *
 * Fix strategy:
 *   1. Throttle mid-burst invalidate to at most once per 120ms -- enough
 *      for the initial stationary->moving trail-erase, but no per-frame
 *      cascade during continuous glide.
 *   2. From ui_present_frame, if last-nudge-tick > 120ms ago AND we
 *      haven't already fired a post-burst clear, fire ONE
 *      invalidate_last_overlay_region to clean up whatever trail the
 *      final resting position left. This is the "user stopped" cleanup
 *      that mid-burst throttling skipped.
 *   3. Same treatment for SetCursorPos (cursor-invalidate trick) -- the
 *      Windows win32k dispatch adds ~100-500µs per call under load.
 *      Throttle to the same 120ms window as the RedrawWindow.
 *
 * Result: burst = ~1 invalidate at start, then pure glide, then 1
 * cleanup ~120ms after stop. BP-parity smooth. */
static volatile LONGLONG g_last_nudge_tick     = 0;   /* set on ui_nudge; consumed by Present */
static volatile LONGLONG g_last_nudge_inv_tick = 0;   /* last time we fired invalidate for a nudge */
static volatile LONG     g_post_burst_pending  = 0;   /* 1 if Present should fire post-burst clear */

/* Called from ui_present_frame at frame start. Fires ONE post-burst
 * trail-clear ~120ms after the last nudge, then latches. Zero cost
 * when no nudge is in flight (fast path == atomic read + compare). */
static void nudge_burst_maybe_finalize(void) {
    LONGLONG last_nudge = g_last_nudge_tick;
    if (last_nudge == 0) return;   /* no burst ever, or already cleaned up */
    ULONGLONG now = GetTickCount64();
    if ((ULONGLONG)((LONGLONG)now - last_nudge) < 120ULL) return;   /* still bursting */
    /* Burst has settled -- fire ONE final invalidate to clean up trail
     * at the resting position. Latch so we don't refire until next burst. */
    InterlockedExchange64(&g_last_nudge_tick, 0);
    invalidate_last_overlay_region("nudge-burst-end");
    /* Cursor-invalidate the resting-position trail region too. */
    __try {
        POINT pt;
        if (GetCursorPos(&pt)) SetCursorPos(pt.x, pt.y);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    (void)g_post_burst_pending;  /* reserved for future finer-grained tracking */
}

extern "C" void ui_nudge(int dx, int dy) {
    ensure_cs();
    ULONGLONG now = GetTickCount64();

    /* v1.7.11.19: THROTTLED trail-clear. Mid-burst invalidates are
     * redundant + variable-latency = source of the glide jitter. Fire
     * at most once per 120ms during a burst; post-burst cleanup is
     * handled by nudge_burst_maybe_finalize from the Present hook. */
    LONGLONG last_inv = g_last_nudge_inv_tick;
    int fire_inv = ((ULONGLONG)((LONGLONG)now - last_inv) >= 120ULL);
    if (fire_inv) {
        InterlockedExchange64(&g_last_nudge_inv_tick, (LONGLONG)now);
        invalidate_last_overlay_region("nudge");
    }
    /* Always mark that a nudge occurred -- Present hook will trigger the
     * post-burst clear ~120ms after the last one. */
    InterlockedExchange64(&g_last_nudge_tick, (LONGLONG)now);

    EnterCriticalSection(&g_ui_cs);
    g_offset_x += dx;
    g_offset_y += dy;
    if (g_offset_x < -4000) g_offset_x = -4000;
    if (g_offset_x >  4000) g_offset_x =  4000;
    if (g_offset_y < -3000) g_offset_y = -3000;
    if (g_offset_y >  3000) g_offset_y =  3000;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    geom_bump();                     /* v1.7.4: force ghost-frame clear next Present */
    wake_dwm_composition();

    /* v1.7.11.13 (2026-07-25) -- CURSOR-INVALIDATE TRICK.
     *
     * LO observation: MOVING MOUSE OVER trail region CLEARS trails.
     * DWM's cursor drawing logic recomposites the region behind the
     * cursor every time it renders. Even a no-op SetCursorPos(same_pt)
     * triggers this recompose.
     *
     * v1.7.11.19: throttled to the same 120ms window as the RedrawWindow
     * cascade -- cursor-invalidate mid-burst is also redundant while the
     * overlay is continuously moving. Post-burst finalize does it once
     * more when the glide settles. */
    if (fire_inv) {
        __try {
            POINT pt;
            if (GetCursorPos(&pt)) {
                SetCursorPos(pt.x, pt.y);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Silent -- non-critical trail-clear trick. */
        }
    }

    diag("nudge dx=%d dy=%d -> off=(%d,%d)%s", dx, dy, g_offset_x, g_offset_y,
         fire_inv ? " [inv]" : " [glide]");
}

extern "C" void ui_resize(int dw, int dh) {
    ensure_cs();
    invalidate_last_overlay_region("resize");   /* v1.7.8 */
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
    geom_bump();                     /* v1.7.4 */
    wake_dwm_composition();
    diag("resize dw=%d dh=%d -> extra=(%d,%d)", dw, dh, g_extra_w, g_extra_h);
}

extern "C" void ui_cycle_corner() {
    ensure_cs();
    invalidate_last_overlay_region("cycle_corner");   /* v1.7.8 */
    EnterCriticalSection(&g_ui_cs);
    g_corner = (g_corner + 1) % 4;
    g_offset_x = g_offset_y = 0;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    geom_bump();                     /* v1.7.4 */
    wake_dwm_composition();
    diag("cycle_corner -> %d", g_corner);
}

extern "C" void ui_bump_alpha(float delta) {
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_alpha += delta;
    /* v13 (2026-08-10): floor 0.20 -> 0.05 -- Ctrl+Alt+- can drive the overlay
     * near-invisible (ghost) instead of stopping at a still-obvious 20%. */
    if (g_alpha < 0.05f) g_alpha = 0.05f;
    if (g_alpha > 1.00f) g_alpha = 1.00f;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    geom_bump();                     /* v1.7.4: alpha change ⇒ visible change */
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
    geom_bump();                     /* v1.7.4: font scale changes overlay size */
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
 * where they hit Ctrl+Alt+= etc.) survive across arms -- the config
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
     * captured post-init and re-persist on next tweak.
     * v13 (2026-08-10): floor 0.20 -> 0.05 so a near-invisible slider value
     * set in svchelper actually applies at launch. */
    if (alpha >= 0.05f && alpha <= 1.00f) g_alpha = alpha;
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
    geom_bump();                     /* v1.7.4 */
    wake_dwm_composition();
    diag("apply_launch_config: base=(%d,%d) alpha=%.2f size_mode=%d",
         base_w, base_h, alpha, size_mode);
}

/* v11 (2026-07-24) -- apply theme + overlay-flags from launch config.
 * Called from dllmain after ui_apply_launch_config. Fresh install / stale
 * v10 config passes overlay_flags=0 which we auto-migrate to
 * SVC_OVFLAG_DEFAULTS so users get the new UX without opt-in. */
extern "C" void ui_apply_theme_and_flags(int theme, unsigned overlay_flags) {
    if (theme < 0 || theme > 2) theme = 2;   /* clamp to valid range */
    InterlockedExchange(&g_theme_pref, (LONG)theme);
    /* Migration: schema-v10 configs pass overlay_flags=0. Treat as
     * "use v11 defaults" so users benefit from the new UX without
     * needing to re-inject through the updated svchelper. */
    unsigned effective_flags = overlay_flags ? overlay_flags : SVC_OVFLAG_DEFAULTS;
    InterlockedExchange(&g_overlay_flags, (LONG)effective_flags);
    /* v13 (2026-08-10): OPAQUE_LOCK force-lock REMOVED. It used to slam
     * g_alpha=1.0 here on every inject, which ran AFTER ui_apply_launch_config
     * had just applied the user's chosen (possibly near-invisible) opacity --
     * that's the exact "transparency doesnt stick / isnt as low as i set it"
     * bug LO reported. The opacity slider is now the single source of truth;
     * whatever alpha state_load_once / apply_launch_config resolved stands.
     * The flag bit is intentionally ignored (kept only for config compat). */
    /* v11.2.4.1 (2026-07-24) -- HARD FORCE g_visible=true on every inject.
     * LO reported: "when i injected it didnt auto show". Belt-and-
     * suspenders -- even though the static initializer says true, and
     * state_load_once ignores iv_visible, apparently some intermediate
     * path can flip it. Just re-set here after all init runs to
     * guarantee visible-on-inject regardless of what came before. */
    ensure_cs();
    EnterCriticalSection(&g_ui_cs);
    g_visible = true;
    LeaveCriticalSection(&g_ui_cs);
    /* Initial theme resolution -- 2s poller updates from here. */
    int resolved;
    if (theme == 2) resolved = query_windows_apps_use_light_theme();   /* auto */
    else            resolved = theme;                                  /* 0 or 1 */
    InterlockedExchange(&g_theme_effective, (LONG)resolved);
    geom_bump();
    wake_dwm_composition();
    diag("apply_theme_and_flags: theme=%d(->%s) flags=0x%x", theme,
         resolved ? "LIGHT" : "DARK", effective_flags);
}

extern "C" unsigned ui_get_overlay_flags(void) {
    return (unsigned)InterlockedCompareExchange(&g_overlay_flags, 0, 0);
}

extern "C" int ui_get_theme_effective(void) {
    return (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
}

/* v11: inline theme poll -- no separate thread. Called from ui_present_frame
 * once every ~2s of frames (throttled by wall-clock tick counter). Zero-cost
 * unless preference is AUTO. */
static void maybe_repoll_theme(void) {
    static ULONGLONG s_last_theme_tick = 0;
    if (InterlockedCompareExchange(&g_theme_pref, 0, 0) != 2) return;   /* not auto */
    ULONGLONG now = GetTickCount64();
    if (now - s_last_theme_tick < 2000) return;                          /* throttle */
    s_last_theme_tick = now;
    int t = query_windows_apps_use_light_theme();
    LONG prev = InterlockedExchange(&g_theme_effective, (LONG)t);
    if (prev != (LONG)t) {
        geom_bump();
        wake_dwm_composition();
        diag("theme_poll: auto -> %s", t ? "LIGHT" : "DARK");
    }
}

extern "C" void ui_reset_geometry() {
    ensure_cs();
    invalidate_last_overlay_region("reset_geometry");   /* v1.7.8 */
    EnterCriticalSection(&g_ui_cs);
    g_corner   = 0;
    g_offset_x = 0;
    g_offset_y = 0;
    g_extra_w  = 0;
    g_extra_h  = 0;
    g_alpha    = 1.00f;   /* v11: OPAQUE default -- matches new config default */
    g_font     = 1.00f;
    LeaveCriticalSection(&g_ui_cs);
    state_mark_dirty();
    geom_bump();                     /* v1.7.4 */
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
 * text -- plenty for a question). Overflow silently drops keystrokes
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
    chat_state_export();
    /* Force overlay visible when starting chat -- otherwise user
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

/* UTF-8 helpers -- step cursor left/right over one codepoint. */
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
        /* Insert at cursor position -- shift tail right by n bytes. */
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
    wake_dwm_composition_typing();
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
    wake_dwm_composition_typing();
}

/* NEW: Delete key -- remove codepoint immediately RIGHT of cursor. */
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
    wake_dwm_composition_typing();
}

/* NEW: cursor navigation. LEFT/RIGHT step one codepoint, HOME/END jump. */
extern "C" void ui_chat_cursor_left(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_cursor = utf8_prev(g_chat_buf, g_chat_cursor);
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition_typing();
}
extern "C" void ui_chat_cursor_right(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_cursor = utf8_next(g_chat_buf, g_chat_len, g_chat_cursor);
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition_typing();
}
extern "C" void ui_chat_cursor_home(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_cursor = 0;
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition_typing();
}
extern "C" void ui_chat_cursor_end(void) {
    if (!g_chat_active) return;
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_cursor = g_chat_len;
    LeaveCriticalSection(&g_chat_cs);
    wake_dwm_composition_typing();
}

extern "C" void ui_chat_cancel() {
    ensure_chat_cs();
    EnterCriticalSection(&g_chat_cs);
    g_chat_buf[0] = 0;
    g_chat_len = 0;
    g_chat_cursor = 0;
    LeaveCriticalSection(&g_chat_cs);
    InterlockedExchange(&g_chat_active, 0);
    chat_state_export();
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
    chat_state_export();
    wake_dwm_composition();
    return out;
}

/* Walk pLayer's vtable to get backbuffer ID3D11Texture2D*.
 * Slot values verified from main hooksdll production code (dwm_payload.c).
 *
 * v1.6.1 (2026-07-15) -- hardened against vtable-layout drift.
 *
 *   The slot indices below (GPB_SLOT=5, GD3D_SLOT=24, ACC3_SLOT=19)
 *   were reverse-engineered from a SPECIFIC dwmcore.dll build.
 *   Windows patch updates can re-order the vtable (verified on user
 *   jay.perkerson@gmail.com's box, 2026-07-15). Calling the wrong
 *   slot invokes a wild function pointer that Windows' CFG / CET
 *   Shadow Stack traps with __fastfail, which BYPASSES __try/__except
 *   entirely and takes DWM down.
 *
 *   Fix: validate each vtable-slot pointer is inside dwmcore.dll's
 *   executable memory BEFORE calling. If not, log detailed diag and
 *   return NULL -- overlay skips this frame instead of crashing DWM.
 *   Payload stays loaded; hotkeys still work (rawinput is separate
 *   from render); support gets a clear log line pointing at the
 *   slot mismatch. */
/* v1.7.11 (2026-07-25) -- BP-parity RTV source fix.
 *
 * Prior sessions established (via handoff-post-v177-shadow-still-broken.md
 * "hypothesis #4 -- highest priority to test") that the trailing / shadow-
 * leak bug is caused by our RTV writing into a QI'd ID3D11Texture2D view
 * that DWM's compositor doesn't track. BP calls
 * pDevice->CreateRenderTargetView(pAccessor, NULL, &rtv) -- passing the
 * ACCESSOR OBJECT DIRECTLY as pResource. DWM's dirty tracker knows the
 * accessor and invalidates on writes -> old-position pixels get naturally
 * overwritten during natural compose cycles.
 *
 * Byte-verified in bp_decomp2.c FUN_180008ac0 line 50:
 *   (**(code **)(*DAT_1800c1250 + 0x48))();
 * where 0x48 = slot 9 on ID3D11Device = CreateRenderTargetView, and
 * the resource arg is pAccessor (obtained via pLayer->slot5->slot24->
 * slot19 chain, same as ours). NO QueryInterface step.
 *
 * out_accessor: caller-owned void** that receives pAcc (borrowed ref,
 * do NOT Release -- same lifetime as our existing pAcc use inside the
 * function). NULL means "caller doesn't need it" (e.g. capture path). */
static ID3D11Texture2D *get_backbuffer_texture(void *pLayer, void **out_accessor) {
    ID3D11Texture2D *out_tex = nullptr;
    if (out_accessor) *out_accessor = nullptr;

    /* Populate dwmcore bounds cache on first call. Cheap. */
    ensure_dwmcore_bounds_cached();

    __try {
        if (!pLayer || !is_readable(pLayer, 8)) return nullptr;
        void **layer_vtbl = *(void ***)pLayer;
        if (!is_readable(layer_vtbl, (ACC3_SLOT + 1) * 8)) return nullptr;

        /* v1.6.2: one-shot dynamic slot discovery. Walk pLayer's vtable
         * looking for the slot whose function pointer's RVA matches the
         * resolver-supplied hint. If found, cache + use dynamically.
         * If not found (RVA hint was 0 OR no matching slot), effective_
         * gpb_slot returns the hardcoded GPB_SLOT constant. */
        discover_gpb_slot_once(layer_vtbl, GPB_SLOT);
        discover_gd3d_slot_once(layer_vtbl, GD3D_SLOT);
        const int slot_gpb  = effective_gpb_slot();
        const int slot_gd3d = effective_gd3d_slot();

        /* v1.6.1: validate GPB slot points into dwmcore. */
        void *fn_gpb = layer_vtbl[slot_gpb];
        if (!is_ptr_in_dwmcore(fn_gpb)) {
            static volatile LONG s_first_bad_gpb = 0;
            if (InterlockedCompareExchange(&s_first_bad_gpb, 1, 0) == 0) {
                diag("vtable slot GPB=%d (dyn=%d hc=%d) points OUTSIDE dwmcore.dll "
                     "(fn=%p base=%p size=%zu) -- Windows build likely re-ordered "
                     "the vtable; skipping overlay draw to prevent CFG/CET crash",
                     slot_gpb, g_dyn_slot_gpb, GPB_SLOT,
                     fn_gpb, g_dwmcore_base, (size_t)g_dwmcore_size);
            }
            return nullptr;
        }
        void *pPhysBack = ((pfnVGet)fn_gpb)(pLayer);
        if (!pPhysBack || !is_readable(pPhysBack, 8)) return nullptr;

        /* v1.6.1: validate GD3D slot. */
        void *fn_gd3d = layer_vtbl[slot_gd3d];
        if (!is_ptr_in_dwmcore(fn_gd3d)) {
            static volatile LONG s_first_bad_gd3d = 0;
            if (InterlockedCompareExchange(&s_first_bad_gd3d, 1, 0) == 0) {
                diag("vtable slot GD3D=%d (dyn=%d hc=%d) points OUTSIDE dwmcore.dll "
                     "(fn=%p) -- skipping overlay draw",
                     slot_gd3d, g_dyn_slot_gd3d, GD3D_SLOT, fn_gd3d);
            }
            return nullptr;
        }
        void *pRes = ((pfnVGet)fn_gd3d)(pLayer);
        if (!pRes || !is_readable(pRes, 8)) return nullptr;

        void **res_vtbl = *(void ***)pRes;
        if (!is_readable(res_vtbl, (ACC3_SLOT + 1) * 8)) return nullptr;

        /* v1.6.2: one-shot dynamic slot discovery on res_vtbl (accessor). */
        discover_acc_slot_once(res_vtbl, ACC3_SLOT);
        const int slot_acc = effective_acc_slot();

        /* v1.6.1: validate ACC slot. */
        void *fn_acc = res_vtbl[slot_acc];
        if (!is_ptr_in_dwmcore(fn_acc)) {
            static volatile LONG s_first_bad_acc = 0;
            if (InterlockedCompareExchange(&s_first_bad_acc, 1, 0) == 0) {
                diag("vtable slot ACC=%d (dyn=%d hc=%d) points OUTSIDE dwmcore.dll "
                     "(fn=%p) -- skipping overlay draw",
                     slot_acc, g_dyn_slot_acc, ACC3_SLOT, fn_acc);
            }
            return nullptr;
        }
        void *pAcc = ((pfnVGet)fn_acc)(pRes);
        if (!pAcc || !is_readable(pAcc, 8)) return nullptr;

        void **acc_vtbl = *(void ***)pAcc;
        if (!is_readable(acc_vtbl, (VTBL_QI + 1) * 8)) return nullptr;

        /* QueryInterface is COM-standard slot 0 on every IUnknown-derived
         * object. The accessor's QI legitimately dispatches into whatever
         * module implements it (often d3d11.dll or dxgi.dll, not dwmcore),
         * so we accept a pointer inside ANY loaded module's executable
         * region -- much looser than the dwmcore-only check used for the
         * GPB/GD3D/ACC3 slots (which are dwmcore-owned methods). */
        void *fn_qi = acc_vtbl[VTBL_QI];
        if (!is_ptr_in_loaded_module_code(fn_qi)) {
            static volatile LONG s_first_bad_qi = 0;
            if (InterlockedCompareExchange(&s_first_bad_qi, 1, 0) == 0) {
                diag("vtable slot VTBL_QI=%d on accessor is NOT executable "
                     "loaded-module code (fn=%p) -- skipping overlay draw",
                     VTBL_QI, fn_qi);
            }
            return nullptr;
        }
        pfnQI qi = (pfnQI)fn_qi;
        HRESULT hr = qi(pAcc, &IID_ID3D11Texture2D_LOCAL, (void **)&out_tex);
        if (FAILED(hr)) {
            static volatile LONG s_first_qi_fail = 0;
            if (InterlockedCompareExchange(&s_first_qi_fail, 1, 0) == 0)
                diag("QueryInterface(ID3D11Texture2D) FAILED hr=0x%08lx", hr);
            return nullptr;
        }
        /* v1.7.11 -- hand pAcc back to caller so it can pass it as pResource
         * to CreateRenderTargetView (BP-parity -- see docstring above). */
        if (out_accessor) *out_accessor = pAcc;

        /* First successful call -- log the pointer values AND their
         * dwmcore RVAs so support has definitive per-Windows-build data
         * on what class::method each slot resolves to.
         *
         * v1.6.3: cross-reference each slot's RVA against the known-
         * symbol table (populated by dllmain from offsets.blob) so the
         * log names each function instead of just showing raw addresses:
         *   "slot=5 rva=0x1DD690 (== getDevice)"
         * Enables support to identify -- WITHOUT needing to run resolver
         * on the user's box -- which dwmcore method each vtable slot
         * actually dispatches to on that specific Windows build. */
        static volatile LONG s_first_ok = 0;
        if (InterlockedCompareExchange(&s_first_ok, 1, 0) == 0) {
            ui_rva_t rva_gpb  = g_dwmcore_base ? (ui_rva_t)((BYTE *)fn_gpb  - g_dwmcore_base) : 0;
            ui_rva_t rva_gd3d = g_dwmcore_base ? (ui_rva_t)((BYTE *)fn_gd3d - g_dwmcore_base) : 0;
            ui_rva_t rva_acc  = g_dwmcore_base ? (ui_rva_t)((BYTE *)fn_acc  - g_dwmcore_base) : 0;
            diag("get_backbuffer_texture: OK on first call "
                 "(gpb_slot=%d rva=0x%llx (== %s)  "
                 "gd3d_slot=%d rva=0x%llx (== %s)  "
                 "acc_slot=%d rva=0x%llx (== %s)  qi=%p  tex=%p)",
                 slot_gpb,  (unsigned long long)rva_gpb,  lookup_rva_name(rva_gpb),
                 slot_gd3d, (unsigned long long)rva_gd3d, lookup_rva_name(rva_gd3d),
                 slot_acc,  (unsigned long long)rva_acc,  lookup_rva_name(rva_acc),
                 fn_qi, out_tex);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        static volatile LONG s_first_seh = 0;
        if (InterlockedCompareExchange(&s_first_seh, 1, 0) == 0)
            diag("get_backbuffer_texture: SEH exception caught (first)");
        return nullptr;
    }
    return out_tex;
}

/* Get or create an RTV for the given texture. Cache per (device, texture).
 * Returns the width/height and format via out params.
 *
 * v1.7.11 (2026-07-25) -- when pRes_for_rtv is non-NULL, CreateRenderTargetView
 * is called with THAT pointer as pResource instead of `tex`. BP-parity: BP
 * passes pAccessor directly, not the QI'd Texture2D. This lets DWM's compositor
 * see our writes on its own tracked resource -> no shadow trails. Falls back
 * to tex if pRes_for_rtv is NULL (safe / old behavior). Cache key stays tex
 * so cache lookup semantics are unchanged. */
static ID3D11RenderTargetView *get_or_create_rtv(ID3D11Device *dev,
                                                 ID3D11Texture2D *tex,
                                                 void *pRes_for_rtv,
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

    /* Track largest layer ever seen -- this is the PRIMARY draw target
     * (typically the physical screen backbuffer). Prior logic drew into
     * ALL >=800x600 layers which caused visible DUPLICATES when DWM had
     * multiple fullscreen surfaces (e.g. LDB main + LDB modal + another
     * fullscreen app). Now we only accept layers within 5% of the
     * largest we've ever seen -- that's ONE effective layer per frame.
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
     * RTV creation. Everything else returns NULL -> present_frame no-op. */
    UINT thresh_w = (g_target_w * 95) / 100;
    UINT thresh_h = (g_target_h * 95) / 100;
    if (desc.Width < thresh_w || desc.Height < thresh_h) {
        return nullptr;
    }

    /* Choose RTV format. For HDR (R16G16B16A16_FLOAT), same format works --
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
    /* v1.7.11 -- pass pRes_for_rtv (BP's pAccessor) when available.
     * Fallback to tex preserves prior behavior if the walk didn't yield
     * an accessor (shouldn't happen but defensive). */
    ID3D11Resource *rtv_source = pRes_for_rtv
        ? (ID3D11Resource *)pRes_for_rtv
        : (ID3D11Resource *)tex;
    HRESULT hr = dev->CreateRenderTargetView(rtv_source, &rvd, &rtv);
    if (FAILED(hr) || !rtv) {
        diag("CreateRTV FAILED hr=0x%lx fmt=%u %ux%u (src=%s)",
             hr, (unsigned)desc.Format, desc.Width, desc.Height,
             pRes_for_rtv ? "accessor" : "tex-fallback");
        /* If pAccessor path failed, retry with the QI'd Texture2D as
         * a safety net so users don't lose overlay on accessor mismatch. */
        if (pRes_for_rtv && !rtv) {
            hr = dev->CreateRenderTargetView((ID3D11Resource *)tex, &rvd, &rtv);
            if (FAILED(hr) || !rtv) return nullptr;
            diag("CreateRTV: fell back to tex-source after accessor rejection");
        } else {
            return nullptr;
        }
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
    /* PERF (v3.1): this used to diag() on EVERY insert. When DWM hands us a
     * freshly-QI'd Texture2D pointer each frame (common -- the cache key is
     * the COM pointer, which changes even for the same underlying resource),
     * the insert path runs every frame and the encrypted per-line slog write
     * (AES-256-GCM) burned measurable CPU/battery inside dwm.exe at ~display
     * refresh rate whenever the overlay was visible. Dedupe: only log when
     * the effective target geometry/format actually changes. Rendering path
     * is UNTOUCHED -- this is a pure logging gate. */
    {
        static UINT s_lw = 0, s_lh = 0; static unsigned s_lfmt = 0xFFFFFFFFu;
        if (desc.Width != s_lw || desc.Height != s_lh || (unsigned)desc.Format != s_lfmt) {
            s_lw = desc.Width; s_lh = desc.Height; s_lfmt = (unsigned)desc.Format;
            diag("RTV cached slot=%d %ux%u fmt=%u", slot, desc.Width, desc.Height, (unsigned)desc.Format);
        }
    }
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
 *                      typeset -- full LaTeX render is out of scope,
 *                      but $\frac{a}{b}$ is still readable + copyable).
 *
 *   $ ... $            inline math: rendered inline as normal text (no
 *                      special styling -- keeps line wrapping simple;
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
 * PARENT chat scrollbar handles all scrolling -- user gets ONE smooth
 * scroll from top to bottom of the entire response.
 *
 * `bg` + `border` + `label_col` + `label` control appearance.
 * `body` is rendered in monospace. `block_idx` disambiguates the
 * copy button id. Long code is NOT truncated -- the parent chat pane
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
    float pad_h = 20.0f, pad_v = 14.0f;
    /* v17 (2026-09-22) -- generous 20x14 padding so code / math body text
     * never hugs the block edges. Header + separator + body inherits from it. */
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
     * For math, no dedicated hotkey -- just show "copy". */
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
     * -1.0f) so long code lines DON'T wrap -- they overflow horizontally
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

/* Language -> accent color palette. Loosely matches editor conventions
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

/* Render a fenced code block -- full-width inline, part of parent
 * scroll. Language label on the left with per-language accent color,
 * copy button on right. The label also shows the line count for
 * long snippets ("python * 12 lines") so the student can eyeball
 * scroll depth. */
static void md_render_code_block(const char *lang, const char *body,
                                 size_t body_len, int block_idx,
                                 float wrap_width, float font_mul) {
    (void)wrap_width;
    /* v16 (2026-09-22) -- breathe: block-level surfaces get vertical air on
     * both sides so they visually separate from surrounding prose. */
    ImGui::Spacing();
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
    ImGui::Spacing();
}

/* latex_to_unicode is defined in the included latex_convert.h below.
 * md_render_math_display uses it -- but the include site is FURTHER
 * down (right after md_render_list_item to keep the ordering readable).
 * Forward-declare it here so md_render_math_display can call it. The
 * `static` matches the header's linkage. */
#include "latex_convert.h"

/* Render a display-math block (\[..\] / $$..$$) -- same pattern as
 * code block but with violet accent so the eye knows "math not code".
 * Body is converted from LaTeX to Unicode for readability. */
static void md_render_math_display(const char *body, size_t body_len,
                                   int block_idx, float font_mul) {
    ImGui::Spacing();
    char uni_buf[8192];
    size_t ulen = latex_to_unicode(body, body_len, uni_buf, sizeof(uni_buf) - 1);
    uni_buf[ulen] = 0;
    /* v1.3 (2026-07-07): bg + border + label alphas all scale with
     * g_frame_alpha_mul so math blocks respect user transparency
     * uniformly with the rest of the overlay. */
    int _mth = (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
    md_render_tinted_block(uni_buf, ulen, block_idx, "math",
        _mth == 1 ? ImVec4(0.0f, 0.0f, 0.0f, 0.05f) : ImVec4(1.0f, 1.0f, 1.0f, 0.05f),   /* bg */
        _mth == 1 ? ImVec4(0.0f, 0.0f, 0.0f, 0.16f) : ImVec4(1.0f, 1.0f, 1.0f, 0.16f),   /* border */
        _mth == 1 ? ImVec4(0.35f, 0.35f, 0.40f, 0.90f) : ImVec4(0.70f, 0.70f, 0.75f, 0.90f), /* label */
        "math", font_mul);
    ImGui::Spacing();
}

/* Render a heading (# / ## / ###) line -- larger font + accent color.
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

    /* Level -> size + color mapping. */
    float scale = (level == 1) ? 1.5f : (level == 2) ? 1.3f : 1.15f;
    /* v15: B&W, theme-aware. Headings just brighter/darker than body. */
    int _hth = (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
    ImVec4 col = (_hth == 1) ? ImVec4(0.05f, 0.05f, 0.07f, 1.0f)
                             : ImVec4(0.98f, 0.98f, 0.99f, 1.0f);

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
 * `* ` marker. v16 (2026-09-22): wrapped in Indent so list items visually
 * hang off the left margin -- reads as a nested block. */
static void md_render_list_item(const char *line, size_t line_len,
                                int is_numbered, int number) {
    ImGui::Indent(12.0f);
    /* Bullet or number, then indented body. B&W, theme-aware. */
    int _lth = (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
    ImGui::PushStyleColor(ImGuiCol_Text,
        _lth == 1 ? ImVec4(0.30f, 0.30f, 0.34f, 1.0f) : ImVec4(0.72f, 0.72f, 0.76f, 1.0f));
    if (is_numbered) {
        ImGui::Text("%d.", number);
    } else {
        ImGui::Text("\xE2\x80\xA2");   /* * U+2022 BULLET */
    }
    ImGui::PopStyleColor();
    ImGui::SameLine(0, 8.0f);
    ImGui::TextUnformatted(line, line + line_len);
    ImGui::Unindent(12.0f);
}

/* LaTeX-to-Unicode simplifier: already included above (right before
 * md_render_math_display) so its definitions are visible where used.
 * Kept a comment here as a visual reminder of where the block used
 * to live pre-refactor. */


/* Render a plain-text run. Splits on newlines and detects per-line
 * markdown structure: headings, list items. Non-structured lines
 * render as TextWrapped. */
/* v16 (2026-09-22) -- Inline formatting emitter. Splits a paragraph at `**`
 * (bold) and `` ` `` (code) markers and emits each run separately, chaining
 * via SameLine(0,0) so ImGui's wrap (set by the caller via PushTextWrapPos)
 * still handles line breaks between runs. Bold gets a shade toward the theme's
 * text extremum; code renders with g_font_mono + a subtly tinted color.
 * Long-standing weakness: previous md_render_plain stripped these markers
 * outright ("makes prose look junky") which flattened every AI heading /
 * emphasis / code identifier. This restores them without introducing hue. */
static void md_emit_para_runs(const char *s, size_t n) {
    if (n == 0) return;
    ImGuiStyle &st = ImGui::GetStyle();
    ImVec4 base = st.Colors[ImGuiCol_Text];
    int th_eff = (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
    ImVec4 bold = (th_eff == 1)
        ? ImVec4(base.x * 0.55f, base.y * 0.55f, base.z * 0.55f, base.w)  /* darker on light */
        : ImVec4(1.00f, 1.00f, 1.00f, base.w);                             /* pure white on dark */
    ImVec4 code = (th_eff == 1)
        ? ImVec4(0.20f, 0.20f, 0.22f, 1.0f)
        : ImVec4(0.82f, 0.86f, 0.92f, 1.0f);

    bool  boldstate = false, codestate = false;
    size_t start = 0, i = 0;
    bool  first = true;

    /* Helper closure: emit s[start..upto). */
    auto flush = [&](size_t upto) {
        if (upto <= start) return;
        char tmp[4096], uni[5120];
        size_t take = upto - start;
        if (take > sizeof(tmp) - 1) take = sizeof(tmp) - 1;
        memcpy(tmp, s + start, take); tmp[take] = 0;
        size_t ulen = latex_to_unicode(tmp, take, uni, sizeof(uni) - 1);
        uni[ulen] = 0;
        if (!first) ImGui::SameLine(0, 0);
        first = false;
        if (codestate) {
            if (g_font_mono) ImGui::PushFont(g_font_mono);
            ImGui::PushStyleColor(ImGuiCol_Text, code);
            ImGui::TextUnformatted(uni);
            ImGui::PopStyleColor();
            if (g_font_mono) ImGui::PopFont();
        } else if (boldstate) {
            ImGui::PushStyleColor(ImGuiCol_Text, bold);
            ImGui::TextUnformatted(uni);
            /* Pseudo-bold via a hairline redraw offset -- last item's rect gives
             * us the position so we don't have to reason about wrapping. Works
             * cleanly for single-line runs (99% of bold segments in AI answers);
             * on wrap it only bolds the last line but stays visually crisp. */
            ImVec2 rmn = ImGui::GetItemRectMin();
            ImGui::GetWindowDrawList()->AddText(ImVec2(rmn.x + 0.6f, rmn.y),
                                                ImGui::GetColorU32(bold), uni);
            ImGui::PopStyleColor();
        } else {
            ImGui::TextUnformatted(uni);
        }
        start = upto;
    };

    while (i < n) {
        /* ** toggles bold (ignored inside code so `**` in a code snippet stays). */
        if (!codestate && i + 1 < n && s[i] == '*' && s[i+1] == '*') {
            flush(i);
            boldstate = !boldstate;
            i += 2; start = i;
            continue;
        }
        /* ` toggles inline code. */
        if (s[i] == '`') {
            flush(i);
            codestate = !codestate;
            i += 1; start = i;
            continue;
        }
        i++;
    }
    flush(n);
}

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
    /* Paragraph buffer -- accumulates consecutive non-structural lines. */
    char para[8192];
    size_t para_len = 0;

    /* Convert LaTeX per-run inside md_emit_para_runs (below). The paragraph
     * buffer here just accumulates raw text -- markers preserved. */
    auto flush_para = [&]() {
        if (para_len == 0) return;
        md_emit_para_runs(para, para_len);
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

        /* Blank line -> paragraph break. */
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

        /* Bullet lists: - item, * item, * item */
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
             * paragraph). v16 (2026-09-22) -- KEEP inline markers (`**`
             * `*` `` ` ``) so md_emit_para_runs can render bold + code
             * runs. Old code stripped them, flattening every heading /
             * emphasis / code identifier in AI answers. */
            if (effective_len > 0) {
                if (para_len > 0 && para_len + 1 < sizeof(para)) {
                    para[para_len++] = ' ';
                }
                for (size_t k = 0; k < effective_len; k++) {
                    if (para_len + 1 >= sizeof(para) - 1) break;
                    para[para_len++] = p[k];
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
        /* Fenced code -- MUST be at line start (after \n or at text
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
                /* No newline after fence -- treat whole rest as code */
                md_render_code_block("", lang_start, end - lang_start,
                                     block_idx++, 0.0f, font_mul);
                return;
            }
            /* Language token -- trim whitespace. */
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
            /* Reject languages > 20 chars -- false-positive fence in
             * prose (very rare but defensive). Fall through to plain. */
            if (lang_raw_len > 20) {
                /* Not a real fence -- advance one char + continue. */
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
            /* No closer -- fall through to plain */
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
            /* No closer -- fall through to plain */
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
 * Ctrl+Shift+arrow. Full 12+ hotkey coverage -- see g_hk table in
 * launcher/src/main.c. */
/* Render a single chat message.
 *
 * Architecture: NO nested BeginChild -- the bubble is drawn as a
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
     * for readability -- text alpha scaling at low overall opacity
     * makes prose unreadable in a way that's worse than the visual
     * inconsistency of opaque text over a semi-transparent bubble. */
    /* v15 (2026-08-11): theme-aware BLACK & WHITE bubbles. All surfaces
     * drawn with GetColorU32 (below) so they FADE with the opacity slider
     * (the global ImGuiStyleVar_Alpha). No hue anywhere. */
    int th_eff = (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
    ImVec4 bg, border, label_col, text_col, dim_col, btn_bg, btn_hi;
    if (th_eff == 1) {
        bg        = (role == UI_MSG_USER) ? ImVec4(0.90f, 0.90f, 0.92f, 1.0f)
                                          : ImVec4(0.965f, 0.965f, 0.975f, 1.0f);
        border    = ImVec4(0.0f, 0.0f, 0.0f, 0.12f);
        label_col = ImVec4(0.36f, 0.36f, 0.41f, 1.0f);
        text_col  = ImVec4(0.09f, 0.09f, 0.11f, 1.0f);
        dim_col   = ImVec4(0.42f, 0.42f, 0.47f, 1.0f);
        btn_bg    = ImVec4(0.0f, 0.0f, 0.0f, 0.05f);
        btn_hi    = ImVec4(0.0f, 0.0f, 0.0f, 0.10f);
    } else {
        /* v16 (2026-09-22) DARK bubbles -- NL palette. AI bubble sits on
         * NL.card (#111) so it lifts crisply off the #0A0A0A window; USER
         * bubble goes one step brighter (~#1E) for right-side distinction.
         * No hue anywhere -- pure monochrome so any exam BG shows through. */
        bg        = (role == UI_MSG_USER) ? ImVec4(0.118f, 0.118f, 0.125f, 1.0f)
                                          : ImVec4(0.067f, 0.067f, 0.067f, 1.0f);
        border    = ImVec4(1.0f, 1.0f, 1.0f, 0.06f);
        label_col = ImVec4(0.604f, 0.604f, 0.604f, 1.0f);
        text_col  = ImVec4(0.960f, 0.960f, 0.970f, 1.0f);
        dim_col   = ImVec4(0.545f, 0.545f, 0.580f, 1.0f);
        btn_bg    = ImVec4(1.0f, 1.0f, 1.0f, 0.05f);
        btn_hi    = ImVec4(1.0f, 1.0f, 1.0f, 0.10f);
    }

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
     * output is dynamic -- bold-strip, list rendering, fenced-code
     * insertion all vary). Instead we use a two-pass approach:
     *  1. Save cursor pos.
     *  2. Render everything (label + md_render'd body).
     *  3. Compute rect from saved pos to current pos.
     *  4. Backfill the rounded background via a channel-splitter so
     *     the bg appears BEHIND the already-emitted text.
     *
     * ImGui's ImDrawListSplitter is the correct tool for this -- it
     * lets us switch to channel 0 (bg) after rendering to channel 1
     * (fg), then merge. */
    ImDrawList *dl = ImGui::GetWindowDrawList();
    static ImDrawListSplitter s_split;   /* reused across bubbles */
    s_split.Split(dl, 2);
    s_split.SetCurrentChannel(dl, 1);    /* draw text on channel 1 (fg) */

    ImVec2 start = ImGui::GetCursorScreenPos();
    /* Padding: 22px horizontal so text has generous breathing room, 15px
     * vertical so paragraphs / MD blocks don't feel cramped against the
     * bubble edges. v16 (2026-09-22): bumped from 20x12 for more air after
     * Sam's readability pass. */
    float pad_h = 22.0f, pad_v = 15.0f;

    /* Constrain body to bubble width. Push cursor inward for padding
     * and push text-wrap so prose wraps within bubble width. */
    ImGui::SetCursorScreenPos(ImVec2(start.x + pad_h, start.y + pad_v));

    /* v16 (2026-09-22) -- NO role label, NO top separator. Right/left alignment
     * + bubble bg already distinguish USER vs AI; a "You"/"AI" chip is redundant
     * chat-app chrome (Sam's rule). Body starts at top padding. */
    (void)label_col;
    ImGui::SetCursorScreenPos(ImVec2(start.x + pad_h, start.y + pad_v));

    /* Body -- text wraps at bubble body width.
     *
     * CRITICAL: PushTextWrapPos takes a WINDOW-LOCAL x coord (per
     * ImGui docs), NOT a screen coord. Passing `start.x + ...` was
     * a bug -- screen coordinates on multi-monitor setups can be
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
        const char *dots[3] = { "* Thinking",
                                "* * Thinking",
                                "* * * Thinking" };
        ImGui::PushStyleColor(ImGuiCol_Text, dim_col);
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
                    ImGui::PushStyleColor(ImGuiCol_Text, dim_col);
                    ImGui::TextUnformatted("\xE2\x96\x8A");
                    ImGui::PopStyleColor();
                }
            }
        }
    }
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();

    /* v16 (2026-09-22) -- Copy-full / Copy-answer buttons removed. The hotkeys
     * (Ctrl+Alt+C full, Ctrl+Alt+A answer) still work and the answer style is
     * cleaner without per-bubble chrome. */
    (void)btn_bg; (void)btn_hi;

    /* Capture end cursor and compute rect. */
    ImVec2 end = ImGui::GetCursorScreenPos();
    float rect_h = (end.y + pad_v) - start.y;
    if (rect_h < 40.0f) rect_h = 40.0f;
    ImVec2 rect_max = ImVec2(start.x + bubble_max_w, start.y + rect_h);

    /* ── Bubble draw phase 2: backfill background on channel 0 ── */
    s_split.SetCurrentChannel(dl, 0);
    dl->AddRectFilled(start, rect_max,
        ImGui::GetColorU32(bg), 8.0f);
    dl->AddRect(start, rect_max,
        ImGui::GetColorU32(border), 8.0f, 0, 1.0f);
    s_split.Merge(dl);

    /* Ensure ImGui knows the item consumed this space so subsequent
     * calls advance below the bubble. Reserve a Dummy at the bottom
     * with the full rect width. */
    ImGui::SetCursorScreenPos(ImVec2(start.x, rect_max.y + 8.0f));
    ImGui::Dummy(ImVec2(bubble_max_w, 0));
}

/* ══════════════════════════════════════════════════════════════════ *
 * v14b (2026-08-11) -- GORGEOUS custom-drawn UI toolkit                 *
 *                                                                      *
 * ImGui's default widgets look utilitarian, so the whole overlay is    *
 * rendered with a hand-built toolkit: vector icons (no icon font       *
 * needed -- the atlas is ASCII-only), pill buttons, a gradient header,  *
 * segmented tabs, and section headers. Every control still calls the   *
 * same runtime setters the hotkeys use, so nothing here is a stub.     *
 * ══════════════════════════════════════════════════════════════════ */

/* Palette bundle passed to every helper (built once per frame). */
struct ui_theme_t {
    ImVec4 accent, accent_hi, accent_dim, accent2, accent_text;
    ImVec4 frame_bg, frame_hi, card_bg, card_border;
    ImVec4 text, text_dim, win_bg, sep;
};

/* Icon identifiers. */
enum {
    IC_NONE = -1, IC_GEAR = 0, IC_MOON, IC_SUN, IC_BOLT, IC_CHAT, IC_SEND,
    IC_PLUS, IC_STOP, IC_REFRESH, IC_SPARK, IC_SLIDERS, IC_LAYOUT, IC_TEXT,
    IC_CHEVRON_UP, IC_CHEVRON_DOWN, IC_CAMERA, IC_TRASH,
    IC_COPY, IC_CODE, IC_EYE_OFF, IC_LEAN,
    /* v16 (2026-09-22) -- reskin additions: cleaner header + composer. */
    IC_MSGSQ, IC_X, IC_EYE, IC_MONITOR
};

/* 8 unit directions (avoids pulling in <math.h> for cos/sin). */
static const float g_dir8[8][2] = {
    { 1.000f,  0.000f}, { 0.707f,  0.707f}, { 0.000f,  1.000f}, {-0.707f,  0.707f},
    {-1.000f,  0.000f}, {-0.707f, -0.707f}, { 0.000f, -1.000f}, { 0.707f, -0.707f},
};

/* Map an icon id to its Lucide glyph (UTF-8). Codepoints from
 * lucide-static font/codepoints.json (stroke icons, modern aesthetic). */
static const char *icon_glyph(int kind) {
    switch (kind) {
    case IC_GEAR:    return "\xEE\x85\x94";  /* E154 settings            */
    case IC_MOON:    return "\xEE\x84\x9E";  /* E11E moon                */
    case IC_SUN:     return "\xEE\x85\xB8";  /* E178 sun                 */
    case IC_BOLT:    return "\xEE\x86\xB4";  /* E1B4 zap                 */
    case IC_CHAT:    return "\xEE\x84\x96";  /* E116 message-circle      */
    case IC_SEND:    return "\xEE\x85\x92";  /* E152 send                */
    case IC_PLUS:    return "\xEE\x84\xBD";  /* E13D plus                */
    case IC_STOP:    return "\xEE\x85\xA7";  /* E167 square (stop)       */
    case IC_REFRESH: return "\xEE\x85\x85";  /* E145 refresh-cw          */
    case IC_SPARK:   return "\xEE\x90\x92";  /* E412 sparkles            */
    case IC_SLIDERS: return "\xEE\x8A\x9A";  /* E29A sliders-horizontal  */
    case IC_LAYOUT:  return "\xEE\x87\x81";  /* E1C1 layout-dashboard    */
    case IC_TEXT:    return "\xEE\x86\x98";  /* E198 type                */
    case IC_CHEVRON_UP:   return "\xEE\x81\xB0";  /* E070 chevron-up      */
    case IC_CHEVRON_DOWN: return "\xEE\x81\xAD";  /* E06D chevron-down    */
    case IC_CAMERA:  return "\xEE\x81\xA4";  /* E064 camera              */
    case IC_TRASH:   return "\xEE\x86\x8E";  /* E18E trash-2             */
    case IC_COPY:    return "\xEE\x82\x9E";  /* E09E copy                */
    case IC_CODE:    return "\xEE\x82\x93";  /* E093 code                */
    case IC_EYE_OFF: return "\xEE\x82\xBB";  /* E0BB eye-off (hide)      */
    case IC_LEAN:    return "\xEE\x84\x9B";  /* E11B minimize-2 (lean)   */
    /* v16 reskin glyphs (Lucide). */
    case IC_MSGSQ:   return "\xEE\x84\x97";  /* E117 message-square      */
    case IC_X:       return "\xEE\x86\xB2";  /* E1B2 x                   */
    case IC_EYE:     return "\xEE\x82\xBA";  /* E0BA eye                 */
    case IC_MONITOR: return "\xEE\x84\x9D";  /* E11D monitor             */
    default:         return 0;
    }
}

/* Draw an icon centered at c, roughly radius r, in colour col.
 * Uses the real Font Awesome glyph when the icon font loaded; otherwise
 * falls back to the hand-drawn vector primitives below. `carve` is the
 * background behind the icon (only the vector IC_MOON/IC_SEND use it). */
static void draw_icon(ImDrawList *dl, int kind, ImVec2 c, float r,
                      ImU32 col, ImU32 carve, float th) {
    if (g_font_icons) {
        const char *g = icon_glyph(kind);
        if (g) {
            float sz = r * 2.6f;
            ImVec2 ts = g_font_icons->CalcTextSizeA(sz, 10000.0f, 0.0f, g);
            dl->AddText(g_font_icons, sz,
                        ImVec2(c.x - ts.x * 0.5f, c.y - ts.y * 0.5f), col, g);
            return;
        }
    }
    switch (kind) {
    case IC_GEAR: {
        for (int i = 0; i < 8; i++) {
            ImVec2 a(c.x + g_dir8[i][0] * r * 0.72f, c.y + g_dir8[i][1] * r * 0.72f);
            ImVec2 b(c.x + g_dir8[i][0] * r * 1.15f, c.y + g_dir8[i][1] * r * 1.15f);
            dl->AddLine(a, b, col, th * 1.6f);
        }
        dl->AddCircle(c, r * 0.72f, col, 20, th);
        dl->AddCircleFilled(c, r * 0.30f, col, 12);
        break;
    }
    case IC_MOON: {
        dl->AddCircleFilled(c, r, col, 24);
        dl->AddCircleFilled(ImVec2(c.x + r * 0.55f, c.y - r * 0.30f), r * 0.92f, carve, 24);
        break;
    }
    case IC_SUN: {
        dl->AddCircleFilled(c, r * 0.55f, col, 16);
        for (int i = 0; i < 8; i++) {
            ImVec2 a(c.x + g_dir8[i][0] * r * 0.85f, c.y + g_dir8[i][1] * r * 0.85f);
            ImVec2 b(c.x + g_dir8[i][0] * r * 1.20f, c.y + g_dir8[i][1] * r * 1.20f);
            dl->AddLine(a, b, col, th);
        }
        break;
    }
    case IC_BOLT: {
        ImVec2 pts[4] = {
            ImVec2(c.x + r * 0.15f, c.y - r * 1.05f),
            ImVec2(c.x - r * 0.55f, c.y + r * 0.15f),
            ImVec2(c.x + r * 0.10f, c.y + r * 0.10f),
            ImVec2(c.x - r * 0.15f, c.y + r * 1.05f),
        };
        dl->AddPolyline(pts, 4, col, 0, th * 1.5f);
        break;
    }
    case IC_CHAT: {
        ImVec2 a(c.x - r, c.y - r * 0.8f), b(c.x + r, c.y + r * 0.35f);
        dl->AddRect(a, b, col, r * 0.4f, 0, th);
        dl->AddTriangleFilled(ImVec2(c.x - r * 0.4f, c.y + r * 0.35f),
                              ImVec2(c.x - r * 0.05f, c.y + r * 0.35f),
                              ImVec2(c.x - r * 0.55f, c.y + r * 0.95f), col);
        break;
    }
    case IC_SEND: {
        dl->AddTriangleFilled(ImVec2(c.x - r * 0.9f, c.y - r * 0.9f),
                              ImVec2(c.x + r * 1.0f, c.y),
                              ImVec2(c.x - r * 0.9f, c.y + r * 0.9f), col);
        dl->AddTriangleFilled(ImVec2(c.x - r * 0.9f, c.y - r * 0.9f),
                              ImVec2(c.x - r * 0.2f, c.y),
                              ImVec2(c.x - r * 0.9f, c.y + r * 0.9f), carve);
        break;
    }
    case IC_PLUS: {
        dl->AddLine(ImVec2(c.x - r, c.y), ImVec2(c.x + r, c.y), col, th);
        dl->AddLine(ImVec2(c.x, c.y - r), ImVec2(c.x, c.y + r), col, th);
        break;
    }
    case IC_STOP: {
        dl->AddRectFilled(ImVec2(c.x - r * 0.7f, c.y - r * 0.7f),
                          ImVec2(c.x + r * 0.7f, c.y + r * 0.7f), col, r * 0.25f);
        break;
    }
    case IC_REFRESH: {
        dl->PathArcTo(c, r * 0.85f, 0.5f, 0.5f + 3.14159265f * 1.5f, 24);
        dl->PathStroke(col, 0, th);
        ImVec2 tip(c.x + g_dir8[0][0] * r * 0.85f, c.y + g_dir8[0][1] * r * 0.85f);
        dl->AddTriangleFilled(ImVec2(tip.x - r * 0.35f, tip.y - r * 0.05f),
                              ImVec2(tip.x + r * 0.35f, tip.y - r * 0.05f),
                              ImVec2(tip.x, tip.y - r * 0.55f), col);
        break;
    }
    case IC_SPARK: {
        ImVec2 up[4] = { ImVec2(c.x, c.y - r), ImVec2(c.x + r * 0.28f, c.y - r * 0.28f),
                         ImVec2(c.x + r, c.y), ImVec2(c.x + r * 0.28f, c.y + r * 0.28f) };
        ImVec2 lo[4] = { ImVec2(c.x, c.y + r), ImVec2(c.x - r * 0.28f, c.y + r * 0.28f),
                         ImVec2(c.x - r, c.y), ImVec2(c.x - r * 0.28f, c.y - r * 0.28f) };
        dl->AddConvexPolyFilled(up, 4, col);
        dl->AddConvexPolyFilled(lo, 4, col);
        break;
    }
    case IC_SLIDERS: {
        for (int i = 0; i < 3; i++) {
            float y = c.y - r * 0.7f + i * r * 0.7f;
            dl->AddLine(ImVec2(c.x - r, y), ImVec2(c.x + r, y), col, th);
            float kx = c.x + ((i & 1) ? -r * 0.4f : r * 0.4f);
            dl->AddCircleFilled(ImVec2(kx, y), th * 1.3f, col, 8);
        }
        break;
    }
    case IC_LAYOUT: {
        dl->AddRect(ImVec2(c.x - r, c.y - r * 0.8f), ImVec2(c.x + r, c.y + r * 0.8f),
                    col, r * 0.2f, 0, th);
        dl->AddLine(ImVec2(c.x - r * 0.1f, c.y - r * 0.8f),
                    ImVec2(c.x - r * 0.1f, c.y + r * 0.8f), col, th);
        break;
    }
    case IC_TEXT: {
        dl->AddLine(ImVec2(c.x - r, c.y - r * 0.6f), ImVec2(c.x + r, c.y - r * 0.6f), col, th);
        dl->AddLine(ImVec2(c.x - r, c.y),            ImVec2(c.x + r * 0.5f, c.y), col, th);
        dl->AddLine(ImVec2(c.x - r, c.y + r * 0.6f), ImVec2(c.x + r * 0.7f, c.y + r * 0.6f), col, th);
        break;
    }
    default:
        dl->AddCircle(c, r * 0.8f, col, 16, th);
        break;
    }
}

/* Circular icon button (used in the header). */
static bool icon_button(const char *id, int kind, float box, const ui_theme_t &T,
                        float scale, bool accent_bg = false) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton(id, ImVec2(box, box));
    bool hov = ImGui::IsItemHovered();
    bool clk = ImGui::IsItemClicked();
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 c(p.x + box * 0.5f, p.y + box * 0.5f);
    ImU32 bgc = accent_bg
        ? ImGui::GetColorU32(hov ? T.accent_hi : T.accent)
        : (hov ? ImGui::GetColorU32(T.frame_hi) : 0);
    if (accent_bg || hov) dl->AddCircleFilled(c, box * 0.46f, bgc, 24);
    ImU32 icol = accent_bg ? ImGui::GetColorU32(T.accent_text)
                           : ImGui::GetColorU32(hov ? T.text : T.text_dim);
    ImU32 carve = accent_bg ? bgc : ImGui::GetColorU32(hov ? T.frame_hi : T.win_bg);
    draw_icon(dl, kind, c, box * 0.24f, icol, carve, 2.0f * scale);
    return clk;
}

/* Pill button with optional leading icon + label. primary => accent fill. */
static bool cta_button(const char *id, int icon_kind, const char *label,
                       bool primary, float scale, const ui_theme_t &T) {
    float h = ImGui::GetFrameHeight() * 1.12f;
    float padx = 13.0f * scale;
    float isz = (icon_kind != IC_NONE) ? h * 0.42f : 0.0f;
    float igap = (icon_kind != IC_NONE) ? 7.0f * scale : 0.0f;
    ImVec2 ts = ImGui::CalcTextSize(label);
    float w = padx * 2 + isz + igap + ts.x;
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton(id, ImVec2(w, h));
    bool hov = ImGui::IsItemHovered();
    bool clk = ImGui::IsItemClicked();
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImU32 bg = primary ? ImGui::GetColorU32(hov ? T.accent_hi : T.accent)
                       : ImGui::GetColorU32(hov ? T.frame_hi : T.frame_bg);
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), bg, h * 0.30f);
    if (primary)   /* subtle top sheen for a glassy accent pill */
        dl->AddLine(ImVec2(p.x + h * 0.35f, p.y + 1.5f * scale),
                    ImVec2(p.x + w - h * 0.35f, p.y + 1.5f * scale),
                    ImGui::GetColorU32(ImVec4(1, 1, 1, 0.28f)), 1.0f);
    if (!primary && hov)
        dl->AddRect(p, ImVec2(p.x + w, p.y + h), ImGui::GetColorU32(T.accent), h * 0.30f, 0, 1.0f);
    ImU32 fg = primary ? ImGui::GetColorU32(T.accent_text) : ImGui::GetColorU32(T.text);
    if (icon_kind != IC_NONE) {
        ImVec2 ic(p.x + padx + isz * 0.5f, p.y + h * 0.5f);
        draw_icon(dl, icon_kind, ic, isz * 0.55f, fg, bg, 2.0f * scale);
    }
    dl->AddText(ImVec2(p.x + padx + isz + igap, p.y + (h - ts.y) * 0.5f), fg, label);
    return clk;
}

/* Section header: icon chip + title + faint accent underline. */
static void section_header(int icon_kind, const char *title, float scale,
                           const ui_theme_t &T) {
    ImGui::Dummy(ImVec2(0, 4.0f * scale));
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList *dl = ImGui::GetWindowDrawList();
    float fh = ImGui::GetFontSize();
    ImVec2 c(p.x + fh * 0.55f, p.y + fh * 0.55f);
    dl->AddCircleFilled(c, fh * 0.62f, ImGui::GetColorU32(T.frame_hi), 16);
    draw_icon(dl, icon_kind, c, fh * 0.34f, ImGui::GetColorU32(T.accent),
              ImGui::GetColorU32(T.frame_hi), 1.8f * scale);
    ImGui::SetCursorScreenPos(ImVec2(p.x + fh * 1.5f, p.y + (fh * 1.1f - fh) * 0.5f));
    ImGui::TextColored(T.text, "%s", title);
    ImVec2 up = ImGui::GetCursorScreenPos();
    float availw = ImGui::GetContentRegionAvail().x;
    dl->AddLine(ImVec2(up.x, up.y + 2.0f * scale),
                ImVec2(up.x + availw, up.y + 2.0f * scale),
                ImGui::GetColorU32(T.sep), 1.0f);
    ImGui::Dummy(ImVec2(0, 7.0f * scale));
}

/* Frosted "glass" card: translucent surface + hairline white border,
 * auto-sized to its content. Wrap a section's widgets in card_begin/end. */
static void card_begin(const char *id, const ui_theme_t &T, float scale) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, T.card_bg);
    ImGui::PushStyleColor(ImGuiCol_Border,  T.card_border);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(13.0f * scale, 11.0f * scale));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::BeginChild(id, ImVec2(0.0f, 0.0f),
                      ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_NoScrollbar);
}
static void card_end(void) {
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

/* v16 (2026-09-22) -- Shared logo tile used by header + welcome hero.
 * A rounded accent square with a sparkle glyph centered on top. No external
 * PNG asset dependency -- pure vector so it always renders. */
static void draw_logo_tile(ImDrawList *dl, ImVec2 lp, float sz, float scale, const ui_theme_t &T) {
    dl->AddRectFilled(lp, ImVec2(lp.x + sz, lp.y + sz),
                      ImGui::GetColorU32(T.accent), sz * 0.22f);
    draw_icon(dl, IC_SPARK, ImVec2(lp.x + sz * 0.5f, lp.y + sz * 0.5f), sz * 0.26f,
              ImGui::GetColorU32(T.accent_text), ImGui::GetColorU32(T.accent), 2.0f * scale);
}

/* v16 (2026-09-22) -- Clean single-row header. Brand tile + "CloakGPT" left;
 * opacity slider + theme chip + camera (Ask) + trash (Clear) + eye-off (Hide)
 * right. NO second row of tabs -- the composer owns input, one view only.
 * Status chip (provider|tier|stream) moved to a subtle right-aligned label
 * BELOW the divider so header stays lean but the info is still discoverable. */
static void draw_topbar(const ui_theme_t &T, float scale, float alpha_cur,
                        const char *prov, const char *tier, int streaming) {
    ImDrawList *dl = ImGui::GetWindowDrawList();
    float rowh = ImGui::GetFrameHeight();

    /* Brand left: logo tile + wordmark. */
    ImVec2 lp = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(rowh, rowh));
    draw_logo_tile(dl, lp, rowh, scale, T);
    ImGui::SameLine(0, 9.0f * scale);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(T.text, "CloakGPT");

    /* Right cluster: opacity slider + theme + camera + trash + hide. */
    float ib      = rowh;
    float sw      = 116.0f * scale;
    float cluster = sw + 8.0f * scale + ib + 6.0f * scale + ib + 4.0f * scale
                       + ib + 4.0f * scale + ib;
    float rx = ImGui::GetContentRegionMax().x - cluster;
    ImGui::SameLine();
    if (rx > ImGui::GetCursorPosX()) ImGui::SetCursorPosX(rx);

    /* v17 (2026-09-22) -- Thin custom opacity slider. 3px track + small knob
     * instead of the chunky ImGui SliderFloat block. Reads immediately as
     * "slider" without dominating the header. Hover shows a tooltip. */
    {
        ImVec2 sp = ImGui::GetCursorScreenPos();
        ImGui::InvisibleButton("##tb_op", ImVec2(sw, rowh));
        bool hov    = ImGui::IsItemHovered();
        bool active = ImGui::IsItemActive();
        float trk_y = sp.y + rowh * 0.5f;
        ImU32 trk_bg = ImGui::GetColorU32(T.frame_bg);
        ImU32 trk_fg = ImGui::GetColorU32(T.accent);
        /* Track base. */
        dl->AddRectFilled(ImVec2(sp.x, trk_y - 1.5f),
                          ImVec2(sp.x + sw, trk_y + 1.5f), trk_bg, 2.0f);
        /* Filled portion (range 0.05..1.00). */
        float t = (alpha_cur - 0.05f) / 0.95f;
        if (t < 0.0f) t = 0.0f; if (t > 1.0f) t = 1.0f;
        float kx = sp.x + t * sw;
        dl->AddRectFilled(ImVec2(sp.x, trk_y - 1.5f),
                          ImVec2(kx,   trk_y + 1.5f), trk_fg, 2.0f);
        /* Knob (grows on hover / drag). */
        float knob_r = (hov || active) ? 6.0f : 5.0f;
        dl->AddCircleFilled(ImVec2(kx, trk_y), knob_r,
                            ImGui::GetColorU32(T.accent_hi), 20);
        /* Drag: alpha proportional to cursor X inside the track. */
        if (active) {
            float mx = ImGui::GetIO().MousePos.x - sp.x;
            if (mx < 0.0f) mx = 0.0f;
            if (mx > sw)   mx = sw;
            float new_a = 0.05f + (mx / sw) * 0.95f;
            float d = new_a - alpha_cur;
            if (d > 0.001f || d < -0.001f) ui_bump_alpha(d);
        }
        if (hov) ImGui::SetTooltip("Opacity  %d%%", (int)(alpha_cur * 100 + 0.5f));
    }
    ImGui::SameLine(0, 8.0f * scale);
    {
        int tp  = ui_get_theme_pref();
        int eff = ui_get_theme_effective();
        if (icon_button("##tb_theme", eff == 1 ? IC_SUN : IC_MOON, ib, T, scale))
            ui_apply_theme_and_flags((tp + 1) % 3, ui_get_overlay_flags());
    }
    ImGui::SameLine(0, 6.0f * scale);
    /* Settings (gear) -- toggles the Home hub over the chat. Highlighted when
     * Home is showing so it reads as "click again to return to chat". */
    if (icon_button("##tb_gear", IC_GEAR, ib, T, scale, g_home_view_forced != 0))
        (g_home_view_forced ? ui_view_show_chat() : ui_view_show_home());
    ImGui::SameLine(0, 4.0f * scale);
    if (icon_button("##tb_clear", IC_TRASH,   ib, T, scale)) ui_action_fire(SVC_HK_NEW_CHAT);
    ImGui::SameLine(0, 4.0f * scale);
    if (icon_button("##tb_hide",  IC_EYE_OFF, ib, T, scale)) ui_action_fire(SVC_HK_TOGGLE);

    /* Thin divider (hairline stroke). */
    ImGui::Dummy(ImVec2(0, 6.0f * scale));
    ImVec2 sp = ImGui::GetCursorScreenPos();
    float availw = ImGui::GetContentRegionAvail().x;
    dl->AddLine(ImVec2(sp.x, sp.y), ImVec2(sp.x + availw, sp.y), ImGui::GetColorU32(T.sep), 1.0f);

    /* Right-aligned status label below the divider: provider | tier | stream. */
    if (prov && prov[0]) {
        char chip[96];
        _snprintf(chip, sizeof(chip) - 1, "%s  \xE2\x80\xA2  %s%s",
                  prov, tier ? tier : "",
                  streaming ? "  \xE2\x80\xA2  stream" : "");
        chip[sizeof(chip) - 1] = 0;
        ImGui::Dummy(ImVec2(0, 4.0f * scale));
        float cw = ImGui::CalcTextSize(chip).x;
        float _availw = ImGui::GetContentRegionAvail().x;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (_availw - cw));
        ImGui::TextColored(T.text_dim, "%s", chip);
    } else {
        ImGui::Dummy(ImVec2(0, 4.0f * scale));
    }
}

/* v17 (2026-09-22) -- Reusable thin slider. Matches the topbar opacity style:
 * 3px track, small knob, accent fill, tooltip on hover. Called from home hub
 * (Opacity + Font) and anywhere else that used ImGui::SliderFloat. */
static void draw_thin_slider(const char *id, float *val, float vmin, float vmax,
                             float width, const ui_theme_t &T, float scale,
                             const char *fmt) {
    float rowh = ImGui::GetFrameHeight();
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 sp = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton(id, ImVec2(width, rowh));
    bool hov    = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    float trk_y = sp.y + rowh * 0.5f;
    dl->AddRectFilled(ImVec2(sp.x, trk_y - 1.5f),
                      ImVec2(sp.x + width, trk_y + 1.5f),
                      ImGui::GetColorU32(T.frame_bg), 2.0f);
    float span = vmax - vmin;
    float t = span > 0 ? (*val - vmin) / span : 0.0f;
    if (t < 0.0f) t = 0.0f; if (t > 1.0f) t = 1.0f;
    float kx = sp.x + t * width;
    dl->AddRectFilled(ImVec2(sp.x, trk_y - 1.5f),
                      ImVec2(kx,   trk_y + 1.5f),
                      ImGui::GetColorU32(T.accent), 2.0f);
    float knob_r = (hov || active) ? 6.0f : 5.0f;
    dl->AddCircleFilled(ImVec2(kx, trk_y), knob_r,
                        ImGui::GetColorU32(T.accent_hi), 20);
    if (active && span > 0) {
        float mx = ImGui::GetIO().MousePos.x - sp.x;
        if (mx < 0.0f) mx = 0.0f;
        if (mx > width) mx = width;
        *val = vmin + (mx / width) * span;
    }
    if (hov) {
        char tt[64];
        _snprintf(tt, sizeof(tt) - 1, fmt ? fmt : "%.2f", *val);
        tt[sizeof(tt) - 1] = 0;
        ImGui::SetTooltip("%s", tt);
    }
    (void)scale;
}

/* HOME hub -- the "master control" surface. Every control is live. */
static void draw_home_hub(const ui_theme_t &T, float scale, float alpha_cur,
                          float font_cur, const char *prov, const char *tier,
                          const char *model, int streaming) {
    char buf[96];

    /* ── AI model card ──────────────────────────────────────────── */
    card_begin("##card_ai", T, scale);
    section_header(IC_SPARK, "AI model", scale, T);
    _snprintf(buf, sizeof(buf) - 1, "Provider: %s", (prov && prov[0]) ? prov : "-");
    buf[sizeof(buf) - 1] = 0;
    /* Config cyclers/toggles re-assert Home so the view doesn't jump to
     * Chat (firing these appends a confirmation message, which otherwise
     * clears the home-forced flag). */
    if (cta_button("##h_prov", IC_SPARK, buf, false, scale, T)) { ui_action_fire(SVC_HK_CYCLE_PROVIDER); ui_view_show_home(); }
    ImGui::SameLine(0, 6.0f * scale);
    _snprintf(buf, sizeof(buf) - 1, "Tier: %s", (tier && tier[0]) ? tier : "-");
    buf[sizeof(buf) - 1] = 0;
    if (cta_button("##h_tier", IC_NONE, buf, false, scale, T)) { ui_action_fire(SVC_HK_CYCLE_TIER); ui_view_show_home(); }
    ImGui::TextColored(T.text_dim, "Model: %s", (model && model[0]) ? model : "(default)");
    if (cta_button("##h_str", IC_NONE, streaming ? "Streaming: ON" : "Streaming: OFF",
                   streaming != 0, scale, T)) { ui_action_fire(SVC_HK_STREAM_TOGGLE); ui_view_show_home(); }
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_dir", IC_NONE, "Direct", false, scale, T)) { ui_action_fire(SVC_HK_DIRECT_TOGGLE); ui_view_show_home(); }
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_ltx", IC_TEXT, "LaTeX", false, scale, T)) { ui_action_fire(SVC_HK_LATEX_TOGGLE); ui_view_show_home(); }
    card_end();

    ImGui::Dummy(ImVec2(0, 8.0f * scale));

    /* ── Ask card ───────────────────────────────────────────────── */
    card_begin("##card_ask", T, scale);
    section_header(IC_BOLT, "Ask", scale, T);
    if (cta_button("##h_solve", IC_BOLT, "Auto Solve", true, scale, T)) ui_action_fire(SVC_HK_ASK);
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_type", IC_CHAT, "Type a question", false, scale, T)) { ui_view_show_chat(); ui_chat_toggle(); }
    if (cta_button("##h_regen", IC_REFRESH, "Regenerate", false, scale, T)) ui_action_fire(SVC_HK_REGENERATE);
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_stop", IC_STOP, "Stop", false, scale, T)) { ui_action_fire(SVC_HK_STOP_GEN); ui_view_show_home(); }
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_new", IC_PLUS, "New chat", false, scale, T)) ui_action_fire(SVC_HK_NEW_CHAT);
    /* Copy actions (don't append messages, so no view flip). */
    if (cta_button("##h_creply", IC_COPY, "Copy reply", false, scale, T)) ui_action_fire(SVC_HK_COPY_REPLY);
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_cans", IC_NONE, "Copy answer", false, scale, T)) ui_action_fire(SVC_HK_COPY_ANSWER);
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_ccode", IC_CODE, "Copy code", false, scale, T)) ui_action_fire(SVC_HK_COPY_CODE);
    card_end();

    ImGui::Dummy(ImVec2(0, 8.0f * scale));

    /* ── Appearance card ────────────────────────────────────────── */
    card_begin("##card_appear", T, scale);
    section_header(IC_SLIDERS, "Appearance", scale, T);
    {
        int tp = ui_get_theme_pref();
        const char *tn = (tp == 0) ? "Dark" : (tp == 1) ? "Light" : "Auto";
        _snprintf(buf, sizeof(buf) - 1, "Theme: %s", tn);
        buf[sizeof(buf) - 1] = 0;
        if (cta_button("##h_theme", tp == 1 ? IC_SUN : IC_MOON, buf, false, scale, T))
            ui_apply_theme_and_flags((tp + 1) % 3, ui_get_overlay_flags());
    }
    float a = alpha_cur;
    /* v17 (2026-09-22) -- thin slider for Opacity + Font (matches topbar
     * style). Label sits to the LEFT via SameLine so it reads clean. */
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(T.text_dim, "Opacity");
    ImGui::SameLine(84.0f * scale);
    draw_thin_slider("##h_opacity", &a, 0.05f, 1.00f, 200.0f * scale, T, scale, "Opacity  %d%%  (%.2f)");
    if (a != alpha_cur) ui_bump_alpha(a - alpha_cur);
    float f = font_cur;
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(T.text_dim, "Font");
    ImGui::SameLine(84.0f * scale);
    draw_thin_slider("##h_font", &f, 0.60f, 3.00f, 200.0f * scale, T, scale, "Font  %.2fx");
    if (f != font_cur) ui_bump_font(f - font_cur);
    {
        int lean_on = ui_is_lean();
        if (cta_button("##h_lean", IC_LEAN, lean_on ? "Lean mode: ON" : "Lean mode: OFF",
                       lean_on != 0, scale, T)) ui_toggle_lean();
    }
    card_end();

    ImGui::Dummy(ImVec2(0, 8.0f * scale));

    /* ── Layout card ────────────────────────────────────────────── */
    card_begin("##card_layout", T, scale);
    section_header(IC_LAYOUT, "Layout", scale, T);
    if (cta_button("##h_wp", IC_NONE, "Wider", false, scale, T)) ui_resize(40, 0);
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_wm", IC_NONE, "Narrower", false, scale, T)) ui_resize(-40, 0);
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_hp", IC_NONE, "Taller", false, scale, T)) ui_resize(0, 40);
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_hm", IC_NONE, "Shorter", false, scale, T)) ui_resize(0, -40);
    if (cta_button("##h_corner", IC_LAYOUT, "Corner", false, scale, T)) ui_cycle_corner();
    ImGui::SameLine(0, 6.0f * scale);
    if (cta_button("##h_reset", IC_REFRESH, "Reset layout", false, scale, T)) ui_reset_geometry();
    ImGui::Dummy(ImVec2(0, 2.0f * scale));
    ImGui::TextColored(T.text_dim, "Drag the header to move. Drag any corner to resize.");
    card_end();
}

/* v16 (2026-09-22) -- Centered empty-state hero: logo tile + welcome + subtitle.
 * NO CTA buttons -- the always-on composer at the bottom of the window provides
 * the Ask affordance (camera + text + send). One clean surface. */
static void draw_welcome_hero(const ui_theme_t &T, float scale) {
    ImDrawList *dl = ImGui::GetWindowDrawList();
    float availw = ImGui::GetContentRegionAvail().x;
    float innerH = ImGui::GetContentRegionAvail().y;
    float logoS  = 48.0f * scale;
    float blockH = logoS + 14.0f * scale + ImGui::GetFontSize() * 3.4f;
    float topPad = (innerH - blockH) * 0.40f;
    if (topPad < 8.0f * scale) topPad = 8.0f * scale;
    ImGui::Dummy(ImVec2(0, topPad));

    ImVec2 lp = ImGui::GetCursorScreenPos();
    draw_logo_tile(dl, ImVec2(lp.x + (availw - logoS) * 0.5f, lp.y), logoS, scale, T);
    ImGui::Dummy(ImVec2(0, logoS + 14.0f * scale));

    ImGui::SetWindowFontScale(1.30f);
    const char *title = "Welcome to CloakGPT";
    float tw = ImGui::CalcTextSize(title).x;
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (ImGui::GetContentRegionAvail().x - tw) * 0.5f);
    ImGui::TextColored(T.text, "%s", title);
    ImGui::SetWindowFontScale(1.0f);

    ImGui::Dummy(ImVec2(0, 4.0f * scale));
    const char *sub = "Ask anything \xE2\x80\x94 the camera / \xE2\x86\x91 button snaps whatever's on screen.";
    float sw2 = ImGui::CalcTextSize(sub).x;
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (ImGui::GetContentRegionAvail().x - sw2) * 0.5f);
    ImGui::TextColored(T.text_dim, "%s", sub);
}

/* v16 (2026-09-22) -- Always-on composer. Camera square (screenshot+ask) +
 * rounded live-input field (click to focus, unfocus on outside click, buffer
 * preserved) + send square (submits typed text OR fires ASK if empty).
 * All svcldb hotkeys stay wired unchanged; the LL keyboard hook still feeds
 * g_chat_buf while active. Field radius 8, corner squares 6 (Apple-tight). */
static void composer_bar(const ui_theme_t &T, float scale) {
    ImDrawList *dl = ImGui::GetWindowDrawList();
    float rowh   = 42.0f * scale;
    float cam    = rowh;
    float send   = rowh;
    float gap    = 8.0f * scale;
    float availw = ImGui::GetContentRegionAvail().x;
    float fieldw = availw - send - cam - gap * 2.0f;
    if (fieldw < 60.0f * scale) fieldw = 60.0f * scale;
    bool  active = ui_chat_is_active() != 0;
    float fh     = ImGui::GetFontSize();

    ImU32 soft_border = ImGui::GetColorU32(T.card_border);
    ImU32 hi_border   = IM_COL32(220, 224, 235, 200);    /* focus ring -- not stark white */

    /* Camera (LEFT). Fires ASK -- screenshot + immediate send to AI. */
    ImVec2 cp = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##cmp_cam", ImVec2(cam, rowh));
    bool cam_hov = ImGui::IsItemHovered(), cam_clk = ImGui::IsItemClicked();
    dl->AddRectFilled(cp, ImVec2(cp.x + cam, cp.y + rowh),
                      ImGui::GetColorU32(cam_hov ? T.frame_hi : T.card_bg), 6.0f * scale);
    dl->AddRect(cp, ImVec2(cp.x + cam, cp.y + rowh), soft_border, 6.0f * scale, 0, 1.0f);
    draw_icon(dl, IC_CAMERA, ImVec2(cp.x + cam * 0.5f, cp.y + rowh * 0.5f),
              cam * 0.24f, ImGui::GetColorU32(T.text),
              ImGui::GetColorU32(T.card_bg), 1.8f * scale);
    if (cam_clk) ui_action_fire(SVC_HK_ASK);
    ImGui::SameLine(0, gap);

    /* Rounded input field. Click to focus; when active, mirrors g_chat_buf. */
    ImVec2 fp = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##cmp_field", ImVec2(fieldw, rowh));
    bool fld_clk = ImGui::IsItemClicked();
    dl->AddRectFilled(fp, ImVec2(fp.x + fieldw, fp.y + rowh),
                      ImGui::GetColorU32(T.card_bg), 8.0f * scale);
    dl->AddRect(fp, ImVec2(fp.x + fieldw, fp.y + rowh),
                active ? hi_border : soft_border, 8.0f * scale, 0,
                active ? 1.4f * scale : 1.0f);

    char cbuf[CHAT_BUF_SIZE]; int clen = 0; int ccur = 0;
    if (active) {
        ensure_chat_cs();
        EnterCriticalSection(&g_chat_cs);
        clen = g_chat_len; if (clen > CHAT_BUF_SIZE - 1) clen = CHAT_BUF_SIZE - 1;
        memcpy(cbuf, g_chat_buf, (size_t)clen); cbuf[clen] = 0;
        ccur = g_chat_cursor; if (ccur < 0) ccur = 0; if (ccur > clen) ccur = clen;
        LeaveCriticalSection(&g_chat_cs);
    }
    /* Clip so long typing doesn't spill into the send square. */
    dl->PushClipRect(ImVec2(fp.x + 8.0f * scale, fp.y),
                     ImVec2(fp.x + fieldw - 8.0f * scale, fp.y + rowh), true);
    ImVec2 tp(fp.x + 14.0f * scale, fp.y + (rowh - fh) * 0.5f);
    bool blink = ((GetTickCount() / 500) & 1) == 0;
    if (active) {
        if (clen > 0) {
            /* Split at cursor so the blink block sits at ccur. */
            char before[CHAT_BUF_SIZE], after[CHAT_BUF_SIZE];
            memcpy(before, cbuf, (size_t)ccur); before[ccur] = 0;
            int tail = clen - ccur;
            memcpy(after, cbuf + ccur, (size_t)tail); after[tail] = 0;
            float bx = tp.x;
            if (ccur > 0) {
                dl->AddText(ImVec2(bx, tp.y), ImGui::GetColorU32(T.text), before);
                bx += ImGui::CalcTextSize(before).x;
            }
            if (blink) dl->AddText(ImVec2(bx, tp.y), ImGui::GetColorU32(T.text), "\xE2\x96\x8A");
            if (tail > 0) {
                float ax = bx + (blink ? ImGui::CalcTextSize("\xE2\x96\x8A").x : 0.0f);
                dl->AddText(ImVec2(ax, tp.y), ImGui::GetColorU32(T.text), after);
            }
        } else {
            dl->AddText(tp, ImGui::GetColorU32(T.text), blink ? "\xE2\x96\x8A" : " ");
        }
    } else {
        dl->AddText(tp, ImGui::GetColorU32(T.text_dim), "Ask anything\xE2\x80\xA6");
    }
    dl->PopClipRect();

    if (fld_clk && !active) {
        /* Activate typing mode -- preserves any existing buffer content. */
        ensure_chat_cs();
        EnterCriticalSection(&g_chat_cs);
        bool has_text = g_chat_len > 0;
        LeaveCriticalSection(&g_chat_cs);
        if (has_text) {
            EnterCriticalSection(&g_ui_cs); g_visible = true; LeaveCriticalSection(&g_ui_cs);
            InterlockedExchange(&g_chat_active, 1);
            wake_dwm_composition();
        } else {
            ui_chat_toggle();
        }
    }

    /* Send square (RIGHT). Only enabled when there's typed text -- the camera
     * (LEFT) handles screenshot-only asks. When empty: renders dim + no-op so
     * users understand it's the "commit what I've typed" affordance. Uses the
     * IC_SEND paper-plane glyph so it reads as "send", not "up arrow". */
    bool has_text = false;
    if (active) {
        ensure_chat_cs();
        EnterCriticalSection(&g_chat_cs);
        has_text = g_chat_len > 0;
        LeaveCriticalSection(&g_chat_cs);
    }
    ImGui::SameLine(0, gap);
    ImVec2 sp = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##cmp_send", ImVec2(send, rowh));
    bool snd_hov = ImGui::IsItemHovered(), snd_clk = ImGui::IsItemClicked();
    ImU32 snd_bg = has_text
        ? ImGui::GetColorU32(snd_hov ? T.accent_hi : T.accent)
        : ImGui::GetColorU32(T.frame_bg);
    dl->AddRectFilled(sp, ImVec2(sp.x + send, sp.y + rowh), snd_bg, 6.0f * scale);
    if (!has_text)
        dl->AddRect(sp, ImVec2(sp.x + send, sp.y + rowh),
                    soft_border, 6.0f * scale, 0, 1.0f);
    ImU32 snd_fg = has_text
        ? ImGui::GetColorU32(T.accent_text)
        : ImGui::GetColorU32(T.text_dim);
    draw_icon(dl, IC_SEND, ImVec2(sp.x + send * 0.5f, sp.y + rowh * 0.5f),
              send * 0.24f, snd_fg, snd_bg, 2.0f * scale);
    if (snd_clk && has_text) chat_submit_typed_text();

    /* Outside-click unfocus. Preserves buffer -- only stops LL key routing. */
    if (active && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        ImVec2 m = ImGui::GetIO().MousePos;
        bool in_field = m.x >= fp.x && m.x <= fp.x + fieldw && m.y >= fp.y && m.y <= fp.y + rowh;
        bool in_send  = m.x >= sp.x && m.x <= sp.x + send   && m.y >= sp.y && m.y <= sp.y + rowh;
        bool in_cam   = m.x >= cp.x && m.x <= cp.x + cam    && m.y >= cp.y && m.y <= cp.y + rowh;
        if (!in_field && !in_send && !in_cam) {
            InterlockedExchange(&g_chat_active, 0);
            wake_dwm_composition();
        }
    }
}

/* Visible resize grips -- corner brackets on ALL FOUR corners so it's
 * obvious the overlay is resizable from any corner. */
static void draw_resize_grip(const ui_theme_t &T, float scale) {
    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 ws = ImGui::GetWindowSize();
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImU32 c = ImGui::GetColorU32(T.text_dim);
    float g  = 9.0f * scale;   /* bracket arm length */
    float in = 5.0f * scale;   /* inset from the edge */
    float th = 1.7f * scale;
    float L = wp.x + in, R = wp.x + ws.x - in;
    float Tp = wp.y + in, B = wp.y + ws.y - in;
    /* TL */ dl->AddLine(ImVec2(L, Tp), ImVec2(L + g, Tp), c, th); dl->AddLine(ImVec2(L, Tp), ImVec2(L, Tp + g), c, th);
    /* TR */ dl->AddLine(ImVec2(R, Tp), ImVec2(R - g, Tp), c, th); dl->AddLine(ImVec2(R, Tp), ImVec2(R, Tp + g), c, th);
    /* BL */ dl->AddLine(ImVec2(L, B),  ImVec2(L + g, B),  c, th); dl->AddLine(ImVec2(L, B),  ImVec2(L, B - g),  c, th);
    /* BR */ dl->AddLine(ImVec2(R, B),  ImVec2(R - g, B),  c, th); dl->AddLine(ImVec2(R, B),  ImVec2(R, B - g),  c, th);
}

/* ══════════════ AutoSolver answer dot + Agent status (v15.1) ══════════════ *
 * Drawn on the foreground draw list from INSIDE draw_chat_window, AFTER the
 * capture-hide early return -- so the dot/card/status never leak into the AI
 * screenshot (same guarantee as the overlay).
 *
 * v15.1 (2026-09-22) FULL REDESIGN per LO reference to hooksdll popout.js:
 *   1. Two UI states: DOT (collapsed) + FULL (expanded card w/ slider + resize)
 *   2. Draggable in either state (click-and-drag; short click toggles)
 *   3. macOS-spec colors + pulsing glow during solving states
 *   4. Default opacity 0.30 (was 0.9) -- discrete presence at rest
 *   5. Bottom-right resize grip in FULL -> shrink to a lean answer view
 *   6. Auto-hidden when the main overlay is open (LO invariant: overlay
 *      and dot are mutually exclusive on-screen surfaces)
 *   7. All fields (position/size/opacity/state/colors/hold_ms) persisted
 *      in autosolver.json via as_cfg -- next inject remembers everything
 *
 * Mouse routing:
 *   - When overlay is HIDDEN and the cursor is over the dot area,
 *     ui_point_in_overlay reports 1 for the dot rect + g_mouse_over_widget
 *     is set to 1. The LL mouse hook (rawinput_hook) consumes those clicks
 *     and drops them through ImGui IO -- we then read them here via
 *     ImGui::IsMouseClicked/Down/Released to run the drag / click state
 *     machine on the foreground draw list. */
#include "../autosolver/as_cfg.h"
extern "C" {
    void as_cfg_set_dot_ui_state(int ui);
    void as_cfg_set_dot_pos(int x, int y);
    void as_cfg_set_dot_full_size(int w, int h);
    void as_cfg_set_dot_opacity(double alpha);
    void as_cfg_set_dot_show_slider(int on);
    const as_settings_t *as_cfg(void);
}

static volatile LONG      g_dot_enabled = 1;
static volatile LONG      g_dot_state   = UI_DOT_IDLE;       /* solve state (color)   */
static volatile LONG      g_dot_ui      = 0;                 /* 0=DOT,1=TOOLBAR,2=FULL*/
static volatile LONG      g_dot_jx      = -1;                /* answer-jump target    */
static volatile LONG      g_dot_jy      = -1;
static volatile LONG      g_dot_px      = -1;                /* dragged position      */
static volatile LONG      g_dot_py      = -1;
static volatile LONG      g_dot_full_w  = 340;               /* FULL card size        */
static volatile LONG      g_dot_full_h  = 210;
static volatile LONG      g_dot_show_slider = 1;
static volatile LONG      g_dot_prefs_loaded = 0;
static float              g_dot_alpha   = 0.30f;             /* default lighter       */
static float              g_dot_confidence = -1.0f;          /* -1 unknown; 0..1 else */
static DWORD              g_dot_copied_at = 0;               /* Tick when Copy fired  */
static CRITICAL_SECTION   g_dot_cs;
static volatile LONG      g_dot_cs_init = 0;
static char               g_dot_short[256]  = {0};
static char               g_dot_full[2048]  = {0};
static char               g_dot_question[512] = {0};
static char               g_agent_status[256] = {0};
static volatile LONG      g_agent_active = 0;

/* Published each frame so ui_point_in_overlay / g_mouse_over_widget can
 * hit-test the dot region + the LL mouse hook can consume clicks there. */
static volatile LONG      g_dot_rect_x = 0;
static volatile LONG      g_dot_rect_y = 0;
static volatile LONG      g_dot_rect_w = 0;
static volatile LONG      g_dot_rect_h = 0;
static volatile LONG      g_dot_rect_valid = 0;   /* 1 = dot is currently rendered */

static void dot_ensure_cs(void) {
    if (InterlockedCompareExchange(&g_dot_cs_init, 1, 0) == 0)
        InitializeCriticalSection(&g_dot_cs);
}

static void dot_load_prefs_once(void) {
    if (InterlockedCompareExchange(&g_dot_prefs_loaded, 1, 0) != 0) return;
    const as_settings_t *s = as_cfg();
    if (!s) return;
    InterlockedExchange(&g_dot_ui,     s->dot_ui_state ? 1 : 0);
    InterlockedExchange(&g_dot_px,     s->dot_pos_x);
    InterlockedExchange(&g_dot_py,     s->dot_pos_y);
    InterlockedExchange(&g_dot_full_w, s->dot_full_w);
    InterlockedExchange(&g_dot_full_h, s->dot_full_h);
    InterlockedExchange(&g_dot_show_slider, s->dot_show_slider ? 1 : 0);
    g_dot_alpha = (float)s->dot_opacity;
}

/* Public: TRUE iff the point lies inside the dot's rendered rect this frame.
 * Used by ui_point_in_overlay to route LL-hook clicks to us when the main
 * overlay is hidden. Also used by rawinput_hook's wheel/drag path. */
extern "C" int ui_point_in_dot(int x, int y) {
    if (!InterlockedCompareExchange(&g_dot_rect_valid, 0, 0)) return 0;
    LONG rx = g_dot_rect_x, ry = g_dot_rect_y;
    LONG rw = g_dot_rect_w, rh = g_dot_rect_h;
    if (rw <= 0 || rh <= 0) return 0;
    return (x >= rx && x < rx + rw && y >= ry && y < ry + rh) ? 1 : 0;
}

extern "C" void ui_dot_set_enabled(int on) { InterlockedExchange(&g_dot_enabled, on ? 1 : 0); }
extern "C" int  ui_dot_is_enabled(void)     { return InterlockedCompareExchange(&g_dot_enabled, 0, 0) != 0; }
extern "C" void ui_dot_set_state(int s)     { InterlockedExchange(&g_dot_state, s); }
extern "C" void ui_dot_jump_to(int x, int y){
    InterlockedExchange(&g_dot_jx, x);
    InterlockedExchange(&g_dot_jy, y);
    /* v15.1.2 -- teleport-on-answer semantics (hooksdll parity): reset the
     * dragged position so the fresh answer coord actually pulls the dot in.
     * User re-drag after solve immediately overrides px/py again. */
    if (x >= 0 && y >= 0) {
        InterlockedExchange(&g_dot_px, -1);
        InterlockedExchange(&g_dot_py, -1);
    }
}
extern "C" void ui_dot_set_opacity(float a) {
    if (a < 0.05f) a = 0.05f; if (a > 1.0f) a = 1.0f;
    g_dot_alpha = a;
    as_cfg_set_dot_opacity((double)a);
}
extern "C" void ui_dot_set_answer(const char *s, const char *f) {
    dot_ensure_cs();
    EnterCriticalSection(&g_dot_cs);
    _snprintf(g_dot_short, sizeof(g_dot_short) - 1, "%s", s ? s : ""); g_dot_short[sizeof(g_dot_short) - 1] = 0;
    _snprintf(g_dot_full,  sizeof(g_dot_full)  - 1, "%s", f ? f : ""); g_dot_full[sizeof(g_dot_full)  - 1] = 0;
    LeaveCriticalSection(&g_dot_cs);
}
extern "C" void ui_dot_set_meta(const char *question, double confidence) {
    dot_ensure_cs();
    EnterCriticalSection(&g_dot_cs);
    _snprintf(g_dot_question, sizeof(g_dot_question) - 1, "%s", question ? question : "");
    g_dot_question[sizeof(g_dot_question) - 1] = 0;
    g_dot_confidence = (float)confidence;
    LeaveCriticalSection(&g_dot_cs);
}
extern "C" void ui_agent_set_status(const char *line, int active) {
    dot_ensure_cs();
    EnterCriticalSection(&g_dot_cs);
    _snprintf(g_agent_status, sizeof(g_agent_status) - 1, "%s", line ? line : ""); g_agent_status[sizeof(g_agent_status) - 1] = 0;
    LeaveCriticalSection(&g_dot_cs);
    InterlockedExchange(&g_agent_active, active ? 1 : 0);
}

/* Compose per-state RGBA (opacity applied) for the current solve state. */
static ImU32 dot_color_for_state(int st, float a) {
    const as_settings_t *s = as_cfg();
    unsigned int c;
    switch (st) {
        case UI_DOT_CAPTURING: c = s ? s->dot_col_capturing : 0xFFF59E0A; break;
        case UI_DOT_ANALYZING: c = s ? s->dot_col_analyzing : 0xFFFF9500; break;
        case UI_DOT_EXECUTING: c = s ? s->dot_col_executing : 0xFFAF52DE; break;
        case UI_DOT_DONE:      c = s ? s->dot_col_done      : 0xFF34C759; break;
        case UI_DOT_ERROR:     c = s ? s->dot_col_error     : 0xFFFF3B30; break;
        default:               c = s ? s->dot_col_idle      : 0xFF34C759; /* IDLE */
    }
    int R = (c >> 16) & 0xFF, G = (c >> 8) & 0xFF, B = c & 0xFF;
    int A = (int)(255 * a);
    return IM_COL32(R, G, B, A);
}

static bool dot_state_is_solving(int st) {
    return st == UI_DOT_CAPTURING || st == UI_DOT_ANALYZING || st == UI_DOT_EXECUTING;
}

/* Draw the DOT (collapsed) visual. Also composes + returns the dot's
 * on-screen circle rect so hit-testing can key off it. */
static void draw_dot_glyph(ImDrawList *fg, float cx, float cy, float r, int st, float a, bool solving_pulse) {
    ImU32 col = dot_color_for_state(st, a);
    /* Soft drop shadow so the dot is discernible on light backgrounds. */
    fg->AddCircleFilled(ImVec2(cx + 0.5f, cy + 1.0f), r + 2.0f,
                        IM_COL32(0, 0, 0, (int)(90 * a)));
    /* Filled body + subtle white rim. */
    fg->AddCircleFilled(ImVec2(cx, cy), r, col);
    fg->AddCircle(ImVec2(cx, cy), r, IM_COL32(255, 255, 255, (int)(140 * a)), 0, 1.4f);
    if (solving_pulse) {
        /* Pulsing outer glow: two concentric halos oscillating in size/alpha
         * (~1 Hz) so "we're working" is unmistakable even at low opacity. */
        float t = (float)(GetTickCount() % 1200) / 1200.0f;   /* 0..1 */
        /* Use a triangle-wave approximation instead of cos so we don't
         * need <cmath> in this translation unit. */
        float tri = t < 0.5f ? (t * 2.0f) : (2.0f - t * 2.0f); /* 0..1..0 */
        float ph = tri;                                        /* 0..1..0 */
        float g1 = r + 4.0f + ph * 4.0f;
        float g2 = r + 8.0f + ph * 6.0f;
        int   ag1 = (int)((0.55f - 0.35f * ph) * 255 * a);
        int   ag2 = (int)((0.30f - 0.20f * ph) * 255 * a);
        int R = (col >> IM_COL32_R_SHIFT) & 0xFF;
        int G = (col >> IM_COL32_G_SHIFT) & 0xFF;
        int B = (col >> IM_COL32_B_SHIFT) & 0xFF;
        fg->AddCircle(ImVec2(cx, cy), g1, IM_COL32(R, G, B, ag1 > 0 ? ag1 : 0), 0, 2.0f);
        fg->AddCircle(ImVec2(cx, cy), g2, IM_COL32(R, G, B, ag2 > 0 ? ag2 : 0), 0, 1.5f);
    }
}

/* Return a single glyph to render INSIDE the collapsed dot / toolbar
 * pill / FULL card header when the short answer is a compact tag.
 * Matches:
 *   - MCQ letters A-E (case-insensitive; may be followed by ) . : or a
 *     separator / whitespace / end-of-string)
 *   - Status sentinels "?" (no question detected) and "!" (error)
 * Returns 0 (no glyph) otherwise. */
static char mcq_letter(const char *ans) {
    if (!ans || !ans[0]) return 0;
    const char *p = ans;
    while (*p == ' ' || *p == '\t') p++;
    char c = *p;
    if (c >= 'a' && c <= 'e') c = (char)(c - 'a' + 'A');
    /* MCQ letter branch */
    if (c >= 'A' && c <= 'E') {
        char n = p[1];
        if (n == 0 || n == ' ' || n == ')' || n == '.' || n == ':' || n == '\t' || n == '\n') return c;
        return 0;
    }
    /* Status-sentinel branch (single-char + end-of-string / whitespace). */
    if (c == '?' || c == '!') {
        char n = p[1];
        if (n == 0 || n == ' ' || n == '\t' || n == '\n') return c;
    }
    return 0;
}

/* v15.1.2 — inline button drawer used by both TOOLBAR + FULL. Returns
 * TRUE on a completed click (mouse released inside the button). Icon is
 * a single unicode char (or letter) drawn centered.
 * v15.1.3 — hit-slop: click detection uses an EXPANDED rect (default +8 px
 * on each side) so users don't need pixel-perfect aim. The DRAWN visual
 * stays at bw × bh but the interactable zone extends by `slop` outward. */
static bool draw_button_icon(ImDrawList *fg, float bx, float by, float bw, float bh,
                             const char *icon, float a, bool armed, bool copied_flash,
                             ImVec2 mp, bool mc, bool mr, float slop = 8.0f) {
    bool over_hit = (mp.x >= bx - slop && mp.x < bx + bw + slop &&
                     mp.y >= by - slop && mp.y < by + bh + slop);
    bool over_vis = (mp.x >= bx && mp.x < bx + bw && mp.y >= by && mp.y < by + bh);
    int   Aval  = (int)(255 * a); if (Aval < 90) Aval = 90;
    /* Highlight the button whenever the cursor is within its hit-slop area
     * so the user gets visual feedback that a click there will land. */
    int   bgA   = over_hit ? (over_vis ? (int)(90 * a) : (int)(45 * a)) : 0;
    ImU32 bg    = IM_COL32(255, 255, 255, bgA);
    ImU32 col   = copied_flash ? IM_COL32(80, 220, 130, Aval)
                               : IM_COL32(230, 230, 235, Aval);
    fg->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh), bg, 4.0f);
    ImFont *font = ImGui::GetFont();
    float fs = ImGui::GetFontSize();
    ImVec2 tsz = ImGui::CalcTextSize(icon);
    fg->AddText(font, fs * 0.95f,
                ImVec2(bx + (bw - tsz.x) * 0.5f, by + (bh - tsz.y) * 0.5f),
                col, icon);
    /* Click detection uses the EXPANDED (hit-slop) rect. */
    return armed && mr && over_hit;
    (void)mc;
}

/* Toolbar pill renderer -- FIXED narrow pill with just the dot + 2 buttons.
 * Answer content is never inline; user expands to FULL card (via hamburger)
 * to see it. Matches hooksdll's toolbar which is a compact icon strip only,
 * and keeps the hit-test rect stable so the buttons never drift out of
 * range because a long answer widened the pill. */
#define TOOLBAR_PILL_W  110.0f
#define TOOLBAR_PILL_H  30.0f
static void draw_toolbar_pill(ImDrawList *fg, float ox, float oy, float *out_w, float h,
                              int st, float a,
                              const char *shortbuf, char mcqL,
                              ImVec2 mp, bool mc, bool mr,
                              bool *hit_dot, bool *hit_copy, bool *hit_ham,
                              bool copy_flashing) {
    (void)shortbuf;
    ImFont *font = ImGui::GetFont();
    float fs = ImGui::GetFontSize();
    float pad = 8.0f, gap = 6.0f;
    float dr = 7.0f;
    float btn = 26.0f;
    float w = TOOLBAR_PILL_W;   /* fixed -- see comment above */
    if (out_w) *out_w = w;

    int   bgA = (int)(200 * a); if (bgA < 60) bgA = 60;
    ImU32 bg  = IM_COL32(17, 17, 17, bgA);
    ImU32 bd  = IM_COL32(255, 255, 255, (int)(60 * a));
    fg->AddRectFilled(ImVec2(ox + 1, oy + 2), ImVec2(ox + w + 1, oy + h + 2),
                      IM_COL32(0, 0, 0, (int)(80 * a)), h * 0.5f);
    fg->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h), bg, h * 0.5f);
    fg->AddRect      (ImVec2(ox, oy), ImVec2(ox + w, oy + h), bd, h * 0.5f, 0, 1.2f);

    /* row-reverse: dot on the RIGHT edge, buttons to its left. */
    float cx = ox + w - pad - dr, cy = oy + h * 0.5f;
    draw_dot_glyph(fg, cx, cy, dr, st, a, dot_state_is_solving(st));
    /* MCQ / status letter (BLACK bold) inside the dot. */
    if (mcqL) {
        char lb[2] = { mcqL, 0 };
        float lfs = dr * 1.4f; if (lfs < 9.0f) lfs = 9.0f;
        ImVec2 lsz = ImGui::CalcTextSize(lb);
        float sc = lfs / lsz.y;
        float ltw = lsz.x * sc, lth = lsz.y * sc;
        fg->AddText(font, lfs, ImVec2(cx - ltw * 0.5f + 0.5f, cy - lth * 0.55f),
                    IM_COL32(0, 0, 0, 255), lb);
        fg->AddText(font, lfs, ImVec2(cx - ltw * 0.5f,        cy - lth * 0.55f),
                    IM_COL32(0, 0, 0, 255), lb);
    }

    /* Buttons: [ham] [copy] * dot ── left of the dot. */
    float bxC = cx - dr - 8 - btn;                 /* copy button LEFT */
    float bxH = bxC - 4 - btn;                     /* hamburger LEFT */
    float by  = oy + (h - btn) * 0.5f;
    if (hit_copy) *hit_copy = draw_button_icon(fg, bxC, by, btn, btn,
                                               copy_flashing ? "\xE2\x9C\x93" : "\xE2\x8E\x98",
                                               a, true, copy_flashing, mp, mc, mr);
    if (hit_ham)  *hit_ham  = draw_button_icon(fg, bxH, by, btn, btn, "\xE2\x98\xB0",
                                               a, true, false, mp, mc, mr);

    /* Dot hit region + generous slop. */
    if (hit_dot) *hit_dot = (mp.x >= cx - dr - 8 && mp.x < cx + dr + 8 &&
                             mp.y >= oy - 4 && mp.y < oy + h + 4);
    (void)mc; (void)fs;
}

/* Full-card renderer -- hooksdll popout.html parity:
 *   ┌─────────────────────────────────────────────┐
 *   │  [opacity slider row]        (top, sliding) │
 *   │  question stem dim italic                   │
 *   │  ● 87% confident                            │
 *   │                                             │
 *   │  A  Photosynthesis in green plants...       │  <- big green MCQ letter + wrapped body
 *   │  ...body continues...                       │
 *   │                                             │
 *   │                       [ham] [chev] [copy] ● │  <- header at bottom-right
 *   └─────────────────────────────────────────────┘
 * MCQ letter in dot = BLACK bold, full-alpha. Big MCQ prefix in answer
 * body = GREEN 16px bold. Sets out_hit_dot when the dot glyph area is
 * tapped so the state machine can collapse FULL -> DOT (hooksdll parity). */
static void draw_full_card(ImDrawList *fg, float ox, float oy, float w, float h,
                           int st, float a,
                           const char *shortbuf, const char *fullbuf,
                           const char *qbuf, float conf, char mcqL,
                           ImVec2 mp, bool mc, bool mr,
                           bool *hit_copy, bool *hit_chevron, bool *hit_ham, bool *hit_dot,
                           bool copy_flashing, bool show_slider) {
    /* v16 (2026-09-22) -- Apple-tight radius (6px, not 8) matches the overlay
     * chrome. Bg = NL.card #111 area (~ IM_COL32(17,17,17)) for cohesion. */
    float radius = 6.0f;
    int   bgA    = (int)(230 * a);
    if (bgA < 60) bgA = 60;
    ImU32 bg  = IM_COL32(17, 17, 17, bgA);
    ImU32 bd  = IM_COL32(255, 255, 255, (int)(60 * a));
    /* Two-layer shadow so the card lifts off the desktop a bit. */
    fg->AddRectFilled(ImVec2(ox + 3, oy + 5), ImVec2(ox + w + 3, oy + h + 5),
                      IM_COL32(0, 0, 0, (int)(60 * a)), radius);
    fg->AddRectFilled(ImVec2(ox + 1, oy + 2), ImVec2(ox + w + 1, oy + h + 2),
                      IM_COL32(0, 0, 0, (int)(90 * a)), radius);
    fg->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + w, oy + h), bg, radius);
    fg->AddRect      (ImVec2(ox, oy), ImVec2(ox + w, oy + h), bd, radius, 0, 1.2f);

    ImFont *font = ImGui::GetFont();
    float fs = ImGui::GetFontSize();
    int   Aval = (int)(255 * a); if (Aval < 90) Aval = 90;
    /* v17 (2026-09-22) -- bumped from 10 -> 14 so answer body never hugs
     * the card edges (Sam: text should never touch borders). */
    float pad = 14.0f;

    /* ── Header row -- bottom-right anchored (hooksdll layout) ── */
    float dr = 8.0f;
    float btn = 26.0f;
    float row_h = 30.0f;
    float row_y = oy + h - row_h;
    /* From right to left: [dot] [copy] [chevron] [hamburger] */
    float cx = ox + w - pad - dr, cy = row_y + row_h * 0.5f;
    draw_dot_glyph(fg, cx, cy, dr, st, a, dot_state_is_solving(st));
    if (mcqL) {
        char lb[2] = { mcqL, 0 };
        float lfs = dr * 1.4f; if (lfs < 9.0f) lfs = 9.0f;
        ImVec2 lsz = ImGui::CalcTextSize(lb);
        float scale_l = lfs / lsz.y;
        float ltw = lsz.x * scale_l, lth = lsz.y * scale_l;
        fg->AddText(font, lfs, ImVec2(cx - ltw * 0.5f + 0.5f, cy - lth * 0.55f),
                    IM_COL32(0, 0, 0, 255), lb);
        fg->AddText(font, lfs, ImVec2(cx - ltw * 0.5f,        cy - lth * 0.55f),
                    IM_COL32(0, 0, 0, 255), lb);
    }
    float bxC = cx - dr - 8 - btn;                 /* copy */
    float bxV = bxC - 4 - btn;                     /* chevron */
    float bxH = bxV - 4 - btn;                     /* hamburger */
    float by  = row_y + (row_h - btn) * 0.5f;
    if (hit_copy)    *hit_copy    = draw_button_icon(fg, bxC, by, btn, btn,
                                                     copy_flashing ? "\xE2\x9C\x93" : "\xE2\x8E\x98",
                                                     a, true, copy_flashing, mp, mc, mr);
    if (hit_chevron) *hit_chevron = draw_button_icon(fg, bxV, by, btn, btn,
                                                     show_slider ? "\xE2\x96\xB2" /*▲*/ : "\xE2\x96\xBC" /*▼*/,
                                                     a, true, false, mp, mc, mr);
    if (hit_ham)     *hit_ham     = draw_button_icon(fg, bxH, by, btn, btn,
                                                     "\xE2\x98\xB0", a, true, false, mp, mc, mr);
    if (hit_dot)     *hit_dot     = (mp.x >= cx - dr - 8 && mp.x < cx + dr + 8 &&
                                     mp.y >= row_y - 4 && mp.y < row_y + row_h + 4);

    /* ── Answer body (top of card, filling down to header row) ── */
    float body_top = oy + pad;
    if (show_slider) body_top += 30.0f;   /* slider row is above answer */
    float body_bot = row_y - 4.0f;
    float body_h  = body_bot - body_top;
    if (body_h < 20) body_h = 20;
    float body_x  = ox + pad;
    float wrapw   = w - pad * 2;

    fg->PushClipRect(ImVec2(body_x, body_top), ImVec2(ox + w - pad, body_bot), true);

    float y = body_top;

    /* Question summary (dim italic-ish; capped ~2 lines). */
    if (qbuf && qbuf[0]) {
        char qshort[280];
        _snprintf(qshort, sizeof(qshort) - 1, "%s", qbuf); qshort[sizeof(qshort) - 1] = 0;
        if (strlen(qshort) > 200) { qshort[197] = '.'; qshort[198] = '.'; qshort[199] = '.'; qshort[200] = 0; }
        fg->AddText(font, fs * 0.85f, ImVec2(body_x, y),
                    IM_COL32(180, 180, 195, (int)(180 * a)), qshort, NULL, wrapw);
        ImVec2 qsz = ImGui::CalcTextSize(qshort, NULL, false, wrapw);
        float qh = qsz.y; if (qh > 40) qh = 40;
        y += qh + 6;
    }

    /* Confidence pill removed per LO (v15.1.7) -- was noise; answer +
     * question stem is enough signal. `conf` remains in the function
     * signature to keep the C ABI stable across builds. */
    (void)conf;

    /* Big green MCQ prefix (own row) + full answer body below. Simpler and
     * always wraps correctly, unlike the previous inline-beside-letter
     * layout which mis-wrapped for long answers. */
    if (mcqL) {
        char lb[2] = { mcqL, 0 };
        float mfs = fs * 1.55f;
        ImVec2 msz = ImGui::CalcTextSize(lb);
        float sc = mfs / msz.y;
        float mw = msz.x * sc;
        (void)sc; (void)mw;
        /* pseudo-bold via double-draw */
        fg->AddText(font, mfs, ImVec2(body_x + 0.6f, y),
                    IM_COL32(52, 199, 89, Aval), lb);
        fg->AddText(font, mfs, ImVec2(body_x,        y),
                    IM_COL32(52, 199, 89, Aval), lb);
        y += mfs + 4;
    }
    /* Answer body — always draws whichever is longest so the user sees
     * the FULL text, always wrapped to card width. When the big MCQ
     * letter is shown above, strip the redundant "X)" / "X." prefix
     * from the body so the letter doesn't appear twice. */
    const char *body_text = NULL;
    if (fullbuf && fullbuf[0])       body_text = fullbuf;
    else if (shortbuf && shortbuf[0]) body_text = shortbuf;
    if (body_text && mcqL) {
        /* Skip leading whitespace, then the MCQ letter, then any
         * separator (). : ) and following whitespace. */
        const char *p = body_text;
        while (*p == ' ' || *p == '\t') p++;
        if ((*p == mcqL || *p == (char)tolower((unsigned char)mcqL))) {
            const char *after = p + 1;
            if (*after == ')' || *after == '.' || *after == ':') after++;
            while (*after == ' ' || *after == '\t') after++;
            if (*after) body_text = after;
        }
    }
    if (body_text) {
        fg->AddText(font, fs, ImVec2(body_x, y),
                    IM_COL32(228, 228, 234, Aval), body_text, NULL, wrapw);
    } else {
        fg->AddText(font, fs * 0.95f, ImVec2(body_x, y),
                    IM_COL32(160, 160, 175, (int)(160 * a)),
                    "hold left click 2s on a question");
    }

    fg->PopClipRect();

    /* ── Opacity slider row at the TOP of the card (like hooksdll). ── */
    if (show_slider) {
        float sr_h = 30.0f;
        float sy = oy + 5;
        /* Measure "Opacity" label width so the track never overlaps it. */
        const char *lbl = "Opacity";
        ImVec2 lblsz = ImGui::CalcTextSize(lbl);
        float lbl_scale = fs * 0.85f / lblsz.y;
        float lbl_w = lblsz.x * lbl_scale;
        float gap = 10.0f;
        float sx0 = ox + pad;
        float sx_track = sx0 + lbl_w + gap;
        float sx1 = ox + w - pad - 44.0f;
        if (sx1 < sx_track + 40) sx1 = sx_track + 40;
        float track_y = sy + 16;
        /* subtle gradient bg strip */
        fg->AddRectFilled(ImVec2(ox + 1, oy + 1), ImVec2(ox + w - 1, oy + sr_h),
                          IM_COL32(20, 22, 28, (int)(180 * a)),
                          radius, ImDrawFlags_RoundCornersTop);
        fg->AddText(font, fs * 0.85f, ImVec2(sx0, sy + 3),
                    IM_COL32(200, 200, 210, Aval), lbl);
        fg->AddRectFilled(ImVec2(sx_track, track_y - 3),
                          ImVec2(sx1,      track_y + 3),
                          IM_COL32(120, 120, 130, Aval), 3.0f);
        float t = (a - 0.05f) / 0.95f; if (t < 0) t = 0; if (t > 1) t = 1;
        float knob_x = sx_track + t * (sx1 - sx_track);
        fg->AddRectFilled(ImVec2(sx_track, track_y - 3),
                          ImVec2(knob_x,   track_y + 3),
                          IM_COL32(240, 240, 245, Aval), 3.0f);
        fg->AddCircleFilled(ImVec2(knob_x, track_y), 6.5f, IM_COL32(255, 255, 255, Aval));
        fg->AddCircle       (ImVec2(knob_x, track_y), 6.5f,
                             IM_COL32(120, 120, 128, Aval), 0, 1.5f);
        char pctbuf[16];
        _snprintf(pctbuf, sizeof(pctbuf) - 1, "%d%%", (int)(a * 100 + 0.5f)); pctbuf[sizeof(pctbuf) - 1] = 0;
        fg->AddText(font, fs * 0.85f, ImVec2(sx1 + 8, sy + 3),
                    IM_COL32(220, 220, 230, Aval), pctbuf);
    }

    /* Bottom-right resize grip (subtle) */
    {
        float gx = ox + w - 3, gy = oy + h - 3;
        ImU32 gc = IM_COL32(255, 255, 255, (int)(140 * a));
        fg->AddLine(ImVec2(gx - 8, gy), ImVec2(gx, gy - 8), gc, 1.2f);
        fg->AddLine(ImVec2(gx - 4, gy), ImVec2(gx, gy - 4), gc, 1.0f);
    }
}

/* Main dot-render + interaction state machine.  Called every frame from
 * draw_chat_window before the overlay-visibility gate.
 *
 * v15.1.2 -- three UI states (DOT / TOOLBAR / FULL) with hooksdll parity:
 *   - DOT     : bare colored dot with optional MCQ letter inside.
 *   - TOOLBAR : horizontal pill dot + MCQ letter + copy + hamburger.
 *   - FULL    : big card with dot + MCQ letter + copy/chevron/hamburger
 *               row, dim question summary, confidence pill, wrapped
 *               answer body, optional opacity slider, BR resize grip.
 * Tapping the dot cycles DOT<->TOOLBAR; hamburger toggles TOOLBAR<->FULL;
 * chevron in FULL toggles the opacity slider row. All widget clicks are
 * dispatched via a manual hit-test since the whole surface is a
 * ForegroundDrawList composite (no ImGui::Begin container). */
extern "C" int clip_set_utf8(const char *utf8);
static void draw_answer_dot(UINT sw, UINT sh) {
    dot_load_prefs_once();

    if (!InterlockedCompareExchange(&g_dot_enabled, 0, 0)) {
        InterlockedExchange(&g_dot_rect_valid, 0);
        return;
    }
    /* Auto-hide when the main overlay is visible (LO invariant). */
    const as_settings_t *scfg = as_cfg();
    bool overlay_hides_dot = scfg ? (scfg->dot_hide_when_overlay != 0) : true;
    if (overlay_hides_dot && g_visible) {
        InterlockedExchange(&g_dot_rect_valid, 0);
        return;
    }

    ImDrawList *fg = ImGui::GetForegroundDrawList();
    if (!fg) return;

    int   st = (int)InterlockedCompareExchange(&g_dot_state, 0, 0);
    int   ui = (int)InterlockedCompareExchange(&g_dot_ui,    0, 0);
    if (ui < 0 || ui > 2) ui = 0;
    float scale = (float)sh / 1080.0f; if (scale < 0.8f) scale = 0.8f; if (scale > 2.5f) scale = 2.5f;
    int   size_px = scfg ? scfg->dot_size_px : 6;
    float r = (float)size_px * (scale < 1.4f ? scale : 1.4f);
    if (r < 4.5f) r = 4.5f;
    if (r > 10.0f) r = 10.0f;

    /* Snapshot the answer + metadata under the CS. */
    char shortbuf[256], fullbuf[1600], qbuf[512];
    float conf;
    dot_ensure_cs();
    EnterCriticalSection(&g_dot_cs);
    _snprintf(shortbuf, sizeof(shortbuf) - 1, "%s", g_dot_short);   shortbuf[sizeof(shortbuf) - 1] = 0;
    _snprintf(fullbuf,  sizeof(fullbuf)  - 1, "%s", g_dot_full);    fullbuf[sizeof(fullbuf)  - 1] = 0;
    _snprintf(qbuf,     sizeof(qbuf)     - 1, "%s", g_dot_question);qbuf[sizeof(qbuf) - 1] = 0;
    conf = g_dot_confidence;
    LeaveCriticalSection(&g_dot_cs);
    char mcqL = mcq_letter(shortbuf);

    /* Copy-flash timer (green checkmark for 1.4s after clipboard write). */
    bool copy_flashing = (g_dot_copied_at != 0 && (GetTickCount() - g_dot_copied_at) < 1400);

    /* Anchor + rect per UI state. */
    long px = InterlockedCompareExchange(&g_dot_px, 0, 0);
    long py = InterlockedCompareExchange(&g_dot_py, 0, 0);
    long jx = InterlockedCompareExchange(&g_dot_jx, 0, 0);
    long jy = InterlockedCompareExchange(&g_dot_jy, 0, 0);

    float ox, oy, cw, ch, cx, cy;
    float edge_margin = 18.0f * scale;
    /* Cache the "dot rect" (collapsed state's rect) so TOOLBAR/FULL can
     * anchor their bottom-right corner to the dot's current position.
     * Matches hooksdll popout.html's `#header { right: 4px; bottom: 4px }`
     * layout -- the dot never visually moves between states; the card
     * grows out from it upward + leftward. */
    const float HITPAD = 14.0f;
    float dot_cw = (r + HITPAD) * 2.0f;
    float dot_ch = dot_cw;
    float dot_ox, dot_oy;
    if (px >= 0 && py >= 0)          { dot_ox = (float)px; dot_oy = (float)py; }
    else if (jx >= 0 && jy >= 0)     { dot_ox = (float)jx - dot_cw * 0.5f;
                                       dot_oy = (float)jy - dot_ch * 0.5f; }
    else                             { dot_ox = (float)sw - dot_cw - edge_margin;
                                       dot_oy = (float)sh - dot_ch - edge_margin; }
    if (dot_ox < 2)                    dot_ox = 2;
    if (dot_oy < 2)                    dot_oy = 2;
    if (dot_ox + dot_cw > sw - 2)      dot_ox = sw - 2 - dot_cw;
    if (dot_oy + dot_ch > sh - 2)      dot_oy = sh - 2 - dot_ch;
    /* Dot bottom-right pixel = anchor point for pill/card growth. */
    float dot_br_x = dot_ox + dot_cw;
    float dot_br_y = dot_oy + dot_ch;

    if (ui == 2) {
        /* FULL card -- anchor its bottom-right to the dot's bottom-right,
         * so the card GROWS upward + leftward from the dot's position. */
        cw = (float)InterlockedCompareExchange(&g_dot_full_w, 0, 0);
        ch = (float)InterlockedCompareExchange(&g_dot_full_h, 0, 0);
        if (cw < 180) cw = 340;
        if (ch < 110) ch = 210;
        ox = dot_br_x - cw;
        oy = dot_br_y - ch;
        if (ox < 4) ox = 4;
        if (oy < 4) oy = 4;
        if (ox + cw > sw - 4) ox = sw - 4 - cw;
        if (oy + ch > sh - 4) oy = sh - 4 - ch;
        cx = ox + cw - 10;  cy = oy + ch - 15;   /* dot is at bottom-right of card */
    } else if (ui == 1) {
        /* TOOLBAR pill -- fixed dimensions (see TOOLBAR_PILL_W/H). No
         * post-render width adjustment needed; the hit-test rect
         * matches the rendered rect exactly. */
        cw = TOOLBAR_PILL_W;
        ch = TOOLBAR_PILL_H;
        ox = dot_br_x - cw;
        oy = dot_br_y - ch;
        if (ox < 2) ox = 2;
        if (oy < 2) oy = 2;
        if (ox + cw > sw - 2) ox = sw - 2 - cw;
        if (oy + ch > sh - 2) oy = sh - 2 - ch;
        cx = ox + cw - 15;  cy = oy + ch * 0.5f;
    } else {
        /* DOT collapsed -- use the pre-computed dot rect. */
        cw = dot_cw; ch = dot_ch;
        ox = dot_ox; oy = dot_oy;
        cx = ox + cw * 0.5f;
        cy = oy + ch * 0.5f;
    }

    float a = g_dot_alpha; if (a < 0.05f) a = 0.05f; if (a > 1.0f) a = 1.0f;

    /* Publish rect for hit-testing BEFORE draw so this frame's press is
     * consumed by us. Width is refined for TOOLBAR post-measure below. */
    InterlockedExchange(&g_dot_rect_x, (LONG)ox);
    InterlockedExchange(&g_dot_rect_y, (LONG)oy);
    InterlockedExchange(&g_dot_rect_w, (LONG)cw);
    InterlockedExchange(&g_dot_rect_h, (LONG)ch);
    InterlockedExchange(&g_dot_rect_valid, 1);

    /* ── Interaction state ──── */
    enum { DR_NONE=0, DR_MOVE=1, DR_RESIZE=2, DR_SLIDER=3, DR_BTN=4 };
    static int   drag_mode = DR_NONE;
    static int   drag_resize_edges = 0;   /* bitfield: 1=L 2=T 4=R 8=B */
    static float drag_start_mx=0, drag_start_my=0;
    static int   drag_start_x=0,  drag_start_y=0;
    static int   drag_start_w=0,  drag_start_h=0;
    static bool  drag_committed = false;
    const  float DRAG_THRESHOLD = 3.0f;

    ImVec2 mp = ImGui::GetMousePos();
    bool   md = ImGui::IsMouseDown(0);
    bool   mc = ImGui::IsMouseClicked(0);
    bool   mr = ImGui::IsMouseReleased(0);
    bool   hover = (mp.x >= ox && mp.x < ox + cw && mp.y >= oy && mp.y < oy + ch);
    if (hover || drag_mode != DR_NONE) InterlockedExchange(&g_mouse_over_widget, 1);

    /* Resize hit -- FULL only. All 4 edges + 3 corners (TL/TR/BL) with a
     * 12-px outer gutter for generous grabbing. The BR corner is
     * reserved for the DOT glyph + surrounding tap/drag zone -- resizing
     * there would fight the dot's move+tap gestures. */
    int in_edges = 0;
    const float EDGE_GUTTER = 12.0f;
    if (ui == 2) {
        if (mp.x >= ox - EDGE_GUTTER && mp.x < ox + EDGE_GUTTER)           in_edges |= 1;   /* L */
        if (mp.y >= oy - EDGE_GUTTER && mp.y < oy + EDGE_GUTTER)           in_edges |= 2;   /* T */
        if (mp.x >= ox + cw - EDGE_GUTTER && mp.x < ox + cw + EDGE_GUTTER) in_edges |= 4;   /* R */
        if (mp.y >= oy + ch - EDGE_GUTTER && mp.y < oy + ch + EDGE_GUTTER) in_edges |= 8;   /* B */
        /* Interior cursor -> not resize. */
        if (mp.x > ox + EDGE_GUTTER && mp.x < ox + cw - EDGE_GUTTER &&
            mp.y > oy + EDGE_GUTTER && mp.y < oy + ch - EDGE_GUTTER) in_edges = 0;
        /* Dot exclusion zone: a 40-px square around the dot glyph at the
         * card's BR. Clicks here belong to the DOT (tap-to-collapse /
         * MOVE), never resize -- fixes the "grabbing the BR corner
         * spazms the app between move+resize" bug LO reported. */
        float dot_cx = ox + cw - 10, dot_cy = oy + ch - 15;
        if (mp.x >= dot_cx - 22 && mp.x <= dot_cx + 22 &&
            mp.y >= dot_cy - 22 && mp.y <= dot_cy + 22) in_edges = 0;
    }
    bool in_grip = in_edges != 0;

    /* Slider hit region -- lives at the TOP of the FULL card (matches
     * draw_full_card). Only the track/knob area triggers slider drag;
     * empty parts of the slider row fall through to MOVE. */
    bool show_slider = (InterlockedCompareExchange(&g_dot_show_slider, 0, 0) != 0);
    bool in_slider_track = false;
    if (ui == 2 && show_slider) {
        float pad_sl = 10.0f;
        float lbl_w  = 48.0f;                 /* matches DR_SLIDER math */
        float sy = oy + 5.0f;
        float track_y = sy + 16.0f;
        float sx_track = ox + pad_sl + lbl_w + 10.0f;
        float sx1 = ox + cw - pad_sl - 44.0f;
        /* Vertical slop ±10 px so misses just above/below the 6-px thick
         * track still count. Horizontal slop -8/+8 for endpoint grabs. */
        if (mp.y >= track_y - 10 && mp.y <= track_y + 10 &&
            mp.x >= sx_track - 8 && mp.x <= sx1 + 8)
            in_slider_track = true;
    }
    bool in_slider = in_slider_track;

    /* Button hit zones (approximation used by the arm-DR_BTN check; the
     * real click gate is inside draw_*_pill/card via the mp/mc/mr args,
     * where the buttons themselves apply an 8-px hit-slop). Header row
     * is at the BOTTOM of the FULL card now (hooksdll parity). */
    float btn = 26.0f;
    const float BTN_SLOP = 10.0f;
    bool in_btn_area = false;
    if (ui == 1) {
        /* TOOLBAR: buttons on the LEFT of the dot at pill's right edge.
         * Dot center cx = ox + cw - 8 - 7 = ox + cw - 15. Copy button
         * starts at cx - dr - 8 - btn = ox + cw - 15 - 7 - 8 - 26 = ox+cw-56.
         * Hamburger at bxC - 4 - btn = ox + cw - 56 - 30 = ox + cw - 86.
         * Two buttons span [ox+cw-86, ox+cw-30] ~ 56px. */
        float bx_min = ox + cw - 86 - BTN_SLOP;
        float bx_max = ox + cw - 30 + BTN_SLOP;
        if (mp.x >= bx_min && mp.x < bx_max &&
            mp.y >= oy - BTN_SLOP && mp.y < oy + ch + BTN_SLOP) in_btn_area = true;
    } else if (ui == 2) {
        /* FULL: three buttons on the bottom row, left of the dot. Header
         * row is at (oy + ch - 30) with buttons roughly at row_y+2. */
        float row_y = oy + ch - 30.0f;
        float cx_dot = ox + cw - 10 - 8;
        if (mp.x >= cx_dot - btn * 3 - 24 - BTN_SLOP && mp.x < cx_dot + BTN_SLOP &&
            mp.y >= row_y - BTN_SLOP && mp.y < row_y + 30 + BTN_SLOP) in_btn_area = true;
    }

    /* Arm drag on down inside our rect */
    if (drag_mode == DR_NONE && mc && hover) {
        drag_start_mx = mp.x; drag_start_my = mp.y;
        /* MOVE uses g_dot_px/py (the DOT'S persistent position) as its
         * anchor, NOT the current visual ox/oy of the pill/card.  In
         * TOOLBAR/FULL the card is drawn at (dot_br_x - cw, dot_br_y - ch)
         * -- if we captured `ox` here and later wrote `g_dot_px = ox+dx`,
         * the next frame's dot would move to what USED to be the card's
         * top-left, snapping card+dot into wildly wrong positions. Always
         * anchor MOVE to the DOT rect. */
        drag_start_x  = (int)dot_ox;
        drag_start_y  = (int)dot_oy;
        drag_start_w  = (int)cw; drag_start_h = (int)ch;
        drag_committed = false;
        if      (in_grip)     { drag_mode = DR_RESIZE; drag_resize_edges = in_edges; }
        else if (in_slider)   { drag_mode = DR_SLIDER; drag_committed = true; }
        else if (in_btn_area) drag_mode = DR_BTN;
        else                  drag_mode = DR_MOVE;
    }
    if (drag_mode != DR_NONE && md) {
        float dx = mp.x - drag_start_mx;
        float dy = mp.y - drag_start_my;
        if (!drag_committed &&
            (dx > DRAG_THRESHOLD || dx < -DRAG_THRESHOLD ||
             dy > DRAG_THRESHOLD || dy < -DRAG_THRESHOLD)) {
            /* If we were armed on a button and moved, degrade to a MOVE
             * (drag beats a tap). */
            if (drag_mode == DR_BTN) drag_mode = DR_MOVE;
            drag_committed = true;
        }
        if (drag_committed) {
            if (drag_mode == DR_MOVE) {
                /* Move the DOT's persistent position (bottom-right of card
                 * follows automatically since card is anchored to it). */
                int nx = drag_start_x + (int)dx;
                int ny = drag_start_y + (int)dy;
                int dw = (int)dot_cw, dh = (int)dot_ch;
                if (nx < 0) nx = 0; if (ny < 0) ny = 0;
                if (nx + dw > (int)sw - 1) nx = (int)sw - 1 - dw;
                if (ny + dh > (int)sh - 1) ny = (int)sh - 1 - dh;
                InterlockedExchange(&g_dot_px, nx);
                InterlockedExchange(&g_dot_py, ny);
            } else if (drag_mode == DR_RESIZE) {
                /* Any-edge/corner resize: compute new box, then re-anchor
                 * the dot's bottom-right so it stays where the user grabbed. */
                int new_x = drag_start_x, new_y = drag_start_y;
                int new_w = drag_start_w, new_h = drag_start_h;
                if (drag_resize_edges & 1) {                 /* left edge */
                    new_x = drag_start_x + (int)dx;
                    new_w = drag_start_w - (int)dx;
                }
                if (drag_resize_edges & 2) {                 /* top edge */
                    new_y = drag_start_y + (int)dy;
                    new_h = drag_start_h - (int)dy;
                }
                if (drag_resize_edges & 4) {                 /* right edge */
                    new_w = drag_start_w + (int)dx;
                }
                if (drag_resize_edges & 8) {                 /* bottom edge */
                    new_h = drag_start_h + (int)dy;
                }
                if (new_w < 200) { if (drag_resize_edges & 1) new_x -= (200 - new_w); new_w = 200; }
                if (new_h < 130) { if (drag_resize_edges & 2) new_y -= (130 - new_h); new_h = 130; }
                if (new_w > (int)sw - 20) new_w = (int)sw - 20;
                if (new_h > (int)sh - 20) new_h = (int)sh - 20;
                InterlockedExchange(&g_dot_full_w, new_w);
                InterlockedExchange(&g_dot_full_h, new_h);
                /* Because FULL anchors bottom-right to the dot position, and
                 * the DOT position is (dot_ox, dot_oy), an R/B edge resize
                 * needs to bump the persisted dot position so the card's
                 * bottom-right stays glued to the user's cursor.
                 * v15.1.7 SPAZM FIX: base the new dot position on the
                 * DRAG-START snapshot, not the live g_dot_px. Reading
                 * live g_dot_px each frame compounded dx (frame 2 added
                 * dx on top of a value that already had the prior frame's
                 * dx applied), which manifested as the card/dot flying
                 * off the screen mid-drag. */
                if (drag_resize_edges & 4) {
                    InterlockedExchange(&g_dot_px, (LONG)(drag_start_x + (int)dx));
                }
                if (drag_resize_edges & 8) {
                    InterlockedExchange(&g_dot_py, (LONG)(drag_start_y + (int)dy));
                }
            } else if (drag_mode == DR_SLIDER && ui == 2) {
                /* Slider drag: computes opacity from cursor x on the track.
                 * Track spans [sx_track .. sx1] where sx_track = pad +
                 * measured "Opacity" label width + 10-gap. Approx here to
                 * keep hit-vs-render in sync (label ~ 45px at 0.85*fs). */
                float pad_sl = 10.0f;
                float lbl_w  = 48.0f;
                float sx_track = ox + pad_sl + lbl_w + 10.0f;
                float sx1 = ox + cw - pad_sl - 44.0f;
                float t   = (mp.x - sx_track) / (sx1 - sx_track);
                if (t < 0) t = 0; if (t > 1) t = 1;
                g_dot_alpha = 0.05f + t * 0.95f;
            }
        }
    }

    /* Render the surface AFTER interaction so buttons can consume the
     * up-click this frame. */
    bool hit_copy = false, hit_ham = false, hit_chevron = false, hit_dot_toolbar = false, hit_dot_full = false;
    if (ui == 2) {
        draw_full_card(fg, ox, oy, cw, ch, st, a,
                       shortbuf, fullbuf, qbuf, conf, mcqL,
                       mp, mc, mr, &hit_copy, &hit_chevron, &hit_ham, &hit_dot_full,
                       copy_flashing, show_slider);
    } else if (ui == 1) {
        float tw = cw;
        draw_toolbar_pill(fg, ox, oy, &tw, ch, st, a,
                          shortbuf, mcqL, mp, mc, mr,
                          &hit_dot_toolbar, &hit_copy, &hit_ham,
                          copy_flashing);
        /* toolbar width is FIXED (TOOLBAR_PILL_W); no republish needed. */
    } else {
        draw_dot_glyph(fg, cx, cy, r, st, a, dot_state_is_solving(st));
        if (mcqL) {
            char lb[2] = { mcqL, 0 };
            ImFont *font = ImGui::GetFont();
            /* Hooksdll spec: BLACK bold monospace letter at ~font-size 7 for
             * a 10px dot (ratio 0.7). Full alpha so the letter stays
             * readable even at very low dot opacity. Draw twice for
             * pseudo-bold since our ImGui font isn't bold-weight variant. */
            float lfs = r * 1.4f; if (lfs < 9.0f) lfs = 9.0f;
            ImVec2 lsz = ImGui::CalcTextSize(lb);
            float sc = lfs / lsz.y;
            float lw = lsz.x * sc, lh = lsz.y * sc;
            fg->AddText(font, lfs,
                        ImVec2(cx - lw * 0.5f + 0.5f, cy - lh * 0.55f),
                        IM_COL32(0, 0, 0, 255), lb);
            fg->AddText(font, lfs,
                        ImVec2(cx - lw * 0.5f,        cy - lh * 0.55f),
                        IM_COL32(0, 0, 0, 255), lb);
        }
    }

    /* Commit drag / handle taps / button clicks on release. */
    if (drag_mode != DR_NONE && mr) {
        int  was_committed = drag_committed;
        int  was_mode      = drag_mode;
        drag_mode = DR_NONE;
        drag_committed = false;
        if (was_committed) {
            if (was_mode == DR_MOVE) {
                long cur_x = InterlockedCompareExchange(&g_dot_px, 0, 0);
                long cur_y = InterlockedCompareExchange(&g_dot_py, 0, 0);
                as_cfg_set_dot_pos((int)cur_x, (int)cur_y);
            }
            if (was_mode == DR_RESIZE) as_cfg_set_dot_full_size((int)cw, (int)ch);
            if (was_mode == DR_SLIDER) as_cfg_set_dot_opacity((double)g_dot_alpha);
        } else {
            /* Was a tap. Priority: button clicks first, then dot area. */
            if (hit_copy) {
                if (fullbuf[0]) clip_set_utf8(fullbuf);
                else if (shortbuf[0]) clip_set_utf8(shortbuf);
                g_dot_copied_at = GetTickCount();
            } else if (hit_chevron && ui == 2) {
                int ns = show_slider ? 0 : 1;
                InterlockedExchange(&g_dot_show_slider, ns);
                as_cfg_set_dot_show_slider(ns);
            } else if (hit_ham) {
                /* toolbar <-> full */
                ui = (ui == 2) ? 1 : 2;
                InterlockedExchange(&g_dot_ui, ui);
                as_cfg_set_dot_ui_state(ui);
            } else if (hit_dot_full || hit_dot_toolbar) {
                /* hooksdll parity: tap on dot glyph in ANY state collapses
                 * (or from DOT expands to TOOLBAR). Explicit dot-hit takes
                 * priority over the general "tap in FULL body" no-op. */
                ui = (ui == 0) ? 1 : 0;
                InterlockedExchange(&g_dot_ui, ui);
                as_cfg_set_dot_ui_state(ui);
            } else if (ui == 0) {
                /* tap on collapsed dot -> toolbar (hooksdll) */
                ui = 1;
                InterlockedExchange(&g_dot_ui, ui);
                as_cfg_set_dot_ui_state(ui);
            }
            /* Note: tap on FULL body outside a button / dot area = no-op. */
        }
    }
}

static void draw_agent_status(UINT sw, UINT sh) {
    if (!InterlockedCompareExchange(&g_agent_active, 0, 0)) return;
    ImDrawList *fg = ImGui::GetForegroundDrawList();
    if (!fg) return;
    char line[256];
    dot_ensure_cs();
    EnterCriticalSection(&g_dot_cs);
    _snprintf(line, sizeof(line) - 1, "%s", g_agent_status); line[sizeof(line) - 1] = 0;
    LeaveCriticalSection(&g_dot_cs);
    if (!line[0]) return;
    float scale = (float)sh / 1080.0f; if (scale < 0.75f) scale = 0.75f; if (scale > 2.5f) scale = 2.5f;
    float fs = ImGui::GetFontSize();
    ImVec2 sz = ImGui::CalcTextSize(line);
    float pad = 7.0f * scale;
    float w = sz.x + pad * 2, h = sz.y + pad * 2;
    float x0 = (sw - w) * 0.5f, y0 = 10.0f * scale;
    fg->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + w, y0 + h), IM_COL32(20, 20, 26, 235), 6 * scale);
    fg->AddRect(ImVec2(x0, y0), ImVec2(x0 + w, y0 + h), IM_COL32(180, 110, 255, 200), 6 * scale, 0, 1.5f);
    fg->AddText(ImGui::GetFont(), fs, ImVec2(x0 + pad, y0 + pad), IM_COL32(230, 220, 255, 255), line);
}

static void draw_chat_window(UINT screen_w, UINT screen_h) {
    /* If a capture is pending, skip drawing so the layer texture stays
     * app-only. The capture path in ui_present_frame ALSO defers the
     * capture until g_hide_frames_for_capture reaches 0 -- by then
     * multiple frames have composed without our overlay and prior
     * overlay pixels have been overwritten by the underlying app. */
    if (g_hide_frames_for_capture > 0) return;

    /* AutoSolver dot + Agent status -- capture-stealth (drawn after the hide
     * gate above), independent of the chat overlay's visibility. */
    draw_answer_dot(screen_w, screen_h);
    draw_agent_status(screen_w, screen_h);

    /* v1.7.11.8 REVERTED (2026-07-25) -- fullscreen dirty-touch quad
     * showed as visible "dim dance" per LO test AND did not fix Chrome
     * shadow trails. Confirms DWM's dirty-region tracking happens at
     * a HIGHER level than raw pixel writes (probably scene-graph
     * dirty rects, not per-RTV dirty). Removed. */
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

    /* v1.7.8c: GLIDE -- interpolate DISPLAY offset toward TARGET each
     * frame. First frame after init: snap to avoid phantom glide from
     * (0,0). Then lerp with 0.30 approach factor at 60Hz = ~130ms to
     * visually settle for a 48px nudge. Snap when within 0.5px to
     * avoid floating subpixel drift. */
    float target_x = (float)off_x;
    float target_y = (float)off_y;
    if (!g_disp_off_primed) {
        g_disp_off_x = target_x;
        g_disp_off_y = target_y;
        g_disp_off_primed = true;
    } else {
        /* v1.7.8f: 1.0 factor = INSTANT snap (no glide). LO ask --
         * BP is instant, so we are too. Hypothesis: BP's smoothness
         * comes from smaller nudge step + LL-hook auto-repeat, not
         * glide animation. If instant + 48px feels choppy, drop step
         * in dllmain SVC_HK_MOVE_* handlers to ~20px. */
        const float k = 1.0f;
        g_disp_off_x += (target_x - g_disp_off_x) * k;
        g_disp_off_y += (target_y - g_disp_off_y) * k;
        /* Snap-to-target when within 0.5px (inline compare -- avoids
         * pulling in <math.h> just for fabsf). */
        float _dx = target_x - g_disp_off_x;
        float _dy = target_y - g_disp_off_y;
        if (_dx > -0.5f && _dx < 0.5f) g_disp_off_x = target_x;
        if (_dy > -0.5f && _dy < 0.5f) g_disp_off_y = target_y;
    }
    float disp_off_x = g_disp_off_x;
    float disp_off_y = g_disp_off_y;

    /* v11.2.1 (2026-07-24) -- hide is now truly INSTANT: on !visible we
     * return immediately. Bypassify does the same (their Present detour
     * short-circuits on shutdown_flag=1 without any grace / erase pass).
     * The prior v11.2 "hide-grace" paint pass caused a visible dark
     * flash for 5 frames after Ctrl+B toggle. Removed. */
    if (!visible) return;

    /* v13 (2026-08-10) -- UNIFORM GLOBAL ALPHA.
     *
     * LO: "the transparency isnt as low as i thought ... should have been
     * near invisible ... especially the top that says 'ai overlay' is mad
     * annoying it doesnt adjust". Root problem: text + title chrome were
     * pinned at full opacity while only the bg faded, so a low slider left
     * bright readable text floating over a ghost bg -- not "near invisible".
     *
     * New model: ONE knob. We push ImGuiStyleVar_Alpha = user alpha below
     * (fades EVERYTHING ImGui draws -- bg, borders, scrollbar, bubbles,
     * code/math, AND text -- uniformly). So here we neutralize the OLD
     * per-color fade sources: g_frame_alpha_mul stays at 1.0 (with_alpha_mul
     * returns design-opaque colors, snapped to 1.0), and the WindowBg is
     * set fully opaque; the single global style alpha then does the fade.
     * This avoids double-fading bg/chrome (which would be alpha^2). */
    g_frame_alpha_mul = 1.0f;

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
    /* v16: focus mode -- when chrome is collapsed we always show the chat
     * body (ignore home-forced) so ONLY the chat is visible. */
    int collapsed = (int)InterlockedCompareExchange(&g_chrome_collapsed, 0, 0);
    int home_forced_eff = collapsed ? 0
                        : (int)InterlockedCompareExchange(&g_home_view_forced, 0, 0);
    int have_msgs = (msg_n > 0) && (home_forced_eff == 0);
    size_t sl = have_msgs ? 1 : 0;

    /* DPI-derived base scale. Baseline 1080p -> scale=1.0; 4K -> scale ~2.0. */
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
    /* v1.7.8c: use disp_off_* (animated) instead of off_x/y (target)
     * so the position glides across the screen instead of jumping. */
    switch (corner) {
        case 0:  /* top-right */
            pos_x = (float)screen_w - base_w - margin + disp_off_x;
            pos_y = margin + disp_off_y;
            break;
        case 1:  /* top-left */
            pos_x = margin + disp_off_x;
            pos_y = margin + disp_off_y;
            break;
        case 2:  /* bottom-right */
            pos_x = (float)screen_w - base_w - margin + disp_off_x;
            pos_y = (float)screen_h - base_h - margin + disp_off_y;
            break;
        case 3:  /* bottom-left */
            pos_x = margin + disp_off_x;
            pos_y = (float)screen_h - base_h - margin + disp_off_y;
            break;
    }
    /* v1.7.8c (2026-07-24) -- CLAMP FULLY ON-SCREEN, ZERO MARGIN.
     * LO ask: BP lets overlay reach TIPPY top / bippy bottom, so we
     * do too. But BP doesn't let overlay go OFF-screen edges -- so
     * clamp so overlay's outer edges stay just inside the screen.
     * Trail-fix at edges is handled by RDW_FRAME in the invalidate
     * helper (covers non-client title-bar / DWM-composited chrome). */
    float max_x = (float)screen_w - base_w;
    float max_y = (float)screen_h - base_h;
    if (max_x < 0.0f) max_x = 0.0f;
    if (max_y < 0.0f) max_y = 0.0f;
    if (pos_x < 0.0f)  pos_x = 0.0f;
    if (pos_y < 0.0f)  pos_y = 0.0f;
    if (pos_x > max_x) pos_x = max_x;
    if (pos_y > max_y) pos_y = max_y;

    /* v6: cache the drawn rect for the LL mouse hook so mouse-wheel
     * scrolling can hit-test the cursor against the overlay. */
    InterlockedExchange(&g_resize_grip_px, (LONG)(30.0f * scale));
    InterlockedExchange(&g_overlay_margin_px, (LONG)margin);
    InterlockedExchange(&g_last_overlay_x, (LONG)pos_x);
    InterlockedExchange(&g_last_overlay_y, (LONG)pos_y);
    InterlockedExchange(&g_last_overlay_w, (LONG)base_w);
    InterlockedExchange(&g_last_overlay_h, (LONG)base_h);

    /* v11 (2026-07-24) -- TRAIL ERASE.
     *
     * Compare current rect vs previous frame's rendered rect. If they differ,
     * push the PRIOR rect onto the trail history so we paint over it with
     * opaque bg color this frame. This eliminates the "solid ghost trail"
     * that persisted from prior overlay positions after nudge.
     *
     * See trail_push_rect + trail history globals near line ~740. */
    /* v11.2.1: trail_push_rect call removed. Bypassify has no trail-erase.
     * Still update g_last_pushed_* so the g_last_overlay_* rect cache
     * stays consistent -- used by mouse-wheel hit-testing (ui_point_in_overlay). */
    g_last_pushed_x = pos_x;
    g_last_pushed_y = pos_y;
    g_last_pushed_w = base_w;
    g_last_pushed_h = base_h;

    /* v11: THEME PALETTE -- dark (existing) or light.
     * Light theme colors ported from Windows Fluent light with adjustments
     * for text contrast at translucent alpha. */
    int   theme = (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
    ImVec4 col_window_bg, col_title_bg, col_title_bg_active, col_border, col_text, col_sep, col_scroll_bg, col_scroll_grab, col_scroll_grab_hi;
    if (theme == 1) {
        /* LIGHT -- white bg, black text, neutral grays (no hue). */
        col_window_bg       = ImVec4(0.97f, 0.97f, 0.98f, 1.00f);
        col_title_bg        = ImVec4(0.92f, 0.92f, 0.94f, 0.98f);
        col_title_bg_active = ImVec4(0.88f, 0.88f, 0.90f, 0.98f);
        col_border          = ImVec4(0.00f, 0.00f, 0.00f, 0.12f);
        col_text            = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
        col_sep             = ImVec4(0.00f, 0.00f, 0.00f, 0.10f);
        col_scroll_bg       = ImVec4(0.00f, 0.00f, 0.00f, 0.05f);
        col_scroll_grab     = ImVec4(0.00f, 0.00f, 0.00f, 0.22f);
        col_scroll_grab_hi  = ImVec4(0.00f, 0.00f, 0.00f, 0.34f);
    } else {
        /* v16 (2026-09-22) DARK -- NL palette. Deeper #0A0A0A window, #1A1A1A
         * title-active lift, softened white text, hairline strokes. Monochrome
         * on purpose: overlay must blend into any exam / test-taker background. */
        col_window_bg       = ImVec4(0.039f, 0.039f, 0.039f, 1.00f); /* NL.bg     #0A0A0A */
        col_title_bg        = ImVec4(0.039f, 0.039f, 0.039f, 0.98f); /* NL.bg     #0A0A0A */
        col_title_bg_active = ImVec4(0.102f, 0.102f, 0.102f, 0.98f); /* NL.cardHi #1A1A1A */
        col_border          = ImVec4(1.000f, 1.000f, 1.000f, 0.08f); /* NL.stroke white/8 */
        col_text            = ImVec4(0.960f, 0.960f, 0.970f, 1.00f); /* NL.txt    softened white */
        col_sep             = ImVec4(1.000f, 1.000f, 1.000f, 0.08f); /* NL.stroke white/8 */
        col_scroll_bg       = ImVec4(1.000f, 1.000f, 1.000f, 0.03f);
        col_scroll_grab     = ImVec4(1.000f, 1.000f, 1.000f, 0.22f);
        col_scroll_grab_hi  = ImVec4(1.000f, 1.000f, 1.000f, 0.34f);
    }

    /* v14 (2026-08-11): accent + surface palette for the redesigned UI.
     * Kept theme-aware. Plain (design-opaque) colors -- the global
     * ImGuiStyleVar_Alpha handles fading uniformly. */
    ImVec4 col_accent, col_accent_hi, col_accent_dim, col_accent2, col_accent_text,
           col_frame_bg, col_frame_hi, col_card_bg, col_card_border, col_text_dim;
    if (theme == 1) {
        /* LIGHT -- accent is near-black; text ON accent is white. */
        col_accent      = ImVec4(0.11f, 0.11f, 0.12f, 1.0f);
        col_accent_hi   = ImVec4(0.00f, 0.00f, 0.00f, 1.0f);
        col_accent_dim  = ImVec4(0.00f, 0.00f, 0.00f, 0.06f);
        col_accent2     = ImVec4(0.11f, 0.11f, 0.12f, 1.0f);
        col_accent_text = ImVec4(0.98f, 0.98f, 0.99f, 1.0f);
        col_frame_bg    = ImVec4(0.00f, 0.00f, 0.00f, 0.05f);
        col_frame_hi    = ImVec4(0.00f, 0.00f, 0.00f, 0.10f);
        col_card_bg     = ImVec4(0.00f, 0.00f, 0.00f, 0.035f);
        col_card_border = ImVec4(0.00f, 0.00f, 0.00f, 0.10f);
        col_text_dim    = ImVec4(0.38f, 0.38f, 0.42f, 1.0f);
    } else {
        /* v16 (2026-09-22) DARK -- NL accent + surface palette. Near-white
         * accent for primary CTAs (the send square, active toggles); SOLID
         * #111 card surfaces so cards visually LIFT off the #0A0A0A window bg
         * instead of blending into it. Hairline strokes throughout. */
        col_accent      = ImVec4(0.950f, 0.950f, 0.960f, 1.0f);
        col_accent_hi   = ImVec4(1.000f, 1.000f, 1.000f, 1.0f);
        col_accent_dim  = ImVec4(1.000f, 1.000f, 1.000f, 0.10f);
        col_accent2     = ImVec4(0.860f, 0.880f, 0.920f, 1.0f); /* icon tint / focus border */
        col_accent_text = ImVec4(0.060f, 0.060f, 0.070f, 1.0f); /* dark text ON white accent */
        col_frame_bg    = ImVec4(1.000f, 1.000f, 1.000f, 0.05f);
        col_frame_hi    = ImVec4(1.000f, 1.000f, 1.000f, 0.10f);
        col_card_bg     = ImVec4(0.067f, 0.067f, 0.067f, 1.00f); /* NL.card   #111  SOLID */
        col_card_border = ImVec4(1.000f, 1.000f, 1.000f, 0.08f); /* NL.stroke white/8 */
        col_text_dim    = ImVec4(0.604f, 0.604f, 0.604f, 1.0f);  /* NL.txt2   #9A9A9A */
    }

    /* v14b: bundle the palette for the custom-drawn UI helpers. */
    ui_theme_t T;
    T.accent = col_accent; T.accent_hi = col_accent_hi; T.accent_dim = col_accent_dim;
    T.accent2 = col_accent2; T.accent_text = col_accent_text;
    T.frame_bg = col_frame_bg; T.frame_hi = col_frame_hi; T.card_bg = col_card_bg;
    T.card_border = col_card_border;
    T.text = col_text; T.text_dim = col_text_dim; T.win_bg = col_window_bg; T.sep = col_sep;

    /* v11.2.1 (2026-07-24) -- TRAIL ERASE PAINT REMOVED.
     *
     * Bypassify has NO trail-erase mechanism. LO tested v11/v11.2 and
     * reported the erase paint left a visible dark-navy "shadow flicker"
     * following the overlay during nudge (each 48px hop painted an
     * opaque rect at the old position for 3+ frames = dark strip
     * behind the moving overlay). BP-1:1 clone: just don't paint it.
     *
     * The g_trail_hist ring buffer + trail_push_rect helper are kept
     * as no-op scaffolding so `state.chosen_tier`-style live reconfig
     * can re-enable via a future flag toggle if needed. */
    (void)theme;   /* still used below in the palette path */

    /* v1.7.8: snapshot the exact rect we're about to draw at, in
     * screen coords. Used by invalidate_last_overlay_region() from
     * ui_nudge / ui_resize / ui_cycle_corner / ui_reset_geometry /
     * ui_toggle_visible / ui_shutdown to force underlying apps to
     * repaint at the OLD rect after a geometry change, killing
     * ghost trails. Written from the single Present detour thread --
     * no lock needed. Moved BEFORE the lean-mode branch so both
     * render paths update the rect. */
    g_last_overlay_rect.left   = (LONG)pos_x;
    g_last_overlay_rect.top    = (LONG)pos_y;
    g_last_overlay_rect.right  = (LONG)(pos_x + base_w);
    g_last_overlay_rect.bottom = (LONG)(pos_y + base_h);

    /* v1.7.10 (2026-07-24) -- LEAN MODE render path (BP-parity).
     * Bypasses ImGui::Begin/End entirely -- uses GetForegroundDrawList
     * to render minimal overlay via raw AddRectFilled + AddText.
     * Matches BP's exact pattern (1 unnamed window, all drawing via
     * draw lists). Much lighter per-frame render workload. */
    if (InterlockedCompareExchange(&g_lean_mode, 0, 0)) {
        /* Snapshot the last AI reply under lock. */
        char *lean_text = NULL;
        ensure_cs();
        EnterCriticalSection(&g_chat_msgs_cs);
        if (g_last_reply_snapshot) lean_text = _strdup(g_last_reply_snapshot);
        LeaveCriticalSection(&g_chat_msgs_cs);

        ImDrawList *fg = ImGui::GetForegroundDrawList();
        if (fg) {
            /* Theme-aware colors. */
            int theme_lean = (int)InterlockedCompareExchange(&g_theme_effective, 0, 0);
            ImU32 bg_col, border_col, text_col, label_col;
            /* v13 (2026-08-10): lean text/label now fade with alpha too, so
             * lean mode also honors "near invisible" instead of leaving
             * opaque glyphs floating over a ghost bg. */
            if (theme_lean == 1) {
                /* LIGHT -- black & white */
                bg_col     = IM_COL32(248, 248, 250, (int)(255.0f * alpha));
                border_col = IM_COL32(0,   0,   0,   (int)(30.0f  * alpha));
                text_col   = IM_COL32(20,  20,  24,  (int)(255.0f * alpha));
                label_col  = IM_COL32(96,  96,  104, (int)(230.0f * alpha));
            } else {
                /* DARK -- black & white */
                bg_col     = IM_COL32(13,  13,  15,  (int)(255.0f * alpha));
                border_col = IM_COL32(255, 255, 255, (int)(30.0f  * alpha));
                text_col   = IM_COL32(240, 240, 244, (int)(255.0f * alpha));
                label_col  = IM_COL32(150, 150, 158, (int)(230.0f * alpha));
            }

            float rx0 = pos_x, ry0 = pos_y;
            float rx1 = pos_x + base_w, ry1 = pos_y + base_h;
            /* Background + border. */
            fg->AddRectFilled(ImVec2(rx0, ry0), ImVec2(rx1, ry1), bg_col, 12.0f * scale);
            fg->AddRect(ImVec2(rx0, ry0), ImVec2(rx1, ry1), border_col, 12.0f * scale, 0, 2.0f);

            /* "LEAN" label top-left. */
            float pad = 14.0f * scale;
            fg->AddText(ImVec2(rx0 + pad, ry0 + pad),
                        label_col, "LEAN  \xE2\x80\xA2  Ctrl+Shift+Alt+M to toggle");

            /* Last AI reply body (or placeholder). */
            const char *body = lean_text && *lean_text
                               ? lean_text
                               : "no reply yet - press Ctrl+Shift+Space to ask";
            /* Wrap text to overlay width via PushTextWrapPos equivalent --
             * ImDrawList::AddText has a wrap_width overload. */
            float text_pad_top = pad + 26.0f * scale;
            ImFont *font = ImGui::GetFont();
            float font_size = ImGui::GetFontSize() * font_mul;
            fg->AddText(font, font_size,
                        ImVec2(rx0 + pad, ry0 + text_pad_top),
                        text_col, body, nullptr, base_w - 2.0f * pad);
        }

        if (lean_text) free(lean_text);
        return;   /* skip normal Begin/End path */
    }

    ImGui::SetNextWindowPos(ImVec2(pos_x, pos_y), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(base_w, base_h), ImGuiCond_Always);
    /* v14d (2026-08-11): bg alpha = user opacity so the WHOLE overlay
     * fades, not just text. SetNextWindowBgAlpha OVERWRITES the window-bg
     * alpha channel; the pushed ImGuiStyleVar_Alpha fades everything else
     * to the same value => uniform fade. (v13 pinned this at 1.0, which is
     * exactly why the panel stayed opaque while only text faded.) */
    ImGui::SetNextWindowBgAlpha(alpha);

    /* Font: baseline scale + user multiplier. */
    ImGui::GetIO().FontGlobalScale = scale * font_mul;

    /* v13 (2026-08-10): ONE global opacity knob -- fades bg + chrome + text
     * together so a low slider truly goes near-invisible. Floored at 0.05
     * so the overlay never fully vanishes (user could never find it again).
     * Popped with the other style vars at end of frame (PopStyleVar count
     * bumped 4 -> 5 accordingly). */
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, alpha < 0.05f ? 0.05f : alpha);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  8.0f * scale);
    /* v1.7.11.15 (2026-07-25) -- tighter chrome. User: "it be nice if
     * we didnt have the outer border or like less ui/ux and more simple
     * ui/ux for the app so more space can be used for the ai answer".
     * Shrunk WindowPadding 20x16 -> 10x10 (+20px horizontal + 12px
     * vertical of content room per overlay), WindowBorderSize 1.5 -> 1.0
     * (thinner but still visible edge for grabbing / orienting),
     * ItemSpacing 10x8 -> 8x6 (tighter vertical rhythm between bubbles
     * without crowding). */
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(10.0f * scale, 10.0f * scale));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,     ImVec2(8.0f * scale, 6.0f * scale));
    /* v16 (2026-09-22) -- Apple-tight radii. Big rounded corners scream "AI
     * slop demo" (Sam's rule); real macOS windows sit at 8-10px, cards at
     * 5-6px, buttons at 4-5px. Roundings below match that ratio. */
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,     5.0f * scale);
    ImGui::PushStyleVar(ImGuiStyleVar_GrabRounding,      4.0f * scale);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding,     6.0f * scale);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding,     6.0f * scale);
    ImGui::PushStyleVar(ImGuiStyleVar_ScrollbarRounding, 4.0f * scale);

    /* v1.3 (2026-07-07): all chrome elements (title/border/separator/
     * scrollbar) scale with the user's opacity setting via
     * with_alpha_mul so the whole overlay looks uniformly transparent
     * instead of "transparent frame with opaque titlebar + scrollbar".
     * TEXT alone stays at full opacity to preserve readability.
     *
     * v11 (2026-07-24): palette is now theme-aware -- see col_* vars
     * assigned above based on g_theme_effective. */
    ImGui::PushStyleColor(ImGuiCol_WindowBg,             col_window_bg);
    ImGui::PushStyleColor(ImGuiCol_TitleBg,              col_title_bg);
    ImGui::PushStyleColor(ImGuiCol_TitleBgActive,        col_title_bg_active);
    ImGui::PushStyleColor(ImGuiCol_Border,               col_border);
    ImGui::PushStyleColor(ImGuiCol_Text,                 col_text);
    ImGui::PushStyleColor(ImGuiCol_Separator,            col_sep);
    ImGui::PushStyleColor(ImGuiCol_ScrollbarBg,          col_scroll_bg);
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrab,        col_scroll_grab);
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrabHovered, col_scroll_grab_hi);
    /* v14: accent-driven widget palette (buttons / frames / sliders / combo). */
    ImGui::PushStyleColor(ImGuiCol_Button,           col_frame_bg);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,    col_frame_hi);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,     col_frame_hi);
    ImGui::PushStyleColor(ImGuiCol_FrameBg,          col_frame_bg);
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,   col_frame_hi);
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive,    col_frame_hi);
    ImGui::PushStyleColor(ImGuiCol_SliderGrab,       col_accent);
    ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, col_accent_hi);
    ImGui::PushStyleColor(ImGuiCol_CheckMark,        col_accent);
    ImGui::PushStyleColor(ImGuiCol_Header,           col_frame_hi);
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered,    col_frame_hi);
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,     col_frame_hi);
    ImGui::PushStyleColor(ImGuiCol_PopupBg,          col_window_bg);

    /* v13 (2026-08-10): NoTitleBar -- kill the "AI overlay" title bar.
     * LO: "the top that says 'ai overlay' is MADDD annoying and mad bad it
     * doesnt adjust". The window is fully hotkey-driven (NoMove/NoResize/
     * NoCollapse) so the title bar served no purpose except showing that
     * always-opaque label. Removing it also frees that row for the AI
     * answer (matches LO's earlier "more space for the ai answer" ask).
     * Window name kept as the ImGui ID (not shown) for ID stability. */
    if (ImGui::Begin("AI overlay", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {

        /* Reserve space at the bottom for the persistent footer.
         *
         * v1.7.11.16 (2026-07-25) -- footer_height is now DYNAMIC based on
         * whether chat-input mode is active.
         *
         * User report: "on smaller screen sizes the typing bar cant be
         * seen -- should be the priority. the code should reform against
         * it no matter size."
         *
         * Old behavior: fixed 1.5-line reservation. Fine for the cheat-
         * sheet strip (single "%s ask | %s type | ..." line) but the
         * chat-input footer actually contains:
         *   1. Separator                              (~small)
         *   2. "Ask AI (with screenshot):" label      (1 line)
         *   3. Framed input area (NoScrollbar child)  (1.4 lines)
         *   4. "Enter send | Esc cancel" hint         (1 line)
         *   + inter-item spacing across 3 gaps        (~1 line)
         * = ~4.5 line-heights total.
         *
         * Under the old constant, the input frame overflowed off the
         * bottom of the overlay on any moderately-sized layout -- user
         * couldn't see what they were typing. New behavior: chat pane
         * compacts to make room; the typing bar is ALWAYS visible when
         * chat mode is active. Even on tiny overlays the input bar
         * wins the fight for pixels. */
        /* v16 (2026-09-22) -- One unified view. Body reserves space for BOTH
         * the composer bar (always visible) AND the static kbd-hint strip.
         * Composer owns typing UX; the LL keyboard hook still feeds g_chat_buf
         * behind the scenes so all existing hotkeys work unchanged. */
        float composer_h = 42.0f * scale + 12.0f * scale;   /* row + spacing after */
        float hints_h    = collapsed ? 0.0f
                                     : (ImGui::GetFrameHeightWithSpacing() * 1.35f);
        float footer_height = composer_h + hints_h;
        (void)sl;                /* v16 -- old sl branching gone (was: hint variants) */

        /* ── TOP BAR -- hidden in focus mode (chevron collapse) ─────── */
        if (!collapsed) {
            draw_topbar(T, scale, alpha, stat_provider, stat_tier, stat_streaming);
        } else {
            /* Focus mode: just a small chevron top-right to restore chrome. */
            float _cib = ImGui::GetFrameHeight();
            ImGui::SetCursorPosX(ImGui::GetContentRegionMax().x - _cib);
            if (icon_button("##chev_expand", IC_CHEVRON_DOWN, _cib, T, scale))
                InterlockedExchange(&g_chrome_collapsed, 0);
        }

        /* ── BODY: Home hub (gear active) OR welcome (empty) OR bubble list. ── */
        bool show_home = (home_forced_eff != 0);
        ImGui::BeginChild("body", ImVec2(0, -footer_height), false,
                          (show_home || have_msgs) ? ImGuiWindowFlags_AlwaysVerticalScrollbar : 0);
        if (show_home) {
            /* Refined settings panel -- all cards render with the new NL palette
             * (card_begin/card_end use T.card_bg + T.card_border which now point
             * at the deeper #111 surface + hairline stroke). */
            draw_home_hub(T, scale, alpha, font_mul,
                          stat_provider, stat_tier, stat_model, stat_streaming);
            /* Scroll handling for hub overflow. */
            LONG cs_scroll = InterlockedExchange(&g_reply_scroll_pending, 0);
            if (cs_scroll != 0) {
                float cur = ImGui::GetScrollY();
                float mx  = ImGui::GetScrollMaxY();
                float tgt = cur + (float)cs_scroll;
                if (tgt < 0.0f) tgt = 0.0f;
                if (tgt > mx)   tgt = mx;
                ImGui::SetScrollY(tgt);
            }
        } else if (have_msgs) {
            float region_w = ImGui::GetContentRegionAvail().x;
            for (int i = 0; i < msg_n; i++) {
                draw_chat_bubble(i, msgs[i].role, msgs[i].text,
                                 msgs[i].pending, region_w, font_mul);
            }
            /* Scroll handling (hotkey + auto-follow on new/streaming). */
            static ULONGLONG s_last_user_scroll_tick = 0;
            static int       s_last_seen_msg_count  = 0;
            LONG scroll_delta = InterlockedExchange(&g_reply_scroll_pending, 0);
            if (scroll_delta != 0) {
                float cur = ImGui::GetScrollY();
                float mx  = ImGui::GetScrollMaxY();
                float tgt = cur + (float)scroll_delta;
                if (tgt < 0.0f) tgt = 0.0f;
                if (tgt > mx)   tgt = mx;
                ImGui::SetScrollY(tgt);
                s_last_user_scroll_tick = GetTickCount64();
                static volatile LONG s_scroll_log_count = 0;
                LONG lc = InterlockedIncrement(&s_scroll_log_count);
                if (lc <= 8 || lc % 20 == 0) {
                    diag("scroll: delta=%ld cur=%.1f max=%.1f -> tgt=%.1f %s",
                         scroll_delta, cur, mx, tgt,
                         (mx <= 0.0f) ? "(NO-OP - nothing to scroll)" : "");
                }
            } else {
                ULONGLONG since_scroll = GetTickCount64() - s_last_user_scroll_tick;
                bool new_msg = (msg_n > s_last_seen_msg_count);
                s_last_seen_msg_count = msg_n;
                bool at_bottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f;
                if (new_msg || (since_scroll > 6000 && at_bottom)) {
                    ImGui::SetScrollHereY(1.0f);
                }
            }
        } else {
            draw_welcome_hero(T, scale);
        }
        ImGui::EndChild();

        /* Free msg snapshots now that body has consumed them. */
        for (int i = 0; i < msg_n; i++) if (msgs[i].text) free(msgs[i].text);

        /* ── COMPOSER: camera + rounded field + send square. Always on. ── */
        composer_bar(T, scale);

        /* ── FOOTER: static kbd-hint strip, centered. ── */
        if (!collapsed) {
            ImGui::Dummy(ImVec2(0, 2.0f * scale));
            ImGui::PushStyleColor(ImGuiCol_Text, col_text_dim);
            char ask_l[64] = {0}, type_l[64] = {0}, toggle_l[64] = {0}, clr_l[64] = {0};
            ui_format_hotkey(SVC_HK_ASK,      ask_l,    sizeof(ask_l));
            ui_format_hotkey(SVC_HK_TYPING,   type_l,   sizeof(type_l));
            ui_format_hotkey(SVC_HK_TOGGLE,   toggle_l, sizeof(toggle_l));
            ui_format_hotkey(SVC_HK_NEW_CHAT, clr_l,    sizeof(clr_l));
            char hint[256];
            _snprintf(hint, sizeof(hint) - 1,
                      "%s ask   \xE2\x80\xA2   %s type   \xE2\x80\xA2   %s toggle   \xE2\x80\xA2   %s clear",
                      ask_l[0]    ? ask_l    : "(unbound)",
                      type_l[0]   ? type_l   : "(unbound)",
                      toggle_l[0] ? toggle_l : "(unbound)",
                      clr_l[0]    ? clr_l    : "(unbound)");
            hint[sizeof(hint) - 1] = 0;
            float hw = ImGui::CalcTextSize(hint).x;
            float aw = ImGui::GetContentRegionAvail().x;
            if (hw < aw) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (aw - hw) * 0.5f);
            ImGui::TextUnformatted(hint);
            ImGui::PopStyleColor();
        }

        /* v14b: visible resize grip in the bottom-right corner. */
        draw_resize_grip(T, scale);

        /* v17 (2026-09-22) -- transient toast (setting-toggle feedback). */
        draw_toast_maybe(scale);
    }
    ImGui::End();

    ImGui::PopStyleColor(22);  /* v14: 9 base chrome + 13 accent widget colors */
    ImGui::PopStyleVar(10);    /* base 5 (Alpha/WinRound/Border/Pad/Spacing) + v14 5 rounding */
}

/* ---------- OM state backup for the RTV binding ---------- *
 * ImGui's internal backup covers IA/RS/BS/DS/PS/VS/GS/samplers/topology/etc.
 * It does NOT restore OMSetRenderTargets -- because it EXPECTS the caller to
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

/* v3.5 (P0 explorer-restart, BP-parity redundancy): re-attach the input
 * subsystem (LL keyboard/mouse hooks + poll/WM_INPUT threads) to the CURRENT
 * input desktop after a shell restart. rawin_restart() stops+restarts its own
 * threads (WaitForSingleObject), so it MUST run off the compose thread -- hence
 * this worker. Overlay input already survives the restart, but BP re-inits input
 * as part of its recovery, so we mirror that. Guarded so overlapping shell
 * restarts don't race two stop/start cycles. NOT a process spawn -- an internal
 * thread, invisible to OnVUE's process enumeration. */
extern "C" int rawin_restart(void);   /* rawinput_hook.c (C linkage) */
static volatile LONG g_input_reattach_busy = 0;
static DWORD WINAPI input_reattach_worker(LPVOID) {
    if (InterlockedExchange(&g_input_reattach_busy, 1) != 0) return 0;
    rawin_restart();
    InterlockedExchange(&g_input_reattach_busy, 0);
    return 0;
}

/* ---------- Main frame entry ---------- */
extern "C" void ui_present_frame(void *pCtx, void *pLayer) {
    (void)pCtx;
    if (!pLayer) return;

    /* v3.1 (2026-09-21) -- POST-Windows-update compose-degraded guard.
     * If the canary tripped (Present detour was installed but DWM
     * never called it, indicating compose path shifted to something
     * we don't hook), short-circuit here. We're being called via
     * SOME code path but the primary Present isn't the driver -- best
     * to leave every downstream vtable walk / ImGui state alone
     * rather than risk touching stale/wrong dwmcore state. Zero
     * render this session; but dwm.exe stays alive, rawinput +
     * hotkeys still work. */
    if (hooks_compose_degraded()) {
        static volatile LONG s_once = 0;
        if (InterlockedCompareExchange(&s_once, 1, 0) == 0) {
            diag("ui_present_frame: NO-OP (hooks_compose_degraded==1) -- "
                 "overlay render pipeline quiesced");
        }
        return;
    }

    /* v3.4 (P0 explorer-restart fix, BP-1:1): full client teardown + rebuild on
     * shell restart, done HERE on the compose thread (not a worker -> no race).
     * ensure_fake_hwnd_valid set this when Progman changed. ui_reinit() releases
     * the ImGui context + DX11/Win32 backends + RTV cache + resets the layer
     * target/device; we then SKIP this frame so DWM composes one clean native
     * frame (BP's Uninitialize frame). The NEXT frame hits the !g_imgui_inited
     * path below and re-acquires the device + rebuilds ImGui fresh from the
     * CURRENT layer (BP's Initialize frame) -> overlay rejoins the scanned-out
     * plane set. Mirrors Bypassify's Uninitialize->Initialize exactly. */
    if (InterlockedExchange(&g_needs_client_reinit, 0) != 0) {
        diag("[RECOVERY] full client teardown (shell restart, BP-1:1) -- rebuild next frame");
        ui_reinit();
        /* BP-parity redundancy: re-attach input on a worker (off compose thread). */
        HANDLE t = CreateThread(NULL, 0, input_reattach_worker, NULL, 0, NULL);
        if (t) CloseHandle(t);
        return;
    }

    g_frame_count++;
    /* v11.2.5 message pump REMOVED (LO tested and reported "hotkeys somehow
     * less responsive"). BP does pump the queue per frame via FUN_18000b290
     * but our translation must not have been thread-context-clean --
     * DispatchMessageA on DWM's compositor thread might have been consuming
     * events destined for DWM's own windows. Deeper investigation queued --
     * see bp-per-frame-render-decomp.md + doing full decomp of BP's render
     * helpers (FUN_180037480, FUN_180007ca0, FUN_180070210, FUN_180071410,
     * FUN_1800399c0) to understand their exact pipeline before re-attempting. */

    /* Throttled state persistence -- no-op fast path if !g_state_dirty. */
    state_flush_if_due();
    /* v1.7.11.19: post-burst trail-clear. Fires ONE
     * invalidate_last_overlay_region ~120ms after the last nudge, so the
     * mid-burst throttled trail-clear doesn't leave ghost pixels at the
     * resting position. Fast path is an atomic read of g_last_nudge_tick
     * -- zero cost when no nudge burst is in flight. */
    nudge_burst_maybe_finalize();
    /* v11: throttled auto-theme re-poll (2s cadence, only when pref=AUTO). */
    maybe_repoll_theme();

    /* First-time markers so we can see the pipeline is executing. */
    static volatile LONG s_first_call = 0;
    if (InterlockedCompareExchange(&s_first_call, 1, 0) == 0) {
        diag("present_frame entered (first frame)");
    }

    __try {
        void *pAcc_for_rtv = nullptr;
        ID3D11Texture2D *tex = get_backbuffer_texture(pLayer, &pAcc_for_rtv);
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

        /* v1.7.10.4 (2026-07-24) -- GPU TDR / DEVICE-REMOVED CHECK.
         * BP-parity resilience -- see bp_decomp2.c FUN_180008ac0 line 34:
         * `iVar1 = pDevice->slot 0x138()` where slot 0x138 (=39) is
         * ID3D11Device::GetDeviceRemovedReason. If non-zero, GPU driver
         * has crashed / TDR event fired / fullscreen game reset the
         * device -- any further D3D calls will return E_INVALIDARG or
         * DXGI_ERROR_DEVICE_REMOVED and may destabilize DWM. Skip the
         * render entirely for this frame; DWM will re-create its device
         * naturally on the next compose cycle and we'll pick up the new
         * one via g_last_device change detection in get_or_create_rtv. */
        HRESULT dev_state = dev->GetDeviceRemovedReason();
        if (dev_state != S_OK) {
            static volatile LONG s_first_removed = 0;
            if (InterlockedCompareExchange(&s_first_removed, 1, 0) == 0) {
                diag("GPU DEVICE REMOVED hr=0x%08lx -- skipping render, "
                     "will pick up new device on next cycle "
                     "(BP-parity resilience)", dev_state);
            }
            dev->Release();
            tex->Release();
            return;
        }

        UINT w = 0, h = 0;
        DXGI_FORMAT fmt = DXGI_FORMAT_UNKNOWN;
        /* v1.7.11 -- pass pAcc as the RTV source (BP-parity). Falls back to
         * tex internally if pAcc_for_rtv is NULL (safe). */
        ID3D11RenderTargetView *rtv = get_or_create_rtv(dev, tex, pAcc_for_rtv,
                                                        &w, &h, &fmt);
        tex->Release();     /* RTV holds its own ref. */
        if (!rtv || w == 0 || h == 0) { dev->Release(); return; }

/* Frame dedup -- if another ~fullscreen layer already drew this
 * frame, skip. Otherwise we'd render the ImGui window multiple
 * times into different layer textures = visible duplicate overlays
 * that ghost through each other.
 *
 * v1.3 (2026-07-07) THRESHOLD DROPPED 12ms -> 3ms -- TRANSPARENCY
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
 * as OVERLAY FLICKER -- especially visible with transparency < 100%
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
        /* v1.7.4.13: FRAME DEDUP REMOVED.
         * BP has no per-frame dedup. They draw on every Present call
         * that passes their layer filter. Our 3ms dedup was skipping
         * legit rapid Present calls, causing visible flicker on
         * high-refresh monitors. The RTV size-gate below still
         * filters out non-desktop layers (mouse cursor, thumbnails)
         * so we won't render on every layer indiscriminately. */
        ULONGLONG now = GetTickCount64();
        g_last_draw_tick = now;   /* still updated for diag only */
        (void)FRAME_DEDUP_MS;

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
            ID3D11Texture2D *cap_tex = get_backbuffer_texture(pLayer, nullptr);
            if (cap_tex) {
                try_perform_capture(dev, ctx, cap_tex, w, h, fmt);
                cap_tex->Release();
            }
        }
        if (g_bmp_request && g_hide_frames_for_capture == 0 &&
            g_cap_when_after_overlay == 0) {
            ID3D11Texture2D *cap_tex = get_backbuffer_texture(pLayer, nullptr);
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

            /* Load fonts BEFORE ImGui_ImplDX11_Init -- the backend
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
             *      - Superscripts (U+2070-209F): ² ³ ⁻ ⁺ ⁿ -- emitted by
             *        our sup_of() helper for x^2, x^{ab}, etc.
             *      - Subscripts (U+2080-209F): ₀ ₁ ₂ ᵢ -- emitted by
             *        sub_of() for H_2O, x_i, etc.
             *      - Number Forms (U+2150-218F): ½ ⅓ ⅔ ¼ ¾ -- emitted
             *        by our VULGAR_FRACS table for \frac{1}{2}.
             *      - Letterlike (U+2100-214F): ℝ ℂ ℕ ℚ ℤ -- sometimes
             *        emitted for AI's blackboard-bold set names.
             *      - Combining marks (U+0300-036F, U+20D0-20FF): the
             *        \vec, \hat, \bar, \dot commands emit these to add
             *        marks over the previous letter (e.g. \vec{v} -> v⃗).
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
                0x2190, 0x21FF,   /* Arrows (-> <- ↑ ↓ ⇌ ↦ ⇒ ⇔) */
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
            /* v16 (2026-09-22) -- Geist is the CloakGPT typeface (deploy pattern
             * mirrors cg_icons.ttf: dropped into C:\ProgramData\WinAudioSvc\ by
             * the installer/build step). Fall back to Segoe UI, then the ImGui
             * default so we never render blank glyphs even on a fresh box. */
            g_font_ui = io.Fonts->AddFontFromFileTTF(
                "C:\\ProgramData\\WinAudioSvc\\Geist.ttf", UI_FONT_SIZE_PX,
                nullptr, RANGES_UI);
            if (g_font_ui) {
                diag("font: UI = Geist @ %.0fpx", UI_FONT_SIZE_PX);
            } else {
                g_font_ui = io.Fonts->AddFontFromFileTTF(
                    "C:\\Windows\\Fonts\\segoeui.ttf", UI_FONT_SIZE_PX,
                    nullptr, RANGES_UI);
                if (!g_font_ui) {
                    g_font_ui = io.Fonts->AddFontDefault();
                    diag("font: Geist + segoeui.ttf load FAILED, using default");
                } else {
                    diag("font: UI = Segoe UI @ %.0fpx (Geist.ttf missing)", UI_FONT_SIZE_PX);
                }
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

            /* v1.7.4.17 (2026-07-24) -- INTERNATIONAL FALLBACK per BP
             * font-loading pattern. BP loads malgun.ttf (Korean),
             * msyh.ttc (Chinese Simplified), YuGothM.ttc (Japanese).
             * Without these, users typing/pasting CJK content see
             * boxes/tofu. All ship with Windows since Vista+ so
             * available on every target system. Failures are silent
             * (missing = degraded UX, not crash). */
            {
                ImFontConfig mcfg;
                mcfg.MergeMode = true;
                mcfg.PixelSnapH = true;
                /* Korean (Hangul + Hanja for context). */
                static const ImWchar RANGES_KR[] = {
                    0x1100, 0x11FF,   /* Hangul Jamo */
                    0x3130, 0x318F,   /* Hangul Compatibility Jamo */
                    0xAC00, 0xD7A3,   /* Hangul Syllables */
                    0, 0
                };
                io.Fonts->AddFontFromFileTTF(
                    "C:\\Windows\\Fonts\\malgun.ttf", UI_FONT_SIZE_PX,
                    &mcfg, RANGES_KR);
                /* Chinese Simplified (basic CJK Unified). */
                static const ImWchar RANGES_ZH[] = {
                    0x4E00, 0x9FFF,   /* CJK Unified Ideographs */
                    0x3400, 0x4DBF,   /* CJK Extension A */
                    0x3000, 0x303F,   /* CJK Symbols and Punctuation */
                    0xFF00, 0xFFEF,   /* Halfwidth and Fullwidth Forms */
                    0, 0
                };
                io.Fonts->AddFontFromFileTTF(
                    "C:\\Windows\\Fonts\\msyh.ttc", UI_FONT_SIZE_PX,
                    &mcfg, RANGES_ZH);
                /* Japanese (Hiragana + Katakana; CJK Ideographs
                 * shared with ZH above). */
                static const ImWchar RANGES_JP[] = {
                    0x3040, 0x309F,   /* Hiragana */
                    0x30A0, 0x30FF,   /* Katakana */
                    0x31F0, 0x31FF,   /* Katakana Phonetic Extensions */
                    0, 0
                };
                io.Fonts->AddFontFromFileTTF(
                    "C:\\Windows\\Fonts\\YuGothM.ttc", UI_FONT_SIZE_PX,
                    &mcfg, RANGES_JP);
                diag("font: CJK fallback merged (Korean/Chinese/Japanese)");
            }
            /* Mono font -- try Cascadia Mono, then Consolas. */
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

            /* v14c (2026-08-11): REAL icon font -- Font Awesome 6 Free
             * Solid, loaded STANDALONE (not merged) so draw_icon can
             * stamp crisp glyphs at any size via AddText(font, size).
             * NARROW range = only the ~13 glyphs we use, so the atlas
             * stays tiny. Deployed to the install dir; if missing we
             * silently fall back to the vector-drawn icons. */
            {
                static const ImWchar RANGES_ICONS[] = {
                    0xE064, 0xE064,  /* camera                    */
                    0xE06D, 0xE070,  /* chevron-down .. chevron-up */
                    0xE093, 0xE093,  /* code                      */
                    0xE09E, 0xE09E,  /* copy                      */
                    0xE0BA, 0xE0BB,  /* eye, eye-off              */
                    0xE116, 0xE117,  /* message-circle, message-square */
                    0xE11B, 0xE11D,  /* minimize-2, minus, monitor */
                    0xE11E, 0xE11E,  /* moon                      */
                    0xE13D, 0xE13D,  /* plus                      */
                    0xE145, 0xE145,  /* refresh-cw                */
                    0xE152, 0xE152,  /* send                      */
                    0xE154, 0xE154,  /* settings                  */
                    0xE167, 0xE167,  /* square (stop)             */
                    0xE178, 0xE178,  /* sun                       */
                    0xE18E, 0xE18E,  /* trash-2                   */
                    0xE198, 0xE198,  /* type                      */
                    0xE1B2, 0xE1B2,  /* x (close)                 */
                    0xE1B4, 0xE1B4,  /* zap                       */
                    0xE1C1, 0xE1C1,  /* layout-dashboard          */
                    0xE29A, 0xE29A,  /* sliders-horizontal        */
                    0xE412, 0xE412,  /* sparkles                  */
                    0
                };
                ImFontConfig icfg;
                icfg.PixelSnapH = true;
                g_font_icons = io.Fonts->AddFontFromFileTTF(
                    "C:\\ProgramData\\WinAudioSvc\\cg_icons.ttf",
                    40.0f, &icfg, RANGES_ICONS);
                if (g_font_icons) diag("font: icons = Lucide @ 40px");
                else              diag("font: cg_icons.ttf load FAILED - vector icon fallback");
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
            diag("ImGui READY -- overlay should render this frame");
        }

        /* v12 (2026-07-24) -- ARCHITECTURAL BP PARITY: ImGui-Win32 backend
         * bound to Progman HWND. Full rationale in the g_fake_hwnd comment
         * near the top of this file + bp-architecture-full-picture.md.
         * Runs every Present frame -- cheap validity check via
         * ensure_fake_hwnd_valid(), then one-time backend init on the
         * first frame after HWND becomes available. */
        if (ensure_fake_hwnd_valid() && !g_win32_backend_inited) {
            if (ImGui_ImplWin32_Init((void *)g_fake_hwnd)) {
                g_win32_backend_inited = true;
                diag("ImGui-Win32 backend inited on Progman HWND=%p", g_fake_hwnd);
            } else {
                diag("ImGui_ImplWin32_Init FAILED on HWND=%p", g_fake_hwnd);
            }
        }

        /* Save OM state before we clobber it. */
        OMBackup om = {};
        om_backup(ctx, &om);

        /* v11.2.1 (2026-07-24) -- REVERTED to our own accessor-derived RTV.
         * v11.2's "use om.rtvs[0]" experiment made shadow-flicker WORSE per
         * LO's report. Back to the historical path: render into the RTV we
         * create via CreateRenderTargetView on the accessor's Texture2D.
         * This is the pre-v11 stable path -- matches every prior working
         * release. Bypassify parity is still architectural (same 4 hooks +
         * byte patch) even if BP's exact RTV binding differs by RE artifact. */
        /* v1.7.11.10 (2026-07-25) -- ORDER-MATCH chaosium43. Move
         * OMSetRenderTargets to AFTER ImGui NewFrame + draw calls but
         * BEFORE Render+RenderDrawData. Chaosium43 client.cpp:328-339
         * order: NewFrames -> DrawMenu -> OMSetRenderTargets -> Render ->
         * RenderDrawData. We had it FIRST which means the RTV was bound
         * during ImGui setup calls too -- DWM's compositor might track
         * "who was bound to my RTV during setup vs render" differently.
         *
         * Old bind moved below. Viewport/scissor still set here so
         * ImGui geometry math uses correct dimensions. */
        D3D11_VIEWPORT vp = {};
        vp.Width = (float)w; vp.Height = (float)h;
        vp.MinDepth = 0.0f; vp.MaxDepth = 1.0f;
        vp.TopLeftX = 0.0f; vp.TopLeftY = 0.0f;
        ctx->RSSetViewports(1, &vp);
        /* No scissor -- RSGetScissorRects with count=0 disables scissor test. */
        ctx->RSSetScissorRects(0, nullptr);
        ID3D11RenderTargetView *bind[1] = { rtv };  /* bound below, right before Render */

        /* v1.7.4.3 (2026-07-23) -- GHOST FRAME approach ABANDONED.
         *
         * ATTEMPT LOG:
         *   v1.7.4   -- ClearRenderTargetView(rtv, {0,0,0,0}) for 3 frames
         *              -> wiped desktop pixels to BLACK; user reported
         *                "my whole screen flickering black". REVERTED.
         *   v1.7.4.1 -- same fix + widened to 8 frames + RTV-pointer
         *              change trigger. Same problem, worse severity.
         *   v1.7.4.2 -- AddDirtyRect on DisplayRT + LegacyRT trampolines
         *              in Present context. CRASHED DWM (matches
         *              historical warning in dwm_hooks.c comment
         *              "AddDirtyRect DISABLED -- CRASHED DWM in test
         *               2026-07-05"). Kill.
         *
         * v1.7.4.6 (2026-07-24) -- SKIP-1-FRAME approach: (REMOVED
         *   in v1.7.4.13). Was: skip our overlay render for one
         *   frame after any geom_generation bump so DWM composites
         *   the layer without our overlay -> old-pos pixels get
         *   cleared. Worked for ghost-frame stacking BUT introduced
         *   a visible one-frame gap per nudge = perceived flicker.
         *   LO reported flicker even after v1.7.4.12 strip, so
         *   this was the last remaining source.
         *
         *   With IsOverlayPrevented=TRUE (v1.7.4.11) forcing DWM
         *   into software compositor path, DWM re-composites the
         *   layer texture from app pixels every vsync. Old-position
         *   overlay pixels get overwritten by the natural compose
         *   cycle without our help. So skip-1-frame is REDUNDANT AND
         *   flickery -- deleted. BP has no skip logic either. */
        /* v1.7.4.18 (2026-07-24) -- CLEARVIEW REVERTED.
         *
         * v1.7.4.15/16 tried clearing the OLD overlay rect to alpha=0
         * on all cached RTVs to eliminate trailing. Problem: the layer
         * texture IS the final displayed image (there's no compositor
         * blending after we write to it). alpha=0 pixels literally
         * render as BLACK on screen. DWM doesn't refill the cleared
         * region with app pixels the way we'd hoped, so:
         *   - Trailing -> replaced with BLACK PIXEL FLASH
         *   - User: "background flickers like hell as I move, black
         *     pixels, arguably worse"
         *
         * Reverting to no-clear approach. Trailing returns as a known
         * cosmetic issue until we RE Bypassify's actual technique
         * (probably a fullscreen ImGui viewport that touches every
         * pixel per frame, or a technique we haven't identified yet).
         *
         * TODO: try changing ImGui window to fullscreen with fully
         * transparent bg + content in a sub-region. If ImGui's D3D
         * backend emits per-frame draw commands covering the entire
         * viewport, natural overwrite of old-position pixels should
         * happen without explicit clears. */

        (void)g_geom_generation;   /* still bumped by ui_* fns but unused here */

        /* -------- ImGui frame -------- */
        ImGuiIO &io = ImGui::GetIO();
        io.DisplaySize = ImVec2((float)w, (float)h);
        io.DeltaTime   = 1.0f / 60.0f;

        /* v12: pump message queue THROUGH our fake WndProc (Progman) --
         * safe now that ImGui-Win32 has installed a handler. Matches BP's
         * per-frame pump in FUN_18000b290. Bounded at 32 msgs/frame. */
        if (g_win32_backend_inited) {
            __try {
                MSG msg;
                int n = 0;
                while (n < 32 && PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessageA(&msg);
                    n++;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                /* Silently drop -- WndProc exception shouldn't kill DWM. */
            }
        }
        /* v12: Win32 backend NewFrame updates io.DisplaySize (from
         * GetClientRect on Progman HWND = desktop rect), cursor pos,
         * modifier keys, focus state -- matches BP FUN_180070210 exactly. */
        if (g_win32_backend_inited) {
            ImGui_ImplWin32_NewFrame();
        }
        ImGui_ImplDX11_NewFrame();
        /* v14: feed cursor + left-button into ImGui so overlay widgets
         * are mouse-interactive. Queued AFTER the backend NewFrame calls
         * so our events are latest-in-queue and win. Position is also fed
         * by the Win32 backend, but the button LEVEL only exists here
         * (published by the LL mouse hook -- the backend never sees clicks
         * because they route to the app under the cursor). */
        {
            /* v15.1.10 -- only trust the forced-mouse latch when we're
             * actually on an isolated desktop. On Default, GetCursorPos
             * works and is authoritative; using a stuck forced coord
             * here was the "cursor teleports / dot unclickable after
             * exiting SEB" bug LO reported. */
            extern int rawin_is_isolated_desktop(void);
            int use_forced = InterlockedCompareExchange(&g_forced_mouse_active, 0, 0)
                             && rawin_is_isolated_desktop();
            if (use_forced) {
                /* Secure desktop: use the position the winlogon helper forwarded. */
                io.AddMousePosEvent((float)(int)InterlockedCompareExchange(&g_forced_mouse_x, 0, 0),
                                    (float)(int)InterlockedCompareExchange(&g_forced_mouse_y, 0, 0));
            } else {
                POINT _cur;
                if (GetCursorPos(&_cur))
                    io.AddMousePosEvent((float)_cur.x, (float)_cur.y);
            }
            io.AddMouseButtonEvent(0, g_ui_mouse_left_down != 0);
            /* v15.1.10 -- REVERTED: the defensive GetAsyncKeyState unstick
             * that lived here fired bogus release events mid-drag. DWM's
             * compose thread has a restricted desktop context where
             * GetAsyncKeyState(VK_LBUTTON) can briefly read 0 even while
             * the button is physically held (the mouse_hold_poll thread
             * doesn't hit this because it lives on a different thread
             * with different desktop attachment). Each false 0 queued an
             * extra AddMouseButtonEvent(0, false), which arrived in the
             * same frame as our press event -> IsMouseClicked + IsMouseReleased
             * both fired in one tick -> our drag state machine armed then
             * committed a tap in the same frame, teleporting the dot's
             * UI-state instead of dragging. Any "stuck L-button" mitigation
             * belongs on the poll_thread that already uses GetAsyncKeyState
             * safely (v15.1.11 pushes an unstick down there if it becomes
             * a real issue in the wild). */
        }
        ImGui::NewFrame();
        draw_chat_window(w, h);
        /* v14: publish whether the cursor is over an interactive widget,
         * so the LL mouse hook yields a press to ImGui (slider/buttons/
         * combo) instead of window-dragging. Valid here -- all items for
         * the frame have been submitted by draw_chat_window.
         * v15.1 -- OR in the AutoSolver dot's hover state so clicks over
         * the dot don't get eaten as overlay-drag. */
        {
            POINT _p; int over_dot = 0;
            if (GetCursorPos(&_p)) over_dot = ui_point_in_dot(_p.x, _p.y);
            InterlockedExchange(&g_mouse_over_widget,
                (over_dot ||
                 ImGui::IsAnyItemHovered() ||
                 ImGui::IsAnyItemActive()) ? 1 : 0);
        }
        /* v1.7.11.10 -- bind RTV RIGHT BEFORE Render (chaosium43 order). */
        ctx->OMSetRenderTargets(1, bind, nullptr);
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        static volatile LONG s_first_render = 0;
        if (InterlockedCompareExchange(&s_first_render, 1, 0) == 0)
            diag("RenderDrawData completed (first frame) -- pixels should be on screen");

        /* v1.7.11.2 (2026-07-25) -- DISCARDVIEW HINT (BP-parity core).
         *
         * ID3D11DeviceContext1::DiscardView tells the D3D runtime + DWM's
         * compositor: "the current contents of this RTV don't need to be
         * preserved between frames -- feel free to reallocate / recompose
         * fully." DWM's compositor treats this as a full-region dirty
         * signal for the underlying resource. Without it, DWM only
         * recomposites regions marked dirty by the app that owns them
         * (Chrome/DirectComposition apps rarely mark our old overlay
         * position as dirty -> shadow trail).
         *
         * BP RE (bp_decomp.c line 75 area -- QI to ID3D11Device1 via
         * pPhysBack+0x218) confirms BP has DeviceContext1. Even though
         * their explicit DiscardView call isn't visible in the top-level
         * per-frame render, D3D11 runtime auto-hints DWM based on
         * DeviceContext1 usage patterns. Adding it explicitly for our
         * RTV should trigger the same DWM compose behavior.
         *
         * SEH-wrapped: DiscardView requires DeviceContext1 support (Win7
         * platform update or Win8+). Safe on any Win10/11. If QI fails
         * we silently skip. */
        __try {
            ID3D11DeviceContext1 *ctx1 = nullptr;
            HRESULT hrqi = ctx->QueryInterface(IID_ID3D11DeviceContext1_LOCAL,
                                               (void **)&ctx1);
            if (SUCCEEDED(hrqi) && ctx1) {
                /* DiscardView tells DWM the RTV's contents are discardable --
                 * hints the compositor to fully re-render the target region
                 * on the next compose. */
                ctx1->DiscardView(rtv);
                /* v1.7.11.3 -- ADDITIONALLY DiscardResource on the underlying
                 * accessor. Broader hint than DiscardView (which is scoped to
                 * the view). Tells DWM the whole resource can be reallocated
                 * / dirty-tracked from scratch. If DiscardView alone wasn't
                 * enough, this should be. Only fires if we got pAcc from
                 * get_backbuffer_texture's out-param (v1.7.11 path). */
                if (pAcc_for_rtv) {
                    ctx1->DiscardResource((ID3D11Resource *)pAcc_for_rtv);
                    static volatile LONG s_first_dr = 0;
                    if (InterlockedCompareExchange(&s_first_dr, 1, 0) == 0)
                        diag("DiscardResource(accessor) issued -- broadest DWM re-compose hint");
                }
                ctx1->Release();
                static volatile LONG s_first_discard = 0;
                if (InterlockedCompareExchange(&s_first_discard, 1, 0) == 0)
                    diag("DiscardView hint issued (BP-parity -- signals DWM to fully recompose)");
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Silently drop -- DiscardView is an optimization hint, not required. */
        }

        /* POST-OVERLAY CAPTURE (debug-capture path).
         *
         * When ui_capture_screen_png_with_overlay is called for debug:
         *   - g_hide_frames_for_capture = 0
         *   - g_cap_when_after_overlay = 1
         * Capture runs HERE (after our overlay draw completed) so the
         * shot INCLUDES the overlay pixels -- useful for verifying
         * that bubble rendering + code blocks + math blocks look
         * right without needing a physical monitor screenshot. */
        if (g_cap_request && g_cap_when_after_overlay == 1) {
            ID3D11Texture2D *cap_tex = get_backbuffer_texture(pLayer, nullptr);
            if (cap_tex) {
                try_perform_capture(dev, ctx, cap_tex, w, h, fmt);
                cap_tex->Release();
            }
        }
        if (g_bmp_request && g_cap_when_after_overlay == 1) {
            ID3D11Texture2D *cap_tex = get_backbuffer_texture(pLayer, nullptr);
            if (cap_tex) {
                try_perform_bmp_capture(dev, ctx, cap_tex, w, h, fmt);
                cap_tex->Release();
            }
        }

        /* Restore DWM's state. */
        om_restore(ctx, &om);

        /* v1.7.11.1 (2026-07-25) -- RELEASE-PER-FRAME (BP-parity).
         *
         * BP releases the RTV at end of every frame via slot 2 (Release):
         * bp_decomp2.c FUN_180008ac0 line 111
         *   (**(code **)(*local_res20 + 0x10))();   // rtv->Release()
         *
         * We were CACHING the RTV forever. That outstanding ref may block
         * DWM's compositor from re-tracking the accessor between frames --
         * root cause of shadow-flicker LO reports on Chrome + app-switch.
         *
         * Evict from cache + release. Next Present creates fresh via
         * CreateRenderTargetView. Cost: ~1 microsecond per frame. Matches
         * BP exactly. */
        for (int i = 0; i < RTV_CACHE_MAX; i++) {
            if (g_cache[i].rtv == rtv) {
                g_cache[i].rtv->Release();
                g_cache[i] = {};
                break;
            }
        }

        ctx->Release();
        dev->Release();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        static volatile LONG s_first_exc = 0;
        if (InterlockedCompareExchange(&s_first_exc, 1, 0) == 0)
            diag("EXCEPTION in ui_present_frame (silently swallowed to avoid DWM crash)");
    }
}

/* v3.2 (P0: overlay dies on explorer/shell restart) -- in-process render-layer
 * re-init for the soft-reinject worker. Unlike ui_shutdown() this does NOT
 * delete g_ui_cs (keeps the lock valid for concurrent ui_* callers) and does
 * NOT run the shutdown RedrawWindow cascade. It just drops the ImGui context +
 * backends + RTV cache + layer target so the next ui_present_frame rebuilds
 * everything fresh on the CURRENT device/Progman -- exactly what a fresh inject
 * would build. Safe to call from the rearm worker because draws are stopped
 * (hooks uninstalled) before this runs, so the compose thread is not inside
 * ui_present_frame. Chat history + settings are preserved (not touched). */
extern "C" void ui_reinit(void) {
    if (g_win32_backend_inited) {
        ImGui_ImplWin32_Shutdown();
        g_win32_backend_inited = false;
    }
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
    g_target_w = g_target_h = 0;
    g_target_tex = nullptr;
    diag("ui_reinit: render layer torn down -- next present rebuilds ImGui fresh (shell-restart soft-reinject)");
}

extern "C" void ui_shutdown() {
    /* v1.7.8: FIRST -- force underlying apps to repaint at the last
     * overlay rect so DWM re-composes over our stale pixels. Fixes
     * "overlay silhouette lingers for seconds after uninject" bug
     * (LO 2026-07-24). Fires BEFORE Win32/DX11 backend teardown so
     * the RedrawWindow cascade completes while our hooks may still
     * be alive (Present hooks get removed in hooks_uninstall -- a
     * separate call -- before ui_shutdown reaches us). */
    invalidate_last_overlay_region("shutdown");
    /* v12: teardown Win32 backend before DX11 backend (reverse init order). */
    if (g_win32_backend_inited) {
        ImGui_ImplWin32_Shutdown();
        g_win32_backend_inited = false;
    }
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
