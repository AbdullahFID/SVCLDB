# Bypassify v1.3.0 DWM Payload — Complete RE (2026-07-04)

Binary: `C:\Temp\bp_re\payload.dll` (815,616 B, from
`launchhere (1).exe` → embedded resource RT_RCDATA id 101).
Timestamp: 2026-07-01 15:55:55 UTC. Only export: `OffsetTable @ RVA
0xC00B0`. ImageBase 0x180000000, EntryPoint (DllMain) RVA 0x9E0A0.

## The complete architecture

### The two magic .data slots

Bypassify's entire "make DWM composite on demand" trick hinges on TWO
`.data` locations, populated by DllMain from the exported OffsetTable:

| .data VA        | Content (populated at DllMain) | Meaning |
|-----------------|--------------------------------|---------|
| `0x1800c1210`   | `dwmcoreBase` (HMODULE)        | Base of loaded dwmcore.dll |
| `0x1800c1218`   | `g_origPresent`                | Out from `MH_CreateHook(Present, ...)` |
| `0x1800c1220`   | `g_origPresentNeeded1`         | Out from `MH_CreateHook(PN1, ...)` — CDDisplayRenderTarget::PresentNeeded |
| `0x1800c1228`   | `g_origPresentNeeded2`         | Out from `MH_CreateHook(PN2, ...)` — CLegacyRenderTarget::PresentNeeded |
| `0x1800c1230`   | `dwmcoreBase + OffsetTable[7]` (0x10e3fc) | **NON-HOOKED** dwmcore function called from PN detours with `(NULL, -1)` |
| `0x1800c1244`   | `g_shutdown_flag` (1 byte)     | **THE MASTER SWITCH.** 0 = actively rendering; 1 = shutdown mode |

### The OffsetTable (data blob, 32 slots × 8 bytes at RVA 0xC00B0)

```
[ 0] 0x028       vtable byte offset — GetPhysicalBackBuffer (slot 5 × 8)
[ 1] 0x0c0       vtable byte offset — GetD3D11Resource      (slot 24 × 8)
[ 2] 0x098       vtable byte offset — accessor              (slot 19 × 8)
[ 3] 0x020       vtable byte offset — slot 4 × 8            (unused?)
[ 4] 0x1ae000    dwmcore RVA — COverlayContext::Present     ← MH_CreateHook'd
[ 5] 0x1d88d0    dwmcore RVA — CDDisplayRenderTarget::PresentNeeded  ← MH_CreateHook'd
[ 6] 0x1d8904    dwmcore RVA — CLegacyRenderTarget::PresentNeeded    ← MH_CreateHook'd
[ 7] 0x10e3fc    dwmcore RVA — MYSTERY FN (called with rcx=0, rdx=-1 inside PN detours; NOT hooked)
[ 8] 0x1f5180    dwmcore RVA — IsOverlayPrevented                    ← MH_CreateHook'd
[ 9] 0x218       struct offset — CPhysBackBuffer + 0x218 = ID3D11Device*
[10] 0           null slot
[11] 0x3fd7b9    dwmcore RVA — some BYTE inside dwmcore (patched to 1 at init, 0 at shutdown)
[14] 0x6
[15] 0x0f
[24] 0x0f
[26] 0x02
```

For **our current dwmcore.dll build**, our resolver got:
- Present @ 0x231000  (bp diff +0x83000)
- PresentNeeded (Display) @ 0x1d0f10  (bp diff -0x79c0)
- PresentNeeded (Legacy) @ 0x1d0f44  (bp diff -0x79c0)
- IsOverlayPrevented @ 0x1ee600  (bp diff -0x6b80)
- ForceFullDirtyRendering @ 0x3fd819  (bp diff +0x60 — extremely close, so bp slot [11] is
  probably a byte INSIDE the same function or an adjacent static flag)

## The DWM init function (at RVA 0x3580, called from DllMain)

```
push rbx; sub rsp, 0x20
DwmLog("[DWM] Init() called")
dwmcoreBase = GetModuleHandleA("dwmcore.dll")
[0x1800c1210] = dwmcoreBase
DwmLog("[DWM] dwmcoreBase=0x%llX", dwmcoreBase)

// Store SLOT[7]'s VA to 0x1800c1230 (the mystery function pointer used by PN detours)
[0x1800c1230] = dwmcoreBase + OffsetTable[7]  // = dwmcoreBase + 0x10e3fc

// Byte-patch dwmcore + OffsetTable[11] (= dwmcoreBase + 0x3fd7b9) to 1
*(BYTE*)(dwmcoreBase + 0x3fd7b9) = 1

status = MH_Initialize(); DwmLog("[DWM] MH_Initialize: %d", status)

// Install 4 MinHooks
MH_CreateHook(dwmcoreBase + 0x1ae000, Detour_Present,     &g_origPresent);        DwmLog("[DWM] Hook Present: %d", ...)
MH_CreateHook(dwmcoreBase + 0x1d88d0, Detour_PN1,         &g_origPresentNeeded1); DwmLog("[DWM] Hook PresentNeeded1: %d", ...)
MH_CreateHook(dwmcoreBase + 0x1d8904, Detour_PN2,         &g_origPresentNeeded2); DwmLog("[DWM] Hook PresentNeeded2: %d", ...)
MH_CreateHook(dwmcoreBase + 0x1f5180, Detour_IOP,         (unused));              DwmLog("[DWM] Hook IsOverlayPrevented: %d", ...)

MH_EnableHook(NULL);                                                              DwmLog("[DWM] EnableHook: %d", ...)
DwmLog("[DWM] Init() success")
```

## The 4 detours (all at low RVAs, MinHooked)

### Detour_IsOverlayPrevented (0x180003460, 13 bytes)

```asm
movzx eax, byte ptr [g_shutdown_flag]
test  al, al
sete  al          ; al = (flag == 0)
ret
```

- **flag = 0 (default, running)** → returns **TRUE** ("overlay IS prevented" → forces dwmcore into non-overlay-optimization path)
- **flag = 1 (shutdown)** → returns **FALSE** (lets dwmcore behave normally)

### Detour_COverlayContextPresent (0x180003470, 6-arg __fastcall)

```c
LONG __fastcall Detour_Present(pCtx, pLayer, flags, a4, a5, a6) {
    // save all 6 args to stack shadow-space
    __try {
        if (g_shutdown_flag == 0) {
            DrawGptWindow_inner(pCtx, pLayer);   // OUR draw into layer texture
        }
    } __except { DwmLog("[CRASH] Exception 0x%08X in HookPresent", code); }
    // restore args, always call orig even during shutdown
    return g_origPresent(pCtx, pLayer, flags, a4, a5, a6);
}
```

### Detour_CDDisplayRenderTarget_PresentNeeded (0x180003520, 1-arg __fastcall)

```c
BOOL __fastcall Detour_PN1(pThis) {
    BOOL orig_result = g_origPresentNeeded1(pThis);   // always call orig
    if (g_shutdown_flag == 0) {
        MysteryFn(NULL, -1);                          // dwmcoreBase + 0x10e3fc(NULL, -1)
        return TRUE;                                  // FORCE compose
    }
    return orig_result;                               // shutdown: pass through
}
```

### Detour_CLegacyRenderTarget_PresentNeeded (0x180003550, 1-arg __fastcall)

**IDENTICAL structure to PN1**, just calls `g_origPresentNeeded2`. Same
"return TRUE if flag == 0, else pass through" pattern. Same
`MysteryFn(NULL, -1)` call.

## The Shutdown function (RVA 0x180003920)

```asm
sub rsp, 0x38
DwmLog("[DWM] Shutdown() called")
rcx = dwmcoreBase
[g_shutdown_flag] = 1       ; ATOMIC: immediately stop drawing + return orig from PN + return FALSE from IOP
if (dwmcoreBase != NULL) {
    // Undo the byte-patch: write 0 back to dwmcoreBase + OffsetTable[11]
    *(BYTE*)(dwmcoreBase + 0x3fd7b9) = 0
}
CreateThread(NULL, 0, ShutdownThread, NULL, 0, NULL)
add rsp, 0x38; ret
```

## The ShutdownThread (RVA 0x180003980)

```asm
push rbx; sub rsp, 0x20
DwmLog("[DWM] ShutdownThread: sleeping 200ms")
Sleep(200)                              ; ~12 frames — let dwmcore composite CLEAN
DwmLog("[DWM] ShutdownThread: disabling hooks")
status = MH_DisableHook(NULL)           ; disable ALL hooks
DwmLog("[DWM] ShutdownThread: MH_DisableHook=%d", status)
DwmLog("[DWM] ShutdownThread: calling Uninitialize")
status = MH_Uninitialize()
DwmLog("[DWM] ShutdownThread: MH_Uninitialize=%d", status)
DwmLog("[DWM] ShutdownThread: Uninitialize done")
FreeLibraryAndExitThread(g_hInstance, 0)
```

## KEY TAKEAWAYS (implementable 1:1 in svcldb)

### 1. The "always return TRUE from PresentNeeded" trick IS Bypassify's core anti-lazy-compose mechanism

Both PN1 and PN2 detours return `TRUE` unconditionally while the
shutdown flag is 0. This forces DWM to composite EVERY vsync,
regardless of whether any window on screen changed. Our overlay
consequently updates at native monitor refresh rate (60/120/144 Hz).

### 2. The `g_shutdown_flag` byte is a MASTER SWITCH that atomically:

- Stops the Present detour from drawing (flag=1 → skip draw call)
- Stops the PN detours from returning TRUE (flag=1 → return orig)
- Inverts IsOverlayPrevented from TRUE to FALSE (flag=1 → allow overlays again = restore default)

This is the CORRECT way to shut down gracefully — flip ONE byte, and
all hook side-effects instantly stop.

### 3. The 200ms delay in ShutdownThread is CRITICAL

After flipping the flag, sleep 200ms (~12 frames at 60Hz), THEN
disable hooks. During those 200ms, orig Present composites CLEAN
pixels from the underlying app → DWM's compositor backbuffer is
naturally cleared of our overlay pixels. Only THEN safely disable
hooks. This is why Bypassify does NOT leave the overlay onscreen after
--unload.

### 4. The `MysteryFn(NULL, -1)` call in PN detours is a NICE-TO-HAVE, not critical

Bypassify calls `dwmcoreBase + 0x10e3fc(NULL, -1)` after each orig
PresentNeeded. Without symbols we can't confirm what it is, but it's
likely a "wake DWM from idle" trigger. Not required — our `return
TRUE` alone forces compose. Skip this call in svcldb (or resolve
`CScheduler::TriggerFrame` / similar).

### 5. The byte-patch at `dwmcoreBase + 0x3fd7b9` is likely a "force full render mode" flag

The RVA is 96 bytes before ForceFullDirtyRendering in our build.
Almost certainly a static bool that dwmcore internally reads. Setting
it to 1 at init makes dwmcore itself take "full-dirty" render paths
always. Reset to 0 at shutdown.

This is OPTIONAL — we can achieve equivalent effect by calling
`ForceFullDirtyRendering()` from our own code when we need it. Skip
the byte-patch for simpler + safer.

## OUR IMPLEMENTATION PLAN (svcldb dwm_hooks.c)

1. Add PN1 + PN2 hooks. Capture pThis on first call. Return TRUE while
   `g_wake_active`, else return orig result.
2. Set `g_wake_active = 1` when overlay is visible.
3. On any UI state change (hotkey toggle, nudge, resize, etc.), bump
   `g_wake_frames_remaining` to 6 (100ms at 60Hz) so we force compose
   for ~100ms after the change. This handles the "hotkey needs click"
   bug.
4. On uninstall: set g_shutdown_flag = 1, Sleep(200), MH_DisableHook,
   MH_Uninitialize. Matches Bypassify's proven pattern.
5. On uninstall ALSO: revert the IsOverlayPrevented byte-patch (write
   original 3 bytes back). Belt-and-suspenders — DWM restart clears
   naturally but a clean uninstall is nicer.

## Key imports Bypassify uses (confirming our IMPLEMENTATION checks)

- **DOES NOT use** DirectComposition (no `IDCompositionDevice`)
- **DOES NOT use** dwmapi (no `DwmFlush`)
- **DOES NOT use** D3D11 directly (only D3DCOMPILER for ImGui shader)
- **DOES NOT use** SendInput (no synthetic keystrokes)
- **DOES import** `SetCursorPos`, `GetCursorPos`, `SetForegroundWindow`,
  `GetForegroundWindow` — but analysis shows these are used inside their
  input handling (not for waking DWM). Our `wake_dwm_composition()`
  should PRIMARILY use the PN detour force-compose trick; SetCursorPos
  is only a belt-and-suspenders fallback.
