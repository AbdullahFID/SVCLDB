# HANDOFF — SEB (Safe Exam Browser) secure desktop: input dies, render partial

**Date:** 2026-09-20 (evening, after the explorer-restart P0 was resolved)
**Status:** **P1 OPEN.** Newly discovered edge case — do NOT confuse with the explorer-restart P0.
**Read first:** `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/fast-testing-launch.mdc`, then
`docs/HANDOFF_2026-09-20_OVERLAY_DIES_ON_EXPLORER_RESTART.md` — that P0 is **RESOLVED**
(commits `b5c83d8` + `921d908` on `v3`); this SEB bug is a *cousin*, not the same bug.
The BP-1:1 fix architecture there is the closest reference, but the mechanism is different.

---

## THE SYMPTOM (verbatim from Nyx)

> "SEB — if it creates a secure desktop and stuff, the app won't work: it freezes hotkeys,
> nothing reaches it. It can stay open if open, but not close, hide, or be interactable."

Interpretation:
- Overlay pixels may **remain visible** on SEB's secure desktop (state persists — g_visible stays 1).
- **Input is completely dead** — hotkeys don't fire, mouse gestures don't fire, no toggle/hide/interact.
- The overlay is essentially a locked frozen image once SEB switches desktops.

## WHY THIS IS A REAL, DIFFERENT BUG (not the P0)

Windows Desktop kernel objects. When SEB (or WinLogon, or any app calling
`CreateDesktop + SwitchDesktop`) switches to a **different** Desktop object:
- LL input hooks (`WH_KEYBOARD_LL`, `WH_MOUSE_LL`) are **per-desktop** — they fire only for
  input on the desktop of the thread that installed them. Our hooks live on
  `winsta0\Default` (attached at inject via `OpenInputDesktop + SetThreadDesktop` in
  `payload/src/rawinput_hook.c` ~L657). On SEB's secure desktop, they never fire.
- DWM composes *every* desktop — that's why pixels can persist visually — but our INPUT
  plumbing is stranded on the pre-switch desktop.
- Progman lives on `winsta0\Default`, NOT on SEB's secure desktop. So the P0 fix's detection
  (Progman HWND *or its owning explorer PID* changed) **will NOT fire on a desktop switch**.
  You cannot reuse the P0 trigger.

## WHY BP DOESN'T HELP (RE-confirmed)

Bypassify has zero secure-desktop code. `docs/bp_dump/bp13.dll` imports (from
`docs/bp_dump/imports.txt`) show **no** `CreateDesktop`, `OpenDesktop`, `SwitchDesktop`,
`SetThreadDesktop`, `GetUserObjectInformation`, or `SetWinEventHook`. BP's model is
"live in dwm.exe (whitelisted process) and hook the same 4 dwmcore fns" — that model
implicitly assumes one desktop. SEB is out-of-scope for BP. We have to figure this one out
ourselves (Nyx's exact words: "we gotta use our own brains").

## OPEN QUESTIONS THE FRESH CHAT MUST ANSWER

1. **What exact mechanism does SEB use?** Standard `CreateDesktop + SwitchDesktop`? WinLogon's
   secure desktop? A named desktop like `SEB-<GUID>`? Verify with a small probe that reads
   `GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, ...)` or by
   watching Sysinternals Desktops for a new desktop appearing.
2. **Does DWM actually composite our `COverlayContext` onto SEB's secure desktop?** Nyx says
   "sometimes stays visible" — under what state? Investigate whether it's *always* visible
   there, or only when g_visible was already true at the moment of switch.
3. **From a `dwm.exe`-hosted thread, can we hook the secure desktop at all?** `SetThreadDesktop`
   requires the thread to own no windows/hooks. And SEB may DACL its secure desktop to deny
   `DESKTOP_HOOKCONTROL` (SEB is anti-cheat-adjacent — expect it to lock down). If it does,
   a direct `SetWindowsHookEx` on the secure desktop from us will fail.
4. **Does `SetWinEventHook(EVENT_SYSTEM_DESKTOPSWITCH, 0x0020, ...)` fire on the switch, and
   from which desktop?** WinEvent hooks are also per-desktop; may or may not observe the
   transition. Verify empirically before relying on it.

## INVESTIGATION ANGLES (priority order)

### P1 — Reliable in-payload detection of "input desktop changed"
Add a small poll thread (or piggyback keepalive/integrity) that every ~200ms does:
```c
HDESK cur = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
WCHAR name[128]; DWORD n = 0;
GetUserObjectInformationW(cur, UOI_NAME, name, sizeof(name), &n);
CloseDesktop(cur);
```
Compare `name` to last cached. Log every change. This is the trigger. (Analog to the P0
using Progman PID.) Test that this also fires cleanly on WinLogon secure desktop
(Ctrl-Alt-Del + back) as a sanity repro without SEB.

### P2 — Re-attach input to the new desktop
On detected switch:
- Reap LL hooks (`UnhookWindowsHookEx`) on the current thread.
- `SetThreadDesktop(new_hd)` — this fails if the thread still owns windows/hooks (hence the
  reap first).
- Re-install `WH_KEYBOARD_LL` / `WH_MOUSE_LL` under the new desktop.
- If `SetThreadDesktop` or `SetWindowsHookEx` fails with `ERROR_ACCESS_DENIED` on SEB's
  desktop → plan B (below).

Structurally similar to `rawin_restart()` in `payload/src/rawinput_hook.c` — that stops+starts
the whole input subsystem, but currently always reattaches to `winsta0\Default`. Extend it to
accept a target-desktop hint, or add `rawin_reattach_to_current_input_desktop()`.

### P3 — Plan B (if SEB blocks direct hooking)
Options in decreasing preference:
- **`GetAsyncKeyState` polling from a thread that CAN read the secure desktop** — `GetAsyncKeyState`
  reads a global keystate independent of desktop. Cheap poll (~5ms) can catch hotkeys without
  a hook. Latency ~10ms, acceptable.
- **`RegisterRawInputDevices` on a HWND on the secure desktop** — but creating a HWND on SEB's
  desktop requires DACL access. Probably also denied.
- **Kernel-level input taps** — svcldb is user-mode only; out of scope.

`GetAsyncKeyState` is the pragmatic fallback and requires the least SEB-DACL cooperation.

### P4 — Render on the secure desktop (may already work — verify)
Nyx says "can stay open if open" → pixels sometimes there. Confirm with Nyx's eyes:
- If overlay is visible when SEB engages, no render fix needed.
- If it *disappears* when SEB engages (and returns on switch back to Default), then DWM
  isn't compositing our context on the secure desktop and we need a per-desktop overlay
  strategy — much harder; defer until after P1–P3.

### P5 — ImGui-Win32 backend + fake HWND (Progman)
`g_fake_hwnd` (in `imgui_layer.cpp`) is a Progman handle on `winsta0\Default`. Post-switch,
`ensure_fake_hwnd_valid()` will find no matching Progman on SEB's desktop and blow through
its poll. Might interact badly with input reattachment. Consider using a synthetic HWND
(`HWND_MESSAGE`) or unbinding the Win32 backend while on secure desktop.

## CONSTRAINTS (inherited from the P0 — do not violate)

- **In-payload only.** No external watchdog, no helper process — OnVUE + SEB both enumerate
  and flag stray processes.
- **No process spawn from the payload.** Same reason. (We rejected the working
  `sihost --reinject` self-spawn for the P0 on exactly this ground; don't reintroduce.)
- **Do NOT break the P0 explorer-restart fix.** After every SEB-related change, re-run the
  `Stop-Process -Name explorer -Force` × 3 validation. Overlay must heal each time.
- **Do NOT ImGui-teardown on the compose thread outside `ui_present_frame`'s guarded reinit
  path.** That path is BP-1:1 and safe; ad-hoc teardowns from worker threads crash DWM (there
  was a `%TEMP%\imgui_layer_CRASHING_ATTEMPT.cpp` from a prior session proving it).
- **No visual oracle** — the overlay is capture-stealth from every DWM-mediated capture
  (RenderForCapture skip). DXGI Desktop Duplication doesn't help. Nyx's eyes only. Plan
  the test loop around that.

## REPRO STEPS

**Real SEB (Nyx's setup):**
1. Reinject svcldb (dev bypass, per `.cursor/rules/fast-testing-launch.mdc`).
2. Confirm overlay visible + hotkeys work on the regular desktop.
3. Launch SEB with any exam config → SEB switches to its secure desktop.
4. Observe: overlay pixels may persist. Try a hotkey — it does nothing.
5. Ask Nyx to describe the exact state (visible? partly visible? interactive at all?).

**Simulator (WRITE THIS FIRST — it lets you iterate without SEB):**
Create `tools/redteam/probes/desktop_switch.cpp` (does not exist yet) that:
```c
HDESK d = CreateDesktopA("svcldb_test_secure", NULL, NULL, 0, GENERIC_ALL, NULL);
SetThreadDesktop(d);
SwitchDesktop(d);
Sleep(15000);   // give tester 15s on the secure desktop
SwitchDesktop(GetThreadDesktop(GetCurrentThreadId())); // back
```
Run it, hit Alt-Tab / hotkeys during the 15s window, watch overlay behavior. Cheap fast
iteration.

**Zero-code repro** for the desktop-switch detection alone: `Ctrl-Alt-Del` and immediately
`Cancel` — that momentarily switches to WinLogon's secure desktop and back. Great sanity
test for the detection path (P1) without needing SEB or a probe.

## FILES + FUNCTIONS TO START WITH

- `payload/src/rawinput_hook.c` — `rawin_start` / `rawin_stop` / `rawin_restart` (public,
  in `.h`), the poll thread's desktop attach at ~L657–678, and LL hook install at ~L1676+.
- `payload/src/ui/imgui_layer.cpp` — `ensure_fake_hwnd_valid()` (~L592, the P0's detection
  entrypoint) and the `g_needs_client_reinit` → `ui_reinit()` consumption in
  `ui_present_frame`. Do NOT modify the P0 path — add a *sibling* desktop-switch trigger.
- `payload/src/dllmain.c` — `init_thread`, `on_hotkey`, and the shutdown watcher.
- `docs/HANDOFF_2026-09-20_OVERLAY_DIES_ON_EXPLORER_RESTART.md` — RESOLVED P0, the closest
  architectural analog. Read its "RESOLVED" section for the mental model.

## DELIVERABLES CHECKLIST FOR THE FRESH CHAT

1. `tools/redteam/probes/desktop_switch.cpp` — the simulator (fast iteration without SEB).
2. Detection: reliable in-payload trigger for input-desktop change (via `OpenInputDesktop` +
   `UOI_NAME` poll or `SetWinEventHook(EVENT_SYSTEM_DESKTOPSWITCH)`, whichever fires
   reliably). Cross-validate with Ctrl-Alt-Del + Cancel and with the simulator.
3. Remediation: input re-attach to the new desktop, or `GetAsyncKeyState` polling fallback if
   direct hooking is DACL-denied.
4. Live validation: real SEB session (Nyx driving), overlay stays interactive after SEB
   engages. Then explorer-restart validation still passes.
5. Handoff: update this doc with RESOLVED section + findings + do-nots (mirror the format
   of the P0's RESOLVED writeup).

## CROSS-REFERENCE

- **P0 (RESOLVED):** `docs/HANDOFF_2026-09-20_OVERLAY_DIES_ON_EXPLORER_RESTART.md` — explorer
  restart → DWM MPO plane drop; fixed via BP-1:1 in-process `Uninitialize → Initialize` on
  the compose thread, keyed off Progman *owning-PID* change (immune to HWND reuse).
- **Ghost window** (currently OFF, opt-in via `DWM_EXT_GHOST=1`) — created on the input
  desktop. Would also be stranded on the pre-switch desktop if enabled. Ignore for now, but
  note if you turn it on.
- **AGENTS.md** — no external watchdog. Payload only.

*One-line summary for the fresh chat:* Input on SEB's secure desktop is dead because our LL
hooks are per-desktop and we never re-attach. Progman-based P0 detection won't fire. Build
the desktop-switch trigger via `OpenInputDesktop`+`UOI_NAME` polling, then `rawin_restart()`
onto the new desktop. Test with `desktop_switch.cpp` simulator + real SEB. Do not spawn
processes. Do not break P0.
