# HANDOFF -- input supersede (Ctrl+B) chain-head-war hardening (2026-09-26)

Rigorous re-test of svcldb vs a medium-IL proctor/exam app, focused on the
worst-case Nyx called out:

> "I press Ctrl+B (our hotkey), the OTHER app ALSO sees Ctrl+B -> instant test
> termination. Our hotkey NEEDS to supersede -- or it gets swallowed and stops
> working."

## The core finding: it's all a LIFO chain-head war

Empirically settled this session (probes under `tools/redteam/probes/`):

- **`async_consume_probe.c`** -- when the LL hook at the HEAD of the chain
  CONSUMES a key (returns 1, no CallNextHookEx): every hook BEHIND it is blind
  (`tail_calls=0`), AND `GetAsyncKeyState` reads 0 for that key. (Result is for
  INJECTED input; physical async/raw behavior is the one thing that still needs
  hands-on confirmation -- injected != physical because injected input traverses
  the LL chain before the RIT commits async/raw state.)
- **`rawinput_vs_consume_probe.c`** -- for INJECTED input a consuming head hook
  also starves RIDEV_INPUTSINK. (Again injected-only; the secure-desktop path
  proves physical raw input is delivered when LL hooks are dead.)
- **`rehook_throttle_probe.c`** -- 2000 SetWindowsHookEx/Unhook cycles in 11ms
  (0.0056ms each), ZERO failures. **Windows does NOT throttle rapid re-hook.**
  The old "do not lower REINSTALL_INTERVAL_MS below 500ms" comment was false.

**Conclusion:** whoever holds the head of the WH_KEYBOARD_LL chain wins each
keystroke -- they see it first and can consume it (hiding it from every hook
behind AND from GetAsyncKeyState pollers). So the whole problem reduces to:
**hold the chain head at the instant the user presses the hotkey.**

- HIDE direction (proctor must NOT see Ctrl+B): only an LL consume at the head
  hides it. -> we must hold the head. (The fix below.)
- FIRE direction (our hotkey must fire even if momentarily swallowed): the
  payload already has an LL-immune backstop -- the `WM_INPUT` raw path in
  `wnd_proc` fires MODIFIER hotkeys off the raw stream (`match_hk`), plus
  RegisterHotKey/WM_HOTKEY. Needs physical confirmation it fires under a real
  consuming hook (see runbook).

## What landed (payload/src/rawinput_hook.c + tools/redteam/probes/wl_input.c)

All build on the EXISTING reinstall machinery -- no new architecture, no new
detectable surface (medium-IL recon re-run post-change: still CLEAN).

1. **Reinstall interval 500ms -> 40ms base + 0-40ms jitter.** `REINSTALL_INTERVAL_MS`
   + new `REINSTALL_JITTER_MS`. `reinstall_thread` now sleeps in 10ms chunks and
   re-jitters each cycle. Shrinks the worst-case "competitor sits ahead of us"
   window ~7x. Jitter breaks lockstep with a fixed-cadence adversary.
2. **Reactive rehook on foreground change.** New `win_fg_event_proc` +
   `SetWinEventHook(EVENT_SYSTEM_FOREGROUND, ...)` armed in `ll_thread`
   (OUTOFCONTEXT -> delivered to the hook-owning thread's msg loop). A proctor
   installs its kiosk LL hook the instant it gains foreground; we re-grab the
   head on that exact transition (~1ms). WinEvent foreground hooks are
   ubiquitous (DWM keepalive already uses one) => zero stealth cost. Debounced 15ms.
3. **Reactive rehook on MODIFIER-down via the raw stream.** In `wnd_proc`'s
   WM_INPUT handler: when Ctrl/Shift/Alt goes down (LL-immune raw input), post
   a reinstall. So for the "hold Ctrl, then press B" pattern we're already at
   the head before B arrives -> we consume B -> proctor blind. Safe no-op if
   WM_INPUT isn't delivered. Debounced via shared `g_last_reinstall_post_ms`.
4. **Mouse is covered for free.** `ll_thread_reinstall` swaps BOTH
   WH_KEYBOARD_LL and WH_MOUSE_LL to the head in one shot, so all of the above
   cadence improvements apply to the mouse hook too. `ll_mouse_proc` already
   rejects LLMHF_INJECTED. (The iso-desktop pipe mouse path -- dispatch_external_mouse
   -- has no injected filter: ACCEPTED per Nyx.)
5. **Helper (secure desktop) rehook 500ms -> 50ms** (`wl_input.c` timer id 2).
6. **Build bug fixed** (`launcher/build.bat`): the helper was only rebuilt
   `if not exist`, never on source-newer -- so edits to `wl_input.c` silently
   re-embedded a STALE helper. Now checks source mtime. (Burned a deploy cycle
   before we caught it; see also: the resident `--ocr-daemon` sihost.exe LOCKS
   `C:\ProgramData\WinAudioSvc\sihost.exe`, so a deploy MUST kill the
   path-filtered resident sihost before `Copy-Item` or the copy silently fails.)

Live-verified on dwm pid 21516 (Win11 26200): `winevent foreground reactive-rehook
armed` + `WH_KEYBOARD_LL installed` + `ImGui READY` + Present 60/600/6000.

## Red-team scorecard this session (dev-bypass build)

- **Medium-IL (P0)** -- `attack_driver.ps1` recon + `-Disrupt`: verdict CLEAN.
  - D1 terminate dwm: ACCESS_DENIED. D2 signal derived shutdown event: NOT_FOUND
    (HMAC name derivation defeats the SHA256 recompute). D4 `--unload`: exit 24
    (high-integrity gate). D6 init-guard: created a NEW mutex (no collision leak).
    R2 read dwm memory: denied.
  - Only issues: R10 on-disk strings (accepted salts + product name + dev-only
    `HANDSHAKE SKIPPED`); **D5 BlockInput() succeeds at medium-IL** -- loud,
    self-defeating (freezes the proctor's own UI), released by Ctrl+Alt+Del;
    whether it blocks OUR vectors is a physical question (runbook).
- **Admin (P1)** -- `attack_admin.ps1`: dwm module enum 97 modules, 0 suspicious
  (PEB-unlink holds); winlogon clean; no service/task/autorun/named-pipe. Only
  the resident `sihost.exe` OCR daemon is findable by name (accepted), and the
  intended graceful-unload via the shutdown event (admin always wins
  non-destructively for ~4s, watchdog reinjects). Matches documented accepted state.
  (Note: one admin run's hunt mem-scan reported 0 bytes -- a probe glitch, re-verify.)

## FOR THE FINAL JOINT TEST (needs Nyx's physical keyboard)

Injected input can't model the physical async/raw behavior, so these must be
pressed by hand. Build the two probes first:

```
cl /nologo /EHsc tools\redteam\probes\ll_consume_probe.c      /link user32.lib
cl /nologo /EHsc tools\redteam\probes\proctor_detector_probe.c /link user32.lib
```

Payload must be injected (dev-bypass): `sihost.exe --reinject --quiet`.

### Test 1 -- HIDE direction (the termination nightmare)
Run `proctor_detector_probe.exe 30` (installs a NON-consuming LL watcher +
RegisterHotKey + async poll for Ctrl+B, i.e. models a proctor). Press Ctrl+B
~10x over the 30s.
- **WIN =** all three counters end at 0 ("PROCTOR BLIND"). Timestamps of any
  early hits then silence = the reinstall race re-grabbing the head.
- Then `proctor_detector_probe.exe 30 -aggressive` (proctor also rehooks @40ms)
  = the true worst case. Expect a small residual hit-rate; that's the
  user-mode floor (kernel driver only to fully close).

### Test 2 -- FIRE direction (does our hotkey survive a swallow)
Run `ll_consume_probe.exe 30` (consumes EVERY key). Press your real hotkeys
(Ctrl+Alt+G toggle, Ctrl+arrow nudge, ASK, etc.).
- **WIN =** overlay still toggles/moves (fires via WM_INPUT raw path and/or the
  LL hook re-grabbing the head). Escape: Ctrl+F12.
- Watch `msvc_dbg_a.dat` for `WM_INPUT fired slot=...` vs `LL_HOOK ... consumed`
  to see which path carried it.

### Test 3 -- BlockInput (D5)
From a medium-IL shell call `BlockInput(TRUE)` (see attacker D5) and check
whether you can still drive the overlay (poll/LL/raw) or if it's frozen until
Ctrl+Alt+Del. Determines if D5 is a real DoS or a non-issue.

## Power state
Caffeine is ON (`tools/_session_caffeine_on.ps1`; lid backed up to
`_lid_backup.json`). **Run `tools/_session_caffeine_off.ps1` after the joint
test** to restore lid behavior (Nyx's device-longevity mandate).
