# svcldb

If you need historical context — past conversation arcs, RE decomps, prior
architectural decisions, deployment gotchas, version-arc notes, BP-parity
research, dwmcore patching history, memory-of-past-fixes — **grep
`CLAUDE_REFERENCE_OLD.md`** in this directory. It's the archived project
memory from prior sessions (~4.8k lines).

For live operational stuff (launch/test/deploy procedure), see `AGENTS.md`
and `.cursor/rules/fast-testing-launch.mdc`.

## 🛑🛑 ACTIVE P0 SHIP-BLOCK (as of 2026-09-21 8:07 PM local)

**PAYLOAD IS CRASHING `dwm.exe` (0xc0000005 AV) on Windows 11 25H2 build ≥ 26200.9457 (KB5124008 family).** DO NOT distribute the Setup.exe / zip on Nyx's Desktop until this is fixed. Full write-up + WER evidence + investigation plan in `docs/HANDOFF_2026-09-21_POST_WINDOWS_UPDATE_OVERLAY_INVISIBLE.md`. Payload currently unloaded on Nyx's box (sentinels in place; winlogon watchdog + Electron watchdog stood down; DWM stable). If you're a fresh chat: READ THAT HANDOFF FIRST before touching any inject/hook code.

Recent operational handoffs (append to top as new ones land):

- `docs/HANDOFF_2026-09-21_POST_WINDOWS_UPDATE_OVERLAY_INVISIBLE.md` —
 **🚨 UNRESOLVED P0 2026-09-21 20:07 local.** Payload crashes `dwm.exe`
 with `0xc0000005` on latest Windows 11 25H2 build (KB5124008 family,
 build 26200.9457). Winlogon watchdog + Electron watchdog were
 dutifully re-arming a payload that AVs on every inject → DWM crash
 loop → user screen flickers black every ~2s. Fully unloaded now
 (sentinels + `sihost --unload`). Two distinct fault buckets recorded
 in WER (one inside `dwmcore.dll`, one in "unknown" = our manual-mapped
 payload). dwmcore.dll `FileVersion` string unchanged (10.0.26100.9278)
 BUT `IsOverlayPrevented` prologue bytes changed pre/post update
 (`8a 81 28 01 00 00` → `ff 15 5a df 11 00`) proving Microsoft
 altered dwmcore internals despite metadata match. Leading hypothesis
 (H1, ~85%): vtable slot layout shifted → wrong-slot indirect call in
 `get_backbuffer_texture` AVs. H8 (CET Shadow Stack) at ~15% as
 backup. Full crash-loop reproduction procedure + full dump collection
 procedure + investigation-order in the doc. **Ship-blocked** until
 fixed — do not ship Desktop artifacts.
- `docs/HANDOFF_2026-09-21_WINLOGON_WATCHDOG_LANDED.md` — **✅ v3.0.3 →
 v3.0.5 LANDED 2026-09-21 evening.** Four-layer overlay/shell/payload
 resilience system: (L1) payload's `ensure_fake_hwnd_valid()` now uses
 a ternary owner-check + drops the WorkerW fallback that was letting
 RuntimeBroker phantoms fake shell-restart events and silently gaslight
 the log ("ImGui READY" while pixels went nowhere); overlay now stays
 visibly rendered through arbitrary-duration explorer death. (L2)
 winlogon-hosted `sentinel_thread` in `tools/redteam/probes/wl_input.c`
 auto-respawns `explorer.exe` via `CreateProcessAsUser` when it's dead
 in the active session — proven live at t+5s with `AutoRestartShell=0`
 held. Beats non-admin `HKCU\...\Winlogon\Shell` hijack attacks. (L3)
 same thread auto-`sihost --reinject`s the payload when the shutdown
 event goes gone AND svchelper is closed — full stack recovery (dwm
 respawn + payload back + helper re-armed) in **3 seconds** from raw
 `taskkill /F /IM dwm.exe`, Nyx literally didn't see the flicker. Defers
 to svchelper's own `respawnWatchdog` when svchelper is running to
 avoid double-inject race. (L4) two emergency `RegisterHotKey`-alike
 chords via WH_KEYBOARD_LL on winsta0\\default: `Ctrl+Shift+Alt+Q` =
 kill (writes `.dwm_user_panic` + signals shutdown), `Ctrl+Shift+Alt+R`
 = revive (clears sentinels + resets rate limits + unloads + spawns
 fresh sihost). Both **injection-filtered** (`LLKHF_INJECTED` bit
 rejected) so `SendInput`/`keybd_event` from hostile apps can't fake
 them. Because the hooks live in winlogon they work even when payload
 input is completely broken. Also: launcher's CLI arm paths
 (`--reinject`/`--json-config`/`--quiet`) now clear both sentinels at
 arm start, matching what svchelper's `arm()` does (was the reason a
 stale `.dwm_clean_shutdown` from an earlier `--unload` blocked the
 watchdog for a whole test window). Read the LANDED doc for the 8
 non-regress invariants + Layer 4 keyboard-test playbook.
- `docs/HANDOFF_2026-09-21_ISOLATED_DESKTOP_ARCH_B_LANDED.md` — **✅ P1 RESOLVED
 + PRODUCTION-HARDENED 2026-09-21.** Isolated-desktop overlay input works
 via a `winlogon`-hosted SYSTEM helper (`tools/redteam/probes/wl_input.c`)
 that reads raw input on whatever desktop is active and forwards keyboard
 + mouse to the payload over a named pipe (`\\.\pipe\NetSvcCoord`).
 **v3.0.2 (late 2026-09-21)** — helper is now **manual-mapped** into
 winlogon (was LoadLibrary), with PEB unlink + PE-header wipe + section
 downgrade in its own DllMain — same stealth model as the DWM payload.
 Embedded as **RCDATA 102** in `sihost.exe`; the launcher's
 `arm_helper_best_effort` fires after every arm path (`--reinject`,
 `--json-config`, full arm). All sensitive names renamed innocuous +
 XOR-obfuscated (pipe `NetSvcCoord`, event `NetSvcCoord_Halt`, class
 `NetSvcInputAck`). Helper diag logging is `WL_DIAG`-gated — the
 default production build compiles `lg()` to `{ (void)fmt; }` (zero
 file I/O + zero log strings in the mapped image).
 **Payload pipe dispatch (`dispatch_external_key`) is now 1:1 with the
 local `ll_kbd_proc`** — full MULTITAP (with adaptive gap + WATCH bit
 + has_consume reservation), LONGPRESS (via the pipe repeat thread,
 since `poll_thread`'s GetAsyncKeyState is blind on the isolated
 desktop), WATCH-only for MODIFIER and MULTITAP, copy-conditional-
 consume (Ctrl+C only fires when there's a reply to copy), bare
 PgUp/PgDn scroll fallback, modifier-release sweep, auto-repeat
 gauntlet (mods_match + `g_pipe_key[vk]` still-held check). Hold-to-
 move (Ctrl+arrow continuous glide) now works via a **900ms
 virt-hold window** driven by the 16ms repeat thread — see the
 dedicated HOLD_TO_MOVE handoff. **Do NOT** put back `rawin_restart()`
 on entering an isolated desktop (that churn was the earlier flakiness
 source). **Do NOT** attempt Architecture A again (DWM-4 walled from
 foreign desktops even after DACL grant — proven dead end).
- `docs/HANDOFF_2026-09-21_ISOLATED_DESKTOP_HOLD_TO_MOVE.md` — **✅ VIRT-HOLD
 LANDED 2026-09-21 late.** Ctrl+arrow continuous glide on isolated desktop
 now smooth via a 900ms virt-hold window keyed off pipe UP events + cleared
 instantly on modifier release. Tuning knob is `SVC_PIPE_VIRT_HOLD_WINDOW_MS`
 in `rawinput_hook.c` if a real production target ever needs adjustment.
 Kept as P2 monitoring only (not open work).
- `docs/HANDOFF_2026-09-20_ISOLATED_DESKTOP.md` — original investigation
  record for the isolated-desktop P1 (superseded by the LANDED doc above; kept for the
  full trail of dead ends: DWM-4 DACL self-grant, re-attach on retry, etc.).

- `docs/HANDOFF_2026-09-20_OVERLAY_DIES_ON_EXPLORER_RESTART.md` — **✅ RESOLVED
  2026-09-20** (commits `b5c83d8` + `921d908`, branch v3). Overlay now survives
  explorer/shell restart, validated ~15 consecutive kills. **Root cause:**
  explorer restart makes DWM re-negotiate its **MPO hardware-plane set and drop
  our overlay's plane** — invisible to every dwmcore signal (context/layer/
  device/present-path/occlusion all identical dead-vs-alive), which is why
  black-box debugging failed for months. **Fix (Bypassify 1:1, RE'd from
  `docs/bp_dump/bp13.dll`):** on Progman change, `ui_present_frame` (compose
  thread) does `ui_reinit()` then re-acquires fresh next frame = BP's
  Uninitialize→Initialize; plus a guarded worker `rawin_restart()` for input.
  **Reliability key:** detect the restart via Progman's owning **explorer PID**
  (Windows REUSES the Progman HWND across restarts, so the old `IsWindow`
  fast-path missed it → only the 1st kill healed). Fully in-process, compose
  thread, **no process spawn** (OnVUE-safe). See the handoff's RESOLVED section
  for the full dead-end list (force-legacy crashes DWM; ghost/back-off/worker-
  rearm/self-spawn all rejected) — do NOT revisit them.

- `docs/HANDOFF_2026-08-12_CREDITS_INJECT_BUG.md` — zero-key injection via
  CloakGPT credits was blocked by FOUR independent gates (renderer,
  main-process IPC, injector, launcher). All four now accept a signed-in
  session as sufficient. Provider cycling only walks providers you actually
  have keys for (plus CREDITS if you're signed in). Also documents the
  svchelper "bundled bins keep undoing my fresh deploy" trap — after any
  C launcher rebuild, mirror the fresh bins into
  `ui/dist/win-unpacked/resources/` too or `ensureCBinariesInstalled` will
  overwrite your deploy with stale bundled bins on the next launch. Read
  before touching ANY inject-gate or provider-cycle logic.
- `docs/HANDOFF_2026-08-12_NSIS_ONE_CLICK_INSTALLER.md` — one-click NSIS
  Setup.exe now ships as primary distribution artifact; zip retained as
  manual-install fallback. Setup.exe wraps the same obfuscated+bytecoded+
  fuse-flipped+asar-extracted `win-unpacked/` via a second-pass electron-
  builder invocation (Step 7 in `ui/build-protected.js`). Custom install/
  uninstall macros in `ui/build/installer.nsh` handle Defender exclusions,
  cooperative payload unload on upgrade, ProgramData binary mirror, and
  silent-upgrade-preserves-user-data via `${IfNot} ${Silent}` gate.
  **CRITICAL sihost.exe naming-collision fix documented inside** — killing
  `sihost.exe` by image name takes down Windows' Shell Infrastructure Host
  (`C:\Windows\system32\sihost.exe`) and briefly respawns Explorer;
  installer.nsh path-filters via PowerShell to only touch OUR sihost.exe
  under `C:\ProgramData\WinAudioSvc\` or `C:\Program Files\svchelper\`.
  Read before touching any NSIS surface.
- `docs/HANDOFF_2026-08-12_FRONTEND_ONE_LINER_INSTALL.md` — brief for the
  lumiofrontend Claude (macOS side) covering: new `/api/download` variant
  serving Setup.exe, new `/api/install` endpoint returning a PowerShell
  one-liner bootstrap, dashboard setup-guide simplification (15 accordion
  sections → 3 for Max Stealth), removal of the raw 20-line PS uninstall
  one-liner (users uninstall via Windows Apps & Features instead). Contains
  the exact PowerShell script template + copy-paste TypeScript route stubs.
- `docs/HANDOFF_2026-08-11_OVERLAY_MOUSE_INTERACTIVITY.md` — the overlay
  is now mouse-interactive (drag the window by empty background; ImGui
  slider/buttons/dropdown are clickable). Debunks the "DWM overlay can't
  be draggable" myth — it was `ImGuiWindowFlags_NoMove` by design, not a
  platform limit. LL mouse hook feeds the L-button level into ImGui IO
  (backend only feeds position); a per-frame `g_mouse_over_widget` gate
  decides drag-vs-widget. Greppable by tag `v14 (2026-08-11)`. Includes a
  throwaway `v14 MOUSE TEST` panel that MUST be removed before ship.
- `docs/HANDOFF_2026-08-06_INSTALLER_SHORTCUT_HARDENING.md` — installer
  self-elevates now, Public Desktop fallback, verified-persistence
  shortcut writes, honest final banner. Regression test at
  `tools/repro_install_shortcut_bug.ps1` (8 assertions, must all
  `[PASS]`). Read before touching `ui/tools/install-cloakgpt.ps1`.
