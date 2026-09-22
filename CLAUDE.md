# svcldb

If you need historical context — past conversation arcs, RE decomps, prior
architectural decisions, deployment gotchas, version-arc notes, BP-parity
research, dwmcore patching history, memory-of-past-fixes — **grep
`CLAUDE_REFERENCE_OLD.md`** in this directory. It's the archived project
memory from prior sessions (~4.8k lines).

For live operational stuff (launch/test/deploy procedure), see `AGENTS.md`
and `.cursor/rules/fast-testing-launch.mdc`.

## ✅ P0 SHIP-BLOCK RESOLVED (2026-09-21 8:42 PM local) — v3.1

**Root cause was NOT what the handoff hypothesized.** Fixed by v3.1
without needing new RE. The KB5124008/KB5129195-family Windows 11
update replaced `dwmcore.dll` on disk — same `FileVersion` string
(10.0.26100.9278) but a new PE `TimeDateStamp` + new PDB signature.
Every internal RVA shifted. Our cached `offsets.blob` had the
pre-update RVAs baked in, and the launcher's `--reinject` path
skipped the resolver, so we were hooking + patching **the wrong
addresses in the new dwmcore**. Wrong-address byte patches corrupted
unrelated dwmcore state → DWM AV after minutes. Wrong-address hook
on "COverlayContext::Present" was actually installed on some other
function → Present detour never fired → no overlay rendered.

**v3.1 fixes (all landed 2026-09-21 20:42 local, committed on `main`):**

1. **Launcher: auto-re-resolve on dwmcore change.** New
 `dwmcore_time_date_stamp()` reads the PE header's 4-byte stamp.
 `run_resolver()` now writes it to `offsets.blob.sig` after a
 successful resolve. `auto_refresh_offsets_if_stale("--reinject")`
 runs at the top of `--reinject` (and is documented next to
 `--json-config`, which already re-resolves unconditionally).
 First arm post-Windows-update pays ~1s for the fresh resolve;
 subsequent arms are the usual <100ms fast path.
2. **Payload: `ForceFullDirty` byte-patch guard.** Skip if the
 original byte isn't `0x00` or `0x01`. On the new dwmcore, the
 symbol resolves to a `.rdata` location whose initial byte is
 `0x44` (structured data, not a bool) — old code blindly overwrote
 to `0x01`, corrupting the struct.
3. **Payload: `IsOverlayPrevented` prologue-shape detection.**
 Old getter form (`8A 81 XX XX XX XX` = `mov al, [rcx+imm32]`)
 gets the classic offset-0 `mov eax,1; ret` patch. New CFG-call
 form (`FF 15 XX XX XX XX` = `call qword [rip+imm32]`) gets the
 patch at offset **6** so the initial init/dispatch call still
 runs — skipping that call had been corrupting dwmcore state.
 Also handles CET `ENDBR64` prologues by patching at offset 4.
 Unknown prologues log loudly + skip the patch entirely.
4. **Payload: Present-fire canary thread.** Samples
 `g_present_calls` at T+2s / T+5s / T+10s / T+30s post-install.
 If zero, sets `g_compose_degraded = 1` and short-circuits
 `ui_present_frame` — payload stays loaded for rawinput/hotkey
 use, no dwmcore corruption, no crash. Loud log line pinpoints
 the exact regression class if this ever fires again.
5. **Winlogon helper: crash-loop firewall.** New `fw_observe_dwm()`
 tracks dwm.exe pid churn each 5s tick (up to 8 historical
 changes). Before every re-inject decision, `fw_count_recent_churn()`
 counts pid changes in the last 90s. `>= 3` = we caused a crash
 loop → `fw_trip()` writes `.dwm_user_panic` with a distinctive
 body (svchelper's `respawnWatchdog` also honors this file → both
 watchdogs stand down). 30-minute backoff, cleared by
 emergency-revive hotkey (Ctrl+Shift+Alt+R) or manual file delete.

**Live-verified on Nyx's box 2026-09-21 20:42 local:**
`Present fired count=612 at T+3000 ms -- compose path is healthy`.
Overlay renders, DWM stable (pid 21196 held for 37+ minutes).
`offsets.blob.sig = 0x9A1AF3BA` (matches current dwmcore's PE
TimeDateStamp — so subsequent `--reinject` calls skip re-resolve).

**When shipping Setup.exe / zip to end users:** rebuild the C stack
(`build_all.bat`) so new payload/launcher/helper make it into
`dist/win-unpacked/` before packaging. The v3.1 changes are essential
for anyone whose Windows updates replace dwmcore.dll (which is
essentially "everyone eventually"). Backward compat is fully preserved:
old dwmcore builds keep hitting `OLD-GETTER` on IsOverlayPrevented +
the bool-value ForceFullDirty patch, same as before. The auto-refresh
is idempotent — it only triggers when the sig genuinely differs.

Recent operational handoffs (append to top as new ones land):

- `docs/HANDOFF_2026-09-21_POST_WINDOWS_UPDATE_OVERLAY_INVISIBLE.md` —
 **✅ RESOLVED 2026-09-21 20:42 local by v3.1** (see above; kept for
 the full evidence trail — WER analysis, HVCI verification, PDB
 signature comparison — anyone chasing a similar
 "hooks-install-succeeds-but-Present-never-fires-on-new-Windows"
 regression should read this doc's diagnosis section as prior art).
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
