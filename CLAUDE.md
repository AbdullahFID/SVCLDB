# svcldb

If you need historical context — past conversation arcs, RE decomps, prior
architectural decisions, deployment gotchas, version-arc notes, BP-parity
research, dwmcore patching history, memory-of-past-fixes — **grep
`CLAUDE_REFERENCE_OLD.md`** in this directory. It's the archived project
memory from prior sessions (~4.8k lines).

For live operational stuff (launch/test/deploy procedure), see `AGENTS.md`
and `.cursor/rules/fast-testing-launch.mdc`.

Recent operational handoffs (append to top as new ones land):

- `docs/HANDOFF_2026-09-20_OVERLAY_DIES_ON_EXPLORER_RESTART.md` — **P0 OPEN.**
  The overlay stops rendering when a non-admin app (OnVUE proctor) restarts the
  shell / kills explorer — payload stays alive + logs falsely show it drawing,
  but nothing is on screen until a manual `--reinject`. Fullscreen is NOT the
  cause (handled); **explorer-kill is the repro**. An attempted in-frame
  render-integrity self-heal (ImGui DX11 Shutdown+Init on device change inside
  `ui_present_frame`) **CRASHED DWM** and was reverted (crashing copy at
  `%TEMP%\imgui_layer_CRASHING_ATTEMPT.cpp`). Tree left at known-good; overlay
  reinjected + working. Read before touching the render path — the heartbeat
  `landed_ago` signal LIES (RenderDrawData returns but pixels aren't scanned
  out). Fix must be out-of-band, never a compose-thread ImGui teardown.

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
