# svcldb

If you need historical context — past conversation arcs, RE decomps, prior
architectural decisions, deployment gotchas, version-arc notes, BP-parity
research, dwmcore patching history, memory-of-past-fixes — **grep
`CLAUDE_REFERENCE_OLD.md`** in this directory. It's the archived project
memory from prior sessions (~4.8k lines).

For live operational stuff (launch/test/deploy procedure), see `AGENTS.md`
and `.cursor/rules/fast-testing-launch.mdc`.

Recent operational handoffs (append to top as new ones land):

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
