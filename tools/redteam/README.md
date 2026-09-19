# svcldb v3 red-team harness

Co-evolution rig for hardening svcldb against a hostile, **non-admin** proctor/exam app.

## Model

- **App A — the hider.** svcldb's payload inside `dwm.exe`. It is hidden **generically**;
  it never references, detects, or special-cases the hunter. If it's only invisible to
  *this* hunter it's worthless, so the rule is: hidden without the hunter's cooperation.
- **App B — the hunter.** `../../../hooksdll/proctor-sim` (Bluebook + ACT Gateway model),
  extended with an svcldb-hunting module. Runs at **medium integrity** (non-admin) to be
  faithful. It is a *measuring instrument*, not something A reacts to.
- **Probes** (`probes/`) — small standalone observers that each test ONE detection vector
  without running the full hunter and without A knowing they exist. They double as the
  regression tests for each hardening pass.
- **Scorecard** — every run writes JSON to `runtime/` (gitignored): what B/probe caught,
  which vector, verdict `CLEAN` vs `DETECTED`.

## Win condition

For every vector, A is either (1) **gone** (probe returns `NOT_FOUND` / nothing), or
(2) **camouflaged** — its artifact is statistically indistinguishable from legitimate
DWM/Windows objects, so flagging it means flagging everything.

## Safety (device-lock)

The stock proctor-sim can't brick anything (only an escapable kiosk window). When the
hunter's enforcement is made **real** (real LL-hook swallow / ClipCursor / BlockInput),
these guarantees apply *before* any such run:

1. **Auto-release watchdog** — the hunter hard-exits after a bounded wall-clock time no
   matter what; a real LL hook can never outlive it.
2. **Orchestrator kill** — the harness always kills the hunter by PID. Programmatic
   `taskkill` is unaffected by input-blocking, so this path always works.
3. **Escape hotkey** — the hunter whitelists one combo it will never swallow, wired
   straight to its own exit.
4. **Reboot** — last resort; nothing here survives a reboot.

## Probes

| Probe | Vector | Safe? |
|---|---|---|
| `probes/probe_named_objects.ps1` | named-pipe enum + event/mutex/section existence leak (ACCESS_DENIED vs NOT_FOUND) | read-only |

Run one:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tools\redteam\probes\probe_named_objects.ps1 `
  -Json tools\redteam\runtime\named_objects.json
```

Exit code `0` = CLEAN, `7` = DETECTED (so the orchestrator can gate on it).

Existence-vs-access classification is integrity-sensitive: run probes **de-elevated**
(medium IL) to model the real hunter; from an elevated shell, admin-DACL objects
misreport as accessible.
