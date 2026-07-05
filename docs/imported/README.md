# docs/imported — background context pulled from sibling projects

These files were CURATED from the hooksdll workspace's Claude memory + the user's Downloads dir and copied here so svcldb is self-contained. Do NOT edit them in place — they're snapshots. If you need to change intent, capture your findings in a new file at `docs/` root.

## Category 1 — DWM / WDA / Screenshot pipeline (foundational)

The techniques svcldb builds on. Nine files:

| File | What it covers |
|---|---|
| `bypassify_dwm_pdb_technique.md` | Bypassify's use of dbghelp+symsrv to resolve dwmcore RVAs dynamically. We use the exact same approach in `resolver/` (aka `dllhost32.exe`). |
| `dwm_hwnd_offset_task.md` + `_v57_resolution.md` | The `CWindowNode+0x??` HWND-offset discovery. We resolve this dynamically now via `CWindowNode::GetHwnd` body parse — hardcoded 0x320 is only fallback. |
| `dwm_zorder_research.md` | Z-order behavior notes — relevant to our ghost window's `HWND_TOPMOST` re-assert (in `keepalive_thread`, every 500 ms). |
| `screenshot_wda_freeze_fix.md` | `WDA_EXCLUDEFROMCAPTURE` gotchas + freeze fix. Our ghost uses this affinity. |
| `screenshot_pipeline_v51.md` + `v51_dwm_capture_state.md` | The DWM-side ID3D11Texture2D → BGRA → PNG capture pipeline. Our `ui_capture_screen_png` + `try_perform_capture` are direct ports. |
| `wda_bypass_architecture.md` | High-level architecture of WDA capture-affinity bypass. |
| `project_architecture.md` | Higher-level architecture doc (hooksdll's V5.x era, but the "why DWM" reasoning is universal). |

## Category 2 — LDB detection + evasion (target intel)

What we're actually bypassing. Six files:

| File | What it covers |
|---|---|
| `ldb_full_re_detection_pipeline.md` | LDB v2.1.5's detection graph — module scans, WDA queries, DirectComposition probes, etc. |
| `ldb_forced_lockdown_completeness.md` | Every state LDB checks when arming lockdown — what we must NOT trip. |
| `lockdownre_1to1_confirmed.md` | Fields where LDB is confirmed 1:1 across our test surface. Nice for baseline. |
| `testing_strategy_lockdown_evasion.md` | Recommended smoke-test order. |
| `ldb_cdp_remote_debug_blocked.md` | LDB's `--disable-features=RemoteDebugging` posture — relevant if we ever want to CDP into LDB's own CEF. |
| `ldb_rbinary_resource_deferred_decrypt.md` | PACE / mfort deferred-decrypt behavior in LDB's `.mfrt` section. |

## Category 3 — Bypassify RE (the standard we're benching against)

Four docs + four helper scripts:

| File | What it covers |
|---|---|
| `bypassify_v1.3.0_gap_analysis.md` (32 KB — THE DEFINITIVE DOC) | Exhaustive Bypassify v1.3.0 vs CloakGPT/svcldb gap table. Read this before ANY parity claim. |
| `bypassify_v13_HARD_VERDICT.md` | First-pass verdict — Bypassify does no LDB-side sauce that we don't do, their architecture avoidance IS the trick. |
| `bypassify_v13_DELTA_ONLY.md` | Pure v1.2.3 → v1.3.0 diff of Bypassify itself (interesting for tracking their evolution). |
| `bypassify_v13_FINAL_TODO.md` | The 4 items adopted from Bypassify into svcldb after the RE (leftover-payload heal, MS-blend class name, clean-shutdown sentinel, raw-input layer). |
| `bypassify_re_scripts/` | Python helper scripts (`bypassify_triage.py`, `_extract.py`, `_strings.py`, `_dll_id.py`) — use these to re-run Bypassify RE against future versions. |

## Category 4 — Windows-port spec (blueprint sources)

Two long-form design docs that shaped svcldb's early architecture:

| File | What it covers |
|---|---|
| `ldb_ban_bypass_and_force_nav_windows_port_spec.md` (37 KB) | The ban-verdict rewrite + force-nav design derived from the macOS reference. |
| `ldb_macos_full_blueprint_for_windows_port.md` (98 KB) | Full macOS LDB bypass blueprint annotated for Windows port. Contains the verdict-grammar rules, cookie handling, and heartbeat/IPC rules that any windows LDB solver must respect. |

## What NOT included

- Bluebook/ACT/Examplify/OnVUE stuff — these are hooksdll-only targets, svcldb is LDB-only
- Electron-specific fixes (teal bar, BSOD PPID spoof, watchdog no-detached-spawn) — hooksdll architecture, doesn't apply here
- CDP / renderer bridge stuff — hooksdll uses CDP into its own Electron; svcldb doesn't have Electron
- Deploy artifacts / feedback loops from hooksdll — different deploy dir + different binaries

## Provenance

Copied 2026-07-05 from:
- `C:\Users\abdul\.claude\projects\C--Users-abdul-Desktop-hooksdll\memory\`
- `C:\Users\abdul\Desktop\hooksdll\tools\re_v588\`
- `C:\Users\abdul\Downloads\`

If you need to re-import newer versions of any of these, look in the same source paths. Provenance is the source of truth; these files are read-only snapshots.
