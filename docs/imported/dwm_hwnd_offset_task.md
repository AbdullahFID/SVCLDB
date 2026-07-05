---
name: dwm-hwnd-offset-task
description: DWM self-calibrating HWND offset discovery — next task after V5.7 fix. Handoff file written for separate Claude session.
metadata: 
  node_type: memory
  type: project
  originSessionId: 8bc6e533-ea0a-4f20-a52b-458a371720f7
---

## Status (2026-05-28)

V5.7 fixed the DWM hiding layer (was dead due to ASCII vs binary HWND format mismatch —
`g_overlayHwnd` permanently NULL, 0/1000 RenderContent matches). Now live: 129/1000 matches.

## Remaining task

`HWND_OFFSET_IN_WINDOWNODE = 0x320` is still hardcoded in `dwm/dwm_payload.c`.
`ValidateStructOffsets` detects a broken offset but does not fix it — smoke alarm
without sprinkler. If a Windows build shifts the `CWindowNode` HWND field, the
DWM hiding layer silently dies again.

**Task**: turn `ValidateStructOffsets` into a discoverer — sweep offsets `0x2F0`–`0x400`
at 8-byte steps, count `IsWindow`-valid hits per candidate, lock winner into runtime
global `g_hwndOffset`, have all detours read that instead of the `#define`.
Same structural-invariant approach as `FindInheritedFromOffset` in `driver/cloakgpt_driver.c:4227`.

## Handoff file
`HANDOFF_DWM_HWND_OFFSET_DYNAMIC.md` in repo root — complete spec for next session.

**Why:** If undone, a future Windows update silently breaks compositor-level hiding
with no user-visible signal. WDA carries the full load alone again.

**How to apply:** Next session working on DWM payload: read handoff file first.
Abdullah approves final diff before commit.

[[bypassify_dwm_pdb_technique]] [[v51_dwm_capture_state]]
