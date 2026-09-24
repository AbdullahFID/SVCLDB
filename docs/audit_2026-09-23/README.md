# Multi-subagent audit — 2026-09-23 late night

Seven opus-4.7-thinking-xhigh subagents fanned out across the whole codebase.
Reports below are the FINAL deliverables each returned before Cursor's billing
system falsely tripped on them (transcripts kept growing in background even
after the error notifications).

## Reports

| Report | Scope | Verdict | Findings |
|---|---|---|---|
| A_DWM_HOOKS_FINAL.md | DWM compositor hooks, Present detour, RTV, resolver | MINOR-FIXES | P0:0 P1:6 P2:5 P3:4 |
| B_INPUT_WINLOGON_FINAL.md | LL hooks, hotkeys, winlogon helper, iso desktop | P0-BLOCKING | P0:2 P1:3 P2:6 P3:3 |
| C_AUTH_BACKEND_FINAL.md | OAuth, TOK2, sub_check, HWID, Cloudflare workers | MINOR-FIXES | P0:0 P1:4 P2:5 P3:4 |
| D_AI_AUTOSOLVER_FINAL.md | AI providers, autosolver, capture, chat streaming | P0 (OCR pipe) | P0:1 P1:4 P2:5 P3:3 |
| E_UI_NOTES_FINAL.md | ImGui rendering, notes editor, human typer, clip ring | P0 (threads) | P0:1 P1:4 P2:4 P3:4 |
| F_INSTALLER_FINAL.md | NSIS installer, PowerShell installer, Electron UI | SHIP-SAFE | P0:0 P1:3 P2:6 P3:3 |
| G_STEALTH_FINAL.md | String encryption, PEB, anti-debug, DACLs, RCDATA | P0-BLOCKING | P0:3 P1:7 P2:3 P3:1 |

## What landed this session

See git log `3f46d9d` (Ctrl+B), `90822f7` (audit batch 1), `b36e8cc`
(audit batch 2), and subsequent commits for what's been fixed. Handoff
docs:

- `docs/HANDOFF_2026-09-23_CTRLB_HARDENING.md`
- `docs/HANDOFF_2026-09-23_MULTI_SUBAGENT_AUDIT.md`

## What's still deferred (as of session end)

Grep the reports for `P0` and `P1` findings and cross-reference against
`git log --grep='v-audit-hardening'` to see what has NOT been landed yet.
Top-priority open items:

- **G-P0-1**: Product name / AI URL / model catalog leaks in ai_provider.c
- **G-P0-2**: SVC_INSTALL_DIR macro expands to literal at ~30 sites
- **G-P0-3**: Cleartext canary alarm reveals compositor hook name
- **C-P1-2**: OAuth flow missing `state` parameter (CSRF/DoS)
- **C-P1-3**: cfg_persist DACL DWM-N-only narrowing
- **F-P1-3**: respawnWatchdog lacks crash-count back-off
