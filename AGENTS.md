# AGENTS.md — svcldb workspace rules

## Scope

This workspace is **`svcldb`** at `C:\Users\abdul\Desktop\svcldb\`.

svcldb is a **standalone project** — a DWM-injected AI overlay for exam bypass. It is NOT part of the hooksdll / CloakGPT Electron project, even though it shares the same author and threat model. Both projects live on the same machine but are separate git repos with different architectures, different code, different builds, different deploy paths.

| | svcldb (THIS PROJECT) | hooksdll (SEPARATE) |
|---|---|---|
| Path | `C:\Users\abdul\Desktop\svcldb` | `C:\Users\abdul\Desktop\hooksdll` |
| Language / runtime | Pure C/C++ payload injected into DWM | Electron app + native hooks DLL |
| Deploy dir | `C:\ProgramData\WinAudioSvc` | `C:\ProgramData\CloakGPT` |
| Git remote | `github.com/AbdullahDaGoat/svcldb` | `github.com/AbdullahDaGoat/hooksdll` |
| Launcher | `sihost.exe` (830 KB, embeds payload as RCDATA) | `svchost.exe` (Electron) |
| Payload | `dwmapiext.dll` (embedded in sihost.exe — zero disk footprint) | `mscorsvc.dll` (LDB DLL) + `dwm_payload.dll` (DWM) |
| Entry point (payload) | `dllmain.c` inside `dwm.exe` | main.js inside Electron |

**When working in this workspace, focus on svcldb code. Reference hooksdll ONLY when explicitly asked to compare or port something over. Never modify hooksdll files unless the user explicitly requests it.**

## Read-first checklist

Before doing ANY substantive work in this repo, read (in order):

1. `CLAUDE.md` — full project memory, 15 architectural invariants, every bug we've fixed, every trap we've hit. This is the source of truth.
2. `docs/HANDOFF_STEALTH_NIGHT_2026-07-05.md` — overnight stealth pass (PEB unlink, PE wipe, hook integrity monitor, anti-debug, encrypted diag)
3. `docs/HANDOFF_UX_POLISH_2026-07-05.md` — 23-slot hotkey manifest + chat input spec + persistence format
4. `docs/HANDOFF_NEXT_CHAT_BYPASSIFY_PARITY_AND_AI.md` — the two-track mission most recent chats have been working on
5. `HANDOFF_SVCLDB_2026-07-04.md` and `HANDOFF_SVCLDB_2026-07-05_HOTKEYS_AND_WAKE.md` — earlier bring-up notes

You should ALSO glance at `payload/src/dwm_hooks.c` (1500+ lines, all 9 DWM hooks) and `payload/src/dllmain.c` (init + PEB unlink + hotkey dispatch + KILL_ALL) since those are the two files you'll touch most.

## Cross-project references — when they're OK

You MAY reference these hooksdll files when they're genuinely useful:

- `C:\Users\abdul\Desktop\hooksdll\tools\re_v588\bypassify_v1.3.0_gap_analysis.md` — the definitive Bypassify RE (32 KB, invaluable)
- `C:\Users\abdul\Desktop\hooksdll\lumio\src\autosolver.js` — battle-tested AI prompt template we're copying for our screenshot-solve path
- `C:\Users\abdul\Desktop\hooksdll\lumio\tools\decrypt-logs.js` — reusable log decrypt tool (svcldb uses same format)
- `C:\Users\abdul\Desktop\hooksdll\dwm\dwm_manual_map.exe` — the debug manual-map tool (works for both projects since manual-map is manual-map)
- Bypassify binaries at `C:\Users\abdul\Downloads\launchhere.exe` and `launchhere (1).exe`

DO NOT edit any hooksdll file from an svcldb chat unless the user explicitly asks. If you need to change something over there, tell the user + ask them to open a hooksdll workspace to do it.

## Build + deploy commands (svcldb-specific)

```powershell
cd C:\Users\abdul\Desktop\svcldb\payload
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && build.bat'

cd C:\Users\abdul\Desktop\svcldb\launcher
cmd /c 'build.bat'   # embeds payload DLL as RCDATA 101

Copy-Item C:\Users\abdul\Desktop\svcldb\build\launcher\sihost.exe `
          C:\ProgramData\WinAudioSvc\sihost.exe -Force
# NO dwmapiext.dll needed on disk — embedded in sihost.exe

# Inject (fast path for iteration; full arm via --quiet if config.dat missing):
& C:\ProgramData\WinAudioSvc\sihost.exe --reinject   # 46 ms
# or
& C:\ProgramData\WinAudioSvc\sihost.exe --quiet      # 3-15 s cold start
```

## Encrypted log decryption

Both `payload.log` and `launcher.log` are AES-256-GCM per-line encrypted. The key is derived at build time from `shared/log_key.c` and cached to `.log_master_key.hex` (gitignored).

Current derived key (2026-07-05 v3):
```
5919246238e69eaf9ab65a4e15bf075141af7189fd5071aee7886505d01551c5
```

Decrypt:
```powershell
$hex = "5919246238e69eaf9ab65a4e15bf075141af7189fd5071aee7886505d01551c5"
node C:\Users\abdul\Desktop\hooksdll\lumio\tools\decrypt-logs.js `
  C:\ProgramData\WinAudioSvc\payload.log --key $hex
```

If the key ever rotates (edit `shared/log_key.c`), recompute via the derivation `SHA256((MATERIAL_A XOR MATERIAL_B) || SALT)` — helper block in `CLAUDE.md`.

## Never regress

Every invariant in `CLAUDE.md` is load-bearing. In particular:

- `/GS-` and `/guard:cf-` are MANDATORY for payload — manual-map skips CRT init so security cookies are uninitialized and CFG bitmap is empty. Removing either → silent __fastfail inside DWM.
- `/OPT:ICF` and `/GUARD:CF` are FORBIDDEN on launcher — they break the manual-map shellcode inside DWM.
- `/MERGE:.pdata=.text` is FORBIDDEN on both — kills x64 SEH silently.
- Hotkey priority tiers (50 / 80 / 250 ms) are tuned — do not flatten.
- Ghost window is DEFAULT-ON — do not make it opt-in again without a very good reason. Regressions are documented in `CLAUDE.md`.

## Subagent policy

Any `Task` tool call MUST pass `model: "claude-4.6-sonnet-medium-thinking"`. Full rule in `.cursor/rules/subagent-model-sonnet.mdc`. No Opus, no GPT, no Composer.

## Read-full-codebase means literally everything

If the user says "read full codebase" — read every source file, every doc, every handoff, and grep the hooksdll Claude / Cursor transcript stores for anything relevant. See `.cursor/rules/read-full-codebase.mdc`.
