# AGENTS.md — svcldb workspace rules

## Scope

This workspace is **`svcldb`** at `C:\Users\<you>\Desktop\svcldb\`.

svcldb is a **standalone project** — a DWM-injected AI overlay for exam bypass. It is NOT part of the hooksdll / CloakGPT Electron project, even though it shares the same author and threat model. Both projects live on the same machine but are separate git repos with different architectures, different code, different builds, different deploy paths.

| | svcldb (THIS PROJECT) | hooksdll (SEPARATE) |
|---|---|---|
| Path | `C:\Users\<you>\Desktop\svcldb` | `C:\Users\<you>\Desktop\hooksdll` |
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
6. `docs/imported/README.md` — INDEX of 25 curated background docs (DWM/WDA techniques, LDB detection intel, Bypassify RE, Windows-port spec). All snapshot-copied from the sibling hooksdll workspace so svcldb is self-contained.

You should ALSO glance at `payload/src/dwm_hooks.c` (1500+ lines, all 9 DWM hooks) and `payload/src/dllmain.c` (init + PEB unlink + hotkey dispatch + KILL_ALL) since those are the two files you'll touch most.

## Cross-project references — when they're OK

Most background context you'll want is already IN this repo under `docs/imported/`. Read `docs/imported/README.md` to see the full index. That covers all Bypassify RE, DWM/WDA/screenshot techniques, LDB detection intel, and the Windows-port spec docs.

If you need something NOT in `docs/imported/`, these hooksdll paths are OK to READ from:

- `C:\Users\<you>\Desktop\hooksdll\lumio\src\autosolver.js` — battle-tested AI prompt template we're copying for our screenshot-solve path
- `C:\Users\<you>\Desktop\hooksdll\lumio\tools\decrypt-logs.js` — reusable log decrypt tool (svcldb uses same format)
- `C:\Users\<you>\Desktop\hooksdll\dwm\dwm_manual_map.exe` — the debug manual-map tool (works for both projects since manual-map is manual-map)
- Bypassify binaries at `C:\Users\<you>\Downloads\launchhere.exe` and `launchhere (1).exe`

DO NOT edit any hooksdll file from an svcldb chat unless the user explicitly asks. If you need to change something over there, tell the user + ask them to open a hooksdll workspace to do it.

## Fast testing launch — DO NOT OVERTHINK (see .cursor/rules/fast-testing-launch.mdc)

"Launch / run / test svcldb", "put it on my screen", "dev bypass then launch" =
a **solved one-shot**. Execute it; do NOT re-recon (no dir listings, no reading
`build.bat`s, no grepping `main.c` flags, no source diffs just to launch). For
"testing", default to **dev bypass + `--reinject`** (reuses `config.dat`'s real
keys; dev-bypass payload skips the expired handshake):

```powershell
$env:SVCLDB_DEV_AUTH="1"
Set-Location payload;  cmd /c "build.bat"
Set-Location ..\launcher; cmd /c "build.bat"
Copy-Item ..\build\launcher\sihost.exe C:\ProgramData\WinAudioSvc\sihost.exe -Force
& C:\ProgramData\WinAudioSvc\sihost.exe --reinject --quiet   # needs admin
```

Already dev-built+deployed? Just `sihost.exe --reinject --quiet`. Verify in ONE
pass: `pwsh -File tools\dlog.ps1 -Path C:\ProgramData\WinAudioSvc\payload.log -Tail 40`
→ look for `HANDSHAKE SKIPPED` + `hooks_install: SUCCESS` + `get_backbuffer_texture: OK`
+ `ImGui READY`. Overlay hard-forces visible on inject (`Ctrl+Alt+G` toggle,
`Ctrl+Alt+R` reset pos). A normal screenshot won't show it (capture-stealth by design).

## Build + deploy commands (svcldb-specific)

```powershell
cd C:\Users\<you>\Desktop\svcldb\payload
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && build.bat'

cd C:\Users\<you>\Desktop\svcldb\launcher
cmd /c 'build.bat'   # embeds payload DLL as RCDATA 101

Copy-Item C:\Users\<you>\Desktop\svcldb\build\launcher\sihost.exe `
          C:\ProgramData\WinAudioSvc\sihost.exe -Force
# NO dwmapiext.dll needed on disk — embedded in sihost.exe

# Inject (fast path for iteration; full arm via --quiet if config.dat missing):
& C:\ProgramData\WinAudioSvc\sihost.exe --reinject   # 46 ms
# or
& C:\ProgramData\WinAudioSvc\sihost.exe --quiet      # 3-15 s cold start
```

## Distribution + packaging pipeline (ship to end users)

This is what you run whenever the user says "update the zip", "package for distribution", "rebuild the installer", or similar. Full doc: `docs/DISTRIBUTION.md`. As of 2026-08-12 the primary shippable is a one-click NSIS Setup.exe; the zip is retained as a manual-install fallback. Recipe:

```powershell
# 1. Build C stack (payload → resolver → launcher) — only if C source changed.
#    Skips cleanly if binaries under build\ are already current.
#    build_all.bat's Step 4 also invokes ui\build.bat which runs pnpm build,
#    which now chains through Steps 1-7 of ui\build-protected.js. Step 7 is
#    a second-pass electron-builder invocation that produces the NSIS
#    Setup.exe via `--win nsis --prepackaged dist/win-unpacked`. So one
#    `build_all.bat` produces the Setup.exe alongside the Electron dir/ output.
cd C:\Users\<you>\Desktop\svcldb
.\build_all.bat

# 2. (Only-UI changes: skip step 1 and just run pnpm build.)
cd C:\Users\<you>\Desktop\svcldb\ui
pnpm build           # ~15–25 s Electron build + ~10 s NSIS second pass = ~35 s

# 3. Package for distribution — drops FOUR artifacts on the CURRENT
#    USER'S REAL Desktop (OneDrive Known-Folder-Move safe via
#    [Environment]::GetFolderPath):
#      CloakGPTWindowsMaxStealth-Setup.exe   ~79 MB   -> primary one-click installer
#      CloakGPTWindowsMaxStealth.zip         ~123 MB  -> manual-install fallback
#      CloakGPT Setup Instructions.md        ~13 KB   -> user-facing guide
#      Launch CloakGPT.lnk                   1.8 KB   -> admin-flagged shortcut
#                                                       (zip-flow only — NSIS
#                                                       Setup.exe writes its own)
cd C:\Users\<you>\Desktop\svcldb
powershell -NoProfile -ExecutionPolicy Bypass -File ui\tools\build-distribution.ps1
```

Key pipeline invariants (from `docs/DISTRIBUTION.md` + `CLAUDE.md` v4.5 entry — DO NOT REGRESS):

- **`ui\tools\build-distribution.ps1`** is the ONE canonical packager. Never hand-zip `dist\win-unpacked\` — you'll skip the shortcut + instructions + `install-cloakgpt.ps1` bundling AND you'll skip the fresh Setup.exe copy, and users will complain the shortcut is missing / the download is stale.
- **NSIS one-click Setup.exe pipeline** (added 2026-08-12 — see `docs/HANDOFF_2026-08-12_NSIS_ONE_CLICK_INSTALLER.md`):
  - `ui\build\installer.nsh` — custom NSIS macros (customInit / customInstall / customUnInstall). Force-tracked via `!ui/build/installer.nsh` in `.gitignore`. Handles: cooperative unload of running payload, path-filtered process kill (sihost.exe COLLIDES with Windows' Shell Infrastructure Host at `C:\Windows\system32\sihost.exe` — MUST filter by executable path or you nuke Explorer's shell coordinator), Defender exclusion add/remove, ProgramData binary mirror on install, silent-upgrade-preserves-user-data via `${IfNot} ${Silent}` gate on the wipe step.
  - `ui\package.json` — has an `nsis` block with `oneClick: true, perMachine: true, artifactName: 'CloakGPTWindowsMaxStealth-Setup.exe', include: 'build/installer.nsh'`. `win.target` array stays as `dir` only; the NSIS second pass overrides via CLI `--win nsis --prepackaged`.
  - `ui\build-protected.js` Step 7 — second-pass `electron-builder --win nsis --prepackaged dist/win-unpacked` that wraps the ALREADY-obfuscated + bytecoded + fuse-flipped + asar-extracted `win-unpacked/` layout as an NSIS installer. Adding `nsis` to the FIRST target array is FORBIDDEN — electron-builder would pack nsis BEFORE afterPack finishes running our fuses + build-protected Step 6 asar extraction, shipping a pre-processed installer that boots into asar integrity errors.
  - Setup.exe outputs to `ui\dist\CloakGPTWindowsMaxStealth-Setup.exe` (~79 MB LZMA vs ~123 MB zip). Installs to `C:\Program Files\svchelper\`, registers in Add/Remove Programs as `CloakGPT (Max Stealth)`, auto-launches via `runAfterFinish: true`, uses NSIS's native shortcut API (no more `.lnk` byte-patching — the admin flag is a first-class NSIS shortcut attribute).
- **`ui\tools\install-cloakgpt.ps1`** is bundled INSIDE the zip at its root. Legacy manual-install path — still shipped because it works on MDM boxes that block Setup.exe elevation AND provides a debug channel that reveals the unpacked layout. It's the end-user's one-click upgrade path: kills stale svchelper, removes old C bins from `C:\ProgramData\WinAudioSvc\` (preserves config.dat + session + api_keys + logs), creates the admin-flagged Desktop shortcut. Users run it with right-click → Run with PowerShell. As of 2026-08-06 (v2) the script:
- **`ui\tools\install-cloakgpt.ps1`** is bundled INSIDE the zip at its root. It's the end-user's one-click upgrade path: kills stale svchelper, removes old C bins from `C:\ProgramData\WinAudioSvc\` (preserves config.dat + session + api_keys + logs), creates the admin-flagged Desktop shortcut. Users run it with right-click → Run with PowerShell. As of 2026-08-06 (v2) the script:
  - **Self-elevates via `Start-Process -Verb RunAs`** at the top — right-click → Run with PowerShell now auto-UAC-prompts and re-executes elevated. The old "must be Administrator" hard-fail path is gone.
  - **Writes shortcut to user Desktop AND falls back to `[Environment]::GetFolderPath('CommonDesktopDirectory')`** (= `C:\Users\Public\Desktop`, visible on every user's merged Desktop view) if user Desktop write fails.
  - **Verifies `.lnk` persistence after Save() + after byte-patch** (250ms + 100ms sleeps) to catch AV/EDR quarantine races. If the file vanishes, reports the specific reason instead of a spurious `[OK]`.
  - **Detects over-the-shoulder-UAC** (elevated as a different SID than the interactive `explorer.exe` owner) and additionally writes to Public Desktop so the actual logged-in user sees the shortcut.
  - **Prints `INSTALL PARTIAL - SHORTCUT MISSING` (yellow)** instead of green `INSTALL COMPLETE` when nothing landed — with a categorized cause list + manual launch path + manual shortcut recipe. See `docs/HANDOFF_2026-08-06_INSTALLER_SHORTCUT_HARDENING.md` for the full failure-mode analysis + reproduction script (`tools/repro_install_shortcut_bug.ps1`).
- **`docs/INSTRUCTIONS.md` is NOT bundled inside the zip anymore** (invariant #41 in CLAUDE.md). The Desktop-standalone `CloakGPT Setup Instructions.md` is enough — bundling it inside the zip clutters the recipient's zip preview.
- The `.lnk` admin-flag is set by binary-patching byte `0x15` with `bor 0x20` (MS-SHLLINK spec §2.1 LinkFlags — invariant #35). Don't try WScript.Shell for the elevation bit; it doesn't support that.
- Both scripts MUST stay ASCII-only (invariant #34). Unicode em-dashes/box-drawing get mojibaked when PowerShell reads without a BOM hint. If you `Read` these scripts and see funny chars, that's the reason.
- The packager runs `Compress-Archive -CompressionLevel Optimal` — zero deps, ships on every Win10+.
- `main.js::ensureCBinariesInstalled` in the Electron app auto-detects upgrades (newer mtime + different size than deployed) and uninjects the running payload BEFORE overwriting `sihost.exe` / `dwmapiext.dll`. This is why in-place zip-over-zip updates work without users needing to manually uninject first.

**When the user asks to "update the zip":** run all 3 steps above. Only skip step 1 (C build) if there are no C source changes; only skip step 2 (Electron build) if there are no JS/UI changes. Step 3 always runs. The freshly-produced zip on Desktop overwrites the previous one atomically.

**Verify success by:**
```powershell
Get-Item C:\Users\<you>\Desktop\CloakGPTWindowsMaxStealth-Setup.exe, `
         C:\Users\<you>\Desktop\CloakGPTWindowsMaxStealth.zip, `
         "C:\Users\<you>\Desktop\Launch CloakGPT.lnk", `
         "C:\Users\<you>\Desktop\CloakGPT Setup Instructions.md" |
    Format-List Name, Length, LastWriteTime
```
All four should have LastWriteTime within the last minute. Sanity ranges: Setup.exe ~75–85 MB, zip ~115–130 MB (varies with Electron version + bundled locale packs; Setup.exe sub-60 MB OR zip sub-90 MB = suspicious, likely missing resources/).

## Encrypted log decryption

Both `payload.log` and `launcher.log` are AES-256-GCM per-line encrypted. The key is derived at build time from `shared/log_key.c` and cached to `.log_master_key.hex` (gitignored).

Current derived key (2026-07-05 v3):
```
5919246238e69eaf9ab65a4e15bf075141af7189fd5071aee7886505d01551c5
```

Decrypt:
```powershell
$hex = "5919246238e69eaf9ab65a4e15bf075141af7189fd5071aee7886505d01551c5"
node C:\Users\<you>\Desktop\hooksdll\lumio\tools\decrypt-logs.js `
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
