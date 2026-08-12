# HANDOFF: NSIS one-click Setup.exe (2026-08-12)

Cursor session, requested by Larpbase.

## Question that started it

> "wanna consolidate this to smth easier ... user runs a curl or powershell
> 5.1 friendly command that downloads the app and puts it in zip if somehow
> the exe could have all the files bundled then u click the exe and it just
> one shot click to open it begins auto installing installcloakgpt then it
> opens up u login etc but its more user friendly"

## Short answer

Added an NSIS one-click installer target to the electron-builder pipeline.
Users now download ONE file (`CloakGPTWindowsMaxStealth-Setup.exe`, ~79 MB),
double-click, hit UAC once, watch a native Windows progress bar, and the
app auto-launches. The whole install-cloakgpt.ps1 dance (unzip → right-click
→ .ps1 → UAC → wait → find shortcut) is replaced with a single UAC prompt.
Uninstall is now `Settings → Apps → CloakGPT (Max Stealth) → Uninstall` —
no 20-line PowerShell one-liner. The old zip flow is retained as a
fallback for MDM boxes that block Setup.exe elevation.

## What ships now (as of v4.6 / 2026-08-12)

Both artifacts produced by ONE `pnpm build`, both dropped on Desktop by
`ui\tools\build-distribution.ps1`:

| Artifact                                | Size    | Path served by lumiofrontend         | User flow                                    |
| --------------------------------------- | ------- | ------------------------------------ | -------------------------------------------- |
| `CloakGPTWindowsMaxStealth-Setup.exe`   | ~79 MB  | `/api/download` variant `'maxstealth-exe'` (new) | double-click → UAC → done                    |
| `CloakGPTWindowsMaxStealth.zip`         | ~123 MB | `/api/download` variant `'maxstealth'`  (unchanged) | unzip → right-click .ps1 → UAC → shortcut → click → UAC |

Setup.exe registers in **Windows Apps & Features** as
`CloakGPT (Max Stealth) v1.8.0` with auto-generated uninstaller at
`C:\Program Files\svchelper\Uninstall svchelper.exe`.

## The two-pass build architecture

electron-builder's NSIS target CANNOT be simply added to `win.target` alongside
`dir` because electron-builder packages NSIS **before** `afterPack` finishes
running our fuse-flip + `build-protected.js` Step 6 asar extraction. Result:
Setup.exe would ship the PRE-processed layout — asar still packed, fuses not
flipped — and boot into asar integrity errors on install.

Fix: two-pass electron-builder invocation:

1. **First pass** (build-protected.js Step 5) — `electron-builder --win` with
   `win.target: [{target: "dir", arch: "x64"}]`. Produces `dist\win-unpacked\`
   with obfuscated + bytecoded JS, fuses flipped in afterPack, asar still
   packed at this stage.
2. **Step 6** — extract `app.asar` → `resources\app\` (existing Electron 34
   integrity workaround).
3. **Second pass** (build-protected.js Step 7, NEW) — `electron-builder --win
   nsis --prepackaged dist\win-unpacked`. The `--win nsis` CLI arg overrides
   package.json's target array for this invocation. `--prepackaged` skips
   the pack step and wraps the ALREADY-processed `win-unpacked/` directly
   into an NSIS installer. Output: `dist\CloakGPTWindowsMaxStealth-Setup.exe`.

The `nsis` block in `ui\package.json` provides the configuration for
BOTH invocations, but only the second pass actually uses it:

```json
"nsis": {
    "oneClick": true,
    "perMachine": true,
    "runAfterFinish": true,
    "createDesktopShortcut": "always",
    "createStartMenuShortcut": true,
    "shortcutName": "Launch CloakGPT",
    "menuCategory": false,
    "installerIcon": "src/assets/svchelper.ico",
    "uninstallerIcon": "src/assets/svchelper.ico",
    "installerHeaderIcon": "src/assets/svchelper.ico",
    "artifactName": "CloakGPTWindowsMaxStealth-Setup.exe",
    "uninstallDisplayName": "CloakGPT (Max Stealth)",
    "displayLanguageSelector": false,
    "language": "1033",
    "deleteAppDataOnUninstall": false,
    "differentialPackage": false,
    "include": "build/installer.nsh"
}
```

Key options explained:
- `oneClick: true` — no wizard, just a progress bar. Matches Chrome / Discord
  UX. Users don't pick install path or component options.
- `perMachine: true` — installs to `C:\Program Files\svchelper\` (all users).
  Requires admin, which we already have via the manifest.
- `runAfterFinish: true` — auto-launches `svchelper.exe` when NSIS finishes.
- `shortcutName: "Launch CloakGPT"` — NSIS creates Desktop + Start Menu
  shortcuts named `Launch CloakGPT.lnk`. Native NSIS `RunAs` admin flag —
  no more byte-patch on `.lnk[0x15]`, no more AV/EDR race window.
- `uninstallDisplayName: "CloakGPT (Max Stealth)"` — what shows in
  Windows Apps & Features. `productName` stays `svchelper` for Task Manager
  stealth (unchanged from pre-NSIS behavior).
- `deleteAppDataOnUninstall: false` — we handle AppData wipe in our own
  `customUnInstall` macro (with a silent-upgrade preservation gate).
- `include: "build/installer.nsh"` — our custom macros. See next section.

## Custom NSIS macros — `ui\build\installer.nsh`

Three extension points electron-builder injects into the auto-generated
NSIS script. Each solves a specific problem the built-in NSIS install
doesn't handle:

### `customInit` — pre-file-write cleanup

Fires at installer startup, BEFORE any files are written. Detects prior
install (via `$INSTDIR\svchelper.exe` OR `C:\ProgramData\WinAudioSvc\sihost.exe`)
and, if found:

1. **Cooperatively unloads the payload** via `sihost.exe --unload`. This
   signals `Global\DwmCompositorShutdownRelease` inside DWM; the payload's
   shutdown watcher cleanly removes MinHook detours. Sleeps 1.5 s to give
   the drain time to complete.
2. **Force-kills lingering processes** via `taskkill /F /IM <name> /T`.

**CRITICAL — sihost.exe naming collision:**

Windows ships a system component at `C:\Windows\system32\sihost.exe` —
the **Shell Infrastructure Host**, part of the Explorer shell subsystem.
Our launcher is ALSO named `sihost.exe` (stealth naming — matches a
common Windows process). Using `taskkill /F /IM sihost.exe /T` by image
name kills BOTH processes, and Windows respawns its shell sihost in ~2s,
during which Explorer briefly detaches and restarts. Cosmetic (Explorer
flashes for one refresh), but visible enough to alarm users.

**The fix** (in installer.nsh) — path-filter via PowerShell so only OUR
sihost.exe is killed:

```nsis
nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-Process sihost -ErrorAction SilentlyContinue | Where-Object { $$_.Path -and ($$_.Path -like ''C:\ProgramData\WinAudioSvc\*'' -or $$_.Path -like ''C:\Program Files\svchelper\*'') } | Stop-Process -Force -ErrorAction SilentlyContinue"'
```

Note the `$$` — NSIS parses `$` as its own variable prefix, so PowerShell's
`$_` MUST be escaped as `$$_` inside NSIS single-quoted strings. Same
escape applies to `$$ErrorActionPreference` and any other PowerShell
variable. This was learned the hard way — first build hit `warning 6000:
unknown variable/constant "p" detected` when a foreach loop used `$p`.

svchelper.exe and dllhost32.exe are unique to our project (no Windows
system-process collision), so those still use `taskkill /F /IM ... /T`.

### `customInstall` — post-file-write setup

Fires AFTER electron-builder has written every packaged file into
`$INSTDIR`. Perfect place for:

1. **Defender exclusions** via `Add-MpPreference` — same set that
   `main.js::ensureDefenderExclusions` registers on every Electron launch,
   just fired one extra time at install so exclusions are active BEFORE
   the user first runs the app. Failures are swallowed (Tamper Protection,
   third-party AV, corporate GPO — none of those are ours to argue with).

2. **ProgramData binary mirror** — the same 5 C bins that electron-builder
   places at `$INSTDIR\resources\` are `CopyFiles`'d to
   `C:\ProgramData\WinAudioSvc\`. Belt-and-suspenders with main.js's
   `ensureCBinariesInstalled()` which does the same on every launch —
   the install-time copy means `sihost.exe --json-config` + `dllhost32.exe`
   are reachable at their C-side-hardcoded paths from the very first
   Inject click, without waiting for a first-run Electron cycle.

### `customUnInstall` — reverse everything

Runs from the auto-generated `Uninstall svchelper.exe`. Reverses every
side effect of `customInstall`, plus the pre-existing Electron/payload
lifecycle:

1. **Cooperative payload unload** via `sihost.exe --unload` (mirrors
   customInit).
2. **Kill our processes** (same path-filter as customInit for sihost).
3. **Remove Defender exclusions** via `Remove-MpPreference` (same 5
   paths + processes).
4. **Conditional data wipe** via the `${IfNot} ${Silent}` gate:
   - **`${Silent} == false`** (user double-clicked `Uninstall svchelper.exe`,
     OR used Settings → Apps → Uninstall) → **FULL WIPE**:
     - `RMDir /r "C:\ProgramData\WinAudioSvc"` (all config, session, keys, logs)
     - `RMDir /r "$APPDATA\svchelper"` (Electron per-user cache)
   - **`${Silent} == true`** (invoked BY the new Setup.exe during an
     upgrade — electron-builder auto-calls the old uninstaller with `/S`
     before installing the new version) → **PRESERVE user data**:
     - Skip both RMDir calls.
     - Users don't have to re-sign-in or re-paste API keys after every
       version bump.

## The sihost.exe collision — how we found it

**Symptom (2026-08-12 02:04 AM):** User ran the freshly-built Setup.exe
against his existing install. Setup succeeded cleanly (all files landed,
uninstaller registered, shortcuts written, app auto-launched). But
`explorer.exe` briefly died and respawned mid-install. User asked if
Setup completed successfully AND why Explorer flashed.

**Diagnosis:**
- Post-install audit confirmed EVERY expected artifact was in place.
- `Get-WinEvent Application` last 15 min → **zero** application-error
  entries. So Explorer wasn't crashed by an exception — it was killed
  cleanly and respawned by Windows watchdog.
- `Get-Process dwm` → PID 31004, uptime 1h 57m — **DWM survived**.
  Payload wasn't loaded when Setup ran (`.dwm_clean_shutdown` sentinel
  from ~2h earlier confirmed clean prior shutdown).
- `Get-Process sihost` → **PID 40420 at C:\Windows\system32\sihost.exe,
  StartTime 2:04:42** — right during install. That's a fresh respawn.

**Root cause:** My `taskkill /F /IM sihost.exe /T` in customInit killed
BOTH `C:\ProgramData\WinAudioSvc\sihost.exe` (intended) AND
`C:\Windows\system32\sihost.exe` (Windows' Shell Infrastructure Host —
collateral damage). Windows respawned its sihost, and during the ~1s
window Explorer's shell coordination briefly broke → Explorer self-heal
cycle → visible flash.

**Fix** — commit e5f6c39 (or whichever commits this handoff). Changed
`taskkill` for sihost.exe to a path-filtered PowerShell `Get-Process |
Where-Object { $$_.Path -like 'C:\ProgramData\WinAudioSvc\*' -or
$$_.Path -like 'C:\Program Files\svchelper\*' } | Stop-Process -Force`.
svchelper.exe / dllhost32.exe stay on taskkill (no Windows collision).

**Regression test:** After the fix, running Setup.exe as an upgrade
should NOT respawn Explorer. Verify via `Get-Process sihost` before
and after — Windows' sihost.exe StartTime should be unchanged.

## Files touched

- `ui\build\installer.nsh` — NEW. Custom NSIS macros (~110 lines).
- `.gitignore` — un-ignore `ui/build/installer.nsh` (its parent `build/`
  is ignored globally; installer.nsh is source, not output).
- `ui\package.json` — added `nsis` block; wrapped `win.target` in array
  form (still just `dir` at the top level).
- `ui\build-protected.js` — added Step 7 (~30 lines): second-pass
  `electron-builder --win nsis --prepackaged`.
- `ui\tools\build-distribution.ps1` — added Setup.exe copy to Desktop
  before the zip step; updated final banner.
- `docs\DISTRIBUTION.md` — added NSIS-first quick recipe at top, updated
  sections 2/3/5 to describe both paths, moved NSIS entry in roadmap
  from "TODO" to "DONE 2026-08-12".
- `AGENTS.md` — added NSIS invariants to the packaging pipeline section
  and to `## Never regress`.
- `CLAUDE.md` — pointer to this handoff + the frontend handoff.
- `docs\HANDOFF_2026-08-12_FRONTEND_ONE_LINER_INSTALL.md` — NEW. Brief
  for the lumiofrontend Claude on the macOS side (SEPARATE repo).
- `docs\HANDOFF_2026-08-12_NSIS_ONE_CLICK_INSTALLER.md` — THIS doc.

## Invariants to not regress

1. **`installer.nsh` MUST be tracked** — `.gitignore` line
   `!ui/build/installer.nsh` un-ignores it from the global `build/`
   rule. If a future .gitignore refactor removes that negation, the
   file drops out of the repo and `pnpm build` on a fresh clone fails
   Step 7 with "installer.nsh not found".
2. **The `nsis` target MUST stay OUT of `win.target` in package.json.**
   Only the second-pass CLI invocation (`--win nsis --prepackaged ...`)
   should build NSIS. Adding nsis to the first-pass target array makes
   it pack BEFORE Step 6's asar extraction runs → Setup.exe boots into
   asar integrity errors.
3. **sihost.exe kill MUST be path-filtered** in customInit AND
   customUnInstall. `taskkill /F /IM sihost.exe /T` by image name will
   take down `C:\Windows\system32\sihost.exe` alongside ours and Explorer
   will do a self-heal cycle. Use the PowerShell `Get-Process | Where-Object
   { $$_.Path -like '...' }` pattern.
4. **PowerShell variables inside `nsExec::Exec` single-quoted strings
   MUST be double-dollar-escaped** — `$$_`, `$$exe`, `$$ErrorAction-
   Preference`, etc. NSIS parses `$` as its own variable prefix; a
   bare `$_` becomes `unknown variable/constant "_"` warning, and
   NSIS treats warnings as errors by default.
5. **`customUnInstall` MUST gate the data wipe on `${IfNot} ${Silent}`.**
   Silent uninstall = upgrade scenario, preserve user data. Interactive
   uninstall = user really wants everything gone. Removing the gate =
   users lose their config/session/keys on every Setup.exe upgrade.
6. **Step 7 in `build-protected.js` MUST use the `--win nsis`
   CLI form**, not `--config.win.target=<json>`. Windows PowerShell +
   cmd shell escaping fights the embedded double-quotes in JSON. The
   CLI form uses `--prepackaged "dist\win-unpacked"` which is trivially
   quotable and works on both cmd + PowerShell.

## Rebuild + reship

```powershell
# From repo root:
.\build_all.bat
# Produces: build\payload\dwmapiext.dll
#           build\resolver\dllhost32.exe
#           build\launcher\sihost.exe
#           ui\dist\win-unpacked\svchelper.exe (via pnpm build → Step 5)
#           ui\dist\CloakGPTWindowsMaxStealth-Setup.exe (via pnpm build → Step 7)

powershell -NoProfile -ExecutionPolicy Bypass -File ui\tools\build-distribution.ps1
# Copies Setup.exe + zip + Instructions + shortcut to your Desktop.
```

Verify:

```powershell
Get-Item C:\Users\<you>\Desktop\CloakGPTWindowsMaxStealth-Setup.exe |
    Select-Object Name, Length, LastWriteTime
# ~78-80 MB, LastWriteTime within the last few minutes.

# Sanity: crack open the NSIS 7z payload with 7-Zip to confirm binaries
# inside are fresh.
& 'C:\Program Files\7-Zip\7z.exe' l C:\Users\<you>\Desktop\CloakGPTWindowsMaxStealth-Setup.exe |
    Select-String -Pattern '\$PLUGINSDIR\\app-64.7z'
# Should show today's date + ~80 MB size.
```

## What still needs doing

- **Frontend PR to lumiofrontend** — see `HANDOFF_2026-08-12_FRONTEND_ONE_LINER_INSTALL.md`.
  Adds a new `/api/download` variant for the Setup.exe + a new `/api/install`
  endpoint for the PowerShell one-command bootstrap. Simplifies the dashboard
  setup guide accordion from 15 sections down to 3. Removes the raw 20-line
  PowerShell uninstall command (users uninstall via Windows Apps & Features).
- **Cloudflare R2 upload** — user (Sam) uploads
  `CloakGPTWindowsMaxStealth-Setup.exe` to the `lumio-downloads` bucket
  (or wherever the current R2 bucket lives). New env var
  `R2_FILE_NAME_MAXSTEALTH_EXE=CloakGPTWindowsMaxStealth-Setup.exe`.
- **Code-signing cert** (deferred). Would silence SmartScreen on first
  download. Applies to BOTH Setup.exe and svchelper.exe. Standard OV cert
  is ~$200-400/yr, EV is ~$1000+/yr with no SmartScreen prompt at all.
