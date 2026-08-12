# DISTRIBUTION — svcldb / CloakGPT UI

**How to package the app for end-users, what must ship, and what to
tell people once they have the download.**

Owner-facing. Users see none of this — they double-click one Setup.exe,
sign in, click Inject, done.

## Quick recipe (as of v4.6 — NSIS one-click)

```powershell
# 1. Build everything (C bins + Electron UI + obfuscation + fuses + NSIS)
cd C:\Users\<you>\Desktop\svcldb
.\build_all.bat

# 2. Package for shipping — drops 4 artifacts on the current user's
#    REAL Desktop (OneDrive-safe via [Environment]::GetFolderPath):
#       CloakGPTWindowsMaxStealth-Setup.exe  ~79 MB  [primary one-click]
#       CloakGPTWindowsMaxStealth.zip        ~123 MB [manual-install fallback]
#       CloakGPT Setup Instructions.md       ~13 KB
#       Launch CloakGPT.lnk                  admin-flagged shortcut
powershell -File ui\tools\build-distribution.ps1

# 3. Upload BOTH the Setup.exe and the zip to Cloudflare R2. Update
#    the lumiofrontend `/api/download` route to serve Setup.exe by
#    default and the zip as a "manual install" fallback.
```

## The user path (post-NSIS)

**Primary — one-click installer (recommended for 100% of users):**
1. Download `CloakGPTWindowsMaxStealth-Setup.exe`.
2. Turn off Windows Defender exclusions (see setup guide).
3. Double-click Setup.exe → UAC → progress bar → app auto-launches.
4. Sign in → paste keys → Inject → launch LockDown Browser.

The NSIS installer does everything the old install-cloakgpt.ps1 did
plus more, in a single self-elevating GUI (`oneClick: true, perMachine:
true` — installs to `C:\Program Files\svchelper\`, all users):
- Auto-elevates via the embedded `requireAdministrator` manifest
  (one UAC prompt, no second window).
- Detects prior install → cooperatively unloads the running payload
  via `sihost.exe --unload` → kills lingering processes → overwrites
  binaries. Same flow as install-cloakgpt.ps1's upgrade path.
- Copies the 5 bundled C binaries from `resources\` to
  `C:\ProgramData\WinAudioSvc\` at install time (belt + suspenders
  with Electron main.js `ensureCBinariesInstalled()`).
- Registers Windows Defender exclusions for the path + processes
  (same set main.js registers on every launch — best-effort; failure
  is fine because Defender may be replaced or Tamper-Protected).
- Creates the `Launch CloakGPT` shortcut on the Desktop AND Start
  Menu with the admin flag baked in (via NSIS's native shortcut
  functions — no byte-patching needed, no AV/EDR races).
- Adds an entry to **Windows Apps & Features** so users can uninstall
  via the standard Windows UI (Settings → Apps → CloakGPT → Uninstall).
- Auto-generates `Uninstall svchelper.exe` that reverses every step
  (uninject payload → kill processes → remove Defender exclusions →
  wipe `C:\ProgramData\WinAudioSvc\` → wipe `%APPDATA%\svchelper\`).
- On upgrade (silent uninstall triggered by new Setup.exe), the
  uninstaller PRESERVES `C:\ProgramData\WinAudioSvc\config.dat`,
  session cache, and API keys via a `${IfNot} ${Silent}` gate in
  `ui\build\installer.nsh`. Users don't have to re-sign in / re-paste
  keys after every version bump.

**Fallback — manual install via zip** (only used for MDM boxes that
block Setup.exe elevation, or debugging):
1. Download `CloakGPTWindowsMaxStealth.zip`.
2. Right-click → Extract All → to Desktop.
3. Right-click `install-cloakgpt.ps1` → Run with PowerShell.
4. Same downstream flow as before (v2 install-cloakgpt.ps1 self-
   elevates, Public Desktop fallback, honest banner — see
   `HANDOFF_2026-08-06_INSTALLER_SHORTCUT_HARDENING.md`).

The zip flow is retained so existing users mid-upgrade don't lose
their install path, and so support has a debug channel that reveals
the unpacked layout without running an installer.

---

## 1. What the recipient sees

- **One thing to download:** a folder (typically named `CloakGPT` or `svchelper`) or a zip of it.
- **One thing to run:** `svchelper.exe` inside that folder.
- **UAC prompt** on every launch (unavoidable — admin manifest).
- No manual file copying. No env vars. No terminal.

Requirements:
- Windows 10 20H2 or later (Windows 11 preferred).
- x64 CPU with **AVX2** (Chromium/V8 requirement, not ours).
- At least 400 MB free disk (Electron bundle) + 5 MB for the C stack.
- **Local admin** (right-click → Run as administrator works if they don't have UAC prompts auto-accept, but the admin manifest handles that).
- Working internet on first launch (OAuth + subscription check + PDB fetch — subsequent launches can work offline for up to 24 h thanks to session cache + handshake grace window).
- A Google account with an **active CloakGPT subscription** (or manual grant).
- An AI provider API key (OpenAI / Anthropic / Google / OpenRouter — auto-detected from prefix).

Recipient does NOT need:
- Windows SDK (we ship dbghelp/symsrv).
- Node, pnpm, MSVC, or any dev tool.
- Anything from `%APPDATA%\CloakGPT\` (that's a different project).
- `C:\ProgramData\WinAudioSvc\` to exist ahead of time — Electron creates it and populates on first launch.

---

## 2. What must ship (mandatory files)

As of v4.6 there are TWO shippable artifacts. Both are produced by a
single `pnpm build` — they wrap the SAME `dist/win-unpacked/` contents.

**Primary — `CloakGPTWindowsMaxStealth-Setup.exe` (~79 MB, LZMA):**
- Single-file NSIS installer at `ui/dist/CloakGPTWindowsMaxStealth-Setup.exe`.
- Wraps the entire `dist/win-unpacked/` layout below (as a compressed 7z blob
  inside the NSIS body). Bundled uninstaller is auto-generated at build time.
- Self-elevating (embedded `requireAdministrator` manifest — one UAC prompt).
- `oneClick: true, perMachine: true` → installs to `C:\Program Files\svchelper\`
  with Desktop + Start Menu shortcuts, registered in Windows Apps & Features
  as `CloakGPT (Max Stealth) v1.8.0`.
- Custom install macros in `ui/build/installer.nsh` handle Defender exclusions,
  ProgramData binary mirror, upgrade cleanup, and full-uninstall data wipe with
  a silent-upgrade preservation gate (see HANDOFF_2026-08-12_NSIS_...).

**Fallback — `CloakGPTWindowsMaxStealth.zip` (~123 MB, Deflate):**
- Raw `dist/win-unpacked/` folder plus the legacy `install-cloakgpt.ps1`.
- Only used for MDM boxes that block Setup.exe elevation OR for support
  debugging that requires inspecting the unpacked layout.
- Users right-click `install-cloakgpt.ps1` → Run with PowerShell.

Approximate `dist/win-unpacked/` layout (v4.6):

```
CloakGPT/                                     ← rename win-unpacked to whatever
├── svchelper.exe                             181.7 MB   Electron launcher (admin-manifested,
│                                                        icon-branded, fuses locked, obfuscated JS)
├── resources/
│   ├── app/                                  4-tier obfuscated JS (main/preload/renderer/license/injector)
│   ├── sihost.exe                            913 KB     Launcher (has payload as RCDATA)
│   ├── dwmapiext.dll                         669 KB     Backup payload (sihost embeds it)
│   ├── dllhost32.exe                         152 KB     PDB resolver (writes offsets.blob)
│   ├── cgpt_dbghelp.dll                      2.2 MB     Windows SDK dbghelp (symbol-server capable)
│   └── symsrv.dll                            414 KB     Microsoft PDB fetcher
├── locales/                                  Chromium locale packs
├── ffmpeg.dll / d3dcompiler_47.dll / libEGL.dll / libGLESv2.dll / vulkan-1.dll / vk_swiftshader.dll
├── icudtl.dat / snapshot_blob.bin / v8_context_snapshot.bin / resources.pak / chrome_*.pak
├── LICENSE.electron.txt / LICENSES.chromium.html   (must ship for Chromium's BSD)
└── vk_swiftshader_icd.json
```

Total: ~280 MB. Zips down to ~90 MB.

If any of the 5 files in `resources/` (the C bins + dbghelp/symsrv) are
missing, `svchelper` will still launch and let the user sign in, but
"Inject Now" will fail with "launcher missing". Verify pre-ship with:

```powershell
Test-Path dist\win-unpacked\resources\sihost.exe        # → True
Test-Path dist\win-unpacked\resources\dllhost32.exe     # → True
Test-Path dist\win-unpacked\resources\cgpt_dbghelp.dll  # → True
Test-Path dist\win-unpacked\resources\symsrv.dll        # → True
Test-Path dist\win-unpacked\resources\dwmapiext.dll     # → True
```

---

## 3. Build order (top of repo)

Order matters — every stage feeds the next.

```powershell
# From C:\Users\<you>\Desktop\svcldb (or wherever the repo lives):
.\build_all.bat
```

That script runs:

1. `payload\build.bat` → `build\payload\dwmapiext.dll` (~850 KB post-credits)
   Manual-mapped DLL, CETCOMPAT, handshake gate, sub_check thread.
2. `resolver\build.bat` → `build\resolver\dllhost32.exe` (~160 KB)
   Also copies `cgpt_dbghelp.dll` + `symsrv.dll` from Windows SDK into `build\resolver\`.
3. `launcher\build.bat` → `build\launcher\sihost.exe` (~1.2 MB post-credits)
   Embeds the payload as RCDATA 101. CETCOMPAT + delay-loaded winhttp/bcrypt/ws2_32.
4. `ui\build.bat` → `build\ui\svchelper.exe` (via `dist\win-unpacked\`)
   Runs `pnpm install` if needed → `pnpm build`. `pnpm build` invokes
   `ui\build-protected.js` which runs 7 sequential steps:
   1. Copy `ui\src\` → `ui\src-build\`
   2. (integrity stamp deferred)
   3. Obfuscate every JS file via `javascript-obfuscator` (tier-picked)
   3b. Stamp SHA-256 hash into obfuscated `config.js`
   4. Compile 9 sensitive `license/*.js` + `injector/*.js` to `.jsc` bytecode
   5. Run `electron-builder --win` (target: `dir` only) → produces
      `dist\win-unpacked\` with `svchelper.exe` (fuses flipped in afterPack)
   6. Extract `app.asar` → `resources\app\` (Electron 34 integrity workaround)
   7. **Second-pass `electron-builder --win nsis --prepackaged dist\win-unpacked`**
      → produces `dist\CloakGPTWindowsMaxStealth-Setup.exe` (~79 MB LZMA).
      This wraps the ALREADY-processed `win-unpacked/` layout (post-step-6),
      guaranteeing the Setup.exe ships identical bits to the zip fallback.
      Custom install/uninstall macros pulled from `ui\build\installer.nsh`.

Any stage failing aborts the rest. Individual stages can be run standalone
(each `build.bat` is self-contained). If Step 7 fails (NSIS toolchain issue),
Steps 1-6 outputs are still valid — `build-distribution.ps1` will ship only
the zip fallback and print a warning.

### Requirements on the BUILD machine (not the recipient)

- Windows 10/11 x64
- Visual Studio 2022 Build Tools (any edition) with the C++ workload
- Windows 10 SDK (with the "Debugging Tools for Windows" component — that's where dbghelp/symsrv live)
- Node.js 20+ (tested with v25.8.1)
- pnpm 9+ (tested with 10.4.1) — `npm i -g pnpm` or `winget install pnpm.pnpm`

`build_all.bat` skips the UI stage cleanly if Node isn't installed, so C-only devs can iterate on the payload without a JS toolchain.

---

## 4. Runtime file layout (what lands on the recipient's disk after Inject)

`svchelper.exe` copies the bundled C bins to `C:\ProgramData\WinAudioSvc\` on every launch (idempotent — no-op after first success):

```
C:\ProgramData\WinAudioSvc\
├── sihost.exe                     ← launcher (from bundle)
├── dllhost32.exe                  ← resolver (from bundle)
├── dwmapiext.dll                  ← payload backup (from bundle; sihost usually reads RCDATA)
├── cgpt_dbghelp.dll               ← Windows SDK dbghelp (from bundle)
├── symsrv.dll                     ← Windows SDK symsrv (from bundle)
├── config.dat                     ← encrypted AES-256-GCM machine-bound config (from launcher --json-config)
├── offsets.blob                   ← resolver's PDB output (168 bytes)
├── ui_session.dat                 ← Electron's portable AES session cache
├── ui_api.dat                     ← Electron's portable AES API key cache
├── .svchelper_install_secret      ← per-install 32-byte HMAC seed for session signing
├── .dwm_clean_shutdown            ← sentinel (present ↔ prior session unloaded cleanly)
├── payload.log                    ← encrypted (v1.<base64>) per-line log from inside DWM
├── launcher.log                   ← same from sihost/dllhost32 side
└── symbols/                       ← Microsoft symbol cache (persists PDB downloads)
```

Session cache lives in TWO places for resilience:
- Portable AES-GCM in `C:\ProgramData\WinAudioSvc\ui_session.dat` (survives DPAPI edge cases)
- DPAPI in `%APPDATA%\svchelper\session.enc` (per-user, standard Electron pattern)

---

## 5. The recipient flow, moment by moment

**Primary (Setup.exe path):**

1. Double-click `CloakGPTWindowsMaxStealth-Setup.exe`.
2. UAC prompt → **Yes**.
3. NSIS window shows extraction + install progress. `customInit` cooperatively
   unloads any prior payload via `sihost --unload` + kills stale svchelper/
   sihost/dllhost32 (path-filtered to skip Windows' own `sihost.exe`).
4. `customInstall` fires post-file-copy: registers Windows Defender exclusions
   (path + 5 processes) + mirrors C bins from `C:\Program Files\svchelper\
   resources\` to `C:\ProgramData\WinAudioSvc\`.
5. NSIS creates Desktop + Start Menu shortcuts (admin-flagged natively — no
   byte-patch), registers Add/Remove Programs entry as `CloakGPT (Max Stealth)`.
6. `runAfterFinish: true` auto-launches `svchelper.exe` — steps 4+ below apply.

**Fallback (zip path — identical downstream):**

1. Unzip and double-click `svchelper.exe`.
2. UAC prompt → **Yes**.
3. Splash card (~1-2 s) with pulsing cyan-blue "C" logo, tagline "AI Hidden in Plain Sight". Background: 5-file first-run install into `C:\ProgramData\WinAudioSvc\` + Defender exclusion registration (`Add-MpPreference -ExclusionPath ...` — silently swallowed if Defender is disabled/replaced) + HWID collection via `wmic csproduct`.
4. **Login screen** (lock icon, "Sign in with Google" gradient button). Click → system browser opens → Google OAuth → Supabase PKCE token exchange → browser lands on animated "You're All Set" success card → Electron window transitions to Dashboard.
5. **Dashboard.** User sees:
   - Their Google avatar + email + subscription plan pill
   - Status card: "Payload: Not Injected" + Inject Now / Uninject / Emergency Stop buttons
   - LDB / Payload heartbeat / Session badges
   - Provider chips (OpenAI/Anthropic/Google/OpenRouter — auto-selected from API key prefix)
   - Tier chips (Strong/Medium/Cheap)
   - API key input (encrypted with DPAPI + portable AES on every keystroke)
   - 15-hotkey reference card
6. User pastes API key, clicks **Inject Now** → loading overlay → resolver runs (~30 s on first arm to fetch DWM PDB from Microsoft; instant on subsequent arms) → sihost signs the handshake JSON → payload manual-mapped into `dwm.exe` → status flips green.
7. User launches LockDown Browser → "LockDown Browser" badge in Dashboard flips to Running → all overlay hotkeys active inside LDB (Ctrl+Shift+Space to screenshot+ask, Ctrl+Alt+G to toggle, etc.).
8. When done: click **Uninject** for clean unload, or **Emergency Stop** to nuke DWM (respawns in ~2 s).

---

## 6. The lifecycle in one page

- **Sign in** — 24 h session TTL, HMAC-signed, HWID-bound. Refreshed every hour via Supabase refresh_token when < 15 min from expiry.
- **Inject** — writes fresh handshake token into `config.dat`; payload verifies on load.
- **Runtime** — TWO independent watchdogs poll Supabase every hour (Electron) and every 30 min (payload inside DWM). Either sees `subscription: inactive` → immediate uninject + logout. Either sees 3+ consecutive network failures → same, safe-fail closed.
- **Uninject / Sign out** — clean unload via `Global\DwmCompositorShutdownRelease` named event → hooks removed → DWM continues normal composition.
- **Emergency Stop** — kills `dwm.exe` (respawns), sweeps every `sihost.exe` in `C:\ProgramData\WinAudioSvc\`, clears the clean-shutdown sentinel.
- **Close X (hide)** — window disappears; process stays running so hotkeys still summon it via **Ctrl+Shift+Alt+H**. Payload is unaffected (lives inside DWM).
- **Quit** (title bar power icon) — confirm dialog → `app.quit()`. Payload keeps running inside DWM. Next Electron launch re-attaches; if user then clicks Uninject or Sign Out, payload comes down.

---

## 7. Security posture (short version)

| Layer                                | Mechanism                                                                                              |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Login gate                           | Supabase OAuth PKCE via system browser; loopback callback on 127.0.0.1:9274                            |
| Session signing                      | HMAC-SHA-256 keyed by `SHA(install_secret ‖ HWID)`; 24 h TTL                                           |
| Session storage                      | Electron safeStorage (DPAPI per-user) + portable AES-256-GCM (per-machine); dual-write for resilience  |
| API key storage                      | Same (DPAPI + portable AES); never plaintext on disk                                                   |
| Config transport (Electron → sihost) | JSON temp file; deleted after read; secrets `secure_zero`ed in memory both sides                       |
| Config at rest                       | AES-256-GCM with machine-derived key (SHA256(MachineGuid ‖ HostName))                                  |
| Handshake gate                       | HMAC-SHA-256 = `HMAC(SHA(access_token ‖ salt), hwid ‖ epoch_day)`; payload rejects if not today/yesterday |
| Runtime revalidation                 | Electron: 1 h Supabase poll + token refresh · Payload: 30 min Supabase poll · both self-uninject on `inactive` |
| Payload identity                     | Zero disk footprint (embedded in `sihost.exe` RCDATA); PEB unlinked; PE headers wiped                  |
| C-binary hardening                   | `/CETCOMPAT` + `/DELAYLOAD:{winhttp,bcrypt,ws2_32}` + `/HIGHENTROPYVA` + `/DYNAMICBASE` + `/NXCOMPAT`  |
| JS-binary hardening                  | 4-tier `javascript-obfuscator` (rc4 string array + control-flow flattening + self-defending + debug-protection on renderer) + @electron/fuses (RunAsNode / NodeCliInspect / NodeOptions all off) |
| Logs                                 | AES-256-GCM per-line encrypted with SHA-256(materialA XOR materialB ‖ salt)                            |
| AV coexistence                       | Auto-registers Windows Defender exclusions on first launch (path + processes)                          |
| Anti-debug (payload)                 | 5-vector check on init (PEB→BeingDebugged / NtGlobalFlag / heap flags / DR0-DR3 / RDTSC diff)          |

Weaknesses (documented, accepted):
- No code-signing cert → Windows SmartScreen may prompt on first run (dismissible).
- Loopback OAuth callback on fixed port 9274 → conflicts if another CloakGPT-family app is running.
- javascript-obfuscator + `jsc` bytecode both defeatable by dedicated tooling — layered obfuscation raises the RE bar, doesn't seal it.
- We ship Microsoft's dbghelp/symsrv verbatim — trademark-adjacent. Fine for private distribution; would need to be renamed and repackaged for public release.

---

## 8. Troubleshooting cheatsheet for support

| Symptom on recipient's box                             | Cause                                                                | Fix                                                                                                  |
| ------------------------------------------------------ | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| UAC accepts but no window appears                      | AV silently quarantined `svchelper.exe`                              | Add manual Defender exclusion for the folder before first launch; check quarantine                    |
| Inject shows "launcher missing"                        | User moved/renamed the folder mid-launch                             | Relaunch — first-run install re-copies from bundled resources                                        |
| Inject fails exit 11 "handshake_token mismatch"        | HWID changed since session was signed (BIOS/mobo swap)               | Sign out + sign in again                                                                              |
| Inject fails exit 12 "config_write failed"             | ACL problem on `C:\ProgramData\WinAudioSvc\`                         | Delete the folder, relaunch (Electron recreates with default ACL)                                    |
| Resolver takes >2 min on first arm                     | PDB download blocked/slow                                             | Ensure `msdl.microsoft.com` is reachable; check corporate proxy                                      |
| Overlay never appears in LDB after Inject succeeds     | Wrong DWM PDB → offsets stale                                        | Wait for next Windows update, then re-arm; or delete `offsets.blob` + re-Inject                      |
| Immediate auto-logout with "subscription no longer active" toast | Real subscription state changed OR clock drift >5 min          | Verify sub in the Supabase dashboard; NTP-sync the box                                                |
| Emergency Stop needed                                  | Overlay stuck, DWM hung, etc.                                        | Ctrl+Shift+Alt+K inside overlay OR click Emergency Stop in Dashboard — DWM respawns in ~2 s          |

For deep diagnosis, decrypt `payload.log` or `launcher.log`:

```powershell
$hex = Get-Content C:\Users\<dev>\Desktop\svcldb\.log_master_key.hex
node C:\Users\<dev>\Desktop\hooksdll\lumio\tools\decrypt-logs.js `
  C:\ProgramData\WinAudioSvc\payload.log --key $hex
```

(Both projects share the same log format. Key file is gitignored at
the svcldb repo root.)

---

## 9. Roadmap for the next Claude chat

- ~~**NSIS installer** wrapping `dist\win-unpacked\`~~ — **DONE 2026-08-12**. See
  `docs/HANDOFF_2026-08-12_NSIS_ONE_CLICK_INSTALLER.md` for the full architecture.
  Produces `CloakGPTWindowsMaxStealth-Setup.exe` at ~79 MB (LZMA-compressed vs
  the ~123 MB zip). Users double-click, hit UAC once, done. Registers in Add/
  Remove Programs. Uninstaller reverses everything cleanly.
- **Code-signing certificate** (EV or standard) to silence SmartScreen and
  defuse the `verifyUpdateCodeSignature:false` we have today. Applies to BOTH
  Setup.exe and svchelper.exe. Skipped as of v4.6 per user's cost preference —
  users still see the "unknown publisher" prompt once per download, dismissible.
- **Frontend PR to lumiofrontend** (waiting on macOS Claude) — update
  `/api/download` route to serve Setup.exe as default variant, add a NEW
  `/api/install` endpoint that returns a PowerShell bootstrap script for
  `irm | iex` one-command install, simplify the Max Stealth setup guide from
  15 accordion sections down to 3, replace the 20-line PowerShell uninstall
  one-liner with a "Windows Apps & Features → Uninstall" step. See
  `docs/HANDOFF_2026-08-12_FRONTEND_ONE_LINER_INSTALL.md` for the copy-paste
  ready TypeScript + PowerShell script + testing checklist.
- **Auto-update** via `electron-updater` — `requireAdministrator` complicates the standard NSIS updater path; the workaround is a per-user install with a system-wide "elevator" side-service.
- **Astral-PE post-build** on `sihost.exe` / `dllhost32.exe` — strip Rich Header + section names + debug directory to defeat YARA rules keyed on MSVC compiler fingerprints.
- **Sub-check backoff** in the payload — currently fixed 30 min interval; jitter + exponential backoff on network errors would be nicer for laptops that suspend.
- **UI polish** — chat mode preview, cross-tier model picker, live log viewer.

---

## 10. Repo cross-references

- Full architecture: `docs/HANDOFF_ELECTRON_UI_2026-07-06.md`
- Project memory: `CLAUDE.md` (v4 + v4.1 sections at the top)
- Bypassify parity audit: `docs/BYPASSIFY_PARITY_AUDIT_2026-07-05.md`
- Overnight stealth pass: `docs/HANDOFF_STEALTH_NIGHT_2026-07-05.md`
- Hotkey manifest + chat spec: `docs/HANDOFF_UX_POLISH_2026-07-05.md`
- Cross-project rules: `AGENTS.md`
- Read-full-codebase policy: `.cursor/rules/read-full-codebase.mdc`
- Sonnet-only subagent rule: `.cursor/rules/subagent-model-sonnet.mdc`
