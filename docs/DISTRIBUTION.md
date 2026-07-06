# DISTRIBUTION — svcldb / CloakGPT UI

**How to package the app for end-users, what must ship, and what to
tell people once they have the download.**

Owner-facing. Users see none of this — they get one folder, click one
exe, sign in, click Inject, done.

## Quick recipe (as of v4.5)

```powershell
# 1. Build everything (C bins + Electron UI + obfuscation + fuses)
cd C:\Users\<you>\Desktop\svcldb
.\build_all.bat

# 2. Package for shipping — drops 3 artifacts on the current user's
#    REAL Desktop (OneDrive-safe via [Environment]::GetFolderPath):
#       CloakGPTWindowsMaxStealth.zip        ~115 MB
#       CloakGPT Setup Instructions.md       ~13 KB
#       Launch CloakGPT.lnk                  admin-flagged shortcut
powershell -File ui\tools\build-distribution.ps1

# 3. Upload the zip to Cloudflare (or wherever). Users download the
#    zip + follow the printed instructions in "CloakGPT Setup
#    Instructions.md" (which is also inside the zip).
```

The users' recipe is even simpler:
1. Download `CloakGPTWindowsMaxStealth.zip`.
2. Extract it (Windows Explorer, right-click → Extract All).
3. Right-click `install-cloakgpt.ps1` → Run with PowerShell. This
   creates the `Launch CloakGPT` shortcut on their Desktop with the
   admin flag pre-set and (on upgrades) cleans up any stale binaries.
4. Double-click **Launch CloakGPT** → UAC → sign in → paste keys →
   Inject → launch LockDown Browser.

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

Everything in `ui/dist/win-unpacked/` after a `pnpm build`. That folder
is self-contained — zip it and hand it over.

Approximate layout (v4.1):

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

1. `payload\build.bat` → `build\payload\dwmapiext.dll` (669 KB)
   Manual-mapped DLL, CETCOMPAT, handshake gate, sub_check thread.
2. `resolver\build.bat` → `build\resolver\dllhost32.exe` (152 KB)
   Also copies `cgpt_dbghelp.dll` + `symsrv.dll` from Windows SDK into `build\resolver\`.
3. `launcher\build.bat` → `build\launcher\sihost.exe` (939 KB)
   Embeds the payload as RCDATA 101. CETCOMPAT + delay-loaded winhttp/bcrypt/ws2_32.
4. `ui\build.bat` → `build\ui\svchelper.exe` (via `dist\win-unpacked\`)
   Runs `pnpm install` if needed → `pnpm build` → obfuscator + electron-builder + flip-fuses + asar extract.

Any stage failing aborts the rest. Individual stages can be run standalone (each `build.bat` is self-contained).

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

- **NSIS installer** wrapping `dist\win-unpacked\` for a proper "Add/Remove Programs" experience with Start Menu shortcut + uninstall.
- **Code-signing certificate** (EV or standard) to silence SmartScreen and defuse the `verifyUpdateCodeSignature:false` we have today.
- **Auto-update** via `electron-updater` — `requireAdministrator` complicates the standard NSIS updater path; the workaround is a per-user install with a system-wide "elevator" side-service.
- **V8 bytecode** (`bytenode`) for the license modules — another obfuscation layer on top of javascript-obfuscator; skipped in v4.x for build simplicity but easy to slot in.
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
