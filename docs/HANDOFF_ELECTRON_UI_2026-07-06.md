# HANDOFF — Electron UI + Handshake Gate (v4 / v4.1)

**Date:** 2026-07-06
**Status:** ✅ shipped, builds clean, smoke-tested launch OK.

## v4.1 addendum — single-exe distribution + C hardening

Everything below the v4 section applies. v4.1 added:

### C-side hardening flags (no source changes)

| File            | Flags added                                                            | Why                                                                                                     |
| --------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `launcher/build.bat` | `/CETCOMPAT` + `/DELAYLOAD:winhttp.dll` + `/DELAYLOAD:bcrypt.dll` + `/DELAYLOAD:ws2_32.dll` + `delayimp.lib` | CET Shadow Stack (hw ROP defense); IAT hides security-related imports (only kernel32/user32/advapi32/shell32 visible statically now — verified via `dumpbin /dependents`) |
| `payload/build.bat`  | `/CETCOMPAT` (only)                                                    | DWM (host) has CET; marking our DLL compatible extends shadow stack over our detours. `/DELAYLOAD` inapplicable (manual-map skips loader).       |
| `resolver/build.bat` | `/CETCOMPAT` + `/GUARD:CF` + copies `cgpt_dbghelp.dll` + `symsrv.dll` from Windows SDK next to `dllhost32.exe` after link | Resolver goes through normal LDR so CFG is safe; SDK dbghelp needed for PDB fetching                    |

Verified via `dumpbin /dependents dist\win-unpacked\resources\sihost.exe`:
```
Image has the following dependencies:
    KERNEL32.dll  USER32.dll  ADVAPI32.dll  SHELL32.dll
Image has the following delay load dependencies:
    bcrypt.dll  WINHTTP.dll  WS2_32.dll
```

`dumpbin /headers` shows `CET compatible` in extended DLL characteristics.

### One-exe distribution — bundled C binaries + first-run install

`ui/package.json` now has `extraResources` for all 5 C binaries:

```json
"extraResources": [
  { "from": "../build/launcher/sihost.exe",       "to": "sihost.exe" },
  { "from": "../build/payload/dwmapiext.dll",     "to": "dwmapiext.dll" },
  { "from": "../build/resolver/dllhost32.exe",    "to": "dllhost32.exe" },
  { "from": "../build/resolver/cgpt_dbghelp.dll", "to": "cgpt_dbghelp.dll" },
  { "from": "../build/resolver/symsrv.dll",       "to": "symsrv.dll"       }
]
```

Total added to svchelper installer: ~4.35 MB. They land in
`dist/win-unpacked/resources/` next to `svchelper.exe`.

`ui/src/main.js::ensureCBinariesInstalled()` runs on `whenReady` BEFORE
`createWindow`. Copies each file from `process.resourcesPath` to
`SVC_INSTALL_DIR` (= `C:\ProgramData\WinAudioSvc`) if the target is
missing OR older OR wrong size. Idempotent — no-op after first success.

### Windows Defender self-exclusion

`ui/src/main.js::ensureDefenderExclusions()` runs on `whenReady` (fire-and-forget,
never blocks startup). Since Electron manifest is `requireAdministrator`,
`Add-MpPreference` runs elevated:

```
-ExclusionPath 'C:\ProgramData\WinAudioSvc'
-ExclusionProcess 'svchelper.exe','sihost.exe','dllhost32.exe','dwmapiext.dll','dwm.exe'
```

Wrapped in PowerShell `try{...}catch{}` — if Defender is disabled by policy,
replaced by a third-party AV, or the MpPreference cmdlet isn't available,
the failure is swallowed and logged. User's threat model is explicit:
AV visibility doesn't matter, functionality does.

### The truly one-click flow (post-v4.1)

Now the answer to *"can I hand someone the folder and they just click and go?"* is **YES**:

1. Zip the entire `ui/dist/win-unpacked/` folder — 195 MB (Chromium is
   most of it). Rename to whatever the user wants.
2. Recipient unzips, double-clicks `svchelper.exe`.
3. UAC prompt → user accepts.
4. Splash appears while we:
   - Copy the 5 bundled C binaries from `resources/` to `C:\ProgramData\WinAudioSvc\`
   - Register the Defender exclusions
   - Collect HWID
5. Login screen → user signs in with Google via browser → success card → Dashboard.
6. Enter API key, click **Inject Now** → resolver runs (~30 s first
   time — PDB download from Microsoft; instant after cache) → sihost
   injects payload → status flips green.
7. User launches LockDown Browser → overlay + all hotkeys active.

No manual copying to `C:\ProgramData\WinAudioSvc\`. No env vars. No
external dependencies beyond a Google account with an active CloakGPT
subscription. Windows SDK is NOT required on the recipient's machine —
we ship the SDK's dbghelp/symsrv inside the exe bundle.

### v4.1 hard invariants (added on top of v4)

11. `ensureCBinariesInstalled()` runs on EVERY launch (idempotent) —
    never gate it behind a first-launch flag. That handles both the
    initial install AND upgrades where a new svchelper ships newer
    C binaries; the size/mtime check triggers a re-copy.
12. `ensureDefenderExclusions()` is fire-and-forget — DO NOT `await` it
    or block window creation on it. Defender operations can take 5-15 s
    on a stressed system and would make the app feel dead.
13. `/CETCOMPAT` on the launcher is safe because the manual-map shellcode
    runs on DWM's threads, using DWM's shadow stack; the launcher's own
    threads use its own. Neither crosses.
14. Resolver `build.bat` uses `set "SDK_DBG_DIR=..."` (quoted assignment)
    so the `(x86)` in the path doesn't confuse cmd.exe's block parser
    when we later `if exist "%SDK_DBG_DIR%\..." goto :HAVE_SDK`.
15. Static IAT of sihost.exe MUST NOT contain bcrypt/winhttp/ws2_32 —
    verified via `dumpbin /dependents` post-build. If they show up in
    "Image has the following dependencies:" instead of "delay load
    dependencies:", the `/DELAYLOAD` flag was lost or `delayimp.lib`
    is missing.

---



## What changed

Added a full Electron "login gate" (`svchelper.exe`) in front of the existing
C-only launcher (`sihost.exe`). The payload (`dwmapiext.dll`) now REFUSES to
install its DWM hooks unless the config it decrypts on init contains a valid
HMAC-SHA256 handshake token derived from a real Supabase access token.

Result:
1. Users **must** launch `svchelper.exe`, sign in with Google via Supabase OAuth,
   verify subscription, and click **Inject Now** — no CLI-only bypass path.
2. Stolen or crafted `config.dat` files are rejected at payload init
   (three-way binding: HWID, calendar day, Supabase JWT).
3. Payload continues to work exactly as before once the handshake passes.
4. Dev iteration path (`sihost --quiet`) still works because the legacy code
   also now stamps a valid handshake before writing `config.dat`.

## Files added or modified

```
+ shared/handshake.h
+ shared/handshake.c
~ shared/config_types.h              # +magic +schema_version +handshake_* fields
~ payload/src/dllmain.c              # handshake_verify gate in init_thread
~ payload/build.bat                  # +handshake.c source
~ launcher/src/main.c                # --json-config mode, JSON parser, stamp helper
~ launcher/build.bat                 # +handshake.c source
~ build_all.bat                      # +ui build orchestration (skip if no node)

+ ui/package.json                    # Electron 34, pnpm, javascript-obfuscator, etc.
+ ui/.npmrc                          # node-linker=hoisted (pnpm ⇔ electron-builder)
+ ui/.gitignore
+ ui/build.bat                       # pnpm-based wrapper
+ ui/build-protected.js              # obfuscator + electron-builder + asar extract
+ ui/flip-fuses.js                   # post-pack fuse flipper
+ ui/src/main.js                     # Electron main process
+ ui/src/preload.js                  # contextBridge only
+ ui/src/renderer.js                 # SPA state machine
+ ui/src/index.html                  # splash / login / nosub / dashboard
+ ui/src/styles.css                  # CloakGPT palette
+ ui/src/license/auth.js             # OAuth PKCE + polished HTML pages
+ ui/src/license/config.js           # XOR-encrypted Supabase URL / anon key
+ ui/src/license/device.js           # HWID via wmic csproduct
+ ui/src/license/handshake.js        # HMAC token — MUST match shared/handshake.c
+ ui/src/license/storage.js          # DPAPI + AES-GCM fallback session store
+ ui/src/license/subscription.js     # Supabase REST sub check
+ ui/src/injector/injector.js        # JSON handoff + spawn sihost + status probe

+ docs/HANDOFF_ELECTRON_UI_2026-07-06.md   ← this file
```

## The v4 config schema

`svc_config_t` gained six fields (see `shared/config_types.h`):

```c
uint32_t    magic;               /* SVC_CONFIG_MAGIC     = 0x53564C43 ("SVLC") */
uint32_t    schema_version;      /* SVC_CONFIG_SCHEMA_VERSION = 4 */
/* ... existing fields ... */
uint8_t     handshake_token[32]; /* HMAC output          */
long long   handshake_epoch_day; /* floor(unix / 86400)  */
char        handshake_hwid[80];  /* HWID token was derived against */
```

Old configs (schema ≤ 3) fail cleanly because `cu_wrap_decrypt` returns
`plen != sizeof(svc_config_t)`. Users re-authenticate via Electron on first
launch after upgrade.

## Handshake protocol

Symmetric derivation on both sides — see `shared/handshake.h` for the C-side
authoritative spec and `ui/src/license/handshake.js` for the JS mirror.

```
salt        = "svcldb-handshake-v1"
sig_key     = SHA-256(access_token || salt)                (32 bytes)
epoch_day   = floor(unix_time / 86400)
msg         = hwid || ":" || epoch_day_decimal
token[32]   = HMAC-SHA-256(sig_key, msg)
```

Payload accepts the token iff:
- `magic` and `schema_version` match, AND
- `handshake_verify(access_token, handshake_hwid, handshake_token)` = 1,
  which recomputes for **today** and **yesterday** (48h grace window) and
  timing-safe-compares.

### Attack surface after the gate

| Attack                                             | Blocked by                                                |
| -------------------------------------------------- | --------------------------------------------------------- |
| Craft a `config.dat` on a different machine        | `cu_wrap_encrypt` machine-binds via SHA(MachineGuid‖Host) |
| Craft a `config.dat` with a fake `access_token`    | `handshake_verify` HMACs the real token — no match        |
| Reuse a stolen `config.dat` from a day > 48h ago   | `handshake_epoch_day` outside today/yesterday window      |
| Ship `sihost.exe --quiet` w/ prebaked bad config   | Same as above; also `assemble_config_from_json` verifies  |
| Modify the payload DLL to skip the gate            | Requires a rebuild — the RCDATA blob inside `sihost.exe`  |
|                                                    | must also be replaced; this is a fork, not a bypass       |

## Launcher (`sihost.exe`) CLI additions

| Flag                       | Behavior                                                |
| -------------------------- | ------------------------------------------------------- |
| `--json-config <path>`     | Electron handoff. Reads JSON, verifies handshake,       |
|                            | writes `config.dat`, runs resolver, injects. Deletes    |
|                            | the input file after read (secrets never linger).       |
| `--quiet` (legacy path)    | Still works — env-var OAuth flow now stamps a valid     |
|                            | handshake before `config_write`. Kept for dev iteration.|
| `--reinject` / `--unload`  | Unchanged — `--reinject` just injects existing          |
| `--kill` / `--kill-all`    | `config.dat` (must have valid handshake) without OAuth. |

### `--json-config` handoff JSON schema

Written by `ui/src/injector/injector.js::buildJson`. Parsed by
`launcher/src/main.c::assemble_config_from_json`. Kept intentionally flat
(no nested objects) so the minimal JSON parser in `shared/json_util.c` can
walk it.

```json
{
  "access_token":        "eyJ...",
  "token_expires_at":    1672531200,
  "hwid":                "SMBIOS-UUID",
  "handshake_epoch_day": 19541,
  "handshake_token_hex": "abc...deadbeef",
  "provider":            1,
  "tier":                1,
  "api_key":             "sk-...",
  "model":               "",
  "reasoning_effort":    4,
  "streaming_enabled":   1,
  "latex_disabled":      0,
  "system_prompt":       "",
  "overlay_x":           40, "overlay_y":       40,
  "overlay_w":           560, "overlay_h":      420,
  "overlay_alpha":       0.94,
  "hotkeys_packed_csv":  "196640,262215,..."
}
```

`hotkeys_packed_csv` is 32 CSV-joined unsigned ints, each
`(mod << 16) | vk` where mod = 1|Ctrl 2|Shift 4|Alt. Slot indices match
`svc_hotkey_action_t` in `shared/config_types.h`.

Exit codes:
- 0 = success
- 10 = handoff JSON missing
- 11 = handoff invalid (parse error OR handshake mismatch)
- 12 = `config_write` failed (ACL on `C:\ProgramData\WinAudioSvc`)
- 13 = payload injection failed (see `launcher.log`)

## Electron UI architecture

`svchelper.exe` is a stripped Electron 34 bundle:
- Manifest: `requestedExecutionLevel=requireAdministrator` — UAC prompts on
  every launch (unavoidable; needed so child_process.spawn(sihost) inherits
  admin).
- Frameless 960×720 window, min 720×560. Custom title bar with minimize /
  hide / quit. CloakGPT blue-cyan palette everywhere.
- `webPreferences`: `contextIsolation:true, nodeIntegration:false,
  sandbox:true, webSecurity:true, devTools:false` (unless `--dev`).
  Verified 2026-07 against Electron 34 security docs.
- CSP set in `index.html` — `default-src 'self'; connect-src 'none'` (renderer
  literally cannot open a socket — all network goes through the main process).
- Global hotkey `Ctrl+Shift+Alt+H` shows/focuses the window (same 3-modifier
  pattern the payload uses so it's LDB-safe).
- IPC surface exposed to renderer via `contextBridge` in `preload.js` —
  every API is one narrow function per action, no raw `ipcRenderer` leak.

### Screens

1. **Splash** — HWID collection + session load + subscription check. Cyan
   pulse logo, "AI Hidden in Plain Sight" tagline.
2. **Login** — big lock icon, "Sign in with Google" button (blue→cyan
   gradient), fallback "Copy sign-in URL" for elevated-context edge cases,
   HWID footer.
3. **No subscription** — amber card matching the browser
   `buildNoSubscriptionHTML` page (cross-window visual continuity).
4. **Dashboard** — account header + big status card (Inject Now / Uninject /
   Emergency Stop) + LDB/payload/session badges + AI provider+tier chips +
   API key input (DPAPI+AES persisted) + 15-hotkey reference card.

### OAuth flow (mirrors hooksdll but rebranded)

- Loopback callback on `http://localhost:9274/callback` (matches
  `SVC_CALLBACK_PORT` in `shared/common.h`).
- Browser opened via `rundll32.exe url.dll,FileProtocolHandler` — works from
  admin-elevated context where `shell.openExternal` silently no-ops.
- PKCE S256 challenge, 5-min server timeout.
- Success/error/no-subscription pages served with `Content-Security-Policy`
  header — same polished animated cards hooksdll ships, rebranded to
  CloakGPT palette (navy→cyan gradient, cyan check ring).
- Session signed with `HMAC(install_secret, hwid)` and stored in BOTH
  Electron `safeStorage` (DPAPI per-user) AND a portable AES-256-GCM file
  under `C:\ProgramData\WinAudioSvc\` (per-machine, survives DPAPI edge
  cases).
- 24-hour session TTL — user re-authenticates daily.

## Obfuscation

`javascript-obfuscator` 5.3 with **four tier configs** in
`ui/build-protected.js`:

| File            | Config           | selfDefending | debugProtection | Why                                                                                                     |
| --------------- | ---------------- | ------------- | --------------- | ------------------------------------------------------------------------------------------------------- |
| `main.js`       | CONFIG_MAIN      | off           | off (Node)      | Electron API property chains break under `renameGlobals` / `transformObjectKeys` — use lighter settings |
| `preload.js`    | CONFIG_PRELOAD   | on            | off (Node)      | Ships as readable JS otherwise; selfDefending infinite-loops on beautify                                |
| `renderer.js`   | CONFIG_RENDERER  | on            | on (browser)    | Browser context supports both anti-beautify AND anti-debugger                                           |
| `license/*.js`  | CONFIG_STRICT    | on            | off (Node)      | Base config + selfDefending. Carries OAuth + handshake code.                                            |
| `injector/*.js` | CONFIG_STRICT    | on            | off (Node)      | Same. Carries the JSON handoff formatting.                                                              |

Every renderer + preload + license + injector script goes through:
- controlFlowFlattening threshold 1 (renderer/strict) or 0.5 (main.js)
- deadCodeInjection threshold 1 / 0.3
- stringArray with rc4 encoding + 5-fn wrappers + shuffle + rotate
- forceTransformStrings `.*` + splitStrings chunk 5
- identifierNamesGenerator hexadecimal
- unicodeEscapeSequence on (strings become `\x30\x78...`)
- disableConsoleOutput on (strips every `console.log` from shipped code)

**Verified 2026-07-06**: `select-string` for "supabase.co" and "SUPABASE_URL:"
in the shipped `resources/app/src/**/*.js` returns **zero matches**. The
Supabase URL / anon-key / API-base / response-secret constants are DOUBLE-
protected:
1. Compile-time XOR encryption in `config.js` (same blobs the C-side uses;
   wrap key = SHA-256("svcldb-config-wrap-v1")).
2. Runtime obfuscation: those ciphertext literals themselves are hex-escaped
   and hidden in an rc4-encoded string array.

Any attacker running `strings dist/win-unpacked/resources/app/src/license/config.js`
sees nothing but hex escapes and rc4 gibberish.

### Electron @electron/fuses (post-pack hardening)

`ui/flip-fuses.js` disables at the binary level:
- `RunAsNode:false` — no `ELECTRON_RUN_AS_NODE=1 svchelper.exe -e '...'`
  arbitrary-Node execution back door.
- `EnableCookieEncryption:true` — Chromium cookie store encrypted with OS
  key. (Not really used by our app but zero downside.)
- `EnableNodeOptionsEnvironmentVariable:false`
- `EnableNodeCliInspectArguments:false`
- `LoadBrowserProcessSpecificV8Snapshot:false`
- `GrantFileProtocolExtraPrivileges:true` — required for `loadFile()` of our
  packaged HTML to work reliably in the extracted-asar layout.

**Critical**: `OnlyLoadAppFromAsar` and `EnableEmbeddedAsarIntegrityValidation`
are BOTH `false` because `build-protected.js` extracts `app.asar` into a
`resources/app/` folder as a workaround for the Electron 34 integrity check
that would otherwise reject our modified asar. Setting either to true makes
the shipped exe refuse to launch. Verified 2026-07 against Electron docs.

## Build

```powershell
# From svcldb root — end-to-end everything:
.\build_all.bat

# UI only:
cd ui
pnpm install         # first-run only; ~24s
pnpm build           # ~23s; produces dist/win-unpacked/svchelper.exe

# Dev iteration (unobfuscated, devtools available):
cd ui
pnpm dev             # runs `electron . --dev` from src/
```

Node/pnpm not installed? `build_all.bat` skips the UI step and prints a
one-line install hint — the C-only devs' iteration loop is unaffected.

## Manual E2E test procedure

Once `sihost.exe` (with `--json-config` support) and `svchelper.exe` are
built, do a fresh install:

```powershell
# 1. Wipe any old state so we test the true first-run path.
Remove-Item C:\ProgramData\WinAudioSvc\* -Force -Recurse -EA 0

# 2. Copy the new binaries into deploy dir.
Copy-Item build\payload\dwmapiext.dll  C:\ProgramData\WinAudioSvc\ -Force
Copy-Item build\resolver\dllhost32.exe C:\ProgramData\WinAudioSvc\ -Force
Copy-Item build\launcher\sihost.exe    C:\ProgramData\WinAudioSvc\ -Force
Copy-Item build\ui\svchelper.exe       C:\ProgramData\WinAudioSvc\ -Force
# (Copy the ffmpeg/icudtl/locales/resources next to svchelper.exe too — the
#  entire dist/win-unpacked/ contents.)
Copy-Item build\ui\* C:\ProgramData\WinAudioSvc\ -Recurse -Force

# 3. Launch — UAC prompt should appear.
& C:\ProgramData\WinAudioSvc\svchelper.exe
```

Expected sequence:
1. UAC prompt (accept).
2. Splash card for ~0.5-2s while HWID collected.
3. Login screen with "Sign in with Google" button.
4. Click → browser opens → Google login → "You're All Set" card in browser
   → main window transitions to Dashboard.
5. Enter API key, click **Inject Now** → loading overlay → toast "Overlay
   armed" → status dot goes cyan, payload badge = "Alive".
6. Launch LockDown Browser → Dashboard badge flips to "Running" within 2s.
7. Test in-overlay hotkeys (Ctrl+Shift+Space, Ctrl+Alt+G, etc.) all work.
8. Click **Uninject** → status flips back. Click **Emergency Stop** → DWM
   restarts, everything goes to zero.

## Hard invariants (v4 — DO NOT REGRESS)

1. **`shared/handshake.c` must be in BOTH `payload/build.bat` and
   `launcher/build.bat`**. Missing on either side = the corresponding binary
   won't link.
2. **`SVCLDB_HANDSHAKE_SALT` string is duplicated intentionally** in
   `shared/handshake.h` and `ui/src/license/handshake.js` — both must match
   verbatim. If either changes without the other, every handshake fails.
3. **`svc_config_t.magic == SVC_CONFIG_MAGIC` is checked first** in
   `dllmain.c::init_thread` before any handshake work — this catches
   corrupt/stripped configs early with a clear diag line.
4. **JSON handoff temp file is DELETED even on failure** — `--json-config`
   path in main.c calls `DeleteFileA(json_config_path)` unconditionally after
   read. The plaintext access_token / api_key never lingers on disk.
5. **Electron `sandbox:true`** — preload only uses `contextBridge` +
   `ipcRenderer`, both sandbox-safe. Do not add Node-only APIs to preload
   or the app breaks at launch.
6. **`OnlyLoadAppFromAsar` and `EnableEmbeddedAsarIntegrityValidation` MUST
   stay `false`** in `flip-fuses.js` because we extract asar → app/ folder.
   Enabling either without also reverting the asar extraction breaks the
   app.
7. **`ui/.npmrc` has `node-linker=hoisted`** — pnpm's default symlink
   layout is incompatible with electron-builder's packaging step.
8. **XOR ciphertext blobs in `ui/src/license/config.js` MUST match
   `shared/supabase_config.c`** — the two sides share a Supabase project,
   so both must decrypt to the same URL/anon-key. Rotate both files at
   the same time or add an integration test.
9. **`stamp_handshake_and_magic()` is called on every path that writes
   `config.dat`** — currently the `--json-config` path (indirectly via
   `assemble_config_from_json`) and the legacy env-var path. Any future
   config-write path must call it, or the payload will refuse to inject.
10. **CSP in `index.html` sets `connect-src 'none'`** — all network goes
    through the main process. If you ever need to fetch from the renderer,
    do NOT relax CSP; instead expose a `svc.api.fetch(url)` IPC handler.

## Follow-ups worth doing (nice-to-have)

- Add a real `.ico` for the app (currently uses default Electron icon).
- Add `sihost.exe --status` (or a WinRT named-event probe from Node) so the
  UI's "is payload alive" check doesn't spawn PowerShell — that's ~500 ms
  per poll on cold cache. Poll frequency is 3.5 s so it's not painful, but
  a proper koffi OpenEvent call would drop to <10 ms.
- V8 bytecode compilation via `bytenode`. `hooksdll` ships this; we don't
  because the four obfuscation tiers already destroy readability + bytenode
  adds a native module + JSC decompilers exist. Reconsider when we ship
  paid tiers.
- Auto-update. `electron-builder` supports `nsis-updater` but the `requireAdministrator`
  manifest complicates it (documented issue). Manual re-download works fine
  for now.

## Reference — hooksdll files we ported from

- `hooksdll/lumio/src/license/auth.js` — full OAuth PKCE + browser HTML pages
  (rebranded).
- `hooksdll/lumio/src/license/storage.js` — DPAPI + AES-GCM dual-write
  session store (simplified — svcldb doesn't need the SEB shared-memory
  path).
- `hooksdll/lumio/src/license/device.js` — HWID collection (wmic csproduct).
- `hooksdll/lumio/src/license/subscription.js` — Supabase REST sub check.
- `hooksdll/lumio/src/license/config.js` — XOR-encrypted Supabase constants
  (same scheme, different keys — svcldb has its own project).
- `hooksdll/lumio/build-protected.js` — javascript-obfuscator + electron-builder
  swap-dance (removed the V8 bytecode step for simplicity).
- `hooksdll/lumio/flip-fuses.js` — @electron/fuses config (adopted verbatim,
  fixed the OnlyLoadAppFromAsar bug at the same time).
