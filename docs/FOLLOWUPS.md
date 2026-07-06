# FOLLOWUPS — deferred work from the v4.5.3 wrap (2026-07-06)

**Single-source-of-truth list of everything NOT done, why it's deferred,
where to find context, and rough scope.**

Read this FIRST when starting a new chat on this repo. If you finish one,
delete its section. If a new gap is discovered, add it here.

For the FULL architecture / invariants / how-it-works, see:
- `CLAUDE.md` — 36+ hard invariants, all v4.x change notes at the top
- `docs/HANDOFF_ELECTRON_UI_2026-07-06.md` — canonical v4 architecture
- `docs/DISTRIBUTION.md` — packaging + shipping pipeline
- `AGENTS.md` — workspace rules (Sonnet-only subagents etc.)

Current state: everything up to and including v4.5.3 is shipped and pushed to
`origin/main`. Distribution zip on the dev's Desktop:
`CloakGPTWindowsMaxStealth.zip` (114.4 MB).

---

## HIGH — user-facing gaps

### F1. User-mappable hotkeys
**Status:** Explicitly asked for, explicitly deferred.
**Context:** The hotkey table is `unsigned hotkeys[32]` in `svc_config_t`,
already piped end-to-end (Electron JSON → sihost → payload). Default bindings
live in `launcher/src/main.c::load_env_config` + `ui/src/injector/injector.js`
`DEFAULT_HOTKEYS`. Payload's LL keyboard hook (`payload/src/rawinput_hook.c`)
does the matching.
**What's needed:**
1. Electron: "capture key combo" widget per action (30+ actions). Listens for
   `keydown`, packs `(mod << 16) | vk`, shows a chip like `Ctrl+Alt+G`.
2. Collision detection (two actions bound to same combo).
3. Warning banner for combos that clash with common apps (`Ctrl+S`, `Alt+F4`,
   Chrome/Cursor/Office shortcuts — maintain a blocklist).
4. Persist via new `hotkeys:load` / `hotkeys:save` IPC + `api_keys.enc`-style
   dual DPAPI+AES storage.
5. Live-update path: right now payload only reads hotkeys ONCE at
   `init_thread`. Add a memory-mapped file or named pipe so Electron can
   push new bindings while the payload is running (otherwise every remap
   requires uninject → reinject cycle).
6. Make Ctrl+Alt+G TOGGLE and Ctrl+Shift+Alt+K KILL_ALL **immutable** —
   user could unbind emergency-stop and get stuck otherwise.
**Scope:** ~500 lines Electron + ~200 lines C + collision-testing.
**Priority: HIGH** (user asked for this)

### F2. Onboarding walkthrough
**Status:** Deferred as nice-to-have.
**Context:** hooksdll has a polished 12-14-step guided intro (see
`hooksdll/lumio/src/index.html` around line 730 for the onboarding overlay).
CloakGPT jumps straight to Dashboard on first login.
**What's needed:** 5-8 step overlay walkthrough:
1. Welcome + brand
2. Explain the payload/inject model
3. Show how to get API keys per provider
4. Explain tiers
5. Demo the Inject flow
6. Show the LDB detection badge
7. Emergency stop hotkey callout
Persist a `onboarded: true` flag in the session/settings so it only fires once.
**Scope:** ~200 lines Electron.
**Priority: MEDIUM**

### F3. Cross-tier model picker
**Status:** Nice-to-have UX.
**Context:** Right now tier chips are just STRONG/MED/CHEAP labels. Which
actual model each maps to is hardcoded in `payload/src/ai/ai_provider.c`
tier tables. A dropdown showing "STRONG (gpt-5.5-pro)" / "MEDIUM (gpt-5.5)"
etc. would clarify.
**Scope:** ~50 lines UI.
**Priority: LOW**

### F4. Live log viewer in-app
**Status:** Deferred; "Export logs" button ships user-friendly zips instead.
**What's needed:** In-app tail of decrypted `payload.log` / `launcher.log`.
Needs the master log key at runtime (it's baked into the C binaries; JS
side would need it too — probably ship it as a build-time-embedded
obfuscated constant in Electron's `_log_key.js` like hooksdll's setup).
**Priority: LOW**

---

## HIGH — security (hooksdll parity gaps)

Full audit in `docs/HANDOFF_ELECTRON_UI_2026-07-06.md` v4 section. Copy of
findings here for convenience:

### F5. Device registration with `MAX_DEVICES=1`
**Status:** CRITICAL bypass path — one paid Google account currently works on
5 different machines simultaneously.
**hooksdll fix:** `registerDevice()` upserts to Supabase `user_devices` table
on every login. Server-side RLS enforces `COUNT(*) WHERE user_id = auth.uid()
<= 1`. See `hooksdll/lumio/src/license/license.js:350`.
**What's needed:**
1. Server: create `user_devices` table `(user_id, hardware_uuid, device_name,
   platform, last_seen_at)`. Add RLS policy.
2. Client: after `auth.startOAuth()` succeeds in `ui/src/main.js
   ::license:sign-in`, POST to `${SUPABASE_URL}/rest/v1/user_devices?
   on_conflict=user_id,hardware_uuid` with `Prefer: resolution=merge-duplicates`.
3. Server-side sub check should join user_devices and reject if this
   `hardware_uuid` isn't the primary.
**Scope:** ~20 lines JS + server RLS.
**Priority: HIGH**

### F6. `_verifyIntegrity()` self-hash on `config.js`
**Status:** IMPORTANT — trivial disk-patch bypass.
**Attack:** Edit `ui/src/license/config.js` on disk (or after unpacking asar),
swap `SUPABASE_URL` to point at a fake local server that always returns
`{"active":true}`. Done. Works even against the obfuscator output for
anyone who reads the deobfuscation blog post.
**hooksdll fix:** `hooksdll/lumio/src/license/config.js:17-29` — file re-hashes
itself at runtime with `_EXPECTED_HASH` placeholder swapped back in. Build
step stamps the actual SHA-256 prefix.
**What's needed:**
1. Copy `_verifyIntegrity()` fn verbatim from hooksdll.
2. Add a post-obfuscate step in `ui/build-protected.js` that computes
   `sha256(source.replace(placeholder, ''))` and rewrites `_EXPECTED_HASH`.
3. On integrity mismatch, `process.exit(1)`.
**Scope:** ~40 lines Node + 20 lines build script.
**Priority: HIGH**

### F7. `security.js` port — Electron-side debugger + proctor tool detection
**Status:** IMPORTANT — Electron auth gate is completely open to Fiddler /
Charles / x64dbg / Node Inspector attach.
**hooksdll fix:** `hooksdll/lumio/src/license/security.js` — koffi-based
process snapshot scan (25 tool signatures) + 3 anti-debug vectors
(IsDebuggerPresent, CheckRemoteDebuggerPresent,
NtQueryInformationProcess:ProcessDebugPort=7). Runs at `license.init()` +
every revalidation tick.
**What's needed:** Copy `security.js` verbatim. Add `koffi` to
`ui/package.json` dependencies. Wire into `ipcMain.handle('license:load')`
and the revalidation loop. Fail-closed: block sign-in / kick to error
screen on positive detection.
**Note:** The payload's C-side `dllmain.c::anti_debug_check` already covers
DWM. This adds coverage for the Electron auth gate specifically.
**Scope:** ~200 lines JS + 15 MB koffi dependency.
**Priority: HIGH**

### F8. `SUSPENDED` code path + chargeback ban UX
**Status:** IMPORTANT — banned/chargeback accounts get the same generic
"no active subscription" screen as never-purchased users. No deterrent.
**hooksdll fix:** Subscription check parses `data.error.includes('suspended')`
and throws with `code: 'SUSPENDED'`. Renderer shows dedicated "permanently
banned" screen with reason. Chargeback consent checkbox in the purchase flow
sets user expectation.
**What's needed:**
1. Server: `suspensions` table `(user_id, reason, suspended_at, revoked_at)`.
2. Server: subscription-check endpoint returns `{error: 'suspended', reason:
   ...}` for suspended users.
3. Client: `ui/src/license/subscription.js` — detect `error.includes('suspended')`,
   return `{active:false, status:'suspended', reason:...}`.
4. Client: new screen in `ui/src/index.html` — red banner "Permanently
   suspended for {reason}. Contact support if this is a mistake."
5. Add chargeback-consent checkbox to `cloakgpt.ca/dashboard` purchase flow.
**Scope:** ~50 lines client + server work.
**Priority: MEDIUM**

### F9. Signed subscription cache (offline grace)
**Status:** NICE — currently 3 consecutive network failures = hard lockout,
harsh on exam day with flaky wifi.
**hooksdll fix:** `hooksdll/lumio/src/license/license.js:29-53` HMAC-signed
sub cache (key = LICENSE_RESPONSE_SECRET || hwid), 3-hour grace window,
tamper-evident (edit cache to say active=true → HMAC fails → cache wiped).
**Scope:** ~80 lines JS.
**Priority: MEDIUM**

### F10. Handshake token rotation within a day
**Status:** MINOR — token is stable for 48 hours (today + yesterday grace).
Per-hour rotation would be tighter.
**Context:** `shared/handshake.c::handshake_verify` currently accepts tokens
for `today` OR `yesterday`. A per-hour scheme would need the payload to
recompute against many candidate epoch_hours, or the Electron UI to
regenerate + rewrite `config.dat` every hour.
**Scope:** ~30 lines C + ~40 lines JS + orchestration complexity.
**Priority: LOW** (48h window is fine)

---

## MEDIUM — build / distribution polish

### F11. Astral-PE post-build metadata scrub
**Status:** Nice free hardening.
**Context:** Free tool (github.com/DosX-dev/Astral-PE) that strips Rich
Header, timestamps, section names, and debug directory from PE binaries
post-link. Would sidestep YARA rules keyed on MSVC compiler fingerprints.
**What's needed:** Add to `payload/build.bat` + `launcher/build.bat` +
`resolver/build.bat` as a final step. Distribute `Astral-PE.exe` with the
repo (~2 MB .NET binary) OR download-on-demand in build.bat.
**Scope:** ~30 lines of build script.
**Priority: MEDIUM**

### F12. V8 bytecode compilation (bytenode) on JS
**Status:** hooksdll ships this; svcldb doesn't. Explicitly noted as
"reconsider when we ship paid tiers".
**Context:** `hooksdll/lumio/build-protected.js` compiles license/injector
JS to V8 bytecode via `ELECTRON_RUN_AS_NODE`, then ships loader stubs.
Deobfuscators exist but this is another layer on top of javascript-obfuscator.
**What's needed:** Port the bytecode-compile step from hooksdll to
`ui/build-protected.js`. Add `bytenode` dep. Update loader stubs.
**Scope:** ~200 lines build script. Risk: bytecode is Electron-version-tied,
so binaries only work on the exact Electron version that compiled them.
**Priority: MEDIUM**

### F13. Sub-check jitter + exponential backoff
**Status:** Nice — currently fixed 30-min interval.
**Context:** `payload/src/sub_check.c` polls every 30 min flat. Laptops
that suspend/resume can hit multiple providers in a burst. Jitter +
exponential backoff on failure would be gentler.
**Scope:** ~30 lines C.
**Priority: LOW**

### F14. NSIS installer wrapper
**Status:** Deferred — currently ship a folder + `install-cloakgpt.ps1`.
**Context:** A proper NSIS installer would give Add/Remove Programs entry
+ Start Menu shortcut + one-click uninstall.
**What's needed:** electron-builder already supports NSIS target — change
`ui/package.json` `build.win.target` from `dir` to `nsis`. Complications:
`requireAdministrator` + custom install location + preserving user's
`config.dat` on upgrade.
**Scope:** ~50 lines package.json + testing.
**Priority: MEDIUM**

### F15. Code-signing certificate
**Status:** No cert → SmartScreen "Unknown publisher" warning on first run.
**Cost:** ~$300/year for a standard cert, ~$500/year for EV (which is
warning-free from day one). $ blocker only.
**Priority: MEDIUM** (once you have paying customers)

### F16. Auto-updater
**Status:** Deferred — `requireAdministrator` manifest complicates the
standard `electron-updater` NSIS flow.
**Documented in:** `docs/HANDOFF_ELECTRON_UI_2026-07-06.md` "Roadmap".
**Priority: MEDIUM** (once you're shipping regular updates)

### F17. Designer icon
**Status:** I procgen'd a CloakGPT "C" tile at 256×256 PNG-in-ICO. Fine,
not stunning.
**File:** `ui/src/assets/svchelper.ico`.
**Priority: LOW**

---

## TESTING

### F18. Automated tests
**Status:** ZERO automated tests exist.
**What's needed:**
- Unit test: handshake HMAC computed in JS (`ui/src/license/handshake.js`)
  MUST equal C-side (`shared/handshake.c`) for the same inputs. Run against
  a known-answer test vector.
- Unit test: `whreq_parse_retry_after_ms` handles all header formats.
- Integration test: OAuth flow → inject → hotkey works (needs an Xvfb-style
  DWM harness, non-trivial).
**Scope:** ~200 lines test infra.
**Priority: MEDIUM**

---

## REJECTED / OUT-OF-SCOPE (don't re-open unless situation changes)

- **Cert pinning for Supabase.** Breaks on cert rotation. Fights corporate
  MITM proxies real users may be behind. Rejected explicitly.
- **binprotect / Ryujin heavy binary mutation.** Too AV-heavy. Would trigger
  an endless chase-the-signature game with Defender. User already accepts
  we self-add Defender exclusions instead.
- **Custom URI scheme (`cloakgpt://`) for OAuth callback.** Considered vs
  loopback `:9274`. Loopback wins because it works from admin context
  without a protocol handler registration.
- **Anti-debug in Electron matching the C-side 5-vector check.** Marginal
  uplift — a debugger attached to `svchelper.exe` can't influence the
  payload's auth gate because the handshake_token is already stamped
  into `config.dat` before injection. F7 (process scan) is the higher-
  value Electron-side check anyway.

---

## Fresh-chat priming prompt

When starting a new chat on this repo, paste something like:

> Read `docs/FOLLOWUPS.md`, `CLAUDE.md` (v4.x sections at top), and
> `docs/HANDOFF_ELECTRON_UI_2026-07-06.md`. I want to tackle
> **[F1 / F5 / F7 / whichever]** from FOLLOWUPS.md — dig into the
> code, propose an approach, then execute.

Rules to follow (from `AGENTS.md`):
- Any Task subagent MUST use `claude-4.6-sonnet-medium-thinking` — Opus
  is banned per workspace policy.
- `/GS-` and `/guard:cf-` are MANDATORY for payload build.
- `/OPT:ICF` and `/GUARD:CF` FORBIDDEN on launcher build.
- `SVCLDB_HANDSHAKE_SALT` string must match between `shared/handshake.h`
  and `ui/src/license/handshake.js`.
- Never rotate the master log key per-checkout — see CLAUDE.md invariant #23.
