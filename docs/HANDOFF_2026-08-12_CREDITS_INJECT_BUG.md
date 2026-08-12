# HANDOFF: zero-key injection via CloakGPT credits — the four-gate bug (2026-08-12)

Cursor session, requested by Larpbase.

## Question that started it

> "if i dont put manual api keys i cant inject through the svchelper.exe i
> need an manual key which defeats the point ... in api key above openai
> it should say our api key kinda like a block like 'cloakgpt api credits'
> or wtv and injection if no api key is populated uses api credits and
> the ui should reflect and allat"

Then, once the first attempt still ran the dev selftest:

> "self test still ran are u sure u copied the build properly or wtv seems
> like ur failing at such a basic task"

## Short answer

The payload's metered/credits path (`ai_ask_metered` → `svcldb-solve` worker
with the signed-in Supabase JWT) was **already fully wired** in the earlier
`ai-credits` commits (`990ad99`, `116e420`). Zero-key injection was blocked
by **four independent gates**, each of which insisted on a BYO key even
though a valid session was already present:

1. `ui/src/renderer.js` — `btn-inject` click handler (`Enter at least one AI provider API key first.`).
2. `ui/src/main.js` — the main-process `injector:inject` IPC handler (`At least one AI provider key is required.`).
3. `ui/src/injector/injector.js` — `inject()` fail-fast (`No API key configured for any provider.`).
4. `launcher/src/main.c` — `parse_json_config` (`no api key for any provider`).

All four now allow no-key injection when a session token is present
(`currentSess` / `json.access_token` / `cfg->access_token[0]`), so the
payload naturally routes solves through `/solve` on credits. `KILL_ALL`,
`DEBUG_CAP` and the hard-quit path stay hotkey-only.

## The four gates, in detail

### 1. Renderer (`ui/src/renderer.js` ~1660)
Old: any missing key would `toast('err')` and `return` before the IPC call.
New: no-key path shows a friendly *"No API key set: using your CloakGPT
credits."* toast and proceeds. The renderer never blocks on missing keys.

### 2. Main process (`ui/src/main.js` ~1229)
`currentSess` is already required immediately above, so signed-in = credits
available. Old gate returned `{ok:false, err:'At least one AI provider key
is required.'}`. New gate only fails if BOTH no key AND no session — which
is impossible past the `currentSess` check.

### 3. Injector (`ui/src/injector/injector.js` ~575)
`inject()` was fail-fasting with `No API key configured for any provider.`.
Now it accepts no-key when `json.access_token` is populated. Also:
`buildJson` defaults the ACTIVE provider to `PROVIDER.CREDITS` (0) so the
overlay starts on credits; explicit `opts.provider` still wins.

### 4. Launcher (`launcher/src/main.c` ~306)
`parse_json_config` rejected any config with no BYO key. Now it only rejects
if `cfg->access_token[0]` is ALSO empty (impossible after the `access_token`
required-field check just above). Comment updated to explain the credits
path.

## Credits-aware provider cycling (the "verify in the DWM too" ask)

The user asked for the overlay to:
- **display** when credits are the active provider,
- allow **cycling only through providers you actually have keys for**,
- and **cycle back to credits**.

Implemented via a new enum value + a small payload change (no schema bump —
`svc_config_t.provider` is an existing int; value 0 was previously unused):

- `shared/config_types.h`:
  ```
  SVC_PROVIDER_CREDITS = 0,   // metered /solve worker via Supabase JWT
  SVC_PROVIDER_OPENAI  = 1, ... (unchanged)
  ```
- `payload/src/ai/ai_provider.c`: `ai_provider_name(0)` → `"CloakGPT credits"`.
- `payload/src/dllmain.c` — `refresh_status_badge`: when provider is
  `CREDITS`, sets `ui_set_status("CloakGPT credits", tier, "metered", …)`
  instead of calling `ai_get_tier(0, …)` (which returns NULL).
- `payload/src/dllmain.c` — `SVC_HK_CYCLE_PROVIDER`: builds a dynamic list
  `[CREDITS if access_token] + [each provider with a key]`, advances index
  with wraparound. If the list has ≤1 entry it says *"only one option"*
  (or *"no credits session and no API keys configured"* if empty). Never
  cycles you onto a provider whose key you don't have.
- `payload/src/dllmain.c` — ask dispatch: the metered block at ~`dllmain:814`
  is now gated on `cfg->provider == SVC_PROVIDER_CREDITS`. When you're on
  a BYO provider (Ctrl+Shift+P cycled to OpenAI/etc), the metered path is
  skipped entirely and the ask goes straight to your key. Credits-only
  users (no BYO key) always get the friendly message on metered failure —
  never a confusing keyless BYO error.
- `ui/src/injector/injector.js`: `PROVIDER.CREDITS = 0`; `buildJson` defaults
  the ACTIVE provider to CREDITS.

The UI also gains a **"CloakGPT AI credits"** block above the OpenAI key
field showing the live balance + a "Buy more" link, and the section
subtitle now reads *"Optional. Credits used by default."*

## The svchelper "bundled bins keep undoing my fix" trap

**This lost 20 minutes**, so it's worth calling out.

`ui/src/main.js::ensureCBinariesInstalled` (called on every svchelper
launch) copies its **bundled** `sihost.exe` + `dwmapiext.dll` from
`ui/dist/win-unpacked/resources/` into `C:\ProgramData\WinAudioSvc\` when
the deployed copy has a different size/mtime — see invariant "auto-detects
upgrades" in AGENTS.md.

If you rebuild the C launcher (say, from dev-bypass to prod) and
`Copy-Item` the fresh sihost into the install dir, then relaunch
svchelper: `ensureCBinariesInstalled` will happily overwrite your fresh
deploy with svchelper's own **stale** bundled sihost — every launch. That
is exactly why the selftest kept firing even though the deployed sihost
was verified prod at build time.

**Fix / recipe going forward**: whenever you rebuild the C launcher, copy
the fresh `build/launcher/sihost.exe` and `build/payload/dwmapiext.dll`
into BOTH:

1. `C:\ProgramData\WinAudioSvc\` (the runtime install dir), and
2. `ui/dist/win-unpacked/resources/` (svchelper's own bundle),

so `ensureCBinariesInstalled` sees the bundle == deploy and cannot
downgrade you. Alternatively, run a fresh `pnpm build` inside `ui/`
AFTER the C rebuild so electron-builder repackages the fresh bins into
the bundle.

Verify with SHA1: `Get-FileHash build/launcher/sihost.exe`,
`C:\ProgramData\WinAudioSvc\sihost.exe`,
`ui/dist/win-unpacked/resources/sihost.exe` — all three must match.

## Also touched (dev QoL)

- **Dev selftest** (`dllmain.c::selftest_thread_dev`) is `#if
  SVCLDB_DEV_BYPASS_AUTH` — dev-bypass builds spawn it 5s after inject.
  Production builds don't. If a user reports selftest firing, they're on
  a dev-bypass sihost — check `Get-FileHash` and rebuild WITHOUT
  `SVCLDB_DEV_AUTH=1` in the environment.
- **Icons "buns"** = `C:\ProgramData\WinAudioSvc\cg_icons.ttf` missing.
  Redeploy from `shared/fonts/lucide.ttf` and the Lucide font-load
  succeeds (`font: icons = Lucide @ 40px` in the log). This deployment
  should be moved into the installer / packager as a proper ship step.
  **FIXED 2026-08-12 (deployment redo):** `shared/fonts/lucide.ttf` is now
  wired into the ship pipeline in three places so fresh users get real
  icons with zero manual steps:
    1. `ui/package.json` extraResources — `{ from: "../shared/fonts/lucide.ttf",
       to: "cg_icons.ttf" }` → lands in `dist/win-unpacked/resources/cg_icons.ttf`.
    2. `ui/src/main.js::ensureCBinariesInstalled` — a dedicated `assets`
       array (separate from `bins` so a font change never trips the payload-
       uninject upgrade path) copies `resources/cg_icons.ttf` →
       `C:\ProgramData\WinAudioSvc\` on every launch (covers the zip flow).
    3. `ui/build/installer.nsh` customInstall — `CopyFiles` places the font
       at install time so icons are correct on the very first overlay draw,
       before the Electron app has even run (covers the NSIS flow).
  Verified: both `CloakGPTWindowsMaxStealth-Setup.exe` and
  `CloakGPTWindowsMaxStealth.zip` now contain `resources/cg_icons.ttf`
  (853920 B, SHA1 23607A0EEE1417A2FF1BEBDC3EA60C74242BA7B8).

## Files touched

- `shared/config_types.h`
- `payload/src/ai/ai_provider.c`
- `payload/src/dllmain.c`
- `launcher/src/main.c`
- `ui/src/renderer.js`
- `ui/src/main.js`
- `ui/src/index.html`
- `ui/src/injector/injector.js`

## Don't regress

- Never re-introduce a "must have a BYO key" gate anywhere in the inject
  chain — the payload can always solve on credits when a session token is
  present. If you need to enforce a paid-user gate, put it at the
  `/solve` worker, not in the client.
- The metered dispatch (`dllmain.c:814`) is deliberately gated on
  `cfg->provider == SVC_PROVIDER_CREDITS`. Reverting this to always-first
  breaks the "I cycled to OpenAI to use MY key" UX.
- After ANY launcher rebuild, keep `ui/dist/win-unpacked/resources/` in
  sync with the fresh build, or `ensureCBinariesInstalled` will re-install
  the stale bundled bins on the next svchelper launch.
- `cg_icons.ttf` is loaded from disk at
  `C:\ProgramData\WinAudioSvc\cg_icons.ttf`. As of 2026-08-12 it ships
  in the installer + bundle + first-launch copy (see the "Icons buns"
  FIXED note above), so a fresh install always has it. If you ever want
  to eliminate the disk dependency entirely, embed the TTF as a
  compressed C array (`binary_to_compressed_c` → `AddFontFromMemory-
  CompressedTTF`) — but that's a nice-to-have now, not a ship blocker.
