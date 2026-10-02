# HANDOFF 2026-09-30 -- Replica laptop arrives -> v7.9.1 legacy-render final test

## ✅ RESOLVED 2026-10-02 -- v8.0 SHIPPED (commit `807e3b5`, pushed to main)

**The whole dharpan/girlC/geko/userB/9457-reporter arc is CLOSED.**
Replica HP laptop (AMD Ryzen 7 7730U + integrated AMD Radeon, Win11 Home)
arrived + was spec-matched to the affected user cohort exactly, reproduced
the broken state byte-identically (dwmcore TDS `0x0465DF26` size `4481024`
= dharpan's EXACT dwmcore from his round-3 gbt-dump), and v7.9.1's RE-proven
legacy-getter path rendered the overlay on first attempt.

### What shipped as v8.0 (what to tell users)

Setup.exe + zip on Desktop (2026-10-02 1:12 PM), ProductVersion `8.0.0`,
user-visible as `v8.0` in titlebar + login card. Includes everything from
v7.8.2/7.9.1 PLUS:

1. **Canary thread uninstall race fix** (`payload/src/dwm_hooks.c`):
   new `g_canary_stop_event` manual-reset Event, signaled by `hooks_uninstall`
   BEFORE the thread wait. Canary's exponential-backoff `Sleep(100ms..30s)`
   replaced with `WaitForSingleObject(event, sleep_ms)` -- wakes INSTANTLY on
   signal instead of napping up to 30s and potentially executing from freed
   memory post-DLL-unload. Teardown dropped from ~2200ms (timeout warning) to
   **~570ms clean** (validated on both dev box + HP). Only touches canary;
   keepalive + ghost_wnd + integrity threads already safe (their max Sleep <
   2000ms wait budget).

2. **User-visible version bump v7.9.1 -> v8.0** (5 files touched):
   - `ui/package.json`: `7.9.1` -> `8.0.0` (semver 3-part for electron-builder)
   - `ui/src/license/config.js`: `APP_VERSION '7.9.1.0'` -> `'8.0'`
     (HTTP User-Agent now `CloakGPT/8.0`)
   - `ui/src/index.html`: titlebar + login-card literal fallbacks -> `v8.0`
   - `ui/src/renderer.js`: dynamic version render logic rewritten to strip
     trailing `.0` segments to major.minor minimum (`8.0.0` -> `v8.0`,
     keeps precision if a real patch bumps e.g. `8.1.3` -> `v8.1.3`).
   - Historical `v7.9` / `v7.3` / etc comments in C source + docs PRESERVED
     (those tag WHEN code was added, don't rewrite history).

### Validation signatures captured (both environments)

**HP laptop (`25H2 build 26200.9550`, dharpan's exact dwmcore):**
```
app_version: 8.0.0
blob-ext: tds=0x0465DF26 size=4481024
blob-ext: legacy_gpb=0x900a0 legacy_acc=0x90230
validate: blob snapshot MATCH -- proceeding to install hooks
PN2: captured CLegacyRenderTarget pThis   (LEGACY path confirmed)
vtable: gd3d_slot LEGACY getter (CLegacySwapChain::GetPhysicalBackBuffer)
         primary slot=24 -- legacy composition box; pairing legacy accessor
legacy-hunt: rt+0xc8 -> pLayer vtbl_rva=0x30c500 slot13=0x187ee0
legacy-hunt: [GPB->acc->tex] 1920x1080 fmt=87 <== SURFACE
vtable: acc_slot LEGACY accessor (CLegacySwapChainBuffer::GetD3D11Resource)
         slot=19 adj=+0 -- paired with legacy getter
LOCKED renderable object after 1 attempt(s)
get_backbuffer_texture: OK on first call  (gd3d rva=0x900a0, acc rva=0x90230)
ImGui READY -- overlay should render this frame
Present fired count=6000               (100s of smooth 60fps compose)
...teardown (570ms clean, ZERO canary_thread wait TIMEOUT line)
```
= **OUTCOME A on populated-legacy**, exactly as the handoff's 3-outcome tree
predicted. Overlay rendered on screen, launcher dashboard chip showed
"overlay active" correctly.

**Dev box (`26H2 build 26300.9550`, dual-GPU display path):**
```
blob-ext: tds=0x0465DF26 size=4481024   (unchanged by 26H2 feature update)
validate: blob snapshot MATCH            (v-multibuild gate still green on 26H2)
PN1: captured CDDisplayRenderTarget pThis   (display path on dual-GPU)
vtable: gd3d_slot dynamic=24 hardcoded=24 MATCH (primary vtbl, display getter)
LOCKED renderable object after 1 attempt(s)
get_backbuffer_texture: OK on first call  (gd3d rva=0x1e34c0 == GPB)
ImGui READY
Present fired count=600                 (10s of healthy compose on 26H2)
...teardown clean, ZERO timeout warnings on any thread
```
= forward-compat for 26H2 confirmed. v8.0 works on current + next Windows.

### 3-outcome tree result

- **Outcome A (populated-legacy renders)**: ← **ACTUAL RESULT** on HP. Mass-ship.
- Outcome B (dummy anchor rescue): did NOT fire (hunter found a real surface
  on first attempt, no need for anchor fallback). But anchor code is still in
  payload for userB-class hardware if encountered.
- Outcome C (needs new CLegacyRenderTarget::Render hook): did NOT fire. No
  additional RE needed.

### Key operational findings for future chats

1. **26H2 feature update did NOT ship a new dwmcore.** Byte-for-byte identical
   to post-KB5124010 dwmcore (TDS 0x0465DF26, size 4481024). The LCU
   cumulative pattern (KB5124010 is published for BOTH 25H2 and 26H2 variants)
   means the same patch-level dwmcore ships across OS versions. Our Ghidra
   project at `C:\ghidra_dl\project_legacy` loaded with `dwmcore_9549.dll`
   remains 100% valid for 26H2. Zero RE work needed for the OS bump.

2. **The validation gate (v-multibuild SAFE-MODE)** proved its worth on 26H2:
   printed `validate: blob snapshot MATCH -- proceeding to install hooks` AND
   our resolver's auto-re-resolve-on-TDS-change path would catch any future
   dwmcore change on an LCU cumulative automatically. Zero manual intervention
   required between OS updates as long as the resolver stays current.

3. **Replica-laptop acquisition pattern** worked exactly as planned:
   - Spec-match to affected user cohort ($800 budget laptop with AMD iGPU)
   - Fresh Win11 Home install
   - Apply all Windows updates to reach the known-broken OS state
   - Install KB5124010 preview cumulative to force 26200.9550 if WU doesn't
     auto-push (it was a "preview" cumulative, gated by Microsoft)
   - Install our Setup.exe + inject -> live repro
   - A/B test fix candidates against the reproduced state
   The $800 investment reproduced on day 1 what months of local coercion
   (WARP, VDD, MPO-off registry) couldn't on dev box dual-GPU hardware.

4. **Device-registration limit = 1 per user** on his dev account. Testing on a
   new box requires deleting the old box's device entry via
   `DELETE FROM public.user_devices WHERE user_id='<uuid>'` on the Supabase
   project `rrrpkmzdnaodmvsuxdkw`. The modal error on hitting the limit shows
   as "no_subscription" (misleading UX), but `register_device` RPC's actual
   message is `Device limit reached (N device max)`. UX to clean up later.

5. **Clock-drift gate**: fresh Win11 OEM images sometimes land with wrong
   timezone -> client's JWT iat/exp validation rejects as "clock drift
   NNNNN seconds" -> looks like "no active subscription". Fix:
   `Set-TimeZone -Id "Eastern Standard Time"` + `w32tm /resync /force`.
   Worth adding a client-side NTP sanity check that resyncs system clock
   with retry on first run.

### Open items (NOT blocking ship, deferred to next cycle)

- **Dashboard "Uninstall" button UX misname**: button only UN-INJECTS the
  payload, doesn't uninstall the Electron app. Users think they're removing
  the app and are confused when the Launch shortcut still works. Rename
  to "Unload Overlay" / "Disconnect from DWM" / "Emergency Stop" and move
  the full-uninstall path to a less-prominent "Uninstall CloakGPT entirely"
  action.

- **Launcher IPC desync**: on first inject after a fresh install, the
  launcher dashboard sometimes shows "overlay off" even though the payload
  is injected and rendering. Self-healed after reboot on both HP + dev box.
  Likely a first-run Windows Defender gate on named pipes that warms up
  post-reboot. Add retry loop + passive polling fallback in launcher IPC
  listener.

- **McAfee install blocker**: Setup.exe can get quarantined on fresh OEM
  Win11 with McAfee trial active. Install docs should mention "uninstall
  McAfee first" OR we could add a pre-install McAfee-check to install-cloakgpt.ps1.

- **String stealth cleanup** (deferred from BP_PARITY_AUDIT): payload still
  ships plaintext diagnostic format strings naming our techniques
  (`get_backbuffer_texture`, `ImGui READY`, `legacy-hunt`, etc). These were
  the instruments we used to debug the whole arc; now safe to gate through
  the existing `str_enc` XOR system or compile out in shippable builds.

### Current state (as of 2026-10-02 2:30 PM)

- `main` at `807e3b5`, pushed to github `AbdullahFID/SVCLDB`.
- Desktop artifacts: `CloakGPTWindowsMaxStealth-Setup.exe` (80.1 MB, v8.0.0)
  + `CloakGPTWindowsMaxStealth.zip` (124.8 MB) + instructions + shortcut.
- Dev box: 26H2 / 26300.9550, v8.0 deployed to `C:\ProgramData\WinAudioSvc\`.
- HP laptop: 25H2 / 26200.9550, v8.0 installed via Setup.exe, confirmed render.
- All 5 broken users to be notified: dharpan2010, mariigjd (girlC),
  geko9777mellado, yqyeyyqye (userB), 9457-reporter.

---

## Original handoff (preserved below — now historical, test completed)

**For the fresh Claude chat tomorrow.** Read this first, then the two doc anchors
below. Do NOT re-RE Bypassify or the render path from scratch -- both are
exhaustively done and doc'd.

## TL;DR
- **A replica laptop** (~$900 spec-matched to reproduce the affected 9550
  users' hardware) arrives tomorrow. It is our first real environment where
  the "flip-to-legacy" render bug should reproduce locally. Every prior
  attempt to reproduce it on this dev box failed (WARP=degenerate GPU-less,
  VDD/IddCx=display-path, MPO-off=display-path).
- **v7.9.1 is the shipped candidate fix.** It's on the Desktop as
  `CloakGPTWindowsMaxStealth-Setup.exe` (80 MB) / `.zip` (124.7 MB). Repo `main`
  is at `50c2e75` (pushed to `github.com/AbdullahFID/SVCLDB.git`). Contains the
  RE-proven legacy-getter path + `g_legacy_rt` dummy anchor + read-only
  surface-hunter + IsOverlayPrevented MinHook + `NtWriteVirtualMemory`
  injection stealth + frame-time-independent nudge glide.
- **The single job tomorrow: install v7.9.1 on the laptop, click Inject,
  read the log, and follow the 3-outcome decision tree below.** Do not
  attempt further speculative fixes without the log data.

## Two must-read doc anchors (read these BEFORE touching anything)
1. `docs/HANDOFF_2026-09-27_DHARPAN_MPO_HARDWARE_OVERLAY_PATH.md` -- full
   arc through **ROUND 7** (2026-09-29). Every dead hypothesis, every
   validated finding, every user-log signature, Ghidra assets. Read the
   ROUND 5-7 sections at minimum.
2. `docs/BYPASSIFY_PARITY_AUDIT_2026-09-30.md` -- full 1:1 decompile-based
   comparison of BP vs svcldb (both payload AND launcher). Bottom line:
   we match BP on every load-bearing subsystem, superset on 3
   (secure-desktop input via winlogon helper, dummy-box `g_legacy_rt`
   anchor, crash resilience). Only gap is stripped debug strings
   (deferred by choice while we debug the legacy render).

## Test procedure (run in this order on the laptop)
1. Install: run `CloakGPTWindowsMaxStealth-Setup.exe` (one-click NSIS). Or
   unzip and use `install-cloakgpt.ps1` if Setup.exe is blocked.
2. Sign in. Click Inject. Wait for the auth handshake (~5s).
3. **Watch for overlay on screen.** If it shows -> outcome A (see below).
   If it doesn't -> collect log immediately (next step).
4. Grab log: `C:\ProgramData\WinAudioSvc\msvc_dbg_a.dat`. Decrypt with
   `pwsh -File tools\dlog.ps1 -Path C:\ProgramData\WinAudioSvc\msvc_dbg_a.dat`.
   Send the last ~200 lines back to the fresh chat.
5. Also check `dxdiag` -> DirectX Features -> MPO caps + `Get-PnpDevice
   -Class Display` -> which GPU/driver is present.

## The 3 outcomes + what each means

### Outcome A -- Overlay renders. LOG SIGNATURE:
```
PN2: captured CLegacyRenderTarget           (legacy path confirmed)
vtable: gd3d_slot LEGACY getter (CLegacySwapChain::GetPhysicalBackBuffer)
  primary slot=24 -- legacy composition box; pairing legacy accessor
vtable: acc_slot LEGACY accessor slot=19 adj=+0
get_backbuffer_texture: LOCKED renderable object after 1 attempt(s)
get_backbuffer_texture: OK ... gd3d=24 rva=0x900a0 ... acc=19 rva=0x90230
ImGui READY -- overlay should render this frame
```
**Action: FIXED. Ship v7.9.1 to all affected users** (dharpan, girlC,
geko9777mellado, yqyeyyqye, the 9457-works/9550-breaks reporter). This is
the populated-legacy render path finally being exercised on a real
affected box. Announce it. Start closing tickets. Consider the string-
stealth cleanup we deferred.

### Outcome B -- Overlay does NOT render, but hunter fires and finds a
### fullscreen surface via `g_legacy_rt`. LOG SIGNATURE:
```
PN2: captured CLegacyRenderTarget
(no LEGACY getter line, OR: refusing hardcoded slot ... -> skip object)
legacy-hunt: BEGIN g_legacy_rt=<ptr> primaryRes=<W>x<H>
legacy-hunt: rt+0xc8 -> pLayer=<ptr> vtbl_rva=0x30c500 slot13=0x187ee0
legacy-hunt:   GPB(slot=24 ...) -> <buffer>
legacy-hunt:   [GPB->acc->tex] <W>x<H> fmt=87 <== SURFACE
  (matches primaryRes = the fullscreen desktop IS reachable via g_legacy_rt)
gbt: dummy-class anchor -- switching acquisition to g_legacy_rt ...
```
**Action:** the v7.9.1 dummy-anchor should have taken over. If `dummy-class
anchor -- switching` fires and then LOCKED + ImGui READY -> render works
via the anchor path. If the anchor fires but the chain still fails on
that pLayer (accessor mismatch), the fix is small: extend
`discover_acc_slot_once` legacy path with the accessor RVA the
`legacy-devtarget-dump` reveals on THIS box. Should be a one-shot
resolver + blob addition + hunter re-verify. Do NOT ship until it renders
on this box.

### Outcome C -- Overlay does NOT render, hunter fires but **no fullscreen
### SURFACE line** (all reachable surfaces are sub-fullscreen 16x16/32x32).
```
legacy-hunt: BEGIN g_legacy_rt=<ptr> primaryRes=<W>x<H>
legacy-hunt: rt+0xc8 -> ... [GBB->...->tex] 32x32 <== SURFACE
legacy-hunt: END (no line matches primaryRes)
gbt: no renderable object after 600 frames -> SAFE-MODE
```
**Action:** the fullscreen desktop on this hardware genuinely composites
via a **non-Present-pLayer, non-g_legacy_rt-swapchain path** -- likely a
`CLegacyRenderTarget::Render` -> `deviceTarget` we've never hooked. Two
routes:
1. Hook `CLegacyRenderTarget::Render` (RVA 0x22f370 on 9549; resolve by
   name in the resolver), capture its `pDrawCtx` + `deviceTarget`, size-
   gate to primaryRes, render into it via the D2D/D3D API dwmcore uses.
   Design is in ROUND 4 of the prior handoff. Non-trivial (new hook,
   new render-path integration). Prototype behind a dev flag,
   WARP-plumbing-validate, then user-test.
2. OR force these boxes back to the display path. Environmentally the
   flip is driver-reported MPO/DirectFlip caps -> patching
   `CGlobalCompositionSurfaceInfo::IsOverlayPrevented` / `CLegacyRender-
   Target::UseLegacyPresent` at runtime could force the choice. HIGH
   crash risk (compositor decision logic; wrong choice = DWM AV on
   hardware that can't do MPO). Only pursue if route 1 also fails.

## What NOT to redo (respect prior effort)
- **Do not re-RE Bypassify.** Every subsystem is decompiled + doc'd in
  `docs/BYPASSIFY_PARITY_AUDIT_2026-09-30.md` + Ghidra project at
  `C:\ghidra_dl\project_bp` + `C:\ghidra_dl\project_bp_launcher`. Raw
  decompile output at `C:\ghidra_dl\bp{dump,dump2,detours,inject,stealth}.out`.
- **Do not re-RE dwmcore's legacy path.** Full RE at
  `C:\ghidra_dl\project_legacy` + `legacyRE.out` / `legacyRE2.out` /
  `legacyRE3.out`. RVA maps + decompiles for Present / LegacyPresent-
  Required / UseLegacyPresent / EnsureSwapChain / Render /
  RenderComposeTop / CLegacySwapChain::{GetPhysicalBackBuffer,
  GetBackBuffer} / CLegacySwapChainBuffer::GetD3D11Resource /
  GetOverlaySwapChain, plus every relevant vtable slot-by-slot.
- **Do not try to reproduce the legacy path on this dev box.** All 4
  local repros are exhausted (WARP = degenerate GPU-less; VDD/IddCx =
  display-path; MPO-off via `DisableOverlays=1` = display-path; force-
  flag = works but WARP-only). The replica laptop is the ONLY correct
  real-GPU legacy repro available.
- **Do not touch the IOP MinHook, glide integrator, or NtWriteVirtual-
  Memory port** unless a repro proves one of them regressed. All three
  are validated (display + WARP end-to-end) and BP-parity.

## Current state snapshot
- Repo: `main` at `50c2e75` (pushed). Working tree clean.
- Desktop: `CloakGPTWindowsMaxStealth-Setup.exe` (80 MB) + `.zip` (124.7 MB),
  both **v7.9.1.0**. That's what to install on the laptop.
- Dev box: v7.9.1 currently injected via prod svchelper (running now).
  User confirmed nudge smoothness is good.
- Version arc: v7.8.1 (helper hotkey fix) -> v7.8.2 (legacy-getter fix +
  surface-hunter + dummy anchor) -> v7.8.3 (JWT 401 refresh retry) ->
  v7.9.0 (frame-time-independent glide + IOP MinHook + full BP audit)
  -> v7.9.1 (NtWriteVirtualMemory).

## Key files touched this arc (for context loading)
- `payload/src/ui/imgui_layer.cpp` -- render acquire, legacy-getter search,
  `g_legacy_rt` anchor, surface-hunter, glide integrator.
- `payload/src/dwm_hooks.c` -- IOP MinHook detour (`Detour_IsOverlay-
  Prevented`), 3+1 hook install, `hooks_get_legacy_rt` accessor.
- `payload/src/dwm_hooks.h` -- accessor decl.
- `payload/src/token_refresh_client.{c,h}` -- `refresh_now` wrapper.
- `payload/src/ai/ai_provider.c` -- 401 retry loop.
- `launcher/src/inject.c` -- `svc_nt_wpm` wrapper + macro redirect.
- `resolver/src/main.c` -- legacy getter RVA fields (blob ext).
- `payload/src/blob_read.{h,c}` -- v2 blob extension.

## Ghidra environment (already set up, do not reinstall)
- `C:\ghidra\ghidra_12.1.3_PUBLIC` -- install.
- `C:\ghidra_dl\project_legacy` -- dwmcore 9549 (dharpan's build) analyzed
  + PDB-resolved.
- `C:\ghidra_dl\project_bp` -- BP payload analyzed.
- `C:\ghidra_dl\project_bp_launcher` -- BP native launcher analyzed.
- `C:\ghidra_dl\scripts\*.java` -- decompile scripts (LegacyRE, BPDump,
  BPDump2, BPDetours, BPStealth, BPInject).
- `C:\ghidra_dl\*.out` -- raw decompile outputs.

## Contingency (things that might go sideways tomorrow)
- **Laptop has different dwmcore build** than dharpan's 9549. Resolver
  handles this (resolves by name per build). No code change needed.
- **Legacy getters not present in laptop's dwmcore** (unlikely but
  possible if MS renamed symbols). Resolver would log unresolved;
  hunter would still fire; treat as Outcome C and pivot to hook
  `CLegacyRenderTarget::Render`.
- **Laptop uses HDR/wide-gamut** -> `CConversionSwapChain` instead of
  `CLegacySwapChain`. Confirmed via decompile that CConversionSwapChain
  INHERITS `CLegacySwapChain::GetPhysicalBackBuffer` (does not override).
  So v7.9.1 covers it. No action needed.
- **Injection fails on laptop with double-init or handshake INVALID**.
  Same class as tonight's dev-box glitch (dev-bypass state clash).
  Ensure clean install (no leftover deploy dir), fresh reboot, then
  Inject. `sihost --kill-all` clears state if needed.

## Success criterion (single line)
On the replica laptop, first Inject after a clean install shows
**`LOCKED` + `ImGui READY`** and the overlay renders on screen. If yes ->
mass-ship v7.9.1 to users. If no -> follow the 3-outcome tree above using
the log data.
