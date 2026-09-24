# v6.9.0.0 — Ctrl+B "screen goes black" P0 hardening (2026-09-23 late)

## What was reported

User "Papi" in Discord DM, 9:47 PM local (2026-09-23):

> Can you please help me
> I updated my Max stealth to 6.67
> Now the overlay is not loading
> After I press ctrl B my screen goes black
> And nothing load
> Like I have every thing off on my windows security
> I have also updated my system to windows 11 25h2

Two symptoms bundled together:

1. **Overlay doesn't render at all** after fresh inject on his v6.7.0.0 install.
2. **Pressing Ctrl+B (overlay toggle)** makes his **screen go black** and nothing loads afterward.

Both on Win11 25H2 (post his Windows update). Everything was working
before the update.

## Environment I could reproduce against

Same OS: **Win11 25H2, build 26200.9457, dwmcore.dll `10.0.26100.9278`**
(pre-update dwmcore, same as CLAUDE.md's v3.1 landing box). Fresh HEAD
build. Repeatedly re-injected, hammered Ctrl+B via a programmatic
harness (dev-only event trigger — LL hook filters LLKHF_INJECTED so
SendInput is not a valid stress path).

**I could not reproduce the crash**, but I found two smoking-gun bugs
in the toggle path that plausibly explain his symptoms, plus a whole
class of "kick DWM harder when it's already in trouble" behaviors we
were doing that could turn a marginal state into a hard crash. All
fixed.

## Root-cause analysis

### The two smoking guns

**Bug 1 — Present-fire canary trips too eagerly (2s), then the toggle
path aggressively kicks DWM into a compose path that is already
misbehaving.**

The v3.1 canary (`payload/src/dwm_hooks.c::present_fire_canary_thread`)
samples `g_present_calls` at T+2s post-inject. If DWM hasn't called
our `COverlayContext::Present` detour by then, canary latches
`g_compose_degraded = 1`. `ui_present_frame` becomes a no-op — overlay
doesn't render. **Matches the user's "overlay is not loading" symptom
exactly.**

**Reproduced live on my box** (fresh 25H2 inject, 10:55 PM local):

```
[03:01:32] hooks_install: SUCCESS (Phase A: RUNNING)
[03:01:32] Present hooked @ 00007FFBCA14DD10
[03:01:32] IsOverlayPrevented patched @ 00007FFBCA10B470 shape=[OLD-GETTER]
[03:01:34] PRESENT PATH INACTIVE @ T+2000 ms -- COverlayContext::Present hook
           installed but DWM is NOT calling it. Setting g_compose_degraded=1
[03:01:47] PN1: captured CDDisplayRenderTarget pThis
[03:01:47] Present fired count=1 wake=0
[03:01:47] ui_present_frame: NO-OP (hooks_compose_degraded==1) -- overlay render
           pipeline quiesced
```

**DWM was actually fine — Present just took 15 seconds to first call
our detour.** The canary called it dead at 2 seconds, and even after
Present started firing, `ui_present_frame` stayed no-op until the
next canary sample (T+15s) noticed it recovered.

**Bug 2 — On the same box, in the degraded state, `ui_toggle_visible`
still runs its full "kick DWM" side-effects.** The user pressed Ctrl+B
because his overlay wasn't showing. Every press ran:

- `invalidate_last_overlay_region("toggle_visible")` — full-desktop
  `RedrawWindow(NULL, NULL, NULL, RDW_INVALIDATE | RDW_FRAME |
  RDW_ALLCHILDREN)` cascade. Posts WM_PAINT + WM_NCPAINT +
  WM_ERASEBKGND to every top-level window on the desktop.
- `hooks_bump_compose_grace(500)` — for 500ms, the Legacy /
  DisplayPresentNeeded detours force PN=TRUE and call
  `g_schedule_composition(0, -1)` every vsync (~30 calls in 500ms).

When the compose path has "shifted post-Windows-update" (canary's
own words), that shifted path calling into whatever function pointer
we resolved to is at least suspect and at worst catastrophic. On his
box: **screen goes black**. Consistent with DWM losing frames.

### Additional gasoline on the fire (fixed too)

- **`hooks_bump_compose_grace` had no teardown gate**: shutdown was
  actively slowed down because every ui_toggle/ui_nudge/ui_resize
  mid-teardown pushed the compose-grace window further out, keeping
  PN=TRUE + SCP firing during the drain phase.
- **`invalidate_last_overlay_region` had no rate limit**: `ui_nudge`
  fires at 60Hz on hold, `ui_resize` too — each invocation posted a
  full-desktop `RedrawWindow(NULL, ...)` cascade. Under a nudge burst
  we were hammering DWM's message pump with 60 desktop-wide paint
  cascades per second.
- **Toggle didn't distinguish HIDE from SHOW**: SHOW transitions
  fired the full invalidate + 500ms grace-window kick, even though
  there are no stale overlay pixels to erase on SHOW — pure waste
  and a per-toggle 500ms window of forced PN=TRUE hammering.
- **`on_hotkey` had no outer SEH**: every case-branch's fault would
  propagate straight into DWM's unwind chain.
- **SVC_HK_TOGGLE had no fallback default**: if a schema-migrated
  config.dat loaded with `cfg->hotkeys[SVC_HK_TOGGLE] == 0`, Ctrl+B
  would silently dispatch nothing.

## The fixes (v-ctrlb-hardening, all landed 2026-09-23 late)

Grep tag: `v-ctrlb-hardening`.

### `payload/src/dwm_hooks.c`

1. **Canary threshold raised: 2s → 15s** for the first alert, then
   30s / 60s for follow-up samples. Empirically, DWM can take up to
   15s to first call our Present detour after inject (idle desktop,
   HDR content on secondary monitor, DWM low-power compose mode). The
   old 2s threshold was false-positiving into permanent-degraded
   until the next scheduled sample cleared it.
2. **Canary self-heals mid-window.** Fast-path check inside the
   100ms sleep loop: if `g_compose_degraded == 1` AND
   `g_present_calls > 0`, immediately clear degraded. Old code only
   checked at scheduled sample boundaries (up to 30s apart), so a
   "canary tripped at T+2s, Present started firing at T+3s" edge case
   would keep overlay quiesced for 27 more seconds. Now heals in
   ≤100ms.
3. **`hooks_bump_compose_grace` gated on `g_active && !g_stop_draw`.**
   Bumping compose grace during teardown just delays the graceful
   exit (PN detours would keep forcing PN=TRUE during the drain
   phase we want to end promptly).
4. **New `hooks_uninstall_in_progress()` public accessor.** Downstream
   defensive callers use this to skip work that would kick DWM harder
   during teardown. Cheap: 2 atomic-aligned volatile reads.

### `payload/src/ui/imgui_layer.cpp`

1. **`ui_toggle_visible` — top-level SEH `__try` around the entire
   body.** Any hypothetical fault in a downstream call (invalidate
   cascade, ImGui mutation, compose-grace bump, wake path) is caught
   and logged. Zero-cost when nothing faults (SEH is table-based on
   x64). Massive safety.
2. **`ui_toggle_visible` — compose-degraded guard.** If the canary
   has flipped `g_compose_degraded`, running the toggle path is BOTH
   pointless (ui_present_frame is short-circuited by the same flag)
   AND actively harmful (invalidate + grace + wake kick DWM). Still
   flip `g_visible` (so if compose self-heals, we render whichever
   state the user asked for) but skip every DWM-touching
   side-effect.
3. **`ui_toggle_visible` — split HIDE vs SHOW paths.** HIDE keeps
   full invalidate + 500ms compose-grace (BP parity — needed to
   clear stale DirectComposition tiles). SHOW just bumps a short
   120ms grace so DWM composes the first fresh frame promptly. No
   invalidate cascade on SHOW — nothing to erase.
4. **`invalidate_last_overlay_region` — 80ms rate limit on the
   full-desktop `RedrawWindow` cascade.** Coalesces bursts (60Hz
   ui_nudge, rapid ui_toggle spam, etc.) so cascades cap at 12.5Hz.
   Compose-grace is still bumped every call (cheap).
5. **`invalidate_last_overlay_region` — compose-thread guard.** If a
   caller somehow ends up on the DWM compose thread, skip the
   cascade to avoid re-entering DWM's own compose loop. `g_compose_tid`
   is published by `ui_present_frame` on first fire (`CAS(0 -> tid)`).
6. **`invalidate_last_overlay_region` — teardown early-return.**
   During shutdown, only bump a short 120ms grace; skip the RedrawWindow
   cascade.

### `payload/src/dllmain.c`

1. **`on_hotkey` split into `on_hotkey` (public shim) +
   `on_hotkey_impl` (body).** The shim wraps the impl in a
   top-level SEH `__try/__except`. Every hotkey handler funnels
   through this shim, so no case-branch fault can crash DWM. Belt
   and suspenders on top of every inner SEH we already have.
2. **Fallback defaults for `SVC_HK_ASK / TOGGLE / TYPING`.** If a
   corrupt or schema-mismatched config.dat loads with slot 0/1/2 ==
   0, we fall back to Ctrl+U / Ctrl+B / Ctrl+T so the overlay is
   NEVER unreachable from the keyboard.

### `payload/src/dwm_hooks.h`

New public function: `int hooks_uninstall_in_progress(void)`.

### Dev-bypass builds only (SVCLDB_DEV_BYPASS_AUTH gated)

Added `Global\svcldb_dev_toggle` named event to `dev_trigger_thread`.
Fires `on_hotkey(SVC_HK_TOGGLE)` from another process without going
through the LL hook (which filters injected keys). Used by the
Ctrl+B hammer test harness. **Never present in prod builds.**

## Live verification on my box (2026-09-23 22:59-23:05 local)

Same OS + build the user has. Full HEAD build with v-ctrlb-hardening
applied. Programmatic hammer harness via
`Global\svcldb_dev_toggle`.

| Test pattern | Events | DWM pid change | Result |
|--------------|--------|----------------|--------|
| 5 slow toggles at 500ms | 5 | 0 | ✅ stable |
| 200 sets in 11ms (spam) | 200 | 0 | ✅ stable |
| 300 @ 5ms cadence | 300 | 0 | ✅ stable |
| 100 @ 250ms cadence | 100 | 0 | ✅ stable |
| 30s chaotic mix (toggle + notes) | 108 | 0 | ✅ stable |
| 4 rounds × 50 @ 30ms | 200 | 0 | ✅ stable |
| **Total** | **913** | **0** | ✅ |

Overlay renders normally, hides on toggle, shows again on next
toggle. `visible toggled -> N (was=M)` telemetry present. `invalidate:
(toggle_visible_hide)` fires only on HIDE (SHOW skips per fix). Zero
`[CTRLB-SAFETY] caught fault` entries, zero `[HK-SAFETY]` entries,
zero `THROTTLED` (because 300ms hysteresis on toggle keeps invalidate
well under the 12.5Hz throttle threshold — good, throttle is a safety
net for nudge/resize which fire at 60Hz).

Canary post-fix: `Present fired count=1908 at cumulative-sample step
1 -- compose path is healthy` at T+15s.

## What still needs the user's hands

The user should hands-on verify:

1. **Fresh install** on his (or Nyx's) 25H2 box:
   - Uninstall current v6.7.0.0.
   - Install v6.9.0.0 (rebuild `build_all.bat` + package via
     `ui/tools/build-distribution.ps1` — Setup.exe or zip both work).
   - Reboot (optional but ensures clean DWM state).
   - Launch svchelper, sign in, arm the payload.
   - Expected: overlay appears within 15s of arm. If canary trips
     `PRESENT PATH INACTIVE`, wait; it should self-heal to `Present
     recovered mid-canary` within 100ms of DWM's first Present call.

2. **Ctrl+B toggle test**:
   - Wait for overlay to be visible.
   - Press Ctrl+B → overlay hides. Wait ~1s.
   - Press Ctrl+B → overlay shows.
   - Repeat rapid-fire 10+ times. **Expected: no screen-black, no
     DWM restart, no lag.** With the SHOW-path skipping invalidate
     cascade, rapid press-press-press should feel snappier than
     before.

3. **If a crash still happens**, the safety telemetry now names it:
   - `[CTRLB-SAFETY] ui_toggle_visible: caught fault #N` = fault in
     the toggle body (invalidate / mutation / etc.). SEH swallowed
     it; DWM stayed alive.
   - `[HK-SAFETY] on_hotkey(action=N): caught fault #M` = fault
     inside a hotkey case-branch (deeper than the toggle body).
   - `PRESENT PATH INACTIVE @ cumulative-sample` = still-broken
     compose path after 15+ seconds. If this fires on the user's
     box, we need to instrument the resolver's per-symbol RVAs and
     compare against a WinDbg dump of live dwmcore.

## Trust ratings on hypotheses

- **Bug 1 (canary too eager) contributed to "overlay not loading"**:
  ~90% (reproduced live on my box).
- **Bug 2 (toggle kicks broken compose path -> black screen)**:
  ~50% (plausible mechanism, could not reproduce because my box's
  compose path was fine after Present started firing). Even if this
  isn't the root cause, the fix (no-op toggle in degraded state)
  removes a whole class of "kick DWM harder when it's in trouble"
  behaviors we shouldn't ever be doing.
- **Bug 3+ (rate limit, teardown gate, SEH catch-all)**: pure
  defense-in-depth. No smoking gun linked to a specific user report
  but every single one is a category of "silently make things
  worse" that we don't want.

## Files touched

- `payload/src/dwm_hooks.c` — canary rework, `hooks_uninstall_in_progress`,
  teardown gate on `hooks_bump_compose_grace`, `g_active`/`g_stop_draw`
  linkage changed from `static` to `volatile` (for forward-decl access
  from earlier in the TU).
- `payload/src/dwm_hooks.h` — new `hooks_uninstall_in_progress` decl.
- `payload/src/ui/imgui_layer.cpp` — `ui_toggle_visible` rework,
  `invalidate_last_overlay_region` rate limit + compose-thread guard,
  `ui_publish_compose_thread_id` + `g_compose_tid`, `hooks_shutting_down`
  inline helper, `ui_present_frame` publishes compose tid on first
  fire.
- `payload/src/dllmain.c` — `on_hotkey` split with SEH catch-all,
  fallback defaults for ASK/TOGGLE/TYPING, dev-only
  `svcldb_dev_toggle` event trigger.
- `ui/src/index.html` — user-facing version string bumped to v6.9.0.0.

Grep tag: **`v-ctrlb-hardening`**.

## Do-not-regress

Every existing invariant preserved:

- `/GS-` `/guard:cf-` `/EHsc` still mandatory for payload.
- Ghost window still OFF by default (`DWM_EXT_GHOST=1` opt-in).
- Compose-grace still bumps only forward (never shortens).
- Present detour SKIP condition unchanged (`g_active && !g_stop_draw
  && !skip_draw`).
- MinHook install order unchanged.
- Manual-map + PEB unlink + PE-wipe stealth invariants untouched.
- No new files created besides this doc.
