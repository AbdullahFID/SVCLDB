# HANDOFF 2026-09-27 — dharpan2010@gmail.com hardware-overlay (MPO) render path

## TL;DR

`dharpan2010@gmail.com` has been unable to render the CloakGPT overlay for
weeks. Root cause is now **definitively identified** and it is **not** any of
the things earlier chats hypothesized (dwmcore build drift, MI this-adjust,
one-shot discovery race, stuck old payload). His DWM composition path is the
**hardware-overlay / MPO (Multi-Plane Overlay)** path — same dwmcore binary
as ours, but the runtime object handed to our `COverlayContext::Present` hook
is a different subclass whose `CDDisplaySwapChain::GetPhysicalBackBuffer`
method **returns NULL by design** because that context has no physical
backbuffer to hand out (the GPU composites via dedicated overlay planes
instead of drawing into a shared buffer).

**No variation of "call GetPhysicalBackBuffer with a different `this`" or
"try more objects" can fix this.** The method is null-returning on his
context. We need a **different render-target acquisition path** on his
box, driven by a **different hook target**.

**Recommended next action, in order:**

1. **Ghidra RE `dwmcore.dll`** (build 26100.9549 / TDS 0x0465DF26, on the
   host at `C:\Windows\System32\dwmcore.dll`; a dump is also at
   `hooksdll/dwm/dwmcore_clean.dll`). Trace what `COverlayContext::Present`
   dispatches to on a hardware-overlay context, and identify the correct
   render-target acquisition (i.e., which object's backbuffer we can
   actually get). Details in **§6 "Ghidra plan"** below.
2. **Then implement Path 1: additional hook on `CDDisplayRenderTarget::Present`
   (RVA 0x2301D0, already resolved by the resolver, sitting unused).**
   Its `this` is a `CDDisplayRenderTarget` with a real backbuffer at
   slot 24 (verified acquisition semantics same as our current chain on
   the primary path — need Ghidra to confirm for his box). When
   `COverlayContext::Present`'s chain NULLs, fall through to rendering
   via the `CDDisplayRenderTarget` hook's `this`.

Before implementing, **verify against this handoff + the raw transcript +
the raw logs**. Do not act on hypotheses alone — this problem has burned
two chats' worth of investigation on wrong hypotheses.

## 1. Where the data lives

### 1a. This handoff
`docs/HANDOFF_2026-09-27_DHARPAN_MPO_HARDWARE_OVERLAY_PATH.md` (this file).

### 1b. Full conversation transcript (Cursor)
`C:\Users\abdul\.cursor\projects\c-Users-abdul-Desktop-svcldb\agent-transcripts\319ef726-19a8-4e27-98e3-2dc4797180b8\319ef726-19a8-4e27-98e3-2dc4797180b8.jsonl`

The transcript walks through: initial (wrong) hypothesis about MI
this-adjust, the retry-discovery attempt, the deep-hide stuck-key fix
(unrelated, landed cleanly), the Shift-passthrough fix (unrelated, landed
cleanly), the inject-supersede fix (unrelated, landed cleanly), and the
final definitive diagnosis from the third log round. Reading it is
strongly recommended to avoid re-deriving what has already been ruled out.

### 1c. Raw dharpan logs (three rounds)
| Round | Directory | Notes |
|---|---|---|
| 1 (7.6.0 test) | `_incoming_logs_2026-09-26/` | dharpan's first 7.6.0 test. One-shot lock picked "bad" object (slot 28 secondary this_adj=+8), silent NULL. HWID `2B618DFF...520A`. |
| 2 (7.6.1 install, payload didn't take over) | `_incoming_logs_2026-09-27/` (a) | dharpan installed 7.6.1 but the 7.6.0 payload was still stuck in `dwm.exe` pid=1580 for 13 hours (see §5). No 7.6.1 payload code ran. |
| 3 (fresh Windows reinstall + 7.6.1) | `_incoming_logs_2026-09-27c/` | **THE definitive round.** New HWID `b07fca57...aeea` (clean reinstall — same person, fresh install). 7.6.1 payload actually ran, retry-discovery + gbt-dump + SAFE-MODE all executed as designed. This is what §2 dissects. |

**All decrypted via** `pwsh -File tools/dlog.ps1 -Path <path>/msvc_dbg_a.dat`.

### 1d. Prior handoffs (upstream context)
- `docs/HANDOFF_2026-09-21_POST_WINDOWS_UPDATE_OVERLAY_INVISIBLE.md` — RESOLVED, dwmcore TimeDateStamp drift. **Different bug.**
- `docs/HANDOFF_2026-09-24_MULTIBUILD_UNIVERSAL_SUPPORT.md` — SAFE-MODE + blob v2 validation. **Working as designed on dharpan's box** — it correctly tripped SAFE-MODE when render couldn't proceed.
- `docs/HANDOFF_2026-09-20_OVERLAY_DIES_ON_EXPLORER_RESTART.md` — RESOLVED, MPO plane drop on explorer restart. **Related in kind (also MPO-adjacent) but different mechanism.**

## 2. Definitive diagnostic data (round 3, 7.6.1 payload actually ran)

From `_incoming_logs_2026-09-27c/msvc_dbg_a.dat`, session `pid=1560`,
2026-09-27T17:08:03Z, **7.6.1 payload actually initialized this time**
(confirmed by presence of `LOCKED` / `gbt-dump` / `SAFE-MODE` diag lines
that only exist in 7.6.1's code):

### 2a. Full render path (decrypted)

```
17:08:03.663  early: init_thread: handshake ok
17:08:03.663  dwm: hooks_install: entered
17:08:03.679  dwm: Present fired count=1 wake=0
17:08:03.726  ui: vtable: gpb_slot dynamic=5 hardcoded=5 MATCH (primary vtbl)
17:08:03.726  dwm: hooks_install: SUCCESS (Phase A: RUNNING)
17:08:03.726  ui: vtable: gd3d_slot dynamic=28 hardcoded=24 DRIFT
              (secondary (MI) vtbl=00007FF95AB4B490 this_adj=+8) -- using dynamic
17:08:03.726  ui: gbt: NULL at GD3D call (slot=28 adj=+8 ret=0000000000000000)
17:08:03.726  ui: get_backbuffer_texture returned NULL (first miss)
17:08:04.192  dwm: Present fired count=60
17:08:08.694  dwm: Present fired count=600
17:08:08.725  ui: get_backbuffer_texture: no renderable object after 600 frames
              (gpb=5 gd3d=28) -> SAFE-MODE (compose_degraded=1). Overlay
              quiesced, DWM stays alive. See gbt-dump above for this box's
              slot->symbol map.
17:08:08.725  hooks_force_compose_degraded: SAFE-MODE tripped externally
17:08:08.725  ui: ui_present_frame: NO-OP (hooks_compose_degraded==1)
17:08:09.856  dwm: Present recovered: count=738 -- compose path healed
              (this line means the compose-degraded canary auto-recovered
              because Present is firing; the SAFE-MODE from
              get_backbuffer_texture is independent and still active)
```

### 2b. His `pLayer` object layout (gbt-dump, definitive)

```
pLayer=0000022EBAEFD618  primary_vtbl=00007FF95AB4C500
dwmcore_base=00007FF95A840000  size=4481024

Primary vtable entries that match a known dwmcore symbol:
  primary[5]   rva=0x1d3e60 == getDevice
  primary[82]  rva=0x1d3e60 == getDevice
  primary[143] rva=0x1d3e60 == getDevice

Secondary vtable @ pLayer+8   = 00007FF95AB4B490
  sec[+8][9]   rva=0x1d3e60 == getDevice
  sec[+8][28]  rva=0x1e34c0 == getPhysicalBackBuffer   <-- THE ONLY ONE

Secondary vtable @ pLayer+232 = 00007FF95AB4C6A8
  sec[+232][29] rva=0x1d3e60 == getDevice
  sec[+232][90] rva=0x1d3e60 == getDevice

Secondary vtable @ pLayer+256 = 00007FF95AB4C6A0
  sec[+256][30] rva=0x1d3e60 == getDevice
  sec[+256][91] rva=0x1d3e60 == getDevice
```

Notes:
- The dumper only logs slots whose function pointer resolves to a
  **known dwmcore symbol** (i.e., a name from `offsets.blob`). All other
  entries — including any adjustor thunks and any function without a
  resolved name — are silently skipped. That's why primary[24] is
  absent from the dump: it's either NULL, outside dwmcore, or points to
  an unknown-symbol function. **Do not assume primary[24] is safe to
  call blind on his box — it might be anything.** RE it before calling.
- The three secondary vtables (+8, +232, +256) match the layout of a
  `CDDisplaySwapChain` (or similarly-shaped class) with multiple MI
  bases. This is consistent with dharpan's Present hook's `this` being
  something like a `COverlayContext` that OWNS a swapchain subobject at
  +8, or IS a multiply-inherited swapchain wrapper.
- `dwmcore size=4481024` — **byte-identical to our (working) box's
  dwmcore**. Same binary, same RVAs, same function signatures. It is
  **not** a Windows patch drift, PDB drift, or dwmcore version issue.

### 2c. Comparison with our (working) box

On this dev machine (2026-09-27, pid=39880, 7.6.1 payload):
```
LOCKED renderable object after 1 attempt(s)
  (gpb_slot=5 adj=+0  gd3d_slot=24 adj=+0  acc_slot=19 adj=+0)
get_backbuffer_texture: OK on first call
  (gpb_slot=5 adj=+0 rva=0x1d3e60 (== getDevice)
   gd3d_slot=24 adj=+0 rva=0x1e34c0 (== getPhysicalBackBuffer)
   acc_slot=19 adj=+0 rva=0x1f6f50 (== getD3D11Resource)
   qi=00007FFBA06C1A50  tex=000001D684971360)
```

**Our box: `GetPhysicalBackBuffer` is at PRIMARY slot 24, adj=0. His box:
NOT in primary at all — only at secondary +8 slot 28, and calling it
returns NULL.** Same dwmcore, different runtime object type.

## 3. What has already been tried (what worked, what failed, don't retry)

| Fix | Ships in | Status on dharpan's box |
|---|---|---|
| MI this-adjust (walk MI vtables, call with correct subobject `this`) | 7.6.0 | Correctly finds gd3d at sec+8 slot 28 with this_adj=+8. Calls the right function with the right `this`. **Returns NULL — no fault of the this-adjust.** |
| Retry-until-renderable + lock (skip "bad" objects until a good one appears, then freeze) | 7.6.1 | Retries 600 frames. **Same object every frame, same NULL.** Falls back to SAFE-MODE as designed. His box only produces this one object type — retry has no alternative to switch to. |
| Read-only `gbt_dump_layout_once` diagnostic (symbol-named vtable dump) | 7.6.1 | Fired correctly. Produced §2b. **This is what identified the real root cause.** |
| Deep-hide balanced consume (Ctrl+Alt only, Shift passes through) | 7.6.1 | **Unrelated to dharpan's render issue.** Fixes stuck-modifier + Shift+9 typing. Fully working. Leave in place. |
| Inject-supersede exit-14 + reboot modal (5s pre-inject wait; if old payload stuck, refuse re-inject and prompt reboot) | 7.6.2 (built but NOT shipped) | Would help if dharpan's box ever hits the "old payload still loaded" state, but the round-3 log shows his 7.6.1 payload initialized normally. **This fix is orthogonal to the render bug; it's a safety net for install-upgrade races.** |

**Do not:**
- Try more variations of `GetPhysicalBackBuffer(this=X)` where X is
  pLayer, pLayer+8, pLayer+232, or pLayer+256. The method returns NULL
  on his object regardless of `this`. This has been reasoned about
  extensively; the return is deliberate on the MPO path.
- Call primary[24] on his box "just to see." primary[24] on his box is
  NOT `GetPhysicalBackBuffer` (his gbt-dump proves it isn't in primary
  at any slot). It could be a completely unrelated function; calling it
  with wrong `this` risks a `__fastfail` (CFG/CET) that bypasses SEH and
  takes DWM down. His DWM is currently stable in SAFE-MODE; do not
  regress that.
- Assume this is a dwmcore version issue. It isn't (§2b confirms
  byte-identical binary).
- Reinstall Windows again or blame it on his machine. He already reset
  Windows twice; the same hardware/driver combination produces the
  same MPO context each time. It's the *display path*, not the *OS*.

## 4. Why the current code path can't fix his box

The chain `get_backbuffer_texture` in `payload/src/ui/imgui_layer.cpp`
does:
```
pPhysBack = pLayer.vtbl[gpb_slot](pLayer + gpb_this_adj)   // GetDevice on our box, unused
pRes      = pLayer.vtbl[gd3d_slot](pLayer + gd3d_this_adj) // GetPhysicalBackBuffer
pAcc      = pRes.vtbl[acc_slot](pRes + acc_this_adj)       // GetD3D11Resource
tex       = pAcc.QueryInterface(ID3D11Texture2D)           // final texture
```

On dharpan's box:
- Step 2 (`GetPhysicalBackBuffer(pLayer+8)`) returns **NULL**.
- The chain bails.
- No amount of retry, this-adjust variation, or slot re-scanning fixes
  step 2 because the method genuinely has no backbuffer to return —
  the composition path his GPU/driver put DWM on doesn't use a
  physical backbuffer at all.

To render on his box we need a **different `pRes`** — one that has a
real backbuffer. The most promising source is
`CDDisplayRenderTarget::Present`'s `this` (see §5).

## 5. What's already RE'd and available (RVAs + resolved symbols)

From `_incoming_logs_2026-09-27c/resolver.log` on dharpan's box (all
RVAs identical to our working box, so all the same on ours):

```
COverlayContext::Present                            RVA=0x22C490  (hooked)
COverlayContext::COverlayContext                    RVA=0x2662B4
CDDisplayRenderTarget::Present                      RVA=0x2301D0  <-- CANDIDATE
CDDisplayRenderTarget::PresentNeeded                RVA=0x1B4998  (hooked as PN1)
CDDisplayRenderTarget::IsPrimaryMonitor             RVA=0x1A5FF0
CDDisplayRenderTarget::AddDirtyRect                 RVA=0x21F050  (resolved)
CLegacyRenderTarget::Present                        RVA=0x22EFA0
CLegacyRenderTarget::PresentNeeded                  RVA=0x1B49CC  (hooked as PN2)
CLegacyRenderTarget::AddDirtyRect                   RVA=0x215260  (resolved)
CDDisplaySwapChain::GetPhysicalBackBuffer           RVA=0x1E34C0  (the one that NULLs)
CDDisplaySwapChainBuffer::GetD3D11Resource          RVA=0x1F6F50
COverlaySwapChain::GetDevice                        RVA=0x1D3E60
CGlobalCompositionSurfaceInfo::IsOverlayPrevented   RVA=0x1E74A0  (patched inline)
CCommonRegistryData::ForceFullDirtyRendering        RVA=0x411A69  (patched inline)
ScheduleCompositionPass                             RVA=0x11F1CC
CVisual::RenderContent                              RVA=0x7E1F0
CWindowNode::RenderContent                          RVA=0x233110
CDrawingContext::IsNormalDesktopRender              RVA=0x1B6980
CWindowNode::GetHwnd                                RVA=0x1451D0
```

## 6. Ghidra plan (do this before Path 1)

**Load** `C:\Windows\System32\dwmcore.dll` (or
`hooksdll/dwm/dwmcore_clean.dll` — same TDS 0x0465DF26, size 4481024)
in Ghidra with the auto-analysis on. Wait for it to finish.

**Focus questions:**

1. **What are the class(es) whose vtable has `GetPhysicalBackBuffer`
   (RVA 0x1E34C0) at slot 28 of the secondary at offset +8, and
   `GetDevice` (RVA 0x1D3E60) at slot 9 of that same secondary?**
   That's the shape of dharpan's `pLayer`. Find the class hierarchy
   in Ghidra's Data Type Manager (or by walking the vtable references
   from 0x1E34C0). You'll get a name like `CDDisplaySwapChain` or a
   subclass thereof. Note the parent chain.
2. **What does `COverlayContext::Present` (RVA 0x22C490) actually do?**
   Decompile it. Trace what it dispatches to. On the *hardware-overlay*
   code path (vs the software-composited path), which member render
   target does it acquire, and how? The dispatch will typically be a
   virtual call through `this` (COverlayContext*). Note which vtable
   slot it goes through — that's the "correct" render-target getter for
   a COverlayContext.
3. **What is `CDDisplayRenderTarget::Present` (RVA 0x2301D0)'s `this`?**
   Decompile it. What class is `this`? What backbuffer does it hold?
   Where in the object is the backbuffer field? Is there a public
   getter method for it in the vtable?
4. **Does dwmcore have a getter like `COverlayContext::GetRenderTarget`,
   `GetCurrentDisplay`, `GetPrimaryTarget`, or similar?** Look in
   `COverlayContext`'s vtable (whose Present is at slot X of the same
   vtable — Present is well-known so you can walk backward from it).
   If such a getter exists, that's the direct path from our
   `COverlayContext::Present` hook to a renderable target on his box.
5. **What is the actual `this`-arg of `GetPhysicalBackBuffer` on the
   hardware-overlay path?** In the decompiled `COverlayContext::Present`
   flow, if the code path branches for hardware-overlay contexts, note
   what value of `this` it would pass to `GetPhysicalBackBuffer` (if
   any). It might not call it at all on that path — in which case,
   confirmed: our chain fundamentally doesn't apply and Path 1 is
   necessary.

**Deliverable from Ghidra work:** either (a) the correct
render-target-acquisition sequence from a `COverlayContext::Present`
hook on a hardware-overlay context (and we implement it directly), or
(b) confirmation that no such sequence exists in this flow, in which
case Path 1 (additional hook) is the only route.

## 7. Path 1 implementation notes (once Ghidra confirms)

**Goal:** when `get_backbuffer_texture(pLayer)` from
`COverlayContext::Present`'s `this` returns NULL after N frames of
retry, fall through to a **second render source** obtained from
`CDDisplayRenderTarget::Present`'s `this`.

### 7a. Resolver
Already resolves `CDDisplayRenderTarget::Present` (RVA 0x2301D0). No
resolver change needed — the RVA is already in `offsets.blob`. Verify
by grepping `resolver/src/main.c` for `CDDisplayRenderTarget::Present`.

### 7b. Blob schema
Currently `offsets.blob` (v1, 192 bytes) has `present` = 0x22C490
(COverlayContext::Present). We need to ALSO store 0x2301D0
(CDDisplayRenderTarget::Present) in the blob. Options:
- Extend the v2 extension (already 112 bytes, gives us headroom) — add
  a `present_dr` field. Bump blob-v2 to include it. Payload's
  `blob_read.c` reads the new field on v2, ignores on v1 (backward
  compat).
- OR: derive it in the payload from the `PN1` hook's `this` (which is
  a CDDisplayRenderTarget) — capture that pointer the first time PN1
  fires, use it as the fallback render source.

The second option is **much simpler and requires no resolver/blob
changes**. Recommend that.

### 7c. Payload hook wiring
- Add a second hook: `CDDisplayRenderTarget::Present` (or reuse the
  existing PN1 hook which already fires for CDDisplayRenderTarget).
- On first fire, capture `this` into a new global
  `g_cddisplay_rendertarget = this`.
- In `get_backbuffer_texture(pLayer)`, if the primary chain (via
  `pLayer` = COverlayContext) returns NULL after `GBT_MAX_ATTEMPTS`,
  **before** tripping SAFE-MODE, try one more path: run the chain
  against `g_cddisplay_rendertarget` (which IS a
  `CDDisplayRenderTarget` — its layout is understood, its slot for
  `GetPhysicalBackBuffer` is known from Ghidra).
- If THAT chain yields a valid texture, LOCK on that pointer + slots
  instead of the COverlayContext pointer.
- Only trip SAFE-MODE if BOTH acquisition sources fail.

### 7d. Safety
- All calls remain SEH-guarded + `is_ptr_in_dwmcore` validated.
- The CDDisplayRenderTarget path is used ONLY if the primary path
  NULLs — no change in behavior for boxes where the primary works
  (ours, everyone-except-MPO users).
- If Ghidra reveals that `CDDisplayRenderTarget`'s backbuffer slot
  differs from primary-vtable slot 24 on his box, use the correct
  slot per the RE finding (do NOT hardcode-guess).

### 7e. Test plan
- Verify no regression on our (working) box: primary path still LOCKS
  on attempt 1, overlay renders normally.
- If we can add a dev flag to force our payload to reject the primary
  chain and take the CDDisplayRenderTarget fallback, we can validate
  the fallback path on our own hardware before shipping to dharpan.
  Suggested env var: `SVCLDB_FORCE_ALT_RENDER_TARGET=1` (dev-bypass
  build only).

## 8. What NOT to change (unrelated fixes to preserve)

The following fixes landed in the 7.6.1/7.6.2 branch and are
independently correct. **Do not revert them** while implementing Path 1:

- **Deep-hide balanced consume (payload + helper).** `SILENT_MODS` now
  targets Ctrl/Alt only; Shift passes through so Shift+9=`(` works.
  Only consumes an UP if we consumed its DOWN (prevents stuck
  modifiers). See `payload/src/rawinput_hook.c` `ll_kbd_proc` deep-hide
  gate, and `tools/redteam/probes/wl_input.c` `wl_ll_kbd` gate 6.
- **`--kill-all` signals winlogon helper + releases modifiers.** See
  `launcher/src/main.c` `--kill-all` block: `inject_helper_signal_unload()`
  call + `release_all_modifiers()` before exit.
- **Inject-supersede exit-14.** `launcher/src/main.c` `--json-config`
  and `--reinject` heal blocks: 5000ms wait + `ExitProcess(14)` if the
  old payload refuses to leave. Electron injector attaches
  `needsReboot: true` on exit 14; renderer shows a `confirm()` dialog
  with a Restart button; main.js has `system:restart-pc` IPC handler.
- **`gbt_dump_layout_once` read-only vtable dump.** Fires on first
  `get_backbuffer_texture` call. Logs only KNOWN dwmcore symbols to
  keep output concise. Keep this — it's how we identified dharpan's
  issue, and it's harmless on all boxes.
- **Retry-until-renderable + lock.** Even though it doesn't help
  dharpan (his box only presents the one object type), it correctly
  handles boxes where multiple objects appear and the first-seen one
  isn't renderable. Keep it as the outer loop; Path 1 fires as a
  fallback inside/after the retry exhausts.

## 9. Current state / what's shipped

- **7.6.2 is built and packaged** at
  `C:\Users\abdul\Desktop\CloakGPTWindowsMaxStealth-Setup.exe` +
  `.zip` (1:10 PM 2026-09-27). NOT distributed to dharpan. User's
  standing decision: hold 7.6.2 for dharpan until the render bug is
  actually addressed — otherwise no functional change for him, just
  another install-and-fail cycle.
- **Dharpan's box is currently in SAFE-MODE quiesce state on 7.6.1.**
  DWM alive, no crash. He needs the render bug fixed to see the
  overlay; no urgency to ship anything to him until then.
- **Uncommitted changes** to payload/launcher/UI from this session
  (deep-hide Shift-passthrough, inject-supersede, retry-discovery,
  vtable dumper) are all in the working tree, not committed. Coordinate
  with Sam before committing.

## 10. If Ghidra reveals something surprising

The three main "surprises" that would change Path 1:

- **His `pLayer` is not a COverlayContext / CDDisplaySwapChain
  subclass.** If Ghidra shows a genuinely different class (e.g., a
  hardware-overlay-specific `COverlayPlaneContext` or similar), the
  hook target and acquisition may need to change more fundamentally.
- **CDDisplayRenderTarget also lacks a usable backbuffer on his
  hardware-overlay path.** In which case, Path 1 doesn't work either,
  and we need to acquire the render target via a compltely different
  route (e.g., DXGI enumeration, hooking `IDXGISwapChain::Present1`,
  or requesting a compositor swap chain via `DCompositionCreate...`).
- **The correct method IS in `pLayer`'s primary vtable at some slot
  the dumper skipped** (because its RVA isn't in our known-symbol
  table). If Ghidra identifies a new method that returns a renderable
  target directly, resolve it and add it to the blob.

Report back in the handoff with what Ghidra shows before writing
code. The whole point of the RE step is to avoid another round of
"try something, ship it, wait a day for logs, learn nothing."

---

*Handoff written 2026-09-27 ~1:23 PM UTC-4 by the Cursor Claude that
did the diagnosis. Fresh chat: read this file, read the transcript,
read the round-3 logs. If you agree with the diagnosis, run Ghidra on
`dwmcore.dll`, then implement Path 1 with the correct
render-target-acquisition sequence Ghidra reveals. If you disagree,
say why in a comment reply before touching code.*

---

## REPLY (2026-09-27 ~1:35 PM UTC-4, fresh chat) — PARTIAL AGREE, ONE LOAD-BEARING CORRECTION

Read this handoff + the round-3 logs (decrypted `27c/msvc_dbg_a/b/f`) +
the payload source (`imgui_layer.cpp` get_backbuffer_texture,
`dwm_hooks.c` Present/PN detours) + the git history back to v6.7.0.0.
Net: the **diagnosis is right, the prescription (Path 1 target) is
wrong**. Details below with the evidence that flips it.

### AGREE with
1. **Not build drift.** blob-ext MATCH, TDS 0x0465DF26, dwmcore size
   4481024 byte-identical to ours. Round-3 resolver.log resolves the
   same RVAs we get. Confirmed.
2. **Not the one-shot race / this-adjust bug.** 7.6.1 retry ran the full
   600 frames, hit the *same* object with `GetPhysicalBackBuffer` at
   secondary+8 slot 28 returning NULL *every frame*, then tripped
   SAFE-MODE. There is no "good object" it lost a race to — his box only
   ever presents the one object type. The v7.6.1 "multiple objects, we
   locked the bad one" theory (imgui_layer.cpp lines 550-571) is **dead**;
   round-3 disproves it.
3. **`GetPhysicalBackBuffer(pLayer)` genuinely NULLs on his box.** Not a
   wrong-`this`. Confirmed.
4. **Ghidra RE before writing code.** Agree, doing it.

### DISAGREE with — the fix target is CLegacyRenderTarget, not CDDisplayRenderTarget

The handoff's §7 Path 1 says: hook `CDDisplayRenderTarget::Present`
(RVA 0x2301D0) / capture its `this` from PN1, render into its
backbuffer. **That RT never runs on his box.** Evidence, side by side:

| | our (working) box | dharpan round-3 |
|---|---|---|
| PN1 `CDDisplayRenderTarget::PresentNeeded` | **fires** → `PN1: captured CDDisplayRenderTarget pThis` (every session in `_local_msvc_a.txt`) | **never fires** — no PN1 capture line anywhere in 45s of log |
| PN2 `CLegacyRenderTarget::PresentNeeded`   | (display path wins) | **fires** → `PN2: captured CLegacyRenderTarget pThis` |
| pLayer `GetPhysicalBackBuffer`             | primary slot 24, returns valid | secondary+8 slot 28, returns **NULL** |

So his DWM composites through the **Legacy** render target
(`CLegacyRenderTarget`), which we already capture as `g_legacy_rt`
(dwm_hooks.c:923). The handoff's recommended "simple option 2" (grab
CDDisplayRenderTarget from PN1) has **no pointer to grab** on his box,
and hooking `CDDisplayRenderTarget::Present` would **never fire** there.
Following Path 1 verbatim = another wasted round. The alternate render
source has to come from what actually runs on his box: the
`CLegacyRenderTarget` (`g_legacy_rt`) and/or the `COverlayContext`
(`pCtx`, which our Present detour already receives but currently
ignores). **This is the load-bearing correction. Ghidra's job is now:
find the renderable D3D texture reachable from `CLegacyRenderTarget`
(or `pCtx`), not from CDDisplaySwapChain.**

### On the "v6.7.0.0 worked for him" clue (from Sam) — RED HERRING for a revert

Checked the git arc. UI app v6.7.0.0 = `5e3f142` (2026-09-22, worked
for him). The only render-path commits after it are v-multibuild
(2026-09-24) and v7.3.0 MI-walk (2026-09-25) — and v7.3.0's own
comments say it was written *because dharpan was already broken*. So the
break is 09-22 → 09-25. But:

- v6.7.0.0's resolver already resolved the identical symbol set (no
  target regression).
- v6.7.0.0's `get_backbuffer_texture` scanned **only the primary
  vtable** (single `find_vtable_slot_by_rva`, no MI, no this-adjust) and
  fell back to hardcoded slot 24. On his *current* object,
  `GetPhysicalBackBuffer` is **not in the primary at all** (his dump:
  only at secondary+8 slot 28). So v6.7.0.0 code, run against his
  *current* object, would call whatever primary[24] is (NOT GPB — proven
  absent from primary) → garbage/crash, **not render**.

Conclusion: v6.7.0.0 could not render on his *current* object, so his
object must have been **different** at v6.7.0.0 — i.e. his DWM was on the
**Display** path then (GPB at primary 24). Since round-3's dwmcore is
byte-identical to ours, the thing that moved him Display→Legacy is
**per-machine: GPU/display driver / MPO capability / display topology**
(a driver or Windows update *on his box*), not our code and not the
dwmcore binary. **Reverting our code will not fix him.** Our overlay's
render source has been COverlayContext::Present's `pLayer` swapchain for
the entire arc; no version ever rendered via the Legacy RT's backbuffer.
So this is a *fix-forward* (support the Legacy/overlay composition path),
not a *revert*. The clue is useful only as confirmation that his path
switched — it does not point at a code regression to undo.

### REPRODUCTION PLAN (per Sam's "recreate it on my box first" rule)

Same dwmcore + different composition path ⇒ I can force this box onto
`CLegacyRenderTarget` by making DWM composite without the modern
display/flip path. Order of attempts (Sam OK'd DWM/box crashes):
1. Add an **indirect/virtual display** or force **Basic Display Adapter
   (WARP)** by disabling the GPU driver in Device Manager → DWM falls
   back to legacy composition → expect PN2-only + pLayer GPB NULL,
   reproducing his exact log signature.
2. Failing that, `OverlayTestMode`/MPO registry toggles + flip-model
   disable.
   Success criterion for the repro: on this box I see `PN2 captured
   CLegacyRenderTarget` **without** `PN1 captured`, and
   `get_backbuffer_texture` NULLs at GD3D — i.e. my box now looks like
   his round-3 log. Only then do I build + verify the fix here before
   shipping to him.

### NEXT ACTIONS (this chat)
1. Ghidra `dwmcore.dll` (26100/26200 @ TDS 0x0465DF26): decompile
   `COverlayContext::Present` (0x22C490) legacy branch,
   `CLegacyRenderTarget::Present` (0x22EFA0) + its class layout /
   backbuffer getter, and `CDDisplaySwapChain::GetPhysicalBackBuffer`
   (0x1E34C0) to confirm the NULL-return condition. Deliverable: the
   exact getter chain to a renderable texture from `CLegacyRenderTarget`
   or `pCtx`.
2. Reproduce the Legacy path on this box (above).
3. Implement fix-forward: when the pLayer chain NULLs, fall through to
   the Legacy-path acquisition (source = `g_legacy_rt` / `pCtx`), lock on
   success, SAFE-MODE only if BOTH fail. Preserve every unrelated
   7.6.1/7.6.2 fix listed in §8.

— reply by the fresh Cursor chat; proceeding to Ghidra + repro next.*

---

## GHIDRA RE RESULTS (2026-09-27 ~2:00 PM UTC-4) — decompiled dharpan's EXACT dwmcore

**Binary:** pulled `dwmcore.dll` 26100.9549 from
`C:\Windows\WinSxS\...compositor_...10.0.26100.9549_...` → copied to
`C:\ghidra_dl\dwmcore_9549.dll`. Verified **TimeDateStamp = 0x0465DF26**
(byte-for-byte matches dharpan round-3 blob-ext). File size 4,456,448;
`SizeOfImage` 4,481,024 (= the "size" his blob reports). Matching PDB
(GUID `08491F82...E070` age 1) already cached at
`C:\ProgramData\WinAudioSvc\symbols\dwmcore.pdb\08491F8213CA601DE6DA72D506F0E0701\`.
Ghidra project: `C:\ghidra_dl\project_legacy\svcldb_9549`; scripts in
`C:\ghidra_dl\scripts\` (`SetPdbExact`, `DumpLegacyPath`, `DumpVtables`);
raw decomp at `C:\ghidra_dl\legacy_run.out` / `legacy_run2.out` /
`vtables.out`.

### The render model (both paths)
`COverlayContext::Present(this, IOverlaySwapChain *param_1, flags, rects,
_, out, bool disableMPO)` — **param_1 is our "pLayer"** (an
`IOverlaySwapChain`/`COverlaySwapChain` subobject at `swapchain+0x18`).
Three sub-paths:
- **DirectFlip** if `this+0x4c28 != 0` → `CDirectFlipInfo::Present`.
- **Legacy** if `disableMPO==true` OR `LegacyPresentRequired(this)` →
  `param_1->vtbl[0x170](param_1, 1, flags, rects)` (the swapchain's own
  present).
- **MPO** otherwise → `PresentMPO(this, param_1, ...)` (builds
  DWM_PRESENT_MULTIPLANE_OVERLAY planes from physical backbuffers).

**Caller determines the path:**
- `CDDisplayRenderTarget::Present` (our box, PN1) calls
  `COverlayContext::Present(..., disableMPO=FALSE)` → MPO path → overlay
  swapchain HAS physical backbuffers → `GetPhysicalBackBuffer` returns a
  buffer → we render. ✔
- `CLegacyRenderTarget::Present` (dharpan, PN2) calls
  `COverlayContext::Present(..., disableMPO=this->vtbl[27]())` → Legacy
  path → **no overlay planes** → physical backbuffer array empty.

### Why GetPhysicalBackBuffer NULLs (definitive)
`CDDisplaySwapChain::GetPhysicalBackBuffer` (0x1E34C0):
```
if (idx@+0x1F4 < (end@+0x1C0 - start@+0x1B8)/8) return buffers[idx];
return NULL;
```
On the legacy path the physical-backbuffer vector is **empty**
(start==end) ⇒ NULL every frame. Not a wrong-`this`, not drift —
by-design: legacy composition has no hardware overlay plane to hand out.

### Where the pixels actually live on the legacy path
`CLegacyRenderTarget::Render(pDrawCtx)` composits the desktop tree via:
```
deviceTarget = param_1->vtbl[0x68]();              // overlay-swapchain virtual
CDrawingContext::BeginFrame(pDrawCtx, deviceTarget, ..., pCtx=this+0xd8);
RenderComposeTop(...);                              // draw desktop into deviceTarget
CDrawingContext::EndFrame(pDrawCtx);
... then CLegacyRenderTarget::Present -> COverlayContext::Present (OUR HOOK).
```
So on the legacy path the composited surface is the **device target
returned by the overlay-swapchain virtual at vtbl offset 0x68**, NOT a
physical overlay-plane backbuffer. `CDeviceTextureTarget::GetTexture2D`
(already in our blob as `acc`=0x865D0) is the likely texture getter on
that device target.

### Candidate alternate getters found (to validate live)
- `CLegacySwapChain::GetBackBuffer` (0x187EE0) and
  `CDDisplaySwapChain::GetBackBuffer` (0xD7B60) — distinct from the
  physical getter; may return a valid buffer where physical is empty.
- The `param_1->vtbl[0x68]()` device-target + `GetTexture2D` chain (the
  exact surface DWM draws the desktop into on legacy).
- His swapchain concrete type is `CLegacySwapChain` (or
  `CConversionSwapChain` — `EnsureSwapChain` picks based on
  `*(rt+0x88) < 2`). Both are DXGI-output swapchains (legacy present).

**Static MI-vtable offset chasing is unreliable past this point**
(adjustor thunks + which concrete swapchain). The exact slot/getter that
yields a renderable `ID3D11Texture2D` on the legacy path will be
confirmed empirically on a reproduced legacy-path DWM (below), where the
payload's own `gbt-dump` prints live vtable/buffer state.

### Fix shape (to implement after repro confirms the getter)
In `get_backbuffer_texture` / the present callback: when the physical
chain NULLs, fall through to the **legacy acquisition** —
`deviceTarget = param_1->vtbl[0x68]()` then
`CDeviceTextureTarget::GetTexture2D` (or `GetBackBuffer`), lock on the
first success, SAFE-MODE only if BOTH the physical and legacy chains
fail. `pCtx` (COverlayContext, already passed to our callback) and
`g_legacy_rt` (CLegacyRenderTarget, already captured by PN2) are both
available as anchors. No new hook needed; no CDDisplayRenderTarget hook
(it never fires on his box).

### Reproduction plan (mandated: recreate on this box first)
This box uses the Display path (dual modern GPUs → PN1). To force the
Legacy path (PN2-only + empty physical backbuffer = his signature) I'll
drive DWM onto a DXGI-output/legacy swapchain via, in order: (1) an
indirect/virtual display made primary, (2) WARP/Basic-Display-Adapter by
disabling the GPU adapters, (3) MPO/flip-model disable
(`OverlayTestMode`). Success = this box's payload log shows `PN2
captured CLegacyRenderTarget` WITHOUT `PN1`, and `gbt: NULL at GD3D`.
Then extend `gbt-dump` to print the legacy device-target chain, confirm
the getter, implement, and verify the overlay renders here before
shipping to dharpan.

---

## IMPLEMENTED + REPRODUCED + VALIDATED (2026-09-27 ~3:05 PM UTC-4)

### Reproduction (mandated "recreate on my box first") — DONE
Forced this dual-GPU box (NVIDIA 5060 + AMD 890M) onto the **legacy
composition path** by disabling BOTH display adapters in Device Manager
(`Disable-PnpDevice` on each PCI instance) → DWM fell back to the
**Microsoft Basic Display Adapter (WARP)**. A logon-triggered
`SvcldbRestoreGPU` scheduled task + `C:\ghidra_dl\restore_gpu.ps1` were
laid down first as a dead-man's switch (both since removed / GPUs
restored). Result on the WARP DWM — **byte-identical to dharpan's
round-3 signature**:
- `PN2: captured CLegacyRenderTarget` and **no PN1** (legacy path).
- `pLayer` primary vtbl RVA **0x30C500 = `CLegacySwapChain::vftable{for
  IDeviceResource}`** — the SAME class + RVA as dharpan's round-3
  gbt-dump (`primary_vtbl=...C500`). His box is confirmed
  `CLegacySwapChain`.
- `gd3d_slot dynamic=28 ... secondary this_adj=+8`, and `gbt: NULL at
  GD3D` — `GetPhysicalBackBuffer` NULLs exactly as on his box.

### The legacy render chain (Ghidra + live probe, both on 9549)
`CLegacyRenderTarget::Render` composits the desktop into
`deviceTarget = pLayer->vtbl[0x68]()` then draws via
`CDrawingContext::BeginFrame(deviceTarget,...)`. Decompiled the exact
functions (RVAs are 9549):
- **`CLegacySwapChain::GetBackBuffer` (0x187EE0)** = slot 13 / offset
  0x68 of pLayer's primary vtable. Returns `*(pLayer+0x110)+0x10` — a
  `CDeviceTextureTarget` (the composition surface). Same offset 0x68 is
  `GetBackBuffer` on `CDDisplaySwapChain` too (0xD7B60) — dwmcore-fixed
  slot, class-appropriate fn.
- **`CDeviceTextureTarget::GetTexture2D` (0x865D0)** = already in the
  blob as `accessorRva`, previously unused by the UI layer. Returns
  `*(deviceTarget+0x20)` (the `ID3D11Texture2D`).
- `BeginFrame` treats the device target as THE render target (reads dims
  via `GetRenderTargetInfo` slot 0x78, binds via D2D `PushTarget`).

A one-shot live probe (`legacy_acquire_probe_once`) on the WARP DWM
proved the chain end-to-end:
`GetBackBuffer(pLayer)` → device target →
`GetTexture2D` (found at MI slot 15 this_adj +120) →
`QI(ID3D11Texture2D)` = **S_OK** (winner). `GetD3D11Resource` absent on
this target; direct QI of the device target = E_NOINTERFACE.

### The fix (files, all in working tree — NOT committed)
- `payload/src/ui/imgui_layer.cpp`:
  - `GBB_SLOT 13` + `legacy_get_device_target()` — calls
    `pLayer->vtbl[0x68]` (validated + SEH-guarded).
  - `get_backbuffer_texture`: when `GetPhysicalBackBuffer` returns NULL,
    fall through to `pRes = legacy_get_device_target(pLayer)` and set
    `g_legacy_mode=1`; the shared accessor→QI→RTV chain continues.
  - `discover_acc_slot_once`: in legacy mode search **GetTexture2D
    (`g_rva_tex2d`) first, then GetD3D11Resource (`g_rva_acc`)** — covers
    both legacy swapchain subclasses.
  - **Legacy SIZE GATE before locking**: legacy `GetBackBuffer` returns
    a valid texture for EVERY presented swapchain (small sub-surfaces AND
    the fullscreen desktop), unlike the display path where
    `GetPhysicalBackBuffer` self-selects the desktop. Without the gate we
    lock the first (small) swapchain. Now: skip any target < 800x600, no
    lock, retry subsequent Present calls until the desktop swapchain
    appears (mirrors the existing retry-until-renderable design).
  - Kept `legacy_acquire_probe_once` (fires only if GetBackBuffer also
    fails) + a `legacy-rtv:` desc log (fires on size change) as
    permanent, harmless, legacy-only diagnostics for dharpan's logs.
  - `ui_set_vtable_slot_hints` gained a 4th arg (`tex2d_rva`); dllmain
    passes `off.accessorRva`. Header + caller updated.
  - Dev-only `SVCLDB_TEST_FORCE_LEGACY` (default 0) forces the legacy
    branch on the display path for real-GPU bring-up.

### Validation status
- ✅ **No display-path regression**: real-GPU display DWM still
  `PN1 captured` → `LOCKED gd3d_slot=24` → `ImGui READY`. Legacy branch
  dormant unless GPB NULLs (`g_legacy_mode` never set on display boxes).
- ✅ **Legacy path on WARP**: GPB-NULL detection, GetBackBuffer,
  GetTexture2D, QI, size-gate, and SAFE-MODE fallback all fire correctly;
  DWM never crashes.
- ⚠️ **Not visually confirmable on WARP**: Basic-Display/WARP's
  `GetBackBuffer` surface is a **degenerate 32x32** (WARP doesn't
  composite a real fullscreen desktop through dwmcore's overlay path), so
  the size-gate correctly skips it → SAFE-MODE on WARP. On a **real GPU**
  legacy box the same code path's device target IS the fullscreen desktop
  (dwmcore draws the desktop into exactly this surface via
  `BeginFrame`), so it will lock + render. The force-legacy-on-display
  test can't proxy this (CDDisplaySwapChain::GetBackBuffer returns a
  different object type with neither GetTexture2D nor GetD3D11Resource).

### For the final real-GPU-legacy validation (Sam / dharpan)
The one thing left is a **real-GPU legacy environment** (dharpan's box IS
exactly that). Ship dharpan a **prod** (non-dev-bypass) build with this
fix; his log should show: `LEGACY acquisition armed` → `legacy-rtv: tex
desc CHANGED <fullscreen>` → `LOCKED ... acc_slot=? rva=0x865d0` →
`ImGui READY`, and the overlay renders. If instead his surface is also
sub-fullscreen, the `legacy-rtv`/`skip sub-fullscreen` lines will say so.
Alternatively reproduce real-GPU-legacy locally via an indirect display
driver (IDD virtual monitor) made primary — not attempted here to avoid
an unsigned-driver install destabilizing the box.

**Do NOT ship the dev-bypass build to dharpan.** Rebuild the full stack
without `SVCLDB_DEV_AUTH` and repackage (the packaged 7.6.2 predates this
fix).

---

## STUCK-MODIFIER FIREWALL (2026-09-27 ~5:15 PM UTC-4) — REQUIRED before dharpan ships

**Symptom (hit live during this session's testing):** after repeated
reinject / DWM-kill / SAFE-MODE cycles, the keyboard was left with Ctrl
stuck "down" — letters stopped typing, number keys became shortcuts, `S`
opened Save. This is **especially dangerous for dharpan** because his box
enters SAFE-MODE, which is one of the trigger states.

**Mechanism:** the low-level keyboard hook + deep-hide (`SILENT_MODS`)
could strand a modifier across a hook (re)install while a key was
physically held. Instance A (deep-hide on) eats a Ctrl DOWN so the OS
never sees it; A is torn down mid-hold; during the hookless gap the OS
processes the still-held Ctrl (auto-repeat) and records it DOWN; fresh
instance B installs and eats the eventual UP as if it owned the DOWN → OS
Ctrl stuck.

**Fix (`payload/src/rawinput_hook.c`, `.h`, `dwm_hooks.c`):**
- New `rawin_release_all_modifiers()` — synthesizes KEYUP for every
  modifier the OS currently has down (`GetAsyncKeyState` gate) and wipes
  `g_silent_mod_consumed[]` + internal modifier state.
- Called on **every LL-hook (re)install** (clears inherited stuck state
  before the new hook eats anything), on **SAFE-MODE entry**
  (`hooks_force_compose_degraded`), and on **teardown** (`ll_thread`
  exit).
- Deep-hide now only SWALLOWS a modifier DOWN while the overlay is
  genuinely up (`ui_is_visible() && !hooks_compose_degraded()`); when
  hidden / SAFE-MODE the modifier passes through (nothing to protect, and
  no risk of stranding). The UP-balance still runs unconditionally so any
  DOWN we did hide always gets its matching hidden UP.

**Validated live:** forced Ctrl stuck-down via `keybd_event`, reinjected,
`GetAsyncKeyState(VK_CONTROL)` went True→False and the log shows
`release_all_modifiers: 2 modifier KEYUP(s) synthesized`. Display path
still `LOCKED` + `ImGui READY` (no regression).

**Shippable:** prod Setup.exe + zip on Desktop (2026-09-27 5:16 PM)
contain BOTH the legacy-render fix and this firewall; bundled `sihost.exe`
verified byte-identical to the fresh prod launcher.

---

## ROUND 2 ON DHARPAN (2026-09-27 ~8:10 PM UTC-4) — accessor mismatch on real-GPU legacy target

Dharpan installed the 5:16 PM build (`_incoming_logs_2026-09-27d`,
pid=1716, app 7.6.2 with all fix fingerprints incl. `release_all_modifiers`
firing — stuck-key firewall confirmed live on his box). Result:

- The legacy path **armed correctly** on his real GPU:
  `GetPhysicalBackBuffer NULL -> falling through to legacy GetBackBuffer
  path -> LEGACY acquisition armed -- deviceTarget=000001CAEFBF2F00`.
- Then **SAFE-MODE** with NO `legacy-rtv` / `skip sub-fullscreen` /
  `LOCKED`. The chain died at the **accessor step**: `discover_acc` found
  NEITHER `GetTexture2D` (0x865D0) nor `GetD3D11Resource` (0x1F6F50) on his
  device target within the 128-byte MI window.

**Root cause:** his `pLayer` is the same `CLegacySwapChain` class as the
WARP repro, but `GetBackBuffer` = `*(pLayer+0x110)+0x10` returns a
**hardware-backed** `IDeviceTarget` whose concrete class differs from
WARP's software `CDeviceTextureTarget` — so its texture getter is a
different method than `GetTexture2D`. (Ghidra texture-getter landscape on
9549: `CDeviceTextureTarget::GetTexture2D` 0x865D0, `CD3DSurface::
GetDXGIResource` 0x2CA86C, `CLegacySwapChainBuffer::GetDXGIResource`
0x189590, `CD2DBitmap::GetTexture2D` 0x1FC640.)

**This round's changes (`imgui_layer.cpp`):**
1. Widened MI accessor scan window 128 -> 384 (WARP's was at +120, edge of
   old window; hardware layouts sit deeper).
2. Legacy accessor discovery now tries the FULL texture-getter set
   (GetTexture2D, GetD3D11Resource, CD3DSurface::GetDXGIResource,
   CLegacySwapChainBuffer::GetDXGIResource, CD2DBitmap::GetTexture2D,
   CDeviceTextureTarget adjustor). Whatever it returns is normalized by the
   existing QI(ID3D11Texture2D). Each candidate is vtable-validated before
   use, so non-matching RVAs are safe no-ops. Hardcoded RVAs are
   9549-specific (dharpan's build); harmless on other builds.
3. New `legacy_devtarget_dump_once` — one-shot, read-only, SEH-guarded dump
   of the device target's primary + MI vtables (named symbols + raw RVAs,
   explicit `*** ACCESSOR ***` flags). **Validated live on WARP** (cleanly
   flags GetTexture2D at pDT+120 slot 15 and +128 slot 19, no SEH).

**If it still fails on his box**, his log's `legacy-dt:` lines give the
device target's exact `primary_vtbl` RVA (identifies the class) + every
accessor RVA/offset -> add that one getter for a certain fix. No display
regression (verified `LOCKED gd3d_slot=24` + `ImGui READY`).

**Shippable:** prod Setup.exe + zip on Desktop (2026-09-27 8:10 PM),
bundled `sihost.exe` (1,552,385) verified == fresh prod launcher.

