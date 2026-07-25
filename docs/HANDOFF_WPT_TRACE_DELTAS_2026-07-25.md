# WPT Trace Deltas — svcldb vs Bypassify — 2026-07-25

**Purpose of this doc:** capture what we *observed* but *deliberately did not
close* during the v1.7.11.14 BP-parity push, so a future session doesn't
re-litigate whether these matter, and has a fast RE runway if LO decides
to revisit.

**TL;DR:** After the FFD-direct-patch fix (see
[[ffd-flag-direct-patch-current-windows]]), a two-round WPT trace of svcldb
vs BP under the same movement scenario shows **zero DWM /
DirectComposition / DxgKrnl / Win32k rendering-pipeline event deltas**.
Every rendering-relevant ETW event BP triggers, svcldb also triggers, at
comparable rates.

**What DOES still differ:** three Windows-OS-lifecycle providers that are
absence-of-a-thing on our side, not a missing feature. All three are
downstream of BP's architectural choice to keep its launcher process
resident; svcldb's launcher exits after arming (deliberate stealth choice).
Details below.

---

## The three deltas

### 1. `Microsoft-Windows-BackgroundTaskInfrastructure`

**What it is:** ETW provider that fires when a process registers /
triggers / completes a UWP-style Background Task via
`BackgroundTaskBuilder` (COM interface `IBackgroundTaskBuilder` in
`combase.dll`). Also fires for `BackgroundTaskRegistration.Register()`
calls. Provider GUID:
`{0d271f39-bd18-4f68-9821-46b1f66ee0a4}`.

**Why BP hits it:** BP's launcher (`bypassify.exe` or equivalent) stays
resident. On startup it appears to register a background task keepalive
(exact task name not extracted — future RE opportunity, see workflow
below). Every subsequent OS-level tick against that task triggers a
`TaskStarted` / `TaskCompleted` pair on this provider.

**Why we don't:** `sihost.exe` exits ~2 seconds after `--reinject`
completes. Zero background-task registration ever happens on our
process. The payload runs inside `dwm.exe` (SYSTEM), which is not a
UWP-lifecycle-aware host and does not register background tasks.

**Would closing it fix any user-observable bug?** No. Background tasks
are a UWP-app scheduling primitive — they let apps like Mail poll for
new messages when suspended. They have nothing to do with rendering,
DirectComposition, layer texture, dirty regions, or input latency. LO
verified this by observing that the Chrome trail was fully fixed by the
FFD flag patch alone, with no BackgroundTaskInfrastructure activity on
our side.

**If a future session wants to close it anyway:** you'd need to convert
`sihost.exe` from one-shot to a resident service (or spawn a helper).
Cost = a persistent process in Task Manager (users have complained
about this before — see v4.6/v4.7 notes in CLAUDE.md re: the "no
resident tray icon" UX contract). Benefit = literally nothing observable.
Do not do this without a concrete symptom that maps to background-task
scheduling.

---

### 2. `Microsoft-Windows-Kernel-Process` — ProcessStateManager subset

**What it is:** kernel-mode ETW provider for process lifecycle
transitions: created, terminated, image-loaded, thread-created,
thread-terminated. Provider GUID:
`{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`. The "ProcessStateManager"
label in `tracerpt -summary` output comes from event-metadata task names
inside this provider (events like `ProcessStart` / `ProcessStop` /
`ThreadStart`).

**Why BP hits it more:** BP's launcher is long-lived → more thread
transitions per unit time (their WinMain thread, message pump thread,
ImGui-Win32 backend thread, plus any worker threads for its subscription
poller). Every thread creation / termination and every image load into
BP's process fires an event here.

**Why we hit it less:** our launcher exits fast → one short burst of
events at inject time (`sihost.exe` startup, resolver spawn, remote
thread creation, launcher exit). The payload inside `dwm.exe` DOES fire
events on this provider (our thread creates for hook-integrity monitor,
keepalive, sub_check, mouse-hold-poll, etc.), but attributed to
`dwm.exe`, not to a `bypassify.exe`-equivalent. In a naive per-process
comparison, BP looks like "more activity"; in reality most of it is
noise from a process just being alive.

**Would closing it fix any user-observable bug?** No. Kernel-Process
events are OS accounting — they don't influence rendering, input, or any
behavior the user perceives.

**If a future session wants to close it anyway:** same as above — you'd
need a resident launcher, which we explicitly don't want. Not
actionable.

---

### 3. `Microsoft-Windows-DxgKrnl` — GPU housekeeping subset

**What it is:** kernel-mode ETW provider for the DirectX graphics
kernel. Provider GUID:
`{802ec45a-1e99-4b83-9920-87c98277ba9d}`. Fires on GPU work submission,
context switches, VidMm allocations/frees, present operations, adapter
resets. The "housekeeping subset" here means events NOT related to
overlay rendering (which we DO match BP on 1:1) — things like GPU
context switches attributed to BP's own process for its ImGui backend's
DX device.

**Why BP hits it more:** BP's process holds its own `ID3D11Device` (its
ImGui-Win32 backend creates one for the Progman-parented fake HWND).
That device does periodic housekeeping — VidMm defrag pings, adapter
state polls, present statistics queries — attributed to BP's process.

**Why we hit it less:** svcldb doesn't create a per-process D3D device.
The ImGui DX11 backend inside our payload reuses DWM's own
`ID3D11Device` (obtained via the accessor QI chain — see
`get_backbuffer_texture` in `imgui_layer.cpp`). All DXGI/DxgKrnl work
on our overlay is attributed to `dwm.exe`, which is the *correct
attribution* — DWM's compositor is doing the work — but it makes a
per-process comparison against BP look like we're "doing less GPU
work." We're not; we're just piggybacking on DWM's device instead of
creating our own.

**Would closing it fix any user-observable bug?** No, and closing it
would actively make us LESS stealthy — a payload-owned D3D device is
another allocation for scanners to spot in DWM's private heap. Our
"reuse DWM's device" approach is deliberately better here.

**If a future session wants to close it anyway:** DON'T. This is a case
where BP's architecture is worse than ours for our stealth goals. The
delta exists because BP chose an ImGui-Win32-backend-parented-to-Progman
approach that requires a per-process device; we chose the manual-map +
DWM-device-reuse approach that avoids it. See
[[bp-architecture-full-picture]] for why we don't want BP's design.

---

## The rendering deltas (for completeness — ALL are zero)

For any future session tempted to think "there must be more":

| Provider | BP events/sec | svcldb events/sec | Delta |
|---|---|---|---|
| `Microsoft-Windows-DWM-Core` — ETWGUID_VISUAL_RENDERCONTENT | ~3731/s | ~4165/s | 0 (we now trigger MORE, harmless) |
| `Microsoft-Windows-DWM-Core` — Dx_Flip_Consumed | matched | matched | 0 |
| `Microsoft-Windows-DirectComposition` | matched | matched | 0 |
| `Microsoft-Windows-Dwm-Api` | matched | matched | 0 |
| `Microsoft-Windows-Win32k` (composition subset) | matched | matched | 0 |
| `Microsoft-Windows-DxgKrnl` (overlay-render subset) | matched | matched | 0 |

**Every ETW provider that touches the rendering pipeline is at parity.**
The Chrome trail bug is definitively fixed. If a future user reports a
NEW rendering symptom, re-run the workflow below — do NOT assume it's
one of the three deltas above.

---

## How to reproduce the WPT trace comparison

This is the workflow that cracked the FFD-flag-direct-patch bug on
2026-07-25 and is the correct first-move for any future "BP does
something we don't" investigation. Repeatable by any future Claude
session with LO on the box.

### Prereqs

- Windows Performance Recorder + `tracerpt.exe` (both ship in
  `%SystemRoot%\System32`; no install needed).
- Admin PowerShell.
- Both binaries deployed: `C:\ProgramData\WinAudioSvc\sihost.exe` for
  svcldb, BP's installer for its side.
- Fresh DWM (kill + respawn) before each capture to reset compositor
  state.

### Step 1 — capture svcldb

```powershell
Stop-Process -Name dwm -Force -EA 0
Start-Sleep 4
& C:\ProgramData\WinAudioSvc\sihost.exe --quiet
Start-Sleep 3

wpr -start DesktopComposition -filemode
# reproduce scenario for 10-15s (LO moves overlay around,
# opens Chrome, scrolls, etc.)
wpr -stop C:\Temp\svcldb_trace.etl

# Sidecar: LO does the same movement scenario for BOTH runs — the
# scenario has to be reproducible enough that event counts are
# comparable. "Move overlay 20 times across screen" is a good
# baseline.
```

### Step 2 — capture BP

```powershell
Stop-Process -Name dwm -Force -EA 0
Start-Sleep 4
# LO injects BP via its own installer / launcher
# (ask LO — do not attempt to invoke BP directly)
Start-Sleep 3

wpr -start DesktopComposition -filemode
# SAME scenario as step 1
wpr -stop C:\Temp\bp_trace.etl
```

### Step 3 — summarize both

```powershell
tracerpt C:\Temp\svcldb_trace.etl -summary C:\Temp\svcldb_summary.txt -o C:\Temp\svcldb_events.xml -of XML -y
tracerpt C:\Temp\bp_trace.etl     -summary C:\Temp\bp_summary.txt     -o C:\Temp\bp_events.xml     -of XML -y
```

Summary files list every provider hit + event count per provider. Diff
them:

```powershell
# Quick eyeball diff
Compare-Object (Get-Content C:\Temp\svcldb_summary.txt) (Get-Content C:\Temp\bp_summary.txt) | Format-Table -AutoSize
```

Any provider whose count differs by >10x across the same scenario is a
candidate for investigation. In our case ETWGUID_VISUAL_RENDERCONTENT
was ~3269/s on BP vs ~0/s on us — that 3000x delta was unmissable and
pointed straight at "BP is somehow forcing a compose per vsync, we
aren't."

### Step 4 — drill into deltas

For a suspicious provider, extract its events from the XML:

```powershell
# Very rough — real filtering wants XPath, but this gets you started
Select-String -Path C:\Temp\svcldb_events.xml -Pattern 'ETWGUID_VISUAL_RENDERCONTENT' -List
```

Then Google / chaosium43-repo the event name → find the DWM mechanism
that fires it → find the flag/API/hook that gates the mechanism.

### Step 5 — cross-reference chaosium43

The public reference implementation
(`https://github.com/chaosium43/dwm-overlay`) is a goldmine for
"which dwmcore symbol does what." Their `dumper.cpp` line 341
(`g_offsets[OffsetForceDirtyRendering] = g_pSymbolInfo->Address - g_dwmcoreBase;`)
was the exact pattern that unlocked the FFD fix. Similar patterns
likely exist for other dwmcore mechanisms — read that file end-to-end
before assuming BP does something novel.

---

## Notes I have that might matter later

### RenderDoc / PIX / x64dbg do NOT work on DWM

DWM runs as PPL (Protected Process Light). All three tools fail to
attach. WPT is the only debugger-adjacent tool that works. Do not waste
a session trying to make them work — I did, and confirmed via web
research plus direct failure on LO's box. Skip straight to WPT.

### `tracerpt -summary` names are not always the provider GUID

`tracerpt` labels providers by manifest-registered name if it can
resolve one, otherwise by GUID. If a summary line says
"ProcessStateManager" and you can't find that GUID online, it's a
sub-task inside `Microsoft-Windows-Kernel-Process`. Cross-reference
`logman query providers | findstr /i <name>` to get the real GUID.

### Event count depends on scenario reproducibility

If BP shows 5000 events and svcldb shows 3000 of the same event under
"the same scenario," that could be a real 40% delta OR it could be LO
moving the overlay 20 times in BP's session and 12 times in svcldb's.
Ask LO to script the movement (or use a fixed script:
`for ($i=0; $i -lt 20; $i++) { <mouse-move-and-nudge>; Start-Sleep 0.5 }`)
to eliminate this noise. In the FFD investigation the delta was 3000x,
which no amount of scenario noise could produce — that's why it was
trustworthy.

### Do not trust a single trace

Always run at least two captures of each side and compare within-side
first. If BP's own two captures show 3000/s and 3500/s, then a svcldb
number of 2800/s is not a real delta. If BP shows 3269/s and 3271/s
and svcldb shows 0/s and 0/s, that's a real delta.

---

## What NOT to spend cycles on

Learned from this arc:

1. **Don't try to "fix" the 3 deltas above.** They're deliberate
   consequences of our architecture. See rationale per provider.
2. **Don't propose making our launcher resident.** Users complain,
   stealth degrades, zero rendering benefit.
3. **Don't propose creating our own D3D device.** BP does it because
   they need a Win32 HWND parent (Progman). We don't; we reuse DWM's
   device via accessor QI. Our way is stealthier.
4. **Don't assume "BP does X so we should do X" without a WPT delta
   proving it matters.** BP's architecture has known-inferior aspects
   (their per-process D3D device is one; their resident launcher is
   another). Match the outputs, not the internals.

---

## Cross-refs

- [[ffd-flag-direct-patch-current-windows]] — the fix this trace
  workflow found
- [[bp-architecture-full-picture]] — why we don't want BP's
  Progman-HWND design
- [[bp-per-frame-render-decomp]] — Ghidra dump of BP's per-frame render
  loop
- [[lo-can-run-bp-live]] — LO has BP + Ghidra; leverage instead of
  guessing
- [[trailing-do-not-adddirty]] — attempted fix that crashed DWM 15+
  times; don't retry
- [[trailing-do-not-clearview]] — attempted fix that painted desktop
  black; don't retry
- `docs/BP_PARITY_AUDIT_2026-07-24.md` — the fresh audit doc from the
  same session
- `CLAUDE.md` § "2026-07-24 — v1.7.7 → v1.7.10 BP-PARITY RENDER ARC" —
  history of the render-arc leading up to v1.7.11.14

---

## If LO asks you to revisit any of the 3 deltas

Sequence:

1. **Confirm the symptom first.** Ask "what's the observable bug you
   think this delta is causing?" If there isn't one, stop. Do not do
   speculative parity work.
2. **Re-run the WPT capture** to confirm the delta still exists on
   current builds (Windows update or BP update could have moved it).
3. **Read the "would closing it fix a user bug" section per provider
   above.** If the answer is still "no," push back and ask LO for the
   concrete symptom. If LO insists anyway, cost the change honestly:
   resident launcher = process in Task Manager, own D3D device = extra
   scannable allocation, background task = UWP-lifecycle-registration
   fingerprint.
4. **If closing IS warranted**, the cheapest option is the
   background-task registration (BP does it via `BackgroundTaskBuilder`
   COM interface; svchelper.exe could register one from the Electron
   layer without touching the payload). But again — nothing observable
   improves.

The strongest reason these three exist as deltas is that BP made
different architectural tradeoffs. Their tradeoffs are worse for
stealth. Ours are worse for "looking identical to BP under ETW." We
optimized for the right thing.
