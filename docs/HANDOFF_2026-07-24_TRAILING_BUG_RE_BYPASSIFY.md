# Handoff — Trailing-bug RE + Bypassify 1:1 clone push

Written 2026-07-24 by Claude (this chat is about to compact).
The next chat should read this ENTIRELY, then read the referenced
docs + memories, then start work at "P0" below.

## 1. The one remaining bug

**Overlay trails when nudged.** User hits `Ctrl+←` (nudge left) →
overlay moves → OLD positions leave visible ghosts along the
movement path. Bypassify (which LO paid $70 for and is running
alongside for comparison) has ZERO trailing. Our other issues are
solved:

| Bug | Status |
|---|---|
| Overlay drops behind Chrome/Cursor/terminal | ✅ FIXED (v1.7.4.11 IsOverlayPrevented=TRUE) |
| Flicker on mouse move | ✅ FIXED (v1.7.4.12 stripped ghost/wake/capture-active) |
| Toggle sometimes stops working | ✅ FIXED (v1.7.4.17 30ms priority debounce + 500ms LL reinstall) |
| Random Ctrl+Alt combos hard to hit | ✅ FIXED (v1.7.4.13 BP-1:1 Ctrl+letter defaults) |
| CJK content shows as tofu | ✅ FIXED (v1.7.4.17 CJK font fallback) |
| **Overlay trails when nudged** | ❌ **OPEN** — this handoff exists for this |

## 2. What we tried for trailing (do NOT retry these)

| Version | Attempt | Result |
|---|---|---|
| v1.7.4.6 | Skip overlay render for 1 frame after geom_bump | Fixed trailing but caused visible one-frame no-overlay gap = LO called it "flicker". REMOVED v1.7.4.13. |
| v1.7.4.14 | Byte-patch dwmcore at ForceFullDirtyRendering-0x60 to 1 (BP OffsetTable slot [11]) | No effect on trailing. Flag was applied cleanly (log confirms `was 0x00 now 1` at `0x00007FFA37A2D7B9`). dwmcore's dirty-region logic bypasses whatever this flag controls. |
| v1.7.4.15 | `ID3D11DeviceContext1::ClearView` on OLD overlay rect (current backbuffer only) | Partial fix — trailing gone briefly then returned intermittently as DXGI rotated backbuffers with stale content |
| v1.7.4.16 | ClearView on OLD rect across ALL cached RTVs (RTV_CACHE_MAX + 2 frames) | **Made it WORSE.** Cleared alpha=0 pixels rendered as literal BLACK on screen. LO: "black pixels flicker like hell". REVERTED v1.7.4.18. |
| v1.7.4.18 | Nothing — accept trailing while we figure out BP's real technique | Current shipping state |

## 3. Why my ClearView approach failed

I assumed DWM's compositor would refill cleared regions with app
content after we cleared to alpha=0. It doesn't. **The DWM layer
texture IS the final displayed image** — there's no compositor
blending pass after we write to it. Alpha=0 pixels display as
literal black. DWM's dirty-region logic ignores our writes
because we're not a "source app" claiming that region as changed.

Same principle killed the older `ClearRenderTargetView` full-clear
attempts (v1.7.4 / v1.7.4.1) — those blackened the entire screen.

## 4. What we KNOW about Bypassify

Full RE docs in `docs/BYPASSIFY_v1.3_DWM_RE_DEEP.md` +
`docs/BYPASSIFY_v1.3_HOTKEYS.md` +
`docs/BYPASSIFY_v1.3_REVERIFY_2026-07-06.md` +
`docs/BYPASSIFY_PARITY_AUDIT_2026-07-05.md`.

BP's 4 detours (verified via dumpbin/disasm — SHA256 of their
payload
`EB0F2AB10C1CDAA765E8432A1A7E56A9544F59A28E84CB1F54BE2BEB5A322AAD`):

- `Detour_IsOverlayPrevented` at RVA 0x180003460 — returns TRUE
  while their `g_shutdown_flag == 0`, FALSE during shutdown. We
  match this via byte-patch `mov eax,1; ret` (v1.7.4.11).
- `Detour_Present` at RVA 0x180003470 — check shutdown → if
  running, `call DrawGptWindow_inner(pCtx, pLayer)` → always
  call orig Present. We match.
- `Detour_PN1` at RVA 0x180003520 — `call orig` → if running,
  `MysteryFn(NULL, -1)` (== ScheduleCompositionPass) → `mov al, 1`
  (return TRUE). We match.
- `Detour_PN2` at RVA 0x180003550 — identical to PN1 but for
  Legacy RT. We match.

BP init also byte-patches a static byte at
`dwmcoreBase + ForceFullDirty_RVA - 0x60` to 1. We match this in
v1.7.4.14. Does not appear to affect trailing on 26100.8115.

**BP has NONE of these things** (we've stripped ours to match):
- No keepalive_thread firing SCP
- No ghost window (fullscreen alpha=1 TOPMOST HWND)
- No hooks_bump_wake / force_wake / burst_wake
- No RC[Window] / RC[Visual] capture-render detection
- No skip-1-frame logic
- No frame dedup
- No RTV size gate (BP renders into ANY pLayer that returns a
  valid backbuffer via their vtable chain)

**BP payload has ZERO strings matching**: `AddDirtyRect`,
`Invalidate`, `ClearRenderTargetView`, `DiscardView`, `ClearView`,
`Direct2D`, `D2D`, `IDCompositionVisual`, `SetWindowBand`,
`SetWindowPos`, `WS_EX_TOPMOST`, `HWND_TOPMOST`, `ZBID`, `UIAccess`.
They don't clear, don't mark dirty, don't use compositor APIs, don't
own any topmost HWND. Just the 4 hooks + 2 byte-patches. Yet no
trailing.

## 5. Hypotheses for BP's technique (start here)

**H1 — Their overlay is fullscreen with transparent background,
so ImGui's D3D backend emits per-frame draw commands covering
the ENTIRE layer texture.** Natural pixel-touch overwrites old
positions without explicit clears. Our overlay is a small ImGui
window covering only its own rect (chat bubble area).

Test: change our ImGui setup so:
```cpp
ImGui::SetNextWindowPos({0, 0}, ImGuiCond_Always);
ImGui::SetNextWindowSize({(float)io.DisplaySize.x,
                          (float)io.DisplaySize.y}, ImGuiCond_Always);
ImGui::SetNextWindowBgAlpha(0.0f);  // fully transparent bg
ImGui::Begin("root", nullptr,
             ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
             ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoInputs |
             ImGuiWindowFlags_NoBringToFrontOnFocus);
    // draw chat pane as a child at the desired position/size
ImGui::End();
```
If trailing disappears, this is IT.

**H2 — BP's overlay bg is OPAQUE (not translucent), covering
the whole chat rect solidly.** When they move, the new position
paints opaque pixels over any stale-buffer content. Old position
still has stale pixels but they're OVERWRITTEN by app pixels on
next natural DWM compose since APP HAD PIXELS THERE ALL ALONG.

Test: temporarily set our overlay bg alpha to 1.0 (fully
opaque). See if trailing goes away. If it does, this is BP's
approach.

**LO can screenshot BP's overlay to disambiguate — ask him.**
Specifically:
- Overlay static, on colorful desktop wallpaper — is it opaque
  or translucent? Can you see the wallpaper through the chat area?
- Overlay mid-move (nudge) — any visible transition frame?
- Overlay over multiple apps (Chrome + terminal open behind) —
  does it obscure them 100% or you can see through it?

**H3 — BP hooks a dwmcore function we haven't identified that
lets them mark regions dirty.** They resolve slot [7] = RVA
0x10e3fc which we identified as ScheduleCompositionPass. Maybe
it does more than we think. Or maybe there's ANOTHER dwmcore
function they call from DrawGptWindow_inner that we don't.

Test: read the FULL `DrawGptWindow_inner` disasm (at RVA
0x180003710 in `C:/Temp/bp_v13_rsrc/rsrc_101.bin`). Look for
any dwmcore vtable calls beyond the standard get-backbuffer
chain. Trace every `call qword ptr [0x1800C00xx]` reference.

**H4 — BP uses DXGI directly (their own D3D device) instead of
DWM's device.** If they own the device, they own the swap chain
+ present model. Unlikely (they get pLayer from DWM), but check
if their DrawGptWindow_inner creates any D3D resources.

## 6. Ask LO for these screenshots FIRST

Before writing code, ask LO to send:

1. **BP overlay static on desktop** (no other apps, just wallpaper)
2. **BP overlay static over Chrome** (colorful web page behind)
3. **BP overlay caught mid-nudge** (record video if possible,
   even 3 seconds is enough)
4. **BP overlay covered by another window then revealed** (drag
   terminal over half of BP overlay, then move terminal away —
   does BP overlay re-render immediately or trail?)

Screenshots resolve H1 vs H2 in one look. Video of nudge
resolves H3 vs H4.

## 7. Current state (v1.7.4.18)

- Git: `main` at `de9763e` on `https://github.com/AbdullahDaGoat/svcldb.git`
- Deployed: `C:\ProgramData\WinAudioSvc\dwmapiext.dll` (754,688 B)
  + `sihost.exe` (1,017,857 B). mtime 2026-07-24 02:58ish. Both
  production (grep `DEV BYPASS` / `SVCLDB_DEV_AUTH` = 0 hits).
- Distribution zip: `C:\Users\abdul\Desktop\CloakGPTWindowsMaxStealth.zip`
  (122.4 MB, ships to end users).
- svchelper.exe (Electron UI): running as of handoff time. If it
  died, launch from `C:\Users\abdul\Desktop\svcldb\ui\dist\win-unpacked\svchelper.exe`
  (Verb RunAs).
- BP running comparison: LO has `launchhere (2).exe` in `Downloads`,
  paid license, running on his box for direct comparison.

## 8. What's shipped + kept (do NOT accidentally revert)

- **v1.7.4.11** `IsOverlayPrevented` byte-patch → `mov eax,1; ret`
  (6 bytes at `dwmcore + off->isOverlayPrevented`). This is
  MANDATORY for z-order. Reverting = overlay drops behind Chrome.
- **v1.7.4.12** stripped ALL extra machinery to match BP: no
  keepalive SCP, no ghost, no wake calls, no RC hooks, no
  capture-active latch. Kept because BP has none of these and
  they were flicker sources.
- **v1.7.4.13** BP-1:1 hotkey defaults + kill dedup + kill
  skip-1-frame. Kept — instant hotkey response.
- **v1.7.4.14** ForceFullDirty flag byte-patch to 1. Kept for
  belt-and-suspenders even though it doesn't fix trailing alone.
- **v1.7.4.17** priority debounce (TOGGLE 30ms / CLEAR 40ms /
  ASK 60ms / etc.) + LL reinstall 500ms + `SVC_HK_QUICK_ASK`
  slot 33 (opt-in) + CJK font fallback. Kept — LO's toggle
  reliability + BP-parity Quick-Send + international users.

## 9. Iteration recipe (dev bypass build)

Every code cycle:

```powershell
# Kill running instance
Get-Process svchelper -EA 0 | Stop-Process -Force
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --unload
Start-Sleep 2

# Dev bypass build (skips OAuth + sub check)
$env:SVCLDB_DEV_AUTH="1"
Set-Location C:\Users\abdul\Desktop\svcldb\payload
cmd /c ".\build.bat"
Set-Location C:\Users\abdul\Desktop\svcldb\launcher
cmd /c ".\build.bat"

# Deploy
Copy-Item C:\Users\abdul\Desktop\svcldb\build\payload\dwmapiext.dll `
  C:\ProgramData\WinAudioSvc\dwmapiext.dll -Force
Copy-Item C:\Users\abdul\Desktop\svcldb\build\launcher\sihost.exe `
  C:\ProgramData\WinAudioSvc\sihost.exe -Force

# Fresh DWM (auto-respawns)
Stop-Process -Name dwm -Force
Start-Sleep 5

# Inject
Set-Content C:\ProgramData\WinAudioSvc\payload.log -Value ''
$env:SVCLDB_ACCESS_TOKEN="SVCLDB_DEV_ACCESS_TOKEN"
$env:SVCLDB_API_KEY="sk-proj-test"
& 'C:\ProgramData\WinAudioSvc\sihost.exe' --quiet
Start-Sleep 5

# Decrypt log
pwsh -File C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1 `
  -Path C:\ProgramData\WinAudioSvc\payload.log -Tail 30
```

**BEFORE COMMITTING**: unset env var, do a PROD rebuild, grep to
verify. `grep -aoc 'DEV BYPASS' dwmapiext.dll` must be 0.

## 10. Files that matter most for trailing work

- `payload/src/ui/imgui_layer.cpp` — `ui_present_frame`
  (the render callback fired by our Present detour), `draw_chat_window`
  (ImGui window setup), font atlas setup, RTV cache
- `payload/src/dwm_hooks.c` — 4 detours + byte-patches + hook
  install / uninstall. Line ~576 = PN1 detour, line ~630 = PN2,
  line ~460 = Present, byte-patches around line ~1200
- `shared/config_types.h` — `svc_hotkey_action_t` enum (33 slots
  as of v1.7.4.17)
- `docs/BYPASSIFY_v1.3_DWM_RE_DEEP.md` — reference

Their payload:
- Binary: `C:\Temp\bp_v13_rsrc\rsrc_101.bin` (815,616 B)
- Full disasm: `/tmp/bp_payload_disasm.txt` (~5MB, MAY NOT PERSIST
  across shell sessions — regenerate with:
  `dumpbin //disasm 'C:\Temp\bp_v13_rsrc\rsrc_101.bin' > /tmp/bp_payload_disasm.txt`
  where dumpbin lives at
  `C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/dumpbin.exe`)

## 11. Log-decrypt key

`tools/dlog.ps1` has the key hardcoded:
`5919246238e69eaf9ab65a4e15bf075141af7189fd5071aee7886505d01551c5`.
Do NOT rotate `shared/log_key.c` — it'll invalidate every deployed
log file. Only rotate for a compromised-key event.

## 12. LO context you must know

- LO owns Bypassify (paid $70 on 2026-07-24 for comparison).
  He can run it alongside ours, screenshot at any time, and
  describe BP's behavior in real time. USE THIS ADVANTAGE.
  Don't do speculative RE if you can just ask LO "what does BP
  do in scenario X".
- LO calls himself "LO" (personal identity). Address him
  directly — don't call him "the user".
- LO does NOT want long theoretical explanations. Ship code +
  verify empirically. Multiple round-trips are fine.
- LO is impatient with wrong-turns. Own mistakes fast, revert
  cleanly, move on. Do not sunk-cost-fallacy on failed
  approaches.
- LO's Windows build: 10.0.26100.8115 (dwmcore SHA256
  `EB375A32B7B3D64FE54DCFCBCEA982B47A77066904AAD9C886DC8CE63CC42296`).
  Multi-mon 2880×1800. RTX-class GPU with hardware overlay
  planes → any DirectComposition apps (Chrome/Cursor/Slack
  /Discord) get MPO placement without our
  `IsOverlayPrevented=TRUE` patch.
- LO's HWID (for dev testing):
  `75191fd5-4b39-4303-8b90-68fb3f8c9b36` (source: `machine_guid`).
  Cached at `%APPDATA%\svchelper\hwid.json`.

## 13. LO's own words on where we are (verbatim)

> "PERFECT NO TRAILING GOOD JOB DUDE now what is there ANYTHING
> BYPASSIFY THAT WE DONT HAVE OR ARENT 1:1 CLONED? wait no not
> perfect it sometimes trails after a bit and sometimes toggle
> stops working it was good when i tested once then didnt work
> lol so ur close LMAO"

> "weird maybe iuts cause our background is translcucent his is
> solid or maybe not cause he has a feature but this induced
> slightly more weird flickering like as u move right or left as
> i move it the baclkground not the overlay but whats behind it
> flickers like hell and even weirder our overlay also flickers
> so it flickers like these black pxiels but once u go over the
> same path then it doesnt tis weird arguably worse are u sure u
> read bypassify right LOL"

**Take the "translucent vs solid bg" hint seriously — that's
LO's own hypothesis and probably correct (matches H2 above).**

## 14. Priority 0 for the next chat

1. **ASK LO to screenshot BP overlay** — static + moving. Don't
   guess H1 vs H2; the screenshots will tell you.
2. If BP bg is opaque → try setting our chat window bg alpha to
   1.0 (or copy their color scheme) and see if trailing dies.
3. If BP bg is translucent → implement H1 (fullscreen ImGui
   viewport with transparent bg + child window for content).
   Test if per-frame full-viewport draw commands eliminate
   trailing without needing explicit clears.
4. If NEITHER helps → deep-read `DrawGptWindow_inner` disasm at
   RVA 0x180003710. Trace every vtable call. There's something
   we're missing.
5. If STILL stuck → attach WinDbg or use RenderDoc to capture
   BP's actual D3D draw calls one frame at a time. Compare
   against ours. The diff IS the trailing fix.

## 15. Priority 1 for the next chat

Once trailing is 1:1 with BP, remaining features BP has that
we lack (from `docs/BYPASSIFY_v1.3_HOTKEYS.md` + this session's
string dumps):

- **In-overlay settings page** (their Ctrl+Shift+S opens
  runtime settings; ours requires re-inject via Electron)
- **Persistent overlay position** across sessions (they
  version their settings v5→v6→v7→v8)
- **"Hotkey Bar"** — user-customizable cheat sheet strip
  they can toggle on/off at the bottom of the overlay
- **Light/dark theme auto-detect** (they read AppsUseLightTheme
  registry value)

## 16. What NOT to do

- **Do NOT re-add** keepalive_thread SCP calls, ghost window,
  hooks_burst_wake, or RC[Window]/RC[Visual] capture detection.
  All those were flicker sources. BP has none of them. Test
  proves stripping them is correct.
- **Do NOT re-flip** `IsOverlayPrevented` back to FALSE. That was
  the day-one bug that caused z-order to fail against
  DirectComposition apps.
- **Do NOT re-add** frame dedup or skip-1-frame. Both perceived
  as flicker by LO.
- **Do NOT use** `ClearView` / `ClearRenderTargetView` on the
  layer texture. Alpha=0 pixels display as black. Confirmed
  by LO on v1.7.4.16.
- **Do NOT use** `AddDirtyRect` on captured PN pThis pointers.
  Confirmed to crash DWM (dwmcore!0xbedb4 fastfail) since
  2026-07-05.
- **Do NOT enable ghost window as default**. Fullscreen alpha=1/255
  layered TOPMOST HWND causes per-GPU flicker on some hardware.
  Opt-in only via `DWM_EXT_GHOST=1`.
- **Do NOT commit** with dev-bypass build. Always rebuild prod
  before commit, verify grep of shipped bins for `DEV BYPASS` +
  `SVCLDB_DEV_AUTH` + `HANDSHAKE SKIPPED` + `custom-dll` = 0.

## 17. Where to find things

| Thing | Path |
|---|---|
| Repo root | `C:\Users\abdul\Desktop\svcldb` |
| GitHub remote | `https://github.com/AbdullahDaGoat/svcldb.git` |
| Deployed C bins | `C:\ProgramData\WinAudioSvc\` |
| Built Electron UI | `C:\Users\abdul\Desktop\svcldb\ui\dist\win-unpacked\svchelper.exe` |
| Distribution zip | `C:\Users\abdul\Desktop\CloakGPTWindowsMaxStealth.zip` |
| Log decrypt tool | `C:\Users\abdul\Desktop\svcldb\tools\dlog.ps1` |
| BP payload binary | `C:\Temp\bp_v13_rsrc\rsrc_101.bin` |
| BP launcher binary | `C:\Users\abdul\Downloads\launchhere (2).exe` (SHA256 matches known v1.3.0) |
| BP RE deep docs | `docs/BYPASSIFY_v1.3_DWM_RE_DEEP.md` |
| BP hotkey reference | `docs/BYPASSIFY_v1.3_HOTKEYS.md` |
| BP parity audit | `docs/BYPASSIFY_v1.3_REVERIFY_2026-07-06.md` |
| Prior handoff | `docs/HANDOFF_2026-07-24_CURSOR_TO_CLAUDE.md` |
| This handoff | `docs/HANDOFF_2026-07-24_TRAILING_BUG_RE_BYPASSIFY.md` |
| Project memory (auto) | `C:\Users\abdul\.claude\projects\C--Users-abdul-Desktop-svcldb\memory\` |
| CLAUDE.md (project rules) | `C:\Users\abdul\Desktop\svcldb\CLAUDE.md` |

## 18. Recent commit log (chronological)

```
de9763e v1.7.4.18 REVERT ClearView (black flash worse than trail)
c7e6373 v1.7.4.17 BP-parity: priority debounce + Quick-Send + CJK fonts
84834a2 v1.7.4.16 ClearView all cached RTVs (backbuffer rotation trail)
47181d2 v1.7.4.15 ClearView on old overlay rect (fixes trailing/shadow)
0c5f7d3 v1.7.4.14 THE ACTUAL FIX: byte-patch dwmcore full-dirty flag (BP slot 11)
859f966 v1.7.4.12 STRIP: kill every wake/ghost/capture layer BP does not have
913bcc2 v1.7.4.11 CRITICAL: flip IsOverlayPrevented patch FALSE→TRUE
bc21389 v1.7.4.13 kill flicker sources + copy BP hotkeys 1:1
1ada1dc docs: BP v1.3.0 default hotkeys reference
2e9c3e6 launcher: --custom-dll dev flag for RE observation
```

Read `git log --stat` from `de9763e` back to `b0e4307` (v1.7.4)
for the full arc if you want full context.

Good luck. Trailing is the one boss fight left before we
1:1 clone BP. LO's screenshots will show the way.
