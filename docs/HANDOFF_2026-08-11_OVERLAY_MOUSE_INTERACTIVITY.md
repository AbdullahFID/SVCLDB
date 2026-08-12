# HANDOFF: overlay mouse interactivity — drag-to-move + live widgets (2026-08-11)

Cursor session, requested by Larpbase.

## Question that started it

> "isn't it true a DWM-injected app can't get a draggable UI — svcldb has
> to be controlled via hotkeys? No bias, if it's possible let me know.
> Some dude has a screenshot with everything workable including a
> draggable overlay while we use hotkeys for everything. If there's a
> shot it's possible, inject it and I'll try to drag it."

Then, once drag worked:

> "can u add a transparency slider in the overlay, i wanna see if i can
> drag a slider around — is buttons possible? create a placeholder
> dropdown."

## Short answer

**The 'DWM overlays can't be draggable / must be hotkey-only' claim is
FALSE.** It was never a platform limitation. svcldb's overlay was pinned
with `ImGuiWindowFlags_NoMove` **on purpose** (v13, 2026-08-10 — LO said
the "AI overlay" title bar was "MADD annoying and mad bad it doesnt
adjust", so the window was made fully hotkey-driven and the title bar was
removed). Rendering into DWM's compositor and *input routing* are two
independent problems: composition happens inside `dwm.exe`, but mouse
input is solved with a hook — which svcldb **already had** for wheel
scroll and mouse-button hotkeys.

As of this session the overlay is **fully mouse-interactive**: drag the
window by any empty background area, and ImGui widgets (a transparency
slider you can drag, buttons that click, a dropdown that opens) work with
the mouse. All existing hotkeys are untouched.

## Why it was easy — the plumbing already existed

Three pieces were already in place before this session:

1. **`WH_MOUSE_LL`** low-level mouse hook (`rawinput_hook.c::ll_mouse_proc`,
   installed on `ll_thread`) — was already routing `WM_MOUSEWHEEL` into
   `ui_scroll_reply` and observing `WM_LBUTTONDOWN/UP` for mouse-button
   hotkeys. It sees every mouse event system-wide with exact screen
   coords in `m->pt`.
2. **`ui_point_in_overlay(x,y)`** (`imgui_layer.cpp`) — hit-tests a screen
   coord against the overlay's live rect (cached each frame in
   `g_last_overlay_{x,y,w,h}`). Was built for wheel-scroll hit-testing.
3. **`ui_nudge(dx,dy)`** (`imgui_layer.cpp`) — the move primitive the
   arrow-key hotkeys already use. Critically, the geometry glide factor
   is `k = 1.0f` (see `ui_present_frame`, "v1.7.8f: 1.0 factor = INSTANT
   snap") so a stream of nudges tracks the cursor **1:1 with zero lag**.

So window-drag = "feed each mouse-move delta into `ui_nudge`," and widget
interactivity = "feed cursor + button into ImGui's IO."

## What shipped — Part A: window drag

In `ll_mouse_proc` (tag: `v14 (2026-08-11)`):

- **`WM_LBUTTONDOWN`** inside the overlay rect (`ui_is_visible() &&
  ui_point_in_overlay`) → grab (`drag_active = 1`, record last point),
  **consume** (`return 1`) so the press doesn't fall through to the app
  underneath (no stray click / drag-select on the page below).
- **`WM_MOUSEMOVE`** while grabbed → `ui_nudge(dx, dy)` with the
  screen-space delta. **Not consumed** — the OS cursor keeps moving
  naturally while the overlay follows it.
- **`WM_LBUTTONUP`** → release, consume the matching up.

New define: `RIN_WM_MOUSEMOVE 0x0200`. New extern: `ui_nudge`.

## What shipped — Part B: full widget interactivity

The DX11/Win32 ImGui backend already feeds cursor **position**
(`ImGui_ImplWin32_NewFrame` reads it off the Progman hwnd), but it
**never sees mouse buttons** — clicks route to whatever app owns the
window under the cursor, not our overlay. So widgets were hover-capable
but not clickable. Fix = publish the button level ourselves.

### New cross-TU plumbing (`imgui_layer.cpp`, extern "C")

```c
static volatile LONG g_ui_mouse_left_down = 0;  /* set by LL hook */
static volatile LONG g_mouse_over_widget  = 0;  /* read by LL hook */

void ui_set_mouse_left_down(int down);  /* LL hook publishes L-button level */
int  ui_mouse_over_widget(void);        /* LL hook asks "yield to widget?" */
```

### Feed cursor + button into ImGui (`ui_present_frame`, right before `ImGui::NewFrame()`)

Queued AFTER the backend `NewFrame` calls so our events win:

```cpp
POINT _cur;
if (GetCursorPos(&_cur))
    io.AddMousePosEvent((float)_cur.x, (float)_cur.y);
io.AddMouseButtonEvent(0, g_ui_mouse_left_down != 0);
```

(ImGui 1.91.9 — `AddMousePosEvent` / `AddMouseButtonEvent` are the modern
event-queue API. Feeding the current level every frame is a no-op unless
it changed, so press/release/click all resolve correctly.)

### Publish "cursor over a widget" (after `draw_chat_window` submits all items)

```cpp
InterlockedExchange(&g_mouse_over_widget,
    (ImGui::IsAnyItemHovered() || ImGui::IsAnyItemActive()) ? 1 : 0);
```

### The drag-vs-widget gate (`ll_mouse_proc`, `WM_LBUTTONDOWN`)

```c
if (wp == RIN_WM_LBUTTONDOWN)    ui_set_mouse_left_down(1);
else if (wp == RIN_WM_LBUTTONUP) ui_set_mouse_left_down(0);
...
if (ui_is_visible() && ui_point_in_overlay(x, y)) {
    press_consumed = 1;
    if (ui_mouse_over_widget()) {
        /* press is on a slider/button/combo — hand to ImGui, NO drag */
    } else {
        drag_active = 1;              /* empty background — window drag */
    }
    return 1;                        /* consume either way (no click-through) */
}
```

Both paths **consume** the click so nothing leaks to the page below.
The button level is published to ImGui regardless, so the widget resolves
from the polled IO state independent of the consume.

### Test panel (`draw_chat_window`, after the status bar — tag `v14`)

A `== v14 MOUSE TEST ==` strip with:
- **`SliderFloat "Transparency"`** — writes `g_alpha` directly under
  `g_ui_cs` + `geom_bump()` (takes effect next frame; `g_alpha` is
  snapshotted at the top of `draw_chat_window`). Range clamped 0.05–1.00.
- **`Button "Click me"` / `"Reset"`** + a `static int` click counter.
- **`Combo "Mode"`** with Alpha/Bravo/Charlie/Delta (placeholder).

## Files touched

- `payload/src/rawinput_hook.c` — `RIN_WM_MOUSEMOVE` define; externs
  `ui_nudge` / `ui_set_mouse_left_down` / `ui_mouse_over_widget`; the
  drag + widget-gate block in `ll_mouse_proc`.
- `payload/src/ui/imgui_layer.cpp` — `g_ui_mouse_left_down` /
  `g_mouse_over_widget` + accessors; the mouse-feed block and
  over-widget publish around `ImGui::NewFrame()`; the test panel in
  `draw_chat_window`.

All greppable by the tag `v14 (2026-08-11)` and `v14:`.

## Verification (from `payload.log`, decrypted)

Fresh inject healthy, no crash:
```
dwm: hooks_install: SUCCESS (Phase A: RUNNING)
ui:  get_backbuffer_texture: OK on first call
ui:  ImGui READY - overlay should render this frame
```
Live interaction:
```
rin: overlay drag: GRAB @ (2532,93)     ->  RELEASE @ (1164,675)   (window drag)
rin: overlay: WIDGET press @ (2327,221) ->  RELEASE @ (2367,244)   (slider drag)
ui:  alpha -> 0.32  ->  alpha -> 0.42                              (transparency live)
```
`nudge dx=-4 dy=2`-style **diagonal** deltas confirm mouse-drag (hotkey
nudges are single-axis only). Tail goes silent the instant the button is
released — no runaway / stuck-drag.

## Tradeoffs & known edge cases

- **Clicks on the overlay do NOT fall through** to the app below (by
  design — that's what lets you grab it). Clicks anywhere else pass
  through normally.
- **Mouse-button hotkeys** (MOUSE_MULTI / MOUSE_HOLD bound to left click)
  do NOT fire when the press is on the overlay — drag/widget wins there.
  They still fire everywhere else.
- **~1-frame (16ms) gate staleness**: `g_mouse_over_widget` reflects the
  previous frame's hover. A very fast stab directly onto a widget can
  start a window-drag instead of using the widget. Rare; acceptable for
  testing. A precise fix would hit-test widget rects in the hook.
- **Combo popup overflow**: if the dropdown popup extends past the cached
  overlay rect, presses on the overflowing items are outside
  `ui_point_in_overlay` so they aren't consumed (ImGui still selects the
  item via polled IO, but the click also reaches the app). Keep test
  combos short / high in the overlay. Not an issue for the 4-item
  placeholder.

## Ship checklist (this is a DEV build)

- Built with `SVCLDB_DEV_AUTH=1` (dev bypass) — **never ship as-is**.
- **Remove the `v14 MOUSE TEST` panel** from `draw_chat_window` before
  any real build (it's cordoned in a single `{ ... }` block tagged
  `v14`).
- Decide the shipping interaction model (see "How to extend").
- The mouse-feed + drag + gate plumbing is production-safe to keep; only
  the test panel is throwaway.

## How to extend (menu of next steps, per LO's call)

- Wire the `Mode` dropdown to the **real model picker** (Claude / GPT /
  etc.) — replace the placeholder combo with the provider/model list.
- Turn the slider into a proper **settings row** (opacity + font +
  scroll-step) as real mouse controls alongside the hotkeys.
- **Modifier-gated interactivity**: only treat clicks as
  drag/widget while a key is held (e.g. Alt), so normal use stays
  pure-hotkey and pure-stealth, and the overlay is click-through
  otherwise. (Gate on the modifier before `press_consumed = 1`.)
- **Corner-resize**: detect a press in a bottom-right grip zone and feed
  `ui_resize(dw, dh)` instead of `ui_nudge`.

## Don't regress

- `NoMove` on the overlay window stays — window movement is driven by
  our geometry system (`ui_nudge` → `g_offset_{x,y}` →
  `SetNextWindowPos(..., ImGuiCond_Always)`), NOT by ImGui's built-in
  window drag (which the `Always` repos would override every frame
  anyway). The custom LL-hook drag is intentional.
- Mouse **position** may be fed by both the Win32 backend and our
  `AddMousePosEvent`; ours is queued last so it wins. Do not remove the
  backend `NewFrame` — it also updates DisplaySize / modifiers / focus.
- Feed the button level from the LL hook, not `GetAsyncKeyState` — the
  latter is documented-unreliable from DWM's process/desktop context
  (see the keyboard-hook notes in `rawinput_hook.c`).
