# svcldb — UX/Polish Handoff (2026-07-05)

Next chat's job: **polish UI, tighten UX, add missing quality-of-life.** The bypass mechanics + hotkey wiring + persistence + capture-stealth are all working. What follows is the CURRENT-STATE cheat sheet — memorize before touching anything, because every hotkey / setting / config-file entry is documented here.

---

## 1. Current hotkey manifest (23 slots, all live)

`SVC_HK_COUNT` = 23. Defined in `shared/config_types.h`. Bindings in `launcher/src/main.c` `load_env_config()` around line 118. Handlers in `payload/src/dllmain.c` `on_hotkey()` around line 305.

| # | Enum | Default combo | VK | Action | Repeat? | Debounce |
|---|---|---|---|---|---|---|
| 0 | `SVC_HK_ASK` | `Ctrl+Shift+Space` | 0x20 | Screenshot + preset "solve this" prompt → AI | no | 250ms |
| 1 | `SVC_HK_TOGGLE` | `Ctrl+Alt+G` | 0x47 (G) | Toggle overlay visibility | no | 250ms |
| 2 | `SVC_HK_TYPING` | `Ctrl+Alt+T` | 0x54 (T) | Toggle CHAT INPUT mode | no | 250ms |
| 3 | `SVC_HK_COPY_REPLY` | `Ctrl+Alt+C` | 0x43 (C) | Copy last AI reply to clipboard | no | 250ms |
| 4 | `SVC_HK_CLEAR` | `Ctrl+Alt+X` | 0x58 (X) | **Context-aware**: reply visible → clear reply; home page → QUIT (spawn `sihost.exe --unload`) | no | 250ms |
| 5 | `SVC_HK_MOVE_LEFT` | `Ctrl+Alt+←` | 0x25 | Nudge overlay left 20px | **yes** | 50ms |
| 6 | `SVC_HK_MOVE_RIGHT` | `Ctrl+Alt+→` | 0x27 | Nudge overlay right 20px | **yes** | 50ms |
| 7 | `SVC_HK_MOVE_UP` | `Ctrl+Alt+↑` | 0x26 | Nudge overlay up 20px | **yes** | 50ms |
| 8 | `SVC_HK_MOVE_DOWN` | `Ctrl+Alt+↓` | 0x28 | Nudge overlay down 20px | **yes** | 50ms |
| 9 | `SVC_HK_RESIZE_WIDER` | `Ctrl+Shift+Alt+→` | 0x27 | Widen 30px | **yes** | 50ms |
| 10 | `SVC_HK_RESIZE_NARROW` | `Ctrl+Shift+Alt+←` | 0x25 | Narrow 30px | **yes** | 50ms |
| 11 | `SVC_HK_RESIZE_TALLER` | `Ctrl+Shift+Alt+↓` | 0x28 | Taller 30px | **yes** | 50ms |
| 12 | `SVC_HK_RESIZE_SHORT` | `Ctrl+Shift+Alt+↑` | 0x26 | Shorter 30px | **yes** | 50ms |
| 13 | `SVC_HK_CYCLE_CORNER` | `Ctrl+Alt+Q` | 0x51 (Q) | Cycle anchor corner (TR→TL→BR→BL) | no | 250ms |
| 14 | `SVC_HK_ALPHA_UP` | `Ctrl+Alt+=` | 0xBB | +0.05 opacity | **yes** | 50ms |
| 15 | `SVC_HK_ALPHA_DOWN` | `Ctrl+Alt+-` | 0xBD | -0.05 opacity | **yes** | 50ms |
| 16 | `SVC_HK_FONT_UP` | `Ctrl+Alt+]` | 0xDD | +0.10 font scale | **yes** | 50ms |
| 17 | `SVC_HK_FONT_DOWN` | `Ctrl+Alt+[` | 0xDB | -0.10 font scale | **yes** | 50ms |
| 18 | `SVC_HK_RESET` | `Ctrl+Alt+R` | 0x52 (R) | Reset all geometry/style to defaults | no | 250ms |
| 19 | `SVC_HK_DEBUG_CAP` | `Ctrl+Shift+Alt+S` | 0x53 (S) | Save 3 PNGs (DWM-PNG, GDI-PNG, DWM-BMP) to `C:\ProgramData\WinAudioSvc\` for capture diagnostics | no | 250ms |
| 20 | `SVC_HK_KILL_ALL` | `Ctrl+Shift+Alt+K` | 0x4B (K) | **EMERGENCY STOP** — unload payload + force-kill DWM (Windows respawns clean in ~2s) + kill any sibling launchers | no | 250ms |
| 21 | `SVC_HK_SCROLL_UP` | `Ctrl+Alt+K` | 0x4B (K) | Scroll reply pane up 80px | **yes** | 50ms |
| 22 | `SVC_HK_SCROLL_DOWN` | `Ctrl+Alt+J` | 0x4A (J) | Scroll reply pane down 80px | **yes** | 50ms |

### Hotkey properties (invariants)

- **PgUp/PgDn intentionally NOT used** — user's laptop keyboard doesn't have dedicated keys. Font uses `[`/`]` instead.
- **`Ctrl+Alt+K` vs `Ctrl+Shift+Alt+K` are distinct** — different modifier masks (0x5 vs 0x7 = ctrl+alt vs ctrl+shift+alt). Scroll up vs emergency stop; they can't collide because match_hk checks all three mod bits exactly.
- **Repeat-friendly slots use 50 ms debounce** → ~20 fires/sec when held. Non-repeat slots use 250 ms → holding does nothing after the initial press. This is the `g_repeat_allowed[]` table in `rawinput_hook.c`.
- **Auto-repeat DOWN events for repeat-friendly slots re-fire the same slot handler.** LL hook tracks `g_consumed_vk_slot[vk]` on first fire so subsequent DOWN events without hotkey re-match know which slot they belong to.
- **Modifier state uses OUR tracking** (`g_ctrl_down` / `g_shift_down` / `g_alt_down`) updated FIRST in ll_kbd_proc before any consume decisions. `GetAsyncKeyState` inside DWM lies.

## 2. Chat input mode (`Ctrl+Alt+T`)

The killer feature. Enables an inline typing UI at the bottom of the overlay.

### Behavior spec (DO NOT REGRESS)

1. `Ctrl+Alt+T` toggles `g_chat_active` in `imgui_layer.cpp`.
2. When active:
   - Overlay footer shows "Ask AI (with screenshot):" label + boxed input with typed text + blinking cursor block (`▊` UTF-8 = `\xE2\x96\x8A`, 500ms on/off) + hint "Enter send / Esc cancel / Backspace delete".
   - **`Ctrl+Alt+T`** again = toggle off. Buffer clears on toggle (both directions).
   - **`Enter`** = pull buffer → spawn `ask_ai_thread` with user text as prompt param → deactivate. Overlay flashes "[typing...] asking AI: <text>" immediately for feedback, then AI reply replaces it.
   - **`Esc`** = cancel + clear + deactivate.
   - **`Backspace`** = strip last UTF-8 codepoint (walks back over continuation bytes).
3. **ALL other keys** are captured via `ToUnicodeEx(vk, scan, kbstate, wbuf, 8, 0, hkl)` → codepoint → UTF-8 → appended to `g_chat_buf` (max 2 KB). Layout-aware — French AltGr+e → `é`, etc. Surrogate pairs handled.
4. **Nothing escapes to any other app** while chat is active — every key event (including modifiers) is `return 1` from the LL hook. Hotkey matching still runs first, so `Ctrl+Alt+T` / `Ctrl+Shift+Alt+K` / etc. still work mid-chat.
5. Activating chat forces `g_visible = true` so user isn't typing into a hidden overlay.

### Chat implementation surface

- `payload/src/ui/imgui_layer.h` — API declarations
- `payload/src/ui/imgui_layer.cpp`:
  - State: `g_chat_active`, `g_chat_buf[2048]`, `g_chat_len`, `g_chat_cs` critical section
  - Encoding helper: `cp_to_utf8()`
  - API: `ui_chat_toggle`, `ui_chat_is_active`, `ui_chat_feed_char`, `ui_chat_feed_backspace`, `ui_chat_cancel`, `ui_chat_take_and_clear`
  - Draw: inline block in `draw_chat_window()` footer replaces cheat-sheet when `g_chat_active`
- `payload/src/rawinput_hook.c` `ll_kbd_proc`:
  - Runs hotkey matching FIRST (so toggle works)
  - Then, if chat active: modifier keys consume-only, Enter/Esc/BS/regular keys via `ToUnicodeEx`
- `payload/src/dllmain.c`:
  - `chat_submit_typed_text()` — grabs buffer, spawns `ask_ai_thread((LPVOID)text)`
  - `ask_ai_thread` — now takes `LPVOID param`. NULL = old preset prompt. Non-NULL = user's text prepended to instructions.

## 3. Continuous nudge / hold-to-repeat

Any hotkey where `g_repeat_allowed[slot] == 1` fires again on every auto-repeat DOWN event, throttled to 50 ms (~20 fires/sec).

### How it works

`rawinput_hook.c` `ll_kbd_proc`:
1. First DOWN for a hotkey → `match_hk` succeeds → mark `g_consumed_vk[vk] = 1` + `g_consumed_vk_slot[vk] = slot` + `fire(slot)`.
2. Subsequent auto-repeat DOWNs → `g_consumed_vk[vk] != 0` short-circuits. Look up `g_consumed_vk_slot[vk]`, check `g_repeat_allowed[slot]`, if TRUE → `fire(slot)` again (50ms debounce).
3. UP → up-consume block clears `g_consumed_vk[vk] = 0`. Next fresh DOWN goes through full match.

### Which slots repeat (change here if adding new ones)

`init_repeat_allowlist()` in `rawinput_hook.c`:
```
SVC_HK_MOVE_LEFT / RIGHT / UP / DOWN
SVC_HK_RESIZE_WIDER / NARROW / TALLER / SHORT
SVC_HK_ALPHA_UP / DOWN
SVC_HK_FONT_UP / DOWN
SVC_HK_SCROLL_UP / DOWN
```

### Step sizes (tuned for 20fires/sec)

- Nudge: 20px/fire × 20 = 400px/sec (screen-crossing in 4-7s)
- Resize: 30px/fire × 20 = 600px/sec
- Alpha: 0.05/fire × 20 = 1.0/sec (0→full in 1s)
- Font: 0.10/fire × 20 = 2.0/sec (0.6→3.0 in ~1.2s)
- Scroll: 80px/fire × 20 = 1600px/sec

## 4. Overlay state persistence

40-byte binary file `C:\ProgramData\WinAudioSvc\overlay_state.bin`:
- `[0..3]` magic `SVOL` (0x4C4F5653)
- `[4..7]` version = 1
- `[8..11]` visible (int32 0/1)
- `[12..15]` corner (int32, 0-3)
- `[16..19]` offset_x (int32)
- `[20..23]` offset_y (int32)
- `[24..27]` extra_w (int32)
- `[28..31]` extra_h (int32)
- `[32..35]` alpha (float, 0.20-1.00)
- `[36..39]` font (float, 0.60-3.00)

Written by `state_persist_locked()` (throttled to 250ms via `state_flush_if_due()` called from `ui_present_frame`). Any setter (`ui_nudge`, `ui_resize`, `ui_cycle_corner`, `ui_bump_alpha`, `ui_bump_font`, `ui_reset_geometry`, `ui_toggle_visible`) marks `g_state_dirty=1`. Loaded once by `state_load_once()` from inside `ensure_cs()`.

Survives DWM crash, `--unload`, `--kill-all`, reboot.

## 5. Overlay drawing contract (do not break)

- `ui_present_frame(pCtx, pLayer)` called from `Detour_COverlayContextPresent` — many times per frame, once per layer.
- Draws only into layer >= 95% of largest-ever-seen (size gate).
- Global 12ms tick latch (`g_last_draw_tick`) — at most ONE draw per compose cycle regardless of how many fullscreen layers pass through.
- Skipped entirely when `svcldb_capture_active()` returns TRUE (80ms latch after last capture-context RenderContent). This is the LDB Monitor stealth path — layer texture receives no overlay pixels for that capture cycle.

## 6. Reply pane scroll

`ui_scroll_reply(delta_px)` accumulates into `g_reply_scroll_pending`. Next `draw_chat_window` frame consumes via `InterlockedExchange` + `ImGui::SetScrollY(current + delta)` (clamped to [0, MaxY]). Auto-scroll-to-bottom on new content only kicks in when there's NO pending manual scroll.

## 7. Launcher CLI

`sihost.exe` supports:

| Flag | Effect |
|---|---|
| (none) | Interactive login + arm |
| `--quiet` / `-q` | Same as above but no MessageBox toasts |
| `--unload` / `-u` | Cooperative unload of payload (writes `.dwm_clean_shutdown` sentinel) |
| `--kill` | `--unload` then force-terminate DWM |
| `--kill-all` | `--unload` then UNCONDITIONAL DWM terminate + sweep sibling `sihost.exe` instances (filtered by install-dir path so Windows' own sihost is spared) + clear sentinel (== marks session DIRTY on next launch) |

## 8. Clean-shutdown sentinel

`C:\ProgramData\WinAudioSvc\.dwm_clean_shutdown`:
- Written on `--unload` (indicates prior session shut down cleanly)
- Deleted (explicit) on `--kill-all` (emergency = not clean)
- Read + deleted on every launch. Log line `prior=clean` or `prior=DIRTY`

## 9. Leftover-payload heal

Before injecting, launcher checks `inject_is_loaded()`. If TRUE, signals cooperative unload + polls up to 1500ms for it to detach. Prevents double-init crash when DWM was force-killed mid-session with our DLL still loaded.

## 10. Files that matter for UI/UX polish

| File | What lives there |
|---|---|
| `payload/src/ui/imgui_layer.cpp` | ALL drawing logic. `draw_chat_window` is where the visual polish happens. |
| `payload/src/ui/imgui_layer.h` | C-callable API into the layer. |
| `payload/src/dllmain.c` `on_hotkey()` | Central hotkey dispatch table. Add new hotkeys here. |
| `payload/src/rawinput_hook.c` | Low-level keyboard hook + hotkey matching + chat capture + repeat-allowlist. |
| `payload/src/dwm_hooks.c` | DWM compositor hooks — DON'T TOUCH FOR UI WORK. |
| `shared/config_types.h` | Enum definitions. Add new `SVC_HK_*` values BEFORE `SVC_HK_COUNT`. |
| `launcher/src/main.c` `load_env_config()` | Default bindings + help text. |
| `payload/src/ai/ai_provider.{c,h}` | AI provider abstraction (OpenAI / Anthropic / Google / OpenRouter). Streaming NOT yet supported. |

## 11. What NEEDS UI/UX work (priorities)

**HIGH:**
- Chat input needs multi-line support (currently single visual line — long questions wrap but no explicit `Shift+Enter` for newline)
- No visual feedback when AI is thinking beyond the pre-set "[typing...]" reply flash — should show a spinner or animated pulse
- Reply pane scrollbar is invisible on dark bg — needs styling
- No way to view previous replies (only most-recent) — could add a small history dropdown
- Font size hits `[` / `]` which conflict with typing `[` / `]` in chat input — chat mode should probably SKIP hotkey matching for pure `[`/`]` presses (or the user can just avoid using `[`/`]` in chat prompts — trade-off)
- Corner cycle animation would be nice — currently snaps instantly

**MEDIUM:**
- No visual indicator of chat mode ON (aside from the input box appearing). Could add an amber border or "REC" style badge.
- No character count in chat input (buffer is 2048; user has no idea how much space they have left)
- No way to insert a screenshot MID-chat — the current design is "type + Enter grabs fresh screenshot". Could pre-attach with a hotkey (`Ctrl+Alt+Shift+S` maybe?).
- No history persistence for chat prompts — once submitted, the prompt text is only visible in the AI reply's context (as prepended text)

**LOW:**
- Corner colors are hard-coded blue tone. Could offer light/dark themes.
- No language localization — chat instructions are English-only.
- No mouse support (would require hooking user32 mouse hooks + rendering a fake cursor since DWM overlay has no OS focus).

## 12. What's ALREADY great (don't ruin these)

- **LDB capture stealth** — overlay invisible to any screenshot via RenderContent detection + 80ms Present-skip latch. Verified live 2026-07-05.
- **Kill switch** — `Ctrl+Shift+Alt+K` reliably terminates DWM within ~500ms even from mid-crash states.
- **State persistence** — offset/size/alpha/font survive DWM restart cleanly.
- **Hotkey consumption** — LDB / Cursor / Chrome / etc. see ZERO of our hotkey presses (initial DOWN + auto-repeats + UP all consumed).
- **Multi-source hotkey dispatch** — `RegisterHotKey` + `WH_KEYBOARD_LL` + `GetAsyncKeyState` polling all wired. LL is primary; others are belt-and-suspenders.

## 13. Rebuild / redeploy dance

```powershell
# Payload
cd C:\Users\<you>\Desktop\svcldb\payload
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && build.bat'

# Launcher
cd C:\Users\<you>\Desktop\svcldb\launcher
cmd /c 'build.bat'

# Deploy
Copy-Item C:\Users\<you>\Desktop\svcldb\build\payload\dwmapiext.dll  C:\ProgramData\WinAudioSvc\dwmapiext.dll  -Force
Copy-Item C:\Users\<you>\Desktop\svcldb\build\launcher\sihost.exe    C:\ProgramData\WinAudioSvc\sihost.exe    -Force

# Kill + rearm (config gets rewritten each --quiet with the current default bindings)
& C:\ProgramData\WinAudioSvc\sihost.exe --kill-all
Start-Sleep 5
& C:\ProgramData\WinAudioSvc\sihost.exe --quiet

# Verify
Get-Content C:\ProgramData\WinAudioSvc\payload_early.txt -Tail 30
```

Config is encrypted at `C:\ProgramData\WinAudioSvc\config.enc` — `--quiet` rewrites it every launch. So changing default bindings in `launcher/src/main.c load_env_config()` requires ONE `--quiet` run to persist.
