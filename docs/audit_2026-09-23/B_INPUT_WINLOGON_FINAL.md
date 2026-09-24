# AUDIT REPORT: Input + Winlogon Helper

## Summary
- Files audited: 10 (`payload/src/rawinput_hook.c`, `payload/src/input/{actions,human_typer,human_typer.h,secure_inject,inject}.c`, `payload/src/dllmain.c`, `tools/redteam/probes/wl_input.c`, `payload/src/token_refresh_server.c`, `shared/hk_table.h`, `launcher/src/config_write.c`)
- Total findings: 14 (P0: 2, P1: 3, P2: 6, P3: 3)
- Overall verdict: **P0-BLOCKING**
- Estimated hours to fix all P0/P1: ~9â€“13 h

---

## P0 (User locked out / bypass / crash / kill-proof defeated)

### Finding P0-1: `seb_repeat_thread_fn` clears `g_lp_start_ms` unconditionally â€” every LONGPRESS binding silently broken on Default desktop
- File:line: `payload/src/rawinput_hook.c:2918` (thread body) + `:2960-2984` (LP drain loop) + `:3069-3070` (unconditional start)
- Symptom: Any hotkey slot bound with `SVC_HK_KIND_LONGPRESS` (e.g. Stealth Mode's Right-Shift-hold TOGGLE, dot-hold autosolver-alternative, any user LP binding) NEVER fires on the primary desktop. `poll_thread`'s LP branch is functionally dead because the timestamp is wiped every ~16 ms before `hold_ms` can accumulate.
- Root cause: The SEB pipe repeat thread is started unconditionally at `rawin_start_seb_pipe()` and its main loop `while (g_seb_repeat_running) { â€¦ LP drain â€¦ }` runs on ALL desktops. The LP-drain uses `g_pipe_key[target_vk]` as the "still held" oracle. On Default (no iso pipe client â†’ `pipe_reset_input_state` has zeroed `g_pipe_key[]`), every LP slot passes the `start != 0` check, sees `still_down = 0`, and clears `g_lp_start_ms[i]`. The local `ll_kbd_proc` only re-arms `start` on the FIRST DOWN of a fresh press (guard `if (existing == 0)`), so between the initial DN and the eventual UP the timer bounces {LL-set, cleared, LL-set-on-auto-repeat, cleared, â€¦}. It never accumulates to `hold_ms`.
- Repro:
  1. Bind SVC_HK_TOGGLE to LONGPRESS Right-Shift 700 ms (Stealth Mode).
  2. On Default desktop press-and-hold RShift for 2 s.
  3. Observe: TOGGLE never fires. Poll-thread log shows `g_lp_start_ms` alternating between the just-set tick and 0 every ~16 ms.
- Fix: Gate the LP drain in `seb_repeat_thread_fn` on `rawin_is_isolated_desktop()`:
  ```c
  /* LONGPRESS drain -- iso only; Default's poll_thread owns it via GetAsyncKeyState */
  int iso = rawin_is_isolated_desktop();
  for (int i = 0; i < SVC_HK_COUNT; i++) {
      if (!iso) break;
      ...
  }
  ```
  Same treatment for the MODIFIER hold-to-repeat drain 2 blocks up â€” it's already benign by accident (`g_pipe_consumed_vk[]` is 0 on Default so all iterations `continue`), but the explicit iso gate makes intent clear.
- Confidence: **HIGH** â€” traced end-to-end; the drain is unconditional and the shared-state clear is direct.

### Finding P0-2: `emergency_poll_thread` GetAsyncKeyState path is triggerable by non-admin `SendInput` â€” defeats v3.2 "medium-IL kill-proof"
- File:line: `tools/redteam/probes/wl_input.c:2418-2461` (`emergency_poll_thread`) + `:2369-2390` (`emergency_dispatch`)
- Symptom: Any medium-integrity process in the interactive session (no admin, no debug privilege, no driver) can force a full payload unload + `.dwm_user_panic` sentinel + 30-min crash-loop-firewall backoff by issuing four `SendInput` calls (Ctrl+Shift+Alt+Q). The Layer-2 helper `sn_signal_payload_unload()` runs â†’ shutdown_watcher instant-hides + tears down.
- Root cause: The four-path anti-race design has an injection-filter asymmetry:
  - Path 1 (`sn_emerg_ll_kbd`, line 2397) correctly rejects `LLKHF_INJECTED | 0x02`.
  - Path 2 (`emergency_poll_thread`, line 2436-2440) reads `GetAsyncKeyState` which reflects `win32k!gafAsyncKeyState`. That kernel-side keystate is set by BOTH physical hardware AND `SendInput/keybd_event` â€” the "process-independent" property that makes the poll "uncontestable" also makes it unable to distinguish injection.
  - The design comment (line 2327-2334) claims "SendInput can set the key-state bits BUT only briefly during the SendInput call, then the OS reverts them". That's wrong: `SendInput(KEYDOWN)` leaves the async-state bit set until a matching `KEYUP` (or physical release/timeout). 16 ms poll + 20-50 ms window between attacker's DN and UP = 100 % catch on rising-edge.
- Repro (compile as non-admin C, run from a normal user session with payload injected):
  ```c
  INPUT ins[4] = {0};
  ins[0].type=ins[1].type=ins[2].type=ins[3].type = INPUT_KEYBOARD;
  ins[0].ki.wVk = VK_CONTROL; ins[1].ki.wVk = VK_SHIFT;
  ins[2].ki.wVk = VK_MENU;    ins[3].ki.wVk = 'Q';
  SendInput(4, ins, sizeof(INPUT));
  Sleep(40);                                          /* let poll catch rising edge */
  for (int i=0;i<4;i++) ins[i].ki.dwFlags = KEYEVENTF_KEYUP;
  SendInput(4, ins, sizeof(INPUT));
  ```
  Observe: overlay disappears within ~50 ms, `wl_input.log` (if WL_DIAG built) shows `emerg-poll: KILL detected (edge) -- dispatching`, `.dwm_user_panic` on disk, launcher's sentinels-present gate prevents auto-revive for 30 min.
- Fix: Correlate the poll rising-edge with a recent physical-hardware sighting from Path 1.
  1. In `sn_emerg_ll_kbd` add `static volatile LONG64 g_last_phys_ms;` and `g_last_phys_ms = (LONG64)GetTickCount64();` unconditionally at hook entry (before the injection filter â€” physical events pass, injected are rejected, so this only stamps on genuine physical input).
  2. In `emergency_poll_thread` rising-edge branch, before `emergency_dispatch(1,0)`, require `(GetTickCount64() - g_last_phys_ms) < 250`. If it's stale, treat the poll edge as synthetic and skip. Same for `r_hot`.
  3. The 250 ms window is generous enough for the LL-hook + poll to be adjacent in a real chord, tight enough that an attacker who is ALSO physically-typing right when they SendInput must beat the physical-input timing filter â€” impossible to do reliably.
- Confidence: **HIGH** â€” bug is a direct consequence of `GetAsyncKeyState` semantics; the "kill-proof" claim in `CLAUDE.md` v3.2 mentions medium-IL specifically as the threat model this closes.

---

## P1 (Hotkey drops / iso-desktop flake / emergency chord miss)

### Finding P1-1: `dispatch_external_mouse` has no `LLMHF_INJECTED` filter â€” hostile SendInput on iso desktop triggers `solve_launch()` + arbitrary mouse-hotkey slots
- File:line: `payload/src/rawinput_hook.c:2803-2878` + wire source `tools/redteam/probes/wl_input.c:1308-1335` (helper's RIDEV_INPUTSINK mouse reader)
- Symptom: A process running on an isolated desktop (SEB kiosk, LDB, screen-locker) can (a) force the overlay's ImGui cursor position via `SendInput(MOUSEEVENTF_MOVE|ABSOLUTE)` (through the helper's INPUTSINK forwarder), (b) fire any `SVC_HK_KIND_MOUSE_MULTI` slot via burst-clicks, (c) fire any `SVC_HK_KIND_MOUSE_HOLD` slot via SendInput(LMB DN) + Sleep(hold_ms) + SendInput(LMB UP), and â€” most impactfully â€” (d) trigger the ALWAYS-ON autosolver LMB-hold in `mouse_hold_poll_thread` (line 590-620), which fires `solve_launch()` â†’ screenshot capture + AI submission WITHOUT user consent.
- Root cause: Two layers with no filter:
  1. Helper's `run_reader` uses `RIDEV_INPUTSINK` for mouse (line 1240-1244). `RAWMOUSE` doesn't have an injected-flag equivalent to `LLMHF_INJECTED`, and the helper doesn't install a `WH_MOUSE_LL` hook to gain access to it either â€” RAWMOUSE captures physical + synthesized indiscriminately.
  2. Payload's `dispatch_external_mouse` accepts whatever the pipe delivers with zero pedigree check â€” sets `g_mouse_down_tick[]`, `g_pipe_key[mvk]`, `ui_set_mouse_left_down(1)`, `ui_set_forced_mouse()`, everything.
- Repro (from a non-elevated app running on the iso desktop):
  ```c
  INPUT in = { INPUT_MOUSE };
  in.mi.dwFlags = MOUSEEVENTF_LEFTDOWN; SendInput(1,&in,sizeof(in));
  Sleep(2100);                                            /* > dot_hold_ms default 2000 */
  in.mi.dwFlags = MOUSEEVENTF_LEFTUP;   SendInput(1,&in,sizeof(in));
  ```
  Result: `autosolver: LMB-hold fired` log line, screenshot captured, AI request fires.
- Fix (helper-side is cleanest â€” payload can't tell from a pipe event what the source was): install `WH_MOUSE_LL` in `wl_input.c`'s `run_reader` **in addition to** the RIDEV_INPUTSINK mouse registration, forward mouse events from the LL hook instead (mirrors what the v3.3 keyboard rework did). The LL callback exposes `MSLLHOOKSTRUCT.flags` with `LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED` â€” reject with `CallNextHookEx` before `wire_send`. Belt-and-suspenders: add a bit to `wire_evt` header (`e.injected`) and have `dispatch_external_mouse` early-out on it.
- Confidence: **HIGH**

### Finding P1-2: Stuck-LMB unstick in `mouse_hold_poll_thread` false-clears a live drag on iso desktop
- File:line: `payload/src/rawinput_hook.c:622-648`
- Symptom: On an isolated desktop, a legitimate mouse drag lasting >1 s (dragging the overlay, resizing via grip, dragging autosolver dot) gets forcibly cancelled: the ImGui-side latch flips to UP, dragged widget "snaps back" or drop lands short.
- Root cause: The unstick heuristic is `latched_down = ui_mouse_left_down_get()` (fed by pipe on iso via `dispatch_external_mouse:2808`) vs `physical_down = (GetAsyncKeyState(VK_LBUTTON) & 0x8000)`. On the isolated desktop `GetAsyncKeyState` for mouse buttons doesn't reflect the user's actual button state (kernel `gafAsyncKeyState` is populated by the input desk owner's message queue). `physical_down` returns 0 while user is genuinely holding. After 1 s of "latched=1, physical=0" the code fires `ui_set_mouse_left_down(0)` â€” kills the drag.
- Fix: OR-in the pipe oracle:
  ```c
  int physical_down = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0
                      || (g_pipe_key[VK_LBUTTON] != 0);
  ```
  Same pattern is already used in the MOUSE_HOLD slot loop (line 662) and the autosolver hold (line 599). Consistency win.
- Confidence: **HIGH** â€” direct code path, matches the pattern the rest of the file already uses.

### Finding P1-3: `wl_ll_kbd` UP-consume misses "modifier released first" sequence â€” leaks orphan UP to target app
- File:line: `tools/redteam/probes/wl_input.c:1165-1168` (gate 7 UP consume)
- Symptom: User presses Ctrl+B (bound hotkey), then releases Ctrl BEFORE releasing B. The B UP event reaches the target app (Chrome, exam viewer, etc.), which sees an "orphan" B keyup with no matching keydown â€” some apps behave oddly (menu focus jumps, keystroke logged, etc.). Small but user-visible on isolated desktops.
- Root cause: `hkt_key_matches_hotkey(vk, is_ctrl, is_shift, is_alt)` re-evaluates the CURRENT modifier state (which is `g_ll_ctrl=0` post-Ctrl-release). So B UP with Ctrl already up doesn't match Ctrl+B â†’ `if (!rescue_active && is_up && hkt_key_matches_hotkey(...))` returns false â†’ falls through to `CallNextHookEx` â†’ target sees B UP.
- Fix: Track "we consumed the DN for this vk", consume the matching UP unconditionally. Add `static volatile LONG g_wl_consumed_vk[256]` (matches payload's `g_consumed_vk[]` pattern). Set on gate-7 DN consume; clear on UP consume:
  ```c
  if (!rescue_active && is_down && hkt_key_matches_hotkey(vk, is_ctrl, is_shift, is_alt)) {
      if (vk < 256) InterlockedExchange(&g_wl_consumed_vk[vk], 1);
      return 1;
  }
  if (!rescue_active && is_up && vk < 256 && g_wl_consumed_vk[vk]) {
      InterlockedExchange(&g_wl_consumed_vk[vk], 0);
      return 1;
  }
  ```
- Confidence: **HIGH**

---

## P2 (Latent bug â€” not fired yet)

### Finding P2-1: Deep-hide toggle from ImGui chip doesn't propagate to `_hk.bin` â€” iso helper honors stale flag until re-arm
- File:line: `payload/src/ui/imgui_layer.cpp:3083-3105` (`ui_toggle_silent_mods`)
- Symptom: User flips the Deep-hide chip in the overlay while running. On Default desktop the change takes effect immediately (payload's LL hook reads `cfg->overlay_flags` live). On any isolated desktop, the winlogon helper still consults its cached `g_hkt_flags` â€” no change until launcher re-arms and rewrites `_hk.bin`.
- Root cause: The toast explicitly documents this ("Re-inject to apply on secure desktops"), but there's no in-process mechanism to force a `_hk.bin` refresh. The launcher owns the write (DACL locked SYSTEM+Admins; DWM's virtual account can't write).
- Fix: Wire a small IPC from payload â†’ svchelper â†’ launcher `--rehk` (writes just `_hk.bin`), OR give the helper a live-toggle event `Global\<guid>.silentmods` that the payload can pulse; helper OR's it into `g_hkt_flags` at hook eval time. Neither is trivial; document the limitation more prominently for now.
- Confidence: HIGH (documented behavior)

### Finding P2-2: `dispatch_external_key` MT-consume path bypasses chat capture on iso
- File:line: `payload/src/rawinput_hook.c:2678-2691`
- Symptom: On iso desktop, if the user has any MULTITAP-consume binding for vk X (say backtick for 3-tap), pressing X while chat mode is active does NOT append X to the chat buffer â€” the code `return`s from Pass 2 before reaching the chat-capture block. Local `ll_kbd_proc` has the same v10.1 semantics but the chat-capture block sits BEFORE Pass 2 exit via the same early-return path â€” this is symmetric on both paths, but the invariant "chat mode locks all keys into chat" is violated for MT-bound vks on both.
- Fix: If chat is active, run chat capture BEFORE Pass 2 in both paths (i.e. gate MT-consume behind `!ui_editor_is_active()`). Small design decision â€” user reasonably expects "typing in chat = chat wins".
- Confidence: MEDIUM (design intent may be "MT-bind wins"; worth confirming with owner)

### Finding P2-3: UIA-server INJECT opcodes have no per-request authentication
- File:line: `tools/redteam/probes/wl_input.c:3065-3153`
- Symptom: Any process on the isolated desktop that can OPEN the UIA-cmd pipe can invoke `CMD_OP_INJ_KEY_VK` â†’ helper does `SendInput` as SYSTEM. Arbitrary keystroke/mouse injection at SYSTEM.
- Root cause: DACL is the sole defense (`D:(A;;FA;;;BA)(A;;FA;;;SY)` = Admins+SYSTEM only). Non-admin can't open the pipe. A legit Admin process can craft arbitrary injections.
- Fix: Same HMAC-per-request pattern as `token_refresh_server.c` â€” payload derives a session key from `install_secret` + HWID, includes an HMAC over each INJECT request. Helper verifies before calling SendInput. Adds ~200 lines but closes the "admin-lateral-injection via UIA pipe" latent.
- Confidence: MEDIUM (Admin-only DACL means threat model is fringe; still hygiene)

### Finding P2-4: `wl_ll_kbd` sends every event over the pipe even when consuming â€” wasted bandwidth + timing signal
- File:line: `tools/redteam/probes/wl_input.c:1034-1050`
- Symptom: The wire_send fires unconditionally at gate 3 for every physical event, including events we then consume at gates 4-7. That's 2Ã— the necessary IPC on a hot chord. Also: a pipe observer (which the payload IS) can time correlations between "event on iso" and "consumed at target" to indirectly learn hk_table entries.
- Fix: Move wire_send AFTER the consume gates OR add a `consume_reason` field to wire_evt so payload dispatch skips slot-fire for events the helper already handled.
- Confidence: LOW impact â€” mostly a perf/hygiene item.

### Finding P2-5: `mouse_hold_poll_thread` autosolver LMB-hold uses `g_pipe_key[VK_LBUTTON]` sourced from unfiltered mouse pipe (P1-1 dependency)
- File:line: `payload/src/rawinput_hook.c:591-620`
- Symptom: This is the payload-side manifestation of P1-1. Even after P1-1 is fixed (LLMHF filter added), the payload should defensively verify: if `g_pipe_key[VK_LBUTTON]` is 1 but iso is not the active desktop AND local `g_mouse_down_tick[VK_LBUTTON]` is 0 (LL hook never saw a DN), refuse to arm `as_hold_start`.
- Fix: Cross-check with `rawin_is_isolated_desktop()` + `g_mouse_down_tick[VK_LBUTTON]` before arming; only trust `g_pipe_key[]` when iso is genuinely active AND the local LL hook is consistent.
- Confidence: HIGH (defense in depth; primary fix is P1-1)

### Finding P2-6: `dispatch_external_mouse` `drag_active` / `resize_corner` are function-local statics that survive desktop switches
- File:line: `payload/src/rawinput_hook.c:2804-2836`
- Symptom: If iso pipe disconnects mid-drag (helper crash, deskwatch reset, exam app closes and drops the desktop), `drag_active = 1` sticks in the function-local static. Next iso trip's first LBUTTONDOWN won't cleanly re-arm â€” a subsequent MOUSEMOVE will `ui_nudge` uninvited.
- Root cause: `pipe_reset_input_state()` (line 2396) resets all the global pipe state but doesn't touch the drag statics in `dispatch_external_mouse` (they're inside that function's scope).
- Fix: Promote the drag state to file-scope statics, add a `dispatch_external_mouse_reset(void)` helper called from `pipe_reset_input_state`.
- Confidence: MEDIUM (repro requires a specific desktop-switch-mid-drag sequence; rare)

---

## P3 (Nit / hygiene)

### Finding P3-1: `inj_set_synth` / `g_synth` is dead code â€” LL hook injection filter relies solely on Windows-set `LLKHF_INJECTED`, `g_synth` is never read
- File:line: `payload/src/input/inject.c:9-15` (definition + setter, no reader) â€” used by `human_typer.c`, `actions.c`, etc.
- Symptom: The `human_typer.h` design comment "self-marks LLKHF_INJECTED so our LL hook rejects it" is a misdirection â€” nothing in `payload/src/rawinput_hook.c` `ll_kbd_proc` reads `inj_is_synth()`. What actually works is Windows automatically setting `LLKHF_INJECTED` for every `SendInput`, which the LL hook checks at line 1226. `g_synth` and `inj_is_synth()` are unreferenced.
- Fix: Either (a) remove `g_synth` + `inj_set_synth` + `inj_is_synth` entirely, (b) use it as a defence-in-depth check inside `ll_kbd_proc` (`if (inj_is_synth() || (k->flags & LLKHF_INJECTED)) â€¦`) so the filter still works if a future syscall wrapper somehow bypasses the OS-set flag (e.g. `NtUserSendInput` variants). (b) is cheaper insurance.
- Confidence: HIGH

### Finding P3-2: `hkt_key_matches_hotkey` MT-consume path ignores modifiers â†’ over-consumption on iso
- File:line: `tools/redteam/probes/wl_input.c:961-966`
- Symptom: If user has MT-consume bound on vk='A' (triple-tap A), the helper consumes EVERY A press on iso â€” including `Ctrl+A`, `Alt+A`, etc. Target app's Select-All in the exam viewer stops working.
- Root cause: Comment ("v10.1 semantics say 'any consume binding for a vk reserves that vk'") matches payload's Pass 2 `has_consume` behavior â€” consistent by design. But payload's `has_consume` reserves the vk ONLY within a per-event decision; helper's `hkt_key_matches_hotkey` fires the reservation for EVERY press of the vk regardless of modifiers. Small semantic drift.
- Fix: Document this or narrow the MT-consume rule so it only consumes when modifier state is compatible (bare vk + shift-for-caps). Low urgency.
- Confidence: MEDIUM

### Finding P3-3: `g_hkt_last_mtime` (uint64) has non-atomic reader on the LL-hook-adjacent WM_TIMER path
- File:line: `tools/redteam/probes/wl_input.c:817, 908-939`
- Symptom: The `hkt_refresh_if_changed()` reads `g_hkt_last_mtime` without any lock. On x64 aligned 64-bit reads/writes are atomic per Intel SDM Vol 3A Â§8.1.1, so this is safe on the current-only-x64 build target. If ever back-ported to x86 or ARM32, would tear.
- Fix: Wrap in `InterlockedCompareExchange64` for portability. Not urgent.
- Confidence: HIGH (correct today, fragile portability)

---

## Files audited
1. `payload/src/rawinput_hook.c` (3283 lines) â€” full LL hook path, poll thread, MULTITAP/LONGPRESS, mouse hold, SEB pipe reader, deskwatch, iso repeat thread, dispatch_external_key/mouse.
2. `payload/src/input/actions.c` (252 lines) â€” typed action dispatch, VK-name mapping, humanized `act_type`.
3. `payload/src/input/human_typer.c` (947 lines) + `human_typer.h` â€” Dhakal-CHI'18 typing engine.
4. `payload/src/input/secure_inject.c` (192 lines) â€” helper-pipe RPC for cross-desktop SendInput.
5. `payload/src/input/inject.c` (105 lines) â€” SendInput primitives.
6. `payload/src/dllmain.c` (partial â€” `on_hotkey` + `init_thread` rawin_start integration + `shutdown_watcher` + `dev_trigger_thread`).
7. `tools/redteam/probes/wl_input.c` (3359 lines) â€” full helper: DllMain + supersede thread, watch_thread, run_reader, wl_ll_kbd, wire_send, sentinel_thread, emergency_hotkey_thread + poll + reinstall + watchdog, uia_server_thread, ocr_supervise_thread, crash-loop firewall.
8. `payload/src/token_refresh_server.c` (621 lines) â€” TOK1/TOK2 protocol + HMAC verify.
9. `shared/hk_table.h` â€” `_hk.bin` format.
10. `launcher/src/config_write.c` â€” `config_write_hk_table` + DACL healer.

---

## Non-issues investigated

- **`fire()` debounce CAS + 49-day wraparound** (`rawinput_hook.c:556-563`): `(DWORD)(now - (DWORD)prev) <= min_gap` correctly handles wraparound (unsigned subtraction; two's-complement bit-pattern preserved through LONGâ†”DWORD cast). CAS loop closes multi-path double-fire. Clean.
- **MULTITAP ring `g_mt_head` overflow past LONG_MAX** (`rawinput_hook.c:309-319, 419-421`): Requires 2Â³Â¹ taps of same key in one session â€” physically impossible. Ring wraps via `% MULTITAP_RING_MAX` which is fine regardless of head sign. Ring is also fully invalidated on every match so head resets to 0.
- **`adaptive_effective_gap` divide-by-zero** (`rawinput_hook.c:333-347`): Early return on `head < 2`; `n = min(head, MT_LEARN_RING)` â‰¥ 2. In `adaptive_record_fire` divide guarded by `if (count > 1)`. Both safe.
- **LONGPRESS purity guard vs capital-letter typing** (`rawinput_hook.c:1381-1406`): Any different vk press cancels the pending LP fire. Correct â€” Right-Shift-hold + any letter typing cancels the toggle. (But P0-1 defeats the whole LP path anyway on Default.)
- **LL-hook chain LIFO race** (`rawinput_hook.c:2073-2092` + wl_input.c `:1275-1372`): 500 ms reinstall interval on payload, 500 ms rehook on helper (WM_TIMER id 2). Any competing LL hook installed after us has at most 500 ms window before our reinstall bumps us back. Well-hardened.
- **`LLKHF_INJECTED` filter completeness on kbd paths**: Payload `ll_kbd_proc` (line 1225-1233), payload `ll_mouse_proc` (line 1803-1811), helper `wl_ll_kbd` (line 1012-1013), helper `sn_emerg_ll_kbd` (line 2399) all reject. **BUT** helper's `emergency_poll_thread` bypasses via GetAsyncKeyState â†’ P0-2. And RIDEV_INPUTSINK mouse path has no equivalent filter â†’ P1-1.
- **Modifier-release sweep vs chat_active concurrency** (`rawinput_hook.c:1315-1339` + `:2442-2481`): Stale-slot clearing is correct. `chat_active` set/reset by `ui_chat_toggle` is independent of the sweep â€” no shared state to race. Clean.
- **`multitap_push_and_check` count>MULTITAP_RING_MAX**: Guard at line 413. Also `SVC_HK_MULTITAP_COUNT` masks with 0xF so count â‰¤ 15 < 16. Safe.
- **TOK1/TOK2 pipe protocol** (`token_refresh_server.c`): HMAC-authenticated, size-capped at 4095/4095, replay-safe (each pipe cycle is a fresh handle), remote-clients-rejected. TOK2 covers all length-prefixed fields in HMAC (prevents field-swap). Clean.
- **`token_refresh_server`'s DACL + `svc_build_pipe_admin_sys_sa`** (line 512-524): Admins+SYSTEM only closes the medium-IL "hold sole pipe instance" DoS. Confirmed correct SDDL.
- **`_hk.bin` DACL** (`shared/common.h:147-179` `svc_write_locked_sentinel`): `D:P(A;;GA;;;SY)(A;;GA;;;BA)` â€” SYSTEM+Admins full, PROTECTED (no inheritance). Payload (DWM virtual account) has no write need â€” helper reads, launcher writes. Sound.
- **Emergency chord debounce CAS** (`wl_input.c:2369-2390`): 1500 ms atomic per-action via `InterlockedCompareExchange64` closes the 4-path race that live-observed as 4Ã— fires in v3.0.6. Clean.
- **Reader singleton mutex** (`wl_input.c:1185-1207`): `Local\<guid>` session-scoped; WAIT_ABANDONED = clean takeover; correctly gates double-reader on rapid re-arms.
- **Fake-hwnd validation** (referenced in scope but lives in `payload/src/ui/imgui_layer.cpp` â€” out of my scope's file list; per CLAUDE.md v3.0.4 handoff, the ternary owner-check + WorkerW drop is landed).
- **`rawin_restart` on iso-desktop entry**: Correctly guarded â€” `desktop_watch_thread` only calls `rawin_restart()` on return-to-Default (line 2258, `if (to_default) { â€¦ rawin_restart(); }`). No restart on iso entry â€” matches the "proven regression" guidance from the iso-desktop handoff.
- **Emergency chord LLKHF_INJECTED filter (wl_ll_kbd gate 4)** (line 1104-1110): Gate 1 (line 1012) rejects injected BEFORE gate 4 runs, so `SendInput(Ctrl+Shift+Alt+Q)` can't fake through wl_ll_kbd's local dispatch. **The bypass is via `emergency_poll_thread`, not `wl_ll_kbd`** â€” see P0-2.
- **`config_write_hk_table` sizing** (line 116-133): `SVC_HK_COUNT` (44) â‰¤ `SVC_HK_TABLE_COUNT` (64); safe iteration. `t.flags` mirror correct. Clean.
- **DWM-pid-churn crash-loop firewall** (`wl_input.c:1668-1789`): 3 pid-changes in 90 s â†’ `fw_trip()` â†’ panic sentinel + 30 min backoff. Manual clear via emergency-revive resets state (line 2264-2269). Sound design.
- **`sentinel_thread` respawn safety** (`wl_input.c:2614-2767`): Startup grace 30 s + `g_sn_confirmed_alive` gate + rate limiter (3/5min + 30 s min-gap + 10 min backoff) + AutoRestartShell=0 gate + user-panic-sentinel deference. All the escape hatches are wired. Clean.
