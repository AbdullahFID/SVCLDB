# Multi-subagent audit consolidation (2026-09-23 late night)

## What ran

7 opus-4.7 subagents fanned out in parallel over the whole codebase. 2 delivered complete formatted reports before Cursor's billing-system rejection hit; 5 got killed mid-audit but their partial investigations captured substantive findings in their transcripts.

| # | Scope | Status | Format |
|---|---|---|---|
| A | DWM hooks + compositor | ✅ complete | Full P0/P1/P2/P3 + Non-issues |
| B | Input + winlogon helper | ⚠ partial | Investigation notes only |
| C | Auth + session + backend | ⚠ partial | Investigation notes only |
| D | AI + autosolver + capture | ✅ complete | Full P0/P1/P2/P3 + Non-issues |
| E | UI + notes + human typer + clip ring | ⚠ partial | Investigation notes + prelim rank |
| F | Installer + Electron UI + launcher non-auth | ⚠ partial | Investigation notes + prelim rank |
| G | Stealth + anti-debug + crypto | ⚠ partial | Investigation notes only |

Transcripts extracted to `%TEMP%\audit_extracts\` (kept for reference during the fix pass).

---

## Consolidated global P0 / P1 / P2 / P3 hit list

### P0 (SHIP-BLOCKING)

**P0-1 [D] OCR redactor pipe hangs DWM compose thread indefinitely**
- File: `payload/src/redact/redact_client.c:100-121, 185-207` (`write_all` + `read_all`)
- Symptom: With OCR redactor toggled ON in Electron, if the winlogon-hosted `--ocr-daemon` accepts the pipe then hangs (deadlock in `Windows.Media.Ocr`, GPU stall, LDB-suspended child), `WriteFile` and `ReadFile` block forever on DWM's compose thread. `try_perform_capture` (imgui_layer.cpp:1810-1927) runs in-Present. Whole desktop stops compositing until daemon is killed.
- Fix: Open pipe with `FILE_FLAG_OVERLAPPED`, use `WaitForSingleObject` with hard timeout (e.g. 2s). OR keep sync I/O and add watchdog thread that `CancelSynchronousIo` on the compose thread. Belt-and-suspenders: treat hang as -1 (fall through to unredacted capture, matches OCR-OFF UX).

### P1 (User-visible bug or crash edge case)

**P1-1 [A] `Detour_LegacyPresentNeeded` (PN2) missing `in_compose_grace_window()` check**
- File: `payload/src/dwm_hooks.c:900` (PN2) vs `dwm_hooks.c:863` (PN1)
- Symptom: `hooks_bump_compose_grace(500)` is a no-op on "most systems" (per code comment) because PN2 short-circuits on `!ui_is_visible()` without honoring the grace window. DirectComposition apps (Chrome/Slack/Cursor/Discord/video) hold stale overlay tiles indefinitely after every HIDE.
- Fix: **ONE LINE.** Mirror PN1: `if (!ui_is_visible() && !in_compose_grace_window()) return orig_result;`

**P1-2 [A + E] Unjoined worker threads race with `FreeLibraryAndExitThread`**
- Files:
  - `payload/src/dwm_hooks.c:1716` (`keepalive_thread`, `Sleep(500|1000)` — widest window)
  - `payload/src/dwm_hooks.c:1727` (`ghost_wnd_thread`, opt-in via DWM_EXT_GHOST)
  - `payload/src/dwm_hooks.c:1761` (`present_fire_canary_thread`, `Sleep(100)`)
  - `payload/src/input/human_typer.c` (typing worker — user report: "autotype crashes when I unload mid-type")
  - `payload/src/clip_ring.c:124-149` (clipboard poll, 500ms cadence)
- Symptom: Random DWM crash on `sihost --unload` / KILL_ALL / emergency-Q. Thread mid-`Sleep` wakes AFTER the payload's pages were `VirtualFree`'d by the launcher → next instruction fetch AVs.
- Fix: Keep each thread's handle in a file-scope static, join on `hooks_uninstall` / `ui_shutdown` with bounded `WaitForSingleObject(1500)`. Also chunk each Sleep to 50ms slices with re-check of the shutdown flag.

**P1-3 [E] Critical-section init pattern is racy across 5 sites**
- Files:
  - `payload/src/ui/imgui_layer.cpp` (`ensure_toast_cs`, `ensure_trail_cs`, `dot_ensure_cs` — 2-state CAS: reader can see "initialized" bit set BEFORE `InitializeCriticalSection` returns)
  - `payload/src/ui/notes.c` (`ensure_cs` — NOT atomic at all)
  - `payload/src/clip_ring.c` (`ensure_cs` — NOT atomic at all)
- Symptom: Rare crash if two threads simultaneously first-touch the CS, second thread `EnterCriticalSection` on an uninitialized CS.
- Fix: Copy the 3-state pattern already used by `diag_init_lock` (0=uninit, 1=initializing, 2=ready — spin-wait on 1).

**P1-4 [E] Notes unsaved edits lost on payload unload**
- File: `payload/src/ui/notes.c` (`notes_mark_dirty` on every edit, `notes_flush` only on explicit save/close, `shutdown_watcher` doesn't call `notes_flush`)
- Symptom: User is typing in notes editor when payload unloads (uninject, emergency-Q, --unload). All unsaved text is lost.
- Fix: Call `notes_flush_if_dirty()` from `shutdown_watcher` in `dllmain.c` before `FreeLibraryAndExitThread`. Or from `ui_shutdown()`.

**P1-5 [D] Batched-mode stream abort discards buffered partial reply**
- File: `payload/src/ai/ai_provider.c:2474-2483` + `payload/src/dllmain.c:712-724`
- Symptom: User hits Ctrl+Alt+S during a long reasoning reply while `cfg->stream_display_batched == 1` (default per docstring at line 692). The `full_reply` buffer is freed inside `ai_try_streaming_once` instead of being surfaced to `on_done`. Chat bubble ends up containing ONLY the "_(stopped by user)_" suffix. User loses everything.
- Fix: In `ai_try_streaming_once` when `!http_ok && ai_abort_requested()`, transfer ownership: `result->full_reply = s.full_reply; s.full_reply = NULL;` Then in `ai_ask_streaming`'s abort branch pass `r.full_reply` into `on_done`.

**P1-6 [D] Navigation-safety filter bypassable by empty description**
- File: `payload/src/autosolver/solve.c:128-132` (`desc_is_navigation` returns 0 for `!d || !d[0]`)
- Symptom: Model returns a click action with no `description` field. Filter degenerates to "AI opted out of being filtered". With `auto_click` ON, an AI hallucination clicking on Submit/Next/Finish will actually submit the exam.
- Fix: Reject any action with `desc[0] == 0` when `auto_click` is ON. Or cross-check the click point against UIA anchor names containing navigation words.

**P1-7 [F] Log export whitelist skips renamed log files**
- File: `ui/src/main.js` (log export flow) + `ui/src/renderer.js` (Export logs handler)
- Symptom: v3.3-hardening renamed `payload.log → msvc_dbg_a.dat`, `launcher.log → msvc_dbg_b.dat`, `wl_input.log → msvc_dbg_h.dat` but the log-export ZIP filter still targets the OLD names. User clicks "Export logs" → gets an empty ZIP. Support can't diagnose their issue.
- Fix: Update the export whitelist to match `msvc_dbg_*.dat` (and keep old names as fallback for legacy installs).

**P1-8 [A] RTV layer-size gate never shrinks → resolution decrease permanently kills overlay**
- File: `payload/src/ui/imgui_layer.cpp:4867-4879`
- Symptom: User plugs in external 4K → overlay works. Unplugs → drops to laptop 1080p. Every subsequent layer < 95% of cached 3840 → `get_or_create_rtv` returns nullptr forever. Silent overlay-invisible until DWM restart or reinject.
- Fix: Track "N consecutive frames where all layers rejected by gate" — if >30 (~500ms), zero `g_target_w/h` so next layer re-anchors. Or listen to `WM_DISPLAYCHANGE`.

**P1-9 [A] `g_compose_degraded` can't recover after canary exits at T+60s**
- File: `payload/src/dwm_hooks.c:1224-1233`
- Symptom: Rare edge (cold GPU / TDR / HDR transition / delayed dwmcore init > 60s). Canary exits after step schedule. If Present starts firing at T+61s, `g_compose_degraded=1` is permanent this session. Overlay silent forever.
- Fix: Convert canary to infinite loop with exponential-backoff sleep (100ms → 1s → 5s → 30s cap). Always check-and-clear when Present > 0. Terminate only on `g_stop_draw`.

### P2 (Latent bug — real but not fired yet)

- **P2-1 [A]** `IsOverlayPrevented` byte-patch install + revert = 6 non-atomic byte stores. Pack into 8-byte + `InterlockedExchange64`. `dwm_hooks.c:1667-1673, 1895-1898`.
- **P2-2 [D]** SSE delta content silently truncated to 8192B for OpenAI/Anthropic branches. Google's new-endpoint branch already uses 2-pass sizing; port the pattern. `ai_provider.c:2071-2075, 2096-2100`.
- **P2-3 [F]** Version drift: `package.json` says 6.7.0, `index.html` was bumped to 6.9.0.0 but `renderer.js` overwrites with `app.getVersion()` at runtime. Users see 6.7.0 despite the cosmetic bump.
- **P2-4 [D]** `ai_ask` (non-streaming) doesn't poll abort flag → Ctrl+Alt+S ignored mid-AutoSolver reasoning-model call.
- **P2-5 [D]** `ui_capture_screen_png` races on shared globals (`g_cap_request`, `g_cap_done_ev`, `g_cap_png_out`) if two ASK threads overlap.
- **P2-6 [D]** `ai_ask_metered` uses 120s WinHTTP timeout regardless of tier → STRONG-tier metered solves time out.
- **P2-7 [D]** `ai_pick_provider_key` returns legacy key for `CREDITS` → wasted retries in fallback loop for legacy users.
- **P2-8 [D]** `clip_ring` stores plaintext clipboard forever in dwm.exe memory (passwords, one-time codes, credit cards recoverable via memory dump).
- **P2-9 [E]** Autotype path calls `human_type_start` on the LL hook thread, calls `OpenClipboard` synchronously → risks 300ms LL-hook watchdog if another app holds the clipboard.
- **P2-10 [F]** `ensureCBinariesInstalled` clock-skew edge: if user clock rolled backward AND bundled+deployed bins happen to be same size but different content, update silently skipped.
- **P2-11 [F]** NSIS Defender exclusion silent-fail under GPO-managed Defender. Users get confused later when SmartScreen flags sihost.exe.
- **P2-12 [G]** Provider name literals ("OpenAI", "Anthropic", "OpenRouter", "CloakGPT credits") appear plaintext in binary data section (used for UI badge). Route through SS() macro or a runtime-decoded pool.
- **P2-13 [G]** `_bind.bin` creation fallback to NULL SA → default ProgramData DACL → readable by Users group. Constant-name it or gate on successful SA build.
- **P2-14 [G]** Anti-debug sentinel 25-30s cadence with jitter — attacker can attach+work+detach in <20s window.

### P3 (Nit / hygiene)

- **P3-1 [A]** `hook_registry_add` populates struct fields AFTER `InterlockedIncrement` — safe now (serial caller only), fragile if a second caller is added.
- **P3-2 [A]** `g_target_tex` dead variable — declared, zeroed in reinit, never assigned.
- **P3-3 [A]** `hooks_add_dirty_full` + `AddDirtyRect` trampolines are dead code (0 real callers).
- **P3-4 [D]** `json_get_bool` uses prefix strncmp (matches "truelove"/"falseness"). Add delimiter check.
- **P3-5 [D]** `copy_str` / `count_str` don't decode `\uXXXX` surrogate pairs → invalid UTF-8 for supplementary-plane emoji.
- **P3-6 [D]** `solve.c` preamble truncates silently at 4KB for large UIA anchor blocks.
- **P3-7 [E]** `human_typer` calls `srand()` in worker thread — pollutes global CRT random state.
- **P3-8 [B]** Deep-hide toggle via ImGui chip doesn't persist to `_hk.bin` until next arm — helper's flag state drifts until re-inject.
- **P3-9 [F]** Unenforced slot lock in hotkey editor: user can unbind ASK/TOGGLE/TYPING slots (payload has fallback defaults now, but Electron doesn't warn).

---

## Non-issues investigated (things audit confirmed CLEAN)

Selected highlights (see individual audit transcripts for the full list):

- **DWM crash class from wrong-vtable-slot walk** — closed by v3.1 `is_ptr_in_dwmcore` + prologue-shape detection + v-ctrlb top-level SEH. No P0.
- **JSON string-aware brace scanner** — correctly handles LaTeX/code braces inside strings; iterative depth counter can't stack-overflow.
- **SSE line buffer overflow** — bumped to 256KB with 1MB single-chunk reject; `full_reply` capped at 4MB with graceful abort.
- **Base64 buffer math (`png_to_b64`)** — correct ceiling arithmetic, correct padding across all three residues.
- **`CYCLE_TIER` wrap** — correctly wraps STRONG(0)→MEDIUM(1)→CHEAP(2)→STRONG(0) skipping CUSTOM.
- **Chat history eviction (CHAT_MAX_MSGS=64)** — clean, no dangling pointer/UAF.
- **Font atlas rebuild on ImGui context recreate** — `DestroyContext` frees fonts; new context rebuilds fresh; no leak.
- **Double-init mutex `obf_mutex_initguard()`** — SHA-256 of MachineGuid + salt, `Local\` namespace, cross-session/cross-machine safe.
- **Hook-integrity monitor false-positive risk** — accepts both `0xE9` and `0xFF` first bytes, SEH-wrapped read, no false-positive against legit MinHook install.
- **`ForceFullDirty` non-bool guard on 25H2** — correctly rejects 0x34/0x44, SKIPPED patch path clean.
- **Ghost window `WS_EX_*` combo** — WS_EX_TOPMOST + WS_EX_LAYERED + WS_EX_TOOLWINDOW + WS_EX_NOACTIVATE + `WDA_EXCLUDEFROMCAPTURE` all correctly constructed.
- **`get_backbuffer_texture` COM ref counting** — QI (+1) matched by `Release`; RTV holds its own ref; per-frame release correct; no leak/UAF.
- **`resolve_effective_model`** — falls through to `cfg->model` correctly for BYO providers.
- **AI-worker double-free** — every exit path frees `full_reply` exactly once, `ctx` exactly once.
- **`clip_ring_push_utf8` UTF-8 boundary trimming** — correctly retreats to lead-byte position, respects NUL terminator.
- **`solve_launch` re-entrancy** — `InterlockedCompareExchange(&g_solving, 1, 0)` guard is race-safe.
- **`chat_msg_by_id` on evicted id** — returns NULL, callers no-op cleanly.
- **`ui_chat_stream_append` + `ui_chat_finalize` lock ordering** — no inversion possible.
- **Toast expiry wraparound** — 64-bit GetTickCount64, safe for centuries.
- **`compare_ct` (handshake constant-time compare)** — correct semantics.
- **`clip_ring_cycle_next` last_tick update** — LL-hook single-caller, safe.
- **`resolve_effective_model` for CREDITS** — falls back correctly.
