```
# AUDIT REPORT: DWM Hooks + Compositor

## Summary
- Files audited: 6 (dwm_hooks.c/.h, imgui_layer.cpp, dllmain.c, capture.c, resolver/main.c) + spot-reads in blob_read.c/.h, obf_names.h, launcher/main.c
- Total findings: 15 (P0: 0, P1: 6, P2: 5, P3: 4)
- Overall verdict: MINOR-FIXES-RECOMMENDED â€” the SEH shell around every dwmcore call site is genuinely load-bearing and closes the classic DWM-crash class of bugs. What survives is a small set of timing/lifetime holes on teardown, one functional bug that halves your compose-grace mechanism on most systems, and a few "recovery latch" edges that don't self-heal.
- Estimated hours to fix all P0/P1: 4-6h (each fix is small; regression testing the shutdown + Progman-restart paths eats most of it).

## P0 (Ship-blocking â€” DWM crash, data corruption, unrecoverable)
None. All primary crash vectors (wrong-vtable-slot walk, wrong-prologue byte-patch, orig-Present exception, dwmcore layout drift) are gated by validated `is_ptr_in_dwmcore` + prologue-shape detection + top-level SEH. The v3.1 + v-ctrlb-hardening passes closed the remaining ones.

## P1 (User-visible bug or crash edge case)

### Finding P1-1: `keepalive_thread` never joined -> post-FreeLibrary code execution
- File:line: `payload/src/dwm_hooks.c:1716` (spawn), `payload/src/dwm_hooks.c:2089` (Sleep 500/1000ms), `payload/src/dwm_hooks.c:1861-1899` (uninstall never waits)
- Symptom: Random DWM crash on `sihost --unload` (or emergency-Q hotkey) roughly one time in N, more often when the overlay was hidden at the moment of unload (Sleep(1000) window is 2x wider than Sleep(500)).
- Root cause: `hooks_install` spawns `keepalive_thread` with `CloseHandle(ka)` immediately â€” the handle is discarded, there is no way to `WaitForSingleObject` on it later. The thread body sits in `Sleep(cur_visible ? 500 : 1000)` at the tail of every loop iteration and only checks `g_active && !g_stop_draw` at the top. `hooks_uninstall` waits on `g_integrity_thread` (which correctly kept its handle) but does NOT wait on the keepalive thread. `shutdown_watcher` in `dllmain.c` then calls `FreeLibraryAndExitThread` around t+500ms-2s. If keepalive was mid-`Sleep(1000)` when the shutdown event fired, it wakes AFTER the DLL was unmapped, tries to execute the next instruction in freed memory -> AV in DWM. Same failure mode applies to the `SetWinEventHook` callback (`ghost_fg_change_cb`, `dwm_hooks.c:1974`) which the OS may dispatch through the thread's message pump after unload.
- Repro: `--unload` while overlay is hidden, in a loop, on a machine with fast subsystem stops (LDB detach + sub_check idle so PHASE 2 returns instantly). Total shutdown ~350ms, well inside the 1000ms Sleep.
- Fix: keep the handle in a file-scope static, and in `hooks_uninstall` (right after `InterlockedExchange(&g_integrity_running, 0)`) do:
  ```c
  if (g_keepalive_thread) {
      WaitForSingleObject(g_keepalive_thread, 1500);
      CloseHandle(g_keepalive_thread);
      g_keepalive_thread = NULL;
  }
  ```
  Same treatment for `g_ghost_wnd_thread` (dwm_hooks.c:2217) and `present_fire_canary_thread` (dwm_hooks.c:1761). Also chunk the keepalive Sleep to 50ms slices with re-check, mirroring the fix already applied to `hook_integrity_thread` (dwm_hooks.c:415).
- Confidence: HIGH (structural, easy to spot in a stress loop).

### Finding P1-2: `Detour_LegacyPresentNeeded` (PN2) silently defeats `compose-grace` on ~most systems
- File:line: `payload/src/dwm_hooks.c:900` (PN2) vs. `payload/src/dwm_hooks.c:863` (PN1)
- Symptom: After every `ui_toggle_visible` (HIDE), `ui_nudge`, `ui_resize`, `ui_cycle_corner`, or `ui_bump_alpha`, DirectComposition apps (Chrome, Slack, Discord, Cursor, Electron, hardware-accelerated video) still hold "chunk-eaten" stale overlay pixels for way longer than the 500ms grace window is supposed to guarantee. This is a KNOWN class of bug that `hooks_bump_compose_grace` was specifically designed to fix and the fix currently only takes effect on machines that route through CDDisplayRenderTarget.
- Root cause: PN1 has `if (!ui_is_visible() && !in_compose_grace_window()) return orig_result;` â€” during the 500ms grace it keeps forcing PN=TRUE + firing SCP even when the overlay is hidden. PN2 has `if (!ui_is_visible()) return orig_result;` with NO grace-window check. Per the code comment at `dwm_hooks.c:881` "(this is the RT that fires on most systems)" â€” so on most user machines PN2 is the primary driver and PN1's compensating logic never runs. The header comment on `hooks_bump_compose_grace` (dwm_hooks.h:198-209) explicitly promises "PN detours force PN=TRUE + fire SCP even when overlay is hidden" â€” plural. Only PN1 honors the contract.
- Repro: Foreground Chrome, hide the overlay, move mouse over the old overlay region â€” trailing tiles persist for several hundred ms or until Chrome naturally presents new content.
- Fix: mirror PN1 verbatim in PN2:
  ```c
  if (!ui_is_visible() && !in_compose_grace_window()) return orig_result;
  ```
  (Same line, right after the `if (!g_active) return orig_result;` guard at dwm_hooks.c:898.)
- Confidence: HIGH (grep-verified there's exactly one `in_compose_grace_window()` call site in the file, and it's PN1).

### Finding P1-3: `IsOverlayPrevented` byte-patch install + revert is non-atomic across 6 bytes -> mid-write race window
- File:line: `payload/src/dwm_hooks.c:1667-1673` (install), `payload/src/dwm_hooks.c:1895-1898` (revert)
- Symptom: Very rare (<1/1000 arm cycles) DWM AV during `--reinject` or `--unload` when a DWM compose thread happens to execute `IsOverlayPrevented` in the same nanosecond window we're rewriting its prologue byte-by-byte. Reads like a random `c0000005` at a dwmcore RVA that doesn't correspond to any of the hooks. Nearly-impossible to reproduce, but the racy write is there in cold-read.
- Root cause: The patch is 6 sequential byte stores:
  ```c
  iop_patch[0] = 0xB8;  iop_patch[1] = 0x01;  iop_patch[2] = 0x00;
  iop_patch[3] = 0x00;  iop_patch[4] = 0x00;  iop_patch[5] = 0xC3;
  ```
  and the revert is the same shape (`for (int i = 0; i < 6; i++) iop[i] = g_iop_saved_bytes[i];`). A concurrent DWM thread reading `IsOverlayPrevented` mid-write can observe (e.g.) `B8 01 00 00 00 C3` -> orig[5] -> orig[6..] which decodes as `mov eax,1; <partial-orig>`. If orig[6..] starts with a byte that begins a prefixed instruction whose continuation was already overwritten, the CPU decodes garbage and AVs. The paired `FlushInstructionCache` happens only at the end, so per-store visibility depends on TSO ordering. Windows Kernel Patch Guard and CET don't help here â€” this is user-mode code.
- Repro: Extremely timing-sensitive. Impossible to force reliably from user space. But the ordering is objectively wrong and Bypassify's exact same pattern in v1.3 was traced to a handful of DWM crashes over 800+ installs.
- Fix: Pack the 6-byte payload into a single 8-byte value (preserving bytes 6-7 with the original bytes read via a paired 8-byte read), then use `InterlockedExchange64` for both install and revert. x64 guarantees atomicity of aligned 8-byte stores. Same treatment for the ForceFullDirty single-byte patch (`dwm_hooks.c:1415`) is not strictly needed (1-byte stores are inherently atomic on x64).
- Confidence: MEDIUM (real race; empirical fault rate on this specific code path is unmeasured but non-zero on hot dwmcore).

### Finding P1-4: RTV layer-size gate never SHRINKS -> mid-session resolution decrease permanently kills overlay
- File:line: `payload/src/ui/imgui_layer.cpp:4867-4879` (grow-only logic + 95%-of-largest gate)
- Symptom: User plugs in an external 4K monitor -> overlay renders fine. Later unplugs it -> desktop drops to laptop's 1080p. Every subsequent DWM layer comes in at 1920x1080 which is <95% of the cached `g_target_w=3840`. `get_or_create_rtv` returns nullptr for EVERY layer. Overlay silently invisible until DWM restart, `sihost --reinject`, or a manual Progman-triggered `ui_reinit`. No log line at "no target layer" cadence â€” the failure is silent.
- Root cause: `g_target_w = desc.Width; g_target_h = desc.Height;` only runs when `desc.Width * desc.Height > g_target_w * g_target_h`. There is no invalidation path on `WM_DISPLAYCHANGE` / `WM_DPICHANGED` / resolution reduction. `ui_reinit` (line 9552-9553) DOES zero these fields, but is only called on Progman HWND change (explorer restart), which does NOT happen on display setting change alone.
- Repro: Plug in external monitor at higher res than internal panel, wait for overlay to draw once, unplug. Overlay stays dead.
- Fix: 
  - Cheap: Track "N consecutive frames where all layers rejected by 95% gate" â€” if that counter exceeds ~30 (~500ms at 60Hz), zero `g_target_w/h` so the next fullscreen layer re-anchors the gate.
  - Better: Register a `WM_DISPLAYCHANGE` listener via the ImGui-Win32 backend's Progman HWND and zero the fields on that message.
  - Cheapest: Change the gate from "95% of largest ever seen" to "match the size returned by `GetSystemMetrics(SM_CXVIRTUALSCREEN/CYVIRTUALSCREEN)` at frame time, refreshed every second." Loses some resolution-change robustness in exchange for zero state.
- Confidence: HIGH (grow-only reads directly; user-observable failure mode).

### Finding P1-5: `g_compose_degraded` cannot recover once `present_fire_canary_thread` exits at T+60s
- File:line: `payload/src/dwm_hooks.c:1224-1233` (steps table + loop bound), `payload/src/ui/imgui_layer.cpp:8807-8814` (consumer)
- Symptom: In the rare case where `COverlayContext::Present` starts firing more than 60 seconds after inject (cold GPU / TDR recovery / dwm-restart-during-inject / HDR-mode transition), the canary has already exited and `g_compose_degraded=1` is permanent. `ui_present_frame` no-ops forever this session; only remedy is `sihost --unload && sihost --reinject`.
- Root cause: The canary is a bounded for-loop over four `steps[]` entries and returns 0 after the last iteration. The self-heal branch inside the sleep loop is bounded to the same 60s wall time. If `g_present_calls == 0` at T+60s the flag latches to 1 (from T+15s or T+30s alert step); if Present begins firing at T+61s, nothing observes the transition. No thread ever clears `g_compose_degraded` outside the canary.
- Repro: SVCLDB_SELFTEST=1 with an artificial delayed-Present harness or on a machine with an HDR + GPU driver reset that takes >30s to recover. Not empirically reported but is present in the code structure.
- Fix: Convert the canary to an infinite loop with an exponential-backoff sleep (100ms -> 1s -> 5s -> 30s cap), and always check-and-clear if `g_present_calls > 0`. Terminates only on `g_stop_draw`. Adds ~0 wakeup cost after the first minute (30s cadence).
- Confidence: MEDIUM (obvious in code; probability in the wild is low but non-zero).

### Finding P1-6: `ghost_wnd_thread` and `present_fire_canary_thread` also not joined -> same class of race as P1-1 with narrower windows
- File:line: `payload/src/dwm_hooks.c:1727` (ghost spawn, handle discarded), `payload/src/dwm_hooks.c:1761` (canary spawn, handle DISCARDED at the `CreateThread` call site â€” no return value captured)
- Symptom: Same DWM-crash-on-unload class as P1-1 with narrower Sleep windows (50ms for ghost, 100ms for canary). Ghost is opt-in via `DWM_EXT_GHOST=1` so it's rarely hit. Canary Sleep(100) IS below typical shutdown_watcher completion so it usually wakes and self-terminates in time â€” but this is timing luck, not correctness.
- Root cause: Same pattern as P1-1 â€” spawn + immediate `CloseHandle` (or no capture at all in the canary case). No join in `hooks_uninstall`.
- Fix: Same as P1-1 â€” keep handles, join on uninstall with a bounded WaitForSingleObject.
- Confidence: MEDIUM (structural; smaller windows than P1-1).

## P2 (Latent bug â€” real but not fired yet)

### Finding P2-1: `discover_gpb_slot_once` latches on FIRST valid pLayer, which can be a non-fullscreen surface with coincidental RVA match at the wrong slot
- File:line: `payload/src/ui/imgui_layer.cpp:445-462` (gpb variant, identical shape for gd3d + acc)
- Symptom: On rare Windows builds where DWM's first Present of an inject cycle is a small surface (32x32 cursor, 100x30 tooltip, thumbnail) whose vtable happens to have a slot pointing to the resolver-hinted RVA in a position DIFFERENT from the fullscreen layer's canonical slot, we cache the wrong dynamic slot forever. Every subsequent fullscreen Present calls the wrong function via that slot -> either returns nullptr (safe, no overlay) or the SEH inside get_backbuffer_texture catches something and disables overlay for the DWM lifetime.
- Root cause: The `s_done` latch fires on the FIRST pLayer whose vtable is 160+ bytes readable, regardless of the layer's dimensions (the size gate is downstream in `get_or_create_rtv`). The RVA-match check only requires that SOME slot in the vtable equals the hinted RVA â€” a small-object vtable that shares a base class with the fullscreen layer's class will have that RVA at a DIFFERENT slot number, and we'll cache that wrong number.
- Repro: Pathological. Requires a specific dwmcore build where multi-inheritance subobjects present before the primary layer AND their vtable contains the hinted RVA at a non-canonical slot. Not observed in the wild yet, but is a strict superset of the jay.perkerson@gmail.com 2026-07-15 failure mode.
- Fix: Two options:
  - (A) Add a `desc.Width * desc.Height >= 800*600` guard in `get_backbuffer_texture` BEFORE calling `discover_XX_slot_once`. Only latch the cache on a real fullscreen layer.
  - (B) Compare the discovered slot against the hardcoded fallback (`GPB_SLOT`/`GD3D_SLOT`/`ACC3_SLOT`) â€” if they mismatch, require a second confirming observation before latching.
- Confidence: MEDIUM (real risk; empirical rate unknown).

### Finding P2-2: `Detour_COverlayContextPresent`'s 7-arg signature is empirically verified against pre-25H2 dwmcore but not re-verified against target build 26200.9457
- File:line: `payload/src/dwm_hooks.c:49-52` (typedef), `payload/src/dwm_hooks.c:709-712` (detour params)
- Symptom: If Microsoft added an 8th arg to `COverlayContext::Present` in the KB5124008 / KB5129195 family or a future 25H2 servicing update, we'd pass garbage from stack as `disableMPO`, and the 8th arg would silently drift into orig-Present's expected 8th slot as whatever's at `[rsp+0x38]`. Symptom: MPO plane assignment thrash (Chrome shadow trails return), or dwmcore internal state corruption -> DWM AV over minutes. Historically 6->7 already happened once (v1.7.11.4 2026-07-25 fix). No PDB-based signature validator to detect a future 7->8.
- Root cause: Function signature is baked into a C typedef. Resolver only pulls the function ADDRESS, not the parameter count or types. First-Present drift would only be caught by a DWM crash pattern-match after the fact.
- Repro: Not currently reproducible on 26200.9457 (production). A future Windows update to `dwmcore.dll` that adds a param.
- Fix: The `run_resolver` path (launcher/src/main.c:807) already re-runs on `dwmcore_time_date_stamp` change. Add a PDB parameter-count query in the resolver (`SymGetTypeInfo` with `TI_GET_COUNT`) and write it into a new `offsets.blob` field. Payload compares against its compile-time `sizeof(pfnCOverlayPresent_t_args)` expectation and sets `g_compose_degraded=1` on mismatch. Zero cost on match; automatic quiesce on drift.
- Confidence: LOW (probabilistic future risk, not a current bug).

### Finding P2-3: `MH_Uninitialize` frees trampoline memory while in-flight detour may still be executing orig-Present
- File:line: `payload/src/dwm_hooks.c:1864-1865` (`Sleep(200)` then `MH_DisableHook + MH_Uninitialize`)
- Symptom: Extremely rare crash on `--unload` if `g_orig_present` was mid-call for >200ms at the moment of `MH_Uninitialize`. When the orig returns, the return address goes through the trampoline which no longer exists -> AV. This is a known Bypassify-pattern risk.
- Root cause: MinHook's `MH_DisableHook` does NOT drain in-flight detours (no synchronization primitive with the ~8 dwmcore threads that may be inside `Detour_COverlayContextPresent`). The 200ms Sleep is a heuristic drain window, not a barrier. Under GPU stall / VRR sync / long-running Present, 200ms is not always enough.
- Repro: Force a GPU stall (`nvidia-smi -pl` clock manipulation, deliberate OOM on ID3D11Device) then trigger `--unload`. Not easy to arrange.
- Fix: Two options:
  - (A) Widen `Sleep(200)` to `Sleep(500)`. Cheap, adds 300ms to unload.
  - (B) Add a "detour active" refcount around every `Detour_*` body and spin-wait on `count == 0` before `MH_Uninitialize`, bounded ~500ms. More correct but adds hot-path atomics.
- Confidence: MEDIUM (documented Bypassify risk; observed once in v1.3 audit trail).

### Finding P2-4: `hooks_add_dirty_full` public API + `AddDirtyRect` trampolines are dead code, still resolved in hooks_install
- File:line: `payload/src/dwm_hooks.c:2506-2540` (definition), `payload/src/dwm_hooks.c:1482-1497` (trampoline resolve), `payload/src/dwm_hooks.h:196` (declaration)
- Symptom: `g_add_dirty_display` and `g_add_dirty_legacy` are populated at every hooks_install from `off->addDirtyRectDisplay/Legacy`. Grep confirms `hooks_add_dirty_full()` has ZERO callers in the payload (the only mention outside the definition is a "REVERTED v1.7.11" comment in the Present detour body). The `dwm_hooks.h` header comment at line 187-197 claims "Called by ui_present_frame on geometry-generation changes for the next 6 frames" â€” this is stale documentation; the real ui_present_frame no longer calls it.
- Root cause: Refactor artifact. v1.7.11 experiment reverted but its resolver hooks + public API were left in place.
- Repro: Read the code.
- Fix: Delete `hooks_add_dirty_full` from both `.c` and `.h`, remove the `addDirtyRectDisplay/Legacy` resolves from hooks_install (dwm_hooks.c:1482) and from the resolver (`resolver/src/main.c:250-251`), and the corresponding blob fields (blob_read.h:40-41). Reduces attack surface + shrinks offsets.blob by 16 bytes. Same treatment for the `Detour_DisplayPresent` / `Detour_LegacyPresent` / `Detour_CWindowNode_RenderContent` / `Detour_CVisual_RenderContent` bodies that are `(void)Fn;`-suppressed but still compiled into the payload.
- Confidence: HIGH (verified by grep: 0 real callers).

### Finding P2-5: `hooks_uninstall_in_progress()` returns 1 for the entire pre-install period (`g_active == 0` at static init)
- File:line: `payload/src/dwm_hooks.c:164-171`
- Symptom: Any code that gates on `hooks_shutting_down()` for defensive early-outs (e.g., `invalidate_last_overlay_region` at imgui_layer.cpp:3693, `hooks_bump_compose_grace` at dwm_hooks.c:150) silently no-ops during the tiny window between DLL load and `hooks_install` completion. In practice this window is <1s and no UI code fires there â€” but the semantic is wrong ("in progress" implies "was installed, now unwinding" not "never installed").
- Root cause: `g_active` is a raw global that starts at 0. `hooks_uninstall_in_progress` treats `!g_active` as "uninstalling" without a separate "never installed" state.
- Repro: Add a diag probe at `dllmain.c:2420` before `hooks_install` and observe `hooks_uninstall_in_progress()` returns 1.
- Fix: Add a `g_installed_once` latch set at the top of `hooks_install` after MH_Initialize success. Return early from `hooks_uninstall_in_progress` if `!g_installed_once && !g_active` -> "never installed, not in progress." Cheap.
- Confidence: HIGH (verified by reading; minor semantic issue).

## P3 (Nit / code hygiene)

### Finding P3-1: `hook_registry_add` populates fields non-atomically after atomic index acquisition
- File:line: `payload/src/dwm_hooks.c:307-317`
- Symptom: None currently â€” `hook_registry_add` is only called serially from `hooks_install`, so the fill-in-after-increment pattern is safe. But if a future refactor adds a second caller (dynamic hook install), the integrity monitor thread could read a partially-populated entry (`target != NULL && name == NULL`).
- Fix: Populate the struct fields BEFORE the InterlockedIncrement that publishes the count. Or move to a write-then-CAS pattern.
- Confidence: HIGH (defensive-nit only).

### Finding P3-2: `g_target_tex` is a dead variable â€” declared, zeroed in ui_reinit, never assigned elsewhere
- File:line: `payload/src/ui/imgui_layer.cpp:1335` (declaration), `payload/src/ui/imgui_layer.cpp:9553` (zero-in-reinit)
- Symptom: None. Just noise.
- Fix: Delete the declaration + the zero-in-reinit line.
- Confidence: HIGH.

### Finding P3-3: `g_compose_tid` never invalidates on DWM compose-thread respawn
- File:line: `payload/src/ui/imgui_layer.cpp:1066` (declaration), `payload/src/ui/imgui_layer.cpp:3765-3769` (one-shot publish)
- Symptom: If DWM internally kills + respawns its compose thread mid-inject (rare but happens on graphics-driver TDR + full recovery), the cached TID is stale. A future user thread whose TID happens to equal the dead compose TID would falsely skip its `invalidate_last_overlay_region` full-desktop cascade. Probability is TID-collision-low but non-zero.
- Fix: Optional â€” republish `g_compose_tid` from a periodic check inside `ui_present_frame` if the current `GetCurrentThreadId()` differs from the cached one. Or accept the current single-shot and mark as WONTFIX.
- Confidence: MEDIUM (real but very low impact â€” worst case one missed cascade fires from a wrong thread).

### Finding P3-4: `keepalive_thread`'s `SetWinEventHook` fires callbacks that hold a ref implicitly via message pump â€” if UnhookWinEvent is skipped, hook survives thread death
- File:line: `payload/src/dwm_hooks.c:2008-2013` (install), `payload/src/dwm_hooks.c:2092` (unhook)
- Symptom: Related to P1-1. If keepalive_thread is killed mid-execution (e.g., DLL unload during Sleep), UnhookWinEvent never runs. The OS-registered WinEvent hook keeps dispatching `ghost_fg_change_cb` callbacks into the (freed) payload memory whenever any foreground window changes. Depending on Win32k dispatching, this either silently no-ops (callback address invalid, syscall path fails) or crashes the process that triggered the foreground change.
- Fix: Fixed as a byproduct of the P1-1 join-and-drain fix. Explicit fix: capture the `HWINEVENTHOOK` in a file-scope static and always call `UnhookWinEvent(fg_hook)` from `hooks_uninstall` before the sleep-drain window.
- Confidence: HIGH (documented lifecycle bug, low real-world hit rate because ghost is opt-in).

## Files audited (list every one)
- `payload/src/dwm_hooks.c` (2539 lines) â€” full read
- `payload/src/dwm_hooks.h` (224 lines) â€” full read
- `payload/src/ui/imgui_layer.cpp` (9597 lines) â€” focused reads: 1-700 (state/globals/Progman recovery), 2800-3400 (toggle/nudge/wake), 3600-3900 (invalidate/compose-tid), 4680-4950 (get_backbuffer_texture + get_or_create_rtv), 8780-9600 (ui_present_frame + ui_reinit + ui_shutdown), plus targeted greps
- `payload/src/dllmain.c` (2751 lines) â€” focused reads: 640-720 (on_present + hotkey plumbing), 1160-1300 (on_hotkey top-level SEH), 1750-2000 (shutdown_watcher), 2180-2600 (init_thread)
- `payload/src/capture.c` (210 lines) â€” full read (GDI + WIC PNG encoder, clean)
- `resolver/src/main.c` (349 lines) â€” full read (symbol resolution + blob write, clean)
- `payload/src/blob_read.c` + `blob_read.h` â€” full read (blob load + legacy-size compat)
- `shared/obf_names.h` â€” spot read (name derivation contract)
- `launcher/src/main.c` â€” targeted read (lines 740-900: `dwmcore_time_date_stamp`, `run_resolver`, `auto_refresh_offsets_if_stale`)

## Non-issues investigated (things I checked and cleared)

- **`ForceFullDirty` non-bool guard on 25H2 initial-byte 0x44** (audit request #6): The guard at `dwm_hooks.c:1404-1411` correctly rejects any byte value that isn't `0x00` or `0x01`. 0x44 (or 0x34 mentioned in the comment) falls through to the "SKIPPED patch" path. Correct.
- **`Detour_COverlayContextPresent` reentrancy guard** (audit request #7 SCP concern): `g_schedule_composition` is written in `hooks_install` at line 1447 BEFORE `InterlockedExchange(&g_active, 1)` at line 1709. The Publish-Set-Active ordering is correct â€” no PN detour can observe `g_active==1` while `g_schedule_composition==NULL`. Verified.
- **Present-fire canary at T+15s alert threshold false-positives** (audit request #9): The v-ctrlb-hardening bump from 2s to 15s is empirically justified. The in-sleep self-heal loop at `dwm_hooks.c:1234-1244` correctly clears `g_compose_degraded=0` the instant Present starts firing. Only the post-T+60s edge (P1-5 above) is unresolved.
- **`hooks_compose_degraded` self-heal in flight** (audit request #10): The 100ms-cadence check inside canary sleep loop DOES self-heal within the 60s canary window. Only fails on post-canary recovery (see P1-5).
- **Ghost window `WS_EX_TOPMOST + WS_EX_LAYERED + WS_EX_TOOLWINDOW + WS_EX_NOACTIVATE` combo** (audit request #11): Correctly constructed at `dwm_hooks.c:2293-2298`. `WDA_EXCLUDEFROMCAPTURE` applied. Ghost is opt-in by default (`DWM_EXT_GHOST=1`) which reduces stealth cost. `k_ghost_class_pool[]` rotation is sound. No z-order fight in the standard `keepalive_thread` sync path.
- **`get_backbuffer_texture` QueryInterface ref count** (audit request #12): Verified. QI (+1 on `out_tex`) matched by `tex->Release()` at `imgui_layer.cpp:8908`. RTV holds its own ref via `CreateRenderTargetView` -> `tex` resource ref stays live. Release-per-frame at line 9512 correctly zeros the cache slot. No leak, no UAF.
- **`get_or_create_rtv` layer-size gate on multi-monitor mixed refresh** (audit request #13): The gate works correctly for adding monitors and for consistent monitor configs. The failing case is resolution DECREASE (see P1-4), not variable refresh rate per se.
- **`Detour_COverlayContextPresent` 7-arg signature on 25H2** (audit request #14): Not empirically re-verified on 26200.9457, but the arg count matches Bypassify's live decomp per docstring and the v1.7.11.4 6->7 fix. Marked as P2 latent risk (P2-2) not a current bug.
- **AddDirtyRect trampoline leaks in offsets.blob** (audit request #15): Trampolines ARE resolved from every offsets.blob but never called (P2-4). No safety impact â€” a NULL pointer from resolver would leave `g_add_dirty_*` at NULL and the `hooks_add_dirty_full` SEH short-circuits. Just dead code.
- **`g_compose_tid` CAS race** (audit request #16): Single-shot CAS from 0 -> tid is race-safe. Early `ui_toggle_visible` before first Present sees `ct=0` in `invalidate_last_overlay_region` and correctly fires the cascade (no compose-thread yet -> no reentrancy risk).
- **`ui_reinit` RTV / device / backend teardown ref counts** (audit request #17): Verified. `g_cache[i].rtv->Release()` matches CreateRTV. `ImGui_ImplDX11_Shutdown` releases backend GPU resources. `ImGui::DestroyContext` frees fonts. `g_last_device` zeroed. No leak.
- **Font atlas rebuild on ImGui context recreate** (audit request #18): Verified. `ImGui::CreateContext` on next frame allocates fresh IO.Fonts; `AddFontFromFileTTF` re-loads from disk; `ImGui_ImplDX11_Init` + `ImGui_ImplDX11_NewFrame` rebuild GPU texture. Prior context's atlas was freed by `DestroyContext`. Note: `ImGui_ImplDX11_NewFrame` is called TWICE on the init frame (once at end of init block, once in the shared per-frame path) â€” no leak, minor CPU waste.
- **Double-init mutex `obf_mutex_initguard()` name derivation** (audit request #19): Verified via `shared/obf_names.h` header comment. Name derived from `HKLM\...\Cryptography\MachineGuid` via SHA-256, per-purpose salt, formatted as GUID. Cross-user-session collision impossible (`Local\` namespace scopes to session). Cross-machine collision statistically impossible (SHA-256 of unique MachineGuid). Fallback to fixed GUID on registry failure is safe. NULL-DACL v3.2 hardening applied.
- **Hook-integrity monitor false-positive risk** (audit request #20): 10s cadence check of `*(unsigned char *)r->target`. First-byte check accepts both `0xE9` (rel32 JMP) and `0xFF` (abs JMP), matching every MinHook variant. SEH-wrapped read. Re-enable is idempotent via `MH_EnableHook`. Cannot false-positive on a valid MinHook install; the only trigger is an AC/EDR NOPing our detour, which is exactly the intended detection.
- **`IsOverlayPrevented` prologue-shape detection** (audit request #6 addendum): The three cases (`0x8A 0x81`, `0x0F 0xB6`, `0x8B 0x01` for OLD-getter; `0xFF 0x15` for NEW-CFG-CALL; `0xF3 0x0F 0x1E 0xFA` for CET-ENDBR64) cover every prologue I've seen documented for this function. Unknown prologue correctly SKIPS the patch and logs verbosely. Cannot corrupt dwmcore state on unexpected shape.
- **`keepalive_thread` thundering herd @ 50ms SCP** (audit request #8): OBSOLETE in current code. v1.7.4.12 killed the SCP fire from keepalive; the thread only handles ghost visibility sync now, and Sleep cadence is 500/1000ms. Not a real concern anymore â€” but the thread's lifetime IS the source of P1-1.
- **`capture.c` GDI + WIC pipeline**: Full read; ref counts on `IWICImagingFactory`, `IStream`, `IWICBitmapEncoder`, `IWICBitmapFrameEncode`, `IPropertyBag2` all match. `SelectObject`/`DeleteObject` on GDI handles correct. `CreateStreamOnHGlobal(NULL, TRUE, ...)` correctly frees HGLOBAL on stream release. Clean.
- **Resolver `run_resolver` retry path** (v3.1 sig re-verify): Verified in launcher/src/main.c:807-849. Correctly deletes stale blob, spawns resolver, waits 3 min, checks blob presence + writes stamp sidecar. Auto-refresh triggered on stamp mismatch from every arm path.
```
