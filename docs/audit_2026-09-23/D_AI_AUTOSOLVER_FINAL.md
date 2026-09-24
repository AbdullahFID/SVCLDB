# AUDIT REPORT: AI + Autosolver + Capture

## Summary
- Files audited: 12 (`ai_provider.[ch]`, `as_cfg.[ch]`, `solve.[ch]`, `capture.c`, `clipboard_out.c`, `clip_ring.[ch]`, relevant slices of `ui/imgui_layer.cpp`, `dllmain.c`, `redact/redact_client.c`, `shared/json_util.c`, `shared/base64.c`)
- Total findings: **13** (P0: 1, P1: 4, P2: 5, P3: 3)
- Overall verdict: **AI/streaming core is solid, but one P0 can hang DWM's compose thread and four P1s degrade or silently misbehave in real user paths.** The auth/model-fallback/tier-wrap/SSE-brace paths I stress-tested are all correct. Concurrency around `ui_capture_screen_png` and `cfg` is loose but not catastrophic.
- Estimated hours to fix all P0/P1: **~6â€“8 hours** (P0 is a 20-min fix; the four P1s are each 30â€“90 min with unit tests).

---

## P0 (AI totally broken / crash / credit theft / infinite spend)

### Finding P0-1: OCR redactor pipe hangs the DWM compose thread indefinitely
- File:line: `payload/src/redact/redact_client.c:100-121, 185-207` (`write_all` / `read_all`)
- Symptom: When "Screenshot redactor" is ON in the Electron toggle and the daemon (`sihost.exe --ocr-daemon`) accepts the pipe but then hangs (deadlock in `Windows.Media.Ocr`, GPU stall, LDB-suspended child, etc.), **DWM's compose thread blocks forever inside `WriteFile`/`ReadFile`**. Every downstream `ui_present_frame` on that same thread stops â†’ the whole desktop stops compositing.
- Root cause: The pipe is opened with default (synchronous, blocking) semantics. `WaitNamedPipeA(..., 200)` only bounds *connection*; once connected, `write_all(pipe, bgra, byte_len)` (up to 8â€“32 MB for a 4K screen) and the follow-up `read_all` have no timeout. `try_perform_capture` in `imgui_layer.cpp:1810-1927` is called *inside* the Present detour, i.e. on DWM's compose thread (`g_compose_tid`). One hung daemon = frozen desktop until the daemon crashes or is killed.
- Repro: Toggle OCR redactor ON â†’ SIGSTOP the daemon (or attach a debugger and break in `ScanBitmapAsync`) â†’ hit Ctrl+Shift+Space to Ask â†’ DWM stops presenting; mouse still moves (cursor is on the LDB layer) but no window updates until the daemon is killed and the pipe breaks.
- Fix: Open the pipe in overlapped mode (or `SetNamedPipeHandleState` alone won't help â€” you need `FILE_FLAG_OVERLAPPED` on `CreateFileA` + explicit `WaitForSingleObject` with a hard timeout). Alternative: keep synchronous I/O but add a watchdog thread that `CancelSynchronousIo` on the compose thread if the round-trip exceeds e.g. 2 s. Belt-and-suspenders: cap `byte_len` and treat any hang the same as `-1` (fall through to unredacted capture â€” matches current OCR-OFF UX).
- Confidence: **High** (read the code carefully; the try_perform_capture caller chain is documented in the file's own comments).

---

## P1 (User-visible AI failure / partial reply / cancel-race)

### Finding P1-1: SSE delta content silently truncated to 8192 bytes for OpenAI/Anthropic
- File:line: `payload/src/ai/ai_provider.c:2071-2075, 2096-2100` (`extract_sse_delta`)
- Symptom: Reasoning-heavy providers (gpt-6-astra @ high effort, Fable 5.1 with adaptive thinking, Sonnet 5) frequently emit a **single** `data:` SSE event whose `delta.content` / `delta.text` field exceeds 8 KB (the v2.0 comment above `full_append` at line 1993 explicitly says events "routinely exceed 16 KB"). Those replies show a mid-sentence cutoff in the UI even though the network payload arrived intact. In *batched* mode (default), the final reply is also missing bytes because `full_append` never sees the truncated portion (it only gets what `extract_sse_delta` returned).
- Root cause: The delta extractors allocate a fixed 8192-byte scratch and call `json_get_str(ob_buf, "content", content, 8192)`. `copy_str` in `shared/json_util.c:97-152` silently returns 1 on overflow (`if (o + 1 >= outsize) { out[outsize - 1] = 0; return 1; }`), so the caller can't distinguish "clean 8 KB delta" from "truncated 64 KB delta". Google's new-endpoint branch (line 2143-2156) already uses the correct 2-pass sizing via `json_get_str_len` â€” OpenAI/Anthropic branches were missed.
- Repro: STRONG-tier ask with a prompt that solicits a >8 KB code block (e.g. "write a full lex+yacc grammar for C89") â†’ reply visibly truncated mid-block; no error logged.
- Fix: Replace the fixed `malloc(8192) + json_get_str(...,8192)` with the same 2-pass pattern used by `extract_openai_reply` at lines 1256-1272:
  ```
  size_t need = json_get_str_len(ob_buf, "content");
  size_t cap  = need + 16; if (cap > 8u*1024u*1024u) cap = 8u*1024u*1024u;
  char *content = (char *)malloc(cap);
  json_get_str(ob_buf, "content", content, cap);
  ```
  Same fix for the Anthropic `text_delta` branch.
- Confidence: **High**.

### Finding P1-2: Batched-mode stream abort discards all buffered partial reply
- File:line: `payload/src/ai/ai_provider.c:2474-2483` (abort branch of `ai_ask_streaming`) + `payload/src/dllmain.c:712-724` (`ai_stream_done_handler` "stopped by user" branch)
- Symptom: User hits Ctrl+Alt+S during a long reasoning reply while `cfg->stream_display_batched == 1` (the current default per `stream_ctx_t`). `ai_ask_streaming` calls `on_done(0, NULL, 0, "stopped by user", userdata)` â€” the `full_reply` buffer that `stream_chunk_recv` was accumulating is freed inside `ai_try_streaming_once` (line 2347/2359) and never surfaces. The done handler only appends `"\n\n_(stopped by user via Ctrl+Alt+S)_"` and finalizes. Net effect in batched mode: **the pending chat bubble contains nothing but the suffix**. In non-batched mode the UI is fine because chunks were live-appended, but in batched mode (which the docstring at line 692 says was made default to reduce flicker) the user loses everything.
- Root cause: `ai_try_streaming_once` treats `!http_ok` as an unconditional cleanup (frees `s.full_reply`) instead of forwarding the partial buffer back to the caller when the failure was a *user-requested* abort. The docstring at line 2181-2188 claims "the caller path ... hands ... any partial reply we buffered so far and hands it to the UI with a '(stopped by user)' suffix" â€” that intent isn't implemented.
- Repro: Set `cfg->stream_display_batched = 1` â†’ ask a STRONG-tier question â†’ 2 s into streaming press Ctrl+Alt+S â†’ chat shows only "_(stopped by user via Ctrl+Alt+S)_".
- Fix: In `ai_try_streaming_once` when `!http_ok && ai_abort_requested()`, transfer ownership: `result->full_reply = s.full_reply; result->full_len = s.full_len; s.full_reply = NULL; return 0;`. Then in `ai_ask_streaming`'s abort branch pass `r.full_reply` / `r.full_len` into `on_done`. The done handler already knows how to render batched replies via `ui_chat_set_reply_of_pending`.
- Confidence: **High**.

### Finding P1-3: Navigation-safety filter is bypassable by empty description
- File:line: `payload/src/autosolver/solve.c:128-132` (`desc_is_navigation`) called at `solve.c:407-410` and `solve.c:385-390`
- Symptom: If the model returns a click action with `description` missing or empty (`""`), `desc_is_navigation` returns 0 unconditionally (`if (!d || !d[0]) return 0;`). With `auto_click` ON, an AI that hallucinates coordinates onto Submit/Next/Finish will actually click through and end the exam â€” which the entire NAVIGATION SAFETY block in the system prompt was designed to prevent. The filter is the LAST line of defense and it degenerates to "AI didn't opt in to being filtered".
- Root cause: The filter only checks the description text. There's no cross-check of the click point against known submit/nav targets (UIA role heuristics, text-anchor overlap with words like "Submit"/"Next" in `ground_build_anchor_block`, etc.). Descriptionless clicks bypass entirely.
- Repro: Craft a fake AI reply (or wait for a real hallucination) with `{"actions":[{"type":"click","x":1600,"y":950}]}` (no description) landing on the LMS "Submit" button while auto-click is ON. Filter skips â†’ `act_click_image` fires â†’ attempt is submitted.
- Fix: Two defenses, either works:
  1. Reject any action whose `desc[0] == 0` when auto-click is ON (force the model to declare intent).
  2. Also check the click coordinates against the UIA anchor block returned by `ground_build_anchor_block` â€” if the target element's role/name contains any navigation word, treat as navigation regardless of description.
- Confidence: **High** on the gap; **medium** on real-world risk (frontier models usually emit description, but v-bumps to new tiers reintroduce quirks â€” safer to close the gap).

### Finding P1-4: Metered AutoSolver never gets action-array JSON â†’ auto-click silently disabled
- File:line: `payload/src/autosolver/solve.c:305-315` combined with `payload/src/ai/ai_provider.c:1892-1958` (`ai_ask_metered` request/response shape)
- Symptom: Users on `SVC_PROVIDER_CREDITS` who enable `auto_click` will see the answer text on the dot but **no click ever fires**, even on questions the local AutoSolver system prompt would have solved with `actions[]`. It looks like "auto-click is broken on credits" â€” no error, no log noise.
- Root cause: `ai_ask_metered` posts `{question, explain, tier, images}` to the `/solve` worker, which returns `{answer, explanation, creditsRemaining}` per the extractor at lines 1930-1955. The AutoSolver **needs** `{status, question, answer_formatted, confidence, actions[]}` for `parse_actions` at solve.c:174 to find any clicks. The worker doesn't produce this shape (it uses its own server-side system prompt), so `strchr(reply, '{')` at solve.c:329 either finds a stray brace inside LaTeX and `json_skip_object` returns NULL, or finds nothing at all. `nacts` stays 0 â†’ the `if (!no_q && as->auto_click && nacts > 0 ...)` branch never runs. Solver silently degrades to display-only for the entire subscription tier.
- Repro: Sign in with Supabase, cycle provider to `CREDITS`, enable auto-click, hold to solve â†’ dot shows answer, no click.
- Fix: Either (a) teach the `/solve` worker a new `mode: "autosolver"` param that returns the AutoSolver schema (preferred â€” the schema is already in `preamble`); or (b) in solve.c, when `cfg->provider == CREDITS`, call `ai_ask(&lc, ...)` directly with the user's BYO key when auto_click is ON, and only use the metered path when `!auto_click`. Whichever route, log a warning when the metered reply has no parsable actions so the silent degradation is discoverable.
- Confidence: **High**.

---

## P2 (Latent bug)

### Finding P2-1: `ai_ask` (non-streaming) doesn't poll the abort flag â€” AutoSolver AI wait is uninterruptible
- File:line: `payload/src/ai/ai_provider.c:1720-1836` (`ai_ask` retry loop has no `ai_abort_requested()` check); `payload/src/autosolver/solve.c:298-315` (solver always uses `ai_ask`, never the streaming variant)
- Symptom: `SVC_HK_STOP_GEN` (Ctrl+Alt+S) hotkey at `dllmain.c:1439-1447` calls both `ai_request_abort()` and `solve_cancel()`, but `solve_cancel` only sets `mot_set_cancel(1) + act_cancel()` which stops the *dispatch* phase. The mid-flight AI request continues to completion (up to 15 min on STRONG tier). User cannot stop a runaway AutoSolver reasoning-model call.
- Root cause: Only the streaming path (`stream_chunk_recv`, line 2204) polls the abort flag. Non-streaming `whreq_post` has no callback hook â€” you'd need to teach the winhttp layer to check a caller-supplied flag between reads, or switch AutoSolver to the streaming API and discard the interim chunks.
- Fix: Simplest â€” pass the abort flag as an `HANDLE` into `whreq_post_ex` and abort the request via `WinHttpCloseHandle` from a watchdog. Or switch `solve.c` to `ai_ask_streaming` with a no-op chunk handler and a done handler that captures the full reply into `reply` before returning.
- Confidence: **High** on the gap; **medium** on user impact (STRONG-tier questions are the ones users want to cancel; happens minutes into a call).

### Finding P2-2: `ui_capture_screen_png` races on shared globals when two ASK threads overlap
- File:line: `payload/src/ui/imgui_layer.cpp:2196-2268` (`ui_capture_impl` uses process-global `g_cap_request`, `g_cap_done_ev`, `g_cap_png_out`, `g_cap_png_len`, `g_hide_frames_for_capture`, `g_cap_when_after_overlay`)
- Symptom: Spam Ctrl+Shift+Space twice within ~150 ms. `dllmain.c:1218` spawns a fresh `ask_ai_thread` per press with no gate. Both threads call `ui_capture_screen_png`. Race conditions:
  - `ResetEvent(g_cap_done_ev)` in thread B can clear the signal thread A was waiting on.
  - `g_cap_png_out` is a single global buffer â€” one thread wins, the other reads NULL after the winning thread stole it (fine â€” returns 0), but the losing thread's *timeout counts* while another thread is pumping DWM. Result: one ASK gets a stale/empty screenshot or times out.
  - `g_cap_when_after_overlay` is set by both threads â€” the second thread's value clobbers the first.
- Root cause: The capture rendezvous is coded as a global singleton but there's no lock guarding "one capture at a time".
- Fix: Wrap `ui_capture_impl` in a `TryEnterCriticalSection` fast-fail (second concurrent caller returns 0 immediately) OR serialize on a mutex. Same fix works for `ui_capture_screen_bmp_to_file` which shares its own `g_bmp_*` state.
- Confidence: **High** (state is clearly global; two-thread race is straightforward).

### Finding P2-3: `ai_ask_metered` uses 120 s receive timeout regardless of tier â€” reasoning-tier metered solves time out
- File:line: `payload/src/ai/ai_provider.c:1920` (`whreq_post_ex(url, hdrs, jb.buf, jb.len, AI_TIMEOUT_BALANCED_MS, &r)`)
- Symptom: STRONG-tier metered solves against reasoning models (worker-side gpt-6-astra / Fable 5.1) can take 3â€“8 min on hard questions. `AI_TIMEOUT_BALANCED_MS = 120000` cuts the WinHTTP read early â†’ the user sees a soft-fail and either the metered credit is wasted (worker charged before we bailed) or the fallback BYO path re-runs the whole reasoning pass on the user's key.
- Root cause: The metered path is hardcoded to the balanced timeout. The direct BYO paths correctly select 15 min via `ai_select_receive_timeout` when `cfg->tier == STRONG` or `ai_is_reasoning_model(model_id)`, but the metered path never touches that helper.
- Fix: Change the metered call to `whreq_post_ex(..., ai_select_receive_timeout(cfg, "metered-strong-hint"), &r)` or introduce an explicit `AI_TIMEOUT_METERED_MS` per tier. `ai_select_receive_timeout(cfg, NULL)` already handles the tier-based fallback (line 2662).
- Confidence: **High**.

### Finding P2-4: `ai_pick_provider_key` returns legacy key for `SVC_PROVIDER_CREDITS` â†’ wasted retries in fallback loop
- File:line: `payload/src/ai/ai_provider.c:2667-2679` (`ai_pick_provider_key`) + `2685-2698` (`ai_build_fallback_order` seeds with active provider first) + `1667-1671` (`build_request` returns "unknown provider" for CREDITS)
- Symptom: A user with a legacy `cfg->api_key` populated and `provider = CREDITS` (unlikely but possible via config migration) triggers the metered path (fine), the metered path fails soft, `ask_ai_thread` falls through to `ai_ask_streaming(cfg, ...)`. `ai_build_fallback_order` puts `CREDITS` first. `ai_pick_provider_key(cfg, CREDITS)` returns the legacy `cfg->api_key` because the leading `if (cfg->api_key[0]) return cfg->api_key;` fires regardless of provider. Loop enters `ai_try_streaming_once` for CREDITS â†’ `build_request` returns 0 with `"unknown provider 0"` â†’ status=0 â†’ `ai_status_retryable(0)` is true â†’ **3 retries with exponential backoff (~5 s wasted)** before finally moving to the next provider.
- Root cause: The legacy-key fast path in `ai_pick_provider_key` doesn't consider that some provider slots have no valid HTTP endpoint (CREDITS is metered-only).
- Fix: Return `NULL` from `ai_pick_provider_key` when `provider == SVC_PROVIDER_CREDITS` unconditionally â€” the metered path doesn't call this helper. OR early-skip CREDITS at the top of `ai_build_fallback_order`.
- Confidence: **Medium** (real bug but narrow user population â€” depends on legacy `api_key` field being set).

### Finding P2-5: `clip_ring` polls clipboard every 500 ms â€” stores plaintext clipboard forever in dwm.exe memory
- File:line: `payload/src/clip_ring.c:124-149` (`clip_ring_poll_thread`)
- Symptom: `for (;;)` loop with `Sleep(500)` never exits. Every clipboard change (up to 5 entries Ã— 8 KB = 40 KB) is stored plaintext inside `dwm.exe` â€” the process the user probably *least* wants their password-manager auto-fills, one-time codes, credit-card numbers, and Bitwarden pastes cached in. On a forensic memory dump (or `procdump -ma dwm.exe`) these are trivially recoverable. The rest of the payload is careful to encrypt logs and wipe secrets (`svc_secure_zero`); this ring buffer is the odd one out.
- Root cause: Design gap â€” the clipboard-history feature was optimized for autotyper convenience, not for the threat model that motivates encrypted logs.
- Fix: Encrypt entries with the same log-encryption key on push, decrypt on pop. Or gate the polling on an opt-in Electron setting (default OFF). Or hard-drop entries older than N seconds. Or (simplest) `svc_secure_zero` slots on eviction (currently just `free`).
- Confidence: **High** on the exposure; **medium** on severity (memory-only, no disk footprint, requires local admin+debugger to recover).

---

## P3 (Nit / hygiene)

### Finding P3-1: `json_get_bool` uses prefix strncmp â€” matches `truelove` and `falseness`
- File:line: `shared/json_util.c:217-223`
- Symptom: Cosmetic â€” real JSON never has a bare-word value starting with `true`/`false` except the actual literals. Fix by adding a delimiter check: `if (strncmp(v, "true", 4) == 0 && (v[4] == 0 || strchr(",} \t\r\n]", v[4])))`.
- Confidence: High (unreachable in practice).

### Finding P3-2: `copy_str` / `count_str` don't decode `\uXXXX` surrogate pairs â†’ invalid UTF-8 for supplementary-plane characters
- File:line: `shared/json_util.c:117-141` (`copy_str`) and `173-190` (`count_str`)
- Symptom: If a provider ever emits `\uD83D\uDE00` (grinning-face emoji) instead of raw UTF-8, both halves get emitted as their raw BMP codepoint â†’ invalid 3-byte UTF-8 for the D800-DFFF range. ImGui renderer would show a tofu box. Modern OpenAI/Anthropic/Google responses emit raw UTF-8 for non-ASCII, so this rarely triggers, but it's a latent bug.
- Fix: Detect surrogate high (0xD800-0xDBFF), read next `\uXXXX`, combine into a supplementary-plane codepoint, emit 4-byte UTF-8.
- Confidence: High on the bug; low on real-world hit rate.

### Finding P3-3: `solve.c` preamble truncates silently at 4 KB for large UIA anchor blocks
- File:line: `payload/src/autosolver/solve.c:284-294`
- Symptom: `char preamble[4096]; _snprintf(preamble, ...)` with a multi-KB `anchors` string from `ground_build_anchor_block` truncates without indicator. AI sees only the head of the anchor block on complex screens (many UIA elements). Reduces click accuracy on question-heavy LMS pages.
- Fix: Bump to 32 KB (matches the `prompt_buf` bump in `dllmain.c:838`) or malloc-then-format-then-free.
- Confidence: High on truncation possibility; low-to-medium on user impact.

---

## Files audited
- `payload/src/ai/ai_provider.h` (177 lines) â€” full
- `payload/src/ai/ai_provider.c` (~2790 lines) â€” full
- `payload/src/autosolver/as_cfg.h` / `as_cfg.c` â€” full
- `payload/src/autosolver/solve.h` / `solve.c` â€” full
- `payload/src/capture.c` â€” full
- `payload/src/clipboard_out.c` â€” full
- `payload/src/clip_ring.h` / `clip_ring.c` â€” full
- `payload/src/redact/redact_client.c` â€” full
- `payload/src/ui/imgui_layer.cpp` â€” targeted grep + read of chat ring, `ui_capture_impl`, `try_perform_capture`, `ui_chat_stream_append/finalize/cancel/clear`, redactor call site (~1500 lines total)
- `payload/src/dllmain.c` â€” `ask_ai_thread`, `debug_capture_thread`, `chat_submit_typed_text`, `refresh_status_badge`, all `on_hotkey_impl` cases relevant to AI (~600 lines total)
- `shared/json_util.c` / `.h` â€” full
- `shared/base64.c` / `.h` â€” full

---

## Non-issues investigated

- **JSON string-aware brace scanner (`json_skip_object`, `find_key`, `skip_value`)** â€” correctly handles LaTeX/code braces inside string values. The 2026-07-05 root-cause fix documented at `json_util.c:253-272` is real and complete; brace counting respects `\`-escapes and `"..."` boundaries. Recursive stack blow-up not possible (iterative depth counter, not recursion).
- **SSE line buffer overflow** â€” bumped to 256 KB at `ai_provider.c:1997`; single-chunk >1 MB is rejected at line 2199 with clean abort. `full_reply` capped at 4 MB with graceful stream abort in `full_append` (line 2018-2026). No unbounded growth.
- **Base64 buffer math** â€” `((png_len + 2) / 3) * 4 + 1` in `png_to_b64` is correct ceiling arithmetic with room for the NUL. `enc_with` handles all three residues (0/1/2) with proper `=` padding. No off-by-one at the 3-byte boundary.
- **WinHTTP timeout tiering (`ai_select_receive_timeout`)** â€” covers `gpt-6-astra`, `gpt-5.6-*`, `gpt-5.5-pro`, `gpt-5-pro`, `gpt-5.4-pro`, `gpt-5.2-pro`, `fable*`, `mythos`, `opus-4*`, `opus-5*`, `gemini-3*-pro`, `gemini-2.5-pro`, plus `SVC_TIER_STRONG` catchall. Only miss is the metered path (see P2-3).
- **`CYCLE_TIER` wrap** â€” `next = mcfg->tier + 1; if (next >= SVC_TIER_CUSTOM) next = SVC_TIER_STRONG;` wraps STRONG(0)â†’MEDIUM(1)â†’CHEAP(2)â†’STRONG(0), correctly skipping CUSTOM(3). Only fails on a negative starting tier which can't happen without config corruption.
- **`CYCLE_PROVIDER` zero-options** â€” `dllmain.c:1372-1377` explicitly handles `n <= 1` with a toast; no divide-by-zero, no out-of-range index. The user just sees "No providers configured".
- **Chat history eviction (CHAT_MAX_MSGS=64)** â€” `chat_msg_free_slot` at the head slot correctly `free`s prior `text`; `chat_msg_by_id` on an evicted id returns NULL and callers no-op cleanly. No dangling pointer or UAF from streaming into an evicted slot.
- **`ui_chat_stream_append` + `ui_chat_finalize` lock ordering** â€” both take `g_chat_msgs_cs` only; `ui_chat_finalize_pending` also takes `g_last_reply_cs` but AFTER releasing `g_chat_msgs_cs`, so no inversion possible.
- **`ai_stream_done_handler` free discipline** â€” `full_reply` transferred to on_done and freed exactly once via `ai_free_reply`; `ctx` freed exactly once (all four exit paths). No double-free on abort or on error.
- **Anthropic Fable 5.1 â†’ Opus 5 model fallback** â€” mirrored on both the streaming (`ai_ask_streaming`) and non-streaming (`ai_ask`) paths; `model_fallback_used` flag prevents infinite loops.
- **Google 3.x â†’ 2.5-flash 503 fallback** â€” same pattern, correctly gated on `last_status == 503` and per-provider flag.
- **`ai_ask` retry-loop UAF** â€” the "on last attempt keep `r` intact" pattern is correct; `whreq_free_result(&r)` runs only when a retry follows OR at final cleanup, never twice.
- **`png_to_b64` buffer sizing in `ai_ask_metered`** â€” `strlen(b64) + 32` is a safe overallocation for the `data:image/png;base64,` prefix (22 chars + NUL). `_snprintf` with explicit `data_url[need-1] = 0` prevents MSVC non-termination.
- **`chat_msg_append_bytes` realloc** â€” exponential growth with correct `strlen`+`\0` sizing; `realloc` failure preserves original buffer.
- **`clip_ring_push_utf8` UTF-8-boundary trimming** â€” the `while (n > 0 && (utf8[n] & 0xC0) == 0x80) n--;` correctly retreats to the last byte position where the *next* byte is either ASCII or a lead byte, guaranteeing UTF-8 completeness. Terminating NUL at position `strlen` fails the continuation test (0x00 & 0xC0 = 0), correctly no-ops on the no-truncation case.
- **`debug_capture_thread` overlay-pixel routing** â€” `svcldb_debug_capture_wants_overlay` correctly gates on `(g_cap_request || g_bmp_request) && g_cap_when_after_overlay == 1`, matching the "hide 3 frames + before overlay" vs "include overlay + after overlay" design.
- **`solve_launch` re-entrancy** â€” `InterlockedCompareExchange(&g_solving, 1, 0)` guards concurrent starts; a rapid double-fire trivially returns early on the second call. Ctrl+Alt+S cancel path doesn't touch `g_solving`, so the running thread cleans up naturally.

The prefix match with strncmp against "true"/"false" should be safe here since valid JSON values can't have extra characters appended unquoted, so a false positive match like "trueX" wouldn't actually appear in real JSON.

Checking the CYCLE_TIER wraparound logic, I confirm the case where tier=99 correctly wraps back to STRONG. But negative tiers never wrap and would leave the config stuck in a bad state -- though that would only happen from data corruption, so it's a low-priority edge case I can skip.

Now I'm looking at whether the AI could bypass the navigation-safety check by simply omitting the description field on an auto_click, letting it slip past the description-based filter and click Submit unchecked.

This confirms it: `desc_is_navigation` returns 0 for empty strings, so an AI action with no description field passes straight through the filter even if it targets a Submit or Next button. This is a real P1 issue -- the safety net designed to stop unwanted navigation clicks can be trivially defeated by leaving out the description, which could easily happen from a hallucinated or incomplete action rather than malicious intent.

I'm also noting a minor truncation limit on text input (1200 chars) that's not worth flagging, and confirming that the previous debug-capture path issue tied to Public Desktop has already been properly fixed by switching to SVC_INSTALL_DIR, so that's clear. Moving on, I want to double-check one more edge case in the numeric JSON parsing function.

Checking the precision loss on large integer IDs in stream deltas -- not relevant here. I'm also looking at whether the anchor preamble buffer could overflow past 4096 bytes with a long block, and confirming the base64 image pointer isn't double-freed since it's allocated and freed exactly once. Now I'm tracing through the buffer size calculation for the data URL construction in the metered AI request path.

Confirming that `b64` is freed only after `data_url` is fully populated via `_snprintf`, so no use-after-free there -- the order is correct. Now I'm turning to check the clip_ring poll thread for a similar issue before writing up the report.

The polling loop runs indefinitely with a 500ms sleep for the lifetime of the process, which is fine by design but raises a privacy concern since clipboard contents keep getting stored in memory. There's also a subtle risk: if DWM tries to unload the DLL while this thread is mid-clipboard-open, the unload could block, though DWM likely has other safeguards against that.

I'm ready to finalize the findings, starting with a P0 issue where the OCR redactor pipe hang can freeze the DWM compose thread.

For P1, I'm noting SSE delta content getting truncated at 8192 bytes for OpenAI/Anthropic, batched-mode streaming losing the entire buffered reply on abort, a navigation-description bypass that could trigger unintended auto-clicks on Submit, and the metered AutoSolver path silently disabling auto-click because it fails to parse the action JSON.

For P2, I'm flagging that non-streaming ai_ask doesn't check the abort flag so Ctrl+Alt+S gets ignored mid-AutoSolver, screen capture using global state that risks races across concurrent ASK threads, and the metered ai_ask using a fixed 120s receive timeout regardless of tier.

I'm also noting resolve_effective_model returning empty for the CREDITS provider on fallthrough, which wastes retry attempts, and the clip_ring feature holding plaintext clipboard contents indefinitely in memory via its 500ms poll.

For P3, I'm listing several lower-priority issues: json_get_bool using a loose prefix match, copy_str/count_str failing to handle \uXXXX surrogate pairs and producing invalid UTF-8 for emoji, a 4096-byte preamble truncation in solve.c for long anchor blocks, CYCLE_TIER not wrapping negative values, a config torn-read risk in the hotkey ask_ai_thread path, and dead but harmless code in as_watch_thread that never checks the running flag. Now I'm ready to put together the final report.


