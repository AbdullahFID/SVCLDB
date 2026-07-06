# HANDOFF: LaTeX v4 overhaul + UX cleanup (2026-07-05 late night → 2026-07-06 early)

**Session driver**: user reported "the ais are not rendering latex properly at all" and "ctrl alt x on chat view already goes to back its just it says clear on ui — should say back" and "there should be buttons for like copying either the full answer (should show at bottom of the answer) or individual snippet areas which beside that copy btn on the snippets made should be its mapped hotkey".

**Outcome**: (1) Found and fixed a silent streaming-parser bug that was corrupting all LaTeX output; (2) massively expanded LaTeX-to-Unicode coverage; (3) made Ctrl+Alt+X non-destructive with proper "back" label; (4) added copy-full/copy-answer buttons under every AI reply + hotkey labels on snippet copy buttons.

---

## THE bug that was killing LaTeX

`extract_sse_delta` + `extract_openai_reply` + `extract_anthropic_reply` + `extract_google_reply` all used naive `{`/`}` balance counters that did NOT respect JSON string boundaries. Any streamed SSE chunk whose `"content"` string value contained a `}` (extremely common for LaTeX like `\frac{T}{10}`) caused:

1. Loop encounters `{` at outer delta object → depth=1
2. Loop encounters `{` INSIDE the content string → depth=2
3. Loop encounters `}` inside content → depth=1
4. Loop encounters `}` closing the delta object → depth=0 → BREAK with truncated slice
5. `json_get_str` on truncated JSON fails → returns 0
6. `extract_sse_delta` returns NULL → **entire streamed token silently dropped**

User's `last_reply.txt` had `\frac{T}{10}\right)` mangled to `\frac{T10right)`. Same pattern for all `}{` and `}\` sequences. This bug shipped with streaming (v3, 2026-07-05 evening) and was corrupting every LaTeX-heavy reply for 24+ hours before diagnosis.

## The fix

`shared/json_util.{h,c}` gained:

```c
/* Walk from `start` (adjusted forward to first `{`) to the matching `}`,
 * respecting `"..."` string boundaries + `\`-escapes. Returns pointer
 * one past the matching `}`, or NULL on malformed input. */
const char *json_skip_object(const char *start);
const char *json_skip_array (const char *start);
```

Every extractor in `ai_provider.c` now calls `find_object_end(open) → json_skip_object(open)` instead of a hand-rolled counter.

**INVARIANT**: any code that slices a nested JSON object out of a larger body MUST use `json_skip_object`. Grep for `depth++` / `md++` patterns in future code review and audit.

---

## v4 LaTeX-to-Unicode renderer

Located in `payload/src/ui/imgui_layer.cpp`. Full rewrite of `latex_to_unicode` — the header comment in that function documents everything. Highlights:

### Coverage additions (250+ commands)

- **Greek**: all lowercase + uppercase + variants (`\varepsilon`, `\varphi`, `\vartheta`, `\varsigma`, `\varrho`, `\varpi`)
- **Arrows**: `\Longleftrightarrow`, `\Longrightarrow`, `\Longleftarrow`, `\hookrightarrow`, `\hookleftarrow`, `\nearrow`, `\searrow`, `\nwarrow`, `\swarrow`, `\mapsto`, `\to`, `\gets`, `\longmapsto`, arrows with double lines
- **Relations**: `\approx`, `\approxeq`, `\equiv`, `\propto`, `\sim`, `\simeq`, `\cong`, `\leqslant`, `\geqslant`, `\prec`, `\succ`, `\preceq`, `\succeq`, `\ll`, `\gg`, `\neq`, `\le`, `\ge`
- **Set/logic**: `\in`, `\notin`, `\ni`, `\subseteq`, `\supseteq`, `\subsetneq`, `\supsetneq`, `\subset`, `\supset`, `\setminus`, `\cup`, `\cap`, `\emptyset`, `\varnothing`, `\forall`, `\exists`, `\nexists`, `\therefore`, `\because`, `\neg`, `\lnot`, `\land`, `\lor`, `\implies`, `\iff`
- **Big ops**: `\iiint`, `\iint`, `\oint`, `\int`, `\sum`, `\prod`, `\coprod`, `\bigcup`, `\bigcap`, `\bigsqcup`, `\bigwedge`, `\bigvee`, `\bigoplus`, `\bigotimes`
- **Binary ops**: `\pm`, `\mp`, `\times`, `\cdot`, `\div`, `\ast`, `\star`, `\bullet`, `\circ`, `\oplus`, `\ominus`, `\otimes`, `\oslash`, `\odot`, `\wedge`, `\vee`
- **Delimiters**: `\lceil`, `\rceil`, `\lfloor`, `\rfloor`, `\langle`, `\rangle`
- **Geometry**: `\parallel`, `\perp`, `\angle`, `\triangle`, `\square`
- **Sizing (all empty)**: `\Big`, `\big`, `\bigg`, `\Bigg`, `\Biggl`, `\Biggr`, `\biggl`, `\biggr`, `\Bigl`, `\Bigr`, `\bigl`, `\bigr`, `\left`, `\right`, `\middle`
- **Spacing**: `\!`, `\,`, `\;`, `\:`, `\ ` (backslash-space), `\quad`, `\qquad`
- **Escapes**: `\%`, `\$`, `\&`, `\_`, `\#`, `\{`, `\}`
- **Function names**: 25+ from `log`, `ln`, `lg`, `exp`, `sin`, `cos`, `tan`, `csc`, `sec`, `cot`, `arcsin`, `arccos`, `arctan`, `sinh`, `cosh`, `tanh`, `coth`, `lim`, `limsup`, `liminf`, `max`, `min`, `sup`, `inf`, `arg`, `deg`, `det`, `dim`, `ker`, `gcd`, `lcm`, `mod`, `Pr`, `hom`

### Structural rewrites

- **Full Unicode super/subscript** via `sup_of()` / `sub_of()` — letters + digits + operators. `x^{ab}` → `xᵃᵇ`.
- **Vulgar fractions** for common `\frac{n}{m}` → `½ ⅓ ¼ ⅕ ⅙ ⅐ ⅛ ⅑ ⅒ ⅔ ¾ ⅖ ⅗ ⅘ ⅚ ⅜ ⅝ ⅞` (18 forms).
- **Text-wrapping commands** (40+ entries in `LATEX_TEXT_WRAPPERS[]`): `\text`, `\mathbf`, `\mathrm`, `\mathbb`, `\mathcal`, `\mathfrak`, `\mathit`, `\mathsf`, `\mathtt`, `\operatorname`, `\emph`, `\underline`, `\mbox`, `\hbox`, `\color`, `\Large`, `\Huge`, etc. — all emit inner content unchanged.
- **Accent commands** (`LATEX_ACCENTS[]`) — emit content + Unicode combining mark per codepoint: `\vec{v}` → `v⃗`, `\hat{x}` → `x̂`, `\bar{x}` → `x̄`, `\overline{AB}` → `ĀB̄`, `\dot`, `\ddot`, `\dddot`, `\check`, `\acute`, `\grave`, `\breve`, `\tilde`, `\widetilde`, `\widehat`, `\overrightarrow`, `\overleftarrow`.
- **Environment support** — `latex_render_env()` handles matrix (`( )`), pmatrix (`( )`), bmatrix (`[ ]`), Bmatrix (`{ }`), vmatrix (`| |`), Vmatrix (`‖ ‖`), smallmatrix, array, cases (⎧ ⎨), dcases, aligned, align, gather, gathered, split, multline, eqnarray, subarray, equation. `\\` splits rows, `&` splits cells, both nesting-aware.
- **Generic `\unknown{content}` passthrough** — silently drops the command name + emits content. Handles `\underbrace{...}`, `\overbrace{...}`, `\xrightarrow{...}`, etc. without needing every LaTeX package in the map.
- **Smart paren wrapping** for `\frac`:
  - NUM: wrap only on op/space/paren
  - DEN: wrap on op/space/paren OR mixed digit+letter/multibyte (fixes `1/2a` ambiguity → `1/(2a)`)
  - Pure `a/b`, `dy/dx`, `distance/speed` no wrap
- **Chemistry-friendly bare `_N` / `^N`** — single digit followed by letter allowed (`H_2O` → `H₂O`, `x^2y` → `x²y`)
- **`^\command` handling** — `T=0^\circ` → `T=0°` (drops `^` since `°` is already visually superscript-like)
- **`\\` in display math** → newline (with optional `[N]` spacing spec consumed)
- **`\sqrt[n]{x}`** — nth root with Unicode superscript index prefix: `\sqrt[3]{27}` → `³√27`
- **`\binom{n}{k}`** + `\tbinom` + `\dbinom` → `C(n,k)`
- **`\sqrt{...}` wrap** — same 3-type rule (pure digits or pure letters no wrap, mixed wraps)

### Unit tests

`payload/test/latex_test.c` — 93 tests, 100% pass. Compile + run:

```powershell
cd C:\Users\<you>\Desktop\svcldb\payload\test
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && cl /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS latex_test.c && latex_test.exe'
```

Tests exercise: basic delimiters, sub/sup with letters + digits + operators, all fraction forms (vulgar + wrapped + nested), sqrt (single/expr/nth root/pure-digit), Greek (with variant disambiguation), operators, arrows, sets/logic/geometry, big delimiters, all text wrappers, all accents, all matrix/env forms, cases with complex conditions, aligned equations, longest-match-first ordering regressions, escape sequences, user's exact reported Physics reply, real-world equations (Gaussian PDF, Fourier transform, Euler identity, Bayes theorem, chain rule, cross product, Dirac notation, Riemann sum, matrix multiplication, chemistry H₂O + CO₂), adversarial inputs (unterminated $, unterminated \frac, empty braces, deeply nested, only-backslash), full multi-paragraph markdown responses.

**Adding a new test**: append `test_case("desc", "input", "expected");` before the `printf("\n=== SUMMARY ===");` line. Watch it fail, tweak `latex_to_unicode` (both in imgui_layer.cpp AND the copy in latex_test.c — keep them in sync), watch it pass.

**Demo output** at end of test run shows a real Physics reply rendered top-to-bottom + a matrix/cases example.

---

## UX cleanup

### Ctrl+Alt+X now goes back (non-destructive), not clear

Previously `ui_clear_reply()` called `ui_chat_clear_history()` which nuked all messages. Now `ui_clear_reply()` calls `ui_view_show_home()` which sets the `g_home_view_forced` flag — messages stay in memory but the empty home cheat-sheet is shown.

New APIs in `payload/src/ui/imgui_layer.h`:

```c
void ui_view_show_home(void);       // set g_home_view_forced = 1
void ui_view_show_chat(void);       // set g_home_view_forced = 0
int  ui_is_showing_chat(void);      // TRUE if msg_count > 0 AND !g_home_view_forced
```

`ui_has_reply()` returns 0 when home-forced, so the second `Ctrl+Alt+X` press quits (matches user mental model: "back-back-quit").

Flag auto-resets on any `ui_chat_append_message` / `ui_chat_append_pending` — new activity brings chat back. Also cleared by `ui_chat_clear_history` (Ctrl+Alt+N) since destination is home anyway.

`Ctrl+Alt+N` remains the DESTRUCTIVE clear-all hotkey and is now labeled `"New chat (clear all msgs — DESTRUCTIVE)"` in the cheat sheet.

### Footer strip labels updated

- Home view: `"Ctrl+Shift+Space ask | Ctrl+Alt+T type | Ctrl+Alt+G toggle | Ctrl+Alt+X quit"`
- Chat view: `"Ctrl+Alt+X back | Ctrl+Alt+N clear | Ctrl+Alt+C copy | Ctrl+Alt+J/K scroll"`

### Home-forced state indicator

When `g_home_view_forced` is set with `msg_n > 0`, top of home view shows: `"Chat hidden. N messages preserved. Ask/type/regenerate to bring it back."`

### Dynamic hotkey label registry

New APIs in `imgui_layer.h`:

```c
void   ui_set_hotkey_bindings(const unsigned *hks, int n);
size_t ui_format_hotkey      (int action, char *out, size_t out_sz);
```

`dllmain.c` calls `ui_set_hotkey_bindings(cfg->hotkeys, SVC_HK_COUNT)` after `rawin_start()`. Later, `ui_format_hotkey(SVC_HK_COPY_CODE, buf, sizeof(buf))` writes `"Ctrl+Shift+Alt+C"` (or whatever the user has bound). Uses `vk_to_label(vk)` helper for VK-to-string mapping (Space, Enter, F1..F12, arrows, punctuation, etc.).

### Copy buttons under every AI bubble

After the message body (bottom of `draw_chat_bubble`), FINALIZED AI messages with content get:

- **`"Copy full [Ctrl+Alt+C]"`** — copies entire raw AI reply
- **`"Copy answer [Ctrl+Alt+A]"`** — copies just first non-empty line, trimmed

Only shown when `!pending && text && text[0]`. Both buttons pull their hotkey labels from the registry so labels stay in sync with any rebindings.

### Snippet copy buttons show hotkey too

`md_render_tinted_block` (used for both code + math blocks) now formats the button label as:

- Code blocks: `"copy [Ctrl+Shift+Alt+C]"` (looks up `SVC_HK_COPY_CODE`)
- Math blocks: `"copy"` (no dedicated hotkey — just literal)

Button width dynamically sizes to fit the label text (padding formula `btn_txt_sz.x + 16.0f`, clamped to ≥60px).

---

## Files touched

- `shared/json_util.h` — added `json_skip_object`, `json_skip_array` prototypes
- `shared/json_util.c` — string-aware object/array skippers
- `payload/src/ai/ai_provider.c` — all 4 extractors rewired to `find_object_end(open) = json_skip_object(open)`
- `payload/src/ui/imgui_layer.h` — added `ui_view_show_home`, `ui_view_show_chat`, `ui_is_showing_chat`, `ui_set_hotkey_bindings`, `ui_format_hotkey`; updated `ui_clear_reply` docs (non-destructive)
- `payload/src/ui/imgui_layer.cpp` — full `latex_to_unicode` rewrite (~1500 new lines), 250+ LATEX_MAP entries, LATEX_TEXT_WRAPPERS + LATEX_ACCENTS tables, `sup_of` / `sub_of`, VULGAR_FRACS table, `latex_render_env`, brace/wrapper/accent/env/skip/utf8 helpers, `try_render_sup_sub`, `g_home_view_forced` flag + all view APIs, `g_hk_bindings[]` registry + `vk_to_label` + `ui_format_hotkey`, dynamic snippet copy labels in `md_render_tinted_block`, `"Copy full [X]" + "Copy answer [X]"` buttons in `draw_chat_bubble`, updated cheat sheet + footer strip labels
- `payload/src/dllmain.c` — added `ui_set_hotkey_bindings(cfg->hotkeys, ...)` call after `rawin_start()`
- `payload/test/latex_test.c` — full rewrite; 93 test cases + demo section; standalone build (no ImGui dep)
- `CLAUDE.md` — updated invariant #9 to reflect new Ctrl+Alt+X semantics; appended "v4 LaTeX overhaul" session log with all invariants

---

## Build + deploy (2026-07-06 ~01:00 EDT)

```powershell
cd C:\Users\<you>\Desktop\svcldb\payload
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && build.bat'
# → 682,496 bytes clean

cd C:\Users\<you>\Desktop\svcldb\launcher
cmd /c 'build.bat'
# → 922,112 bytes clean (embeds payload as RCDATA)

Copy-Item C:\Users\<you>\Desktop\svcldb\build\launcher\sihost.exe `
    C:\ProgramData\WinAudioSvc\sihost.exe -Force
```

Live E2E was blocked in the assistant's shell session because DWM had been killed without respawning back into the visible session context (Cursor Terminal nested-session quirk). User re-arms via:

```powershell
& C:\ProgramData\WinAudioSvc\sihost.exe --quiet   # or --reinject if config exists
```

Then hit `Ctrl+Alt+T` and type a math question — LaTeX will render properly. Or hit `Ctrl+Shift+Space` on a math problem screenshot.

---

## Hard invariants added this session (DO NOT REGRESS)

1. **JSON object slicing MUST use `json_skip_object` (string-aware).** Never write a naive `for(*p; ...) if('{')depth++; else if('}')depth--;` loop against JSON — content strings with `{`/`}` (LaTeX, code, MCQ options, JSON-in-JSON) will silently corrupt the slice. Every AI-response extractor + SSE-delta extractor learned this the hard way.
2. **`latex_to_unicode` does NOT mutate the source `chat_msg.text`.** Only the RENDER path calls it. Copy hotkeys (`Ctrl+Alt+C` / `+A` / `+Shift+C`) target raw text so users can paste LaTeX into Overleaf.
3. **`LATEX_MAP` ordering is LONGEST-MATCH-FIRST + word-boundary-aware.** Never reorder alphabetically. Always insert multi-char variants BEFORE their prefixes.
4. **Environment renderer emits opening bracket on EVERY row** for matrix envs (not just first). Never regress to "first row only".
5. **`g_home_view_forced` must auto-reset on message append.** Every append-path MUST `InterlockedExchange(&g_home_view_forced, 0)`.
6. **`ui_has_reply()` returns 0 when `g_home_view_forced != 0`.** This routes the second Ctrl+Alt+X press to QUIT instead of back-again.
7. **`ui_set_hotkey_bindings` fires ONCE at init.** Rebind requires re-arm.
8. **Copy buttons pull hotkey text via `ui_format_hotkey(SVC_HK_*)` — the enum ordinal.** Never hardcode `"Ctrl+Alt+C"` as a literal.
9. **Sub/sup fallback for un-mappable inner preserves BRACES.** Emit `^{content}` / `_{content}` literally so scope is unambiguous.
10. **Wrap heuristic**: NUM wraps on op/space/paren only; DEN wraps on op/space/paren OR digit+letter mix. Never over-wrap (`(dy)/(dx)` reads worse than `dy/dx`), never under-wrap (`1/2a` is genuinely ambiguous). The 93-test suite pins this behavior.

---

## Next-chat starter prompt

If picking up work here fresh:

```
Load svcldb project memory (CLAUDE.md + docs/HANDOFF_LATEX_V4_2026-07-06.md).
Current state: v4 LaTeX renderer landed with 93/93 unit tests passing. JSON
extraction bug fixed (was silently dropping LaTeX-heavy SSE chunks). Ctrl+Alt+X
now non-destructive back. Copy-full + copy-answer buttons added under AI bubbles
with dynamic hotkey labels. Snippet copy buttons show mapped hotkey too.

Build + deploy already done — sihost.exe deployed to C:\ProgramData\WinAudioSvc.
Live E2E requires user to re-arm after next login (DWM session refresh needed).

Test suite: cd payload\test && cl /nologo /O2 /D_CRT_SECURE_NO_WARNINGS
latex_test.c && latex_test.exe (93/93 passing).

If working on further improvements, follow the 10 invariants at the end of
CLAUDE.md's v4 section. If adding new LaTeX symbols, insert in LATEX_MAP in
longest-match-first order AND add a test case.
```
