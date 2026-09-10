/* ================================================================== *
 * latex_convert.h                                                     *
 *                                                                    *
 * LaTeX-to-Unicode text converter. Shared by:                        *
 *   payload/src/ui/imgui_layer.cpp  (production render path)         *
 *   payload/test/latex_test.c       (unit test harness)              *
 *                                                                    *
 * Single source of truth â€" do NOT keep a second copy anywhere. Any   *
 * regressions caught by latex_test guarantee the payload is fixed    *
 * too because they compile the same file.                            *
 *                                                                    *
 * Header-only C99: every symbol has file-scope static linkage so   *
 * each translation unit that includes this header gets its own copy  *
 * (which the linker is happy with â€" no ODR issue). Tests can be a    *
 * .c file, payload .cpp file, both OK.                               *
 *                                                                    *
 * Public API:                                                        *
 *   size_t latex_to_unicode(const char *src, size_t src_len,         *
 *                           char *dst, size_t dst_cap);              *
 * ================================================================== */
#ifndef SVCLDB_LATEX_CONVERT_H
#define SVCLDB_LATEX_CONVERT_H

#include <stddef.h>
#include <string.h>
#include <stdio.h>

#ifdef _MSC_VER
#  define SVCLDB_LTX_SNPRINTF _snprintf
#else
#  define SVCLDB_LTX_SNPRINTF snprintf
#endif

/* NB: no `extern "C"` wrapper -- every symbol below has file-scope `static`
 * linkage which is unaffected by name mangling. Wrapping in `extern "C"`
 * would conflict with C++'s treatment of `static`-linkage function decls
 * in the including .cpp. */
/* ── LaTeX-to-Unicode simplifier ─────────────────────────────────
 *
 * Renders LaTeX-style math as readable Unicode text. The overlay
 * doesn't have a full math typesetter -- it's a lightweight ImGui
 * pane -- so we convert common LaTeX commands to Unicode equivalents
 * at RENDER TIME. The chat_msg text still holds the ORIGINAL LaTeX
 * so copy hotkeys give you raw LaTeX (paste into Overleaf / ChatGPT /
 * paper); DISPLAY gets the readable Unicode form.
 *
 * Coverage:
 *   Delimiters:  $..$  \(..\)   -> stripped, content inline
 *   Fractions:   \frac{a}{b}    -> (a)/(b) if either side has ops, else a/b
 *   Roots:       \sqrt{x}       -> √(x) if x has ops, else √x
 *   Superscript: ^2/^3/^n       -> ² ³ n (Unicode 2-3, keep n as-is)
 *                ^{...}         -> keep ^ + strip braces
 *   Subscript:   _{...}         -> strip braces (keep as _content)
 *   Symbols:     \pi \Delta \int \sum etc -> π Δ ∫ Σ ...
 *   Relations:   \leq \geq \neq \pm etc -> ≤ ≥ ≠ ± ...
 *   Functions:   \log \ln \sin \cos etc -> log ln sin cos (drop \)
 *   Arrows:      \to \rightarrow etc -> -> <- ⇒ ⇐ ↔
 *
 * NOT converted (kept as-is because they're structural or too rare):
 *   \begin{...} \end{...}  \left \right   \\ (newline)   \text{...}
 *
 * Applies to PROSE and DISPLAY MATH BLOCKS. Does NOT apply to
 * fenced code blocks (Python could have `$` in strings).
 *
 * Returns bytes written to `dst`. `dst` must have room for AT LEAST
 * `src_len + 32` bytes as a safety margin (most conversions are
 * shorter than the source; some like \pi -> π are same or shorter
 * length in UTF-8). */
struct latex_map_entry {
    const char *tex;
    const char *uni;
};

/* Ordered by longest-match-first so `\Rightarrow` matches before
 * `\rightarrow` etc. All entries START with backslash.
 *
 * IMPORTANT ORDERING RULE: LONGER commands must come BEFORE any
 * command they share a prefix with. E.g. `\arcsin` before `\sin`,
 * `\Longrightarrow` before `\Rightarrow`, `\varepsilon` before
 * `\epsilon`, `\iiint` before `\iint` before `\int`. The
 * latex_match_at walker uses first-match wins + word-boundary check
 * (next char must not be alpha), so a shorter command CAN be
 * ambiguously matched at the start of a longer one if entries are
 * out of order. Verified 2026-07-05: `\int` before `\infty` would
 * make `\infty` never match. */
static const struct latex_map_entry LATEX_MAP[] = {
    /* ── Sizing / spacing (all EMPTY -- they don't render literally) ──
     * These control delimiter size, style, or whitespace in real LaTeX;
     * in plain-text render they're pure noise and get dropped. */
    { "\\Biggl",              ""    },
    { "\\Biggr",              ""    },
    { "\\biggl",              ""    },
    { "\\biggr",              ""    },
    { "\\Bigl",               ""    },
    { "\\Bigr",               ""    },
    { "\\bigl",               ""    },
    { "\\bigr",               ""    },
    { "\\Bigg",               ""    },
    { "\\bigg",               ""    },
    { "\\Big",                ""    },
    { "\\big",                ""    },
    { "\\left",               ""    },
    { "\\right",              ""    },
    { "\\middle",             ""    },
    { "\\displaystyle",       ""    },
    { "\\textstyle",          ""    },
    { "\\scriptscriptstyle",  ""    },
    { "\\scriptstyle",        ""    },
    { "\\limits",             ""    },
    { "\\nolimits",           ""    },
    { "\\smash",              ""    },
    { "\\allowbreak",         ""    },
    { "\\nobreak",            ""    },
    { "\\relax",              ""    },
    { "\\noexpand",           ""    },
    { "\\expandafter",        ""    },
    { "\\!",                  ""    },
    { "\\,",                  ""    },  /* thin space -- collapse */
    { "\\;",                  ""    },
    { "\\:",                  ""    },
    { "\\>",                  ""    },  /* medium space */
    { "\\ ",                  " "   },  /* backslash-space = literal space */
    { "\\quad",               "  "  },
    { "\\qquad",              "    "},
    { "\\thinspace",          " "   },
    { "\\medspace",           " "   },
    { "\\thickspace",         " "   },
    { "\\enspace",            " "   },
    { "\\nobreakspace",       " "   },
    { "\\space",              " "   },
    { "\\negthinspace",       ""    },
    { "\\negmedspace",        ""    },
    { "\\negthickspace",      ""    },
    { "\\newline",            "\n"  },
    /* \\ in display math = newline. Handled specially by the walker
     * (adjacent double-backslash) so a real backslash-in-content
     * (like Windows path in a code fence -- but we don't run this on
     * code) isn't mistranslated. */
    /* ── Escaped punctuation -- LaTeX escapes these to render literally ── */
    { "\\%",          "%"              },
    { "\\$",          "$"              },
    { "\\&",          "&"              },
    { "\\_",          "_"              },
    { "\\#",          "#"              },
    { "\\{",          "{"              },
    { "\\}",          "}"              },
    { "\\|",          "\xE2\x80\x96"   },  /* ‖ (double-vert) */
    { "\\And",        "&"              },
    { "\\gt",         ">"              },
    { "\\lt",         "<"              },
    { "\\KaTeX",      "KaTeX"          },
    { "\\LaTeX",      "LaTeX"          },
    { "\\TeX",        "TeX"            },
    /* ── Function names -- drop the leading backslash so `\log n` renders as `log n`.
     * Multi-char variants (arcsin) come BEFORE their prefix (arc, sin) -- the
     * word-boundary check + longest-match walker rely on this ordering. */
    { "\\arcsin",     "arcsin" },
    { "\\arccos",     "arccos" },
    { "\\arctan",     "arctan" },
    { "\\arcctg",     "arcctg" },   /* Russian/European math notation */
    { "\\arctg",      "arctg"  },
    { "\\argmax",     "argmax" },
    { "\\argmin",     "argmin" },
    { "\\injlim",     "inj lim" },
    { "\\projlim",    "proj lim" },
    { "\\varliminf",  "liminf" },
    { "\\varlimsup",  "limsup" },
    { "\\varinjlim",  "lim" },
    { "\\varprojlim", "lim" },
    { "\\limsup",     "limsup" },
    { "\\liminf",     "liminf" },
    { "\\sinh",       "sinh"},
    { "\\cosh",       "cosh"},
    { "\\tanh",       "tanh"},
    { "\\coth",       "coth"},
    { "\\cosec",      "cosec" },
    { "\\cotg",       "cotg" },
    { "\\log",        "log" },
    { "\\ln",         "ln"  },
    { "\\lg",         "lg"  },
    { "\\exp",        "exp" },
    { "\\sin",        "sin" },
    { "\\cos",        "cos" },
    { "\\tan",        "tan" },
    { "\\ctg",        "ctg" },
    { "\\csc",        "csc" },
    { "\\sec",        "sec" },
    { "\\cot",        "cot" },
    { "\\cth",        "cth" },
    { "\\sh",         "sh"  },
    { "\\ch",         "ch"  },
    { "\\th",         "th"  },
    { "\\tg",         "tg"  },
    { "\\plim",       "plim" },
    { "\\lim",        "lim" },
    { "\\max",        "max" },
    { "\\min",        "min" },
    { "\\sup",        "sup" },
    { "\\inf",        "inf" },
    { "\\arg",        "arg" },
    { "\\deg",        "deg" },
    { "\\det",        "det" },
    { "\\dim",        "dim" },
    { "\\ker",        "ker" },
    { "\\gcd",        "gcd" },
    { "\\lcm",        "lcm" },
    { "\\mod",        "mod" },
    { "\\bmod",       "mod" },
    /* \pmod{X} gets special handling below (needs parens: `(mod X)`).
     * The bare `\pmod` mapping is a fallback if the special handler
     * doesn't fire (no `{` follows). */
    { "\\pmod",       "mod" },
    { "\\Pr",         "Pr" },
    { "\\hom",        "hom" },
    /* ── Arrows (multi-char first). Ordering rule: longest command
     * NAME must come first (\longrightarrow before \rightarrow, etc)
     * OR entries beginning with the same char must be sorted longest
     * first so word-boundary check picks the intended one. ── */
    { "\\Longleftrightarrow", "\xE2\x87\x94" },   /* ⇔ */
    { "\\longleftrightarrow", "\xE2\x86\x94" },   /* ↔ */
    { "\\nLeftrightarrow",    "\xE2\x87\x8E" },   /* ⇎ */
    { "\\nleftrightarrow",    "\xE2\x86\xAE" },   /* ↮ */
    { "\\Leftrightarrow",     "\xE2\x87\x94" },   /* ⇔ */
    { "\\leftrightarrow",     "\xE2\x86\x94" },   /* ↔ */
    { "\\leftrightarrows",    "\xE2\x87\x86" },   /* ⇆ */
    { "\\leftrightharpoons",  "\xE2\x87\x8B" },   /* ⇋ */
    { "\\Longrightarrow",     "\xE2\x87\x92" },   /* ⇒ */
    { "\\Longleftarrow",      "\xE2\x87\x90" },   /* ⇐ */
    { "\\nRightarrow",        "\xE2\x87\x8F" },   /* ⇏ */
    { "\\nLeftarrow",         "\xE2\x87\x8D" },   /* ⇍ */
    { "\\Rightarrow",         "\xE2\x87\x92" },   /* ⇒ */
    { "\\Leftarrow",          "\xE2\x87\x90" },   /* ⇐ */
    { "\\longrightarrow",     "\xE2\x9F\xB6" },   /* ⟶ */
    { "\\longleftarrow",      "\xE2\x9F\xB5" },   /* ⟵ */
    { "\\longmapsto",         "\xE2\x9F\xBC" },   /* ⟼ */
    { "\\rightsquigarrow",    "\xE2\x87\x9D" },   /* ⇝ */
    { "\\leftsquigarrow",     "\xE2\x86\x9C" },   /* ↜ */
    { "\\leadsto",            "\xE2\x87\x9D" },   /* ⇝ */
    { "\\twoheadrightarrow",  "\xE2\x86\xA0" },   /* ↠ */
    { "\\twoheadleftarrow",   "\xE2\x86\x9E" },   /* ↞ */
    { "\\rightarrowtail",     "\xE2\x86\xA3" },   /* ↣ */
    { "\\leftarrowtail",      "\xE2\x86\xA2" },   /* ↢ */
    { "\\rightleftharpoons",  "\xE2\x87\x8C" },   /* ⇌ */
    { "\\rightleftarrows",    "\xE2\x87\x84" },   /* ⇄ */
    { "\\leftleftarrows",     "\xE2\x87\x87" },   /* ⇇ */
    { "\\rightrightarrows",   "\xE2\x87\x89" },   /* ⇉ */
    { "\\upuparrows",         "\xE2\x87\x88" },   /* ⇈ */
    { "\\downdownarrows",     "\xE2\x87\x8A" },   /* ⇊ */
    { "\\dashleftarrow",      "\xE2\x87\xA0" },   /* ⇠ */
    { "\\dashrightarrow",     "\xE2\x87\xA2" },   /* ⇢ */
    { "\\Rrightarrow",        "\xE2\x87\x9B" },   /* ⇛ */
    { "\\Lleftarrow",         "\xE2\x87\x9A" },   /* ⇚ */
    { "\\circlearrowright",   "\xE2\x86\xBB" },   /* ↻ */
    { "\\circlearrowleft",    "\xE2\x86\xBA" },   /* ↺ */
    { "\\curvearrowright",    "\xE2\x86\xB7" },   /* ↷ */
    { "\\curvearrowleft",     "\xE2\x86\xB6" },   /* ↶ */
    { "\\leftharpoondown",    "\xE2\x86\xBD" },   /* ↽ */
    { "\\leftharpoonup",      "\xE2\x86\xBC" },   /* ↼ */
    { "\\rightharpoondown",   "\xE2\x87\x81" },   /* ⇁ */
    { "\\rightharpoonup",     "\xE2\x87\x80" },   /* ⇀ */
    { "\\upharpoonright",     "\xE2\x86\xBE" },   /* ↾ */
    { "\\upharpoonleft",      "\xE2\x86\xBF" },   /* ↿ */
    { "\\downharpoonright",   "\xE2\x87\x82" },   /* ⇂ */
    { "\\downharpoonleft",    "\xE2\x87\x83" },   /* ⇃ */
    { "\\restriction",        "\xE2\x86\xBE" },   /* ↾ */
    { "\\rightarrow",         "\xE2\x86\x92" },   /* -> */
    { "\\leftarrow",          "\xE2\x86\x90" },   /* <- */
    { "\\nrightarrow",        "\xE2\x86\x9B" },   /* ↛ */
    { "\\nleftarrow",         "\xE2\x86\x9A" },   /* ↚ */
    { "\\Uparrow",            "\xE2\x87\x91" },   /* ⇑ */
    { "\\Downarrow",          "\xE2\x87\x93" },   /* ⇓ */
    { "\\Updownarrow",        "\xE2\x87\x95" },   /* ⇕ */
    { "\\uparrow",            "\xE2\x86\x91" },   /* ↑ */
    { "\\downarrow",          "\xE2\x86\x93" },   /* ↓ */
    { "\\updownarrow",        "\xE2\x86\x95" },   /* ↕ */
    { "\\hookrightarrow",     "\xE2\x86\xAA" },   /* ↪ */
    { "\\hookleftarrow",      "\xE2\x86\xA9" },   /* ↩ */
    { "\\nearrow",            "\xE2\x86\x97" },   /* ↗ */
    { "\\searrow",            "\xE2\x86\x98" },   /* ↘ */
    { "\\nwarrow",            "\xE2\x86\x96" },   /* ↖ */
    { "\\swarrow",            "\xE2\x86\x99" },   /* ↙ */
    { "\\Lsh",                "\xE2\x86\xB0" },   /* ↰ */
    { "\\Rsh",                "\xE2\x86\xB1" },   /* ↱ */
    { "\\mapsto",             "\xE2\x86\xA6" },   /* ↦ */
    { "\\to",                 "\xE2\x86\x92" },   /* -> */
    { "\\gets",               "\xE2\x86\x90" },   /* <- */
    /* Short-form arrow aliases per KaTeX (\Darr, \Uarr, etc.). */
    { "\\Harr",               "\xE2\x87\x94" },   /* ⇔ */
    { "\\hArr",               "\xE2\x87\x94" },   /* ⇔ */
    { "\\harr",               "\xE2\x86\x94" },   /* ↔ */
    { "\\Larr",               "\xE2\x87\x90" },   /* ⇐ */
    { "\\lArr",               "\xE2\x87\x90" },   /* ⇐ */
    { "\\larr",               "\xE2\x86\x90" },   /* <- */
    { "\\Rarr",               "\xE2\x87\x92" },   /* ⇒ */
    { "\\rArr",               "\xE2\x87\x92" },   /* ⇒ */
    { "\\rarr",               "\xE2\x86\x92" },   /* -> */
    { "\\Uarr",               "\xE2\x87\x91" },   /* ⇑ */
    { "\\uArr",               "\xE2\x87\x91" },   /* ⇑ */
    { "\\uarr",               "\xE2\x86\x91" },   /* ↑ */
    { "\\Darr",               "\xE2\x87\x93" },   /* ⇓ */
    { "\\dArr",               "\xE2\x87\x93" },   /* ⇓ */
    { "\\darr",               "\xE2\x86\x93" },   /* ↓ */
    { "\\Lrarr",              "\xE2\x87\x94" },   /* ⇔ */
    { "\\lrArr",              "\xE2\x87\x94" },   /* ⇔ */
    { "\\lrarr",              "\xE2\x86\x94" },   /* ↔ */
    { "\\impliedby",          "\xE2\x87\x90" },   /* ⇐ */
    /* ── Relations. Multi-char forms must come BEFORE their prefixes
     * (\approxeq before \approx, \simeq before \sim, \succcurlyeq
     * before \succeq before \succ, etc). Negations use the boundary
     * check to distinguish \nleq from \ncong from \not (also handled
     * as prefix specially below). ── */
    /* Approximation / equivalence */
    { "\\approxeq",       "\xE2\x89\x8A" },   /* ≊ */
    { "\\approx",         "\xE2\x89\x88" },   /* ≈ */
    { "\\thickapprox",    "\xE2\x89\x88" },   /* ≈ */
    { "\\equiv",          "\xE2\x89\xA1" },   /* ≡ */
    { "\\propto",         "\xE2\x88\x9D" },   /* ∝ */
    { "\\varpropto",      "\xE2\x88\x9D" },   /* ∝ */
    { "\\simeq",          "\xE2\x89\x83" },   /* ≃ */
    { "\\sim",            "\xE2\x88\xBC" },   /* ∼ */
    { "\\thicksim",       "\xE2\x88\xBC" },   /* ∼ */
    { "\\backsim",        "\xE2\x88\xBD" },   /* ∽ */
    { "\\backsimeq",      "\xE2\x8B\x8D" },   /* ⋍ */
    { "\\backprime",      "\xE2\x80\xB5" },   /* ‵ */
    { "\\backepsilon",    "\xE2\x88\x8D" },   /* ∍ */
    { "\\cong",           "\xE2\x89\x85" },   /* ≅ */
    { "\\ncong",          "\xE2\x89\x86" },   /* ≆ */
    { "\\nsim",           "\xE2\x89\x81" },   /* ≁ */
    { "\\doteq",          "\xE2\x89\x90" },   /* ≐ */
    { "\\doteqdot",       "\xE2\x89\x91" },   /* ≑ */
    { "\\Doteq",          "\xE2\x89\x91" },   /* ≑ */
    { "\\eqcirc",         "\xE2\x89\x96" },   /* ≖ */
    { "\\circeq",         "\xE2\x89\x97" },   /* ≗ */
    { "\\risingdotseq",   "\xE2\x89\x93" },   /* ≓ */
    { "\\fallingdotseq",  "\xE2\x89\x92" },   /* ≒ */
    { "\\bumpeq",         "\xE2\x89\x8F" },   /* ≏ */
    { "\\Bumpeq",         "\xE2\x89\x8E" },   /* ≎ */
    { "\\triangleq",      "\xE2\x89\x9C" },   /* ≜ */
    { "\\eqsim",          "\xE2\x89\x82" },   /* ≂ */
    /* Ordering */
    { "\\leqslant",       "\xE2\xA9\xBD" },   /* ⩽ */
    { "\\geqslant",       "\xE2\xA9\xBE" },   /* ⩾ */
    { "\\leqq",           "\xE2\x89\xA6" },   /* ≦ */
    { "\\geqq",           "\xE2\x89\xA7" },   /* ≧ */
    { "\\lneqq",          "\xE2\x89\xA8" },   /* ≨ */
    { "\\gneqq",          "\xE2\x89\xA9" },   /* ≩ */
    { "\\lvertneqq",      "\xE2\x89\xA8" },   /* ≨ */
    { "\\gvertneqq",      "\xE2\x89\xA9" },   /* ≩ */
    { "\\lneq",           "\xE2\xAA\x87" },   /* ⪇ */
    { "\\gneq",           "\xE2\xAA\x88" },   /* ⪈ */
    { "\\lnapprox",       "\xE2\xAA\x89" },   /* ⪉ */
    { "\\gnapprox",       "\xE2\xAA\x8A" },   /* ⪊ */
    { "\\lnsim",          "\xE2\x8B\xA6" },   /* ⋦ */
    { "\\gnsim",          "\xE2\x8B\xA7" },   /* ⋧ */
    { "\\leq",            "\xE2\x89\xA4" },   /* ≤ */
    { "\\geq",            "\xE2\x89\xA5" },   /* ≥ */
    { "\\le",             "\xE2\x89\xA4" },   /* ≤ */
    { "\\ge",             "\xE2\x89\xA5" },   /* ≥ */
    { "\\nleq",           "\xE2\x89\xB0" },   /* ≰ */
    { "\\ngeq",           "\xE2\x89\xB1" },   /* ≱ */
    { "\\nleqq",          "\xE2\x89\xB0" },   /* ≰ */
    { "\\ngeqq",          "\xE2\x89\xB1" },   /* ≱ */
    { "\\nleqslant",      "\xE2\x89\xB0" },   /* ≰ */
    { "\\ngeqslant",      "\xE2\x89\xB1" },   /* ≱ */
    { "\\nless",          "\xE2\x89\xAE" },   /* ≮ */
    { "\\ngtr",           "\xE2\x89\xAF" },   /* ≯ */
    { "\\lessgtr",        "\xE2\x89\xB6" },   /* ≶ */
    { "\\gtrless",        "\xE2\x89\xB7" },   /* ≷ */
    { "\\lesssim",        "\xE2\x89\xB2" },   /* ≲ */
    { "\\gtrsim",         "\xE2\x89\xB3" },   /* ≳ */
    { "\\lessapprox",     "\xE2\xAA\x85" },   /* ⪅ */
    { "\\gtrapprox",      "\xE2\xAA\x86" },   /* ⪆ */
    { "\\lessdot",        "\xE2\x8B\x96" },   /* ⋖ */
    { "\\gtrdot",         "\xE2\x8B\x97" },   /* ⋗ */
    { "\\lesseqgtr",      "\xE2\x8B\x9A" },   /* ⋚ */
    { "\\gtreqless",      "\xE2\x8B\x9B" },   /* ⋛ */
    { "\\lesseqqgtr",     "\xE2\xAA\x8B" },   /* ⪋ */
    { "\\gtreqqless",     "\xE2\xAA\x8C" },   /* ⪌ */
    { "\\lll",            "\xE2\x8B\x98" },   /* ⋘ */
    { "\\ggg",            "\xE2\x8B\x99" },   /* ⋙ */
    { "\\llless",         "\xE2\x8B\x98" },   /* ⋘ */
    { "\\gggtr",          "\xE2\x8B\x99" },   /* ⋙ */
    { "\\ll",             "\xE2\x89\xAA" },   /* ≪ */
    { "\\gg",             "\xE2\x89\xAB" },   /* ≫ */
    { "\\neq",            "\xE2\x89\xA0" },   /* ≠ */
    { "\\ne",             "\xE2\x89\xA0" },   /* ≠ */
    /* Precedes / succeeds */
    { "\\preccurlyeq",    "\xE2\x89\xBC" },   /* ≼ */
    { "\\succcurlyeq",    "\xE2\x89\xBD" },   /* ≽ */
    { "\\curlyeqprec",    "\xE2\x8B\x9E" },   /* ⋞ */
    { "\\curlyeqsucc",    "\xE2\x8B\x9F" },   /* ⋟ */
    { "\\precapprox",     "\xE2\xAA\xB7" },   /* ⪷ */
    { "\\succapprox",     "\xE2\xAA\xB8" },   /* ⪸ */
    { "\\precnapprox",    "\xE2\xAA\xB9" },   /* ⪹ */
    { "\\succnapprox",    "\xE2\xAA\xBA" },   /* ⪺ */
    { "\\precneqq",       "\xE2\xAA\xB5" },   /* ⪵ */
    { "\\succneqq",       "\xE2\xAA\xB6" },   /* ⪶ */
    { "\\precnsim",       "\xE2\x8B\xA8" },   /* ⋨ */
    { "\\succnsim",       "\xE2\x8B\xA9" },   /* ⋩ */
    { "\\precsim",        "\xE2\x89\xBE" },   /* ≾ */
    { "\\succsim",        "\xE2\x89\xBF" },   /* ≿ */
    { "\\preceq",         "\xE2\xAA\xAF" },   /* ⪯ */
    { "\\succeq",         "\xE2\xAA\xB0" },   /* ⪰ */
    { "\\prec",           "\xE2\x89\xBA" },   /* ≺ */
    { "\\succ",           "\xE2\x89\xBB" },   /* ≻ */
    { "\\nprec",          "\xE2\x8A\x80" },   /* ⊀ */
    { "\\nsucc",          "\xE2\x8A\x81" },   /* ⊁ */
    { "\\npreceq",        "\xE2\x8B\xA0" },   /* ⋠ */
    { "\\nsucceq",        "\xE2\x8B\xA1" },   /* ⋡ */
    /* Turnstile family */
    { "\\vDash",          "\xE2\x8A\xA8" },   /* ⊨ */
    { "\\Vdash",          "\xE2\x8A\xA9" },   /* ⊩ */
    { "\\Vvdash",         "\xE2\x8A\xAA" },   /* ⊪ */
    { "\\vdash",          "\xE2\x8A\xA2" },   /* ⊢ */
    { "\\dashv",          "\xE2\x8A\xA3" },   /* ⊣ */
    { "\\models",         "\xE2\x8A\xA8" },   /* ⊨ */
    { "\\nvdash",         "\xE2\x8A\xAC" },   /* ⊬ */
    { "\\nvDash",         "\xE2\x8A\xAD" },   /* ⊭ */
    { "\\nVdash",         "\xE2\x8A\xAE" },   /* ⊮ */
    { "\\nVDash",         "\xE2\x8A\xAF" },   /* ⊯ */
    /* Other relations */
    { "\\bowtie",         "\xE2\x8B\x88" },   /* ⋈ */
    { "\\Join",           "\xE2\x8B\x88" },   /* ⋈ */
    { "\\asymp",          "\xE2\x89\x8D" },   /* ≍ */
    { "\\smile",          "\xE2\x8C\xA3" },   /* ⌣ */
    { "\\frown",          "\xE2\x8C\xA2" },   /* ⌢ */
    { "\\smallsmile",     "\xE2\x8C\xA3" },   /* ⌣ */
    { "\\smallfrown",     "\xE2\x8C\xA2" },   /* ⌢ */
    { "\\vartriangleleft",  "\xE2\x8A\xB2" },   /* ⊲ */
    { "\\vartriangleright", "\xE2\x8A\xB3" },   /* ⊳ */
    { "\\trianglelefteq",   "\xE2\x8A\xB4" },   /* ⊴ */
    { "\\trianglerighteq",  "\xE2\x8A\xB5" },   /* ⊵ */
    { "\\ntriangleleft",    "\xE2\x8B\xAA" },   /* ⋪ */
    { "\\ntriangleright",   "\xE2\x8B\xAB" },   /* ⋫ */
    { "\\ntrianglelefteq",  "\xE2\x8B\xAC" },   /* ⋬ */
    { "\\ntrianglerighteq", "\xE2\x8B\xAD" },   /* ⋭ */
    { "\\lhd",            "\xE2\x8A\xB2" },   /* ⊲ */
    { "\\rhd",            "\xE2\x8A\xB3" },   /* ⊳ */
    { "\\unlhd",          "\xE2\x8A\xB4" },   /* ⊴ */
    { "\\unrhd",          "\xE2\x8A\xB5" },   /* ⊵ */
    { "\\multimap",       "\xE2\x8A\xB8" },   /* ⊸ */
    { "\\pitchfork",      "\xE2\x8B\x94" },   /* ⋔ */
    { "\\between",        "\xE2\x89\xAC" },   /* ≬ */
    { "\\therefore",      "\xE2\x88\xB4" },   /* ∴ */
    { "\\because",        "\xE2\x88\xB5" },   /* ∵ */
    /* Colon-relations (KaTeX's colon family) */
    { "\\coloneqq",       "\xE2\x89\x94" },   /* ≔ */
    { "\\coloneq",        "\xE2\x89\x94" },   /* ≔ (alias) */
    { "\\colonequals",    "\xE2\x89\x94" },   /* ≔ */
    { "\\eqqcolon",       "\xE2\x89\x95" },   /* ≕ */
    { "\\equalscolon",    "\xE2\x89\x95" },   /* ≕ */
    { "\\dblcolon",       "\xE2\x88\xB7" },   /* ∷ */
    { "\\coloncolon",     "\xE2\x88\xB7" },   /* ∷ */
    { "\\colonapprox",    ":\xE2\x89\x88" },  /* :≈ */
    { "\\colonsim",       ":\xE2\x88\xBC" },  /* :∼ */
    /* ── Binary operators ── */
    { "\\pm",             "\xC2\xB1"     },   /* ± */
    { "\\mp",             "\xE2\x88\x93" },   /* ∓ */
    { "\\plusmn",         "\xC2\xB1"     },   /* ± */
    { "\\times",          "\xC3\x97"     },   /* × */
    { "\\cdot",           "\xC2\xB7"     },   /* · */
    { "\\cdotp",          "\xC2\xB7"     },   /* · (punct) */
    { "\\ldotp",          "."            },   /* . (low dot punct) */
    { "\\sdot",           "\xE2\x8B\x85" },   /* ⋅ */
    { "\\centerdot",      "\xC2\xB7"     },   /* · */
    { "\\div",            "\xC3\xB7"     },   /* ÷ */
    { "\\divideontimes",  "\xE2\x8B\x87" },   /* ⋇ */
    { "\\ast",            "\xE2\x88\x97" },   /* ∗ */
    { "\\star",           "\xE2\x8B\x86" },   /* ⋆ */
    { "\\bullet",         "\xE2\x88\x99" },   /* ∙ */
    { "\\bull",           "\xE2\x88\x99" },   /* ∙ */
    { "\\circ",           "\xE2\x88\x98" },   /* ∘ */
    { "\\oplus",          "\xE2\x8A\x95" },   /* ⊕ */
    { "\\ominus",         "\xE2\x8A\x96" },   /* ⊖ */
    { "\\otimes",         "\xE2\x8A\x97" },   /* ⊗ */
    { "\\oslash",         "\xE2\x8A\x98" },   /* ⊘ */
    { "\\odot",           "\xE2\x8A\x99" },   /* ⊙ */
    { "\\dotplus",        "\xE2\x88\x94" },   /* ∔ */
    { "\\amalg",          "\xE2\xA8\xBF" },   /* ⨿ */
    { "\\uplus",          "\xE2\x8A\x8E" },   /* ⊎ */
    { "\\sqcap",          "\xE2\x8A\x93" },   /* ⊓ */
    { "\\sqcup",          "\xE2\x8A\x94" },   /* ⊔ */
    { "\\ltimes",         "\xE2\x8B\x89" },   /* ⋉ */
    { "\\rtimes",         "\xE2\x8B\x8A" },   /* ⋊ */
    { "\\intercal",       "\xE2\x8A\xBA" },   /* ⊺ */
    { "\\boxplus",        "\xE2\x8A\x9E" },   /* ⊞ */
    { "\\boxminus",       "\xE2\x8A\x9F" },   /* ⊟ */
    { "\\boxtimes",       "\xE2\x8A\xA0" },   /* ⊠ */
    { "\\boxdot",         "\xE2\x8A\xA1" },   /* ⊡ */
    { "\\circledast",     "\xE2\x8A\x9B" },   /* ⊛ */
    { "\\circledcirc",    "\xE2\x8A\x9A" },   /* ⊚ */
    { "\\circleddash",    "\xE2\x8A\x9D" },   /* ⊝ */
    { "\\circledR",       "\xC2\xAE"     },   /* ® */
    { "\\barwedge",       "\xE2\x8A\xBC" },   /* ⊼ */
    { "\\veebar",         "\xE2\x8A\xBB" },   /* ⊻ */
    { "\\doublebarwedge", "\xE2\xA9\x9E" },   /* ⩞ */
    { "\\curlywedge",     "\xE2\x8B\x8F" },   /* ⋏ */
    { "\\curlyvee",       "\xE2\x8B\x8E" },   /* ⋎ */
    { "\\bigoplus",       "\xE2\xA8\x81" },   /* ⨁ */
    { "\\bigotimes",      "\xE2\xA8\x82" },   /* ⨂ */
    { "\\bigodot",        "\xE2\xA8\x80" },   /* ⨀ */
    { "\\bigsqcap",       "\xE2\xA8\x85" },   /* ⨅ */
    { "\\biguplus",       "\xE2\xA8\x84" },   /* ⨄ */
    { "\\wedge",          "\xE2\x88\xA7" },   /* ∧ */
    { "\\vee",            "\xE2\x88\xA8" },   /* ∨ */
    { "\\wr",             "\xE2\x89\x80" },   /* ≀ */
    /* ── Set / logic ── */
    { "\\notin",          "\xE2\x88\x89" },   /* ∉ */
    { "\\notni",          "\xE2\x88\x8C" },   /* ∌ */
    { "\\in",             "\xE2\x88\x88" },   /* ∈ */
    { "\\isin",           "\xE2\x88\x88" },   /* ∈ (alias) */
    { "\\ni",             "\xE2\x88\x8B" },   /* ∋ */
    { "\\owns",           "\xE2\x88\x8B" },   /* ∋ */
    { "\\subseteqq",      "\xE2\xAB\x85" },   /* ⫅ */
    { "\\supseteqq",      "\xE2\xAB\x86" },   /* ⫆ */
    { "\\subseteq",       "\xE2\x8A\x86" },   /* ⊆ */
    { "\\supseteq",       "\xE2\x8A\x87" },   /* ⊇ */
    { "\\nsubseteq",      "\xE2\x8A\x88" },   /* ⊈ */
    { "\\nsupseteq",      "\xE2\x8A\x89" },   /* ⊉ */
    { "\\nsubseteqq",     "\xE2\x8A\x88" },   /* ⊈ */
    { "\\nsupseteqq",     "\xE2\x8A\x89" },   /* ⊉ */
    { "\\subsetneqq",     "\xE2\xAB\x8B" },   /* ⫋ */
    { "\\supsetneqq",     "\xE2\xAB\x8C" },   /* ⫌ */
    { "\\varsubsetneq",   "\xE2\x8A\x8A" },   /* ⊊ */
    { "\\varsupsetneq",   "\xE2\x8A\x8B" },   /* ⊋ */
    { "\\varsubsetneqq",  "\xE2\xAB\x8B" },   /* ⫋ */
    { "\\varsupsetneqq",  "\xE2\xAB\x8C" },   /* ⫌ */
    { "\\subsetneq",      "\xE2\x8A\x8A" },   /* ⊊ */
    { "\\supsetneq",      "\xE2\x8A\x8B" },   /* ⊋ */
    { "\\subset",         "\xE2\x8A\x82" },   /* ⊂ */
    { "\\supset",         "\xE2\x8A\x83" },   /* ⊃ */
    { "\\sub",            "\xE2\x8A\x82" },   /* ⊂ (alias) */
    { "\\sube",           "\xE2\x8A\x86" },   /* ⊆ (alias) */
    { "\\supe",           "\xE2\x8A\x87" },   /* ⊇ (alias) */
    { "\\Subset",         "\xE2\x8B\x90" },   /* ⋐ */
    { "\\Supset",         "\xE2\x8B\x91" },   /* ⋑ */
    { "\\sqsubseteq",     "\xE2\x8A\x91" },   /* ⊑ */
    { "\\sqsupseteq",     "\xE2\x8A\x92" },   /* ⊒ */
    { "\\sqsubset",       "\xE2\x8A\x8F" },   /* ⊏ */
    { "\\sqsupset",       "\xE2\x8A\x90" },   /* ⊐ */
    { "\\setminus",       "\xE2\x88\x96" },   /* ∖ */
    { "\\smallsetminus",  "\xE2\x88\x96" },   /* ∖ */
    { "\\Cup",            "\xE2\x8B\x93" },   /* ⋓ */
    { "\\Cap",            "\xE2\x8B\x92" },   /* ⋒ */
    { "\\doublecup",      "\xE2\x8B\x93" },   /* ⋓ */
    { "\\doublecap",      "\xE2\x8B\x92" },   /* ⋒ */
    { "\\cup",            "\xE2\x88\xAA" },   /* ∪ */
    { "\\cap",            "\xE2\x88\xA9" },   /* ∩ */
    { "\\emptyset",       "\xE2\x88\x85" },   /* ∅ */
    { "\\varnothing",     "\xE2\x88\x85" },   /* ∅ */
    { "\\empty",          "\xE2\x88\x85" },   /* ∅ (deprecated alias) */
    { "\\forall",         "\xE2\x88\x80" },   /* ∀ */
    { "\\exists",         "\xE2\x88\x83" },   /* ∃ */
    { "\\exist",          "\xE2\x88\x83" },   /* ∃ (deprecated alias) */
    { "\\nexists",        "\xE2\x88\x84" },   /* ∄ */
    { "\\complement",     "\xE2\x88\x81" },   /* ∁ */
    { "\\neg",            "\xC2\xAC"     },   /* ¬ */
    { "\\lnot",           "\xC2\xAC"     },   /* ¬ */
    { "\\land",           "\xE2\x88\xA7" },   /* ∧ */
    { "\\lor",            "\xE2\x88\xA8" },   /* ∨ */
    { "\\implies",        "\xE2\x87\x92" },   /* ⇒ */
    { "\\iff",            "\xE2\x87\x94" },   /* ⇔ */
    { "\\top",            "\xE2\x8A\xA4" },   /* ⊤ */
    { "\\bot",            "\xE2\x8A\xA5" },   /* ⊥ */
    /* ── Big operators ── */
    { "\\iiint",      "\xE2\x88\xAD" },   /* ∭ */
    { "\\iint",       "\xE2\x88\xAC" },   /* ∬ */
    { "\\oiiint",     "\xE2\x88\xB0" },   /* ∰ */
    { "\\oiint",      "\xE2\x88\xAF" },   /* ∯ */
    { "\\oint",       "\xE2\x88\xAE" },   /* ∮ */
    { "\\int",        "\xE2\x88\xAB" },   /* ∫ */
    { "\\intop",      "\xE2\x88\xAB" },   /* ∫ */
    { "\\smallint",   "\xE2\x88\xAB" },   /* ∫ */
    { "\\sum",        "\xE2\x88\x91" },   /* ∑ */
    { "\\prod",       "\xE2\x88\x8F" },   /* ∏ */
    { "\\coprod",     "\xE2\x88\x90" },   /* ∐ */
    { "\\bigcup",     "\xE2\x8B\x83" },   /* ⋃ */
    { "\\bigcap",     "\xE2\x8B\x82" },   /* ⋂ */
    { "\\bigsqcup",   "\xE2\xA8\x86" },   /* ⨆ */
    { "\\bigwedge",   "\xE2\x8B\x80" },   /* ⋀ */
    { "\\bigvee",     "\xE2\x8B\x81" },   /* ⋁ */
    /* ── Calculus / analysis ── */
    { "\\partial",    "\xE2\x88\x82" },   /* ∂ */
    { "\\nabla",      "\xE2\x88\x87" },   /* ∇ */
    { "\\infty",      "\xE2\x88\x9E" },   /* ∞ */
    { "\\infin",      "\xE2\x88\x9E" },   /* ∞ (deprecated alias) */
    /* ── Not-mid / not-parallel ── */
    { "\\nmid",           "\xE2\x88\xA4" },   /* ∤ */
    { "\\nparallel",      "\xE2\x88\xA6" },   /* ∦ */
    { "\\nshortmid",      "\xE2\x88\xA4" },   /* ∤ */
    { "\\nshortparallel", "\xE2\x88\xA6" },   /* ∦ */
    { "\\mid",            "\xE2\x88\xA3" },   /* ∣ */
    { "\\shortmid",       "\xE2\x88\xA3" },   /* ∣ */
    { "\\shortparallel",  "\xE2\x88\xA5" },   /* ∥ */
    /* ── Greek variants (MUST come BEFORE their base commands so
     * longest-match wins: \varepsilon before \epsilon, \varkappa
     * before \kappa, \varphi before \phi, etc.) ── */
    { "\\varepsilon", "\xCE\xB5" },       /* ε */
    { "\\varphi",     "\xCF\x95" },       /* ϕ */
    { "\\vartheta",   "\xCF\x91" },       /* ϑ */
    { "\\varsigma",   "\xCF\x82" },       /* ς */
    { "\\varrho",     "\xCF\xB1" },       /* ϱ (U+03F1) */
    { "\\varpi",      "\xCF\x96" },       /* ϖ */
    { "\\varkappa",   "\xCF\xB0" },       /* ϰ (U+03F0) */
    { "\\varDelta",   "\xF0\x9D\x9B\xA5" },  /* 𝛥 U+1D6E5 -- 4-byte UTF-8; falls back if font missing */
    { "\\varGamma",   "\xF0\x9D\x9B\xA4" },  /* 𝛤 */
    { "\\varLambda",  "\xF0\x9D\x9B\xAC" },  /* 𝛬 */
    { "\\varOmega",   "\xF0\x9D\x9B\xBA" },  /* 𝛺 */
    { "\\varPhi",     "\xF0\x9D\x9B\xB7" },  /* 𝛷 */
    { "\\varPi",      "\xF0\x9D\x9B\xB1" },  /* 𝛱 */
    { "\\varPsi",     "\xF0\x9D\x9B\xB9" },  /* 𝛹 */
    { "\\varSigma",   "\xF0\x9D\x9B\xB4" },  /* 𝛴 */
    { "\\varTheta",   "\xF0\x9D\x9B\xA9" },  /* 𝛩 */
    { "\\varUpsilon", "\xF0\x9D\x9B\xB6" },  /* 𝛶 */
    { "\\varXi",      "\xF0\x9D\x9B\xAF" },  /* 𝛯 */
    { "\\digamma",    "\xCF\x9D" },       /* ϝ (U+03DD) */
    { "\\thetasym",   "\xCF\x91" },       /* ϑ (deprecated alias for \vartheta) */
    { "\\alpha",      "\xCE\xB1" },       /* α */
    { "\\beta",       "\xCE\xB2" },       /* β */
    { "\\gamma",      "\xCE\xB3" },       /* γ */
    { "\\delta",      "\xCE\xB4" },       /* δ */
    { "\\epsilon",    "\xCE\xB5" },       /* ε */
    { "\\zeta",       "\xCE\xB6" },       /* ζ */
    { "\\eta",        "\xCE\xB7" },       /* η */
    { "\\theta",      "\xCE\xB8" },       /* θ */
    { "\\iota",       "\xCE\xB9" },       /* ι */
    { "\\kappa",      "\xCE\xBA" },       /* κ */
    { "\\lambda",     "\xCE\xBB" },       /* λ */
    { "\\mu",         "\xCE\xBC" },       /* μ */
    { "\\nu",         "\xCE\xBD" },       /* ν */
    { "\\xi",         "\xCE\xBE" },       /* ξ */
    { "\\omicron",    "\xCE\xBF" },       /* ο */
    { "\\pi",         "\xCF\x80" },       /* π */
    { "\\rho",        "\xCF\x81" },       /* ρ */
    { "\\sigma",      "\xCF\x83" },       /* σ */
    { "\\tau",        "\xCF\x84" },       /* τ */
    { "\\upsilon",    "\xCF\x85" },       /* υ */
    { "\\phi",        "\xCF\x86" },       /* φ */
    { "\\chi",        "\xCF\x87" },       /* χ */
    { "\\psi",        "\xCF\x88" },       /* ψ */
    { "\\omega",      "\xCF\x89" },       /* ω */
    /* ── Greek uppercase ── */
    { "\\Alpha",      "\xCE\x91" },       /* Α */
    { "\\Beta",       "\xCE\x92" },       /* Β */
    { "\\Gamma",      "\xCE\x93" },       /* Γ */
    { "\\Delta",      "\xCE\x94" },       /* Δ */
    { "\\Epsilon",    "\xCE\x95" },       /* Ε */
    { "\\Zeta",       "\xCE\x96" },       /* Ζ */
    { "\\Eta",        "\xCE\x97" },       /* Η */
    { "\\Theta",      "\xCE\x98" },       /* Θ */
    { "\\Iota",       "\xCE\x99" },       /* Ι */
    { "\\Kappa",      "\xCE\x9A" },       /* Κ */
    { "\\Lambda",     "\xCE\x9B" },       /* Λ */
    { "\\Mu",         "\xCE\x9C" },       /* Μ */
    { "\\Nu",         "\xCE\x9D" },       /* Ν */
    { "\\Xi",         "\xCE\x9E" },       /* Ξ */
    { "\\Omicron",    "\xCE\x9F" },       /* Ο */
    { "\\Pi",         "\xCE\xA0" },       /* Π */
    { "\\Rho",        "\xCE\xA1" },       /* Ρ */
    { "\\Sigma",      "\xCE\xA3" },       /* Σ */
    { "\\Tau",        "\xCE\xA4" },       /* Τ */
    { "\\Upsilon",    "\xCE\xA5" },       /* Υ */
    { "\\Phi",        "\xCE\xA6" },       /* Φ */
    { "\\Chi",        "\xCE\xA7" },       /* Χ */
    { "\\Psi",        "\xCE\xA8" },       /* Ψ */
    { "\\Omega",      "\xCE\xA9" },       /* Ω */
    /* ── Geometry / shapes ── */
    { "\\parallel",         "\xE2\x88\xA5" },   /* ∥ */
    { "\\perp",             "\xE2\x8A\xA5" },   /* ⊥ */
    { "\\angle",            "\xE2\x88\xA0" },   /* ∠ */
    { "\\measuredangle",    "\xE2\x88\xA1" },   /* ∡ */
    { "\\sphericalangle",   "\xE2\x88\xA2" },   /* ∢ */
    { "\\triangledown",     "\xE2\x96\xBD" },   /* ▽ */
    { "\\vartriangle",      "\xE2\x96\xB3" },   /* △ */
    { "\\triangle",         "\xE2\x96\xB3" },   /* △ */
    { "\\triangleleft",     "\xE2\x97\x83" },   /* ◃ */
    { "\\triangleright",    "\xE2\x96\xB9" },   /* ▹ */
    { "\\bigtriangleup",    "\xE2\x96\xB3" },   /* △ */
    { "\\bigtriangledown",  "\xE2\x96\xBD" },   /* ▽ */
    { "\\blacktriangle",       "\xE2\x96\xB2" },   /* ▲ */
    { "\\blacktriangledown",   "\xE2\x96\xBC" },   /* ▼ */
    { "\\blacktriangleleft",   "\xE2\x97\x80" },   /* ◀ */
    { "\\blacktriangleright",  "\xE2\x96\xB6" },   /* ▶ */
    { "\\blacksquare",      "\xE2\x96\xA0" },   /* ■ */
    { "\\square",           "\xE2\x96\xA1" },   /* □ */
    { "\\Box",              "\xE2\x96\xA1" },   /* □ */
    { "\\blacklozenge",     "\xE2\xA7\xAB" },   /* ⧫ */
    { "\\lozenge",          "\xE2\x97\x8A" },   /* ◊ */
    { "\\Diamond",          "\xE2\x97\x8A" },   /* ◊ */
    { "\\diamond",          "\xE2\x8B\x84" },   /* ⋄ */
    { "\\bigstar",          "\xE2\x98\x85" },   /* ★ */
    { "\\bigcirc",          "\xE2\x97\xAF" },   /* ◯ */
    { "\\diagup",           "\xE2\x95\xB1" },   /* ╱ */
    { "\\diagdown",         "\xE2\x95\xB2" },   /* ╲ */
    /* ── Delimiters (paired brackets) ── */
    { "\\lceil",            "\xE2\x8C\x88" },   /* ⌈ */
    { "\\rceil",            "\xE2\x8C\x89" },   /* ⌉ */
    { "\\lfloor",           "\xE2\x8C\x8A" },   /* ⌊ */
    { "\\rfloor",           "\xE2\x8C\x8B" },   /* ⌋ */
    { "\\ulcorner",         "\xE2\x8C\x9C" },   /* ⌜ */
    { "\\urcorner",         "\xE2\x8C\x9D" },   /* ⌝ */
    { "\\llcorner",         "\xE2\x8C\x9E" },   /* ⌞ */
    { "\\lrcorner",         "\xE2\x8C\x9F" },   /* ⌟ */
    { "\\langle",           "\xE2\x9F\xA8" },   /* ⟨ */
    { "\\rangle",           "\xE2\x9F\xA9" },   /* ⟩ */
    { "\\lAngle",           "\xE2\x9F\xAA" },   /* ⟪ */
    { "\\rAngle",           "\xE2\x9F\xAB" },   /* ⟫ */
    { "\\lang",             "\xE2\x9F\xA8" },   /* ⟨ (alias) */
    { "\\rang",             "\xE2\x9F\xA9" },   /* ⟩ (alias) */
    { "\\llbracket",        "\xE2\x9F\xA6" },   /* ⟦ */
    { "\\rrbracket",        "\xE2\x9F\xA7" },   /* ⟧ */
    { "\\lBrace",           "\xE2\xA6\x83" },   /* ⦃ */
    { "\\rBrace",           "\xE2\xA6\x84" },   /* ⦄ */
    { "\\lbrace",           "{"              }, /* { */
    { "\\rbrace",           "}"              }, /* } */
    { "\\lbrack",           "["              }, /* [ */
    { "\\rbrack",           "]"              }, /* ] */
    { "\\lparen",           "("              }, /* ( */
    { "\\rparen",           ")"              }, /* ) */
    { "\\lgroup",           "\xE2\x9F\xAE" },   /* ⟮ */
    { "\\rgroup",           "\xE2\x9F\xAF" },   /* ⟯ */
    { "\\lmoustache",       "\xE2\x8E\xB0" },   /* ⎰ */
    { "\\rmoustache",       "\xE2\x8E\xB1" },   /* ⎱ */
    { "\\backslash",        "\\"             }, /* \ */
    { "\\vert",             "|"              }, /* | */
    { "\\lvert",            "|"              }, /* | */
    { "\\rvert",            "|"              }, /* | */
    { "\\Vert",             "\xE2\x80\x96" },   /* ‖ */
    { "\\lVert",            "\xE2\x80\x96" },   /* ‖ */
    { "\\rVert",            "\xE2\x80\x96" },   /* ‖ */
    /* ── Ellipses (all forms -- KaTeX has 6 variants) ── */
    { "\\dotsb",            "\xE2\x8B\xAF" },   /* ⋯ (bin/rel context) */
    { "\\dotsc",            "\xE2\x80\xA6" },   /* ... (comma context) */
    { "\\dotsi",            "\xE2\x8B\xAF" },   /* ⋯ (integral context) */
    { "\\dotsm",            "\xE2\x8B\xAF" },   /* ⋯ (multiplication) */
    { "\\dotso",            "\xE2\x80\xA6" },   /* ... (other) */
    { "\\dots",             "\xE2\x80\xA6" },   /* ... */
    { "\\ldots",            "\xE2\x80\xA6" },   /* ... */
    { "\\cdots",            "\xE2\x8B\xAF" },   /* ⋯ */
    { "\\vdots",            "\xE2\x8B\xAE" },   /* ⋮ */
    { "\\ddots",            "\xE2\x8B\xB1" },   /* ⋱ */
    { "\\mathellipsis",     "\xE2\x80\xA6" },   /* ... */
    /* ── Number sets (blackboard bold) -- single-letter shortcuts +
     * long names. \mathbb{R} is handled by the text-wrapper fallback
     * which drops the wrapper and keeps 'R' -- so `\mathbb{R}` renders
     * as literal 'R'. These single-letter shortcuts render as the
     * actual double-struck Unicode which looks much nicer. ── */
    { "\\R",                "\xE2\x84\x9D" },   /* ℝ */
    { "\\N",                "\xE2\x84\x95" },   /* ℕ */
    { "\\Z",                "\xE2\x84\xA4" },   /* ℤ */
    { "\\Q",                "\xE2\x84\x9A" },   /* ℚ */
    { "\\C",                "\xE2\x84\x82" },   /* ℂ */
    { "\\H",                "\xE2\x84\x8D" },   /* ℍ */
    { "\\Reals",            "\xE2\x84\x9D" },   /* ℝ */
    { "\\reals",            "\xE2\x84\x9D" },   /* ℝ */
    { "\\Complex",          "\xE2\x84\x82" },   /* ℂ */
    { "\\cnums",            "\xE2\x84\x82" },   /* ℂ */
    { "\\natnums",          "\xE2\x84\x95" },   /* ℕ */
    { "\\Rationals",        "\xE2\x84\x9A" },   /* ℚ */
    { "\\Integers",         "\xE2\x84\xA4" },   /* ℤ */
    /* ── Misc scalars / constants ── */
    { "\\degree",           "\xC2\xB0" },       /* ° */
    { "\\textdegree",       "\xC2\xB0" },       /* ° */
    { "\\prime",            "\xE2\x80\xB2" },   /* ' */
    { "\\hbar",             "\xC4\xA7" },       /* ħ */
    { "\\hslash",           "\xE2\x84\x8F" },   /* ℏ */
    { "\\ell",              "\xE2\x84\x93" },   /* ℓ */
    { "\\Re",               "\xE2\x84\x9C" },   /* ℜ */
    { "\\Im",               "\xE2\x84\x91" },   /* ℑ */
    { "\\real",             "\xE2\x84\x9C" },   /* ℜ */
    { "\\image",            "\xE2\x84\x91" },   /* ℑ */
    { "\\aleph",            "\xE2\x84\xB5" },   /* ℵ */
    { "\\alef",             "\xE2\x84\xB5" },   /* ℵ (alias) */
    { "\\alefsym",          "\xE2\x84\xB5" },   /* ℵ (alias) */
    { "\\beth",             "\xE2\x84\xB6" },   /* ℶ */
    { "\\gimel",            "\xE2\x84\xB7" },   /* ℷ */
    { "\\daleth",           "\xE2\x84\xB8" },   /* ℸ */
    { "\\imath",            "\xC4\xB1" },       /* ı */
    { "\\jmath",            "\xC8\xB7" },       /* ȷ */
    { "\\wp",               "\xE2\x84\x98" },   /* ℘ */
    { "\\weierp",           "\xE2\x84\x98" },   /* ℘ */
    { "\\Finv",             "\xE2\x84\xB2" },   /* Ⅎ */
    { "\\Game",             "\xE2\x85\x81" },   /* ⅁ */
    { "\\Bbbk",             "\xF0\x9D\x95\x9C" }, /* 𝕜 (4-byte UTF-8) */
    { "\\eth",              "\xC3\xB0" },       /* ð */
    { "\\matheth",          "\xC3\xB0" },       /* ð */
    { "\\mho",              "\xE2\x84\xA7" },   /* ℧ */
    /* Card suits + music */
    { "\\clubsuit",         "\xE2\x99\xA3" },   /* ♣ */
    { "\\diamondsuit",      "\xE2\x99\xA2" },   /* ♢ */
    { "\\heartsuit",        "\xE2\x99\xA1" },   /* ♡ */
    { "\\spadesuit",        "\xE2\x99\xA0" },   /* ♠ */
    { "\\clubs",            "\xE2\x99\xA3" },   /* ♣ */
    { "\\diams",            "\xE2\x99\xA2" },   /* ♢ */
    { "\\diamonds",         "\xE2\x99\xA2" },   /* ♢ */
    { "\\hearts",           "\xE2\x99\xA1" },   /* ♡ */
    { "\\spades",           "\xE2\x99\xA0" },   /* ♠ */
    { "\\flat",             "\xE2\x99\xAD" },   /* ♭ */
    { "\\sharp",            "\xE2\x99\xAF" },   /* ♯ */
    { "\\natural",          "\xE2\x99\xAE" },   /* ♮ */
    /* Currency */
    { "\\pounds",           "\xC2\xA3" },       /* £ */
    { "\\mathsterling",     "\xC2\xA3" },       /* £ */
    { "\\textsterling",     "\xC2\xA3" },       /* £ */
    { "\\yen",              "\xC2\xA5" },       /* ¥ */
    { "\\euro",             "\xE2\x82\xAC" },   /* € */
    { "\\textdollar",       "$"              }, /* $ */
    /* Punctuation / dingbats */
    { "\\checkmark",        "\xE2\x9C\x93" },   /* ✓ */
    { "\\maltese",          "\xE2\x9C\xA0" },   /* ✠ */
    { "\\dagger",           "\xE2\x80\xA0" },   /* † */
    { "\\dag",              "\xE2\x80\xA0" },   /* † */
    { "\\ddagger",          "\xE2\x80\xA1" },   /* ‡ */
    { "\\ddag",             "\xE2\x80\xA1" },   /* ‡ */
    { "\\S",                "\xC2\xA7" },       /* § */
    { "\\sect",             "\xC2\xA7" },       /* § */
    { "\\P",                "\xC2\xB6" },       /* ¶ */
    { "\\copyright",        "\xC2\xA9" },       /* © */
    { "\\textregistered",   "\xC2\xAE" },       /* ® */
    { "\\textcircledP",     "\xE2\x84\x97" },   /* ℗ */
    { "\\smiley",           "\xE2\x98\xBA" },   /* ☺ */
    { NULL, NULL }
};

/* Text-wrapping commands: `\text{...}`, `\mathbf{...}`, `\mathrm{...}`,
 * etc. all just wrap their content for typography. In plain-text render
 * we emit the CONTENT unchanged (recursively converted so nested
 * commands still work). Listed here for O(N) linear check per unknown
 * `\word{...}` occurrence.
 *
 * IMPORTANT: entries must match with WORD-BOUNDARY semantics -- i.e.
 * `\mathbf` followed by `{` matches, but `\mathbfriend` doesn't. */
static const char *LATEX_TEXT_WRAPPERS[] = {
    /* Text/math font-style wrappers -- drop the command, keep the content. */
    "text", "textbf", "textit", "textrm", "textsf", "texttt",
    "textnormal", "textup", "textsl", "textsc", "textmd", "textbrace",
    "mathbf", "mathrm", "mathbb", "mathcal", "mathfrak", "mathit",
    "mathsf", "mathtt", "mathnormal", "mathring", "mathord", "mathop",
    "mathopen", "mathclose", "mathpunct", "mathrel", "mathbin",
    "mathstrut", "mathchoice", "mathinner", "mathscr",
    "boldsymbol", "bm", "pmb", "bf", "rm", "it", "sf", "tt", "sc", "sl",
    "cal", "frak", "scr", "Bbb", "bold",
    "operatorname", "operatorname*", "operatornamewithlimits",
    "emph", "underline", "underbar",
    /* Common package extras we can safely pass through by extracting content. */
    "mbox", "hbox", "phantom", "vphantom", "hphantom",
    "color", "textcolor", "colorbox", "fcolorbox",
    "small", "large", "Large", "LARGE", "Huge", "huge",
    "tiny", "footnotesize", "normalsize", "scriptsize", "sixptsize",
    "smash",
    /* Overbrace/underbrace: drop the brace, keep content. Any `^{label}`
     * or `_{label}` that follows is handled by normal sub/sup processing
     * so `\overbrace{a+b+c}^{sum}` renders as `a+b+cˢᵘᵐ`. */
    "overbrace", "underbrace",
    "overbracket", "underbracket", "overgroup", "undergroup",
    /* Substack: multi-line subscript. Content includes `\\` which we
     * convert to `\n` -- inside a `_{}` context the multi-byte result
     * won't map to Unicode subscript so falls back to `_{...}` literal
     * form, which shows the multi-line content readably. */
    "substack",
    /* Cancel commands: drop the strikethrough, keep the cancelled value.
     * In a text render, showing the raw value is more informative than
     * hiding it (which is what real strikethrough would do in TeX). */
    "cancel", "bcancel", "xcancel", "sout", "cancelto",
    /* Frame / box wrappers -- the box art doesn't survive text mode. */
    "boxed", "fbox",
    /* Enclose / phase / raisebox -- extract inner text only. */
    "enclose", "phase", "raisebox",
    /* Row/column tags in equation envs -- usually invisible; content stays. */
    "tag", "notag", "label", "nonumber",
    /* URL wrapper -- `\url{URL}` -- best-effort: show URL as text. */
    "url",
    /* Character formatting that doesn't affect rendering. */
    "widecheck",
    NULL
};

/* Accent commands -- emit inner content + Unicode combining mark
 * appended AFTER each character. E.g. `\vec{v}` -> `v⃗` (v + U+20D7). */
struct latex_accent_entry {
    const char *cmd;      /* command name (no backslash) */
    const char *combining; /* UTF-8 combining mark (usually 2-3 bytes) */
};
static const struct latex_accent_entry LATEX_ACCENTS[] = {
    { "vec",              "\xE2\x83\x97" },   /* ⃗ combining right arrow above (U+20D7) */
    { "overrightarrow",   "\xE2\x83\x97" },
    { "underrightarrow",  "\xE2\x83\x97" },   /* combining right arrow below not in BMP, use above as approx */
    { "overleftarrow",    "\xE2\x83\x96" },   /* ⃖ combining left arrow (U+20D6) */
    { "underleftarrow",   "\xE2\x83\x96" },
    { "Overrightarrow",   "\xE2\x83\x9C" },   /* ⃜ (approx double-arrow -- combining) -- actually use ⇒ approach */
    { "overleftrightarrow","\xE2\x83\x94" },  /* combining left-right arrow (U+20D4 or similar); we use ↔-style */
    { "underleftrightarrow","\xE2\x83\x94" },
    { "overrightharpoon", "\xE2\x83\x91" },   /* ⃑ combining right harpoon (U+20D1) */
    { "overleftharpoon",  "\xE2\x83\x90" },   /* ⃐ combining left harpoon (U+20D0) */
    { "hat",              "\xCC\x82" },       /* ̂ combining circumflex (U+0302) */
    { "widehat",          "\xCC\x82" },
    { "tilde",            "\xCC\x83" },       /* ̃ combining tilde (U+0303) */
    { "widetilde",        "\xCC\x83" },
    { "utilde",           "\xCC\xB0" },       /* ̰ combining tilde below (U+0330) */
    { "bar",              "\xCC\x84" },       /* ̄ combining macron (U+0304) */
    { "overline",         "\xCC\x84" },
    { "underline",        "\xCC\xB2" },       /* ̲ combining low line (U+0332) */
    { "underbar",         "\xCC\xB2" },
    { "dot",              "\xCC\x87" },       /* ̇ combining dot above (U+0307) */
    { "ddot",             "\xCC\x88" },       /* ̈ combining diaeresis (U+0308) */
    { "dddot",            "\xE2\x83\x9B" },   /* ⃛ combining three dots above (U+20DB) */
    { "ddddot",           "\xE2\x83\x9C" },   /* ⃜ combining four dots above (U+20DC) */
    { "check",            "\xCC\x8C" },       /* ̌ combining caron (U+030C) */
    { "acute",            "\xCC\x81" },       /* ́ combining acute (U+0301) */
    { "grave",            "\xCC\x80" },       /* ̀ combining grave (U+0300) */
    { "breve",            "\xCC\x86" },       /* ̆ combining breve (U+0306) */
    { "mathring",         "\xCC\x8A" },       /* ̊ combining ring above (U+030A) */
    { NULL, NULL }
};

/* Superscript digit lookup for ^0..^9 -> Unicode superscript. */
static const char *SUP_DIGITS[10] = {
    "\xE2\x81\xB0", "\xC2\xB9",     "\xC2\xB2",     "\xC2\xB3",
    "\xE2\x81\xB4", "\xE2\x81\xB5", "\xE2\x81\xB6", "\xE2\x81\xB7",
    "\xE2\x81\xB8", "\xE2\x81\xB9"
};
/* Subscript digit lookup for _0.._9 -> Unicode subscript. */
static const char *SUB_DIGITS[10] = {
    "\xE2\x82\x80", "\xE2\x82\x81", "\xE2\x82\x82", "\xE2\x82\x83",
    "\xE2\x82\x84", "\xE2\x82\x85", "\xE2\x82\x86", "\xE2\x82\x87",
    "\xE2\x82\x88", "\xE2\x82\x89"
};

/* Match a LaTeX command at src[pos]. Returns entry index or -1.
 * Uses longest-match -- we walk the table in order and pick the first
 * where the source starts with entry->tex AND the char after
 * entry->tex is NOT an ASCII letter (so `\pi` doesn't match `\pion`). */
static int latex_match_at(const char *src, size_t src_len, size_t pos) {
    for (int i = 0; LATEX_MAP[i].tex; i++) {
        size_t tlen = strlen(LATEX_MAP[i].tex);
        if (pos + tlen > src_len) continue;
        if (memcmp(src + pos, LATEX_MAP[i].tex, tlen) != 0) continue;
        /* Boundary check: next char must not be [a-zA-Z] so we don't
         * partial-match longer commands. `\pi` is fine before space
         * or digit or `\`, but not before `on` (which would make it
         * `\pion` -- not a real command but we shouldn't confuse).
         *
         * EXCEPTION: entries whose command name ENDS in a non-alpha
         * (like `\!`, `\,`, `\;`, `\ `, `\%`, `\{`) are self-
         * terminating and skip this check entirely. */
        const char *tex_end = LATEX_MAP[i].tex + tlen - 1;
        char last_cmd_char = *tex_end;
        int is_alpha_cmd = (last_cmd_char >= 'a' && last_cmd_char <= 'z') ||
                           (last_cmd_char >= 'A' && last_cmd_char <= 'Z');
        if (is_alpha_cmd && pos + tlen < src_len) {
            char nx = src[pos + tlen];
            if ((nx >= 'a' && nx <= 'z') || (nx >= 'A' && nx <= 'Z')) continue;
        }
        return i;
    }
    return -1;
}

/* If src at pos starts with `\<word>` where <word> is one of the
 * text-wrapping commands (LATEX_TEXT_WRAPPERS) AND is followed by `{`,
 * returns the wrapper name length (word length + 1 for backslash).
 * Otherwise 0.
 *
 * E.g. for `\text{foo}` at pos=0, returns 5 (length of `\text`).
 * The caller then extracts the `{...}` argument, recursively converts,
 * and emits the inner content. */
static size_t latex_wrapper_at(const char *src, size_t src_len, size_t pos) {
    if (pos >= src_len || src[pos] != '\\') return 0;
    /* Extract command word after backslash. */
    size_t start = pos + 1;
    size_t end = start;
    while (end < src_len &&
           ((src[end] >= 'a' && src[end] <= 'z') ||
            (src[end] >= 'A' && src[end] <= 'Z'))) end++;
    if (end == start) return 0;
    size_t wlen = end - start;
    /* Must be followed by `{`. */
    if (end >= src_len || src[end] != '{') return 0;
    /* Look up in wrapper table. */
    for (int i = 0; LATEX_TEXT_WRAPPERS[i]; i++) {
        size_t klen = strlen(LATEX_TEXT_WRAPPERS[i]);
        if (klen != wlen) continue;
        if (memcmp(src + start, LATEX_TEXT_WRAPPERS[i], klen) != 0) continue;
        return end - pos;   /* full command length including backslash */
    }
    return 0;
}

/* Same for accent commands -- returns entry index or -1. */
static int latex_accent_at(const char *src, size_t src_len, size_t pos) {
    if (pos >= src_len || src[pos] != '\\') return -1;
    size_t start = pos + 1;
    size_t end = start;
    while (end < src_len &&
           ((src[end] >= 'a' && src[end] <= 'z') ||
            (src[end] >= 'A' && src[end] <= 'Z'))) end++;
    if (end == start) return -1;
    size_t wlen = end - start;
    if (end >= src_len || src[end] != '{') return -1;
    for (int i = 0; LATEX_ACCENTS[i].cmd; i++) {
        size_t klen = strlen(LATEX_ACCENTS[i].cmd);
        if (klen != wlen) continue;
        if (memcmp(src + start, LATEX_ACCENTS[i].cmd, klen) != 0) continue;
        return i;
    }
    return -1;
}

/* Detect `\begin{env}` at pos. Returns length of the `\begin{env}`
 * prefix on match (i.e. count to just past the `}`) and writes env
 * name + length into out params. Returns 0 on no match. */
static size_t latex_begin_at(const char *src, size_t src_len, size_t pos,
                              const char **env_name_out, size_t *env_len_out) {
    static const char *BEGIN = "\\begin{";
    size_t blen = 7;
    if (pos + blen > src_len) return 0;
    if (memcmp(src + pos, BEGIN, blen) != 0) return 0;
    size_t p = pos + blen;
    size_t env_start = p;
    while (p < src_len && src[p] != '}') {
        /* Env names are alphanumeric plus `*` for starred variants. */
        char c = src[p];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '*')) return 0;
        p++;
    }
    if (p >= src_len || src[p] != '}') return 0;
    if (env_name_out) *env_name_out = src + env_start;
    if (env_len_out)  *env_len_out  = p - env_start;
    return (p + 1) - pos;
}

/* Find the corresponding `\end{env}` in src starting from pos. Returns
 * offset of the `\end{env}` start relative to `pos`, or 0 if not found. */
static size_t latex_find_end(const char *src, size_t src_len, size_t pos,
                              const char *env, size_t env_len) {
    /* Build match string `\end{env}`. */
    char pattern[128];
    if (env_len > 100) return 0;
    int pn = _snprintf(pattern, sizeof(pattern) - 1, "\\end{%.*s}",
                       (int)env_len, env);
    if (pn <= 0) return 0;
    /* Walk src looking for pattern. Track nesting: same-env `\begin`
     * increments; matching `\end` decrements. */
    int depth = 1;
    size_t p = pos;
    while (p < src_len) {
        /* Try to match \begin{env} at p. */
        const char *inner_env = NULL;
        size_t inner_len = 0;
        size_t blen = latex_begin_at(src, src_len, p, &inner_env, &inner_len);
        if (blen && inner_len == env_len && memcmp(inner_env, env, env_len) == 0) {
            depth++;
            p += blen;
            continue;
        }
        /* Try to match \end{env} at p. */
        if (p + (size_t)pn <= src_len && memcmp(src + p, pattern, pn) == 0) {
            depth--;
            if (depth == 0) return p - pos;
            p += pn;
            continue;
        }
        p++;
    }
    return 0;
}

/* Append helper. Bounds-checked. */
static void ltx_put(char *dst, size_t *dp, size_t dst_cap, const char *s, size_t n) {
    if (*dp + n >= dst_cap) return;
    memcpy(dst + *dp, s, n);
    *dp += n;
}
static void ltx_putc(char *dst, size_t *dp, size_t dst_cap, char c) {
    if (*dp + 1 >= dst_cap) return;
    dst[(*dp)++] = c;
}
static void ltx_puts(char *dst, size_t *dp, size_t dst_cap, const char *s) {
    ltx_put(dst, dp, dst_cap, s, strlen(s));
}

/* Skip past a `{...}` group starting at src[pos] (which must be `{`).
 * Returns index of matching `}`, or src_len on unterminated. */
static size_t latex_skip_brace(const char *src, size_t src_len, size_t pos) {
    if (pos >= src_len || src[pos] != '{') return pos;
    size_t p = pos + 1;
    int depth = 1;
    while (p < src_len && depth > 0) {
        if (src[p] == '\\' && p + 1 < src_len) { p += 2; continue; }
        if (src[p] == '{') depth++;
        else if (src[p] == '}') { depth--; if (depth == 0) return p; }
        p++;
    }
    return src_len;
}

/* Advance past a UTF-8 codepoint (or 1 byte if not UTF-8 lead). */
static size_t utf8_advance(const char *s, size_t pos, size_t end) {
    if (pos >= end) return pos;
    unsigned char c = (unsigned char)s[pos];
    if (c < 0x80) return pos + 1;
    if ((c & 0xE0) == 0xC0) return (pos + 2 <= end) ? pos + 2 : end;
    if ((c & 0xF0) == 0xE0) return (pos + 3 <= end) ? pos + 3 : end;
    if ((c & 0xF8) == 0xF0) return (pos + 4 <= end) ? pos + 4 : end;
    return pos + 1;
}

/* ── Unicode super/subscript helpers ─────────────────────────────
 *
 * Full alphabetic coverage isn't 1:1 in Unicode (some letters have no
 * subscript form) -- we fall back to caret/underscore for those.
 * See U+2070..209F block + Latin-1 sups + Spacing Modifier Letters. */

/* Convert an ASCII char to its Unicode SUPERSCRIPT UTF-8 string.
 * Returns NULL if no mapping. */
static const char *sup_of(char c) {
    switch (c) {
        case '0': return "\xE2\x81\xB0";  /* ⁰ */
        case '1': return "\xC2\xB9";      /* ¹ */
        case '2': return "\xC2\xB2";      /* ² */
        case '3': return "\xC2\xB3";      /* ³ */
        case '4': return "\xE2\x81\xB4";  /* ⁴ */
        case '5': return "\xE2\x81\xB5";  /* ⁵ */
        case '6': return "\xE2\x81\xB6";  /* ⁶ */
        case '7': return "\xE2\x81\xB7";  /* ⁷ */
        case '8': return "\xE2\x81\xB8";  /* ⁸ */
        case '9': return "\xE2\x81\xB9";  /* ⁹ */
        case '+': return "\xE2\x81\xBA";  /* ⁺ */
        case '-': return "\xE2\x81\xBB";  /* ⁻ */
        case '=': return "\xE2\x81\xBC";  /* ⁼ */
        case '(': return "\xE2\x81\xBD";  /* ⁽ */
        case ')': return "\xE2\x81\xBE";  /* ⁾ */
        case 'a': return "\xE1\xB5\x83";  /* ᵃ  U+1D43 */
        case 'b': return "\xE1\xB5\x87";  /* ᵇ  U+1D47 */
        case 'c': return "\xE1\xB6\x9C";  /* ᶜ  U+1D9C */
        case 'd': return "\xE1\xB5\x88";  /* ᵈ  U+1D48 */
        case 'e': return "\xE1\xB5\x89";  /* ᵉ  U+1D49 */
        case 'f': return "\xE1\xB6\xA0";  /* ᶠ  U+1DA0 */
        case 'g': return "\xE1\xB5\x8D";  /* ᵍ  U+1D4D */
        case 'h': return "\xCA\xB0";      /* ʰ  U+02B0 */
        case 'i': return "\xE2\x81\xB1";  /* ⁱ  U+2071 */
        case 'j': return "\xCA\xB2";      /* ʲ  U+02B2 */
        case 'k': return "\xE1\xB5\x8F";  /* ᵏ  U+1D4F */
        case 'l': return "\xCB\xA1";      /* ˡ  U+02E1 */
        case 'm': return "\xE1\xB5\x90";  /* ᵐ  U+1D50 */
        case 'n': return "\xE2\x81\xBF";  /* ⁿ  U+207F */
        case 'o': return "\xE1\xB5\x92";  /* ᵒ  U+1D52 */
        case 'p': return "\xE1\xB5\x96";  /* ᵖ  U+1D56 */
        case 'r': return "\xCA\xB3";      /* ʳ  U+02B3 */
        case 's': return "\xCB\xA2";      /* ˢ  U+02E2 */
        case 't': return "\xE1\xB5\x97";  /* ᵗ  U+1D57 */
        case 'u': return "\xE1\xB5\x98";  /* ᵘ  U+1D58 */
        case 'v': return "\xE1\xB5\x9B";  /* ᵛ  U+1D5B */
        case 'w': return "\xCA\xB7";      /* ʷ  U+02B7 */
        case 'x': return "\xCB\xA3";      /* ˣ  U+02E3 */
        case 'y': return "\xCA\xB8";      /* ʸ  U+02B8 */
        default:  return NULL;
    }
}

/* Convert an ASCII char to its Unicode SUBSCRIPT UTF-8 string.
 * Returns NULL if no mapping. */
static const char *sub_of(char c) {
    switch (c) {
        case '0': return "\xE2\x82\x80";  /* ₀ */
        case '1': return "\xE2\x82\x81";  /* ₁ */
        case '2': return "\xE2\x82\x82";  /* ₂ */
        case '3': return "\xE2\x82\x83";  /* ₃ */
        case '4': return "\xE2\x82\x84";  /* ₄ */
        case '5': return "\xE2\x82\x85";  /* ₅ */
        case '6': return "\xE2\x82\x86";  /* ₆ */
        case '7': return "\xE2\x82\x87";  /* ₇ */
        case '8': return "\xE2\x82\x88";  /* ₈ */
        case '9': return "\xE2\x82\x89";  /* ₉ */
        case '+': return "\xE2\x82\x8A";  /* ₊ */
        case '-': return "\xE2\x82\x8B";  /* ₋ */
        case '=': return "\xE2\x82\x8C";  /* ₌ */
        case '(': return "\xE2\x82\x8D";  /* ₍ */
        case ')': return "\xE2\x82\x8E";  /* ₎ */
        case 'a': return "\xE2\x82\x90";  /* ₐ */
        case 'e': return "\xE2\x82\x91";  /* ₑ */
        case 'h': return "\xE2\x82\x95";  /* ₕ */
        case 'i': return "\xE1\xB5\xA2";  /* ᵢ  U+1D62 */
        case 'j': return "\xE2\xB1\xBC";  /* ⱼ  U+2C7C */
        case 'k': return "\xE2\x82\x96";  /* ₖ */
        case 'l': return "\xE2\x82\x97";  /* ₗ */
        case 'm': return "\xE2\x82\x98";  /* ₘ */
        case 'n': return "\xE2\x82\x99";  /* ₙ */
        case 'o': return "\xE2\x82\x92";  /* ₒ */
        case 'p': return "\xE2\x82\x9A";  /* ₚ */
        case 'r': return "\xE1\xB5\xA3";  /* ᵣ  U+1D63 */
        case 's': return "\xE2\x82\x9B";  /* ₛ */
        case 't': return "\xE2\x82\x9C";  /* ₜ */
        case 'u': return "\xE1\xB5\xA4";  /* ᵤ  U+1D64 */
        case 'v': return "\xE1\xB5\xA5";  /* ᵥ  U+1D65 */
        case 'x': return "\xE2\x82\x93";  /* ₓ */
        default:  return NULL;
    }
}

/* Try to render an entire ASCII string as Unicode super/subscript.
 * Returns 1 if every char had a mapping (dst fully filled), 0 if any
 * char lacks a mapping (dst left partially written but caller should
 * fall back to `^{...}` or `_{...}` literal form).
 * `is_super`: 1 = superscript, 0 = subscript. */
static int try_render_sup_sub(const char *s, size_t n, int is_super,
                              char *dst, size_t *dp, size_t dst_cap) {
    for (size_t i = 0; i < n; i++) {
        const char *u = is_super ? sup_of(s[i]) : sub_of(s[i]);
        if (!u) return 0;   /* no clean mapping -- abort */
        ltx_puts(dst, dp, dst_cap, u);
    }
    return 1;
}

/* Unicode vulgar-fraction chars for common `\frac{a}{b}` forms -- much
 * more readable than `1/2` inline. */
struct vulgar_frac_entry { const char *num; const char *den; const char *uni; };
static const struct vulgar_frac_entry VULGAR_FRACS[] = {
    { "1", "2", "\xC2\xBD" },       /* ½ */
    { "1", "3", "\xE2\x85\x93" },   /* ⅓ */
    { "2", "3", "\xE2\x85\x94" },   /* ⅔ */
    { "1", "4", "\xC2\xBC" },       /* ¼ */
    { "3", "4", "\xC2\xBE" },       /* ¾ */
    { "1", "5", "\xE2\x85\x95" },   /* ⅕ */
    { "2", "5", "\xE2\x85\x96" },   /* ⅖ */
    { "3", "5", "\xE2\x85\x97" },   /* ⅗ */
    { "4", "5", "\xE2\x85\x98" },   /* ⅘ */
    { "1", "6", "\xE2\x85\x99" },   /* ⅙ */
    { "5", "6", "\xE2\x85\x9A" },   /* ⅚ */
    { "1", "7", "\xE2\x85\x90" },   /* ⅐ */
    { "1", "8", "\xE2\x85\x9B" },   /* ⅛ */
    { "3", "8", "\xE2\x85\x9C" },   /* ⅜ */
    { "5", "8", "\xE2\x85\x9D" },   /* ⅝ */
    { "7", "8", "\xE2\x85\x9E" },   /* ⅞ */
    { "1", "9", "\xE2\x85\x91" },   /* ⅑ */
    { "1", "10","\xE2\x85\x92" },   /* ⅒ */
    { NULL, NULL, NULL }
};

/* ── Helper functions (previously C++ lambdas -- converted to file-static
 * for C compatibility so the same source can be shared with test/tools). ─── */

/* Read ONE LaTeX-arg starting at `pos`. Supports:
 *   { ... }         (braced group)
 *   single-char     (a-z A-Z 0-9)
 *   \command        (backslash + alpha word)
 * Skips leading whitespace. Writes arg bounds into `*out_start`/`*out_end`
 * and returns new position past the arg. Returns 0 if no arg found. */
static size_t latex_read_arg(const char *src, size_t src_len, size_t pos,
                              size_t *out_start, size_t *out_end) {
    while (pos < src_len && src[pos] == ' ') pos++;
    if (pos >= src_len) return 0;
    if (src[pos] == '{') {
        *out_start = pos + 1;
        size_t e = latex_skip_brace(src, src_len, pos);
        *out_end = e;
        return (e < src_len) ? e + 1 : src_len;
    }
    if (src[pos] == '\\') {
        *out_start = pos;
        size_t e = pos + 1;
        while (e < src_len && ((src[e] >= 'a' && src[e] <= 'z') ||
                               (src[e] >= 'A' && src[e] <= 'Z'))) e++;
        if (e == pos + 1) return 0;   /* backslash + nothing = not an arg */
        *out_end = e;
        return e;
    }
    if ((src[pos] >= '0' && src[pos] <= '9') ||
        (src[pos] >= 'a' && src[pos] <= 'z') ||
        (src[pos] >= 'A' && src[pos] <= 'Z')) {
        *out_start = pos;
        *out_end   = pos + 1;
        return pos + 1;
    }
    return 0;
}

/* TRUE if `s` contains any arithmetic op or space or paren. Used by
 * the \frac wrap heuristic to decide when to parenthesize num/den. */
static int latex_has_op_chars(const char *s, size_t len) {
    for (size_t k = 0; k < len; k++) {
        char nc = s[k];
        if (nc == '+' || nc == '-' || nc == ' ' ||
            nc == '*' || nc == '/' || nc == '=' ||
            nc == '(' || nc == ')') return 1;
    }
    return 0;
}

/* TRUE if `s` has BOTH an ASCII digit AND (letter OR multibyte char).
 * Used by \frac denominator wrap heuristic to detect ambiguous
 * denominators like `2a` in `1/2a` (should be `1/(2a)` to disambiguate
 * from `(1/2)*a`). */
static int latex_is_ambiguous_den(const char *s, size_t len) {
    int has_digit = 0, has_letter = 0;
    for (size_t k = 0; k < len; ) {
        unsigned char b = (unsigned char)s[k];
        if (b < 0x80) {
            if (b >= '0' && b <= '9') has_digit = 1;
            else if ((b >= 'a' && b <= 'z') ||
                     (b >= 'A' && b <= 'Z')) has_letter = 1;
            k++;
        } else if ((b & 0xE0) == 0xC0) { has_letter = 1; k += 2; }
        else if ((b & 0xF0) == 0xE0) { has_letter = 1; k += 3; }
        else if ((b & 0xF8) == 0xF0) { has_letter = 1; k += 4; }
        else k++;
    }
    return has_digit && has_letter;
}

/* ── Environment renderer (matrix / cases / align) ────────────────
 *
 * Renders a `\begin{env}...\end{env}` body as text art:
 *
 *   pmatrix   ->   ⎛ 1 2 ⎞      (Unicode brackets)
 *                 ⎝ 3 4 ⎠
 *   bmatrix   ->   ⎡ 1 2 ⎤
 *                 ⎣ 3 4 ⎦
 *   cases     ->   ⎧ x  if x>0   (open brace, no close)
 *                 ⎩ -x otherwise
 *   align/aligned -> each `&` becomes space, `\\` becomes newline
 *
 * All row separators (`\\`) become `\n`. Column separators (`&`) become
 * a single space (best-effort -- ImGui isn't a real math typesetter).
 *
 * Body is recursively latex_to_unicode'd cell-by-cell so nested \frac,
 * \sqrt, etc. work. Row alignment is preserved by padding each cell to
 * the widest cell in that column (based on byte length -- approximate). */
static size_t latex_render_env(const char *env, size_t env_len,
                                const char *body, size_t body_len,
                                char *dst, size_t dst_cap);

/* Convert LaTeX to Unicode. Returns bytes written to dst (NOT NUL-
 * terminated; caller adds if needed).
 *
 * 2026-07-05 late-night rewrite -- much more comprehensive:
 *   - $ / \( / \) / \[ / \] delimiters stripped
 *   - \\ in display math -> newline
 *   - \frac{a}{b} -> Unicode vulgar frac (½ ⅓ ...) if applicable, else a/b
 *   - \sqrt{x} -> √(x) -- always wrapped for readability
 *   - ^{...} / _{...} -> Unicode super/subscript when all chars mappable
 *   - Bare ^N / _N (single digit) -> Unicode super/sub
 *   - \text{...} / \mathbf{...} / \mathrm{...} etc. -> strip wrapper, keep content
 *   - \vec{x} / \hat{x} / \bar{x} etc. -> x + Unicode combining mark
 *   - \begin{matrix}...\end{matrix} -> text-art rendering (via latex_render_env)
 *   - Full LATEX_MAP lookup (~200 symbols, longest-match-first)
 *   - Unknown \command{content} -> recursively emit content (drop cmd)
 *   - Unknown \command (no braces) -> preserve as literal for user diag
 *   - Stray { } stripped (they're LaTeX grouping)
 *   - $ ` * and ** stay as-is (paragraph accumulator handles md-strip) */
static size_t latex_to_unicode(const char *src, size_t src_len,
                               char *dst, size_t dst_cap) {
    size_t sp = 0, dp = 0;
    while (sp < src_len && dp + 1 < dst_cap) {
        char c = src[sp];

        /* $ delimiters (inline math): stripped. Handles $$ too. */
        if (c == '$') {
            sp++;
            if (sp < src_len && src[sp] == '$') sp++;
            continue;
        }
        /* \( \) delimiters: stripped. */
        if (c == '\\' && sp + 1 < src_len &&
            (src[sp + 1] == '(' || src[sp + 1] == ')')) {
            sp += 2;
            continue;
        }
        /* \[ \] delimiters: stripped. */
        if (c == '\\' && sp + 1 < src_len &&
            (src[sp + 1] == '[' || src[sp + 1] == ']')) {
            sp += 2;
            continue;
        }
        /* \\ (double-backslash) in display math = line break. */
        if (c == '\\' && sp + 1 < src_len && src[sp + 1] == '\\') {
            ltx_putc(dst, &dp, dst_cap, '\n');
            sp += 2;
            /* Consume optional `[spacing]` after \\ (e.g. `\\[1ex]`). */
            if (sp < src_len && src[sp] == '[') {
                while (sp < src_len && src[sp] != ']') sp++;
                if (sp < src_len) sp++;   /* past ] */
            }
            /* Absorb ONE leading whitespace after line break so
             * `\\\n  next line` doesn't produce a double blank. */
            while (sp < src_len && (src[sp] == ' ' || src[sp] == '\t')) sp++;
            continue;
        }

        /* \begin{env}...\end{env} -- dispatch to environment renderer. */
        if (c == '\\' && sp + 7 <= src_len &&
            memcmp(src + sp, "\\begin{", 7) == 0) {
            const char *env_name = NULL;
            size_t env_len = 0;
            size_t begin_len = latex_begin_at(src, src_len, sp,
                                               &env_name, &env_len);
            if (begin_len > 0) {
                size_t body_start = sp + begin_len;
                size_t end_off = latex_find_end(src, src_len, body_start,
                                                 env_name, env_len);
                if (end_off > 0) {
                    /* Extract env body + render. */
                    char rendered[4096];
                    size_t rlen = latex_render_env(env_name, env_len,
                                                    src + body_start, end_off,
                                                    rendered, sizeof(rendered) - 1);
                    ltx_put(dst, &dp, dst_cap, rendered, rlen);
                    /* Skip past \end{env}. */
                    char end_pat[128];
                    _snprintf(end_pat, sizeof(end_pat) - 1, "\\end{%.*s}",
                              (int)env_len, env_name);
                    sp = body_start + end_off + strlen(end_pat);
                    continue;
                }
            }
        }

        /* \not X prefix -- negation. Emits the negated Unicode form:
         *   \not=       -> ≠   (specific -- same as \neq)
         *   \not<       -> ≮
         *   \not>       -> ≯
         *   \not\in     -> ∉   (specific -- same as \notin)
         *   \not\equiv  -> ≢
         *   \not\subset -> ⊄
         *   \not\prec   -> ⊀   (specific -- same as \nprec)
         *   ... more via NEGATION_MAP below
         * For unknown targets: emit the target's rendered form + a
         * combining long-solidus-overlay (U+0338) which visually strikes
         * out the previous char in most fonts. */
        if (c == '\\' && sp + 4 <= src_len &&
            memcmp(src + sp, "\\not", 4) == 0 &&
            (sp + 4 == src_len ||
             src[sp + 4] == '=' || src[sp + 4] == '<' || src[sp + 4] == '>' ||
             src[sp + 4] == '\\' || src[sp + 4] == ' ' ||
             src[sp + 4] == '{')) {
            size_t p = sp + 4;
            /* Absorb optional {} that AI sometimes emits: \not{=} */
            int had_brace = 0;
            if (p < src_len && src[p] == '{') { p++; had_brace = 1; }
            /* Absorb whitespace between \not and target. */
            while (p < src_len && src[p] == ' ') p++;
            if (p >= src_len) {
                /* orphan \not -- emit literal for diagnostic */
                ltx_puts(dst, &dp, dst_cap, "\\not");
                sp = p;
                continue;
            }
            /* Look at target. */
            const char *neg_uni = NULL;
            size_t consume = 0;
            if (src[p] == '=') { neg_uni = "\xE2\x89\xA0"; consume = 1; }     /* ≠ */
            else if (src[p] == '<') { neg_uni = "\xE2\x89\xAE"; consume = 1; } /* ≮ */
            else if (src[p] == '>') { neg_uni = "\xE2\x89\xAF"; consume = 1; } /* ≯ */
            else if (src[p] == '\\') {
                /* Try to match a command in LATEX_MAP */
                int idx = latex_match_at(src, src_len, p);
                if (idx >= 0) {
                    size_t tlen = strlen(LATEX_MAP[idx].tex);
                    const char *tex = LATEX_MAP[idx].tex;
                    /* Known specific negations */
                    if (strcmp(tex, "\\in") == 0)              neg_uni = "\xE2\x88\x89";    /* ∉ */
                    else if (strcmp(tex, "\\ni") == 0)         neg_uni = "\xE2\x88\x8C";    /* ∌ */
                    else if (strcmp(tex, "\\equiv") == 0)      neg_uni = "\xE2\x89\xA2";    /* ≢ */
                    else if (strcmp(tex, "\\sim") == 0)        neg_uni = "\xE2\x89\x81";    /* ≁ */
                    else if (strcmp(tex, "\\cong") == 0)       neg_uni = "\xE2\x89\x86";    /* ≆ */
                    else if (strcmp(tex, "\\approx") == 0)     neg_uni = "\xE2\x89\x89";    /* ≉ */
                    else if (strcmp(tex, "\\subset") == 0)     neg_uni = "\xE2\x8A\x84";    /* ⊄ */
                    else if (strcmp(tex, "\\supset") == 0)     neg_uni = "\xE2\x8A\x85";    /* ⊅ */
                    else if (strcmp(tex, "\\subseteq") == 0)   neg_uni = "\xE2\x8A\x88";    /* ⊈ */
                    else if (strcmp(tex, "\\supseteq") == 0)   neg_uni = "\xE2\x8A\x89";    /* ⊉ */
                    else if (strcmp(tex, "\\prec") == 0)       neg_uni = "\xE2\x8A\x80";    /* ⊀ */
                    else if (strcmp(tex, "\\succ") == 0)       neg_uni = "\xE2\x8A\x81";    /* ⊁ */
                    else if (strcmp(tex, "\\preceq") == 0)     neg_uni = "\xE2\x8B\xA0";    /* ⋠ */
                    else if (strcmp(tex, "\\succeq") == 0)     neg_uni = "\xE2\x8B\xA1";    /* ⋡ */
                    else if (strcmp(tex, "\\leq") == 0 ||
                             strcmp(tex, "\\le") == 0)         neg_uni = "\xE2\x89\xB0";    /* ≰ */
                    else if (strcmp(tex, "\\geq") == 0 ||
                             strcmp(tex, "\\ge") == 0)         neg_uni = "\xE2\x89\xB1";    /* ≱ */
                    else if (strcmp(tex, "\\mid") == 0)        neg_uni = "\xE2\x88\xA4";    /* ∤ */
                    else if (strcmp(tex, "\\parallel") == 0)   neg_uni = "\xE2\x88\xA6";    /* ∦ */
                    else if (strcmp(tex, "\\vdash") == 0)      neg_uni = "\xE2\x8A\xAC";    /* ⊬ */
                    else if (strcmp(tex, "\\models") == 0 ||
                             strcmp(tex, "\\vDash") == 0)      neg_uni = "\xE2\x8A\xAD";    /* ⊭ */
                    else if (strcmp(tex, "\\rightarrow") == 0 ||
                             strcmp(tex, "\\to") == 0)         neg_uni = "\xE2\x86\x9B";    /* ↛ */
                    else if (strcmp(tex, "\\leftarrow") == 0)  neg_uni = "\xE2\x86\x9A";    /* ↚ */
                    else if (strcmp(tex, "\\Rightarrow") == 0) neg_uni = "\xE2\x87\x8F";    /* ⇏ */
                    else if (strcmp(tex, "\\Leftarrow") == 0)  neg_uni = "\xE2\x87\x8D";    /* ⇍ */
                    else if (strcmp(tex, "\\Leftrightarrow") == 0) neg_uni = "\xE2\x87\x8E"; /* ⇎ */
                    else if (strcmp(tex, "\\leftrightarrow") == 0) neg_uni = "\xE2\x86\xAE"; /* ↮ */
                    if (neg_uni) {
                        consume = tlen;
                    } else {
                        /* Fallback: emit mapped Unicode + combining slash overlay. */
                        ltx_puts(dst, &dp, dst_cap, LATEX_MAP[idx].uni);
                        ltx_puts(dst, &dp, dst_cap, "\xCC\xB8");   /* U+0338 combining long solidus */
                        sp = p + tlen;
                        if (had_brace && sp < src_len && src[sp] == '}') sp++;
                        continue;
                    }
                }
            }
            if (neg_uni) {
                ltx_puts(dst, &dp, dst_cap, neg_uni);
                sp = p + consume;
                if (had_brace && sp < src_len && src[sp] == '}') sp++;
                continue;
            }
            /* Fallback: emit next char + combining slash (works for any
             * arbitrary char). */
            if (p < src_len) {
                size_t np = utf8_advance(src, p, src_len);
                ltx_put(dst, &dp, dst_cap, src + p, np - p);
                ltx_puts(dst, &dp, dst_cap, "\xCC\xB8");   /* combining slash */
                sp = np;
                if (had_brace && sp < src_len && src[sp] == '}') sp++;
                continue;
            }
        }

        /* \pmod{a} -> " (mod a)" -- parenthesized modular arithmetic
         * marker. Standard LaTeX renders \pmod with parens which our
         * bare \pmod -> "mod" mapping doesn't do; catch it here so we
         * emit the parens explicitly. */
        if (c == '\\' && sp + 6 <= src_len &&
            memcmp(src + sp, "\\pmod", 5) == 0 && src[sp + 5] == '{') {
            size_t p = sp + 5;
            size_t inner_start = p + 1;
            size_t inner_end = latex_skip_brace(src, src_len, p);
            p = (inner_end < src_len) ? inner_end + 1 : src_len;
            char inner_buf[256];
            size_t il = latex_to_unicode(src + inner_start,
                                          inner_end - inner_start,
                                          inner_buf, sizeof(inner_buf) - 1);
            inner_buf[il] = 0;
            /* No leading space -- the source usually has one already
             * ("$a \equiv b \pmod{7}$" -> "a ≡ b (mod 7)"). Emitting a
             * leading space here would double it. */
            ltx_puts(dst, &dp, dst_cap, "(mod ");
            ltx_put(dst, &dp, dst_cap, inner_buf, il);
            ltx_putc(dst, &dp, dst_cap, ')');
            sp = p;
            continue;
        }

        /* \ang{degrees} -> "degrees°" (KaTeX \ang extension). */
        if (c == '\\' && sp + 5 <= src_len &&
            memcmp(src + sp, "\\ang", 4) == 0 && src[sp + 4] == '{') {
            size_t p = sp + 4;
            size_t inner_start = p + 1;
            size_t inner_end = latex_skip_brace(src, src_len, p);
            p = (inner_end < src_len) ? inner_end + 1 : src_len;
            char inner_buf[128];
            size_t il = latex_to_unicode(src + inner_start,
                                          inner_end - inner_start,
                                          inner_buf, sizeof(inner_buf) - 1);
            inner_buf[il] = 0;
            ltx_put(dst, &dp, dst_cap, inner_buf, il);
            ltx_puts(dst, &dp, dst_cap, "\xC2\xB0");   /* ° */
            sp = p;
            continue;
        }

        /* \ket{X} -> |X⟩   quantum ket notation
         * \bra{X} -> ⟨X|   bra notation
         * \Ket, \Bra -- same (tall delimiter variants render identically in text mode)
         * \braket{ϕ|ψ} -> ⟨ϕ|ψ⟩   inner-product bracket
         * \Braket -- same
         * \bra & \ket must match BEFORE \braket because they're prefixes.
         * Order in the string check: check longer prefix first. */
        if (c == '\\' && sp + 8 <= src_len &&
            (memcmp(src + sp, "\\braket", 7) == 0 ||
             memcmp(src + sp, "\\Braket", 7) == 0) &&
            src[sp + 7] == '{') {
            size_t p = sp + 7;
            size_t inner_start = p + 1;
            size_t inner_end = latex_skip_brace(src, src_len, p);
            p = (inner_end < src_len) ? inner_end + 1 : src_len;
            char inner_buf[512];
            size_t il = latex_to_unicode(src + inner_start,
                                          inner_end - inner_start,
                                          inner_buf, sizeof(inner_buf) - 1);
            inner_buf[il] = 0;
            ltx_puts(dst, &dp, dst_cap, "\xE2\x9F\xA8");   /* ⟨ */
            ltx_put(dst, &dp, dst_cap, inner_buf, il);
            ltx_puts(dst, &dp, dst_cap, "\xE2\x9F\xA9");   /* ⟩ */
            sp = p;
            continue;
        }
        if (c == '\\' && sp + 5 <= src_len &&
            (memcmp(src + sp, "\\ket", 4) == 0 ||
             memcmp(src + sp, "\\Ket", 4) == 0) &&
            src[sp + 4] == '{') {
            size_t p = sp + 4;
            size_t inner_start = p + 1;
            size_t inner_end = latex_skip_brace(src, src_len, p);
            p = (inner_end < src_len) ? inner_end + 1 : src_len;
            char inner_buf[256];
            size_t il = latex_to_unicode(src + inner_start,
                                          inner_end - inner_start,
                                          inner_buf, sizeof(inner_buf) - 1);
            inner_buf[il] = 0;
            ltx_putc(dst, &dp, dst_cap, '|');
            ltx_put(dst, &dp, dst_cap, inner_buf, il);
            ltx_puts(dst, &dp, dst_cap, "\xE2\x9F\xA9");   /* ⟩ */
            sp = p;
            continue;
        }
        if (c == '\\' && sp + 5 <= src_len &&
            (memcmp(src + sp, "\\bra", 4) == 0 ||
             memcmp(src + sp, "\\Bra", 4) == 0) &&
            src[sp + 4] == '{') {
            size_t p = sp + 4;
            size_t inner_start = p + 1;
            size_t inner_end = latex_skip_brace(src, src_len, p);
            p = (inner_end < src_len) ? inner_end + 1 : src_len;
            char inner_buf[256];
            size_t il = latex_to_unicode(src + inner_start,
                                          inner_end - inner_start,
                                          inner_buf, sizeof(inner_buf) - 1);
            inner_buf[il] = 0;
            ltx_puts(dst, &dp, dst_cap, "\xE2\x9F\xA8");   /* ⟨ */
            ltx_put(dst, &dp, dst_cap, inner_buf, il);
            ltx_putc(dst, &dp, dst_cap, '|');
            sp = p;
            continue;
        }

        /* \overset{above}{base} -> "base" + "^{above}" recursion
         * \underset{below}{base} -> "base" + "_{below}"
         * \stackrel{above}{base} -> same as \overset (deprecated alias)
         * The best text rendering is to emit `base` first, then let the
         * sup/sub handler render `above`/`below`. */
        if (c == '\\' && sp + 9 <= src_len) {
            int is_over = memcmp(src + sp, "\\overset",   8) == 0 && src[sp + 8] == '{';
            int is_under = memcmp(src + sp, "\\underset", 9) == 0 && sp + 9 < src_len && src[sp + 9] == '{';
            int is_stack = memcmp(src + sp, "\\stackrel", 9) == 0 && sp + 9 < src_len && src[sp + 9] == '{';
            if (is_over || is_under || is_stack) {
                size_t cmd_len = is_over ? 8 : 9;
                size_t p = sp + cmd_len;
                size_t sup_start = p + 1;
                size_t sup_end = latex_skip_brace(src, src_len, p);
                p = (sup_end < src_len) ? sup_end + 1 : src_len;
                if (p < src_len && src[p] == '{') {
                    size_t base_start = p + 1;
                    size_t base_end = latex_skip_brace(src, src_len, p);
                    p = (base_end < src_len) ? base_end + 1 : src_len;
                    /* Recursively render base first. */
                    char base_buf[512];
                    size_t bl = latex_to_unicode(src + base_start,
                                                  base_end - base_start,
                                                  base_buf, sizeof(base_buf) - 1);
                    ltx_put(dst, &dp, dst_cap, base_buf, bl);
                    /* Then render "annotation" (sup or sub) if non-empty.
                     * Build a synthetic string `^{content}` or `_{content}`
                     * and recursively process it so sub/sup handling
                     * kicks in and tries Unicode super/sub first. */
                    if (sup_end > sup_start) {
                        char pseudo[520];
                        int ml = _snprintf(pseudo, sizeof(pseudo) - 1,
                            "%c{%.*s}", is_under ? '_' : '^',
                            (int)(sup_end - sup_start),
                            src + sup_start);
                        if (ml > 0) {
                            char ann_buf[512];
                            size_t al = latex_to_unicode(pseudo, (size_t)ml,
                                                          ann_buf, sizeof(ann_buf) - 1);
                            ltx_put(dst, &dp, dst_cap, ann_buf, al);
                        }
                    }
                    sp = p;
                    continue;
                }
            }
        }

        /* \hspace{X}, \hspace*{X}, \vspace{X}, \kern{X}, \mkern{X},
         * \hskip{X}, \mskip{X} -- drop command + drop {} arg, emit
         * one space (best-effort). Matches KaTeX behavior of visible
         * gap. */
        if (c == '\\' && sp + 7 <= src_len) {
            struct { const char *name; size_t nlen; } spacers[] = {
                { "\\hspace", 7 }, { "\\vspace", 7 },
                { "\\hskip",  6 }, { "\\vskip",  6 },
                { "\\mkern",  6 }, { "\\mskip",  6 },
                { "\\kern",   5 }, { NULL, 0 }
            };
            int matched = 0;
            for (int i = 0; spacers[i].name; i++) {
                size_t nl = spacers[i].nlen;
                if (sp + nl + 1 > src_len) continue;
                if (memcmp(src + sp, spacers[i].name, nl) != 0) continue;
                size_t q = sp + nl;
                /* Optional `*` after \hspace / \vspace */
                if (q < src_len && src[q] == '*') q++;
                /* Optional `{...}` or `<number><unit>` arg */
                if (q < src_len && src[q] == '{') {
                    size_t e = latex_skip_brace(src, src_len, q);
                    q = (e < src_len) ? e + 1 : src_len;
                } else {
                    /* Skip a number+unit like `2em` `10pt` `-2.5pt` */
                    if (q < src_len && (src[q] == '-' || src[q] == '+')) q++;
                    while (q < src_len && ((src[q] >= '0' && src[q] <= '9') ||
                                            src[q] == '.')) q++;
                    /* Skip unit (2 letters typically: em, ex, pt, mm, cm, in, mu) */
                    int unit_chars = 0;
                    while (q < src_len && unit_chars < 3 &&
                           ((src[q] >= 'a' && src[q] <= 'z') ||
                            (src[q] >= 'A' && src[q] <= 'Z'))) {
                        q++; unit_chars++;
                    }
                }
                ltx_putc(dst, &dp, dst_cap, ' ');
                sp = q;
                matched = 1;
                break;
            }
            if (matched) continue;
        }

        /* \href{url}{text} -- extract text only (drop url).
         * KaTeX renders as link -- in text mode we just show label. */
        if (c == '\\' && sp + 7 <= src_len &&
            memcmp(src + sp, "\\href", 5) == 0 && src[sp + 5] == '{') {
            size_t p = sp + 5;
            size_t url_end = latex_skip_brace(src, src_len, p);
            p = (url_end < src_len) ? url_end + 1 : src_len;
            if (p < src_len && src[p] == '{') {
                size_t text_start = p + 1;
                size_t text_end = latex_skip_brace(src, src_len, p);
                p = (text_end < src_len) ? text_end + 1 : src_len;
                char text_buf[512];
                size_t tl = latex_to_unicode(src + text_start,
                                              text_end - text_start,
                                              text_buf, sizeof(text_buf) - 1);
                ltx_put(dst, &dp, dst_cap, text_buf, tl);
                sp = p;
                continue;
            }
        }

        /* \frac{a}{b} + synonyms \dfrac \tfrac \cfrac (display / text /
         * continued) -- all render the same in text mode. PLUS v6.1
         * shorthand for the single-token forms:
         *   \frac12       -> 1/2                  (two single-char args)
         *   \frac1{2x}    -> 1/(2x)               (single-char + braced)
         *   \frac{1}2     -> 1/2                  (braced + single-char)
         *   \frac1\pi     -> 1/π                  (\command as arg)
         * All are legal LaTeX shorthand for single-token arguments.
         * AI models emit these frequently and pre-fix they rendered
         * as literal "\frac12" text. */
        size_t frac_cmd_len = 0;
        if (c == '\\' && sp + 5 <= src_len) {
            if (memcmp(src + sp, "\\frac",  5) == 0) frac_cmd_len = 5;
            else if (sp + 6 <= src_len && (
                memcmp(src + sp, "\\dfrac", 6) == 0 ||
                memcmp(src + sp, "\\tfrac", 6) == 0 ||
                memcmp(src + sp, "\\cfrac", 6) == 0)) frac_cmd_len = 6;
        }
        if (frac_cmd_len > 0 &&
            (sp + frac_cmd_len == src_len ||
             src[sp + frac_cmd_len] == '{' || src[sp + frac_cmd_len] == ' ' ||
             src[sp + frac_cmd_len] == '\\' ||
             (src[sp + frac_cmd_len] >= '0' && src[sp + frac_cmd_len] <= '9') ||
             (src[sp + frac_cmd_len] >= 'a' && src[sp + frac_cmd_len] <= 'z') ||
             (src[sp + frac_cmd_len] >= 'A' && src[sp + frac_cmd_len] <= 'Z'))) {
            size_t p = sp + frac_cmd_len;
            size_t num_start = 0, num_end = 0;
            size_t after_num = latex_read_arg(src, src_len, p, &num_start, &num_end);
            if (after_num > 0) {
                size_t den_start = 0, den_end = 0;
                size_t after_den = latex_read_arg(src, src_len, after_num, &den_start, &den_end);
                if (after_den > 0) {
                    p = after_den;
                    /* Recursively convert num + den. */
                    char num_buf[512], den_buf[512];
                    size_t nl = latex_to_unicode(src + num_start,
                                                  num_end - num_start,
                                                  num_buf, sizeof(num_buf) - 1);
                    num_buf[nl] = 0;
                    size_t dl = latex_to_unicode(src + den_start,
                                                  den_end - den_start,
                                                  den_buf, sizeof(den_buf) - 1);
                    den_buf[dl] = 0;
                    /* Try vulgar fraction lookup first -- much prettier. */
                    int vulgar_ok = 0;
                    for (int i = 0; VULGAR_FRACS[i].num; i++) {
                        if (strcmp(num_buf, VULGAR_FRACS[i].num) == 0 &&
                            strcmp(den_buf, VULGAR_FRACS[i].den) == 0) {
                            ltx_puts(dst, &dp, dst_cap, VULGAR_FRACS[i].uni);
                            vulgar_ok = 1;
                            break;
                        }
                    }
                    if (!vulgar_ok) {
                        /* Wrap rules:
                         *
                         * NUM: wrap only if has op/space/paren.
                         *
                         * DEN: wrap if has op/space/paren OR if content
                         *   mixes DIGIT with LETTER/multibyte (e.g. `2a`,
                         *   `2σ²` -- `1/2a` reads as `(1/2)·a` OR `1/(2a)`
                         *   ambiguously without parens). Pure `a`, pure
                         *   `10`, pure `speed` etc. don't need wrap
                         *   (unambiguous atomic units).
                         *
                         * Yields (all real AI outputs):
                         *   1/2         -> ½ (vulgar path)
                         *   a/b         -> a/b
                         *   dy/dx       -> dy/dx (standard notation)
                         *   distance/speed -> distance/speed
                         *   1/2a        -> 1/(2a) (ambiguous -> wrap)
                         *   2/2σ²       -> 2/(2σ²)
                         *   (a+b)/(c-d) -> wrap both
                         *   1/(σ√(2π))  -> den has `(` -> wrap */
                        int wrap_num = latex_has_op_chars(num_buf, nl);
                        int wrap_den = latex_has_op_chars(den_buf, dl) ||
                                       latex_is_ambiguous_den(den_buf, dl);
                        if (wrap_num) ltx_putc(dst, &dp, dst_cap, '(');
                        ltx_put(dst, &dp, dst_cap, num_buf, nl);
                        if (wrap_num) ltx_putc(dst, &dp, dst_cap, ')');
                        ltx_putc(dst, &dp, dst_cap, '/');
                        if (wrap_den) ltx_putc(dst, &dp, dst_cap, '(');
                        ltx_put(dst, &dp, dst_cap, den_buf, dl);
                        if (wrap_den) ltx_putc(dst, &dp, dst_cap, ')');
                    }
                    sp = p;
                    continue;
                }
            }
        }

        /* \binom{a}{b} -> C(a,b) form. */
        if (c == '\\' && sp + 6 <= src_len &&
            (memcmp(src + sp, "\\binom", 6) == 0 ||
             memcmp(src + sp, "\\tbinom", 7) == 0 ||
             memcmp(src + sp, "\\dbinom", 7) == 0)) {
            size_t cmd_len = (src[sp + 1] == 'b') ? 6 : 7;
            size_t p = sp + cmd_len;
            if (p < src_len && src[p] == '{') {
                size_t top_start = p + 1;
                size_t top_end = latex_skip_brace(src, src_len, p);
                p = (top_end < src_len) ? top_end + 1 : src_len;
                if (p < src_len && src[p] == '{') {
                    size_t bot_start = p + 1;
                    size_t bot_end = latex_skip_brace(src, src_len, p);
                    p = (bot_end < src_len) ? bot_end + 1 : src_len;
                    char t_buf[256], b_buf[256];
                    size_t tl = latex_to_unicode(src + top_start,
                                                  top_end - top_start,
                                                  t_buf, sizeof(t_buf) - 1);
                    t_buf[tl] = 0;
                    size_t bl = latex_to_unicode(src + bot_start,
                                                  bot_end - bot_start,
                                                  b_buf, sizeof(b_buf) - 1);
                    b_buf[bl] = 0;
                    ltx_putc(dst, &dp, dst_cap, 'C');
                    ltx_putc(dst, &dp, dst_cap, '(');
                    ltx_put(dst, &dp, dst_cap, t_buf, tl);
                    ltx_putc(dst, &dp, dst_cap, ',');
                    ltx_put(dst, &dp, dst_cap, b_buf, bl);
                    ltx_putc(dst, &dp, dst_cap, ')');
                    sp = p;
                    continue;
                }
            }
        }

        /* \sqrt[n]{x} (nth root) and \sqrt{x}, PLUS v6.1 shorthand:
         *   \sqrt2       -> √2        (single-char arg without braces)
         *   \sqrt\pi     -> √π        (\command as arg)
         *   \sqrt {x}    -> √x        (space then braced)
         * The single-char shorthand is legal AMS-LaTeX and AI models
         * emit it a lot. Reported symptom from user: '2+ \sqrt2,2,2'
         * came out as literal text pre-fix. */
        if (c == '\\' && sp + 5 <= src_len &&
            memcmp(src + sp, "\\sqrt", 5) == 0 &&
            (sp + 5 == src_len || src[sp + 5] == '{' || src[sp + 5] == '[' ||
             src[sp + 5] == ' '  || src[sp + 5] == '\\' ||
             (src[sp + 5] >= '0' && src[sp + 5] <= '9') ||
             (src[sp + 5] >= 'a' && src[sp + 5] <= 'z') ||
             (src[sp + 5] >= 'A' && src[sp + 5] <= 'Z'))) {
            size_t p = sp + 5;
            /* Optional [n] index for nth root -- emit as n√ prefix. */
            if (p < src_len && src[p] == '[') {
                p++;
                size_t idx_start = p;
                while (p < src_len && src[p] != ']') p++;
                if (p < src_len) {
                    char idx_buf[64];
                    size_t il = latex_to_unicode(src + idx_start,
                                                  p - idx_start,
                                                  idx_buf, sizeof(idx_buf) - 1);
                    idx_buf[il] = 0;
                    /* Try Unicode superscript for the index. */
                    size_t before_dp = dp;
                    if (!try_render_sup_sub(idx_buf, il, 1, dst, &dp, dst_cap)) {
                        dp = before_dp;
                        ltx_put(dst, &dp, dst_cap, idx_buf, il);
                    }
                    p++;   /* past ] */
                }
            }
            ltx_puts(dst, &dp, dst_cap, "\xE2\x88\x9A");   /* √ */
            if (p < src_len && src[p] == '{') {
                size_t inner_start = p + 1;
                size_t inner_end = latex_skip_brace(src, src_len, p);
                p = (inner_end < src_len) ? inner_end + 1 : src_len;
                char inner_buf[512];
                size_t il = latex_to_unicode(src + inner_start,
                                              inner_end - inner_start,
                                              inner_buf, sizeof(inner_buf) - 1);
                inner_buf[il] = 0;
                /* Wrap in parens for readability. Rules (in order):
                 *   YES if inner has any op/space -> √(a+b), √(a b)
                 *   YES if inner has mixed content (digit+letter, digit
                 *     + multibyte greek) -> √(2π), √(2ac), √(2x)
                 *   NO for pure digits (√27, √100)
                 *   NO for pure letters (√x, √xy, √abc)
                 *   NO for single-char content
                 * Rationale: √27 reads unambiguously; √2π is confusing
                 * (is it √2 · π or √(2π)?), so we wrap. */
                int wrap = 0;
                int has_digit = 0, has_ascii_letter = 0, has_multibyte = 0;
                for (size_t k = 0; k < il; ) {
                    unsigned char b = (unsigned char)inner_buf[k];
                    if (b < 0x80) {
                        char nc = (char)b;
                        if (nc == '+' || nc == '-' || nc == ' ' || nc == '*' ||
                            nc == '/' || nc == '=' || nc == '(' || nc == ')') {
                            wrap = 1; break;
                        }
                        if (nc >= '0' && nc <= '9') has_digit = 1;
                        if ((nc >= 'a' && nc <= 'z') || (nc >= 'A' && nc <= 'Z'))
                            has_ascii_letter = 1;
                        k++;
                    } else if ((b & 0xE0) == 0xC0) { has_multibyte = 1; k += 2; }
                    else if ((b & 0xF0) == 0xE0) { has_multibyte = 1; k += 3; }
                    else if ((b & 0xF8) == 0xF0) { has_multibyte = 1; k += 4; }
                    else k++;
                }
                if (!wrap) {
                    int types = (has_digit != 0) + (has_ascii_letter != 0) +
                                (has_multibyte != 0);
                    if (types >= 2) wrap = 1;
                }
                if (wrap) ltx_putc(dst, &dp, dst_cap, '(');
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
                if (wrap) ltx_putc(dst, &dp, dst_cap, ')');
                sp = p;
                continue;
            } else if (p < src_len && src[p] == ' ') {
                /* v6.1: `\sqrt {x}` (space then braced) - skip space + retry. */
                sp += 5; while (sp < src_len && src[sp] == ' ') sp++;
                continue;
            } else if (p < src_len && src[p] == '\\') {
                /* v6.1: `\sqrt\pi` shorthand - read next \command as
                 * a single token, recurse it, emit under the radical. */
                size_t cmd_start = p; p++;
                while (p < src_len && ((src[p] >= 'a' && src[p] <= 'z') ||
                                       (src[p] >= 'A' && src[p] <= 'Z'))) p++;
                char sub_buf[64];
                size_t sl = latex_to_unicode(src + cmd_start, p - cmd_start,
                                              sub_buf, sizeof(sub_buf) - 1);
                sub_buf[sl] = 0;
                ltx_put(dst, &dp, dst_cap, sub_buf, sl);
                sp = p;
                continue;
            } else if (p < src_len &&
                       ((src[p] >= '0' && src[p] <= '9') ||
                        (src[p] >= 'a' && src[p] <= 'z') ||
                        (src[p] >= 'A' && src[p] <= 'Z'))) {
                /* v6.1: `\sqrt2` / `\sqrtx` shorthand - single char arg. */
                ltx_putc(dst, &dp, dst_cap, src[p]);
                sp = p + 1;
                continue;
            } else {
                sp += 5;
                continue;
            }
        }

        /* Accent commands: \vec{x} -> x⃗ etc. */
        {
            int acc = latex_accent_at(src, src_len, sp);
            if (acc >= 0) {
                size_t cmd_len = 1 + strlen(LATEX_ACCENTS[acc].cmd);
                size_t p = sp + cmd_len;   /* at `{` */
                size_t inner_start = p + 1;
                size_t inner_end = latex_skip_brace(src, src_len, p);
                p = (inner_end < src_len) ? inner_end + 1 : src_len;
                char inner_buf[256];
                size_t il = latex_to_unicode(src + inner_start,
                                              inner_end - inner_start,
                                              inner_buf, sizeof(inner_buf) - 1);
                inner_buf[il] = 0;
                /* Emit each codepoint of inner + combining mark. */
                size_t ip = 0;
                while (ip < il) {
                    size_t np = utf8_advance(inner_buf, ip, il);
                    ltx_put(dst, &dp, dst_cap, inner_buf + ip, np - ip);
                    ltx_puts(dst, &dp, dst_cap, LATEX_ACCENTS[acc].combining);
                    ip = np;
                }
                sp = p;
                continue;
            }
        }

        /* Wrapper commands: \text{foo} / \mathbf{x} / \operatorname{lcm} etc.
         * Emit inner content unchanged (recursively converted). */
        {
            size_t wrap_cmd = latex_wrapper_at(src, src_len, sp);
            if (wrap_cmd > 0) {
                size_t p = sp + wrap_cmd;   /* at `{` */
                size_t inner_start = p + 1;
                size_t inner_end = latex_skip_brace(src, src_len, p);
                p = (inner_end < src_len) ? inner_end + 1 : src_len;
                char inner_buf[1024];
                size_t il = latex_to_unicode(src + inner_start,
                                              inner_end - inner_start,
                                              inner_buf, sizeof(inner_buf) - 1);
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
                sp = p;
                continue;
            }
        }

        /* Superscript/subscript with braces: ^{...} / _{...}
         * Try full Unicode super/sub for all chars; fall back to
         * `^{inner}` / `_{inner}` literal on any un-mappable char.
         * We KEEP the braces on fallback so scope is unambiguous --
         * `\lim_{n \to \infty}` renders as `lim_{n -> ∞}`, not
         * `lim_n -> ∞` which is unreadable. */
        if ((c == '^' || c == '_') && sp + 1 < src_len && src[sp + 1] == '{') {
            char op = c;
            sp += 2;
            size_t inner_start = sp;
            size_t inner_end = latex_skip_brace(src, src_len, sp - 1);
            sp = (inner_end < src_len) ? inner_end + 1 : src_len;
            size_t ilen = inner_end - inner_start;

            /* Recursively convert the inner content first (so \pi etc.
             * become π etc). */
            char inner_buf[256];
            size_t il = latex_to_unicode(src + inner_start, ilen,
                                          inner_buf, sizeof(inner_buf) - 1);
            inner_buf[il] = 0;

            /* Try Unicode super/sub rendering. */
            size_t before_dp = dp;
            int rendered_uni = try_render_sup_sub(inner_buf, il,
                                                    op == '^', dst, &dp, dst_cap);
            if (!rendered_uni) {
                /* Roll back + emit literal `^{inner}` / `_{inner}`.
                 * Braces preserved so reader knows what's being
                 * sub/superscripted. */
                dp = before_dp;
                ltx_putc(dst, &dp, dst_cap, op);
                ltx_putc(dst, &dp, dst_cap, '{');
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
                ltx_putc(dst, &dp, dst_cap, '}');
            }
            continue;
        }

        /* Bare ^X or _X handling.
         *
         * SPECIAL CASE: ^\command -- if the command is in LATEX_MAP,
         * emit its Unicode DIRECTLY (dropping the `^`). This makes
         * `T=0^\circ\text{C}` render as `T=0°C` -- the ° symbol is
         * already "superscript-like" so `^°` would be redundant. */
        if ((c == '^' || c == '_') && sp + 1 < src_len && src[sp + 1] == '\\') {
            int idx = latex_match_at(src, src_len, sp + 1);
            if (idx >= 0) {
                size_t tlen = strlen(LATEX_MAP[idx].tex);
                ltx_puts(dst, &dp, dst_cap, LATEX_MAP[idx].uni);
                sp += 1 + tlen;
                continue;
            }
        }

        /* Bare ^X where X is a single ASCII char (digit/letter/op).
         * Convert to Unicode superscript if possible.
         *
         * Same chemistry-friendly rule as `_`: single-digit sup can be
         * followed by a letter (e.g. `x^2y` = `x²y`), which is standard
         * math notation. Only reject if it's followed by another digit
         * (multi-digit sup -- requires braces). */
        if (c == '^' && sp + 1 < src_len) {
            char nx = src[sp + 1];
            int is_digit = (nx >= '0' && nx <= '9');
            int at_boundary = (sp + 2 >= src_len) ||
                (!(src[sp + 2] >= '0' && src[sp + 2] <= '9') &&
                 !(src[sp + 2] >= 'a' && src[sp + 2] <= 'z') &&
                 !(src[sp + 2] >= 'A' && src[sp + 2] <= 'Z'));
            const char *uni = sup_of(nx);
            int digit_ok = is_digit && (sp + 2 >= src_len ||
                                          !(src[sp + 2] >= '0' && src[sp + 2] <= '9'));
            if (uni && (at_boundary || digit_ok)) {
                ltx_puts(dst, &dp, dst_cap, uni);
                sp += 2;
                continue;
            }
        }
        /* Bare _X analogous -- with a special case for chemistry:
         * `H_2O` and `CO_2` are ubiquitous, so allow single-digit
         * subscript even when followed by another letter. `x_ab`
         * (unlikely in real math) still stays literal because
         * we only subscript the single digit. */
        if (c == '_' && sp + 1 < src_len) {
            char nx = src[sp + 1];
            int is_digit = (nx >= '0' && nx <= '9');
            int at_boundary = (sp + 2 >= src_len) ||
                (!(src[sp + 2] >= '0' && src[sp + 2] <= '9') &&
                 !(src[sp + 2] >= 'a' && src[sp + 2] <= 'z') &&
                 !(src[sp + 2] >= 'A' && src[sp + 2] <= 'Z'));
            const char *uni = sub_of(nx);
            /* Chemistry-friendly: single-digit sub can be followed by a
             * letter (H_2O) but not another digit (which would be a
             * multi-digit subscript that should use `_{...}` form). */
            int digit_ok = is_digit && (sp + 2 >= src_len ||
                                          !(src[sp + 2] >= '0' && src[sp + 2] <= '9'));
            if (uni && (at_boundary || digit_ok)) {
                ltx_puts(dst, &dp, dst_cap, uni);
                sp += 2;
                continue;
            }
        }

        /* Known backslash commands via LATEX_MAP. */
        if (c == '\\' && sp + 1 < src_len) {
            int idx = latex_match_at(src, src_len, sp);
            if (idx >= 0) {
                size_t tlen = strlen(LATEX_MAP[idx].tex);
                const char *uni = LATEX_MAP[idx].uni;
                size_t ulen = strlen(uni);
                ltx_puts(dst, &dp, dst_cap, uni);
                sp += tlen;
                /* Empty replacements (\left, \right, thin-space, etc.)
                 * consume an adjacent space to avoid doubled spaces. */
                if (ulen == 0 && sp < src_len && src[sp] == ' ') {
                    if (dp > 0 && dst[dp - 1] == ' ') sp++;
                }
                continue;
            }
            /* Unknown \command -- if followed by `{...}`, safest is to
             * silently drop the command name and emit the content
             * (so `\weird{content}` becomes `content`). This handles
             * long-tail LaTeX (`\mathbb{R}` -> `R`) even without adding
             * every package's symbols to LATEX_MAP.
             *
             * If NOT followed by `{`, preserve as literal `\name` so
             * user sees something didn't convert (helps diagnose new
             * symbols worth adding to the map). */
            size_t after_bs = sp + 1;
            /* Find end of command word. */
            size_t word_end = after_bs;
            while (word_end < src_len &&
                   ((src[word_end] >= 'a' && src[word_end] <= 'z') ||
                    (src[word_end] >= 'A' && src[word_end] <= 'Z'))) {
                word_end++;
            }
            if (word_end > after_bs && word_end < src_len && src[word_end] == '{') {
                /* Drop command name, recurse on {content}. */
                size_t inner_start = word_end + 1;
                size_t inner_end = latex_skip_brace(src, src_len, word_end);
                size_t after = (inner_end < src_len) ? inner_end + 1 : src_len;
                char inner_buf[1024];
                size_t il = latex_to_unicode(src + inner_start,
                                              inner_end - inner_start,
                                              inner_buf, sizeof(inner_buf) - 1);
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
                sp = after;
                continue;
            }
            /* No braces after -- emit `\name` verbatim for diagnostic. */
            ltx_putc(dst, &dp, dst_cap, '\\');
            sp = after_bs;
            while (sp < word_end) ltx_putc(dst, &dp, dst_cap, src[sp++]);
            continue;
        }

        /* Strip stray { } (LaTeX grouping -- no meaning in prose). */
        if (c == '{' || c == '}') {
            sp++;
            continue;
        }

        /* & in a plain (non-env) context: column separator in a
         * partial matrix or misuse. Emit a space so text doesn't
         * jam together. */
        if (c == '&') {
            ltx_putc(dst, &dp, dst_cap, ' ');
            sp++;
            continue;
        }

        /* Default: copy verbatim (includes UTF-8 multibyte chars). */
        ltx_putc(dst, &dp, dst_cap, c);
        sp++;
    }
    return dp;
}

/* ── Environment renderer implementation ──────────────────────────
 *
 * Splits body on `\\` (row separators) and `&` (column separators),
 * recursively converts each cell, then formats with appropriate
 * bracket / alignment style.
 *
 * Supported environments:
 *   matrix, pmatrix, bmatrix, Bmatrix, vmatrix, Vmatrix, smallmatrix
 *   array   (columns spec { }|c|c|| ignored -- same as matrix)
 *   cases   (open brace on left, right-aligned second col)
 *   align, aligned, gather, gathered, split, multline, eqnarray,
 *   subarray (all treat & as space + \\ as newline)
 *   equation (single-line, treat \\ as newline just in case) */
static size_t latex_render_env(const char *env, size_t env_len,
                                const char *body, size_t body_len,
                                char *dst, size_t dst_cap) {
    /* Copy env name into local for strcmp-style dispatch. */
    char env_buf[32];
    size_t n = env_len > sizeof(env_buf) - 1 ? sizeof(env_buf) - 1 : env_len;
    memcpy(env_buf, env, n);
    env_buf[n] = 0;
    /* Strip trailing `*` (starred variants like `align*`). */
    if (n > 0 && env_buf[n - 1] == '*') env_buf[--n] = 0;

    /* Detect matrix-family + bracket style. */
    int is_matrix = 0;
    const char *bracket_open = "";
    const char *bracket_close = "";
    if (strcmp(env_buf, "matrix") == 0 ||
        strcmp(env_buf, "smallmatrix") == 0 ||
        strcmp(env_buf, "array") == 0) {
        is_matrix = 1;
    } else if (strcmp(env_buf, "pmatrix") == 0) {
        is_matrix = 1;
        bracket_open  = "( ";
        bracket_close = " )";
    } else if (strcmp(env_buf, "bmatrix") == 0) {
        is_matrix = 1;
        bracket_open  = "[ ";
        bracket_close = " ]";
    } else if (strcmp(env_buf, "Bmatrix") == 0) {
        is_matrix = 1;
        bracket_open  = "{ ";
        bracket_close = " }";
    } else if (strcmp(env_buf, "vmatrix") == 0) {
        is_matrix = 1;
        bracket_open  = "| ";
        bracket_close = " |";
    } else if (strcmp(env_buf, "Vmatrix") == 0) {
        is_matrix = 1;
        bracket_open  = "\xE2\x80\x96 ";      /* ‖ */
        bracket_close = " \xE2\x80\x96";
    }

    int is_cases = (strcmp(env_buf, "cases") == 0 ||
                    strcmp(env_buf, "dcases") == 0);

    /* Skip initial `[colspec]` block for `array` env. */
    size_t bp = 0;
    if (strcmp(env_buf, "array") == 0 && bp < body_len && body[bp] == '{') {
        while (bp < body_len && body[bp] != '}') bp++;
        if (bp < body_len) bp++;
    }
    /* Skip a leading `{...}` alignment spec for align etc. -- rare. */

    /* Skip leading whitespace/newlines. */
    while (bp < body_len && (body[bp] == ' ' || body[bp] == '\t' ||
                             body[bp] == '\n' || body[bp] == '\r')) bp++;

    /* Body sub-body. */
    const char *sub = body + bp;
    size_t sub_len = body_len - bp;
    /* Trim trailing whitespace + optional trailing `\\`. */
    while (sub_len > 0 && (sub[sub_len - 1] == ' ' || sub[sub_len - 1] == '\t' ||
                            sub[sub_len - 1] == '\n' || sub[sub_len - 1] == '\r')) sub_len--;
    if (sub_len >= 2 && sub[sub_len - 2] == '\\' && sub[sub_len - 1] == '\\') sub_len -= 2;

    size_t dp = 0;

    /* Split rows on `\\` (respecting brace nesting). */
    size_t rp = 0;
    int row_idx = 0;
    while (rp < sub_len) {
        /* Find next `\\` at same brace depth. */
        size_t row_end = rp;
        int depth = 0;
        while (row_end < sub_len) {
            char cc = sub[row_end];
            if (cc == '{') depth++;
            else if (cc == '}' && depth > 0) depth--;
            else if (cc == '\\' && row_end + 1 < sub_len &&
                     sub[row_end + 1] == '\\' && depth == 0) break;
            row_end++;
        }
        /* Trim whitespace from row bounds. */
        size_t r_start = rp;
        size_t r_end = row_end;
        while (r_start < r_end && (sub[r_start] == ' ' || sub[r_start] == '\t' ||
                                    sub[r_start] == '\n' || sub[r_start] == '\r')) r_start++;
        while (r_end > r_start && (sub[r_end - 1] == ' ' || sub[r_end - 1] == '\t' ||
                                    sub[r_end - 1] == '\n' || sub[r_end - 1] == '\r')) r_end--;

        if (r_end > r_start) {
            if (row_idx > 0) ltx_putc(dst, &dp, dst_cap, '\n');
            /* Cases: open brace on FIRST row, continuation ⎨ on later. */
            if (is_cases && row_idx == 0) ltx_puts(dst, &dp, dst_cap, "\xE2\x8E\xA7 ");   /* ⎧ */
            else if (is_cases) ltx_puts(dst, &dp, dst_cap, "\xE2\x8E\xA8 ");              /* ⎨ */
            else if (bracket_open[0]) {
                /* Matrix: emit opening bracket on EVERY row for readability.
                 * Ideal LaTeX rendering uses tall stretchy brackets, but
                 * text-mode text-art works better with per-row brackets. */
                ltx_puts(dst, &dp, dst_cap, bracket_open);
            }

            /* Split cells on `&`. */
            size_t cp = r_start;
            int col_idx = 0;
            while (cp < r_end) {
                size_t cell_end = cp;
                int cd = 0;
                while (cell_end < r_end) {
                    char cc = sub[cell_end];
                    if (cc == '{') cd++;
                    else if (cc == '}' && cd > 0) cd--;
                    else if (cc == '&' && cd == 0) break;
                    else if (cc == '\\' && cell_end + 1 < r_end &&
                             sub[cell_end + 1] == '\\' && cd == 0) break;
                    cell_end++;
                }
                /* Trim cell. */
                size_t c_start = cp, c_end = cell_end;
                while (c_start < c_end && (sub[c_start] == ' ' || sub[c_start] == '\t')) c_start++;
                while (c_end > c_start && (sub[c_end - 1] == ' ' || sub[c_end - 1] == '\t')) c_end--;
                if (col_idx > 0) {
                    /* cases: 2 spaces to visually separate expr from condition. */
                    if (is_cases) ltx_puts(dst, &dp, dst_cap, "  if  ");
                    else ltx_puts(dst, &dp, dst_cap, "  ");
                }
                char cell_buf[512];
                size_t cl = latex_to_unicode(sub + c_start, c_end - c_start,
                                              cell_buf, sizeof(cell_buf) - 1);
                ltx_put(dst, &dp, dst_cap, cell_buf, cl);
                cp = (cell_end < r_end) ? cell_end + 1 : r_end;
                col_idx++;
            }

            if (bracket_close[0] && !is_cases) {
                /* Only close on the LAST row for matrices. We don't know
                 * ahead if this IS the last row, so close every row (visual
                 * approximation -- tall matrices show brackets on each
                 * row, which is imperfect but readable). */
                ltx_puts(dst, &dp, dst_cap, bracket_close);
            }
            row_idx++;
        }
        rp = (row_end < sub_len) ? row_end + 2 : sub_len;
        /* Skip optional `[N]` spacing after \\. */
        if (rp < sub_len && sub[rp] == '[') {
            while (rp < sub_len && sub[rp] != ']') rp++;
            if (rp < sub_len) rp++;
        }
    }
    (void)is_matrix;
    return dp;
}

#endif /* SVCLDB_LATEX_CONVERT_H */