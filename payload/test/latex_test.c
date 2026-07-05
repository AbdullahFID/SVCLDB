/* latex_test.c — standalone unit test for latex_to_unicode.
 *
 * Copies just the converter code out of imgui_layer.cpp so we can
 * exercise it without booting DWM. Run:
 *   cl /nologo /W3 /O2 latex_test.c && latex_test.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── PASTE MATCHING LATEX MAP + latex_to_unicode from imgui_layer.cpp ── */

struct latex_map_entry {
    const char *tex;
    const char *uni;
};

static const struct latex_map_entry LATEX_MAP[] = {
    { "\\left", "" }, { "\\right", "" }, { "\\!", "" }, { "\\,", "" },
    { "\\;", "" }, { "\\:", "" }, { "\\quad", "  " }, { "\\qquad", "    " },
    { "\\log", "log" }, { "\\ln", "ln" }, { "\\exp", "exp" },
    { "\\sin", "sin" }, { "\\cos", "cos" }, { "\\tan", "tan" },
    { "\\lim", "lim" }, { "\\max", "max" }, { "\\min", "min" },
    { "\\Rightarrow", "\xE2\x87\x92" }, { "\\Leftarrow", "\xE2\x87\x90" },
    { "\\rightarrow", "\xE2\x86\x92" }, { "\\leftarrow", "\xE2\x86\x90" },
    { "\\to", "\xE2\x86\x92" },
    { "\\approx", "\xE2\x89\x88" }, { "\\equiv", "\xE2\x89\xA1" },
    { "\\leq", "\xE2\x89\xA4" }, { "\\geq", "\xE2\x89\xA5" },
    { "\\le", "\xE2\x89\xA4" }, { "\\ge", "\xE2\x89\xA5" },
    { "\\neq", "\xE2\x89\xA0" }, { "\\ne", "\xE2\x89\xA0" },
    { "\\pm", "\xC2\xB1" }, { "\\times", "\xC3\x97" }, { "\\cdot", "\xC2\xB7" },
    { "\\in", "\xE2\x88\x88" }, { "\\notin", "\xE2\x88\x89" },
    { "\\subset", "\xE2\x8A\x82" }, { "\\cup", "\xE2\x88\xAA" }, { "\\cap", "\xE2\x88\xA9" },
    { "\\forall", "\xE2\x88\x80" }, { "\\exists", "\xE2\x88\x83" },
    { "\\int", "\xE2\x88\xAB" }, { "\\sum", "\xE2\x88\x91" }, { "\\prod", "\xE2\x88\x8F" },
    { "\\partial", "\xE2\x88\x82" }, { "\\nabla", "\xE2\x88\x87" },
    { "\\infty", "\xE2\x88\x9E" },
    { "\\alpha", "\xCE\xB1" }, { "\\beta", "\xCE\xB2" }, { "\\gamma", "\xCE\xB3" },
    { "\\delta", "\xCE\xB4" }, { "\\epsilon", "\xCE\xB5" },
    { "\\theta", "\xCE\xB8" }, { "\\lambda", "\xCE\xBB" }, { "\\mu", "\xCE\xBC" },
    { "\\pi", "\xCF\x80" }, { "\\rho", "\xCF\x81" }, { "\\sigma", "\xCF\x83" },
    { "\\tau", "\xCF\x84" }, { "\\phi", "\xCF\x86" }, { "\\chi", "\xCF\x87" },
    { "\\psi", "\xCF\x88" }, { "\\omega", "\xCF\x89" },
    { "\\Gamma", "\xCE\x93" }, { "\\Delta", "\xCE\x94" }, { "\\Theta", "\xCE\x98" },
    { "\\Lambda", "\xCE\x9B" }, { "\\Pi", "\xCE\xA0" }, { "\\Sigma", "\xCE\xA3" },
    { "\\Phi", "\xCE\xA6" }, { "\\Omega", "\xCE\xA9" },
    { "\\degree", "\xC2\xB0" }, { "\\ell", "\xE2\x84\x93" },
    { "\\dots", "\xE2\x80\xA6" }, { "\\ldots", "\xE2\x80\xA6" },
    { "\\cdots", "\xE2\x8B\xAF" },
    { NULL, NULL }
};

static const char *SUP_DIGITS[10] = {
    "\xE2\x81\xB0", "\xC2\xB9",     "\xC2\xB2",     "\xC2\xB3",
    "\xE2\x81\xB4", "\xE2\x81\xB5", "\xE2\x81\xB6", "\xE2\x81\xB7",
    "\xE2\x81\xB8", "\xE2\x81\xB9"
};

static int latex_match_at(const char *src, size_t src_len, size_t pos) {
    for (int i = 0; LATEX_MAP[i].tex; i++) {
        size_t tlen = strlen(LATEX_MAP[i].tex);
        if (pos + tlen > src_len) continue;
        if (memcmp(src + pos, LATEX_MAP[i].tex, tlen) != 0) continue;
        if (pos + tlen < src_len) {
            char nx = src[pos + tlen];
            if ((nx >= 'a' && nx <= 'z') || (nx >= 'A' && nx <= 'Z')) continue;
        }
        return i;
    }
    return -1;
}

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

static size_t latex_to_unicode(const char *src, size_t src_len,
                               char *dst, size_t dst_cap) {
    size_t sp = 0, dp = 0;
    while (sp < src_len && dp + 1 < dst_cap) {
        char c = src[sp];

        if (c == '$') {
            sp++;
            if (sp < src_len && src[sp] == '$') sp++;
            continue;
        }
        if (c == '\\' && sp + 1 < src_len &&
            (src[sp + 1] == '(' || src[sp + 1] == ')')) {
            sp += 2; continue;
        }
        if (c == '\\' && sp + 1 < src_len &&
            (src[sp + 1] == '[' || src[sp + 1] == ']')) {
            sp += 2; continue;
        }

        if (c == '\\' && sp + 5 <= src_len &&
            memcmp(src + sp, "\\frac", 5) == 0 &&
            (sp + 5 == src_len || src[sp + 5] == '{')) {
            size_t p = sp + 5;
            if (p < src_len && src[p] == '{') {
                p++;
                size_t num_start = p; int depth = 1;
                while (p < src_len && depth > 0) {
                    if (src[p] == '{') depth++;
                    else if (src[p] == '}') { depth--; if (depth == 0) break; }
                    p++;
                }
                size_t num_end = p;
                if (p < src_len && src[p] == '}') p++;
                if (p < src_len && src[p] == '{') {
                    p++;
                    size_t den_start = p; depth = 1;
                    while (p < src_len && depth > 0) {
                        if (src[p] == '{') depth++;
                        else if (src[p] == '}') { depth--; if (depth == 0) break; }
                        p++;
                    }
                    size_t den_end = p;
                    if (p < src_len && src[p] == '}') p++;
                    char num_buf[512], den_buf[512];
                    size_t nl = latex_to_unicode(src + num_start, num_end - num_start, num_buf, sizeof(num_buf) - 1);
                    num_buf[nl] = 0;
                    size_t dl = latex_to_unicode(src + den_start, den_end - den_start, den_buf, sizeof(den_buf) - 1);
                    den_buf[dl] = 0;
                    int wrap_num = 0, wrap_den = 0;
                    for (size_t k = 0; k < nl; k++) {
                        char nc = num_buf[k];
                        if (nc == '+' || nc == '-' || nc == ' ' || nc == '*' || nc == '/') {
                            wrap_num = 1; break;
                        }
                    }
                    int den_has_letter = 0;
                    for (size_t k = 0; k < dl; k++) {
                        char nc = den_buf[k];
                        if (nc == '+' || nc == '-' || nc == ' ' || nc == '*' || nc == '/') {
                            wrap_den = 1; break;
                        }
                        if ((nc >= 'a' && nc <= 'z') || (nc >= 'A' && nc <= 'Z')) {
                            den_has_letter = 1;
                        }
                    }
                    if (!wrap_den && dl > 1 && den_has_letter) wrap_den = 1;
                    if (wrap_num) ltx_putc(dst, &dp, dst_cap, '(');
                    ltx_put(dst, &dp, dst_cap, num_buf, nl);
                    if (wrap_num) ltx_putc(dst, &dp, dst_cap, ')');
                    ltx_putc(dst, &dp, dst_cap, '/');
                    if (wrap_den) ltx_putc(dst, &dp, dst_cap, '(');
                    ltx_put(dst, &dp, dst_cap, den_buf, dl);
                    if (wrap_den) ltx_putc(dst, &dp, dst_cap, ')');
                    sp = p;
                    continue;
                }
            }
        }

        if (c == '\\' && sp + 5 <= src_len &&
            memcmp(src + sp, "\\sqrt", 5) == 0 &&
            (sp + 5 == src_len || src[sp + 5] == '{')) {
            size_t p = sp + 5;
            ltx_puts(dst, &dp, dst_cap, "\xE2\x88\x9A");
            if (p < src_len && src[p] == '{') {
                p++;
                size_t inner_start = p; int depth = 1;
                while (p < src_len && depth > 0) {
                    if (src[p] == '{') depth++;
                    else if (src[p] == '}') { depth--; if (depth == 0) break; }
                    p++;
                }
                size_t inner_end = p;
                if (p < src_len && src[p] == '}') p++;
                char inner_buf[512];
                size_t il = latex_to_unicode(src + inner_start, inner_end - inner_start, inner_buf, sizeof(inner_buf) - 1);
                inner_buf[il] = 0;
                int wrap = (il > 1);
                if (wrap) ltx_putc(dst, &dp, dst_cap, '(');
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
                if (wrap) ltx_putc(dst, &dp, dst_cap, ')');
                sp = p;
                continue;
            } else {
                sp += 5;
                continue;
            }
        }

        if ((c == '^' || c == '_') && sp + 1 < src_len && src[sp + 1] == '{') {
            char op = c;
            sp += 2;
            size_t inner_start = sp; int depth = 1;
            while (sp < src_len && depth > 0) {
                if (src[sp] == '{') depth++;
                else if (src[sp] == '}') { depth--; if (depth == 0) break; }
                sp++;
            }
            size_t inner_end = sp;
            if (sp < src_len && src[sp] == '}') sp++;
            size_t ilen = inner_end - inner_start;
            if (op == '^' && ilen == 1 &&
                src[inner_start] >= '0' && src[inner_start] <= '9') {
                ltx_puts(dst, &dp, dst_cap, SUP_DIGITS[src[inner_start] - '0']);
            } else {
                ltx_putc(dst, &dp, dst_cap, op);
                char inner_buf[512];
                size_t il = latex_to_unicode(src + inner_start, ilen,
                                              inner_buf, sizeof(inner_buf) - 1);
                inner_buf[il] = 0;
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
            }
            continue;
        }

        if (c == '^' && sp + 1 < src_len &&
            src[sp + 1] >= '0' && src[sp + 1] <= '9' &&
            (sp + 2 == src_len ||
             (!(src[sp + 2] >= '0' && src[sp + 2] <= '9') &&
              !(src[sp + 2] >= 'a' && src[sp + 2] <= 'z') &&
              !(src[sp + 2] >= 'A' && src[sp + 2] <= 'Z')))) {
            ltx_puts(dst, &dp, dst_cap, SUP_DIGITS[src[sp + 1] - '0']);
            sp += 2;
            continue;
        }

        if (c == '\\' && sp + 1 < src_len) {
            int idx = latex_match_at(src, src_len, sp);
            if (idx >= 0) {
                size_t tlen = strlen(LATEX_MAP[idx].tex);
                const char *uni = LATEX_MAP[idx].uni;
                size_t ulen = strlen(uni);
                ltx_puts(dst, &dp, dst_cap, uni);
                sp += tlen;
                if (ulen == 0 && sp < src_len && src[sp] == ' ') {
                    if (dp > 0 && dst[dp - 1] == ' ') sp++;
                }
                continue;
            }
            ltx_putc(dst, &dp, dst_cap, '\\');
            sp++;
            while (sp < src_len && ((src[sp] >= 'a' && src[sp] <= 'z') ||
                                     (src[sp] >= 'A' && src[sp] <= 'Z'))) {
                ltx_putc(dst, &dp, dst_cap, src[sp++]);
            }
            continue;
        }

        if (c == '{' || c == '}') { sp++; continue; }

        ltx_putc(dst, &dp, dst_cap, c);
        sp++;
    }
    return dp;
}

/* ── test harness ── */

static int test_count = 0;
static int test_pass = 0;

static void test_case(const char *desc, const char *input, const char *expected) {
    test_count++;
    char out[1024];
    size_t ol = latex_to_unicode(input, strlen(input), out, sizeof(out) - 1);
    out[ol] = 0;
    int pass = (strcmp(out, expected) == 0);
    if (pass) test_pass++;
    printf("[%s] %s\n", pass ? "PASS" : "FAIL", desc);
    printf("   in:  %s\n", input);
    printf("   out: %s\n", out);
    printf("   exp: %s\n", expected);
    if (!pass) printf("   *** MISMATCH ***\n");
    printf("\n");
}

int main(void) {
    /* Windows console UTF-8. */
    SetConsoleOutputCP(65001);

    /* Test 1: Simple inline dollar */
    test_case("simple $..$",
              "Merge sort time: $O(n \\log n)$ best.",
              "Merge sort time: O(n log n) best.");

    /* Test 2: Recurrence */
    test_case("recurrence $T(n) = 2T(n/2) + O(n)$",
              "$T(n) = 2T(n/2) + O(n)$",
              "T(n) = 2T(n/2) + O(n)");

    /* Test 3: Theta with capital greek */
    test_case("$\\Theta(n \\log n)$",
              "Result: $T(n) = \\Theta(n \\log n)$",
              "Result: T(n) = \xCE\x98(n log n)");

    /* Test 4: Fraction */
    test_case("$\\frac{1}{2}$",
              "Half is $\\frac{1}{2}$.",
              "Half is 1/2.");

    /* Test 5: Fraction with expression */
    test_case("$\\frac{a+b}{c-d}$",
              "$\\frac{a+b}{c-d}$",
              "(a+b)/(c-d)");

    /* Test 6: Sqrt */
    test_case("$\\sqrt{x}$",
              "$\\sqrt{x}$",
              "\xE2\x88\x9Ax");

    /* Test 7: Sqrt with expression */
    test_case("$\\sqrt{b^2 - 4ac}$",
              "$\\sqrt{b^2 - 4ac}$",
              "\xE2\x88\x9A(b\xC2\xB2 - 4ac)");

    /* Test 8: Superscript digit */
    test_case("$x^2 + y^2 = z^2$",
              "$x^2 + y^2 = z^2$",
              "x\xC2\xB2 + y\xC2\xB2 = z\xC2\xB2");

    /* Test 9: Sum + Sigma */
    test_case("Sigma sum",
              "$\\sum_{i=1}^{n} i = \\frac{n(n+1)}{2}$",
              "\xE2\x88\x91_i=1^n i = (n(n+1))/2");

    /* Test 10: Integral */
    test_case("Integral",
              "$\\int_0^1 x^2 \\, dx = \\frac{1}{3}$",
              "\xE2\x88\xAB_0\xC2\xB9 x\xC2\xB2 dx = 1/3");

    /* Test 11: Multi-symbol. Note \mathbb is unknown, kept as-is;
     * braces stripped so `\mathbb{R}` becomes `\mathbbR`. */
    test_case("Set + logic",
              "$\\forall x \\in \\mathbb{R}, x^2 \\geq 0$",
              "\xE2\x88\x80 x \xE2\x88\x88 \\mathbbR, x\xC2\xB2 \xE2\x89\xA5 0");

    /* Test 12: \(..\) delimiter */
    test_case("\\(..\\) delim",
              "Formula: \\(a^2 + b^2 = c^2\\).",
              "Formula: a\xC2\xB2 + b\xC2\xB2 = c\xC2\xB2.");

    /* Test 13: $$..$$ display */
    test_case("$$..$$",
              "$$E = mc^2$$",
              "E = mc\xC2\xB2");

    /* Test 14: Arrow */
    test_case("Arrow",
              "$f: A \\to B$",
              "f: A \xE2\x86\x92 B");

    /* Test 15: LaTeX in middle of prose */
    test_case("Mixed prose",
              "The quadratic formula is $x = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}$ (memorize it).",
              "The quadratic formula is x = (-b \xC2\xB1 \xE2\x88\x9A(b\xC2\xB2 - 4ac))/(2a) (memorize it).");

    printf("\n=== SUMMARY ===\n");
    printf("Pass: %d / %d\n", test_pass, test_count);
    return (test_pass == test_count) ? 0 : 1;
}
