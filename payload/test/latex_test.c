/* latex_test.c: unit tests for the LaTeX-to-Unicode converter.
 *
 * Build + run (from repo root):
   cd payload\test
   cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && cl /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS latex_test.c && latex_test.exe'
 *
 * The converter code lives in payload/src/ui/latex_convert.h so
 * the test compiles the EXACT SAME code the payload does. No
 * copy-drift risk. If a symbol is missing here just add it to the
 * header. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define _CRT_SECURE_NO_WARNINGS 1

#ifdef _WIN32
#include <windows.h>
#endif

#include "../src/ui/latex_convert.h"


/* ── test harness ── */

static int test_count = 0;
static int test_pass = 0;

static void test_case(const char *desc, const char *input, const char *expected) {
    test_count++;
    char out[4096];
    size_t ol = latex_to_unicode(input, strlen(input), out, sizeof(out) - 1);
    out[ol] = 0;
    int pass = (strcmp(out, expected) == 0);
    if (pass) test_pass++;
    printf("[%s] %s\n", pass ? "PASS" : "FAIL", desc);
    if (!pass) {
        printf("   in:  %s\n", input);
        printf("   out: %s\n", out);
        printf("   exp: %s\n", expected);
        printf("   *** MISMATCH ***\n");
    }
}

int main(void) {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif

    /* ── Basic delimiters ── */
    test_case("simple $..$",
              "Merge sort time: $O(n \\log n)$ best.",
              "Merge sort time: O(n log n) best.");
    test_case("recurrence $T(n) = 2T(n/2) + O(n)$",
              "$T(n) = 2T(n/2) + O(n)$",
              "T(n) = 2T(n/2) + O(n)");
    test_case("$\\Theta(n \\log n)$ (capital Greek)",
              "Result: $T(n) = \\Theta(n \\log n)$",
              "Result: T(n) = \xCE\x98(n log n)");
    test_case("\\(..\\) delim",
              "Formula: \\(a^2 + b^2 = c^2\\).",
              "Formula: a\xC2\xB2 + b\xC2\xB2 = c\xC2\xB2.");
    test_case("$$..$$ display",
              "$$E = mc^2$$",
              "E = mc\xC2\xB2");

    /* ── Fractions ── */
    test_case("vulgar 1/2",
              "Half is $\\frac{1}{2}$.",
              "Half is \xC2\xBD.");
    test_case("vulgar 3/4",
              "$\\frac{3}{4}$ full",
              "\xC2\xBE full");
    test_case("vulgar 1/3",
              "$\\frac{1}{3}$",
              "\xE2\x85\x93");
    test_case("frac expr num/den",
              "$\\frac{a+b}{c-d}$",
              "(a+b)/(c-d)");
    test_case("frac with recursive contents",
              "The quadratic formula is $x = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}$ (memorize it).",
              "The quadratic formula is x = (-b \xC2\xB1 \xE2\x88\x9A(b\xC2\xB2 - 4ac))/(2a) (memorize it).");
    test_case("nested frac",
              "$\\frac{1}{\\frac{1}{2}}$",
              "1/\xC2\xBD");

    /* ── Sqrt ── */
    test_case("sqrt single",
              "$\\sqrt{x}$",
              "\xE2\x88\x9Ax");
    test_case("sqrt expr",
              "$\\sqrt{b^2 - 4ac}$",
              "\xE2\x88\x9A(b\xC2\xB2 - 4ac)");
    test_case("sqrt with nth root (no wrap for numeric)",
              "$\\sqrt[3]{27}$",
              "\xC2\xB3" "\xE2\x88\x9A" "27");

    /* ── Super/subscript ── */
    test_case("superscript digit",
              "$x^2 + y^2 = z^2$",
              "x\xC2\xB2 + y\xC2\xB2 = z\xC2\xB2");
    test_case("superscript letter",
              "$e^x$",
              "e\xCB\xA3");
    test_case("subscript digit",
              "$x_1 + x_2$",
              "x\xE2\x82\x81 + x\xE2\x82\x82");
    test_case("subscript letter i",
              "$a_i$",
              "a\xE1\xB5\xA2");
    test_case("sub multi-char with braces",
              "$T_{max}$",
              "T\xE2\x82\x98\xE2\x82\x90\xE2\x82\x93");
    test_case("sup multi-char with braces",
              "$x^{ab}$",
              "x\xE1\xB5\x83\xE1\xB5\x87");

    /* ── Sum/integral with limits ── */
    test_case("Sigma sum with limits (all-sub Unicode wins)",
              "$\\sum_{i=1}^{n} i$",
              "\xE2\x88\x91\xE1\xB5\xA2\xE2\x82\x8C\xE2\x82\x81\xE2\x81\xBF i");
    test_case("Integral limits",
              "$\\int_0^1 x^2 dx$",
              "\xE2\x88\xAB\xE2\x82\x80\xC2\xB9 x\xC2\xB2 dx");

    /* ── Text wrappers ── */
    test_case("\\text passthrough",
              "$T=0^\\circ\\text{C}$",
              "T=0" "\xE2\x88\x98" "C");
    test_case("\\mathbf passthrough",
              "$\\mathbf{v} = m \\mathbf{a}$",
              "v = m a");
    test_case("\\mathbb{R}",
              "$\\forall x \\in \\mathbb{R}$",
              "\xE2\x88\x80 x \xE2\x88\x88 R");
    test_case("\\text with spaces",
              "$V(T) = 2T + 5\\text{ (linear)}$",
              "V(T) = 2T + 5 (linear)");
    test_case("nested \\mathrm inside \\text",
              "$\\text{units of } \\mathrm{m/s}$",
              "units of  m/s");
    test_case("\\operatorname",
              "$\\operatorname{arg\\,min} f(x)$",
              "argmin f(x)");

    /* ── Accents ── */
    test_case("\\vec{v}",
              "$\\vec{v}$",
              "v\xE2\x83\x97");
    test_case("\\hat{x}",
              "$\\hat{x}$",
              "x\xCC\x82");
    test_case("\\bar{x}",
              "$\\bar{x}$",
              "x\xCC\x84");
    test_case("\\dot{y}",
              "$\\dot{y}$",
              "y\xCC\x87");

    /* ── \left \right \big etc — should be stripped silently ── */
    test_case("\\left \\right stripped",
              "$f(x) = \\left( \\frac{1}{2} \\right)$",
              "f(x) = ( \xC2\xBD )");
    test_case("\\Big delims",
              "$\\Big( x \\Big)$",
              "( x )");
    test_case("\\bigg delims",
              "$\\bigg[ \\frac{a}{b} \\bigg]$",
              "[ a/b ]");

    /* ── \\ line break inside math ── */
    test_case("\\\\ becomes newline",
              "$a = 1 \\\\ b = 2$",
              "a = 1 \nb = 2");

    /* ── Environments ── */
    test_case("pmatrix 2x2",
              "$\\begin{pmatrix} 1 & 2 \\\\ 3 & 4 \\end{pmatrix}$",
              "( 1  2 )\n( 3  4 )");
    test_case("bmatrix 2x2",
              "$\\begin{bmatrix} a & b \\\\ c & d \\end{bmatrix}$",
              "[ a  b ]\n[ c  d ]");
    test_case("vmatrix (determinant)",
              "$\\begin{vmatrix} 1 & 0 \\\\ 0 & 1 \\end{vmatrix}$",
              "| 1  0 |\n| 0  1 |");
    test_case("cases piecewise",
              "$f(x) = \\begin{cases} x & x > 0 \\\\ -x & x \\le 0 \\end{cases}$",
              "f(x) = \xE2\x8E\xA7 x  if  x > 0\n\xE2\x8E\xA8 -x  if  x \xE2\x89\xA4 0");
    test_case("aligned equations",
              "$\\begin{aligned} a &= 1 \\\\ b &= 2 \\end{aligned}$",
              "a  = 1\nb  = 2");

    /* ── Unknown \cmd{content} → drop cmd, keep content ── */
    test_case("unknown \\mathbb \u2192 drop, keep R",
              "$\\mathbb{R}^n$",
              "R\xE2\x81\xBF");
    test_case("unknown \\text{something}",
              "$\\text{something}$",
              "something");
    test_case("unknown \\underbrace + sub is all-mappable",
              "$\\underbrace{1+2+3}_{sum}$",
              "1+2+3\xE2\x82\x9B\xE1\xB5\xA4\xE2\x82\x98");

    /* ── Symbols ── */
    test_case("Set + logic (mixed)",
              "$\\forall x \\in \\mathbb{R}, x^2 \\geq 0$",
              "\xE2\x88\x80 x \xE2\x88\x88 R, x\xC2\xB2 \xE2\x89\xA5 0");
    test_case("Arrow \\to",
              "$f: A \\to B$",
              "f: A \xE2\x86\x92 B");
    test_case("Existential + implies",
              "$\\exists x : P(x) \\implies Q(x)$",
              "\xE2\x88\x83 x : P(x) \xE2\x87\x92 Q(x)");
    test_case("\\pm \\times \\cdot",
              "$a \\pm b \\times c \\cdot d$",
              "a \xC2\xB1 b \xC3\x97 c \xC2\xB7 d");
    test_case("\\lim_{n \\to \\infty} \u2014 sub with space keeps braces",
              "$\\lim_{n \\to \\infty}$",
              "lim_{n \xE2\x86\x92 \xE2\x88\x9E}");

    /* ── LONGEST-MATCH ORDERING (regressions I've seen) ── */
    test_case("\\infty NOT \\int + fty",
              "$\\infty$",
              "\xE2\x88\x9E");
    test_case("\\arcsin NOT \\arc + sin",
              "$\\arcsin(x)$",
              "arcsin(x)");
    test_case("\\Rightarrow NOT \\Right + arrow",
              "$A \\Rightarrow B$",
              "A \xE2\x87\x92 B");
    test_case("\\varepsilon NOT \\var + epsilon",
              "$\\varepsilon > 0$",
              "\xCE\xB5 > 0");
    test_case("\\pi vs \\pion (fake cmd)",
              "$\\pi \\pion$",
              "\xCF\x80 \\pion");

    /* ── Escaped punctuation ── */
    test_case("\\% escape",
              "$50\\%$",
              "50%");
    test_case("\\_ escape",
              "$x\\_1$",
              "x_1");

    /* ── EXACT USER-REPORTED FAILING CASE (last_reply.txt) ── */
    test_case("user Physics: T=0^circ text",
              "$T=0^\\circ\\text{C}$, sensitivity",
              "T=0" "\xE2\x88\x98" "C, sensitivity");
    test_case("user Physics: V(T)=2T+5sin(T/10)",
              "\\[V(T)=2T+5\\sin\\left(\\frac{T}{10}\\right)\\]",
              "V(T)=2T+5sin(T/10)");
    test_case("user Physics: dV/dT (no wrap for simple diffs)",
              "\\[\\frac{dV}{dT}=2+\\frac{5}{10}\\cos\\left(\\frac{T}{10}\\right)\\]",
              "dV/dT=2+5/10cos(T/10)");
    test_case("user Physics: T in [0,30]",
              "$T\\in[0,30]$",
              "T\xE2\x88\x88[0,30]");

    /* ── Real-world complex expressions ── */
    test_case("Gaussian pdf",
              "$f(x) = \\frac{1}{\\sigma\\sqrt{2\\pi}} e^{-\\frac{(x-\\mu)^2}{2\\sigma^2}}$",
              "f(x) = 1/(\xCF\x83" "\xE2\x88\x9A(2\xCF\x80)) e^{-((x-\xCE\xBC)\xC2\xB2)/(2\xCF\x83\xC2\xB2)}");
    test_case("Euler identity (sup with braces preserved)",
              "$e^{i\\pi} + 1 = 0$",
              "e^{i\xCF\x80} + 1 = 0");
    test_case("chain rule (no wrap for simple diffs)",
              "$\\frac{dy}{dx} = \\frac{dy}{du}\\frac{du}{dx}$",
              "dy/dx = dy/du" "du/dx");
    test_case("Fourier",
              "$F(\\omega) = \\int_{-\\infty}^{\\infty} f(t) e^{-i\\omega t} dt$",
              "F(\xCF\x89) = \xE2\x88\xAB_{-\xE2\x88\x9E}^{\xE2\x88\x9E} f(t) e^{-i\xCF\x89 t} dt");
    test_case("Maxwell 3rd (Faraday)",
              "$\\nabla \\times \\vec{E} = -\\frac{\\partial \\vec{B}}{\\partial t}$",
              "\xE2\x88\x87 \xC3\x97 E\xE2\x83\x97 = -(\xE2\x88\x82 B\xE2\x83\x97)/(\xE2\x88\x82 t)");

    /* ── Stress tests: real-world outputs from AI models ── */
    test_case("Bayes theorem (den has parens \u2192 wraps)",
              "$P(A|B) = \\frac{P(B|A)P(A)}{P(B)}$",
              "P(A|B) = (P(B|A)P(A))/(P(B))");
    test_case("Big-O complexity",
              "Insertion sort is $O(n^2)$ average.",
              "Insertion sort is O(n\xC2\xB2) average.");
    test_case("Binomial coefficient (den has parens \u2192 wrap)",
              "$\\binom{n}{k} = \\frac{n!}{k!(n-k)!}$",
              "C(n,k) = n!/(k!(n-k)!)");
    test_case("Cross product",
              "$\\vec{a} \\times \\vec{b} = \\vec{c}$",
              "a\xE2\x83\x97 \xC3\x97 b\xE2\x83\x97 = c\xE2\x83\x97");
    test_case("Dot product",
              "$\\vec{u} \\cdot \\vec{v} = \\sum u_i v_i$",
              "u\xE2\x83\x97 \xC2\xB7 v\xE2\x83\x97 = \xE2\x88\x91 u\xE1\xB5\xA2 v\xE1\xB5\xA2");
    test_case("Piecewise cases with complex conds",
              "$f(x) = \\begin{cases} x^2 & x \\geq 0 \\\\ -x^2 & x < 0 \\end{cases}$",
              "f(x) = \xE2\x8E\xA7 x\xC2\xB2  if  x \xE2\x89\xA5 0\n\xE2\x8E\xA8 -x\xC2\xB2  if  x < 0");
    test_case("Chemical equation with \\to",
              "$2H_2 + O_2 \\to 2H_2O$",
              "2H\xE2\x82\x82 + O\xE2\x82\x82 \xE2\x86\x92 2H\xE2\x82\x82O");
    test_case("Dirac notation",
              "$\\langle \\psi | H | \\psi \\rangle = E$",
              "\xE2\x9F\xA8 \xCF\x88 | H | \xCF\x88 \xE2\x9F\xA9 = E");
    test_case("Riemann sum",
              "$\\int_a^b f(x) dx = \\lim_{n \\to \\infty} \\sum_{i=1}^n f(x_i) \\Delta x$",
              "\xE2\x88\xAB\xE2\x82\x90\xE1\xB5\x87 f(x) dx = lim_{n \xE2\x86\x92 \xE2\x88\x9E} \xE2\x88\x91\xE1\xB5\xA2\xE2\x82\x8C\xE2\x82\x81\xE2\x81\xBF f(x\xE1\xB5\xA2) \xCE\x94 x");
    test_case("Matrix multiplication",
              "$A = \\begin{pmatrix} 1 & 2 & 3 \\\\ 4 & 5 & 6 \\end{pmatrix}$",
              "A = ( 1  2  3 )\n( 4  5  6 )");
    test_case("Nested fractions",
              "$\\frac{a}{\\frac{b}{c}}$",
              "a/(b/c)");
    test_case("Escaped braces \\{ \\}",
              "$\\{ 1, 2, 3 \\}$",
              "{ 1, 2, 3 }");
    test_case("Deg + apostrophe",
              "$45\\degree$",
              "45\xC2\xB0");
    test_case("Standard notation triple bar",
              "$\\vec{v}_x$",
              "v\xE2\x83\x97\xE2\x82\x93");
    test_case("Overline",
              "$\\overline{AB}$",
              "A\xCC\x84" "B\xCC\x84");
    test_case("Curl notation",
              "$\\nabla \\times \\vec{F}$",
              "\xE2\x88\x87 \xC3\x97 F\xE2\x83\x97");
    test_case("Integers Z",
              "For all $n \\in \\mathbb{Z}$",
              "For all n \xE2\x88\x88 Z");
    test_case("Real interval",
              "$x \\in [0, 1]$",
              "x \xE2\x88\x88 [0, 1]");
    test_case("Trig identity",
              "$\\sin^2\\theta + \\cos^2\\theta = 1$",
              "sin\xC2\xB2\xCE\xB8 + cos\xC2\xB2\xCE\xB8 = 1");
    test_case("Logarithm base",
              "$\\log_2 8 = 3$",
              "log\xE2\x82\x82 8 = 3");
    test_case("Complex fraction with binom",
              "$P = \\binom{52}{5}$",
              "P = C(52,5)");
    test_case("Combined \\text and math",
              "$\\text{time} = \\frac{\\text{distance}}{\\text{speed}}$",
              "time = distance/speed");

    /* ── Adversarial: things that could crash the parser ── */
    test_case("Unterminated $ ",
              "Half of $x",
              "Half of x");
    test_case("Unterminated \\frac (best effort)",
              "$\\frac{a}{",
              "a/");
    test_case("Empty braces",
              "$a^{}$",
              "a");
    test_case("Deeply nested (inner has / \u2192 wraps)",
              "$\\frac{\\frac{\\frac{1}{2}}{3}}{4}$",
              "(\xC2\xBD/3)/4");
    test_case("Only backslash",
              "$\\$",
              "$");
    test_case("Real-world Physics screenshot answer",
              "**Answer:** $x = 4$\n\nThe equation is:\n\\[ 2x + 5 = 13 \\]\n\\[ 2x = 8 \\]\n\\[ x = 4 \\]",
              "**Answer:** x = 4\n\nThe equation is:\n 2x + 5 = 13 \n 2x = 8 \n x = 4 ");

    /* ============================================================
     * V7 ADDITIONS (2026-07-06 evening — expanded coverage) — grouped
     * by category. Every test exercises a NEW symbol/wrapper/special
     * that pre-v7 either failed silently or emitted raw LaTeX.
     * ============================================================ */

    /* ── V7: new delimiter aliases ── */
    test_case("v7: \\vert x \\vert = |x|",
              "$\\vert x \\vert = 5$",
              "| x | = 5");
    test_case("v7: \\Vert v \\Vert",
              "$\\Vert v \\Vert$",
              "\xE2\x80\x96 v \xE2\x80\x96");
    test_case("v7: \\lVert v \\rVert",
              "$\\lVert v \\rVert^2$",
              "\xE2\x80\x96 v \xE2\x80\x96\xC2\xB2");
    test_case("v7: \\mid in set-builder",
              "$\\{ x \\mid x > 0 \\}$",
              "{ x \xE2\x88\xA3 x > 0 }");
    test_case("v7: \\lbrace \\rbrace",
              "$\\lbrace 1, 2, 3 \\rbrace$",
              "{ 1, 2, 3 }");
    test_case("v7: \\lbrack \\rbrack",
              "$\\lbrack a, b \\rbrack$",
              "[ a, b ]");
    test_case("v7: \\lparen \\rparen",
              "$\\lparen x \\rparen$",
              "( x )");
    test_case("v7: \\lang \\rang alias",
              "$\\lang \\phi \\rang$",
              "\xE2\x9F\xA8 \xCF\x86 \xE2\x9F\xA9");
    test_case("v7: \\llbracket \\rrbracket",
              "$\\llbracket X \\rrbracket$",
              "\xE2\x9F\xA6 X \xE2\x9F\xA7");
    test_case("v7: \\lceil \\rceil already worked",
              "$\\lceil x \\rceil$",
              "\xE2\x8C\x88 x \xE2\x8C\x89");
    test_case("v7: \\ulcorner \\urcorner",
              "$\\ulcorner X \\urcorner$",
              "\xE2\x8C\x9C X \xE2\x8C\x9D");
    test_case("v7: \\backslash",
              "$a \\backslash b$",
              "a \\ b");

    /* ── V7: shapes + symbols ── */
    test_case("v7: \\top and \\bot",
              "$\\top \\vee \\bot$",
              "\xE2\x8A\xA4 \xE2\x88\xA8 \xE2\x8A\xA5");
    test_case("v7: \\complement",
              "$\\complement A$",
              "\xE2\x88\x81 A");
    test_case("v7: card suits",
              "$\\clubsuit \\diamondsuit \\heartsuit \\spadesuit$",
              "\xE2\x99\xA3 \xE2\x99\xA2 \xE2\x99\xA1 \xE2\x99\xA0");
    test_case("v7: music",
              "$\\flat \\sharp \\natural$",
              "\xE2\x99\xAD \xE2\x99\xAF \xE2\x99\xAE");
    test_case("v7: \\checkmark + \\maltese",
              "$\\checkmark \\maltese$",
              "\xE2\x9C\x93 \xE2\x9C\xA0");
    test_case("v7: currency",
              "$\\pounds 100, \\yen 500, \\euro 50$",
              "\xC2\xA3 100, \xC2\xA5 500, \xE2\x82\xAC 50");
    test_case("v7: \\gt and \\lt aliases",
              "$5 \\gt 3, 2 \\lt 7$",
              "5 > 3, 2 < 7");
    test_case("v7: \\dagger \\ddagger",
              "$a \\dagger b \\ddagger c$",
              "a \xE2\x80\xA0 b \xE2\x80\xA1 c");
    test_case("v7: \\S and \\P",
              "$\\S \\P$",
              "\xC2\xA7 \xC2\xB6");
    test_case("v7: shapes triangle + lozenge",
              "$\\triangle \\lozenge \\bigstar \\Box$",
              "\xE2\x96\xB3 \xE2\x97\x8A \xE2\x98\x85 \xE2\x96\xA1");

    /* ── V7: extended relations ── */
    test_case("v7: \\doteq",
              "$x \\doteq y$",
              "x \xE2\x89\x90 y");
    test_case("v7: \\models and \\vdash",
              "$\\Gamma \\vdash P, M \\models Q$",
              "\xCE\x93 \xE2\x8A\xA2 P, M \xE2\x8A\xA8 Q");
    test_case("v7: \\bowtie",
              "$A \\bowtie B$",
              "A \xE2\x8B\x88 B");
    test_case("v7: \\ncong and \\nsim",
              "$X \\ncong Y, A \\nsim B$",
              "X \xE2\x89\x86 Y, A \xE2\x89\x81 B");
    test_case("v7: \\leqq \\geqq",
              "$a \\leqq b, c \\geqq d$",
              "a \xE2\x89\xA6 b, c \xE2\x89\xA7 d");
    test_case("v7: \\nleq \\ngeq",
              "$x \\nleq y, a \\ngeq b$",
              "x \xE2\x89\xB0 y, a \xE2\x89\xB1 b");
    test_case("v7: \\lessgtr and \\gtrless",
              "$a \\lessgtr b, c \\gtrless d$",
              "a \xE2\x89\xB6 b, c \xE2\x89\xB7 d");
    test_case("v7: \\prec \\succ family",
              "$a \\preceq b \\prec c \\succ d \\succeq e$",
              "a \xE2\xAA\xAF b \xE2\x89\xBA c \xE2\x89\xBB d \xE2\xAA\xB0 e");
    test_case("v7: \\subsetneq \\supsetneq",
              "$A \\subsetneq B, C \\supsetneq D$",
              "A \xE2\x8A\x8A B, C \xE2\x8A\x8B D");
    test_case("v7: \\Subset \\Supset",
              "$A \\Subset B \\Supset C$",
              "A \xE2\x8B\x90 B \xE2\x8B\x91 C");
    test_case("v7: colon relations",
              "$x \\coloneqq 5, y \\eqqcolon 3$",
              "x \xE2\x89\x94 5, y \xE2\x89\x95 3");
    test_case("v7: \\triangleq",
              "$f(x) \\triangleq x^2 + 1$",
              "f(x) \xE2\x89\x9C x\xC2\xB2 + 1");

    /* ── V7: extended arrows ── */
    test_case("v7: \\rightleftharpoons chemistry",
              "$H_2O \\rightleftharpoons H^+ + OH^-$",
              "H\xE2\x82\x82O \xE2\x87\x8C H\xE2\x81\xBA + OH\xE2\x81\xBB");
    test_case("v7: \\rightsquigarrow",
              "$A \\rightsquigarrow B$",
              "A \xE2\x87\x9D B");
    test_case("v7: \\twoheadrightarrow",
              "$f: X \\twoheadrightarrow Y$",
              "f: X \xE2\x86\xA0 Y");
    test_case("v7: dashed arrow",
              "$A \\dashrightarrow B$",
              "A \xE2\x87\xA2 B");
    test_case("v7: \\Rrightarrow",
              "$P \\Rrightarrow Q$",
              "P \xE2\x87\x9B Q");
    test_case("v7: harpoons",
              "$a \\rightharpoonup b \\leftharpoonup c$",
              "a \xE2\x87\x80 b \xE2\x86\xBC c");
    test_case("v7: \\circlearrowright",
              "$\\circlearrowleft \\circlearrowright$",
              "\xE2\x86\xBA \xE2\x86\xBB");
    test_case("v7: \\nrightarrow negation arrow",
              "$A \\nrightarrow B$",
              "A \xE2\x86\x9B B");
    test_case("v7: short arrow aliases",
              "$A \\rarr B \\lArr C$",
              "A \xE2\x86\x92 B \xE2\x87\x90 C");

    /* ── V7: binary operators ── */
    test_case("v7: \\amalg + \\uplus",
              "$A \\amalg B \\uplus C$",
              "A \xE2\xA8\xBF B \xE2\x8A\x8E C");
    test_case("v7: \\sqcap \\sqcup",
              "$A \\sqcap B, X \\sqcup Y$",
              "A \xE2\x8A\x93 B, X \xE2\x8A\x94 Y");
    test_case("v7: \\ltimes \\rtimes semi-direct",
              "$G \\ltimes H, K \\rtimes L$",
              "G \xE2\x8B\x89 H, K \xE2\x8B\x8A L");
    test_case("v7: \\intercal transpose (^\\intercal drops the caret)",
              "$A^\\intercal$",
              "A\xE2\x8A\xBA");   /* ⊺ — same special-case as ^\circ */
    test_case("v7: \\boxplus family",
              "$a \\boxplus b, c \\boxtimes d$",
              "a \xE2\x8A\x9E b, c \xE2\x8A\xA0 d");
    test_case("v7: \\bigodot \\bigoplus",
              "$\\bigodot_{i=1}^n a_i, \\bigoplus_i V_i$",
              "\xE2\xA8\x80\xE1\xB5\xA2\xE2\x82\x8C\xE2\x82\x81\xE2\x81\xBF a\xE1\xB5\xA2, \xE2\xA8\x81\xE1\xB5\xA2 V\xE1\xB5\xA2");
    test_case("v7: \\wr wreath product",
              "$G \\wr H$",
              "G \xE2\x89\x80 H");

    /* ── V7: number-set shortcuts ── */
    test_case("v7: \\R real numbers",
              "$x \\in \\R$",
              "x \xE2\x88\x88 \xE2\x84\x9D");
    test_case("v7: \\N \\Z \\Q",
              "$\\N \\subset \\Z \\subset \\Q \\subset \\R$",
              "\xE2\x84\x95 \xE2\x8A\x82 \xE2\x84\xA4 \xE2\x8A\x82 \xE2\x84\x9A \xE2\x8A\x82 \xE2\x84\x9D");
    test_case("v7: \\C complex",
              "$e^{i\\pi} \\in \\C$",
              "e^{i\xCF\x80} \xE2\x88\x88 \xE2\x84\x82");
    test_case("v7: \\Reals \\Complex long forms",
              "$\\Reals \\Complex$",
              "\xE2\x84\x9D \xE2\x84\x82");

    /* ── V7: Greek variants ── */
    test_case("v7: \\varkappa",
              "$\\varkappa$",
              "\xCF\xB0");
    test_case("v7: \\digamma",
              "$\\digamma$",
              "\xCF\x9D");
    test_case("v7: \\thetasym alias",
              "$\\thetasym = \\vartheta$",
              "\xCF\x91 = \xCF\x91");

    /* ── V7: spacing. Rules:
     *   - Commands that emit a SPACE (thinspace, medspace, quad, ...) —
     *     the source-space AFTER the command is preserved, so `X\Y Z`
     *     becomes `X<space><source-space>Z` = double-space. This is
     *     intentional: preserving source spacing keeps chemistry etc
     *     readable, and doubles are visually indistinguishable in the
     *     overlay's variable-width font.
     *   - Commands that emit EMPTY (negthinspace, !) trigger the
     *     collapse-adjacent-space rule: if the last dst char is a space
     *     AND the next src char is a space, skip the src space. */
    test_case("v7: \\thinspace \\medspace \\thickspace (emit + preserve)",
              "$a\\thinspace b\\medspace c\\thickspace d$",
              "a  b  c  d");
    test_case("v7: \\enspace \\quad \\qquad (varying widths)",
              "$a\\enspace b \\quad c \\qquad d$",
              "a  b    c      d");
    test_case("v7: \\negthinspace collapses adjacent source-space",
              "$a\\negthinspace b$",
              "a b");
    test_case("v7: \\newline emits real newline (source space kept)",
              "$a\\newline b$",
              "a\n b");
    test_case("v7: \\space (source space preserved)",
              "$a\\space b$",
              "a  b");
    test_case("v7: \\And renders as &",
              "$a \\And b$",
              "a & b");

    /* ── V7: fraction synonyms ── */
    test_case("v7: \\dfrac same as \\frac",
              "$\\dfrac{a+b}{c-d}$",
              "(a+b)/(c-d)");
    test_case("v7: \\tfrac same as \\frac",
              "$\\tfrac{1}{2}$",
              "\xC2\xBD");
    test_case("v7: \\cfrac continued fraction flat",
              "$\\cfrac{a}{b}$",
              "a/b");

    /* ── V7: quantum notation ── */
    test_case("v7: \\ket{psi}",
              "$\\ket{\\psi}$",
              "|\xCF\x88\xE2\x9F\xA9");
    test_case("v7: \\bra{psi}",
              "$\\bra{\\psi}$",
              "\xE2\x9F\xA8\xCF\x88|");
    test_case("v7: \\Ket \\Bra (tall variants same)",
              "$\\Bra{a} \\Ket{b}$",
              "\xE2\x9F\xA8" "a| |b" "\xE2\x9F\xA9");
    test_case("v7: \\braket inner product",
              "$\\braket{\\phi | \\psi} = 1$",
              "\xE2\x9F\xA8\xCF\x86 | \xCF\x88\xE2\x9F\xA9 = 1");
    test_case("v7: \\Braket same as braket",
              "$\\Braket{\\phi | H | \\psi}$",
              "\xE2\x9F\xA8\xCF\x86 | H | \xCF\x88\xE2\x9F\xA9");

    /* ── V7: \not prefix ── */
    test_case("v7: \\not= renders as ≠",
              "$a \\not= b$",
              "a \xE2\x89\xA0 b");
    test_case("v7: \\not< renders as ≮",
              "$x \\not< y$",
              "x \xE2\x89\xAE y");
    test_case("v7: \\not> renders as ≯",
              "$x \\not> y$",
              "x \xE2\x89\xAF y");
    test_case("v7: \\not\\in renders as ∉",
              "$x \\not\\in S$",
              "x \xE2\x88\x89 S");
    test_case("v7: \\not\\equiv",
              "$a \\not\\equiv b \\pmod{5}$",
              "a \xE2\x89\xA2 b (mod 5)");
    test_case("v7: \\not\\subset",
              "$A \\not\\subset B$",
              "A \xE2\x8A\x84 B");
    test_case("v7: \\not\\sim",
              "$a \\not\\sim b$",
              "a \xE2\x89\x81 b");
    test_case("v7: \\not\\leq",
              "$x \\not\\leq y$",
              "x \xE2\x89\xB0 y");
    test_case("v7: \\not with unknown fallback (combining slash)",
              "$a \\not\\propto b$",
              "a \xE2\x88\x9D\xCC\xB8 b");

    /* ── V7: modular arithmetic ── */
    test_case("v7: \\pmod adds parens",
              "$a \\equiv b \\pmod{7}$",
              "a \xE2\x89\xA1 b (mod 7)");
    test_case("v7: \\bmod stays bare",
              "$17 \\bmod 5 = 2$",
              "17 mod 5 = 2");

    /* ── V7: overset/underset/stackrel ── */
    test_case("v7: \\overset digit",
              "$\\overset{5}{=}$",
              "=\xE2\x81\xB5");
    test_case("v7: \\stackrel def",
              "$\\stackrel{\\text{def}}{=}$",
              "=\xE1\xB5\x88\xE1\xB5\x89\xE1\xB6\xA0");   /* =ᵈᵉᶠ */
    test_case("v7: \\underset limit",
              "$\\underset{x \\to 0}{\\lim} f(x)$",
              "lim_{x \xE2\x86\x92 0} f(x)");

    /* ── V7: cancel/boxed/sout wrappers ── */
    test_case("v7: \\cancel keeps content",
              "$\\cancel{5}$",
              "5");
    test_case("v7: \\bcancel keeps content",
              "$\\bcancel{X + Y}$",
              "X + Y");
    test_case("v7: \\xcancel keeps content",
              "$\\xcancel{ABC}$",
              "ABC");
    test_case("v7: \\boxed keeps content",
              "$\\boxed{x = 4}$",
              "x = 4");
    test_case("v7: \\fbox keeps content",
              "$\\fbox{Hello}$",
              "Hello");
    test_case("v7: \\pmb keeps content",
              "$\\pmb{\\mu}$",
              "\xCE\xBC");
    test_case("v7: \\sout strikethrough — keep content",
              "$\\sout{gone}$",
              "gone");
    test_case("v7: \\Bbb same as \\mathbb (wrapper)",
              "$\\Bbb{R}^n$",
              "R\xE2\x81\xBF");

    /* ── V7: overbrace/underbrace + labels ── */
    test_case("v7: \\overbrace with sup label",
              "$\\overbrace{a+b+c}^{sum}$",
              "a+b+c\xCB\xA2\xE1\xB5\x98\xE1\xB5\x90");   /* a+b+cˢᵘᵐ */
    test_case("v7: \\underbrace with sub label",
              "$\\underbrace{1+2+3}_{sum}$",
              "1+2+3\xE2\x82\x9B\xE1\xB5\xA4\xE2\x82\x98");   /* 1+2+3ₛᵤₘ */

    /* ── V7: \ang for angles ── */
    test_case("v7: \\ang{45}",
              "$\\ang{45}$",
              "45\xC2\xB0");
    test_case("v7: \\ang{90}",
              "$\\ang{90}$",
              "90\xC2\xB0");

    /* ── V7: \href drops URL, keeps text ── */
    test_case("v7: \\href drops URL",
              "$\\href{https://example.com}{click here}$",
              "click here");

    /* ── V7: \hspace / \vspace drop cmd + arg + emit space ── */
    test_case("v7: \\hspace{2em}",
              "$a\\hspace{2em}b$",
              "a b");
    test_case("v7: \\hspace* variant",
              "$a\\hspace*{1cm}b$",
              "a b");
    test_case("v7: \\vspace",
              "$a\\vspace{1em}b$",
              "a b");
    test_case("v7: \\kern with unit (space then source-space)",
              "$a\\kern2pt b$",
              "a  b");

    /* ── V7: KaTeX/TeX branding ── */
    test_case("v7: \\KaTeX renders as literal",
              "Uses \\KaTeX for math",
              "Uses KaTeX for math");
    test_case("v7: \\LaTeX \\TeX",
              "Written in \\LaTeX (based on \\TeX)",
              "Written in LaTeX (based on TeX)");

    /* ── V7: Real-world AI outputs stress test ── */
    test_case("v7: derivative rule (sup n-1 fully unicoded)",
              "$\\frac{d}{dx}\\left(x^n\\right) = nx^{n-1}$",
              "d/dx(x\xE2\x81\xBF) = nx\xE2\x81\xBF\xE2\x81\xBB\xC2\xB9");
    test_case("v7: definite integral computation (\\, absorbs space)",
              "$\\int_0^{\\pi} \\sin x \\, dx = 2$",
              "\xE2\x88\xAB\xE2\x82\x80^{\xCF\x80} sin x dx = 2");
    test_case("v7: standard deviation (1/n stays unwrapped)",
              "$\\sigma = \\sqrt{\\frac{1}{n}\\sum_{i=1}^n (x_i - \\mu)^2}$",
              "\xCF\x83 = \xE2\x88\x9A(1/n\xE2\x88\x91\xE1\xB5\xA2\xE2\x82\x8C\xE2\x82\x81\xE2\x81\xBF (x\xE1\xB5\xA2 - \xCE\xBC)\xC2\xB2)");
    test_case("v7: Stokes theorem",
              "$\\oint_{\\partial S} \\vec{F} \\cdot d\\vec{r} = \\iint_S (\\nabla \\times \\vec{F}) \\cdot d\\vec{S}$",
              "\xE2\x88\xAE_{\xE2\x88\x82 S} F\xE2\x83\x97 \xC2\xB7 dr\xE2\x83\x97 = \xE2\x88\xAC_S (\xE2\x88\x87 \xC3\x97 F\xE2\x83\x97) \xC2\xB7 dS\xE2\x83\x97");
    test_case("v7: chemistry with subscripts",
              "$Ca(OH)_2 + CO_2 \\to CaCO_3 + H_2O$",
              "Ca(OH)\xE2\x82\x82 + CO\xE2\x82\x82 \xE2\x86\x92 CaCO\xE2\x82\x83 + H\xE2\x82\x82O");
    test_case("v7: quantum expectation",
              "$\\langle \\hat{H} \\rangle = \\bra{\\psi} \\hat{H} \\ket{\\psi}$",
              "\xE2\x9F\xA8 H\xCC\x82 \xE2\x9F\xA9 = \xE2\x9F\xA8\xCF\x88| H\xCC\x82 |\xCF\x88\xE2\x9F\xA9");
    test_case("v7: probability with pmod",
              "$P(A \\cap B) = P(A) P(B)$ if $A, B$ independent",
              "P(A \xE2\x88\xA9 B) = P(A) P(B) if A, B independent");
    test_case("v7: fibonacci — all subs fully unicode",
              "$F_n = F_{n-1} + F_{n-2}$",
              "F\xE2\x82\x99 = F\xE2\x82\x99\xE2\x82\x8B\xE2\x82\x81 + F\xE2\x82\x99\xE2\x82\x8B\xE2\x82\x82");   /* Fₙ = Fₙ₋₁ + Fₙ₋₂ */
    test_case("v7: big-O notation",
              "$T(n) = O(n \\log n) + \\Theta(n^2)$",
              "T(n) = O(n log n) + \xCE\x98(n\xC2\xB2)");
    test_case("v7: set difference + membership",
              "$A \\setminus B = \\{x \\in A \\mid x \\notin B\\}$",
              "A \xE2\x88\x96 B = {x \xE2\x88\x88 A \xE2\x88\xA3 x \xE2\x88\x89 B}");
    test_case("v7: p-value convention",
              "$H_0: \\mu \\geq 0$ vs $H_1: \\mu < 0$",
              "H\xE2\x82\x80: \xCE\xBC \xE2\x89\xA5 0 vs H\xE2\x82\x81: \xCE\xBC < 0");
    test_case("v7: linear regression (^\\top drops caret + emits ⊤)",
              "$\\hat{\\beta} = (X^\\top X)^{-1} X^\\top y$",
              "\xCE\xB2\xCC\x82 = (X\xE2\x8A\xA4 X)\xE2\x81\xBB\xC2\xB9 X\xE2\x8A\xA4 y");
    test_case("v7: ODE with prime",
              "$y'' + 2y' + y = 0$",
              "y'' + 2y' + y = 0");
    test_case("v7: Fourier series (all subs fully unicoded)",
              "$f(x) = a_0 + \\sum_{n=1}^{\\infty} (a_n \\cos nx + b_n \\sin nx)$",
              "f(x) = a\xE2\x82\x80 + \xE2\x88\x91\xE2\x82\x99\xE2\x82\x8C\xE2\x82\x81^{\xE2\x88\x9E} (a\xE2\x82\x99 cos nx + b\xE2\x82\x99 sin nx)");
    test_case("v7: eigenvalue equation",
              "$A \\vec{v} = \\lambda \\vec{v}$",
              "A v\xE2\x83\x97 = \xCE\xBB v\xE2\x83\x97");
    test_case("v7: convergent series",
              "$\\lim_{n \\to \\infty} \\sum_{k=1}^n \\frac{1}{k^2} = \\frac{\\pi^2}{6}$",
              "lim_{n \xE2\x86\x92 \xE2\x88\x9E} \xE2\x88\x91\xE2\x82\x96\xE2\x82\x8C\xE2\x82\x81\xE2\x81\xBF 1/k\xC2\xB2 = \xCF\x80\xC2\xB2/6");

    /* ── V7: adversarial + edge cases ── */
    test_case("v7: unterminated \\ket (emits |〉 as best-effort)",
              "$\\ket{",
              "|\xE2\x9F\xA9");
    test_case("v7: \\overset with only one arg (unknown-cmd path)",
              "$\\overset{a}$",
              "a");   /* Falls through to \unknown{content} → emits `a` */
    test_case("v7: \\pmod with empty arg",
              "$a \\equiv b \\pmod{}$",
              "a \xE2\x89\xA1 b (mod )");
    test_case("v7: super long chain",
              "$A \\Rightarrow B \\Rightarrow C \\Rightarrow D \\Rightarrow E$",
              "A \xE2\x87\x92 B \xE2\x87\x92 C \xE2\x87\x92 D \xE2\x87\x92 E");
    test_case("v7: many wrappers nested",
              "$\\mathbf{\\text{\\emph{hello}}}$",
              "hello");
    test_case("v7: escape in text",
              "$\\text{100\\% pure}$",
              "100% pure");
    test_case("v7: real-world Chem \\xrightarrow{spark} (fallback emits content)",
              "$2H_2 + O_2 \\xrightarrow{spark} 2H_2O$",
              "2H\xE2\x82\x82 + O\xE2\x82\x82 spark 2H\xE2\x82\x82O");

    /* ============================================================
     * V7.1: ULTIMATE REAL-WORLD BATTERY — actual multi-paragraph AI
     * responses across every major subject. These are ALL blocks that
     * v6 would emit as raw LaTeX text; v7 renders as clean Unicode. */

    test_case("v7.1: full Chemistry equilibrium answer (K_c stays literal — no sub_of('c'))",
              "**Answer:** K_c = 4.16 x 10^{-3}\n\n"
              "For $2NO_2 \\rightleftharpoons N_2O_4$ at 298K:\n"
              "\\[ K_c = \\frac{[N_2O_4]}{[NO_2]^2} \\]",
              "**Answer:** K_c = 4.16 x 10\xE2\x81\xBB\xC2\xB3\n\n"
              "For 2NO\xE2\x82\x82 \xE2\x87\x8C N\xE2\x82\x82O\xE2\x82\x84 at 298K:\n"
              " K_c = [N\xE2\x82\x82O\xE2\x82\x84]/[NO\xE2\x82\x82]\xC2\xB2 ");
    test_case("v7.1: full Statistics normal distribution",
              "The Z-score is: \\[ Z = \\frac{X - \\mu}{\\sigma} \\]",
              "The Z-score is:  Z = (X - \xCE\xBC)/\xCF\x83 ");
    test_case("v7.1: full CS complexity analysis",
              "Time complexity: $\\Theta(n \\log n)$ average, $O(n^2)$ worst.\n"
              "Space: $\\Theta(\\log n)$ for recursion stack.",
              "Time complexity: \xCE\x98(n log n) average, O(n\xC2\xB2) worst.\n"
              "Space: \xCE\x98(log n) for recursion stack.");
    test_case("v7.1: sum with substack (falls back gracefully)",
              "$\\sum_{i \\in S} f(i)$",
              "\xE2\x88\x91_{i \xE2\x88\x88 S} f(i)");
    test_case("v7.1: chained inequalities",
              "$0 \\leq a \\leq b < c$",
              "0 \xE2\x89\xA4 a \xE2\x89\xA4 b < c");
    test_case("v7.1: mixed prose + LaTeX + code all in one reply",
              "**Setup:** Let $f(x) = x^2 + 3x - 4$.\n\n"
              "Roots via factoring: $(x+4)(x-1)$, so $x = -4$ or $x = 1$.\n\n"
              "```python\n"
              "def solve():\n"
              "    from math import sqrt\n"
              "    a, b, c = 1, 3, -4\n"
              "    d = b*b - 4*a*c\n"
              "    return (-b + sqrt(d))/(2*a), (-b - sqrt(d))/(2*a)\n"
              "```\n\n"
              "Check: $f(1) = 1 + 3 - 4 = 0$ \xE2\x9C\x93",
              "**Setup:** Let f(x) = x\xC2\xB2 + 3x - 4.\n\n"
              "Roots via factoring: (x+4)(x-1), so x = -4 or x = 1.\n\n"
              "```python\n"
              "def solve():\n"
              "    from math import sqrt\n"
              "    a, b, c = 1, 3, -4\n"
              "    d = b*b - 4*a*c\n"
              "    return (-b + sqrt(d))/(2*a), (-b - sqrt(d))/(2*a)\n"
              "```\n\n"
              "Check: f(1) = 1 + 3 - 4 = 0 \xE2\x9C\x93");
    test_case("v7.1: physics with derivatives + all Greek",
              "$\\theta(t) = \\theta_0 + \\omega_0 t + \\frac{1}{2}\\alpha t^2$",
              "\xCE\xB8(t) = \xCE\xB8\xE2\x82\x80 + \xCF\x89\xE2\x82\x80 t + \xC2\xBD\xCE\xB1 t\xC2\xB2");
    test_case("v7.1: expected value + variance (\\quad = 2 spaces + source spaces)",
              "$E[X] = \\mu, \\quad Var(X) = E[(X-\\mu)^2] = \\sigma^2$",
              "E[X] = \xCE\xBC,    Var(X) = E[(X-\xCE\xBC)\xC2\xB2] = \xCF\x83\xC2\xB2");
    test_case("v7.1: cross product with vectors",
              "$\\vec{a} \\times \\vec{b} = |a||b|\\sin\\theta\\, \\hat{n}$",
              "a\xE2\x83\x97 \xC3\x97 b\xE2\x83\x97 = |a||b|sin\xCE\xB8 n\xCC\x82");
    test_case("v7.1: circuit analysis (Ohms + Kirchhoff)",
              "By KVL: $V - IR_1 - IR_2 = 0$, so $I = \\frac{V}{R_1 + R_2}$",
              "By KVL: V - IR\xE2\x82\x81 - IR\xE2\x82\x82 = 0, so I = V/(R\xE2\x82\x81 + R\xE2\x82\x82)");
    test_case("v7.1: quantum wave function + probability",
              "$|\\psi\\rangle = \\alpha|0\\rangle + \\beta|1\\rangle$ where $|\\alpha|^2 + |\\beta|^2 = 1$",
              "|\xCF\x88\xE2\x9F\xA9 = \xCE\xB1|0\xE2\x9F\xA9 + \xCE\xB2|1\xE2\x9F\xA9 where |\xCE\xB1|\xC2\xB2 + |\xCE\xB2|\xC2\xB2 = 1");
    test_case("v7.1: partial derivative chain rule",
              "$\\frac{\\partial f}{\\partial x} = \\frac{\\partial f}{\\partial u}\\frac{\\partial u}{\\partial x}$",
              "(\xE2\x88\x82 f)/(\xE2\x88\x82 x) = (\xE2\x88\x82 f)/(\xE2\x88\x82 u)(\xE2\x88\x82 u)/(\xE2\x88\x82 x)");
    test_case("v7.1: matrix inverse formula (num=1 no wrap, den=det(A) wraps for paren)",
              "$A^{-1} = \\frac{1}{\\det(A)}\\text{adj}(A)$",
              "A\xE2\x81\xBB\xC2\xB9 = 1/(det(A))adj(A)");
    test_case("v7.1: nested pmatrix (best-effort)",
              "$\\begin{pmatrix} \\vec{a} & \\vec{b} \\end{pmatrix}$",
              "( a\xE2\x83\x97  b\xE2\x83\x97 )");
    test_case("v7.1: multiple lines with sub/sup",
              "$x_1 y_1 + x_2 y_2 + \\dots + x_n y_n$",
              "x\xE2\x82\x81 y\xE2\x82\x81 + x\xE2\x82\x82 y\xE2\x82\x82 + \xE2\x80\xA6 + x\xE2\x82\x99 y\xE2\x82\x99");
    test_case("v7.1: absolute value + inequality",
              "$|x - 3| < 5 \\iff -5 < x - 3 < 5$",
              "|x - 3| < 5 \xE2\x87\x94 -5 < x - 3 < 5");
    test_case("v7.1: partial with symbols mixed",
              "The gradient is $\\nabla f = (\\partial f / \\partial x, \\partial f / \\partial y, \\partial f / \\partial z)$",
              "The gradient is \xE2\x88\x87 f = (\xE2\x88\x82 f / \xE2\x88\x82 x, \xE2\x88\x82 f / \xE2\x88\x82 y, \xE2\x88\x82 f / \xE2\x88\x82 z)");

    printf("\n=== SUMMARY ===\n");
    printf("Pass: %d / %d (%d%%)\n", test_pass, test_count,
           test_count ? (100 * test_pass / test_count) : 0);

    /* ── DEMO: real-world before/after ─────────────────────────────
     *
     * Take the actual raw AI reply the user was seeing (from
     * last_reply.txt) and show what it renders as. Also show what a
     * PROPERLY-formed reply (post JSON-fix) renders as. */
    printf("\n\n");
    printf("=================================================================\n");
    printf("DEMO: How the ACTUAL Physics reply renders after all fixes\n");
    printf("=================================================================\n\n");

    const char *fixed_reply =
        "**Answer:** max sensitivity 2.5 mV/\xC2\xB0" "C at $T=0^\\circ\\text{C}$\n\n"
        "Differentiate the voltage:\n"
        "\\[V(T)=2T+5\\sin\\left(\\frac{T}{10}\\right)\\]\n"
        "\\[\\frac{dV}{dT}=2+\\frac{5}{10}\\cos\\left(\\frac{T}{10}\\right)\\]\n"
        "\\[=2+0.5\\cos\\left(\\frac{T}{10}\\right)\\]\n\n"
        "On $T\\in[0,30]$, $\\frac{T}{10}\\in[0,3]$, and $\\cos(x)$ is largest at $x=0$.\n\n"
        "units check: $\\text{mV}/^\\circ\\text{C}$ \xE2\x9C\x93";

    char rendered[8192];
    size_t rn = latex_to_unicode(fixed_reply, strlen(fixed_reply),
                                  rendered, sizeof(rendered) - 1);
    rendered[rn] = 0;
    printf("--- RAW LATEX (as AI would output post JSON-fix) ---\n%s\n\n",
           fixed_reply);
    printf("--- RENDERED UNICODE (as user sees in overlay) ---\n%s\n\n",
           rendered);

    /* Second demo: matrix + cases. */
    const char *matrix_reply =
        "The rotation matrix is:\n"
        "\\[R = \\begin{pmatrix} \\cos\\theta & -\\sin\\theta \\\\ "
        "\\sin\\theta & \\cos\\theta \\end{pmatrix}\\]\n\n"
        "Piecewise absolute value:\n"
        "\\[|x| = \\begin{cases} x & x \\geq 0 \\\\ -x & x < 0 \\end{cases}\\]\n";
    rn = latex_to_unicode(matrix_reply, strlen(matrix_reply),
                           rendered, sizeof(rendered) - 1);
    rendered[rn] = 0;
    printf("--- MATRIX + CASES demo ---\n%s\n", rendered);

    return (test_pass == test_count) ? 0 : 1;
}
