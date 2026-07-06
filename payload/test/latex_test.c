/* latex_test.c — comprehensive unit test for the LaTeX-to-Unicode
 * converter. Copies the converter code out of imgui_layer.cpp so we
 * can exercise it without booting DWM.
 *
 * Build + run:
 *   cl /nologo /W3 /O2 latex_test.c && latex_test.exe
 *
 * Every test that runs prints its assertion; failing tests print
 * expected vs actual. Exit code 0 = all pass, non-zero = at least one
 * failure. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define _CRT_SECURE_NO_WARNINGS 1
#ifdef _WIN32
#include <windows.h>
#endif

/* ── COPY FROM imgui_layer.cpp: LATEX_MAP + accents + wrappers +
 *    latex_to_unicode + latex_render_env ─────────────────────────── */

struct latex_map_entry {
    const char *tex;
    const char *uni;
};

/* Ordered longest-match-first. Must match the copy in imgui_layer.cpp. */
static const struct latex_map_entry LATEX_MAP[] = {
    { "\\Biggl", "" }, { "\\Biggr", "" }, { "\\biggl", "" }, { "\\biggr", "" },
    { "\\Bigl", "" }, { "\\Bigr", "" }, { "\\bigl", "" }, { "\\bigr", "" },
    { "\\Bigg", "" }, { "\\bigg", "" }, { "\\Big", "" }, { "\\big", "" },
    { "\\left", "" }, { "\\right", "" }, { "\\middle", "" },
    { "\\!", "" }, { "\\,", "" }, { "\\;", "" }, { "\\:", "" }, { "\\ ", " " },
    { "\\quad", "  " }, { "\\qquad", "    " },
    { "\\%", "%" }, { "\\$", "$" }, { "\\&", "&" }, { "\\_", "_" }, { "\\#", "#" },
    { "\\{", "{" }, { "\\}", "}" },
    { "\\arcsin", "arcsin" }, { "\\arccos", "arccos" }, { "\\arctan", "arctan" },
    { "\\sinh", "sinh" }, { "\\cosh", "cosh" }, { "\\tanh", "tanh" }, { "\\coth", "coth" },
    { "\\log", "log" }, { "\\ln", "ln" }, { "\\lg", "lg" }, { "\\exp", "exp" },
    { "\\sin", "sin" }, { "\\cos", "cos" }, { "\\tan", "tan" },
    { "\\csc", "csc" }, { "\\sec", "sec" }, { "\\cot", "cot" },
    { "\\lim", "lim" }, { "\\limsup", "limsup" }, { "\\liminf", "liminf" },
    { "\\max", "max" }, { "\\min", "min" }, { "\\sup", "sup" }, { "\\inf", "inf" },
    { "\\arg", "arg" }, { "\\deg", "deg" }, { "\\det", "det" }, { "\\dim", "dim" },
    { "\\ker", "ker" }, { "\\gcd", "gcd" }, { "\\lcm", "lcm" },
    { "\\mod", "mod" }, { "\\bmod", "mod" }, { "\\pmod", "mod" },
    { "\\Pr", "Pr" }, { "\\hom", "hom" },
    { "\\Longleftrightarrow", "\xE2\x87\x94" }, { "\\longleftrightarrow", "\xE2\x86\x94" },
    { "\\Leftrightarrow", "\xE2\x87\x94" }, { "\\leftrightarrow", "\xE2\x86\x94" },
    { "\\Longrightarrow", "\xE2\x87\x92" }, { "\\Longleftarrow", "\xE2\x87\x90" },
    { "\\Rightarrow", "\xE2\x87\x92" }, { "\\Leftarrow", "\xE2\x87\x90" },
    { "\\longrightarrow", "\xE2\x86\x92" }, { "\\longleftarrow", "\xE2\x86\x90" },
    { "\\longmapsto", "\xE2\x9F\xBC" },
    { "\\rightarrow", "\xE2\x86\x92" }, { "\\leftarrow", "\xE2\x86\x90" },
    { "\\uparrow", "\xE2\x86\x91" }, { "\\downarrow", "\xE2\x86\x93" },
    { "\\updownarrow", "\xE2\x86\x95" },
    { "\\hookrightarrow", "\xE2\x86\xAA" }, { "\\hookleftarrow", "\xE2\x86\xA9" },
    { "\\Uparrow", "\xE2\x87\x91" }, { "\\Downarrow", "\xE2\x87\x93" },
    { "\\nearrow", "\xE2\x86\x97" }, { "\\searrow", "\xE2\x86\x98" },
    { "\\nwarrow", "\xE2\x86\x96" }, { "\\swarrow", "\xE2\x86\x99" },
    { "\\mapsto", "\xE2\x86\xA6" }, { "\\to", "\xE2\x86\x92" }, { "\\gets", "\xE2\x86\x90" },
    { "\\approx", "\xE2\x89\x88" }, { "\\approxeq", "\xE2\x89\x8A" },
    { "\\equiv", "\xE2\x89\xA1" }, { "\\propto", "\xE2\x88\x9D" },
    { "\\simeq", "\xE2\x89\x83" }, { "\\sim", "\xE2\x88\xBC" }, { "\\cong", "\xE2\x89\x85" },
    { "\\leqslant", "\xE2\x89\xBD" }, { "\\geqslant", "\xE2\x89\xBE" },
    { "\\leq", "\xE2\x89\xA4" }, { "\\geq", "\xE2\x89\xA5" },
    { "\\le", "\xE2\x89\xA4" }, { "\\ge", "\xE2\x89\xA5" },
    { "\\ll", "\xE2\x89\xAA" }, { "\\gg", "\xE2\x89\xAB" },
    { "\\neq", "\xE2\x89\xA0" }, { "\\ne", "\xE2\x89\xA0" },
    { "\\prec", "\xE2\x89\xBA" }, { "\\succ", "\xE2\x89\xBB" },
    { "\\preceq", "\xE2\xAA\xAF" }, { "\\succeq", "\xE2\xAA\xB0" },
    { "\\pm", "\xC2\xB1" }, { "\\mp", "\xE2\x88\x93" }, { "\\times", "\xC3\x97" },
    { "\\cdot", "\xC2\xB7" }, { "\\div", "\xC3\xB7" }, { "\\ast", "\xE2\x88\x97" },
    { "\\star", "\xE2\x8B\x86" }, { "\\bullet", "\xE2\x88\x99" }, { "\\circ", "\xE2\x88\x98" },
    { "\\oplus", "\xE2\x8A\x95" }, { "\\ominus", "\xE2\x8A\x96" },
    { "\\otimes", "\xE2\x8A\x97" }, { "\\oslash", "\xE2\x8A\x98" }, { "\\odot", "\xE2\x8A\x99" },
    { "\\bigoplus", "\xE2\xA8\x81" }, { "\\bigotimes", "\xE2\xA8\x82" },
    { "\\wedge", "\xE2\x88\xA7" }, { "\\vee", "\xE2\x88\xA8" },
    { "\\notin", "\xE2\x88\x89" }, { "\\in", "\xE2\x88\x88" }, { "\\ni", "\xE2\x88\x8B" },
    { "\\subseteq", "\xE2\x8A\x86" }, { "\\supseteq", "\xE2\x8A\x87" },
    { "\\subsetneq", "\xE2\x8A\x8A" }, { "\\supsetneq", "\xE2\x8A\x8B" },
    { "\\subset", "\xE2\x8A\x82" }, { "\\supset", "\xE2\x8A\x83" },
    { "\\setminus", "\xE2\x88\x96" }, { "\\cup", "\xE2\x88\xAA" }, { "\\cap", "\xE2\x88\xA9" },
    { "\\emptyset", "\xE2\x88\x85" }, { "\\varnothing", "\xE2\x88\x85" },
    { "\\forall", "\xE2\x88\x80" }, { "\\exists", "\xE2\x88\x83" },
    { "\\nexists", "\xE2\x88\x84" },
    { "\\therefore", "\xE2\x88\xB4" }, { "\\because", "\xE2\x88\xB5" },
    { "\\neg", "\xC2\xAC" }, { "\\lnot", "\xC2\xAC" },
    { "\\land", "\xE2\x88\xA7" }, { "\\lor", "\xE2\x88\xA8" },
    { "\\implies", "\xE2\x87\x92" }, { "\\iff", "\xE2\x87\x94" },
    { "\\iiint", "\xE2\x88\xAD" }, { "\\iint", "\xE2\x88\xAC" },
    { "\\oint", "\xE2\x88\xAE" }, { "\\int", "\xE2\x88\xAB" },
    { "\\sum", "\xE2\x88\x91" }, { "\\prod", "\xE2\x88\x8F" }, { "\\coprod", "\xE2\x88\x90" },
    { "\\bigcup", "\xE2\x8B\x83" }, { "\\bigcap", "\xE2\x8B\x82" },
    { "\\bigsqcup", "\xE2\xA8\x86" },
    { "\\bigwedge", "\xE2\x8B\x80" }, { "\\bigvee", "\xE2\x8B\x81" },
    { "\\partial", "\xE2\x88\x82" }, { "\\nabla", "\xE2\x88\x87" }, { "\\infty", "\xE2\x88\x9E" },
    { "\\varepsilon", "\xCE\xB5" }, { "\\varphi", "\xCF\x95" }, { "\\vartheta", "\xCF\x91" },
    { "\\varsigma", "\xCF\x82" }, { "\\varrho", "\xCF\x9A" }, { "\\varpi", "\xCF\x96" },
    { "\\alpha", "\xCE\xB1" }, { "\\beta", "\xCE\xB2" }, { "\\gamma", "\xCE\xB3" },
    { "\\delta", "\xCE\xB4" }, { "\\epsilon", "\xCE\xB5" }, { "\\zeta", "\xCE\xB6" },
    { "\\eta", "\xCE\xB7" }, { "\\theta", "\xCE\xB8" }, { "\\iota", "\xCE\xB9" },
    { "\\kappa", "\xCE\xBA" }, { "\\lambda", "\xCE\xBB" }, { "\\mu", "\xCE\xBC" },
    { "\\nu", "\xCE\xBD" }, { "\\xi", "\xCE\xBE" }, { "\\omicron", "\xCE\xBF" },
    { "\\pi", "\xCF\x80" }, { "\\rho", "\xCF\x81" }, { "\\sigma", "\xCF\x83" },
    { "\\tau", "\xCF\x84" }, { "\\upsilon", "\xCF\x85" }, { "\\phi", "\xCF\x86" },
    { "\\chi", "\xCF\x87" }, { "\\psi", "\xCF\x88" }, { "\\omega", "\xCF\x89" },
    { "\\Alpha", "\xCE\x91" }, { "\\Beta", "\xCE\x92" }, { "\\Gamma", "\xCE\x93" },
    { "\\Delta", "\xCE\x94" }, { "\\Epsilon", "\xCE\x95" }, { "\\Zeta", "\xCE\x96" },
    { "\\Eta", "\xCE\x97" }, { "\\Theta", "\xCE\x98" }, { "\\Iota", "\xCE\x99" },
    { "\\Kappa", "\xCE\x9A" }, { "\\Lambda", "\xCE\x9B" }, { "\\Mu", "\xCE\x9C" },
    { "\\Nu", "\xCE\x9D" }, { "\\Xi", "\xCE\x9E" }, { "\\Omicron", "\xCE\x9F" },
    { "\\Pi", "\xCE\xA0" }, { "\\Rho", "\xCE\xA1" }, { "\\Sigma", "\xCE\xA3" },
    { "\\Tau", "\xCE\xA4" }, { "\\Upsilon", "\xCE\xA5" }, { "\\Phi", "\xCE\xA6" },
    { "\\Chi", "\xCE\xA7" }, { "\\Psi", "\xCE\xA8" }, { "\\Omega", "\xCE\xA9" },
    { "\\parallel", "\xE2\x88\xA5" }, { "\\perp", "\xE2\x8A\xA5" },
    { "\\angle", "\xE2\x88\xA0" }, { "\\triangle", "\xE2\x96\xB3" }, { "\\square", "\xE2\x96\xA1" },
    { "\\lceil", "\xE2\x8C\x88" }, { "\\rceil", "\xE2\x8C\x89" },
    { "\\lfloor", "\xE2\x8C\x8A" }, { "\\rfloor", "\xE2\x8C\x8B" },
    { "\\langle", "\xE2\x9F\xA8" }, { "\\rangle", "\xE2\x9F\xA9" },
    { "\\dots", "\xE2\x80\xA6" }, { "\\ldots", "\xE2\x80\xA6" }, { "\\cdots", "\xE2\x8B\xAF" },
    { "\\vdots", "\xE2\x8B\xAE" }, { "\\ddots", "\xE2\x8B\xB1" },
    { "\\degree", "\xC2\xB0" }, { "\\prime", "\xE2\x80\xB2" }, { "\\hbar", "\xC4\xA7" },
    { "\\ell", "\xE2\x84\x93" }, { "\\Re", "\xE2\x84\x9C" }, { "\\Im", "\xE2\x84\x91" },
    { "\\aleph", "\xE2\x84\xB5" }, { "\\beth", "\xE2\x84\xB6" },
    { "\\imath", "\xC4\xB1" }, { "\\jmath", "\xC8\xB7" }, { "\\wp", "\xE2\x84\x98" },
    { NULL, NULL }
};

static const char *LATEX_TEXT_WRAPPERS[] = {
    "text", "textbf", "textit", "textrm", "textsf", "texttt",
    "textnormal", "textup", "textsl", "textsc", "textmd",
    "mathbf", "mathrm", "mathbb", "mathcal", "mathfrak", "mathit",
    "mathsf", "mathtt", "mathnormal",
    "boldsymbol", "bm", "bf", "rm", "it", "sf", "tt", "sc", "sl", "cal",
    "operatorname", "emph", "underline",
    "mbox", "hbox", "phantom", "vphantom", "hphantom",
    "color", "textcolor", "colorbox",
    "small", "large", "Large", "LARGE", "Huge", "huge",
    "tiny", "footnotesize", "normalsize", "scriptsize", "scriptstyle",
    "displaystyle", "textstyle", "smash",
    NULL
};

struct latex_accent_entry { const char *cmd; const char *combining; };
static const struct latex_accent_entry LATEX_ACCENTS[] = {
    { "vec", "\xE2\x83\x97" }, { "overrightarrow", "\xE2\x83\x97" },
    { "overleftarrow", "\xE2\x83\x96" },
    { "hat", "\xCC\x82" }, { "widehat", "\xCC\x82" },
    { "tilde", "\xCC\x83" }, { "widetilde", "\xCC\x83" },
    { "bar", "\xCC\x84" }, { "overline", "\xCC\x84" },
    { "dot", "\xCC\x87" }, { "ddot", "\xCC\x88" }, { "dddot", "\xE2\x83\x9B" },
    { "check", "\xCC\x8C" }, { "acute", "\xCC\x81" }, { "grave", "\xCC\x80" },
    { "breve", "\xCC\x86" },
    { NULL, NULL }
};

/* Sup/sub tables. */
static const char *sup_of(char c) {
    switch (c) {
        case '0': return "\xE2\x81\xB0"; case '1': return "\xC2\xB9";
        case '2': return "\xC2\xB2";     case '3': return "\xC2\xB3";
        case '4': return "\xE2\x81\xB4"; case '5': return "\xE2\x81\xB5";
        case '6': return "\xE2\x81\xB6"; case '7': return "\xE2\x81\xB7";
        case '8': return "\xE2\x81\xB8"; case '9': return "\xE2\x81\xB9";
        case '+': return "\xE2\x81\xBA"; case '-': return "\xE2\x81\xBB";
        case '=': return "\xE2\x81\xBC"; case '(': return "\xE2\x81\xBD";
        case ')': return "\xE2\x81\xBE";
        case 'a': return "\xE1\xB5\x83"; case 'b': return "\xE1\xB5\x87";
        case 'c': return "\xE1\xB6\x9C"; case 'd': return "\xE1\xB5\x88";
        case 'e': return "\xE1\xB5\x89"; case 'f': return "\xE1\xB6\xA0";
        case 'g': return "\xE1\xB5\x8D"; case 'h': return "\xCA\xB0";
        case 'i': return "\xE2\x81\xB1"; case 'j': return "\xCA\xB2";
        case 'k': return "\xE1\xB5\x8F"; case 'l': return "\xCB\xA1";
        case 'm': return "\xE1\xB5\x90"; case 'n': return "\xE2\x81\xBF";
        case 'o': return "\xE1\xB5\x92"; case 'p': return "\xE1\xB5\x96";
        case 'r': return "\xCA\xB3";     case 's': return "\xCB\xA2";
        case 't': return "\xE1\xB5\x97"; case 'u': return "\xE1\xB5\x98";
        case 'v': return "\xE1\xB5\x9B"; case 'w': return "\xCA\xB7";
        case 'x': return "\xCB\xA3";     case 'y': return "\xCA\xB8";
        default: return NULL;
    }
}
static const char *sub_of(char c) {
    switch (c) {
        case '0': return "\xE2\x82\x80"; case '1': return "\xE2\x82\x81";
        case '2': return "\xE2\x82\x82"; case '3': return "\xE2\x82\x83";
        case '4': return "\xE2\x82\x84"; case '5': return "\xE2\x82\x85";
        case '6': return "\xE2\x82\x86"; case '7': return "\xE2\x82\x87";
        case '8': return "\xE2\x82\x88"; case '9': return "\xE2\x82\x89";
        case '+': return "\xE2\x82\x8A"; case '-': return "\xE2\x82\x8B";
        case '=': return "\xE2\x82\x8C"; case '(': return "\xE2\x82\x8D";
        case ')': return "\xE2\x82\x8E";
        case 'a': return "\xE2\x82\x90"; case 'e': return "\xE2\x82\x91";
        case 'h': return "\xE2\x82\x95"; case 'i': return "\xE1\xB5\xA2";
        case 'j': return "\xE2\xB1\xBC"; case 'k': return "\xE2\x82\x96";
        case 'l': return "\xE2\x82\x97"; case 'm': return "\xE2\x82\x98";
        case 'n': return "\xE2\x82\x99"; case 'o': return "\xE2\x82\x92";
        case 'p': return "\xE2\x82\x9A"; case 'r': return "\xE1\xB5\xA3";
        case 's': return "\xE2\x82\x9B"; case 't': return "\xE2\x82\x9C";
        case 'u': return "\xE1\xB5\xA4"; case 'v': return "\xE1\xB5\xA5";
        case 'x': return "\xE2\x82\x93";
        default: return NULL;
    }
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

static int try_render_sup_sub(const char *s, size_t n, int is_super,
                              char *dst, size_t *dp, size_t dst_cap) {
    for (size_t i = 0; i < n; i++) {
        const char *u = is_super ? sup_of(s[i]) : sub_of(s[i]);
        if (!u) return 0;
        ltx_puts(dst, dp, dst_cap, u);
    }
    return 1;
}

struct vulgar_frac_entry { const char *num; const char *den; const char *uni; };
static const struct vulgar_frac_entry VULGAR_FRACS[] = {
    { "1", "2", "\xC2\xBD" }, { "1", "3", "\xE2\x85\x93" }, { "2", "3", "\xE2\x85\x94" },
    { "1", "4", "\xC2\xBC" }, { "3", "4", "\xC2\xBE" },
    { "1", "5", "\xE2\x85\x95" }, { "2", "5", "\xE2\x85\x96" },
    { "3", "5", "\xE2\x85\x97" }, { "4", "5", "\xE2\x85\x98" },
    { "1", "6", "\xE2\x85\x99" }, { "5", "6", "\xE2\x85\x9A" },
    { "1", "7", "\xE2\x85\x90" },
    { "1", "8", "\xE2\x85\x9B" }, { "3", "8", "\xE2\x85\x9C" },
    { "5", "8", "\xE2\x85\x9D" }, { "7", "8", "\xE2\x85\x9E" },
    { "1", "9", "\xE2\x85\x91" }, { "1", "10", "\xE2\x85\x92" },
    { NULL, NULL, NULL }
};

static int latex_match_at(const char *src, size_t src_len, size_t pos) {
    for (int i = 0; LATEX_MAP[i].tex; i++) {
        size_t tlen = strlen(LATEX_MAP[i].tex);
        if (pos + tlen > src_len) continue;
        if (memcmp(src + pos, LATEX_MAP[i].tex, tlen) != 0) continue;
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

static size_t latex_wrapper_at(const char *src, size_t src_len, size_t pos) {
    if (pos >= src_len || src[pos] != '\\') return 0;
    size_t start = pos + 1;
    size_t end = start;
    while (end < src_len && ((src[end] >= 'a' && src[end] <= 'z') ||
                              (src[end] >= 'A' && src[end] <= 'Z'))) end++;
    if (end == start) return 0;
    size_t wlen = end - start;
    if (end >= src_len || src[end] != '{') return 0;
    for (int i = 0; LATEX_TEXT_WRAPPERS[i]; i++) {
        size_t klen = strlen(LATEX_TEXT_WRAPPERS[i]);
        if (klen != wlen) continue;
        if (memcmp(src + start, LATEX_TEXT_WRAPPERS[i], klen) != 0) continue;
        return end - pos;
    }
    return 0;
}

static int latex_accent_at(const char *src, size_t src_len, size_t pos) {
    if (pos >= src_len || src[pos] != '\\') return -1;
    size_t start = pos + 1;
    size_t end = start;
    while (end < src_len && ((src[end] >= 'a' && src[end] <= 'z') ||
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

static size_t latex_begin_at(const char *src, size_t src_len, size_t pos,
                              const char **env_name_out, size_t *env_len_out) {
    static const char *BEGIN = "\\begin{";
    size_t blen = 7;
    if (pos + blen > src_len) return 0;
    if (memcmp(src + pos, BEGIN, blen) != 0) return 0;
    size_t p = pos + blen;
    size_t env_start = p;
    while (p < src_len && src[p] != '}') {
        char c = src[p];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '*')) return 0;
        p++;
    }
    if (p >= src_len || src[p] != '}') return 0;
    if (env_name_out) *env_name_out = src + env_start;
    if (env_len_out) *env_len_out = p - env_start;
    return (p + 1) - pos;
}

static size_t latex_find_end(const char *src, size_t src_len, size_t pos,
                              const char *env, size_t env_len) {
    char pattern[128];
    if (env_len > 100) return 0;
    int pn = _snprintf(pattern, sizeof(pattern) - 1, "\\end{%.*s}", (int)env_len, env);
    if (pn <= 0) return 0;
    int depth = 1;
    size_t p = pos;
    while (p < src_len) {
        const char *inner_env = NULL;
        size_t inner_len = 0;
        size_t blen = latex_begin_at(src, src_len, p, &inner_env, &inner_len);
        if (blen && inner_len == env_len && memcmp(inner_env, env, env_len) == 0) {
            depth++;
            p += blen;
            continue;
        }
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

static size_t utf8_advance(const char *s, size_t pos, size_t end) {
    if (pos >= end) return pos;
    unsigned char c = (unsigned char)s[pos];
    if (c < 0x80) return pos + 1;
    if ((c & 0xE0) == 0xC0) return (pos + 2 <= end) ? pos + 2 : end;
    if ((c & 0xF0) == 0xE0) return (pos + 3 <= end) ? pos + 3 : end;
    if ((c & 0xF8) == 0xF0) return (pos + 4 <= end) ? pos + 4 : end;
    return pos + 1;
}

/* Forward decl. */
static size_t latex_render_env(const char *env, size_t env_len,
                                const char *body, size_t body_len,
                                char *dst, size_t dst_cap);

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
        if (c == '\\' && sp + 1 < src_len && (src[sp + 1] == '(' || src[sp + 1] == ')')) {
            sp += 2; continue;
        }
        if (c == '\\' && sp + 1 < src_len && (src[sp + 1] == '[' || src[sp + 1] == ']')) {
            sp += 2; continue;
        }
        if (c == '\\' && sp + 1 < src_len && src[sp + 1] == '\\') {
            ltx_putc(dst, &dp, dst_cap, '\n');
            sp += 2;
            if (sp < src_len && src[sp] == '[') {
                while (sp < src_len && src[sp] != ']') sp++;
                if (sp < src_len) sp++;
            }
            while (sp < src_len && (src[sp] == ' ' || src[sp] == '\t')) sp++;
            continue;
        }

        if (c == '\\' && sp + 7 <= src_len && memcmp(src + sp, "\\begin{", 7) == 0) {
            const char *env_name = NULL;
            size_t env_len = 0;
            size_t begin_len = latex_begin_at(src, src_len, sp, &env_name, &env_len);
            if (begin_len > 0) {
                size_t body_start = sp + begin_len;
                size_t end_off = latex_find_end(src, src_len, body_start, env_name, env_len);
                if (end_off > 0) {
                    char rendered[4096];
                    size_t rlen = latex_render_env(env_name, env_len,
                                                    src + body_start, end_off,
                                                    rendered, sizeof(rendered) - 1);
                    ltx_put(dst, &dp, dst_cap, rendered, rlen);
                    char end_pat[128];
                    _snprintf(end_pat, sizeof(end_pat) - 1, "\\end{%.*s}",
                              (int)env_len, env_name);
                    sp = body_start + end_off + strlen(end_pat);
                    continue;
                }
            }
        }

        if (c == '\\' && sp + 5 <= src_len &&
            memcmp(src + sp, "\\frac", 5) == 0 &&
            (sp + 5 == src_len || src[sp + 5] == '{')) {
            size_t p = sp + 5;
            if (p < src_len && src[p] == '{') {
                size_t num_start = p + 1;
                size_t num_end = latex_skip_brace(src, src_len, p);
                p = (num_end < src_len) ? num_end + 1 : src_len;
                if (p < src_len && src[p] == '{') {
                    size_t den_start = p + 1;
                    size_t den_end = latex_skip_brace(src, src_len, p);
                    p = (den_end < src_len) ? den_end + 1 : src_len;
                    char num_buf[512], den_buf[512];
                    size_t nl = latex_to_unicode(src + num_start, num_end - num_start,
                                                  num_buf, sizeof(num_buf) - 1);
                    num_buf[nl] = 0;
                    size_t dl = latex_to_unicode(src + den_start, den_end - den_start,
                                                  den_buf, sizeof(den_buf) - 1);
                    den_buf[dl] = 0;
                    int vulgar_ok = 0;
                    for (int i = 0; VULGAR_FRACS[i].num; i++) {
                        if (strcmp(num_buf, VULGAR_FRACS[i].num) == 0 &&
                            strcmp(den_buf, VULGAR_FRACS[i].den) == 0) {
                            ltx_puts(dst, &dp, dst_cap, VULGAR_FRACS[i].uni);
                            vulgar_ok = 1; break;
                        }
                    }
                    if (!vulgar_ok) {
                        /* Mirrors imgui_layer.cpp: NUM wraps only on ops,
                         * DEN wraps on ops OR digit+letter ambiguity. */
                        #define HAS_OP(s, len, out_var) do { \
                            out_var = 0; \
                            for (size_t k = 0; k < (len); k++) { \
                                char nc = (s)[k]; \
                                if (nc == '+' || nc == '-' || nc == ' ' || \
                                    nc == '*' || nc == '/' || nc == '=' || \
                                    nc == '(' || nc == ')') { out_var = 1; break; } \
                            } \
                        } while (0)
                        #define IS_AMBIG_DEN(s, len, out_var) do { \
                            int hd = 0, hl = 0; \
                            for (size_t k = 0; k < (len); ) { \
                                unsigned char b = (unsigned char)(s)[k]; \
                                if (b < 0x80) { \
                                    if (b >= '0' && b <= '9') hd = 1; \
                                    else if ((b >= 'a' && b <= 'z') || \
                                             (b >= 'A' && b <= 'Z')) hl = 1; \
                                    k++; \
                                } else if ((b & 0xE0) == 0xC0) { hl = 1; k += 2; } \
                                else if ((b & 0xF0) == 0xE0) { hl = 1; k += 3; } \
                                else if ((b & 0xF8) == 0xF0) { hl = 1; k += 4; } \
                                else k++; \
                            } \
                            out_var = hd && hl; \
                        } while (0)
                        int wrap_num = 0, wrap_den = 0, ambig_den = 0;
                        HAS_OP(num_buf, nl, wrap_num);
                        HAS_OP(den_buf, dl, wrap_den);
                        IS_AMBIG_DEN(den_buf, dl, ambig_den);
                        if (ambig_den) wrap_den = 1;
                        #undef HAS_OP
                        #undef IS_AMBIG_DEN
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
                    size_t tl = latex_to_unicode(src + top_start, top_end - top_start,
                                                  t_buf, sizeof(t_buf) - 1);
                    t_buf[tl] = 0;
                    size_t bl = latex_to_unicode(src + bot_start, bot_end - bot_start,
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

        if (c == '\\' && sp + 5 <= src_len &&
            memcmp(src + sp, "\\sqrt", 5) == 0 &&
            (sp + 5 == src_len || src[sp + 5] == '{' || src[sp + 5] == '[')) {
            size_t p = sp + 5;
            if (p < src_len && src[p] == '[') {
                p++;
                size_t idx_start = p;
                while (p < src_len && src[p] != ']') p++;
                if (p < src_len) {
                    char idx_buf[64];
                    size_t il = latex_to_unicode(src + idx_start, p - idx_start,
                                                  idx_buf, sizeof(idx_buf) - 1);
                    idx_buf[il] = 0;
                    size_t before_dp = dp;
                    if (!try_render_sup_sub(idx_buf, il, 1, dst, &dp, dst_cap)) {
                        dp = before_dp;
                        ltx_put(dst, &dp, dst_cap, idx_buf, il);
                    }
                    p++;
                }
            }
            ltx_puts(dst, &dp, dst_cap, "\xE2\x88\x9A");
            if (p < src_len && src[p] == '{') {
                size_t inner_start = p + 1;
                size_t inner_end = latex_skip_brace(src, src_len, p);
                p = (inner_end < src_len) ? inner_end + 1 : src_len;
                char inner_buf[512];
                size_t il = latex_to_unicode(src + inner_start, inner_end - inner_start,
                                              inner_buf, sizeof(inner_buf) - 1);
                inner_buf[il] = 0;
                /* Wrap heuristic mirrors imgui_layer.cpp. */
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
            } else {
                sp += 5;
                continue;
            }
        }

        {
            int acc = latex_accent_at(src, src_len, sp);
            if (acc >= 0) {
                size_t cmd_len = 1 + strlen(LATEX_ACCENTS[acc].cmd);
                size_t p = sp + cmd_len;
                size_t inner_start = p + 1;
                size_t inner_end = latex_skip_brace(src, src_len, p);
                p = (inner_end < src_len) ? inner_end + 1 : src_len;
                char inner_buf[256];
                size_t il = latex_to_unicode(src + inner_start, inner_end - inner_start,
                                              inner_buf, sizeof(inner_buf) - 1);
                inner_buf[il] = 0;
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

        {
            size_t wrap_cmd = latex_wrapper_at(src, src_len, sp);
            if (wrap_cmd > 0) {
                size_t p = sp + wrap_cmd;
                size_t inner_start = p + 1;
                size_t inner_end = latex_skip_brace(src, src_len, p);
                p = (inner_end < src_len) ? inner_end + 1 : src_len;
                char inner_buf[1024];
                size_t il = latex_to_unicode(src + inner_start, inner_end - inner_start,
                                              inner_buf, sizeof(inner_buf) - 1);
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
                sp = p;
                continue;
            }
        }

        if ((c == '^' || c == '_') && sp + 1 < src_len && src[sp + 1] == '{') {
            char op = c;
            sp += 2;
            size_t inner_start = sp;
            size_t inner_end = latex_skip_brace(src, src_len, sp - 1);
            sp = (inner_end < src_len) ? inner_end + 1 : src_len;
            size_t ilen = inner_end - inner_start;
            char inner_buf[256];
            size_t il = latex_to_unicode(src + inner_start, ilen,
                                          inner_buf, sizeof(inner_buf) - 1);
            inner_buf[il] = 0;
            size_t before_dp = dp;
            int rendered_uni = try_render_sup_sub(inner_buf, il, op == '^',
                                                    dst, &dp, dst_cap);
            if (!rendered_uni) {
                /* Preserve braces on fallback so scope is unambiguous. */
                dp = before_dp;
                ltx_putc(dst, &dp, dst_cap, op);
                ltx_putc(dst, &dp, dst_cap, '{');
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
                ltx_putc(dst, &dp, dst_cap, '}');
            }
            continue;
        }

        /* ^\command / _\command: emit command's Unicode directly, skip op. */
        if ((c == '^' || c == '_') && sp + 1 < src_len && src[sp + 1] == '\\') {
            int idx = latex_match_at(src, src_len, sp + 1);
            if (idx >= 0) {
                size_t tlen = strlen(LATEX_MAP[idx].tex);
                ltx_puts(dst, &dp, dst_cap, LATEX_MAP[idx].uni);
                sp += 1 + tlen;
                continue;
            }
        }

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
        if (c == '_' && sp + 1 < src_len) {
            char nx = src[sp + 1];
            int is_digit = (nx >= '0' && nx <= '9');
            int at_boundary = (sp + 2 >= src_len) ||
                (!(src[sp + 2] >= '0' && src[sp + 2] <= '9') &&
                 !(src[sp + 2] >= 'a' && src[sp + 2] <= 'z') &&
                 !(src[sp + 2] >= 'A' && src[sp + 2] <= 'Z'));
            const char *uni = sub_of(nx);
            int digit_ok = is_digit && (sp + 2 >= src_len ||
                                          !(src[sp + 2] >= '0' && src[sp + 2] <= '9'));
            if (uni && (at_boundary || digit_ok)) {
                ltx_puts(dst, &dp, dst_cap, uni);
                sp += 2;
                continue;
            }
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
            size_t after_bs = sp + 1;
            size_t word_end = after_bs;
            while (word_end < src_len &&
                   ((src[word_end] >= 'a' && src[word_end] <= 'z') ||
                    (src[word_end] >= 'A' && src[word_end] <= 'Z'))) {
                word_end++;
            }
            if (word_end > after_bs && word_end < src_len && src[word_end] == '{') {
                size_t inner_start = word_end + 1;
                size_t inner_end = latex_skip_brace(src, src_len, word_end);
                size_t after = (inner_end < src_len) ? inner_end + 1 : src_len;
                char inner_buf[1024];
                size_t il = latex_to_unicode(src + inner_start, inner_end - inner_start,
                                              inner_buf, sizeof(inner_buf) - 1);
                ltx_put(dst, &dp, dst_cap, inner_buf, il);
                sp = after;
                continue;
            }
            ltx_putc(dst, &dp, dst_cap, '\\');
            sp = after_bs;
            while (sp < word_end) ltx_putc(dst, &dp, dst_cap, src[sp++]);
            continue;
        }

        if (c == '{' || c == '}') { sp++; continue; }
        if (c == '&') { ltx_putc(dst, &dp, dst_cap, ' '); sp++; continue; }

        ltx_putc(dst, &dp, dst_cap, c);
        sp++;
    }
    return dp;
}

static size_t latex_render_env(const char *env, size_t env_len,
                                const char *body, size_t body_len,
                                char *dst, size_t dst_cap) {
    char env_buf[32];
    size_t n = env_len > sizeof(env_buf) - 1 ? sizeof(env_buf) - 1 : env_len;
    memcpy(env_buf, env, n);
    env_buf[n] = 0;
    if (n > 0 && env_buf[n - 1] == '*') env_buf[--n] = 0;

    const char *bracket_open = "";
    const char *bracket_close = "";
    if (strcmp(env_buf, "pmatrix") == 0)      { bracket_open = "( "; bracket_close = " )"; }
    else if (strcmp(env_buf, "bmatrix") == 0) { bracket_open = "[ "; bracket_close = " ]"; }
    else if (strcmp(env_buf, "Bmatrix") == 0) { bracket_open = "{ "; bracket_close = " }"; }
    else if (strcmp(env_buf, "vmatrix") == 0) { bracket_open = "| "; bracket_close = " |"; }
    else if (strcmp(env_buf, "Vmatrix") == 0) { bracket_open = "\xE2\x80\x96 "; bracket_close = " \xE2\x80\x96"; }

    int is_cases = (strcmp(env_buf, "cases") == 0 || strcmp(env_buf, "dcases") == 0);

    size_t bp = 0;
    if (strcmp(env_buf, "array") == 0 && bp < body_len && body[bp] == '{') {
        while (bp < body_len && body[bp] != '}') bp++;
        if (bp < body_len) bp++;
    }
    while (bp < body_len && (body[bp] == ' ' || body[bp] == '\t' ||
                              body[bp] == '\n' || body[bp] == '\r')) bp++;

    const char *sub = body + bp;
    size_t sub_len = body_len - bp;
    while (sub_len > 0 && (sub[sub_len - 1] == ' ' || sub[sub_len - 1] == '\t' ||
                            sub[sub_len - 1] == '\n' || sub[sub_len - 1] == '\r')) sub_len--;
    if (sub_len >= 2 && sub[sub_len - 2] == '\\' && sub[sub_len - 1] == '\\') sub_len -= 2;

    size_t dp = 0;
    size_t rp = 0;
    int row_idx = 0;
    while (rp < sub_len) {
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
        size_t r_start = rp, r_end = row_end;
        while (r_start < r_end && (sub[r_start] == ' ' || sub[r_start] == '\t' ||
                                    sub[r_start] == '\n' || sub[r_start] == '\r')) r_start++;
        while (r_end > r_start && (sub[r_end - 1] == ' ' || sub[r_end - 1] == '\t' ||
                                    sub[r_end - 1] == '\n' || sub[r_end - 1] == '\r')) r_end--;

        if (r_end > r_start) {
            if (row_idx > 0) ltx_putc(dst, &dp, dst_cap, '\n');
            if (is_cases && row_idx == 0) ltx_puts(dst, &dp, dst_cap, "\xE2\x8E\xA7 ");
            else if (is_cases) ltx_puts(dst, &dp, dst_cap, "\xE2\x8E\xA8 ");
            else if (bracket_open[0]) ltx_puts(dst, &dp, dst_cap, bracket_open);

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
                size_t c_start = cp, c_end = cell_end;
                while (c_start < c_end && (sub[c_start] == ' ' || sub[c_start] == '\t')) c_start++;
                while (c_end > c_start && (sub[c_end - 1] == ' ' || sub[c_end - 1] == '\t')) c_end--;
                if (col_idx > 0) {
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

            if (bracket_close[0] && !is_cases) ltx_puts(dst, &dp, dst_cap, bracket_close);
            row_idx++;
        }
        rp = (row_end < sub_len) ? row_end + 2 : sub_len;
        if (rp < sub_len && sub[rp] == '[') {
            while (rp < sub_len && sub[rp] != ']') rp++;
            if (rp < sub_len) rp++;
        }
    }
    return dp;
}

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
