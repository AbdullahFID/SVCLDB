/* answer_strip_test.c — unit-test the copy_answer preamble stripper.
 *
 * Standalone compile (no imgui dependency):
 *   cd payload/test
 *   cl /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS answer_strip_test.c
 *   answer_strip_test.exe
 *
 * Runs the same strip_answer_preambles + asterisk-strip logic that
 * ui_copy_last_ai_answer() calls, and asserts the expected outputs
 * for a suite of real-world AI response shapes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Vendored copy of ui_copy_last_ai_answer's preamble stripper —
 * MUST stay byte-identical with imgui_layer.cpp's implementation.
 * If you tweak one, tweak the other. */

static size_t answer_prefix_match(const char *p, size_t plen,
                                   const char *needle) {
    size_t nl = strlen(needle);
    if (plen < nl) return 0;
    for (size_t i = 0; i < nl; i++) {
        char a = p[i];
        char b = needle[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return nl;
}

static const char *ANSWER_KEYWORDS[] = {
    "the correct answer is",
    "the answer is",
    "correct answer is",
    "correct answer",
    "final answer",
    "the answer",
    "answer is",
    "tl;dr", "tldr",
    "solution", "result",
    "answer",  "ans",
    NULL,
};

static int is_strong_sep_at(const char *p) {
    if (*p == ':' || *p == '=') return 1;
    if ((unsigned char)*p == 0xE2 &&
        (unsigned char)p[1] == 0x80 &&
        (unsigned char)p[2] == 0x94) return 3;
    return 0;
}
static int is_dash_sep_at(const char *p) {
    if (*p != '-') return 0;
    return (p[1] == ' ' || p[1] == '\t') ? 1 : 0;
}

static int keyword_is_copular(const char *kw, size_t kw_len) {
    if (kw_len < 3) return 0;
    return (kw[kw_len - 3] == ' ' &&
            (kw[kw_len - 2] == 'i' || kw[kw_len - 2] == 'I') &&
            (kw[kw_len - 1] == 's' || kw[kw_len - 1] == 'S'));
}

static void strip_answer_preambles(char *buf) {
    if (!buf) return;
    for (int loops = 0; loops < 3; loops++) {
        char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        size_t rem = strlen(p);
        size_t matched = 0;
        size_t consume_extra = 0;
        for (int i = 0; ANSWER_KEYWORDS[i]; i++) {
            const char *kw = ANSWER_KEYWORDS[i];
            size_t m = answer_prefix_match(p, rem, kw);
            if (m == 0) continue;
            size_t extra = 0;
            const char *tail = p + m;
            int copular = keyword_is_copular(kw, m);
            if (*tail == 0) {
                extra = 0;
            } else if (is_strong_sep_at(tail)) {
                extra = is_strong_sep_at(tail);
            } else if (is_dash_sep_at(tail)) {
                extra = 2;
            } else if (*tail == ' ' || *tail == '\t') {
                if (copular) {
                    const char *q = tail;
                    while (*q == ' ' || *q == '\t') q++;
                    extra = (size_t)(q - tail);
                } else {
                    const char *q = tail;
                    while (*q == ' ' || *q == '\t') q++;
                    int ssep = is_strong_sep_at(q);
                    int dsep = is_dash_sep_at(q);
                    if (ssep) extra = (size_t)(q - tail) + (size_t)ssep;
                    else if (dsep) extra = (size_t)(q - tail) + 2;
                    else continue;
                }
            } else {
                continue;
            }
            if (m > matched) { matched = m; consume_extra = extra; }
        }
        if (matched == 0) return;
        p += matched + consume_extra;
        while (*p == ' ' || *p == '\t' || *p == ':' || *p == '=' ||
               (unsigned char)*p == 0xE2 ||
               (*p == '-' && (p[1] == ' ' || p[1] == '\t' || p[1] == 0))) {
            if ((unsigned char)*p == 0xE2 &&
                (unsigned char)p[1] == 0x80 &&
                (unsigned char)p[2] == 0x94) {
                p += 3;
            } else {
                p++;
            }
        }
        memmove(buf, p, strlen(p) + 1);
    }
}

/* Simulated first-line-with-markdown-strip pipeline. */
static char *simulate_copy_answer(const char *reply) {
    if (!reply) return NULL;
    const char *p = reply;
    while (*p && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) p++;
    if (!*p) return NULL;
    const char *nl = strchr(p, '\n');
    size_t line_len = nl ? (size_t)(nl - p) : strlen(p);
    while (line_len > 0 && (p[line_len - 1] == '\r' || p[line_len - 1] == ' ')) line_len--;
    if (line_len == 0) return NULL;

    char *clean = malloc(line_len + 1);
    size_t cl = 0;
    for (size_t k = 0; k < line_len; k++) {
        char c = p[k];
        if (c == '*') {
            if (k + 1 < line_len && p[k + 1] == '*') k++;
            continue;
        }
        if (c == '`') continue;
        clean[cl++] = c;
    }
    clean[cl] = 0;
    strip_answer_preambles(clean);
    return clean;
}

static int g_pass = 0, g_fail = 0;
static void check(const char *label, const char *reply, const char *expected) {
    char *got = simulate_copy_answer(reply);
    if (!got) got = strdup("(nothing)");
    int ok = strcmp(got, expected) == 0;
    printf("%s %-45s | expected=\"%s\" got=\"%s\"\n",
           ok ? "OK  " : "FAIL", label, expected, got);
    if (ok) g_pass++; else g_fail++;
    free(got);
}

int main(void) {
    puts("=== strip_answer_preambles + first-line copy tests ===\n");

    /* Common shapes the AI produces. */
    check("plain single-letter MCQ",   "B",                           "B");
    check("MCQ with description",      "B) Photosynthesis",           "B) Photosynthesis");
    check("Answer prefix + letter",    "Answer: B",                   "B");
    check("Bold answer + letter",      "**Answer:** B",               "B");
    check("Bold answer + long text",   "**Answer:** x = 4",           "x = 4");
    check("The answer is",             "The answer is: 42",           "42");
    check("Final Answer variant",      "Final answer: yes",           "yes");
    check("TL;DR",                     "TL;DR: 3.14",                 "3.14");
    check("Correct answer variant",    "Correct answer: option D",    "option D");
    check("Solution prefix",           "Solution: 2x + 5",            "2x + 5");
    check("Result prefix",             "Result: pass",                "pass");
    check("Ans shortform",             "Ans: 7",                      "7");
    check("Answer with em-dash",       "Answer \xE2\x80\x94 4",       "4");
    check("Prose without preamble",    "The bird is a robin.",        "The bird is a robin.");
    check("Multiline first-line only", "Answer: 42\n\nBecause the...","42");
    check("Bold+markdown+content",     "**B) Photosynthesis**",       "B) Photosynthesis");
    check("Leading whitespace",        "   Answer: 5",                "5");
    check("Mixed case preamble",       "ANSWER: X",                   "X");
    check("Trailing spaces",           "Answer: hi   ",               "hi");
    check("Bullet-list first item",    "- item one",                  "- item one");
    check("Empty then answer line",    "\n\nAnswer: 99",              "99");
    check("Nested Answer prefix",      "Answer: Answer: Y",           "Y");
    check("Numeric bold answer",       "**x = 3.14**",                "x = 3.14");
    check("Code inline in first line", "`ret 0`",                     "ret 0");

    /* Anti-over-match: keyword followed by content (no separator) must NOT strip. */
    check("Answer options (prose)",    "Answer options include A and B", "Answer options include A and B");
    check("Answered by (prose)",       "Answered by 1855",             "Answered by 1855");
    check("Ansible in first line",     "Ansible playbook fails",       "Ansible playbook fails");
    check("Result-oriented (prose)",   "Result-oriented approach.",    "Result-oriented approach.");

    /* Extra separator variants. */
    check("Answer= equals variant",    "Answer = 42",                  "42");
    check("Bold answer + em-dash",     "**Answer** — 4",               "4");
    check("Solution — em-dash",        "Solution — apply chain rule",  "apply chain rule");
    check("The correct answer is X",   "The correct answer is C",      "C");

    printf("\n=== %d/%d passed ===\n", g_pass, g_pass + g_fail);
    if (g_fail == 0) puts("ALL PASS");
    return g_fail ? 1 : 0;
}
