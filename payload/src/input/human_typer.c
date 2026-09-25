/* ================================================================== *
 * human_typer.c -- see human_typer.h. Full C port of hooksdll's       *
 * `human_typer.js` engine.                                            *
 *                                                                     *
 * Grounding for every magic number below:                             *
 *   * Dhakal et al. CHI'18 "Observations on typing from 136 million   *
 *     keystrokes" -- log-normal IKI, hand-alternation speedup,        *
 *     same-finger delay, burst-typing for common words, fatigue ramp. *
 *   * Free-text keystroke-dynamics literature -- tempo momentum       *
 *     (mean-reverting random walk) + 4-kind typo model with immediate *
 *     and delayed backspace correction.                               *
 *                                                                     *
 * Do NOT round the constants down to "nicer" values. They are         *
 * grounded and tuned; each one is load-bearing against a specific     *
 * statistical fingerprint of AI-generated input. If a future edit     *
 * wants to change one, verify against the CHI'18 tables first.        *
 *                                                                     *
 * The engine is thread-safe for single-caller-at-a-time:              *
 *   `human_type_start` refuses if a session is already active; the    *
 *   next start is only accepted after the previous session's worker   *
 *   thread exits (which happens ~immediately after the last char OR   *
 *   Esc cancel).                                                      *
 *                                                                     *
 * Every keystroke goes through `input/inject.c` primitives which      *
 * self-mark as synth via `inj_set_synth(1)` -- our own LL keyboard    *
 * hook rejects LLKHF_INJECTED events, so the engine's SendInput can   *
 * never re-fire our own hotkeys. When on an isolated desktop the      *
 * same primitives route via secure_inject.c -> winlogon helper.       *
 * ================================================================== */
#include "../../../shared/common.h"
#include "human_typer.h"
#include "inject.h"
#include "secure_inject.h"
#include "../clipboard_out.h"
#include "../../../shared/log_secure.h"
/* v7.3 (2026-09-24) -- hoisted from inside human_type_default_opts()
 * (was at line ~469) so ht_is_esc() near the top of this file can also
 * read as_cfg()->typer_cancel_vk. */
#include "../autosolver/as_cfg.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

/* External: helper flag telling us to route to winlogon helper. */
extern int  rawin_is_isolated_desktop(void);

/* ══════════════════════════════════════════════════════
 * Appendix B -- HumanTypingConfig (verbatim from macOS)
 * ══════════════════════════════════════════════════════ */

typedef struct {
    /* Log-normal IKI scatter. */
    double log_normal_sigma;

    /* Hand / finger bigram model. */
    int    enable_hand_model;
    double repetition_speedup;         /* < 1 = faster (double letters bounce) */
    double same_finger_delay_mult;     /* same finger, different key = slower  */
    double same_hand_mult;             /* same hand, different finger = slower */
    double hand_alternation_mult;      /* opposite hands = faster              */

    /* Tempo momentum -- mean-reverting random walk. */
    int    enable_tempo_momentum;
    double tempo_drift_step;
    double tempo_reversion;
    double tempo_min;
    double tempo_max;

    /* Initial planning pause -- writers stage a sentence before typing. */
    double initial_planning_pause_min;
    double initial_planning_pause_max;

    /* Reach penalties. */
    double shift_key_delay_mult;
    double number_row_delay_mult;

    /* Word familiarity. */
    int    enable_burst_typing;
    double burst_speed_mult;           /* common words -> /1.5 (faster)        */
    double unfamiliar_slowdown;        /* unfamiliar long words -> /0.65        */
    int    unfamiliar_word_length;

    /* Fatigue (disabled above 200 WPM). */
    int    enable_fatigue;
    int    fatigue_start_char;
    double max_fatigue_slowdown;
    int    fatigue_ramp_chars;

    /* Thinking pauses (occasional at word boundaries). */
    int    enable_thinking_pauses;
    double thinking_pause_rate;
    double thinking_pause_duration_min;
    double thinking_pause_duration_max;

    /* Post-character dwell by punctuation. */
    double sentence_end_delay_min;
    double sentence_end_delay_max;
    double pause_punctuation_delay_min;
    double pause_punctuation_delay_max;
    double word_boundary_delay_min;
    double word_boundary_delay_max;
    double newline_delay_min;
    double newline_delay_max;

    /* Typo model. */
    int    enable_typos;
    double typo_rate;
    double typo_fix_rate;
    double immediate_fix_rate;
    int    delayed_fix_char_min;
    int    delayed_fix_char_max;
    double typo_transposition_weight;
    double typo_substitution_weight;
    double typo_doubling_weight;
    double typo_omission_weight;

    /* Hard floor / ceiling on any single inter-key gap (seconds). */
    double min_key_delay;
    double max_key_delay;
} human_typer_cfg_t;

static const human_typer_cfg_t CFG = {
    /*log_normal_sigma*/ 0.50,

    /*enable_hand_model*/       1,
    /*repetition_speedup*/      0.62,
    /*same_finger_delay_mult*/  1.40,
    /*same_hand_mult*/          1.07,
    /*hand_alternation_mult*/   0.90,

    /*enable_tempo_momentum*/   1,
    /*tempo_drift_step*/        0.06,
    /*tempo_reversion*/         0.05,
    /*tempo_min*/               0.80,
    /*tempo_max*/               1.28,

    /*initial_planning_pause_min*/ 0.20,
    /*initial_planning_pause_max*/ 0.85,

    /*shift_key_delay_mult*/    1.15,
    /*number_row_delay_mult*/   1.22,

    /*enable_burst_typing*/     1,
    /*burst_speed_mult*/        1.5,
    /*unfamiliar_slowdown*/     0.65,
    /*unfamiliar_word_length*/  7,

    /*enable_fatigue*/          1,
    /*fatigue_start_char*/      200,
    /*max_fatigue_slowdown*/    0.15,
    /*fatigue_ramp_chars*/      500,

    /*enable_thinking_pauses*/  1,
    /*thinking_pause_rate*/           0.05,
    /*thinking_pause_duration_min*/   0.30,
    /*thinking_pause_duration_max*/   1.50,

    /*sentence_end_delay_min*/        0.18,
    /*sentence_end_delay_max*/        0.55,
    /*pause_punctuation_delay_min*/   0.06,
    /*pause_punctuation_delay_max*/   0.22,
    /*word_boundary_delay_min*/       0.01,
    /*word_boundary_delay_max*/       0.08,
    /*newline_delay_min*/             0.25,
    /*newline_delay_max*/             0.70,

    /*enable_typos*/            1,
    /*typo_rate*/               0.025,
    /*typo_fix_rate*/           0.97,
    /*immediate_fix_rate*/      0.80,
    /*delayed_fix_char_min*/    1,
    /*delayed_fix_char_max*/    5,
    /*typo_transposition_weight*/ 0.40,
    /*typo_substitution_weight*/  0.32,
    /*typo_doubling_weight*/      0.14,
    /*typo_omission_weight*/      0.14,

    /*min_key_delay*/           0.012,
    /*max_key_delay*/           2.50,
};

/* ══════════════════════════════════════════════════════
 * QWERTY layout tables (verbatim from JS)
 * ══════════════════════════════════════════════════════ */

/* Finger map: 0..7 = left-pinky, left-ring, left-middle, left-index,
 *             right-index, right-middle, right-ring, right-pinky. */
static const struct { int finger; const char *chars; } FINGER_ROWS[] = {
    {0, "qaz1`"},
    {1, "wsx2"},
    {2, "edc3"},
    {3, "rfv4tgb5"},
    {4, "yhn6ujm7"},
    {5, "ik,8"},
    {6, "ol.9"},
    {7, "p;/0[]'-="},
};

/* Hand map: 0 = left, 1 = right. */
static const char *HAND_LEFT  = "qwertasdfgzxcvb12345`";
static const char *HAND_RIGHT = "yuiophjklnm67890[];',./-=";

/* Return finger index [0..7] for lowercase `ch`, or -1 if unknown. */
static int ht_finger_of(char ch) {
    for (int i = 0; i < (int)(sizeof(FINGER_ROWS)/sizeof(FINGER_ROWS[0])); i++) {
        const char *p = FINGER_ROWS[i].chars;
        while (*p) { if (*p == ch) return FINGER_ROWS[i].finger; p++; }
    }
    return -1;
}
/* Return hand: 0 = left, 1 = right, -1 = unknown. */
static int ht_hand_of(char ch) {
    for (const char *p = HAND_LEFT;  *p; p++) if (*p == ch) return 0;
    for (const char *p = HAND_RIGHT; *p; p++) if (*p == ch) return 1;
    return -1;
}

/* QWERTY physical adjacency for substitution typos. Small hand-coded
 * table keyed by lowercase char -> up to 8 neighbours (NUL-terminated). */
typedef struct { char ch; const char *adj; } ht_adj_t;
static const ht_adj_t ADJACENT[] = {
    {'q', "wa12"},  {'w', "qeas23"}, {'e', "wrsd34"}, {'r', "etdf45"},
    {'t', "ryfg56"},{'y', "tugh67"}, {'u', "yihj78"}, {'i', "uojk89"},
    {'o', "ipkl90"},{'p', "ol[;0-"}, {'a', "qwsz"},   {'s', "awedxz"},
    {'d', "serfcx"},{'f', "drtgvc"}, {'g', "ftyhbv"}, {'h', "gyujnb"},
    {'j', "huikmn"},{'k', "jiol,m"}, {'l', "kop;,./"},{'z', "asx"},
    {'x', "zsdc"},  {'c', "xdfv"},   {'v', "cfgb"},   {'b', "vghn"},
    {'n', "bhjm"},  {'m', "njk,"},   {' ', "cvbnm"},
};
static const char *ht_adj_lookup(char ch) {
    for (size_t i = 0; i < sizeof(ADJACENT)/sizeof(ADJACENT[0]); i++)
        if (ADJACENT[i].ch == ch) return ADJACENT[i].adj;
    return NULL;
}

/* Visual / phonetic confusion pairs. */
static const ht_adj_t CONFUSION[] = {
    {'i', "oe"},  {'o', "ip0"}, {'e', "ri3"}, {'r', "et"},
    {'t', "ry"},  {'n', "mb"},  {'m', "n"},   {'a', "se"},
    {'s', "ad"},  {'c', "vx"},  {'u', "iy"},  {'b', "vn"},
    {'p', "o0"},  {'l', "1i"},  {'0', "o9"},  {'1', "li"},
};
static const char *ht_conf_lookup(char ch) {
    for (size_t i = 0; i < sizeof(CONFUSION)/sizeof(CONFUSION[0]); i++)
        if (CONFUSION[i].ch == ch) return CONFUSION[i].adj;
    return NULL;
}

/* Common-word set -- drives burst-typing speedup. Verbatim from JS. */
static const char *COMMON_WORDS[] = {
    "the","a","an","i","you","he","she","it","we","they",
    "me","him","her","us","them","my","your","his","its",
    "our","their","this","that","these","those","who","what",
    "is","am","are","was","were","be","been","being",
    "have","has","had","do","does","did","will","would",
    "could","should","may","might","must","shall","can",
    "go","going","went","gone","get","got","make","made",
    "know","knew","known","think","thought","see","saw",
    "come","came","take","took","want","use","find","give",
    "tell","say","said","work","call","try","ask","need",
    "feel","become","leave","put","mean","keep","let","begin",
    "and","but","or","if","then","so","because","when",
    "where","how","why","which","while","after",
    "before","since","until","although","though","unless",
    "in","on","at","to","for","with","by","from","up",
    "down","out","off","over","under","about","into","through",
    "not","no","yes","all","any","some","many","much",
    "more","most","other","such","only","just","also","well",
    "very","even","still","already","always","never","often",
    "good","new","first","last","long","great","little","own",
    "old","right","big","high","small","large","next","early",
    "young","important","few","public","bad","same","able",
    NULL
};

static int ht_is_common_word(const char *lowered_word) {
    if (!lowered_word || !*lowered_word) return 0;
    for (int i = 0; COMMON_WORDS[i]; i++)
        if (strcmp(COMMON_WORDS[i], lowered_word) == 0) return 1;
    return 0;
}

/* ══════════════════════════════════════════════════════
 * RNG + math helpers
 * ══════════════════════════════════════════════════════ */

static double ht_uniform_01(void) {
    /* rand()/RAND_MAX is fine here -- we don't need crypto quality; we
     * need statistical variance across characters. Seed once per session
     * from GetTickCount to decorrelate identical texts. */
    return (double)rand() / (double)RAND_MAX;
}
static double ht_rng(double a, double b) {
    return a + ht_uniform_01() * (b - a);
}
/* Standard normal via Box-Muller. */
static double ht_gaussian(void) {
    double u = 0, v = 0;
    while (u == 0) u = ht_uniform_01();
    while (v == 0) v = ht_uniform_01();
    return sqrt(-2.0 * log(u)) * cos(2.0 * 3.14159265358979323846 * v);
}
static void ht_sleep_ms(double ms) {
    if (ms < 1) ms = 1;
    Sleep((DWORD)(ms + 0.5));
}
static int ht_is_esc(void) {
    /* v7.3 (2026-09-24) -- Honor the user-configurable autotyper cancel
     * key (default VK_ESCAPE).  This is a belt-and-suspenders secondary
     * check -- the LL keyboard hook's cancel path (rawinput_hook.c
     * ll_kbd_proc and dispatch_external_key) is the primary trigger
     * because it fires INSTANTLY on the physical keydown even when
     * this worker is deep inside a Sleep().  This check catches the
     * rare case where the LL hook cancel hasn't yet propagated to
     * g_cancel by the time we sample it here (e.g. rapid tap during
     * a burst of typos).  Only fires on Default desktop -- on an iso
     * desktop GetAsyncKeyState is desktop-blind so we rely 100% on
     * the pipe-dispatched cancel from wl_input's LL hook. */
    const as_settings_t *asc = as_cfg();
    int cancel_vk = asc ? asc->typer_cancel_vk : VK_ESCAPE;
    if (cancel_vk <= 0 || cancel_vk > 0xFF) return 0;  /* disabled */
    return (GetAsyncKeyState(cancel_vk) & 0x8000) != 0;
}

/* Wait until Ctrl/Shift/Alt are all physically UP -- otherwise our first
 * few keystrokes would combine with a still-held modifier (Shift+t types
 * T, Ctrl+v triggers paste on top of our paste, etc.). Bounded at
 * `max_ms`. Returns the ms actually waited. */
static int ht_wait_modifiers_released(int max_ms) {
    int waited = 0;
    while (waited < max_ms) {
        int c = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        int s = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) != 0;
        int a = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;
        if (!c && !s && !a) break;
        Sleep(20); waited += 20;
    }
    Sleep(50);   /* tiny settle so keyup events flush through the queue */
    return waited;
}

/* ══════════════════════════════════════════════════════
 * State
 * ══════════════════════════════════════════════════════ */

static volatile LONG g_typing     = 0;      /* 0 = idle, 1 = worker running    */
static volatile LONG g_cancel     = 0;      /* set to abort current session    */
/* v-audit-hardening (2026-09-23): worker thread handle, kept so
 * `human_type_shutdown()` can cancel-and-join before unload.  Prior
 * code discarded the handle via CloseHandle right after CreateThread,
 * leaving no way to prevent post-unload code execution.  See P1
 * comment in `human_type_start()`. */
static void * volatile g_ht_thread = NULL;
static double        g_tempo      = 1.0;    /* tempo momentum, reset per sess. */
static CRITICAL_SECTION g_prefs_cs;
static int           g_prefs_cs_init = 0;
static int           g_prefs_loaded   = 0;
static int           g_pref_wpm       = 110;
static int           g_pref_humanize  = 1;
static int           g_pref_paste     = 0;

static void ht_ensure_prefs_cs(void) {
    if (!g_prefs_cs_init) { InitializeCriticalSection(&g_prefs_cs); g_prefs_cs_init = 1; }
}

/* ══════════════════════════════════════════════════════
 * Prefs on-disk store -- SVC_INSTALL_DIR\typer.json
 * (matches hooksdll's typer_settings.json shape; simple key=value
 * lines so we don't need a JSON parser here).
 * ══════════════════════════════════════════════════════ */

static void ht_prefs_path(char *out, size_t cap) {
    _snprintf(out, cap - 1, "%s\\typer_settings.txt", SVC_INSTALL_DIR);
    out[cap - 1] = 0;
}

void human_type_load_prefs(void) {
    ht_ensure_prefs_cs();
    EnterCriticalSection(&g_prefs_cs);
    if (g_prefs_loaded) { LeaveCriticalSection(&g_prefs_cs); return; }
    g_prefs_loaded = 1;
    char path[MAX_PATH];
    ht_prefs_path(path, sizeof(path));
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_prefs_cs);
        return;
    }
    char buf[512];
    DWORD n = 0;
    if (!ReadFile(h, buf, sizeof(buf) - 1, &n, NULL)) n = 0;
    CloseHandle(h);
    buf[n] = 0;
    /* Very small parser: `wpm=NNN\nhumanize=N\npaste=N\n`. */
    char *line = buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *eq = strchr(line, '=');
        if (eq) {
            *eq = 0;
            int val = atoi(eq + 1);
            if      (!strcmp(line, "wpm"))      g_pref_wpm      = (val < 30 ? 30 : val > 500 ? 500 : val);
            else if (!strcmp(line, "humanize")) g_pref_humanize = val ? 1 : 0;
            else if (!strcmp(line, "paste"))    g_pref_paste    = val ? 1 : 0;
        }
        if (!nl) break;
        line = nl + 1;
    }
    LeaveCriticalSection(&g_prefs_cs);
}

void human_type_save_prefs(void) {
    ht_ensure_prefs_cs();
    EnterCriticalSection(&g_prefs_cs);
    char path[MAX_PATH];
    ht_prefs_path(path, sizeof(path));
    CreateDirectoryA(SVC_INSTALL_DIR, NULL);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char blob[256];
        int n = _snprintf(blob, sizeof(blob) - 1,
                          "wpm=%d\nhumanize=%d\npaste=%d\n",
                          g_pref_wpm, g_pref_humanize, g_pref_paste);
        if (n > 0 && n < (int)sizeof(blob)) {
            DWORD w = 0;
            WriteFile(h, blob, (DWORD)n, &w, NULL);
        }
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_prefs_cs);
}

int  human_type_get_wpm(void)      { human_type_load_prefs(); return g_pref_wpm; }
void human_type_set_wpm(int wpm)   {
    ht_ensure_prefs_cs();
    EnterCriticalSection(&g_prefs_cs);
    if (wpm < 30)  wpm = 30;
    if (wpm > 500) wpm = 500;
    g_pref_wpm = wpm;
    LeaveCriticalSection(&g_prefs_cs);
    human_type_save_prefs();
}
int  human_type_get_humanize(void)      { human_type_load_prefs(); return g_pref_humanize; }
void human_type_set_humanize(int h)     {
    ht_ensure_prefs_cs();
    EnterCriticalSection(&g_prefs_cs);
    g_pref_humanize = h ? 1 : 0;
    LeaveCriticalSection(&g_prefs_cs);
    human_type_save_prefs();
}
int  human_type_get_paste_mode(void)    { human_type_load_prefs(); return g_pref_paste; }
void human_type_set_paste_mode(int p)   {
    ht_ensure_prefs_cs();
    EnterCriticalSection(&g_prefs_cs);
    g_pref_paste = p ? 1 : 0;
    LeaveCriticalSection(&g_prefs_cs);
    human_type_save_prefs();
}

/* v17 (2026-09-23) -- Read defaults from autosolver.json (as_cfg) first,
 * legacy typer_settings.txt as fallback. Electron dashboard writes
 * autosolver.json, so any live-edit there is picked up on the next
 * human_type_start() without a re-inject. If as_cfg is uninitialized
 * (e.g. very early boot before init_thread's as_cfg_load()), the load
 * call inside as_cfg() ensures we still get sane defaults.
 * v7.3 (2026-09-24) -- header moved to top-of-file so ht_is_esc()
 * can also read from as_cfg (was previously only visible from this
 * function down). */

void human_type_default_opts(human_typer_opts_t *opts) {
    if (!opts) return;
    const as_settings_t *s = as_cfg();
    /* Fall back to per-payload prefs if autosolver.json is somehow missing
     * a field (both source paths clamp to sane ranges internally). */
    human_type_load_prefs();
    opts->wpm              = (s && s->typer_wpm > 0) ? s->typer_wpm : g_pref_wpm;
    opts->humanize         = (s) ? s->typer_humanize : g_pref_humanize;
    opts->planning_pause   = (s) ? s->typer_planning : 1;
    opts->wait_mod_release = (s) ? s->typer_wait_mods : 1;
    opts->esc_cancels      = 1;
    opts->paste_mode       = (s) ? s->typer_paste_mode : g_pref_paste;
}

/* ══════════════════════════════════════════════════════
 * UTF-8 helpers
 * ══════════════════════════════════════════════════════ */

/* Decode ONE UTF-8 codepoint starting at *p, advancing *p past it.
 * Returns 0 (end) or the codepoint. Silently repairs invalid bytes by
 * treating them as ISO-8859-1 fallback. */
static unsigned int ht_utf8_next(const char **p) {
    const unsigned char *b = (const unsigned char *)*p;
    if (!b[0]) return 0;
    unsigned int cp;
    int adv;
    if (b[0] < 0x80)                      { cp = b[0]; adv = 1; }
    else if ((b[0] & 0xE0) == 0xC0 && b[1]) {
        cp = ((b[0] & 0x1F) << 6) | (b[1] & 0x3F); adv = 2;
    }
    else if ((b[0] & 0xF0) == 0xE0 && b[1] && b[2]) {
        cp = ((b[0] & 0x0F) << 12) | ((b[1] & 0x3F) << 6) | (b[2] & 0x3F); adv = 3;
    }
    else if ((b[0] & 0xF8) == 0xF0 && b[1] && b[2] && b[3]) {
        cp = ((b[0] & 0x07) << 18) | ((b[1] & 0x3F) << 12) |
             ((b[2] & 0x3F) << 6)  | (b[3] & 0x3F); adv = 4;
    }
    else { cp = b[0]; adv = 1; }
    *p = (const char *)(b + adv);
    return cp;
}

/* ══════════════════════════════════════════════════════
 * Emission primitives
 * ══════════════════════════════════════════════════════ */

/* Fire one codepoint via SendInput (routed through inj_char which
 * self-marks LLKHF_INJECTED so our LL hook rejects it). */
static void ht_emit_cp(unsigned int cp) {
    inj_char(cp);
}
/* Fire one specific ASCII character via UTF-8 encoding of a codepoint. */
static void ht_emit_ascii(char ch) {
    ht_emit_cp((unsigned int)(unsigned char)ch);
}
/* Backspace = VK_BACK make+break. */
static void ht_emit_backspace(void) {
    inj_vk(VK_BACK, 1, 0);
    Sleep(1);
    inj_vk(VK_BACK, 0, 0);
}
static void ht_backspace_n(int n, int base_delay_ms) {
    for (int i = 0; i < n; i++) {
        if (g_cancel || ht_is_esc()) { g_cancel = 1; return; }
        ht_emit_backspace();
        ht_sleep_ms(base_delay_ms + ht_uniform_01() * 30);
    }
}

/* ══════════════════════════════════════════════════════
 * Typo helpers
 * ══════════════════════════════════════════════════════ */

typedef enum {
    TYPO_TRANSPOSE = 0,
    TYPO_SUBSTITUTE,
    TYPO_DOUBLE,
    TYPO_OMIT,
} ht_typo_kind_t;

/* Pick a weighted-random typo kind. Some kinds require a differing next
 * codepoint (transpose, omit); we filter those out. */
static ht_typo_kind_t ht_pick_typo_kind(unsigned int cur, unsigned int next) {
    double w_sub = CFG.typo_substitution_weight;
    double w_dbl = CFG.typo_doubling_weight;
    double w_trn = 0, w_omt = 0;
    if (next && next != cur) {
        w_trn = CFG.typo_transposition_weight;
        w_omt = CFG.typo_omission_weight;
    }
    double total = w_sub + w_dbl + w_trn + w_omt;
    double r = ht_uniform_01() * total;
    r -= w_sub; if (r <= 0) return TYPO_SUBSTITUTE;
    r -= w_dbl; if (r <= 0) return TYPO_DOUBLE;
    r -= w_trn; if (r <= 0) return TYPO_TRANSPOSE;
    return TYPO_OMIT;
}

/* Return a substitute character for `ch`. 60% adjacent key, 20% same
 * key (a doubled/held press), 20% visual confusion pair. Falls back to
 * `ch` itself if no table entry exists. */
static char ht_pick_substitute(char ch) {
    char low = (char)tolower((unsigned char)ch);
    double r = ht_uniform_01();
    if (r < 0.60) {
        const char *adj = ht_adj_lookup(low);
        if (adj && *adj) {
            int n = (int)strlen(adj);
            return adj[rand() % n];
        }
    }
    if (r < 0.80) return low;
    const char *conf = ht_conf_lookup(low);
    if (conf && *conf) {
        int n = (int)strlen(conf);
        return conf[rand() % n];
    }
    const char *adj = ht_adj_lookup(low);
    if (adj && *adj) {
        int n = (int)strlen(adj);
        return adj[rand() % n];
    }
    return low;
}

/* ══════════════════════════════════════════════════════
 * Core engine
 * ══════════════════════════════════════════════════════ */

/* One "delayed fix" record. Only ONE fix can be in flight at a time; a
 * new typo cannot start while a previous delayed fix is armed (matches
 * JS engine). */
typedef struct {
    int  active;
    int  remaining;                 /* chars-until-fix countdown  */
    char run_chars[16];             /* wrong codepoints typed so far */
    int  run_len;
} ht_pending_fix_t;

static void ht_perform(const char *utf8, human_typer_opts_t opts) {
    /* Session-local seed decorrelation. */
    srand((unsigned)GetTickCount() ^ (unsigned)(uintptr_t)utf8);

    int base_wpm = opts.wpm;
    if (base_wpm < 20)  base_wpm = 20;
    if (base_wpm > 500) base_wpm = 500;
    /* speed_scale ramps DOWN all human overhead as WPM rises. */
    double speed_scale = 110.0 / (double)base_wpm;
    if (speed_scale < 0.12) speed_scale = 0.12;
    if (speed_scale > 1.00) speed_scale = 1.00;

    /* Routing: SEB / secure desktop -> helper pipe; Default -> local SendInput. */
    int iso = rawin_is_isolated_desktop();
    inj_set_secure(iso ? 1 : 0);
    inj_set_synth(1);

    /* Wait for Ctrl/Shift/Alt release so the first char doesn't
     * combine with the hotkey's own held modifiers. */
    if (opts.wait_mod_release) {
        int waited = ht_wait_modifiers_released(1500);
        (void)waited;
    }

    /* PASTE mode: write to clipboard, send Ctrl+V, done. No humanization
     * beyond a random-lag modifier release. */
    if (opts.paste_mode) {
        if (utf8 && *utf8) {
            clip_set_utf8(utf8);
            /* Small settle so target app sees a fresh clipboard state. */
            Sleep(60 + rand() % 40);
            /* Ctrl+V chord. */
            inj_vk(VK_CONTROL, 1, 0);
            Sleep(15 + rand() % 20);
            inj_vk('V',        1, 0);
            Sleep(20 + rand() % 25);
            inj_vk('V',        0, 0);
            Sleep(10 + rand() % 15);
            inj_vk(VK_CONTROL, 0, 0);
        }
        inj_set_synth(0);
        inj_set_secure(0);
        return;
    }

    /* Initial planning pause. */
    if (opts.humanize && opts.planning_pause) {
        double p = ht_rng(CFG.initial_planning_pause_min,
                          CFG.initial_planning_pause_max) * 1000.0 * speed_scale;
        ht_sleep_ms(p);
        if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; goto done; }
    }

    /* Reset tempo. */
    g_tempo = 1.0;

    int total_typed = 0;
    unsigned int prev_cp = 0;
    char word[64]; int word_len = 0;
    ht_pending_fix_t fix = {0};

    const char *p = utf8;
    /* Two-char lookahead so we can peek at the "next" char for typo
     * kind selection (transpose / omission require next != cur). */
    for (;;) {
        if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
        const char *save_p = p;
        unsigned int cp = ht_utf8_next(&p);
        if (!cp) break;
        const char *peek_p = p;
        unsigned int next_cp = ht_utf8_next(&peek_p);
        (void)save_p;

        /* Word tracking (ASCII letters only for the common-word test). */
        int prev_word_len = word_len;
        if (cp < 128 && isalpha((int)cp)) {
            if (word_len < (int)sizeof(word) - 1) {
                word[word_len++] = (char)tolower((int)cp);
                word[word_len] = 0;
            }
        } else {
            word_len = 0; word[0] = 0;
        }

        /* Base inter-key delay from WPM (chars/sec = wpm*5/60). */
        double delay = 60.0 / ((double)base_wpm * 5.0);

        if (opts.humanize) {
            /* Bigram hand/finger model. */
            if (CFG.enable_hand_model && prev_cp && prev_cp < 128 && cp < 128) {
                char lp = (char)tolower((int)prev_cp);
                char lc = (char)tolower((int)cp);
                int  pf = ht_finger_of(lp);
                int  cf = ht_finger_of(lc);
                int  ph = ht_hand_of(lp);
                int  ch = ht_hand_of(lc);
                if (lp == lc) delay *= CFG.repetition_speedup;
                else if (pf >= 0 && cf >= 0 && pf == cf) delay *= CFG.same_finger_delay_mult;
                else if (ph >= 0 && ch >= 0)
                    delay *= (ph == ch) ? CFG.same_hand_mult : CFG.hand_alternation_mult;
            }

            /* Word familiarity burst / slowdown. */
            if (CFG.enable_burst_typing && word_len > 0) {
                if (ht_is_common_word(word)) delay /= CFG.burst_speed_mult;
                else if (word_len >= CFG.unfamiliar_word_length) delay /= CFG.unfamiliar_slowdown;
            }

            /* Fatigue (disabled above 200 WPM). */
            if (CFG.enable_fatigue && base_wpm < 200 && total_typed > CFG.fatigue_start_char) {
                double ramp = (double)(total_typed - CFG.fatigue_start_char) /
                              (double)CFG.fatigue_ramp_chars;
                if (ramp > 1.0) ramp = 1.0;
                delay *= (1.0 + ramp * CFG.max_fatigue_slowdown);
            }

            /* Reach penalties. */
            if (cp < 128 && cp >= 'A' && cp <= 'Z') delay *= CFG.shift_key_delay_mult;
            if (cp < 128 && cp >= '0' && cp <= '9') delay *= CFG.number_row_delay_mult;

            /* Tempo momentum. */
            if (CFG.enable_tempo_momentum) {
                g_tempo += ht_gaussian() * CFG.tempo_drift_step;
                g_tempo += (1.0 - g_tempo) * CFG.tempo_reversion;
                if (g_tempo < CFG.tempo_min) g_tempo = CFG.tempo_min;
                if (g_tempo > CFG.tempo_max) g_tempo = CFG.tempo_max;
                delay *= g_tempo;
            }

            /* Log-normal scatter: delay = median * exp(sigma * N(0,1)). */
            double sigma = CFG.log_normal_sigma * (speed_scale < 0.55 ? 0.55 : speed_scale);
            delay *= exp(sigma * ht_gaussian());
        }

        /* Hard clamp. */
        if (delay < CFG.min_key_delay) delay = CFG.min_key_delay;
        if (delay > CFG.max_key_delay) delay = CFG.max_key_delay;

        ht_sleep_ms(delay * 1000.0);
        if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }

        /* Optional typo injection (ASCII letters only, no pending fix). */
        int typo_fired = 0;
        if (opts.humanize && CFG.enable_typos && !fix.active &&
            cp < 128 && isalpha((int)cp) &&
            ht_uniform_01() < CFG.typo_rate * speed_scale) {

            ht_typo_kind_t kind = ht_pick_typo_kind(cp, next_cp);
            int will_fix   = ht_uniform_01() < CFG.typo_fix_rate;
            int immediate  = ht_uniform_01() < CFG.immediate_fix_rate;

            if (kind == TYPO_TRANSPOSE && next_cp && next_cp != cp && next_cp < 128) {
                /* Type next then current -- classic "teh" slip. */
                ht_emit_cp(next_cp);
                if (will_fix) {
                    ht_sleep_ms(ht_rng(120, 450));
                    if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
                    ht_backspace_n(1, 35);
                    ht_emit_cp(cp);
                    ht_sleep_ms(ht_rng(40, 90));
                    ht_emit_cp(next_cp);
                    /* Skip forward past next_cp too. */
                    p = peek_p; prev_cp = next_cp; total_typed += 2; typo_fired = 1;
                } else {
                    p = peek_p; prev_cp = cp; total_typed += 2; typo_fired = 1;
                }
            } else if (kind == TYPO_DOUBLE) {
                ht_emit_cp(cp);
                Sleep(20);
                ht_emit_cp(cp);
                if (will_fix) {
                    ht_sleep_ms(ht_rng(120, 380));
                    if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
                    ht_backspace_n(1, 35);
                }
                prev_cp = cp; total_typed += 1; typo_fired = 1;
            } else if (kind == TYPO_OMIT && next_cp && next_cp != cp && next_cp < 128) {
                /* Skip current -- type next in its place. */
                ht_emit_cp(next_cp);
                if (will_fix) {
                    ht_sleep_ms(ht_rng(140, 440));
                    if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
                    ht_backspace_n(1, 35);
                    ht_emit_cp(cp);
                    ht_sleep_ms(ht_rng(40, 90));
                    ht_emit_cp(next_cp);
                    p = peek_p; prev_cp = next_cp; total_typed += 2; typo_fired = 1;
                } else {
                    p = peek_p; prev_cp = next_cp; total_typed += 1; typo_fired = 1;
                }
            } else {
                /* Substitution -- fires for any letter regardless of next_cp. */
                char wrong = ht_pick_substitute((char)cp);
                ht_emit_ascii(wrong);
                if (will_fix && immediate) {
                    ht_sleep_ms(ht_rng(120, 450));
                    if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
                    ht_backspace_n(1, 35);
                    ht_emit_cp(cp);
                    ht_sleep_ms(ht_rng(40, 90));
                    prev_cp = cp; total_typed += 1; typo_fired = 1;
                } else if (will_fix) {
                    /* Delayed correction: leave the typo in for
                     * delayed_fix_char_min..max chars, then backspace
                     * the run and retype it. */
                    int window = CFG.delayed_fix_char_min +
                                 rand() % (CFG.delayed_fix_char_max -
                                           CFG.delayed_fix_char_min + 1);
                    fix.active    = 1;
                    fix.remaining = window;
                    fix.run_len   = 1;
                    fix.run_chars[0] = (char)wrong;
                    prev_cp = (unsigned int)wrong; total_typed += 1; typo_fired = 1;
                } else {
                    /* Uncorrected substitution -- leave it. */
                    prev_cp = (unsigned int)wrong; total_typed += 1; typo_fired = 1;
                }
            }
        }

        /* Normal emission (if a typo above didn't handle this char). */
        if (!typo_fired) {
            ht_emit_cp(cp);
            total_typed++;
            /* If a delayed fix is armed and this char happened to land
             * in its window, extend the "run" to include it -- when the
             * fix fires we backspace ALL the chars typed after the
             * wrong one. */
            if (fix.active && cp < 128 && fix.run_len < (int)sizeof(fix.run_chars) - 1) {
                fix.run_chars[fix.run_len++] = (char)cp;
                fix.run_chars[fix.run_len]   = 0;
            }
        }

        /* Post-character dwell (punctuation rhythm). */
        if (opts.humanize && !typo_fired) {
            double pd = 0;
            if (cp < 128 && (cp == '.' || cp == '!' || cp == '?'))
                pd = ht_rng(CFG.sentence_end_delay_min, CFG.sentence_end_delay_max);
            else if (cp < 128 && (cp == ',' || cp == ';' || cp == ':'))
                pd = ht_rng(CFG.pause_punctuation_delay_min, CFG.pause_punctuation_delay_max);
            else if (cp == ' ')
                pd = ht_rng(CFG.word_boundary_delay_min, CFG.word_boundary_delay_max);
            else if (cp == '\n' || cp == '\r')
                pd = ht_rng(CFG.newline_delay_min, CFG.newline_delay_max);
            if (pd > 0) {
                ht_sleep_ms(pd * speed_scale * 1000.0);
                if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
            }

            /* Occasional thinking pause at word boundaries. */
            if (CFG.enable_thinking_pauses && cp == ' ' && prev_word_len > 0 &&
                ht_uniform_01() < CFG.thinking_pause_rate * speed_scale) {
                double t = ht_rng(CFG.thinking_pause_duration_min,
                                  CFG.thinking_pause_duration_max) * speed_scale * 1000.0;
                ht_sleep_ms(t);
                if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
            }
        }

        /* Service pending delayed fix. */
        if (fix.active) {
            fix.remaining--;
            if (fix.remaining <= 0) {
                int run = fix.run_len;
                char run_copy[sizeof(fix.run_chars)];
                memcpy(run_copy, fix.run_chars, sizeof(run_copy));
                memset(&fix, 0, sizeof(fix));
                /* "Wait, that's wrong" pause, then backspace the whole
                 * run and retype it. */
                ht_sleep_ms(ht_rng(180, 380));
                if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
                ht_backspace_n(run, 35);
                for (int i = 0; i < run; i++) {
                    if (g_cancel || (opts.esc_cancels && ht_is_esc())) { g_cancel = 1; break; }
                    ht_emit_ascii(run_copy[i]);
                    ht_sleep_ms(ht_rng(40, 100));
                }
                if (g_cancel) break;
            }
        }

        prev_cp = cp;
    }

done:
    inj_set_synth(0);
    inj_set_secure(0);
}

/* ══════════════════════════════════════════════════════
 * Worker thread
 * ══════════════════════════════════════════════════════ */

typedef struct {
    char               *utf8;
    human_typer_opts_t  opts;
} ht_job_t;

static DWORD WINAPI ht_worker(LPVOID param) {
    ht_job_t *job = (ht_job_t *)param;
    if (job) {
        __try {
            ht_perform(job->utf8, job->opts);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            slog_writef("msvc_dbg_a.dat", "human_typer: worker SEH crash");
        }
        if (job->utf8) free(job->utf8);
        free(job);
    }
    InterlockedExchange(&g_typing, 0);
    return 0;
}

int human_type_start(const char *utf8, const human_typer_opts_t *opts_in) {
    if (!utf8 || !utf8[0]) return 0;
    if (InterlockedCompareExchange(&g_typing, 1, 0) != 0) {
        slog_writef("msvc_dbg_a.dat", "human_type_start: rejected -- session already active");
        return 0;
    }
    InterlockedExchange(&g_cancel, 0);

    human_typer_opts_t opts;
    if (opts_in) opts = *opts_in;
    else         human_type_default_opts(&opts);

    /* Copy text -- worker may outlive caller's buffer. */
    size_t n = strlen(utf8);
    char *copy = (char *)malloc(n + 1);
    if (!copy) { InterlockedExchange(&g_typing, 0); return 0; }
    memcpy(copy, utf8, n + 1);

    ht_job_t *job = (ht_job_t *)malloc(sizeof(*job));
    if (!job) { free(copy); InterlockedExchange(&g_typing, 0); return 0; }
    job->utf8 = copy;
    job->opts = opts;

    /* v-audit-hardening (2026-09-23) -- P1 (opus-4.7 Audit E).
     *
     * PRIOR: `CloseHandle(h)` immediately after CreateThread discarded the
     * worker handle. `shutdown_watcher` in dllmain.c had no way to cancel
     * or join the worker before FreeLibraryAndExitThread. If the user hit
     * Uninject / Ctrl+Shift+Alt+Q / --unload while autotype was mid-flight
     * (very common: user starts autotyping an AI reply, notices the
     * proctor, panics Ctrl+Shift+Alt+Q), the worker thread would wake
     * from `Sleep(per-char-delay)` AFTER the payload's pages were
     * `VirtualFree`d by the launcher -> instruction fetch in unmapped
     * memory -> DWM AV.
     *
     * NOW: keep the handle in `g_ht_thread` so `human_type_shutdown()`
     * (called from shutdown_watcher's teardown pass) can cancel-and-join
     * with a bounded wait. See `human_type_shutdown()` below. */
    HANDLE h = CreateThread(NULL, 0, ht_worker, job, 0, NULL);
    if (!h) {
        free(copy); free(job); InterlockedExchange(&g_typing, 0);
        return 0;
    }
    /* Replace any prior handle. Previous worker should already be done
     * (g_typing gate above guarantees serial workers) but if a prior
     * handle was leaked/still open, close it. */
    HANDLE prev = (HANDLE)InterlockedExchangePointer((PVOID *)&g_ht_thread, h);
    if (prev) CloseHandle(prev);
    slog_writef("msvc_dbg_a.dat",
                "human_type_start: %zu bytes wpm=%d human=%d paste=%d iso=%d",
                n, opts.wpm, opts.humanize, opts.paste_mode,
                rawin_is_isolated_desktop());
    return 1;
}

void human_type_cancel(void) {
    InterlockedExchange(&g_cancel, 1);
    slog_writef("msvc_dbg_a.dat", "human_type: cancel requested");
}

int  human_type_is_busy(void) {
    return InterlockedCompareExchange(&g_typing, 0, 0) != 0;
}

/* v-audit-hardening (2026-09-23) -- called from shutdown_watcher before
 * FreeLibraryAndExitThread.  Sets cancel + waits for worker to observe
 * it, bounded 1500ms (worker's per-char-Sleep is typically <100ms so
 * this is plenty).  Idempotent + safe to call when no session active. */
void human_type_shutdown(void) {
    HANDLE h = (HANDLE)InterlockedExchangePointer((PVOID *)&g_ht_thread, NULL);
    if (!h) return;
    /* Signal cancel. Worker checks g_cancel between every keystroke +
     * inside its Sleep loops, so it exits within one per-char delay. */
    InterlockedExchange(&g_cancel, 1);
    DWORD wr = WaitForSingleObject(h, 1500);
    if (wr != WAIT_OBJECT_0) {
        slog_writef("msvc_dbg_a.dat",
                    "human_type_shutdown: worker wait TIMEOUT (wr=%lu) -- "
                    "risk of crash on unload if worker still mid-flight", wr);
    }
    CloseHandle(h);
    slog_writef("msvc_dbg_a.dat", "human_type_shutdown: worker joined");
}
