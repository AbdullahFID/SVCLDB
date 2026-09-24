/* ================================================================== *
 * human_typer.h -- Human-like autotyper (Dhakal et al. CHI'18 model).  *
 *                                                                     *
 * v17 (2026-09-23). Port of hooksdll's `human_typer.js` engine to C,   *
 * running from a worker thread inside the payload. Every keystroke     *
 * goes through `input/inject.c`, which routes to the winlogon helper's *
 * reverse-inject pipe when the payload is on a secure/isolated desktop *
 * (SEB, LDB kiosk, WinLogon lock screen) and falls back to a local     *
 * SendInput on the Default desktop.                                    *
 *                                                                     *
 * Fires from:                                                          *
 *   * Hotkey SVC_HK_AUTOTYPE_CLIP   -- clipboard -> type               *
 *   * Hotkey SVC_HK_AUTOTYPE_REPLY  -- last AI answer -> type          *
 *   * ImGui autosolver popout "Autotype" button                        *
 *   * ImGui chat-bubble hover "Autotype" button on AI messages         *
 *   * AutoSolver `type` action (routed via input/actions.c act_type)   *
 *                                                                     *
 * Cancellation: any subsequent hotkey fires human_type_cancel();       *
 * the engine also polls VK_ESCAPE via GetAsyncKeyState so the user     *
 * can bail out with a single tap.                                      *
 * ================================================================== */
#ifndef SVCLDB_INPUT_HUMAN_TYPER_H
#define SVCLDB_INPUT_HUMAN_TYPER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int  wpm;             /* target words-per-minute (30..500, default 110)  */
    int  humanize;        /* 1 = full engine (typos + tempo + fatigue);
                             0 = constant baseWPM with no typos              */
    int  planning_pause;  /* 1 = initial 0.2..0.85 s pre-type pause          */
    int  wait_mod_release;/* 1 = block until Ctrl/Shift/Alt physically up    */
    int  esc_cancels;     /* 1 = VK_ESCAPE aborts mid-type                   */
    int  paste_mode;      /* 1 = Ctrl+V clipboard paste (no humanization) --
                                 caller writes text to clipboard first.
                             0 = keystroke-by-keystroke humanized type       */
} human_typer_opts_t;

/* Start a typing session on a background thread. Returns 1 if started,
 * 0 if a session was already in flight (busy) or if `utf8` is empty/NULL.
 * Ownership of `utf8` is COPIED internally -- caller may free after
 * this returns. */
int  human_type_start(const char *utf8, const human_typer_opts_t *opts);

/* Fire-and-forget cancel. Sets a flag the engine polls between chars;
 * next call to `human_type_is_busy()` returning 0 confirms teardown. */
void human_type_cancel(void);

/* Non-blocking status check. */
int  human_type_is_busy(void);

/* Convenience: set defaults on `opts` (wpm=110, humanize=1, planning=1,
 * wait_mod_release=1, esc_cancels=1, paste_mode=0). */
void human_type_default_opts(human_typer_opts_t *opts);

/* Persist / retrieve the user's preferred autotyper settings. Stored
 * in a small file under SVC_INSTALL_DIR beside autosolver.json so the
 * user's WPM survives DWM crash / reboot. Called by the settings UI. */
void human_type_load_prefs(void);
void human_type_save_prefs(void);
int  human_type_get_wpm(void);
void human_type_set_wpm(int wpm);
int  human_type_get_humanize(void);
void human_type_set_humanize(int humanize);
int  human_type_get_paste_mode(void);
void human_type_set_paste_mode(int paste);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_INPUT_HUMAN_TYPER_H */
