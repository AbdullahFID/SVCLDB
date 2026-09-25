/* ================================================================== *
 * as_cfg.h -- AutoSolver + Agent settings, persisted in a payload-owned *
 * autosolver.json (SVC_INSTALL_DIR). Kept SEPARATE from svc_config_t so  *
 * the payload stays autonomous from svchelper and we avoid a schema bump. *
 * Electron may also write this file; the payload reloads on demand.      *
 * ================================================================== */
#ifndef SVCLDB_AUTOSOLVER_AS_CFG_H
#define SVCLDB_AUTOSOLVER_AS_CFG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* ── AutoSolver ── */
    int   autosolver_enabled;   /* master enable for hold-to-solve */
    int   auto_click;           /* 0 = display-only (STEALTH DEFAULT), 1 = move+click */
    int   humanize;             /* Sigma-Lognormal motion + log-normal dwell */
    int   uia_snap;             /* snap clicks to UIA element center */
    int   dot_enabled;          /* show the capture-stealth answer dot */
    int   dot_jump;             /* move the dot to the answer's click coord */
    int   render_max_edge;      /* downscale long-edge budget (default 1280) */
    /* ── Dot look & feel (v15.1) ── */
    double dot_opacity;         /* 0.05..1.0 (default 0.30 -- lighter for stealth) */
    int   dot_size_px;          /* dot radius base (6..20, default 9) */
    int   dot_ui_state;         /* 0 = collapsed dot, 1 = expanded FULL card */
    int   dot_pos_x;            /* dragged position (-1 = default top-right) */
    int   dot_pos_y;
    int   dot_full_w;           /* FULL card width  in px (default 340) */
    int   dot_full_h;           /* FULL card height in px (default 210; user-resizable) */
    int   dot_show_slider;      /* show opacity slider row when expanded */
    int   dot_hold_ms;          /* LMB-hold trigger threshold (200..5000, default 2000) */
    int   dot_hide_when_overlay;/* 1 = auto-hide dot when overlay is visible */
    /* ── Custom dot colors (per state, 0xAARRGGBB packed). 0 = use default. ── */
    unsigned int dot_col_idle;
    unsigned int dot_col_capturing;
    unsigned int dot_col_analyzing;
    unsigned int dot_col_executing;
    unsigned int dot_col_done;
    unsigned int dot_col_error;
    /* ── Agent Mode ── */
    int    agent_provider;      /* 0=anthropic, 1=openai, 2=gemini (CU adapters) */
    int    agent_tier;          /* svc_tier_t (0 strong,1 medium,2 cheap) */
    double agent_budget_usd;
    int    agent_max_steps;
    int    agent_max_wallclock_ms;
    int    agent_pace;          /* 0 fast, 1 balanced, 2 careful */
    /* ── Human autotyper (v17, 2026-09-23) ── *
     * svchelper (Electron dashboard) is the master control for these;
     * payload reads via as_cfg() on every human_type_default_opts()
     * call so live-edits from the dashboard take effect on the next
     * autotype run without needing a --reinject. */
    int    typer_wpm;           /* 30..500, default 110 */
    int    typer_humanize;      /* 1 = full Dhakal engine, 0 = constant timing */
    int    typer_paste_mode;    /* 1 = Ctrl+V paste (fast), 0 = per-keystroke */
    int    typer_planning;      /* 1 = initial 0.2..0.85 s pre-type pause */
    int    typer_wait_mods;     /* 1 = poll VK_CONTROL/SHIFT/MENU until up before typing */
    /* v7.3 (2026-09-24) -- USER-CONFIGURABLE AUTOTYPER CANCEL KEY.
     * VK code that hard-cancels an in-flight autotyper session when
     * pressed physically.  Default 0x1B == VK_ESCAPE.  Set to 0 to
     * disable the global-hotkey cancel entirely (only the dot's
     * in-overlay stop button still works).  Read by both the
     * Default-desktop LL hook (rawinput_hook.c ll_kbd_proc) and the
     * iso-desktop pipe dispatcher (dispatch_external_key), so the
     * chosen key works on every input surface. */
    int    typer_cancel_vk;
    /* ── v7.4 (2026-09-25) -- multi-turn conversation memory ──────
     * Number of prior chat turns (USER + AI) whose text is
     * re-sent to the AI on every follow-up question, so the model
     * can reference earlier context. Cap at ~24 for token/latency
     * sanity; default 5 gives ~10 messages of context, enough for
     * most exam-help follow-ups without blowing up the prompt.
     * Each retained USER turn keeps a copy of its ORIGINAL
     * screenshot bytes in the chat ring (bounded to `chat_history_turns`
     * images = ~2.5 MB @ 500 KB avg PNG). Set to 1 for the pre-v7.4
     * stateless behavior; set to 0 also treated as 1 (never silently
     * disable memory). */
    int    chat_history_turns;
    /* Similar knob but for the autosolver's own history ring (kept
     * separately in payload/src/autosolver/solve.c so hold-to-solve
     * bursts see prior screenshots + answers as context). Default 5. */
    int    autosolver_history_turns;
} as_settings_t;

/* Current settings (loads defaults + autosolver.json on first call). */
const as_settings_t *as_cfg(void);

void as_cfg_load(void);              /* (re)read autosolver.json */
void as_cfg_save(void);              /* synchronous flush of current in-mem state */
void as_cfg_reload_if_changed(void); /* reload only if the file's mtime moved */
void as_cfg_start_watch(void);       /* start the ~1.5s mtime watcher + debounce persister (once) */
/* v7.3 (2026-09-24) -- Cancel-and-join the persister thread + flush any
 * pending dirty state to disk.  Called from shutdown_watcher (dllmain.c)
 * BEFORE FreeLibraryAndExitThread so unsaved dot state (position/size/
 * opacity/ui_state) survives an --unload / user-Ctrl-Shift-Alt-Q kill. */
void as_cfg_shutdown(void);

/* Live toggles (persist immediately). Return new state where applicable. */
int  as_cfg_toggle_autosolver(void);
int  as_cfg_toggle_auto_click(void);

/* v15.1 -- setters for dot state that persist across sessions. Called from
 * the ImGui layer whenever the user drags / resizes / clicks-to-expand
 * the dot so the next inject remembers where it was. */
void as_cfg_set_dot_ui_state(int ui);         /* 0 collapsed, 1 full */
void as_cfg_set_dot_pos(int x, int y);        /* screen px; -1,-1 = default */
void as_cfg_set_dot_full_size(int w, int h);
void as_cfg_set_dot_opacity(double alpha);    /* 0.05..1.0 */
void as_cfg_set_dot_show_slider(int on);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_AUTOSOLVER_AS_CFG_H */
