/* ================================================================== *
 * config_types.h -- Shared struct definition for the config file.      *
 *                                                                    *
 * Written by launcher, read by payload. Encrypted at rest via         *
 * cu_wrap_encrypt (machine-bound AES-256-GCM).                        *
 * ================================================================== */
#ifndef SVCLDB_CONFIG_TYPES_H
#define SVCLDB_CONFIG_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* v16 (2026-08-12): 0 = managed "CloakGPT credits" (metered /solve
     * worker via the Supabase JWT). No BYO key needed. Default when the
     * user hasn't picked a provider. Struct layout unchanged (provider is
     * an existing int) so NO schema bump. */
    SVC_PROVIDER_CREDITS    = 0,
    SVC_PROVIDER_OPENAI     = 1,
    SVC_PROVIDER_ANTHROPIC  = 2,
    SVC_PROVIDER_GOOGLE     = 3,
    SVC_PROVIDER_OPENROUTER = 4,
    SVC_PROVIDER_COUNT      = 4,
} svc_provider_t;

/* Model tiers per provider (except OpenRouter which is user-picked).
 * ai_provider.c holds tier->model lookup tables. User cycles via
 * Ctrl+Alt+M hotkey (SVC_HK_CYCLE_TIER). */
typedef enum {
    SVC_TIER_STRONG = 0,   /* max quality / most expensive */
    SVC_TIER_MEDIUM = 1,   /* balanced quality + cost */
    SVC_TIER_CHEAP  = 2,   /* fastest + affordable */
    SVC_TIER_CUSTOM = 3,   /* honor cfg->model verbatim */
    SVC_TIER_COUNT  = 4,
} svc_tier_t;

/* Wire-format magic + schema version. The Electron UI stamps these into
 * every config it writes. The payload's cfg_read validates BOTH so that
 * an older/stripped/malformed config.dat is rejected before any downstream
 * code reads a field.
 *
 * Bump SVC_CONFIG_SCHEMA_VERSION on any layout change (add-only). Old
 * configs cleanly fail via cu_wrap_decrypt's plen != sizeof(svc_config_t)
 * check when a field is added -- this magic is defence-in-depth. */
#define SVC_CONFIG_MAGIC             0x53564C43u  /* 'SVLC' little-endian */
#define SVC_CONFIG_SCHEMA_VERSION    14u  /* v14 (2026-09-19): + refresh_token (payload-side JWT refresh so overlay survives with Electron closed -- see docs/HANDOFF_2026-09-19_PAYLOAD_JWT_AUTONOMY.md). v13 (2026-08-10): + nudge_step_px. v12: + scroll_step_px. */

typedef struct {
    /* ── v4 header: written by Electron UI / launcher --json-config.
     * Payload validates both fields before touching anything else. */
    uint32_t    magic;                 /* MUST == SVC_CONFIG_MAGIC              */
    uint32_t    schema_version;        /* MUST == SVC_CONFIG_SCHEMA_VERSION     */

    /* Auth (payload uses this to prove subscription validity via periodic
     * re-check against Supabase -- attacker can't just extract config
     * and use it without a valid token). */
    char        access_token [4096];
    long long   token_expires_at;

    /* AI provider + key + model + tier.
     * When tier != CUSTOM, ai_provider.c resolves model_id from the
     * tier table (ignores `model` field). When tier == CUSTOM, uses
     * `model` verbatim. Live rotation via Ctrl+Alt+M / Ctrl+Alt+P. */
    int         provider;       /* svc_provider_t -- currently-active provider */
    int         tier;           /* svc_tier_t; default MEDIUM */
    char        api_key [512];  /* legacy shared key (v3 and earlier).
                                 * v4+: still used as override if non-empty.
                                 * v5+: prefer api_key_<provider> when this
                                 *      is empty. */
    char        model   [128];  /* CUSTOM tier + OpenRouter free-picking */
    int         reasoning_effort;   /* 0=none 1=minimal 2=low 3=medium 4=high 5=xhigh */
    int         streaming_enabled;  /* 1 = SSE stream reply into chat */
    int         latex_disabled;     /* 1 = tell AI to use Unicode/keyboard math instead of LaTeX */
    /* v6.1 (2026-07-06 evening): BATCHED-display streaming mode.
     * When 1 AND streaming_enabled=1: SSE chunks are BUFFERED internally
     * but NOT rendered to the overlay live. On stream-done the full
     * reply is pushed to the UI in ONE final render. Benefits:
     *   - Stability: 1 DWM recomposition per answer instead of ~200
     *     (~50-100x less GPU churn during a long answer). Big win on
     *     slower GPUs where the RE-tester's flicker was observed.
     *   - Layout stability: no ImGui re-flow as tokens arrive; math /
     *     code blocks render in their final form once, correctly.
     *   - Copy-full-answer is guaranteed-complete on Ctrl+Alt+C.
     * Trade-off: no "watching it type" UX; user sees a "Thinking..."
     * indicator until the full answer appears.
     * Ignored when streaming_enabled=0 (non-stream ai_ask path already
     * waits for the full reply). */
    int         stream_display_batched;

    /* v6 (2026-07-06): DIRECT ANSWER MODE. When 1, the AI system prompt
     * is replaced with a strict "reply with ONLY the direct factual
     * answer, no explanation, ERROR if unsure" contract. User toggles
     * via Ctrl+Shift+Alt+D or dashboard checkbox. See
     * materialize_default_system in ai_provider.c. */
    int         direct_answer_mode;

    /* System prompt (user-editable in settings UI). Sized to hold the
     * built-in SVCLDB_DEFAULT_SYSTEM_PROMPT (~10 KB of subject-matter
     * expertise ported from hooksdll/lumio/src/autosolver.js) plus
     * headroom for user overrides.
     *
     * v6 (2026-07-06): SEMANTICS -
     *   - Empty OR literal "DEFAULT" -> payload uses SVCLDB_DEFAULT_SYSTEM_PROMPT
     *   - Starts with the sentinel "APPEND:\n" -> payload uses default + user
     *     text appended (user AUGMENTS the built-in expertise)
     *   - Anything else -> payload uses the string VERBATIM (user OVERRIDES
     *     the built-in prompt entirely; power user territory)
     *   - direct_answer_mode=1 overrides ALL of the above with the strict
     *     data-extraction contract. */
    char        system_prompt[16384];

    /* Hotkeys (packed: (mod << 16) | vk; mod: 1=ctrl 2=shift 4=alt).
     * Slot index matches svc_hotkey_action_t enum below. Zero = unbound.
     *
     * v9 (2026-07-06 late): grew 32 -> 64 to fix a serious OOB bug.
     * SVC_HK_DIRECT_TOGGLE was added as enum value 32, but the payload's
     * rawin_start loop reads hotkeys[i] for i < SVC_HK_COUNT (33). With
     * the array only 32 wide, i=32 read into overlay_x (the very next
     * field), which defaults to 40 = 0x28 = VK_DOWN with NO modifiers.
     * Result: any DOWN arrow press fired the direct-answer toggle. The
     * static_assert below guarantees the array is always at least as
     * large as SVC_HK_COUNT, so future additions to the enum can't
     * silently reintroduce the same OOB read.
     *
     * 64 slots is generous headroom (~2x current usage of 33). Keep as
     * multiple-of-cache-line to avoid future re-alignment surprises. */
    unsigned    hotkeys[64];

    /* Overlay geometry defaults.
     *
     * v8 (2026-07-06): these are now READ AND HONORED by the payload's
     * imgui_layer as the INITIAL BASE size at first draw (previously the
     * payload used hardcoded 600x460 * DPI and ignored these fields).
     * Users pick these in the Electron dashboard's "Overlay appearance"
     * card. `overlay_state.bin` still persists the user's LIVE tweaks
     * (extra_w/h from hotkey resizes) on top of this base.
     *
     * Sensible ranges (enforced client-side by the Electron slider
     * clamps AND server-side by the payload's clamp_launch_size):
     *   Normal mode : w [200 .. 1400],  h [140 .. 1200]
     *   Ultra mode  : w [ 80 .. 4000],  h [ 60 .. 3000]
     * overlay_alpha stays in [0.20 .. 1.00]. */
    int         overlay_x, overlay_y;
    int         overlay_w, overlay_h;
    float       overlay_alpha;

    /* v8 (2026-07-06): SIZE MODE toggle. Controls the runtime clamp
     * range for BOTH the launch base size AND the user's live Ctrl+
     * Shift+Alt+Arrow resize hotkeys.
     *   0 = normal -- sensible on-screen ranges (default)
     *   1 = ultra  -- allow tiny 80x60 pip-in-corner OR near-fullscreen
     * See ui_apply_launch_config in imgui_layer.cpp for the exact
     * clamp values applied. This is a per-user cosmetic preference,
     * not a security-sensitive value. */
    int         size_mode;

    /* ── v4 handshake fields: Electron/launcher populate BEFORE writing
     * this struct. Payload's init_thread computes the expected token and
     * refuses to install hooks if it doesn't match. See
     * shared/handshake.h for the derivation contract. */
    uint8_t     handshake_token[32];   /* HMAC-SHA256 output -- see handshake.h */
    long long   handshake_epoch_day;   /* floor(unix_time / 86400) at gen time */
    char        handshake_hwid[80];    /* HWID Electron used to derive token   */

    /* ── v5 per-provider API keys (2026-07-06). Enables cross-provider
     * failover: on 429/5xx/rate_limit from the active provider, ai_provider
     * tries each remaining provider that has a non-empty key.
     *
     * Population order in ai_provider.c:
     *   1. Legacy `api_key` field above (backward-compat override)
     *   2. api_key_<provider> for the active provider
     *   3. Empty -> skip / error / try next in fallback chain
     *
     * Written by launcher --json-config from the Electron settings card
     * (one input per provider). */
    char        api_key_openai    [512];
    char        api_key_anthropic [512];
    char        api_key_google    [512];
    char        api_key_openrouter[512];

    /* ── v11 (2026-07-24) -- Bypassify-parity theme + overlay behavior flags.
     * theme:
     *   0 = dark        (current default -- dark navy bg, white text)
     *   1 = light       (white bg, dark text -- matches Windows light theme)
     *   2 = auto        (payload polls HKCU\...\Themes\Personalize\AppsUseLightTheme
     *                    every ~2s and switches; matches Bypassify's behavior)
     *
     * overlay_flags: bitfield of TRAIL/NUDGE/OPACITY behavior.
     *   bit 0 (SVC_OVFLAG_TRAIL_ERASE)   -- 1 = paint over old positions with
     *                                       opaque bg color so trailing after
     *                                       nudge is invisible. Default ON.
     *   bit 1 (SVC_OVFLAG_SMOOTH_NUDGE)  -- 1 = nudge uses small 8px steps at
     *                                       60Hz repeat (butter smooth, BP-like).
     *                                       0 = old jaggy 20px @ 20Hz.
     *                                       Default ON.
     *   bit 2 (SVC_OVFLAG_UNIFORM_ALPHA) -- 1 = user's alpha applies uniformly
     *                                       to WindowBg + child bubbles + code
     *                                       + math blocks + chrome. Default ON.
     *   bit 3 (SVC_OVFLAG_OPAQUE_LOCK)   -- 1 = force alpha=1.0 regardless of
     *                                       user setting (best trail hiding).
     *                                       Default OFF (let user pick alpha).
     *
     * If overlay_flags == 0 (stale v10 config or explicit 0), the payload treats
     * it as "all v11 default flags on" via a safe migration path in
     * ui_apply_launch_config. */
    int         theme;
    unsigned    overlay_flags;

    /* v12 (2026-07-25) -- user-configurable scroll granularity.
     *
     * LO's ask: "we should also let users control how much the scroll
     * scrolls like if they wanna make it more or less a granular control."
     *
     * Applied by:
     *   - SVC_HK_SCROLL_UP/DOWN hotkeys -> ui_scroll_reply(±scroll_step_px)
     *   - PgUp/PgDn fallback in rawinput_hook -> ±(scroll_step_px * 2)
     *   - Mouse wheel notch -> scroll_step_px per notch (was fixed 90px)
     *
     * Default 80 preserves pre-v12 hotkey feel. Range 20-400 clamped
     * by the dashboard slider. 0 or out-of-range = fallback to 80 in
     * ui_apply_launch_config so an unmigrated field never zero-scrolls. */
    int         scroll_step_px;

    /* v13 (2026-08-10) -- user-configurable arrow-key nudge granularity.
     *
     * LO's ask: "with the fast pace arrow keys ... if we can adjust speed
     * on how fast it goes when u click the arrow keys rn its mediocre fast
     * so if u wanna be able to do micro adjustments thats a lot easier".
     *
     * Pixels the overlay moves PER arrow-key fire (SVC_HK_MOVE_LEFT/RIGHT/
     * UP/DOWN). Held keys auto-repeat, so effective slide speed =
     * nudge_step_px * repeat-rate. A small value (e.g. 2-4) gives precise
     * micro-adjustment on single taps AND a slow controllable slide on hold.
     *
     * Default 48 preserves the pre-v13 "1cm per press" feel. Range 1-200
     * clamped by the dashboard slider. 0 or out-of-range = fallback to 48
     * in the dllmain hotkey handler so an unmigrated field never zero-moves. */
    int         nudge_step_px;

    /* v14 (2026-09-19) -- Payload-side JWT refresh.
     *
     * Root problem: pre-v14 the payload cached `access_token` at inject
     * time and depended ENTIRELY on Electron (`ui/src/license/revalidation.js`
     * + `token_refresh_server.c` pipe push) to swap in a fresh JWT before
     * Supabase's ~1h TTL expired. When svchelper.exe was closed after a
     * successful inject (real user flow: sign in -> inject -> close Electron
     * to keep only sihost.exe running during an exam), no one refreshed the
     * JWT, `sub_check.c` hit 401 at T+~1h, and after the 9-min grace the
     * payload self-unloaded mid-exam. Sam reported this THREE times before
     * we finally added payload autonomy. See
     * docs/HANDOFF_2026-09-19_PAYLOAD_JWT_AUTONOMY.md.
     *
     * v14 fix: Electron writes the current `refresh_token` into config.dat
     * (encrypted at rest by cu_wrap_encrypt like every other secret). The
     * payload's new `token_refresh_client.c` background thread wakes ~15
     * min before `token_expires_at`, POSTs to
     *   `POST {SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`
     *   header:  apikey: <anon>
     *   body:    {"refresh_token":"<rt>"}
     * and on success writes the rotated `{access_token, refresh_token,
     * expires_in}` back into this struct + persists to disk (cfg_persist).
     * Bounded at 4096 to match Supabase's refresh-token size (~40 chars
     * typical but budget for envelope + safety). NUL-terminated. */
    char        refresh_token[4096];
} svc_config_t;

/* v11 overlay_flags bit constants. */
#define SVC_OVFLAG_TRAIL_ERASE    0x1u
#define SVC_OVFLAG_SMOOTH_NUDGE   0x2u
#define SVC_OVFLAG_UNIFORM_ALPHA  0x4u
#define SVC_OVFLAG_OPAQUE_LOCK    0x8u
/* v3.3 (2026-09-23) -- "Deep hide" mode. When set, the payload's low-level
 * keyboard hook AND the winlogon helper's LL hook both swallow every
 * standalone Ctrl/Shift/Alt DOWN and UP transition instead of letting
 * them fall through to whichever app owns foreground focus. Effect: the
 * target app's window queue never sees the modifier press at all, so no
 * "Ctrl was held" state ever leaks. Trade-off: in-app Ctrl-based shortcuts
 * (Ctrl+C copy, Ctrl+V paste, Ctrl+A select-all, etc.) stop working in
 * the target app while this is on -- user opt-in. Our OWN hotkeys still
 * fire cleanly because internal modifier tracking still runs; only the
 * downstream-app propagation is suppressed. Applies on Default AND on
 * every isolated/secure desktop through the helper's LL path. */
#define SVC_OVFLAG_SILENT_MODS    0x10u
/* v13 (2026-08-10) -- OPAQUE_LOCK OUT of defaults (DEPRECATED as a forced
 * lock). LO wants real, low, PERSISTENT transparency ("i put it damn low,
 * should've been near invisible"). OPAQUE_LOCK's whole job was to slam
 * g_alpha=1.0 at every apply_theme_and_flags, which directly fought the
 * user's chosen opacity and made transparency "not stick". The payload no
 * longer honors OPAQUE_LOCK at all (see ui_apply_theme_and_flags) -- the
 * slider is now the single source of truth for opacity. The bit constant
 * stays defined for backward-compatible config reads; it is inert.
 * TRAIL_ERASE stays OFF (v1.7.6.1 shadow-flicker fix). */
#define SVC_OVFLAG_DEFAULTS       (SVC_OVFLAG_SMOOTH_NUDGE | SVC_OVFLAG_UNIFORM_ALPHA)

/* Hotkey action identifiers -- index into svc_config_t.hotkeys[].
 * When adding new actions: append at the end, never renumber. */
typedef enum {
    SVC_HK_ASK           = 0,   /* Screenshot + ask AI                    */
    SVC_HK_TOGGLE        = 1,   /* Show/hide overlay                      */
    SVC_HK_TYPING        = 2,   /* Enter typing mode (WIP)                */
    SVC_HK_COPY_REPLY    = 3,   /* Copy last reply to clipboard           */
    SVC_HK_CLEAR         = 4,   /* Clear reply text                       */
    SVC_HK_MOVE_LEFT     = 5,   /* Nudge overlay left  (20 px)            */
    SVC_HK_MOVE_RIGHT    = 6,   /* Nudge overlay right (20 px)            */
    SVC_HK_MOVE_UP       = 7,   /* Nudge overlay up    (20 px)            */
    SVC_HK_MOVE_DOWN     = 8,   /* Nudge overlay down  (20 px)            */
    SVC_HK_RESIZE_WIDER  = 9,   /* Grow overlay width  (40 px)            */
    SVC_HK_RESIZE_NARROW = 10,  /* Shrink overlay width                   */
    SVC_HK_RESIZE_TALLER = 11,  /* Grow overlay height                    */
    SVC_HK_RESIZE_SHORT  = 12,  /* Shrink overlay height                  */
    SVC_HK_CYCLE_CORNER  = 13,  /* Cycle TL -> TR -> BR -> BL corners        */
    SVC_HK_ALPHA_UP      = 14,  /* +5% background opacity                 */
    SVC_HK_ALPHA_DOWN    = 15,  /* -5% background opacity                 */
    SVC_HK_FONT_UP       = 16,  /* +10% font scale                        */
    SVC_HK_FONT_DOWN     = 17,  /* -10% font scale                        */
    SVC_HK_RESET         = 18,  /* Reset overlay to default position/size */
    SVC_HK_DEBUG_CAP     = 19,  /* Debug capture -- save PNGs to Desktop   */
    SVC_HK_KILL_ALL      = 20,  /* Emergency stop -- unload payload + kill  *
                                 * DWM + kill any running launcher inst.   */
    SVC_HK_SCROLL_UP     = 21,  /* Reply pane scroll up (Ctrl+Alt+K)       */
    SVC_HK_SCROLL_DOWN   = 22,  /* Reply pane scroll down (Ctrl+Alt+J)     */

    /* Chat-conversation controls (added 2026-07-05 v3). */
    SVC_HK_NEW_CHAT      = 23,  /* Clear ALL chat history (Ctrl+Alt+N)     */
    SVC_HK_CYCLE_TIER    = 24,  /* Cycle STRONG->MEDIUM->CHEAP (Ctrl+Alt+M)*/
    SVC_HK_CYCLE_PROVIDER= 25,  /* Cycle OA->AN->GG->OR   (Ctrl+Shift+P)   *
                                 * (Ctrl+Alt+P conflicts w Chrome print;    *
                                 * Ctrl+Shift+P conflicts w Cursor palette; *
                                 * we picked Ctrl+Shift+Alt+P -- 3-mod safe) */
    SVC_HK_REGENERATE    = 26,  /* Re-ask last user turn (Ctrl+Alt+Enter)  */
    SVC_HK_STREAM_TOGGLE = 27,  /* Toggle SSE streaming (Ctrl+Shift+Alt+T) */

    /* v3.1 additions (2026-07-05 evening) */
    SVC_HK_COPY_CODE     = 28,  /* Copy JUST code blocks (Ctrl+Shift+Alt+C)*/
    SVC_HK_COPY_ANSWER   = 29,  /* Copy JUST first-line answer (Ctrl+Alt+A)*/
    SVC_HK_LATEX_TOGGLE  = 30,  /* Toggle LaTeX vs Unicode (Ctrl+Shift+Alt+L)*/

    /* v4.5 (2026-07-06) -- Stop an in-flight AI response. */
    SVC_HK_STOP_GEN      = 31,  /* Abort current stream (Ctrl+Alt+S)      */

    /* v6 (2026-07-06 late) -- Direct-answer mode toggle. When ON, AI
     * replies with ONLY the direct answer (no explanation, ERROR if
     * unsure) via a system prompt override. */
    SVC_HK_DIRECT_TOGGLE = 32,  /* Toggle direct-answer mode (Ctrl+Shift+Alt+D) */

    /* v1.7.4.17 (2026-07-24) -- Bypassify "Quick-Send" parity. Same
     * handler as SVC_HK_ASK (screenshot + immediately send to AI),
     * but a SECOND binding slot so user can wire it to a mouse-hold
     * gesture (e.g. hold LMB 2s) for zero-keyboard operation. BP
     * markets this as "Hold left click anywhere outside the overlay
     * to snap + send" -- a hallmark of proctor-tool-safe UX because
     * mouse-hold-and-drag is universally normal user behavior.
     *
     * Default binding: UNBOUND (opt-in). User enables in the hotkey
     * editor UI, typically as MOUSE_HOLD LMB 2000ms. */
    SVC_HK_QUICK_ASK     = 33,

    /* v1.7.10 (2026-07-24) -- LEAN MODE toggle. When ON, overlay draws
     * via ImDrawList::AddText/AddRectFilled on GetForegroundDrawList()
     * (BP-parity render path -- see bp-per-frame-render-decomp.md notes
     * + RPM verification of BP's ImGui Windows vector = 1 unnamed).
     * Sacrifices chat scrollback / MD rendering / bubbles / buttons
     * for pure BP-parity smoothness. */
    SVC_HK_LEAN_TOGGLE   = 34,

    /* v15 (2026-09-22) -- AutoSolver + Agent Mode (see
     * docs/HANDOFF_AUTOSOLVER_AGENTMODE_SVCLDB_PLAN_2026-09-22.md).
     *
     * These are ADDITIVE enum slots only -- they index into the existing
     * hotkeys[64] array, so NO svc_config_t schema bump is required. Unbound
     * (0) slots are inert; the payload installs sane fallback defaults for
     * them at arm time when the slot is 0 (see dllmain install_hk_defaults).
     *
     * AutoSolver/Agent *settings* (toggles, budget, pace, provider/tier for
     * the agent) live in a SEPARATE payload-owned file (autosolver.json under
     * SVC_INSTALL_DIR) -- see autosolver/as_cfg.c -- so the payload stays
     * autonomous from svchelper and we avoid a fragile struct-writer bump. */
    SVC_HK_AUTOSOLVE_TOGGLE = 35, /* Enable/disable AutoSolver (hold-to-solve)      */
    SVC_HK_AUTOCLICK_TOGGLE = 36, /* Toggle auto-click vs display-only (dot only)   */
    SVC_HK_AGENT_START      = 37, /* Start Agent Mode with the pending task         */
    SVC_HK_AGENT_STOP       = 38, /* Stop Agent Mode (also ESC while running)       */
    SVC_HK_AGENT_PAUSE      = 39, /* Pause/resume Agent Mode                        */

    /* v17 (2026-09-23) -- Human autotyper (see docs/HANDOFF_2026-09-23_HUMAN_AUTOTYPER_AND_NOTES.md).
     *
     * Ported from hooksdll's `human_typer.js` (Dhakal et al. CHI'18 log-normal
     * IKI model + 8-finger bigram delays + tempo-momentum walk + fatigue
     * + burst-typing for common words + 4-kind typo model with immediate +
     * delayed backspace correction). Runs from a worker thread inside the
     * payload; routes SendInput through `input/inject.c` which switches
     * to the winlogon-helper reverse-inject pipe when we're on an isolated
     * desktop (SEB / secure). Cancel: Esc while typing (inline in engine).
     *
     * Defaults chosen so no chord collides with existing bindings:
     *   40 SVC_HK_AUTOTYPE_CLIP  = Ctrl+Alt+T  -- grab clipboard, wait mod
     *                                            release, human-type it
     *   41 SVC_HK_AUTOTYPE_REPLY = Ctrl+Alt+Y  -- human-type the last AI
     *                                            answer (Y sits next to T)
     *   42 SVC_HK_NOTES_TOGGLE   = Ctrl+Shift+Alt+N -- open/close the notes
     *                                            editor (multi-line panel;
     *                                            contents get prepended to
     *                                            AI prompts as reference
     *                                            context)                    */
    SVC_HK_AUTOTYPE_CLIP    = 40,
    SVC_HK_AUTOTYPE_REPLY   = 41,
    SVC_HK_NOTES_TOGGLE     = 42,

    /* v17 -- clipboard-history cycle. Pressing Ctrl+Shift+Alt+T once
     * autotypes the SECOND-newest clipboard entry (i.e. the one BEFORE
     * whatever's currently on clipboard). Pressing again within 2 s
     * cycles to third-newest, etc. Wraps at count-1 back to 1. Cycle
     * cursor resets after 2 s idle so the next press always starts at
     * "the previous thing I copied".
     *
     * Complements SVC_HK_AUTOTYPE_CLIP (Ctrl+Alt+T) which always types
     * the LATEST clipboard content. Together the two hotkeys give
     * unlimited-depth autotype without needing a picker UI. */
    SVC_HK_CLIP_CYCLE       = 43,

    SVC_HK_COUNT
} svc_hotkey_action_t;

/* v9 (2026-07-06): compile-time gate against re-introducing the
 * hotkeys[N] out-of-bounds bug where SVC_HK_COUNT exceeded the array
 * length. If someone adds a new SVC_HK_* enum value AND the array
 * isn't big enough, compilation fails with a message pointing here.
 *
 * The check is written as an anonymous typedef so it works from both
 * C and C++ translation units without a C11 dependency (some MinHook
 * includes drag in older headers). If SVC_HK_COUNT ever grows past
 * 64, bump the array size AND the schema version + document why. */
typedef char svcldb_hotkeys_size_assert[(SVC_HK_COUNT <= (int)(sizeof((svc_config_t*)0)->hotkeys / sizeof(unsigned))) ? 1 : -1];

/* ── Hotkey packed-uint format (32-bit) ────────────────────────────
 *
 *   bits 0-15  : vk (Windows virtual-key code, 0-65535)
 *   bits 16-23 : extra byte (kind-dependent):
 *                  KIND_MODIFIER: mod bits (bit0=Ctrl bit1=Shift bit2=Alt)
 *                  KIND_LONGPRESS: hold time in 10ms units (max 2550ms)
 *                  KIND_MULTITAP: low nibble = tap count (1..15)
 *                                 high nibble = max_gap_ms/50 (0..750ms)
 *   bits 24-27 : kind (0-15):
 *                  0 = MODIFIER (default; backward-compat with v9 configs)
 *                  1 = LONGPRESS (watch-only semantics -- initial DOWN passes
 *                                 through, action fires when key held past
 *                                 hold_ms threshold)
 *                  2 = MULTITAP  (N taps within max_gap; consume OR
 *                                 watch-only per WATCH_ONLY flag)
 *                  3 = DISABLED  (slot is off -- no binding fires)
 *   bit  28    : WATCH_ONLY flag -- for MULTITAP: DON'T consume events,
 *                let user's typing through; action fires but keys reach
 *                downstream apps normally. Enables plausible-deniability
 *                stealth (proctor sees "user typed ggg" typo, not a
 *                mysterious blocked key sequence).
 *   bits 29-31 : reserved (must be 0)
 *
 * Backward compat: any packed value with bits 24-31 == 0 reads as
 * KIND_MODIFIER with old-style (mod<<16)|vk semantics. Existing v9
 * hotkey configs work unchanged.
 *
 * v10 (2026-07-17): new binding modes added for stealth hotkey rebinds.
 * Old defaults preserved; new defaults use LONGPRESS/MULTITAP where
 * they improve concealment vs proctor-tool observation. */
#define SVC_HK_KIND_MODIFIER   0u
#define SVC_HK_KIND_LONGPRESS  1u
#define SVC_HK_KIND_MULTITAP   2u
#define SVC_HK_KIND_DISABLED   3u
/* v1.7.4 (2026-07-23): MOUSE_HOLD -- hold a mouse button for hold_ms ms
 * to fire. VK field holds the mouse-button VK (VK_LBUTTON=1, VK_RBUTTON=2,
 * VK_MBUTTON=4, VK_XBUTTON1=5, VK_XBUTTON2=6). Extra field = hold_ms/10.
 * Motivation: user request "hold left/right click for 2-3 secs would be
 * nice ... im using my logitech mx mouse and can't do double-press binds
 * ... need some way to draw less attention with only mouse". Mouse button
 * clicks are semantically indistinguishable from normal clicks; long-hold
 * pattern is impossible to log as "hotkey" by any user-mode proctor tool.
 * Runs via existing WH_MOUSE_LL hook chain -- LDB doesn't intercept mouse
 * hooks, so this is our most reliable stealth-hotkey path. */
#define SVC_HK_KIND_MOUSE_HOLD 4u
/* v1.7.4: MOUSE_MULTI -- N clicks of a mouse button within max_gap.
 * Extra encoding: same as MULTITAP (low nibble count, high nibble gap/50).
 * Users who don't want to hold can triple-click instead. Fires even if
 * clicks land in different windows (LL hook is per-desktop, not per-app). */
#define SVC_HK_KIND_MOUSE_MULTI 5u

#define SVC_HK_FLAG_WATCH_ONLY 0x10000000u   /* bit 28 */
/* v1.7.2 (2026-07-17): ADAPTIVE flag on MULTITAP bindings -- payload
 * learns the user's actual tap rhythm and dynamically adjusts the
 * effective gap threshold. Baseline gap in the packed uint is used
 * as a fallback for the first few taps before learning kicks in. */
#define SVC_HK_FLAG_ADAPTIVE   0x20000000u   /* bit 29 */

/* Extract fields from a packed hotkey uint. */
#define SVC_HK_VK(pk)       ((unsigned)(pk) & 0xFFFFu)
#define SVC_HK_EXTRA(pk)    (((unsigned)(pk) >> 16) & 0xFFu)
#define SVC_HK_KIND(pk)     (((unsigned)(pk) >> 24) & 0x0Fu)
#define SVC_HK_WATCH(pk)    (((unsigned)(pk) & SVC_HK_FLAG_WATCH_ONLY) != 0)
#define SVC_HK_ADAPTIVE(pk) (((unsigned)(pk) & SVC_HK_FLAG_ADAPTIVE)   != 0)

/* Legacy MODIFIER pack (backward compat) -- v9 hotkey configs use this.
 *   Ctrl+G       = SVC_HK_PACK(1, 'G')
 *   Ctrl+Shift+G = SVC_HK_PACK(3, 'G')
 *   Ctrl+Alt+G   = SVC_HK_PACK(5, 'G')
 *   3-mod combos = SVC_HK_PACK(7, 'K') */
#define SVC_HK_PACK(mod, vk) (((unsigned)(mod) << 16) | (unsigned)(vk))

/* Pack a LONGPRESS binding: hold this VK for hold_ms milliseconds -> fire.
 * Initial keypress passes through unchanged (proctor sees single tap).
 * hold_ms clamped to [100..2550] internally. */
#define SVC_HK_PACK_LONGPRESS(hold_ms, vk) \
    ((SVC_HK_KIND_LONGPRESS << 24) | (((unsigned)((hold_ms) / 10) & 0xFFu) << 16) | ((unsigned)(vk) & 0xFFFFu))

/* Pack a MULTITAP binding: N taps of this VK within max_gap ms -> fire.
 * When WATCH_ONLY (watch != 0), the taps are NOT consumed -- user's
 * typing goes through unchanged, action fires when pattern matches.
 * count: [1..15], max_gap_ms: [0..750] rounded to 50ms granularity. */
#define SVC_HK_PACK_MULTITAP(count, gap_ms, vk, watch) \
    ((SVC_HK_KIND_MULTITAP << 24) | \
     ((((((unsigned)(gap_ms) / 50) & 0xFu) << 4) | ((unsigned)(count) & 0xFu)) << 16) | \
     ((unsigned)(vk) & 0xFFFFu) | \
     ((watch) ? SVC_HK_FLAG_WATCH_ONLY : 0u))

/* MULTITAP extra-byte accessors (only meaningful when KIND == MULTITAP
 * or KIND == MOUSE_MULTI). */
#define SVC_HK_MULTITAP_COUNT(pk)      (SVC_HK_EXTRA(pk) & 0xFu)
#define SVC_HK_MULTITAP_GAP_MS(pk)     (((SVC_HK_EXTRA(pk) >> 4) & 0xFu) * 50u)

/* LONGPRESS extra-byte accessor (also used for MOUSE_HOLD). */
#define SVC_HK_LONGPRESS_MS(pk)        ((unsigned)SVC_HK_EXTRA(pk) * 10u)

/* v1.7.4: MOUSE_HOLD pack -- hold `mouse_vk` for hold_ms -> fire.
 * mouse_vk must be one of VK_LBUTTON(1)/VK_RBUTTON(2)/VK_MBUTTON(4)/
 * VK_XBUTTON1(5)/VK_XBUTTON2(6). hold_ms is clamped [100..2550]. */
#define SVC_HK_PACK_MOUSE_HOLD(hold_ms, mouse_vk) \
    ((SVC_HK_KIND_MOUSE_HOLD << 24) | (((unsigned)((hold_ms) / 10) & 0xFFu) << 16) | ((unsigned)(mouse_vk) & 0xFFFFu))

/* v1.7.4: MOUSE_MULTI pack -- N clicks within gap_ms -> fire. */
#define SVC_HK_PACK_MOUSE_MULTI(count, gap_ms, mouse_vk) \
    ((SVC_HK_KIND_MOUSE_MULTI << 24) | \
     ((((((unsigned)(gap_ms) / 50) & 0xFu) << 4) | ((unsigned)(count) & 0xFu)) << 16) | \
     ((unsigned)(mouse_vk) & 0xFFFFu))

/* Mouse VK helpers so payload can quickly identify mouse-vk bindings. */
#define SVC_HK_IS_MOUSE_KIND(k) ((k) == SVC_HK_KIND_MOUSE_HOLD || (k) == SVC_HK_KIND_MOUSE_MULTI)

#define SVC_HK_MOD_CTRL      1
#define SVC_HK_MOD_SHIFT     2
#define SVC_HK_MOD_ALT       4

#ifdef __cplusplus
}
#endif

#endif
