/* ================================================================== *
 * config_types.h — Shared struct definition for the config file.      *
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
    SVC_PROVIDER_OPENAI     = 1,
    SVC_PROVIDER_ANTHROPIC  = 2,
    SVC_PROVIDER_GOOGLE     = 3,
    SVC_PROVIDER_OPENROUTER = 4,
    SVC_PROVIDER_COUNT      = 4,
} svc_provider_t;

/* Model tiers per provider (except OpenRouter which is user-picked).
 * ai_provider.c holds tier→model lookup tables. User cycles via
 * Ctrl+Alt+M hotkey (SVC_HK_CYCLE_TIER). */
typedef enum {
    SVC_TIER_STRONG = 0,   /* max quality / most expensive */
    SVC_TIER_MEDIUM = 1,   /* balanced quality + cost */
    SVC_TIER_CHEAP  = 2,   /* fastest + affordable */
    SVC_TIER_CUSTOM = 3,   /* honor cfg->model verbatim */
    SVC_TIER_COUNT  = 4,
} svc_tier_t;

typedef struct {
    /* Auth (payload uses this to prove subscription validity via periodic
     * re-check against Supabase — attacker can't just extract config
     * and use it without a valid token). */
    char        access_token [4096];
    long long   token_expires_at;

    /* AI provider + key + model + tier.
     * When tier != CUSTOM, ai_provider.c resolves model_id from the
     * tier table (ignores `model` field). When tier == CUSTOM, uses
     * `model` verbatim. Live rotation via Ctrl+Alt+M / Ctrl+Alt+P. */
    int         provider;       /* svc_provider_t */
    int         tier;           /* svc_tier_t; default MEDIUM */
    char        api_key [512];
    char        model   [128];  /* CUSTOM tier + OpenRouter free-picking */
    int         reasoning_effort;   /* 0=none 1=minimal 2=low 3=medium 4=high 5=xhigh */
    int         streaming_enabled;  /* 1 = SSE stream reply into chat */

    /* System prompt (user-editable in settings UI). Sized to hold the
     * built-in SVCLDB_DEFAULT_SYSTEM_PROMPT (~10 KB of subject-matter
     * expertise ported from hooksdll/lumio/src/autosolver.js) plus
     * headroom for user overrides. */
    char        system_prompt[16384];

    /* Hotkeys (packed: (mod << 16) | vk; mod: 1=ctrl 2=shift 4=alt).
     * Slot index matches svc_hotkey_action_t enum below. Zero = unbound.
     * 32 slots is generous but keeps struct size fixed for wire compat. */
    unsigned    hotkeys[32];

    /* Overlay geometry defaults. */
    int         overlay_x, overlay_y;
    int         overlay_w, overlay_h;
    float       overlay_alpha;
} svc_config_t;

/* Hotkey action identifiers — index into svc_config_t.hotkeys[].
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
    SVC_HK_CYCLE_CORNER  = 13,  /* Cycle TL → TR → BR → BL corners        */
    SVC_HK_ALPHA_UP      = 14,  /* +5% background opacity                 */
    SVC_HK_ALPHA_DOWN    = 15,  /* -5% background opacity                 */
    SVC_HK_FONT_UP       = 16,  /* +10% font scale                        */
    SVC_HK_FONT_DOWN     = 17,  /* -10% font scale                        */
    SVC_HK_RESET         = 18,  /* Reset overlay to default position/size */
    SVC_HK_DEBUG_CAP     = 19,  /* Debug capture — save PNGs to Desktop   */
    SVC_HK_KILL_ALL      = 20,  /* Emergency stop — unload payload + kill  *
                                 * DWM + kill any running launcher inst.   */
    SVC_HK_SCROLL_UP     = 21,  /* Reply pane scroll up (Ctrl+Alt+K)       */
    SVC_HK_SCROLL_DOWN   = 22,  /* Reply pane scroll down (Ctrl+Alt+J)     */

    /* Chat-conversation controls (added 2026-07-05 v3). */
    SVC_HK_NEW_CHAT      = 23,  /* Clear ALL chat history (Ctrl+Alt+N)     */
    SVC_HK_CYCLE_TIER    = 24,  /* Cycle STRONG->MEDIUM->CHEAP (Ctrl+Alt+M)*/
    SVC_HK_CYCLE_PROVIDER= 25,  /* Cycle OA->AN->GG->OR   (Ctrl+Shift+P)   *
                                 * (Ctrl+Alt+P conflicts w Chrome print;    *
                                 * Ctrl+Shift+P conflicts w Cursor palette; *
                                 * we picked Ctrl+Shift+Alt+P — 3-mod safe) */
    SVC_HK_REGENERATE    = 26,  /* Re-ask last user turn (Ctrl+Alt+Enter)  */
    SVC_HK_STREAM_TOGGLE = 27,  /* Toggle SSE streaming (Ctrl+Shift+Alt+T) */

    SVC_HK_COUNT
} svc_hotkey_action_t;

/* Hotkey packing helper (mod bits: 1=ctrl 2=shift 4=alt).
 * Ctrl+G would be SVC_HK_PACK(1, 'G'); Ctrl+Shift+Space is SVC_HK_PACK(3, ' '). */
#define SVC_HK_PACK(mod, vk) (((unsigned)(mod) << 16) | (unsigned)(vk))
#define SVC_HK_MOD_CTRL      1
#define SVC_HK_MOD_SHIFT     2
#define SVC_HK_MOD_ALT       4

#ifdef __cplusplus
}
#endif

#endif
