/* ================================================================== *
 * cu_common.h -- Shared types for the three vendor computer-use (CU)
 * adapters (Anthropic / OpenAI / Gemini). 1:1 port of the canonical
 * action shape + provider dispatch spine used by hooksdll's
 * lumio/src/agent_mode.js. The three adapters each produce a list of
 * these canonical actions from their vendor-specific tool call
 * outputs; agent_loop.c dispatches them via the shared humanized
 * injection stack (input/actions.c).
 * ================================================================== */
#ifndef SVCLDB_AGENT_CU_COMMON_H
#define SVCLDB_AGENT_CU_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Canonical action ──────────────────────────────────────────────
 * Every vendor emits its own tool-call shape; each adapter converts
 * to this one type. Matches hooksdll's per-action objects fed to
 * dispatchAgentAction. `action[]` is one of:
 *   "left_click", "right_click", "double_click", "middle_click",
 *   "mouse_move", "type", "key", "scroll", "left_click_drag",
 *   "wait", "screenshot" (no-op).
 * coordinate    -- IMAGE-space (px in the shot we sent), when applicable
 * start_coord   -- only for left_click_drag
 * text          -- for type / key
 * scroll_dir    -- "up"/"down"/"left"/"right"
 * scroll_amount -- notches (1..20 typical)
 * duration_ms   -- for wait
 * tool_use_id   -- Anthropic-only bookkeeping (paired with tool_result
 *                  in the next turn's user message; empty otherwise). */
typedef struct {
    char  action[24];
    int   has_coord;   int coord_x,     coord_y;
    int   has_start;   int start_x,     start_y;
    char  text[1024];
    char  scroll_dir[8];
    int   scroll_amount;
    int   duration_ms;
    char  tool_use_id[80];
} cu_action_t;

/* Capture bundle handed to each vendor adapter. Same shape hooksdll's
 * `cap` object had (b64 image + width + height + optional UIA anchor
 * block). Ownership: adapter READS these; caller owns the memory. */
typedef struct {
    const char *b64;              /* base64 JPEG (no data: prefix) */
    int         w;                /* image width  in px */
    int         h;                /* image height in px */
    const char *uia_anchor_block; /* nullable */
} cu_cap_t;

/* Usage + cost accounting returned by each vendor turn. */
typedef struct {
    int    input_tokens;
    int    output_tokens;
    int    cache_read;
    int    cache_create;
    double cost_usd;
} cu_usage_t;

/* Result of one adapter turn. `actions` is a malloc'd array; caller
 * frees via cu_actions_free. `stop_reason` mirrors hooksdll's:
 *   "end_turn" | "stop" | "end"  -> model is DONE
 *   "tool_use"                   -> keep looping (action taken)
 *   "error"                      -> hard failure, err[] populated */
typedef struct {
    cu_action_t *actions;
    int          n_actions;
    char         stop_reason[24];
    cu_usage_t   usage;
    char         model[128];
    char         err[256];         /* populated on error, else empty */
} cu_turn_result_t;

void cu_actions_free(cu_turn_result_t *r);

/* Per-provider adapter (implemented in cu_anthropic.c / cu_openai.c /
 * cu_gemini.c). Returns 1 on success (fills *out); 0 on hard error
 * (out->err populated). Reads model + API key + conversation state
 * from the shared cu_state passed by agent_loop. */
struct cu_state_s;
typedef struct cu_state_s cu_state_t;

int cu_anthropic_turn(cu_state_t *st, const char *model, const char *api_key,
                      const cu_cap_t *cap, const char *task,
                      cu_turn_result_t *out);
int cu_openai_turn(cu_state_t *st, const char *model, const char *api_key,
                   const cu_cap_t *cap, const char *task,
                   cu_turn_result_t *out);
int cu_gemini_turn(cu_state_t *st, const char *model, const char *api_key,
                   const cu_cap_t *cap, const char *task,
                   cu_turn_result_t *out);

/* ── Provider registry (matches hooksdll PROVIDERS block) ─────────
 * Tier resolution: 0=strong, 1=medium, 2=cheap. Fallback used on a
 * per-turn 429/5xx retry (see agent_loop.c). */
typedef struct {
    const char *label;
    const char *strong;
    const char *medium;
    const char *cheap;
    const char *fallback;
    int (*turn)(cu_state_t *, const char *, const char *,
                const cu_cap_t *, const char *,
                cu_turn_result_t *);
} cu_provider_t;

extern const cu_provider_t cu_providers[3];      /* index = agent_provider */

/* Shared conversation state across turns. Provider-specific pieces are
 * kept as raw heap strings + counters (JSON fragments accumulated per
 * turn). Cleared via cu_state_reset when the agent restarts. */
struct cu_state_s {
    /* Anthropic: full messages array, JSON-encoded on the fly.
     * We accumulate each turn's user/assistant message pair as a
     * growing text buffer of comma-separated JSON objects. This lets
     * us paste it into the request body's `messages` field literally. */
    char *anth_conv_json;    /* heap-allocated growing buffer */
    size_t anth_conv_len;
    size_t anth_conv_cap;
    int   anth_screenshot_count;

    /* OpenAI: stateful via previous_response_id. */
    char  openai_prev_response_id[128];
    char  openai_call_id[128];

    /* Gemini: accumulated contents JSON list */
    char *gem_conv_json;
    size_t gem_conv_len;
    size_t gem_conv_cap;

    /* Total spend across all turns this session (USD). Reset on start. */
    double total_spend_usd;
    int    total_turns;
};

cu_state_t *cu_state_new(void);
void        cu_state_free(cu_state_t *st);
void        cu_state_reset(cu_state_t *st);

/* Per-model pricing lookup (matches hooksdll PRICING dict). Returns
 * per-token cost in USD. Missing model -> generic default. */
typedef struct { double in_per_tok; double out_per_tok; double cached_per_tok; } cu_price_t;
cu_price_t cu_price_for(const char *model);

/* ── Byte-stable system prompt used by ALL three CU adapters ──
 * Copied verbatim from hooksdll's SYSTEM_PROMPT so provider prompt-
 * caching hits with the same 4-KB block. Update in lockstep with
 * hooksdll if you ever tweak it there. */
extern const char CU_SYSTEM_PROMPT[];

/* ── Task sanitizer (matches hooksdll _sanitizeTask). Rewrites in
 * place. Replaces vendor-policy trigger tokens with neutral synonyms
 * (exam->form, proctor->monitored, ...). */
void cu_sanitize_task(char *s, size_t sz);

/* ── Utility: append to a growing char buffer with realloc. Returns
 * new capacity or 0 on OOM. Used by adapters to build conv JSON. */
int  cu_buf_append(char **buf, size_t *len, size_t *cap, const char *s, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_AGENT_CU_COMMON_H */
