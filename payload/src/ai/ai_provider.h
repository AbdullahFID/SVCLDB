/* ================================================================== *
 * ai_provider.h — Unified interface over OpenAI / Anthropic /         *
 * Google / OpenRouter.                                                *
 *                                                                    *
 * Supports:                                                          *
 *  - Vision (screenshot input)                                       *
 *  - Reasoning-effort routing per provider                           *
 *  - STRONG / MEDIUM / CHEAP tier presets                            *
 *  - Streaming (SSE) response                                        *
 *  - Automatic retry with exponential backoff                        *
 *                                                                    *
 * Every provider follows the "text before image" content-ordering    *
 * rule — Anthropic + OpenAI docs are both explicit that this yields  *
 * measurably better vision accuracy.                                 *
 * ================================================================== */
#ifndef SVCLDB_AI_PROVIDER_H
#define SVCLDB_AI_PROVIDER_H

#include "../../../shared/config_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Tier tables ──
 *
 * OpenAI, Anthropic, Google each expose 3 tiers we curate. OpenRouter
 * is user-picked — either "openrouter/free" (default, zero-cost auto-
 * routing) or any specific slug like "meta-llama/llama-4-maverick:free".
 */
typedef struct {
    const char *model_id;       /* API slug */
    const char *display_name;   /* user-facing */
    const char *notes;          /* pricing + context hint */
    int         supports_vision;
    int         supports_reasoning;
    int         default_max_output_tokens;
} svc_model_tier_t;

/* Lookup model info for a (provider, tier) pair.
 * For OpenRouter, tier is ignored — always returns the entry pointing
 * at "openrouter/free". Non-OpenRouter with tier=CUSTOM returns NULL
 * (caller must use cfg->model verbatim).
 * Returns NULL if the (provider, tier) combo isn't supported. */
const svc_model_tier_t *ai_get_tier(int provider, int tier);

/* Human-readable name of a provider ("OpenAI", "Anthropic", etc.). */
const char *ai_provider_name(int provider);

/* Human-readable name of a tier ("STRONG", "MEDIUM", "CHEAP", "CUSTOM"). */
const char *ai_tier_name(int tier);

/* ── Non-streaming single-shot query.
 * screenshot_png / screenshot_len may be NULL/0 for text-only.
 * out_reply is a heap-alloc'd null-terminated string on success (free with ai_free_reply).
 * Returns 1 on success. */
int ai_ask(const svc_config_t *cfg,
           const char *user_prompt,
           const uint8_t *screenshot_png, size_t screenshot_len,
           char **out_reply,
           char *err, size_t err_sz);

/* ── Streaming query.
 *
 * on_chunk is called for every incremental token/word (may be called
 * many times per request). `chunk` is UTF-8 text (NOT null-terminated —
 * use `len`). Return 0 to keep streaming, non-zero to abort.
 *
 * on_done fires exactly once when the stream ends, with the full
 * response text (heap-alloc'd, caller owns via ai_free_reply) — or
 * NULL if the stream errored. `err` in on_done is populated only on
 * error.
 *
 * cfg->streaming_enabled must be 1 or this fails immediately.
 *
 * Returns 1 if the HTTP roundtrip completed, 0 on transport error.
 */
typedef void (*ai_stream_chunk_cb)(const char *chunk, size_t len, void *userdata);
typedef void (*ai_stream_done_cb)(int ok, const char *full_reply, size_t reply_len,
                                  const char *err, void *userdata);

int ai_ask_streaming(const svc_config_t *cfg,
                     const char *user_prompt,
                     const uint8_t *screenshot_png, size_t screenshot_len,
                     ai_stream_chunk_cb on_chunk,
                     ai_stream_done_cb on_done,
                     void *userdata);

/* Free reply from ai_ask / on_done. */
void ai_free_reply(char *reply);

/* Retrieve the default system prompt (the ~10 KB SVCLDB constant).
 * Returned pointer is static storage; do not free. */
const char *ai_default_system_prompt(void);

#ifdef __cplusplus
}
#endif

#endif
