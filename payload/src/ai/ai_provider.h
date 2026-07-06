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

/* ── Test an API key ──
 *
 * Hits the provider's cheapest "list models" endpoint with the given key.
 * Returns the HTTP status (200 = valid, 401/403 = bad key, 429 = valid
 * but rate-limited, 5xx = provider-side issue). Fills out_latency_ms
 * with round-trip time when the roundtrip succeeded.
 *
 * Fast — 6s cap. Doesn't consume any tokens (models list is free).
 * Safe to call from a UI thread as a diagnostic check.
 *
 * Returns 1 iff the HTTP roundtrip completed (status may still be non-2xx),
 * 0 on transport failure (err populated). */
int ai_test_key(int provider, const char *api_key,
                unsigned *out_status, unsigned *out_latency_ms,
                char *err, size_t err_sz);

/* Pick the effective API key for a given provider from the config.
 * Order:
 *   1. cfg->api_key (legacy shared field) if non-empty
 *   2. cfg->api_key_<provider>
 * Returns NULL if no usable key. Never returns an empty string.
 *
 * Exposed for the fallback loop in ai_ask / ai_ask_streaming and for
 * the UI's local "which providers can I fall back to?" query. */
const char *ai_pick_provider_key(const svc_config_t *cfg, int provider);

/* Return non-zero if the model_id names a "reasoning-heavy" model that
 * routinely produces long silences between SSE chunks and therefore
 * needs the extended (15-min) receive timeout. Matches o3*, gpt-5.5-pro,
 * claude-opus-4*, gemini-3.*-pro*. */
int ai_is_reasoning_model(const char *model_id);

/* ── User-triggered stream abort ──
 *
 * Sets a process-wide flag that ai_ask_streaming's chunk callback
 * checks on every incoming SSE token. When set, the WinHTTP read loop
 * returns non-zero from the callback → WinHTTP tears down the request
 * cleanly → on_done fires with a friendly "stopped by user" message.
 *
 * The flag is auto-cleared at the START of every ai_ask / ai_ask_streaming
 * call so a stale abort from before doesn't poison a fresh request.
 *
 * Bound to Ctrl+Alt+S by default (SVC_HK_STOP_GEN). Safe to call from
 * any thread — uses InterlockedExchange. */
void ai_request_abort(void);

/* Zero the abort flag. Called implicitly at the start of each request
 * but exposed for tests + explicit reset paths. */
void ai_clear_abort(void);

/* Non-zero if the abort flag is currently set. Used by both the C
 * stream callback and the UI's "show cancel button" state check. */
int  ai_abort_requested(void);

#ifdef __cplusplus
}
#endif

#endif
