/* ================================================================== *
 * ai_provider.h — Unified interface over OpenAI / Anthropic /         *
 * Google / Openrouter.                                                *
 *                                                                    *
 * MVP: text-only chat completion. Vision (screenshot upload) lands   *
 * in v1.1 once we add PNG encoding.                                  *
 * ================================================================== */
#ifndef SVCLDB_AI_PROVIDER_H
#define SVCLDB_AI_PROVIDER_H

#include "../../../shared/config_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ai_chunk_cb_t)(const char *chunk, size_t len, void *userdata);

/* Single-shot text query. Non-streaming for MVP.
 * screenshot_png / screenshot_len may be NULL/0 for text-only.
 * When present, image is included as vision input.
 *
 * out_reply is a heap-alloc'd null-terminated string on success (free with free()).
 * Returns 1 on success. */
int ai_ask(const svc_config_t *cfg,
           const char *user_prompt,
           const uint8_t *screenshot_png, size_t screenshot_len,
           char **out_reply,
           char *err, size_t err_sz);

/* Free reply from ai_ask. */
void ai_free_reply(char *reply);

#ifdef __cplusplus
}
#endif

#endif
