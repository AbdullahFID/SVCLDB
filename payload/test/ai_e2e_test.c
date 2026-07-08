/*
 * ai_e2e_test.c — live end-to-end test of ai_ask_streaming.
 *
 * Calls the SAME ai_provider.c code the payload uses, but from a
 * normal Win32 process, so we can iterate without DWM injection.
 *
 * Usage:
 *   ai_e2e_test.exe google  <key>  [model]
 *   ai_e2e_test.exe openai  <key>  [model]
 *   ai_e2e_test.exe anthro  <key>  [model]
 *   ai_e2e_test.exe orouter <key>  [model]
 *
 * `<model>` optional. If omitted, uses tier MEDIUM default.
 *
 * Prints each streaming chunk to stdout. Prints a summary line at
 * the end. Exit code 0 = success, non-zero = failure.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#include "config_types.h"
#include "../src/ai/ai_provider.h"

static void on_chunk(const char *bytes, size_t len, void *userdata) {
    (void)userdata;
    fwrite(bytes, 1, len, stdout);
    fflush(stdout);
}

static void on_done(int ok, const char *full_reply, size_t full_len,
                    const char *err, void *userdata) {
    (void)userdata;
    printf("\n\n=== on_done ok=%d full_len=%zu ===\n", ok, full_len);
    if (!ok && err) {
        printf("=== ERROR: %s ===\n", err);
    } else if (ok) {
        printf("=== SUCCESS (first 100 chars of full_reply): %.100s ===\n",
               full_reply ? full_reply : "(null)");
    }
    if (full_reply) ai_free_reply((char *)full_reply);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s google|openai|anthro|orouter <key> [model]\n", argv[0]);
        return 2;
    }
    const char *prov_str  = argv[1];
    const char *key       = argv[2];
    const char *model_ov  = argc >= 4 ? argv[3] : NULL;

    svc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.magic          = SVC_CONFIG_MAGIC;
    cfg.schema_version = SVC_CONFIG_SCHEMA_VERSION;
    cfg.tier           = SVC_TIER_MEDIUM;
    cfg.reasoning_effort = 3;
    cfg.streaming_enabled = 1;
    cfg.stream_display_batched = 0;
    cfg.latex_disabled = 0;

    if      (strcmp(prov_str, "google") == 0)  cfg.provider = SVC_PROVIDER_GOOGLE;
    else if (strcmp(prov_str, "openai") == 0)  cfg.provider = SVC_PROVIDER_OPENAI;
    else if (strcmp(prov_str, "anthro") == 0)  cfg.provider = SVC_PROVIDER_ANTHROPIC;
    else if (strcmp(prov_str, "orouter") == 0) cfg.provider = SVC_PROVIDER_OPENROUTER;
    else { fprintf(stderr, "bad provider: %s\n", prov_str); return 2; }

    /* Plant the key in BOTH the legacy field + the per-provider slot so
     * ai_pick_provider_key returns it under either code path. */
    _snprintf(cfg.api_key, sizeof(cfg.api_key) - 1, "%s", key);
    switch (cfg.provider) {
        case SVC_PROVIDER_OPENAI:
            _snprintf(cfg.api_key_openai, sizeof(cfg.api_key_openai) - 1, "%s", key);
            break;
        case SVC_PROVIDER_ANTHROPIC:
            _snprintf(cfg.api_key_anthropic, sizeof(cfg.api_key_anthropic) - 1, "%s", key);
            break;
        case SVC_PROVIDER_GOOGLE:
            _snprintf(cfg.api_key_google, sizeof(cfg.api_key_google) - 1, "%s", key);
            break;
        case SVC_PROVIDER_OPENROUTER:
            _snprintf(cfg.api_key_openrouter, sizeof(cfg.api_key_openrouter) - 1, "%s", key);
            break;
    }

    if (model_ov) {
        cfg.tier = SVC_TIER_CUSTOM;
        _snprintf(cfg.model, sizeof(cfg.model) - 1, "%s", model_ov);
    }

    /* Use empty system prompt so the payload materializes DEFAULT. */
    cfg.system_prompt[0] = 0;

    printf("=== ai_ask_streaming provider=%s tier=%d model=%s ===\n",
           prov_str, cfg.tier, model_ov ? model_ov : "<tier default>");

    const char *user_prompt =
        "One-line answer only: what is the capital of France?";

    int rc = ai_ask_streaming(&cfg, user_prompt, NULL, 0,
                              on_chunk, on_done, NULL);
    printf("\n=== ai_ask_streaming returned %d ===\n", rc);
    return rc ? 0 : 1;
}
