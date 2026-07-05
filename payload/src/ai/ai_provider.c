/* ================================================================== *
 * ai_provider.c — Provider-agnostic AI request layer.                 *
 *                                                                    *
 * All four providers accept nearly-identical chat-completion shapes: *
 *  - OpenAI / Openrouter: {model, messages:[{role,content}]}         *
 *  - Anthropic:           {model, messages:[{role,content}], system, max_tokens} *
 *  - Google:              {contents:[{role, parts:[{text}]}], generationConfig} *
 *                                                                    *
 * We build the right JSON per provider, POST via WinHTTP, parse the  *
 * response text field. MVP is text-only.                             *
 * ================================================================== */

#include "../../../shared/common.h"
#include "ai_provider.h"
#include "../../../shared/base64.h"
#include "../../../shared/json_util.h"
#include "../../../shared/log_secure.h"
#include "../../../shared/winhttp_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Convert PNG bytes to base64 string. Caller frees. */
static char *png_to_b64(const uint8_t *png, size_t png_len) {
    if (!png || png_len == 0) return NULL;
    size_t enc_len = ((png_len + 2) / 3) * 4 + 1;
    char *out = (char *)malloc(enc_len);
    if (!out) return NULL;
    b64_encode_std(png, png_len, out);
    return out;
}

static const char *effort_str(int e) {
    switch (e) {
        case 1: return "minimal";
        case 2: return "low";
        case 3: return "medium";
        case 4: return "high";
        case 5: return "xhigh";
        default: return NULL;
    }
}

/* ── OpenAI-compatible (also handles Openrouter) ─────────────────── */
static int build_openai_body(const svc_config_t *cfg, const char *user_prompt,
                             const char *image_b64, json_builder_t *jb) {
    if (!jb_init(jb, 4096 + (image_b64 ? strlen(image_b64) : 0))) return 0;
    jb_obj_begin(jb);
      jb_key(jb, "model");    jb_str(jb, cfg->model);
      jb_key(jb, "messages"); jb_arr_begin(jb);
        if (cfg->system_prompt[0]) {
          jb_obj_begin(jb);
            jb_key(jb, "role");    jb_str(jb, "system");
            jb_key(jb, "content"); jb_str(jb, cfg->system_prompt);
          jb_obj_end(jb);
        }
        jb_obj_begin(jb);
          jb_key(jb, "role"); jb_str(jb, "user");
          if (image_b64) {
            /* Vision: content is an array with text + image_url parts. */
            jb_key(jb, "content"); jb_arr_begin(jb);
              jb_obj_begin(jb);
                jb_key(jb, "type"); jb_str(jb, "text");
                jb_key(jb, "text"); jb_str(jb, user_prompt);
              jb_obj_end(jb);
              jb_obj_begin(jb);
                jb_key(jb, "type"); jb_str(jb, "image_url");
                jb_key(jb, "image_url");
                jb_obj_begin(jb);
                  jb_key(jb, "url");
                  {
                    /* Emit "data:image/png;base64,<b64>" as one string. */
                    size_t need = strlen(image_b64) + 32;
                    char *dat = (char *)malloc(need);
                    if (dat) {
                      _snprintf(dat, need - 1, "data:image/png;base64,%s", image_b64);
                      dat[need - 1] = 0;
                      jb_str(jb, dat);
                      free(dat);
                    }
                  }
                jb_obj_end(jb);
              jb_obj_end(jb);
            jb_arr_end(jb);
          } else {
            jb_key(jb, "content"); jb_str(jb, user_prompt);
          }
        jb_obj_end(jb);
      jb_arr_end(jb);
      /* `reasoning` / `reasoning_effort` is ONLY accepted by OpenAI's o-series
       * (o1, o1-mini, o3-mini, o4-mini) and OpenRouter reasoning-tagged models.
       * Sending it to gpt-4o / gpt-4-turbo / claude-* triggers HTTP 400
       * "Unrecognized request argument". Detect by model name. */
      const char *effort = effort_str(cfg->reasoning_effort);
      int is_reasoning_model = 0;
      if (cfg->model[0]) {
          const char *m = cfg->model;
          /* OpenAI reasoning models: o1, o1-mini, o1-preview, o3, o3-mini, o4, o4-mini */
          if ((m[0] == 'o' || m[0] == 'O') &&
              (m[1] >= '1' && m[1] <= '9') &&
              (m[2] == '-' || m[2] == '\0'))
              is_reasoning_model = 1;
          /* OpenRouter models with reasoning suffix. */
          if (strstr(m, "reasoning") || strstr(m, "thinking"))
              is_reasoning_model = 1;
      }
      if (effort && is_reasoning_model) {
        jb_key(jb, "reasoning_effort"); jb_str(jb, effort);
      }
    jb_obj_end(jb);
    return !jb->err;
}

static int extract_openai_reply(const char *body, char **out_reply) {
    /* Response: {"choices":[{"message":{"content":"..."}}]} */
    const char *ch = strstr(body, "\"choices\"");
    if (!ch) return 0;
    const char *arr = strchr(ch, '[');
    if (!arr) return 0;
    const char *obj = strchr(arr, '{');
    if (!obj) return 0;
    /* Balanced brace scan for the first choice object. */
    int depth = 0; const char *e = obj;
    for (; *e; e++) {
        if (*e == '{') depth++;
        else if (*e == '}') { depth--; if (depth == 0) { e++; break; } }
    }
    if (depth != 0) return 0;
    size_t clen = e - obj;
    char *cbuf = (char *)malloc(clen + 1);
    if (!cbuf) return 0;
    memcpy(cbuf, obj, clen); cbuf[clen] = 0;

    /* Nested "message":{"content": "..."} */
    const char *msg = strstr(cbuf, "\"message\"");
    int ok = 0;
    if (msg) {
        const char *mo = strchr(msg, '{');
        if (mo) {
            int md = 0; const char *me = mo;
            for (; *me; me++) {
                if (*me == '{') md++;
                else if (*me == '}') { md--; if (md == 0) { me++; break; } }
            }
            if (md == 0) {
                size_t mlen = me - mo;
                char *mbuf = (char *)malloc(mlen + 1);
                if (mbuf) {
                    memcpy(mbuf, mo, mlen); mbuf[mlen] = 0;
                    char *content = (char *)malloc(65536);
                    if (content) {
                        if (json_get_str(mbuf, "content", content, 65536)) {
                            *out_reply = content;
                            ok = 1;
                        } else {
                            free(content);
                        }
                    }
                    free(mbuf);
                }
            }
        }
    }
    free(cbuf);
    return ok;
}

/* ── Anthropic ────────────────────────────────────────────────── */
static int build_anthropic_body(const svc_config_t *cfg, const char *user_prompt,
                                const char *image_b64, json_builder_t *jb) {
    if (!jb_init(jb, 4096 + (image_b64 ? strlen(image_b64) : 0))) return 0;
    jb_obj_begin(jb);
      jb_key(jb, "model");      jb_str(jb, cfg->model);
      jb_key(jb, "max_tokens"); jb_num_i(jb, 8192);
      if (cfg->system_prompt[0]) {
        jb_key(jb, "system");   jb_str(jb, cfg->system_prompt);
      }
      const char *effort = effort_str(cfg->reasoning_effort);
      if (effort && (cfg->reasoning_effort >= 3)) {
        jb_key(jb, "thinking");
        jb_obj_begin(jb);
          jb_key(jb, "type");          jb_str(jb, "enabled");
          jb_key(jb, "budget_tokens"); jb_num_i(jb, cfg->reasoning_effort >= 5 ? 32768 : 16384);
        jb_obj_end(jb);
      }
      jb_key(jb, "messages"); jb_arr_begin(jb);
        jb_obj_begin(jb);
          jb_key(jb, "role"); jb_str(jb, "user");
          if (image_b64) {
            /* Vision: content is array of {type,text}/{type,image} parts. */
            jb_key(jb, "content"); jb_arr_begin(jb);
              jb_obj_begin(jb);
                jb_key(jb, "type"); jb_str(jb, "image");
                jb_key(jb, "source");
                jb_obj_begin(jb);
                  jb_key(jb, "type");        jb_str(jb, "base64");
                  jb_key(jb, "media_type");  jb_str(jb, "image/png");
                  jb_key(jb, "data");        jb_str(jb, image_b64);
                jb_obj_end(jb);
              jb_obj_end(jb);
              jb_obj_begin(jb);
                jb_key(jb, "type"); jb_str(jb, "text");
                jb_key(jb, "text"); jb_str(jb, user_prompt);
              jb_obj_end(jb);
            jb_arr_end(jb);
          } else {
            jb_key(jb, "content"); jb_str(jb, user_prompt);
          }
        jb_obj_end(jb);
      jb_arr_end(jb);
    jb_obj_end(jb);
    return !jb->err;
}

static int extract_anthropic_reply(const char *body, char **out_reply) {
    /* Response: {"content":[{"type":"text","text":"..."}]} */
    const char *ch = strstr(body, "\"content\"");
    if (!ch) return 0;
    const char *arr = strchr(ch, '[');
    if (!arr) return 0;
    /* Find first "text" block. */
    const char *t = arr;
    while ((t = strstr(t, "\"type\":\"text\""))) {
        const char *o_end = strchr(t, '}');
        if (!o_end) break;
        size_t olen = o_end - arr + 1;   /* approx */
        char *obuf = (char *)malloc(olen + 1);
        if (!obuf) return 0;
        /* Find containing object braces. */
        const char *ob = t; while (ob > arr && *ob != '{') ob--;
        int md = 0; const char *oe = ob;
        for (; *oe; oe++) {
            if (*oe == '{') md++;
            else if (*oe == '}') { md--; if (md == 0) { oe++; break; } }
        }
        if (md == 0) {
            size_t sz = oe - ob;
            memcpy(obuf, ob, sz); obuf[sz] = 0;
            char *reply = (char *)malloc(65536);
            if (reply) {
                if (json_get_str(obuf, "text", reply, 65536)) {
                    *out_reply = reply;
                    free(obuf);
                    return 1;
                }
                free(reply);
            }
        }
        free(obuf);
        t += 8;
    }
    return 0;
}

/* ── Google Gemini ────────────────────────────────────────────── */
static int build_google_body(const svc_config_t *cfg, const char *user_prompt,
                             const char *image_b64, json_builder_t *jb) {
    if (!jb_init(jb, 4096 + (image_b64 ? strlen(image_b64) : 0))) return 0;
    jb_obj_begin(jb);
      if (cfg->system_prompt[0]) {
        jb_key(jb, "system_instruction");
        jb_obj_begin(jb);
          jb_key(jb, "parts");
          jb_arr_begin(jb);
            jb_obj_begin(jb);
              jb_key(jb, "text"); jb_str(jb, cfg->system_prompt);
            jb_obj_end(jb);
          jb_arr_end(jb);
        jb_obj_end(jb);
      }
      jb_key(jb, "contents");
      jb_arr_begin(jb);
        jb_obj_begin(jb);
          jb_key(jb, "role"); jb_str(jb, "user");
          jb_key(jb, "parts");
          jb_arr_begin(jb);
            if (image_b64) {
              jb_obj_begin(jb);
                jb_key(jb, "inline_data");
                jb_obj_begin(jb);
                  jb_key(jb, "mime_type"); jb_str(jb, "image/png");
                  jb_key(jb, "data");      jb_str(jb, image_b64);
                jb_obj_end(jb);
              jb_obj_end(jb);
            }
            jb_obj_begin(jb);
              jb_key(jb, "text"); jb_str(jb, user_prompt);
            jb_obj_end(jb);
          jb_arr_end(jb);
        jb_obj_end(jb);
      jb_arr_end(jb);
      if (cfg->reasoning_effort >= 3) {
        jb_key(jb, "generationConfig");
        jb_obj_begin(jb);
          jb_key(jb, "thinkingConfig");
          jb_obj_begin(jb);
            jb_key(jb, "thinkingBudget");
            jb_num_i(jb, cfg->reasoning_effort >= 5 ? 32768 : (cfg->reasoning_effort >= 4 ? 16384 : 8192));
          jb_obj_end(jb);
        jb_obj_end(jb);
      }
    jb_obj_end(jb);
    return !jb->err;
}

static int extract_google_reply(const char *body, char **out_reply) {
    /* Response: {"candidates":[{"content":{"parts":[{"text":"..."}]}}]} */
    const char *cand = strstr(body, "\"candidates\"");
    if (!cand) return 0;
    const char *text_key = strstr(cand, "\"text\"");
    if (!text_key) return 0;
    /* Roll back to enclosing object. */
    const char *ob = text_key;
    while (ob > cand && *ob != '{') ob--;
    int md = 0; const char *oe = ob;
    for (; *oe; oe++) {
        if (*oe == '{') md++;
        else if (*oe == '}') { md--; if (md == 0) { oe++; break; } }
    }
    if (md != 0) return 0;
    size_t sz = oe - ob;
    char *obuf = (char *)malloc(sz + 1);
    if (!obuf) return 0;
    memcpy(obuf, ob, sz); obuf[sz] = 0;
    char *reply = (char *)malloc(65536);
    int ok = 0;
    if (reply) {
        if (json_get_str(obuf, "text", reply, 65536)) {
            *out_reply = reply;
            ok = 1;
        } else {
            free(reply);
        }
    }
    free(obuf);
    return ok;
}

/* ── Public entry ─────────────────────────────────────────────── */
int ai_ask(const svc_config_t *cfg, const char *user_prompt,
           const uint8_t *screenshot_png, size_t screenshot_len,
           char **out_reply, char *err, size_t err_sz) {
    (void)screenshot_png; (void)screenshot_len;   /* v1.1: vision */
    if (!cfg || !user_prompt || !out_reply || !err) return 0;
    *out_reply = NULL;
    err[0] = 0;

    if (cfg->api_key[0] == 0) {
        _snprintf(err, err_sz - 1, "no api key configured"); err[err_sz - 1] = 0;
        return 0;
    }
    if (cfg->model[0] == 0) {
        _snprintf(err, err_sz - 1, "no model configured"); err[err_sz - 1] = 0;
        return 0;
    }

    json_builder_t jb = {0};
    char url[256] = {0};
    char auth_hdr[1024] = {0};
    char extra_hdr[256] = {0};
    const char *hdrs[6] = { NULL };

    /* base64-encode screenshot once, share across providers. */
    char *image_b64 = NULL;
    if (screenshot_png && screenshot_len > 0) {
        image_b64 = png_to_b64(screenshot_png, screenshot_len);
        if (!image_b64) {
            _snprintf(err, err_sz - 1, "image base64 encode failed"); err[err_sz - 1] = 0;
            return 0;
        }
    }

    switch (cfg->provider) {
        case SVC_PROVIDER_OPENAI:
            if (!build_openai_body(cfg, user_prompt, image_b64, &jb)) {
                _snprintf(err, err_sz - 1, "json build failed");
                if (image_b64) free(image_b64);
                return 0;
            }
            _snprintf(url,      sizeof(url) - 1,      "https://api.openai.com/v1/chat/completions");
            _snprintf(auth_hdr, sizeof(auth_hdr) - 1, "Authorization: Bearer %s", cfg->api_key);
            hdrs[0] = "Content-Type: application/json";
            hdrs[1] = auth_hdr;
            hdrs[2] = NULL;
            break;
        case SVC_PROVIDER_OPENROUTER:
            if (!build_openai_body(cfg, user_prompt, image_b64, &jb)) {
                _snprintf(err, err_sz - 1, "json build failed");
                if (image_b64) free(image_b64);
                return 0;
            }
            _snprintf(url,      sizeof(url) - 1,      "https://openrouter.ai/api/v1/chat/completions");
            _snprintf(auth_hdr, sizeof(auth_hdr) - 1, "Authorization: Bearer %s", cfg->api_key);
            _snprintf(extra_hdr,sizeof(extra_hdr) - 1,"HTTP-Referer: https://svcldb.local");
            hdrs[0] = "Content-Type: application/json";
            hdrs[1] = auth_hdr;
            hdrs[2] = extra_hdr;
            hdrs[3] = "X-Title: svcldb";
            hdrs[4] = NULL;
            break;
        case SVC_PROVIDER_ANTHROPIC:
            if (!build_anthropic_body(cfg, user_prompt, image_b64, &jb)) {
                _snprintf(err, err_sz - 1, "json build failed");
                if (image_b64) free(image_b64);
                return 0;
            }
            _snprintf(url,      sizeof(url) - 1,      "https://api.anthropic.com/v1/messages");
            _snprintf(auth_hdr, sizeof(auth_hdr) - 1, "x-api-key: %s", cfg->api_key);
            hdrs[0] = "Content-Type: application/json";
            hdrs[1] = auth_hdr;
            hdrs[2] = "anthropic-version: 2023-06-01";
            hdrs[3] = NULL;
            break;
        case SVC_PROVIDER_GOOGLE: {
            if (!build_google_body(cfg, user_prompt, image_b64, &jb)) {
                _snprintf(err, err_sz - 1, "json build failed");
                if (image_b64) free(image_b64);
                return 0;
            }
            _snprintf(url, sizeof(url) - 1,
                      "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent",
                      cfg->model);
            _snprintf(auth_hdr, sizeof(auth_hdr) - 1, "x-goog-api-key: %s", cfg->api_key);
            hdrs[0] = "Content-Type: application/json";
            hdrs[1] = auth_hdr;
            hdrs[2] = NULL;
            break;
        }
        default:
            _snprintf(err, err_sz - 1, "unknown provider %d", cfg->provider);
            err[err_sz - 1] = 0;
            if (image_b64) free(image_b64);
            return 0;
    }
    if (image_b64) { free(image_b64); image_b64 = NULL; }

    slog_writef("ai.log", "ai_ask provider=%d model=%s prompt_len=%zu",
                cfg->provider, cfg->model, strlen(user_prompt));

    whreq_result_t r = {0};
    int ok = whreq_post(url, hdrs, jb.buf, jb.len, &r);
    jb_free(&jb);
    if (!ok) {
        _snprintf(err, err_sz - 1, "transport: %s", r.err); err[err_sz - 1] = 0;
        whreq_free_result(&r);
        return 0;
    }
    if (r.status < 200 || r.status >= 300) {
        _snprintf(err, err_sz - 1, "http %u: %.256s",
                  r.status, r.body ? r.body : "");
        err[err_sz - 1] = 0;
        slog_writef("ai.log", "ai_ask failed http=%u", r.status);
        whreq_free_result(&r);
        return 0;
    }

    int extracted = 0;
    if (cfg->provider == SVC_PROVIDER_ANTHROPIC)     extracted = extract_anthropic_reply(r.body, out_reply);
    else if (cfg->provider == SVC_PROVIDER_GOOGLE)   extracted = extract_google_reply(r.body,    out_reply);
    else /* OpenAI + Openrouter */                    extracted = extract_openai_reply(r.body,    out_reply);

    if (!extracted) {
        _snprintf(err, err_sz - 1, "no reply text in response"); err[err_sz - 1] = 0;
        whreq_free_result(&r);
        return 0;
    }
    slog_writef("ai.log", "ai_ask ok reply_len=%zu", strlen(*out_reply));
    whreq_free_result(&r);
    return 1;
}

void ai_free_reply(char *reply) { if (reply) free(reply); }
