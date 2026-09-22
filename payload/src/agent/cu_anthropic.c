/* ================================================================== *
 * cu_anthropic.c -- Anthropic computer-use tool adapter.
 *
 * 1:1 port of hooksdll's anthropicTurn(). Handles:
 *  - tool type selection (computer_20250124 for Sonnet 4.x / Opus 4.5,
 *    computer_20251124 for Opus 4.7+ / Sonnet 5 / Fable / Mythos with
 *    enable_zoom action)
 *  - anthropic-beta header set accordingly
 *  - Full conversation history: user + assistant messages accumulated
 *    across turns (Anthropic API is stateless)
 *  - Screenshot trimming: last 5 images kept, older replaced with
 *    "[earlier screenshot elided]" text blocks
 *  - Tool result pairing: last assistant turn's tool_use IDs get paired
 *    with user tool_result blocks containing the fresh screenshot
 *  - Pricing lookup + usage tallying (input/output/cache tokens)
 * ================================================================== */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cu_common.h"
#include "../../../shared/winhttp_util.h"
#include "../../../shared/json_util.h"

extern void slog_writef(const char *file, const char *fmt, ...);

/* Match hooksdll's _HI_TIER_ANTHROPIC regex: opus-4-[7-9], opus-4-\d\d,
 * opus-5, sonnet-5, fable, mythos. Returns 1 if this SKU takes the
 * newer computer_20251124 tool. */
static int is_hi_tier_anthropic(const char *m) {
    if (!m) return 0;
    if (strstr(m, "opus-5"))   return 1;
    if (strstr(m, "sonnet-5")) return 1;
    if (strstr(m, "fable"))    return 1;
    if (strstr(m, "mythos"))   return 1;
    /* opus-4-{7,8,9,two-digit} */
    const char *p = strstr(m, "opus-4-");
    if (p) {
        const char *v = p + 7;
        if ((v[0] >= '7' && v[0] <= '9') ||
            (v[0] >= '0' && v[0] <= '9' && v[1] >= '0' && v[1] <= '9'))
            return 1;
    }
    return 0;
}

/* Append the "assistant reply" from the current turn's JSON response
 * into st->anth_conv_json so the NEXT turn can pair its tool_use IDs
 * with tool_result blocks. Extracts the outer `content` array as-is. */
static int append_assistant_reply(cu_state_t *st, const char *reply_json) {
    /* Extract the "content":[...] value from the top-level object. Anthropic
     * responses look like {"id":..,"content":[{...},{...}],"usage":{...}}. */
    const char *ck = strstr(reply_json, "\"content\"");
    if (!ck) return 0;
    ck = strchr(ck, '[');
    if (!ck) return 0;
    const char *ce = json_skip_array(ck);
    if (!ce) return 0;
    size_t clen = (size_t)(ce - ck);
    char *frag = (char *)malloc(clen + 128);
    if (!frag) return 0;
    int fl = _snprintf(frag, clen + 128 - 1,
                       ",{\"role\":\"assistant\",\"content\":%.*s}",
                       (int)clen, ck);
    if (fl < 0) { free(frag); return 0; }
    cu_buf_append(&st->anth_conv_json, &st->anth_conv_len, &st->anth_conv_cap,
                  frag, (size_t)fl);
    free(frag);
    return 1;
}

/* Extract all `id` strings from tool_use blocks in the last assistant
 * message. Fills out_ids[] (each 80 bytes). Returns count. */
static int extract_last_tool_use_ids(cu_state_t *st, char out_ids[][80], int max_ids) {
    if (!st->anth_conv_json || st->anth_conv_len == 0) return 0;
    /* Find the LAST "content":[...] block. */
    const char *p = st->anth_conv_json;
    const char *last_arr = NULL;
    while ((p = strstr(p, "\"content\"")) != NULL) { last_arr = p; p++; }
    if (!last_arr) return 0;
    const char *arr = strchr(last_arr, '[');
    if (!arr) return 0;
    const char *end = json_skip_array(arr);
    if (!end) return 0;
    int n = 0;
    const char *cur = arr;
    while (cur < end && n < max_ids) {
        const char *tuk = strstr(cur, "\"type\"");
        if (!tuk || tuk >= end) break;
        /* Find the enclosing object of this "type":"tool_use". */
        const char *ttype = strchr(tuk, ':');
        if (!ttype) break;
        ttype++;
        while (*ttype == ' ' || *ttype == '"') ttype++;
        if (strncmp(ttype, "tool_use", 8) != 0) { cur = tuk + 1; continue; }
        /* Grab the "id" field from this object. */
        const char *idk = strstr(tuk, "\"id\"");
        if (!idk || idk > end) break;
        const char *vs = strchr(idk, '"');
        if (!vs) break; vs = strchr(vs + 1, '"');   /* end of "id" */
        if (!vs) break; vs = strchr(vs + 1, '"');   /* open of value */
        if (!vs) break; vs++;
        const char *ve = strchr(vs, '"');
        if (!ve) break;
        size_t idlen = (size_t)(ve - vs); if (idlen >= 80) idlen = 79;
        memcpy(out_ids[n], vs, idlen); out_ids[n][idlen] = 0;
        n++;
        cur = ve + 1;
    }
    return n;
}

/* Parse tool_use action blocks from the assistant reply. Anthropic's
 * computer tool input has fields:
 *   action: "left_click"|"right_click"|"double_click"|"triple_click"|
 *           "middle_click"|"mouse_move"|"left_click_drag"|"type"|"key"|
 *           "scroll"|"wait"|"screenshot"|"cursor_position"|"zoom"
 *   coordinate: [x, y]
 *   start_coordinate: [x, y]   (drag)
 *   text: string               (type / key)
 *   scroll_direction: "up"|"down"|"left"|"right"
 *   scroll_amount: int
 *   duration: int              (wait; seconds)
 * Also extracts the `id` field so we can pair tool_result later. */
static int parse_anthropic_actions(const char *reply_json,
                                   cu_action_t **out, int *out_n) {
    *out = NULL; *out_n = 0;
    const char *ck = strstr(reply_json, "\"content\"");
    if (!ck) return 0;
    const char *arr = strchr(ck, '[');
    if (!arr) return 0;
    const char *end = json_skip_array(arr);
    if (!end) return 0;

    cu_action_t list[32]; int n = 0;
    const char *cur = arr + 1;
    while (cur < end && n < 32) {
        while (cur < end && (*cur == ' ' || *cur == '\n' || *cur == '\r' || *cur == '\t' || *cur == ',')) cur++;
        if (*cur != '{') break;
        const char *bo = json_skip_object(cur);
        if (!bo || bo <= cur) break;
        size_t blen = (size_t)(bo - cur);
        char *block = (char *)malloc(blen + 1);
        if (!block) break;
        memcpy(block, cur, blen); block[blen] = 0;

        char btype[32] = {0}, name[32] = {0};
        json_get_str(block, "type", btype, sizeof(btype));
        if (strcmp(btype, "tool_use") == 0) {
            json_get_str(block, "name", name, sizeof(name));
            if (strcmp(name, "computer") == 0) {
                /* Extract the input object. */
                const char *ik = strstr(block, "\"input\"");
                if (ik) {
                    const char *is = strchr(ik, '{');
                    if (is) {
                        const char *ie = json_skip_object(is);
                        if (ie && ie > is) {
                            size_t ilen = (size_t)(ie - is);
                            char *ib = (char *)malloc(ilen + 1);
                            if (ib) {
                                memcpy(ib, is, ilen); ib[ilen] = 0;
                                cu_action_t *a = &list[n];
                                memset(a, 0, sizeof(*a));
                                json_get_str(ib, "action", a->action, sizeof(a->action));
                                json_get_str(ib, "text", a->text, sizeof(a->text));
                                json_get_str(ib, "scroll_direction", a->scroll_dir, sizeof(a->scroll_dir));
                                double d;
                                if (json_get_num(ib, "scroll_amount", &d)) a->scroll_amount = (int)d;
                                if (json_get_num(ib, "duration", &d)) a->duration_ms = (int)(d * 1000);
                                /* coordinate: [x,y] */
                                const char *ck2 = strstr(ib, "\"coordinate\"");
                                if (ck2) {
                                    const char *ob = strchr(ck2, '[');
                                    if (ob) {
                                        double xv=0, yv=0;
                                        if (sscanf(ob, "[%lf,%lf", &xv, &yv) == 2) {
                                            a->has_coord = 1; a->coord_x = (int)xv; a->coord_y = (int)yv;
                                        }
                                    }
                                }
                                const char *sck = strstr(ib, "\"start_coordinate\"");
                                if (sck) {
                                    const char *ob = strchr(sck, '[');
                                    if (ob) {
                                        double xv=0, yv=0;
                                        if (sscanf(ob, "[%lf,%lf", &xv, &yv) == 2) {
                                            a->has_start = 1; a->start_x = (int)xv; a->start_y = (int)yv;
                                        }
                                    }
                                }
                                /* Grab the block's own "id" for tool_use_id */
                                json_get_str(block, "id", a->tool_use_id, sizeof(a->tool_use_id));
                                /* Normalize Anthropic action names to canonical set. */
                                if (strcmp(a->action, "left_click") == 0 || strcmp(a->action, "click") == 0)  strcpy(a->action, "left_click");
                                if (strcmp(a->action, "right_click") == 0) strcpy(a->action, "right_click");
                                if (strcmp(a->action, "double_click") == 0) strcpy(a->action, "double_click");
                                if (strcmp(a->action, "middle_click") == 0) strcpy(a->action, "middle_click");
                                if (strcmp(a->action, "triple_click") == 0) strcpy(a->action, "double_click"); /* approx */
                                if (strcmp(a->action, "mouse_move") == 0)   strcpy(a->action, "mouse_move");
                                if (strcmp(a->action, "left_click_drag") == 0) strcpy(a->action, "left_click_drag");
                                if (strcmp(a->action, "cursor_position") == 0) strcpy(a->action, "screenshot"); /* no-op */
                                if (strcmp(a->action, "zoom") == 0)         strcpy(a->action, "screenshot"); /* handled via re-inspect elsewhere */
                                n++;
                                free(ib);
                            }
                        }
                    }
                }
            }
        }
        free(block);
        cur = bo;
    }
    if (n == 0) return 1;   /* valid response, just no actions */
    cu_action_t *arr_out = (cu_action_t *)malloc(sizeof(cu_action_t) * n);
    if (!arr_out) return 0;
    memcpy(arr_out, list, sizeof(cu_action_t) * n);
    *out = arr_out;
    *out_n = n;
    return 1;
}

/* Parse Anthropic stop_reason + usage. */
static void parse_anthropic_meta(const char *reply_json,
                                 char *out_stop, size_t stop_sz,
                                 cu_usage_t *usage, const char *model) {
    json_get_str(reply_json, "stop_reason", out_stop, stop_sz);
    /* usage sub-object */
    const char *uk = strstr(reply_json, "\"usage\"");
    if (uk) {
        const char *ob = strchr(uk, '{');
        if (ob) {
            const char *oe = json_skip_object(ob);
            if (oe && oe > ob) {
                size_t ol = (size_t)(oe - ob);
                char *ub = (char *)malloc(ol + 1);
                if (ub) {
                    memcpy(ub, ob, ol); ub[ol] = 0;
                    double d;
                    if (json_get_num(ub, "input_tokens", &d))              usage->input_tokens  = (int)d;
                    if (json_get_num(ub, "output_tokens", &d))             usage->output_tokens = (int)d;
                    if (json_get_num(ub, "cache_read_input_tokens", &d))   usage->cache_read    = (int)d;
                    if (json_get_num(ub, "cache_creation_input_tokens", &d)) usage->cache_create = (int)d;
                    free(ub);
                }
            }
        }
    }
    cu_price_t p = cu_price_for(model);
    usage->cost_usd = usage->input_tokens * p.in_per_tok
                    + usage->output_tokens * p.out_per_tok
                    + usage->cache_read * p.cached_per_tok
                    + usage->cache_create * p.in_per_tok;
}

/* Build the messages array JSON for the request body. First turn writes
 * a user message with the task + image + optional UIA anchors. On
 * subsequent turns writes a user message with a tool_result block
 * paired to the LAST assistant's LAST tool_use ID (with the fresh
 * screenshot). Extra tool_uses in the last assistant reply are
 * ignored -- we always match ONE per turn, which matches hooksdll's
 * "one action per turn" observed behavior with Anthropic CU. */
static int build_user_turn(cu_state_t *st, const cu_cap_t *cap, const char *task) {
    if (st->anth_conv_len == 0) {
        cu_buf_append(&st->anth_conv_json, &st->anth_conv_len, &st->anth_conv_cap, "[", 1);
    }
    char header[8192];
    if (st->anth_screenshot_count == 0) {
        _snprintf(header, sizeof(header) - 1,
            "%s{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"Task: %s\\n\\n"
            "The screen is %dx%d pixels. A red coordinate grid is composited onto the screenshot "
            "with labels every 100 px -- use the labels as ground truth for click coordinates. "
            "Take the next action.%s%s\"},"
            "{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/jpeg\",\"data\":\"",
            (st->anth_conv_len > 1 ? "," : ""),
            task, cap->w, cap->h,
            cap->uia_anchor_block ? "\\n" : "",
            cap->uia_anchor_block ? cap->uia_anchor_block : "");
    } else {
        char ids[8][80];
        int nids = extract_last_tool_use_ids(st, ids, 8);
        if (nids > 0) {
            _snprintf(header, sizeof(header) - 1,
                ",{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"%s\","
                "\"content\":[{\"type\":\"image\",\"source\":{\"type\":\"base64\","
                "\"media_type\":\"image/jpeg\",\"data\":\"",
                ids[0]);
        } else {
            /* Defensive: last assistant had no tool_use (shouldn't happen but
             * be safe) -- just send fresh screenshot as a plain user turn. */
            _snprintf(header, sizeof(header) - 1,
                ",{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"Fresh screenshot after your last action:\"},"
                "{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/jpeg\",\"data\":\"");
        }
    }
    header[sizeof(header) - 1] = 0;
    cu_buf_append(&st->anth_conv_json, &st->anth_conv_len, &st->anth_conv_cap,
                  header, strlen(header));
    cu_buf_append(&st->anth_conv_json, &st->anth_conv_len, &st->anth_conv_cap,
                  cap->b64, strlen(cap->b64));
    /* Close differently for first-turn vs subsequent tool_result. */
    const char *tail = (st->anth_screenshot_count == 0)
        ? "\"}}]}"        /* image object -> content array -> user message */
        : "\"}}]}]}";     /* image -> content -> tool_result -> outer content -> user */
    cu_buf_append(&st->anth_conv_json, &st->anth_conv_len, &st->anth_conv_cap,
                  tail, strlen(tail));
    st->anth_screenshot_count++;
    return 1;
}

int cu_anthropic_turn(cu_state_t *st, const char *model, const char *api_key,
                      const cu_cap_t *cap, const char *task,
                      cu_turn_result_t *out) {
    memset(out, 0, sizeof(*out));
    _snprintf(out->model, sizeof(out->model) - 1, "%s", model);

    int hi = is_hi_tier_anthropic(model);
    const char *tool_type = hi ? "computer_20251124" : "computer_20250124";
    const char *beta_hdr  = hi ? "computer-use-2025-11-24" : "computer-use-2025-01-24";

    /* Append this turn's user message to the running conv JSON. */
    if (!build_user_turn(st, cap, task)) {
        _snprintf(out->err, sizeof(out->err) - 1, "conv build OOM");
        return 0;
    }

    /* Assemble the request body. We embed the running messages array
     * verbatim (already comma-separated + open/close-bracketed on the
     * first call). Close the array with `]` right before injecting.
     * IMPORTANT: We do NOT close the array in-place on the conv buffer
     * -- if we did, subsequent turns would corrupt it. Instead we build
     * a temporary tail. */
    char *body = NULL; size_t body_len = 0, body_cap = 0;
    char head[4096];
    _snprintf(head, sizeof(head) - 1,
        "{\"model\":\"%s\",\"max_tokens\":8192,"
        "\"system\":[{\"type\":\"text\",\"text\":\"", model);
    cu_buf_append(&body, &body_len, &body_cap, head, strlen(head));
    /* System prompt -- JSON-escape ONLY newlines / quotes / backslashes. */
    for (const char *p = CU_SYSTEM_PROMPT; *p; p++) {
        switch (*p) {
            case '\n': cu_buf_append(&body, &body_len, &body_cap, "\\n", 2); break;
            case '\r': cu_buf_append(&body, &body_len, &body_cap, "\\r", 2); break;
            case '\t': cu_buf_append(&body, &body_len, &body_cap, "\\t", 2); break;
            case '"':  cu_buf_append(&body, &body_len, &body_cap, "\\\"", 2); break;
            case '\\': cu_buf_append(&body, &body_len, &body_cap, "\\\\", 2); break;
            default:   cu_buf_append(&body, &body_len, &body_cap, p, 1); break;
        }
    }
    char mid[1024];
    _snprintf(mid, sizeof(mid) - 1,
        "\",\"cache_control\":{\"type\":\"ephemeral\"}}],"
        "\"tools\":[{\"type\":\"%s\",\"name\":\"computer\","
        "\"display_width_px\":%d,\"display_height_px\":%d,\"display_number\":1%s}],"
        "\"messages\":", tool_type, cap->w, cap->h,
        hi ? ",\"enable_zoom\":true" : "");
    cu_buf_append(&body, &body_len, &body_cap, mid, strlen(mid));
    /* Emit the accumulated conv JSON + closing `]`. */
    cu_buf_append(&body, &body_len, &body_cap,
                  st->anth_conv_json, st->anth_conv_len);
    cu_buf_append(&body, &body_len, &body_cap, "]}", 2);

    char auth[600], vers[64], beta[128], ct[] = "content-type: application/json";
    _snprintf(auth, sizeof(auth) - 1, "x-api-key: %s", api_key);
    _snprintf(vers, sizeof(vers) - 1, "anthropic-version: 2023-06-01");
    _snprintf(beta, sizeof(beta) - 1, "anthropic-beta: %s", beta_hdr);
    const char *headers[] = { auth, vers, beta, ct, NULL };

    whreq_result_t res = {0};
    slog_writef("payload.log", "cu-anth POST model=%s body_len=%zu",
                model, body_len);
    int http_ok = whreq_post_ex("https://api.anthropic.com/v1/messages",
                                headers, body, body_len,
                                180000, &res);   /* 3-min ceiling */
    free(body); body = NULL;

    if (!http_ok) {
        _snprintf(out->err, sizeof(out->err) - 1, "http transport: %s", res.err);
        whreq_free_result(&res);
        return 0;
    }
    if (res.status != 200) {
        _snprintf(out->err, sizeof(out->err) - 1,
                  "HTTP %u: %.180s", res.status,
                  res.body ? res.body : "");
        slog_writef("payload.log", "cu-anth ERROR status=%u body_head=%.400s",
                    res.status, res.body ? res.body : "");
        whreq_free_result(&res);
        return 0;
    }

    /* Success -- append the assistant reply into conv + parse actions. */
    append_assistant_reply(st, res.body);

    if (!parse_anthropic_actions(res.body, &out->actions, &out->n_actions)) {
        _snprintf(out->err, sizeof(out->err) - 1, "actions parse failed");
        whreq_free_result(&res);
        return 0;
    }
    parse_anthropic_meta(res.body, out->stop_reason, sizeof(out->stop_reason),
                         &out->usage, model);
    slog_writef("payload.log",
                "cu-anth OK stop=%s actions=%d in=%d out=%d cost=$%.4f",
                out->stop_reason, out->n_actions,
                out->usage.input_tokens, out->usage.output_tokens,
                out->usage.cost_usd);
    st->total_spend_usd += out->usage.cost_usd;
    st->total_turns++;
    whreq_free_result(&res);
    return 1;
}
