/* ================================================================== *
 * cu_openai.c -- OpenAI computer-use tool adapter.
 *
 * 1:1 port of hooksdll's openaiTurn(). Uses the Responses API with a
 * {type:"computer"} tool. Conversation is SERVER-side via
 * previous_response_id, so we only cache the last response_id +
 * computer_call callId across turns (much simpler than Anthropic).
 *
 * gpt-5.6 returns computer_call items with an `actions` ARRAY (plural)
 * -- verified live against the SDK. Older SKUs return `action` (singular
 * object). We accept both.
 * ================================================================== */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cu_common.h"
#include "../../../shared/winhttp_util.h"
#include "../../../shared/json_util.h"

extern void slog_writef(const char *file, const char *fmt, ...);

/* Canonicalize one OpenAI computer_call action per _canonOpenAIAction. */
static int canon_openai_action(const char *action_json, cu_action_t *out) {
    memset(out, 0, sizeof(*out));
    char t[32] = {0};
    json_get_str(action_json, "type", t, sizeof(t));
    if (!t[0]) return 0;
    double dx = 0, dy = 0;
    int hxy = json_get_num(action_json, "x", &dx) && json_get_num(action_json, "y", &dy);

    if (strcmp(t, "click") == 0) {
        char btn[16] = {0}; json_get_str(action_json, "button", btn, sizeof(btn));
        if      (!strcmp(btn, "right")) strcpy(out->action, "right_click");
        else if (!strcmp(btn, "wheel") || !strcmp(btn, "middle")) strcpy(out->action, "middle_click");
        else strcpy(out->action, "left_click");
        if (hxy) { out->has_coord = 1; out->coord_x = (int)dx; out->coord_y = (int)dy; }
        /* held modifiers via keys[] -- join into `text` if present */
        const char *k = strstr(action_json, "\"keys\"");
        if (k) {
            const char *lb = strchr(k, '[');
            const char *re = lb ? json_skip_array(lb) : NULL;
            if (lb && re && re > lb + 1) {
                size_t l = (size_t)(re - lb - 2);
                if (l < sizeof(out->text) - 1) {
                    for (const char *p = lb + 1; p < re - 1 && strlen(out->text) < sizeof(out->text) - 4; p++) {
                        if (*p == '"' || *p == ' ' || *p == '\n' || *p == '\t') continue;
                        if (*p == ',') { strcat(out->text, "+"); continue; }
                        char one[2] = { *p, 0 };
                        strcat(out->text, one);
                    }
                }
            }
        }
        return 1;
    }
    if (strcmp(t, "double_click") == 0) {
        strcpy(out->action, "double_click");
        if (hxy) { out->has_coord = 1; out->coord_x = (int)dx; out->coord_y = (int)dy; }
        return 1;
    }
    if (strcmp(t, "move") == 0) {
        strcpy(out->action, "mouse_move");
        if (hxy) { out->has_coord = 1; out->coord_x = (int)dx; out->coord_y = (int)dy; }
        return 1;
    }
    if (strcmp(t, "type") == 0) {
        strcpy(out->action, "type");
        json_get_str(action_json, "text", out->text, sizeof(out->text));
        return 1;
    }
    if (strcmp(t, "keypress") == 0) {
        strcpy(out->action, "key");
        /* keys[] -> "ctrl+a" style */
        const char *k = strstr(action_json, "\"keys\"");
        if (k) {
            const char *lb = strchr(k, '[');
            const char *re = lb ? json_skip_array(lb) : NULL;
            if (lb && re) {
                for (const char *p = lb + 1; p < re - 1 && strlen(out->text) < sizeof(out->text) - 4; p++) {
                    if (*p == '"' || *p == ' ' || *p == '\n' || *p == '\t') continue;
                    if (*p == ',') { strcat(out->text, "+"); continue; }
                    char one[2] = { *p, 0 };
                    strcat(out->text, one);
                }
            }
        }
        return 1;
    }
    if (strcmp(t, "scroll") == 0) {
        strcpy(out->action, "scroll");
        if (hxy) { out->has_coord = 1; out->coord_x = (int)dx; out->coord_y = (int)dy; }
        double sx = 0, sy = 0;
        json_get_num(action_json, "scroll_x", &sx);
        json_get_num(action_json, "scroll_y", &sy);
        double asx = sx < 0 ? -sx : sx, asy = sy < 0 ? -sy : sy;
        if (asy >= asx) {
            strcpy(out->scroll_dir, sy >= 0 ? "down" : "up");
            int mag = (int)(asy / 100); if (mag < 1) mag = 3; if (mag > 20) mag = 20;
            out->scroll_amount = mag;
        } else {
            strcpy(out->scroll_dir, sx >= 0 ? "right" : "left");
            int mag = (int)(asx / 100); if (mag < 1) mag = 3; if (mag > 20) mag = 20;
            out->scroll_amount = mag;
        }
        return 1;
    }
    if (strcmp(t, "drag") == 0) {
        /* path:[{x,y},...] -- use first and last points */
        const char *pk = strstr(action_json, "\"path\"");
        if (pk) {
            const char *lb = strchr(pk, '[');
            if (lb) {
                double x1 = 0, y1 = 0, x2 = 0, y2 = 0;
                const char *ob = strchr(lb, '{');
                if (ob) sscanf(ob, "{\"x\":%lf,\"y\":%lf", &x1, &y1);
                /* find last object */
                const char *last_ob = NULL, *p = lb;
                while ((p = strchr(p + 1, '{')) != NULL) last_ob = p;
                if (last_ob) sscanf(last_ob, "{\"x\":%lf,\"y\":%lf", &x2, &y2);
                strcpy(out->action, "left_click_drag");
                out->has_start = 1; out->start_x = (int)x1; out->start_y = (int)y1;
                out->has_coord = 1; out->coord_x = (int)x2; out->coord_y = (int)y2;
                return 1;
            }
        }
        return 0;
    }
    if (strcmp(t, "wait") == 0) {
        strcpy(out->action, "wait");
        double ms = 0; json_get_num(action_json, "ms", &ms);
        out->duration_ms = ms > 0 ? (int)ms : 1000;
        return 1;
    }
    if (strcmp(t, "screenshot") == 0) {
        strcpy(out->action, "screenshot");
        return 1;
    }
    return 0;
}

/* Walk `output` array: extract computer_call items + their inner actions[]. */
static int parse_openai_actions(const char *reply,
                                cu_action_t **out, int *out_n,
                                char *out_call_id, size_t call_id_sz,
                                int *out_raw_fc_count) {
    *out = NULL; *out_n = 0; if (out_call_id) out_call_id[0] = 0;
    if (out_raw_fc_count) *out_raw_fc_count = 0;
    const char *ok = strstr(reply, "\"output\"");
    if (!ok) return 0;
    const char *arr = strchr(ok, '[');
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

        char btype[32] = {0};
        json_get_str(block, "type", btype, sizeof(btype));
        if (strcmp(btype, "computer_call") == 0) {
            if (out_call_id) json_get_str(block, "call_id", out_call_id, (int)call_id_sz);
            /* Two shapes: gpt-5.6 uses `actions` array; older uses `action` object. */
            const char *ak = strstr(block, "\"actions\"");
            if (ak) {
                const char *lb = strchr(ak, '[');
                const char *le = lb ? json_skip_array(lb) : NULL;
                if (lb && le) {
                    const char *ap = lb + 1;
                    while (ap < le && n < 32) {
                        while (ap < le && (*ap == ' ' || *ap == '\n' || *ap == ',' || *ap == '\r' || *ap == '\t')) ap++;
                        if (*ap != '{') break;
                        const char *ae = json_skip_object(ap);
                        if (!ae) break;
                        size_t alen = (size_t)(ae - ap);
                        char *ab = (char *)malloc(alen + 1);
                        if (ab) {
                            memcpy(ab, ap, alen); ab[alen] = 0;
                            if (out_raw_fc_count) (*out_raw_fc_count)++;
                            if (canon_openai_action(ab, &list[n])) n++;
                            free(ab);
                        }
                        ap = ae;
                    }
                }
            } else {
                const char *sk = strstr(block, "\"action\"");
                if (sk) {
                    const char *ob = strchr(sk, '{');
                    const char *oe = ob ? json_skip_object(ob) : NULL;
                    if (ob && oe) {
                        size_t alen = (size_t)(oe - ob);
                        char *ab = (char *)malloc(alen + 1);
                        if (ab) {
                            memcpy(ab, ob, alen); ab[alen] = 0;
                            if (out_raw_fc_count) (*out_raw_fc_count)++;
                            if (canon_openai_action(ab, &list[n])) n++;
                            free(ab);
                        }
                    }
                }
            }
        }
        free(block);
        cur = bo;
    }
    if (n > 0) {
        cu_action_t *arr_out = (cu_action_t *)malloc(sizeof(cu_action_t) * n);
        if (!arr_out) return 0;
        memcpy(arr_out, list, sizeof(cu_action_t) * n);
        *out = arr_out;
        *out_n = n;
    }
    return 1;
}

int cu_openai_turn(cu_state_t *st, const char *model, const char *api_key,
                   const cu_cap_t *cap, const char *task,
                   cu_turn_result_t *out) {
    memset(out, 0, sizeof(*out));
    _snprintf(out->model, sizeof(out->model) - 1, "%s", model);

    /* Build request body. Two paths: no prev_id -> initial input;
     * have prev_id -> input is a computer_call_output with fresh screenshot. */
    char *body = NULL; size_t body_len = 0, body_cap = 0;
    char head[2048];
    _snprintf(head, sizeof(head) - 1,
        "{\"model\":\"%s\",\"instructions\":\"", model);
    cu_buf_append(&body, &body_len, &body_cap, head, strlen(head));
    /* System prompt (JSON-escaped) */
    for (const char *p = CU_SYSTEM_PROMPT; *p; p++) {
        switch (*p) {
            case '\n': cu_buf_append(&body, &body_len, &body_cap, "\\n", 2); break;
            case '\r': cu_buf_append(&body, &body_len, &body_cap, "\\r", 2); break;
            case '"':  cu_buf_append(&body, &body_len, &body_cap, "\\\"", 2); break;
            case '\\': cu_buf_append(&body, &body_len, &body_cap, "\\\\", 2); break;
            default:   cu_buf_append(&body, &body_len, &body_cap, p, 1); break;
        }
    }
    cu_buf_append(&body, &body_len, &body_cap,
                  "\",\"tools\":[{\"type\":\"computer\"}],\"max_output_tokens\":8192,\"input\":", 62);

    if (!st->openai_prev_response_id[0]) {
        /* Initial input: user message with text + image */
        char input_head[4096];
        _snprintf(input_head, sizeof(input_head) - 1,
            "[{\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"Task: %s\\n\\n"
            "The screen is %dx%d pixels. A red coordinate grid is composited onto the screenshot "
            "with labels every 100 px -- use the labels as ground truth for click coordinates. "
            "Take the next action.%s%s\"},"
            "{\"type\":\"input_image\",\"detail\":\"original\",\"image_url\":\"data:image/jpeg;base64,",
            task, cap->w, cap->h,
            cap->uia_anchor_block ? "\\n" : "",
            cap->uia_anchor_block ? cap->uia_anchor_block : "");
        cu_buf_append(&body, &body_len, &body_cap, input_head, strlen(input_head));
        cu_buf_append(&body, &body_len, &body_cap, cap->b64, strlen(cap->b64));
        cu_buf_append(&body, &body_len, &body_cap, "\"}]}]}", 6);
    } else {
        /* Subsequent turn: computer_call_output with fresh screenshot. */
        char input_head[512];
        _snprintf(input_head, sizeof(input_head) - 1,
            "[{\"type\":\"computer_call_output\",\"call_id\":\"%s\","
            "\"output\":{\"type\":\"computer_screenshot\","
            "\"detail\":\"original\","
            "\"image_url\":\"data:image/jpeg;base64,",
            st->openai_call_id[0] ? st->openai_call_id : "call_prev");
        cu_buf_append(&body, &body_len, &body_cap, input_head, strlen(input_head));
        cu_buf_append(&body, &body_len, &body_cap, cap->b64, strlen(cap->b64));
        char tail[256];
        _snprintf(tail, sizeof(tail) - 1,
            "\"}}],\"previous_response_id\":\"%s\"}",
            st->openai_prev_response_id);
        cu_buf_append(&body, &body_len, &body_cap, tail, strlen(tail));
    }

    char auth[600], ct[] = "content-type: application/json";
    _snprintf(auth, sizeof(auth) - 1, "authorization: Bearer %s", api_key);
    const char *headers[] = { auth, ct, NULL };

    whreq_result_t res = {0};
    slog_writef("payload.log", "cu-openai POST model=%s body_len=%zu prev_id=%s",
                model, body_len,
                st->openai_prev_response_id[0] ? st->openai_prev_response_id : "none");
    int http_ok = whreq_post_ex("https://api.openai.com/v1/responses",
                                headers, body, body_len,
                                180000, &res);
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
        slog_writef("payload.log", "cu-openai ERROR status=%u body_head=%.400s",
                    res.status, res.body ? res.body : "");
        whreq_free_result(&res);
        return 0;
    }

    /* Extract new response id */
    json_get_str(res.body, "id", st->openai_prev_response_id,
                 sizeof(st->openai_prev_response_id));

    int raw_fc = 0;
    parse_openai_actions(res.body, &out->actions, &out->n_actions,
                         st->openai_call_id, sizeof(st->openai_call_id),
                         &raw_fc);
    /* If model emitted function calls but none mapped, force loop-continue. */
    if (raw_fc > 0 && out->n_actions == 0) {
        strcpy(out->stop_reason, "tool_use");
    } else if (out->n_actions > 0) {
        strcpy(out->stop_reason, "tool_use");
    } else {
        strcpy(out->stop_reason, "end_turn");
    }

    /* Usage / cost */
    const char *uk = strstr(res.body, "\"usage\"");
    if (uk) {
        const char *ob = strchr(uk, '{');
        const char *oe = ob ? json_skip_object(ob) : NULL;
        if (ob && oe) {
            size_t ol = (size_t)(oe - ob);
            char *ub = (char *)malloc(ol + 1);
            if (ub) {
                memcpy(ub, ob, ol); ub[ol] = 0;
                double d;
                if (json_get_num(ub, "input_tokens", &d))  out->usage.input_tokens  = (int)d;
                if (json_get_num(ub, "output_tokens", &d)) out->usage.output_tokens = (int)d;
                free(ub);
            }
        }
    }
    cu_price_t p = cu_price_for(model);
    out->usage.cost_usd = out->usage.input_tokens * p.in_per_tok
                        + out->usage.output_tokens * p.out_per_tok;
    slog_writef("payload.log",
                "cu-openai OK stop=%s actions=%d raw_fc=%d in=%d out=%d cost=$%.4f",
                out->stop_reason, out->n_actions, raw_fc,
                out->usage.input_tokens, out->usage.output_tokens,
                out->usage.cost_usd);
    st->total_spend_usd += out->usage.cost_usd;
    st->total_turns++;
    whreq_free_result(&res);
    return 1;
}
