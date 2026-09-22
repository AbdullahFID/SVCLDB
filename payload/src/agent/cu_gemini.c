/* ================================================================== *
 * cu_gemini.c -- Google Gemini computer-use adapter.
 *
 * Uses gemini-2.5-computer-use-preview-10-2025 or gemini-3.5-flash.
 * 1:1 port of hooksdll's geminiTurn(). Coordinates come normalized
 * 0..1000 -- we scale to cap.w / cap.h on the way to canonical.
 * Contents (message history) is client-side, accumulated as a JSON
 * fragment across turns.
 *
 * Function calls: Gemini's CU emits INDIVIDUAL NAMED calls (click_at,
 * type_text_at, scroll_at, drag_and_drop, key_combination, ...). We
 * canonicalize per-name via _canonGeminiFunctionCall (see the giant
 * if-tree at the bottom).
 *
 * Anti-nav preamble on turn 1: without it Gemini calls
 * `open_web_browser` on the first turn. We ALSO exclude browser-control
 * functions server-side via `excluded_predefined_functions`.
 * ================================================================== */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cu_common.h"
#include "../../../shared/winhttp_util.h"
#include "../../../shared/json_util.h"

extern void slog_writef(const char *file, const char *fmt, ...);

/* Canonicalize one Gemini functionCall into 1 (or 2) canonical actions.
 * Returns count added (0/1/2). Coordinates scaled from 0..1000 -> cap. */
static int canon_gemini_fc(const char *name, const char *args_json,
                           const cu_cap_t *cap,
                           cu_action_t *out, int cap_slots) {
    if (!name || !args_json || cap_slots < 1) return 0;
    double dx = 0, dy = 0;
    int has_x = json_get_num(args_json, "x", &dx);
    int has_y = json_get_num(args_json, "y", &dy);
    double sx = cap->w / 1000.0, sy = cap->h / 1000.0;
    int px = has_x ? (int)(dx * sx + 0.5) : 0;
    int py = has_y ? (int)(dy * sy + 0.5) : 0;

    /* Lowercase for case-insensitive match. */
    char nm[64] = {0};
    for (int i = 0; i < (int)sizeof(nm) - 1 && name[i]; i++)
        nm[i] = (name[i] >= 'A' && name[i] <= 'Z') ? (char)(name[i] + 32) : name[i];

    memset(out, 0, sizeof(*out));

    /* Click family */
    if (!strcmp(nm, "click_at") || !strcmp(nm, "left_click") ||
        !strcmp(nm, "click")    || !strcmp(nm, "tap_at") || !strcmp(nm, "tap")) {
        strcpy(out->action, "left_click");
        out->has_coord = 1; out->coord_x = px; out->coord_y = py;
        return 1;
    }
    if (!strcmp(nm, "right_click_at") || !strcmp(nm, "right_click")) {
        strcpy(out->action, "right_click");
        out->has_coord = 1; out->coord_x = px; out->coord_y = py;
        return 1;
    }
    if (!strcmp(nm, "double_click_at") || !strcmp(nm, "double_click")) {
        strcpy(out->action, "double_click");
        out->has_coord = 1; out->coord_x = px; out->coord_y = py;
        return 1;
    }
    if (!strcmp(nm, "move_cursor_to") || !strcmp(nm, "move_cursor") ||
        !strcmp(nm, "mouse_move")     || !strcmp(nm, "hover") ||
        !strcmp(nm, "move")) {
        strcpy(out->action, "mouse_move");
        out->has_coord = 1; out->coord_x = px; out->coord_y = py;
        return 1;
    }
    /* Type text -- optionally preceded by a click. */
    if (!strcmp(nm, "type_text_at") || !strcmp(nm, "type_text") || !strcmp(nm, "type")) {
        char txt[1024] = {0};
        if (!json_get_str(args_json, "text", txt, sizeof(txt))) {
            if (!json_get_str(args_json, "value", txt, sizeof(txt)))
                json_get_str(args_json, "input", txt, sizeof(txt));
        }
        int n = 0;
        if (has_x && has_y && cap_slots >= 2) {
            strcpy(out[0].action, "left_click");
            out[0].has_coord = 1; out[0].coord_x = px; out[0].coord_y = py;
            n = 1;
            memset(&out[1], 0, sizeof(out[1]));
            strcpy(out[1].action, "type");
            _snprintf(out[1].text, sizeof(out[1].text) - 1, "%s", txt);
            n = 2;
        } else {
            strcpy(out->action, "type");
            _snprintf(out->text, sizeof(out->text) - 1, "%s", txt);
            n = 1;
        }
        return n;
    }
    /* Keys / hotkeys */
    if (!strcmp(nm, "key_combination") || !strcmp(nm, "key") || !strcmp(nm, "press_key") ||
        !strcmp(nm, "hotkey") || !strcmp(nm, "key_press")) {
        strcpy(out->action, "key");
        char t[128] = {0};
        if (!json_get_str(args_json, "keys", t, sizeof(t))) {
            if (!json_get_str(args_json, "text", t, sizeof(t)))
                if (!json_get_str(args_json, "key", t, sizeof(t))) {
                    /* combination[] array */
                    const char *ck = strstr(args_json, "\"combination\"");
                    if (ck) {
                        const char *lb = strchr(ck, '[');
                        const char *re = lb ? json_skip_array(lb) : NULL;
                        if (lb && re) {
                            for (const char *p = lb + 1; p < re - 1 && strlen(t) < sizeof(t) - 4; p++) {
                                if (*p == '"' || *p == ' ' || *p == '\n' || *p == '\t') continue;
                                if (*p == ',') { strcat(t, "+"); continue; }
                                char one[2] = { *p, 0 };
                                strcat(t, one);
                            }
                        }
                    }
                }
        }
        _snprintf(out->text, sizeof(out->text) - 1, "%s", t);
        return 1;
    }
    /* Scroll */
    if (!strcmp(nm, "scroll_at") || !strcmp(nm, "scroll_document") || !strcmp(nm, "scroll")) {
        strcpy(out->action, "scroll");
        out->has_coord = 1;
        out->coord_x = has_x ? px : (cap->w / 2);
        out->coord_y = has_y ? py : (cap->h / 2);
        char dir[16] = {0}; json_get_str(args_json, "direction", dir, sizeof(dir));
        for (int i = 0; dir[i]; i++) if (dir[i] >= 'A' && dir[i] <= 'Z') dir[i] += 32;
        _snprintf(out->scroll_dir, sizeof(out->scroll_dir) - 1, "%s", dir[0] ? dir : "down");
        double m = 0;
        if (!json_get_num(args_json, "magnitude", &m))
            json_get_num(args_json, "amount", &m);
        int mag = (int)m; if (mag < 1) mag = 3; if (mag > 20) mag = 20;
        out->scroll_amount = mag;
        return 1;
    }
    /* Drag */
    if (!strcmp(nm, "drag_and_drop") || !strcmp(nm, "drag") || !strcmp(nm, "drag_and_drop_at")) {
        double x1 = 0, y1 = 0, x2 = 0, y2 = 0;
        if (!json_get_num(args_json, "x1", &x1)) if (!json_get_num(args_json, "start_x", &x1)) json_get_num(args_json, "from_x", &x1);
        if (!json_get_num(args_json, "y1", &y1)) if (!json_get_num(args_json, "start_y", &y1)) json_get_num(args_json, "from_y", &y1);
        if (!json_get_num(args_json, "x2", &x2)) if (!json_get_num(args_json, "end_x", &x2)) json_get_num(args_json, "to_x", &x2);
        if (!json_get_num(args_json, "y2", &y2)) if (!json_get_num(args_json, "end_y", &y2)) json_get_num(args_json, "to_y", &y2);
        strcpy(out->action, "left_click_drag");
        out->has_start = 1; out->start_x = (int)(x1 * sx + 0.5); out->start_y = (int)(y1 * sy + 0.5);
        out->has_coord = 1; out->coord_x = (int)(x2 * sx + 0.5); out->coord_y = (int)(y2 * sy + 0.5);
        return 1;
    }
    /* Wait */
    if (!strcmp(nm, "wait") || !strcmp(nm, "wait_for") || !strcmp(nm, "sleep")) {
        strcpy(out->action, "wait");
        double d = 0;
        if (!json_get_num(args_json, "duration", &d))
            if (!json_get_num(args_json, "seconds", &d)) {
                double ms = 0; json_get_num(args_json, "ms", &ms); d = ms / 1000.0;
            }
        if (d <= 0) d = 1;
        out->duration_ms = (int)(d * 1000);
        return 1;
    }
    /* Screenshot / browser-control (no-ops so loop continues) */
    if (!strcmp(nm, "take_screenshot") || !strcmp(nm, "screenshot") ||
        !strcmp(nm, "open_web_browser") || !strcmp(nm, "navigate") ||
        !strcmp(nm, "go_back") || !strcmp(nm, "go_forward") ||
        !strcmp(nm, "search_google") || !strcmp(nm, "search") ||
        !strcmp(nm, "open_url") || !strcmp(nm, "goto")) {
        strcpy(out->action, "screenshot");
        return 1;
    }
    return 0;   /* unknown -- caller counts + logs */
}

int cu_gemini_turn(cu_state_t *st, const char *model, const char *api_key,
                   const cu_cap_t *cap, const char *task,
                   cu_turn_result_t *out) {
    memset(out, 0, sizeof(*out));
    _snprintf(out->model, sizeof(out->model) - 1, "%s", model);

    /* Append this turn's user parts into the running contents JSON. */
    if (st->gem_conv_len == 0) {
        cu_buf_append(&st->gem_conv_json, &st->gem_conv_len, &st->gem_conv_cap, "[", 1);
    }
    char head[8192];
    if (st->total_turns == 0) {
        _snprintf(head, sizeof(head) - 1,
            "%s{\"role\":\"user\",\"parts\":[{\"text\":\"Task: %s\\n\\n"
            "CRITICAL CONTEXT: The target application is ALREADY OPEN and visible in the screenshot below. "
            "You are NOT starting from a blank browser or home screen. Do NOT call open_web_browser, navigate, "
            "go_back, go_forward, search_google, or any browser-control function -- the page is already loaded. "
            "Your ONLY job is to interact with the visible UI elements (click buttons, type in fields, scroll) to complete the task.\\n\\n"
            "The screen is %dx%d pixels. A red coordinate grid is composited onto the screenshot with labels every 100 px -- "
            "use the labels as ground truth for click coordinates. Every click must land on a visible UI element (button, radio circle, "
            "checkbox, input, link), NEVER on blank whitespace.%s%s\"},"
            "{\"inlineData\":{\"mimeType\":\"image/jpeg\",\"data\":\"",
            (st->gem_conv_len > 1 ? "," : ""),
            task, cap->w, cap->h,
            cap->uia_anchor_block ? "\\n" : "",
            cap->uia_anchor_block ? cap->uia_anchor_block : "");
    } else {
        _snprintf(head, sizeof(head) - 1,
            ",{\"role\":\"user\",\"parts\":[{\"text\":\"Fresh screenshot after your last action:\"},"
            "{\"inlineData\":{\"mimeType\":\"image/jpeg\",\"data\":\"");
    }
    head[sizeof(head) - 1] = 0;
    cu_buf_append(&st->gem_conv_json, &st->gem_conv_len, &st->gem_conv_cap, head, strlen(head));
    cu_buf_append(&st->gem_conv_json, &st->gem_conv_len, &st->gem_conv_cap,
                  cap->b64, strlen(cap->b64));
    cu_buf_append(&st->gem_conv_json, &st->gem_conv_len, &st->gem_conv_cap,
                  "\"}}]}", 5);

    /* Full request body */
    char *body = NULL; size_t body_len = 0, body_cap = 0;
    cu_buf_append(&body, &body_len, &body_cap,
        "{\"systemInstruction\":{\"parts\":[{\"text\":\"", 40);
    for (const char *p = CU_SYSTEM_PROMPT; *p; p++) {
        switch (*p) {
            case '\n': cu_buf_append(&body, &body_len, &body_cap, "\\n", 2); break;
            case '\r': cu_buf_append(&body, &body_len, &body_cap, "\\r", 2); break;
            case '"':  cu_buf_append(&body, &body_len, &body_cap, "\\\"", 2); break;
            case '\\': cu_buf_append(&body, &body_len, &body_cap, "\\\\", 2); break;
            default:   cu_buf_append(&body, &body_len, &body_cap, p, 1); break;
        }
    }
    cu_buf_append(&body, &body_len, &body_cap, "\"}]},\"contents\":", 16);
    cu_buf_append(&body, &body_len, &body_cap, st->gem_conv_json, st->gem_conv_len);
    cu_buf_append(&body, &body_len, &body_cap, "],", 2);
    cu_buf_append(&body, &body_len, &body_cap,
        "\"tools\":[{\"computer_use\":{\"environment\":\"ENVIRONMENT_BROWSER\","
        "\"excluded_predefined_functions\":[\"open_web_browser\",\"navigate\",\"go_back\",\"go_forward\"]}}],"
        "\"generationConfig\":{\"temperature\":0.4,\"maxOutputTokens\":4096}}", 236);

    char url[512], apikey[600], ct[] = "content-type: application/json";
    _snprintf(url, sizeof(url) - 1,
              "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent",
              model);
    _snprintf(apikey, sizeof(apikey) - 1, "x-goog-api-key: %s", api_key);
    const char *headers[] = { apikey, ct, NULL };

    whreq_result_t res = {0};
    slog_writef("payload.log", "cu-gem POST model=%s body_len=%zu",
                model, body_len);
    int http_ok = whreq_post_ex(url, headers, body, body_len, 180000, &res);
    free(body); body = NULL;

    if (!http_ok) {
        _snprintf(out->err, sizeof(out->err) - 1, "http transport: %s", res.err);
        whreq_free_result(&res);
        return 0;
    }
    if (res.status != 200) {
        _snprintf(out->err, sizeof(out->err) - 1,
                  "HTTP %u: %.180s", res.status, res.body ? res.body : "");
        slog_writef("payload.log", "cu-gem ERROR status=%u body_head=%.400s",
                    res.status, res.body ? res.body : "");
        whreq_free_result(&res);
        return 0;
    }

    /* Parse candidates[0].content.parts[]. Look for functionCall entries.
     * Append the model's response to contents JSON so next turn has history. */
    cu_action_t list[32]; int n = 0; int raw_fc = 0;
    const char *ck = strstr(res.body, "\"candidates\"");
    if (ck) {
        const char *arr = strchr(ck, '[');
        const char *ae = arr ? json_skip_array(arr) : NULL;
        if (arr && ae) {
            const char *pk = strstr(arr, "\"parts\"");
            if (pk && pk < ae) {
                const char *pb = strchr(pk, '[');
                const char *pe = pb ? json_skip_array(pb) : NULL;
                if (pb && pe) {
                    /* Append `{"role":"model","parts":<parts_array>}` to conv. */
                    size_t plen = (size_t)(pe - pb);
                    char *frag = (char *)malloc(plen + 64);
                    if (frag) {
                        int fl = _snprintf(frag, plen + 64 - 1,
                                           ",{\"role\":\"model\",\"parts\":%.*s}",
                                           (int)plen, pb);
                        if (fl > 0) {
                            cu_buf_append(&st->gem_conv_json, &st->gem_conv_len, &st->gem_conv_cap,
                                          frag, (size_t)fl);
                        }
                        free(frag);
                    }
                    /* Iterate parts for functionCall entries */
                    const char *cur = pb + 1;
                    while (cur < pe && n < 32) {
                        while (cur < pe && (*cur == ' ' || *cur == '\n' || *cur == ',' || *cur == '\t' || *cur == '\r')) cur++;
                        if (*cur != '{') break;
                        const char *ob = json_skip_object(cur);
                        if (!ob) break;
                        size_t blen = (size_t)(ob - cur);
                        char *blk = (char *)malloc(blen + 1);
                        if (blk) {
                            memcpy(blk, cur, blen); blk[blen] = 0;
                            const char *fk = strstr(blk, "\"functionCall\"");
                            if (fk) {
                                char fname[64] = {0};
                                json_get_str(blk, "name", fname, sizeof(fname));
                                const char *ak = strstr(blk, "\"args\"");
                                char *args = NULL;
                                if (ak) {
                                    const char *asob = strchr(ak, '{');
                                    const char *asoe = asob ? json_skip_object(asob) : NULL;
                                    if (asob && asoe) {
                                        size_t alen = (size_t)(asoe - asob);
                                        args = (char *)malloc(alen + 1);
                                        if (args) { memcpy(args, asob, alen); args[alen] = 0; }
                                    }
                                }
                                if (fname[0] && args) {
                                    raw_fc++;
                                    int added = canon_gemini_fc(fname, args, cap,
                                                                &list[n], 32 - n);
                                    n += added;
                                    slog_writef("payload.log",
                                                "cu-gem fc name=%s added=%d",
                                                fname, added);
                                }
                                if (args) free(args);
                            }
                            free(blk);
                        }
                        cur = ob;
                    }
                }
            }
        }
    }
    if (n > 0) {
        cu_action_t *arr_out = (cu_action_t *)malloc(sizeof(cu_action_t) * n);
        if (arr_out) {
            memcpy(arr_out, list, sizeof(cu_action_t) * n);
            out->actions = arr_out;
            out->n_actions = n;
        }
    }
    /* Same defense as hooksdll: if model emitted calls but none mapped,
     * force stop=tool_use so loop keeps going. */
    if (raw_fc > 0 && n == 0) strcpy(out->stop_reason, "tool_use");
    else if (n > 0)           strcpy(out->stop_reason, "tool_use");
    else                      strcpy(out->stop_reason, "end_turn");

    /* Usage */
    const char *um = strstr(res.body, "\"usageMetadata\"");
    if (um) {
        const char *ob = strchr(um, '{');
        const char *oe = ob ? json_skip_object(ob) : NULL;
        if (ob && oe) {
            size_t ol = (size_t)(oe - ob);
            char *ub = (char *)malloc(ol + 1);
            if (ub) {
                memcpy(ub, ob, ol); ub[ol] = 0;
                double d;
                if (json_get_num(ub, "promptTokenCount", &d))     out->usage.input_tokens  = (int)d;
                if (json_get_num(ub, "candidatesTokenCount", &d)) out->usage.output_tokens = (int)d;
                free(ub);
            }
        }
    }
    cu_price_t p = cu_price_for(model);
    out->usage.cost_usd = out->usage.input_tokens * p.in_per_tok
                        + out->usage.output_tokens * p.out_per_tok;
    slog_writef("payload.log",
                "cu-gem OK stop=%s actions=%d raw_fc=%d in=%d out=%d cost=$%.4f",
                out->stop_reason, out->n_actions, raw_fc,
                out->usage.input_tokens, out->usage.output_tokens,
                out->usage.cost_usd);
    st->total_spend_usd += out->usage.cost_usd;
    st->total_turns++;
    whreq_free_result(&res);
    return 1;
}
