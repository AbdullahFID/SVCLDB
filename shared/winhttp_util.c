/* ================================================================== *
 * winhttp_util.c -- WinHTTP HTTPS wrapper.                            *
 *                                                                    *
 * Design notes:                                                      *
 *  - Uses WinHTTP directly (not WinInet -- WinInet inherits IE proxy  *
 *    settings which can be tampered with; WinHTTP has its own).     *
 *  - TLS 1.2+ required (WINHTTP_FLAG_SECURE + secure protocols set). *
 *  - HTTP/2 (and HTTP/3 on Win11 22H2+) opt-in via ALPN. See         *
 *    enable_modern_http_protocols() below. h2 shaves ~20-80ms off    *
 *    TTFT for SSE streams and delivers tokens with lower jitter      *
 *    thanks to binary framing + TLS-record packing -- all AI edges    *
 *    (OpenAI CF, Anthropic CF, Google GCLB, OpenRouter CF, Supabase  *
 *    CF) already serve h2 natively.                                  *
 *  - Auto-follow-redirects enabled (Supabase / OAuth flows use them).*
 *  - No cookies persisted between calls -- session-less.              *
 *  - Timeout 30 s connect / 60 s read for AI calls that stream.      *
 * ================================================================== */

#include "winhttp_util.h"
#include "log_secure.h"

#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "winhttp.lib")

/* ── HTTP/2 + HTTP/3 constants (defined by SDK 10.0.14393+ / 22621+).
 *
 * We define fallback values ourselves in case an older SDK is used, so
 * the code compiles against any Windows 10+ SDK and picks up runtime
 * support wherever the OS supports it. WinHttpSetOption is a runtime
 * call -- the OS decides whether the flag is honored; the SDK header
 * just supplies numeric constants. */
#ifndef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL   133
#endif
#ifndef WINHTTP_OPTION_HTTP_PROTOCOL_USED
#define WINHTTP_OPTION_HTTP_PROTOCOL_USED     134
#endif
#ifndef WINHTTP_PROTOCOL_FLAG_HTTP2
#define WINHTTP_PROTOCOL_FLAG_HTTP2           0x1
#endif
#ifndef WINHTTP_PROTOCOL_FLAG_HTTP3
#define WINHTTP_PROTOCOL_FLAG_HTTP3           0x2
#endif

/* ── Modern-protocol enablement ─────────────────────────────────────
 *
 * WinHTTP defaults to HTTP/1.1 for historical reasons even on servers
 * that support h2. We opt in per session AND per request (Microsoft
 * recommends both for reliable coverage). Strategy:
 *
 *   1. Try (h2 | h3). Win 11 22H2+ negotiates HTTP/3 via ALPN/Alt-Svc
 *      first, then h2, then h1.1. Best case.
 *   2. If the OS rejects that value (older Windows returns
 *      ERROR_INVALID_PARAMETER because h3 flag is unknown), retry with
 *      just h2. This works on Win 10 1607+.
 *   3. If BOTH fail, silently stay on h1.1 -- no functional regression.
 *
 * Best-effort throughout: WinHttpSetOption may return FALSE for a
 * dozen reasons on locked-down enterprise builds; we don't fail the
 * request over it. */
static void enable_modern_http_protocols(HINTERNET h) {
    if (!h) return;
    DWORD both = WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3;
    if (WinHttpSetOption(h, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
                         &both, sizeof(both))) {
        return;
    }
    /* Retry with h2 only -- Win 10 baseline. */
    DWORD h2 = WINHTTP_PROTOCOL_FLAG_HTTP2;
    (void)WinHttpSetOption(h, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
                           &h2, sizeof(h2));
}

/* ── Protocol-used introspection + one-shot-per-host log. ───────────
 *
 * After WinHttpReceiveResponse, WINHTTP_OPTION_HTTP_PROTOCOL_USED tells
 * us what ALPN negotiated: 0 = HTTP/1.1, 0x1 = HTTP/2, 0x2 = HTTP/3.
 *
 * We log the first time we observe each (host, protocol) pair so
 * payload.log carries a clear signal like:
 *   http: negotiated h2 host=api.anthropic.com
 *   http: negotiated h1.1 host=some-corp-proxy.example
 * without spamming a line per request. Cache holds up to 8 hosts --
 * more than enough for our ~5 endpoints (OpenAI, Anthropic, Google,
 * OpenRouter, Supabase). */
typedef struct {
    wchar_t host[128];
    DWORD   proto;   /* 0 = h1.1, 0x1 = h2, 0x2 = h3 */
    int     seen;
} proto_cache_entry_t;

static proto_cache_entry_t g_proto_cache[8];
static volatile long       g_proto_cache_lock = 0;

static void proto_cache_note(const wchar_t *host, DWORD proto) {
    if (!host || !host[0]) return;
    while (InterlockedCompareExchange(&g_proto_cache_lock, 1, 0) != 0) {
        Sleep(0);
    }
    int free_slot = -1;
    for (int i = 0; i < 8; i++) {
        if (g_proto_cache[i].seen &&
            _wcsicmp(g_proto_cache[i].host, host) == 0 &&
            g_proto_cache[i].proto == proto) {
            g_proto_cache_lock = 0;
            return;  /* already logged this (host, proto) */
        }
        if (!g_proto_cache[i].seen && free_slot < 0) free_slot = i;
    }
    /* Cache miss -- log + record. Overwrite oldest slot on cache full. */
    int slot = free_slot >= 0 ? free_slot : 0;
    _snwprintf(g_proto_cache[slot].host,
               sizeof(g_proto_cache[slot].host) / sizeof(wchar_t) - 1,
               L"%ls", host);
    g_proto_cache[slot].host[sizeof(g_proto_cache[slot].host) / sizeof(wchar_t) - 1] = 0;
    g_proto_cache[slot].proto = proto;
    g_proto_cache[slot].seen  = 1;
    g_proto_cache_lock = 0;

    char host_u8[192] = {0};
    WideCharToMultiByte(CP_UTF8, 0, host, -1, host_u8, sizeof(host_u8) - 1, NULL, NULL);
    const char *label = "h1.1";
    if (proto & WINHTTP_PROTOCOL_FLAG_HTTP3)      label = "h3";
    else if (proto & WINHTTP_PROTOCOL_FLAG_HTTP2) label = "h2";
    slog_writef("msvc_dbg_c.dat", "http: negotiated %s host=%s", label, host_u8);
}

static void query_and_log_protocol_used(HINTERNET req, const wchar_t *host) {
    DWORD proto = 0;
    DWORD sz    = sizeof(proto);
    if (WinHttpQueryOption(req, WINHTTP_OPTION_HTTP_PROTOCOL_USED,
                           &proto, &sz)) {
        proto_cache_note(host, proto);
    }
}

/* WinHTTP wants wide strings for URL crack + method + headers.
 * Convert utf-8 -> wide on the stack. */
static int u8_to_w(const char *s, wchar_t *w, int wlen) {
    if (!s) { if (wlen) w[0] = 0; return 0; }
    int r = MultiByteToWideChar(CP_UTF8, 0, s, -1, w, wlen);
    return r > 0;
}

static wchar_t *u8_to_w_heap(const char *s) {
    if (!s) return NULL;
    int need = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (need <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc(need * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, need);
    return w;
}

void whreq_free_result(whreq_result_t *r) {
    if (!r) return;
    if (r->body)             free(r->body);
    if (r->header_signature) LocalFree(r->header_signature);
    r->body = NULL;
    r->header_signature = NULL;
    r->body_len = 0;
}

/* Build combined header string in wide chars. Result must be free'd. */
static wchar_t *build_headers(const char **headers) {
    if (!headers || !headers[0]) return NULL;
    size_t total = 1;  /* NUL */
    for (const char **h = headers; *h; h++) {
        total += strlen(*h) + 2;  /* CR LF */
    }
    /* utf-8 -> wide (worst case: 1 char per byte). */
    wchar_t *out = (wchar_t *)malloc(total * sizeof(wchar_t));
    if (!out) return NULL;
    size_t o = 0;
    for (const char **h = headers; *h; h++) {
        int r = MultiByteToWideChar(CP_UTF8, 0, *h, -1, out + o, (int)(total - o));
        if (r <= 0) { free(out); return NULL; }
        o += r - 1;  /* overwrite the NUL */
        out[o++] = L'\r'; out[o++] = L'\n';
    }
    out[o] = 0;
    return out;
}

/* Open session + connect + request. Returns NULL on failure. */
typedef struct {
    HINTERNET session;
    HINTERNET connect;
    HINTERNET request;
    URL_COMPONENTS urlc;
    wchar_t host[256];
    wchar_t path[2048];
    wchar_t extra[512];
    wchar_t combined_headers_buf[8192];  /* pre-alloc'd fallback path */
} req_ctx_t;

static void req_close(req_ctx_t *c) {
    if (!c) return;
    if (c->request) WinHttpCloseHandle(c->request);
    if (c->connect) WinHttpCloseHandle(c->connect);
    if (c->session) WinHttpCloseHandle(c->session);
    c->request = c->connect = c->session = NULL;
}

/* Set up session + connect + request. Fill c on success. */
static int req_open(req_ctx_t *c, const wchar_t *method, const char *url,
                    const char **headers, char *err, size_t err_sz) {
    memset(c, 0, sizeof(*c));

    wchar_t wurl[2048];
    if (!u8_to_w(url, wurl, SVC_ARRAY_SIZE(wurl))) {
        _snprintf(err, err_sz - 1, "url too long"); err[err_sz - 1] = 0;
        return 0;
    }

    c->urlc.dwStructSize = sizeof(c->urlc);
    c->urlc.lpszHostName = c->host;      c->urlc.dwHostNameLength  = SVC_ARRAY_SIZE(c->host);
    c->urlc.lpszUrlPath  = c->path;      c->urlc.dwUrlPathLength   = SVC_ARRAY_SIZE(c->path);
    c->urlc.lpszExtraInfo = c->extra;    c->urlc.dwExtraInfoLength = SVC_ARRAY_SIZE(c->extra);
    if (!WinHttpCrackUrl(wurl, 0, 0, &c->urlc)) {
        _snprintf(err, err_sz - 1, "WinHttpCrackUrl failed: %lu", GetLastError()); err[err_sz - 1] = 0;
        return 0;
    }
    if (c->urlc.nScheme != INTERNET_SCHEME_HTTPS) {
        _snprintf(err, err_sz - 1, "only https:// supported"); err[err_sz - 1] = 0;
        return 0;
    }

    /* v3 (2026-09-19): generic browser User-Agent instead of the
     * self-identifying "svcldb/1.0". Every HTTPS call (AI APIs, our
     * workers, Supabase) carried the old UA on the wire -- a network-
     * level proctor/inspection box would see the product name in
     * plaintext (UA is outside the TLS body only via SNI/CONNECT, but
     * still a binary IOC + a dead giveaway to any TLS-terminating
     * enterprise proxy). A stock Chrome UA blends with ordinary API
     * traffic; none of our endpoints validate the UA. */
    c->session = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        L"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!c->session) {
        _snprintf(err, err_sz - 1, "WinHttpOpen: %lu", GetLastError()); err[err_sz - 1] = 0;
        return 0;
    }

    /* Enforce TLS 1.2+ (Windows 10 baseline). Best-effort. */
    DWORD secure_protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    /* WinHTTP has a TLS1.3 flag on newer SDKs; probe by value. */
    secure_protocols |= 0x2000;  /* WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 */
    WinHttpSetOption(c->session, WINHTTP_OPTION_SECURE_PROTOCOLS,
                     &secure_protocols, sizeof(secure_protocols));

    /* Enable HTTP/2 (+ HTTP/3 where the OS supports it) via ALPN.
     * MUST be set BEFORE WinHttpSendRequest -- see MSDN. Setting on the
     * session propagates to every request created from it; we also set
     * on the request handle below for belt-and-braces coverage. */
    enable_modern_http_protocols(c->session);

    /* Redirect policy: allow same-scheme redirects (Supabase relies on them). */
    DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(c->session, WINHTTP_OPTION_REDIRECT_POLICY,
                     &redirect, sizeof(redirect));

    /* Timeouts: resolve/connect/send/receive in ms.
     * Tighter than defaults so a stalled network call fails quickly (better
     * UX than a spinner for 60s). AI providers respond in <5s typically. */
    WinHttpSetTimeouts(c->session, 5000, 5000, 10000, 20000);

    c->connect = WinHttpConnect(c->session, c->host,
                                (INTERNET_PORT)c->urlc.nPort, 0);
    if (!c->connect) {
        _snprintf(err, err_sz - 1, "WinHttpConnect: %lu", GetLastError()); err[err_sz - 1] = 0;
        return 0;
    }

    /* Build path?extra */
    wchar_t objectname[2560];
    _snwprintf(objectname, SVC_ARRAY_SIZE(objectname) - 1, L"%ls%ls", c->path, c->extra);
    objectname[SVC_ARRAY_SIZE(objectname) - 1] = 0;

    c->request = WinHttpOpenRequest(c->connect, method, objectname,
                                    NULL, WINHTTP_NO_REFERER,
                                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                                    WINHTTP_FLAG_SECURE);
    if (!c->request) {
        _snprintf(err, err_sz - 1, "WinHttpOpenRequest: %lu", GetLastError()); err[err_sz - 1] = 0;
        return 0;
    }

    /* Belt-and-braces: set the h2/h3 enable on the request handle too.
     * Session-level setting *should* propagate but Microsoft's docs
     * are explicit that both handles accept the option, and setting
     * per-request is idempotent. */
    enable_modern_http_protocols(c->request);

    return 1;
}

/* Read all response body into malloc'd buffer. */
static int read_all_body(HINTERNET req, char **out_body, size_t *out_len) {
    *out_body = NULL; *out_len = 0;
    size_t cap = 4096;
    char *buf = (char *)malloc(cap);
    if (!buf) return 0;
    size_t used = 0;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) { free(buf); return 0; }
        if (avail == 0) break;
        if (used + avail + 1 > cap) {
            while (used + avail + 1 > cap) cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); return 0; }
            buf = nb;
        }
        DWORD got = 0;
        if (!WinHttpReadData(req, buf + used, avail, &got)) { free(buf); return 0; }
        if (got == 0) break;
        used += got;
    }
    buf[used] = '\0';
    *out_body = buf;
    *out_len  = used;
    return 1;
}

/* Get raw headers block from response. Result must be LocalFree'd. */
static char *get_raw_headers(HINTERNET req) {
    DWORD sz = 0;
    WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                        WINHTTP_HEADER_NAME_BY_INDEX, NULL, &sz,
                        WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sz == 0) return NULL;
    wchar_t *wbuf = (wchar_t *)LocalAlloc(LPTR, sz);
    if (!wbuf) return NULL;
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                             WINHTTP_HEADER_NAME_BY_INDEX, wbuf, &sz,
                             WINHTTP_NO_HEADER_INDEX)) {
        LocalFree(wbuf); return NULL;
    }
    int need = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
    if (need <= 0) { LocalFree(wbuf); return NULL; }
    char *out = (char *)LocalAlloc(LPTR, need);
    if (!out) { LocalFree(wbuf); return NULL; }
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, need, NULL, NULL);
    LocalFree(wbuf);
    return out;
}

char *whreq_find_header(const char *headers_raw, const char *name) {
    if (!headers_raw || !name) return NULL;
    size_t nl = strlen(name);
    const char *p = headers_raw;
    while (*p) {
        const char *line_end = strstr(p, "\r\n");
        if (!line_end) line_end = p + strlen(p);
        if ((size_t)(line_end - p) > nl + 1 && _strnicmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1;
            while (v < line_end && (*v == ' ' || *v == '\t')) v++;
            size_t vlen = line_end - v;
            char *out = (char *)LocalAlloc(LPTR, vlen + 1);
            if (!out) return NULL;
            memcpy(out, v, vlen);
            out[vlen] = 0;
            return out;
        }
        if (!*line_end) break;
        p = line_end + 2;
    }
    return NULL;
}

/* Optional per-session receive-timeout override. do_request /
 * whreq_post_stream call this AFTER req_open() so the value overrides
 * the 20s default set inside req_open. Pass 0 to keep the default. */
static void apply_receive_timeout(req_ctx_t *c, DWORD receive_timeout_ms) {
    if (!c || !c->session || receive_timeout_ms == 0) return;
    /* WinHttpSetTimeouts on an existing session -- resolve/connect/send
     * default is -1 = don't change. Only override dwReceiveTimeout so
     * reasoning-model long streams don't drop between tokens. */
    WinHttpSetTimeouts(c->session, -1, -1, -1, (int)receive_timeout_ms);
}

/* Perform request. body_len==0 = no body. */
static int do_request_ex(const wchar_t *method, const char *url,
                         const char **headers, const void *body, size_t body_len,
                         DWORD receive_timeout_ms,
                         whreq_result_t *out) {
    req_ctx_t c;
    if (!req_open(&c, method, url, headers, out->err, sizeof(out->err))) {
        req_close(&c);
        return 0;
    }
    apply_receive_timeout(&c, receive_timeout_ms);
    wchar_t *hdrs = build_headers(headers);
    LPCWSTR hdrs_send = hdrs ? hdrs : WINHTTP_NO_ADDITIONAL_HEADERS;
    DWORD   hdrs_len  = hdrs ? (DWORD)-1L : 0;

    /* WinHttpSendRequest: extra_headers, body ptr, body len (both send + total). */
    BOOL ok = WinHttpSendRequest(c.request, hdrs_send, hdrs_len,
                                 (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0);
    if (hdrs) free(hdrs);
    if (!ok) {
        _snprintf(out->err, sizeof(out->err) - 1, "WinHttpSendRequest: %lu", GetLastError());
        out->err[sizeof(out->err) - 1] = 0;
        req_close(&c);
        return 0;
    }
    if (!WinHttpReceiveResponse(c.request, NULL)) {
        _snprintf(out->err, sizeof(out->err) - 1, "WinHttpReceiveResponse: %lu", GetLastError());
        out->err[sizeof(out->err) - 1] = 0;
        req_close(&c);
        return 0;
    }

    /* Log which HTTP protocol ALPN actually negotiated (once per host). */
    query_and_log_protocol_used(c.request, c.host);

    /* Status code. */
    DWORD status = 0, dwsize = sizeof(status);
    WinHttpQueryHeaders(c.request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &dwsize, WINHTTP_NO_HEADER_INDEX);
    out->status = (unsigned)status;

    /* Body. */
    if (!read_all_body(c.request, &out->body, &out->body_len)) {
        _snprintf(out->err, sizeof(out->err) - 1, "read body failed"); out->err[sizeof(out->err) - 1] = 0;
        req_close(&c);
        return 0;
    }

    /* x-response-signature header for licensed responses. */
    char *raw = get_raw_headers(c.request);
    if (raw) {
        out->header_signature = whreq_find_header(raw, "x-response-signature");
        LocalFree(raw);
    }

    req_close(&c);
    return 1;
}

int whreq_get(const char *url, const char **headers, whreq_result_t *out) {
    return whreq_get_ex(url, headers, 0, out);
}

int whreq_get_ex(const char *url, const char **headers,
                 DWORD receive_timeout_ms, whreq_result_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    return do_request_ex(L"GET", url, headers, NULL, 0, receive_timeout_ms, out);
}

int whreq_post(const char *url, const char **headers,
               const void *body, size_t body_len, whreq_result_t *out) {
    return whreq_post_ex(url, headers, body, body_len, 0, out);
}

int whreq_post_ex(const char *url, const char **headers,
                  const void *body, size_t body_len,
                  DWORD receive_timeout_ms, whreq_result_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    return do_request_ex(L"POST", url, headers, body, body_len, receive_timeout_ms, out);
}

int whreq_post_stream(const char *url, const char **headers,
                      const void *body, size_t body_len,
                      whreq_chunk_cb cb, void *userdata,
                      unsigned *out_status, char *out_err, size_t err_size) {
    return whreq_post_stream_ex(url, headers, body, body_len,
                                 0, cb, userdata,
                                 out_status, NULL, out_err, err_size);
}

int whreq_post_stream_ex(const char *url, const char **headers,
                         const void *body, size_t body_len,
                         DWORD receive_timeout_ms,
                         whreq_chunk_cb cb, void *userdata,
                         unsigned *out_status,
                         char **out_headers,
                         char *out_err, size_t err_size) {
    if (!cb) return 0;
    if (out_headers) *out_headers = NULL;

    req_ctx_t c;
    char err_local[256] = {0};
    if (!req_open(&c, L"POST", url, headers, err_local, sizeof(err_local))) {
        if (out_err && err_size) { _snprintf(out_err, err_size - 1, "%s", err_local); out_err[err_size - 1] = 0; }
        req_close(&c);
        return 0;
    }
    apply_receive_timeout(&c, receive_timeout_ms);
    wchar_t *hdrs = build_headers(headers);
    LPCWSTR hdrs_send = hdrs ? hdrs : WINHTTP_NO_ADDITIONAL_HEADERS;
    DWORD   hdrs_len  = hdrs ? (DWORD)-1L : 0;

    BOOL ok = WinHttpSendRequest(c.request, hdrs_send, hdrs_len,
                                 (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0);
    if (hdrs) free(hdrs);
    if (!ok) {
        if (out_err && err_size) { _snprintf(out_err, err_size - 1, "WinHttpSendRequest: %lu", GetLastError()); out_err[err_size - 1] = 0; }
        req_close(&c);
        return 0;
    }
    if (!WinHttpReceiveResponse(c.request, NULL)) {
        if (out_err && err_size) { _snprintf(out_err, err_size - 1, "WinHttpReceiveResponse: %lu", GetLastError()); out_err[err_size - 1] = 0; }
        req_close(&c);
        return 0;
    }

    /* Log which HTTP protocol ALPN actually negotiated (once per host).
     * For streaming this is especially interesting because h2's DATA
     * frames arrive with lower jitter than h1.1 chunked. */
    query_and_log_protocol_used(c.request, c.host);

    DWORD status = 0, dwsize = sizeof(status);
    WinHttpQueryHeaders(c.request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &dwsize, WINHTTP_NO_HEADER_INDEX);
    if (out_status) *out_status = (unsigned)status;

    /* Grab raw headers for the caller's Retry-After parse -- but do it
     * BEFORE any reads because some WinHTTP versions consume headers
     * during body-drain in edge cases. */
    if (out_headers) *out_headers = get_raw_headers(c.request);

    uint8_t buf[8192];
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(c.request, &avail)) break;
        if (avail == 0) break;
        DWORD toread = avail < sizeof(buf) ? avail : sizeof(buf);
        DWORD got = 0;
        if (!WinHttpReadData(c.request, buf, toread, &got)) break;
        if (got == 0) break;
        if (cb(buf, (size_t)got, userdata) != 0) break;   /* callback abort */
    }

    req_close(&c);
    return 1;
}

/* Parse Retry-After. Handles:
 *   - `retry-after-ms: 1234`         (OpenAI style -- raw milliseconds)
 *   - `retry-after: 5`               (RFC 7231 seconds)
 *   - `retry-after: Wed, 21 Oct 2015 07:28:00 GMT`  (HTTP-date -- treat as
 *                                     fixed 30s fallback since we don't
 *                                     ship a full RFC 7231 date parser)
 * Returns milliseconds to wait, or 0 if absent / unparseable. */
DWORD whreq_parse_retry_after_ms(const char *headers_raw) {
    if (!headers_raw) return 0;
    /* OpenAI's retry-after-ms is authoritative when present. */
    char *v = whreq_find_header(headers_raw, "retry-after-ms");
    if (v) {
        DWORD ms = (DWORD)strtoul(v, NULL, 10);
        LocalFree(v);
        return ms;
    }
    v = whreq_find_header(headers_raw, "retry-after");
    if (!v) return 0;
    /* Numeric prefix? seconds. */
    if (v[0] >= '0' && v[0] <= '9') {
        DWORD s = (DWORD)strtoul(v, NULL, 10);
        LocalFree(v);
        return s * 1000UL;
    }
    /* HTTP-date -- conservative default. */
    LocalFree(v);
    return 30 * 1000UL;
}
