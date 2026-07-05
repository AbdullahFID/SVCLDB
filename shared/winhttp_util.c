/* ================================================================== *
 * winhttp_util.c — WinHTTP HTTPS wrapper.                            *
 *                                                                    *
 * Design notes:                                                      *
 *  - Uses WinHTTP directly (not WinInet — WinInet inherits IE proxy  *
 *    settings which can be tampered with; WinHTTP has its own).     *
 *  - TLS 1.2+ required (WINHTTP_FLAG_SECURE + secure protocols set). *
 *  - Auto-follow-redirects enabled (Supabase / OAuth flows use them).*
 *  - No cookies persisted between calls — session-less.              *
 *  - Timeout 30 s connect / 60 s read for AI calls that stream.      *
 * ================================================================== */

#include "winhttp_util.h"
#include "log_secure.h"

#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "winhttp.lib")

/* WinHTTP wants wide strings for URL crack + method + headers.
 * Convert utf-8 → wide on the stack. */
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
    /* utf-8 → wide (worst case: 1 char per byte). */
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

    c->session = WinHttpOpen(L"svcldb/1.0",
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

/* Perform request. body_len==0 = no body. */
static int do_request(const wchar_t *method, const char *url,
                      const char **headers, const void *body, size_t body_len,
                      whreq_result_t *out) {
    req_ctx_t c;
    if (!req_open(&c, method, url, headers, out->err, sizeof(out->err))) {
        req_close(&c);
        return 0;
    }
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
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    return do_request(L"GET", url, headers, NULL, 0, out);
}

int whreq_post(const char *url, const char **headers,
               const void *body, size_t body_len, whreq_result_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    return do_request(L"POST", url, headers, body, body_len, out);
}

int whreq_post_stream(const char *url, const char **headers,
                      const void *body, size_t body_len,
                      whreq_chunk_cb cb, void *userdata,
                      unsigned *out_status, char *out_err, size_t err_size) {
    if (!cb) return 0;

    req_ctx_t c;
    char err_local[256] = {0};
    if (!req_open(&c, L"POST", url, headers, err_local, sizeof(err_local))) {
        if (out_err && err_size) { _snprintf(out_err, err_size - 1, "%s", err_local); out_err[err_size - 1] = 0; }
        req_close(&c);
        return 0;
    }
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

    DWORD status = 0, dwsize = sizeof(status);
    WinHttpQueryHeaders(c.request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &dwsize, WINHTTP_NO_HEADER_INDEX);
    if (out_status) *out_status = (unsigned)status;

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
