/* ================================================================== *
 * oauth.c -- Supabase PKCE OAuth via WinHTTP + WinSock2 listener.      *
 * ================================================================== */

#include "../../shared/common.h"
#include "oauth.h"
#include "../../shared/base64.h"
#include "../../shared/crypto_util.h"
#include "../../shared/hwid.h"
#include "../../shared/json_util.h"
#include "../../shared/log_secure.h"
#include "../../shared/supabase_config.h"
#include "../../shared/winhttp_util.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")

#define OAUTH_CALLBACK_TIMEOUT_MS   (5 * 60 * 1000)

/* ── URL-encode a value for a query string. */
static void url_encode(const char *in, char *out, size_t outsize) {
    static const char H[] = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 4 < outsize; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = H[c >> 4];
            out[o++] = H[c & 0xF];
        }
    }
    out[o] = 0;
}

/* ── HTML pages for the callback response. */
static const char SUCCESS_HTML[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Cache-Control: no-store\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Signed in</title>"
    "<style>body{background:#0a0d12;color:#e4e4e7;font-family:-apple-system,'Segoe UI',sans-serif;"
    "display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}"
    ".card{background:#111827;border:1px solid #1f2937;border-radius:16px;padding:40px 48px;text-align:center;max-width:400px}"
    ".c{width:64px;height:64px;border-radius:50%;background:#065f46;display:flex;align-items:center;justify-content:center;margin:0 auto 24px}"
    ".c svg{width:32px;height:32px;stroke:#a7f3d0;stroke-width:3;fill:none;stroke-linecap:round;stroke-linejoin:round}"
    "h1{font-size:22px;font-weight:600;margin:0 0 12px}p{color:#9ca3af;font-size:14px;margin:0 0 24px;line-height:1.5}"
    ".d{font-size:13px;color:#6b7280}</style></head><body><div class='card'>"
    "<div class='c'><svg viewBox='0 0 24 24'><polyline points='4 12 10 18 20 6'/></svg></div>"
    "<h1>You're signed in</h1><p>Authentication complete. You can close this tab and return to the app.</p>"
    "<p class='d'>Closing in <span id='t'>3</span>s...</p></div>"
    "<script>let s=3;setInterval(()=>{s--;document.getElementById('t').textContent=s;if(s<=0)window.close()},1000)</script>"
    "</body></html>";

static const char ERROR_HTML_HDR[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Cache-Control: no-store\r\n"
    "Connection: close\r\n"
    "\r\n";
static const char ERROR_HTML_BODY_PRE[] =
    "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Error</title>"
    "<style>body{background:#0a0d12;color:#e4e4e7;font-family:-apple-system,'Segoe UI',sans-serif;"
    "display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}"
    ".card{background:#111827;border:1px solid #7f1d1d;border-radius:16px;padding:40px 48px;text-align:center;max-width:500px}"
    "h1{font-size:22px;font-weight:600;margin:0 0 12px;color:#f87171}"
    ".m{color:#9ca3af;font-size:14px;margin:0;line-height:1.5;word-break:break-word}</style></head>"
    "<body><div class='card'><h1>Sign-in failed</h1><p class='m'>";
static const char ERROR_HTML_BODY_POST[] =
    "</p></div></body></html>";

/* ── Open a URL in the default browser (best-effort, non-blocking). */
static void open_in_browser(const char *url) {
    /* Prefer rundll32 url.dll -- same trick auth.js uses to escape elevated context. */
    char cmd[4096];
    _snprintf(cmd, sizeof(cmd) - 1,
              "rundll32.exe url.dll,FileProtocolHandler %s", url);
    cmd[sizeof(cmd) - 1] = 0;

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }
    /* Fallback: ShellExecute (may fail from elevated context). */
    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
}

/* ── Bind + accept a single HTTP request on 127.0.0.1:SVC_CALLBACK_PORT.
 * Populates *code_out with the ?code=... value. Sends success or error HTML.
 * Returns 1 on success, 0 on error/timeout. */
static int wait_for_callback(char *code_out, size_t code_size,
                             char *err, size_t err_sz) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        _snprintf(err, err_sz - 1, "WSAStartup failed"); err[err_sz - 1] = 0;
        return 0;
    }

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        _snprintf(err, err_sz - 1, "socket() failed: %d", WSAGetLastError());
        err[err_sz - 1] = 0;
        WSACleanup();
        return 0;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(SVC_CALLBACK_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        _snprintf(err, err_sz - 1, "bind :%d failed: %d",
                  SVC_CALLBACK_PORT, WSAGetLastError());
        err[err_sz - 1] = 0;
        closesocket(srv);
        WSACleanup();
        return 0;
    }
    if (listen(srv, 1) == SOCKET_ERROR) {
        _snprintf(err, err_sz - 1, "listen failed: %d", WSAGetLastError());
        err[err_sz - 1] = 0;
        closesocket(srv);
        WSACleanup();
        return 0;
    }

    /* Poll for accept with 5-min total timeout. */
    DWORD deadline = GetTickCount() + OAUTH_CALLBACK_TIMEOUT_MS;
    for (;;) {
        DWORD remaining = deadline > GetTickCount() ? deadline - GetTickCount() : 0;
        if (remaining == 0) {
            _snprintf(err, err_sz - 1, "callback timeout"); err[err_sz - 1] = 0;
            closesocket(srv); WSACleanup(); return 0;
        }
        fd_set rf; FD_ZERO(&rf); FD_SET(srv, &rf);
        TIMEVAL tv;
        tv.tv_sec  = (long)(remaining / 1000);
        tv.tv_usec = (long)((remaining % 1000) * 1000);
        int sr = select(0, &rf, NULL, NULL, &tv);
        if (sr <= 0) continue;

        SOCKET cli = accept(srv, NULL, NULL);
        if (cli == INVALID_SOCKET) continue;

        /* Read one HTTP request line. */
        char req[8192] = {0};
        int total = 0;
        while (total < (int)sizeof(req) - 1) {
            int r = recv(cli, req + total, sizeof(req) - 1 - total, 0);
            if (r <= 0) break;
            total += r;
            /* Wait for end-of-headers (double CRLF) or one full line at least. */
            if (strstr(req, "\r\n\r\n")) break;
            if (total > 4096) break;
        }
        req[total < (int)sizeof(req) ? total : (int)sizeof(req) - 1] = 0;

        /* Look for GET /callback?...&code=xxx&... */
        const char *q = strstr(req, "?");
        const char *space_after = q ? strchr(q, ' ') : NULL;
        if (!q || !space_after || space_after < q) {
            const char *reply =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(cli, reply, (int)strlen(reply), 0);
            closesocket(cli);
            continue;
        }
        /* Extract code= or error= from query. */
        char query[4096] = {0};
        size_t qlen = space_after - q - 1;
        if (qlen >= sizeof(query)) qlen = sizeof(query) - 1;
        memcpy(query, q + 1, qlen); query[qlen] = 0;

        char code_val[2048]  = {0};
        char error_val[512]  = {0};
        char desc_val[1024]  = {0};

        /* Simple key=value&... parsing. */
        char *save = NULL, *tok = strtok_s(query, "&", &save);
        while (tok) {
            char *eq = strchr(tok, '=');
            if (eq) {
                *eq = 0;
                const char *k = tok;
                const char *v = eq + 1;
                /* URL-decode v in place (safe -- smaller output than input). */
                char decoded[2048]; size_t di = 0;
                for (size_t i = 0; v[i] && di < sizeof(decoded) - 1; i++) {
                    if (v[i] == '%' && v[i+1] && v[i+2]) {
                        char hb[3] = { v[i+1], v[i+2], 0 };
                        unsigned int b;
                        if (sscanf(hb, "%02x", &b) == 1) {
                            decoded[di++] = (char)b; i += 2; continue;
                        }
                    }
                    decoded[di++] = (v[i] == '+') ? ' ' : v[i];
                }
                decoded[di] = 0;
                if (strcmp(k, "code")              == 0) strncpy(code_val, decoded,  sizeof(code_val)  - 1);
                if (strcmp(k, "error")             == 0) strncpy(error_val, decoded, sizeof(error_val) - 1);
                if (strcmp(k, "error_description") == 0) strncpy(desc_val, decoded,  sizeof(desc_val)  - 1);
            }
            tok = strtok_s(NULL, "&", &save);
        }

        if (error_val[0]) {
            /* Send error HTML. */
            send(cli, ERROR_HTML_HDR, (int)strlen(ERROR_HTML_HDR), 0);
            send(cli, ERROR_HTML_BODY_PRE,  (int)strlen(ERROR_HTML_BODY_PRE), 0);
            const char *msg = desc_val[0] ? desc_val : error_val;
            send(cli, msg, (int)strlen(msg), 0);
            send(cli, ERROR_HTML_BODY_POST, (int)strlen(ERROR_HTML_BODY_POST), 0);
            closesocket(cli);
            closesocket(srv);
            WSACleanup();
            _snprintf(err, err_sz - 1, "oauth error: %s", msg); err[err_sz - 1] = 0;
            return 0;
        }

        if (!code_val[0]) {
            const char *reply =
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(cli, reply, (int)strlen(reply), 0);
            closesocket(cli);
            continue;
        }

        /* Success -- send success HTML, capture code. */
        send(cli, SUCCESS_HTML, (int)strlen(SUCCESS_HTML), 0);
        closesocket(cli);
        closesocket(srv);
        WSACleanup();

        strncpy(code_out, code_val, code_size - 1);
        code_out[code_size - 1] = 0;
        return 1;
    }
}

/* ── Exchange PKCE auth code for tokens. */
static int exchange_code(const char *code, const char *verifier, oauth_session_t *out,
                         char *err, size_t err_sz) {
    const char *sb = sb_url();
    const char *anon = sb_anon_key();
    if (!sb || !anon) {
        _snprintf(err, err_sz - 1, "supabase config unavailable"); err[err_sz - 1] = 0;
        return 0;
    }

    char url[512];
    _snprintf(url, sizeof(url) - 1, "%s/auth/v1/token?grant_type=pkce", sb);
    url[sizeof(url) - 1] = 0;

    /* Build request body. */
    json_builder_t jb;
    if (!jb_init(&jb, 512)) return 0;
    jb_obj_begin(&jb);
      jb_key(&jb, "auth_code");     jb_str(&jb, code);
      jb_key(&jb, "code_verifier"); jb_str(&jb, verifier);
    jb_obj_end(&jb);
    if (jb.err) { jb_free(&jb); _snprintf(err, err_sz - 1, "json build failed"); return 0; }

    char apikey_hdr[512];
    _snprintf(apikey_hdr, sizeof(apikey_hdr) - 1, "apikey: %s", anon);
    apikey_hdr[sizeof(apikey_hdr) - 1] = 0;
    const char *hdrs[] = {
        "Content-Type: application/json",
        apikey_hdr,
        NULL
    };

    whreq_result_t r = {0};
    int ok = whreq_post(url, hdrs, jb.buf, jb.len, &r);
    jb_free(&jb);
    if (!ok || r.status < 200 || r.status >= 300) {
        _snprintf(err, err_sz - 1, "token exchange failed (%u): %s",
                  r.status, r.err[0] ? r.err : (r.body ? r.body : ""));
        err[err_sz - 1] = 0;
        whreq_free_result(&r);
        return 0;
    }

    /* Parse response. */
    if (!json_get_str(r.body, "access_token",  out->access_token,  sizeof(out->access_token))) {
        _snprintf(err, err_sz - 1, "no access_token in response"); err[err_sz - 1] = 0;
        whreq_free_result(&r);
        return 0;
    }
    json_get_str(r.body, "refresh_token", out->refresh_token, sizeof(out->refresh_token));

    /* expires_in (relative) or expires_at (absolute). */
    double expires_in = 3600, expires_at = 0;
    if (json_get_num(r.body, "expires_at", &expires_at) && expires_at > 0) {
        out->expires_at = (long long)expires_at;
    } else {
        json_get_num(r.body, "expires_in", &expires_in);
        out->expires_at = (long long)time(NULL) + (long long)expires_in;
    }

    /* Nested user{}: extract via crude but correct approach -- find "user":
     * then apply json_get_str against the object substring. */
    const char *user_start = strstr(r.body, "\"user\"");
    if (user_start) {
        const char *brace = strchr(user_start, '{');
        if (brace) {
            /* Balanced brace scan */
            int depth = 0;
            const char *e = brace;
            for (; *e; e++) {
                if (*e == '{') depth++;
                else if (*e == '}') { depth--; if (depth == 0) { e++; break; } }
            }
            if (depth == 0 && e > brace) {
                size_t ulen = e - brace;
                char *ubuf = (char *)malloc(ulen + 1);
                if (ubuf) {
                    memcpy(ubuf, brace, ulen);
                    ubuf[ulen] = 0;
                    json_get_str(ubuf, "id",    out->user_id,      sizeof(out->user_id));
                    json_get_str(ubuf, "email", out->email,        sizeof(out->email));
                    /* display_name lives at user.user_metadata.full_name / name */
                    const char *meta = strstr(ubuf, "\"user_metadata\"");
                    if (meta) {
                        const char *mb = strchr(meta, '{');
                        if (mb) {
                            int md = 0; const char *me = mb;
                            for (; *me; me++) {
                                if (*me == '{') md++;
                                else if (*me == '}') { md--; if (md == 0) { me++; break; } }
                            }
                            if (md == 0 && me > mb) {
                                size_t mlen = me - mb;
                                char *mbuf = (char *)malloc(mlen + 1);
                                if (mbuf) {
                                    memcpy(mbuf, mb, mlen); mbuf[mlen] = 0;
                                    if (!json_get_str(mbuf, "full_name", out->display_name, sizeof(out->display_name))) {
                                        json_get_str(mbuf, "name", out->display_name, sizeof(out->display_name));
                                    }
                                    free(mbuf);
                                }
                            }
                        }
                    }
                    free(ubuf);
                }
            }
        }
    }

    out->created_at = (long long)time(NULL);
    oauth_sign_session(out);

    whreq_free_result(&r);
    return 1;
}

/* ── Public API ──────────────────────────────────────────────────── */

void oauth_sign_session(oauth_session_t *sess) {
    if (!sess) return;
    char hwid[80];
    if (!hwid_get_cached(hwid, sizeof(hwid))) return;

    uint8_t key[32];
    if (!cu_hmac_sha256((const uint8_t *)"svcldb-session-v1", 17,
                        hwid, strlen(hwid), key)) return;

    /* Compose the signed data: access_token || user_id || email || expires_at_le */
    uint8_t buf[8192];
    size_t o = 0;
    size_t tl = strlen(sess->access_token);
    size_t ul = strlen(sess->user_id);
    size_t el = strlen(sess->email);
    if (tl + ul + el + 8 > sizeof(buf)) return;
    memcpy(buf + o, sess->access_token, tl); o += tl;
    memcpy(buf + o, sess->user_id, ul);      o += ul;
    memcpy(buf + o, sess->email, el);        o += el;
    for (int i = 0; i < 8; i++)
        buf[o++] = (uint8_t)((sess->expires_at >> (i * 8)) & 0xFF);

    cu_hmac_sha256(key, 32, buf, o, sess->signature);
    svc_secure_zero(key, sizeof(key));
    svc_secure_zero(buf, sizeof(buf));
}

int oauth_verify_session(const oauth_session_t *sess) {
    if (!sess) return 0;
    oauth_session_t copy = *sess;
    uint8_t saved_sig[32];
    memcpy(saved_sig, sess->signature, 32);
    oauth_sign_session(&copy);
    int diff = cu_ct_eq(saved_sig, copy.signature, 32);
    svc_secure_zero(&copy, sizeof(copy));
    svc_secure_zero(saved_sig, sizeof(saved_sig));
    return diff == 0;
}

int oauth_expired(const oauth_session_t *sess) {
    if (!sess) return 1;
    return sess->expires_at < (long long)time(NULL) + 300;
}
int oauth_stale(const oauth_session_t *sess) {
    if (!sess || sess->created_at == 0) return 0;
    return (long long)time(NULL) - sess->created_at > (24 * 60 * 60);
}

int oauth_run(oauth_session_t *out, char *err, size_t err_sz) {
    if (!out || !err || err_sz == 0) return 0;
    memset(out, 0, sizeof(*out));

    /* 1. PKCE verifier + challenge. */
    char verifier[64], challenge[64];
    if (!cu_pkce_verifier(verifier) || !cu_pkce_challenge(verifier, challenge)) {
        _snprintf(err, err_sz - 1, "PKCE gen failed"); err[err_sz - 1] = 0;
        return 0;
    }

    /* 2. Build authorize URL. */
    const char *sb = sb_url();
    if (!sb) { _snprintf(err, err_sz - 1, "supabase url unavailable"); err[err_sz - 1] = 0; return 0; }

    char redirect[128];
    _snprintf(redirect, sizeof(redirect) - 1, "http://localhost:%d/callback", SVC_CALLBACK_PORT);
    redirect[sizeof(redirect) - 1] = 0;

    char redirect_enc[256];
    url_encode(redirect, redirect_enc, sizeof(redirect_enc));

    char auth_url[2048];
    _snprintf(auth_url, sizeof(auth_url) - 1,
        "%s/auth/v1/authorize?provider=google&redirect_to=%s"
        "&code_challenge=%s&code_challenge_method=S256"
        "&response_type=code&flow_type=pkce&prompt=consent",
        sb, redirect_enc, challenge);
    auth_url[sizeof(auth_url) - 1] = 0;

    slog_auth("oauth start");

    /* 3. Open browser + start listener in parallel. */
    open_in_browser(auth_url);

    char code[2048];
    if (!wait_for_callback(code, sizeof(code), err, err_sz)) {
        slog_writef("auth.log", "oauth callback failed: %s", err);
        return 0;
    }

    /* 4. Exchange code for tokens. */
    if (!exchange_code(code, verifier, out, err, err_sz)) {
        slog_writef("auth.log", "oauth code exchange failed: %s", err);
        return 0;
    }
    slog_writef("auth.log", "oauth ok user=%s", out->email);
    return 1;
}

int oauth_refresh(oauth_session_t *sess, char *err, size_t err_sz) {
    if (!sess || !sess->refresh_token[0]) {
        _snprintf(err, err_sz - 1, "no refresh_token"); err[err_sz - 1] = 0;
        return 0;
    }
    const char *sb = sb_url();
    const char *anon = sb_anon_key();
    if (!sb || !anon) {
        _snprintf(err, err_sz - 1, "supabase config unavailable"); err[err_sz - 1] = 0;
        return 0;
    }

    char url[512];
    _snprintf(url, sizeof(url) - 1, "%s/auth/v1/token?grant_type=refresh_token", sb);
    url[sizeof(url) - 1] = 0;

    json_builder_t jb;
    if (!jb_init(&jb, 512)) return 0;
    jb_obj_begin(&jb);
      jb_key(&jb, "refresh_token"); jb_str(&jb, sess->refresh_token);
    jb_obj_end(&jb);

    char apikey_hdr[512];
    _snprintf(apikey_hdr, sizeof(apikey_hdr) - 1, "apikey: %s", anon);
    apikey_hdr[sizeof(apikey_hdr) - 1] = 0;
    const char *hdrs[] = {
        "Content-Type: application/json",
        apikey_hdr,
        NULL
    };

    whreq_result_t r = {0};
    int ok = whreq_post(url, hdrs, jb.buf, jb.len, &r);
    jb_free(&jb);
    if (!ok || r.status < 200 || r.status >= 300) {
        _snprintf(err, err_sz - 1, "refresh failed (%u)", r.status); err[err_sz - 1] = 0;
        whreq_free_result(&r);
        return 0;
    }
    json_get_str(r.body, "access_token",  sess->access_token,  sizeof(sess->access_token));
    json_get_str(r.body, "refresh_token", sess->refresh_token, sizeof(sess->refresh_token));
    double expires_in = 3600;
    json_get_num(r.body, "expires_in", &expires_in);
    sess->expires_at = (long long)time(NULL) + (long long)expires_in;
    oauth_sign_session(sess);
    whreq_free_result(&r);
    return 1;
}
