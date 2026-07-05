/* ================================================================== *
 * license.c — Session persist + Supabase subscription check.          *
 * ================================================================== */

#include "../../shared/common.h"
#include "license.h"
#include "../../shared/crypto_util.h"
#include "../../shared/hwid.h"
#include "../../shared/json_util.h"
#include "../../shared/log_secure.h"
#include "../../shared/supabase_config.h"
#include "../../shared/winhttp_util.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define SESSION_FILE  SVC_INSTALL_DIR "\\session.dat"

static int save_bytes(const char *path, const uint8_t *data, size_t len) {
    CreateDirectoryA(SVC_INSTALL_DIR, NULL);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w = 0;
    BOOL ok = WriteFile(h, data, (DWORD)len, &w, NULL);
    CloseHandle(h);
    return ok && w == len;
}

static int load_bytes(const char *path, uint8_t *out, size_t outmax, size_t *out_len) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz > outmax) { CloseHandle(h); return 0; }
    DWORD r = 0;
    BOOL ok = ReadFile(h, out, sz, &r, NULL);
    CloseHandle(h);
    if (!ok || r != sz) return 0;
    *out_len = r;
    return 1;
}

int license_save_session(const oauth_session_t *sess) {
    if (!sess) return 0;
    uint8_t cipher[sizeof(oauth_session_t) + 64];
    size_t clen = 0;
    if (!cu_wrap_encrypt(sess, sizeof(*sess), cipher, sizeof(cipher), &clen))
        return 0;
    int ok = save_bytes(SESSION_FILE, cipher, clen);
    svc_secure_zero(cipher, sizeof(cipher));
    return ok;
}

int license_load_session(oauth_session_t *out) {
    if (!out) return 0;
    uint8_t cipher[sizeof(oauth_session_t) + 128];
    size_t clen = 0;
    if (!load_bytes(SESSION_FILE, cipher, sizeof(cipher), &clen)) return 0;

    uint8_t plain[sizeof(oauth_session_t)];
    size_t plen = 0;
    if (!cu_wrap_decrypt(cipher, clen, plain, sizeof(plain), &plen)) {
        svc_secure_zero(cipher, sizeof(cipher));
        return 0;
    }
    svc_secure_zero(cipher, sizeof(cipher));
    if (plen != sizeof(oauth_session_t)) {
        svc_secure_zero(plain, sizeof(plain));
        return 0;
    }
    memcpy(out, plain, sizeof(*out));
    svc_secure_zero(plain, sizeof(plain));

    if (!oauth_verify_session(out)) {
        slog_auth("session signature invalid — clearing");
        license_clear();
        memset(out, 0, sizeof(*out));
        return 0;
    }
    if (oauth_stale(out)) {
        slog_auth("session stale (>24h) — forcing re-login");
        license_clear();
        memset(out, 0, sizeof(*out));
        return 0;
    }
    return 1;
}

void license_clear(void) {
    DeleteFileA(SESSION_FILE);
}

int license_login(oauth_session_t *out, char *err, size_t err_sz) {
    /* 1. Load-from-disk fast path. */
    if (license_load_session(out)) {
        if (oauth_expired(out)) {
            slog_auth("access_token expired — refreshing");
            if (!oauth_refresh(out, err, err_sz)) {
                slog_writef("auth.log", "refresh failed: %s — full re-login", err);
                license_clear();
                memset(out, 0, sizeof(*out));
            } else {
                license_save_session(out);
                return 1;
            }
        } else {
            return 1;
        }
    }
    /* 2. Full OAuth. */
    if (!oauth_run(out, err, err_sz)) return 0;
    license_save_session(out);
    return 1;
}

/* ── Subscription check via Supabase REST ─────────────────────────── */

int license_check_subscription(const oauth_session_t *sess,
                               license_status_t *out,
                               char *err, size_t err_sz) {
    if (!sess || !out) return 0;
    memset(out, 0, sizeof(*out));

    const char *sb = sb_url();
    const char *anon = sb_anon_key();
    if (!sb || !anon) {
        _snprintf(err, err_sz - 1, "supabase config unavailable"); err[err_sz - 1] = 0;
        return 0;
    }

    char apikey_hdr[512], bearer_hdr[8192];
    _snprintf(apikey_hdr, sizeof(apikey_hdr) - 1, "apikey: %s", anon);
    _snprintf(bearer_hdr, sizeof(bearer_hdr) - 1, "Authorization: Bearer %s", sess->access_token);
    apikey_hdr[sizeof(apikey_hdr) - 1] = 0;
    bearer_hdr[sizeof(bearer_hdr) - 1] = 0;
    const char *hdrs[] = { apikey_hdr, bearer_hdr, NULL };

    /* 1. manual_grants (lifetime whitelist). */
    {
        char url[512];
        _snprintf(url, sizeof(url) - 1,
            "%s/rest/v1/manual_grants?select=plan_type,status,expires_at"
            "&status=eq.active&revoked_at=is.null",
            sb);
        url[sizeof(url) - 1] = 0;
        whreq_result_t r = {0};
        if (whreq_get(url, hdrs, &r) && r.status == 200 && r.body) {
            if (json_has_nonempty_array_or_object(r.body)) {
                const char *os = NULL, *oe = NULL;
                if (json_first_array_object(r.body, &os, &oe)) {
                    char sub[2048] = {0};
                    size_t sl = oe - os < (int)sizeof(sub) ? (size_t)(oe - os) : sizeof(sub) - 1;
                    memcpy(sub, os, sl); sub[sl] = 0;
                    json_get_str(sub, "plan_type", out->plan, sizeof(out->plan));
                    if (out->plan[0] == 0) strncpy(out->plan, "lifetime", sizeof(out->plan) - 1);
                    strncpy(out->status, "active", sizeof(out->status) - 1);
                    out->active = 1;
                    out->is_lifetime = 1;
                    whreq_free_result(&r);
                    slog_writef("auth.log", "manual grant %s", out->plan);
                    return 1;
                }
            }
        }
        whreq_free_result(&r);
    }

    /* 2. subscriptions. */
    {
        char url[512];
        _snprintf(url, sizeof(url) - 1,
            "%s/rest/v1/subscriptions?select=plan_type,status,current_period_end,is_lifetime"
            "&status=in.(active,cancelling)",
            sb);
        url[sizeof(url) - 1] = 0;
        whreq_result_t r = {0};
        if (whreq_get(url, hdrs, &r) && r.status == 200 && r.body) {
            if (json_has_nonempty_array_or_object(r.body)) {
                const char *os = NULL, *oe = NULL;
                if (json_first_array_object(r.body, &os, &oe)) {
                    char sub[2048] = {0};
                    size_t sl = oe - os < (int)sizeof(sub) ? (size_t)(oe - os) : sizeof(sub) - 1;
                    memcpy(sub, os, sl); sub[sl] = 0;
                    json_get_str(sub, "plan_type", out->plan,   sizeof(out->plan));
                    json_get_str(sub, "status",    out->status, sizeof(out->status));
                    int lt = 0; json_get_bool(sub, "is_lifetime", &lt);
                    out->is_lifetime = lt;
                    out->active = 1;
                    whreq_free_result(&r);
                    slog_writef("auth.log", "subscription %s %s", out->plan, out->status);
                    return 1;
                }
            }
        }
        whreq_free_result(&r);
    }

    /* Neither found — treat as no subscription. */
    strncpy(out->status, "no_subscription", sizeof(out->status) - 1);
    slog_auth("no active subscription");
    return 1;
}
