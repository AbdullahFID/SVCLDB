/* ================================================================== *
 * notes.c -- see notes.h. Persistent reference-notes text, encrypted   *
 * at rest with AES-256-GCM (keyed off the shared SVCLDB_LOG_KEY).      *
 *                                                                     *
 * Threat model: defends against an admin dumping ProgramData and      *
 * reading last-typed exam context in plaintext. NOT defence against   *
 * RE of the payload binary itself (that adversary pulls the key       *
 * trivially). Same tier as encrypted payload.log -- transparently     *
 * opaque to forensic sweeps.                                          *
 * ================================================================== */
#include "../../../shared/common.h"
#include "notes.h"
#include "../../../shared/log_secure.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>    /* malloc/free */

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

extern uint8_t SVCLDB_LOG_KEY[32];

/* ── State ────────────────────────────────────────────────────────── */
static CRITICAL_SECTION g_cs;
static int              g_cs_init = 0;
static char             g_buf[NOTES_MAX_BYTES] = {0};
static int              g_len = 0;
static int              g_cur = 0;
static volatile LONG    g_editor_open = 0;
static volatile LONG    g_dirty       = 0;
static volatile LONG    g_loaded      = 0;

static void ensure_cs(void) {
    if (!g_cs_init) { InitializeCriticalSection(&g_cs); g_cs_init = 1; }
}

/* File format: 'NOTS'(4) + ver(1) + iv(12) + tag(16) + ct(N). */
#define NOTES_MAGIC   0x53544F4Eu
#define NOTES_VERSION 1

/* ── Crypto ─────────────────────────────────────────────────────── */
static BOOL enc_gcm(const uint8_t *pt, ULONG pt_len, uint8_t *iv12,
                    uint8_t *tag16, uint8_t *ct, ULONG *ct_cap) {
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE key = NULL; BOOL ok = FALSE;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto d;
    if (!NT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)), 0))) goto d;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(alg, &key, NULL, 0, SVCLDB_LOG_KEY, 32, 0))) goto d;
    if (!NT_SUCCESS(BCryptGenRandom(NULL, iv12, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) goto d;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv12; info.cbNonce = 12; info.pbTag = tag16; info.cbTag = 16;
    ULONG w = 0;
    if (!NT_SUCCESS(BCryptEncrypt(key, (PUCHAR)pt, pt_len, &info,
                                  NULL, 0, ct, *ct_cap, &w, 0))) goto d;
    *ct_cap = w; ok = TRUE;
d:  if (key) BCryptDestroyKey(key); if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static BOOL dec_gcm(const uint8_t *ct, ULONG ct_len, const uint8_t *iv12,
                    const uint8_t *tag16, uint8_t *pt, ULONG *pt_cap) {
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE key = NULL; BOOL ok = FALSE;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto d;
    if (!NT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)), 0))) goto d;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(alg, &key, NULL, 0, SVCLDB_LOG_KEY, 32, 0))) goto d;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)iv12; info.cbNonce = 12;
    info.pbTag   = (PUCHAR)tag16; info.cbTag = 16;
    ULONG w = 0;
    if (!NT_SUCCESS(BCryptDecrypt(key, (PUCHAR)ct, ct_len, &info,
                                  NULL, 0, pt, *pt_cap, &w, 0))) goto d;
    *pt_cap = w; ok = TRUE;
d:  if (key) BCryptDestroyKey(key); if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static void notes_path(char *out, size_t cap) {
    _snprintf(out, cap - 1, "%s\\notes.enc", SVC_INSTALL_DIR);
    out[cap - 1] = 0;
}

/* ── Load / flush ──────────────────────────────────────────────── */
void notes_load(void) {
    ensure_cs();
    if (InterlockedCompareExchange(&g_loaded, 1, 0) != 0) return;
    char path[MAX_PATH]; notes_path(path, sizeof(path));
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    uint8_t buf[NOTES_MAX_BYTES + 64];
    DWORD n = 0;
    BOOL rok = ReadFile(h, buf, sizeof(buf), &n, NULL);
    CloseHandle(h);
    if (!rok || n < 33) return;
    if (*(uint32_t *)(buf + 0) != NOTES_MAGIC || buf[4] != NOTES_VERSION) return;
    uint8_t *iv  = buf + 5;
    uint8_t *tag = buf + 5 + 12;
    uint8_t *ct  = buf + 5 + 12 + 16;
    ULONG    ct_len = n - (5 + 12 + 16);
    if (ct_len == 0 || ct_len > NOTES_MAX_BYTES) return;

    uint8_t pt[NOTES_MAX_BYTES];
    ULONG   pt_len = sizeof(pt);
    if (!dec_gcm(ct, ct_len, iv, tag, pt, &pt_len)) {
        slog_writef("msvc_dbg_a.dat", "notes_load: GCM decrypt failed");
        return;
    }
    if (pt_len > NOTES_MAX_BYTES - 1) pt_len = NOTES_MAX_BYTES - 1;
    EnterCriticalSection(&g_cs);
    memcpy(g_buf, pt, pt_len);
    g_buf[pt_len] = 0;
    g_len = (int)pt_len;
    g_cur = g_len;
    LeaveCriticalSection(&g_cs);
    slog_writef("msvc_dbg_a.dat", "notes_load: %lu bytes loaded", pt_len);
}

void notes_flush(void) {
    ensure_cs();
    if (!InterlockedCompareExchange(&g_dirty, 0, 0)) return;
    char pt[NOTES_MAX_BYTES]; int pt_len = 0;
    EnterCriticalSection(&g_cs);
    pt_len = g_len; if (pt_len > 0) memcpy(pt, g_buf, (size_t)pt_len);
    LeaveCriticalSection(&g_cs);

    if (pt_len == 0) {
        char path[MAX_PATH]; notes_path(path, sizeof(path));
        DeleteFileA(path);
        InterlockedExchange(&g_dirty, 0);
        return;
    }
    uint8_t iv[12], tag[16];
    uint8_t ct[NOTES_MAX_BYTES + 32];
    ULONG   ct_len = sizeof(ct);
    if (!enc_gcm((const uint8_t *)pt, (ULONG)pt_len, iv, tag, ct, &ct_len)) {
        slog_writef("msvc_dbg_a.dat", "notes_flush: encrypt failed");
        return;
    }
    char path[MAX_PATH], tmp[MAX_PATH];
    notes_path(path, sizeof(path));
    _snprintf(tmp, sizeof(tmp) - 1, "%s.tmp", path); tmp[sizeof(tmp) - 1] = 0;
    CreateDirectoryA(SVC_INSTALL_DIR, NULL);
    HANDLE h = CreateFileA(tmp, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { return; }
    uint32_t magic = NOTES_MAGIC; uint8_t ver = NOTES_VERSION; DWORD wr = 0;
    WriteFile(h, &magic, sizeof(magic), &wr, NULL);
    WriteFile(h, &ver,   1,             &wr, NULL);
    WriteFile(h, iv,     12,            &wr, NULL);
    WriteFile(h, tag,    16,            &wr, NULL);
    WriteFile(h, ct,     ct_len,        &wr, NULL);
    CloseHandle(h);
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileA(tmp);
        return;
    }
    InterlockedExchange(&g_dirty, 0);
    slog_writef("msvc_dbg_a.dat", "notes_flush: %d pt -> %lu ct", pt_len, ct_len);
}

void notes_mark_dirty(void) { InterlockedExchange(&g_dirty, 1); }

int  notes_snapshot(char *out, int cap) {
    if (!out || cap <= 0) return 0;
    ensure_cs();
    notes_load();
    EnterCriticalSection(&g_cs);
    int n = g_len; if (n > cap - 1) n = cap - 1;
    if (n > 0) memcpy(out, g_buf, (size_t)n);
    out[n] = 0;
    LeaveCriticalSection(&g_cs);
    return n;
}

/* ── Editor open/close ─────────────────────────────────────────── */
extern void ui_wake_composition_typing(void);
extern void ui_wake_composition(void);
extern char *clip_get_utf8(void);
#define wake_dwm_composition_typing ui_wake_composition_typing
#define wake_dwm_composition        ui_wake_composition

int  notes_editor_is_open(void) {
    return InterlockedCompareExchange((volatile LONG *)&g_editor_open, 0, 0);
}
void notes_editor_toggle(void) {
    ensure_cs();
    notes_load();
    LONG was = InterlockedExchange(&g_editor_open, !g_editor_open);
    slog_writef("msvc_dbg_a.dat", "notes_editor -> %d", (int)!was);
    wake_dwm_composition();
    (void)was;
}
void notes_editor_close_save(void) {
    InterlockedExchange(&g_editor_open, 0);
    notes_flush();
    wake_dwm_composition();
}
void notes_editor_close_no_save(void) {
    InterlockedExchange(&g_editor_open, 0);
    InterlockedExchange(&g_dirty, 0);
    InterlockedExchange(&g_loaded, 0);
    notes_load();
    wake_dwm_composition();
}

/* ── UTF-8 + word helpers (mirror imgui_layer.cpp chat_* helpers) ── */
static int cp_to_u8(unsigned int cp, unsigned char *out) {
    if (cp < 0x80)                    { out[0] = (unsigned char)cp; return 1; }
    if (cp < 0x800)                   { out[0] = 0xC0 | (cp >> 6);      out[1] = 0x80 | (cp & 0x3F); return 2; }
    if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
    if (cp < 0x10000)                 { out[0] = 0xE0 | (cp >> 12);     out[1] = 0x80 | ((cp >> 6) & 0x3F); out[2] = 0x80 | (cp & 0x3F); return 3; }
    if (cp < 0x110000)                { out[0] = 0xF0 | (cp >> 18);     out[1] = 0x80 | ((cp >> 12) & 0x3F); out[2] = 0x80 | ((cp >> 6) & 0x3F); out[3] = 0x80 | (cp & 0x3F); return 4; }
    return 0;
}
static int u8_prev(const char *b, int p) {
    if (p <= 0) return 0; p--;
    while (p > 0 && ((unsigned char)b[p] & 0xC0) == 0x80) p--;
    return p;
}
static int u8_next(const char *b, int len, int p) {
    if (p >= len) return len; p++;
    while (p < len && ((unsigned char)b[p] & 0xC0) == 0x80) p++;
    return p;
}
static int is_word_b(unsigned char b) {
    if (b >= '0' && b <= '9') return 1;
    if (b >= 'A' && b <= 'Z') return 1;
    if (b >= 'a' && b <= 'z') return 1;
    if (b == '_') return 1;
    if (b >= 0x80) return 1;
    return 0;
}

/* ── Character/edit feeds ──────────────────────────────────────── */
#define GUARD_OPEN() do { if (!notes_editor_is_open()) return; } while (0)

void notes_feed_char(unsigned int cp) {
    GUARD_OPEN(); ensure_cs();
    unsigned char enc[4]; int n = cp_to_u8(cp, enc);
    if (n <= 0) return;
    EnterCriticalSection(&g_cs);
    if (g_len + n < NOTES_MAX_BYTES - 1) {
        int tail = g_len - g_cur;
        if (tail > 0) memmove(g_buf + g_cur + n, g_buf + g_cur, (size_t)tail);
        memcpy(g_buf + g_cur, enc, n);
        g_len += n; g_cur += n; g_buf[g_len] = 0;
        InterlockedExchange(&g_dirty, 1);
    }
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_feed_backspace(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_cur > 0) {
        int nc = u8_prev(g_buf, g_cur);
        int gap = g_cur - nc, tail = g_len - g_cur;
        if (tail > 0) memmove(g_buf + nc, g_buf + g_cur, (size_t)tail);
        g_len -= gap; g_cur = nc; g_buf[g_len] = 0;
        InterlockedExchange(&g_dirty, 1);
    }
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_feed_delete(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_cur < g_len) {
        int ne = u8_next(g_buf, g_len, g_cur);
        int gap = ne - g_cur, tail = g_len - ne;
        if (tail > 0) memmove(g_buf + g_cur, g_buf + ne, (size_t)tail);
        g_len -= gap; g_buf[g_len] = 0;
        InterlockedExchange(&g_dirty, 1);
    }
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_feed_newline(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    if (g_len + 1 < NOTES_MAX_BYTES - 1) {
        int tail = g_len - g_cur;
        if (tail > 0) memmove(g_buf + g_cur + 1, g_buf + g_cur, (size_t)tail);
        g_buf[g_cur] = '\n';
        g_len += 1; g_cur += 1; g_buf[g_len] = 0;
        InterlockedExchange(&g_dirty, 1);
    }
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_feed_clipboard_paste(void) {
    GUARD_OPEN();
    char *cb = clip_get_utf8();
    if (!cb) return;
    int in = 0, out = 0;
    for (; cb[in]; in++) {
        if (cb[in] == '\r') { if (cb[in+1] == '\n') continue; cb[out++] = '\n'; }
        else cb[out++] = cb[in];
    }
    cb[out] = 0;
    int plen = out;
    if (plen <= 0) { free(cb); return; }
    ensure_cs();
    EnterCriticalSection(&g_cs);
    int room = NOTES_MAX_BYTES - 1 - g_len;
    if (room < 0) room = 0;
    int copy = (plen < room) ? plen : room;
    while (copy > 0 && ((unsigned char)cb[copy] & 0xC0) == 0x80) copy--;
    if (copy > 0) {
        int tail = g_len - g_cur;
        if (tail > 0) memmove(g_buf + g_cur + copy, g_buf + g_cur, (size_t)tail);
        memcpy(g_buf + g_cur, cb, (size_t)copy);
        g_len += copy; g_cur += copy; g_buf[g_len] = 0;
        InterlockedExchange(&g_dirty, 1);
    }
    LeaveCriticalSection(&g_cs);
    free(cb);
    wake_dwm_composition_typing();
}
void notes_feed_word_backspace(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    int p = g_cur;
    while (p > 0 && !is_word_b((unsigned char)g_buf[p-1])) p--;
    while (p > 0 &&  is_word_b((unsigned char)g_buf[p-1])) p--;
    if (p < g_cur) {
        int gap = g_cur - p, tail = g_len - g_cur;
        if (tail > 0) memmove(g_buf + p, g_buf + g_cur, (size_t)tail);
        g_len -= gap; g_cur = p; g_buf[g_len] = 0;
        InterlockedExchange(&g_dirty, 1);
    }
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_feed_word_delete(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    int p = g_cur;
    while (p < g_len &&  is_word_b((unsigned char)g_buf[p])) p++;
    while (p < g_len && !is_word_b((unsigned char)g_buf[p])) p++;
    if (p > g_cur) {
        int gap = p - g_cur, tail = g_len - p;
        if (tail > 0) memmove(g_buf + g_cur, g_buf + p, (size_t)tail);
        g_len -= gap; g_buf[g_len] = 0;
        InterlockedExchange(&g_dirty, 1);
    }
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_cursor_left(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs); g_cur = u8_prev(g_buf, g_cur); LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_cursor_right(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs); g_cur = u8_next(g_buf, g_len, g_cur); LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_cursor_home(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    while (g_cur > 0 && g_buf[g_cur - 1] != '\n') g_cur--;
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_cursor_end(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    while (g_cur < g_len && g_buf[g_cur] != '\n') g_cur++;
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_cursor_word_left(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    int p = g_cur;
    while (p > 0 && !is_word_b((unsigned char)g_buf[p-1])) p--;
    while (p > 0 &&  is_word_b((unsigned char)g_buf[p-1])) p--;
    g_cur = p;
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_cursor_word_right(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    int p = g_cur;
    while (p < g_len &&  is_word_b((unsigned char)g_buf[p])) p++;
    while (p < g_len && !is_word_b((unsigned char)g_buf[p])) p++;
    g_cur = p;
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_cursor_up(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    /* Row start / prev-row start */
    int rs = g_cur; while (rs > 0 && g_buf[rs - 1] != '\n') rs--;
    if (rs == 0) { g_cur = 0; }
    else {
        int col = g_cur - rs;
        int prs = rs - 1;
        int pss = prs; while (pss > 0 && g_buf[pss - 1] != '\n') pss--;
        int prl = prs - pss;
        int nc  = (col < prl) ? col : prl;
        while (nc > 0 && ((unsigned char)g_buf[pss + nc] & 0xC0) == 0x80) nc--;
        g_cur = pss + nc;
    }
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}
void notes_cursor_down(void) {
    GUARD_OPEN(); ensure_cs();
    EnterCriticalSection(&g_cs);
    int rs = g_cur; while (rs > 0 && g_buf[rs - 1] != '\n') rs--;
    int re = g_cur; while (re < g_len && g_buf[re] != '\n') re++;
    if (re == g_len) { g_cur = g_len; }
    else {
        int col = g_cur - rs;
        int nrs = re + 1;
        int nre = nrs; while (nre < g_len && g_buf[nre] != '\n') nre++;
        int nrl = nre - nrs;
        int nc  = (col < nrl) ? col : nrl;
        while (nc > 0 && ((unsigned char)g_buf[nrs + nc] & 0xC0) == 0x80) nc--;
        g_cur = nrs + nc;
    }
    LeaveCriticalSection(&g_cs);
    wake_dwm_composition_typing();
}

int notes_render_snapshot(char *out, int cap, int *cursor_out) {
    if (!out || cap <= 0) { if (cursor_out) *cursor_out = 0; return 0; }
    ensure_cs();
    notes_load();
    EnterCriticalSection(&g_cs);
    int n = g_len; if (n > cap - 1) n = cap - 1;
    if (n > 0) memcpy(out, g_buf, (size_t)n);
    out[n] = 0;
    if (cursor_out) *cursor_out = (g_cur > n) ? n : g_cur;
    LeaveCriticalSection(&g_cs);
    return n;
}
