/* ================================================================== *
 * str_enc.c -- Transient (poof-gone) decryption of the string blob.   *
 *                                                                    *
 * See str_enc.h for the full design rationale.                        *
 *                                                                    *
 * v3.1 (2026-09-19) -- THREAT-MODEL UPGRADE: runtime memory scan.     *
 *                                                                    *
 * The original design XOR-decrypted the whole blob IN PLACE at init.  *
 * That defeats a static `strings dwmapiext.dll` sweep but does NOTHING *
 * against an admin who OpenProcess(dwm, VM_READ) + greps live memory:  *
 * after init every smoking-gun string sat in .rdata as permanent      *
 * plaintext. Our real adversary (a proctor/hunter with admin) does     *
 * exactly that memory grep, and it was finding peb_unlink, hooks_*,    *
 * handshake:, sub_check:, the AI URLs, etc. all in cleartext.          *
 *                                                                    *
 * NEW MODEL: the blob stays ENCRYPTED at rest for the whole process    *
 * lifetime. svc_str() decrypts ON DEMAND into a small rotating ring of *
 * scratch slots, returns a pointer, and the slot is SecureZeroMemory'd *
 * again shortly after (opportunistically on the next svc_str() call,   *
 * and periodically via svc_str_scrub_idle() driven from an existing    *
 * always-running loop -- the payload's 60 Hz hotkey poll_thread).      *
 *                                                                    *
 * Consequence: at any instant only the handful of strings touched in   *
 * the last ~600 ms are plaintext anywhere in memory. During an exam    *
 * (steady state, nothing being logged) the ring is fully scrubbed ->   *
 * an admin memory grep for our vocabulary comes up EMPTY. The window   *
 * is bounded to the transient decrypt-use-scrub interval.              *
 *                                                                    *
 * Contract for callers: treat svc_str()'s return as VALID ONLY UNTIL   *
 * you have consumed it (copied it, or passed it to a function that     *
 * copies it -- slog_write/_snprintf/strncpy/resolve all do). Do NOT    *
 * stash the pointer across a long-lived operation (a network call, a   *
 * Sleep). Every current call site obeys this. If you need a string to  *
 * outlive the immediate expression, _snprintf it into your own buffer  *
 * (see ai_provider.c's per-provider header construction).              *
 * ================================================================== */

#include "str_enc.h"
#include <windows.h>

/* g_svc_enc_blob[] (ciphertext, const/read-only) + g_svc_enc_table[]
 * live in the auto-generated data companion. Included exactly once. */
#include "str_enc_generated_data.h"

/* --- Ring of transient scratch slots ---------------------------------
 * Power-of-two slot count so the round-robin index is a cheap mask.
 * SLOT_CAP bounds the longest decrypted string (+ NUL). Longest entry
 * in strings.list is well under this; _decrypt_into clamps as a belt-
 * and-braces guard so an over-long entry truncates instead of overruns. */
#define SVC_STR_RING_SLOTS   64u
#define SVC_STR_SLOT_CAP     512u
#define SVC_STR_SCRUB_MS     600ull   /* wipe a slot this long after last touch */

static char               g_ring[SVC_STR_RING_SLOTS][SVC_STR_SLOT_CAP];
static volatile ULONGLONG g_ring_touch[SVC_STR_RING_SLOTS];  /* GetTickCount64 of last write; 0 == clean */
static volatile LONG      g_ring_next = 0;

/* Per-index XOR key. MUST match the generator (gen_str_enc.ps1) exactly:
 *   key = ((byte_index * 37) + (str_length * 91) + KEY_MIX) & 0xFF
 * Simple position/length mixing so a known-plaintext break on one string
 * gives no leverage on any other (different length -> different keystream). */
static unsigned char _svc_key_byte(size_t idx, size_t len) {
    return (unsigned char)(((idx * 37u) + (len * 91u) + SVC_STR_KEY_MIX) & 0xFFu);
}

/* Decrypt table entry `idx` into `dst` (capacity SVC_STR_SLOT_CAP). */
static void _decrypt_into(int idx, char *dst) {
    size_t off  = g_svc_enc_table[idx].offset;
    size_t len  = g_svc_enc_table[idx].length;
    size_t klen = len;                        /* keystream uses the TRUE length */
    if (len > SVC_STR_SLOT_CAP - 1u) len = SVC_STR_SLOT_CAP - 1u;   /* clamp */
    const unsigned char *src = (const unsigned char *)&g_svc_enc_blob[off];
    for (size_t j = 0; j < len; j++)
        dst[j] = (char)(src[j] ^ _svc_key_byte(j, klen));
    dst[len] = 0;
}

/* Zero any slot whose last touch is older than SVC_STR_SCRUB_MS. Safe to
 * call from any thread / any frequency. Cheap: 64 timestamp compares.
 * Called opportunistically from svc_str() and periodically from the
 * payload's poll_thread so steady-state memory holds no plaintext. */
void svc_str_scrub_idle(void) {
    ULONGLONG now = GetTickCount64();
    for (unsigned i = 0; i < SVC_STR_RING_SLOTS; i++) {
        ULONGLONG t = g_ring_touch[i];
        if (t == 0) continue;                                   /* already clean */
        if ((now - t) >= SVC_STR_SCRUB_MS) {
            SecureZeroMemory(g_ring[i], SVC_STR_SLOT_CAP);
            g_ring_touch[i] = 0;
        }
    }
}

/* Force-scrub every slot regardless of age. Call before cooperative
 * unload so no decrypted fragment lingers after our threads stop. */
void svc_str_scrub_all(void) {
    for (unsigned i = 0; i < SVC_STR_RING_SLOTS; i++) {
        SecureZeroMemory(g_ring[i], SVC_STR_SLOT_CAP);
        g_ring_touch[i] = 0;
    }
}

/* No blob decryption happens here any more (blob is decrypt-on-demand).
 * Retained for API/init-ordering compatibility: zero the ring so a slot
 * never returns uninitialized garbage before its first real use. */
void svc_str_init(void) {
    static volatile LONG done = 0;
    if (InterlockedCompareExchange(&done, 1, 0) != 0) return;
    svc_str_scrub_all();
}

const char *svc_str(int idx) {
    if (idx < 0 || idx >= SVC_STR_COUNT) return "";
    /* Opportunistic scrub keeps the ring clean even in processes with no
     * external periodic scrubber (launcher/resolver). */
    svc_str_scrub_idle();
    /* Atomic round-robin slot pick. */
    LONG slot = (InterlockedIncrement(&g_ring_next) - 1) & (LONG)(SVC_STR_RING_SLOTS - 1u);
    /* Touch FIRST so a concurrent scrub_idle sees a fresh slot and skips
     * it, then recycle (scrub stale plaintext) + decrypt fresh. */
    g_ring_touch[slot] = GetTickCount64();
    SecureZeroMemory(g_ring[slot], SVC_STR_SLOT_CAP);
    _decrypt_into(idx, g_ring[slot]);
    return g_ring[slot];
}
