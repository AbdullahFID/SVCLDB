/* ================================================================== *
 * str_enc.c -- Runtime XOR-decryption of the encrypted string blob.   *
 *                                                                    *
 * See str_enc.h for the full design rationale.                        *
 * ================================================================== */

#include "str_enc.h"
#include <windows.h>

/* g_svc_enc_blob[] + g_svc_enc_table[] definitions live in the auto-
 * generated data companion. Included exactly once (from this .c file).
 * The header declares extern; this include supplies the actual bytes. */
#include "str_enc_generated_data.h"

static volatile LONG g_str_init_done = 0;

/* Per-index XOR key. Matches the generator in gen_str_enc.ps1 exactly.
 * Simple mixing so patterns don't repeat across strings -- a "known
 * plaintext" attack on one string doesn't help with another (different
 * len -> different key stream). Not cryptographic; just enough to defeat
 * `strings`, grep, and pattern-based binary diffing. */
static unsigned char _svc_key_byte(size_t idx, size_t len) {
    return (unsigned char)(((idx * 37) + (len * 91) + SVC_STR_KEY_MIX) & 0xFF);
}

void svc_str_init(void) {
    /* InterlockedCompareExchange to make this thread-safe + idempotent.
     * Payload's DllMain is called before any thread we spawn ourselves,
     * but the launcher's main() is single-threaded so both are safe. */
    if (InterlockedCompareExchange(&g_str_init_done, 1, 0) != 0) return;

    /* The blob lives in .rdata by default (const-qualified). Flip its
     * page to PAGE_READWRITE so we can XOR in place, then flip back to
     * PAGE_READONLY when done. Without this the XOR triggers a write-
     * to-readonly-memory access violation.
     *
     * VirtualProtect only affects the current process, and the blob is
     * process-local, so no cross-process concerns. */
    DWORD old_prot = 0;
    if (!VirtualProtect((LPVOID)g_svc_enc_blob, sizeof(g_svc_enc_blob),
                        PAGE_READWRITE, &old_prot)) {
        /* v2.0 (2026-09-10) -- Permanently failed. DO NOT reset g_str_init_done
         * to 0. Pre-fix: on VirtualProtect failure this reset the flag,
         * which let a second thread see 0, race in, retry VirtualProtect
         * (which may now succeed), and XOR the blob a SECOND time. XOR
         * twice restores the ENCRYPTED form -> every SS() lookup returns
         * garbage bytes after that point. Since VirtualProtect on our own
         * .rdata page is extraordinarily unlikely to fail, giving up
         * permanently (state=3) is safer than an ambiguous retry that
         * can silently corrupt the whole string table. Post-failure,
         * svc_str() will return the still-encrypted blob (visible-garbage
         * failure mode, per the design intent noted below). */
        InterlockedExchange(&g_str_init_done, 3);
        return;
    }

    /* Walk the table + XOR each string range with its per-index key. */
    for (int i = 0; i < SVC_STR_COUNT; i++) {
        size_t offset = g_svc_enc_table[i].offset;
        size_t length = g_svc_enc_table[i].length;
        unsigned char *p = (unsigned char *)&g_svc_enc_blob[offset];
        for (size_t j = 0; j < length; j++) {
            p[j] ^= _svc_key_byte(j, length);
        }
    }

    /* Flip back to read-only so a post-init memory scanner that flags
     * "writable code / data regions" doesn't see this as writable. */
    VirtualProtect((LPVOID)g_svc_enc_blob, sizeof(g_svc_enc_blob),
                   old_prot, &old_prot);
}

const char *svc_str(int idx) {
    if (idx < 0 || idx >= SVC_STR_COUNT) return "";
    /* Lazy init -- cheap after first call (single Interlocked load). */
    if (!g_str_init_done) svc_str_init();
    return &g_svc_enc_blob[g_svc_enc_table[idx].offset];
}
