/* ================================================================== *
 * str_enc.h -- Runtime XOR-decryption of "smoking-gun" strings.        *
 *                                                                    *
 * Motivation: even after Astral-PE metadata scrub, the .rdata        *
 * section of dwmapiext.dll leaks ~128 identifying strings that a     *
 * 30-second `strings` sweep reveals -- product name, ProgramData      *
 * paths, named events, hook function names, model names, error       *
 * messages, etc. Analysts use these as the FIRST triage step.        *
 *                                                                    *
 * Fix (v3.1 transient ring): XOR-encrypt each smoking-gun string at   *
 * build time into a CONST .rdata blob that stays ENCRYPTED at rest    *
 * for the whole process lifetime. svc_str() decrypts ON DEMAND into a *
 * small rotating scratch ring, returns a pointer, and the slot is     *
 * SecureZeroMemory'd again within ~600 ms (opportunistically on the   *
 * next svc_str() call + periodically via svc_str_scrub_idle() driven  *
 * from the 60 Hz poll_thread). Result: `strings` sees only garbage    *
 * AND an admin OpenProcess(dwm,VM_READ) memory grep at steady state   *
 * finds NONE of our vocabulary -- only the handful of strings touched *
 * in the last ~600 ms are ever plaintext anywhere. Defeats BOTH the   *
 * static `strings` sweep and the runtime memory grep. See str_enc.c   *
 * for the full contract (returned pointer is valid only until used).  *
 *                                                                    *
 * Implementation:                                                     *
 *   1. `strings.list` (kept in `scripts/`) enumerates every string   *
 *      we want encrypted, one per line, with a matching enum name.   *
 *   2. `scripts/gen_str_enc.ps1` reads that list, XOR-encrypts each  *
 *      string with a per-index rotating key, and emits                *
 *      `shared/str_enc_generated.h` (an enum + `g_enc_blob[]` +       *
 *      offset/length table + xor key macro).                          *
 *   3. This header exposes `svc_str(SVC_STR_XXX)` returning a         *
 *      `const char *` to the decrypted string. Call `svc_str_init()`  *
 *      ONCE from DllMain (payload) or main() (launcher) before any    *
 *      logging code runs.                                             *
 *   4. Decryption happens ON DEMAND into a transient scratch ring --  *
 *      the blob stays ciphertext at rest; no bulk in-place decrypt.   *
 *                                                                    *
 * The generated file is committed to the repo (not built each time)  *
 * so incremental rebuilds are fast; only re-run gen_str_enc.ps1      *
 * when strings.list changes.                                          *
 * ================================================================== */
#ifndef SVCLDB_STR_ENC_H
#define SVCLDB_STR_ENC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Enum of every encrypted string. Populated by gen_str_enc.ps1 into
 * str_enc_generated.h. */
#include "str_enc_generated.h"

/* One-time init: zeroes the transient scratch ring. Idempotent, cheap.
 * The blob itself stays ENCRYPTED at rest -- there is no bulk decrypt.
 * Kept for API/init-ordering compatibility with existing callers. */
void svc_str_init(void);

/* Retrieve the decrypted string at the given index. The returned pointer
 * is valid ONLY until you have consumed it (copied it, or handed it to a
 * function that copies -- slog_write/_snprintf/strncpy/resolve all do).
 * It points into a rotating scratch ring that is scrubbed within
 * ~600 ms; do NOT stash it across a Sleep, a network call, or a long
 * chain of other svc_str() calls. Need a longer lifetime? _snprintf it
 * into your own buffer first (see ai_provider.c header construction). */
const char *svc_str(int idx);

/* Scrub ring slots whose last use is older than the transient window.
 * Drive this from an existing always-running loop (the payload's 60 Hz
 * hotkey poll_thread) so steady-state process memory holds ZERO of our
 * decrypted strings -- defeats an admin runtime memory grep, not just a
 * static `strings` sweep. Safe to call from any thread at any rate. */
void svc_str_scrub_idle(void);

/* Force-scrub every slot regardless of age. Call before cooperative
 * unload so no decrypted fragment survives after our threads stop. */
void svc_str_scrub_all(void);

/* Convenience macro -- shorter at call sites. Equivalent to svc_str(x). */
#define SS(x)  svc_str(x)

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_STR_ENC_H */
