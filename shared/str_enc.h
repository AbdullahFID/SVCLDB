/* ================================================================== *
 * str_enc.h -- Runtime XOR-decryption of "smoking-gun" strings.        *
 *                                                                    *
 * Motivation: even after Astral-PE metadata scrub, the .rdata        *
 * section of dwmapiext.dll leaks ~128 identifying strings that a     *
 * 30-second `strings` sweep reveals -- product name, ProgramData      *
 * paths, named events, hook function names, model names, error       *
 * messages, etc. Analysts use these as the FIRST triage step.        *
 *                                                                    *
 * Fix: XOR-encrypt each smoking-gun string at build time and write   *
 * the encrypted blob into .rdata. At DllMain time, XOR back in-place  *
 * so runtime code sees plaintext. Analyst sees garbage in `strings`  *
 * but a memory dump of the running process still shows plaintext --   *
 * that's a tradeoff: static analysis becomes MUCH harder, dynamic    *
 * analysis is unaffected. Since this project's real threat is        *
 * static RE / theft (not runtime EDR), this is the right tradeoff.   *
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
 *   4. Decryption happens IN-PLACE on the blob -- after init the blob  *
 *      contains plaintext. No allocation, no thread-local buffers.   *
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

/* Decrypt the entire blob in-place. Idempotent -- safe to call multiple
 * times, subsequent calls become no-ops via an internal flag. */
void svc_str_init(void);

/* Retrieve the decrypted string at the given index. If svc_str_init()
 * has not yet been called, this triggers it lazily (so callers don't
 * have to worry about init ordering during early boot). */
const char *svc_str(int idx);

/* Convenience macro -- shorter at call sites. Equivalent to svc_str(x). */
#define SS(x)  svc_str(x)

#ifdef __cplusplus
}
#endif

#endif /* SVCLDB_STR_ENC_H */
