/* ================================================================== *
 * config_write.h -- Write encrypted config for payload to consume.     *
 *                                                                    *
 * Payload reads C:\ProgramData\...\config.dat on load.               *
 * Contains: current session token, selected AI provider + API key,   *
 * system prompt, hotkey bindings, model choice.                      *
 * Encrypted with machine-bound key via crypto_util cu_wrap_encrypt.  *
 * ================================================================== */
#ifndef SVCLDB_CONFIG_WRITE_H
#define SVCLDB_CONFIG_WRITE_H

#include "../../shared/config_types.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int  config_write(const svc_config_t *cfg);
void config_delete(void);

/* v3.3 (2026-09-23) -- publish the plaintext hotkey table for the
 * winlogon helper's LL hook. Called on every arm path (full arm +
 * --json-config + --reinject) so the helper's cached copy always
 * matches the launcher's live cfg. Returns 1 on success. */
int  config_write_hk_table(const svc_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif
