#ifndef SVCLDB_CONFIG_READ_H
#define SVCLDB_CONFIG_READ_H

#include "../../shared/config_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Read + decrypt config file. Returns 1 on success. */
int  cfg_read(svc_config_t *out);

/* Cache-accessing variant. First call loads; subsequent return the cached copy. */
const svc_config_t *cfg_get(void);

/* v14 (2026-08-24) — Update ONLY the access_token field in the cached
 * config. Used by token_refresh_server.c's pipe handler to receive
 * fresh JWTs from Electron mid-session, so sub_check.c doesn't hit
 * 401 on expired tokens. Thread-safe under the config CS. Returns 1
 * on success; 0 if the config isn't loaded yet or the input is
 * invalid (empty / too long / NULL). All other cfg fields are left
 * untouched — this is not a full re-read. */
int  cfg_update_access_token(const char *new_token, size_t new_len);

/* Securely zero cached config. Called on payload shutdown. */
void cfg_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
