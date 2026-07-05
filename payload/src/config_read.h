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

/* Securely zero cached config. Called on payload shutdown. */
void cfg_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
