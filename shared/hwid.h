/* ================================================================== *
 * hwid.h — Hardware ID derivation.                                    *
 *                                                                    *
 * Mirrors main app's lumio/src/license/device.js. Same fallback     *
 * chain so a session signed against the main app can (in theory)     *
 * be validated by us too — though we bind to different backends so   *
 * this is more about consistent HWID than session interop.           *
 * ================================================================== */
#ifndef SVCLDB_HWID_H
#define SVCLDB_HWID_H

#ifdef __cplusplus
extern "C" {
#endif

/* Fills out with UUID string (up to 64 chars incl NUL).
 * Order:
 *   1. SMBIOS UUID via wmic csproduct (matches device.js primary path)
 *   2. HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid (fallback #1)
 *   3. SHA-256(computer_name || volume_c_serial) → formatted as UUID (fallback #2)
 * Returns 1 on success, 0 on failure (out unchanged).
 */
int hwid_get(char *out, unsigned outsize);

/* Cached variant. First call runs hwid_get + caches; subsequent
 * calls copy from cache. Cache is per-process, cleared on exit. */
int hwid_get_cached(char *out, unsigned outsize);

#ifdef __cplusplus
}
#endif

#endif
