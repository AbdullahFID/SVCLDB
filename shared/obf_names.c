/* ================================================================== *
 * obf_names.c -- see obf_names.h for the full rationale.               *
 *                                                                    *
 * Derivation (MUST match ui/src/lib/obf-names.js byte-for-byte):      *
 *   guid_lower = lowercase(trim(MachineGuid))   ; HKLM Cryptography    *
 *   digest     = SHA256( salt || ":" || guid_lower )   ; ASCII bytes   *
 *   name_guid  = hex(digest[0..15]) grouped 8-4-4-4-12 (lowercase)    *
 *   full       = <prefix> + name_guid                                 *
 * ================================================================== */
#include "common.h"
#include "obf_names.h"

#include <bcrypt.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

/* ── Per-purpose salts. Deliberately opaque + NON-identifying (they
 * land in the binary as plaintext hash inputs, so they must NOT
 * contain "svcldb"/"cloakgpt"/etc). Changing any salt changes that
 * object's name on every box -- keep in lockstep with obf-names.js. */
#define SALT_PIPE_TOKEN   "wasvc.pipe.token.1"
#define SALT_PIPE_OCR     "wasvc.pipe.ocr.1"
#define SALT_MTX_INIT     "wasvc.mtx.init.1"
#define SALT_MTX_OCRD     "wasvc.mtx.ocrd.1"
#define SALT_EVT_SHUT     "wasvc.evt.shut.1"
/* v3.0.2.4 (2026-09-21) -- iso-desktop input plumbing. Same GUID-per-
 * install treatment as the Default-desktop pipes, so a non-admin
 * enumeration of \\.\pipe\* + \BaseNamedObjects sees only GUID-named
 * objects statistically indistinguishable from Windows/COM/RPC pipes.
 * Salts MUST match the copies in tools/redteam/probes/wl_input.c. */
#define SALT_PIPE_ISO      "wasvc.pipe.iso.1"
#define SALT_EVT_ISO_HALT  "wasvc.evt.iso.halt.1"
#define SALT_EVT_ISO_CHAT  "wasvc.evt.iso.chat.1"
#define SALT_CLS_ISO_INPUT "wasvc.cls.iso.input.1"

/* Fallback machine key used only if the registry read fails. Both C
 * and JS use this SAME literal so the endpoints still agree in the
 * degenerate case (keeps IPC + status probe functional). */
#define OBF_FALLBACK_GUID "3b1e9c27-1d54-4a8f-9e2b-7c6a0f5d84b1"

/* Read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, lowercased +
 * trimmed. Returns 1 on success. Mirrors hwid.c's reader but kept
 * local so obf_names has no link dependency on hwid.c (the payload
 * build does not compile hwid.c). */
static int read_machine_guid_lower(char *out, unsigned outsize) {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, sz = outsize;
    LONG r = RegQueryValueExA(k, "MachineGuid", NULL, &type, (LPBYTE)out, &sz);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_SZ) return 0;
    while (sz > 0 && (out[sz - 1] == '\0' || out[sz - 1] == '\r' ||
                      out[sz - 1] == '\n' || out[sz - 1] == ' ' ||
                      out[sz - 1] == '\t'))
        sz--;
    if (sz == 0) return 0;
    if (sz >= outsize) sz = outsize - 1;
    out[sz] = '\0';
    for (unsigned i = 0; i < sz; i++) {
        char c = out[i];
        if (c >= 'A' && c <= 'Z') out[i] = (char)(c - 'A' + 'a');
    }
    return 1;
}

/* SHA-256(salt || ":" || guid_lower) -> first 16 bytes -> canonical
 * lowercase GUID into `out` (needs >= 37 bytes). Returns 1 on success. */
static int derive_guid(const char *salt, char *out, unsigned outsize) {
    if (outsize < 37) return 0;

    char guid[80];
    if (!read_machine_guid_lower(guid, sizeof(guid))) {
        strncpy(guid, OBF_FALLBACK_GUID, sizeof(guid) - 1);
        guid[sizeof(guid) - 1] = '\0';
    }

    BCRYPT_ALG_HANDLE alg = NULL;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                NULL, 0)))
        return 0;
    BCRYPT_HASH_HANDLE h = NULL;
    if (!NT_SUCCESS(BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return 0;
    }
    static const char sep[1] = { ':' };
    BCryptHashData(h, (PUCHAR)salt, (ULONG)strlen(salt), 0);
    BCryptHashData(h, (PUCHAR)sep, 1, 0);
    BCryptHashData(h, (PUCHAR)guid, (ULONG)strlen(guid), 0);

    UCHAR d[32];
    NTSTATUS fs = BCryptFinishHash(h, d, sizeof(d), 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(fs)) return 0;

    _snprintf(out, outsize - 1,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
        d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
    out[outsize - 1] = '\0';
    /* zero the derived digest + guid material we no longer need */
    svc_secure_zero(d, sizeof(d));
    svc_secure_zero(guid, sizeof(guid));
    return 1;
}

/* Build "<prefix><guid>" into a caller-owned static buffer once.
 * `cached[0]` acts as the init sentinel. */
static const char *cached_name(char *cached, unsigned cachesize,
                               const char *prefix, const char *salt) {
    if (cached[0] != '\0') return cached;
    char guid[40] = {0};
    if (!derive_guid(salt, guid, sizeof(guid))) {
        /* Absolute last resort -- format the fallback constant so the
         * two IPC ends still agree. Should never happen (BCrypt on
         * a static input). */
        strncpy(guid, OBF_FALLBACK_GUID, sizeof(guid) - 1);
    }
    _snprintf(cached, cachesize - 1, "%s%s", prefix, guid);
    cached[cachesize - 1] = '\0';
    return cached;
}

const char *obf_pipe_token(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "\\\\.\\pipe\\", SALT_PIPE_TOKEN);
}

const char *obf_pipe_ocr(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "\\\\.\\pipe\\", SALT_PIPE_OCR);
}

const char *obf_mutex_initguard(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "Local\\", SALT_MTX_INIT);
}

const char *obf_mutex_ocrdaemon(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "Global\\", SALT_MTX_OCRD);
}

const char *obf_event_shutdown(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "Global\\", SALT_EVT_SHUT);
}

/* ── v3.0.2.4 (2026-09-21) iso-desktop names ───────────────────────
 * Same GUID-per-install treatment as the Default-desktop pipes.
 * MUST match the inline derivation in tools/redteam/probes/wl_input.c
 * (the helper is manual-mapped + self-contained, so it re-derives
 * from the same salts + MachineGuid input). */
const char *obf_pipe_iso(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "\\\\.\\pipe\\", SALT_PIPE_ISO);
}
const char *obf_event_iso_halt(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "Global\\", SALT_EVT_ISO_HALT);
}
const char *obf_event_iso_chat(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "Global\\", SALT_EVT_ISO_CHAT);
}
/* Class names have NO prefix (raw GUID); a plain lowercase-GUID class
 * looks like a random Windows registered class atom (there are dozens
 * in a live session). */
const char *obf_class_iso_input(void) {
    static char buf[64] = {0};
    return cached_name(buf, sizeof(buf), "", SALT_CLS_ISO_INPUT);
}
