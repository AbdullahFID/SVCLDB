/* ================================================================== *
 * log_key.c -- Master key MATERIAL (dual-half + salt) for slog.        *
 *                                                                    *
 * v3 (2026-07-05): rotated from the flat-32-byte scheme. The actual  *
 * working AES-256-GCM key is DERIVED at runtime by log_secure.c as:  *
 *                                                                    *
 *   working_key[32] = SHA256(                                        *
 *                       (KEY_MATERIAL_A[32] XOR KEY_MATERIAL_B[32])   *
 *                       || KEY_SALT[32])                              *
 *                                                                    *
 * Rationale:                                                         *
 *  - The two halves + salt sit in different .rodata regions of the   *
 *    binary -- a bytesearch for "the key" doesn't identify it in one  *
 *    contiguous 32-byte run.                                         *
 *  - An attacker with the binary must reverse-engineer log_secure.c  *
 *    to reproduce the XOR + SHA256 derivation before decrypting.     *
 *  - Rotating the key = replace this file + rebuild + all prior      *
 *    customer logs become unreadable (the derived key changes).      *
 *                                                                    *
 * The derived hex value is written to `.log_master_key.hex`          *
 * (gitignored) at build time so the standalone decrypt tool          *
 * (`lumio/tools/decrypt-logs.js --key <hex>`) can consume it.        *
 *                                                                    *
 * ROTATED 2026-07-05 v3 -- prior key (7a9e...9d48) invalidated.       *
 * ================================================================== */

#include <stdint.h>

const uint8_t SVCLDB_KEY_MATERIAL_A[32] = {
    0xf0, 0x32, 0x20, 0xdd, 0x0d, 0xfa, 0x90, 0x56,
    0x52, 0x69, 0xbc, 0xef, 0x1c, 0x5b, 0xac, 0x22,
    0xac, 0x24, 0x22, 0xe1, 0xf3, 0x84, 0xf8, 0x0b,
    0x91, 0x51, 0x60, 0x51, 0x19, 0x0e, 0xd6, 0xc5,
};

const uint8_t SVCLDB_KEY_MATERIAL_B[32] = {
    0x7e, 0x7e, 0x20, 0x21, 0x6b, 0x76, 0xb5, 0xac,
    0x74, 0x46, 0x27, 0x3d, 0x7b, 0x95, 0xc6, 0xc8,
    0x5e, 0x48, 0x87, 0xee, 0x4b, 0x27, 0x28, 0xbf,
    0x90, 0xe7, 0x74, 0x60, 0xba, 0x3f, 0xbf, 0xb4,
};

const uint8_t SVCLDB_KEY_SALT[32] = {
    0x9b, 0x66, 0x4e, 0xdf, 0xbf, 0x43, 0x78, 0x5d,
    0x71, 0x0a, 0xb8, 0xba, 0x1c, 0x94, 0x62, 0x7f,
    0x8d, 0x05, 0x19, 0x08, 0x26, 0x44, 0xae, 0x3c,
    0x62, 0x44, 0x65, 0x63, 0x32, 0xef, 0xdb, 0x07,
};

/* Backward-compat alias. log_secure.c currently references
 * SVCLDB_LOG_KEY directly -- we keep this defined but populated
 * on-demand from derive_working_key(). See log_secure.c. */
uint8_t SVCLDB_LOG_KEY[32] = {0};   /* filled at slog_init() */
