/* ================================================================== *
 * log_key.c — 32-byte AES-256 master key for slog_write.              *
 *                                                                    *
 * NOTE — this file is intentionally committed with a HARDCODED key   *
 * for the initial development build. Before shipping to customers,   *
 * regenerate via:                                                    *
 *   cd svcldb && python3 gen_key.py > shared/log_key.c               *
 * (which produces a fresh 32-byte random key and rewrites this file).*
 *                                                                    *
 * Rotating the key invalidates every prior log the customer sent us. *
 * ================================================================== */

#include <stdint.h>

/* Generated 2026-07-04, deterministic dev key so team can decrypt. */
const uint8_t SVCLDB_LOG_KEY[32] = {
    0x7a, 0x9e, 0x14, 0x3b, 0x62, 0x8c, 0xd1, 0x05,
    0xf7, 0x2a, 0x4b, 0x91, 0xc6, 0x08, 0x5d, 0xea,
    0x33, 0x71, 0xbf, 0x02, 0x88, 0x4e, 0xd3, 0x1a,
    0x66, 0xa9, 0x0c, 0xf5, 0x27, 0xb0, 0x9d, 0x48,
};
