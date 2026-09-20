// ═══════════════════════════════════════════════════════════════
// handshake.js — Payload injection gate token.
//
// MUST produce the same 32-byte output as shared/handshake.c's
// handshake_compute() for the same (access_token, hwid, epoch_day)
// triple, or the payload's init_thread will reject the config.
//
// Derivation (see shared/handshake.h for the C-side authoritative spec):
//   sig_key = SHA-256(access_token || "svcldb-handshake-v1")
//   msg     = hwid || ":" || epoch_day_decimal
//   token   = HMAC-SHA-256(sig_key, msg)   → 32 bytes
// ═══════════════════════════════════════════════════════════════

const crypto = require('crypto');

// MUST match SVCLDB_HANDSHAKE_SALT in shared/handshake.h.
const HANDSHAKE_SALT = 'wa.hs.v1';   // v3 (2026-09-19): was 'svcldb-handshake-v1' -- MUST match SVCLDB_HANDSHAKE_SALT in shared/handshake.h. See that file for the rename rationale.

/** Current UNIX epoch day (floor(time / 86400)). */
function currentEpochDay() {
  return Math.floor(Date.now() / 1000 / 86400);
}

/**
 * Compute the 32-byte handshake token as a Buffer.
 *
 * @param {string} accessToken - Supabase JWT.
 * @param {string} hwid        - HWID from device.collect().
 * @param {number} epochDay    - typically currentEpochDay().
 * @returns {Buffer}           - 32-byte token.
 */
function compute(accessToken, hwid, epochDay) {
  if (!accessToken || !hwid) throw new Error('handshake.compute: missing accessToken or hwid');
  // sig_key = SHA-256(access_token || SALT)
  const sigKey = crypto.createHash('sha256')
    .update(accessToken, 'utf8')
    .update(HANDSHAKE_SALT, 'utf8')
    .digest();
  const msg = `${hwid}:${epochDay}`;
  const token = crypto.createHmac('sha256', sigKey).update(msg, 'utf8').digest();
  // sigKey holds a secret derivation; zero it eagerly.
  sigKey.fill(0);
  return token;
}

/**
 * Build the fields the launcher's --json-config mode expects:
 * {
 *   hwid,
 *   handshake_epoch_day,
 *   handshake_token_hex   (64-char hex — matches cu_from_hex on C-side)
 * }
 */
function buildTokenFields(accessToken, hwid) {
  const day = currentEpochDay();
  const tok = compute(accessToken, hwid, day);
  const hex = tok.toString('hex');
  tok.fill(0);
  return {
    hwid,
    handshake_epoch_day: day,
    handshake_token_hex: hex,
  };
}

module.exports = { compute, currentEpochDay, buildTokenFields, HANDSHAKE_SALT };
