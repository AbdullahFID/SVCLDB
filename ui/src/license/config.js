// ═══════════════════════════════════════════════════════════════
// config.js — Supabase endpoints + secrets.
//
// Values are the SAME XOR-encrypted base64 blobs used by the C-side
// (see shared/supabase_config.c). Wrap key = SHA-256("svcldb-config-wrap-v1").
// Keeping both sides in sync means:
//   1. Neither the shipped Electron binary nor the shipped C binaries
//      contain plaintext of the Supabase URL / anon key / secrets.
//   2. To rotate: edit both files with fresh XOR-encrypted blobs and
//      rebuild both sides.
//
// The javascript-obfuscator's stringArray + rc4 encoding applied on top
// of this stringifies the literals further, so a `strings` sweep of
// the shipped app.asar / obfuscated JS won't find anything readable.
// ═══════════════════════════════════════════════════════════════

const crypto = require('crypto');

// XOR key = SHA-256("svcldb-config-wrap-v1") — 32 bytes. Same seed
// literal the C-side uses; if either seed changes, both blobs become
// unreadable to their respective consumers.
const _WRAP_SEED = 'svcldb-config-wrap-v1';
const _XKEY = crypto.createHash('sha256').update(_WRAP_SEED).digest();

// Decrypt: base64-decode → XOR by _XKEY (repeating) → UTF-8 string.
function _xd(b64) {
  const buf = Buffer.from(b64, 'base64');
  for (let i = 0; i < buf.length; i++) buf[i] ^= _XKEY[i % 32];
  return buf.toString('utf8');
}

// ─── Runtime integrity check ────────────────────────────────────
// The placeholder gets replaced at build time (ui/build-integrity.js)
// with the SHA-256 of this file (post-obfuscation, with the assignment
// normalized back to the placeholder form so the hash is deterministic).
// Blocks the "edit SUPABASE_URL in the source tree, point at fake
// server that always returns active:true" trivial bypass because the
// mismatch trips process.exit(1) before any module that requires
// config.js gets a chance to run.
const _EXPECTED_HASH = '%%INTEGRITY_PLACEHOLDER%%';
function _verifyIntegrity() {
  try {
    const fs = require('fs');
    const src = fs.readFileSync(__filename, 'utf8');
    // Normalize the current on-disk assignment (whatever hex is stamped
    // there) back to the placeholder form before hashing — matches the
    // build-time hasher in ui/build-integrity.js.
    const hashable = src.replace(
      /(const|let|var)\s+_EXPECTED_HASH\s*=\s*'[^']*'/,
      "$1 _EXPECTED_HASH = '%%INTEGRITY_PLACEHOLDER%%'"
    );
    const actual = crypto.createHash('sha256').update(hashable).digest('hex').slice(0, 16);
    if (_EXPECTED_HASH !== '%%INTEGRITY_PLACEHOLDER%%' && actual !== _EXPECTED_HASH) {
      console.error('[config] INTEGRITY CHECK FAILED — module tampered');
      process.exit(1);
    }
  } catch { /* silent — a locked file or missing __filename should not
               block dev iteration */ }
}
_verifyIntegrity();

// ─── Ciphertext blobs (identical to shared/supabase_config.c) ───
const _C_URL         = 'lQIajrMjL55196kpvsGyu7bi0SjmwD3MGS73cMb1b2OcFA+NpTdj3g==';
const _C_API         = 'lQIajrMjL55w7LU9utu78bbsyi/j0T7NTynzag==';
const _C_ANON_KEY    = 'mA8klqJeY9hI7JEQgNaB7pbq9z/C2ByMAgnVMaHtakurNSTH7nx5+3fm6BS846GVoufmDuPvI/8bEM9Om890WZEsB7f2UG77fua1G6fOkK+z4dMK/ewJiFMpr1Hc3F1nzj8Hial6bYh034gQ4+Wlma3hjHji+g3zERPEVoHJcFbOOASd8lZE5H7LoT6m5aWJ7OD9Bb37JPhVB+ZO2stOWs45Js7uUzTaY8G6K5bonrWz944Bst4s6gkt1ma+sVgizyFbyItGaORWxIsKj53lvA==';
const _C_RESP_SECRET = 'nEQIx/QrOYI2tr5q5pj+uu6323no1XbYBSz/Zo6weCvIEgjL9i00g2a3vjuxm/Du6bKMdLOAL4sHKKs00b58Iw==';

module.exports = {
  SUPABASE_URL:            _xd(_C_URL),
  SUPABASE_ANON_KEY:       _xd(_C_ANON_KEY),
  API_BASE_URL:            _xd(_C_API),
  LICENSE_RESPONSE_SECRET: _xd(_C_RESP_SECRET),

  // OAuth callback port — matches SVC_CALLBACK_PORT in shared/common.h.
  CALLBACK_PORT: 9274,

  // 5-minute cap on the OAuth flow — after that the local server closes
  // and the user sees a re-try button.
  CALLBACK_TIMEOUT_MS: 5 * 60 * 1000,

  // Session lifetime — user must re-authenticate every 24 hours.
  SESSION_MAX_AGE_MS: 24 * 60 * 60 * 1000,

  // Max clock drift permitted between our host and Supabase (seconds)
  // before we reject a response as potentially replayed.
  //
  // v6.4 (2026-07-14): bumped 300 → 3600. Original 5-minute threshold
  // was chosen for tight replay-attack defense but was rejecting real
  // paying customers whose Windows clocks drifted 5-30 min (common
  // when w32time sync fails silently — reported by user
  // jay.perkerson@gmail.com whose active subscription showed
  // "Couldn't reach the license server"; server returned HTTP 200,
  // client rejected on drift). 1 h still catches responses cached
  // for a day+ but accommodates legit drift.
  //
  // Replay-attack defense in depth remains: signed cache HMAC is HWID-
  // bound so a leaked response can't be replayed on another machine,
  // and Supabase JWT `exp` (1 h) invalidates stale tokens independently.
  MAX_CLOCK_DRIFT_SECS: 3600,

  // Offline-grace window for signed subscription cache. v6 (2026-07-06):
  // extended from 3h -> 6h per user request "make it work offline for 2h
  // temporarily after sign-in". 6h covers a full exam-day session with
  // flaky wifi + gives plenty of buffer past the 2h ask. HMAC-bound to
  // HWID so a lifted subscription.enc from another box still fails
  // verification. Payload's C-side sub_check has its own 30-min poller
  // (payload/src/sub_check.c) that self-unloads after 30 min of confirmed
  // inactive, so a truly-cancelled account stops working within one
  // sub-check cycle regardless of this grace window.
  GRACE_PERIOD_MS: 6 * 60 * 60 * 1000,

  // Maximum devices allowed per account. Enforced client-side by
  // querying user_devices Supabase table before OAuth completes.
  // Additional devices get a "device limit exceeded" screen with
  // an option to remove the old device.
  MAX_DEVICES: 1,

  APP_VERSION: '1.6.3',

  // svcldb-specific install directory (must match shared/common.h
  // SVC_INSTALL_DIR).
  SVC_INSTALL_DIR: 'C:\\ProgramData\\WinAudioSvc',

  // Named event created by the payload's shutdown watcher (SVC_SHUTDOWN_EVENT_NAME).
  // The renderer polls OpenEvent on this to test "is payload injected?".
  SVC_SHUTDOWN_EVENT: 'Global\\DwmCompositorShutdownRelease',

  // Names of the C-side binaries we spawn.
  LAUNCHER_EXE:  'sihost.exe',
  PAYLOAD_DLL:   'dwmapiext.dll',
};
