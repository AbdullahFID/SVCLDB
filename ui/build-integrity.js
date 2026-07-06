// ═══════════════════════════════════════════════════════════════
// build-integrity.js — Stamp SHA-256 into license/config.js.
//
// The %%INTEGRITY_PLACEHOLDER%% inside config.js gets replaced with
// a truncated (16-char) hex prefix of SHA-256 over the file's own
// bytes WITH the placeholder still in place. Runtime _verifyIntegrity()
// recomputes the same hash and process.exit(1)s if it doesn't match.
//
// Why: the trivial disk-patch bypass (edit SUPABASE_URL in config.js,
// point at a fake license server that always returns active:true) is
// blocked because the mutated file's hash won't match the baked-in
// value. Attackers who can also patch _EXPECTED_HASH need to know the
// derivation, which they can figure out — but they now need TWO
// coordinated edits + rebuild, not one line.
//
// The stamp is stable across runs (deterministic) and reproducible
// (given the same source you always get the same 16-char hex). Run
// this BEFORE javascript-obfuscator so the obfuscator sees the final
// hex value, not the placeholder.
// ═══════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PLACEHOLDER = '%%INTEGRITY_PLACEHOLDER%%';

// Whitespace-tolerant regex that matches BOTH pre-obfuscation source
// (`const _EXPECTED_HASH = '...'` with spaces) and post-obfuscation
// (`const _EXPECTED_HASH='...'` compact). Also accepts `var` / `let`
// in case a bundler swaps keyword. Preserves the leading whitespace
// context so replace-substitute produces valid syntax either way.
const ASSIGN_REGEX = /(const|let|var)\s+_EXPECTED_HASH\s*=\s*'[^']*'/;

// Normalize any current `_EXPECTED_HASH = '<something>'` back to the
// placeholder form used at build time BEFORE hashing so that the
// hashable content is stable regardless of what's currently stamped.
function normalizeToPlaceholder(src) {
  return src.replace(ASSIGN_REGEX, `$1 _EXPECTED_HASH = '${PLACEHOLDER}'`);
}

function stampIntegrityInto(filePath) {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) {
    throw new Error(`build-integrity: file not found: ${abs}`);
  }
  const originalSrc = fs.readFileSync(abs, 'utf8');
  if (!ASSIGN_REGEX.test(originalSrc)) {
    console.warn(`  ⚠ build-integrity: no _EXPECTED_HASH assignment in ${filePath} — skipping`);
    return { ok: false, reason: 'no_placeholder' };
  }
  // Compute hash with the assignment normalized back to placeholder
  // form so the same hash comes out regardless of current stamp.
  const hashable = normalizeToPlaceholder(originalSrc);
  const digest = crypto.createHash('sha256').update(hashable).digest('hex').slice(0, 16);
  // Write back with the digest in place of whatever was there.
  const stamped = originalSrc.replace(ASSIGN_REGEX, `$1 _EXPECTED_HASH = '${digest}'`);
  fs.writeFileSync(abs, stamped, 'utf8');
  return { ok: true, digest };
}

// Support both direct-invocation and require()-import.
if (require.main === module) {
  const targets = process.argv.slice(2);
  if (targets.length === 0) {
    console.error('Usage: node build-integrity.js <file> [<file>...]');
    process.exit(1);
  }
  for (const t of targets) {
    const r = stampIntegrityInto(t);
    if (r.ok) console.log(`  ✓ ${t} stamped ${r.digest}`);
  }
}

module.exports = { stampIntegrityInto, PLACEHOLDER };
