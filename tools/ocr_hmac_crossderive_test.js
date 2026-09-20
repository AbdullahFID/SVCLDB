// tools/ocr_hmac_crossderive_test.js
//
// Reproducibility test for MM-1: does the OCR HMAC key derive
// byte-identical on all three sides (payload, launcher-daemon, Electron)?
// If any of the three diverges, the daemon rejects the payload's scan
// requests -> redact_bgra_via_pipe returns -1 -> payload silently sends
// unredacted screenshots to the AI (pre-fix "OCR OFF" fallback).
//
// This test simulates each side's exact byte-level behavior against the
// real .svchelper_install_secret on disk. All three should produce the
// same 32-byte HMAC-SHA256 key.
//
// Run: node tools/ocr_hmac_crossderive_test.js

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SECRET_PATH = 'C:\\ProgramData\\WinAudioSvc\\.svchelper_install_secret';
const DOMAIN      = 'wa.ocr.v1';   // v3 (2026-09-19): must match C payload + launcher + Electron OCR_HMAC_DOMAIN.

if (!fs.existsSync(SECRET_PATH)) {
  console.error(`Install secret not found at ${SECRET_PATH}`);
  console.error('Cannot repro; sign in via Electron once (auth.js writes it on first launch).');
  process.exit(2);
}

const rawBytes = fs.readFileSync(SECRET_PATH);
console.log(`File: ${SECRET_PATH}`);
console.log(`Size: ${rawBytes.length} bytes`);
console.log(`Bytes (hex): ${rawBytes.toString('hex')}`);
console.log(`First 4 bytes: ${[...rawBytes.subarray(0, 4)].map(b => '0x' + b.toString(16).padStart(2, '0')).join(' ')}`);
console.log(`Last  4 bytes: ${[...rawBytes.subarray(-4)].map(b => '0x' + b.toString(16).padStart(2, '0')).join(' ')}`);
console.log();

// ─── DERIVATION 1: JS (Electron main.js:_deriveOcrHmacKey) ─────────
// Reads as UTF-8 string, .trim(), key = string (Node -> UTF-8 bytes).
function deriveJS() {
  const raw = fs.readFileSync(SECRET_PATH, 'utf8').trim();
  if (raw.length < 32) return null;
  return {
    keyStr: raw,
    keyBytes: Buffer.from(raw, 'utf8'),
    hmac: crypto.createHmac('sha256', raw).update(DOMAIN).digest(),
  };
}

// ─── DERIVATION 2: C launcher --ocr-daemon (main.c:1119-1131) ──────
// Reads raw bytes (max 128), trim trailing \r\n\t/space only.
function deriveCLauncher() {
  const buf = Buffer.alloc(128);
  const n = Math.min(rawBytes.length, buf.length);
  rawBytes.copy(buf, 0, 0, n);
  let got = n;
  while (got > 0 && (buf[got-1] === 0x0D /*\r*/ || buf[got-1] === 0x0A /*\n*/ ||
                     buf[got-1] === 0x20 /*sp*/  || buf[got-1] === 0x09 /*\t*/)) {
    got--;
  }
  if (got < 32) return null;
  const keyBytes = buf.subarray(0, got);
  return {
    keyStr: keyBytes.toString('latin1'),  // for display only
    keyBytes,
    hmac: crypto.createHmac('sha256', keyBytes).update(DOMAIN).digest(),
  };
}

// ─── DERIVATION 3: C payload (redact_client.c:76-84) ───────────────
// Identical to derivation 2 (same C code pattern).
function deriveCPayload() {
  return deriveCLauncher();  // same algorithm
}

// ─── COMPARE ────────────────────────────────────────────────────────
const js  = deriveJS();
const cL  = deriveCLauncher();
const cP  = deriveCPayload();

function fmt(buf) { return buf ? buf.toString('hex') : '(null)'; }

console.log('Derivation results (32-byte HMAC-SHA256 output):');
console.log(`  JS (Electron)      : ${fmt(js  && js.hmac)}`);
console.log(`  C launcher daemon  : ${fmt(cL  && cL.hmac)}`);
console.log(`  C payload redact   : ${fmt(cP  && cP.hmac)}`);
console.log();

// Also compare intermediate key bytes
console.log('Key byte-length used:');
console.log(`  JS               : ${js  && js.keyBytes.length}`);
console.log(`  C launcher       : ${cL  && cL.keyBytes.length}`);
console.log(`  C payload        : ${cP  && cP.keyBytes.length}`);

const jsHex  = js  && js.hmac.toString('hex');
const clHex  = cL  && cL.hmac.toString('hex');
const cpHex  = cP  && cP.hmac.toString('hex');

const jsKeyHex = js && js.keyBytes.toString('hex');
const clKeyHex = cL && cL.keyBytes.toString('hex');

console.log();
console.log('Key byte equality:');
console.log(`  JS vs C launcher    : ${jsKeyHex === clKeyHex ? 'MATCH' : 'DIFFER'}`);
if (jsKeyHex !== clKeyHex) {
  console.log(`    JS key hex : ${jsKeyHex}`);
  console.log(`    C  key hex : ${clKeyHex}`);
}
console.log();
console.log('Final HMAC equality:');
console.log(`  JS vs C launcher    : ${jsHex === clHex ? 'MATCH' : 'DIFFER'}`);
console.log(`  JS vs C payload     : ${jsHex === cpHex ? 'MATCH' : 'DIFFER'}`);
console.log(`  C launcher vs pyld  : ${clHex === cpHex ? 'MATCH' : 'DIFFER'}`);

// Adversarial cases: probe edge conditions that could cause divergence
console.log();
console.log('=== Edge-case probes ===');
// Simulate: file with trailing \v (JS .trim() removes it, C doesn't)
{
  const test = Buffer.concat([Buffer.from('a'.repeat(64), 'utf8'), Buffer.from([0x0B])]); // \v
  const jsStr = test.toString('utf8').trim();  // JS trims \v
  const cLen = (function(){
    let n = test.length;
    while (n > 0 && (test[n-1]===0x0D||test[n-1]===0x0A||test[n-1]===0x20||test[n-1]===0x09)) n--;
    return n;  // C won't trim \v -> keeps it
  })();
  const jsK  = crypto.createHmac('sha256', jsStr).update(DOMAIN).digest();
  const cK   = crypto.createHmac('sha256', test.subarray(0, cLen)).update(DOMAIN).digest();
  console.log(`  trailing \\v (VT):    JS key len=${jsStr.length}, C key len=${cLen} -> ${jsK.equals(cK) ? 'MATCH' : 'DIFFER (BUG)'}`);
}
// Simulate: file with leading BOM (JS may strip on modern Node, C doesn't)
{
  const test = Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from('a'.repeat(64), 'utf8')]);
  const jsStr = test.toString('utf8').trim();  // Node preserves BOM in string; .trim() may or may not strip depending on Node version
  const cLen = (function(){ let n = test.length; while (n > 0 && (test[n-1]===0x0D||test[n-1]===0x0A||test[n-1]===0x20||test[n-1]===0x09)) n--; return n; })();
  const jsK  = crypto.createHmac('sha256', jsStr).update(DOMAIN).digest();
  const cK   = crypto.createHmac('sha256', test.subarray(0, cLen)).update(DOMAIN).digest();
  console.log(`  leading BOM (EF BB BF): JS key len=${Buffer.byteLength(jsStr,'utf8')}, C key len=${cLen} -> ${jsK.equals(cK) ? 'MATCH' : 'DIFFER (BUG)'}`);
}
// Simulate: file > 128 bytes (C truncates to first 128; JS reads all)
{
  const test = Buffer.from('a'.repeat(200), 'utf8');
  const jsStr = test.toString('utf8').trim();
  const cBuf = Buffer.alloc(128);
  test.copy(cBuf, 0, 0, 128);
  const jsK = crypto.createHmac('sha256', jsStr).update(DOMAIN).digest();
  const cK  = crypto.createHmac('sha256', cBuf).update(DOMAIN).digest();
  console.log(`  file > 128 bytes:    JS key len=${jsStr.length}, C key len=128 -> ${jsK.equals(cK) ? 'MATCH' : 'DIFFER (BUG)'}`);
}
// Verdict
console.log();
const allMatch = (jsHex === clHex) && (jsHex === cpHex);
if (allMatch) {
  console.log('=== VERDICT: NOT reproduced on this install. Current secret file produces byte-identical HMAC across all 3 sides.');
  process.exit(0);
} else {
  console.log('=== VERDICT: MM-1 REPRODUCED. HMAC divergence WILL cause redactor silent no-op.');
  process.exit(1);
}
