// ═══════════════════════════════════════════════════════════════
// test_pipe_tok2.js
//
// End-to-end test of the v14.2 TOK2 pipe protocol.
//
// Requires the payload to be loaded (sihost.exe --status == 0).
// Requires C:\ProgramData\WinAudioSvc\.svchelper_install_secret to exist.
//
// Test matrix:
//   1. TOK2 with valid HMAC + real-shaped AT + RT + exp -> status 0 (accepted)
//   2. TOK2 with TAMPERED HMAC                          -> status -1 (HMAC MISMATCH)
//   3. TOK2 with AT too long (5000 chars)               -> status -2 (bad at_len)
//   4. TOK2 with rt_len=0 (AT-only push)                -> status 0 (rt preserved)
//   5. TOK1 legacy fallback                             -> status 0 (backcompat)
//   6. Unknown magic (TOK3)                             -> reply magic=TOK1, status -1
// ═══════════════════════════════════════════════════════════════

'use strict';
const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const obf = require('../../ui/src/lib/obf-names.js');
const PIPE = obf.pipeToken();

const SECRET_PATH = 'C:\\ProgramData\\WinAudioSvc\\.svchelper_install_secret';
const MAGIC_V1 = 0x544F4B31;
const MAGIC_V2 = 0x544F4B32;

// hwid must match what the payload's derive_verify_key uses.
// Payload reads cfg->handshake_hwid; we compute the same via device.js.
const device = require('../../ui/src/license/device.js');

function hex4(u) { return '0x' + u.toString(16).padStart(8, '0'); }

async function loadCfgHwid() {
  // Use device.collect() -- same call chain Electron uses when writing
  // cfg->handshake_hwid via launcher's --json-config path. This resolves
  // to the same 3-source cascade: SMBIOS -> MachineGuid -> synthetic.
  try {
    const cached = device.getCached();
    if (cached && cached.hardware_uuid) return cached.hardware_uuid;
    const fresh = await device.collect();
    if (fresh && fresh.hardware_uuid) return fresh.hardware_uuid;
  } catch (e) {
    console.log('  ⚠ device.collect() failed:', e.message);
  }
  return 'no-hwid';
}

function loadInstallSecret() {
  const raw = fs.readFileSync(SECRET_PATH, 'utf8').trim();
  if (raw.length < 32) throw new Error('secret too short');
  return raw;
}

// key = HMAC-SHA256(install_secret_string_utf8_bytes, hwid_bytes)
function deriveKey(secret, hwid) {
  return crypto.createHmac('sha256', secret).update(hwid).digest();
}

function buildTok2Frame(at, rt, expAt, { tamperHmac = false } = {}) {
  const secret = loadInstallSecret();
  // Note: we resolve hwid lazily via a promise upstream; caller provides it.
  return async (hwid) => {
    const key = deriveKey(secret, hwid);
    const atBuf = Buffer.from(at, 'utf8');
    const rtBuf = Buffer.from(rt || '', 'utf8');
    const expNum = BigInt(Math.max(0, Math.floor(expAt || 0)));
    const hmacIn = Buffer.alloc(4 + 4 + 8 + atBuf.length + rtBuf.length);
    hmacIn.writeUInt32LE(atBuf.length, 0);
    hmacIn.writeUInt32LE(rtBuf.length, 4);
    hmacIn.writeBigInt64LE(expNum, 8);
    atBuf.copy(hmacIn, 16);
    rtBuf.copy(hmacIn, 16 + atBuf.length);
    let hmac = crypto.createHmac('sha256', key).update(hmacIn).digest();
    if (tamperHmac) hmac[0] ^= 0xFF;
    const hdr = Buffer.alloc(56);
    hdr.writeUInt32LE(MAGIC_V2, 0);
    hdr.writeUInt32LE(0, 4);
    hmac.copy(hdr, 8);
    hdr.writeUInt32LE(atBuf.length, 40);
    hdr.writeUInt32LE(rtBuf.length, 44);
    hdr.writeBigInt64LE(expNum, 48);
    return Buffer.concat([hdr, atBuf, rtBuf]);
  };
}

function buildTok1Frame(at) {
  const secret = loadInstallSecret();
  return async (hwid) => {
    const key = deriveKey(secret, hwid);
    const atBuf = Buffer.from(at, 'utf8');
    const hmac = crypto.createHmac('sha256', key).update(atBuf).digest();
    const hdr = Buffer.alloc(44);
    hdr.writeUInt32LE(MAGIC_V1, 0);
    hdr.writeUInt32LE(0, 4);
    hmac.copy(hdr, 8);
    hdr.writeUInt32LE(atBuf.length, 40);
    return Buffer.concat([hdr, atBuf]);
  };
}

function buildBogusMagic() {
  return async (_hwid) => {
    const hdr = Buffer.alloc(44);
    hdr.writeUInt32LE(0x544F4B33, 0);   // 'TOK3'
    hdr.writeUInt32LE(0, 4);
    // Fill hmac with zeros
    hdr.writeUInt32LE(10, 40);  // token_len
    const body = Buffer.from('0123456789', 'utf8');
    return Buffer.concat([hdr, body]);
  };
}

function sendFrame(frame, label) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (r) => { if (settled) return; settled = true; resolve(r); };
    let client;
    try {
      client = net.createConnection(PIPE, () => { client.write(frame); });
    } catch (e) { return finish({ err: `connect: ${e.message}` }); }
    let buf = Buffer.alloc(0);
    client.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= 8) {
        const m = buf.readUInt32LE(0);
        const s = buf.readInt32LE(4);
        try { client.end(); } catch {}
        finish({ magic: m, status: s });
      }
    });
    client.on('error', (e) => finish({ err: e.message }));
    client.setTimeout(3000, () => { try { client.destroy(); } catch {} finish({ err: 'timeout' }); });
    client.on('close', () => finish({ err: 'closed' }));
  });
}

async function main() {
  console.log('─'.repeat(72));
  console.log('TOK2 PIPE PROTOCOL — END-TO-END TEST');
  console.log(`Pipe: ${PIPE}`);
  console.log('─'.repeat(72));

  const hwid = await loadCfgHwid();
  console.log(`HWID: ${hwid.substring(0, 16)}...`);
  const secretExists = fs.existsSync(SECRET_PATH);
  console.log(`Install secret: ${secretExists ? 'present' : 'MISSING'}`);
  if (!secretExists) { console.error('cannot run without install secret'); process.exit(2); }

  const FAKE_AT = 'eyJ0ZXN0IjoxfQ.' + 'A'.repeat(200) + '.fake-signature-testing-only';
  const FAKE_RT = crypto.randomBytes(24).toString('base64url');   // ~32 chars, like Supabase rt
  const FAKE_EXP = Math.floor(Date.now() / 1000) + 3600;

  const tests = [
    { label: 'TOK2 valid AT+RT+exp',            build: buildTok2Frame(FAKE_AT, FAKE_RT, FAKE_EXP),                     expectMagic: MAGIC_V2, expectStatus: 0 },
    { label: 'TOK2 tampered HMAC',              build: buildTok2Frame(FAKE_AT, FAKE_RT, FAKE_EXP, { tamperHmac: true }), expectMagic: MAGIC_V2, expectStatus: -1 },
    { label: 'TOK2 AT too long (5000 chars)',   build: buildTok2Frame('X'.repeat(5000), FAKE_RT, FAKE_EXP),             expectMagic: MAGIC_V2, expectStatus: -2 },
    { label: 'TOK2 AT-only push (rt_len=0)',    build: buildTok2Frame(FAKE_AT, '', FAKE_EXP),                          expectMagic: MAGIC_V2, expectStatus: 0 },
    { label: 'TOK1 legacy fallback',            build: buildTok1Frame(FAKE_AT),                                        expectMagic: MAGIC_V1, expectStatus: 0 },
    { label: 'Unknown magic (TOK3)',            build: buildBogusMagic(),                                              expectMagic: MAGIC_V1, expectStatus: -1 },
  ];

  let passed = 0, failed = 0;
  for (const t of tests) {
    const frame = await t.build(hwid);
    const r = await sendFrame(frame, t.label);
    let ok = false;
    let detail;
    if (r.err) {
      detail = `err: ${r.err}`;
    } else {
      const magicOk = (t.expectMagic == null) || (r.magic === t.expectMagic);
      const statusOk = r.status === t.expectStatus;
      ok = magicOk && statusOk;
      detail = `magic=${hex4(r.magic)} status=${r.status}` +
        (magicOk ? '' : ` (expected magic=${hex4(t.expectMagic)})`) +
        (statusOk ? '' : ` (expected status=${t.expectStatus})`);
    }
    if (ok) { console.log(`  ✓ PASS  ${t.label}  -- ${detail}`); passed++; }
    else    { console.log(`  ✗ FAIL  ${t.label}  -- ${detail}`); failed++; }
    // Small gap so the payload's log line makes it in order
    await new Promise(r => setTimeout(r, 200));
  }
  console.log('─'.repeat(72));
  console.log(`RESULTS: ${passed} pass, ${failed} fail`);
  console.log('─'.repeat(72));
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(e => { console.error('FATAL:', e); process.exit(2); });
