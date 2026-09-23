// Step-by-step isolation: send TOK2 with progressively more work triggered.
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const obf = require('../../ui/src/lib/obf-names.js');
const device = require('../../ui/src/license/device.js');

const PIPE = obf.pipeToken();
const MAGIC_V2 = 0x544F4B32;

async function build(at, rt, expAt, hwid) {
  const secret = fs.readFileSync('C:\\ProgramData\\WinAudioSvc\\.svchelper_install_secret', 'utf8').trim();
  const key = crypto.createHmac('sha256', secret).update(hwid).digest();
  const atBuf = Buffer.from(at, 'utf8');
  const rtBuf = Buffer.from(rt || '', 'utf8');
  const expNum = BigInt(Math.max(0, Math.floor(expAt || 0)));
  const hmacIn = Buffer.alloc(4 + 4 + 8 + atBuf.length + rtBuf.length);
  hmacIn.writeUInt32LE(atBuf.length, 0);
  hmacIn.writeUInt32LE(rtBuf.length, 4);
  hmacIn.writeBigInt64LE(expNum, 8);
  atBuf.copy(hmacIn, 16);
  rtBuf.copy(hmacIn, 16 + atBuf.length);
  const hmac = crypto.createHmac('sha256', key).update(hmacIn).digest();
  const hdr = Buffer.alloc(56);
  hdr.writeUInt32LE(MAGIC_V2, 0);
  hdr.writeUInt32LE(0, 4);
  hmac.copy(hdr, 8);
  hdr.writeUInt32LE(atBuf.length, 40);
  hdr.writeUInt32LE(rtBuf.length, 44);
  hdr.writeBigInt64LE(expNum, 48);
  return Buffer.concat([hdr, atBuf, rtBuf]);
}

function sendFrame(frame, timeoutMs = 5000) {
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
    client.setTimeout(timeoutMs, () => { try { client.destroy(); } catch {} finish({ err: 'timeout' }); });
    client.on('close', () => finish({ err: 'closed' }));
  });
}

(async () => {
  const cached = device.getCached() || await device.collect();
  const hwid = cached && cached.hardware_uuid ? cached.hardware_uuid : 'no-hwid';
  console.log(`HWID: ${hwid.substring(0, 16)}...`);
  const FAKE_AT = 'eyJ0ZXN0IjoxfQ.' + 'A'.repeat(200) + '.fake-signature-testing-only';

  console.log('STEP 1: TOK2 AT only, rt_len=0, exp=0  (no cfg_persist should fire)');
  const f1 = await build(FAKE_AT, '', 0, hwid);
  console.log('  ->', await sendFrame(f1));
  await new Promise(r => setTimeout(r, 500));

  console.log('STEP 2: TOK2 AT + exp only, rt_len=0, exp!=0  (cfg_persist should fire)');
  const f2 = await build(FAKE_AT, '', Math.floor(Date.now()/1000) + 3600, hwid);
  console.log('  ->', await sendFrame(f2));
  await new Promise(r => setTimeout(r, 500));

  console.log('STEP 3: TOK2 AT + RT + exp  (cfg_persist should fire)');
  const rt = crypto.randomBytes(24).toString('base64url');
  const f3 = await build(FAKE_AT, rt, Math.floor(Date.now()/1000) + 3600, hwid);
  console.log('  ->', await sendFrame(f3));
})();
