// Send just 4 bytes (a magic) to see if the server responds and logs.
const net = require('net');
const obf = require('../../ui/src/lib/obf-names.js');
const PIPE = obf.pipeToken();

async function tryOne(magic) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (r) => { if (settled) return; settled = true; resolve(r); };
    let client;
    try {
      client = net.createConnection(PIPE, () => {
        const b = Buffer.alloc(4);
        b.writeUInt32LE(magic, 0);
        client.write(b);
      });
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

(async () => {
  console.log('Send TOK3 (bogus magic) alone:', await tryOne(0x544F4B33));
  await new Promise(r => setTimeout(r, 300));
  console.log('Send TOK1 magic alone (no body):', await tryOne(0x544F4B31));
})();
