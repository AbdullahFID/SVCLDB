'use strict';
/*
 * tools/probe_uia_rpc.js -- live probe for the winlogon helper's UIA RPC path.
 *
 * Opens the HMAC-derived \\.\pipe\<guid> (SALT_PIPE_ISO_CMD = wasvc.pipe.iso.cmd.1),
 * sends a UIA_OP_SNAP(sx, sy) request, waits for the helper's reply,
 * prints snapped/not-snapped + the resolved coordinate.
 *
 * This confirms the entire RPC pipeline is reachable from userland:
 *   client -> \\.\pipe\<guid> -> winlogon.exe helper's uia_server_thread
 *   -> IUIAutomation::ElementFromPoint on the active input desktop
 *   -> reply over the same pipe.
 *
 * Needed to validate the v8.2 ground.cpp promotion (helper is now the
 * PRIMARY UIA path on both normal + iso desktops). If this probe
 * succeeds, the production code path works.
 *
 * Usage:
 *   node tools/probe_uia_rpc.js [sx] [sy]
 * Default (sx, sy) = current cursor position (via PowerShell).
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const { execFileSync } = require('child_process');

// Same derivation as ui/src/lib/obf-names.js + shared/obf_names.c
const SALT_PIPE_ISO_CMD = 'wasvc.pipe.iso.cmd.1';
const FALLBACK_GUID = '3b1e9c27-1d54-4a8f-9e2b-7c6a0f5d84b1';
const DEFAULT_BIND = Buffer.from([
  0x7c, 0x3f, 0xa1, 0x92, 0x4d, 0x88, 0x1e, 0x60,
  0x5b, 0x37, 0xd0, 0x2c, 0x9e, 0xea, 0x14, 0x77,
  0x33, 0x4a, 0xf5, 0x11, 0x08, 0xbc, 0x69, 0x82,
  0xc4, 0x17, 0x5d, 0x2f, 0xaa, 0x93, 0x76, 0xe1,
]);
const BIND_FILE = 'C:\\ProgramData\\WinAudioSvc\\_bind.bin';

function readMachineGuid() {
  try {
    const out = execFileSync('reg',
      ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid', '/reg:64'],
      { windowsHide: true, encoding: 'utf8', timeout: 4000 });
    const m = out.match(/MachineGuid\s+REG_SZ\s+([^\r\n]+)/i);
    if (m) return m[1].trim().toLowerCase();
  } catch (_) {}
  return FALLBACK_GUID;
}

function readBind() {
  try {
    const b = fs.readFileSync(BIND_FILE);
    if (b && b.length >= 32) return b.slice(0, 32);
  } catch (_) {}
  return DEFAULT_BIND;
}

function deriveGuid(salt) {
  const guid = readMachineGuid();
  const bind = readBind();
  const h = crypto.createHmac('sha256', bind).update(salt + ':' + guid, 'utf8').digest();
  const hex = h.slice(0, 16).toString('hex');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
}

function getCursor() {
  try {
    const out = execFileSync('powershell',
      ['-NoProfile', '-Command', 'Add-Type -AssemblyName System.Windows.Forms; $p = [System.Windows.Forms.Cursor]::Position; "$($p.X),$($p.Y)"'],
      { windowsHide: true, encoding: 'utf8', timeout: 3000 });
    const [x, y] = out.trim().split(',').map(Number);
    return { x, y };
  } catch (_) { return { x: 100, y: 100 }; }
}

async function main() {
  const argSx = process.argv[2] ? parseInt(process.argv[2], 10) : null;
  const argSy = process.argv[3] ? parseInt(process.argv[3], 10) : null;
  const cur = (argSx === null || argSy === null) ? getCursor() : null;
  const sx = argSx !== null ? argSx : cur.x;
  const sy = argSy !== null ? argSy : cur.y;

  const bindUsed = fs.existsSync(BIND_FILE);
  const machineGuid = readMachineGuid();
  const pipeGuid = deriveGuid(SALT_PIPE_ISO_CMD);
  const pipeName = `\\\\.\\pipe\\${pipeGuid}`;

  console.log(`[probe] bind source : ${bindUsed ? BIND_FILE : 'DEFAULT_BIND (fallback)'}`);
  console.log(`[probe] MachineGuid : ${machineGuid}`);
  console.log(`[probe] pipe name   : ${pipeName}`);
  console.log(`[probe] query coord : (${sx}, ${sy})`);
  console.log('');

  // Wire format (ground.cpp UIA RPC):
  //   hdr = { u32 magic=0x00415155, u32 opcode, u32 payload_len } (12 bytes)
  //   OP_SNAP req(8)  = int32 sx, int32 sy
  //   OP_SNAP rep(12) = u32 snapped, int32 sx, int32 sy
  const UIA_MAGIC = 0x00415155;
  const UIA_OP_SNAP = 1;

  const hdr = Buffer.alloc(12);
  hdr.writeUInt32LE(UIA_MAGIC, 0);
  hdr.writeUInt32LE(UIA_OP_SNAP, 4);
  hdr.writeUInt32LE(8, 8);         // payload_len = 8 (sx + sy)
  const req = Buffer.alloc(8);
  req.writeInt32LE(sx, 0);
  req.writeInt32LE(sy, 4);

  return new Promise((resolve) => {
    const sock = net.createConnection(pipeName);
    const chunks = [];
    let timer = setTimeout(() => {
      console.log('[probe] TIMEOUT after 5s -- helper not responding');
      sock.destroy();
      resolve(1);
    }, 5000);

    sock.on('connect', () => {
      console.log('[probe] pipe connected -- sending UIA_OP_SNAP');
      sock.write(Buffer.concat([hdr, req]));
    });
    sock.on('data', (d) => { chunks.push(d); });
    sock.on('error', (e) => {
      clearTimeout(timer);
      console.log(`[probe] ERROR: ${e.code} ${e.message}`);
      if (e.code === 'ENOENT') {
        console.log('[probe] -> pipe does not exist. Helper not loaded OR _bind.bin missing/different.');
      } else if (e.code === 'EACCES') {
        console.log('[probe] -> ACCESS_DENIED on CreateFile. Pipe DACL blocking us (good -- medium IL also would be blocked). Run elevated.');
      }
      resolve(1);
    });
    sock.on('end', () => {
      clearTimeout(timer);
      const buf = Buffer.concat(chunks);
      if (buf.length < 24) {
        console.log(`[probe] SHORT reply (${buf.length} bytes) -- expected >= 24`);
        resolve(1); return;
      }
      const rMagic = buf.readUInt32LE(0);
      const rOp    = buf.readUInt32LE(4);
      const rLen   = buf.readUInt32LE(8);
      if (rMagic !== UIA_MAGIC) {
        console.log(`[probe] BAD magic 0x${rMagic.toString(16)}`);
        resolve(1); return;
      }
      if (rLen >= 12) {
        const snapped = buf.readUInt32LE(12);
        const rsx = buf.readInt32LE(16);
        const rsy = buf.readInt32LE(20);
        console.log(`[probe] reply: op=${rOp} snapped=${snapped} coord=(${rsx},${rsy})`);
        if (snapped) {
          const dx = rsx - sx, dy = rsy - sy;
          console.log(`[probe] -> HELPER UIA SUCCESS. Snap moved cursor target by (${dx},${dy})px.`);
        } else {
          console.log('[probe] -> helper connected + answered, but no UIA element at that point (snapped=0).');
          console.log('[probe]    This still proves the RPC path is live. Try pointing at an actual button.');
        }
      }
      resolve(0);
    });
  });
}

main().then((code) => process.exit(code));
