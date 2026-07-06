// ═══════════════════════════════════════════════════════════════
// device.js — HWID collection matching the C-side hwid_get contract
// (shared/hwid.c). Order MUST match:
//   1. SMBIOS UUID via wmic csproduct  ← primary
//   2. HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid  ← fallback 1
//   3. SHA-256(ComputerName || vol C:) → UUID-formatted  ← fallback 2
//
// Same HWID must be produced on the same box across languages, or the
// handshake_verify() call inside the payload will reject the config
// even though both sides "have the right HWID".
// ═══════════════════════════════════════════════════════════════

const { execFile, execFileSync } = require('child_process');
const crypto = require('crypto');

let _cache = null;

function _exec(cmd, args, timeout) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, {
      windowsHide: true,
      timeout: timeout || 10000,
      encoding: 'utf8',
    }, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

// Primary: SMBIOS UUID
async function _smbios() {
  try {
    const s = await _exec('wmic', ['csproduct', 'get', 'uuid', '/format:value'], 5000);
    const m = s.match(/UUID=(.+)/i);
    if (m) {
      const v = m[1].trim();
      if (v.length >= 32 && v.includes('-') &&
          v.toUpperCase() !== 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF') {
        return v;
      }
    }
  } catch { /* fall through */ }
  return null;
}

// Fallback 1: MachineGuid from registry
async function _machineGuid() {
  try {
    const s = await _exec('reg',
      ['query', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'],
      5000);
    for (const line of s.split('\n')) {
      if (line.includes('MachineGuid')) {
        const parts = line.trim().split(/\s+/);
        const g = parts[parts.length - 1];
        if (g) return g;
      }
    }
  } catch { /* fall through */ }
  return null;
}

// Fallback 2: SHA-256(ComputerName || vol C:) formatted as UUID
function _syntheticUuid() {
  const h = crypto.createHash('sha256');
  h.update(process.env.COMPUTERNAME || 'unknown');
  try {
    const vol = execFileSync('cmd', ['/c', 'vol', 'C:'], { windowsHide: true, timeout: 5000 });
    h.update(vol);
  } catch { /* ignore — pure hostname fallback */ }
  const b = h.digest();
  const hx = (from, to) => b.subarray(from, to).toString('hex').toUpperCase();
  return `${hx(0,4)}-${hx(4,6)}-${hx(6,8)}-${hx(8,10)}-${hx(10,16)}`;
}

async function collect() {
  if (_cache) return _cache;
  let uuid = await _smbios();
  if (!uuid) uuid = await _machineGuid();
  if (!uuid) uuid = _syntheticUuid();

  _cache = {
    hardware_uuid: uuid,
    device_name:   process.env.COMPUTERNAME || 'Windows PC',
  };
  return _cache;
}

function getCached() { return _cache; }

module.exports = { collect, getCached };
