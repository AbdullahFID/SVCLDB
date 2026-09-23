'use strict';
/*
 * obf-names.js -- Electron-side mirror of shared/obf_names.c.
 *
 * Derives the SAME per-box camouflaged object names the C payload +
 * launcher derive, so the token-refresh pipe, OCR pipe, and (future)
 * status event line up. See shared/obf_names.h for the full rationale.
 *
 * CONTRACT (must match shared/obf_names.c derive_guid byte-for-byte):
 *   v3.2 (2026-09-23) HMAC path:
 *     bind      = 32 bytes from %ProgramData%\WinAudioSvc\_bind.bin
 *                 OR compile-time DEFAULT_BIND if unreadable
 *     guidLower = lowercase(trim(MachineGuid))     // HKLM Cryptography
 *     digest    = HMAC-SHA256(bind, salt + ":" + guidLower)
 *     nameGuid  = hex(digest[0..15]) grouped 8-4-4-4-12 (lowercase)
 *     full      = prefix + nameGuid
 *
 * Any change to the salts, DEFAULT_BIND, or formatting MUST be mirrored
 * in shared/obf_names.c AND tools/redteam/probes/wl_input.c and re-
 * verified with the cross-language check, or IPC + the injected-status
 * probe silently break.
 *
 * PRODUCTION: svchelper always runs elevated (per invariant #35 admin
 * .lnk flag) so it can read _bind.bin. Dev-mode `pnpm dev` may run at
 * medium IL -- readBindSecret() falls back to DEFAULT_BIND, meaning
 * dev-electron uses the same (public) fallback as production would if
 * the file were missing. Names still deterministic, IPC still works
 * against a dev-payload that also fell back. In production (both sides
 * read the real file) the fallback is never taken.
 */

const crypto = require('crypto');
const fs = require('fs');
const { execFileSync } = require('child_process');

// Per-purpose salts -- MUST equal the SALT_* macros in obf_names.c.
const SALT = {
  pipeToken: 'wasvc.pipe.token.1',
  pipeOcr: 'wasvc.pipe.ocr.1',
  mtxInit: 'wasvc.mtx.init.1',
  mtxOcrd: 'wasvc.mtx.ocrd.1',
  evtShut: 'wasvc.evt.shut.1',
};

// MUST equal OBF_FALLBACK_GUID in obf_names.c.
const FALLBACK_GUID = '3b1e9c27-1d54-4a8f-9e2b-7c6a0f5d84b1';

// MUST equal DEFAULT_BIND in shared/bind_secret.c AND WL_DEFAULT_BIND
// in tools/redteam/probes/wl_input.c.
const DEFAULT_BIND = Buffer.from([
  0x7c, 0x3f, 0xa1, 0x92, 0x4d, 0x88, 0x1e, 0x60,
  0x5b, 0x37, 0xd0, 0x2c, 0x9e, 0xea, 0x14, 0x77,
  0x33, 0x4a, 0xf5, 0x11, 0x08, 0xbc, 0x69, 0x82,
  0xc4, 0x17, 0x5d, 0x2f, 0xaa, 0x93, 0x76, 0xe1,
]);
const BIND_FILE = 'C:\\ProgramData\\WinAudioSvc\\_bind.bin';

let _machineGuid = null;
let _bind = null;

function readMachineGuid() {
  if (_machineGuid !== null) return _machineGuid;
  let g = '';
  try {
    // 64-bit view of the key so a 32-bit Electron still reads the real value.
    const out = execFileSync(
      'reg',
      ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid', '/reg:64'],
      { windowsHide: true, encoding: 'utf8', timeout: 4000 }
    );
    const m = out.match(/MachineGuid\s+REG_SZ\s+([^\r\n]+)/i);
    if (m) g = m[1].trim();
  } catch (_) {
    g = '';
  }
  if (!g) g = FALLBACK_GUID;
  _machineGuid = g.toLowerCase().trim();
  return _machineGuid;
}

function readBindSecret() {
  if (_bind !== null) return _bind;
  try {
    const b = fs.readFileSync(BIND_FILE);
    if (b && b.length >= 32) { _bind = b.slice(0, 32); return _bind; }
  } catch (_) { /* fall through to DEFAULT_BIND */ }
  _bind = DEFAULT_BIND;
  return _bind;
}

function deriveGuid(salt) {
  const guidLower = readMachineGuid();
  const bind = readBindSecret();
  const h = crypto.createHmac('sha256', bind).update(salt + ':' + guidLower, 'utf8').digest();
  const hex = h.slice(0, 16).toString('hex'); // 32 lowercase hex chars
  return (
    hex.slice(0, 8) + '-' +
    hex.slice(8, 12) + '-' +
    hex.slice(12, 16) + '-' +
    hex.slice(16, 20) + '-' +
    hex.slice(20, 32)
  );
}

const _cache = {};
function cachedName(key, prefix, salt) {
  if (_cache[key]) return _cache[key];
  _cache[key] = prefix + deriveGuid(salt);
  return _cache[key];
}

module.exports = {
  pipeToken: () => cachedName('pipeToken', '\\\\.\\pipe\\', SALT.pipeToken),
  pipeOcr: () => cachedName('pipeOcr', '\\\\.\\pipe\\', SALT.pipeOcr),
  mutexInitGuard: () => cachedName('mtxInit', 'Local\\', SALT.mtxInit),
  mutexOcrDaemon: () => cachedName('mtxOcrd', 'Global\\', SALT.mtxOcrd),
  eventShutdown: () => cachedName('evtShut', 'Global\\', SALT.evtShut),
  // exposed for the cross-language verification test
  _deriveGuid: deriveGuid,
  _readMachineGuid: readMachineGuid,
  _readBindSecret: readBindSecret,
};
