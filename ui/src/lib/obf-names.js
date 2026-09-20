'use strict';
/*
 * obf-names.js -- Electron-side mirror of shared/obf_names.c.
 *
 * Derives the SAME per-box camouflaged object names the C payload +
 * launcher derive, so the token-refresh pipe, OCR pipe, and (future)
 * status event line up. See shared/obf_names.h for the full rationale.
 *
 * CONTRACT (must match shared/obf_names.c byte-for-byte):
 *   guidLower = lowercase(trim(MachineGuid))         // HKLM Cryptography
 *   digest    = SHA256( salt + ":" + guidLower )     // UTF-8/ASCII bytes
 *   nameGuid  = hex(digest[0..15]) grouped 8-4-4-4-12 (lowercase)
 *   full      = prefix + nameGuid
 *
 * Any change to the salts or formatting MUST be mirrored in
 * shared/obf_names.c and re-verified with the cross-language check,
 * or IPC + the injected-status probe silently break.
 */

const crypto = require('crypto');
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

let _machineGuid = null;

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

function deriveGuid(salt) {
  const guidLower = readMachineGuid();
  const h = crypto.createHash('sha256').update(salt + ':' + guidLower, 'utf8').digest();
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
};
