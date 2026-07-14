// ═══════════════════════════════════════════════════════════════
// device.js — HWID collection with DISK-PERSISTENT CACHE.
//
// Matches the C-side hwid_get contract (shared/hwid.c). Same fallback
// chain so cross-side computed values agree on a healthy machine:
//   1. SMBIOS UUID via wmic csproduct  ← primary
//   2. HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid  ← fallback 1
//   3. SHA-256(ComputerName || vol C:) → UUID-formatted  ← fallback 2
//
// v6.4 (2026-07-14) — HWID rotation fix.
//
//   Reported by user jay.perkerson@gmail.com: THREE separate device
//   rows in user_devices for a single laptop (LAPTOP-PUOUN0O3), all
//   with last_seen_at within 2h of each other today. Root cause:
//   `wmic csproduct` is deprecated in Windows 11 22H2+ and behaves
//   inconsistently — sometimes returns a valid SMBIOS UUID, sometimes
//   fails silently (falls through to MachineGuid), sometimes returns
//   a malformed value that skips to synthetic. Each fallback tier
//   produces a DIFFERENT UUID for the same physical box, so:
//
//     - HWID rotates on every run → MAX_DEVICES=1 enforcement chaos
//     - Signed sub cache is HMAC-bound to HWID → rotation invalidates
//       the cache → offline-grace becomes useless
//     - Session signature is HWID-bound → rotation → sign-out loop
//
//   Fix: cache the FIRST successful HWID to disk in TWO locations
//   (dual-write, like session storage):
//     %APPDATA%\svchelper\hwid.json       (per-user, DPAPI-adjacent)
//     %ProgramData%\WinAudioSvc\hwid.json (per-machine, ACL admin+SYSTEM)
//   Subsequent runs return cached value without re-probing. Fresh
//   compute only happens if BOTH files are absent (first-ever run
//   or user wiped both).
//
//   The cache is a plain JSON blob — {hwid, source, computed_at}.
//   Not encrypted because:
//     (a) HWID is not a secret; it's a fingerprint of THIS machine
//         and any local process can compute it via the same APIs.
//     (b) If we encrypted it, we'd need to encrypt with the HWID
//         itself as the key (chicken/egg), or hard-code a key
//         (pointless).
//
//   Same HWID must be produced on the same box across launches AND
//   across the JS ↔ C boundary, or handshake_verify() inside the
//   payload rejects the config. JS caching keeps JS consistent; the
//   payload uses `cfg->handshake_hwid` (which JS wrote) so cross-
//   boundary consistency is preserved as long as JS is stable.
// ═══════════════════════════════════════════════════════════════

const { execFile, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { SVC_INSTALL_DIR } = require('./config');

// ─── Cache locations (dual-write) ────────────────────────────────
// Delegate resolution to a function so we can lazy-import Electron's
// app module (may not be available in unit tests or if this file is
// required before app.whenReady).
function _cacheAppdataPath() {
  try {
    const { app } = require('electron');
    return path.join(app.getPath('appData'), 'svchelper', 'hwid.json');
  } catch {
    // Fallback if Electron isn't available (extremely rare — unit tests
    // or non-Electron consumers). Uses APPDATA env directly.
    const base = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(base, 'svchelper', 'hwid.json');
  }
}
function _cacheProgramdataPath() {
  return path.join(SVC_INSTALL_DIR, 'hwid.json');
}

let _cache = null;                 // in-process cache — populated once
let _diskLoaded = false;           // has _loadCachedFromDisk run yet?
let _lastComputedCandidates = null;  // { wmic, machineGuid, synthetic } — see getAllCandidates()

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

// ─── HWID sources (same order as shared/hwid.c) ─────────────────
// Primary: SMBIOS UUID via wmic csproduct.
// NOTE: wmic is DEPRECATED in Windows 11 22H2+ and may be uninstalled
// entirely by 24H2. We still probe it because it's the primary path
// on Win10/early-Win11 where it works reliably. If wmic isn't
// present or returns garbage we fall through gracefully.
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

// Fallback 1: MachineGuid from registry. STABLE — written once at
// Windows install time, never rotates on the same OS install.
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

// Fallback 2: SHA-256(ComputerName || vol C:) formatted as UUID.
// STABLE — inputs don't change on the same machine.
//
// NOTE: this formula intentionally matches JS-side behavior only; the
// C-side (shared/hwid.c) uses BCrypt SHA-256 over
// (salt || computer_name || vol_c_dword) which produces a different
// digest. This divergence is BENIGN in practice because both sides
// almost always resolve HWID via one of the first two tiers where
// they agree; only pathological machines (wmic broken AND reg blocked)
// fall through to synthetic on either side. If cross-side handshake
// breaks on such a machine the user has bigger problems and support
// intervention is warranted.
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

// ─── Disk cache load/save ────────────────────────────────────────
function _ensureDir(p) {
  try { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); } catch {}
}

function _isValidHwidString(s) {
  return typeof s === 'string' && s.length >= 32 && s.includes('-') &&
         s.toUpperCase() !== 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF';
}

function _loadCachedFromDisk() {
  if (_diskLoaded) return _cache;
  _diskLoaded = true;
  // Try appdata first (per-user, more likely to be readable), then
  // programdata (per-machine, admin-only writable but readable by us
  // since we're elevated).
  const paths = [_cacheAppdataPath(), _cacheProgramdataPath()];
  for (const p of paths) {
    try {
      if (!fs.existsSync(p)) continue;
      const raw = fs.readFileSync(p, 'utf8');
      const obj = JSON.parse(raw);
      if (obj && _isValidHwidString(obj.hwid)) {
        _cache = {
          hardware_uuid: obj.hwid,
          device_name:   process.env.COMPUTERNAME || 'Windows PC',
          _source:       obj.source || 'cache',
          _computed_at:  obj.computed_at || null,
        };
        console.log(`[device] hwid loaded from ${p} (source=${obj.source || '?'}, computed=${obj.computed_at || '?'})`);
        // Also mirror to the other cache location if it's missing —
        // heals a half-wiped state (user cleared %APPDATA% but not
        // %ProgramData% or vice-versa).
        _mirrorCache(obj);
        return _cache;
      }
    } catch (e) {
      console.log(`[device] hwid cache load failed for ${p}: ${e.message}`);
    }
  }
  return null;
}

function _saveCachedToDisk(hwid, source) {
  const payload = {
    hwid,
    source: source || 'unknown',
    computed_at: new Date().toISOString(),
    version: 1,
  };
  _mirrorCache(payload);
}

function _mirrorCache(payload) {
  const json = JSON.stringify(payload, null, 2);
  const targets = [_cacheAppdataPath(), _cacheProgramdataPath()];
  for (const target of targets) {
    try {
      _ensureDir(path.dirname(target));
      fs.writeFileSync(target, json, 'utf8');
    } catch (e) {
      console.log(`[device] hwid cache write failed for ${target}: ${e.message}`);
    }
  }
}

// ─── Public API ───────────────────────────────────────────────────
async function collect() {
  // In-process cache — return immediately if we've already resolved
  // during this run.
  if (_cache) return _cache;

  // Disk cache — if a valid HWID was cached on a previous run, USE IT
  // and skip re-probing. This is the critical stability guarantee.
  const disk = _loadCachedFromDisk();
  if (disk) return disk;

  // Fresh compute — first ever run OR user wiped both cache locations.
  // Probe all three sources so callers can inspect candidates via
  // getAllCandidates() (used by main.js for HWID-rotation auto-heal
  // when the user upgraded from a pre-cache build and has stale
  // registered devices from previous rotating HWIDs).
  let source = 'unknown';
  const wmic       = await _smbios();
  const machineGuid = await _machineGuid();
  const synthetic  = _syntheticUuid();
  _lastComputedCandidates = { wmic, machineGuid, synthetic };

  let uuid = wmic;
  if (uuid) source = 'smbios_wmic';
  if (!uuid) { uuid = machineGuid; if (uuid) source = 'machine_guid'; }
  if (!uuid) { uuid = synthetic;   source = 'synthetic'; }

  _cache = {
    hardware_uuid: uuid,
    device_name:   process.env.COMPUTERNAME || 'Windows PC',
    _source:       source,
    _computed_at:  new Date().toISOString(),
  };

  console.log(`[device] hwid computed fresh (source=${source}) — persisting to disk cache`);
  _saveCachedToDisk(uuid, source);
  return _cache;
}

function getCached() { return _cache; }

// v6.4 (2026-07-14): return all HWID candidates for the current run.
// Used by main.js when verifying signed sub cache — the cache may
// have been signed against a previous HWID (before we started
// caching to disk), so we try to verify against wmic/machineGuid/
// synthetic in turn. Only meaningful after collect() has run.
async function getAllCandidates() {
  // If collect() hasn't run yet, or ran but hit the disk-cache fast
  // path (so _lastComputedCandidates is null), probe now.
  if (!_lastComputedCandidates) {
    const wmic       = await _smbios();
    const machineGuid = await _machineGuid();
    const synthetic  = _syntheticUuid();
    _lastComputedCandidates = { wmic, machineGuid, synthetic };
  }
  const c = _lastComputedCandidates;
  const cached = _cache && _cache.hardware_uuid ? _cache.hardware_uuid : null;
  // Include the currently-cached HWID first (most likely to match a
  // registered device), then all candidates, deduplicated.
  const seen = new Set();
  const out = [];
  for (const v of [cached, c.wmic, c.machineGuid, c.synthetic]) {
    if (!v) continue;
    const k = v.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  return out;
}

// v6.4: wipe on-disk cache — invoked by the renderer's "Reset local
// data & retry" nuclear option. Next call to collect() re-probes and
// re-caches. Also clears in-process state so we don't return the
// pre-wipe value from RAM.
function clearCache() {
  _cache = null;
  _diskLoaded = false;
  _lastComputedCandidates = null;
  const targets = [_cacheAppdataPath(), _cacheProgramdataPath()];
  for (const t of targets) {
    try { if (fs.existsSync(t)) fs.unlinkSync(t); }
    catch (e) { console.log(`[device] clearCache unlink ${t} failed: ${e.message}`); }
  }
}

module.exports = { collect, getCached, getAllCandidates, clearCache };
