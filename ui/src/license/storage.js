// ═══════════════════════════════════════════════════════════════
// storage.js — Encrypted session persistence.
//
// Primary:  Electron safeStorage (DPAPI on Windows) → session.enc in
//           appData. Bound to the current Windows user account.
// Fallback: AES-256-GCM with a key derived from HWID + hostname →
//           session.dat in SVC_INSTALL_DIR. Survives DPAPI edge cases
//           (safe-storage-not-available: user profile still loading, or
//           process launched from an unusual desktop / integrity level).
//
// Loading: try DPAPI first; on failure fall back to portable AES.
// Saving:  write BOTH, so recovery works from either.
// ═══════════════════════════════════════════════════════════════

const { safeStorage, app } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

const device = require('./device');
const { SVC_INSTALL_DIR } = require('./config');

const APPDATA_DIR = path.join(app.getPath('appData'), 'svchelper');
const DPAPI_FILE  = path.join(APPDATA_DIR, 'session.enc');
const AES_FILE    = path.join(SVC_INSTALL_DIR, 'ui_session.dat');

function ensureDir(p) {
  try { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); } catch {}
}

// ─── Portable AES-256-GCM (HWID + host derived key) ─────────────
function portableKey() {
  const hwid = device.getCached()?.hardware_uuid || 'no-hwid';
  const seed = `${hwid}|${os.hostname()}|svchelper-portable-v1`;
  return crypto.createHash('sha256').update(seed).digest();
}

function aesEncrypt(plaintext) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', portableKey(), iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]);
}

function aesDecrypt(buf) {
  if (!buf || buf.length < 29) return null;
  const iv  = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', portableKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
  } catch { return null; }
}

// ─── DPAPI helpers ──────────────────────────────────────────────
function dpapiSave(filepath, plaintext) {
  try {
    if (!safeStorage.isEncryptionAvailable()) return false;
    const enc = safeStorage.encryptString(plaintext);
    fs.writeFileSync(filepath, enc);
    return true;
  } catch (e) {
    console.log('[storage] dpapi save failed:', e.message);
    return false;
  }
}

function dpapiLoad(filepath) {
  try {
    if (!fs.existsSync(filepath)) return null;
    if (!safeStorage.isEncryptionAvailable()) return null;
    return safeStorage.decryptString(fs.readFileSync(filepath));
  } catch (e) {
    console.log('[storage] dpapi load failed:', e.message);
    return null;
  }
}

function del(filepath) {
  try { if (fs.existsSync(filepath)) fs.unlinkSync(filepath); } catch {}
}

// ─── Public session API ─────────────────────────────────────────
function saveSession(session) {
  ensureDir(APPDATA_DIR);
  ensureDir(SVC_INSTALL_DIR);
  const json = JSON.stringify(session);
  const dOk = dpapiSave(DPAPI_FILE, json);
  try { fs.writeFileSync(AES_FILE, aesEncrypt(json)); } catch (e) {
    console.log('[storage] aes save failed:', e.message);
  }
  console.log(`[storage] saveSession dpapi=${dOk} aes_written=${fs.existsSync(AES_FILE)}`);
}

function loadSession() {
  // Try DPAPI first (per-user), then portable AES (per-machine).
  let raw = dpapiLoad(DPAPI_FILE);
  if (!raw && fs.existsSync(AES_FILE)) {
    try { raw = aesDecrypt(fs.readFileSync(AES_FILE)); } catch {}
  }
  if (!raw) return null;
  try { return JSON.parse(raw); }
  catch { clearSession(); return null; }
}

function clearSession() {
  del(DPAPI_FILE);
  del(AES_FILE);
}

function hasSession() {
  return fs.existsSync(DPAPI_FILE) || fs.existsSync(AES_FILE);
}

// ─── Session validity helpers ────────────────────────────────────
function isExpired(session) {
  if (!session || !session.expires_at) return true;
  // 5-minute buffer so we treat "about to expire" as expired.
  return session.expires_at < Math.floor(Date.now() / 1000) + 300;
}

function isStale(session, maxAgeMs) {
  if (!session || !session.created_at) return false;
  const ageMs = Date.now() - session.created_at * 1000;
  return ageMs > maxAgeMs;
}

module.exports = {
  saveSession, loadSession, clearSession, hasSession,
  isExpired, isStale,
};
