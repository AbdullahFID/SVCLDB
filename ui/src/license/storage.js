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
const SUB_DPAPI_FILE = path.join(APPDATA_DIR,      'subscription.enc');
const SUB_AES_FILE   = path.join(SVC_INSTALL_DIR,  'ui_subscription.dat');

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

// ─── Signed subscription cache ───────────────────────────────────
//
// Used by subscription.js + revalidation.js to provide OFFLINE GRACE:
// after N consecutive network failures the app would normally lock the
// user out (fair on stolen configs; unfair to a paying customer on flaky
// exam-day wifi). We instead check if we have a cached subscription
// whose HMAC signature verifies AND whose `_cachedAt` is inside the
// GRACE_PERIOD_MS window, in which case we let them continue.
//
// The HMAC is computed by license/subscription.js using
// LICENSE_RESPONSE_SECRET + HWID as the key, so a stolen file lifted
// off a different machine won't verify — the cache is bound to the
// hardware that signed it.
function saveSubscriptionCache(sub) {
  ensureDir(APPDATA_DIR);
  ensureDir(SVC_INSTALL_DIR);
  const json = typeof sub === 'string' ? sub : JSON.stringify(sub);
  const dOk = dpapiSave(SUB_DPAPI_FILE, json);
  try { fs.writeFileSync(SUB_AES_FILE, aesEncrypt(json)); } catch (e) {
    console.log('[storage] sub aes save failed:', e.message);
  }
  console.log(`[storage] saveSubscriptionCache dpapi=${dOk} aes_written=${fs.existsSync(SUB_AES_FILE)}`);
}

function loadSubscriptionCache() {
  let raw = dpapiLoad(SUB_DPAPI_FILE);
  if (!raw && fs.existsSync(SUB_AES_FILE)) {
    try { raw = aesDecrypt(fs.readFileSync(SUB_AES_FILE)); } catch {}
  }
  if (!raw) return null;
  try { return JSON.parse(raw); }
  catch { clearSubscriptionCache(); return null; }
}

function clearSubscriptionCache() {
  del(SUB_DPAPI_FILE);
  del(SUB_AES_FILE);
}

// ─── Onboarding flag ─────────────────────────────────────────────
// Stored as a marker file in appData. Absence = show onboarding
// (first-run OR user requested "restart tutorial"). Presence =
// user has completed the walkthrough at least once. Nothing sensitive
// so no encryption needed.
const ONBOARDING_FILE = path.join(APPDATA_DIR, 'onboarding_complete.flag');

function isOnboardingComplete() {
  try { return fs.existsSync(ONBOARDING_FILE); }
  catch { return false; }
}

function setOnboardingComplete() {
  ensureDir(APPDATA_DIR);
  try { fs.writeFileSync(ONBOARDING_FILE, String(Date.now())); return true; }
  catch (e) {
    console.log('[storage] onboarding flag set failed:', e.message);
    return false;
  }
}

function resetOnboarding() {
  del(ONBOARDING_FILE);
}

// ─── Hotkey overrides ────────────────────────────────────────────
// User-customized hotkey bindings from the settings UI. Persisted as
// a JSON dict { [slotIndex]: packedUInt } — slots the user hasn't
// customized are absent and fall back to injector.js DEFAULT_HOTKEYS.
//
// Stored under appData (not encrypted — hotkey preferences aren't
// secret and users may want to hand-edit the JSON if the UI breaks).
const HOTKEYS_FILE = path.join(APPDATA_DIR, 'hotkeys.json');

function loadHotkeyOverrides() {
  try {
    if (!fs.existsSync(HOTKEYS_FILE)) return {};
    const raw = fs.readFileSync(HOTKEYS_FILE, 'utf8');
    const obj = JSON.parse(raw);
    if (obj && typeof obj === 'object') return obj;
  } catch (e) {
    console.log('[storage] hotkey load failed:', e.message);
  }
  return {};
}

function saveHotkeyOverrides(map) {
  ensureDir(APPDATA_DIR);
  try {
    fs.writeFileSync(HOTKEYS_FILE, JSON.stringify(map || {}, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.log('[storage] hotkey save failed:', e.message);
    return false;
  }
}

function clearHotkeyOverrides() {
  del(HOTKEYS_FILE);
}

module.exports = {
  saveSession, loadSession, clearSession, hasSession,
  isExpired, isStale,
  saveSubscriptionCache, loadSubscriptionCache, clearSubscriptionCache,
  isOnboardingComplete, setOnboardingComplete, resetOnboarding,
  loadHotkeyOverrides, saveHotkeyOverrides, clearHotkeyOverrides,
};
