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

/* v1.7.2 (2026-07-17): file now supports two shapes for back-compat:
 *   { "3": 66535, "24": ... }                                (legacy)
 *   { "v":2, "overrides":{...}, "speed_mode":"adaptive" }    (v2)
 *   { "v":3, "defaults_version": N, "overrides":..., ... }   (v3)
 * Callers use loadHotkeyOverrides / loadHotkeyPrefs and get either
 * the flat override map or the full prefs object. Writers always
 * emit v3 shape.
 *
 * v1.7.4.6 (2026-07-24): added defaults_version stamp.
 *
 * When we ship a new default hotkey map (e.g. flipping from Ctrl+
 * Alt+G to triple-G for TOGGLE), users with saved overrides from
 * an OLDER default set would see the OLD binding — because the
 * override slot's packed uint takes precedence over the new default
 * for that slot, regardless of what changed. Result: user reports
 * "why is toggle overlay not 3x G though thats the question i
 * thought u said u got that".
 *
 * Fix: stamp each save with `defaults_version = HOTKEYS_DEFAULTS_VER`.
 * On load, if stamp differs from current version, DISCARD the
 * overrides (return empty {}) so the new defaults apply cleanly.
 * User's speed_mode preference is preserved across the discard.
 *
 * IMPORTANT: BUMP this constant every time DEFAULT_HOTKEYS in
 * injector.js changes shape or slot->key mapping. Ok to leave
 * constant across minor bug-fix versions that don't touch the
 * default map. */
const HOTKEYS_DEFAULTS_VER = 5;   /* v1.7.4.17 = + SVC_HK_QUICK_ASK slot 33 (unbound default) */
const SPEED_MODES = ['fast','normal','slow','adaptive'];

function _readHotkeyFile() {
  try {
    if (!fs.existsSync(HOTKEYS_FILE)) return { overrides: {}, speed_mode: 'adaptive' };
    const raw = fs.readFileSync(HOTKEYS_FILE, 'utf8');
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== 'object') return { overrides: {}, speed_mode: 'adaptive' };
    /* v1.7.4.6: check defaults_version — if the saved overrides are
     * from an older default set, discard them so the user gets the
     * fresh defaults (rather than being stuck with obsolete mappings
     * they never explicitly chose). speed_mode preference survives. */
    const stampedVer = (obj.v === 3 && Number.isFinite(obj.defaults_version))
                       ? obj.defaults_version : 0;
    if (obj.v === 2 || obj.v === 3) {
      const speed = SPEED_MODES.includes(obj.speed_mode) ? obj.speed_mode : 'adaptive';
      if (stampedVer !== HOTKEYS_DEFAULTS_VER) {
        console.log(`[storage] hotkey overrides from defaults v${stampedVer} discarded (current v${HOTKEYS_DEFAULTS_VER})`);
        return { overrides: {}, speed_mode: speed };
      }
      return { overrides: (obj.overrides || {}), speed_mode: speed };
    }
    // Legacy shape (flat map) = definitely from an old default set.
    console.log('[storage] legacy-shape hotkey overrides discarded (defaults changed)');
    return { overrides: {}, speed_mode: 'adaptive' };
  } catch (e) {
    console.log('[storage] hotkey load failed:', e.message);
    return { overrides: {}, speed_mode: 'adaptive' };
  }
}

function loadHotkeyOverrides() {
  return _readHotkeyFile().overrides;
}

function loadHotkeyPrefs() {
  return _readHotkeyFile();
}

function saveHotkeyOverrides(map) {
  const prev = _readHotkeyFile();
  return saveHotkeyPrefs({ overrides: map || {}, speed_mode: prev.speed_mode });
}

function saveHotkeyPrefs(prefs) {
  ensureDir(APPDATA_DIR);
  try {
    const speed = SPEED_MODES.includes(prefs && prefs.speed_mode) ? prefs.speed_mode : 'adaptive';
    const overrides = (prefs && prefs.overrides && typeof prefs.overrides === 'object') ? prefs.overrides : {};
    /* v1.7.4.6: stamp with current defaults version so future loads
     * can detect stale overrides + auto-discard. */
    const doc = { v: 3, defaults_version: HOTKEYS_DEFAULTS_VER, overrides, speed_mode: speed };
    fs.writeFileSync(HOTKEYS_FILE, JSON.stringify(doc, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.log('[storage] hotkey save failed:', e.message);
    return false;
  }
}

function clearHotkeyOverrides() {
  del(HOTKEYS_FILE);
}

// ─── v1.2 (2026-07-06) — Overlay-appearance persistence ─────────
// User-picked launch size + alpha + ultra-mode toggle from the
// dashboard's "Overlay appearance" card. Persisted as plain JSON
// (no secrets - purely cosmetic). Applied on next "Inject Now".
//
// Shape returned by loadOverlayConfig (always fully populated —
// missing fields default so the caller can spread directly):
//   {
//     size_mode:      0 | 1,          // 0=normal, 1=ultra
//     w:              200..4000,
//     h:              140..3000,
//     alpha:          0.20..1.00,
//     theme:          0 | 1 | 2,      // 0=dark 1=light 2=auto (v11)
//     overlay_flags:  bitfield,       // v11: TRAIL_ERASE | SMOOTH_NUDGE | UNIFORM_ALPHA | OPAQUE_LOCK
//   }
const OVERLAY_FILE = path.join(APPDATA_DIR, 'overlay.json');

// v11 overlay flag bit constants — mirror shared/config_types.h.
const OVFLAG_TRAIL_ERASE   = 0x1;
const OVFLAG_SMOOTH_NUDGE  = 0x2;
const OVFLAG_UNIFORM_ALPHA = 0x4;
const OVFLAG_OPAQUE_LOCK   = 0x8;
/* v11.2.3 — TRAIL_ERASE off (v1.7.6.1 shadow-flicker fix), OPAQUE_LOCK
 * ON (forces g_alpha=1.0 unconditionally, cures persistent translucency). */
const OVFLAG_DEFAULTS      = OVFLAG_SMOOTH_NUDGE | OVFLAG_UNIFORM_ALPHA | OVFLAG_OPAQUE_LOCK;

const OVERLAY_DEFAULTS = Object.freeze({
  size_mode:      0,
  w:              560,
  h:              420,
  alpha:          1.00,             // v11 (2026-07-24): default OPAQUE for zero trailing
  theme:          2,                // v11: default AUTO — follow Windows theme
  overlay_flags:  OVFLAG_DEFAULTS,  // v11: trail-erase + smooth-nudge + uniform-alpha ON
  scroll_step_px: 80,               // v12 (2026-07-25): pixels per scroll hotkey / mouse wheel notch
});

function _clampOverlayInput(o) {
  if (!o || typeof o !== 'object') return { ...OVERLAY_DEFAULTS };
  const ultra = o.size_mode === 1 || o.size_mode === '1' || o.size_mode === true ? 1 : 0;
  const wMin = ultra ?  80 : 200;
  const wMax = ultra ? 4000 : 1400;
  const hMin = ultra ?  60 : 140;
  const hMax = ultra ? 3000 : 1200;
  let w = Number.isFinite(+o.w) ? Math.round(+o.w) : OVERLAY_DEFAULTS.w;
  let h = Number.isFinite(+o.h) ? Math.round(+o.h) : OVERLAY_DEFAULTS.h;
  let a = Number.isFinite(+o.alpha) ? +o.alpha : OVERLAY_DEFAULTS.alpha;
  if (w < wMin) w = wMin;
  if (w > wMax) w = wMax;
  if (h < hMin) h = hMin;
  if (h > hMax) h = hMax;
  if (a < 0.20) a = 0.20;
  if (a > 1.00) a = 1.00;
  // theme: 0=dark, 1=light, 2=auto — anything else defaults to auto.
  let theme = 2;
  if (o.theme === 0 || o.theme === '0' || o.theme === 'dark')  theme = 0;
  else if (o.theme === 1 || o.theme === '1' || o.theme === 'light') theme = 1;
  else if (o.theme === 2 || o.theme === '2' || o.theme === 'auto')  theme = 2;
  // overlay_flags: bitfield, sanitize to known bits only.
  let flg = Number.isFinite(+o.overlay_flags) ? (+o.overlay_flags | 0) : OVFLAG_DEFAULTS;
  flg &= (OVFLAG_TRAIL_ERASE | OVFLAG_SMOOTH_NUDGE | OVFLAG_UNIFORM_ALPHA | OVFLAG_OPAQUE_LOCK);
  // v12 (2026-07-25): scroll_step_px — user-configurable scroll granularity.
  // Range 20-400. Default 80 matches pre-v12 hardcoded value.
  let scr = Number.isFinite(+o.scroll_step_px) ? Math.round(+o.scroll_step_px) : OVERLAY_DEFAULTS.scroll_step_px;
  if (scr < 20)  scr = 20;
  if (scr > 400) scr = 400;
  return {
    size_mode: ultra,
    w, h,
    alpha: Math.round(a * 100) / 100,
    theme,
    overlay_flags: flg,
    scroll_step_px: scr,
  };
}

function loadOverlayConfig() {
  try {
    if (!fs.existsSync(OVERLAY_FILE)) return { ...OVERLAY_DEFAULTS };
    const raw = fs.readFileSync(OVERLAY_FILE, 'utf8');
    const obj = JSON.parse(raw);
    return _clampOverlayInput(obj);
  } catch (e) {
    console.log('[storage] overlay load failed:', e.message);
  }
  return { ...OVERLAY_DEFAULTS };
}

function saveOverlayConfig(o) {
  ensureDir(APPDATA_DIR);
  const clean = _clampOverlayInput(o);
  try {
    fs.writeFileSync(OVERLAY_FILE, JSON.stringify(clean, null, 2), 'utf8');
    return clean;
  } catch (e) {
    console.log('[storage] overlay save failed:', e.message);
    return null;
  }
}

function clearOverlayConfig() {
  del(OVERLAY_FILE);
}

module.exports = {
  saveSession, loadSession, clearSession, hasSession,
  isExpired, isStale,
  saveSubscriptionCache, loadSubscriptionCache, clearSubscriptionCache,
  isOnboardingComplete, setOnboardingComplete, resetOnboarding,
  loadHotkeyOverrides, saveHotkeyOverrides, clearHotkeyOverrides,
  loadHotkeyPrefs, saveHotkeyPrefs,
  loadOverlayConfig, saveOverlayConfig, clearOverlayConfig,
  OVERLAY_DEFAULTS,
  OVFLAG_TRAIL_ERASE, OVFLAG_SMOOTH_NUDGE, OVFLAG_UNIFORM_ALPHA, OVFLAG_OPAQUE_LOCK,
  OVFLAG_DEFAULTS,
};
