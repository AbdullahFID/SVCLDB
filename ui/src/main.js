// ═══════════════════════════════════════════════════════════════
// main.js — Electron entry point for svchelper (CloakGPT UI).
//
// Responsibilities:
//   1. Enforce single-instance + admin elevation (declared in manifest).
//   2. Create the frameless 900×680 window with the CloakGPT palette.
//   3. Wire IPC handlers the renderer calls:
//      - license:load         → { session, subscription } or null
//      - license:sign-in      → run OAuth PKCE
//      - license:sign-out     → clear cached session
//      - license:pending-url  → most recent auth URL (for Copy button)
//      - api-key:load         → read persisted API key
//      - api-key:save         → persist API key (DPAPI + portable AES)
//      - injector:status      → { payload_loaded, ldb_running }
//      - injector:inject      → run sihost --json-config
//      - injector:uninject    → run sihost --unload
//      - injector:kill-all    → run sihost --kill-all
//      - window:minimize / :close
//   4. Register a global hotkey Ctrl+Shift+Alt+H that shows/focuses
//      the window (so the user can re-summon it after minimize).
// ═══════════════════════════════════════════════════════════════

const { app, BrowserWindow, ipcMain, globalShortcut, safeStorage, shell, screen } = require('electron');
const path = require('path');
const fs   = require('fs');
const { execFile } = require('child_process');

const device       = require('./license/device');
const auth         = require('./license/auth');
const storage      = require('./license/storage');
const subscription = require('./license/subscription');
const revalidation = require('./license/revalidation');
const security     = require('./license/security');
const mitm         = require('./license/mitm');
const registration = require('./license/registration');
const injector     = require('./injector/injector');
const { SVC_INSTALL_DIR } = require('./license/config');

// ─── First-run install ─────────────────────────────────────────
// Copy the C binaries bundled as extraResources into SVC_INSTALL_DIR
// so `sihost.exe --json-config` + `dllhost32.exe` are reachable at the
// paths the injector hardcodes. Idempotent — only copies files that
// are MISSING or STALE (size or mtime mismatch). Runs on every launch,
// but the copy is a no-op after first successful install.
//
// The user's exe is single-download-run — Electron packs these 5 C
// binaries inside `resources/` next to the exe; on first launch we
// mirror them out to C:\ProgramData\WinAudioSvc\.
function ensureCBinariesInstalled() {
  const bins = [
    'sihost.exe',        // launcher (embeds dwmapiext.dll as RCDATA)
    'dllhost32.exe',     // resolver (fetches DWM PDB → offsets.blob)
    'cgpt_dbghelp.dll',  // SDK dbghelp (symbol-server capable)
    'symsrv.dll',        // Microsoft PDB fetcher
    'dwmapiext.dll',     // payload — backup, sihost.exe usually reads from its own RCDATA
  ];
  try { if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true }); }
  catch (e) { console.log('[install] mkdir SVC_INSTALL_DIR failed:', e.message); return; }

  // In dev (`npm start`), resourcesPath points to node_modules/electron/dist/resources
  // — no bundled binaries there. Skip cleanly; user runs iteration builds by hand.
  const srcDir = process.resourcesPath;
  if (!srcDir || !fs.existsSync(path.join(srcDir, 'sihost.exe'))) {
    console.log('[install] no bundled C binaries in resourcesPath — skipping (dev mode?)');
    return;
  }

  /* v4.5: on-upgrade auto-cleanup. If ANY bundled binary is newer AND
   * different-sized than what's already deployed, it means the user
   * dropped a newer svchelper.exe next to an older-version install
   * (typical zip-over-zip upgrade). We uninject the currently-loaded
   * payload BEFORE overwriting sihost.exe / dwmapiext.dll — otherwise
   * the DLL file on disk changes while DWM still holds the old copy,
   * subsequent --reinject would double-init, and the offsets.blob would
   * be for a different DLL layout. Config.dat + session + api_keys are
   * preserved (they're not in the `bins` list). */
  let upgradeDetected = false;
  for (const b of bins) {
    const src = path.join(srcDir, b);
    const dst = path.join(SVC_INSTALL_DIR, b);
    if (!fs.existsSync(src) || !fs.existsSync(dst)) continue;
    try {
      const s = fs.statSync(src), d = fs.statSync(dst);
      if (s.mtimeMs > d.mtimeMs && s.size !== d.size) {
        upgradeDetected = true;
        break;
      }
    } catch {}
  }
  if (upgradeDetected) {
    console.log('[install] upgrade detected — uninjecting stale payload before overwrite');
    try {
      const injector = require('./injector/injector');
      // Fire and forget with short timeout — if payload isn't loaded,
      // this returns quickly; if it is, sihost --unload takes ~500ms.
      const { spawnSync } = require('child_process');
      const legacySihost = path.join(SVC_INSTALL_DIR, 'sihost.exe');
      if (fs.existsSync(legacySihost)) {
        spawnSync(legacySihost, ['--unload'], {
          windowsHide: true, stdio: 'ignore', timeout: 4000,
        });
        console.log('[install] legacy sihost --unload complete');
      }
    } catch (e) {
      console.log('[install] pre-upgrade uninject skipped:', e.message);
    }
  }

  for (const b of bins) {
    const src = path.join(srcDir, b);
    if (!fs.existsSync(src)) continue;
    const dst = path.join(SVC_INSTALL_DIR, b);
    let needCopy = !fs.existsSync(dst);
    if (!needCopy) {
      try {
        const s = fs.statSync(src), d = fs.statSync(dst);
        needCopy = s.mtimeMs > d.mtimeMs || s.size !== d.size;
      } catch { needCopy = true; }
    }
    if (needCopy) {
      try { fs.copyFileSync(src, dst); console.log(`[install] copied ${b} (${fs.statSync(dst).size} B)`); }
      catch (e) { console.log(`[install] copy ${b} FAILED: ${e.message}`); }
    }
  }
}

// ─── Windows Defender self-exclusion ──────────────────────────
// User's threat model prioritises functionality over AV visibility.
// We're already elevated (admin manifest), so Add-MpPreference works.
// Adds:
//   - ExclusionPath  C:\ProgramData\WinAudioSvc\
//   - ExclusionProcess svchelper.exe / sihost.exe / dllhost32.exe / dwm.exe
//
// If Defender is disabled by policy, replaced by third-party AV, or the
// module is not present, Add-MpPreference throws and we swallow it.
// Fires once per launch — Defender preferences are stored persistently
// so subsequent runs are effectively no-ops.
function ensureDefenderExclusions() {
  const paths = [SVC_INSTALL_DIR];
  const procs = ['svchelper.exe', 'sihost.exe', 'dllhost32.exe', 'dwmapiext.dll', 'dwm.exe'];
  const ps = `
    $ErrorActionPreference = 'SilentlyContinue'
    try {
      Add-MpPreference -ExclusionPath ${paths.map(p => `'${p.replace(/'/g, "''")}'`).join(',')} -ErrorAction Stop
      Add-MpPreference -ExclusionProcess ${procs.map(p => `'${p}'`).join(',')}  -ErrorAction Stop
      Write-Output 'DEFENDER_OK'
    } catch {
      Write-Output ('DEFENDER_FAIL: ' + $_.Exception.Message)
    }
  `.trim();
  return new Promise((resolve) => {
    execFile('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', ps],
      { windowsHide: true, timeout: 15000, encoding: 'utf8' },
      (err, stdout) => {
        console.log('[defender]', (stdout || '').trim() || (err ? err.message : ''));
        resolve(true);
      });
  });
}

// ─── Single instance ────────────────────────────────────────────
if (!app.requestSingleInstanceLock()) {
  app.quit();
}
app.on('second-instance', () => {
  if (mainWin) {
    if (mainWin.isMinimized()) mainWin.restore();
    mainWin.show();
    mainWin.focus();
  }
});

// ─── Global state ───────────────────────────────────────────────
let mainWin      = null;
let currentSess  = null;
let currentSub   = null;

// ─── API-key persistence (DPAPI-first + portable AES fallback) ──
//
// v4.4: bag of keys, one per provider. Stored as a JSON dict then
// encrypted end-to-end with the same DPAPI + portable-AES dual write
// the session storage uses.
//
// Legacy `api.enc` (single-key blob) is auto-migrated on first load
// into keys.openrouter (safest catch-all) so users upgrading from v4.3
// don't lose their key.
const API_KEYS_APPDATA  = () => path.join(app.getPath('appData'), 'svchelper', 'api_keys.enc');
const API_KEYS_PORTABLE = () => path.join(SVC_INSTALL_DIR, 'ui_api_keys.dat');
const API_KEYS_LEGACY_APPDATA  = () => path.join(app.getPath('appData'), 'svchelper', 'api.enc');
const API_KEYS_LEGACY_PORTABLE = () => path.join(SVC_INSTALL_DIR, 'ui_api.dat');

function _portableCryptoKey() {
  const os = require('os');
  const crypto = require('crypto');
  const hwid = device.getCached()?.hardware_uuid || 'no-hwid';
  const seed = `${hwid}|${os.hostname()}|svchelper-portable-v1`;
  return crypto.createHash('sha256').update(seed).digest();
}

function _aesEnc(plain) {
  const crypto = require('crypto');
  const key = _portableCryptoKey();
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]);
}
function _aesDec(buf) {
  if (!buf || buf.length < 29) return null;
  const crypto = require('crypto');
  const key = _portableCryptoKey();
  const iv  = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
  } catch { return null; }
}

// Return { openai, anthropic, google, openrouter } — never null, always
// a full object with (possibly empty) string values.
function loadApiKeys() {
  const empty = { openai: '', anthropic: '', google: '', openrouter: '' };
  let raw = null;
  // 1. Try DPAPI first (per-user, most trusted).
  try {
    if (fs.existsSync(API_KEYS_APPDATA()) && safeStorage.isEncryptionAvailable()) {
      raw = safeStorage.decryptString(fs.readFileSync(API_KEYS_APPDATA()));
    }
  } catch (e) { console.log('[main] api-keys dpapi load fail:', e.message); }
  // 2. Fall back to portable AES-GCM.
  if (!raw) {
    try {
      if (fs.existsSync(API_KEYS_PORTABLE())) {
        raw = _aesDec(fs.readFileSync(API_KEYS_PORTABLE()));
      }
    } catch (e) { console.log('[main] api-keys aes load fail:', e.message); }
  }
  if (raw) {
    try {
      const obj = JSON.parse(raw);
      return { ...empty, ...obj };
    } catch { /* fall through to legacy migration */ }
  }
  // 3. Legacy migration: single-key blob from v4.3.
  //    Best guess is that the previously-used single key was for
  //    whichever provider the prefix identifies; slot it there.
  let legacy = null;
  try {
    if (fs.existsSync(API_KEYS_LEGACY_APPDATA()) && safeStorage.isEncryptionAvailable()) {
      legacy = safeStorage.decryptString(fs.readFileSync(API_KEYS_LEGACY_APPDATA()));
    }
  } catch {}
  if (!legacy) {
    try {
      if (fs.existsSync(API_KEYS_LEGACY_PORTABLE())) {
        legacy = _aesDec(fs.readFileSync(API_KEYS_LEGACY_PORTABLE()));
      }
    } catch {}
  }
  if (legacy) {
    const inj = require('./injector/injector');
    const p = inj.detectProvider(legacy);
    const slot =
      p === inj.PROVIDER.OPENAI     ? 'openai' :
      p === inj.PROVIDER.ANTHROPIC  ? 'anthropic' :
      p === inj.PROVIDER.GOOGLE     ? 'google' :
                                       'openrouter';
    const migrated = { ...empty, [slot]: legacy };
    console.log('[main] migrated legacy single api_key into slot:', slot);
    saveApiKeys(migrated);
    // Best-effort delete legacy files so we don't migrate twice.
    try { fs.unlinkSync(API_KEYS_LEGACY_APPDATA()); } catch {}
    try { fs.unlinkSync(API_KEYS_LEGACY_PORTABLE()); } catch {}
    return migrated;
  }
  return empty;
}

function saveApiKeys(keys) {
  const empty = { openai: '', anthropic: '', google: '', openrouter: '' };
  const merged = { ...empty, ...(keys || {}) };
  const json = JSON.stringify(merged);
  try { if (!fs.existsSync(path.dirname(API_KEYS_APPDATA()))) fs.mkdirSync(path.dirname(API_KEYS_APPDATA()), { recursive: true }); } catch {}
  try { if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true }); } catch {}
  let dOk = false;
  try {
    if (safeStorage.isEncryptionAvailable()) {
      fs.writeFileSync(API_KEYS_APPDATA(), safeStorage.encryptString(json));
      dOk = true;
    }
  } catch (e) { console.log('[main] api-keys dpapi save fail:', e.message); }
  try { fs.writeFileSync(API_KEYS_PORTABLE(), _aesEnc(json)); }
  catch (e) { console.log('[main] api-keys aes save fail:', e.message); }
  return dOk;
}

function clearApiKeys() {
  try { fs.unlinkSync(API_KEYS_APPDATA()); } catch {}
  try { fs.unlinkSync(API_KEYS_PORTABLE()); } catch {}
  try { fs.unlinkSync(API_KEYS_LEGACY_APPDATA()); } catch {}
  try { fs.unlinkSync(API_KEYS_LEGACY_PORTABLE()); } catch {}
}

// ─── v6 (2026-07-06) — User's custom system-prompt persistence ──
//
// Two shapes stored in one JSON blob under appData:
//   { text: "...", mode: "off" | "append" | "override" }
//
//   - mode "off" (default): payload uses its built-in ~10 KB prompt
//     (SVCLDB_DEFAULT_SYSTEM_PROMPT in ai_provider.c). User's text
//     is preserved on disk but not sent.
//   - mode "append": inject as `APPEND:\n<text>` so the payload uses
//     the built-in prompt + user's text appended (recommended path).
//   - mode "override": inject the user's text verbatim (power user;
//     they lose the built-in expertise + display constraints).
//
// Also stores direct_answer_mode flag as a separate persisted setting
// (independent of custom-prompt text since users typically toggle it
// per-question rather than per-session).
const SYSTEM_PROMPT_APPDATA  = () => path.join(app.getPath('appData'), 'svchelper', 'system_prompt.json');
const SYSTEM_PROMPT_PORTABLE = () => path.join(SVC_INSTALL_DIR, 'ui_system_prompt.dat');

function loadSystemPrompt() {
  const empty = {
    text: '', mode: 'off',
    direct_answer_mode: 0,
    /* v6.1 (2026-07-06 evening): AI-answer preferences that live in
     * the same encrypted blob because they're all "how the AI
     * behaves" toggles the user configures in one card:
     *   latex_mode: 'auto' (AI decides) | 'off' (AI told to use Unicode)
     *   stream_display: 'live' | 'batched' (hold until complete)
     * v6.3 (2026-07-06 later): stream_display DEFAULTS to 'batched'
     * per user request. Reasoning: ~200x fewer DWM recompose passes
     * per answer + no ImGui re-layout of partial math/code = massive
     * stability win. The live-typing UX is a novelty; correctness of
     * the final rendered answer is what matters. Users who prefer
     * the type-along feel can flip the toggle back off. */
    latex_mode: 'auto',
    stream_display: 'batched',
  };
  let raw = null;
  try {
    if (fs.existsSync(SYSTEM_PROMPT_APPDATA()) && safeStorage.isEncryptionAvailable()) {
      raw = safeStorage.decryptString(fs.readFileSync(SYSTEM_PROMPT_APPDATA()));
    }
  } catch (e) { console.log('[main] system-prompt dpapi load fail:', e.message); }
  if (!raw) {
    try {
      if (fs.existsSync(SYSTEM_PROMPT_PORTABLE())) {
        raw = _aesDec(fs.readFileSync(SYSTEM_PROMPT_PORTABLE()));
      }
    } catch (e) { console.log('[main] system-prompt aes load fail:', e.message); }
  }
  if (!raw) return empty;
  try {
    const obj = JSON.parse(raw);
    return { ...empty, ...obj };
  } catch { return empty; }
}

function saveSystemPrompt(payload) {
  const empty = {
    text: '', mode: 'off',
    direct_answer_mode: 0,
    latex_mode: 'auto',
    /* v6.3: default stream_display flipped to 'batched' - see loadSystemPrompt */
    stream_display: 'batched',
  };
  const merged = { ...empty, ...(payload || {}) };
  // Sanitize: cap text at 15 KB (payload struct field is 16 KB;
  // leave headroom for APPEND: prefix + framing).
  if (typeof merged.text !== 'string') merged.text = '';
  if (merged.text.length > 15 * 1024) merged.text = merged.text.slice(0, 15 * 1024);
  if (!['off', 'append', 'override'].includes(merged.mode)) merged.mode = 'off';
  if (!['auto', 'off'].includes(merged.latex_mode)) merged.latex_mode = 'auto';
  if (!['live', 'batched'].includes(merged.stream_display)) merged.stream_display = 'live';
  merged.direct_answer_mode = merged.direct_answer_mode ? 1 : 0;

  const json = JSON.stringify(merged);
  try { if (!fs.existsSync(path.dirname(SYSTEM_PROMPT_APPDATA()))) fs.mkdirSync(path.dirname(SYSTEM_PROMPT_APPDATA()), { recursive: true }); } catch {}
  try { if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true }); } catch {}
  try {
    if (safeStorage.isEncryptionAvailable()) {
      fs.writeFileSync(SYSTEM_PROMPT_APPDATA(), safeStorage.encryptString(json));
    }
  } catch (e) { console.log('[main] system-prompt dpapi save fail:', e.message); }
  try { fs.writeFileSync(SYSTEM_PROMPT_PORTABLE(), _aesEnc(json)); }
  catch (e) { console.log('[main] system-prompt aes save fail:', e.message); }
  return merged;
}

function clearSystemPrompt() {
  try { fs.unlinkSync(SYSTEM_PROMPT_APPDATA()); } catch {}
  try { fs.unlinkSync(SYSTEM_PROMPT_PORTABLE()); } catch {}
}

// Turn a persisted { text, mode } record into the string that goes
// into cfg->system_prompt on the C side. Contract mirrored in
// payload/src/ai/ai_provider.c::materialize_default_system.
function _computeSystemPromptString(persisted) {
  if (!persisted || !persisted.text) return '';
  const t = String(persisted.text).trim();
  if (!t) return '';
  if (persisted.mode === 'override') return t;                         // verbatim
  if (persisted.mode === 'append')   return 'APPEND:\n' + t;           // built-in + append
  return '';                                                            // 'off' - use built-in
}

// ─── Window creation ────────────────────────────────────────────
function createWindow() {
  const primary = screen.getPrimaryDisplay();
  const w = 960, h = 720;
  const x = Math.round((primary.workAreaSize.width  - w) / 2);
  const y = Math.round((primary.workAreaSize.height - h) / 2);

  mainWin = new BrowserWindow({
    width: w, height: h, x, y,
    minWidth: 720, minHeight: 560,
    frame: false, transparent: false, resizable: true,
    show: false, backgroundColor: '#020617',
    title: '',
    icon: path.join(__dirname, 'assets', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,     // Electron 12+ default — never disable.
      nodeIntegration: false,     // Renderer has zero Node access.
      sandbox: true,              // Chromium sandbox on the renderer.
                                  // Preload only uses contextBridge +
                                  // ipcRenderer, both sandbox-safe per
                                  // Electron docs 2026-07.
      webSecurity: true,          // Enforce same-origin policy.
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      spellcheck: false,
      backgroundThrottling: false,// Keep the OAuth callback timer alive.
      devTools: process.argv.includes('--dev'),
    },
  });
  mainWin.on('page-title-updated', (e) => e.preventDefault());
  mainWin.loadFile(path.join(__dirname, 'index.html'));
  mainWin.once('ready-to-show', () => mainWin.show());

  if (!process.argv.includes('--dev')) {
    mainWin.webContents.on('devtools-opened', () => mainWin.webContents.closeDevTools());
  }
}

// ─── IPC ───────────────────────────────────────────────────────
ipcMain.handle('license:load', async () => {
  // 1. Security checks — anti-debug + proctor tool scan. If a debugger
  //    is attached or a known RE tool is running, refuse to even try
  //    to load a session. Payload's C-side anti-debug is still a safety
  //    net at inject time; this catches earlier + gives the user a
  //    friendly error instead of the C-side silent-refuse.
  const secResult = await security.runChecks();
  if (!secResult.ok) {
    console.log('[main] security check FAILED:', secResult.reason);
    return { session: null, subscription: null, clearReason: 'security_failed',
             securityReason: secResult.reason };
  }

  // v6 (2026-07-06): MITM proxy / traffic-inspection scan. If Fiddler
  // / mitmproxy / Charles / Burp / etc. root CA is installed OR
  // HTTPS_PROXY env var is set, refuse to load the session - our
  // Supabase auth exchange would be MITM-vulnerable.
  const mitmResult = await mitm.checkForMitm();
  if (!mitmResult.ok) {
    console.log('[main] MITM check FAILED:', mitmResult.tool, mitmResult.kind);
    return {
      session: null, subscription: null,
      clearReason: 'mitm_detected',
      mitmKind:    mitmResult.kind,
      mitmTool:    mitmResult.tool,
      mitmDetails: mitmResult.details,
    };
  }

  let { session, clearReason } = auth.loadSessionWithRecovery();
  if (!session) {
    currentSess = null; currentSub = null;
    revalidation.stop();
    return { session: null, subscription: null, clearReason };
  }
  const hwid = device.getCached()?.hardware_uuid || null;

  // v4.5.3: proactively refresh an expired (or about-to-expire) access
  // token BEFORE hitting Supabase. Supabase JWTs are 1h — if the user
  // quit + reopened after that window, the on-disk session has a stale
  // access_token that gets 401'd on every REST query.
  //
  // v4.9: on REFRESH failure due to NETWORK error, short-circuit into
  // signed-cache offline-grace path instead of falling through to a
  // sub check we know will also fail. Matches hooksdll behavior +
  // avoids an extra failed request when we're offline.
  if (storage.isExpired(session) && session.refresh_token) {
    try {
      console.log('[main] access token expired on load - refreshing...');
      session = await auth.refreshSession(session);
      console.log('[main] token refreshed, new expiry',
                  new Date((session.expires_at || 0) * 1000).toISOString());
    } catch (e) {
      console.log('[main] refresh failed:', e.message);
      // Network-error refresh failure → try signed cache before giving up.
      const isNetworkErr = /fetch|network|timeout|ETIMEDOUT|ENOTFOUND|ECONNRESET|ECONNREFUSED|abort/i.test(e.message || '');
      if (isNetworkErr) {
        try {
          const cached = storage.loadSubscriptionCache();
          if (cached && subscription.verifySubCache(cached, hwid) &&
              cached.active && cached._cachedAt) {
            const ageMs = Date.now() - cached._cachedAt * 1000;
            const { GRACE_PERIOD_MS } = require('./license/config');
            if (ageMs < GRACE_PERIOD_MS) {
              console.log(`[main] refresh offline; using signed cache ` +
                          `(${Math.round(ageMs/1000)}s / ${GRACE_PERIOD_MS/1000}s grace)`);
              currentSess = session;
              currentSub = { ...cached, _fromCache: true, _cacheAgeMs: ageMs };
              startRevalidationLoop();
              return _sessionDto();
            }
          }
        } catch (cacheErr) {
          console.log('[main] refresh-offline cache load failed:', cacheErr.message);
        }
      }
      // Fall through — the sub check will hit 401 which we handle below.
    }
  }
  currentSess = session;
  try {
    currentSub = await subscription.checkSubscription(session.access_token);
    if (currentSub && currentSub.active) {
      // Persist signed cache — offline-grace can serve this later.
      subscription.attachSigToCache(currentSub, hwid);
      storage.saveSubscriptionCache(currentSub);
    }
  } catch (e) {
    console.log('[main] sub-check on load failed:', e.message);
    // OFFLINE-GRACE FAST PATH: try signed cache before giving up.
    let usedCache = false;
    try {
      const cached = storage.loadSubscriptionCache();
      if (cached && subscription.verifySubCache(cached, hwid) &&
          cached.active && cached._cachedAt) {
        const ageMs = Date.now() - cached._cachedAt * 1000;
        const { GRACE_PERIOD_MS } = require('./license/config');
        if (ageMs < GRACE_PERIOD_MS) {
          console.log(`[main] sub check offline; using signed cache ` +
                      `(${Math.round(ageMs/1000)}s / ${GRACE_PERIOD_MS/1000}s grace)`);
          currentSub = { ...cached, _fromCache: true, _cacheAgeMs: ageMs };
          usedCache = true;
        }
      }
    } catch {}
    if (!usedCache) {
      currentSub = {
        active: null, plan: null, status: 'unknown',
        error: { kind: 'network', message: e.message || String(e) },
      };
    }
  }
  // If the sub check hit 401, EVEN the refreshed token is bad → force
  // full re-login rather than showing an unrecoverable "no active
  // subscription" screen.
  //
  // v4.9: use structured error shape (checkSubscription now returns
  // { error: { kind, statusCode, endpoint, ... } }) instead of the
  // fragile /http 401/ regex on a stringly-typed field.
  if (currentSub && currentSub.error &&
      typeof currentSub.error === 'object' &&
      currentSub.error.kind === 'http' &&
      currentSub.error.statusCode === 401) {
    console.log('[main] 401 on sub check even after refresh - forcing re-login');
    storage.clearSession();
    storage.clearSubscriptionCache();
    currentSess = null; currentSub = null;
    revalidation.stop();
    return { session: null, subscription: null, clearReason: 'token_rejected' };
  }
  if (currentSub && currentSub.active) startRevalidationLoop();
  return _sessionDto();
});

ipcMain.handle('license:sign-in', async () => {
  // Same security gate as license:load — refuse to run OAuth if a
  // debugger / RE tool is attached.
  const secResult = await security.runChecks();
  if (!secResult.ok) {
    console.log('[main] sign-in blocked by security check:', secResult.reason);
    return { error: secResult.reason, securityBlocked: true };
  }

  // v6 MITM gate: refuse to run OAuth if a proxy inspector's CA is
  // installed. Same message shape as license:load so renderer handles
  // both paths identically.
  const mitmResult = await mitm.checkForMitm();
  if (!mitmResult.ok) {
    console.log('[main] sign-in blocked by MITM check:', mitmResult.tool);
    return {
      error: mitmResult.details,
      mitmBlocked: true,
      mitmKind:    mitmResult.kind,
      mitmTool:    mitmResult.tool,
    };
  }
  try {
    const session = await auth.startOAuth();
    currentSess = session;

    // Device registration + MAX_DEVICES enforcement.
    // Fires BEFORE sub check so a user hitting the device limit gets
    // the right error screen instead of the ambiguous "no subscription".
    try {
      const info = device.getCached() || (await device.collect());
      const enf = await registration.enforceDeviceLimit(session, info);
      if (!enf.ok && enf.reason === 'device_limit_exceeded') {
        console.log('[main] sign-in blocked: device limit exceeded');
        // Don't save session — user must remove an old device first.
        currentSess = null;
        return {
          deviceLimitExceeded: true,
          devices: enf.devices || [],
          currentHwid: enf.currentHwid || null,
          currentDeviceName: enf.currentDeviceName || 'This PC',
          currentModel: enf.currentModel || null,
          limit: enf.limit || 1,
          _pendingSession: {
            access_token: session.access_token,
            user_id:      session.user_id,
            email:        session.email,
            display_name: session.display_name,
            avatar_url:   session.avatar_url,
            expires_at:   session.expires_at,
          },
        };
      }
      console.log('[main] device registration:', enf.action || 'ok');
    } catch (e) {
      console.log('[main] device registration threw:', e.message);
    }

    const hwid = device.getCached()?.hardware_uuid || null;
    try {
      currentSub = await subscription.checkSubscription(session.access_token);
      if (currentSub && currentSub.active) {
        subscription.attachSigToCache(currentSub, hwid);
        storage.saveSubscriptionCache(currentSub);
      }
    } catch (e) {
      currentSub = {
        active: null, plan: null, status: 'unknown',
        error: { kind: 'network', message: e.message || String(e) },
      };
    }
    if (currentSub && currentSub.active) startRevalidationLoop();
    return _sessionDto();
  } catch (e) {
    console.log('[main] sign-in failed:', e.message);
    return { error: e.message };
  }
});

// v4.9: lightweight force-recheck path for the renderer. Doesn't touch
// the session or run OAuth — just re-hits Supabase for the current sub
// state + refreshes the signed cache. Renderer wires the "Retry check"
// button on the nosub screen through this instead of the heavier
// license:load (which re-runs the whole security + session recovery
// dance).
ipcMain.handle('license:revalidate', async () => {
  if (!currentSess) return { ok: false, err: 'not signed in' };
  // Re-run security checks — user may have opened x64dbg since load.
  const secResult = await security.runChecks();
  if (!secResult.ok) {
    console.log('[main] revalidate: security blocked:', secResult.reason);
    return { ok: false, err: secResult.reason, securityBlocked: true };
  }
  const hwid = device.getCached()?.hardware_uuid || null;
  // Refresh token first if it's about to expire.
  if (storage.isExpired(currentSess) && currentSess.refresh_token) {
    try {
      currentSess = await auth.refreshSession(currentSess);
      if (mainWin && !mainWin.isDestroyed()) {
        mainWin.webContents.send('license:session-updated', _sessionDto());
      }
    } catch (e) {
      console.log('[main] revalidate: refresh failed:', e.message);
    }
  }
  try {
    const sub = await subscription.checkSubscription(currentSess.access_token);
    if (sub && sub.active) {
      subscription.attachSigToCache(sub, hwid);
      storage.saveSubscriptionCache(sub);
    }
    currentSub = sub;
    if (sub && sub.active && !revalidation.isRunning()) startRevalidationLoop();
    return { ok: true, subscription: sub };
  } catch (e) {
    return { ok: false, err: e.message || String(e) };
  }
});

// v4.7: Device management — remove a device from user_devices so the
// user can log in on a new machine (MAX_DEVICES=1 policy). Called from
// the "Device limit reached" screen after user picks which old device
// to unregister.
//
// Auth: uses the CURRENTLY-PENDING access_token from the aborted sign-in
// (renderer passes it back via IPC), because currentSess is still null
// at this point (login didn't complete).
ipcMain.handle('license:remove-device', async (_e, { pendingAccessToken, pendingUserId, hardwareUuid }) => {
  if (!pendingAccessToken || !pendingUserId || !hardwareUuid) {
    return { ok: false, err: 'missing_params' };
  }
  const fakeSession = { access_token: pendingAccessToken, user_id: pendingUserId };
  const r = await registration.deleteDevice(fakeSession, hardwareUuid);
  return r;
});

ipcMain.handle('license:sign-out', async () => {
  revalidation.stop();
  storage.clearSession();
  storage.clearSubscriptionCache();
  // Sign-out also resets onboarding — next sign-in walks the user
  // through the tutorial again. Matches hooksdll behaviour.
  storage.resetOnboarding();
  currentSess = null; currentSub = null;
  // Also uninject on sign-out — a session-less user should not have
  // the payload running with their (now-invalid) config.
  try { await injector.uninject(); } catch {}
  return { ok: true };
});

ipcMain.handle('license:pending-url', async () => auth.getPendingAuthUrl());

/* v6.2 (2026-07-06): one-click remediation for the "why is sign-in
 * blocked" MITM banner. Renderer passes back the `{ kind, tool }` from
 * the last check result; we route to mitm.remediate() which knows how
 * to nuke each kind (env var / proxy / CA). Returns:
 *   { ok, action, message, details? }
 * Renderer toasts the message + auto-re-runs license:load to refresh
 * the banner state. */
ipcMain.handle('mitm:remediate', async (_e, payload) => {
  if (!payload || typeof payload.kind !== 'string') {
    return { ok: false, message: 'bad payload' };
  }
  try {
    return await mitm.remediate(payload.kind, payload.tool);
  } catch (e) {
    console.log('[main] mitm remediate threw:', e.message);
    return { ok: false, message: e.message || String(e) };
  }
});

/* v4.4 multi-key IPC. Returns full bag { openai, anthropic, google,
 * openrouter } — never null. Legacy single-key handlers below stay
 * for backward compat (renderer.js may still call them during upgrade). */
ipcMain.handle('api-keys:load',  async ()      => loadApiKeys());
ipcMain.handle('api-keys:save',  async (_e, k) => { saveApiKeys(k); return true; });
ipcMain.handle('api-keys:clear', async ()      => { clearApiKeys(); return true; });

/* Test a single API key against its provider's list-models endpoint.
 * Uses Node fetch directly — same endpoints ai_test_key on the C side
 * would hit if invoked from within DWM. Returns:
 *   { ok, status, latency_ms, err? }
 *   ok=true  → status 2xx (key is valid, quota available)
 *   ok=false → transport error OR status !=2xx (err populated with why) */
ipcMain.handle('api-keys:test', async (_e, provider, key) => {
  if (!key || typeof key !== 'string') return { ok: false, err: 'no key' };
  const started = Date.now();
  const timeoutMs = 6000;
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let url, headers;
    switch (provider) {
      case 1: // OpenAI
        url = 'https://api.openai.com/v1/models';
        headers = { 'Authorization': `Bearer ${key}`, 'Accept': 'application/json' };
        break;
      case 2: // Anthropic
        url = 'https://api.anthropic.com/v1/models';
        headers = {
          'x-api-key': key,
          'anthropic-version': '2023-06-01',
          'Accept': 'application/json',
        };
        break;
      case 3: // Google
        url = 'https://generativelanguage.googleapis.com/v1beta/models';
        headers = { 'x-goog-api-key': key, 'Accept': 'application/json' };
        break;
      case 4: // OpenRouter
        url = 'https://openrouter.ai/api/v1/models';
        headers = { 'Authorization': `Bearer ${key}`, 'Accept': 'application/json' };
        break;
      default:
        return { ok: false, err: `unknown provider ${provider}` };
    }
    const resp = await fetch(url, { method: 'GET', headers, signal: controller.signal });
    clearTimeout(t);
    const latency = Date.now() - started;
    if (resp.status >= 200 && resp.status < 300) {
      // Try to count models for a nicer status message.
      let models = -1;
      try {
        const body = await resp.json();
        if (Array.isArray(body?.data))     models = body.data.length;
        else if (Array.isArray(body?.models)) models = body.models.length;
      } catch {}
      return { ok: true, status: resp.status, latency_ms: latency, models };
    }
    let errBody = '';
    try { errBody = (await resp.text()).slice(0, 250); } catch {}
    return {
      ok: false,
      status: resp.status,
      latency_ms: latency,
      err: `HTTP ${resp.status}${errBody ? ': ' + errBody : ''}`,
    };
  } catch (e) {
    clearTimeout(t);
    return {
      ok: false,
      latency_ms: Date.now() - started,
      err: e.name === 'AbortError' ? `timeout after ${timeoutMs}ms` : (e.message || String(e)),
    };
  }
});

/* v6 (2026-07-06): user-tunable system prompt + direct-answer-mode
 * persistence. `load` always returns a full { text, mode,
 * direct_answer_mode } record; `save` merges partial updates. */
ipcMain.handle('system-prompt:load',  async ()          => loadSystemPrompt());
ipcMain.handle('system-prompt:save',  async (_e, obj)   => saveSystemPrompt(obj));
ipcMain.handle('system-prompt:clear', async ()          => { clearSystemPrompt(); return true; });

/* Legacy single-key IPC shims — keep so a stale renderer bundle still
 * loads without ReferenceErrors. Prefer api-keys:* going forward. */
ipcMain.handle('api-key:load',  async ()      => {
  const bag = loadApiKeys();
  return bag.openai || bag.anthropic || bag.google || bag.openrouter || '';
});
ipcMain.handle('api-key:save',  async (_e, k) => {
  const inj = require('./injector/injector');
  const p = inj.detectProvider(k);
  const bag = loadApiKeys();
  const slot =
    p === inj.PROVIDER.OPENAI     ? 'openai' :
    p === inj.PROVIDER.ANTHROPIC  ? 'anthropic' :
    p === inj.PROVIDER.GOOGLE     ? 'google' :
                                     'openrouter';
  bag[slot] = k;
  saveApiKeys(bag);
  return true;
});
ipcMain.handle('api-key:clear', async () => { clearApiKeys(); return true; });

ipcMain.handle('injector:status', async () => ({
  payload_loaded: await injector.isPayloadLoaded(),
  ldb_running:    await injector.isLdbRunning(),
}));

ipcMain.handle('injector:inject', async (_e, args) => {
  if (!currentSess) return { ok: false, err: 'not signed in' };
  /* v4.4: prefer the multi-key bag; fall back to legacy single-key. */
  const keys = (args && args.keys) || loadApiKeys();
  const hasAny = keys.openai || keys.anthropic || keys.google || keys.openrouter
              || (args && args.apiKey);
  if (!hasAny) return { ok: false, err: 'At least one AI provider key is required.' };

  const hwid = (device.getCached()?.hardware_uuid) || (await device.collect()).hardware_uuid;

  // v4.7: merge user hotkey overrides on top of DEFAULT_HOTKEYS. Overrides
  // dict is { [slotIndex]: packedUInt } from the settings UI. Any slot the
  // user has NOT customized keeps its default binding.
  const hotkeys = [...injector.DEFAULT_HOTKEYS];
  const overrides = storage.loadHotkeyOverrides();
  for (const [k, v] of Object.entries(overrides || {})) {
    const slot = parseInt(k, 10);
    if (Number.isFinite(slot) && slot >= 0 && slot < hotkeys.length) {
      hotkeys[slot] = v;
    }
  }

  // v6: pull persisted system-prompt customization + all "AI answer
  // style" prefs (direct mode / latex mode / stream display) and pass
  // them through to the injector. Renderer may override any of these
  // on a per-inject basis via args.
  const persistedPrompt = loadSystemPrompt();
  const systemPromptStr = (args && typeof args.system_prompt === 'string')
    ? args.system_prompt
    : _computeSystemPromptString(persistedPrompt);
  const directAnswerMode = (args && args.direct_answer_mode != null)
    ? (args.direct_answer_mode ? 1 : 0)
    : (persistedPrompt.direct_answer_mode ? 1 : 0);
  // v6.1: latex_mode 'off' -> latex_disabled=1 (AI told to use Unicode).
  const latexDisabled = (args && args.latex_disabled != null)
    ? (args.latex_disabled ? 1 : 0)
    : (persistedPrompt.latex_mode === 'off' ? 1 : 0);
  // v6.1: stream_display 'batched' -> stream_display_batched=1.
  const streamBatched = (args && args.stream_display_batched != null)
    ? (args.stream_display_batched ? 1 : 0)
    : (persistedPrompt.stream_display === 'batched' ? 1 : 0);

  /* v1.2 (v8 schema): pull persisted overlay-appearance prefs and merge
   * with any per-inject override the renderer sent. Storage returns fully
   * clamped values; renderer can pass args.overlay to override for testing.
   * size_mode moves to the top-level field so injector.buildJson can pack
   * it directly into the JSON handoff. */
  const overlayCfg = storage.loadOverlayConfig();
  const overlayOvr = (args && args.overlay) || {};
  const overlayFinal = {
    x:     overlayOvr.x     != null ? overlayOvr.x     : 40,
    y:     overlayOvr.y     != null ? overlayOvr.y     : 40,
    w:     overlayOvr.w     != null ? overlayOvr.w     : overlayCfg.w,
    h:     overlayOvr.h     != null ? overlayOvr.h     : overlayCfg.h,
    alpha: overlayOvr.alpha != null ? overlayOvr.alpha : overlayCfg.alpha,
  };
  const sizeMode = (args && args.size_mode != null)
    ? (args.size_mode ? 1 : 0)
    : (overlayCfg.size_mode ? 1 : 0);

  const result = await injector.inject({
    session: currentSess,
    hwid,
    keys,
    apiKey:            (args && args.apiKey) || '',
    tier:              (args && args.tier),
    provider:          (args && args.provider),
    model:             (args && args.model),
    reasoning_effort:  (args && args.reasoning_effort),
    streaming_enabled: (args && args.streaming_enabled),
    latex_disabled:    latexDisabled,
    /* v6 additions */
    direct_answer_mode: directAnswerMode,
    system_prompt:      systemPromptStr,
    /* v6.1 addition */
    stream_display_batched: streamBatched,
    /* v1.2 additions (v8 schema): custom launch geometry + ultra toggle */
    overlay:           overlayFinal,
    size_mode:         sizeMode,
    hotkeys,
  });
  return result;
});

ipcMain.handle('injector:uninject', async () => injector.uninject());
ipcMain.handle('injector:kill-all', async () => injector.killAll());

// v6 (2026-07-06) FULL UNINSTALL. User-visible "wipe everything and
// restart DWM cleanly" action from the Support card. Runs in sequence:
//   1. Stop the runtime revalidation loop so it doesn't try to poll
//      Supabase mid-teardown.
//   2. Uninject the payload cleanly (sihost --unload signals the
//      shutdown watcher which drains + removes hooks).
//   3. Kill DWM (sihost --kill-all). Windows respawns dwm.exe within
//      ~2s so the user's desktop doesn't die.
//   4. Delete user AppData: session, subscription cache, hotkey
//      overrides, custom system prompt, onboarding flag, API keys.
//   5. Delete C:\ProgramData\WinAudioSvc\ contents (config.dat,
//      offsets.blob, api_key.txt, encrypted logs, overlay state).
//   6. Return { ok } so the renderer can show a "reboot recommended"
//      dialog + offer to quit svchelper.
//
// Users typically run this before uninstalling svchelper.exe from
// Windows Apps & Features - clears our footprint completely.
ipcMain.handle('injector:full-uninstall', async () => {
  const steps = [];
  const record = (name, ok, extra) => {
    steps.push({ name, ok, extra: extra || null });
    console.log(`[uninstall] ${name}: ${ok ? 'ok' : 'FAIL'} ${extra || ''}`);
  };

  try { revalidation.stop(); record('stop_revalidation', true); }
  catch (e) { record('stop_revalidation', false, e.message); }

  try {
    const r = await injector.uninject();
    record('uninject', !!(r && r.ok), r?.err);
  } catch (e) { record('uninject', false, e.message); }

  try {
    const r = await injector.killAll();
    record('kill_dwm', !!(r && r.ok), r?.err);
  } catch (e) { record('kill_dwm', false, e.message); }

  // Wipe user session + cache + prefs from appData.
  try { storage.clearSession();             record('clear_session',      true); }
  catch (e) { record('clear_session', false, e.message); }
  try { storage.clearSubscriptionCache();   record('clear_sub_cache',    true); }
  catch (e) { record('clear_sub_cache', false, e.message); }
  try { storage.clearHotkeyOverrides();     record('clear_hotkeys',      true); }
  catch (e) { record('clear_hotkeys', false, e.message); }
  try { storage.resetOnboarding();          record('reset_onboarding',   true); }
  catch (e) { record('reset_onboarding', false, e.message); }
  try { clearApiKeys();                     record('clear_api_keys',     true); }
  catch (e) { record('clear_api_keys', false, e.message); }
  try { clearSystemPrompt();                record('clear_system_prompt',true); }
  catch (e) { record('clear_system_prompt', false, e.message); }

  // Wipe the ProgramData install dir contents. We do NOT delete the dir
  // itself - keeping it around avoids a permissions dance if user
  // re-installs later; contents are the actual footprint we care about.
  try {
    if (fs.existsSync(SVC_INSTALL_DIR)) {
      let wiped = 0;
      for (const name of fs.readdirSync(SVC_INSTALL_DIR)) {
        const full = path.join(SVC_INSTALL_DIR, name);
        try {
          const stat = fs.lstatSync(full);
          if (stat.isDirectory()) {
            fs.rmSync(full, { recursive: true, force: true });
          } else {
            fs.unlinkSync(full);
          }
          wiped++;
        } catch { /* file in use etc - skip */ }
      }
      record('wipe_programdata', true, `${wiped} entries`);
    } else {
      record('wipe_programdata', true, 'dir absent');
    }
  } catch (e) { record('wipe_programdata', false, e.message); }

  // Clear in-memory state so the renderer's next license:load sees
  // a clean slate.
  currentSess = null;
  currentSub  = null;

  return {
    ok: steps.every(s => s.ok || s.name === 'kill_dwm' /* DWM restart may race */),
    steps,
  };
});

ipcMain.handle('window:minimize', () => { if (mainWin) mainWin.minimize(); });
ipcMain.handle('window:close',    () => { if (mainWin) mainWin.hide(); });
ipcMain.handle('window:quit',     () => { app.quit(); });

/* v1.2 (2026-07-06): expose the app version to the renderer so the login
 * screen + titlebar can render it without a hard-coded literal that drifts
 * across releases. Single source of truth = package.json. */
ipcMain.handle('app:get-version', () => app.getVersion());

ipcMain.handle('shell:open-external', (_e, url) => {
  if (typeof url !== 'string') return false;
  if (!/^https?:\/\//i.test(url)) return false;
  shell.openExternal(url);
  return true;
});

// ─── Hotkey overrides (user customization) ─────────────────────
// Renderer sends a dict { [slotIndex]: packedUInt } via hotkeys:save.
// injector.js reads the current overrides via storage.loadHotkeyOverrides
// and merges them into DEFAULT_HOTKEYS at inject time. Overrides
// persist across launches via appData/hotkeys.json.
ipcMain.handle('hotkeys:load', async () => {
  const overrides = storage.loadHotkeyOverrides();
  // Also return the defaults so the renderer knows the base binding to
  // show alongside each override (or as the fallback if unset).
  return {
    defaults: injector.DEFAULT_HOTKEYS,
    overrides,
  };
});

ipcMain.handle('hotkeys:save', async (_e, overrides) => {
  if (!overrides || typeof overrides !== 'object') return { ok: false, err: 'bad_overrides' };
  // Sanitize: values must be integers 0..(2^24-1). Drop bogus entries.
  const clean = {};
  for (const [k, v] of Object.entries(overrides)) {
    const slot = parseInt(k, 10);
    const packed = (typeof v === 'number') ? v : parseInt(v, 10);
    if (Number.isFinite(slot) && slot >= 0 && slot < 64 &&
        Number.isFinite(packed) && packed >= 0 && packed < (1 << 24)) {
      clean[slot] = packed;
    }
  }
  const ok = storage.saveHotkeyOverrides(clean);
  return { ok };
});

ipcMain.handle('hotkeys:reset', async () => {
  storage.clearHotkeyOverrides();
  return { ok: true };
});

// ─── v1.2 (2026-07-06) — Overlay-appearance settings ──────────────
// User-picked launch size + alpha + size_mode from the "Overlay
// appearance" dashboard card. Purely cosmetic — no secrets, no
// signature. Applied on next injector:inject.
ipcMain.handle('overlay:load',  async () => storage.loadOverlayConfig());
ipcMain.handle('overlay:save',  async (_e, o) => storage.saveOverlayConfig(o));
ipcMain.handle('overlay:reset', async () => {
  storage.clearOverlayConfig();
  return storage.loadOverlayConfig();   /* returns defaults */
});

// ─── Onboarding walkthrough ────────────────────────────────────
// Renderer queries onboarding:get on splash → decides whether to show
// the 12-step overlay before dashboard becomes visible.
ipcMain.handle('onboarding:get', async () => {
  return { complete: storage.isOnboardingComplete() };
});

ipcMain.handle('onboarding:complete', async () => {
  const ok = storage.setOnboardingComplete();
  return { ok };
});

ipcMain.handle('onboarding:reset', async () => {
  storage.resetOnboarding();
  return { ok: true };
});

// ─── Export encrypted logs for support ─────────────────────────
//
// User clicks "Export logs" on the dashboard. We:
//   1. Copy every *.log / *.blob from SVC_INSTALL_DIR into a temp folder.
//   2. Write a `meta.json` sidecar with install identity (short HWID hash,
//      user email, app version, OS, timestamp) so support can identify
//      the install without asking the user to type anything.
//   3. Zip via PowerShell Compress-Archive (built-in on Win10+, zero deps).
//   4. Drop the zip on the user's Desktop and reveal in Explorer.
//   5. Delete the staging folder.
//
// The logs remain encrypted (`v1.<base64>` AES-256-GCM per line) — the
// user cannot read them, only we can (with the master key baked into
// our binaries at build time; see shared/log_key.c). This means the
// user CAN safely email us the zip without leaking secrets to their
// mail provider.
ipcMain.handle('logs:export', async () => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const desktop = app.getPath('desktop');
  const outZip  = path.join(desktop, `cloakgpt-logs-${timestamp}.zip`);
  const staging = path.join(app.getPath('temp'), `cloakgpt-logs-${timestamp}`);

  const isLogLike = (name) =>
    /\.(log|blob|txt|hex)$/i.test(name) || name === '.dwm_clean_shutdown';

  try {
    if (!fs.existsSync(SVC_INSTALL_DIR)) {
      return { ok: false, err: 'No install directory yet — nothing to export.' };
    }
    fs.mkdirSync(staging, { recursive: true });

    let copied = 0;
    for (const name of fs.readdirSync(SVC_INSTALL_DIR)) {
      if (!isLogLike(name)) continue;
      try {
        fs.copyFileSync(path.join(SVC_INSTALL_DIR, name), path.join(staging, name));
        copied++;
      } catch { /* skip locked or vanished files */ }
    }

    const hwid = device.getCached()?.hardware_uuid || '';
    const meta = {
      exported_at: new Date().toISOString(),
      app_version: app.getVersion(),
      productName: 'svchelper',
      user_email:  currentSess?.email || null,
      subscription: currentSub ? {
        active:      !!currentSub.active,
        plan:        currentSub.plan  || null,
        status:      currentSub.status || null,
        is_lifetime: !!currentSub.is_lifetime,
      } : null,
      hwid_short: hwid ? (hwid.slice(0, 8) + '...' + hwid.slice(-4)) : null,
      os: `${process.platform} ${process.arch}`,
      electron: process.versions.electron,
      node:     process.versions.node,
      copied_files: copied,
    };
    fs.writeFileSync(path.join(staging, 'meta.json'), JSON.stringify(meta, null, 2), 'utf8');

    // Zip via PowerShell. Compress-Archive is present on every Windows 10+
    // (System.IO.Compression under the hood). Single-shot, ~1-2s for a
    // multi-MB log set.
    await new Promise((resolve, reject) => {
      execFile('powershell.exe', [
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
        `Compress-Archive -Path '${staging.replace(/'/g, "''")}\\*' -DestinationPath '${outZip.replace(/'/g, "''")}' -Force -ErrorAction Stop`,
      ], { windowsHide: true, timeout: 60_000, encoding: 'utf8' },
      (err, _stdout, stderr) => {
        if (err) reject(new Error(stderr || err.message));
        else resolve();
      });
    });

    try { fs.rmSync(staging, { recursive: true, force: true }); } catch {}

    // Reveal in Explorer so the user knows exactly where the zip is.
    try { shell.showItemInFolder(outZip); } catch {}

    const size = (fs.statSync(outZip).size / 1024).toFixed(1);
    return {
      ok: true,
      path: outZip,
      files: copied + 1,   // +1 for meta.json
      size_kb: Number(size),
    };
  } catch (e) {
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch {}
    return { ok: false, err: e.message };
  }
});

// ─── Runtime revalidation loop ─────────────────────────────────
// Wired into every path that produces a valid, subscribed session. Polls
// Supabase every hour (jittered ±20%). If subscription lapses or the
// user's account is disabled server-side, immediately uninject + logout
// + push the renderer back to the login screen with an explanation
// banner. If the network is DOWN, uses the HMAC-signed sub cache to
// stay active for up to GRACE_PERIOD_MS (3h) before hard lockout.
function startRevalidationLoop() {
  const _hwid = () => device.getCached()?.hardware_uuid || null;
  revalidation.start({
    getSession: () => currentSess,
    refreshFn:  async (s) => auth.refreshSession(s),
    subCheckFn: async (t) => {
      // v4.9: run security checks on every tick — a user could have
      // launched x64dbg / WireShark AFTER signing in. Without this,
      // the app kept running until the next full restart.
      const sec = await security.runChecks();
      if (!sec.ok) {
        console.log('[main] revalidation: security check failed:', sec.reason);
        const err = new Error(sec.reason || 'security_check_failed');
        err.securityBlocked = true;
        throw err;
      }
      const r = await subscription.checkSubscription(t);
      // Keep in-mem sub current so the dashboard reflects live state.
      if (r && r.active) currentSub = r;
      return r;
    },
    getHwid: _hwid,
    loadSignedCache: (hwid) => {
      const cached = storage.loadSubscriptionCache();
      if (!cached) return null;
      if (!subscription.verifySubCache(cached, hwid || _hwid())) return null;
      return cached;
    },
    saveSignedCache: (sub) => {
      subscription.attachSigToCache(sub, _hwid());
      storage.saveSubscriptionCache(sub);
    },
    onRefreshed: (newSess) => {
      currentSess = newSess;
      console.log('[main] session refreshed, new expiry',
                  new Date((newSess.expires_at || 0) * 1000).toISOString());
      if (mainWin && !mainWin.isDestroyed()) {
        mainWin.webContents.send('license:session-updated', _sessionDto());
      }
    },
    onExpired: async (reason, extra) => {
      console.log('[main] LOCKOUT:', reason, extra || '');
      // v4.9: no more SUSPENDED handling (see subscription.js header —
      // server-side has no suspension concept). Only real lockout
      // reasons are: subscription_inactive, too_many_failures:<msg>,
      // license_server_schema_error (new — PostgREST 42703).
      currentSess = null;
      currentSub = null;
      storage.clearSession();
      storage.clearSubscriptionCache();
      try { await injector.uninject(); }
      catch (e) { console.log('[main] auto-uninject failed:', e.message); }
      if (mainWin && !mainWin.isDestroyed()) {
        mainWin.webContents.send('license:expired-lockout', {
          reason,
          serverError: extra?.serverError || null,
        });
        try { mainWin.show(); mainWin.focus(); } catch {}
      }
    },
  });
}

// ─── DTO for the renderer ───────────────────────────────────────
function _sessionDto() {
  return {
    session: currentSess ? {
      email:        currentSess.email,
      display_name: currentSess.display_name,
      avatar_url:   currentSess.avatar_url,
      user_id:      currentSess.user_id,
      expires_at:   currentSess.expires_at,
      created_at:   currentSess.created_at,
    } : null,
    subscription: currentSub,
    hwid: device.getCached()?.hardware_uuid || null,
  };
}

// ─── App lifecycle ──────────────────────────────────────────────
app.whenReady().then(async () => {
  // 1. First-run install: unpack the bundled C binaries into the shared
  //    ProgramData install dir so sihost.exe --json-config + dllhost32.exe
  //    are on disk before the user clicks Inject. Idempotent.
  ensureCBinariesInstalled();

  // 2. Windows Defender self-exclusion. Fire-and-forget — never block on
  //    Defender. Failure is fine (third-party AV, disabled by policy, etc.).
  ensureDefenderExclusions();

  // 3. Collect HWID — auth.js signSession() + injector both need it.
  try { await device.collect(); } catch (e) { console.log('[main] device.collect fail:', e.message); }

  createWindow();

  // Ctrl+Shift+Alt+H — global hotkey to summon window from tray.
  // Same 3-modifier pattern the payload uses so we never collide with
  // Cursor / Chrome / any app.
  try {
    globalShortcut.register('Ctrl+Shift+Alt+H', () => {
      if (!mainWin) return;
      if (mainWin.isMinimized()) mainWin.restore();
      mainWin.show();
      mainWin.focus();
    });
  } catch (e) { console.log('[main] hotkey register fail:', e.message); }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('will-quit', () => {
  try { revalidation.stop(); } catch {}
  try { globalShortcut.unregisterAll(); } catch {}
});

app.on('window-all-closed', () => {
  // Don't quit on Windows when all windows close — user summons via
  // the Ctrl+Shift+Alt+H hotkey. Only actual "Quit" from the UI exits.
});
