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
  const { session, clearReason } = auth.loadSessionWithRecovery();
  if (!session) {
    currentSess = null; currentSub = null;
    revalidation.stop();
    return { session: null, subscription: null, clearReason };
  }
  currentSess = session;
  // Best-effort sub check; if it fails, we still return the session so
  // the UI can show a "sub check retry" state instead of forcing re-login.
  try {
    currentSub = await subscription.checkSubscription(session.access_token);
  } catch (e) {
    console.log('[main] sub-check on load failed:', e.message);
    currentSub = { active: null, plan: null, status: 'unknown', error: e.message };
  }
  if (currentSub && currentSub.active) startRevalidationLoop();
  return _sessionDto();
});

ipcMain.handle('license:sign-in', async () => {
  try {
    const session = await auth.startOAuth();
    currentSess = session;
    try {
      currentSub = await subscription.checkSubscription(session.access_token);
    } catch (e) {
      currentSub = { active: null, plan: null, status: 'unknown', error: e.message };
    }
    if (currentSub && currentSub.active) startRevalidationLoop();
    return _sessionDto();
  } catch (e) {
    console.log('[main] sign-in failed:', e.message);
    return { error: e.message };
  }
});

ipcMain.handle('license:sign-out', async () => {
  revalidation.stop();
  storage.clearSession();
  currentSess = null; currentSub = null;
  // Also uninject on sign-out — a session-less user should not have
  // the payload running with their (now-invalid) config.
  try { await injector.uninject(); } catch {}
  return { ok: true };
});

ipcMain.handle('license:pending-url', async () => auth.getPendingAuthUrl());

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
  const result = await injector.inject({
    session: currentSess,
    hwid,
    keys,
    apiKey:           (args && args.apiKey) || '',
    tier:             (args && args.tier),
    provider:         (args && args.provider),
    model:            (args && args.model),
    reasoning_effort: (args && args.reasoning_effort),
    streaming_enabled:(args && args.streaming_enabled),
    latex_disabled:   (args && args.latex_disabled),
    overlay:          (args && args.overlay),
  });
  return result;
});

ipcMain.handle('injector:uninject', async () => injector.uninject());
ipcMain.handle('injector:kill-all', async () => injector.killAll());

ipcMain.handle('window:minimize', () => { if (mainWin) mainWin.minimize(); });
ipcMain.handle('window:close',    () => { if (mainWin) mainWin.hide(); });
ipcMain.handle('window:quit',     () => { app.quit(); });

ipcMain.handle('shell:open-external', (_e, url) => {
  if (typeof url !== 'string') return false;
  if (!/^https?:\/\//i.test(url)) return false;
  shell.openExternal(url);
  return true;
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
// Supabase every hour. If subscription lapses or the user's account is
// disabled server-side, immediately uninject + logout + push the renderer
// back to the login screen with an explanation banner.
function startRevalidationLoop() {
  revalidation.start({
    getSession: () => currentSess,
    refreshFn:  async (s) => auth.refreshSession(s),
    subCheckFn: async (t) => subscription.checkSubscription(t),
    onRefreshed: (newSess) => {
      currentSess = newSess;
      console.log('[main] session refreshed, new expiry',
                  new Date((newSess.expires_at || 0) * 1000).toISOString());
      if (mainWin && !mainWin.isDestroyed()) {
        mainWin.webContents.send('license:session-updated', _sessionDto());
      }
    },
    onExpired: async (reason) => {
      console.log('[main] LOCKOUT:', reason);
      currentSess = null; currentSub = null;
      storage.clearSession();
      try { await injector.uninject(); }
      catch (e) { console.log('[main] auto-uninject failed:', e.message); }
      if (mainWin && !mainWin.isDestroyed()) {
        mainWin.webContents.send('license:expired-lockout', { reason });
        // Bring the window forward — user needs to see the lockout page.
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
