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

const { app, BrowserWindow, ipcMain, globalShortcut, safeStorage, shell, screen, dialog } = require('electron');
const path = require('path');
const fs   = require('fs');
const net  = require('net');
const { execFile, spawn } = require('child_process');

/* ═══════════════════════════════════════════════════════════════
 * v18 (2026-09-23) -- Silence non-encrypted logs in production.
 *
 * Every real log line in the C stack (payload + launcher + winlogon helper)
 * is AES-256-GCM per line -- see shared/log_key.c + tools/decrypt-logs.js.
 * The Electron JS side, however, uses plain `console.log` all over
 * main.js + renderer.js. In a packaged build those calls normally have no
 * reader (devTools disabled below; stdout of a detached process goes
 * nowhere) BUT if a user launches with --enable-logging (or attaches a
 * debugger, or someone runs the app from a terminal to see what it does)
 * they get plaintext internals. That leaks jargon we've spent this whole
 * pass removing from the visible UI. Belt + braces: in production,
 * replace console.log / info / warn / debug with a no-op. console.error
 * stays live so genuine crashes still surface in Electron's built-in
 * unhandledRejection / render-process-gone reporters.
 *
 * v18.1 (2026-09-23) -- HARDENED. The previous revision honored
 * SVCLDB_DEBUG env var + --dev CLI flag + NODE_ENV=development as runtime
 * opt-outs. All three are trivially attacker-controlled from a shipped
 * binary (`set SVCLDB_DEBUG=1 && svchelper.exe`, or `svchelper.exe --dev`).
 * An investigator or user could flip logging back on in seconds. NOW: the
 * ONLY signal is `app.isPackaged` -- a compile-time bit embedded by
 * electron-builder into the packaged executable that cannot be changed
 * without modifying the binary. Dev flow (running `electron .` from the
 * source tree) still gets full logging because isPackaged is false there.
 * ═══════════════════════════════════════════════════════════════ */
if (app.isPackaged) {
  const _noop = () => {};
  console.log   = _noop;
  console.info  = _noop;
  console.warn  = _noop;
  console.debug = _noop;
  // console.error deliberately left intact so hard failures still make it
  // to Electron's crash pipeline.
}

const device       = require('./license/device');
const auth         = require('./license/auth');
const storage      = require('./license/storage');
const subscription = require('./license/subscription');
const revalidation = require('./license/revalidation');
const security     = require('./license/security');
const mitm         = require('./license/mitm');
const registration = require('./license/registration');
const injector     = require('./injector/injector');
const { SVC_INSTALL_DIR, BUNDLED_BINS, BUNDLED_ASSETS } = require('./license/config');
const autoRestartShell = require('./lib/auto-restart-shell');

/* v17 (2026-09-22) -- Safe mode. If the user hit "Restart in safe mode" on
 * the fallback screen, the renderer's IPC handler wrote a marker file. On
 * this next boot we consume the file + disable HW acceleration BEFORE
 * app.ready fires (Electron requires it), so GPU-driver-related blank
 * screens don't recur. Also mirrors the flag via --disable-gpu CLI flag so
 * child renderer processes inherit it. */
const _SAFE_MODE_FLAG = path.join(app.getPath('userData'), 'safe-mode.flag');
try {
  if (fs.existsSync(_SAFE_MODE_FLAG)) {
    app.disableHardwareAcceleration();
    app.commandLine.appendSwitch('disable-gpu');
    app.commandLine.appendSwitch('disable-gpu-compositing');
    console.log('[main] SAFE MODE: HW acceleration + GPU compositing disabled (flag present).');
    try { fs.unlinkSync(_SAFE_MODE_FLAG); } catch {}
  }
} catch (e) { console.log('[main] safe-mode probe failed:', e && e.message || e); }

/* Restart the whole app in safe mode. Writes the flag file so the NEXT boot
 * disables HW accel, then relaunches. Called from the renderer's safety
 * fallback screen AND from the main-process render-process-gone dialog. */
function _restartInSafeMode() {
  try {
    fs.writeFileSync(_SAFE_MODE_FLAG,
      'restart requested at ' + new Date().toISOString() + '\n', 'utf8');
    console.log('[main] safe-mode flag written; relaunching...');
  } catch (e) { console.log('[main] failed to write safe-mode flag:', e && e.message || e); }
  try { app.relaunch(); } catch {}
  try { app.exit(0); } catch {}
}

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
  /* v2.0.2: the bin + asset manifests now live in license/config.js as the
   * SINGLE SOURCE OF TRUTH, shared with injector.js::ensureBinariesPresent
   * so the on-demand self-repair path restores the exact same set (no drift).
   *   sihost.exe       launcher (embeds dwmapiext.dll as RCDATA)
   *   dllhost32.exe    resolver (fetches DWM PDB -> offsets.blob)
   *   cgpt_dbghelp.dll SDK dbghelp (symbol-server capable)
   *   symsrv.dll       Microsoft PDB fetcher
   *   dwmapiext.dll    payload - backup, sihost usually reads its own RCDATA */
  const bins = BUNDLED_BINS;
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

  /* Non-executable runtime assets that the payload reads by absolute path
   * from SVC_INSTALL_DIR. Kept OUT of the `bins` array above so a future
   * asset change never trips the upgrade-detection uninject path (assets
   * don't need the payload torn down before overwrite).
   *
   *   cg_icons.ttf — Lucide icon font the DWM overlay loads via
   *   AddFontFromFileTTF("C:\ProgramData\WinAudioSvc\cg_icons.ttf", ...).
   *   Bundled as extraResources (from shared/fonts/lucide.ttf → cg_icons.ttf).
   *   Without this copy the overlay silently falls back to hand-drawn vector
   *   icons ("buns") — see docs/HANDOFF_2026-08-12_CREDITS_INJECT_BUG.md. */
  const assets = BUNDLED_ASSETS;
  for (const a of assets) {
    const src = path.join(srcDir, a);
    if (!fs.existsSync(src)) continue;
    const dst = path.join(SVC_INSTALL_DIR, a);
    let needCopy = !fs.existsSync(dst);
    if (!needCopy) {
      try {
        const s = fs.statSync(src), d = fs.statSync(dst);
        needCopy = s.mtimeMs > d.mtimeMs || s.size !== d.size;
      } catch { needCopy = true; }
    }
    if (needCopy) {
      try { fs.copyFileSync(src, dst); console.log(`[install] copied asset ${a} (${fs.statSync(dst).size} B)`); }
      catch (e) { console.log(`[install] copy asset ${a} FAILED: ${e.message}`); }
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
// A losing (second) instance must exit IMMEDIATELY via app.exit(0) —
// NOT app.quit(). app.quit() is a graceful/async teardown that can let
// `ready` fire first, so the losing instance briefly runs
// whenReady()→createWindow() and FLASHES a window on screen before dying.
// That is the "app opens then auto-closes, but only the once (right after
// install)" report: the NSIS one-click installer's runAfterFinish
// auto-launch races a second launch (impatient double-click of the fresh
// Desktop shortcut, or the elevated re-spawn) exactly once, and the loser
// flashed + quit. app.exit(0) is synchronous (no window, no
// before-quit/will-quit) so nothing flashes; and we additionally gate
// BOTH app.whenReady() handlers on `gotSingleInstanceLock` (belt +
// suspenders in case app.exit is deferred). Subsequent launches only ever
// have one instance, so it never recurs — matching the report exactly.
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.exit(0);
}
app.on('second-instance', () => {
  /* v1.9.2 (2026-09-09) — CRASH FIX ("A JavaScript error occurred in the
   * main process: TypeError: Object has been destroyed at App.<anonymous>").
   *
   * The old code checked `if (mainWin)` but NOT `mainWin.isDestroyed()`.
   * Repro: session dies at ~1h → overlay tells the user "Re-launch CloakGPT"
   * → they relaunch while THIS instance is still alive (or mid-teardown).
   * requestSingleInstanceLock() routes the relaunch here as `second-instance`.
   * If mainWin's BrowserWindow was already destroyed (quit teardown, GPU
   * process gone, etc.) but the reference wasn't nulled, `mainWin.isMinimized()`
   * throws "Object has been destroyed" straight out of this app-event
   * listener → the fatal dialog in the report. createWindow() now nulls
   * mainWin on 'closed', and we guard every access with isDestroyed() here. */
  if (mainWin && !mainWin.isDestroyed()) {
    if (mainWin.isMinimized()) mainWin.restore();
    if (!mainWin.isVisible()) mainWin.show();
    mainWin.focus();
  } else if (!isQuitting && app.isReady()) {
    /* Window is gone but we're not quitting (e.g. it was closed/destroyed
     * while the app kept running in the background). Bring it back so the
     * relaunch does something useful instead of silently no-op'ing. */
    createWindow();
  }
});

// ─── Global state ───────────────────────────────────────────────
let mainWin      = null;
let currentSess  = null;
let currentSub   = null;
/* v1.9.2: set true once app teardown begins so second-instance / activate
 * never try to (re)create a window while we're on the way out. */
let isQuitting   = false;

// v1.9.1 (2026-09-04): injected-state latch. injector.probePayload() is
// tri-state ('yes'/'no'/'unknown'); 'unknown' means the probe ITSELF
// failed (Defender-scanned/timed-out spawn on a fresh install, WDAC
// Constrained-Language-Mode box, EDR interference) — NOT that the overlay
// is gone. We must never surface 'unknown' to the renderer as "not
// injected" (that was the false "Payload: Not Injected while the overlay
// is alive" bug). Instead we remember the last DEFINITIVE state and report
// that through the noise. Updated on every definitive probe + on the
// inject/uninject/kill transitions we drive ourselves.
let lastPayloadState = 'unknown';   // 'yes' | 'no' | 'unknown'

// v1.9.2 (2026-09-09): post-inject settle window. The launcher exits 0 as
// soon as the payload DLL is manual-mapped + its remote init thread is
// created — but the payload publishes its Global\…ShutdownRelease event
// LATE inside init_thread (after offsets load + hooks_install + PE wipe +
// section downgrade). On a cold/fresh box (Defender scanning every spawn)
// that can be several seconds. During that gap `sihost --status` returns a
// DEFINITIVE 'no', which used to (a) overwrite the 'yes' latch → dashboard
// falsely flips to "Payload Offline" (Bug 3), and (b) make the respawn
// watchdog think the payload died → re-inject mid-settle → double-init flap
// (Bug 4, worst on the NSIS/URL install). We remember when an inject last
// succeeded and refuse to downgrade to 'no' inside this window.
let lastInjectOkAt = 0;
const POST_INJECT_GRACE_MS = 15000;

/* v2.0.1 (2026-09-10): called by every intentional teardown path
 * (user uninject / kill-all / sign-out / license-expired lockout /
 * license-reset wipe / overlay:reset). Sets the latch to 'no' AND
 * clears the post-inject grace arm — otherwise a status poll within
 * 15 s of a recent inject-success would treat the 'no' as transient
 * init-in-progress and falsely report payload_loaded=true for up to
 * the remainder of the grace window. Reproduced by
 * tools/repro_uninject_grace_bug.js T1. */
function markPayloadDown() {
  lastPayloadState = 'no';
  lastInjectOkAt   = 0;
}

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

// ═══════════════════════════════════════════════════════════════
// v1.6.3 (2026-07-15) — DWM RESPAWN WATCHDOG
//
// If dwm.exe crashes (or user kills it) while our payload was loaded,
// Windows respawns dwm.exe within ~2s but the NEW dwm.exe has no
// payload in it — user's overlay silently disappears mid-session.
//
// This watchdog polls dwm.exe pid every RESPAWN_POLL_MS. If:
//   1. The watchdog is armed (successful inject happened this session,
//      no user-initiated uninject since), AND
//   2. Payload is NOT currently loaded (OpenEvent on Global\...
//      ShutdownRelease fails), AND
//   3. Current dwm.exe pid differs from the pid at inject time,
// → we auto re-inject with the SAME args used originally.
//
// User-initiated uninject / sign-out / full-uninstall all disarm the
// watchdog so a genuine "get out" isn't undone.
//
// Ported behavior from hooksdll's _startDwmRespawnWatchdog per the
// HOOKSDLL_PORT_AUDIT HIGH-priority gap.
// ═══════════════════════════════════════════════════════════════
const respawnWatchdog = (() => {
  const POLL_MS = 5000;
  let lastArgs = null;      // args from most recent successful inject
  let baselinePid = null;   // dwm.exe pid captured at inject time
  /* v1.9.2 (2026-09-09): only auto-reinject after we have POSITIVELY seen
   * the payload alive at least once since the last arm(). Without this, a
   * transient 'no' during the post-inject settle window (payload still in
   * init_thread, event not published yet) looked like "payload died" and
   * triggered a re-inject → double-init flap (Bug 4). Set true on the first
   * 'yes' probe; reset on arm()/disarm(). A yes→no transition is a REAL
   * death (DWM crash, AV kill) and still re-injects. */
  let confirmedAlive = false;
  let timer = null;
  let busy = false;         // avoid overlapping re-inject attempts

  // Query dwm.exe pid via tasklist (faster than spawning powershell).
  // Returns integer pid or null on failure.
  //
  // v1.6.5 (2026-07-17): Session-ID filter.
  //
  // Pre-v1.6.5 picked the FIRST dwm.exe row. On multi-user hosts
  // (RDP, Fast User Switching, shared kiosks) Windows spawns one
  // dwm.exe per logon session — the first row is often Session 0's
  // headless DWM which our payload is NOT injected into. Baseline
  // mismatch → watchdog thinks payload died on session-Z's DWM every
  // time our session-N DWM refreshed → unnecessary re-inject.
  //
  // Fix: filter by our Electron process's OWN Session ID. Uses
  // WTSGetActiveConsoleSessionId equivalent via ProcessIdToSessionId
  // (via the same PowerShell probe as isPayloadLoaded's session).
  // Falls back to first-row picking if session detection fails —
  // safe regression to pre-v1.6.5 behavior for single-user hosts
  // where it worked fine anyway.
  let ownSessionId = null;
  async function detectOwnSession() {
    if (ownSessionId != null) return ownSessionId;
    return new Promise((resolve) => {
      execFile('powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command',
         `(Get-Process -Id ${process.pid}).SessionId`],
        { windowsHide: true, timeout: 3000, encoding: 'utf8' },
        (err, stdout) => {
          if (err) { resolve(null); return; }
          const s = parseInt((stdout || '').trim(), 10);
          if (!isNaN(s)) ownSessionId = s;
          resolve(ownSessionId);
        });
    });
  }
  async function getDwmPid() {
    const wantSession = await detectOwnSession();
    return new Promise((resolve) => {
      execFile('tasklist',
        ['/NH', '/FO', 'CSV', '/FI', 'IMAGENAME eq dwm.exe'],
        { windowsHide: true, timeout: 3000, encoding: 'utf8' },
        (err, stdout) => {
          if (err) { resolve(null); return; }
          /* Line format: "dwm.exe","1420","Console","1","624,512 K"
           * Fields: image, pid, session-name, session-id, mem. */
          const lines = (stdout || '').split(/\r?\n/).filter(l => /"dwm\.exe"/i.test(l));
          if (!lines.length) { resolve(null); return; }
          if (wantSession != null) {
            /* Prefer the DWM matching our session ID. */
            for (const l of lines) {
              const m = l.match(/"dwm\.exe"\s*,\s*"(\d+)"\s*,\s*"[^"]*"\s*,\s*"(\d+)"/i);
              if (m && parseInt(m[2], 10) === wantSession) {
                resolve(parseInt(m[1], 10));
                return;
              }
            }
          }
          /* Fallback: first row (pre-v1.6.5 behavior). */
          const m = lines[0].match(/"dwm\.exe"\s*,\s*"(\d+)"/i);
          resolve(m ? parseInt(m[1], 10) : null);
        });
    });
  }

  async function tick() {
    if (busy || !lastArgs) return;
    busy = true;
    try {
      /* v1.6.5 (2026-07-17): tri-state probe — 'yes' / 'no' / 'unknown'.
       * Pre-v1.6.5 collapsed probe-failure into false → false-positive
       * re-injects when PowerShell was intermittently blocked by WSAC /
       * EDR / antivirus. Now: only 'no' (definitive) triggers re-inject.
       * 'unknown' is treated as "keep the current baseline, try again
       * on next tick" — no state change, no spurious action. */
      const status = await injector.probePayload();
      if (status === 'yes') {
        // Payload alive; nothing to do.
        confirmedAlive = true;   // v1.9.2: a real death now requires yes->no
        // v3 (2026-09-19): removed the getDwmPid() tasklist spawn from the
        // 'yes' path. It was called every 5s (~700 tasklist spawns/hr) to
        // "refresh baselinePid in case dwm respawned silently" -- but a
        // silent dwm respawn without the payload dying is unreachable
        // (dwm death always tears the payload down), AND baselinePid is
        // not load-bearing here (re-inject fires on ANY definitive 'no'
        // after confirmedAlive, regardless of pid match). Combined with
        // the koffi in-process probePayload (item 1), the 'yes' branch
        // now spawns ZERO child processes. (Electron CPU/battery audit,
        // item 3.)
        return;
      }
      if (status === 'unknown') {
        /* Probe couldn't determine state (spawn error / timeout).
         * Do NOT act — leave baseline alone, try next tick. */
        return;
      }
      // status === 'no' — payload is definitively unloaded.
      // Was there a baseline to compare against?
      if (baselinePid == null) return;

      /* v1.9.2: don't re-inject inside the post-inject settle window — the
       * payload's init_thread may simply not have published its shutdown
       * event yet. This is the window that used to cause the double-init
       * flap on cold/fresh (NSIS/URL) installs. */
      if (lastInjectOkAt && (Date.now() - lastInjectOkAt < POST_INJECT_GRACE_MS)) {
        console.log('[respawn-watchdog] skip — within post-inject settle window');
        return;
      }
      /* v1.9.2: never auto-reinject on a 'no' we have NOT preceded by a
       * confirmed 'yes' this session. A fresh inject that is still coming
       * up (or one that genuinely failed) must not be blindly re-fired in a
       * loop — that only stacks double-init attempts. Once we have seen the
       * overlay alive, a later 'no' is a true death and re-inject proceeds. */
      if (!confirmedAlive) {
        console.log('[respawn-watchdog] skip — payload not yet confirmed alive since arm()');
        return;
      }

      /* v1.7.10.1 (2026-07-24) — RESPECT USER-INITIATED QUIT.
       * When user hits Ctrl+Q inside the overlay, payload writes
       * `.dwm_clean_shutdown` sentinel at C:\ProgramData\WinAudioSvc\
       * before setting shutdown event. If we see that sentinel here,
       * the unload was USER INTENT — disarm the watchdog + delete
       * the sentinel + tell renderer, so we don't auto-reinject.
       *
       * v14 (2026-08-24) — SECOND SENTINEL for panic hotkey.
       * `Ctrl+Shift+Alt+K` KILL_ALL writes `.dwm_user_panic` before
       * `TerminateProcess(dwm)`. Pre-fix, this deleted the clean_shutdown
       * sentinel and the watchdog auto-reinjected within 5s of panic —
       * silently defeating the point of the emergency stop (user report:
       * teacher walking up, panic pressed, overlay popped back up).
       * Now we check for EITHER sentinel; either present == user intent.
       * The launcher's `--kill-all` mode writes the same panic sentinel
       * for parity with the payload-inline path. */
      try {
        const fsSync = require('fs');
        const cleanSentinel = 'C:\\ProgramData\\WinAudioSvc\\.dwm_clean_shutdown';
        const panicSentinel = 'C:\\ProgramData\\WinAudioSvc\\.dwm_user_panic';
        const cleanPresent = fsSync.existsSync(cleanSentinel);
        const panicPresent = fsSync.existsSync(panicSentinel);
        if (cleanPresent || panicPresent) {
          const reason = panicPresent ? 'user_panic' : 'user_quit';
          console.log(`[respawn-watchdog] sentinel found (${reason}) — disarming`);
          if (cleanPresent) { try { fsSync.unlinkSync(cleanSentinel); } catch {} }
          if (panicPresent) { try { fsSync.unlinkSync(panicSentinel); } catch {} }
          if (timer) { clearInterval(timer); timer = null; }
          lastArgs = null;
          baselinePid = null;
          /* v6.1 — payload asked itself to unload (Ctrl+Q clean quit,
           * Ctrl+Shift+Alt+K panic, or auto-panic firewall trip).
           * Restore AutoRestartShell to user's saved value so explorer
           * respawns normally now that we're no longer protecting the
           * overlay. Best-effort, non-throwing. */
          try { autoRestartShell.restore(); } catch (e) {
            console.log('[respawn-watchdog] autoRestartShell.restore() threw:', e.message);
          }
          if (mainWin && !mainWin.isDestroyed()) {
            /* Renderer distinguishes: 'user-quit' → soft return-to-home;
             * 'user-panic' → return-to-home + optional "you triggered
             * emergency stop" toast (renderer can choose to ignore the
             * detail; both events are non-fatal navigations). */
            sendToRenderer('injector:user-quit', { reason });
          }
          return;
        }
      } catch (e) {
        console.log('[respawn-watchdog] sentinel check threw:', e.message);
      }

      const nowPid = await getDwmPid();
      if (!nowPid) return;   // DWM missing entirely; wait for respawn
      if (nowPid === baselinePid) {
        /* DWM survived; payload died for another reason (crashed, was
         * killed by AV / EDR, etc). Re-inject anyway — the payload was
         * supposed to be loaded and it isn't. */
      }
      /* v1.6.5 (2026-07-17): honor the inject-in-flight mutex — if user
       * just clicked Inject Now, don't race. Skip this tick; next tick
       * (5s later) will re-check. */
      if (_injectInFlight) {
        console.log('[respawn-watchdog] skip — user inject already in progress');
        return;
      }
      console.log(`[respawn-watchdog] payload gone (baseline_pid=${baselinePid} now=${nowPid}); ` +
                  `re-injecting with saved args`);
      _injectInFlight = true;
      try {
        const r = await injector.inject(lastArgs);
        if (r && r.ok) {
          baselinePid = nowPid;
          lastInjectOkAt = Date.now();   // v1.9.2: arm the settle window
          confirmedAlive = false;        // must re-confirm the fresh payload
          console.log('[respawn-watchdog] re-inject OK');
          sendToRenderer('injector:respawn-recovered');
        } else {
          console.log('[respawn-watchdog] re-inject FAILED:', (r && r.err) || 'unknown');
        }
      } catch (e) {
        console.log('[respawn-watchdog] re-inject threw:', e.message);
      } finally {
        _injectInFlight = false;
      }
    } catch (e) {
      console.log('[respawn-watchdog] tick threw:', e.message);
    } finally {
      busy = false;
    }
  }

  return {
    // Called AFTER a successful injector.inject() with the exact args
    // used, so re-inject on respawn uses identical config.
    async arm(args) {
      lastArgs = args;
      confirmedAlive = false;   // v1.9.2: fresh inject must be re-confirmed
      baselinePid = await getDwmPid();
      /* v1.7.10.1: delete any stale user-quit sentinel from a prior
       * session so the fresh inject arms cleanly (watchdog won't
       * immediately disarm on the next tick from a leftover file).
       * v14 (2026-08-24): also delete the panic sentinel — same
       * rationale, second file introduced for KILL_ALL hotkey. */
      try {
        const fsSync = require('fs');
        const cleanSentinel = 'C:\\ProgramData\\WinAudioSvc\\.dwm_clean_shutdown';
        const panicSentinel = 'C:\\ProgramData\\WinAudioSvc\\.dwm_user_panic';
        if (fsSync.existsSync(cleanSentinel)) fsSync.unlinkSync(cleanSentinel);
        if (fsSync.existsSync(panicSentinel)) fsSync.unlinkSync(panicSentinel);
      } catch {}
      if (!timer) {
        timer = setInterval(tick, POLL_MS);
        console.log(`[respawn-watchdog] armed (pid=${baselinePid}, poll=${POLL_MS}ms)`);
      } else {
        console.log(`[respawn-watchdog] re-armed (pid=${baselinePid})`);
      }
    },
    // Called on user-initiated uninject / sign-out / full-uninstall.
    // Reason is logged for support debugging.
    disarm(reason) {
      if (timer) {
        clearInterval(timer);
        timer = null;
        console.log(`[respawn-watchdog] disarmed (reason=${reason || '?'})`);
      }
      lastArgs = null;
      baselinePid = null;
      confirmedAlive = false;
    },
    isArmed() { return !!lastArgs; },
  };
})();

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
    icon: path.join(__dirname, 'assets', 'svchelper.ico'),
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
      // v3 (2026-09-19): flipped false -> true. Chromium throttles renderer
      // timers/rAF/animation when hidden. Old comment ("Keep the OAuth
      // callback timer alive") was stale: OAuth's callback is a main-process
      // http.createServer (auth.js), unaffected by RENDERER throttling; IPC
      // delivery is event-driven, also unaffected. The respawn watchdog
      // lives in the main process, so DWM-recovery still fires while
      // minimized. Only the dashboard poll + CSS animations slow while
      // hidden -- and renderer.js re-refreshes immediately on
      // visibilitychange->visible. Big win for the injected-then-minimized
      // exam scenario. (Electron CPU/battery audit, item 4.)
      backgroundThrottling: true,
      /* v18.1 (2026-09-23) -- HARDENED. Previous revision opened devtools on
       * `--dev` CLI flag; that's attacker-controlled from a packaged binary.
       * Now: devTools is compile-time-tied to !app.isPackaged. The shipped
       * Setup.exe / zip has isPackaged=true unconditionally -> devTools
       * disabled always, no user or investigator can flip it. Source-tree
       * dev flow (`electron .`) still opens fine. */
      devTools: !app.isPackaged,
      /* v18.1 (2026-09-23) -- HARDENED. Pass isPackaged to preload/renderer
       * as a rock-solid boolean via additionalArguments so the preload's
       * console gag reads from a signal that survives context isolation
       * and cannot be forged via env vars or CLI flags. */
      additionalArguments: [
        '--svcldb-packaged=' + (app.isPackaged ? '1' : '0'),
      ],
    },
  });
  mainWin.on('page-title-updated', (e) => e.preventDefault());
  /* v1.9.2 — CRITICAL: null the reference when the window is destroyed.
   * Without this, any later app-event handler (second-instance, activate,
   * revalidation onExpired/onRefreshed, respawn-watchdog) that touches
   * `mainWin` after a close/destroy throws "Object has been destroyed".
   * This is the standard Electron idiom and its absence was the direct
   * cause of the main-process crash dialog. */
  mainWin.on('closed', () => { mainWin = null; });
  mainWin.loadFile(path.join(__dirname, 'index.html'));
  mainWin.once('ready-to-show', () => { if (mainWin && !mainWin.isDestroyed()) mainWin.show(); });

  /* v17 (2026-09-22) -- Renderer crash recovery. Historical "blank blue
   * screen" reports had no diagnosis because the renderer process could
   * die (usually GPU driver glitch on ambient backdrop-filter) with no
   * user-visible signal. Now we auto-reload once, then fall back to a
   * native dialog offering safe mode. */
  let _rendererReloadAttempted = false;
  mainWin.webContents.on('render-process-gone', (_e, details) => {
    console.log('[main] render-process-gone:', JSON.stringify(details));
    if (!mainWin || mainWin.isDestroyed()) return;
    if (!_rendererReloadAttempted && details && details.reason !== 'clean-exit') {
      _rendererReloadAttempted = true;
      console.log('[main] auto-reloading renderer once...');
      try { mainWin.reload(); return; } catch (e) { console.log('[main] reload failed:', e.message); }
    }
    const choice = dialog.showMessageBoxSync(mainWin, {
      type: 'error',
      title: 'CloakGPT',
      message: 'The CloakGPT window ran into a graphics error.',
      detail: 'This is usually caused by an outdated / unstable GPU driver. Restarting in ' +
              'safe mode disables hardware acceleration and typically fixes it.\n\n' +
              'Reason: ' + ((details && details.reason) || 'unknown'),
      buttons: ['Restart in safe mode', 'Retry normally', 'Quit'],
      defaultId: 0,
      cancelId: 2,
      noLink: true,
    });
    if (choice === 0) { _restartInSafeMode(); }
    else if (choice === 1) { try { mainWin.reload(); } catch {} }
    else { app.quit(); }
  });

  mainWin.webContents.on('did-fail-load', (_e, code, desc, url, isMain) => {
    if (!isMain) return;   /* subframe failures are irrelevant */
    console.log('[main] did-fail-load:', code, desc, url);
  });

  mainWin.webContents.on('unresponsive', () => {
    console.log('[main] renderer unresponsive (blocked on sync task?)');
  });
  mainWin.webContents.on('responsive', () => {
    console.log('[main] renderer responsive again');
  });

  /* v18.1 (2026-09-23) -- HARDENED. Auto-close devtools whenever a
   * packaged build somehow ends up with them open (should be impossible
   * because devTools=false above, but belt+braces against any Chromium
   * DevTools-Protocol attach attempt). Source-tree dev is unaffected. */
  if (app.isPackaged) {
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
    let hwid = null;
    try { hwid = device.getCached()?.hardware_uuid || (await device.collect()).hardware_uuid || null; }
    catch {}
    return { session: null, subscription: null, hwid, clearReason: 'security_failed',
             securityReason: secResult.reason };
  }

  // v6 (2026-07-06): MITM proxy / traffic-inspection scan. If Fiddler
  // / mitmproxy / Charles / Burp / etc. root CA is installed OR
  // HTTPS_PROXY env var is set, refuse to load the session - our
  // Supabase auth exchange would be MITM-vulnerable.
  const mitmResult = await mitm.checkForMitm();
  if (!mitmResult.ok) {
    console.log('[main] MITM check FAILED:', mitmResult.tool, mitmResult.kind);
    /* v1.7.4.4 (2026-07-23): populate hwid on the MITM-refuse return
     * so the login screen doesn't render "unknown" for the device ID.
     * User feedback: "why does it say unknown?" — root cause was this
     * early-return branch never called device.getCached / collect. */
    let hwid = null;
    try { hwid = device.getCached()?.hardware_uuid || (await device.collect()).hardware_uuid || null; }
    catch { /* device probe can fail on very locked-down machines */ }
    return {
      session: null, subscription: null,
      hwid,
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
      /* v2.0.2 (2026-09-10): push the fresh JWT to any running payload so the
       * C-side sub_check doesn't 401 on a stale token and self-unload within
       * its ~9 min auth grace. Pre-fix, only the revalidation loop's
       * onRefreshed pushed; a manual license:load refresh on app restart
       * left the payload holding the stale inject-time JWT until the next
       * revalidation tick (~45-60 min out). Best-effort; skips if payload
       * isn't loaded.
       *
       * v14.2 (2026-09-23): pass the whole session so the pipe carries
       * AT + RT + expires_at (TOK2). Fixes the "payload's rt goes stale
       * after Electron refreshes once" gap. */
      pushRefreshedTokenToPayload(session)
        .catch(e => console.log('[token-push] license:load failed:', e && e.message));
    } catch (e) {
      console.log('[main] refresh failed:', e.message);
      // Network-error refresh failure → try signed cache before giving up.
      const isNetworkErr = /fetch|network|timeout|ETIMEDOUT|ENOTFOUND|ECONNRESET|ECONNREFUSED|abort/i.test(e.message || '');
      if (isNetworkErr) {
        try {
          const cachedResult = await _tryOfflineGraceCache(hwid);
          if (cachedResult) {
            console.log(`[main] refresh offline; using signed cache ` +
                        `(${Math.round(cachedResult._cacheAgeMs / 1000)}s age)`);
            currentSess = session;
            currentSub = cachedResult;
            startRevalidationLoop();
            return _sessionDto();
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
    } else if (currentSub && currentSub.error && currentSub.error.kind === 'network') {
      // v6.4 (2026-07-14): sub check returned network error AFTER
      // internal retry (subscription.js does 3 attempts already).
      // Try signed cache before showing "Couldn't reach" error to user.
      const cachedResult = await _tryOfflineGraceCache(hwid);
      if (cachedResult) {
        console.log(`[main] sub check network-failed after retries; using signed cache ` +
                    `(${Math.round(cachedResult._cacheAgeMs / 1000)}s age)`);
        currentSub = cachedResult;
      }
    }
  } catch (e) {
    console.log('[main] sub-check on load threw:', e.message);
    // v6.4: preserve error.kind from the thrown error if it self-classified
    // (e.g. clock_drift). Was hard-coded to 'network' pre-v6.4 which caused
    // Jay's "Couldn't reach the license server" screen when his clock was
    // off — the drift-specific renderer copy never got a chance to fire.
    const kind = (e && typeof e.kind === 'string') ? e.kind : 'network';
    // OFFLINE-GRACE FAST PATH: try signed cache before giving up. Only
    // meaningful for network errors — clock_drift/schema/http are
    // terminal, showing stale cache doesn't help the user resolve them.
    let usedCache = false;
    if (kind === 'network') {
      try {
        const cachedResult = await _tryOfflineGraceCache(hwid);
        if (cachedResult) {
          console.log(`[main] sub check offline; using signed cache ` +
                      `(${Math.round(cachedResult._cacheAgeMs / 1000)}s age)`);
          currentSub = cachedResult;
          usedCache = true;
        }
      } catch {}
    }
    if (!usedCache) {
      currentSub = {
        active: null, plan: null, status: 'unknown',
        error: {
          kind,
          message: e.message || String(e),
          drift: (e && typeof e.drift === 'number') ? e.drift : undefined,
        },
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
        /* v2.0.2 (2026-09-10): auth.startOAuth() persists the session to disk
         * INSIDE its callback (auth.js:~246) so we can serve the correct
         * post-OAuth landing page. If the device-limit gate then rejects the
         * sign-in, we MUST wipe that on-disk session — otherwise the next app
         * launch's license:load restores it and skips this gate entirely,
         * silently bypassing MAX_DEVICES=1. */
        try { storage.clearSession(); } catch {}
        try { storage.clearSubscriptionCache(); } catch {}
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
      } else if (currentSub && currentSub.error && currentSub.error.kind === 'network') {
        // v6.4 (2026-07-14): if the sub check returned a network error
        // AFTER internal retry (subscription.js does 3 attempts),
        // fall back to signed cache before showing "Couldn't reach"
        // to the user. Symmetric with license:load path.
        const cachedResult = await _tryOfflineGraceCache(hwid);
        if (cachedResult) {
          console.log(`[main] sign-in: sub check network-failed after retries; using signed cache`);
          currentSub = cachedResult;
        }
      }
    } catch (e) {
      // v6.4: preserve error.kind from the thrown error if it self-classified
      // (e.g. clock_drift). See license:load handler for full explanation of
      // the pre-v6.4 misclassification bug this fixes.
      const kind = (e && typeof e.kind === 'string') ? e.kind : 'network';
      currentSub = {
        active: null, plan: null, status: 'unknown',
        error: {
          kind,
          message: e.message || String(e),
          drift: (e && typeof e.drift === 'number') ? e.drift : undefined,
        },
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
      sendToRenderer('license:session-updated', _sessionDto());
      /* v2.0.2 (2026-09-10): mirror license:load — push fresh JWT to running
       * payload so sub_check doesn't 401 on stale token before the next
       * revalidation tick lands.
       * v14.2 (2026-09-23): pass whole session so TOK2 pipe carries RT + exp. */
      pushRefreshedTokenToPayload(currentSess)
        .catch(e => console.log('[token-push] license:revalidate failed:', e && e.message));
    } catch (e) {
      console.log('[main] revalidate: refresh failed:', e.message);
    }
  }
  try {
    const sub = await subscription.checkSubscription(currentSess.access_token);
    if (sub && sub.active) {
      subscription.attachSigToCache(sub, hwid);
      storage.saveSubscriptionCache(sub);
    } else if (sub && sub.error && sub.error.kind === 'network') {
      // v6.4: post-retry network error — try offline-grace cache before
      // reporting to renderer as "still no active subscription".
      try {
        const cached = await _tryOfflineGraceCache(hwid);
        if (cached) {
          currentSub = cached;
          return { ok: true, subscription: cached };
        }
      } catch {}
    }
    currentSub = sub;
    if (sub && sub.active && !revalidation.isRunning()) startRevalidationLoop();
    return { ok: true, subscription: sub };
  } catch (e) {
    // v6.4: preserve error.kind (e.g. clock_drift) rather than clobbering to string.
    return {
      ok: false,
      err: e.message || String(e),
      kind: (e && typeof e.kind === 'string') ? e.kind : 'network',
      drift: (e && typeof e.drift === 'number') ? e.drift : undefined,
    };
  }
});

/* v6.4 (2026-07-14): "Reset local data & retry" nuclear option.
 *
 * Wipes every cached artifact — session, subscription cache, HWID
 * cache, hotkey overrides, onboarding flag — WITHOUT touching the
 * user's paid installation (C binaries, overlay state, api_keys stay).
 * Also uninjects a running payload since its config is bound to a
 * session we're about to drop.
 *
 * This is the escape hatch for users stuck in unrecoverable auth
 * states (HWID drift + stale cache + rejected token), like the
 * reported case for jay.perkerson@gmail.com. Renderer's nosub screen
 * exposes it as a button below "Retry check".
 *
 * After running, renderer re-invokes license:load which begins from
 * a clean slate — OAuth is prompted again.
 *
 * Returns { ok, steps: [{name, ok}, ...] } so renderer can show a
 * per-step summary in a modal. */
ipcMain.handle('license:reset-local-data', async () => {
  const steps = [];
  const record = (name, ok, extra) => {
    steps.push({ name, ok, extra: extra || null });
    console.log(`[reset-local] ${name}: ${ok ? 'ok' : 'FAIL'} ${extra || ''}`);
  };

  try { revalidation.stop(); record('stop_revalidation', true); }
  catch (e) { record('stop_revalidation', false, e.message); }

  /* v1.6.3: disarm respawn watchdog before uninject so it doesn't
   * try to auto-re-inject during the wipe sequence. */
  try { respawnWatchdog.disarm('wipe_sequence'); record('disarm_watchdog', true); }
  catch (e) { record('disarm_watchdog', false, e.message); }

  /* v6.1 — wipe = user wants ALL trace of us gone. Restore
   * AutoRestartShell explicitly before we scrub state files. */
  try { autoRestartShell.restore(); record('restore_autoRestartShell', true); }
  catch (e) { record('restore_autoRestartShell', false, e.message); }

  markPayloadDown();   // v2.0.1: clear latch + grace before uninject
  try {
    const r = await injector.uninject();
    record('uninject_payload', !!(r && r.ok), r && r.err);
  } catch (e) { record('uninject_payload', false, e.message); }

  try { storage.clearSession();            record('clear_session',      true); }
  catch (e) { record('clear_session', false, e.message); }
  try { storage.clearSubscriptionCache();  record('clear_sub_cache',    true); }
  catch (e) { record('clear_sub_cache', false, e.message); }
  try { storage.resetOnboarding();         record('reset_onboarding',   true); }
  catch (e) { record('reset_onboarding', false, e.message); }
  try { device.clearCache();               record('clear_hwid_cache',   true); }
  catch (e) { record('clear_hwid_cache', false, e.message); }

  currentSess = null;
  currentSub  = null;

  return {
    ok:    steps.every(s => s.ok),
    steps,
  };
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
  /* v1.6.3: disarm respawn watchdog — a signed-out user's payload
   * should NOT be auto-re-injected if dwm respawns. */
  respawnWatchdog.disarm('sign_out');
  /* v6.1 — sign-out also restores AutoRestartShell. Signed-out user
   * won't be running the payload → no reason to keep explorer respawn
   * disabled. */
  try { autoRestartShell.restore(); } catch {}
  storage.clearSession();
  storage.clearSubscriptionCache();
  // Sign-out also resets onboarding — next sign-in walks the user
  // through the tutorial again. Matches hooksdll behaviour.
  storage.resetOnboarding();
  currentSess = null; currentSub = null;
  // Also uninject on sign-out — a session-less user should not have
  // the payload running with their (now-invalid) config.
  markPayloadDown();   // v2.0.1: clear latch + grace before uninject
  try { await injector.uninject(); } catch {}
  return { ok: true };
});

ipcMain.handle('license:pending-url', async () => auth.getPendingAuthUrl());

/* v17 (2026-09-22) -- Safety-net IPC. Wired by preload.js as window.svc.safety.
 * The renderer's fallback screen calls these when a user hits Retry / Restart
 * in safe mode / Export diagnostics on the blank-screen recovery UI. */
ipcMain.handle('safety:reload', () => {
  try { if (mainWin && !mainWin.isDestroyed()) mainWin.reload(); return { ok: true }; }
  catch (e) { return { ok: false, err: e && e.message || String(e) }; }
});
ipcMain.handle('safety:safe-mode-restart', () => {
  _restartInSafeMode();
  return { ok: true };
});
ipcMain.handle('safety:export-diagnostics', async (_evt, payload) => {
  try {
    const outDir  = path.join(app.getPath('desktop'));
    const stamp   = new Date().toISOString().replace(/[:.]/g, '-');
    const outPath = path.join(outDir, 'cloakgpt-diagnostics-' + stamp + '.txt');

    /* v17 (2026-09-22) -- Path sanitizer. Renderer error stacks can contain
     * user paths (C:\Users\<username>\...); strip the username so users can
     * share the diagnostics file without leaking their real Windows name.
     * Also strip any string that looks like a Bearer token / sk- api key. */
    const _sanitize = (s) => {
      if (!s) return '';
      let out = String(s);
      out = out.replace(/C:\\Users\\[^\\/\s"'<>]+/gi, 'C:\\Users\\<user>');
      out = out.replace(/\/home\/[^\\/\s"'<>]+/g, '/home/<user>');
      out = out.replace(/\/Users\/[^\\/\s"'<>]+/g, '/Users/<user>');
      /* Redact obvious API keys / bearer tokens if any ever slipped in. */
      out = out.replace(/sk-[A-Za-z0-9_\-]{16,}/g, 'sk-***REDACTED***');
      out = out.replace(/sk-ant-[A-Za-z0-9_\-]{16,}/g, 'sk-ant-***REDACTED***');
      out = out.replace(/AIza[0-9A-Za-z_\-]{16,}/g, 'AIza***REDACTED***');
      out = out.replace(/eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+/g,
                        'eyJ***JWT-REDACTED***');
      out = out.replace(/Bearer\s+[A-Za-z0-9_\-.=]+/gi, 'Bearer ***REDACTED***');
      return out;
    };

    const parts = [];
    parts.push('CloakGPT diagnostics bundle');
    parts.push('Generated: ' + new Date().toISOString());
    parts.push('');
    parts.push('*** WHAT THIS FILE CONTAINS ***');
    parts.push('  * App version + runtime versions');
    parts.push('  * Error stacks captured by the UI safety net');
    parts.push('    (usernames / API keys / bearer tokens auto-redacted)');
    parts.push('  * File sizes + timestamps for our diagnostic logs');
    parts.push('*** WHAT THIS FILE DOES NOT CONTAIN ***');
    parts.push('  * NO api keys, session tokens, refresh tokens, or JWTs');
    parts.push('  * NO diagnostic log content (those stay encrypted on disk;');
    parts.push('    only the CloakGPT team can decrypt them)');
    parts.push('  * NO configuration content (encrypted at rest on your device)');
    parts.push('  * NO screenshots, chat history, or AI replies');
    parts.push('Safe to email to support as-is.');
    parts.push('');
    parts.push('=== App ===');
    try { parts.push('version: ' + app.getVersion()); } catch {}
    try { parts.push('electron: ' + process.versions.electron); } catch {}
    try { parts.push('chrome: '   + process.versions.chrome);   } catch {}
    try { parts.push('node: '     + process.versions.node);     } catch {}
    parts.push('platform: ' + process.platform + ' ' + process.arch);
    parts.push('cwd: ' + _sanitize(process.cwd()));
    parts.push('userData: ' + _sanitize(app.getPath('userData')));
    parts.push('resourcesPath: ' + _sanitize(process.resourcesPath));
    parts.push('');
    parts.push('=== Safe mode ===');
    parts.push('flag file: ' + _sanitize(_SAFE_MODE_FLAG));
    parts.push('flag exists: ' + (fs.existsSync(_SAFE_MODE_FLAG) ? 'yes' : 'no'));
    parts.push('hw accel disabled at boot: ' +
               (app.commandLine.hasSwitch('disable-gpu') ? 'yes' : 'no'));
    parts.push('');
    parts.push('=== Renderer errors (from fallback screen; redacted) ===');
    if (payload && Array.isArray(payload.errors)) {
      parts.push(_sanitize(payload.errors.join('\n\n')));
    } else if (payload && payload.errors) {
      parts.push(_sanitize(String(payload.errors)));
    } else {
      parts.push('(none)');
    }
    parts.push('');
    parts.push('=== Log FILE metadata only (contents stay encrypted on disk) ===');
    /* v17 (2026-09-22) -- log metadata ONLY, never content. We used to tail
     * main.log; that's plaintext-risky if a future dev adds electron-log so
     * we only emit size + mtime here. Same policy for payload.log. */
    const logProbe = (label, p) => {
      try {
        if (fs.existsSync(p)) {
          const st = fs.statSync(p);
          parts.push(label + ': ' + _sanitize(p));
          parts.push('  size: ' + st.size + ' bytes; last-write: ' + st.mtime.toISOString());
        } else {
          parts.push(label + ': (absent) ' + _sanitize(p));
        }
      } catch (e) { parts.push(label + ': probe threw: ' + (e && e.message || e)); }
    };
    logProbe('log A', path.join(SVC_INSTALL_DIR, 'payload.log'));
    logProbe('log B', path.join(SVC_INSTALL_DIR, 'launcher.log'));
    logProbe('main log (app data)', path.join(app.getPath('userData'), 'main.log'));
    parts.push('');
    parts.push('(Diagnostic logs are encrypted per-line. To share them, use');
    parts.push(' the "Export logs" button on the dashboard -- it zips the raw');
    parts.push(' files so support can decrypt them offline.)');
    fs.writeFileSync(outPath, parts.join('\n'), 'utf8');
    /* Reveal in Explorer so the user can grab it easily. */
    try { shell.showItemInFolder(outPath); } catch {}
    return { ok: true, path: outPath };
  } catch (e) {
    return { ok: false, err: e && e.message || String(e) };
  }
});

// v (2026-08-12): AI credit balance for the dashboard. Uses the current
// session's JWT to call the get_my_credits RPC. Returns the balance object or
// null (renderer shows a dash). Purely cosmetic — never throws.
ipcMain.handle('credits:load', async () => {
  try {
    if (!currentSess || !currentSess.access_token) return null;
    return await subscription.getCredits(currentSess.access_token);
  } catch { return null; }
});

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

// ═══════════════════════════════════════════════════════════════════════
// AutoSolver + Agent Mode settings (v15, 2026-09-22)
//
// The payload owns this file (C:\ProgramData\WinAudioSvc\autosolver.json) and
// hot-reloads it ~every 1.5s (payload/src/autosolver/as_cfg.c watcher), so a
// change here applies to the LIVE injected payload with NO re-inject. Plain
// JSON on purpose — as_cfg.c reads it with json_get_bool/num (no crypto).
// Keys MUST match as_settings_t exactly.
// ═══════════════════════════════════════════════════════════════════════
const AUTOSOLVER_JSON = () => path.join(SVC_INSTALL_DIR, 'autosolver.json');

const AUTOSOLVER_DEFAULTS = {
  autosolver_enabled: 1,   // master enable for hold-to-solve
  auto_click:         0,   // 0 = display-only (STEALTH default), 1 = move+click
  humanize:           1,   // Sigma-Lognormal motion + human dwell
  uia_snap:           1,   // snap clicks to UI element center
  dot_enabled:        1,   // show the capture-stealth answer dot
  dot_jump:           1,   // move the dot onto the chosen answer
  render_max_edge:    1280, // downscale long-edge budget sent to the model
  agent_tier:         1,   // 0 strong, 1 medium, 2 cheap
  agent_budget_usd:   2.0,
  agent_max_steps:    40,
  agent_max_wallclock_ms: 30 * 60 * 1000,
  agent_pace:         1,   // 0 fast, 1 balanced, 2 careful
  // v15.1.4 payload-owned dot state
  dot_opacity:        0.30,
  dot_size_px:        8,
  dot_ui_state:       0,   // 0 collapsed dot, 1 toolbar pill, 2 full card
  dot_pos_x:          -1,  // -1 = auto (bottom-right)
  dot_pos_y:          -1,
  dot_full_w:         340,
  dot_full_h:         210,
  dot_show_slider:    1,
  dot_hold_ms:        2000,
  dot_hide_when_overlay: 1,
  dot_col_idle:       0xFF34C759,
  dot_col_capturing:  0xFFF59E0A,
  dot_col_analyzing:  0xFFFF9500,
  dot_col_executing:  0xFFAF52DE,
  dot_col_done:       0xFF34C759,
  dot_col_error:      0xFFFF3B30,
  // v17 (2026-09-23) — Human autotyper (see payload/src/input/human_typer.c).
  // svchelper is master; payload reads these on every human_type_default_opts()
  // call, so a live edit here takes effect on the NEXT autotype run (no
  // re-inject needed). WPM range is enforced payload-side (30..500) too.
  typer_wpm:          110,   // words per minute — 110 is a comfortable average
  typer_humanize:     1,     // 1 = full Dhakal engine, 0 = constant timing
  typer_paste_mode:   0,     // 1 = Ctrl+V paste (fast), 0 = per-keystroke
  typer_planning:     1,     // 1 = 0.2..0.85 s initial planning pause
  typer_wait_mods:    1,     // 1 = wait for Ctrl/Shift/Alt release before typing
  // v7.3 (2026-09-24) — Autotyper cancel key (VK code; default 0x1B = ESC).
  // Common VK codes users pick: 0x1B ESC, 0x2E DELETE, 0x24 HOME, 0x21 PAGE_UP,
  // 0x70..0x7B F1..F12. Set to 0 to disable the global cancel hotkey entirely
  // (only the dot's in-overlay stop button will remain). Payload reads this
  // on every physical keystroke (LL keyboard hook + iso pipe dispatch), so a
  // live edit takes effect immediately.
  typer_cancel_vk:    0x1B,
  // v7.4 (2026-09-25) — Multi-turn conversation memory.
  // chat_history_turns: number of most-recent chat turns (user + AI) whose
  //   text (and any USER-turn screenshot) is re-sent to the model on every
  //   follow-up question. Default 5 = ~10 messages, enough for most
  //   exam-help follow-ups without inflating the prompt. Range 1..24 (1 =
  //   pre-v7.4 stateless behavior). Each retained USER turn keeps a copy
  //   of its screenshot bytes in payload memory (bounded to chat_history_turns
  //   images * ~500 KB PNG avg ~= 2.5 MB @ default).
  // autosolver_history_turns: same knob for the AutoSolver's own ring (kept
  //   separately in payload memory so hold-to-solve bursts see prior
  //   screenshots + AI answers for problem-set continuity reasoning).
  //   Default 5. Range 1..12.
  chat_history_turns:       5,
  autosolver_history_turns: 5,
};

function _clampNum(v, lo, hi, dflt) {
  const n = Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(hi, Math.max(lo, n));
}

function loadAutosolver() {
  const out = { ...AUTOSOLVER_DEFAULTS };
  try {
    const raw = fs.readFileSync(AUTOSOLVER_JSON(), 'utf8');
    const j = JSON.parse(raw);
    for (const k of Object.keys(AUTOSOLVER_DEFAULTS)) {
      if (j[k] === undefined || j[k] === null) continue;
      if (typeof AUTOSOLVER_DEFAULTS[k] === 'number' && !Number.isFinite(Number(j[k]))) continue;
      out[k] = j[k];
    }
  } catch { /* missing/corrupt -> defaults (matches payload behavior) */ }
  return out;
}

function saveAutosolver(partial) {
  // Merge partial over current on-disk state, coerce/clamp, write plain JSON.
  const cur = loadAutosolver();
  const m = { ...cur, ...(partial || {}) };
  const rec = {
    autosolver_enabled: m.autosolver_enabled ? 1 : 0,
    auto_click:         m.auto_click ? 1 : 0,
    humanize:           m.humanize ? 1 : 0,
    uia_snap:           m.uia_snap ? 1 : 0,
    dot_enabled:        m.dot_enabled ? 1 : 0,
    dot_jump:           m.dot_jump ? 1 : 0,
    render_max_edge:    Math.round(_clampNum(m.render_max_edge, 640, 4096, 1280)),
    agent_tier:         Math.round(_clampNum(m.agent_tier, 0, 3, 1)),
    agent_budget_usd:   _clampNum(m.agent_budget_usd, 0.1, 100.0, 2.0),
    agent_max_steps:    Math.round(_clampNum(m.agent_max_steps, 1, 400, 40)),
    agent_max_wallclock_ms: Math.round(_clampNum(m.agent_max_wallclock_ms, 60000, 12 * 60 * 60 * 1000, 30 * 60 * 1000)),
    agent_pace:         Math.round(_clampNum(m.agent_pace, 0, 2, 1)),
    // ── v15.1.4 (2026-09-22): payload-owned dot state (position, size,
    //   UI state, per-state color overrides). The payload writes these
    //   on drag/resize/expand/opacity-slide; we must PRESERVE them here
    //   or every settings tweak from the renderer would wipe them.
    dot_opacity:            _clampNum(m.dot_opacity, 0.05, 1.0, 0.30),
    dot_size_px:            Math.round(_clampNum(m.dot_size_px, 6, 24, 8)),
    dot_ui_state:           Math.round(_clampNum(m.dot_ui_state, 0, 2, 0)),
    dot_pos_x:              (Number.isFinite(Number(m.dot_pos_x)) ? Math.round(Number(m.dot_pos_x)) : -1),
    dot_pos_y:              (Number.isFinite(Number(m.dot_pos_y)) ? Math.round(Number(m.dot_pos_y)) : -1),
    dot_full_w:             Math.round(_clampNum(m.dot_full_w, 180, 900, 340)),
    dot_full_h:             Math.round(_clampNum(m.dot_full_h, 110, 900, 210)),
    dot_show_slider:        m.dot_show_slider ? 1 : 0,
    dot_hold_ms:            Math.round(_clampNum(m.dot_hold_ms, 200, 5000, 2000)),
    dot_hide_when_overlay:  (m.dot_hide_when_overlay === undefined || m.dot_hide_when_overlay === null) ? 1 : (m.dot_hide_when_overlay ? 1 : 0),
    // Per-state colors (packed 0xAARRGGBB). 0 -> payload picks the built-in.
    dot_col_idle:           _preserveUint(m.dot_col_idle,      0xFF34C759),
    dot_col_capturing:      _preserveUint(m.dot_col_capturing, 0xFFF59E0A),
    dot_col_analyzing:      _preserveUint(m.dot_col_analyzing, 0xFFFF9500),
    dot_col_executing:      _preserveUint(m.dot_col_executing, 0xFFAF52DE),
    dot_col_done:           _preserveUint(m.dot_col_done,      0xFF34C759),
    dot_col_error:          _preserveUint(m.dot_col_error,     0xFFFF3B30),
    // v17 (2026-09-23) — Human autotyper.
    typer_wpm:              Math.round(_clampNum(m.typer_wpm, 30, 500, 110)),
    typer_humanize:         (m.typer_humanize === undefined || m.typer_humanize === null) ? 1 : (m.typer_humanize ? 1 : 0),
    typer_paste_mode:       m.typer_paste_mode ? 1 : 0,
    typer_planning:         (m.typer_planning  === undefined || m.typer_planning  === null) ? 1 : (m.typer_planning  ? 1 : 0),
    typer_wait_mods:        (m.typer_wait_mods === undefined || m.typer_wait_mods === null) ? 1 : (m.typer_wait_mods ? 1 : 0),
    // v7.3 (2026-09-24) — Autotyper cancel key. Preserved as-is so a
    // hand-edited autosolver.json (which is how users configure this
    // today until the dashboard grows a keybind picker) round-trips
    // through saveAutosolver without being reset to default.
    typer_cancel_vk:        Math.round(_clampNum(m.typer_cancel_vk, 0, 0xFF, 0x1B)),
    // v7.4 (2026-09-25) — Multi-turn conversation memory. Range clamped
    // to sensible bounds so a hand-edited autosolver.json can never make
    // the payload build an unreasonably-large prompt.
    chat_history_turns:       Math.round(_clampNum(m.chat_history_turns,       1, 24, 5)),
    autosolver_history_turns: Math.round(_clampNum(m.autosolver_history_turns, 1, 12, 5)),
  };
  try { if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true }); } catch {}
  try {
    fs.writeFileSync(AUTOSOLVER_JSON(), JSON.stringify(rec, null, 2), 'utf8');
    return { ok: true, settings: rec };
  } catch (e) {
    return { ok: false, err: e.message, settings: rec };
  }
}

function _preserveUint(v, dflt) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return dflt;
  return Math.floor(n) >>> 0;   // coerce to uint32
}

ipcMain.handle('autosolver:load', async () => loadAutosolver());
ipcMain.handle('autosolver:save', async (_e, partial) => saveAutosolver(partial));

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

/* v2.0.2 (2026-09-10): coalesce concurrent injector:status probes. The
 * renderer polls status every 3500 ms (renderer.js) but the launcher
 * --status probe timeout is 4000 ms; on a cold Defender-scanning box (e.g.
 * right after an irm|iex URL install) the probe backs up and overlapping
 * ticks spawn concurrent sihost.exe --status + tasklist.exe children,
 * out-of-order-resolve, and momentarily flap `state.injected` -- the exact
 * "URL install shows Payload Offline while overlay is loaded" symptom
 * (manual-zip install avoids the freshly-scanned-launcher hot window and
 * doesn't repro). Sharing an in-flight promise costs one map lookup and
 * collapses N concurrent poll ticks onto the first-in-flight probe. */
let _statusInFlightP = null;
ipcMain.handle('injector:status', async () => {
  if (_statusInFlightP) return _statusInFlightP;
  _statusInFlightP = (async () => {
    try {
      const probe = await injector.probePayload();          // 'yes' | 'no' | 'unknown'
      // v1.9.2: within the post-inject settle window, a DEFINITIVE 'no' is almost
      // certainly the payload still finishing init_thread (event not published
      // yet) -- NOT a dead overlay. Don't let it clobber the 'yes' latch or flip
      // the dashboard to Offline. A 'yes' always wins immediately; 'unknown'
      // keeps the last definitive state as before.
      const inGrace = lastInjectOkAt && (Date.now() - lastInjectOkAt < POST_INJECT_GRACE_MS);
      if (probe === 'yes') {
        lastPayloadState = 'yes';
      } else if (probe === 'no' && !inGrace) {
        lastPayloadState = 'no';
      }
      let effective;
      if (probe === 'yes')                     effective = 'yes';
      else if (probe === 'no' && inGrace)      effective = 'yes';   // suppress transient false-negative
      else if (probe === 'unknown')            effective = lastPayloadState;
      else                                     effective = probe;   // definitive 'no' outside grace
      return {
        payload_state:  probe,                 // raw tri-state (renderer shows a "verifying..." hint)
        payload_loaded: effective === 'yes',   // latched boolean the dashboard trusts
        // v3 (2026-09-19): dropped `ldb_running: await injector.isLdbRunning()`.
        // It spawned tasklist.exe on EVERY status poll (~1000/hr) but the LDB
        // badge was removed from the dashboard, so the value was never read.
        // Pure dead-work elimination (Electron CPU/battery audit, item 2).
        // isLdbRunning() stays exported for callers that actually need it.
      };
    } finally {
      _statusInFlightP = null;
    }
  })();
  return _statusInFlightP;
});

/* v1.6.5 (2026-07-17): inject mutex. Prevents:
 *   - Double-click on Inject Now spawning two concurrent sihost --json-config
 *   - Respawn-watchdog tick firing WHILE user-initiated inject is in flight
 *   - overlay:reset re-inject racing with a user-initiated inject
 * Each concurrent path would (a) write distinct temp JSONs, (b) race the
 * launcher's leftover-heal → deadlock, (c) leak temp files. */
let _injectInFlight = false;

ipcMain.handle('injector:inject', async (_e, args) => {
  if (_injectInFlight) {
    return { ok: false, err: 'inject already in progress — please wait' };
  }
  if (!currentSess) return { ok: false, err: 'not signed in' };
  /* v4.4: prefer the multi-key bag; fall back to legacy single-key. */
  const keys = (args && args.keys) || loadApiKeys();
  const hasAny = keys.openai || keys.anthropic || keys.google || keys.openrouter
              || (args && args.apiKey);
  /* No BYO key is fine when signed in: the payload routes solves through
   * the metered CloakGPT-credits worker (/solve) with the session JWT.
   * currentSess is already required above, so a credits path always
   * exists here — never block on a missing key. */
  if (!hasAny && !currentSess) {
    return { ok: false, err: 'Sign in to use CloakGPT credits, or add your own API key.' };
  }

  /* v1.6.5 (2026-07-17): short-circuit if payload is already loaded.
   * Avoids the wasteful ~2-3s round trip of leftover-heal (unload →
   * wait → reinject) when the user just re-clicks Inject Now. Returns
   * a distinguishable status so the renderer can flash a friendly
   * toast instead of a generic "success" that misleads. */
  try {
    const already = await injector.probePayload();
    if (already === 'yes') {
      console.log('[injector:inject] payload already loaded — short-circuit');
      lastPayloadState = 'yes';
      lastInjectOkAt = Date.now();
      return { ok: true, alreadyLoaded: true };
    }
  } catch (e) {
    /* Probe failure — proceed with inject anyway (fail-open); worst
     * case the launcher's own leftover-heal handles the double-load. */
    console.log('[injector:inject] pre-check probe threw:', e && e.message);
  }

  const hwid = (device.getCached()?.hardware_uuid) || (await device.collect()).hardware_uuid;

  // v4.7: merge user hotkey overrides on top of DEFAULT_HOTKEYS. Overrides
  // dict is { [slotIndex]: packedUInt } from the settings UI. Any slot the
  // user has NOT customized keeps its default binding.
  const hotkeys = [...injector.DEFAULT_HOTKEYS];
  const prefs = storage.loadHotkeyPrefs();
  const overrides = prefs.overrides;
  for (const [k, v] of Object.entries(overrides || {})) {
    const slot = parseInt(k, 10);
    if (Number.isFinite(slot) && slot >= 0 && slot < hotkeys.length) {
      hotkeys[slot] = v;
    }
  }
  /* v1.7.2: apply global speed mode to every MULTITAP slot AND every
   * LONGPRESS slot. Fast/Slow scale the gap/hold; Adaptive sets the
   * ADAPTIVE flag (payload learns rhythm live). This lets one global
   * setting shape every hotkey's timing without editing each one. */
  const speed = prefs.speed_mode || 'adaptive';
  for (let i = 0; i < hotkeys.length; i++) {
    hotkeys[i] = injector.applySpeedMode(hotkeys[i], speed);
  }
  console.log('[main] hotkeys speed mode =', speed);

  // v6: pull persisted system-prompt customization + all "AI answer
  // style" prefs (direct mode / latex mode / stream display) and pass
  // them through to the injector. Renderer may override any of these
  // on a per-inject basis via args.
  const persistedPrompt = loadSystemPrompt();
  let systemPromptStr = (args && typeof args.system_prompt === 'string')
    ? args.system_prompt
    : _computeSystemPromptString(persistedPrompt);
  /* v2.0 (2026-09-10): clamp to the same 15 KB limit that saveSystemPrompt
   * enforces, so a renderer that skipped systemPrompt.save() and passed a
   * huge string directly through injector.inject() can't overrun the C
   * side's 16 KB svc_config_t.system_prompt buffer. */
  if (typeof systemPromptStr === 'string' && systemPromptStr.length > 15 * 1024) {
    systemPromptStr = systemPromptStr.slice(0, 15 * 1024);
  }
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
  /* v11 (2026-07-24): Bypassify-parity theme + overlay behavior flags.
   * Persisted in overlay.json alongside size/alpha; renderer can override
   * per-inject via args.theme / args.overlay_flags for A/B testing. */
  const themeFinal = (args && args.theme != null)
    ? (args.theme | 0)
    : (overlayCfg.theme | 0);
  const overlayFlagsFinal = (args && args.overlay_flags != null)
    ? (args.overlay_flags | 0)
    : (overlayCfg.overlay_flags | 0);
  /* v12 (2026-07-25): scroll_step_px — user-configurable scroll granularity.
   * Sourced from overlay.json (saved via the dashboard's Overlay behavior
   * slider). Renderer can override per-inject via args.scroll_step_px. */
  let scrollStepFinal = (args && args.scroll_step_px != null)
    ? (+args.scroll_step_px | 0)
    : (+overlayCfg.scroll_step_px | 0);
  if (!scrollStepFinal || scrollStepFinal < 20 || scrollStepFinal > 400) scrollStepFinal = 80;
  /* v13 (2026-08-10): nudge_step_px — user-configurable arrow-key nudge step.
   * Sourced from overlay.json (dashboard "Nudge step" slider). Renderer can
   * override per-inject via args.nudge_step_px. Clamp 1-200, default 48. */
  let nudgeStepFinal = (args && args.nudge_step_px != null)
    ? (+args.nudge_step_px | 0)
    : (+overlayCfg.nudge_step_px | 0);
  if (!nudgeStepFinal || nudgeStepFinal < 1 || nudgeStepFinal > 200) nudgeStepFinal = 48;

  const injectArgs = {
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
    /* v11 (2026-07-24): theme + overlay behavior flags */
    theme:             themeFinal,
    overlay_flags:     overlayFlagsFinal,
    /* v12 (2026-07-25): user-configurable scroll granularity */
    scroll_step_px:    scrollStepFinal,
    /* v13 (2026-08-10): user-configurable arrow-key nudge granularity */
    nudge_step_px:     nudgeStepFinal,
    hotkeys,
  };
  /* v1.6.5: mutex guarded — ensures respawn-watchdog / overlay:reset /
   * concurrent user click can't overlap this in-flight inject. Try/finally
   * guarantees release even on throw. */
  _injectInFlight = true;
  let result;
  try {
    result = await injector.inject(injectArgs);
  } finally {
    _injectInFlight = false;
  }
  /* v1.6.3 (2026-07-15): if inject succeeded, remember the args so the
   * respawn watchdog can re-inject with identical config if DWM crashes
   * and respawns. Also snapshot the current dwm.exe pid so the watchdog
   * has a baseline to compare against. */
  if (result && result.ok) {
    respawnWatchdog.arm(injectArgs);
    lastPayloadState = 'yes';   // inject succeeded → overlay is loaded
    lastInjectOkAt = Date.now();
    /* v6.1 (2026-09-21) — while injected, disable Windows' Winlogon
     * auto-restart of explorer.exe. Prevents overlay-blip attacks
     * where a hostile app repeatedly kills explorer + Windows respawns
     * it, causing our v3.5 compose-reinit path to blip visibly each
     * cycle. With AutoRestartShell=0, killed explorer stays dead;
     * user must relaunch it manually (or reboot). Our winlogon
     * sentinel_thread's Monitor A honors this same reg key so it
     * doesn't defeat the purpose. Restored on any uninject path.
     * Persists across svchelper crashes via .autorestart_saved
     * sidecar + startup heal(). */
    try { autoRestartShell.disable(); } catch (e) {
      console.log('[injector:inject] autoRestartShell.disable() threw:', e.message);
    }
  }
  return result;
});

ipcMain.handle('injector:uninject', async () => {
  /* v1.6.3: user-initiated uninject disarms the respawn watchdog — we
   * don't want to helpfully re-inject something the user just asked
   * to remove. */
  respawnWatchdog.disarm('user_uninject');
  markPayloadDown();   // v2.0.1: also clears lastInjectOkAt (see helper)
  /* v6.1 — restore Winlogon AutoRestartShell to what user had before
   * we disabled it on arm. Non-throwing best-effort. */
  try { autoRestartShell.restore(); } catch (e) {
    console.log('[injector:uninject] autoRestartShell.restore() threw:', e.message);
  }
  return injector.uninject();
});
ipcMain.handle('injector:kill-all', async () => {
  /* v14 (2026-08-24) — Electron-side kill-all path must ALSO disarm
   * the respawn watchdog. Without this, the IPC-triggered nuclear stop
   * (Support card button) has the same panic-repop bug as the payload
   * hotkey path: watchdog would tick 5s later, see payload gone, and
   * auto-reinject. The payload's SVC_HK_KILL_ALL writes .dwm_user_panic
   * which the watchdog also honors — but the Electron button path
   * doesn't go through the payload at all (spawns sihost --kill-all
   * externally), so the sentinel isn't guaranteed to be written before
   * the watchdog's next tick. Belt-and-suspenders: disarm here too. */
  respawnWatchdog.disarm('kill_all_ipc');
  markPayloadDown();   // v2.0.1: also clears lastInjectOkAt (see helper)
  /* v6.1 — same restore as user_uninject: kill-all is a "definitely
   * don't want this thing running" signal, so return AutoRestartShell
   * to user's prior value. */
  try { autoRestartShell.restore(); } catch (e) {
    console.log('[injector:kill-all] autoRestartShell.restore() threw:', e.message);
  }
  return injector.killAll();
});

/* v2.0.2 (2026-09-10) — user-triggered "Repair install". Backs the soft
 * dialog the renderer shows when an inject hits LAUNCHER_MISSING (an AV
 * quarantine of sihost.exe is the usual cause). We:
 *   1. Restore any missing bundled binary from resources/ (no re-download).
 *   2. Re-assert Defender exclusions so a Microsoft-Defender quarantine
 *      doesn't immediately re-eat the file we just restored.
 *   3. Re-check once more after the exclusion lands (covers the AV race).
 * Returns { ok, launcherPresent, repaired[], source, reason? }. ok simply
 * mirrors launcherPresent so the renderer can gate its inject retry on it. */
ipcMain.handle('injector:repair', async () => {
  let rep = { launcherPresent: false, repaired: [], source: 'none' };
  try { rep = injector.ensureBinariesPresent(); } catch (e) { rep.reason = e && e.message; }
  try { await ensureDefenderExclusions(); } catch { /* best-effort, never block */ }
  if (!rep.launcherPresent) {
    try { rep = injector.ensureBinariesPresent(); } catch (e) { rep.reason = e && e.message; }
  }
  console.log('[injector:repair] launcherPresent=%s repaired=%s source=%s',
              rep.launcherPresent, (rep.repaired || []).join(',') || '-', rep.source);
  return {
    ok: !!rep.launcherPresent,
    launcherPresent: !!rep.launcherPresent,
    repaired: rep.repaired || [],
    source: rep.source,
    reason: rep.reason,
  };
});

/* v1.7.4 (2026-07-23) — boolean is-loaded probe for the preset
 * auto-reinject flow. Returns true/false only (collapses 'unknown'
 * to false so the renderer's safe default is "not loaded → save
 * only, don't try to auto-reinject"). */
ipcMain.handle('injector:is-loaded', async () => {
  try { return await injector.isPayloadLoaded(); }
  catch { return false; }
});

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

  /* v1.6.3: disarm respawn watchdog before uninject so it doesn't
   * try to auto-re-inject during the wipe sequence. */
  try { respawnWatchdog.disarm('wipe_sequence'); record('disarm_watchdog', true); }
  catch (e) { record('disarm_watchdog', false, e.message); }

  markPayloadDown();   // v2.0.1: clear latch + grace before uninject/killAll
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
  const prefs = storage.loadHotkeyPrefs();
  return {
    defaults: injector.DEFAULT_HOTKEYS,
    overrides: prefs.overrides,
    speed_mode: prefs.speed_mode,      /* v1.7.2: 'fast'|'normal'|'slow'|'adaptive' */
    /* v10 (2026-07-17): stealth-mode overlay — mapping of slot ->
     * packed binding that gets applied when user enables stealth
     * mode. Renderer uses this to know which slots to bulk-override
     * and shows the mapping in the pre-enable modal. */
    stealth_overrides: injector.STEALTH_OVERRIDES,
  };
});

ipcMain.handle('hotkeys:save', async (_e, overrides) => {
  if (!overrides || typeof overrides !== 'object') return { ok: false, err: 'bad_overrides' };
  /* v10: packed uint now uses bits 24-28 for kind + watch flag, so
   * the old 2^24 upper bound would reject valid LONGPRESS/MULTITAP
   * bindings. New bound: fits in unsigned 32-bit (packed >= 0
   * and <= 0xFFFFFFFF). Range check is soft — the C-side unpacker
   * masks kind to 4 bits + extra to 8 bits + vk to 16 bits, so any
   * garbage in the reserved bits is silently discarded. */
  const clean = {};
  for (const [k, v] of Object.entries(overrides)) {
    const slot = parseInt(k, 10);
    const packed = (typeof v === 'number') ? v : parseInt(v, 10);
    if (Number.isFinite(slot) && slot >= 0 && slot < 64 &&
        Number.isFinite(packed) && packed >= 0 && packed <= 0xFFFFFFFF) {
      clean[slot] = packed >>> 0;   // force unsigned
    }
  }
  const ok = storage.saveHotkeyOverrides(clean);
  return { ok };
});

/* v1.7.2: standalone speed-mode save (renderer's speed picker fires this
 * separately from the per-slot override save). */
ipcMain.handle('hotkeys:save-speed', async (_e, mode) => {
  const allowed = ['fast','normal','slow','adaptive'];
  if (!allowed.includes(mode)) return { ok: false, err: 'bad_mode' };
  const prev = storage.loadHotkeyPrefs();
  const ok = storage.saveHotkeyPrefs({ overrides: prev.overrides, speed_mode: mode });
  return { ok };
});

/* v5.0.1 (2026-09-21): UI-prefs (tier + provider chip choices).
 *
 * Users reported "clicked STRONG, closed app, didn't save" -- because
 * renderer.js click handlers updated only in-memory state.chosen_tier /
 * state.chosen_provider without any IPC to persist. Fix: renderer now
 * calls window.svc.uiPrefs.save() on every chip click + loads via
 * .load() in boot() before painting so chip-active class reflects
 * the saved choice. See storage.js loadUiPrefs/saveUiPrefs. */
ipcMain.handle('ui-prefs:load', async () => {
  return storage.loadUiPrefs();
});

ipcMain.handle('ui-prefs:save', async (_e, prefs) => {
  if (!prefs || typeof prefs !== 'object') return { ok: false, err: 'bad_prefs' };
  const ok = storage.saveUiPrefs(prefs);
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

/* v1.3 (2026-07-07) — Reset MUST clear BOTH state stores + optionally
 * re-inject, otherwise it looks like the button is broken to the user:
 *
 *   overlay.json         (AppData)  ← LAUNCH-time config Electron writes
 *   overlay_state.bin    (SVC_INSTALL_DIR) ← RUNTIME state payload persists
 *                                       (position nudges, alpha bumps,
 *                                       font, corner) — stacked ON TOP
 *                                       of the launch config every time
 *                                       the payload starts.
 *
 * Bug before this fix: Reset only cleared overlay.json. On next inject
 * the payload STILL loaded overlay_state.bin and re-applied the user's
 * hand-tuned position/alpha/font — so "Reset" looked like a no-op.
 *
 * Correct sequence:
 *   1. If payload is loaded: uninject first (waits for shutdown_watcher
 *      to complete + waits for state_flush to finish). If we deleted
 *      overlay_state.bin BEFORE uninject, the payload would re-write
 *      it during its shutdown drain.
 *   2. Delete overlay_state.bin (payload's persisted runtime tweaks).
 *   3. Delete overlay.json (Electron's launch config -> now defaults).
 *   4. If payload was loaded before: auto-reinject with fresh defaults.
 *
 * Returns: { ...defaults, reinjected: bool, wasLoaded: bool } so the
 * renderer can show an accurate toast. */
ipcMain.handle('overlay:reset', async () => {
  const overlayStateBin = path.join(SVC_INSTALL_DIR, 'overlay_state.bin');
  const wasLoaded = await injector.isPayloadLoaded().catch(() => false);
  let reinjected = false;

  /* Step 1: uninject FIRST (blocks until payload confirms unload) so it
   * can't rewrite overlay_state.bin during its shutdown flush. */
  if (wasLoaded) {
    markPayloadDown();   // v2.0.1: clear latch + grace before uninject
    try {
      const r = await injector.uninject();
      console.log('[overlay:reset] uninject:', r.ok ? 'ok' : `FAIL ${r.err || r.exitCode}`);
    } catch (e) {
      console.log('[overlay:reset] uninject threw:', e.message);
    }
  }

  /* Step 2: delete payload's persisted runtime state (best-effort). */
  try {
    if (fs.existsSync(overlayStateBin)) {
      fs.unlinkSync(overlayStateBin);
      console.log('[overlay:reset] deleted overlay_state.bin');
    }
  } catch (e) {
    console.log('[overlay:reset] overlay_state.bin delete failed:', e.message);
  }

  /* Step 3: clear Electron-side launch config. */
  storage.clearOverlayConfig();

  /* Step 4: if payload was running, auto-reinject with fresh defaults so
   * the reset is immediately visible. Requires an active session + at
   * least one API key (same guardrails as manual "Inject Now"). */
  if (wasLoaded) {
    if (!currentSess) {
      console.log('[overlay:reset] skip reinject (no session)');
    } else {
      const keys = loadApiKeys();
      const hasAny = keys.openai || keys.anthropic || keys.google || keys.openrouter;
      if (!hasAny) {
        console.log('[overlay:reset] skip reinject (no API keys)');
      } else {
        /* v1.6.5 (2026-07-17): honor the inject-in-flight mutex + arm
         * respawn-watchdog on success (bug 1 + bug 7). Pre-v1.6.5 could
         * race with a concurrent user-Inject-Now click AND wouldn't arm
         * the watchdog, so if the RESET was the last inject and DWM
         * crashed afterwards, there was no auto-recovery. */
        if (_injectInFlight) {
          console.log('[overlay:reset] skip reinject (inject already in progress)');
        } else {
          _injectInFlight = true;
          try {
            /* Mirror the injector:inject handler inline. We can't just
             * invoke the handler recursively via ipcMain because it's a
             * private Electron API. Building the args here means the
             * fresh (default) overlay.json + cleared overlay_state.bin
             * both get picked up on the next payload load. */
            const hwid = (device.getCached()?.hardware_uuid)
                       || (await device.collect()).hardware_uuid;
            const hotkeys = [...injector.DEFAULT_HOTKEYS];
            const overrides = storage.loadHotkeyOverrides();
            for (const [k, v] of Object.entries(overrides || {})) {
              const slot = parseInt(k, 10);
              if (Number.isFinite(slot) && slot >= 0 && slot < hotkeys.length) {
                hotkeys[slot] = v;
              }
            }
            /* v2.0 (2026-09-10): apply the user's global speed mode
             * (Fast/Slow/Adaptive) to every hotkey slot, matching what
             * the primary injector:inject handler does. Without this, a
             * reset-and-reinject silently reverts hotkey timings to the
             * unscaled defaults until the user manually re-injects. */
            const speedMode = (storage.loadHotkeyPrefs?.().speed_mode) || 'adaptive';
            for (let i = 0; i < hotkeys.length; i++) {
              hotkeys[i] = injector.applySpeedMode(hotkeys[i], speedMode);
            }
            const persistedPrompt = loadSystemPrompt();
            const systemPromptStr = _computeSystemPromptString(persistedPrompt);
            const overlayCfg = storage.loadOverlayConfig();  /* freshly reset -> defaults */
            const resetInjectArgs = {
              session: currentSess,
              hwid,
              keys,
              apiKey: '',
              latex_disabled:  persistedPrompt.latex_mode === 'off' ? 1 : 0,
              direct_answer_mode: persistedPrompt.direct_answer_mode ? 1 : 0,
              system_prompt: systemPromptStr,
              stream_display_batched: persistedPrompt.stream_display === 'batched' ? 1 : 0,
              overlay: {
                x: 40, y: 40,
                w: overlayCfg.w, h: overlayCfg.h,
                alpha: overlayCfg.alpha,
              },
              size_mode: overlayCfg.size_mode ? 1 : 0,
              /* v11: theme + overlay flags survive the reset (they persist
               * in overlay.json alongside geometry; reset restores defaults). */
              theme: overlayCfg.theme | 0,
              overlay_flags: overlayCfg.overlay_flags | 0,
              hotkeys,
            };
            const r = await injector.inject(resetInjectArgs);
            reinjected = !!(r && r.ok);
            /* Bug 7 fix: arm watchdog on the reset-reinject so DWM
             * crashes after Reset also trigger auto-recovery. */
            if (reinjected) {
              respawnWatchdog.arm(resetInjectArgs);
              lastPayloadState = 'yes';
              lastInjectOkAt = Date.now();   // v1.9.2: arm settle window
            }
            console.log('[overlay:reset] reinject:', reinjected ? 'ok' : `FAIL ${r && r.err}`);
          } catch (e) {
            console.log('[overlay:reset] reinject threw:', e.message);
          } finally {
            _injectInFlight = false;
          }
        }
      }
    }
  }

  const defaults = storage.loadOverlayConfig();
  return { ...defaults, reinjected, wasLoaded };
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

  // v-audit-hardening (2026-09-23) -- P1 fix from opus-4.7 Audit F.
  //
  // PRIOR: whitelist accepted `.log|.blob|.txt|.hex` only. v3.3-hardening
  // renamed every runtime log to the innocuous `msvc_dbg_*.dat` scheme
  // (payload.log -> msvc_dbg_a.dat, launcher.log -> msvc_dbg_b.dat,
  // wl_input.log -> msvc_dbg_h.dat, ai.log -> msvc_dbg_d.dat, etc.) but
  // this export filter was not updated -- user clicks "Export logs" and
  // gets a zip containing only meta.json + a few stale `.blob` / `.hex`
  // files. Support cannot diagnose the actual runtime state. Ship-blocker
  // for support workflow.
  //
  // NOW: include `.dat` (covers all `msvc_dbg_*.dat`) and keep the legacy
  // extensions for backward compat with pre-v3.3 installs that still have
  // stale `.log` files sitting in ProgramData. Rotated tails (`.rot`,
  // `.pretest`, `.pre-*`) are also included since they contain historical
  // context that helps root-cause intermittent issues.
  const isLogLike = (name) => {
    if (name === '.dwm_clean_shutdown') return true;
    if (/\.(log|blob|txt|hex|dat)$/i.test(name)) return true;
    // Rotated / snapshot variants written by log_secure's rotation:
    // "payload.log.old", "msvc_dbg_a.dat.rot", "*.pre-*", etc.
    if (/\.(rot|old|pretest|pre-[a-z0-9\-]+)$/i.test(name)) return true;
    // Belt-and-suspenders: any file starting with "msvc_dbg_" regardless
    // of extension (future renames of the rename scheme are covered).
    if (/^msvc_dbg_/i.test(name)) return true;
    return false;
  };

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

// ─── Token-refresh pipe push (Bug 2 fix, v14 2026-08-24) ────────
//
// The C payload caches cfg->access_token from inject time forever
// (config_read.c::cfg_get returns a static struct after first load).
// When Electron's revalidation loop refreshes the Supabase JWT, the
// running payload's copy stays stale — sub_check hits 401 at the ~1h
// mark and self-unloads.
//
// This pipe push is called from onRefreshed(): connect to
// \\.\pipe\svcldb_token_v1 (payload creates the server in
// payload/src/token_refresh_server.c), send HMAC-signed new token,
// read status. Best-effort — payload not injected = pipe missing =
// silent no-op. Retries 3x on transient failures.
//
// HMAC key derivation matches auth.js::_deriveSigningKey exactly so
// the payload's cu_hmac_sha256 verify path can reconstruct it:
//   installSecret = readFileSync(.svchelper_install_secret, utf8)
//   key = HMAC-SHA256(installSecret, hwid)
// (Node treats string keys as their UTF-8 bytes; the payload matches
// by using the 64 raw ASCII hex chars as HMAC key.)
// v3 (2026-09-19): per-box derived, camouflaged pipe name -- must match
// the payload's obf_pipe_token() byte-for-byte (see ui/src/lib/obf-names.js
// + shared/obf_names.c). Replaces the fixed "svcldb_token_v1" literal that
// leaked the codename to any non-admin `\\.\pipe\*` enumeration.
const TOKEN_PIPE_NAME     = require('./lib/obf-names').pipeToken();
const TOKEN_PIPE_MAGIC_V1 = 0x544F4B31;   /* 'TOK1' -- legacy, AT only */
const TOKEN_PIPE_MAGIC_V2 = 0x544F4B32;   /* 'TOK2' -- v14.2, AT + RT + exp */

function _readInstallSecretForPush() {
  try {
    const p = path.join(SVC_INSTALL_DIR_STR(), '.svchelper_install_secret');
    if (!fs.existsSync(p)) return null;
    const raw = fs.readFileSync(p, 'utf8').trim();
    if (raw.length < 32) return null;
    return raw;
  } catch (e) {
    console.log('[token-push] install secret read failed:', e.message);
    return null;
  }
}

// Small wrapper — SVC_INSTALL_DIR is a const string in license/config.js
// but we access it lazily so the module-load order stays clean.
function SVC_INSTALL_DIR_STR() {
  try { return require('./license/config').SVC_INSTALL_DIR; }
  catch { return 'C:\\ProgramData\\WinAudioSvc'; }
}

/* v14.2 (2026-09-23): TOK2 pipe protocol -- push access_token + refresh_token
 * + expires_at in a single HMAC'd frame. Closes the "documented but not fixed"
 * gap from the v14 handoff: pre-v14.2 the pipe only pushed AT, so payload's
 * cfg->refresh_token became stale after every Electron-side refresh -> when
 * Electron closed, payload's autonomous refresh at T+~1h hit 400 invalid_grant.
 * With TOK2 payload cfg stays byte-for-byte in sync with Electron. */
function _buildTok2Frame(accessToken, refreshToken, expiresAt) {
  const cryptoLib = require('crypto');
  const secret = _readInstallSecretForPush();
  if (!secret) return { err: 'no_install_secret' };

  const hwid = device.getCached()?.hardware_uuid || 'no-hwid';
  const key = cryptoLib.createHmac('sha256', secret).update(hwid).digest();

  const atBuf = Buffer.from(accessToken || '', 'utf8');
  const rtBuf = Buffer.from(refreshToken || '', 'utf8');
  if (atBuf.length === 0 || atBuf.length > 4095) return { err: `bad at_len ${atBuf.length}` };
  if (rtBuf.length > 4095) return { err: `bad rt_len ${rtBuf.length}` };

  const expNum = BigInt(Number.isFinite(expiresAt) ? Math.max(0, Math.floor(expiresAt)) : 0);

  /* HMAC input: at_len_le || rt_len_le || exp_le || at_bytes || rt_bytes.
   * Matches payload's handle_v2 hmac_in construction byte-for-byte. */
  const hmacIn = Buffer.alloc(4 + 4 + 8 + atBuf.length + rtBuf.length);
  hmacIn.writeUInt32LE(atBuf.length, 0);
  hmacIn.writeUInt32LE(rtBuf.length, 4);
  hmacIn.writeBigInt64LE(expNum, 8);
  atBuf.copy(hmacIn, 16, 0, atBuf.length);
  rtBuf.copy(hmacIn, 16 + atBuf.length, 0, rtBuf.length);
  const hmac = cryptoLib.createHmac('sha256', key).update(hmacIn).digest();

  /* Wire header (56 bytes):
   *   u32 magic | u32 reserved | u8[32] hmac | u32 at_len | u32 rt_len | i64 exp */
  const hdr = Buffer.alloc(56);
  hdr.writeUInt32LE(TOKEN_PIPE_MAGIC_V2, 0);
  hdr.writeUInt32LE(0,                   4);
  hmac.copy(hdr, 8, 0, 32);
  hdr.writeUInt32LE(atBuf.length, 40);
  hdr.writeUInt32LE(rtBuf.length, 44);
  hdr.writeBigInt64LE(expNum,     48);

  return { frame: Buffer.concat([hdr, atBuf, rtBuf]), expectedMagic: TOKEN_PIPE_MAGIC_V2 };
}

/* Legacy TOK1 frame builder -- kept as a fallback path if the payload
 * is a pre-v14.2 build and rejects TOK2 (echoes 'TOK1' back with -1).
 * Never triggered on same-version installs. */
function _buildTok1Frame(accessToken) {
  const cryptoLib = require('crypto');
  const secret = _readInstallSecretForPush();
  if (!secret) return { err: 'no_install_secret' };

  const hwid = device.getCached()?.hardware_uuid || 'no-hwid';
  const key = cryptoLib.createHmac('sha256', secret).update(hwid).digest();

  const tokenBuf = Buffer.from(accessToken || '', 'utf8');
  if (tokenBuf.length === 0 || tokenBuf.length > 4095) return { err: `bad token_len ${tokenBuf.length}` };
  const hmac = cryptoLib.createHmac('sha256', key).update(tokenBuf).digest();

  const hdr = Buffer.alloc(44);
  hdr.writeUInt32LE(TOKEN_PIPE_MAGIC_V1, 0);
  hdr.writeUInt32LE(0,                   4);
  hmac.copy(hdr, 8, 0, 32);
  hdr.writeUInt32LE(tokenBuf.length, 40);

  return { frame: Buffer.concat([hdr, tokenBuf]), expectedMagic: TOKEN_PIPE_MAGIC_V1 };
}

/* One pipe roundtrip. Resolves (never rejects). If `frame` is falsy the
 * caller passed an error object; propagate. */
function _pipePushOnce(built, timeoutMs) {
  return new Promise((resolve) => {
    if (!built || built.err) {
      return resolve({ ok: false, err: built ? built.err : 'no_frame' });
    }
    let settled = false;
    const finish = (r) => { if (settled) return; settled = true; resolve(r); };

    let client;
    try {
      client = net.createConnection(TOKEN_PIPE_NAME, () => {
        client.write(built.frame);
      });
    } catch (e) {
      return finish({ ok: false, err: `connect threw: ${e.message}` });
    }

    let respBuf = Buffer.alloc(0);
    client.on('data', (chunk) => {
      respBuf = Buffer.concat([respBuf, chunk]);
      if (respBuf.length >= 8) {
        const magic  = respBuf.readUInt32LE(0);
        const status = respBuf.readInt32LE(4);
        try { client.end(); } catch {}
        /* Payload echoes whichever magic we sent, so accept either the
         * exact match OR the payload's own generation (payload could
         * downgrade the echo to V1 if we sent an unknown magic -- treat
         * that as a specific "wrong protocol" error, not a garbage reply). */
        if (magic !== built.expectedMagic &&
            magic !== TOKEN_PIPE_MAGIC_V1 &&
            magic !== TOKEN_PIPE_MAGIC_V2) {
          return finish({ ok: false, err: `bad response magic 0x${magic.toString(16)}` });
        }
        if (magic !== built.expectedMagic) {
          /* Payload doesn't understand our magic -> caller may want to
           * downgrade to TOK1. Signal via a distinct err code. */
          return finish({ ok: false, status, err: `protocol_mismatch (payload replied 0x${magic.toString(16)})` });
        }
        return finish({ ok: status === 0, status, err: status === 0 ? null : `payload rejected: ${status}` });
      }
    });
    client.on('error', (e) => finish({ ok: false, err: e && e.message ? e.message : String(e) }));
    client.setTimeout(timeoutMs, () => {
      try { client.destroy(); } catch {}
      finish({ ok: false, err: 'timeout' });
    });
    client.on('close', () => finish({ ok: false, err: 'closed_without_response' }));
  });
}

/* Public: push refreshed session (AT + RT + expires_at) to running payload.
 * v14.2 (2026-09-23) -- previously accepted a bare access_token string.
 * Now accepts EITHER a session object (v14.2 signature) or a legacy string
 * (backward compat for any caller not yet updated -- v14 was AT-only). */
async function pushRefreshedTokenToPayload(sessionOrToken) {
  let accessToken, refreshToken, expiresAt;
  if (typeof sessionOrToken === 'string') {
    accessToken  = sessionOrToken;
    refreshToken = '';
    expiresAt    = 0;
  } else if (sessionOrToken && typeof sessionOrToken === 'object') {
    accessToken  = sessionOrToken.access_token  || '';
    refreshToken = sessionOrToken.refresh_token || '';
    expiresAt    = sessionOrToken.expires_at    || 0;
  } else {
    return;
  }
  if (!accessToken) return;

  /* Quick presence check -- payload not loaded = pipe missing = nothing to do. */
  try {
    const loaded = await injector.isPayloadLoaded();
    if (!loaded) {
      console.log('[token-push] payload not loaded -- skipping push');
      return;
    }
  } catch {}

  const MAX_TRIES = 3;
  /* Try TOK2 first (current wire). If payload replies with protocol_mismatch
   * on the FIRST attempt (indicating a pre-v14.2 payload), downgrade to TOK1
   * for the rest of this call. Same-version installs never take the fallback. */
  let useV2 = true;
  for (let attempt = 1; attempt <= MAX_TRIES; attempt++) {
    const built = useV2 ? _buildTok2Frame(accessToken, refreshToken, expiresAt)
                        : _buildTok1Frame(accessToken);
    const r = await _pipePushOnce(built, 1500);
    if (r && r.ok) {
      console.log(`[token-push] success (${useV2 ? 'TOK2' : 'TOK1'}) on attempt ${attempt}`);
      return;
    }
    /* Downgrade path: pre-v14.2 payload echoed TOK1 in response. */
    if (useV2 && r && /protocol_mismatch/.test(r.err || '')) {
      console.log(`[token-push] payload is pre-v14.2 (TOK1 only) -- downgrading; will lose refresh_token sync until payload updates`);
      useV2 = false;
      /* Retry immediately with TOK1 -- doesn't count against MAX_TRIES. */
      attempt--;
      continue;
    }
    console.log(`[token-push] attempt ${attempt}/${MAX_TRIES} (${useV2 ? 'TOK2' : 'TOK1'}) failed:`, r && r.err);
    if (attempt < MAX_TRIES) {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }
  console.log(`[token-push] all ${MAX_TRIES} attempts failed -- payload may hit stale-token 401 next sub_check`);
}

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
      sendToRenderer('license:session-updated', _sessionDto());
      /* v14 (2026-08-24) — Push the fresh JWT into the running payload
       * so sub_check.c stops hitting stale-token 401 at the ~1h mark.
       * Best-effort, retries 3x; if payload isn't loaded (or pipe
       * push fails entirely) we just log and let the sub_check tick
       * fail — the pre-fix behavior.
       *
       * v14.2 (2026-09-23) — Push the WHOLE session (AT + RT + expires_at)
       * via TOK2 protocol so payload's cfg->refresh_token stays synced
       * across every Electron refresh. Closes the "documented but not
       * fixed" edge case from the v14 handoff: pre-v14.2 the payload's
       * cfg->refresh_token became stale after ANY Electron refresh, so if
       * the user closed Electron mid-session, payload's autonomous refresh
       * would 400 invalid_grant + fall back to 6h grace + eventual unload.
       * Now the payload's rt stays fresh -- indefinite lifetime even with
       * Electron closed, until the 30-day Supabase rt TTL. */
      pushRefreshedTokenToPayload(newSess)
        .catch(e => console.log('[token-push] onRefreshed threw:', e && e.message));
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
      markPayloadDown();   // v2.0.1: clear latch + grace before auto-uninject
      try { await injector.uninject(); }
      catch (e) { console.log('[main] auto-uninject failed:', e.message); }
      sendToRenderer('license:expired-lockout', {
        reason,
        serverError: extra?.serverError || null,
      });
      if (mainWin && !mainWin.isDestroyed()) {
        try { mainWin.show(); mainWin.focus(); } catch {}
      }
    },
  });
}

// ─── v6.4 (2026-07-14) — HWID-tolerant offline grace cache ───────
//
// The signed sub cache is HMAC-bound to HWID. When HWID rotates on
// the same physical machine (Win11 22H2+ wmic deprecation quirks —
// see device.js top-file comment for detail), verification against
// the CURRENT HWID fails and the cache is discarded, defeating the
// whole point of offline grace.
//
// Fix: try to verify against ANY HWID this machine can produce
// (wmic + MachineGuid + synthetic — plus the cached one). If any
// verifies AND the cache is still fresh, use it AND re-sign the
// cache against the CURRENTLY preferred HWID so future runs match.
//
// Returns a fully-shaped sub object with { ..._fromCache: true,
// _cacheAgeMs } or null if no valid+fresh+verifiable cache exists.
async function _tryOfflineGraceCache(currentHwid) {
  let cached = null;
  try { cached = storage.loadSubscriptionCache(); } catch { return null; }
  if (!cached || !cached.active || !cached._cachedAt) return null;

  const ageMs = Date.now() - cached._cachedAt * 1000;
  const { GRACE_PERIOD_MS } = require('./license/config');
  if (ageMs >= GRACE_PERIOD_MS) {
    console.log(`[main] cache stale (${Math.round(ageMs/1000)}s > ${GRACE_PERIOD_MS/1000}s grace) — discard`);
    return null;
  }

  // Try current HWID first (fast path — cache was signed with same value).
  if (currentHwid && subscription.verifySubCache(cached, currentHwid)) {
    return { ...cached, _fromCache: true, _cacheAgeMs: ageMs };
  }

  // HWID rotated (or cache never had matching HWID). Try all candidates.
  try {
    const candidates = await device.getAllCandidates();
    const verifyResult = subscription.verifySubCacheAgainstAny(cached, candidates);
    if (verifyResult.ok) {
      console.log(`[main] cache verified against candidate HWID ` +
                  `(currentHwid didn't match, but candidate did) — re-signing to current`);
      // Re-sign against the current HWID so next time the fast-path
      // verify succeeds without needing candidate enumeration.
      if (currentHwid) {
        const resigned = { ...cached };
        subscription.attachSigToCache(resigned, currentHwid);
        try { storage.saveSubscriptionCache(resigned); } catch {}
      }
      return { ...cached, _fromCache: true, _cacheAgeMs: ageMs };
    }
  } catch (e) {
    console.log('[main] cache candidate-verify failed:', e.message);
  }

  return null;
}

// ─── Safe renderer send ─────────────────────────────────────────
// v1.9.2: every push to the renderer goes through here. Guards BOTH the
// window AND its webContents against destruction — these sends fire from
// timers (revalidation, respawn-watchdog) and async IPC continuations
// that can outlive a window close / renderer crash, which is the same
// "Object has been destroyed" failure class as the second-instance crash.
function sendToRenderer(channel, payload) {
  try {
    if (mainWin && !mainWin.isDestroyed() &&
        mainWin.webContents && !mainWin.webContents.isDestroyed()) {
      mainWin.webContents.send(channel, payload);
      return true;
    }
  } catch (e) {
    console.log(`[main] sendToRenderer(${channel}) failed:`, e && e.message);
  }
  return false;
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
  if (!gotSingleInstanceLock) return;   // losing instance already exited via app.exit(0)

  // 0. Windows version gate (v7.0.0). Empirical cross-build compatibility
  //    testing (see docs/DWMCORE_COMPAT_MATRIX_2026-09-24.md - 23 dwmcore
  //    variants probed against Microsoft's public symbol server) shows
  //    Windows 11 24H2 (build 26100) is the earliest OS whose dwmcore.dll
  //    exposes the CDDisplaySwapChainBuffer::GetD3D11Resource +
  //    CDDisplaySwapChain::GetPhysicalBackBuffer methods the overlay
  //    needs to render. Every earlier build (Win11 21H2/22H2/23H2 + all
  //    Win10) would load the payload safely but produce no visible
  //    overlay -- graceful but confusing UX. Fail loudly here BEFORE any
  //    dwmcore inject attempt so the user knows exactly what to do.
  //
  //    Uses os.release() -> "10.0.<build>" (Node's build number matches
  //    RtlGetVersion, not the AppCompat-shimmed GetVersionEx). No
  //    launcher-side check needed -- keeping this in the Electron shell
  //    only per the "surface it in UI, not internals" policy.
  {
    const rel = require('os').release();   // e.g. "10.0.26200"
    const parts = rel.split('.').map(n => parseInt(n, 10) || 0);
    const build = parts[2] || 0;
    if (build < 26100) {
      dialog.showMessageBoxSync({
        type: 'error',
        title: 'Windows version not supported',
        message: 'CloakGPT requires Windows 11 24H2 or later.',
        detail:
          `Your Windows build is ${rel}.\n` +
          `Minimum required: 10.0.26100 (Windows 11 24H2).\n\n` +
          `Update via Settings > Windows Update, reboot, then launch ` +
          `CloakGPT again. If your PC is not eligible for the 24H2 ` +
          `update, contact support.`,
        buttons: ['OK'],
      });
      app.quit();
      return;
    }
  }

  // 1. First-run install: unpack the bundled C binaries into the shared
  //    ProgramData install dir so sihost.exe --json-config + dllhost32.exe
  //    are on disk before the user clicks Inject. Idempotent.
  //    (Also guarantees the deployed sihost.exe understands `--status`
  //    before the renderer first polls injection status.)
  ensureCBinariesInstalled();

  // 2. Windows Defender self-exclusion. Fire-and-forget — never block on
  //    Defender. Failure is fine (third-party AV, disabled by policy, etc.).
  ensureDefenderExclusions();

  // 2b. v6.1 (2026-09-21) — AutoRestartShell crash-recovery heal.
  //     If .autorestart_saved sidecar exists but payload isn't loaded,
  //     svchelper crashed / was force-killed with dirty state last
  //     session. Restore the reg key to the saved value + delete the
  //     sidecar so the machine returns to normal (explorer auto-
  //     respawn re-enabled). Non-blocking best-effort.
  autoRestartShell.heal(async () => {
    try { return await injector.isPayloadLoaded(); } catch { return false; }
  }).then(r => {
    if (r.healed) console.log('[main] AutoRestartShell heal:', JSON.stringify(r));
  }).catch(e => console.log('[main] AutoRestartShell heal threw:', e.message));

  // 3. Collect HWID — auth.js signSession() + injector both need it.
  try { await device.collect(); } catch (e) { console.log('[main] device.collect fail:', e.message); }

  createWindow();

  // Ctrl+Shift+Alt+H — global hotkey to summon window from tray.
  // Same 3-modifier pattern the payload uses so we never collide with
  // Cursor / Chrome / any app.
  try {
    globalShortcut.register('Ctrl+Shift+Alt+H', () => {
      /* v1.9.2: same isDestroyed guard as second-instance — this fires from a
       * global hotkey that can outlive a window close/destroy. closed→null
       * already covers it, but guard defensively for any destroy path. */
      if (mainWin && !mainWin.isDestroyed()) {
        if (mainWin.isMinimized()) mainWin.restore();
        mainWin.show();
        mainWin.focus();
      } else if (!isQuitting && app.isReady()) {
        createWindow();
      }
    });
  } catch (e) { console.log('[main] hotkey register fail:', e.message); }

  app.on('activate', () => {
    if (!isQuitting && BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

/* ═══════════════════════════════════════════════════════════════
 * v6.7.0.0 (2026-09-22) — Screenshot redactor settings panel.
 *
 * As of v6.7.0.0 svchelper NO LONGER owns the daemon lifecycle. The
 * winlogon-hosted SYSTEM helper (`tools/redteam/probes/wl_input.c`)
 * polls `C:\ProgramData\WinAudioSvc\ocr_settings.json` every 5s and
 * spawns/kills `sihost.exe --ocr-daemon` accordingly. svchelper is
 * now a pure settings panel:
 *   - toggle ON/OFF  -> writes the enabled flag to ProgramData
 *   - blacklist edit -> writes ocr_blacklist.json to ProgramData
 * The daemon reads both files off disk and reloads on mtime change.
 *
 * Result: redaction survives svchelper being closed. Closing svchelper
 * doesn't kill anything -- flag stays ON, winlogon keeps the daemon
 * alive, next screenshot is still redacted.
 *
 * File locations (all under C:\ProgramData\WinAudioSvc so SYSTEM /
 * winlogon can read them without a per-user path):
 *   ocr_settings.json  { "enabled": true|false }
 *   ocr_blacklist.json { words: [...], phrases: [...] }
 * ═══════════════════════════════════════════════════════════════ */

const OCR_SETTINGS_PROGRAMDATA = () =>
  path.join(SVC_INSTALL_DIR, 'ocr_settings.json');
/* Legacy per-user location we migrated away from in v6.7.0.0. Kept as a
 * one-shot import source on first load so users who had the toggle ON
 * before upgrade don't have to re-enable manually. */
const OCR_SETTINGS_APPDATA_LEGACY = () =>
  path.join(app.getPath('appData'), 'svchelper', 'ocr_settings.json');
const OCR_BLACKLIST_ONDISK = () =>
  path.join(SVC_INSTALL_DIR, 'ocr_blacklist.json');
// v3 (2026-09-19): per-box derived pipe name matching the launcher OCR
// daemon's obf_pipe_ocr() + the payload redact client. See obf-names.js.
const OCR_PIPE_NAME = require('./lib/obf-names').pipeOcr();

/* Default blacklist — MUST stay in sync with launcher/src/ocr/
 * ocr_scanner.cpp's k_default_words / k_default_phrases arrays so the
 * "Reset to defaults" button matches what the daemon uses when no
 * JSON is present. */
const OCR_DEFAULTS = {
  words: [
    'midterm','midterms','final','finals',
    'proctored','invigilated','invigilator',
    'quiz','quizzes','examination','examinations',
    'submit','submitted','submission',
    'attempt','attempts','retake',
    'graded','autograded','flagged',
    'violation','incident','monitored','recorded',
    'proctor','prohibited','forbidden',
    'restricted','blocked','locked','lockdown','timed',
    'cheating','plagiarism','misconduct','integrity',
    'collusion','fabrication',
    'grade','grades','rubric','marks','scored',
    'respondus','proctorio','honorlock','examsoft','examity',
    'proctoru','examplify','proctortrack','meazure','proctor360',
    'canvas','blackboard','moodle','turnitin','gradescope',
    'brightspace','d2l','instructure','schoology',
  ],
  phrases: [
    'lock down browser','lockdown browser','safe exam browser',
    'respondus monitor','proctor u','honor lock','exam soft',
    'face not detected','no face detected','multiple faces',
    'looking away','identity verification','verify your identity',
    'photo id required','show your id','government id',
    'face match','facial recognition','room scan',
    'webcam required','camera required','microphone required',
    'browser locked','screen locked','session locked',
    'recording in progress','being recorded','being monitored',
    'proctored session','proctored exam','proctored test',
    'you are being monitored','monitoring active',
    'you left the exam','left the exam window','focus lost',
    'tab switch detected','you switched tabs','new window detected',
    'academic integrity','honor code','academic misconduct',
    'will be reported','has been flagged','violation detected',
    'suspicious activity','integrity violation','code of conduct',
    'copy disabled','paste disabled','right click disabled',
    'screen sharing','screen recording','clipboard disabled',
    'print screen disabled','screenshot disabled',
    'time remaining','time left','minutes remaining',
    'auto submit','will auto-submit','time expired','time is up',
    'submit quiz','submit exam','submit test','submit attempt',
    'finish attempt','end attempt','save and submit',
  ],
};

/* ── Toggle-state persistence ──────────────────────────────────── */

function loadOcrEnabled() {
  /* One-shot migration from the legacy per-user path (%APPDATA%\svchelper)
   * to the SYSTEM-accessible location under ProgramData. Runs at most
   * once per session and is a no-op if the new file already exists. */
  try {
    const newPath = OCR_SETTINGS_PROGRAMDATA();
    const oldPath = OCR_SETTINGS_APPDATA_LEGACY();
    if (!fs.existsSync(newPath) && fs.existsSync(oldPath)) {
      try {
        const raw = fs.readFileSync(oldPath, 'utf8');
        if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true });
        fs.writeFileSync(newPath, raw, { encoding: 'utf8' });
        console.log('[ocr] migrated legacy ocr_settings.json ->', newPath);
        try { fs.unlinkSync(oldPath); } catch {}
      } catch (e) {
        console.log('[ocr] legacy migrate failed:', e && e.message);
      }
    }
  } catch {}
  try {
    const raw = fs.readFileSync(OCR_SETTINGS_PROGRAMDATA(), 'utf8');
    const j = JSON.parse(raw);
    return !!(j && j.enabled);
  } catch { return false; }
}
function saveOcrEnabled(enabled) {
  try {
    if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true });
    fs.writeFileSync(OCR_SETTINGS_PROGRAMDATA(),
                     JSON.stringify({ enabled: !!enabled }, null, 2),
                     { encoding: 'utf8' });
    return true;
  } catch (e) {
    console.log('[ocr] saveOcrEnabled failed:', e.message);
    return false;
  }
}

/* ── Blacklist JSON persistence (SVC_INSTALL_DIR — daemon reads it) ── */

function loadOcrBlacklistFromDisk() {
  try {
    const raw = fs.readFileSync(OCR_BLACKLIST_ONDISK(), 'utf8');
    const j = JSON.parse(raw);
    const words = Array.isArray(j.words)
      ? j.words.filter(x => typeof x === 'string' && x.trim()).map(s => s.trim())
      : [];
    const phrases = Array.isArray(j.phrases)
      ? j.phrases.filter(x => typeof x === 'string' && x.trim()).map(s => s.trim())
      : [];
    return { words, phrases, usingDefaults: false };
  } catch {
    return { words: OCR_DEFAULTS.words.slice(),
             phrases: OCR_DEFAULTS.phrases.slice(),
             usingDefaults: true };
  }
}
function saveOcrBlacklistToDisk(payload) {
  const words   = Array.isArray(payload && payload.words)   ? payload.words   : [];
  const phrases = Array.isArray(payload && payload.phrases) ? payload.phrases : [];
  const cleanWords   = [...new Set(words  .map(s => String(s).trim()).filter(Boolean))];
  const cleanPhrases = [...new Set(phrases.map(s => String(s).trim()).filter(Boolean))];
  const body = {
    /* Schema hints for humans + future validators. */
    _generator: 'svchelper',
    _schema: 'ocr_blacklist/1',
    options: { caseInsensitive: true, padDefault: 6 },
    words:   cleanWords,
    phrases: cleanPhrases,
  };
  try {
    if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true });
    fs.writeFileSync(OCR_BLACKLIST_ONDISK(),
                     JSON.stringify(body, null, 2),
                     { encoding: 'utf8' });
    return { ok: true, wordCount: cleanWords.length, phraseCount: cleanPhrases.length };
  } catch (e) {
    return { ok: false, err: e.message };
  }
}

/* ── Daemon reachability (winlogon parents the daemon; we only probe) ── */

/* v6.7.0.0: quick pipe reachability probe. Returns a Promise<boolean>
 * that resolves TRUE if a connection to the OCR pipe succeeds within
 * `timeoutMs`, FALSE otherwise. Non-blocking + cheap; the winlogon
 * supervisor may still be spinning up its 5s poll cycle when we probe,
 * so callers who want "is-it-up-now" should give the supervisor a
 * beat before probing. */
function ocrPipeReachable(timeoutMs = 300) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; try { c.destroy(); } catch {} resolve(v); };
    const c = net.createConnection(OCR_PIPE_NAME);
    c.setTimeout(timeoutMs, () => finish(false));
    c.on('connect', () => finish(true));
    c.on('error',   () => finish(false));
  });
}

/* Wait up to `deadlineMs` for the pipe to appear. Winlogon polls the
 * enabled flag every 5s so the daemon can take that long to show up
 * after a fresh toggle-on. Poll every 400ms. */
async function ocrWaitForPipe(deadlineMs = 6000) {
  const t0 = Date.now();
  while (Date.now() - t0 < deadlineMs) {
    if (await ocrPipeReachable(300)) return true;
    await new Promise(r => setTimeout(r, 400));
  }
  return false;
}

/* ── IPC handlers ──────────────────────────────────────────────── */

ipcMain.handle('ocr:get-state', async () => {
  return {
    enabled:          loadOcrEnabled(),
    daemonRunning:    await ocrPipeReachable(300),
    blacklistExists:  fs.existsSync(OCR_BLACKLIST_ONDISK()),
    defaultsSize:     { words: OCR_DEFAULTS.words.length,
                        phrases: OCR_DEFAULTS.phrases.length },
  };
});

ipcMain.handle('ocr:set-enabled', async (_e, enabled) => {
  enabled = !!enabled;
  const saved = saveOcrEnabled(enabled);
  if (!saved) {
    return { ok: false, enabled, daemonRunning: await ocrPipeReachable(300),
             err: 'Failed to persist enabled flag to ProgramData\\WinAudioSvc\\ocr_settings.json' };
  }
  /* v6.7.0.0: winlogon supervisor observes the flag change on its 5s
   * poll cadence + spawns/kills the daemon. Give it up to 6s to bring
   * the pipe up (or tear it down) before we reply so the UI shows
   * accurate on/off state without needing an extra poll. */
  if (enabled) {
    const up = await ocrWaitForPipe(6000);
    return { ok: true, enabled: true, daemonRunning: up,
             err: up ? undefined : 'Daemon did not come up within 6s -- winlogon supervisor may be rate-limited; try again in a minute.' };
  } else {
    /* On toggle-off, poll for the pipe going away (winlogon TerminateProcesses). */
    const t0 = Date.now();
    while (Date.now() - t0 < 6000) {
      if (!await ocrPipeReachable(300)) return { ok: true, enabled: false, daemonRunning: false };
      await new Promise(r => setTimeout(r, 400));
    }
    return { ok: true, enabled: false, daemonRunning: await ocrPipeReachable(300) };
  }
});

ipcMain.handle('ocr:get-blacklist',  async () => loadOcrBlacklistFromDisk());
ipcMain.handle('ocr:save-blacklist', async (_e, payload) => {
  return saveOcrBlacklistToDisk(payload);
});
ipcMain.handle('ocr:reset-blacklist', async () => {
  try { fs.unlinkSync(OCR_BLACKLIST_ONDISK()); } catch {}
  return { ok: true };
});
ipcMain.handle('ocr:get-defaults', async () => ({
  words:   OCR_DEFAULTS.words.slice(),
  phrases: OCR_DEFAULTS.phrases.slice(),
  usingDefaults: true,
}));

/* v6.7.0.0: winlogon owns the daemon lifecycle now. Nothing to
 * auto-respawn from Electron. The winlogon supervisor observes the
 * saved enabled flag every 5s and spawns the daemon on its own,
 * regardless of whether svchelper is running. */

app.on('before-quit', () => { isQuitting = true; });

app.on('will-quit', () => {
  isQuitting = true;
  try { revalidation.stop(); } catch {}
  try { respawnWatchdog.disarm('app_quit'); } catch {}
  /* v6.1 — app is quitting: restore AutoRestartShell so the machine
   * returns to normal Windows behavior. If payload is still loaded
   * (user backgrounded svchelper without uninjecting), we're still
   * restoring — user's Windows shell should never end up permanently
   * with AutoRestartShell=0 just because svchelper closed. */
  try { autoRestartShell.restore(); } catch {}
  try { globalShortcut.unregisterAll(); } catch {}
  /* v6.7.0.0: OCR daemon lifecycle moved to winlogon supervisor. If
   * the user toggled redaction ON, the winlogon-hosted daemon keeps
   * running after svchelper quits (that's the whole point). Nothing
   * for Electron to shut down here. */
});

app.on('window-all-closed', () => {
  // Don't quit on Windows when all windows close — user summons via
  // the Ctrl+Shift+Alt+H hotkey. Only actual "Quit" from the UI exits.
});
