// ═══════════════════════════════════════════════════════════════
// renderer.js — CloakGPT UI state machine.
//
// Screens (only one .active at a time):
//   splash    → HWID + session + subscription load
//   login     → Sign in with Google
//   nosub     → Authenticated but no active subscription
//   dashboard → Inject / Uninject + settings + hotkeys
//
// All secrets (session, api key) flow through window.svc.* IPC
// (defined in preload.js). No direct fs / process access here.
// ═══════════════════════════════════════════════════════════════

'use strict';

/* v18 (2026-09-23) -- Renderer console gag in production.
 *
 * Every real log line in the C stack is AES-256-GCM per line. The renderer
 * side, however, is peppered with plain console.log calls. In a packaged
 * build these normally have no reader (devTools disabled), but if a user
 * launches with --enable-logging or attaches a debugger they get plaintext
 * internals. That leaks jargon the visible UI already scrubbed. Belt +
 * braces: turn console.log / info / warn / debug into no-ops when running
 * packaged.
 *
 * v18.1 (2026-09-23) -- HARDENED. The only path to enable logging is
 * running from the source tree (`electron .`) where app.isPackaged is
 * false. There is NO env var, NO CLI flag, and NO NODE_ENV override that
 * can flip logging back on from a shipped binary -- the signal (via
 * preload's __debugOn -> --svcldb-packaged=0 argv from main.js) is
 * computed from app.isPackaged, a compile-time bit that cannot be forged
 * without modifying the executable. console.error stays live for genuine
 * crash reporting. */
(function _gagConsoleInProd() {
  try {
    const debugOn = !!(window.svc && window.svc.__debugOn);
    if (debugOn) return;
    const _noop = () => {};
    console.log   = _noop;
    console.info  = _noop;
    console.warn  = _noop;
    console.debug = _noop;
    // console.error left intact.
  } catch (_) { /* preload not ready is fine -- means dev harness */ }
})();

/* v17 (2026-09-22) -- Error boundary. "Blank blue screen" reports from a
 * handful of users historically had no diagnosis because the renderer just
 * died silently (usually a GPU driver glitch on the ambient backdrop-filter,
 * or an early await throwing before the first showScreen('splash') painted).
 *
 * These handlers convert any uncaught error / unhandled rejection / long boot
 * stall into the visible #safety-fallback screen with Retry, Safe-mode, and
 * Export-diagnostics buttons. Users always see something actionable. */
(function installSafetyNet() {
  const errors = [];
  const rec = (label, e) => {
    const at = new Date().toISOString();
    const msg = e && (e.stack || e.message) ? (e.stack || e.message) : String(e);
    errors.push(at + '  ' + label + '  ' + msg);
    try { console.error('[safety]', label, e); } catch {}
    // Any error inside the first ~15s of boot -> show fallback immediately.
    if (!document.body || !document.body.classList.contains('booted-ok')) {
      showSafetyFallback(errors.join('\n\n'));
    }
  };
  window.addEventListener('error', (ev) => rec('window.error', ev.error || ev.message));
  window.addEventListener('unhandledrejection', (ev) => rec('unhandledrejection', ev.reason));

  /* Boot-timeout watchdog. If 15s after DOM-ready NO screen is `.active`
   * AND we haven't marked boot as OK, assume the renderer stalled and
   * reveal the fallback. */
  const startWatchdog = () => setTimeout(() => {
    const anyActive = document.querySelector('.screen.active');
    if (!document.body.classList.contains('booted-ok') && !anyActive) {
      rec('boot-timeout', new Error('No screen became active within 15s of DOM-ready.'));
    }
  }, 15000);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startWatchdog, { once: true });
  } else {
    startWatchdog();
  }

  // Wire the fallback screen's action buttons once the DOM has parsed them.
  const wireFallback = () => {
    const $ = (id) => document.getElementById(id);
    const retry = $('safety-retry');
    const safe  = $('safety-safe-mode');
    const exp   = $('safety-export');
    if (retry && !retry.dataset.wired) {
      retry.dataset.wired = '1';
      retry.addEventListener('click', () => {
        try { window.svc && window.svc.safety && window.svc.safety.reload && window.svc.safety.reload(); }
        catch { location.reload(); }
      });
    }
    if (safe && !safe.dataset.wired) {
      safe.dataset.wired = '1';
      safe.addEventListener('click', () => {
        try { window.svc && window.svc.safety && window.svc.safety.safeModeRestart && window.svc.safety.safeModeRestart(); }
        catch (e) { alert('Safe-mode restart unavailable: ' + (e && e.message || e)); }
      });
    }
    if (exp && !exp.dataset.wired) {
      exp.dataset.wired = '1';
      exp.addEventListener('click', async () => {
        try {
          const r = window.svc && window.svc.safety && window.svc.safety.exportDiagnostics
            ? await window.svc.safety.exportDiagnostics({ errors })
            : null;
          alert(r && r.ok ? 'Diagnostics exported to:\n\n' + r.path
                          : 'Export failed: ' + ((r && r.err) || 'IPC unavailable'));
        } catch (e) { alert('Export failed: ' + (e && e.message || e)); }
      });
    }
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wireFallback, { once: true });
  } else {
    wireFallback();
  }
})();

function showSafetyFallback(details) {
  try {
    const fb = document.getElementById('safety-fallback');
    if (!fb) return;
    /* Hide any half-rendered screen so the fallback owns the viewport. */
    for (const s of document.querySelectorAll('.screen.active')) s.classList.remove('active');
    fb.style.display = 'flex';
    const d = document.getElementById('safety-detail');
    if (d) d.textContent = String(details || '(no detail)');
  } catch { /* worst case, nothing more we can do */ }
}

// ─── Screen management ──────────────────────────────────────────
const SCREENS = ['splash', 'login', 'nosub', 'dashboard', 'suspended', 'devicelimit'];
function showScreen(name) {
  // v3: stop the dashboard status poll (a 3.5s child-spawn loop) whenever we
  // navigate away, so it never leaks across sign-out / lockout screens
  // (Electron CPU/battery audit, item 7). Dashboard re-entry re-arms it via
  // pollStatusLoop(). clearInterval(null/undefined) is a safe no-op.
  if (name !== 'dashboard') { try { clearInterval(_pollTimer); } catch (_) {} }
  for (const s of SCREENS) {
    const el = document.getElementById(`screen-${s}`);
    if (el) el.classList.toggle('active', s === name);
  }
  /* v17 -- signal the safety-net watchdog that we successfully routed. */
  try { document.body.classList.add('booted-ok'); } catch {}
}

// ─── Toast + loading ────────────────────────────────────────────
let _toastTimer = null;
function toast(msg, kind = 'ok') {
  const el = document.getElementById('toast');
  if (!el) return;
  const iconOk =
    `<svg class="icon ok" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
  const iconErr =
    `<svg class="icon err" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
  el.className = ''; // reset
  el.classList.add(kind === 'ok' ? 'ok' : 'err');
  el.innerHTML = (kind === 'ok' ? iconOk : iconErr) + `<span>${escapeHtml(msg)}</span>`;
  requestAnimationFrame(() => el.classList.add('show'));
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { el.classList.remove('show'); }, 4200);
}

function showLoading(msg, sub) {
  const box = document.getElementById('loading');
  document.getElementById('loading-msg').textContent = msg || 'Working…';
  document.getElementById('loading-sub').textContent = sub || '';
  box.classList.add('show');
}
function hideLoading() {
  document.getElementById('loading').classList.remove('show');
}

function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function shortenHwid(h) {
  if (!h) return 'unknown';
  return `${h.slice(0, 8)}••••${h.slice(-4)}`;
}

// ─── Title bar wiring ──────────────────────────────────────────
document.getElementById('tb-min').addEventListener('click',  () => window.svc.window.minimize());
document.getElementById('tb-hide').addEventListener('click', () => window.svc.window.close());
document.getElementById('tb-quit').addEventListener('click', () => {
  if (confirm('Quit CloakGPT? The injected overlay will keep running until you sign out or emergency-stop.')) {
    window.svc.window.quit();
  }
});

// ─── v1.2: dynamic app-version rendering ───────────────────────────
// Pulled from package.json via app.getVersion() at boot so the login
// card + titlebar always show the shipped build number. Falls back to
// the hard-coded literal in index.html if IPC is unavailable (e.g.
// preload broken during dev iteration).
(async () => {
  try {
    const v = await window.svc.app.getVersion();
    if (!v) return;
    /* v6.7.0.0 (2026-09-22): user-visible convention is 4-part (Windows
     * file-version style). package.json holds 3-part (npm/semver limit
     * enforced by electron-builder 25), so we append a ".0" fourth
     * segment for the UI when the raw version is 3 dotted numbers. */
    const parts = String(v).split('.');
    const display = (parts.length === 3 && parts.every(p => /^\d+$/.test(p)))
      ? v + '.0' : v;
    const short = 'v' + display;                                    // full version, e.g. "v6.7.0.0"
    const long  = 'CloakGPT v' + display;                             // "CloakGPT v6.7.0.0"
    const tb    = document.getElementById('titlebar-ver');
    if (tb)  tb.textContent = short;
    const lv   = document.getElementById('login-app-ver');
    if (lv)  lv.textContent = long;
  } catch { /* preload not ready during dev — index.html defaults suffice */ }
})();

// ─── Global state ───────────────────────────────────────────────
let state = {
  session: null,
  subscription: null,
  hwid: null,
  injected: false,
  payloadUnverified: false, // v1.9.1: probe returned 'unknown' with no latched state yet
  chosen_provider: null,   // 0 (auto) or 1..4
  chosen_tier: 1,          // 0..3
};

// ─── Splash → figure out where to go ────────────────────────────
async function boot() {
  showScreen('splash');
  const st = document.getElementById('splash-status');

  /* v5.0.1 (2026-09-21) BUG FIX: load persisted UI-prefs BEFORE any
   * dashboard paint so chip-active class reflects saved tier/provider.
   * Previously state.chosen_tier / state.chosen_provider were
   * in-memory only + reset to hardcoded defaults on every boot; users
   * reported "clicked STRONG, closed app, didn't save." Fire-and-
   * forget best-effort -- on load failure we use the hardcoded state
   * defaults (tier=1 MEDIUM, provider=null auto), same as pre-fix
   * behavior so nothing regresses if IPC fails. */
  try {
    if (window.svc && window.svc.uiPrefs && window.svc.uiPrefs.load) {
      const p = await window.svc.uiPrefs.load();
      if (p && typeof p === 'object') {
        if (typeof p.tier === 'number') state.chosen_tier = p.tier;
        if (p.provider === null || typeof p.provider === 'number') state.chosen_provider = p.provider;
      }
    }
  } catch (e) { /* silent -- fall back to state defaults */ }

  st.textContent = 'Verifying hardware fingerprint…';
  const dto = await window.svc.license.load();
  if (dto && dto.hwid) state.hwid = dto.hwid;
  st.textContent = 'Checking session…';
  await new Promise(r => setTimeout(r, 200)); // beat frame for perceived polish

  // Security check failed — refuse to load. Show login with the reason.
  if (dto && dto.clearReason === 'security_failed') {
    _renderLoginDeviceId();
    showLoginError(dto.securityReason ||
      'CloakGPT will not start while a debugger or reverse-engineering tool is running. Close it and retry.',
      { blocking: true });
    showScreen('login');
    return;
  }

  // v6 (2026-07-06): MITM check failed — refuse to load. A traffic
  // inspection tool's root CA is installed OR HTTPS_PROXY is set.
  // Show login with the specific reason so the user knows exactly
  // what to remove.
  //
  // v6.2: pass { remediate: { kind, tool } } so showLoginError can
  // render an inline "Fix now" button that auto-remediates via
  // svc.mitm.remediate + re-checks. Zero shell-fiddling from the user.
  if (dto && dto.clearReason === 'mitm_detected') {
    _renderLoginDeviceId();
    showLoginError(dto.mitmDetails ||
      `CloakGPT refuses to run because a network traffic inspection tool ` +
      `(${dto.mitmTool || 'unknown'}) is present on this machine. Uninstall it and retry.`,
      {
        blocking:  true,
        remediate: { kind: dto.mitmKind, tool: dto.mitmTool },
      });
    showScreen('login');
    return;
  }

  if (!dto || !dto.session) {
    _renderLoginDeviceId();
    if (dto && dto.clearReason === 'session_expired') {
      showLoginError('Your session expired (24-hour policy). Please sign in again.');
    } else if (dto && dto.clearReason === 'tampered') {
      showLoginError('Session file was modified — signed out for safety. Please sign in again.');
    } else if (dto && dto.clearReason === 'token_rejected') {
      showLoginError('Your Google authentication token was rejected by the license server (likely expired beyond refresh). Please sign in again.');
    }
    showScreen('login');
    return;
  }
  state.session = dto.session;
  state.subscription = dto.subscription;

  // SUSPENDED → dedicated ban screen (not nosub).
  if (dto.subscription && dto.subscription.status === 'suspended') {
    _renderSuspended(dto.subscription);
    showScreen('suspended');
    return;
  }

  if (!dto.subscription || dto.subscription.active === false) {
    _renderNoSub();
    showScreen('nosub');
    return;
  }
  _renderDashboard();
  showScreen('dashboard');
  pollStatusLoop();

  // ONBOARDING GATE — only show if subscription is EXPLICITLY VERIFIED
  // active (not stale-cache, not "unknown", not lifetime-grant-only-if-
  // network-was-online). This prevents a user with a bad session or
  // offline-cache serving them a dashboard from also getting the tutorial
  // — the tutorial is a "welcome, you're now a paying customer" thing.
  //
  // Explicit gate:
  //   1. subscription is a real object
  //   2. active is literally boolean true (not null/undefined/"unknown")
  //   3. status ISN'T suspended (would already have routed away above)
  //   4. server-verified: didn't come from offline-grace cache
  //      (_fromCache flag added in main.js when we serve stale cache)
  const sub = dto.subscription;
  const verified = sub && sub.active === true && sub.status !== 'suspended'
                   && !sub._fromCache && !sub.error;
  if (!verified) return;
  const ob = await window.svc.onboarding.get().catch(() => ({ complete: true }));
  if (!ob.complete) showOnboarding();
}

// ─── Login ──────────────────────────────────────────────────────
function _renderLoginDeviceId() {
  const el = document.getElementById('login-device');
  if (el) el.textContent = shortenHwid(state.hwid);
}

// v6 (2026-07-06): `blocking` flag greys out the Sign-in button when
// the error is unrecoverable-without-user-action (security / MITM
// check found a debugger or a proxy CA). Recoverable errors like
// session_expired / tampered / token_rejected leave the button live
// because a fresh sign-in IS the fix.
//
// v6.2 (2026-07-06): if opts includes { remediate: { kind, tool } },
// we add a "Fix now" button that calls svc.mitm.remediate and then
// re-runs the boot check. Only offered for MITM kinds we know how to
// auto-fix.
const _REMEDIATE_LABEL = {
  tls_bypass:      () => 'Unset NODE_TLS_REJECT_UNAUTHORIZED for me',
  https_proxy_env: () => 'Remove the proxy env var for me',
  winhttp_proxy:   () => 'Reset WinHTTP proxy for me',
  mitm_ca:         (tool) => `Uninstall the ${tool || 'MITM'} certificate for me`,
};

function showLoginError(msg, opts) {
  const el = document.getElementById('login-error');
  if (!el) return;
  opts = opts || {};

  el.innerHTML = '';
  const msgEl = document.createElement('div');
  msgEl.className = 'login-error-msg';
  msgEl.textContent = msg;
  el.appendChild(msgEl);

  // v6.2: inline "Fix now" button for auto-remediable errors.
  if (opts.remediate && opts.remediate.kind &&
      _REMEDIATE_LABEL[opts.remediate.kind]) {
    const btn = document.createElement('button');
    btn.className = 'login-error-fix';
    btn.type = 'button';
    btn.textContent = '\u{1F527} ' +
      _REMEDIATE_LABEL[opts.remediate.kind](opts.remediate.tool);
    btn.addEventListener('click', () => _handleRemediateClick(btn, opts.remediate));
    el.appendChild(btn);

    /* v1.7.4.4 (2026-07-23) — manual RECHECK button.
     *
     * User feedback: "after removal it should either periodically
     * recheck or allow users to force recheck cause once i closed
     * exe and reopened it showed [the same MITM banner]".
     *
     * Fix: add "Recheck now" button next to "Fix now". Runs the
     * whole boot() again (which re-runs security.runChecks +
     * mitm.checkForMitm). If nothing bad is detected this time, the
     * banner clears + sign-in unlocks. Zero app-restart required. */
    const recheck = document.createElement('button');
    recheck.className = 'login-error-recheck';
    recheck.type = 'button';
    recheck.textContent = '\u21BB Retry check';
    recheck.addEventListener('click', () => _handleRecheckClick(recheck));
    el.appendChild(recheck);
  }

  el.classList.add('show');
  const blocking = !!opts.blocking;
  const btn  = document.getElementById('btn-signin');
  const link = document.getElementById('copy-auth-url');
  if (btn) {
    btn.disabled = blocking;
    btn.classList.toggle('is-blocked', blocking);
    btn.title = blocking
      ? 'Fix the issue in the banner above to unlock sign-in'
      : '';
  }
  if (link) {
    link.style.pointerEvents = blocking ? 'none' : '';
    link.style.opacity       = blocking ? '0.35' : '';
  }
}
function clearLoginError() {
  const el = document.getElementById('login-error');
  if (el) { el.classList.remove('show'); el.innerHTML = ''; }
  const btn  = document.getElementById('btn-signin');
  const link = document.getElementById('copy-auth-url');
  if (btn)  { btn.disabled = false; btn.classList.remove('is-blocked'); btn.title = ''; }
  if (link) { link.style.pointerEvents = ''; link.style.opacity = ''; }
}

async function _handleRemediateClick(btn, remediate) {
  const origLabel = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Fixing\u2026';
  try {
    const r = await window.svc.mitm.remediate({
      kind: remediate.kind,
      tool: remediate.tool,
    });
    /* v1.7.4.4: r.ok now correctly returns true when nothing needed
     * removal (mitm.js fixed to treat "already-clean" as success). We
     * show the message from the remediate result (positive framing)
     * and re-boot to re-check. */
    const positive = r && r.ok;
    toast((r && r.message) || (positive ? 'Fixed. Re-checking\u2026' : 'Nothing to fix — re-checking'), positive ? 'ok' : 'err');
    // Re-run the whole boot check - if the ONLY issue was the one
    // we just fixed, sign-in becomes available again.
    setTimeout(() => { boot().catch(e => console.log('[renderer] boot after fix:', e.message)); }, 400);
  } catch (e) {
    toast(`Fix failed: ${e.message || e}`, 'err');
    btn.disabled = false;
    btn.textContent = origLabel;
  }
}

/* v1.7.4.4 (2026-07-23) — manual RECHECK handler. */
async function _handleRecheckClick(btn) {
  const origLabel = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Checking\u2026';
  try {
    await boot();
    // If boot() completes without re-showing the login-error banner,
    // sign-in is unlocked. If banner reappears, boot() re-rendered it.
    // Either way, our button state was replaced by boot()'s render.
  } catch (e) {
    toast(`Recheck failed: ${e.message || e}`, 'err');
    btn.disabled = false;
    btn.textContent = origLabel;
  }
}

document.getElementById('btn-signin').addEventListener('click', async () => {
  clearLoginError();
  showLoading('Opening browser…', 'Complete Google sign-in in your browser.');
  try {
    const dto = await window.svc.license.signIn();
    hideLoading();

    // Security check blocked sign-in.
    if (dto && dto.securityBlocked) {
      showLoginError(dto.error, { blocking: true });
      toast('Sign-in blocked — see banner.', 'err');
      return;
    }

    // v6: MITM check blocked sign-in. v6.2: same fix-now button as boot.
    if (dto && dto.mitmBlocked) {
      showLoginError(dto.error, {
        blocking:  true,
        remediate: { kind: dto.mitmKind, tool: dto.mitmTool },
      });
      toast(`Sign-in blocked - click "Fix now" or remove ${dto.mitmTool || 'proxy tool'} manually.`, 'err');
      return;
    }

    // Device limit exceeded — dedicated screen with remove-device UI.
    if (dto && dto.deviceLimitExceeded) {
      _renderDeviceLimit(dto);
      showScreen('devicelimit');
      return;
    }

    if (dto && dto.error) {
      showLoginError(dto.error);
      toast(dto.error, 'err');
      return;
    }
    state.session = dto.session;
    state.subscription = dto.subscription;
    state.hwid = dto.hwid || state.hwid;

    // SUSPENDED path — dedicated ban screen.
    if (dto.subscription && dto.subscription.status === 'suspended') {
      _renderSuspended(dto.subscription);
      showScreen('suspended');
      return;
    }

    if (!dto.subscription || dto.subscription.active === false) {
      _renderNoSub();
      showScreen('nosub');
      return;
    }
    _renderDashboard();
    showScreen('dashboard');
    pollStatusLoop();
    toast('Signed in — welcome back.', 'ok');

    // First-time signer with a VERIFIED-ACTIVE subscription only.
    // See boot() for the same gate — tutorial isn't shown to
    // offline-cache users or anyone whose sub status is uncertain.
    const sub = dto.subscription;
    const verified = sub && sub.active === true && sub.status !== 'suspended'
                     && !sub._fromCache && !sub.error;
    if (verified) {
      try {
        const ob = await window.svc.onboarding.get();
        if (ob && !ob.complete) showOnboarding();
      } catch {}
    }
  } catch (e) {
    hideLoading();
    showLoginError(e.message || String(e));
  }
});

document.getElementById('copy-auth-url').addEventListener('click', async () => {
  const url = await window.svc.license.pendingUrl();
  if (!url) {
    toast('No sign-in in progress — click "Sign in with Google" first.', 'err');
    return;
  }
  try {
    await navigator.clipboard.writeText(url);
    toast('Sign-in URL copied to clipboard — paste it in your browser.', 'ok');
  } catch {
    toast('Copy failed — please try again.', 'err');
  }
});

// ─── No-subscription screen ────────────────────────────────────
function _renderNoSub() {
  const s = state.session || {};
  const email = s.email || '';
  const displayName = s.display_name || (email.split('@')[0]) || 'user';

  document.getElementById('nosub-email').textContent = email || '(unknown account)';
  document.getElementById('nosub-device').textContent = shortenHwid(state.hwid);

  const av = document.getElementById('nosub-avatar');
  av.innerHTML = '';
  if (s.avatar_url) {
    const img = document.createElement('img');
    img.src = s.avatar_url;
    img.referrerPolicy = 'no-referrer';
    img.onerror = () => { av.textContent = displayName.charAt(0).toUpperCase(); };
    av.appendChild(img);
  } else {
    av.textContent = displayName.charAt(0).toUpperCase();
  }

  const sub = state.subscription || {};
  const statusEl = document.getElementById('nosub-status');

  // v4.9: structured error shape from subscription.js.
  //   error.kind = 'http' | 'network' | 'schema' | 'clock_drift'
  // Show a specific, actionable message per kind instead of dumping
  // the internal message string (which used to include garbage like
  // "subscriptions http 400" that customers can't act on).
  if (sub && sub.error && typeof sub.error === 'object') {
    const err = sub.error;
    if (err.kind === 'schema') {
      // PostgREST 42703 — server schema mismatch. This is OUR bug, not
      // the user's. Different copy so support isn't flooded with
      // "why is my subscription showing as inactive" tickets.
      statusEl.innerHTML =
        `<b>License server error</b> — the client is asking for a column ` +
        `the server doesn't have. Please contact <b>support@cloakgpt.ca</b> ` +
        `with the code <code>SCHEMA_${escapeHtml(err.endpoint || 'unknown')}_${err.statusCode || '?'}</code>. ` +
        `This is not a subscription problem.`;
    } else if (err.kind === 'network') {
      statusEl.innerHTML =
        `Couldn't reach the license server — check your internet connection and click <b>Retry check</b>.`;
    } else if (err.kind === 'clock_drift') {
      statusEl.innerHTML =
        `System clock drift detected (${err.drift || '?'}s off). ` +
        `Fix your Windows time settings (Settings → Time & Language → Date & time → Sync now) and click <b>Retry check</b>.`;
    } else {
      // Generic HTTP error (401 → we'd already be at login; 403 / 5xx / etc).
      statusEl.innerHTML =
        `License server returned HTTP <b>${err.statusCode || '?'}</b> on <b>${escapeHtml(err.endpoint || 'sub check')}</b>. ` +
        `Click <b>Retry check</b>. If this persists, contact support.`;
    }
  } else if (sub && sub._fromCache) {
    // We're serving offline-grace cache; show it as such so the user
    // knows the network is off, not that their sub is inactive.
    const ageMin = Math.floor((sub._cacheAgeMs || 0) / 60000);
    statusEl.innerHTML =
      `Using cached subscription (last verified ${ageMin} min ago) — will re-check when back online.`;
  } else {
    statusEl.innerHTML = `Subscription status: <b>${escapeHtml(sub.status || 'not_found')}</b>`;
  }
}

document.getElementById('btn-nosub-billing').addEventListener('click', () => {
  window.svc.shell.openExternal('https://cloakgpt.ca/dashboard');
});

// v1.6 (2026-07-14): "Reset local data & sign in fresh" escape hatch.
// Wipes session, sub cache, HWID cache, onboarding flag WITHOUT touching
// paid installation (C binaries, overlay state, api keys preserved).
// Then re-runs OAuth from scratch. For users stuck in HWID-drift /
// stale-cache / rejected-token loops (see subscription.js v6.4 notes).
document.getElementById('btn-nosub-reset').addEventListener('click', async () => {
  const el = document.getElementById('btn-nosub-reset');
  if (!el || el.classList.contains('busy')) return;
  const confirmed = confirm(
    'Reset all local CloakGPT data?\n\n' +
    'This will clear:\n' +
    '  • Your saved session (you will need to sign in again)\n' +
    '  • The cached subscription state\n' +
    '  • The cached hardware fingerprint\n' +
    '  • The onboarding tutorial flag\n\n' +
    'This will NOT touch:\n' +
    '  • Your API keys\n' +
    '  • Your custom hotkeys\n' +
    '  • Your overlay appearance settings\n' +
    '  • The installed CloakGPT program itself\n\n' +
    'The overlay will be uninjected if currently running. Continue?'
  );
  if (!confirmed) return;

  const origLabel = el.textContent;
  el.classList.add('busy');
  el.textContent = 'Resetting local data…';
  showLoading('Resetting local data…', 'Clearing session, cache, and device fingerprint.');
  try {
    const r = await window.svc.license.resetLocalData();
    hideLoading();
    el.classList.remove('busy');
    el.textContent = origLabel;
    if (!r || !r.ok) {
      const failed = (r && Array.isArray(r.steps))
        ? r.steps.filter(s => !s.ok).map(s => s.name).join(', ')
        : 'unknown';
      toast(`Reset partially failed: ${failed}. Please restart CloakGPT.`, 'err');
      return;
    }
    toast('Local data cleared. Sign in fresh from the next screen.', 'ok');
    // Route back to login. The user will click "Sign in with Google" and
    // start a fresh OAuth flow — no session, no cache, no stale HWID.
    state.session = null;
    state.subscription = null;
    _renderLoginDeviceId();
    clearLoginError();
    showScreen('login');
  } catch (e) {
    hideLoading();
    el.classList.remove('busy');
    el.textContent = origLabel;
    toast(`Reset failed: ${e.message || e}`, 'err');
  }
});

document.getElementById('btn-nosub-retry').addEventListener('click', async () => {
  showLoading('Re-checking subscription…', 'Querying Supabase for active grants + subscriptions.');
  try {
    // v4.9: use lightweight revalidate IPC instead of full license:load.
    // Doesn't re-run security scans or session recovery — just re-hits
    // Supabase with current token (refresh if needed).
    const r = await window.svc.license.revalidate();
    hideLoading();
    if (r && r.securityBlocked) {
      showLoginError(r.err || 'Security check blocked re-validation.');
      showScreen('login');
      return;
    }
    if (!r || !r.ok) {
      const why = r && r.err ? ` (${_shortErr(r.err)})` : '';
      toast(`Retry failed${why}.`, 'err');
      return;
    }
    const sub = r.subscription;
    state.subscription = sub;
    if (sub && sub.active) {
      _renderDashboard();
      showScreen('dashboard');
      pollStatusLoop();
      toast('Subscription active — welcome back.', 'ok');
    } else {
      _renderNoSub();
      const why = _describeSubError(sub);
      toast(`Still no active subscription${why}.`, 'err');
    }
  } catch (e) {
    hideLoading();
    toast(`Retry failed: ${e.message || e}`, 'err');
  }
});

// Format a subscription error for a brief toast message. Uses the same
// structured error shape (from subscription.js v4.9).
function _describeSubError(sub) {
  if (!sub || !sub.error) return '';
  const e = sub.error;
  if (typeof e === 'string') return ` (${e})`;
  if (e.kind === 'schema') return ` (server schema error — support code SCHEMA_${e.endpoint}_${e.statusCode})`;
  if (e.kind === 'network') return ' (network unreachable)';
  if (e.kind === 'clock_drift') return ` (clock drift ${e.drift}s)`;
  return e.statusCode ? ` (HTTP ${e.statusCode})` : ` (${e.message || 'unknown'})`;
}
function _shortErr(e) {
  if (!e) return '';
  if (typeof e === 'string') return e.slice(0, 120);
  if (e.message) return String(e.message).slice(0, 120);
  return String(e).slice(0, 120);
}

async function _doSignOutAndReturnToLogin() {
  showLoading('Signing out…');
  await window.svc.license.signOut();
  hideLoading();
  state.session = null; state.subscription = null;
  _renderLoginDeviceId();
  showScreen('login');
}
document.getElementById('btn-nosub-signout').addEventListener('click', _doSignOutAndReturnToLogin);
document.getElementById('nosub-switch-account').addEventListener('click', (e) => {
  e.preventDefault();
  _doSignOutAndReturnToLogin();
});

// ─── Suspended (ban) screen ────────────────────────────────────
function _renderSuspended(sub) {
  const s = state.session || {};
  const email = s.email || (sub && sub._preservedEmail) || '';
  const displayName = s.display_name || (email.split('@')[0]) || 'user';

  document.getElementById('susp-email').textContent = email || '(unknown account)';
  document.getElementById('susp-device').textContent = shortenHwid(state.hwid);

  const av = document.getElementById('susp-avatar');
  av.innerHTML = '';
  if (s.avatar_url) {
    const img = document.createElement('img');
    img.src = s.avatar_url;
    img.referrerPolicy = 'no-referrer';
    img.onerror = () => { av.textContent = displayName.charAt(0).toUpperCase(); };
    av.appendChild(img);
  } else {
    av.textContent = displayName.charAt(0).toUpperCase();
  }

  const reason = (sub && sub.suspension_reason) || 'No reason provided.';
  document.getElementById('susp-reason-body').textContent = reason;

  const suspAt = sub && sub.suspended_at;
  const whenEl = document.getElementById('susp-reason-when');
  if (suspAt) {
    try {
      const d = new Date(suspAt);
      whenEl.textContent = `Suspended ${d.toLocaleDateString()} at ${d.toLocaleTimeString()}`;
    } catch { whenEl.textContent = ''; }
  } else {
    whenEl.textContent = '';
  }
}

document.getElementById('btn-susp-contact').addEventListener('click', () => {
  window.svc.shell.openExternal('https://cloakgpt.ca/support');
});
document.getElementById('btn-susp-signout').addEventListener('click', _doSignOutAndReturnToLogin);

// ─── Device-limit screen ───────────────────────────────────────
let _dlPending = null;   // { pendingAccessToken, pendingUserId, currentHwid }

function _renderDeviceLimit(dto) {
  _dlPending = {
    pendingAccessToken: dto._pendingSession?.access_token || null,
    pendingUserId:      dto._pendingSession?.user_id || null,
    currentHwid:        dto.currentHwid || null,
  };
  document.getElementById('dl-limit').textContent = String(dto.limit || 1);
  const currBody = document.getElementById('dl-current-body');
  const parts = [];
  if (dto.currentDeviceName) parts.push(escapeHtml(dto.currentDeviceName));
  if (dto.currentModel)      parts.push(`<span style="color:var(--fg3)">${escapeHtml(dto.currentModel)}</span>`);
  if (dto.currentHwid)       parts.push(`<span class="dl-device-hwid" style="margin-left:8px">${shortenHwid(dto.currentHwid)}</span>`);
  currBody.innerHTML = parts.join(' ');

  const listEl = document.getElementById('dl-devices-list');
  listEl.innerHTML = '';
  for (const d of (dto.devices || [])) {
    const row = document.createElement('div');
    row.className = 'dl-device-row';
    const name  = d.device_name || 'Unknown device';
    const model = d.model || '';
    const seen  = d.last_seen_at ? new Date(d.last_seen_at) : null;
    const seenStr = seen ? `Last seen ${seen.toLocaleDateString()}` : 'Never seen';
    row.innerHTML = `
      <div class="dl-device-icon">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
        </svg>
      </div>
      <div class="dl-device-info">
        <div class="dl-device-name">${escapeHtml(name)}${model ? ' <span style="color:var(--fg3);font-weight:400">· ' + escapeHtml(model) + '</span>' : ''}</div>
        <div class="dl-device-meta"><span class="dl-device-hwid">${shortenHwid(d.hardware_uuid)}</span> · ${escapeHtml(seenStr)}</div>
      </div>
      <button class="dl-btn-remove" data-hwid="${escapeHtml(d.hardware_uuid)}" data-name="${escapeHtml(name)}">
        Remove
      </button>
    `;
    listEl.appendChild(row);
  }

  // Wire remove buttons.
  for (const btn of listEl.querySelectorAll('.dl-btn-remove')) {
    btn.addEventListener('click', async (e) => {
      const b = e.currentTarget;
      const hwid = b.dataset.hwid;
      const name = b.dataset.name;
      if (!confirm(`Remove device "${name}"?\n\nThat device will be signed out of CloakGPT the next time it tries to reach the license server (up to ~30 min).`)) return;
      b.disabled = true;
      b.textContent = 'Removing…';
      const r = await window.svc.license.removeDevice({
        pendingAccessToken: _dlPending.pendingAccessToken,
        pendingUserId:      _dlPending.pendingUserId,
        hardwareUuid:       hwid,
      });
      if (r && r.ok) {
        toast(`Removed "${name}". You can sign in again now.`, 'ok');
        // Auto-retry sign-in — the user_devices count is now under the limit.
        showLoading('Retrying sign-in…');
        setTimeout(async () => {
          try {
            const retryDto = await window.svc.license.signIn();
            hideLoading();
            if (retryDto && retryDto.deviceLimitExceeded) {
              _renderDeviceLimit(retryDto);
              return;
            }
            if (retryDto && retryDto.error) {
              showLoginError(retryDto.error);
              showScreen('login');
              return;
            }
            state.session = retryDto.session;
            state.subscription = retryDto.subscription;
            state.hwid = retryDto.hwid || state.hwid;
            if (retryDto.subscription && retryDto.subscription.status === 'suspended') {
              _renderSuspended(retryDto.subscription);
              showScreen('suspended'); return;
            }
            if (!retryDto.subscription || !retryDto.subscription.active) {
              _renderNoSub();
              showScreen('nosub'); return;
            }
            _renderDashboard();
            showScreen('dashboard');
            pollStatusLoop();
            toast('Signed in on this device.', 'ok');
          } catch (err) {
            hideLoading();
            toast(`Retry failed: ${err.message || err}`, 'err');
          }
        }, 600);
      } else {
        b.disabled = false;
        b.textContent = 'Remove';
        // v4.9: server-side has NO DELETE RLS policy for authenticated
        // users on user_devices. registration.deleteDevice returns
        // needsSupportAction=true in that case. Show a longer, clearer
        // message using a confirm dialog instead of a fleeting toast so
        // the user has time to copy the support-contact instructions.
        if (r && r.needsSupportAction) {
          const supportMsg =
            `Device removal isn't self-serve yet.\n\n` +
            `Please email support@cloakgpt.ca with the subject:\n` +
            `  "Remove device: ${(hwid || '').slice(0, 12)}..."\n\n` +
            `Include your account email (${state.session?.email || '(sign-in email)'}). ` +
            `We'll remove it within one business day so you can sign in on this PC.\n\n` +
            `Click OK to copy the support email address to your clipboard.`;
          if (confirm(supportMsg)) {
            try {
              navigator.clipboard.writeText('support@cloakgpt.ca');
              toast('support@cloakgpt.ca copied to clipboard.', 'ok');
            } catch { /* clipboard denied — fine, user knows the address */ }
          }
        } else {
          toast(`Remove failed: ${(r && r.err) || 'unknown error'}`, 'err');
        }
      }
    });
  }
}

document.getElementById('btn-dl-cancel').addEventListener('click', () => {
  _dlPending = null;
  state.session = null; state.subscription = null;
  _renderLoginDeviceId();
  showScreen('login');
  toast('Sign-in cancelled.', 'err');
});

// ─── Dashboard ─────────────────────────────────────────────────
function _renderDashboard() {
  const s = state.session || {};
  document.getElementById('d-name').textContent  = s.display_name || (s.email || '').split('@')[0] || 'User';
  document.getElementById('d-email').textContent = s.email || '';
  const av = document.getElementById('d-avatar');
  av.innerHTML = '';
  if (s.avatar_url) {
    const img = document.createElement('img');
    img.src = s.avatar_url;
    img.referrerPolicy = 'no-referrer';
    img.onerror = () => { av.textContent = (s.display_name || s.email || '?').charAt(0).toUpperCase(); };
    av.appendChild(img);
  } else {
    av.textContent = (s.display_name || s.email || '?').charAt(0).toUpperCase();
  }
  const sub = state.subscription || {};
  const pill = document.getElementById('d-sub');
  if (sub.active) {
    pill.textContent = (sub.is_lifetime ? 'LIFETIME' : (sub.plan || 'PRO')).toUpperCase();
    pill.classList.remove('inactive');
  } else {
    pill.textContent = 'INACTIVE';
    pill.classList.add('inactive');
  }
  refreshCredits();
  document.getElementById('d-badge-session').textContent =
    s.expires_at ? _formatExpiry(s.expires_at) : '—';

  // Restore chosen tier chip
  _syncChipUi();

  // Load persisted API keys (v4.4 multi-provider bag).
  window.svc.apiKeys.load().then((bag) => {
    if (!bag) return;
    for (const slot of PROVIDER_SLOTS) {
      const row = document.querySelector(`.provider-row[data-slot="${slot}"]`);
      const ipt = row?.querySelector('.provider-input');
      if (ipt && bag[slot]) {
        ipt.value = bag[slot];
        row.classList.add('has-key');
        _statusPill(row, 'untested', 'Untested');
      } else if (ipt) {
        _statusPill(row, 'untested', 'Not tested');
      }
    }
  });
}

function _formatExpiry(ts) {
  try {
    const d = new Date(ts * 1000);
    const now = Date.now();
    const diffMs = d.getTime() - now;
    if (diffMs < 0) return 'expired';
    const hrs = Math.round(diffMs / 3_600_000);
    if (hrs < 48) return `${hrs}h`;
    const days = Math.round(hrs / 24);
    return `${days}d`;
  } catch { return '—'; }
}

// v (2026-08-12): AI credit balance in the dashboard. Calls get_my_credits
// (authenticated RPC) via main. Shows a dollar balance; "Buy more" opens the
// cloakgpt.ca web dashboard (Next.js billing) for one-time top-ups. Cosmetic —
// failures just show a dash, never block anything.
function refreshCredits() {
  const el  = document.getElementById('d-badge-credits');  // dashboard badge
  const kel = document.getElementById('k-credits-bal');    // API-keys card block
  if (!el && !kel) return;
  const setBoth = (txt, title) => {
    if (el)  { el.textContent  = txt; if (title) el.title  = title; }
    if (kel) { kel.textContent = txt; if (title) kel.title = title; }
  };
  const sub = state.subscription || {};
  if (!sub.active) { setBoth('—'); return; }
  setBoth('…');
  window.svc.credits.load().then((c) => {
    if (c && typeof c.credits === 'number') {
      const used = (c.total_usage || 0).toFixed(2);
      const title = `Used $${used} of AI so far` +
        (c.refreshed_at ? ` · last topped up ${new Date(c.refreshed_at).toLocaleDateString()}` : '');
      setBoth('$' + c.credits.toFixed(2), title);
    } else {
      setBoth('—');
    }
  }).catch(() => { setBoth('—'); });
}

function _openBilling(e) {
  if (e) e.preventDefault();
  window.svc.shell.openExternal('https://cloakgpt.ca/dashboard');
}
document.getElementById('btn-buy-credits')?.addEventListener('click', _openBilling);
document.getElementById('k-buy-credits')?.addEventListener('click', _openBilling);

document.getElementById('btn-signout').addEventListener('click', async () => {
  if (!confirm('Sign out? The overlay will turn off.')) return;
  showLoading('Signing out…', 'Turning off the overlay.');
  await window.svc.license.signOut();
  hideLoading();
  state.session = null; state.subscription = null;
  state.injected = false;
  _renderLoginDeviceId();
  showScreen('login');
  toast('Signed out.', 'ok');
});

// ─── Tier chip selection ─────────────────────────────────────────
//
// Provider chips removed in v4.4 — provider is auto-picked from
// whichever keys are configured, with runtime failover between them.
// Tier chips remain (users still want STRONG/MED/CHEAP control).
//
// v5.0.1 (2026-09-21) BUG FIX: click handler used to only update
// in-memory state.chosen_tier without persisting to disk. Users
// reported "clicked STRONG, closed app, didn't save" -- correct: on
// next boot state.chosen_tier reset to hardcoded default 1 (MEDIUM).
// Now: every click also fires window.svc.uiPrefs.save() so the choice
// survives app restart. boot() loads via .load() before UI paint so
// chip-active class reflects the saved tier.
document.querySelectorAll('#chip-tier .chip[data-tier]').forEach(c => {
  c.addEventListener('click', () => {
    document.querySelectorAll('#chip-tier .chip[data-tier]').forEach(x => x.classList.remove('active'));
    c.classList.add('active');
    state.chosen_tier = parseInt(c.dataset.tier, 10);
    /* Persist immediately (single-value, no debounce needed). Best-
     * effort -- on save failure the choice still applies for THIS
     * session; only survival across restart is lost. */
    if (window.svc && window.svc.uiPrefs && window.svc.uiPrefs.save) {
      window.svc.uiPrefs.save({ tier: state.chosen_tier, provider: state.chosen_provider })
        .catch(e => console.log('[ui-prefs] tier save failed:', e && e.message));
    }
  });
});
function _syncChipUi() {
  document.querySelectorAll('#chip-tier .chip[data-tier]').forEach(c => {
    c.classList.toggle('active', parseInt(c.dataset.tier, 10) === state.chosen_tier);
  });
}

// ─── v4.4 multi-provider API-key rows ──────────────────────────
//
// Each `.provider-row` has data-slot ∈ {openai,anthropic,google,openrouter}
// + data-provider ∈ {1,2,3,4}. Wiring:
//   - eye toggle for password visibility
//   - debounced save on input
//   - Test button hits the provider's list-models endpoint (via main
//     process — never renderer-side because CSP forbids connect-src)
//   - "How do I get a key?" link opens the provider's key page in the
//     system browser
const PROVIDER_SLOTS = ['openai', 'anthropic', 'google', 'openrouter'];
let _keySaveTimer = null;
let _pendingKeys = null;   // dict-in-flight, flushed on debounce

function _readAllKeys() {
  const bag = { openai: '', anthropic: '', google: '', openrouter: '' };
  for (const slot of PROVIDER_SLOTS) {
    const row = document.querySelector(`.provider-row[data-slot="${slot}"]`);
    const ipt = row?.querySelector('.provider-input');
    if (ipt) bag[slot] = ipt.value.trim();
  }
  return bag;
}

function _flushKeysSoon() {
  clearTimeout(_keySaveTimer);
  _keySaveTimer = setTimeout(() => {
    _pendingKeys = _readAllKeys();
    window.svc.apiKeys.save(_pendingKeys);
  }, 400);
}

function _statusPill(row, cls, text) {
  const p = row.querySelector('.provider-status');
  if (!p) return;
  p.className = 'provider-status ' + cls;
  p.textContent = text;
}

async function _testRow(row) {
  const slot = row.dataset.slot;
  const provider = parseInt(row.dataset.provider, 10);
  const ipt = row.querySelector('.provider-input');
  const key = ipt.value.trim();
  if (!key) {
    _statusPill(row, 'empty', 'Empty');
    row.classList.remove('has-key', 'test-ok', 'test-err');
    return;
  }
  _statusPill(row, 'testing', 'Testing…');
  row.classList.remove('test-ok', 'test-err');
  const btn = row.querySelector('.btn-test');
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const r = await window.svc.apiKeys.test(provider, key);
    if (r.ok) {
      const detail = r.models > 0 ? `${r.models} models · ${r.latency_ms}ms` : `${r.latency_ms}ms`;
      _statusPill(row, 'ok', `OK · ${detail}`);
      row.classList.add('test-ok'); row.classList.remove('test-err');
      toast(`${slot}: key valid (${detail}).`, 'ok');
    } else {
      const brief = (r.err || 'error').slice(0, 90);
      _statusPill(row, 'err', `Failed · ${r.status || '?'}`);
      row.classList.add('test-err'); row.classList.remove('test-ok');
      toast(`${slot}: ${brief}`, 'err');
    }
  } catch (e) {
    _statusPill(row, 'err', 'Error');
    row.classList.add('test-err'); row.classList.remove('test-ok');
    toast(`${slot}: ${e.message || e}`, 'err');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Test'; }
  }
}

for (const slot of PROVIDER_SLOTS) {
  const row = document.querySelector(`.provider-row[data-slot="${slot}"]`);
  if (!row) continue;
  const ipt = row.querySelector('.provider-input');
  const eye = row.querySelector('.btn-eye');
  const test = row.querySelector('.btn-test');
  const link = row.querySelector('.provider-link');
  ipt?.addEventListener('input', () => {
    row.classList.toggle('has-key', !!ipt.value.trim());
    row.classList.remove('test-ok', 'test-err');
    if (ipt.value.trim()) _statusPill(row, 'untested', 'Untested');
    else                  _statusPill(row, 'untested', 'Not tested');
    _flushKeysSoon();
  });
  eye?.addEventListener('click', () => {
    ipt.type = (ipt.type === 'password') ? 'text' : 'password';
  });
  test?.addEventListener('click', () => _testRow(row));
  link?.addEventListener('click', (e) => {
    e.preventDefault();
    const href = link.dataset.href;
    if (href) window.svc.shell.openExternal(href);
  });
}

// Tier explainer toggle
document.getElementById('btn-tiers-explain')?.addEventListener('click', (e) => {
  e.preventDefault();
  const box = document.getElementById('tier-explainer');
  if (box) box.style.display = (box.style.display === 'none' || !box.style.display) ? 'block' : 'none';
});

// Nuke API keys — wipes every stored key from disk (DPAPI + portable
// AES + legacy single-key blob) AND clears all 4 inputs on screen +
// their status pills. Destructive — confirms first. Does NOT trigger an
// auto-uninject of the payload; if user wants that too they can hit
// Uninject / Emergency Stop separately.
document.getElementById('btn-nuke-keys')?.addEventListener('click', async () => {
  if (!confirm(
    'NUKE ALL API KEYS?\n\n' +
    'This will delete every stored provider key from this device:\n' +
    '  - OpenAI\n' +
    '  - Anthropic\n' +
    '  - Google (Gemini)\n' +
    '  - OpenRouter\n\n' +
    'Every encrypted copy on this device is wiped. You will need to re-enter each key before you can Inject again.\n\n' +
    'Continue?'
  )) return;
  try {
    await window.svc.apiKeys.clear();
    // Also wipe legacy single-key blob in case of leftovers.
    await window.svc.apiKey.clear().catch(() => {});
    // Clear each input + reset status pill to "Not tested".
    for (const slot of PROVIDER_SLOTS) {
      const row = document.querySelector(`.provider-row[data-slot="${slot}"]`);
      if (!row) continue;
      const ipt = row.querySelector('.provider-input');
      if (ipt) { ipt.value = ''; ipt.type = 'password'; }
      row.classList.remove('has-key', 'test-ok', 'test-err');
      _statusPill(row, 'untested', 'Not tested');
    }
    toast('All API keys nuked from disk. Enter new keys before re-injecting.', 'ok');
  } catch (e) {
    toast(`Nuke failed: ${e.message || e}`, 'err');
  }
});

// ─── v6 (2026-07-06): AI answer style card wiring ────────────────
// Persist textarea + mode radio + direct-mode checkbox + latex_mode +
// stream_display. Auto-save with a 400ms debounce so we don't hammer
// disk on every keystroke.
let _promptState = {
  text: '', mode: 'off',
  direct_answer_mode: 0,
  latex_mode: 'auto',
  stream_display: 'live',
};
let _promptSaveTimer = null;

function _renderPromptLen() {
  const badge = document.getElementById('prompt-len-badge');
  const ta    = document.getElementById('txt-system-prompt');
  if (!badge || !ta) return;
  const n = ta.value.length;
  badge.textContent = `${n} / 15000`;
  badge.classList.remove('warn', 'err');
  if (n > 14000) badge.classList.add('err');
  else if (n > 12000) badge.classList.add('warn');
}

function _flushPromptSoon() {
  clearTimeout(_promptSaveTimer);
  _promptSaveTimer = setTimeout(async () => {
    try {
      await window.svc.systemPrompt.save({
        text: _promptState.text,
        mode: _promptState.mode,
        direct_answer_mode: _promptState.direct_answer_mode,
        latex_mode: _promptState.latex_mode,
        stream_display: _promptState.stream_display,
      });
    } catch (e) { console.log('[renderer] system-prompt save failed:', e.message); }
  }, 400);
}

async function _initAnswerStyleCard() {
  try {
    const p = await window.svc.systemPrompt.load();
    _promptState = {
      text:               p.text || '',
      mode:               p.mode || 'off',
      direct_answer_mode: p.direct_answer_mode ? 1 : 0,
      latex_mode:         p.latex_mode         || 'auto',
      /* v6.3: batched is the default; user can flip to 'live' via UI */
      stream_display:     p.stream_display     || 'batched',
    };
  } catch (e) { console.log('[renderer] system-prompt load failed:', e.message); }

  const ta          = document.getElementById('txt-system-prompt');
  const chkDirect   = document.getElementById('chk-direct-mode');
  const chkLatexOff = document.getElementById('chk-latex-off');
  const chkBatched  = document.getElementById('chk-batched-display');
  const btnClear    = document.getElementById('btn-prompt-clear');
  const modeRadios  = document.querySelectorAll('input[name="prompt-mode"]');

  if (ta) {
    ta.value = _promptState.text;
    ta.disabled = (_promptState.mode === 'off');
    ta.addEventListener('input', () => {
      _promptState.text = ta.value;
      _renderPromptLen();
      _flushPromptSoon();
    });
  }
  if (chkDirect) {
    chkDirect.checked = !!_promptState.direct_answer_mode;
    chkDirect.addEventListener('change', () => {
      _promptState.direct_answer_mode = chkDirect.checked ? 1 : 0;
      _flushPromptSoon();
      if (chkDirect.checked) {
        toast('Direct-answer mode ON. AI will reply with ONLY the answer next time. Reinject to apply now.', 'ok');
      }
    });
  }
  if (chkLatexOff) {
    chkLatexOff.checked = (_promptState.latex_mode === 'off');
    chkLatexOff.addEventListener('change', () => {
      _promptState.latex_mode = chkLatexOff.checked ? 'off' : 'auto';
      _flushPromptSoon();
      toast(chkLatexOff.checked
        ? 'LaTeX disabled. AI will use plain Unicode/keyboard math. Reinject to apply.'
        : 'LaTeX re-enabled. AI may use LaTeX commands. Reinject to apply.', 'ok');
    });
  }
  if (chkBatched) {
    chkBatched.checked = (_promptState.stream_display === 'batched');
    chkBatched.addEventListener('change', () => {
      _promptState.stream_display = chkBatched.checked ? 'batched' : 'live';
      _flushPromptSoon();
      toast(chkBatched.checked
        ? 'Batched display ON. Answers appear all at once after streaming completes. Reinject to apply.'
        : 'Live display ON. Answers stream token-by-token. Reinject to apply.', 'ok');
    });
  }
  modeRadios.forEach((r) => {
    r.checked = (r.value === _promptState.mode);
    r.addEventListener('change', () => {
      if (!r.checked) return;
      _promptState.mode = r.value;
      if (ta) ta.disabled = (r.value === 'off');
      _flushPromptSoon();
    });
  });
  if (btnClear) {
    btnClear.addEventListener('click', () => {
      if (ta) ta.value = '';
      _promptState.text = '';
      _renderPromptLen();
      _flushPromptSoon();
      toast('Custom prompt cleared. Built-in prompt will be used on next Inject.', 'ok');
    });
  }
  _renderPromptLen();
}

// v6: FULL UNINSTALL button on Support card.
async function _handleFullUninstall() {
  const confirm1 = confirm(
    'UNINSTALL CLOAKGPT?\n\n' +
    'This will:\n' +
    '  1. Turn off the overlay\n' +
    '  2. Reset Windows\u2019 screen manager (screen briefly goes black, then recovers)\n' +
    '  3. DELETE everything:\n' +
    '       - your session (you\'ll need to sign in with Google again)\n' +
    '       - all 4 stored API keys\n' +
    '       - your custom system prompt\n' +
    '       - hotkey customizations\n' +
    '       - encrypted diagnostic logs\n' +
    '       - the CloakGPT install folder contents\n\n' +
    'After this you should uninstall svchelper.exe from Windows Apps & Features.\n\n' +
    'Continue?'
  );
  if (!confirm1) return;
  const confirm2 = confirm(
    'FINAL CONFIRMATION.\n\n' +
    'The overlay will disappear, your screen will briefly flash black, ' +
    'and this app will forget everything about you.\n\n' +
    'Really continue?'
  );
  if (!confirm2) return;

  showLoading('Uninstalling CloakGPT…',
    'Turning off the overlay + wiping your data. ~5 seconds.');
  try {
    const r = await window.svc.injector.fullUninstall();
    hideLoading();
    // We always show a big "done" dialog even on partial failures
    // because the state is likely still cleaned up enough that a
    // fresh install would work.
    const steps = (r && r.steps) || [];
    const failed = steps.filter(s => !s.ok);
    const summary = steps.map(s =>
      (s.ok ? '\u2713 ' : '\u2717 ') + s.name +
      (s.extra ? ` (${s.extra})` : '')
    ).join('\n');
    alert(
      `UNINSTALL ${r.ok ? 'COMPLETE' : 'MOSTLY DONE'}\n\n` +
      summary + '\n\n' +
      (failed.length > 0
        ? `${failed.length} step(s) failed \u2014 some files in the CloakGPT install folder may need to be deleted manually. Reboot recommended.\n\n`
        : '') +
      'CloakGPT is now removed from this machine.\n' +
      'You can safely uninstall svchelper.exe from Windows Apps & Features.\n\n' +
      'This window will close after you click OK.'
    );
    try { await window.svc.window.quit(); } catch {}
  } catch (e) {
    hideLoading();
    toast(`Uninstall failed: ${e.message || e}`, 'err');
  }
}
document.getElementById('btn-full-uninstall')?.addEventListener('click', _handleFullUninstall);

// Fire the answer-style card init once the dashboard first renders.
_initAnswerStyleCard().catch(e => console.log('[renderer] answer style init:', e.message));

// ─── v1.2 (2026-07-06) — Overlay-appearance card ─────────────────
//
// User picks LAUNCH width / height / alpha + ultra-mode toggle. All
// changes are persisted to overlay.json in appData via svc.overlay.
// A "Save" button applies-on-next-Inject; live-preview updates as the
// user drags sliders. The preview box is scaled to a mock 1920×1080
// display so the user gets an intuitive sense of "how big will this
// look on my screen?" without needing to actually inject first.
//
// SIZE_MODE CLAMP RULES (must mirror storage.js _clampOverlayInput
// AND payload's ui_apply_launch_config bounds):
//   normal : w [200 .. 1400], h [140 .. 1200]
//   ultra  : w [ 80 .. 4000], h [ 60 .. 3000]
//
// Alpha always [0.20 .. 1.00] regardless of size mode.
const _OVA_BOUNDS = {
  0: { wMin:  200, wMax: 1400, hMin: 140, hMax: 1200 },  // normal
  1: { wMin:   80, wMax: 4000, hMin:  60, hMax: 3000 },  // ultra
};
/* v11 (2026-07-24) — added `theme` (0=dark 1=light 2=auto) and `overlay_flags`
 * (bitfield of TRAIL_ERASE|SMOOTH_NUDGE|UNIFORM_ALPHA|OPAQUE_LOCK) to the
 * overlay state so the dashboard can persist Bypassify-parity look-and-feel
 * across sessions. Defaults: OPAQUE, AUTO theme, all v11 behavior flags on. */
const OVFLAG_TRAIL_ERASE   = 0x1;
const OVFLAG_SMOOTH_NUDGE  = 0x2;
const OVFLAG_UNIFORM_ALPHA = 0x4;
const OVFLAG_OPAQUE_LOCK   = 0x8;
/* v13 (2026-08-10) — OPAQUE_LOCK dropped (deprecated; payload ignores it).
 * Opacity slider is the single source of truth so transparency actually
 * sticks + can go near-invisible. TRAIL_ERASE stays off. */
const OVFLAG_DEFAULTS      = OVFLAG_SMOOTH_NUDGE | OVFLAG_UNIFORM_ALPHA;

let _ovaState  = { size_mode: 0, w: 560, h: 420, alpha: 1.00, theme: 2, overlay_flags: OVFLAG_DEFAULTS, scroll_step_px: 80, nudge_step_px: 48 };
let _ovaSaved  = { ...(_ovaState) };   // last-saved snapshot for dirty check
let _ovaPresetReinject = null;         // v1.7.4: debounce timer for preset auto-reinject

function _ovaBounds() { return _OVA_BOUNDS[_ovaState.size_mode] || _OVA_BOUNDS[0]; }

function _ovaRenderPreview() {
  const box = document.getElementById('ova-preview-box');
  const lbl = document.getElementById('ova-preview-w');
  if (!box) return;
  /* Scale from real overlay dimensions -> preview % of a mock 1920x1080
   * display. Aspect-ratio preserving; taskbar strip at bottom already
   * takes 6% so we treat the preview area as full 100% top-to-bottom. */
  const pctW = Math.min(100, (_ovaState.w / 1920) * 100);
  const pctH = Math.min(94,  (_ovaState.h / 1080) * 100);   // -6% for taskbar visual
  box.style.width  = pctW.toFixed(2) + '%';
  box.style.height = pctH.toFixed(2) + '%';
  box.style.opacity = String(_ovaState.alpha.toFixed(2));
  /* Hide the "560x420" text label if the preview box gets tiny enough
   * that the label overflows visually; UX polish. */
  if (lbl) {
    if (pctW < 10 || pctH < 10) {
      lbl.style.opacity = '0';
    } else {
      lbl.style.opacity = '1';
      lbl.textContent = `${_ovaState.w}\u2009\u00d7\u2009${_ovaState.h}`;
    }
  }
}

function _ovaRenderValues() {
  const setText = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  setText('val-ova-w',      `${_ovaState.w} px`);
  setText('val-ova-h',      `${_ovaState.h} px`);
  setText('val-ova-alpha',  `${Math.round(_ovaState.alpha * 100)}%`);
  setText('val-ova-scroll', `${_ovaState.scroll_step_px | 0} px`);
  setText('val-ova-nudge',  `${_ovaState.nudge_step_px | 0} px`);
}

function _ovaDirty() {
  return _ovaState.size_mode     !== _ovaSaved.size_mode
      || _ovaState.w             !== _ovaSaved.w
      || _ovaState.h             !== _ovaSaved.h
      || Math.abs(_ovaState.alpha - _ovaSaved.alpha) > 0.005
      || _ovaState.theme          !== _ovaSaved.theme
      || _ovaState.overlay_flags  !== _ovaSaved.overlay_flags
      || _ovaState.scroll_step_px !== _ovaSaved.scroll_step_px
      || _ovaState.nudge_step_px  !== _ovaSaved.nudge_step_px;
}

// v11: reflect current theme + flag chips as .is-active based on _ovaState.
function _ovaRefreshChipsActive() {
  document.querySelectorAll('#overlay-appearance-card .ova-theme-preset').forEach((chip) => {
    const t = +chip.dataset.theme;
    chip.classList.toggle('is-active', t === _ovaState.theme);
  });
  document.querySelectorAll('#overlay-appearance-card .ova-flag-toggle').forEach((chip) => {
    const bit = +chip.dataset.flag;
    chip.classList.toggle('is-active', !!(_ovaState.overlay_flags & bit));
  });
  document.querySelectorAll('#overlay-appearance-card .ova-alpha-preset').forEach((chip) => {
    const a = +chip.dataset.alpha;
    chip.classList.toggle('is-active', Math.abs(a - _ovaState.alpha) < 0.005);
  });
}

function _ovaRenderStatus() {
  const btn  = document.getElementById('btn-ova-save');
  const hint = document.getElementById('ova-status');
  const dirty = _ovaDirty();
  if (btn)  btn.disabled = !dirty;
  if (hint) {
    hint.classList.toggle('dirty', dirty);
    hint.textContent = dirty
      ? 'Unsaved changes \u2014 click Save then Inject to apply.'
      : 'Saved. Applies on next Inject Now.';
  }
}

function _ovaClampToBounds() {
  const b = _ovaBounds();
  if (_ovaState.w < b.wMin) _ovaState.w = b.wMin;
  if (_ovaState.w > b.wMax) _ovaState.w = b.wMax;
  if (_ovaState.h < b.hMin) _ovaState.h = b.hMin;
  if (_ovaState.h > b.hMax) _ovaState.h = b.hMax;
  // v13 (2026-08-10): floor 0.20 -> 0.05 so the opacity slider reaches near-invisible.
  if (_ovaState.alpha < 0.05) _ovaState.alpha = 0.05;
  if (_ovaState.alpha > 1.00) _ovaState.alpha = 1.00;
}

function _ovaSyncSliderRanges() {
  const b = _ovaBounds();
  const rW = document.getElementById('rng-ova-w');
  const rH = document.getElementById('rng-ova-h');
  if (rW) { rW.min = b.wMin; rW.max = b.wMax; rW.value = _ovaState.w; }
  if (rH) { rH.min = b.hMin; rH.max = b.hMax; rH.value = _ovaState.h; }
  const rA = document.getElementById('rng-ova-alpha');
  if (rA) rA.value = Math.round(_ovaState.alpha * 100);
  const rS = document.getElementById('rng-ova-scroll');
  if (rS) rS.value = _ovaState.scroll_step_px | 0;
  const rN = document.getElementById('rng-ova-nudge');
  if (rN) rN.value = _ovaState.nudge_step_px | 0;
}

function _ovaRefreshAll() {
  _ovaClampToBounds();
  _ovaSyncSliderRanges();
  _ovaRenderValues();
  _ovaRenderPreview();
  _ovaRenderStatus();
  _ovaRefreshChipsActive();
}

async function _initOverlayCard() {
  try {
    const p = await window.svc.overlay.load();
    if (p) {
      _ovaState = {
        size_mode: p.size_mode ? 1 : 0,
        w: +p.w, h: +p.h,
        alpha: +p.alpha,
        /* v11: pull theme + overlay_flags with sensible defaults if the
         * saved file was written by an older svchelper (missing fields). */
        theme:         (p.theme != null ? (p.theme | 0) : 2),
        overlay_flags: (p.overlay_flags != null ? (p.overlay_flags | 0) : OVFLAG_DEFAULTS),
        /* v12 (2026-07-25): scroll granularity. Sensible default 80 on missing. */
        scroll_step_px: (p.scroll_step_px != null ? (+p.scroll_step_px | 0) : 80),
        /* v13 (2026-08-10): arrow-key nudge step. Sensible default 48 on missing. */
        nudge_step_px: (p.nudge_step_px != null ? (+p.nudge_step_px | 0) : 48),
      };
      _ovaSaved = { ..._ovaState };
    }
  } catch (e) { console.log('[renderer] overlay load failed:', e.message); }

  const chkUltra = document.getElementById('chk-ova-ultra');
  const rngW     = document.getElementById('rng-ova-w');
  const rngH     = document.getElementById('rng-ova-h');
  const rngA     = document.getElementById('rng-ova-alpha');
  const rngScr   = document.getElementById('rng-ova-scroll');
  const rngNud   = document.getElementById('rng-ova-nudge');
  const btnSave  = document.getElementById('btn-ova-save');
  const btnReset = document.getElementById('btn-ova-reset');

  if (chkUltra) chkUltra.checked = !!_ovaState.size_mode;
  _ovaRefreshAll();

  if (chkUltra) {
    chkUltra.addEventListener('change', () => {
      _ovaState.size_mode = chkUltra.checked ? 1 : 0;
      _ovaRefreshAll();
    });
  }
  if (rngW) {
    rngW.addEventListener('input', () => {
      _ovaState.w = +rngW.value;
      _ovaRenderValues(); _ovaRenderPreview(); _ovaRenderStatus();
    });
  }
  if (rngH) {
    rngH.addEventListener('input', () => {
      _ovaState.h = +rngH.value;
      _ovaRenderValues(); _ovaRenderPreview(); _ovaRenderStatus();
    });
  }
  if (rngA) {
    /* v11.2 (2026-07-24) — live preview + refresh chip actives so the
     * preset chip auto-lights when the slider lands on 100/85/60/35. */
    rngA.addEventListener('input', () => {
      _ovaState.alpha = (+rngA.value) / 100;
      _ovaRenderValues(); _ovaRenderPreview(); _ovaRenderStatus();
      _ovaRefreshChipsActive();
    });
  }
  if (rngScr) {
    /* v12 (2026-07-25) — scroll granularity live update. Requires
     * Inject Now to apply (payload reads cfg->scroll_step_px on
     * config load, no live hot-swap). */
    rngScr.value = _ovaState.scroll_step_px;
    rngScr.addEventListener('input', () => {
      _ovaState.scroll_step_px = +rngScr.value | 0;
      _ovaRenderValues(); _ovaRenderStatus();
    });
  }
  if (rngNud) {
    /* v13 (2026-08-10) — arrow-key nudge granularity. Small = micro-adjust,
     * large = fast hops. Requires Inject Now to apply (payload reads
     * cfg->nudge_step_px on config load, no live hot-swap). */
    rngNud.value = _ovaState.nudge_step_px;
    rngNud.addEventListener('input', () => {
      _ovaState.nudge_step_px = +rngNud.value | 0;
      _ovaRenderValues(); _ovaRenderStatus();
    });
  }

  document.querySelectorAll('#overlay-appearance-card .ova-preset').forEach((chip) => {
    chip.addEventListener('click', async () => {
      const w = +chip.dataset.w, h = +chip.dataset.h;
      const ultra = chip.dataset.ultra === '1' ? 1 : 0;
      _ovaState = {
        size_mode: ultra, w, h, alpha: _ovaState.alpha,
        theme: _ovaState.theme, overlay_flags: _ovaState.overlay_flags,
        /* v12 (2026-07-25): preserve scroll granularity across size presets. */
        scroll_step_px: _ovaState.scroll_step_px,
        /* v13 (2026-08-10): preserve nudge granularity across size presets. */
        nudge_step_px: _ovaState.nudge_step_px,
      };
      if (chkUltra) chkUltra.checked = !!ultra;
      _ovaRefreshAll();
      /* v1.7.4 (2026-07-23) — LIVE APPLY.
       *
       * User bug: "I clicked small when I injected and it's not doing
       * anything". Old behavior: preset click only updated the local
       * preview DIV, requiring the user to also click Save + then
       * Inject Now (three-step process, most users didn't discover).
       *
       * New: auto-save the new dimensions immediately. If the payload
       * is currently loaded, also fire a background re-inject so the
       * change is visible on screen within ~2s. If not loaded (user
       * is prepping), just save + toast "click Inject Now".
       *
       * We use a debounced approach: back-to-back preset clicks are
       * coalesced so we don't spam re-inject. */
      try {
        await window.svc.overlay.save(_ovaState);
        _ovaSaved = { ..._ovaState };
        _ovaRenderStatus();
        clearTimeout(_ovaPresetReinject);
        _ovaPresetReinject = setTimeout(async () => {
          const loaded = await window.svc.injector.isPayloadLoaded();
          if (loaded) {
            toast(`${chip.textContent} preset: re-injecting overlay…`, 'ok');
            try {
              /* Fire an inject with current settings — main.js will
               * see the payload already loaded, uninject + reinject
               * with the new overlay dimensions from cfg. */
              const bag = _readAllKeys();
              await window.svc.injector.inject({ keys: bag, tier: state.chosen_tier });
              toast(`${chip.textContent} preset applied.`, 'ok');
            } catch (e) {
              toast(`${chip.textContent}: preset saved but auto-reinject failed. Click Inject Now.`, 'err');
            }
          } else {
            toast(`${chip.textContent} preset saved. Click Inject Now to apply.`, 'ok');
          }
        }, 350);
      } catch (e) {
        toast(`Preset save failed: ${e.message || e}`, 'err');
      }
    });
  });

  /* v11 (2026-07-24) \u2014 Bypassify-parity theme + opacity presets + flag chips.
   *
   * All three sets auto-save + auto-reinject (if payload is loaded) so the
   * user can experiment without hunting for Save + Inject buttons. Reuses
   * the same 350ms debounce as the size presets so back-to-back chip clicks
   * coalesce into ONE reinject at the last-clicked state. */
  const _autoSaveAndReinject = async (labelPrefix) => {
    try {
      await window.svc.overlay.save(_ovaState);
      _ovaSaved = { ..._ovaState };
      _ovaRenderStatus();
      _ovaRefreshChipsActive();
      clearTimeout(_ovaPresetReinject);
      _ovaPresetReinject = setTimeout(async () => {
        const loaded = await window.svc.injector.isPayloadLoaded();
        if (loaded) {
          try {
            const bag = _readAllKeys();
            await window.svc.injector.inject({ keys: bag, tier: state.chosen_tier });
            toast(`${labelPrefix} applied.`, 'ok');
          } catch (e) {
            toast(`${labelPrefix}: saved but auto-reinject failed. Click Inject Now.`, 'err');
          }
        } else {
          toast(`${labelPrefix} saved. Click Inject Now to apply.`, 'ok');
        }
      }, 350);
    } catch (e) {
      toast(`Save failed: ${e.message || e}`, 'err');
    }
  };

  document.querySelectorAll('#overlay-appearance-card .ova-alpha-preset').forEach((chip) => {
    chip.addEventListener('click', () => {
      _ovaState.alpha = +chip.dataset.alpha;
      _ovaRefreshAll();
      _autoSaveAndReinject(`Opacity ${Math.round(_ovaState.alpha*100)}%`);
    });
  });

  document.querySelectorAll('#overlay-appearance-card .ova-theme-preset').forEach((chip) => {
    chip.addEventListener('click', () => {
      _ovaState.theme = +chip.dataset.theme;
      _ovaRefreshAll();
      const names = { 0: 'Dark', 1: 'Light', 2: 'Auto' };
      _autoSaveAndReinject(`Theme: ${names[_ovaState.theme] || 'Auto'}`);
    });
  });

  document.querySelectorAll('#overlay-appearance-card .ova-flag-toggle').forEach((chip) => {
    chip.addEventListener('click', () => {
      const bit = +chip.dataset.flag;
      /* v13 (2026-08-10): plain bit toggle. The old OPAQUE_LOCK auto-alpha
       * special-case is gone (that chip was removed; the flag is deprecated
       * and the payload ignores it). Opacity is slider-driven only. */
      _ovaState.overlay_flags ^= bit;
      _ovaRefreshAll();
      const label = chip.textContent.trim();
      const onOff = (_ovaState.overlay_flags & bit) ? 'ON' : 'OFF';
      _autoSaveAndReinject(`${label}: ${onOff}`);
    });
  });

  if (btnSave) {
    btnSave.addEventListener('click', async () => {
      if (btnSave.disabled) return;
      btnSave.disabled = true;
      try {
        const saved = await window.svc.overlay.save(_ovaState);
        if (saved) {
          _ovaSaved = { ..._ovaState };
          _ovaRenderStatus();
          toast('Overlay appearance saved. Click Inject Now to apply.', 'ok');
        } else {
          toast('Save failed \u2014 see console for details.', 'err');
        }
      } catch (e) {
        toast(`Save failed: ${e.message || e}`, 'err');
      } finally {
        _ovaRenderStatus();
      }
    });
  }
  if (btnReset) {
    btnReset.addEventListener('click', async () => {
      /* v1.3 (2026-07-07) — the confirm dialog now explains WHAT gets
       * reset AND that the overlay auto-reinjects if it's running. This
       * matters because reset used to look like a no-op: it only cleared
       * the launch config, leaving the payload's runtime tweaks
       * (overlay_state.bin) in place. Backend now clears both stores +
       * auto-reinjects when the payload is loaded. */
      if (!confirm(
        'Reset overlay appearance to defaults?\n\n' +
        'This clears:\n' +
        '  \u2022 Launch size (defaults to 560\u00d7420)\n' +
        '  \u2022 Alpha / opacity (defaults to 100% \u2014 opaque)\n' +
        '  \u2022 Theme (defaults to Auto \u2014 follows Windows)\n' +
        '  \u2022 Behavior flags (smooth-nudge + uniform-alpha ON)\n' +
        '  \u2022 Scroll + nudge step (defaults 80 / 48 px)\n' +
        '  \u2022 Ultra-size toggle (defaults to normal)\n' +
        '  \u2022 Payload runtime state (position, alpha bumps, font, corner)\n\n' +
        'If the overlay is currently injected, it will be re-injected\n' +
        'automatically so the reset is visible immediately.'
      )) return;
      btnReset.disabled = true;
      const oldLabel = btnReset.textContent;
      btnReset.textContent = 'Resetting\u2026';
      try {
        const p = await window.svc.overlay.reset();
        _ovaState = {
          size_mode: p.size_mode ? 1 : 0,
          w: +p.w, h: +p.h,
          alpha: +p.alpha,
          theme:         (p.theme != null ? (p.theme | 0) : 2),
          overlay_flags: (p.overlay_flags != null ? (p.overlay_flags | 0) : OVFLAG_DEFAULTS),
          /* v12/v13 — carry step granularities through reset so they don't
           * become undefined (would render "NaN px" + break dirty-check). */
          scroll_step_px: (p.scroll_step_px != null ? (+p.scroll_step_px | 0) : 80),
          nudge_step_px:  (p.nudge_step_px  != null ? (+p.nudge_step_px  | 0) : 48),
        };
        _ovaSaved = { ..._ovaState };
        if (chkUltra) chkUltra.checked = !!_ovaState.size_mode;
        _ovaRefreshAll();
        /* Toast reflects what actually happened server-side so the user
         * isn't left guessing. Toast supports only 'ok' + 'err' so the
         * "needs manual re-inject" case stays as 'ok' with a call-to-
         * action embedded in the message. */
        if (p.reinjected) {
          toast('Overlay reset to defaults.', 'ok');
        } else if (p.wasLoaded) {
          toast('Overlay reset. Re-inject skipped (no session/keys) \u2014 click Inject Now.', 'ok');
        } else {
          toast('Overlay reset. Click Inject Now to apply.', 'ok');
        }
      } catch (e) {
        toast(`Reset failed: ${e.message || e}`, 'err');
      } finally {
        btnReset.disabled = false;
        btnReset.textContent = oldLabel;
      }
    });
  }
}

// Init the overlay-appearance card at boot (safe to call before any
// screen is shown - it just reads state + wires listeners; the card
// itself only becomes visible when the dashboard renders).
_initOverlayCard().catch(e => console.log('[renderer] overlay card init:', e.message));

// ─── Inject / Uninject / Kill-all ──────────────────────────────
document.getElementById('btn-inject').addEventListener('click', async () => {
  const bag = _readAllKeys();
  const anyKey = bag.openai || bag.anthropic || bag.google || bag.openrouter;
  // No manual key is fine: injection falls back to CloakGPT credits
  // (managed AI via the metered /solve worker, billed against the signed-in
  // session). Just a heads-up toast, never a block.
  if (!anyKey) {
    toast('No API key set: using your CloakGPT credits.', 'ok');
  }
  // Persist immediately so a crash between Inject and background save
  // doesn't drop the newly-typed keys.
  await window.svc.apiKeys.save(bag);
  const configured = Object.entries(bag).filter(([, v]) => v).map(([k]) => k);
  showLoading(
    `Starting overlay…`,
    `Configured: ${configured.join(', ')}. First-time setup takes about 30 seconds; instant every time after.`
  );
  try {
    // v6: main.js reads persisted system-prompt + direct-mode when we
    // don't pass them here. Not overriding = using the settings the
    // user configured in the "AI answer style" card.
    const r = await window.svc.injector.inject({
      keys: bag,
      tier: state.chosen_tier,
    });
    hideLoading();
    if (r.ok) {
      state.injected = true;
      toast(`Overlay armed with ${configured.length} provider${configured.length === 1 ? '' : 's'} — hotkeys are live.`, 'ok');
      _refreshStatus();
    } else if (r.code === 'LAUNCHER_MISSING') {
      /* v2.0.2: soft recovery instead of a dead red toast — the app is still
       * fully open; only this Inject action needs the engine restored. */
      await _handleLauncherMissing(bag, configured);
    } else {
      const msg = _explainInjectExit(r.exitCode, r.err);
      toast(`Inject failed: ${msg}`, 'err');
    }
  } catch (e) {
    hideLoading();
    toast(`Inject failed: ${e.message || e}`, 'err');
  }
});

document.getElementById('btn-uninject').addEventListener('click', async () => {
  showLoading('Stopping overlay…', 'Shutting down cleanly.');
  try {
    const r = await window.svc.injector.uninject();
    hideLoading();
    if (r.ok) {
      state.injected = false;
      toast('Overlay stopped.', 'ok');
      _refreshStatus();
    } else {
      toast(`Stop returned code ${r.exitCode}. Overlay may already be off.`, 'err');
      _refreshStatus();
    }
  } catch (e) {
    hideLoading();
    toast(`Stop failed: ${e.message || e}`, 'err');
  }
});

document.getElementById('btn-killall').addEventListener('click', async () => {
  if (!confirm(
    'EMERGENCY STOP will:\n' +
    '  \u2022 shut the overlay down immediately\n' +
    '  \u2022 reset Windows\u2019 screen manager (auto-recovers in ~2 s)\n' +
    '  \u2022 close any of our background processes\n\n' +
    'Your screen will briefly go black. Continue?'
  )) return;
  showLoading('Emergency stopping…', 'Shutting everything down.');
  try {
    const r = await window.svc.injector.killAll();
    hideLoading();
    if (r.ok) {
      state.injected = false;
      toast('Everything stopped.', 'ok');
      _refreshStatus();
    } else {
      toast(`Emergency stop returned ${r.exitCode}.`, 'err');
    }
  } catch (e) {
    hideLoading();
    toast(`Emergency stop failed: ${e.message || e}`, 'err');
  }
});

/* v2.0.2 (2026-09-10): graceful recovery for a missing overlay engine
 * (sihost.exe). The #1 real-world cause of "Inject failed: launcher missing"
 * is antivirus quarantining the injector after install. Rather than a dead
 * red toast, we explain the likely cause, offer one-click repair from the
 * app's OWN bundled copy (no re-download), and retry the inject once if the
 * repair sticks. The dashboard itself stays fully usable throughout — this
 * only ever affects the Inject action, never opening the app. */
async function _handleLauncherMissing(bag, configured) {
  const go = confirm(
    "CloakGPT can't find some of its own files.\n\n" +
    "This is almost always your antivirus quarantining them. We ship spare " +
    "copies inside CloakGPT, so it can be restored without re-downloading anything.\n\n" +
    "Repair now and try again?"
  );
  if (!go) {
    toast('Skipped — click Inject Now anytime to repair and retry.', 'err');
    return;
  }
  showLoading('Repairing install…', 'Restoring files and re-checking antivirus exclusions.');
  let rep;
  try {
    rep = await window.svc.injector.repair();
  } catch (e) {
    hideLoading();
    toast(`Repair failed: ${e.message || e}`, 'err');
    return;
  }
  if (!rep || !rep.ok) {
    hideLoading();
    toast('Could not restore files \u2014 your antivirus is likely blocking them. Add a CloakGPT exclusion, then click Inject Now.', 'err');
    return;
  }
  // Repair stuck — retry the inject once with the same args.
  showLoading('Starting overlay…', 'Files restored. Starting up.');
  try {
    const r2 = await window.svc.injector.inject({ keys: bag, tier: state.chosen_tier });
    hideLoading();
    if (r2.ok) {
      state.injected = true;
      toast(`Repaired and started with ${configured.length} provider${configured.length === 1 ? '' : 's'} \u2014 hotkeys are live.`, 'ok');
      _refreshStatus();
    } else if (r2.code === 'LAUNCHER_MISSING') {
      toast('Antivirus re-removed our files immediately. Add a CloakGPT exclusion, then click Inject Now.', 'err');
    } else {
      toast(`Start failed after repair: ${_explainInjectExit(r2.exitCode, r2.err)}`, 'err');
    }
  } catch (e) {
    hideLoading();
    toast(`Start failed after repair: ${e.message || e}`, 'err');
  }
}

function _explainInjectExit(code, err) {
  if (err) return err;
  switch (code) {
    case 10: return 'Setup file missing (install issue).';
    case 11: return 'Setup file invalid (version mismatch).';
    case 12: return 'Could not write to install folder (check permissions).';
    case 13: return 'Overlay failed to start. Try again, or use Emergency stop and retry.';
    case  2: return 'Not running as administrator.';
    case  3: return 'API key missing.';
    default: return `exit ${code}`;
  }
}

// ─── Status polling ────────────────────────────────────────────
async function _refreshStatus() {
  try {
    const s = await window.svc.injector.status();
    state.injected = !!s.payload_loaded;
    // main.js already latches payload_loaded through transient 'unknown'
    // probes; this flag only drives a neutral "verifying…" hint at cold
    // start when there is no definitive read yet (e.g. a WDAC/Constrained-
    // Language box or an AV scan storm) so we never show a false
    // "Not Injected" while the overlay is actually alive.
    state.payloadUnverified = (s.payload_state === 'unknown') && !s.payload_loaded;
  } catch (e) {
    console.log('[renderer] status failed:', e.message);
  }
  _renderStatus();
}
function _renderStatus() {
  // Payload status block
  const dot   = document.getElementById('d-status-dot');
  const title = document.getElementById('d-status-title');
  const sub   = document.getElementById('d-status-sub');
  dot.classList.remove('on', 'error');
  if (state.injected) {
    dot.classList.add('on');
    title.textContent = 'Overlay: Active';
    /* v16 (2026-09-22) -- ask hotkey is user-configurable (SVC_HK_ASK = 0);
     * pull the current binding via _hotkeyLabelFor so this text stays truthful
     * across rebinds + across the two default sets (aggressive vs legacy). */
    const askHk = _hotkeyLabelFor(0, 'Ctrl+U');
    sub.textContent = 'Overlay is on. Hotkeys are live \u2014 ' + askHk + ' to ask AI.';
    document.getElementById('btn-inject').disabled = true;
    document.getElementById('btn-uninject').disabled = false;
  } else if (state.payloadUnverified) {
    // Probe couldn't get a definitive answer (locked-down PowerShell / AV
    // scan). Do NOT claim "Off" — that's the false-negative bug.
    title.textContent = 'Overlay: Checking\u2026';
    sub.textContent = 'Couldn\u2019t confirm the overlay status right now. If your overlay is on screen, it\u2019s still running.';
    document.getElementById('btn-inject').disabled = false;
    document.getElementById('btn-uninject').disabled = false;
  } else {
    title.textContent = 'Overlay: Off';
    sub.textContent = 'Click Inject to start the overlay.';
    document.getElementById('btn-inject').disabled = false;
    document.getElementById('btn-uninject').disabled = true;
  }
  // Badges — LDB badge removed; only payload heartbeat + session left
  const dwmDot = document.getElementById('d-badge-dwm-dot');
  dwmDot.classList.remove('on', 'error');
  if (state.injected) dwmDot.classList.add('on');
  document.getElementById('d-badge-dwm').textContent = state.injected ? 'Alive' : 'Offline';

  const s = state.session || {};
  document.getElementById('d-badge-session').textContent = s.expires_at ? _formatExpiry(s.expires_at) : '—';
}

let _pollTimer = null;
function pollStatusLoop() {
  clearInterval(_pollTimer);
  _refreshStatus();
  _pollTimer = setInterval(_refreshStatus, 3500);
}

// v3 (2026-09-19): with backgroundThrottling=true (main.js) the renderer's
// timers slow to ~1/s while the window is hidden. Refresh immediately on
// hidden->visible so the dashboard is fresh the moment the user restores it,
// without waiting the throttled interval. Also toggle body.bg-paused which
// pauses every decorative CSS keyframe animation while hidden (belt+braces
// on top of Chromium's throttling -- audit item 5). No-op if the dashboard
// isn't active (showScreen clears _pollTimer when we leave).
document.addEventListener('visibilitychange', () => {
  const hidden = document.visibilityState !== 'visible';
  try { document.body.classList.toggle('bg-paused', hidden); } catch (_) {}
  if (!hidden && _pollTimer) {
    try { _refreshStatus(); } catch (_) {}
  }
});

// ─── Export encrypted logs for support ────────────────────────
document.getElementById('btn-export-logs').addEventListener('click', async () => {
  showLoading('Exporting logs…', 'Copying encrypted diag files + zipping to Desktop.');
  try {
    const r = await window.svc.logs.export();
    hideLoading();
    if (r.ok) {
      const fname = r.path.split(/[\\/]/).pop();
      toast(`Exported ${r.files} files (${r.size_kb} KB) → ${fname}. Explorer opened to show it.`, 'ok');
    } else {
      toast(`Export failed: ${r.err}`, 'err');
    }
  } catch (e) {
    hideLoading();
    toast(`Export failed: ${e.message || e}`, 'err');
  }
});

// ─── Push events from main process ─────────────────────────────
// Main revalidates the subscription every hour + auto-refreshes the
// access token when near expiry. Two events can arrive:
//
//   session-updated  → main just refreshed; update dashboard's expiry pill
//   expired-lockout  → sub inactive OR 3 consecutive network failures;
//                      main already uninjected + cleared session, now we
//                      show the login screen with a red banner.
if (window.svc && typeof window.svc.on === 'function') {
  window.svc.on('license:session-updated', (dto) => {
    if (!dto || !dto.session) return;
    state.session = dto.session;
    if (dto.subscription) state.subscription = dto.subscription;
    _renderDashboard();
  });
  /* v1.6.3: DWM crashed + respawned; main auto-re-injected the payload
   * with the same args. Nothing for the user to do; just let them know
   * their overlay recovered so they don't panic + manually re-inject. */
  window.svc.on('injector:respawn-recovered', () => {
    toast('Windows recovered \u2014 overlay restarted automatically.', 'ok');
  });
  window.svc.on('license:expired-lockout', (info) => {
    state.injected = false;
    clearInterval(_pollTimer);
    const reason = (info && info.reason) || 'unknown';

    // v4.9: server-side has no suspension concept anymore (see
    // subscription.js header). The `subscription_suspended` branch is
    // kept dormant below — it will never fire but if we ever add
    // server-side suspensions it's ready.
    if (reason === 'subscription_suspended') {
      const preserved = info.preservedSession || {};
      state.session = {
        email: preserved.email || '',
        display_name: preserved.display_name || '',
        avatar_url: preserved.avatar_url || null,
      };
      const susp = {
        status: 'suspended',
        suspension_reason: info.suspensionInfo?.suspension_reason || null,
        suspended_at: info.suspensionInfo?.suspended_at || null,
        _preservedEmail: preserved.email,
      };
      state.subscription = susp;
      _renderSuspended(susp);
      showScreen('suspended');
      toast('Account was suspended — see reason on screen.', 'err');
      return;
    }

    state.session = null; state.subscription = null;
    _renderLoginDeviceId();
    let msg = 'Your session was locked out.';
    if (reason === 'subscription_inactive') {
      msg = 'Your CloakGPT subscription is no longer active. The overlay has been unloaded. Please renew and sign in again.';
    } else if (reason.startsWith('too_many_failures')) {
      msg = 'Could not reach the license server after several attempts. The overlay has been unloaded for safety. Sign in again once you have a stable connection.';
    } else if (reason === 'license_server_schema_error') {
      // v4.9: PostgREST returned 42703 (column does not exist) — this is a
      // client/server schema mismatch, not the user's fault. Show a
      // support-contact message instead of the generic "renew subscription".
      const err = info && info.serverError;
      const code = err ? `SCHEMA_${err.endpoint || 'unknown'}_${err.statusCode || '?'}` : 'SCHEMA_UNKNOWN';
      msg = `License server error — a schema mismatch is preventing verification. Please contact support@cloakgpt.ca with code ${code}. This is not a subscription problem; DO NOT renew.`;
    }
    showLoginError(msg);
    showScreen('login');
    toast('Signed out automatically — see banner for details.', 'err');
  });
}

// ═══════════════════════════════════════════════════════════════
//  Hotkey Editor
// ═══════════════════════════════════════════════════════════════
//
// The 32 payload hotkey slots (svc_hotkey_action_t enum) each have a
// default binding from injector.js DEFAULT_HOTKEYS. Users can override
// any slot; the override is persisted to appData/hotkeys.json via the
// hotkeys:save IPC and merged into DEFAULT_HOTKEYS at inject time in
// main.js. So changes take effect on the NEXT Inject click (not
// hot-reloaded into the running payload — that would require a re-arm).
//
// Rendering: two-column grid of "action name → current binding button".
// Click a binding to open the record modal. Record modal grabs all
// keydown events until Esc (cancel), Enter (save current combo), or a
// valid printable-key + modifier combo is captured.

const HK_LABELS = [
  'Screenshot + Ask AI',        // 0  SVC_HK_ASK
  'Toggle overlay',             // 1  SVC_HK_TOGGLE
  'Chat mode (type)',           // 2  SVC_HK_TYPING
  'Copy full reply',            // 3  SVC_HK_COPY_REPLY
  'Clear reply / quit',         // 4  SVC_HK_CLEAR
  'Nudge left',                 // 5
  'Nudge right',                // 6
  'Nudge up',                   // 7
  'Nudge down',                 // 8
  'Resize wider',               // 9
  'Resize narrower',            // 10
  'Resize taller',              // 11
  'Resize shorter',             // 12
  'Cycle corner',               // 13
  'Opacity +',                  // 14
  'Opacity -',                  // 15
  'Font +',                     // 16
  'Font -',                     // 17
  'Reset geometry',             // 18
  'Debug capture',              // 19
  'EMERGENCY STOP',             // 20
  'Scroll reply up',            // 21
  'Scroll reply down',          // 22
  'New chat',                   // 23
  'Cycle model tier',           // 24
  'Cycle provider',             // 25
  'Regenerate last reply',      // 26
  'Toggle streaming',           // 27
  'Copy code only',             // 28
  'Copy first-line answer',     // 29
  'Toggle LaTeX',               // 30
  'Stop AI response',           // 31
  'Direct-answer mode',         // 32
  'Quick-Ask (mouse-hold, opt-in)', // 33 — v1.7.4.17, BP parity
];

// Human-readable names for every VK we might encounter. Modifier keys
// use the L/R distinction because that's what LONGPRESS needs to bind
// to — "Right Shift" and "Left Shift" are treated as distinct keys.
const VK_TO_NAME = {
  0x08: 'Backspace', 0x09: 'Tab', 0x0D: 'Enter', 0x1B: 'Esc',
  0x14: 'Caps Lock', 0x20: 'Space',
  0x25: 'Left Arrow', 0x26: 'Up Arrow', 0x27: 'Right Arrow', 0x28: 'Down Arrow',
  0x2D: 'Insert', 0x2E: 'Delete', 0x23: 'End', 0x24: 'Home',
  0x21: 'Page Up', 0x22: 'Page Down',
  0x5B: 'Left Windows', 0x5C: 'Right Windows', 0x5D: 'Menu',
  0x70: 'F1', 0x71: 'F2', 0x72: 'F3', 0x73: 'F4', 0x74: 'F5', 0x75: 'F6',
  0x76: 'F7', 0x77: 'F8', 0x78: 'F9', 0x79: 'F10', 0x7A: 'F11', 0x7B: 'F12',
  0x90: 'Num Lock', 0x91: 'Scroll Lock',
  0xA0: 'Left Shift', 0xA1: 'Right Shift',
  0xA2: 'Left Ctrl',  0xA3: 'Right Ctrl',
  0xA4: 'Left Alt',   0xA5: 'Right Alt',
  0xBA: 'Semicolon (;)', 0xBB: 'Equals (=)', 0xBC: 'Comma (,)',
  0xBD: 'Minus (-)', 0xBE: 'Period (.)', 0xBF: 'Slash (/)',
  0xC0: 'Backtick (`)',
  0xDB: 'Left Bracket ([)', 0xDC: 'Backslash (\\)', 0xDD: 'Right Bracket (])',
  0xDE: "Quote (')",
};

// Map a browser `event.code` / `event.key` to a Windows VK code.
// Falls back to charCodeAt for printable A-Z / 0-9.
function eventToVk(e) {
  const key = (e.key || '').toUpperCase();
  const code = e.code || '';
  // Printable letters / digits.
  if (key.length === 1 && /[A-Z0-9]/.test(key)) return key.charCodeAt(0);
  // Function keys.
  if (/^F(\d+)$/i.test(code)) {
    const n = parseInt(code.slice(1), 10);
    if (n >= 1 && n <= 12) return 0x70 + (n - 1);
  }
  const map = {
    'Space': 0x20, 'Enter': 0x0D, 'Tab': 0x09, 'Backspace': 0x08,
    'Escape': 0x1B, 'Delete': 0x2E, 'Insert': 0x2D,
    'Home': 0x24, 'End': 0x23, 'PageUp': 0x21, 'PageDown': 0x22,
    'ArrowLeft': 0x25, 'ArrowUp': 0x26, 'ArrowRight': 0x27, 'ArrowDown': 0x28,
    'Minus': 0xBD, 'Equal': 0xBB, 'BracketLeft': 0xDB, 'BracketRight': 0xDD,
    'Backslash': 0xDC, 'Semicolon': 0xBA, 'Quote': 0xDE, 'Comma': 0xBC,
    'Period': 0xBE, 'Slash': 0xBF, 'Backquote': 0xC0,
    // Modifier keys distinguished by side — needed so users can bind
    // long-press "Right Shift" (0xA1) vs "Left Shift" (0xA0).
    'ShiftLeft':   0xA0, 'ShiftRight':   0xA1,
    'ControlLeft': 0xA2, 'ControlRight': 0xA3,
    'AltLeft':     0xA4, 'AltRight':     0xA5,
    'CapsLock':    0x14, 'NumLock':      0x90, 'ScrollLock': 0x91,
    'MetaLeft':    0x5B, 'MetaRight':    0x5C, 'ContextMenu': 0x5D,
  };
  if (map[code]) return map[code];
  if (map[key]) return map[key];
  return 0;
}

// v10 (2026-07-17): binding-kind support. Mirror of shared/config_types.h.
const HK_KIND_MODIFIER    = 0;
const HK_KIND_LONGPRESS   = 1;
const HK_KIND_MULTITAP    = 2;
const HK_KIND_DISABLED    = 3;
/* v1.7.4 (2026-07-23): mouse-button binding kinds. Match
 * shared/config_types.h `SVC_HK_KIND_MOUSE_*`. Users can bind a slot
 * to holding LMB/RMB/MMB/X1/X2 for N ms, or N clicks within gap. */
const HK_KIND_MOUSE_HOLD  = 4;
const HK_KIND_MOUSE_MULTI = 5;
const HK_FLAG_WATCH_ONLY  = 0x10000000;
const HK_FLAG_ADAPTIVE    = 0x20000000;

/* Mouse VK codes (match Windows VK_LBUTTON..VK_XBUTTON2). */
const MOUSE_VK = {
  LMB: 1, RMB: 2, MMB: 4, XB1: 5, XB2: 6,
};
const MOUSE_VK_LABEL = {
  1: 'Left mouse button',
  2: 'Right mouse button',
  4: 'Middle mouse button (wheel click)',
  5: 'Mouse button 4 (back / X1)',
  6: 'Mouse button 5 (forward / X2)',
};
const MOUSE_VK_SHORT = { 1: 'LMB', 2: 'RMB', 4: 'MMB', 5: 'MX1', 6: 'MX2' };

/* Max tap count exposed in the UI. Payload nibble supports 15 but 6 is
 * the realistic UX ceiling — LO's ask. */
const HK_TAP_MAX = 6;

/* v1.7.11.18 (2026-07-25) — packHotkey accepts optional `watch` flag.
 * When true, sets the WATCH-ONLY bit so the C-side LL hook fires the
 * action but doesn't consume the key event (lets it pass through to
 * the focused app). Enables "Ctrl+A as both copy-answer AND select-all"
 * kind of setups. */
function packHotkey(mod, vk, watch) {
  let out = ((mod & 0xFF) << 16) | (vk & 0xFFFF);
  if (watch) out |= HK_FLAG_WATCH_ONLY;
  return out >>> 0;
}
function packLongpress(vk, hold_ms) {
  const h = Math.max(10, Math.min(2550, Math.floor(hold_ms / 10) * 10));
  return (HK_KIND_LONGPRESS << 24) | (((h / 10) & 0xFF) << 16) | (vk & 0xFFFF);
}
function packMultitap(vk, count, gap_ms, watch, adaptive) {
  const c = Math.max(1, Math.min(15, count | 0));
  const g = Math.max(0, Math.min(15, Math.floor(gap_ms / 50)));
  let out = (HK_KIND_MULTITAP << 24) | (((g << 4) | c) << 16) | (vk & 0xFFFF);
  if (watch)    out |= HK_FLAG_WATCH_ONLY;
  if (adaptive) out |= HK_FLAG_ADAPTIVE;
  return out >>> 0;
}
/* v1.7.4: pack a mouse-hold binding — hold mouse-button `mvk` for
 * hold_ms ms to fire the action. mvk ∈ {1,2,4,5,6}. */
function packMouseHold(mvk, hold_ms) {
  const h = Math.max(10, Math.min(2550, Math.floor(hold_ms / 10) * 10));
  return ((HK_KIND_MOUSE_HOLD << 24) | (((h / 10) & 0xFF) << 16) | (mvk & 0xFFFF)) >>> 0;
}
/* v1.7.4: pack a mouse-multi-click binding — N clicks of button
 * `mvk` within gap_ms ms fires the action. */
function packMouseMulti(mvk, count, gap_ms) {
  const c = Math.max(1, Math.min(15, count | 0));
  const g = Math.max(0, Math.min(15, Math.floor(gap_ms / 50)));
  return ((HK_KIND_MOUSE_MULTI << 24) | (((g << 4) | c) << 16) | (mvk & 0xFFFF)) >>> 0;
}

function unpackHotkey(packed) {
  const kind = (packed >>> 24) & 0x0F;
  const extra = (packed >>> 16) & 0xFF;
  const vk = packed & 0xFFFF;
  const watch    = (packed & HK_FLAG_WATCH_ONLY) !== 0;
  const adaptive = (packed & HK_FLAG_ADAPTIVE)   !== 0;
  if (kind === HK_KIND_MODIFIER) {
    return { kind, vk, mod: extra, watch, adaptive };
  }
  if (kind === HK_KIND_LONGPRESS) {
    return { kind, vk, hold_ms: extra * 10, watch, adaptive };
  }
  if (kind === HK_KIND_MULTITAP) {
    return { kind, vk, count: extra & 0x0F, gap_ms: ((extra >>> 4) & 0x0F) * 50, watch, adaptive };
  }
  if (kind === HK_KIND_MOUSE_HOLD) {
    return { kind, vk, hold_ms: extra * 10, watch, adaptive };
  }
  if (kind === HK_KIND_MOUSE_MULTI) {
    return { kind, vk, count: extra & 0x0F, gap_ms: ((extra >>> 4) & 0x0F) * 50, watch, adaptive };
  }
  return { kind, vk, watch, adaptive };
}

function _vkName(vk) {
  return VK_TO_NAME[vk] || (vk >= 0x30 && vk <= 0x5A
    ? String.fromCharCode(vk)
    : `0x${vk.toString(16).toUpperCase()}`);
}

function formatHotkey(packed) {
  if (!packed) return '(unbound)';
  const u = unpackHotkey(packed);
  if (u.kind === HK_KIND_DISABLED) return '(disabled)';
  if (u.kind === HK_KIND_MODIFIER) {
    const parts = [];
    if (u.mod & 1) parts.push('Ctrl');
    if (u.mod & 2) parts.push('Shift');
    if (u.mod & 4) parts.push('Alt');
    parts.push(_vkName(u.vk));
    return parts.join('+');
  }
  if (u.kind === HK_KIND_LONGPRESS) {
    const secs = (u.hold_ms / 1000).toFixed(1).replace(/\.0$/, '');
    return `Hold ${_vkName(u.vk)} for ${secs}s`;
  }
  if (u.kind === HK_KIND_MULTITAP) {
    const words = ['once','twice','three times','four times','five times','six times','seven times'];
    const times = u.count >= 2 && u.count <= 7 ? words[u.count - 1] : `${u.count} times`;
    /* v1.7.4.9: no more inline "(silent)" — the per-row mode chip carries
     * that info explicitly + more clearly. Keeps the binding text short so
     * it doesn't truncate in the row layout. */
    return `Tap ${_vkName(u.vk)} ${times}`;
  }
  /* v1.7.4: mouse bindings — user-friendly labels. */
  if (u.kind === HK_KIND_MOUSE_HOLD) {
    const secs = (u.hold_ms / 1000).toFixed(1).replace(/\.0$/, '');
    const btn = MOUSE_VK_LABEL[u.vk] || `mouse vk=${u.vk}`;
    return `Hold ${btn} for ${secs}s`;
  }
  if (u.kind === HK_KIND_MOUSE_MULTI) {
    const words = ['once','twice','three times','four times','five times','six times','seven times'];
    const times = u.count >= 2 && u.count <= 7 ? words[u.count - 1] : `${u.count} times`;
    const btn = MOUSE_VK_LABEL[u.vk] || `mouse vk=${u.vk}`;
    return `Click ${btn} ${times}`;
  }
  return `?kind${u.kind}`;
}

/* Categorize a captured binding for the risk-analysis disclaimer.
 * Returns { level: 'safe'|'caution'|'high'|'very-high', reason: string } */
function riskAnalyze(packed) {
  if (!packed) return { level: 'safe', reason: 'unbound' };
  const u = unpackHotkey(packed);
  if (u.kind === HK_KIND_MODIFIER) {
    if (!u.mod) {
      // Single letter/digit/punct without modifier — very high FP
      if (u.vk >= 0x30 && u.vk <= 0x5A) {
        return { level: 'very-high', reason: `This will fire every time you type <b>${_vkName(u.vk)}</b> — including in your exam. Add Ctrl or Alt, or switch to a triple-tap.` };
      }
      if ((u.vk >= 0xBA && u.vk <= 0xC0) || (u.vk >= 0xDB && u.vk <= 0xDE)) {
        return { level: 'high', reason: `This will fire whenever you type that character (in code, math answers, etc.). Add a modifier or use triple-tap instead.` };
      }
    }
    return { level: 'safe', reason: `Fires when you press ${formatHotkey(packed)}.` };
  }
  if (u.kind === HK_KIND_LONGPRESS) {
    if (u.vk >= 0x30 && u.vk <= 0x5A && u.hold_ms < 500) {
      return { level: 'caution', reason: `Under half a second on a letter key may fire when you type fast. Try 700ms or bind to a modifier key like Right Shift.` };
    }
    const secs = (u.hold_ms / 1000).toFixed(1).replace(/\.0$/, '');
    return { level: 'safe', reason: `Hold ${_vkName(u.vk)} by itself for ${secs}s to fire. Pressing any other key during the hold cancels it.` };
  }
  if (u.kind === HK_KIND_MULTITAP) {
    if (u.count === 1 && u.vk >= 0x30 && u.vk <= 0x5A) {
      return { level: 'very-high', reason: `1 tap on a letter fires on every keystroke of <b>${_vkName(u.vk)}</b>. Use at least 3 taps.` };
    }
    if (u.count === 2 && u.watch && u.vk >= 0x30 && u.vk <= 0x5A) {
      return { level: 'high', reason: `Double-tapping a letter fires on common typos like "gg" or "aa". Bump to 3+ taps for safety.` };
    }
    if (!u.watch && u.vk >= 0x30 && u.vk <= 0x5A) {
      return { level: 'caution', reason: `Blocked mode reserves the letter — you won't be able to type <b>${_vkName(u.vk)}</b> anywhere while CloakGPT is armed.` };
    }
    return { level: 'safe', reason: u.watch
      ? `Tap ${_vkName(u.vk)} ${u.count} times quickly. The key still types normally in your app.`
      : `Tap ${_vkName(u.vk)} ${u.count} times quickly. Rare key, safe to reserve.` };
  }
  /* v1.7.4: mouse binding risk analysis. */
  if (u.kind === HK_KIND_MOUSE_HOLD) {
    const btn = MOUSE_VK_LABEL[u.vk] || `mouse vk=${u.vk}`;
    if (u.hold_ms < 400 && (u.vk === 1 || u.vk === 2)) {
      return { level: 'caution', reason: `Under 400ms on ${btn} may fire during normal click-and-drag or double-click. Try 800ms+ for safety.` };
    }
    if (u.hold_ms < 700 && u.vk === 1) {
      return { level: 'caution', reason: `Left-click holds under 700ms can trigger during text selection. Prefer Right/Middle/X1/X2 or 1000ms+ hold time.` };
    }
    const secs = (u.hold_ms / 1000).toFixed(1).replace(/\.0$/, '');
    return { level: 'safe', reason: `Hold ${btn} for ${secs}s to fire. Normal single-click ignored. No keyboard activity \u2014 the most discreet hotkey type.` };
  }
  if (u.kind === HK_KIND_MOUSE_MULTI) {
    const btn = MOUSE_VK_LABEL[u.vk] || `mouse vk=${u.vk}`;
    if (u.count === 1) {
      return { level: 'very-high', reason: `1 click of ${btn} fires on every click. Effectively unusable. Use 2+ clicks.` };
    }
    if (u.count === 2 && u.vk === 1) {
      return { level: 'caution', reason: `Double-left-click matches Windows' double-click gesture — will fire when you double-click ANYTHING. Consider triple-click or a different button.` };
    }
    return { level: 'safe', reason: `Click ${btn} ${u.count} times within ${(u.gap_ms/1000).toFixed(2)}s to fire. Best for keyboard-conscious environments.` };
  }
  return { level: 'safe', reason: '' };
}

let _hkState = { defaults: [], overrides: {}, stealth_overrides: {}, speed_mode: 'adaptive' };
let _hkRecording = null;   // { slot } while a modal is open

async function _loadHotkeys() {
  const r = await window.svc.hotkeys.load();
  _hkState.defaults  = r.defaults || [];
  _hkState.overrides = r.overrides || {};
  _hkState.stealth_overrides = r.stealth_overrides || {};
  _hkState.speed_mode = r.speed_mode || 'adaptive';
  _renderHotkeyEditor();
  /* v16 -- push fresh bindings into every [data-hk] label in the DOM AND
   * refresh the dashboard status sub if the payload is showing "armed". */
  try { _applyHotkeyLabels(); } catch {}
  try { if (state && state.injected) _renderStatus(); } catch {}
}

/* v10 (2026-07-17): stealth mode = every slot in stealth_overrides
 * currently has an override matching the stealth binding. Detects
 * "user has applied stealth mode" state without persisting a separate
 * flag — the override values themselves are the source of truth. */
function _isStealthActive() {
  const st = _hkState.stealth_overrides || {};
  const ov = _hkState.overrides || {};
  const keys = Object.keys(st);
  if (keys.length === 0) return false;
  for (const k of keys) {
    if ((ov[k] >>> 0) !== (st[k] >>> 0)) return false;
  }
  return true;
}

// Effective binding for a slot: override wins, else default.
function _bindingFor(slot) {
  if (Object.prototype.hasOwnProperty.call(_hkState.overrides, slot)) {
    return _hkState.overrides[slot];
  }
  return _hkState.defaults[slot] || 0;
}

/* v16 (2026-09-22) -- Dynamic hotkey label for UI text that references the
 * user's real binding. Returns a formatted string (e.g. "Ctrl+U", "Tap G three
 * times", "Hold Left Click for 2.0s") or the caller's fallback if hotkeys
 * haven't loaded yet OR the slot is unbound. Never returns "(unbound)" so UI
 * copy stays readable even mid-load. */
function _hotkeyLabelFor(slot, fallback) {
  const loaded = _hkState && Array.isArray(_hkState.defaults) && _hkState.defaults.length > 0;
  if (!loaded) return fallback;
  const packed = _bindingFor(slot);
  if (!packed) return fallback;
  const s = formatHotkey(packed);
  return (s === '(unbound)' || s === '(disabled)') ? fallback : s;
}

/* v16 -- Walk every [data-hk="N"] / [data-hk-fallback="..."] element and
 * replace its textContent with the current binding label for slot N (fallback
 * text preserved if unbound / not loaded). Called after _loadHotkeys() and
 * whenever hotkeys change so any static HTML that references a hotkey stays
 * truthful. Elements MUST have data-hk-fallback set; without it the mechanism
 * assumes the element's initial textContent is the fallback and captures it
 * on first sweep. */
function _applyHotkeyLabels() {
  const nodes = document.querySelectorAll('[data-hk]');
  for (const n of nodes) {
    const slot = Number(n.getAttribute('data-hk'));
    if (!Number.isFinite(slot)) continue;
    if (!n.hasAttribute('data-hk-fallback')) {
      n.setAttribute('data-hk-fallback', n.textContent || '');
    }
    const fb = n.getAttribute('data-hk-fallback') || '';
    n.textContent = _hotkeyLabelFor(slot, fb);
  }
}

// Which slots share the same packed binding as `packed`?
// Returns array of slot indices; excludes `except`.
function _slotsMatching(packed, except) {
  const out = [];
  const total = Math.max(_hkState.defaults.length, 32);
  for (let s = 0; s < total; s++) {
    if (s === except) continue;
    if (_bindingFor(s) === packed) out.push(s);
  }
  return out;
}

function _renderHotkeyEditor() {
  const root = document.getElementById('hk-editor');
  if (!root) return;
  root.innerHTML = '';

  /* v1.7.4.9 (2026-07-24): compact controls row containing BOTH the
   * speed picker and the invisible-hotkeys toggle. Prior design put
   * these as two full-width stacked banners eating half the card
   * before the user could even see any hotkey rows. */
  const speed = _hkState.speed_mode || 'adaptive';
  const stealthActive = _isStealthActive();
  const controlsRow = document.createElement('div');
  controlsRow.className = 'hk-controls-row';
  const speedOpts = [
    { id: 'fast',     label: 'Fast' },
    { id: 'normal',   label: 'Normal' },
    { id: 'slow',     label: 'Slow' },
    { id: 'adaptive', label: 'Adaptive' },
  ];
  const speedSub = {
    fast:     'Quick taps &amp; short holds.',
    normal:   'Balanced. Most people.',
    slow:     'More time to complete.',
    adaptive: 'Learns your rhythm live.',
  }[speed] || '';
  controlsRow.innerHTML = `
    <div class="hk-speed-picker">
      <div class="hk-speed-head">
        <div class="hk-speed-title">Speed</div>
        <div class="hk-speed-sub">${speedSub}</div>
      </div>
      <div class="hk-speed-buttons">
        ${speedOpts.map(o => `
          <button class="hk-speed-btn${o.id === speed ? ' active' : ''}" data-speed="${o.id}">${o.label}</button>
        `).join('')}
      </div>
    </div>
    <div class="hk-stealth-banner${stealthActive ? ' active' : ''}">
      <div class="hk-stealth-head">
        <div style="min-width:0;">
          <div class="hk-stealth-title">Invisible Hotkeys ${stealthActive ? '<span class="hk-stealth-on">ON</span>' : ''}</div>
          <div class="hk-stealth-sub">
            ${stealthActive
              ? 'Your shortcuts don\'t use Ctrl / Alt / Shift &mdash; keeps your typing discreet.'
              : 'Switches shortcuts to typing-like patterns. <b>Recommended for exams.</b>'}
          </div>
        </div>
        <label class="hk-toggle-switch">
          <input type="checkbox" id="hk-stealth-toggle" ${stealthActive ? 'checked' : ''}>
          <span class="hk-toggle-slider"></span>
        </label>
      </div>
    </div>
  `;
  root.appendChild(controlsRow);
  for (const btn of controlsRow.querySelectorAll('.hk-speed-btn')) {
    btn.addEventListener('click', async () => {
      const mode = btn.dataset.speed;
      _hkState.speed_mode = mode;
      const r = await window.svc.hotkeys.saveSpeed(mode);
      if (r && r.ok) {
        toast(`Shortcut speed: ${mode.charAt(0).toUpperCase() + mode.slice(1)} — click Inject Now to apply.`, 'ok');
      } else {
        toast('Save failed.', 'err');
      }
      _renderHotkeyEditor();
    });
  }
  document.getElementById('hk-stealth-toggle').addEventListener('change', (e) => {
    if (e.target.checked) {
      e.target.checked = false;   // wait for modal confirm
      _openStealthEnableModal();
    } else {
      _disableStealthMode();
    }
  });

  const total = Math.max(_hkState.defaults.length, 32);
  for (let slot = 0; slot < total; slot++) {
    const label = HK_LABELS[slot] || `Slot ${slot}`;
    if (!label || label.startsWith('Slot ') && !_hkState.defaults[slot]) continue;
    const packed = _bindingFor(slot);
    const isOverride = Object.prototype.hasOwnProperty.call(_hkState.overrides, slot);
    const conflicts = packed ? _slotsMatching(packed, slot) : [];
    const row = document.createElement('div');
    row.className = 'hk-editor-row' + (conflicts.length > 0 ? ' conflict' : '');
    row.dataset.slot = String(slot);
    const btnLabel = packed ? formatHotkey(packed) : '(unbound)';
    const pencilSvg = `<svg class="hk-pencil" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>`;
    /* v1.7.4.6 (2026-07-24): per-row watch/consume toggle for MULTITAP
     * bindings. LO's ask: "there should be an OPTION to swallow fully vs
     * watch only rn zero option is given at least by default make it
     * watch only". Default IS watch-only, but users couldn't SEE the
     * option without opening the recorder modal. This chip lets them
     * flip it in place with a single click. Only rendered for MULTITAP
     * kinds — modifier/longpress/mouse don't consume the way multitap
     * does (they either fire on hold-release or on click, not on every
     * key edge). */
    let modeChipHtml = '<span></span>';   /* placeholder keeps grid alignment */
    if (packed) {
      const u = unpackHotkey(packed);
      /* v1.7.11.18 (2026-07-25) — MODIFIER kind now honors the chip too.
       * User asked to be able to run Ctrl+A as both "copy answer" AND
       * regular select-all. When flipped to silent, the LL hook fires
       * the action but doesn't consume the keystroke — apps still see
       * their normal Ctrl+A. */
      if (u.kind === HK_KIND_MULTITAP || u.kind === HK_KIND_MODIFIER) {
        const isWatch = !!u.watch;
        const chipCls = isWatch ? 'hk-mode-chip hk-mode-silent' : 'hk-mode-chip hk-mode-blocked';
        const chipLabel = isWatch ? 'silent' : 'blocks';
        const isMod = u.kind === HK_KIND_MODIFIER;
        const chipTitle = isWatch
          ? (isMod
              ? 'Silent mode — key still works normally in apps (Ctrl+A still selects-all, plus fires this action). Click to switch to BLOCKED.'
              : 'Silent mode — the key still types normally in your exam. Click to switch to BLOCKED (reserves the key).')
          : (isMod
              ? 'BLOCKED mode — key is intercepted, apps don\'t see it. Click to switch to SILENT (fires action AND lets key through).'
              : 'BLOCKED mode — the key is reserved and won\'t type anywhere. Click to switch to SILENT.');
        modeChipHtml = `<button class="${chipCls}" title="${escapeHtml(chipTitle)}" data-slot-mode-toggle="${slot}">${chipLabel}</button>`;
      }
    }
    const resetHtml = isOverride
      ? `<button class="hk-editor-clear" title="Reset to default (${escapeHtml(formatHotkey(_hkState.defaults[slot]))})">↺</button>`
      : `<span class="hk-editor-clear-placeholder"></span>`;
    row.innerHTML = `
      <div class="hk-editor-label" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
      ${modeChipHtml}
      <button class="hk-editor-btn${!packed ? ' unbound' : ''}" title="Click to remap${conflicts.length ? ' — CONFLICT with slot ' + conflicts.join(', ') : ''}">
        <span class="hk-editor-btn-text">${escapeHtml(btnLabel)}</span>
        ${pencilSvg}
      </button>
      ${resetHtml}
    `;
    root.appendChild(row);
  }
  for (const btn of root.querySelectorAll('.hk-editor-btn')) {
    btn.addEventListener('click', (e) => {
      const slot = parseInt(e.currentTarget.closest('.hk-editor-row').dataset.slot, 10);
      _openHotkeyRecorder(slot);
    });
  }
  for (const btn of root.querySelectorAll('.hk-editor-clear')) {
    btn.addEventListener('click', async (e) => {
      const slot = parseInt(e.currentTarget.closest('.hk-editor-row').dataset.slot, 10);
      delete _hkState.overrides[slot];
      await window.svc.hotkeys.save(_hkState.overrides);
      _renderHotkeyEditor();
      toast(`Reset ${HK_LABELS[slot]} to default.`, 'ok');
    });
  }
  /* v1.7.4.6: per-row silent/blocked toggle. Handles MULTITAP + (as of
   * v1.7.11.18) MODIFIER kinds. Other kinds don't render the chip. */
  for (const chip of root.querySelectorAll('[data-slot-mode-toggle]')) {
    chip.addEventListener('click', async (e) => {
      e.stopPropagation();
      const slot = parseInt(chip.dataset.slotModeToggle, 10);
      const current = _bindingFor(slot);
      const u = unpackHotkey(current);
      let newPacked = null;
      const newWatch = !u.watch;
      if (u.kind === HK_KIND_MULTITAP) {
        newPacked = packMultitap(u.vk, u.count, u.gap_ms, newWatch, u.adaptive);
      } else if (u.kind === HK_KIND_MODIFIER) {
        newPacked = packHotkey(u.mod, u.vk, newWatch);
      } else {
        return;
      }
      _hkState.overrides[slot] = newPacked;
      const save = await window.svc.hotkeys.save(_hkState.overrides);
      _renderHotkeyEditor();
      if (save && save.ok) {
        toast(newWatch
          ? `${HK_LABELS[slot]}: switched to SILENT — key still types. Inject Now to apply.`
          : `${HK_LABELS[slot]}: switched to BLOCKED — key is reserved. Inject Now to apply.`,
          'ok');
      } else {
        toast('Save failed.', 'err');
      }
    });
  }
}

/* v10 (2026-07-17): Modal shown when user flips stealth toggle on.
 * Explains what changes + tradeoffs, lets user cancel before commit. */
function _openStealthEnableModal() {
  const root = document.getElementById('hk-record-modal-root');
  const st = _hkState.stealth_overrides || {};
  const rows = Object.keys(st)
    .map(k => parseInt(k, 10))
    .sort((a, b) => a - b)
    .map(slot => {
      const oldBinding = formatHotkey(_hkState.defaults[slot] || 0);
      const newBinding = formatHotkey(st[slot]);
      const label = HK_LABELS[slot] || `Slot ${slot}`;
      return `
        <tr>
          <td class="stealth-slot-label">${escapeHtml(label)}</td>
          <td class="stealth-slot-old">${escapeHtml(oldBinding)}</td>
          <td class="stealth-slot-arrow">→</td>
          <td class="stealth-slot-new">${escapeHtml(newBinding)}</td>
        </tr>
      `;
    }).join('');
  root.innerHTML = `
    <div class="modal-shade">
      <div class="modal-box modal-box-wide modal-box-scroll">
        <div class="modal-title">Turn on Invisible Hotkeys?</div>
        <div class="stealth-lead">
          Some exam software watches every time you press <b>Ctrl</b>, <b>Alt</b>, <b>Shift</b>, or the <b>Windows key</b> — even when nothing happens after. This mode switches CloakGPT's shortcuts to patterns that <b>don't press those keys at all</b>, so there's nothing suspicious to log.
        </div>
        <div class="stealth-tradeoff-title">Your shortcuts will change to:</div>
        <table class="stealth-mapping-table">
          <thead>
            <tr><th>What it does</th><th>Before</th><th></th><th>After</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
        <div class="stealth-tradeoff-title" style="margin-top:16px;">Two things to know:</div>
        <ul class="stealth-tradeoff-list">
          <li><b>Silent triple-taps</b> (like tapping <code>C</code> three times fast to copy) let the key still type normally in your exam. To anyone watching it looks like you typo'd "ccc" \u2014 the copy happens in the background.</li>
          <li><b>Reserved triple-taps</b> use rare keys like backtick (<code>\`</code>) or backslash (<code>\\</code>). While CloakGPT is on you won't be able to type these characters — but you almost never need them in an exam anyway.</li>
        </ul>
        <div class="stealth-tradeoff-note">
          You can change any shortcut individually after turning this on. Turning it off puts everything back the way it was.
        </div>
        <div class="modal-actions">
          <button id="stealth-cancel" class="btn btn-secondary">Cancel</button>
          <button id="stealth-enable" class="btn btn-primary">Turn On</button>
        </div>
      </div>
    </div>
  `;
  document.getElementById('stealth-cancel').addEventListener('click', () => {
    root.innerHTML = '';
    _renderHotkeyEditor();   // re-render to reset the toggle visual state
  });
  document.getElementById('stealth-enable').addEventListener('click', async () => {
    /* Apply the stealth overrides on top of any existing user
     * overrides. Existing user customizations for slots NOT in
     * STEALTH_OVERRIDES are preserved. */
    const ov = { ..._hkState.overrides };
    for (const [k, v] of Object.entries(_hkState.stealth_overrides || {})) {
      ov[k] = v >>> 0;
    }
    _hkState.overrides = ov;
    const save = await window.svc.hotkeys.save(ov);
    root.innerHTML = '';
    _renderHotkeyEditor();
    if (save && save.ok) {
      toast('Invisible Hotkeys on — click Inject Now to apply.', 'ok');
    } else {
      toast('Save failed.', 'err');
    }
  });
}

async function _disableStealthMode() {
  /* Remove ONLY the stealth-slot overrides so those slots fall back
   * to their standard modifier defaults. Any user-customized slot
   * NOT in the stealth map is preserved. */
  const ov = { ..._hkState.overrides };
  for (const k of Object.keys(_hkState.stealth_overrides || {})) {
    delete ov[k];
  }
  _hkState.overrides = ov;
  const save = await window.svc.hotkeys.save(ov);
  _renderHotkeyEditor();
  if (save && save.ok) {
    toast('Invisible Hotkeys off — standard shortcuts restored.', 'ok');
  } else {
    toast('Save failed.', 'err');
  }
}

function _openHotkeyRecorder(slot) {
  if (_hkRecording) return;
  const root = document.getElementById('hk-record-modal-root');
  const label = HK_LABELS[slot] || `Slot ${slot}`;
  const current = _bindingFor(slot);
  const defBinding = _hkState.defaults[slot] || 0;
  const curUnpacked = current ? unpackHotkey(current) : { kind: 0 };
  _hkRecording = { slot };

  /* v10: mode-aware recorder. Tabs pick MODIFIER / LONGPRESS / MULTITAP.
   * Each mode has its own inputs. Live risk analyzer at the bottom
   * warns for high-false-positive bindings (e.g. single letter, double
   * tap of common letter). */
  root.innerHTML = `
    <div class="modal-shade">
      <div class="modal-box modal-box-wide modal-box-scroll">
        <div class="modal-title">Change shortcut for: ${escapeHtml(label)}</div>
        <div class="hk-mode-tabs">
          <button class="hk-mode-tab" data-mode="0">Press keys together</button>
          <button class="hk-mode-tab" data-mode="1">Hold a key</button>
          <button class="hk-mode-tab" data-mode="2">Tap a key fast</button>
          <button class="hk-mode-tab" data-mode="3">Use your mouse</button>
        </div>
        <div id="hk-mode-body"></div>
        <div class="hk-risk" id="hk-risk-badge"></div>
        <div class="modal-hint">
          ${defBinding ? `Original: <b>${escapeHtml(formatHotkey(defBinding))}</b>.` : ''}
          Press <kbd>Esc</kbd> to cancel.
        </div>
        <div class="modal-actions">
          <button id="rec-cancel" class="btn btn-secondary">Cancel</button>
          <button id="rec-unbind" class="btn btn-danger">Remove</button>
          <button id="rec-save" class="btn btn-primary" disabled>Save</button>
        </div>
      </div>
    </div>
  `;

  let candidate = null;   /* live-updated packed uint */
  /* v1.7.4: modes 4 (MOUSE_HOLD) + 5 (MOUSE_MULTI) both surface via
   * modal tab index 3 ("Use your mouse"). Body renders a sub-picker
   * for hold vs multi. Map kind -> tab index for initial state. */
  let currentMode;
  if (curUnpacked.kind === HK_KIND_MOUSE_HOLD || curUnpacked.kind === HK_KIND_MOUSE_MULTI) {
    currentMode = 3;
  } else {
    currentMode = curUnpacked.kind || 0;
  }
  const bodyEl = document.getElementById('hk-mode-body');
  const riskEl = document.getElementById('hk-risk-badge');
  const saveBtn = document.getElementById('rec-save');

  function _updateRisk() {
    if (!candidate) { riskEl.innerHTML = ''; saveBtn.disabled = true; return; }
    saveBtn.disabled = false;
    const r = riskAnalyze(candidate);
    const badge = {
      safe:       { color: '#22c55e', icon: '✓', label: 'Safe' },
      caution:    { color: '#f59e0b', icon: '⚠', label: 'Caution' },
      high:       { color: '#ef4444', icon: '⚠', label: 'High risk' },
      'very-high':{ color: '#dc2626', icon: '⛔', label: 'Very high risk' },
    }[r.level] || { color: '#94a3b8', icon: '?', label: r.level };
    riskEl.innerHTML = `
      <div class="hk-risk-inner" style="border-color:${badge.color}20; background:${badge.color}12;">
        <div class="hk-risk-head" style="color:${badge.color};">${badge.icon} ${badge.label} — ${escapeHtml(formatHotkey(candidate))}</div>
        <div class="hk-risk-body">${r.reason}</div>
      </div>`;
  }

  function _setMode(mode) {
    currentMode = mode;
    for (const t of root.querySelectorAll('.hk-mode-tab')) {
      t.classList.toggle('active', parseInt(t.dataset.mode, 10) === mode);
    }
    candidate = null;
    _updateRisk();
    _renderModeBody();
  }

  function _renderModeBody() {
    if (currentMode === 0) {
      bodyEl.innerHTML = `
        <div class="hk-capture-area" id="hk-capture" tabindex="0">
          <div class="hk-capture-hint">Click this box, then press your shortcut (e.g. hold Ctrl+Alt and press G).</div>
          <div class="hk-capture-current" id="hk-capture-current">${current && curUnpacked.kind === 0 ? escapeHtml(formatHotkey(current)) : '(nothing chosen yet)'}</div>
        </div>
      `;
      const cap = document.getElementById('hk-capture');
      cap.focus();
      cap.addEventListener('keydown', (e) => {
        e.preventDefault(); e.stopPropagation();
        if (e.key === 'Escape') { _closeRecorder(false); return; }
        if (e.key === 'Control' || e.key === 'Shift' || e.key === 'Alt' || e.key === 'Meta') return;
        const vk = eventToVk(e);
        if (!vk) return;
        let mod = 0;
        if (e.ctrlKey)  mod |= 1;
        if (e.shiftKey) mod |= 2;
        if (e.altKey)   mod |= 4;
        /* v1.7.11.15 (2026-07-25) — reject bare-key MODIFIER bindings.
         *
         * Without this guard the recorder would happily save mod=0
         * bindings (e.g. bare "H"), which then match EVERY press of
         * that key in the LL hook — turning normal typing of that
         * letter into a hotkey trigger. Nasty when it's a common
         * letter (H, S, T, etc.) because the user then can't type
         * that letter in the AI chat OR any other app without firing
         * the shortcut.
         *
         * If the user genuinely wants a bare-key trigger they should
         * use the "Tap a key fast" tab (MULTITAP, 3 taps within a
         * gap) or the "Hold a key" tab (LONGPRESS) — both of which
         * are stealth-safe because normal typing doesn't produce the
         * pattern. */
        if (mod === 0) {
          candidate = null;
          _updateRisk();
          const curEl = document.getElementById('hk-capture-current');
          if (curEl) {
            curEl.innerHTML = '<span style="color:#ef4444;">Hold <b>Ctrl</b>, <b>Shift</b>, or <b>Alt</b> and press the key.</span> Bare-key shortcuts would fire on every keystroke in your apps — try the <b>Tap a key fast</b> or <b>Hold a key</b> tabs instead.';
          }
          return;
        }
        candidate = packHotkey(mod, vk);
        document.getElementById('hk-capture-current').textContent = formatHotkey(candidate);
        _updateRisk();
      });
    } else if (currentMode === 1) {
      const curHold = curUnpacked.kind === 1 ? curUnpacked.hold_ms : 700;
      const curVk = curUnpacked.kind === 1 ? curUnpacked.vk : 0xA1;
      bodyEl.innerHTML = `
        <div class="hk-longpress-body">
          <div class="hk-explainer">
            <b>How this works:</b> Press and hold one key by itself for the time below. Right Shift works great — you tap it every time you type a capital, but you rarely <i>hold</i> it. Pressing any other key during the hold cancels it, so normal typing won't trigger this.
          </div>
          <div class="hk-field">
            <label>Which key do you want to hold?</label>
            <div class="hk-capture-area" id="hk-lp-capture" tabindex="0">
              <span id="hk-lp-key">${_vkName(curVk)}</span>
              <span class="hk-capture-hint" style="margin-left:.5em;">(click here, then press the key you want)</span>
            </div>
          </div>
          <div class="hk-field">
            <label>How long to hold it: <span id="hk-lp-ms-label">${(curHold/1000).toFixed(1).replace(/\.0$/,'')}</span> seconds</label>
            <input type="range" id="hk-lp-ms" min="300" max="1500" step="100" value="${curHold}" />
            <div class="hk-hint-small">Longer = fewer accidents. 0.7s is a good balance.</div>
          </div>
        </div>
      `;
      let vk = curVk;
      let ms = curHold;
      candidate = packLongpress(vk, ms);
      _updateRisk();
      const cap = document.getElementById('hk-lp-capture');
      cap.addEventListener('keydown', (e) => {
        e.preventDefault(); e.stopPropagation();
        if (e.key === 'Escape') { _closeRecorder(false); return; }
        const v = eventToVk(e); if (!v) return;
        vk = v;
        document.getElementById('hk-lp-key').textContent = _vkName(vk);
        candidate = packLongpress(vk, ms);
        _updateRisk();
      });
      document.getElementById('hk-lp-ms').addEventListener('input', (e) => {
        ms = parseInt(e.target.value, 10);
        document.getElementById('hk-lp-ms-label').textContent =
          (ms / 1000).toFixed(1).replace(/\.0$/, '');
        candidate = packLongpress(vk, ms);
        _updateRisk();
      });
    } else if (currentMode === 2) {
      const curCount = curUnpacked.kind === 2 ? curUnpacked.count : 3;
      const curGap = curUnpacked.kind === 2 ? curUnpacked.gap_ms : 400;
      const curWatch = curUnpacked.kind === 2 ? curUnpacked.watch : false;
      const curVk = curUnpacked.kind === 2 ? curUnpacked.vk : 0xC0;
      bodyEl.innerHTML = `
        <div class="hk-multitap-body">
          <div class="hk-explainer">
            <b>How this works:</b> Tap a key several times in a row, fast. If you use a common letter like C, leave "Let the key still type normally" ON — to your exam it looks like a "ccc" typo, but CloakGPT quietly runs your shortcut.
          </div>
          <div class="hk-field">
            <label>Which key do you want to tap?</label>
            <div class="hk-capture-area" id="hk-mt-capture" tabindex="0">
              <span id="hk-mt-key">${_vkName(curVk)}</span>
              <span class="hk-capture-hint" style="margin-left:.5em;">(click here, then press the key you want)</span>
            </div>
          </div>
          <div class="hk-field">
            <label>How many taps: <span id="hk-mt-count-label">${curCount}</span></label>
            <input type="range" id="hk-mt-count" min="1" max="${HK_TAP_MAX}" step="1" value="${curCount}" />
            <div class="hk-hint-small">3 taps is the sweet spot — rarely happens by accident. Higher = harder to trigger by mistake.</div>
          </div>
          <div class="hk-field">
            <label>How fast (total time): <span id="hk-mt-gap-label">${(curGap/1000).toFixed(2)}</span> seconds</label>
            <input type="range" id="hk-mt-gap" min="200" max="750" step="50" value="${curGap}" />
            <div class="hk-hint-small">Time from the first tap to the last. 0.30-0.50s feels natural.</div>
          </div>
          <div class="hk-field">
            <label style="display:flex;gap:.5em;align-items:center;">
              <input type="checkbox" id="hk-mt-watch" ${curWatch ? 'checked' : ''} />
              <span>Let the key still type normally (recommended for letters)</span>
            </label>
            <div class="hk-hint-small">
              <b>On:</b> The key still types in your app. Your exam sees you typed "ccc" — a typo. CloakGPT runs the shortcut in the background.<br>
              <b>Off:</b> The key is blocked while CloakGPT is on. Good for rare keys like backtick <code>\`</code>. Bad for common letters — you won't be able to type them.
            </div>
          </div>
        </div>
      `;
      let vk = curVk;
      let count = curCount, gap = curGap, watch = curWatch;
      candidate = packMultitap(vk, count, gap, watch, false);
      _updateRisk();
      document.getElementById('hk-mt-capture').addEventListener('keydown', (e) => {
        e.preventDefault(); e.stopPropagation();
        if (e.key === 'Escape') { _closeRecorder(false); return; }
        const v = eventToVk(e); if (!v) return;
        vk = v;
        document.getElementById('hk-mt-key').textContent = _vkName(vk);
        candidate = packMultitap(vk, count, gap, watch, false);
        _updateRisk();
      });
      document.getElementById('hk-mt-count').addEventListener('input', (e) => {
        count = parseInt(e.target.value, 10);
        document.getElementById('hk-mt-count-label').textContent = count;
        candidate = packMultitap(vk, count, gap, watch, false);
        _updateRisk();
      });
      document.getElementById('hk-mt-gap').addEventListener('input', (e) => {
        gap = parseInt(e.target.value, 10);
        document.getElementById('hk-mt-gap-label').textContent = (gap / 1000).toFixed(2);
        candidate = packMultitap(vk, count, gap, watch, false);
        _updateRisk();
      });
      document.getElementById('hk-mt-watch').addEventListener('change', (e) => {
        watch = e.target.checked;
        candidate = packMultitap(vk, count, gap, watch, false);
        _updateRisk();
      });
    } else if (currentMode === 3) {
      /* v1.7.4 (2026-07-23) — MOUSE BINDING PICKER.
       *
       * Fully-fledged mouse-button hotkey picker. Two sub-modes:
       *   - HOLD  : press+hold mouse button for N ms
       *   - MULTI : N clicks of mouse button within gap
       * Button picker: LMB / RMB / MMB / X1 / X2 (all supported by
       * SVC_HK_KIND_MOUSE_HOLD/MULTI in the C payload).
       *
       * User's ask: "hold left/right click for 2-3 secs would be
       * nice", "I use my logitech mx mouse ... draw less attention
       * with only using my mouse". This tab makes it accessible to
       * every user without editing hotkeys.json manually. */
      const isMouseHold  = curUnpacked.kind === HK_KIND_MOUSE_HOLD;
      const isMouseMulti = curUnpacked.kind === HK_KIND_MOUSE_MULTI;
      let subKind = isMouseHold ? 'hold' : (isMouseMulti ? 'multi' : 'hold');
      let mvk = (isMouseHold || isMouseMulti) ? curUnpacked.vk : MOUSE_VK.MMB;
      let holdMs = isMouseHold ? curUnpacked.hold_ms : 1200;
      let clickCount = isMouseMulti ? curUnpacked.count : 3;
      let clickGap = isMouseMulti ? curUnpacked.gap_ms : 400;

      function _updateCandidate() {
        if (subKind === 'hold') candidate = packMouseHold(mvk, holdMs);
        else candidate = packMouseMulti(mvk, clickCount, clickGap);
        _updateRisk();
      }

      bodyEl.innerHTML = `
        <div class="hk-mouse-body">
          <div class="hk-explainer">
            <b>Zero-keyboard stealth mode.</b> Bind this shortcut to a mouse gesture \u2014 hold a button for a couple seconds, or triple-click. No modifier keys, no key presses, nothing that stands out as a hotkey. Just mouse activity, which every user does thousands of times per session. This is the <i>most</i> discreet hotkey type CloakGPT offers.
          </div>

          <div class="hk-field">
            <label>Which button?</label>
            <div class="hk-mouse-btn-grid">
              ${Object.entries(MOUSE_VK).map(([short, v]) => `
                <button class="hk-mouse-btn${v === mvk ? ' active' : ''}" data-mvk="${v}">
                  <div class="hk-mouse-btn-short">${short}</div>
                  <div class="hk-mouse-btn-full">${MOUSE_VK_LABEL[v]}</div>
                </button>
              `).join('')}
            </div>
            <div class="hk-hint-small">
              <b>MMB (middle click / wheel click)</b> and <b>X1/X2</b> (thumb buttons on gaming/MX-style mice) are safest — rarely used by other apps, so hold gestures never collide. Left/Right button holds work but can conflict with drag-select in text.
            </div>
          </div>

          <div class="hk-field">
            <label>Gesture type:</label>
            <div class="hk-mouse-subkind">
              <button class="hk-mouse-subkind-btn${subKind === 'hold' ? ' active' : ''}" data-sub="hold">
                <div class="hk-mouse-subkind-label">Hold the button</div>
                <div class="hk-mouse-subkind-hint">Press + hold for X seconds. Best for zero-attention stealth.</div>
              </button>
              <button class="hk-mouse-subkind-btn${subKind === 'multi' ? ' active' : ''}" data-sub="multi">
                <div class="hk-mouse-subkind-label">Click multiple times</div>
                <div class="hk-mouse-subkind-hint">N quick clicks in a row. Fires faster than hold.</div>
              </button>
            </div>
          </div>

          <div class="hk-field" id="hk-mouse-hold-field">
            <label>How long to hold: <span id="hk-mh-ms-label">${(holdMs/1000).toFixed(1).replace(/\.0$/,'')}</span> seconds</label>
            <input type="range" id="hk-mh-ms" min="400" max="2500" step="100" value="${holdMs}" />
            <div class="hk-hint-small">1.0-1.5s is a good balance: long enough to never fire on accidental clicks, short enough to feel snappy.</div>
          </div>

          <div class="hk-field" id="hk-mouse-multi-field-count">
            <label>Number of clicks: <span id="hk-mm-count-label">${clickCount}</span></label>
            <input type="range" id="hk-mm-count" min="2" max="${HK_TAP_MAX}" step="1" value="${clickCount}" />
            <div class="hk-hint-small">3 clicks is the sweet spot — Windows only recognizes 2 (double-click), so 3+ never collides.</div>
          </div>

          <div class="hk-field" id="hk-mouse-multi-field-gap">
            <label>Time window: <span id="hk-mm-gap-label">${(clickGap/1000).toFixed(2)}</span> seconds</label>
            <input type="range" id="hk-mm-gap" min="200" max="750" step="50" value="${clickGap}" />
            <div class="hk-hint-small">Total time from first to last click. 0.30-0.50s feels natural.</div>
          </div>
        </div>
      `;

      /* Show/hide fields based on subKind. */
      const showFields = () => {
        document.getElementById('hk-mouse-hold-field').style.display   = (subKind === 'hold')  ? '' : 'none';
        document.getElementById('hk-mouse-multi-field-count').style.display = (subKind === 'multi') ? '' : 'none';
        document.getElementById('hk-mouse-multi-field-gap').style.display   = (subKind === 'multi') ? '' : 'none';
      };
      showFields();
      _updateCandidate();

      /* Button picker wiring. */
      for (const b of bodyEl.querySelectorAll('.hk-mouse-btn')) {
        b.addEventListener('click', () => {
          mvk = parseInt(b.dataset.mvk, 10);
          for (const bb of bodyEl.querySelectorAll('.hk-mouse-btn')) {
            bb.classList.toggle('active', parseInt(bb.dataset.mvk, 10) === mvk);
          }
          _updateCandidate();
        });
      }
      /* Sub-kind picker wiring. */
      for (const s of bodyEl.querySelectorAll('.hk-mouse-subkind-btn')) {
        s.addEventListener('click', () => {
          subKind = s.dataset.sub;
          for (const ss of bodyEl.querySelectorAll('.hk-mouse-subkind-btn')) {
            ss.classList.toggle('active', ss.dataset.sub === subKind);
          }
          showFields();
          _updateCandidate();
        });
      }
      /* Hold-time slider. */
      document.getElementById('hk-mh-ms').addEventListener('input', (e) => {
        holdMs = parseInt(e.target.value, 10);
        document.getElementById('hk-mh-ms-label').textContent =
          (holdMs / 1000).toFixed(1).replace(/\.0$/, '');
        _updateCandidate();
      });
      /* Multi count + gap sliders. */
      document.getElementById('hk-mm-count').addEventListener('input', (e) => {
        clickCount = parseInt(e.target.value, 10);
        document.getElementById('hk-mm-count-label').textContent = clickCount;
        _updateCandidate();
      });
      document.getElementById('hk-mm-gap').addEventListener('input', (e) => {
        clickGap = parseInt(e.target.value, 10);
        document.getElementById('hk-mm-gap-label').textContent = (clickGap / 1000).toFixed(2);
        _updateCandidate();
      });
    }
  }

  /* Wire tab clicks. */
  for (const t of root.querySelectorAll('.hk-mode-tab')) {
    t.addEventListener('click', () => _setMode(parseInt(t.dataset.mode, 10)));
  }
  /* Start on the current binding's mode. */
  _setMode(currentMode);

  /* Escape closes. */
  const escHandler = (e) => { if (e.key === 'Escape' && _hkRecording) { _closeRecorder(false); } };
  window.addEventListener('keydown', escHandler, true);

  function _closeRecorder(_saved) {
    window.removeEventListener('keydown', escHandler, true);
    root.innerHTML = '';
    _hkRecording = null;
    _renderHotkeyEditor();
  }

  saveBtn.addEventListener('click', async () => {
    if (!candidate) return;
    _hkState.overrides[slot] = candidate;
    const save = await window.svc.hotkeys.save(_hkState.overrides);
    _closeRecorder(true);
    if (save && save.ok) {
      toast(`Set ${HK_LABELS[slot]} to ${formatHotkey(candidate)} — takes effect on next Inject.`, 'ok');
    } else {
      toast('Save failed.', 'err');
    }
  });
  document.getElementById('rec-cancel').addEventListener('click', () => _closeRecorder(false));
  document.getElementById('rec-unbind').addEventListener('click', async () => {
    _hkState.overrides[slot] = 0;
    await window.svc.hotkeys.save(_hkState.overrides);
    _closeRecorder(true);
    toast(`Unbound ${HK_LABELS[slot]}.`, 'ok');
  });
}

document.getElementById('btn-hk-reset').addEventListener('click', async () => {
  if (!confirm('Reset ALL hotkeys to defaults?\n\nAny customizations you made will be discarded.')) return;
  const r = await window.svc.hotkeys.reset();
  if (r && r.ok) {
    _hkState.overrides = {};
    _renderHotkeyEditor();
    toast('All hotkeys reset to defaults.', 'ok');
  }
});

document.getElementById('btn-restart-tour').addEventListener('click', async () => {
  await window.svc.onboarding.reset();
  showOnboarding();
});

// ═══════════════════════════════════════════════════════════════
//  Onboarding walkthrough (first-launch, 15 steps as of v17)
// ═══════════════════════════════════════════════════════════════

let _obActive = false;
let _obStep = 0;
let _obChecks = { tos: false, chargeback: false };

function _obSteps() {
  return [
    { // 0
      tag: 'GETTING STARTED',
      icon: 'sparkles',
      title: 'Welcome to CloakGPT',
      lead: 'The world\'s best AI, one keystroke away — anywhere on your screen.',
      body: `
        <p>CloakGPT is an invisible overlay you drive entirely with keyboard shortcuts. A few things to know up front:</p>
        <ul>
          <li>The overlay sits <b>above</b> whatever app you\'re looking at.</li>
          <li>It stays <b>hidden</b> from screen recording and screen sharing.</li>
          <li>You control it with hotkeys — nothing to click or alt-tab to.</li>
        </ul>
        <p>This quick tour will get you set up in under a minute.</p>
      `,
      features: [
        'Full-screen invisible overlay',
        'Global hotkeys everywhere',
        'Multiple AI providers with automatic failover',
      ],
    },
    { // 1
      tag: 'STEP 1',
      icon: 'key',
      title: 'Add your AI keys',
      lead: 'CloakGPT uses your OWN API keys — nothing is billed through us.',
      body: `
        <p>On the dashboard\'s <b>API keys</b> card, paste keys for one or more providers:</p>
        <ul>
          <li><b>OpenAI</b> — GPT-6 Astra (Strong) + GPT-5.6 Terra / Luna</li>
          <li><b>Anthropic</b> — Claude Fable 5.1, Sonnet 5, Haiku 4.5</li>
          <li><b>Google</b> — Gemini 3.1 Pro, 3.8 Flash, 3.5 Flash-Lite</li>
          <li><b>OpenRouter</b> — has free models if you\'re trying it out</li>
        </ul>
        <p>Configure multiple providers so if one rate-limits, we transparently fall back to the next.</p>
        <p>Keys are encrypted and stay on this device — never plaintext on disk.</p>
      `,
      features: [
        'Multi-provider failover on rate limits',
        'Per-key live tester + latency stats',
        'Encrypted at rest, tied to your Windows account',
      ],
    },
    { // 2
      tag: 'STEP 2',
      icon: 'zap',
      title: 'Click Inject',
      lead: 'Starts the overlay. About 30 s the first time; instant after.',
      body: `
        <p>Once you have at least one API key configured (or you\'re using credits), hit the big blue <b>Inject Now</b> button.</p>
        <p>The first launch does a one-time setup in the background — that\'s where the 30-second wait comes from. Every launch after that is instant.</p>
        <p>When you see <b>Overlay: Active</b> with a green dot, the overlay is ready and hotkeys are live.</p>
      `,
      features: [
        'Nothing extra written to disk',
        'Windows updates? Just click Inject again — we handle the rest.',
      ],
    },
    { // 3
      tag: 'STEP 3',
      icon: 'zap',
      title: 'Screenshot + ask AI',
      lead: 'The bread-and-butter workflow: press one hotkey, get an answer.',
      body: `
        <div class="ob-kbdrow">
          <kbd data-hk="0">Ctrl+U</kbd>
          <span class="desc">Capture the current screen + send to your active AI tier</span>
        </div>
        <p>The AI reply appears in the overlay a few seconds later. Cycle model tier with <kbd data-hk="24" style="font-family:monospace">Ctrl+Alt+M</kbd> if you want faster (Cheap) or better (Strong) answers.</p>
        <p>Hotkey presses go straight to the overlay — the app you\'re inside of never sees them.</p>
      `,
      features: [
        'Overlay pixels don\'t show up in screen captures',
        'Reply is copied to clipboard automatically — Ctrl+V to paste it',
      ],
    },
    { // 4
      tag: 'STEP 4',
      icon: 'message-square',
      title: 'Type a follow-up',
      lead: 'For freeform questions, use chat mode -- no screenshot required.',
      body: `
        <div class="ob-kbdrow">
          <kbd data-hk="2">Ctrl+Alt+T</kbd>
          <span class="desc">Enter chat mode -- type your question, press Enter to submit</span>
        </div>
        <p>Chat mode catches every keystroke -- even letters and punctuation -- so <b>nothing</b> leaks into the underlying app while you\'re typing. Perfect if you\'re on a Google Doc or exam browser and don\'t want it to hear you type.</p>
        <p>The current screenshot is attached as context, so you can ask "explain this passage" or "what step comes next?".</p>
      `,
      features: [
        'Works with every keyboard layout',
        'Enter submits, Esc cancels',
      ],
    },
    { // 5 -- NEW (v17 2026-09-22): AutoSolver / hidden dot
      tag: 'STEP 5',
      icon: 'target',
      title: 'AutoSolver -- the hands-free dot',
      lead: 'Hold left-click on any question for ~2 s. A tiny hidden dot appears with the answer.',
      body: `
        <div class="ob-kbdrow">
          <kbd>Hold Left-Click 2 s</kbd>
          <span class="desc">Snap the screen + solve + surface answer in the dot (no keyboard)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd data-hk="35">Ctrl+Shift+Alt+O</kbd>
          <span class="desc">Master toggle for AutoSolver</span>
        </div>
        <p>The <b>dot</b> is a small colored circle that sits on the right edge of your screen. It changes state -- <span style="color:#34c759">idle</span> &rarr; <span style="color:#f59e0a">capturing</span> &rarr; <span style="color:#ff9500">analyzing</span> &rarr; <span style="color:#34c759">done</span> -- and expands into a card showing the answer + question stem. Click the hamburger to switch between dot / expanded views; drag to reposition; drag the corner to resize.</p>
        <p>The dot is <b>hidden from screenshots and screen sharing</b>, same as the main overlay. Perfect for MCQs -- glance at the letter and click the option yourself.</p>
        <p><b>Auto-click is OFF by default</b> (the discreet choice). Enable it in the dashboard\'s <i>AutoSolver</i> card if you want the mouse to move and click / type the answer for you (with humanized curves + timing). Off = display-only, safer.</p>
        <p>Master switch: the <b>Show answer dot</b> toggle in the status card (right next to Inject) flips the dot on / off live -- no re-inject needed.</p>
      `,
      features: [
        'No hotkey needed -- just hold left-click',
        'Dot hides itself when the main overlay is open (mutually exclusive)',
        'Auto-click OFF by default; display-only is the discreet pick',
        'Image detail configurable per-provider',
      ],
    },
    { // 6 -- NEW (v17): Composer bar + gear/settings hub + toasts
      tag: 'STEP 6',
      icon: 'layout',
      title: 'The overlay -- composer + gear + toasts',
      lead: 'The layout you see every session, top to bottom.',
      body: `
        <p><b>Header row</b> -- brand mark + wordmark on the left; on the right, a thin opacity slider, a theme chip (moon / sun / auto), a gear (opens settings), a trash (clear chat), and an eye-off (hide overlay).</p>
        <p><b>Body</b> -- either an empty welcome screen or your chat transcript. Bubbles auto-follow new AI content unless you scrolled up recently (auto-follow resumes after 6 s of no interaction).</p>
        <p><b>Composer</b> -- pinned at the bottom of the overlay:</p>
        <ul>
          <li><b>Camera square</b> (left) -- click = screenshot + ask AI (same as <kbd data-hk="0" style="font-family:monospace">Ctrl+U</kbd>).</li>
          <li><b>Rounded text field</b> (middle) -- click to focus and start typing. The field catches every keystroke so nothing leaks into the underlying app. Click outside the composer to unfocus (your text stays).</li>
          <li><b>Send square</b> (right, paper-plane icon) -- lights up only when there\'s text in the field. Empty = dimmed + nothing happens (camera is for screenshot-only asks).</li>
        </ul>
        <p><b>Gear icon</b> -- opens the in-overlay <i>settings hub</i> (AI model, Ask actions, Appearance sliders, Layout controls). Everything you can tune on the dashboard is reachable here too, so you can adjust the overlay <i>from inside the overlay</i> without alt-tabbing. Click gear again to return to chat.</p>
        <p><b>Toasts</b> -- when you toggle a setting via hotkey (LaTeX, direct-answer, streaming, tier / provider cycle, etc.) a small pill fades in at the top of the overlay confirming the new state. Chat stays clean -- settings feedback lives in the toast, not in the conversation.</p>
      `,
      features: [
        'Composer never leaves your view -- Ask is always one click away',
        'Gear = full settings hub without alt-tabbing to the dashboard',
        'Toast feedback keeps chat noise-free',
      ],
    },
    { // 7 -- was 5
      tag: 'STEP 7',
      icon: 'move',
      title: 'Position + resize',
      lead: 'The overlay starts in the top-right. Move / resize / restyle to taste.',
      body: `
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+Arrows</kbd>
          <span class="desc">Nudge overlay in any direction (hold to repeat)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd>Ctrl+Shift+Alt+Arrows</kbd>
          <span class="desc">Resize the overlay (wider / taller / narrower / shorter)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd data-hk="13">Ctrl+Alt+Q</kbd>
          <span class="desc">Snap to next corner (TL -> TR -> BR -> BL)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd data-hk="18">Ctrl+Alt+R</kbd>
          <span class="desc">Reset overlay to default position + size</span>
        </div>
        <p>Position, size, opacity, and font size are all remembered across launches. You can also set the launch defaults from the dashboard\'s <b>Overlay appearance</b> card -- <i>Ultra size mode</i> unlocks a tiny corner pip or near-fullscreen.</p>
      `,
      features: [
        'Hold Ctrl+Alt+Arrow to auto-repeat move at 20 Hz',
        'Everything you tweak persists automatically',
      ],
    },
    { // 8 -- was 6
      tag: 'STEP 8',
      icon: 'eye-off',
      title: 'Panic key + toggle',
      lead: 'Two hotkeys that always work: hide the overlay, or shut it off entirely.',
      body: `
        <div class="ob-kbdrow">
          <kbd data-hk="1">Ctrl+Alt+G</kbd>
          <span class="desc">Toggle overlay visibility (overlay stays ready)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd data-hk="4">Ctrl+Alt+X</kbd>
          <span class="desc">Back to home / soft quit (turn off overlay)</span>
        </div>
        <div class="ob-kbdrow" style="border-color:rgba(239,68,68,0.35);background:rgba(239,68,68,0.05)">
          <kbd data-hk="20">Ctrl+Shift+Alt+K</kbd>
          <span class="desc" style="color:#fca5a5"><b>EMERGENCY STOP</b> -- shuts everything down. Screen flashes black for ~2 s as Windows recovers.</span>
        </div>
        <p>Use <kbd data-hk="1" style="font-family:monospace">Ctrl+Alt+G</kbd> if someone walks up. Use <kbd data-hk="20" style="font-family:monospace">Ctrl+Shift+Alt+K</kbd> if you need the overlay <b>gone</b> immediately -- your screen will flash black for a couple seconds while Windows recovers.</p>
      `,
      features: [
        'Panic keys always work, even mid-AI-request',
        'Emergency stop leaves nothing behind',
      ],
    },
    { // 9 -- was 7
      tag: 'STEP 9',
      icon: 'copy',
      title: 'Copy modes',
      lead: 'Three different copy hotkeys for different situations.',
      body: `
        <div class="ob-kbdrow">
          <kbd data-hk="3">Ctrl+Alt+C</kbd>
          <span class="desc">Copy the ENTIRE last AI reply (markdown + code + math)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd data-hk="29">Ctrl+Alt+A</kbd>
          <span class="desc">Copy JUST the direct answer (first line -- "x = 4", "B) Photosynthesis")</span>
        </div>
        <div class="ob-kbdrow">
          <kbd data-hk="28">Ctrl+Shift+Alt+C</kbd>
          <span class="desc">Copy JUST fenced code blocks (Python, JS, etc.)</span>
        </div>
        <p>Pick the shortest one that fits -- the AI is prompted to always put the direct answer on line 1, so <kbd data-hk="29" style="font-family:monospace">Ctrl+Alt+A</kbd> is often enough for MCQs.</p>
      `,
      features: [
        'Copies clean plaintext (no markdown asterisks or backticks)',
        'Preserved exactly as generated — you paste into anything',
      ],
    },
    { // 10 -- was 8
      tag: 'STEP 10',
      icon: 'stop-circle',
      title: 'Reasoning + stop',
      lead: 'Reasoning models can take a while. You can abort any time.',
      body: `
        <div class="ob-kbdrow">
          <kbd data-hk="31">Ctrl+Alt+S</kbd>
          <span class="desc">Stop the current AI response (partial reply preserved)</span>
        </div>
        <p>Strong-tier reasoning models (GPT-6 Astra, Claude Fable 5.1, Gemini 3.1 Pro) can spend 30 s -- 10 min thinking. The stop hotkey aborts cleanly and appends "(stopped by user)" to whatever streamed so far.</p>
        <p>Regen the last question with a fresh AI call:</p>
        <div class="ob-kbdrow">
          <kbd data-hk="26">Ctrl+Alt+Enter</kbd>
          <span class="desc">Regenerate -- re-runs your last question with the current tier/provider</span>
        </div>
      `,
      features: [
        'Abort works even mid-reasoning-thinking-phase',
        'Regen useful for cycling tier and comparing answers',
      ],
    },
    { // 11 -- NEW (v17 2026-09-22): Screenshot redactor
      tag: 'STEP 11',
      icon: 'shield-off',
      title: 'Screenshot redactor',
      lead: 'Blacks out unwanted text in every screenshot before it leaves your device.',
      body: `
        <p>Some apps stamp their name or a banner across your screen. Sending that text to an AI can be a giveaway.</p>
        <p>The <b>Screenshot redactor</b> card on the dashboard scans every outbound screenshot for words or phrases you\'ve added to the blacklist, and paints them <b>solid black</b> before the image is sent. Nothing is uploaded -- everything runs on your device.</p>
        <p><b>Off by default</b> -- turning it on keeps a small helper running in the background. Flip it on only when you actually need it. The default blacklist covers the common cases; click <i>Edit blacklist</i> to add your own words.</p>
        <div class="ob-kbdrow">
          <kbd>Words</kbd>
          <span class="desc">Whole-word match, one word per line</span>
        </div>
        <div class="ob-kbdrow">
          <kbd>Phrases</kbd>
          <span class="desc">Matches anywhere across a line (multi-word banners)</span>
        </div>
      `,
      features: [
        'Runs on your device -- nothing uploaded',
        'Off by default; flip on only when needed',
        'Fully editable blacklist',
      ],
    },
    { // 12 -- was 9
      tag: 'STEP 12',
      icon: 'sliders',
      title: 'Customize hotkeys',
      lead: 'Don\'t like a default binding? Change it.',
      body: `
        <p>The <b>Overlay hotkeys</b> card on the dashboard lets you remap every hotkey. Click a binding, then press the combo you want. Changes take effect on your next Inject.</p>
        <p>Conflicts (two slots on the same combo) get highlighted in red — pick one and rebind the other.</p>
        <p>Ctrl+Alt+... combos are usually safest because most apps don\'t bind them. Ctrl+Shift+... is fine for letters not in the Windows accessibility set (F/K/S/H are safe; G/P/T/N are risky).</p>
      `,
      features: [
        'Any combo you can type is a valid hotkey',
        'Reset any single hotkey or all of them',
      ],
    },
    { // 13 -- was 10
      tag: 'STEP 13',
      icon: 'shield',
      title: 'One device policy',
      lead: 'Your subscription is bound to this machine.',
      body: `
        <p>To keep pricing fair we allow one active device per account. If you sign in on a second machine, you\'ll be prompted to unregister this one first.</p>
        <p>To move CloakGPT between devices:</p>
        <ul>
          <li>Sign in on the new machine.</li>
          <li>On the "Device limit reached" screen, click <b>Remove</b> next to the old device.</li>
          <li>Sign-in retries automatically. Old device unloads within ~30 min.</li>
        </ul>
        <p>Your API keys don\'t transfer — re-enter them on the new device.</p>
      `,
      features: [
        'Removing a device turns off the overlay there',
        'This machine is remembered by a stable device fingerprint',
      ],
    },
    { // 14 -- final agreement (was 11)
      tag: 'BEFORE YOU START',
      icon: 'file-text',
      title: 'One last thing',
      lead: 'Please confirm you understand a couple of things.',
      body: `
        <p>Almost done. Two quick agreements before we drop you into the app.</p>
        <div class="ob-check-row" data-check="tos">
          <div class="ob-check-box"><svg class="ob-check-mark" viewBox="0 0 16 16"><polyline points="3 8.5 6.5 12 13 4.5"/></svg></div>
          <div class="ob-check-text">I have read and agree to the <a href="#" id="ob-tos-link" style="color:var(--cyan-light);text-decoration:underline">Terms of Service</a>. I understand that CloakGPT is provided as-is with no warranty, and using it to violate any exam-taker\'s honor code is my own responsibility.</div>
        </div>
        <div class="ob-check-row is-danger" data-check="chargeback">
          <div class="ob-check-box"><svg class="ob-check-mark" viewBox="0 0 16 16"><polyline points="3 8.5 6.5 12 13 4.5"/></svg></div>
          <div class="ob-check-text">If I initiate a chargeback on my subscription, I understand my account will be permanently suspended from CloakGPT and any associated services.</div>
        </div>
        <p style="margin-top:16px;color:var(--fg3);font-size:12px">You can revisit this walkthrough anytime from the Support card on the dashboard.</p>
      `,
      isFinal: true,
    },
  ];
}

const _obIconSvgs = {
  'sparkles':     '<path d="M12 3v18M3 12h18M6 6l12 12M18 6L6 18"/>',
  'key':          '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
  'zap':          '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  'message-square':'<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
  'move':         '<polyline points="5 9 2 12 5 15"/><polyline points="9 5 12 2 15 5"/><polyline points="15 19 12 22 9 19"/><polyline points="19 9 22 12 19 15"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="12" y1="2" x2="12" y2="22"/>',
  'eye-off':      '<path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a20 20 0 0 1 5.06-5.94"/><path d="M9.9 4.24A11.05 11.05 0 0 1 12 4c7 0 11 8 11 8a19.53 19.53 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>',
  'copy':         '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  'stop-circle':  '<circle cx="12" cy="12" r="10"/><rect x="9" y="9" width="6" height="6"/>',
  'sliders':      '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
  'shield':       '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  'file-text':    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>',
  /* v17 (2026-09-22) -- new icons for AutoSolver / Composer / Redactor steps. */
  'target':       '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
  'layout':       '<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/>',
  'shield-off':   '<path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18"/><path d="M4.73 4.73L4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38"/><line x1="1" y1="1" x2="23" y2="23"/>',
};

function showOnboarding() {
  if (_obActive) return;
  _obActive = true;
  _obStep = 0;
  _obChecks = { tos: false, chargeback: false };
  const root = document.getElementById('onboarding-root');
  root.innerHTML = `
    <div id="onboarding-overlay">
      <div class="ob-header">
        <div class="ob-brand"><div class="logo">C</div><div class="name">CloakGPT</div></div>
        <div class="ob-progress">
          <div class="ob-progress-bar"><div class="ob-progress-fill" id="ob-fill" style="width:0%"></div></div>
          <div class="ob-progress-label" id="ob-label">1 / 15</div>
        </div>
        <div class="ob-header-actions">
          <button id="ob-skip" class="ob-header-btn">Skip tutorial</button>
          <button id="ob-close" class="ob-header-btn danger">Close</button>
        </div>
      </div>
      <div class="ob-body">
        <div class="ob-hero" id="ob-hero"></div>
        <div class="ob-content" id="ob-content">
          <div class="ob-step-body" id="ob-step-body"></div>
          <div class="ob-nav">
            <button id="ob-back" class="btn btn-secondary" disabled>&larr; Back</button>
            <div class="grow"></div>
            <div class="ob-nav-hint">Use <kbd>&larr;</kbd> / <kbd>&rarr;</kbd> arrows</div>
            <button id="ob-next" class="btn btn-primary">Next &rarr;</button>
          </div>
        </div>
      </div>
    </div>
  `;
  _renderObStep();

  document.getElementById('ob-next').addEventListener('click', _obNext);
  document.getElementById('ob-back').addEventListener('click', _obBack);
  document.getElementById('ob-skip').addEventListener('click', _obSkipToEnd);
  document.getElementById('ob-close').addEventListener('click', _obDismiss);

  window.addEventListener('keydown', _obKeyNav, true);
}

function _obKeyNav(e) {
  if (!_obActive) return;
  if (e.key === 'ArrowRight') { e.preventDefault(); _obNext(); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); _obBack(); }
  else if (e.key === 'Escape') { e.preventDefault(); _obDismiss(); }
}

function _renderObStep() {
  const steps = _obSteps();
  const step = steps[_obStep];
  const total = steps.length;
  document.getElementById('ob-label').textContent = `${_obStep + 1} / ${total}`;
  document.getElementById('ob-fill').style.width = `${((_obStep + 1) / total) * 100}%`;

  const hero = document.getElementById('ob-hero');
  const iconSvg = _obIconSvgs[step.icon] || _obIconSvgs['sparkles'];
  hero.innerHTML = `
    <div class="ob-hero-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${iconSvg}</svg>
    </div>
    <div class="ob-hero-tag">${escapeHtml(step.tag)}</div>
    <div class="ob-hero-title">${escapeHtml(step.title)}</div>
    <div class="ob-hero-subtitle">${escapeHtml(step.lead)}</div>
    ${(step.features || []).length ? `<div class="ob-hero-features">${step.features.map(f => `
      <div class="ob-hero-feature">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
        <span>${escapeHtml(f)}</span>
      </div>`).join('')}</div>` : ''}
  `;

  document.getElementById('ob-step-body').innerHTML = `
    <div class="ob-step-heading">${escapeHtml(step.title)}</div>
    <div class="ob-step-lead">${escapeHtml(step.lead)}</div>
    ${step.body || ''}
  `;
  /* v16 -- refresh any [data-hk] hotkey labels the tour body added. */
  try { _applyHotkeyLabels(); } catch {}

  document.getElementById('ob-back').disabled = (_obStep === 0);
  const nextBtn = document.getElementById('ob-next');
  if (step.isFinal) {
    _wireAgreementChecks();
    _updateFinalButton();
  } else {
    nextBtn.textContent = 'Next →';
    nextBtn.disabled = false;
    nextBtn.classList.remove('ob-nav-final');
  }

  // Also wire the TOS link to open external.
  const tos = document.getElementById('ob-tos-link');
  if (tos) tos.addEventListener('click', (ev) => {
    ev.preventDefault();
    window.svc.shell.openExternal('https://cloakgpt.ca/terms');
  });
}

function _wireAgreementChecks() {
  for (const el of document.querySelectorAll('#ob-step-body .ob-check-row')) {
    el.addEventListener('click', () => {
      const key = el.dataset.check;
      _obChecks[key] = !_obChecks[key];
      el.classList.toggle('checked', _obChecks[key]);
      _updateFinalButton();
    });
  }
}

function _updateFinalButton() {
  const nextBtn = document.getElementById('ob-next');
  const allChecked = _obChecks.tos && _obChecks.chargeback;
  nextBtn.textContent = 'I agree — Get started';
  nextBtn.disabled = !allChecked;
  nextBtn.classList.add('ob-nav-final');
}

async function _obNext() {
  const steps = _obSteps();
  const step = steps[_obStep];
  if (step.isFinal) {
    if (!(_obChecks.tos && _obChecks.chargeback)) return;
    await window.svc.onboarding.complete();
    _obTeardown();
    toast('Welcome to CloakGPT!', 'ok');
    return;
  }
  _obStep = Math.min(_obStep + 1, steps.length - 1);
  _renderObStep();
}

function _obBack() {
  if (_obStep === 0) return;
  _obStep -= 1;
  _renderObStep();
}

function _obSkipToEnd() {
  const steps = _obSteps();
  _obStep = steps.length - 1;
  _renderObStep();
}

async function _obDismiss() {
  if (!confirm('Skip the tutorial? You can restart it from the Support card any time.')) return;
  await window.svc.onboarding.complete();
  _obTeardown();
}

function _obTeardown() {
  window.removeEventListener('keydown', _obKeyNav, true);
  const root = document.getElementById('onboarding-root');
  if (root) root.innerHTML = '';
  _obActive = false;
}

// ─── Boot ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  /* v17 -- boot() runs in a try/catch so ANY thrown exception (missing
   * window.svc, IPC failure, downstream throw) shows the fallback with a
   * specific reason instead of silently dying to a blank blue screen. */
  try {
    await boot();
  } catch (e) {
    try { console.error('[boot] failed:', e); } catch {}
    showSafetyFallback('boot() threw:\n\n' + (e && (e.stack || e.message) ? (e.stack || e.message) : String(e)));
  }
  // Load hotkeys once the dashboard is likely to be shown.
  try { await _loadHotkeys(); } catch (e) { try { console.error('[hotkeys] load:', e); } catch {} }
});

/* ══════════════════════════════════════════════════════════════════
 * v1.7.12 (2026-08-01) — Screenshot redactor card + modal wiring.
 *
 * Self-contained IIFE — depends only on window.svc.ocr (exposed via
 * preload.js) and DOM elements added to index.html for the redactor
 * card + modal. Registers its own DOMContentLoaded handler so it
 * survives being appended anywhere in renderer.js.
 * ══════════════════════════════════════════════════════════════════ */
(function initOcrRedactor() {
  const run = () => {
    const chk       = document.getElementById('chk-ocr-enabled');
    const badge     = document.getElementById('ocr-status-badge');
    const editBtn   = document.getElementById('btn-ocr-edit');
    const modal     = document.getElementById('ocr-modal');
    const backdrop  = document.getElementById('ocr-modal-backdrop');
    const closeBtn  = document.getElementById('btn-ocr-close');
    const wordsTa   = document.getElementById('ocr-modal-words');
    const phrasesTa = document.getElementById('ocr-modal-phrases');
    const wordsCnt  = document.getElementById('ocr-modal-words-count');
    const phrasesCnt= document.getElementById('ocr-modal-phrases-count');
    const saveBtn   = document.getElementById('btn-ocr-save');
    const resetBtn  = document.getElementById('btn-ocr-reset');
    const status    = document.getElementById('ocr-modal-status');

    if (!chk || !badge || !editBtn || !modal || !window.svc || !window.svc.ocr) {
      /* Redactor UI not present or preload missing — nothing to wire. */
      return;
    }

    /* ── State helpers ────────────────────────────────── */
    const setBadge = (state) => {
      badge.classList.remove('on', 'error');
      if (state === 'on')    { badge.textContent = 'on';       badge.classList.add('on'); }
      else if (state === 'starting') { badge.textContent = 'starting…'; }
      else if (state === 'stopping') { badge.textContent = 'stopping…'; }
      else if (state === 'error')    { badge.textContent = 'error';    badge.classList.add('error'); }
      else                    { badge.textContent = 'off'; }
    };

    const linesFromTa = (ta) => {
      return (ta.value || '')
        .split('\n')
        .map(s => s.trim())
        .filter(s => s && !s.startsWith('#'));
    };
    const linesToTa = (arr) => (arr || []).join('\n');

    const updateCounts = () => {
      wordsCnt.textContent   = '(' + linesFromTa(wordsTa).length + ')';
      phrasesCnt.textContent = '(' + linesFromTa(phrasesTa).length + ')';
    };

    let dirty = false;
    const markDirty = () => {
      dirty = true;
      status.textContent = 'Unsaved changes.';
      status.className = 'ocr-modal-status dirty';
      updateCounts();
    };
    const markSaved = (n) => {
      dirty = false;
      status.textContent = `Saved ${n.wordCount} words + ${n.phraseCount} phrases.`;
      status.className = 'ocr-modal-status saved';
    };
    const markError = (msg) => {
      status.textContent = msg;
      status.className = 'ocr-modal-status error';
    };

    /* ── Initial state fetch ───────────────────────────── */
    const refreshState = async () => {
      try {
        const s = await window.svc.ocr.getState();
        chk.checked = !!s.enabled;
        setBadge(s.enabled && s.daemonRunning ? 'on'
                : s.enabled ? 'error'
                : 'off');
      } catch (e) {
        console.log('[ocr] getState failed:', e && e.message);
      }
    };
    refreshState();

    /* ── Toggle handler ────────────────────────────────── */
    chk.addEventListener('change', async () => {
      const want = chk.checked;
      setBadge(want ? 'starting' : 'stopping');
      chk.disabled = true;
      try {
        const r = await window.svc.ocr.setEnabled(want);
        if (!r || !r.ok) {
          setBadge('error');
          chk.checked = !want;
        } else {
          setBadge(r.daemonRunning ? 'on' : (want ? 'error' : 'off'));
        }
      } catch (e) {
        setBadge('error');
        chk.checked = !want;
        console.log('[ocr] setEnabled failed:', e && e.message);
      } finally {
        chk.disabled = false;
      }
    });

    /* ── Modal open / close ────────────────────────────── */
    const openModal = async () => {
      status.textContent = 'Loading…';
      status.className = 'ocr-modal-status';
      dirty = false;
      try {
        const bl = await window.svc.ocr.getBlacklist();
        wordsTa.value   = linesToTa(bl.words);
        phrasesTa.value = linesToTa(bl.phrases);
        updateCounts();
        status.textContent = bl.usingDefaults
          ? 'Loaded (using built-in defaults).'
          : 'Loaded from disk.';
      } catch (e) {
        markError('Load failed: ' + (e && e.message || 'unknown'));
      }
      modal.hidden = false;
      modal.setAttribute('aria-hidden', 'false');
      setTimeout(() => wordsTa.focus(), 30);
    };
    const closeModal = () => {
      if (dirty) {
        if (!confirm('Discard unsaved changes to the redactor blacklist?')) return;
      }
      modal.hidden = true;
      modal.setAttribute('aria-hidden', 'true');
    };

    editBtn.addEventListener('click', openModal);
    closeBtn.addEventListener('click', closeModal);
    backdrop.addEventListener('click', closeModal);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !modal.hidden) closeModal();
    });

    /* ── Textarea change tracking ──────────────────────── */
    wordsTa.addEventListener('input', markDirty);
    phrasesTa.addEventListener('input', markDirty);

    /* ── Save ──────────────────────────────────────────── */
    saveBtn.addEventListener('click', async () => {
      saveBtn.disabled = true;
      const payload = {
        words:   linesFromTa(wordsTa),
        phrases: linesFromTa(phrasesTa),
      };
      try {
        const r = await window.svc.ocr.saveBlacklist(payload);
        if (r && r.ok) {
          markSaved(r);
        } else {
          markError('Save failed: ' + (r && r.err || 'unknown'));
        }
      } catch (e) {
        markError('Save threw: ' + (e && e.message || 'unknown'));
      } finally {
        saveBtn.disabled = false;
      }
    });

    /* ── Reset (repopulates textareas from defaults; user still saves) ── */
    resetBtn.addEventListener('click', async () => {
      if (!confirm('Replace both lists with the built-in defaults? '
                 + 'You will still need to press Save to persist.')) return;
      try {
        const d = await window.svc.ocr.getDefaults();
        wordsTa.value   = linesToTa(d.words);
        phrasesTa.value = linesToTa(d.phrases);
        markDirty();
        status.textContent = 'Defaults loaded — press Save to persist.';
        status.className = 'ocr-modal-status dirty';
      } catch (e) {
        markError('Defaults load failed: ' + (e && e.message || 'unknown'));
      }
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true });
  } else {
    run();
  }
})();

/* ══════════════════════════════════════════════════════════════════
 * v15 (2026-09-22) — AutoSolver + Agent settings card wiring.
 *
 * Self-contained IIFE. Depends only on window.svc.autosolver (preload).
 * Loads on boot, saves the FULL settings object on any change, and the
 * injected payload hot-reloads autosolver.json within ~1.5s. No re-inject.
 * ══════════════════════════════════════════════════════════════════ */
(function initAutosolverCard() {
  const run = async () => {
    const el = (id) => document.getElementById(id);
    const chkEnabled  = el('chk-as-enabled');
    const chkClick    = el('chk-as-autoclick');
    const chkHuman    = el('chk-as-humanize');
    const chkUia      = el('chk-as-uia');
    const chkDot      = el('chk-as-dot');
    const chkDotJump  = el('chk-as-dotjump');
    const selEdge     = el('sel-as-edge');
    const statusEl    = el('as-save-status');
    // v15.1.7 dot appearance controls
    const rngDotSize    = el('rng-dot-size');
    const lblDotSize    = el('lbl-dot-size');
    const rngDotOpacity = el('rng-dot-opacity');
    const lblDotOpacity = el('lbl-dot-opacity');
    const rngDotHold    = el('rng-dot-hold');
    const lblDotHold    = el('lbl-dot-hold');
    const numDotW       = el('num-dot-w');
    const numDotH       = el('num-dot-h');
    const chkDotHide    = el('chk-dot-hide-when-overlay');

    if (!chkEnabled || !window.svc || !window.svc.autosolver) return; // card / preload absent

    let saveTimer = null;
    const flash = (ok, msg) => {
      if (!statusEl) return;
      statusEl.textContent = msg;
      statusEl.classList.toggle('saved', !!ok);
    };

    const collect = () => ({
      autosolver_enabled: chkEnabled.checked ? 1 : 0,
      auto_click:         chkClick.checked ? 1 : 0,
      humanize:           chkHuman.checked ? 1 : 0,
      uia_snap:           chkUia.checked ? 1 : 0,
      dot_enabled:        chkDot.checked ? 1 : 0,
      dot_jump:           chkDotJump.checked ? 1 : 0,
      render_max_edge:    Number(selEdge.value) || 1280,
      // v15.1.7 dot appearance / behavior master controls
      dot_size_px:         rngDotSize    ? (Number(rngDotSize.value)    || 8)    : undefined,
      dot_opacity:         rngDotOpacity ? ((Number(rngDotOpacity.value) || 30) / 100) : undefined,
      dot_hold_ms:         rngDotHold    ? (Number(rngDotHold.value)    || 2000) : undefined,
      dot_full_w:          numDotW       ? (Number(numDotW.value)       || 340)  : undefined,
      dot_full_h:          numDotH       ? (Number(numDotH.value)       || 210)  : undefined,
      dot_hide_when_overlay: chkDotHide  ? (chkDotHide.checked ? 1 : 0)          : undefined,
    });

    const save = () => {
      flash(false, 'Saving…');
      clearTimeout(saveTimer);
      saveTimer = setTimeout(async () => {
        try {
          const r = await window.svc.autosolver.save(collect());
          if (r && r.ok) flash(true, 'Saved — applies to the running overlay within ~2s.');
          else           flash(false, 'Save failed: ' + ((r && r.err) || 'unknown'));
        } catch (e) {
          flash(false, 'Save failed: ' + (e && e.message || 'unknown'));
        }
      }, 250);
    };

    // Live label updates while sliding.
    const bindRangeLbl = (rng, lbl, suffix) => {
      if (!rng || !lbl) return;
      const upd = () => { lbl.textContent = rng.value + suffix; };
      rng.addEventListener('input', upd);
      upd();
    };
    bindRangeLbl(rngDotSize,    lblDotSize,    ' px');
    bindRangeLbl(rngDotOpacity, lblDotOpacity, '%');
    bindRangeLbl(rngDotHold,    lblDotHold,    ' ms');

    // ── initial load ──
    try {
      const s = await window.svc.autosolver.load();
      if (s) {
        chkEnabled.checked = !!s.autosolver_enabled;
        chkClick.checked   = !!s.auto_click;
        chkHuman.checked   = !!s.humanize;
        chkUia.checked     = !!s.uia_snap;
        chkDot.checked     = !!s.dot_enabled;
        chkDotJump.checked = !!s.dot_jump;
        const edges = [960, 1280, 1600, 1920];
        const near = edges.reduce((a, b) => Math.abs(b - s.render_max_edge) < Math.abs(a - s.render_max_edge) ? b : a, 1280);
        selEdge.value = String(near);
        // dot appearance
        if (rngDotSize)    { rngDotSize.value    = String(Math.max(5, Math.min(16, Number(s.dot_size_px) || 8))); lblDotSize.textContent = rngDotSize.value + ' px'; }
        if (rngDotOpacity) { const p = Math.round((Number(s.dot_opacity) || 0.30) * 100); rngDotOpacity.value = String(Math.max(10, Math.min(100, p))); lblDotOpacity.textContent = rngDotOpacity.value + '%'; }
        if (rngDotHold)    { rngDotHold.value    = String(Math.max(500, Math.min(4000, Number(s.dot_hold_ms) || 2000))); lblDotHold.textContent = rngDotHold.value + ' ms'; }
        if (numDotW)       numDotW.value = Number(s.dot_full_w) || 340;
        if (numDotH)       numDotH.value = Number(s.dot_full_h) || 210;
        if (chkDotHide)    chkDotHide.checked = s.dot_hide_when_overlay !== 0;
      }
    } catch { /* leave HTML defaults */ }

    // ── change listeners ──
    [chkEnabled, chkClick, chkHuman, chkUia, chkDot, chkDotJump].forEach(c => c.addEventListener('change', save));
    selEdge.addEventListener('change', save);
    // v15.1.7
    [rngDotSize, rngDotOpacity, rngDotHold].forEach(r => { if (r) r.addEventListener('change', save); });
    [numDotW, numDotH].forEach(n => { if (n) n.addEventListener('change', save); });
    if (chkDotHide) chkDotHide.addEventListener('change', save);

    // v16 (2026-09-22) -- dashboard's promoted "Show answer dot" toggle in the
    // status card mirrors chk-as-dot two-ways. Flipping either side updates the
    // other + fires the same save (autosolver.json, mtime-watched by payload).
    const chkDashDot = el('chk-dashboard-dot');
    if (chkDashDot) {
      chkDashDot.checked = chkDot.checked;
      chkDashDot.addEventListener('change', () => {
        chkDot.checked = chkDashDot.checked;
        save();
      });
      chkDot.addEventListener('change', () => {
        chkDashDot.checked = chkDot.checked;
      });
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true });
  } else {
    run();
  }
})();
