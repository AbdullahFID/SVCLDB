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

// ─── Screen management ──────────────────────────────────────────
const SCREENS = ['splash', 'login', 'nosub', 'dashboard', 'suspended', 'devicelimit'];
function showScreen(name) {
  for (const s of SCREENS) {
    const el = document.getElementById(`screen-${s}`);
    if (el) el.classList.toggle('active', s === name);
  }
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
    const short = 'v' + v.split('.').slice(0, 2).join('.');   // "v1.2"
    const long  = 'CloakGPT v' + v;                             // "CloakGPT v1.2.0"
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
  chosen_provider: null,   // 0 (auto) or 1..4
  chosen_tier: 1,          // 0..3
};

// ─── Splash → figure out where to go ────────────────────────────
async function boot() {
  showScreen('splash');
  const st = document.getElementById('splash-status');
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
    if (r && r.ok) {
      toast(r.message || 'Fixed. Re-checking\u2026', 'ok');
      // Re-run the whole boot check - if the ONLY issue was the one
      // we just fixed, sign-in becomes available again.
      setTimeout(() => { boot().catch(e => console.log('[renderer] boot after fix:', e.message)); }, 400);
    } else {
      const err = (r && r.message) || 'remediation failed';
      toast(`Fix failed: ${err}`, 'err');
      btn.disabled = false;
      btn.textContent = origLabel;
    }
  } catch (e) {
    toast(`Fix failed: ${e.message || e}`, 'err');
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
  showLoading('Resetting local data…', 'Clearing session, cache, and hardware fingerprint.');
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

document.getElementById('btn-signout').addEventListener('click', async () => {
  if (!confirm('Sign out? The payload will be unloaded from DWM.')) return;
  showLoading('Signing out…', 'Unloading payload from DWM.');
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
document.querySelectorAll('#chip-tier .chip[data-tier]').forEach(c => {
  c.addEventListener('click', () => {
    document.querySelectorAll('#chip-tier .chip[data-tier]').forEach(x => x.classList.remove('active'));
    c.classList.add('active');
    state.chosen_tier = parseInt(c.dataset.tier, 10);
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
    'Both the encrypted DPAPI store and the HWID-bound AES-GCM fallback ' +
    'are wiped. You will need to re-enter every key before you can Inject again.\n\n' +
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
    '  1. Uninject the overlay from DWM\n' +
    '  2. Kill DWM cleanly (screen briefly goes black, Windows auto-respawns)\n' +
    '  3. DELETE everything:\n' +
    '       - your session (you\'ll need to sign in with Google again)\n' +
    '       - all 4 stored API keys\n' +
    '       - your custom system prompt\n' +
    '       - hotkey customizations\n' +
    '       - encrypted diagnostic logs\n' +
    '       - contents of C:\\ProgramData\\WinAudioSvc\\\n\n' +
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
    'Uninjecting + killing DWM + wiping user data. ~5 seconds.');
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
        ? `${failed.length} step(s) failed - some files may need manual deletion from ` +
          `C:\\ProgramData\\WinAudioSvc\\. Reboot recommended.\n\n`
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
let _ovaState  = { size_mode: 0, w: 560, h: 420, alpha: 0.94 };
let _ovaSaved  = { ...(_ovaState) };   // last-saved snapshot for dirty check

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
  setText('val-ova-w',     `${_ovaState.w} px`);
  setText('val-ova-h',     `${_ovaState.h} px`);
  setText('val-ova-alpha', `${Math.round(_ovaState.alpha * 100)}%`);
}

function _ovaDirty() {
  return _ovaState.size_mode !== _ovaSaved.size_mode
      || _ovaState.w         !== _ovaSaved.w
      || _ovaState.h         !== _ovaSaved.h
      || Math.abs(_ovaState.alpha - _ovaSaved.alpha) > 0.005;
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
  if (_ovaState.alpha < 0.20) _ovaState.alpha = 0.20;
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
}

function _ovaRefreshAll() {
  _ovaClampToBounds();
  _ovaSyncSliderRanges();
  _ovaRenderValues();
  _ovaRenderPreview();
  _ovaRenderStatus();
}

async function _initOverlayCard() {
  try {
    const p = await window.svc.overlay.load();
    if (p) {
      _ovaState = { size_mode: p.size_mode ? 1 : 0, w: +p.w, h: +p.h, alpha: +p.alpha };
      _ovaSaved = { ..._ovaState };
    }
  } catch (e) { console.log('[renderer] overlay load failed:', e.message); }

  const chkUltra = document.getElementById('chk-ova-ultra');
  const rngW     = document.getElementById('rng-ova-w');
  const rngH     = document.getElementById('rng-ova-h');
  const rngA     = document.getElementById('rng-ova-alpha');
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
    rngA.addEventListener('input', () => {
      _ovaState.alpha = (+rngA.value) / 100;
      _ovaRenderValues(); _ovaRenderPreview(); _ovaRenderStatus();
    });
  }

  document.querySelectorAll('#overlay-appearance-card .ova-preset').forEach((chip) => {
    chip.addEventListener('click', () => {
      const w = +chip.dataset.w, h = +chip.dataset.h;
      const ultra = chip.dataset.ultra === '1' ? 1 : 0;
      _ovaState = { size_mode: ultra, w, h, alpha: _ovaState.alpha };
      if (chkUltra) chkUltra.checked = !!ultra;
      _ovaRefreshAll();
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
        '  \u2022 Alpha / opacity (defaults to 94%)\n' +
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
        _ovaState = { size_mode: p.size_mode ? 1 : 0, w: +p.w, h: +p.h, alpha: +p.alpha };
        _ovaSaved = { ..._ovaState };
        if (chkUltra) chkUltra.checked = !!_ovaState.size_mode;
        _ovaRefreshAll();
        /* Toast reflects what actually happened server-side so the user
         * isn't left guessing. Toast supports only 'ok' + 'err' so the
         * "needs manual re-inject" case stays as 'ok' with a call-to-
         * action embedded in the message. */
        if (p.reinjected) {
          toast('Overlay reset \u2014 payload re-injected with defaults.', 'ok');
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
  if (!anyKey) {
    toast('Enter at least one AI provider API key first.', 'err');
    const firstIpt = document.querySelector('.provider-input');
    if (firstIpt) firstIpt.focus();
    return;
  }
  // Persist immediately so a crash between Inject and background save
  // doesn't drop the newly-typed keys.
  await window.svc.apiKeys.save(bag);
  const configured = Object.entries(bag).filter(([, v]) => v).map(([k]) => k);
  showLoading(
    `Injecting overlay…`,
    `Configured: ${configured.join(', ')}. Runs symbol resolver on first arm (~30 s for PDB download; instant after).`
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
  showLoading('Uninjecting…', 'Signaling payload to unload cleanly.');
  try {
    const r = await window.svc.injector.uninject();
    hideLoading();
    if (r.ok) {
      state.injected = false;
      toast('Payload unloaded.', 'ok');
      _refreshStatus();
    } else {
      toast(`Uninject returned code ${r.exitCode}. Payload may already be down.`, 'err');
      _refreshStatus();
    }
  } catch (e) {
    hideLoading();
    toast(`Uninject failed: ${e.message || e}`, 'err');
  }
});

document.getElementById('btn-killall').addEventListener('click', async () => {
  if (!confirm(
    'EMERGENCY STOP will:\n' +
    '  • unload the payload\n' +
    '  • terminate dwm.exe (Windows respawns in ~2s)\n' +
    '  • kill every running sihost.exe from our install dir\n\n' +
    'Your screen will briefly go black. Continue?'
  )) return;
  showLoading('Emergency stopping…', 'Terminating DWM + sweeping launchers.');
  try {
    const r = await window.svc.injector.killAll();
    hideLoading();
    if (r.ok) {
      state.injected = false;
      toast('All CloakGPT processes stopped.', 'ok');
      _refreshStatus();
    } else {
      toast(`Kill-all returned ${r.exitCode}.`, 'err');
    }
  } catch (e) {
    hideLoading();
    toast(`Kill-all failed: ${e.message || e}`, 'err');
  }
});

function _explainInjectExit(code, err) {
  if (err) return err;
  switch (code) {
    case 10: return 'JSON handoff file missing (installer issue).';
    case 11: return 'JSON handoff invalid (may indicate a version mismatch).';
    case 12: return 'Could not write encrypted config.dat (check ACLs on C:\\ProgramData\\WinAudioSvc).';
    case 13: return 'Payload injection into dwm.exe failed (see launcher.log).';
    case  2: return 'Not elevated — launcher requires admin.';
    case  3: return 'API key missing.';
    default: return `exit ${code}`;
  }
}

// ─── Status polling ────────────────────────────────────────────
async function _refreshStatus() {
  try {
    const s = await window.svc.injector.status();
    state.injected = !!s.payload_loaded;
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
    title.textContent = 'Payload: Active';
    sub.textContent = 'Overlay is armed. Hotkeys are live — Ctrl+Shift+Space to ask AI.';
    document.getElementById('btn-inject').disabled = true;
    document.getElementById('btn-uninject').disabled = false;
  } else {
    title.textContent = 'Payload: Not Injected';
    sub.textContent = 'Click Inject to arm the overlay inside DWM.';
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
];

const VK_TO_NAME = {
  0x08: 'Backspace', 0x09: 'Tab', 0x0D: 'Enter', 0x1B: 'Esc',
  0x20: 'Space',
  0x25: 'Left', 0x26: 'Up', 0x27: 'Right', 0x28: 'Down',
  0x2D: 'Ins', 0x2E: 'Del', 0x23: 'End', 0x24: 'Home',
  0x21: 'PgUp', 0x22: 'PgDn',
  0x70: 'F1', 0x71: 'F2', 0x72: 'F3', 0x73: 'F4', 0x74: 'F5', 0x75: 'F6',
  0x76: 'F7', 0x77: 'F8', 0x78: 'F9', 0x79: 'F10', 0x7A: 'F11', 0x7B: 'F12',
  0xBA: ';', 0xBB: '=', 0xBC: ',', 0xBD: '-', 0xBE: '.', 0xBF: '/',
  0xC0: '`', 0xDB: '[', 0xDC: '\\', 0xDD: ']', 0xDE: "'",
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
  };
  if (map[code]) return map[code];
  if (map[key]) return map[key];
  return 0;
}

function packHotkey(mod, vk) {
  return ((mod & 0xFF) << 16) | (vk & 0xFFFF);
}

function unpackHotkey(packed) {
  return { mod: (packed >>> 16) & 0xFF, vk: packed & 0xFFFF };
}

function formatHotkey(packed) {
  if (!packed) return '(unbound)';
  const { mod, vk } = unpackHotkey(packed);
  const parts = [];
  if (mod & 1) parts.push('Ctrl');
  if (mod & 2) parts.push('Shift');
  if (mod & 4) parts.push('Alt');
  const name = VK_TO_NAME[vk] || (vk >= 0x30 && vk <= 0x5A
    ? String.fromCharCode(vk)
    : `0x${vk.toString(16).toUpperCase()}`);
  parts.push(name);
  return parts.join('+');
}

let _hkState = { defaults: [], overrides: {} };
let _hkRecording = null;   // { slot } while a modal is open

async function _loadHotkeys() {
  const r = await window.svc.hotkeys.load();
  _hkState.defaults  = r.defaults || [];
  _hkState.overrides = r.overrides || {};
  _renderHotkeyEditor();
}

// Effective binding for a slot: override wins, else default.
function _bindingFor(slot) {
  if (Object.prototype.hasOwnProperty.call(_hkState.overrides, slot)) {
    return _hkState.overrides[slot];
  }
  return _hkState.defaults[slot] || 0;
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
    row.innerHTML = `
      <div class="hk-editor-label" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
      <div class="hk-editor-reset-cell">
        <button class="hk-editor-btn${!packed ? ' unbound' : ''}" title="Click the pencil to remap${conflicts.length ? ' — CONFLICT with slot ' + conflicts.join(', ') : ''}">
          <span class="hk-editor-btn-text">${escapeHtml(btnLabel)}</span>
          ${pencilSvg}
        </button>
        ${isOverride ? `<button class="hk-editor-clear" title="Reset to default (${formatHotkey(_hkState.defaults[slot])})">↺</button>` : ''}
      </div>
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
}

function _openHotkeyRecorder(slot) {
  if (_hkRecording) return;
  const root = document.getElementById('hk-record-modal-root');
  const label = HK_LABELS[slot] || `Slot ${slot}`;
  const current = _bindingFor(slot);
  const defBinding = _hkState.defaults[slot] || 0;
  _hkRecording = { slot };
  root.innerHTML = `
    <div class="modal-shade">
      <div class="modal-box">
        <div class="modal-title">Record new hotkey</div>
        <div class="modal-action-name">${escapeHtml(label)}</div>
        <div class="modal-current recording" id="rec-current">Press any key…</div>
        <div class="modal-hint">
          Hold <kbd>Ctrl</kbd> / <kbd>Shift</kbd> / <kbd>Alt</kbd> then press the target key.
          <br>Press <kbd>Esc</kbd> to cancel${current ? '' : ' (leave unbound)'}.
          ${defBinding && defBinding !== current ? `<br>Default is <b>${escapeHtml(formatHotkey(defBinding))}</b>.` : ''}
        </div>
        <div class="modal-actions">
          <button id="rec-cancel" class="btn btn-secondary">Cancel</button>
          <button id="rec-unbind" class="btn btn-danger">Unbind</button>
        </div>
      </div>
    </div>
  `;
  const curEl = document.getElementById('rec-current');
  let captured = null;

  const onKey = (e) => {
    if (!_hkRecording) return;
    e.preventDefault(); e.stopPropagation();
    if (e.key === 'Escape') { _closeRecorder(false); return; }
    // Modifier-only key = live preview.
    if (e.key === 'Control' || e.key === 'Shift' || e.key === 'Alt' || e.key === 'Meta') {
      const parts = [];
      if (e.ctrlKey)  parts.push('Ctrl');
      if (e.shiftKey) parts.push('Shift');
      if (e.altKey)   parts.push('Alt');
      parts.push('___');
      curEl.textContent = parts.join('+');
      return;
    }
    const vk = eventToVk(e);
    if (!vk) return;
    let mod = 0;
    if (e.ctrlKey)  mod |= 1;
    if (e.shiftKey) mod |= 2;
    if (e.altKey)   mod |= 4;
    const packed = packHotkey(mod, vk);
    captured = packed;
    curEl.classList.remove('recording');
    curEl.textContent = formatHotkey(packed);
    // Auto-save + close after a short debounce so the user sees confirmation.
    setTimeout(async () => {
      if (!_hkRecording) return;
      _hkState.overrides[slot] = packed;
      const save = await window.svc.hotkeys.save(_hkState.overrides);
      _closeRecorder(true);
      if (save && save.ok) {
        toast(`Set ${HK_LABELS[slot]} to ${formatHotkey(packed)} — takes effect on next Inject.`, 'ok');
      } else {
        toast('Save failed.', 'err');
      }
    }, 350);
  };

  const onKeyUp = (e) => { e.preventDefault(); e.stopPropagation(); };

  window.addEventListener('keydown', onKey, true);
  window.addEventListener('keyup',   onKeyUp, true);

  function _closeRecorder(_saved) {
    window.removeEventListener('keydown', onKey, true);
    window.removeEventListener('keyup',   onKeyUp, true);
    root.innerHTML = '';
    _hkRecording = null;
    _renderHotkeyEditor();
  }

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
//  Onboarding walkthrough (first-launch, 12 steps)
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
        <p>CloakGPT lives inside the Windows Desktop Window Manager (dwm.exe). That means:</p>
        <ul>
          <li>The overlay renders <b>above</b> whatever app you\'re looking at (including kiosk/exam browsers).</li>
          <li>It stays <b>hidden</b> from screen recorders and monitoring tools.</li>
          <li>You control it entirely with keyboard shortcuts — no window to click.</li>
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
          <li><b>OpenAI</b> — GPT-5, o-series reasoning models</li>
          <li><b>Anthropic</b> — Claude Opus, Sonnet, Haiku</li>
          <li><b>Google</b> — Gemini 3.x, 2.5 flash</li>
          <li><b>OpenRouter</b> — has free models if you\'re trying it out</li>
        </ul>
        <p>Configure multiple providers so if one rate-limits, we transparently fall back to the next.</p>
        <p>Keys are encrypted with DPAPI (per-user) + AES-256-GCM (HWID-bound) — never plaintext on disk.</p>
      `,
      features: [
        'Multi-provider failover on rate limits',
        'Per-key live tester + latency stats',
        'Encrypted at rest with your Windows account key',
      ],
    },
    { // 2
      tag: 'STEP 2',
      icon: 'zap',
      title: 'Click Inject',
      lead: 'Loads the overlay into dwm.exe. About 30 s the first time (PDB download), instant after.',
      body: `
        <p>Once you have at least one API key configured, hit the big blue <b>Inject Now</b> button.</p>
        <p>Behind the scenes we:</p>
        <ul>
          <li>Resolve the current Windows build\'s dwmcore offsets from the Microsoft symbol server.</li>
          <li>Manually map our payload DLL into dwm.exe (bypasses code-integrity policy).</li>
          <li>Install 7 rendering hooks so we can composite the overlay every frame.</li>
        </ul>
        <p>When you see <b>Payload: Active</b> with a green dot, the overlay is armed and hotkeys are live.</p>
      `,
      features: [
        'Zero disk footprint (payload embedded in launcher exe)',
        'Windows updates? Just click Inject again — offsets refresh automatically.',
      ],
    },
    { // 3
      tag: 'STEP 3',
      icon: 'zap',
      title: 'Screenshot + ask AI',
      lead: 'The bread-and-butter workflow: press one hotkey, get an answer.',
      body: `
        <div class="ob-kbdrow">
          <kbd>Ctrl+Shift+Space</kbd>
          <span class="desc">Capture the current screen + send to your active AI tier</span>
        </div>
        <p>The AI reply appears in the overlay a few seconds later. Cycle model tier with <kbd style="font-family:monospace">Ctrl+Alt+M</kbd> if you want faster (Cheap) or better (Strong) answers.</p>
        <p>All keystrokes for hotkeys are consumed by a low-level hook <b>before</b> any other app sees them — invisible to whatever app you're inside of.</p>
      `,
      features: [
        'Overlay pixels are excluded from every screen capture',
        'Reply is copied to clipboard automatically — Ctrl+V to paste it',
      ],
    },
    { // 4
      tag: 'STEP 4',
      icon: 'message-square',
      title: 'Type a follow-up',
      lead: 'For freeform questions, use chat mode — no screenshot required.',
      body: `
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+T</kbd>
          <span class="desc">Enter chat mode — type your question, press Enter to submit</span>
        </div>
        <p>Chat mode captures every keystroke — even letters and punctuation — so <b>nothing</b> leaks into the underlying app while you\'re typing. Perfect if you\'re on a Google Doc or exam browser and don\'t want it to hear you type.</p>
        <p>The current screenshot is attached as context, so you can ask "explain this passage" or "what step comes next?".</p>
      `,
      features: [
        'Fully layout-aware (French AZERTY, dead keys, etc.)',
        'Enter submits, Esc cancels',
      ],
    },
    { // 5
      tag: 'STEP 5',
      icon: 'move',
      title: 'Position + resize',
      lead: 'The overlay starts in the top-left. Move / resize / restyle to taste.',
      body: `
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+Arrows</kbd>
          <span class="desc">Nudge overlay 20 px in any direction (hold to repeat)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd>Ctrl+Shift+Alt+Arrows</kbd>
          <span class="desc">Resize the overlay (wider/taller/narrower/shorter)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+Q</kbd>
          <span class="desc">Snap to next corner (TL → TR → BR → BL)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+R</kbd>
          <span class="desc">Reset overlay to default position + size</span>
        </div>
        <p>Position, size, opacity, and font size are all remembered across launches.</p>
      `,
      features: [
        'Hold Ctrl+Alt+Arrow to auto-repeat move at 20 Hz',
        'Everything you tweak persists automatically',
      ],
    },
    { // 6
      tag: 'STEP 6',
      icon: 'eye-off',
      title: 'Panic key + toggle',
      lead: 'Two hotkeys that always work: hide the overlay, or unload it entirely.',
      body: `
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+G</kbd>
          <span class="desc">Toggle overlay visibility (payload still armed)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+X</kbd>
          <span class="desc">Back to home / soft quit (clean uninject)</span>
        </div>
        <div class="ob-kbdrow" style="border-color:rgba(239,68,68,0.35);background:rgba(239,68,68,0.05)">
          <kbd>Ctrl+Shift+Alt+K</kbd>
          <span class="desc" style="color:#fca5a5"><b>EMERGENCY STOP</b> — unloads + terminates dwm.exe (Windows respawns fresh in ~2 s)</span>
        </div>
        <p>Use <kbd style="font-family:monospace">Ctrl+Alt+G</kbd> if a proctor walks up. Use <kbd style="font-family:monospace">Ctrl+Shift+Alt+K</kbd> if you need the overlay <b>gone</b> immediately — your screen will flash black for 2 s while DWM restarts.</p>
      `,
      features: [
        'Panic keys always work, even mid-AI-request',
        'Emergency stop leaves no trace of the payload in memory',
      ],
    },
    { // 7
      tag: 'STEP 7',
      icon: 'copy',
      title: 'Copy modes',
      lead: 'Three different copy hotkeys for different situations.',
      body: `
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+C</kbd>
          <span class="desc">Copy the ENTIRE last AI reply (markdown + code + math)</span>
        </div>
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+A</kbd>
          <span class="desc">Copy JUST the direct answer (first line — "x = 4", "B) Photosynthesis")</span>
        </div>
        <div class="ob-kbdrow">
          <kbd>Ctrl+Shift+Alt+C</kbd>
          <span class="desc">Copy JUST fenced code blocks (Python, JS, etc.)</span>
        </div>
        <p>Pick the shortest one that fits — the AI is prompted to always put the direct answer on line 1, so <kbd style="font-family:monospace">Ctrl+Alt+A</kbd> is often enough for MCQs.</p>
      `,
      features: [
        'Copies clean plaintext (no markdown asterisks or backticks)',
        'Preserved exactly as generated — you paste into anything',
      ],
    },
    { // 8
      tag: 'STEP 8',
      icon: 'stop-circle',
      title: 'Reasoning + stop',
      lead: 'Reasoning models can take a while. You can abort any time.',
      body: `
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+S</kbd>
          <span class="desc">Stop the current AI response (partial reply preserved)</span>
        </div>
        <p>Strong-tier reasoning models (o3, Opus 4.8, GPT-5.5 Pro) can spend 30 s – 10 min thinking. Ctrl+Alt+S aborts cleanly and appends "(stopped by user)" to whatever streamed so far.</p>
        <p>Regen the last question with a fresh AI call:</p>
        <div class="ob-kbdrow">
          <kbd>Ctrl+Alt+Enter</kbd>
          <span class="desc">Regenerate — re-runs your last question with the current tier/provider</span>
        </div>
      `,
      features: [
        'Abort works even mid-reasoning-thinking-phase',
        'Regen useful for cycling tier and comparing answers',
      ],
    },
    { // 9
      tag: 'STEP 9',
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
    { // 10
      tag: 'STEP 10',
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
        'Removing a device unloads any injected overlay there',
        'HWID is derived from your motherboard + Windows install — stable',
      ],
    },
    { // 11 — final agreement
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
          <div class="ob-progress-label" id="ob-label">1 / 12</div>
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
  boot();
  // Load hotkeys once the dashboard is likely to be shown.
  try { await _loadHotkeys(); } catch {}
});
