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
const SCREENS = ['splash', 'login', 'nosub', 'dashboard'];
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

// ─── Global state ───────────────────────────────────────────────
let state = {
  session: null,
  subscription: null,
  hwid: null,
  injected: false,
  ldb_running: false,
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
  if (!dto || !dto.session) {
    _renderLoginDeviceId();
    // Show a clean-slate reason if the session was cleared for a specific cause.
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
  if (!dto.subscription || dto.subscription.active === false) {
    _renderNoSub();
    showScreen('nosub');
    return;
  }
  _renderDashboard();
  showScreen('dashboard');
  pollStatusLoop();
}

// ─── Login ──────────────────────────────────────────────────────
function _renderLoginDeviceId() {
  const el = document.getElementById('login-device');
  if (el) el.textContent = shortenHwid(state.hwid);
}

function showLoginError(msg) {
  const el = document.getElementById('login-error');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
}
function clearLoginError() {
  const el = document.getElementById('login-error');
  if (el) { el.classList.remove('show'); el.textContent = ''; }
}

document.getElementById('btn-signin').addEventListener('click', async () => {
  clearLoginError();
  showLoading('Opening browser…', 'Complete Google sign-in in your browser.');
  try {
    const dto = await window.svc.license.signIn();
    if (dto && dto.error) {
      hideLoading();
      showLoginError(dto.error);
      toast(dto.error, 'err');
      return;
    }
    state.session = dto.session;
    state.subscription = dto.subscription;
    state.hwid = dto.hwid || state.hwid;
    hideLoading();
    if (!dto.subscription || dto.subscription.active === false) {
      _renderNoSub();
      showScreen('nosub');
      return;
    }
    _renderDashboard();
    showScreen('dashboard');
    pollStatusLoop();
    toast('Signed in — welcome back.', 'ok');
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
  if (sub.error) {
    statusEl.innerHTML = `Couldn't reach license server: <b>${escapeHtml(sub.error)}</b>`;
  } else {
    statusEl.innerHTML = `Subscription status: <b>${escapeHtml(sub.status || 'not_found')}</b>`;
  }
}

document.getElementById('btn-nosub-billing').addEventListener('click', () => {
  window.svc.shell.openExternal('https://cloakgpt.ca/dashboard');
});

document.getElementById('btn-nosub-retry').addEventListener('click', async () => {
  showLoading('Re-checking subscription…', 'Querying Supabase for active grants + subscriptions.');
  try {
    const dto = await window.svc.license.load();
    hideLoading();
    if (!dto || !dto.session) {
      state.session = null; state.subscription = null;
      _renderLoginDeviceId();
      showScreen('login');
      toast('Signed out — please sign in again.', 'err');
      return;
    }
    state.session = dto.session;
    state.subscription = dto.subscription;
    state.hwid = dto.hwid || state.hwid;
    if (dto.subscription && dto.subscription.active) {
      _renderDashboard();
      showScreen('dashboard');
      pollStatusLoop();
      toast('Subscription active — welcome back.', 'ok');
    } else {
      _renderNoSub();
      const why = (dto.subscription && dto.subscription.error) ? ` (${dto.subscription.error})` : '';
      toast(`Still no active subscription${why}.`, 'err');
    }
  } catch (e) {
    hideLoading();
    toast(`Retry failed: ${e.message || e}`, 'err');
  }
});

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
    const r = await window.svc.injector.inject({
      keys: bag,
      tier: state.chosen_tier,
    });
    hideLoading();
    if (r.ok) {
      state.injected = true;
      toast(`Overlay armed with ${configured.length} provider${configured.length === 1 ? '' : 's'} — launch LockDown Browser now.`, 'ok');
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
    state.injected    = !!s.payload_loaded;
    state.ldb_running = !!s.ldb_running;
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
    sub.textContent = state.ldb_running
      ? 'LockDown Browser is running — hotkeys are active. Ctrl+Shift+Space to solve.'
      : 'Overlay armed. Waiting for LockDown Browser to launch.';
    document.getElementById('btn-inject').disabled = true;
    document.getElementById('btn-uninject').disabled = false;
  } else {
    title.textContent = 'Payload: Not Injected';
    sub.textContent = 'Click Inject to arm the overlay inside DWM.';
    document.getElementById('btn-inject').disabled = false;
    document.getElementById('btn-uninject').disabled = true;
  }
  // Badges
  const ldbDot = document.getElementById('d-badge-ldb-dot');
  ldbDot.classList.remove('on', 'warn');
  if (state.ldb_running) ldbDot.classList.add('on');
  document.getElementById('d-badge-ldb').textContent = state.ldb_running ? 'Running' : 'Not detected';

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
    state.session = null; state.subscription = null;
    state.injected = false;
    clearInterval(_pollTimer);
    _renderLoginDeviceId();
    const reason = (info && info.reason) || 'unknown';
    let msg = 'Your session was locked out.';
    if (reason === 'subscription_inactive') {
      msg = 'Your CloakGPT subscription is no longer active. The overlay has been unloaded. Please renew and sign in again.';
    } else if (reason.startsWith('too_many_failures')) {
      msg = 'Could not reach the license server after several attempts. The overlay has been unloaded for safety. Sign in again once you have a stable connection.';
    }
    showLoginError(msg);
    showScreen('login');
    toast('Signed out automatically — see banner for details.', 'err');
  });
}

// ─── Boot ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', boot);
