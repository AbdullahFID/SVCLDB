// ═══════════════════════════════════════════════════════════════
// auth.js — Supabase PKCE OAuth via local HTTP callback + system browser.
//
// Adapted from hooksdll/lumio/src/license/auth.js. Kept the same
// contract:
//   - startOAuth()  →  Promise<session>
//   - loadSessionWithRecovery()  →  { session, clearReason }
//   - refreshSession(session)  →  Promise<newSession>
//   - browser HTML pages (success / error / no-subscription) rendered
//     server-side so the user sees a polished landing after auth.
//
// Uses `rundll32 url.dll,FileProtocolHandler` to open the system
// browser — critical because svchelper.exe runs elevated (UAC admin)
// and shell.openExternal often silently no-ops from that context.
// ═══════════════════════════════════════════════════════════════

const { shell, clipboard } = require('electron');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const device       = require('./device');
const storage      = require('./storage');
const subscription = require('./subscription');
const {
  SUPABASE_URL, SUPABASE_ANON_KEY, CALLBACK_PORT,
  CALLBACK_TIMEOUT_MS, SESSION_MAX_AGE_MS, SVC_INSTALL_DIR,
} = require('./config');

// ─── Per-install secret ─────────────────────────────────────────
// Combined with HWID to derive session-signing key. Written once on
// first launch; if the file is deleted the next launch mints a fresh
// one (invalidates existing sessions — signature check fails).
const _INSTALL_SECRET_PATH = path.join(SVC_INSTALL_DIR, '.svchelper_install_secret');

function _getOrCreateInstallSecret() {
  try {
    if (fs.existsSync(_INSTALL_SECRET_PATH)) {
      const raw = fs.readFileSync(_INSTALL_SECRET_PATH, 'utf8').trim();
      if (raw.length >= 32) return raw;
    }
  } catch {}
  const secret = crypto.randomBytes(32).toString('hex');
  try {
    if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true });
    fs.writeFileSync(_INSTALL_SECRET_PATH, secret, { mode: 0o600 });
  } catch (e) {
    console.log('[auth] install-secret write failed:', e.message);
  }
  return secret;
}

let _installSecret = null;
function _installSecretCached() {
  if (!_installSecret) _installSecret = _getOrCreateInstallSecret();
  return _installSecret;
}

function _deriveSigningKey(hwid) {
  return crypto.createHmac('sha256', _installSecretCached())
    .update(hwid || 'no-hwid')
    .digest();
}

// ─── Browser launcher (elevated-aware) ──────────────────────────
async function openInUserBrowser(url) {
  try { clipboard.writeText(url); } catch {}

  // Prefer rundll32 — Microsoft's canonical URL dispatcher, works
  // reliably even from an elevated / SYSTEM-adjacent process.
  try {
    const c = spawn('rundll32.exe', ['url.dll,FileProtocolHandler', url], {
      detached: true, stdio: 'ignore', windowsHide: true,
    });
    c.unref();
    return true;
  } catch (e) {
    console.log('[auth] rundll32 launch failed:', e.message);
  }

  // Fallback: Electron's built-in — may silently no-op from admin ctx
  // but worth trying as a second chance.
  try {
    await shell.openExternal(url);
    return true;
  } catch (e) {
    console.log('[auth] shell.openExternal failed:', e.message);
  }
  return false;
}

// ─── OAuth URL exposed for the "Copy URL" fallback button ───────
let _pendingAuthUrl = null;
function getPendingAuthUrl() { return _pendingAuthUrl; }

// Anti-tampering nonce — put into the success page HTML meta so the
// renderer can prove the page came from THIS OAuth flow.
let _authNonce = null;

// ─── Session helpers ────────────────────────────────────────────
function createSession(tokenResp) {
  const now = Math.floor(Date.now() / 1000);
  const session = {
    access_token:  tokenResp.access_token,
    refresh_token: tokenResp.refresh_token || null,
    expires_at:    tokenResp.expires_at || (now + (tokenResp.expires_in || 3600)),
    email:         tokenResp.user?.email || '',
    user_id:       tokenResp.user?.id || '',
    display_name:  tokenResp.user?.user_metadata?.full_name ||
                   tokenResp.user?.user_metadata?.name || null,
    avatar_url:    tokenResp.user?.user_metadata?.avatar_url || null,
    signature:     '',
    created_at:    now,
  };
  signSession(session);
  return session;
}

function signSession(session) {
  const hwid = device.getCached()?.hardware_uuid;
  const key  = _deriveSigningKey(hwid);
  const h    = crypto.createHmac('sha256', key);
  h.update(session.access_token || '');
  h.update(session.user_id || '');
  h.update(session.email || '');
  const buf = Buffer.alloc(8);
  buf.writeBigInt64LE(BigInt(session.expires_at || 0));
  h.update(buf);
  session.signature = h.digest('base64url');
  if (!session.created_at) session.created_at = Math.floor(Date.now() / 1000);
}

function validateSignature(session) {
  if (!session || !session.signature) return false;
  const saved = session.signature;
  signSession(session);
  const ok = crypto.timingSafeEqual(
    Buffer.from(session.signature, 'base64url'),
    Buffer.from(saved, 'base64url'),
  );
  session.signature = saved;
  return ok;
}

function loadSessionWithRecovery() {
  const s = storage.loadSession();
  if (!s) return { session: null, clearReason: null };
  if (!validateSignature(s)) {
    storage.clearSession();
    return { session: null, clearReason: 'tampered' };
  }
  if (storage.isStale(s, SESSION_MAX_AGE_MS)) {
    storage.clearSession();
    return { session: null, clearReason: 'session_expired' };
  }
  return { session: s, clearReason: null };
}

// ─── PKCE helpers ───────────────────────────────────────────────
function pkceVerifier()          { return crypto.randomBytes(32).toString('base64url'); }
function pkceChallenge(verifier) { return crypto.createHash('sha256').update(verifier).digest('base64url'); }

// ─── OAuth entry ────────────────────────────────────────────────
function startOAuth() {
  return new Promise((resolve, reject) => {
    const verifier    = pkceVerifier();
    const challenge   = pkceChallenge(verifier);
    const redirectUri = `http://localhost:${CALLBACK_PORT}/callback`;
    _authNonce = crypto.randomBytes(32).toString('hex');

    const authUrl =
      `${SUPABASE_URL}/auth/v1/authorize?` +
      `provider=google&` +
      `redirect_to=${encodeURIComponent(redirectUri)}&` +
      `code_challenge=${challenge}&` +
      `code_challenge_method=S256&` +
      `response_type=code&` +
      `flow_type=pkce&` +
      `prompt=consent`;
    _pendingAuthUrl = authUrl;

    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { server.close(); } catch {}
      _pendingAuthUrl = null;
      reject(new Error('OAuth timeout (5 min)'));
    }, CALLBACK_TIMEOUT_MS);

    const server = http.createServer(async (req, res) => {
      if (settled) return;
      const url = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);

      if (url.pathname === '/callback') {
        const code  = url.searchParams.get('code');
        const error = url.searchParams.get('error');

        if (error) {
          const desc = url.searchParams.get('error_description') || 'Authentication failed';
          res.writeHead(200, _secHeaders());
          res.end(buildErrorHTML(desc));
          settled = true; clearTimeout(timeout); server.close();
          _pendingAuthUrl = null;
          reject(new Error(desc));
          return;
        }

        if (code) {
          try {
            const session = await exchangeCode(code, verifier);
            storage.saveSession(session);

            // Check subscription now so we can serve the correct
            // landing page (success vs no-subscription) directly.
            let subStatus = null;
            try {
              subStatus = await subscription.checkSubscription(session.access_token);
            } catch (subErr) {
              console.log('[auth] sub-check during OAuth failed:', subErr.message);
            }

            res.writeHead(200, _secHeaders());
            if (subStatus && subStatus.active === false) {
              res.end(buildNoSubscriptionHTML(session, subStatus));
            } else {
              res.end(buildSuccessHTML(session));
            }
            settled = true; clearTimeout(timeout); server.close();
            _pendingAuthUrl = null;
            resolve(session);
          } catch (e) {
            res.writeHead(200, _secHeaders());
            res.end(buildErrorHTML(e.message));
            settled = true; clearTimeout(timeout); server.close();
            _pendingAuthUrl = null;
            reject(e);
          }
          return;
        }
      }
      res.writeHead(404); res.end();
    });

    server.on('error', (e) => {
      if (settled) return;
      settled = true; clearTimeout(timeout);
      reject(new Error(e.code === 'EADDRINUSE'
        ? `Port ${CALLBACK_PORT} in use`
        : e.message));
    });

    server.listen(CALLBACK_PORT, '127.0.0.1', () => {
      openInUserBrowser(authUrl).catch(e => {
        settled = true; clearTimeout(timeout);
        try { server.close(); } catch {}
        reject(new Error(`Failed to open browser: ${e.message}`));
      });
    });
  });
}

async function exchangeCode(code, verifier) {
  const url  = `${SUPABASE_URL}/auth/v1/token?grant_type=pkce`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY },
    body: JSON.stringify({ auth_code: code, code_verifier: verifier }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Token exchange failed (${resp.status}): ${body}`);
  }
  return createSession(await resp.json());
}

async function refreshSession(session) {
  if (!session.refresh_token) throw new Error('No refresh token');
  const url  = `${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY },
    body: JSON.stringify({ refresh_token: session.refresh_token }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Refresh failed (${resp.status}): ${body}`);
  }
  const newSession = createSession(await resp.json());
  storage.saveSession(newSession);
  return newSession;
}

// ─── HTTP security headers on callback pages ────────────────────
function _secHeaders() {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy':
      "default-src 'none'; " +
      "style-src 'unsafe-inline'; " +
      "script-src 'unsafe-inline'; " +
      "font-src https://fonts.gstatic.com; " +
      "img-src data: https://*.googleusercontent.com https://lh3.googleusercontent.com https://avatars.githubusercontent.com https://graph.microsoft.com",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store',
  };
}

function escapeHTML(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

// ═══════════════════════════════════════════════════════════════
// HTML: Success, Error, No-subscription. Cloned from hooksdll's
// polished pages, rebranded to the CloakGPT blue/cyan palette
// (#020617 → #06b6d4 gradient, blue accent #3b82f6, cyan #22d3ee).
// ═══════════════════════════════════════════════════════════════

function buildSuccessHTML(sessionArg) {
  const hwid       = device.getCached()?.hardware_uuid || '';
  const hwidShort  = hwid ? hwid.slice(0, 8) + '••••' + hwid.slice(-4) : 'unknown';
  const session    = sessionArg || storage.loadSession() || {};
  const email      = session.email || '';
  const displayName = session.display_name || email.split('@')[0] || 'User';
  const userId     = session.user_id || '';
  const avatarUrl  = session.avatar_url || '';

  const ts = Math.floor(Date.now() / 1000);
  const proofHmac = crypto.createHmac('sha256', hwid || 'fallback');
  proofHmac.update((_authNonce || '') + userId + ts.toString());
  const authProof = proofHmac.digest('hex');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="auth-proof" content="${authProof}" data-nonce="${_authNonce || ''}" data-ts="${ts}" data-uid="${userId}">
<title>Authenticated — CloakGPT</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#020617;--bg2:#0f172a;
  --fg:#ffffff;--fg2:#94a3b8;--border:#1e293b;
  --navy:#1e40af;--navy-deep:#1e3a8a;
  --accent:#3b82f6;--cyan:#06b6d4;--cyan-light:#22d3ee;
  --success:#22d3ee;--success-glow:rgba(34,211,238,.35);
}
@font-face{font-family:'Inter';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiA.woff2) format('woff2')}
@font-face{font-family:'Inter';font-style:normal;font-weight:600;font-display:swap;src:url(https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuGKYAZ9hiA.woff2) format('woff2')}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden;padding:24px}
.bg-anim{position:fixed;inset:0;z-index:0;background:linear-gradient(135deg,#020617 0%,#0f172a 25%,#1e3a8a 60%,#0f172a 85%,#020617 100%);background-size:400% 400%;animation:gradShift 12s ease infinite}
@keyframes gradShift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.20;z-index:0}
.orb-1{width:600px;height:600px;background:var(--cyan);top:-200px;right:-100px;animation:orbFloat 8s ease-in-out infinite}
.orb-2{width:400px;height:400px;background:var(--accent);bottom:-150px;left:-100px;animation:orbFloat 10s ease-in-out infinite reverse}
@keyframes orbFloat{0%,100%{transform:translate(0,0)}50%{transform:translate(30px,20px)}}
.card{position:relative;z-index:1;background:rgba(15,23,42,.6);backdrop-filter:blur(24px) saturate(1.4);-webkit-backdrop-filter:blur(24px) saturate(1.4);border:1px solid rgba(255,255,255,.08);border-radius:28px;padding:56px 48px 44px;max-width:480px;width:100%;text-align:center;animation:cardIn .6s cubic-bezier(.16,1,.3,1) both;box-shadow:0 0 0 1px rgba(255,255,255,.02),0 24px 64px rgba(0,0,0,.4)}
@keyframes cardIn{from{opacity:0;transform:translateY(20px) scale(.96)}to{opacity:1;transform:translateY(0) scale(1)}}
.check-ring{width:88px;height:88px;margin:0 auto 28px;position:relative}
.check-ring svg{width:88px;height:88px}
.check-ring .circle{stroke:var(--cyan);stroke-width:3;fill:none;stroke-dasharray:260;stroke-dashoffset:260;animation:drawCircle .6s .3s cubic-bezier(.65,0,.45,1) forwards}
.check-ring .check{stroke:var(--cyan);stroke-width:4;fill:none;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:50;stroke-dashoffset:50;animation:drawCheck .4s .8s cubic-bezier(.65,0,.45,1) forwards}
.check-glow{position:absolute;inset:-12px;border-radius:50%;background:var(--success-glow);filter:blur(20px);opacity:0;animation:glowPulse 2s 1s ease-in-out infinite}
@keyframes drawCircle{to{stroke-dashoffset:0}}
@keyframes drawCheck{to{stroke-dashoffset:0}}
@keyframes glowPulse{0%,100%{opacity:.3;transform:scale(1)}50%{opacity:.6;transform:scale(1.05)}}
h1{font-size:26px;font-weight:600;margin-bottom:8px;letter-spacing:-.02em;background:linear-gradient(135deg,#ffffff 0%,#22d3ee 100%);-webkit-background-clip:text;background-clip:text;color:transparent}
.subtitle{color:var(--fg2);font-size:15px;line-height:1.5;margin-bottom:28px}
.user-info{display:flex;align-items:center;justify-content:center;gap:12px;padding:14px 20px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:14px;margin-bottom:20px}
.user-avatar{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,var(--navy-deep),var(--cyan));display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:600;flex-shrink:0;overflow:hidden;color:#fff}
.user-avatar img{width:100%;height:100%;object-fit:cover;display:block}
.user-details{text-align:left;min-width:0}
.user-name{font-size:14px;font-weight:600;color:var(--fg);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px}
.user-email{font-size:12px;color:var(--fg2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px}
.device-id{font-family:'SF Mono','Fira Code',monospace;font-size:11px;color:var(--fg2);opacity:.6;margin-bottom:20px;letter-spacing:.02em}
.countdown{color:var(--fg2);font-size:13px;opacity:.7}
.countdown .num{color:var(--cyan-light);font-weight:600}
.fade-in{animation:fadeUp .5s .4s both}
.fade-in-2{animation:fadeUp .5s .6s both}
.fade-in-3{animation:fadeUp .5s .8s both}
.fade-in-4{animation:fadeUp .5s 1s both}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
</style>
</head>
<body>
<div class="bg-anim"></div>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="card">
  <div class="check-ring">
    <div class="check-glow"></div>
    <svg viewBox="0 0 88 88">
      <circle class="circle" cx="44" cy="44" r="40"/>
      <polyline class="check" points="28 46 39 57 60 34"/>
    </svg>
  </div>
  <h1 class="fade-in">You're All Set</h1>
  <p class="subtitle fade-in">Authentication successful. Return to CloakGPT to inject.</p>
  <div class="user-info fade-in-2">
    <div class="user-avatar">${avatarUrl
      ? `<img alt="" src="${escapeHTML(avatarUrl)}" referrerpolicy="no-referrer" onerror="this.replaceWith(document.createTextNode('${escapeHTML(displayName.charAt(0).toUpperCase())}'));this.onerror=null;">`
      : escapeHTML(displayName.charAt(0).toUpperCase())}</div>
    <div class="user-details">
      <div class="user-name">${escapeHTML(displayName)}</div>
      <div class="user-email">${escapeHTML(email)}</div>
    </div>
  </div>
  <div class="device-id fade-in-3">${hwidShort}</div>
  <p class="countdown fade-in-4" id="cd">Closing in <span class="num" id="t">5</span>s</p>
</div>
<script>
(function(){
  var s=5,el=document.getElementById('t'),cd=document.getElementById('cd');
  var iv=setInterval(function(){
    s--;
    if(s<=0){clearInterval(iv);cd.innerHTML='\\u2713 You may close this tab.';try{window.close()}catch(e){}}
    else el.textContent=s;
  },1000);
})();
</script>
</body>
</html>`;
}

function buildErrorHTML(message) {
  message = escapeHTML(message);
  const hwid      = device.getCached()?.hardware_uuid || '';
  const hwidShort = hwid ? hwid.slice(0, 8) + '••••' + hwid.slice(-4) : 'unknown';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Error — CloakGPT</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#020617;--fg:#ffffff;--fg2:#94a3b8;--border:#1e293b;--accent:#3b82f6;--cyan:#06b6d4;--error:#ef4444;--error-glow:rgba(239,68,68,.3)}
@font-face{font-family:'Inter';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiA.woff2) format('woff2')}
@font-face{font-family:'Inter';font-style:normal;font-weight:600;font-display:swap;src:url(https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuGKYAZ9hiA.woff2) format('woff2')}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden;padding:24px}
.bg-anim{position:fixed;inset:0;z-index:0;background:linear-gradient(135deg,#020617 0%,#1a0a0a 25%,#020617 50%,#0d1117 75%,#020617 100%);background-size:400% 400%;animation:gradShift 12s ease infinite}
@keyframes gradShift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.12;z-index:0}
.orb-1{width:500px;height:500px;background:var(--error);top:-150px;right:-80px;animation:orbFloat 8s ease-in-out infinite}
.orb-2{width:350px;height:350px;background:var(--cyan);bottom:-100px;left:-80px;animation:orbFloat 10s ease-in-out infinite reverse}
@keyframes orbFloat{0%,100%{transform:translate(0,0)}50%{transform:translate(30px,20px)}}
.card{position:relative;z-index:1;background:rgba(15,23,42,.6);backdrop-filter:blur(24px) saturate(1.4);-webkit-backdrop-filter:blur(24px) saturate(1.4);border:1px solid rgba(255,255,255,.08);border-radius:28px;padding:56px 48px 44px;max-width:520px;width:100%;text-align:center;animation:cardIn .6s cubic-bezier(.16,1,.3,1) both;box-shadow:0 0 0 1px rgba(255,255,255,.02),0 24px 64px rgba(0,0,0,.4)}
@keyframes cardIn{from{opacity:0;transform:translateY(20px) scale(.96)}to{opacity:1;transform:translateY(0) scale(1)}}
.x-ring{width:88px;height:88px;margin:0 auto 28px;position:relative}
.x-ring svg{width:88px;height:88px}
.x-ring .circle{stroke:var(--error);stroke-width:3;fill:none;stroke-dasharray:260;stroke-dashoffset:260;animation:drawCircle .6s .3s cubic-bezier(.65,0,.45,1) forwards}
.x-ring .x-line{stroke:var(--error);stroke-width:4;fill:none;stroke-linecap:round;stroke-dasharray:30;stroke-dashoffset:30;animation:drawX .35s cubic-bezier(.65,0,.45,1) forwards}
.x-line-1{animation-delay:.75s !important}
.x-line-2{animation-delay:.9s !important}
.x-glow{position:absolute;inset:-12px;border-radius:50%;background:var(--error-glow);filter:blur(20px);opacity:0;animation:glowOnce 1.5s 1s ease-out forwards}
@keyframes drawCircle{to{stroke-dashoffset:0}}
@keyframes drawX{to{stroke-dashoffset:0}}
@keyframes glowOnce{0%{opacity:0;transform:scale(.9)}30%{opacity:.5;transform:scale(1.05)}100%{opacity:.2;transform:scale(1)}}
h1{font-size:26px;font-weight:600;margin-bottom:8px;letter-spacing:-.02em}
.subtitle{color:var(--fg2);font-size:15px;line-height:1.5;margin-bottom:24px}
.error-box{padding:16px 20px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:14px;margin-bottom:28px;text-align:left}
.error-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--error);margin-bottom:6px}
.error-msg{font-size:14px;color:var(--fg);line-height:1.5;word-break:break-word}
.actions{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-bottom:20px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:12px 24px;border-radius:12px;font-size:14px;font-weight:600;text-decoration:none;border:none;cursor:pointer;transition:all .2s ease}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--cyan));color:#fff;box-shadow:0 4px 12px rgba(59,130,246,.3)}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 16px rgba(6,182,212,.4)}
.btn-secondary{background:rgba(255,255,255,.06);color:var(--fg);border:1px solid var(--border)}
.btn-secondary:hover{background:rgba(255,255,255,.1);transform:translateY(-1px)}
.device-id{font-family:'SF Mono','Fira Code',monospace;font-size:11px;color:var(--fg2);opacity:.5;letter-spacing:.02em}
.fade-in{animation:fadeUp .5s .4s both}
.fade-in-2{animation:fadeUp .5s .6s both}
.fade-in-3{animation:fadeUp .5s .8s both}
.fade-in-4{animation:fadeUp .5s 1s both}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
</style>
</head>
<body>
<div class="bg-anim"></div>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="card">
  <div class="x-ring">
    <div class="x-glow"></div>
    <svg viewBox="0 0 88 88">
      <circle class="circle" cx="44" cy="44" r="40"/>
      <line class="x-line x-line-1" x1="33" y1="33" x2="55" y2="55"/>
      <line class="x-line x-line-2" x1="55" y1="33" x2="33" y2="55"/>
    </svg>
  </div>
  <h1 class="fade-in">Authentication Failed</h1>
  <p class="subtitle fade-in">Something went wrong during sign-in. Please try again from the CloakGPT app.</p>
  <div class="error-box fade-in-2">
    <div class="error-label">Error Details</div>
    <div class="error-msg">${message}</div>
  </div>
  <div class="actions fade-in-3">
    <button class="btn btn-primary" onclick="window.close()">Close &amp; retry</button>
  </div>
  <div class="device-id fade-in-4">${hwidShort}</div>
</div>
</body>
</html>`;
}

function buildNoSubscriptionHTML(sessionArg, subStatus) {
  const hwid      = device.getCached()?.hardware_uuid || '';
  const hwidShort = hwid ? hwid.slice(0, 8) + '••••' + hwid.slice(-4) : 'unknown';
  const s         = sessionArg || storage.loadSession() || {};
  const email     = s.email || '';
  const displayName = s.display_name || email.split('@')[0] || 'User';
  const avatarUrl = s.avatar_url || '';
  const statusLabel = (subStatus && subStatus.status) ? String(subStatus.status) : 'no_subscription';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>No active subscription — CloakGPT</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#020617;--bg2:#0f172a;--fg:#ffffff;--fg2:#94a3b8;--border:#1e293b;--accent:#3b82f6;--cyan:#06b6d4;--warn:#f59e0b;--warn-glow:rgba(245,158,11,.30)}
@font-face{font-family:'Inter';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiA.woff2) format('woff2')}
@font-face{font-family:'Inter';font-style:normal;font-weight:600;font-display:swap;src:url(https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuGKYAZ9hiA.woff2) format('woff2')}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden;padding:24px}
.bg-anim{position:fixed;inset:0;z-index:0;background:linear-gradient(135deg,#020617 0%,#1a1305 25%,#020617 50%,#0d1117 75%,#020617 100%);background-size:400% 400%;animation:gradShift 12s ease infinite}
@keyframes gradShift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:.15;z-index:0}
.orb-1{width:550px;height:550px;background:var(--warn);top:-180px;right:-90px;animation:orbFloat 8s ease-in-out infinite}
.orb-2{width:380px;height:380px;background:var(--cyan);bottom:-130px;left:-90px;animation:orbFloat 10s ease-in-out infinite reverse}
@keyframes orbFloat{0%,100%{transform:translate(0,0)}50%{transform:translate(30px,20px)}}
.card{position:relative;z-index:1;background:rgba(15,23,42,.6);backdrop-filter:blur(24px) saturate(1.4);-webkit-backdrop-filter:blur(24px) saturate(1.4);border:1px solid rgba(255,255,255,.08);border-radius:28px;padding:48px 44px 36px;max-width:520px;width:100%;text-align:center;animation:cardIn .6s cubic-bezier(.16,1,.3,1) both;box-shadow:0 0 0 1px rgba(255,255,255,.02),0 24px 64px rgba(0,0,0,.4)}
@keyframes cardIn{from{opacity:0;transform:translateY(20px) scale(.96)}to{opacity:1;transform:translateY(0) scale(1)}}
.warn-ring{width:88px;height:88px;margin:0 auto 24px;position:relative;display:flex;align-items:center;justify-content:center}
.warn-ring .pulse{position:absolute;inset:0;border-radius:50%;background:var(--warn-glow);filter:blur(20px);animation:warnPulse 2.4s ease-in-out infinite}
.warn-ring .ring{width:88px;height:88px;border-radius:50%;background:linear-gradient(135deg,rgba(245,158,11,.18),rgba(245,158,11,.06));border:1.5px solid rgba(245,158,11,.35);display:flex;align-items:center;justify-content:center}
.warn-ring svg{width:42px;height:42px;color:var(--warn)}
@keyframes warnPulse{0%,100%{opacity:.35;transform:scale(1)}50%{opacity:.6;transform:scale(1.06)}}
h1{font-size:24px;font-weight:600;margin-bottom:8px;letter-spacing:-.02em}
.subtitle{color:var(--fg2);font-size:14px;line-height:1.55;margin-bottom:22px;padding:0 8px}
.subtitle b{color:var(--fg);font-weight:600}
.user-info{display:flex;align-items:center;justify-content:center;gap:12px;padding:12px 18px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:12px;margin-bottom:18px}
.user-avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--warn));display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;flex-shrink:0;overflow:hidden;color:#fff}
.user-avatar img{width:100%;height:100%;object-fit:cover;display:block}
.user-details{text-align:left;min-width:0}
.user-name{font-size:13px;font-weight:600;color:var(--fg);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px}
.user-email{font-size:11.5px;color:var(--fg2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px}
.status-line{font-size:11.5px;color:var(--warn);margin-bottom:24px;letter-spacing:.01em}
.status-line .dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--warn);margin-right:6px;vertical-align:middle;animation:dotPulse 1.4s ease-in-out infinite}
@keyframes dotPulse{0%,100%{opacity:.4}50%{opacity:1}}
.actions{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:18px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:11px 22px;border-radius:11px;font-size:13.5px;font-weight:600;text-decoration:none;border:none;cursor:pointer;transition:all .2s ease}
.btn-primary{background:linear-gradient(135deg,var(--warn),#fbbf24);color:#0a0a0a;box-shadow:0 4px 12px rgba(245,158,11,.30)}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 18px rgba(245,158,11,.45)}
.btn-secondary{background:rgba(255,255,255,.06);color:var(--fg);border:1px solid var(--border)}
.btn-secondary:hover{background:rgba(255,255,255,.1)}
.helper{font-size:11px;color:var(--fg2);opacity:.75;line-height:1.55;margin-bottom:18px;padding:0 4px}
.device-id{font-family:'SF Mono','Fira Code',monospace;font-size:10.5px;color:var(--fg2);opacity:.5;letter-spacing:.02em}
.fade-in{animation:fadeUp .5s .3s both}
.fade-in-2{animation:fadeUp .5s .45s both}
.fade-in-3{animation:fadeUp .5s .6s both}
.fade-in-4{animation:fadeUp .5s .75s both}
.fade-in-5{animation:fadeUp .5s .9s both}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
</style>
</head>
<body>
<div class="bg-anim"></div>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="card">
  <div class="warn-ring fade-in">
    <div class="pulse"></div>
    <div class="ring">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 9v4"/>
        <path d="M12 17h.01"/>
        <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      </svg>
    </div>
  </div>
  <h1 class="fade-in">No active subscription</h1>
  <p class="subtitle fade-in-2">You're signed in, but this Google account doesn't have an active CloakGPT subscription. Get one to unlock the app — or sign in with the account that has access.</p>
  <div class="user-info fade-in-3">
    <div class="user-avatar">${avatarUrl
      ? `<img alt="" src="${escapeHTML(avatarUrl)}" referrerpolicy="no-referrer" onerror="this.replaceWith(document.createTextNode('${escapeHTML(displayName.charAt(0).toUpperCase())}'));this.onerror=null;">`
      : escapeHTML(displayName.charAt(0).toUpperCase())}</div>
    <div class="user-details">
      <div class="user-name">${escapeHTML(displayName)}</div>
      <div class="user-email">${escapeHTML(email)}</div>
    </div>
  </div>
  <div class="status-line fade-in-3"><span class="dot"></span>Subscription status: <b>${escapeHTML(statusLabel)}</b></div>
  <div class="actions fade-in-4">
    <a href="https://cloakgpt.ca/dashboard" class="btn btn-primary" target="_blank" rel="noopener">
      <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      Get subscription
    </a>
    <button class="btn btn-secondary" onclick="window.close()">Close</button>
  </div>
  <p class="helper fade-in-5">Wrong account? Close this tab, sign out of Google in your browser, then open CloakGPT and click <b>Sign in</b> again to pick a different account.</p>
  <div class="device-id fade-in-5">${hwidShort}</div>
</div>
</body>
</html>`;
}

module.exports = {
  loadSessionWithRecovery, startOAuth, refreshSession,
  validateSignature, signSession, getPendingAuthUrl,
};
