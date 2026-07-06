// ═══════════════════════════════════════════════════════════════
// mitm.js — MITM proxy / traffic-inspection detection.
//
// v6 (2026-07-06) — response to authorized-RE tester's concern:
//   "I can try to sniff the connection with fiddler and check if there
//    is a way to give a false get/post to force it to sign in."
//
// Attack model: attacker installs Fiddler / mitmproxy / Charles / Burp
// root CA into Windows cert store, points our app through the proxy,
// intercepts the Supabase sign-in / subscription-check exchange, and
// spoofs an `active:true` response so we grant access without a real
// subscription. Our fetch() call succeeds because Node's TLS validator
// walks the chain up to the ATTACKER'S root (which is now legitimately
// trusted by the OS thanks to their earlier install-CA click).
//
// Countermeasure (this file): scan the Windows Root cert stores for
// well-known MITM-tool CAs. If any is present, REFUSE to sign in with
// a clear on-screen error. Fiddler / mitmproxy / Charles / Burp all
// install CAs with distinctive Subject strings that we hardcode below.
//
// Layered defense: also check env vars (HTTPS_PROXY, HTTP_PROXY, NODE_
// TLS_REJECT_UNAUTHORIZED) and WinHTTP proxy config (via netsh) - these
// signal intent to route through a middlebox even before the CA scan
// completes.
//
// Non-goal: we can't defend against a kernel driver stealing our
// session bytes post-fetch, or against Fiddler running with a
// stealth-installed CA whose CN doesn't match our patterns. This is
// a Ring-3 defense against off-the-shelf MITM tools.
//
// Dev escape hatch: set SVCLDB_ALLOW_PROXY=1 in the environment to
// skip these checks. Intentionally undocumented in the UI - if you
// want to iterate against a proxy for development, you know where to
// look. NEVER set this in production distribution builds.
// ═══════════════════════════════════════════════════════════════

const { execFile } = require('child_process');

// Known-bad root CA subject fragments. Case-insensitive substring match
// against the full Subject string reported by Get-ChildItem in the
// Windows cert store. Sourced from each tool's documented default CA:
//
//   - Fiddler:      "DO_NOT_TRUST_FiddlerRoot" (verified w/ current Fiddler Everywhere + Classic)
//   - mitmproxy:    "mitmproxy" (CN=mitmproxy, O=mitmproxy)
//   - Charles:      "Charles Proxy" (CN=Charles Proxy CA, O=XK72 Ltd)
//   - Burp Suite:   "PortSwigger" (CN=PortSwigger CA)
//   - Proxyman:     "Proxyman" (CN=Proxyman Custom CA)
//   - HTTP Toolkit: "HTTP Toolkit" (CN=HTTP Toolkit CA)
//   - AnyProxy:     "AnyProxy" (CN=AnyProxy CA)
//   - Zaproxy:      "OWASP Zed Attack Proxy" (CN=OWASP Zed Attack Proxy Root CA)
//   - Squid + SSL-bump: "Squid" (rarer but catches some corp mitm setups)
//   - Cellebrite / Grayshift forensic tools also install CAs, but their
//     patterns are less consistent — skipped to avoid false positives.
const MITM_CA_PATTERNS = [
  { needle: 'DO_NOT_TRUST_FiddlerRoot', tool: 'Fiddler' },
  { needle: 'FiddlerRoot',              tool: 'Fiddler' },
  { needle: 'mitmproxy',                tool: 'mitmproxy' },
  { needle: 'Charles Proxy',            tool: 'Charles Proxy' },
  { needle: 'Charles Web Debugging',    tool: 'Charles Proxy' },
  { needle: 'PortSwigger',              tool: 'Burp Suite' },
  { needle: 'Proxyman',                 tool: 'Proxyman' },
  { needle: 'HTTP Toolkit',             tool: 'HTTP Toolkit' },
  { needle: 'AnyProxy',                 tool: 'AnyProxy' },
  { needle: 'OWASP Zed Attack',         tool: 'OWASP ZAP' },
  { needle: 'ZAP Root',                 tool: 'OWASP ZAP' },
  { needle: 'BadSSL',                   tool: 'BadSSL (test CA)' },
];

// PowerShell one-liner that enumerates BOTH LocalMachine\Root AND
// CurrentUser\Root cert stores and prints Subject lines. We scan the
// output for the needles above. Runs with 8s timeout — cold cert store
// enum can take 2-3s on some machines.
const PS_CERT_LIST =
  "Get-ChildItem 'Cert:\\LocalMachine\\Root','Cert:\\CurrentUser\\Root' " +
  "-ErrorAction SilentlyContinue " +
  "| Select-Object -ExpandProperty Subject";

async function _enumRootCAs() {
  return new Promise((resolve) => {
    execFile('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', PS_CERT_LIST],
      { windowsHide: true, timeout: 8000, encoding: 'utf8' },
      (err, stdout) => {
        if (err) {
          console.log('[mitm] cert enum failed:', err.message);
          resolve(''); return;
        }
        resolve(stdout || '');
      });
  });
}

// netsh winhttp show proxy — returns "Direct access" for no proxy,
// or "Proxy Server(s): host:port" if one is configured. This is
// LOWER priority than app-level HTTPS_PROXY env var; both worth
// checking. Runs quickly (~200ms).
const NETSH_PROXY = 'netsh winhttp show proxy';

async function _winhttpProxy() {
  return new Promise((resolve) => {
    execFile('cmd.exe', ['/c', NETSH_PROXY],
      { windowsHide: true, timeout: 3000, encoding: 'utf8' },
      (err, stdout) => {
        if (err) { resolve(''); return; }
        resolve(stdout || '');
      });
  });
}

/**
 * Run the full MITM detection sweep. Returns:
 *   { ok: true }                                    - safe to proceed
 *   { ok: false, kind, tool, details }              - block sign-in
 *
 * kind is one of:
 *   'mitm_ca'          - proxy tool's CA is installed
 *   'https_proxy_env'  - HTTPS_PROXY / HTTP_PROXY env var set
 *   'winhttp_proxy'    - system-wide WinHTTP proxy configured
 *   'tls_bypass'       - NODE_TLS_REJECT_UNAUTHORIZED=0 (very dangerous)
 */
async function checkForMitm() {
  // Dev escape hatch — see file header. NEVER ship with this set.
  if (process.env.SVCLDB_ALLOW_PROXY === '1' ||
      process.env.SVCLDB_ALLOW_PROXY === 'true') {
    console.log('[mitm] SVCLDB_ALLOW_PROXY set - MITM check skipped');
    return { ok: true, skipped: true };
  }

  // 1. NODE_TLS_REJECT_UNAUTHORIZED=0 is the worst possible env var
  //    for us — it globally disables TLS cert verification in Node.
  //    A user setting this + running our app is either debugging (in
  //    which case they know why they can't sign in) or being attacked.
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
    return {
      ok: false,
      kind: 'tls_bypass',
      tool: 'NODE_TLS_REJECT_UNAUTHORIZED=0',
      details: 'The NODE_TLS_REJECT_UNAUTHORIZED environment variable ' +
               'is set to 0, which globally disables TLS certificate ' +
               'validation. This is unsafe - unset it before signing in.',
    };
  }

  // 2. HTTPS_PROXY / HTTP_PROXY env vars route ALL Node fetch traffic
  //    through the named proxy. Any traffic-inspecting tool works this
  //    way. Refuse to sign in until they're cleared.
  const proxyEnv = process.env.HTTPS_PROXY || process.env.https_proxy ||
                   process.env.HTTP_PROXY  || process.env.http_proxy;
  if (proxyEnv) {
    return {
      ok: false,
      kind: 'https_proxy_env',
      tool: 'HTTPS_PROXY environment variable',
      details: `The HTTPS_PROXY / HTTP_PROXY environment variable is ` +
               `set to "${proxyEnv}". This forces all our HTTPS traffic ` +
               `through that proxy, which can intercept + replay our ` +
               `Supabase auth exchange. Unset it and restart CloakGPT.`,
    };
  }

  // 3. System-wide WinHTTP proxy - lower priority than env vars but
  //    still routes system-level HTTPS traffic through a middlebox.
  //    Many corporate networks use this legitimately; we accept it
  //    only if no MITM CA is also present (checked below).
  const netsh = await _winhttpProxy();
  const winhttpProxyDetected = /Proxy Server\(s\)\s*:\s*[^\s]/i.test(netsh) ||
                                /Proxy Server\s*:\s*[^\s]/i.test(netsh);

  // 4. Certificate-store scan for known MITM tool CAs. This is the
  //    smoking-gun detection - a user has to actively click "install
  //    certificate" for any of these to end up in the trust store.
  const certList = await _enumRootCAs();
  const lowered = certList.toLowerCase();
  for (const { needle, tool } of MITM_CA_PATTERNS) {
    if (lowered.includes(needle.toLowerCase())) {
      return {
        ok: false,
        kind: 'mitm_ca',
        tool,
        details: `A root certificate for ${tool} is installed in the ` +
                 `Windows trust store. This CA can sign fake TLS certs ` +
                 `for supabase.co that our HTTPS layer would accept as ` +
                 `valid, letting the tool intercept and modify our ` +
                 `subscription check. Uninstall the ${tool} CA before ` +
                 `signing in.\n\n` +
                 `Windows: Manage user certificates -> Trusted Root ` +
                 `Certification Authorities -> Certificates -> ` +
                 `find + delete the ${tool} entry.`,
      };
    }
  }

  // 5. If a WinHTTP proxy IS configured but no MITM CA is present,
  //    that's usually a legit corporate proxy that doesn't intercept
  //    HTTPS (it just forwards). Allow but log so support can see it.
  if (winhttpProxyDetected) {
    console.log('[mitm] winhttp proxy detected but no MITM CA - allowing');
  }

  return { ok: true };
}

/* ═══════════════════════════════════════════════════════════════
 * v6.2 (2026-07-06 evening) — REMEDIATION
 *
 * When checkForMitm() returns { ok:false, kind, tool }, the renderer
 * offers the user a "Fix now" button that calls remediate() with the
 * same shape. This module then knows how to auto-clean each kind:
 *
 *   tls_bypass       - delete NODE_TLS_REJECT_UNAUTHORIZED from
 *                      Process + User + Machine env scopes.
 *   https_proxy_env  - delete HTTPS_PROXY / HTTP_PROXY / ALL_PROXY
 *                      (all case variants) from Process + User +
 *                      Machine.
 *   winhttp_proxy    - `netsh winhttp reset proxy` (needs admin;
 *                      svchelper has requireAdministrator manifest
 *                      so this works).
 *   mitm_ca          - `Remove-Item Cert:\...` for every root CA
 *                      whose Subject matches the pattern. Both
 *                      CurrentUser\Root and LocalMachine\Root.
 *
 * All paths update process.env IN-PROCESS after touching the
 * persistent store, because Node's env block is a snapshot at fork
 * time - a subsequent checkForMitm() would read the stale value
 * otherwise.
 * ═══════════════════════════════════════════════════════════════ */

async function _runPS(script, timeoutMs) {
  return new Promise((resolve) => {
    execFile('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { windowsHide: true, timeout: timeoutMs || 15000, encoding: 'utf8' },
      (err, stdout, stderr) => {
        resolve({
          ok: !err,
          stdout: (stdout || '').trim(),
          stderr: (stderr || '').trim(),
          err: err ? (err.message || String(err)) : null,
        });
      });
  });
}

// Patterns that a tool's CA Subject can match. Same list as
// MITM_CA_PATTERNS at the top of this file but keyed by tool name
// for the remediation path (renderer passes back the tool string
// from the check result).
const _TOOL_TO_NEEDLE = {
  'Fiddler':          'FiddlerRoot|DO_NOT_TRUST_FiddlerRoot',
  'mitmproxy':        'mitmproxy',
  'Charles Proxy':    'Charles Proxy|Charles Web Debugging',
  'Burp Suite':       'PortSwigger',
  'Proxyman':         'Proxyman',
  'HTTP Toolkit':     'HTTP Toolkit',
  'AnyProxy':         'AnyProxy',
  'OWASP ZAP':        'OWASP Zed Attack|ZAP Root',
  'BadSSL (test CA)': 'BadSSL',
};

async function remediate(kind, tool) {
  console.log(`[mitm] remediate kind=${kind} tool=${tool || '(none)'}`);
  switch (kind) {

    case 'tls_bypass': {
      // Delete from in-process env FIRST so the immediate re-check
      // sees the clean value, then persist to User+Machine so it
      // survives across launches.
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      const r = await _runPS(
        "[Environment]::SetEnvironmentVariable('NODE_TLS_REJECT_UNAUTHORIZED', $null, 'User'); " +
        "[Environment]::SetEnvironmentVariable('NODE_TLS_REJECT_UNAUTHORIZED', $null, 'Machine'); " +
        "Write-Output 'OK'"
      );
      return {
        ok:      r.ok,
        action:  'unset_env_var',
        message: r.ok
          ? 'Removed NODE_TLS_REJECT_UNAUTHORIZED from all scopes.'
          : `Failed to remove env var: ${r.err || r.stderr}`,
        details: r.stdout,
      };
    }

    case 'https_proxy_env': {
      const vars = [
        'HTTPS_PROXY', 'https_proxy',
        'HTTP_PROXY',  'http_proxy',
        'ALL_PROXY',   'all_proxy',
      ];
      for (const v of vars) delete process.env[v];
      const psList = vars.map(v => `'${v}'`).join(',');
      const r = await _runPS(
        `foreach ($v in ${psList}) {\n` +
        `  [Environment]::SetEnvironmentVariable($v, $null, 'User')\n` +
        `  [Environment]::SetEnvironmentVariable($v, $null, 'Machine')\n` +
        `}\nWrite-Output 'OK'`
      );
      return {
        ok:      r.ok,
        action:  'unset_proxy_env',
        message: r.ok
          ? 'Removed HTTPS_PROXY / HTTP_PROXY / ALL_PROXY from all scopes.'
          : `Failed to remove proxy env vars: ${r.err || r.stderr}`,
      };
    }

    case 'winhttp_proxy': {
      const r = await _runPS('netsh winhttp reset proxy');
      return {
        ok:      r.ok,
        action:  'reset_winhttp',
        message: r.ok
          ? 'Reset WinHTTP proxy to direct access.'
          : `Failed to reset WinHTTP: ${r.err || r.stderr}`,
        details: r.stdout,
      };
    }

    case 'mitm_ca': {
      const needle = _TOOL_TO_NEEDLE[tool] || tool || 'nomatch';
      // Escape single quotes for PowerShell string literal.
      const psEsc = needle.replace(/'/g, "''");
      const script =
        "$hits = Get-ChildItem Cert:\\CurrentUser\\Root, Cert:\\LocalMachine\\Root " +
        "-EA SilentlyContinue | Where-Object { $_.Subject -match '" + psEsc + "' }\n" +
        "$deleted = 0; $failed = 0\n" +
        "foreach ($c in $hits) {\n" +
        "  try { Remove-Item -Path $c.PSPath -Force -EA Stop; $deleted++ }\n" +
        "  catch { $failed++; Write-Output \"FAIL: $($c.Subject) - $($_.Exception.Message)\" }\n" +
        "}\n" +
        "Write-Output \"DELETED=$deleted FAILED=$failed\"";
      const r = await _runPS(script, 20000);
      // Extract the summary from the PowerShell output.
      const m = /DELETED=(\d+)\s+FAILED=(\d+)/.exec(r.stdout);
      const deleted = m ? parseInt(m[1], 10) : 0;
      const failed  = m ? parseInt(m[2], 10) : 0;
      return {
        ok:      r.ok && failed === 0 && deleted > 0,
        action:  'delete_ca',
        message: (deleted > 0
          ? `Removed ${deleted} ${tool} root certificate(s) from Windows trust store.`
          : `No matching ${tool} certificates found - it may have been removed already.`) +
          (failed > 0
            ? ` ${failed} deletion(s) failed - see details.`
            : ''),
        details: r.stdout,
      };
    }

    default:
      return {
        ok: false,
        message: `Don't know how to auto-fix "${kind}". Please remediate manually.`,
      };
  }
}

module.exports = { checkForMitm, remediate };
