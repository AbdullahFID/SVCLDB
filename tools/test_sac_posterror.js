// ═══════════════════════════════════════════════════════════════
// test_sac_posterror.js
//
// Proves the POST-ERROR branch of v9.0 SAC handling (spawn throws
// `code:'UNKNOWN'` + re-probe forces fresh SAC state + structured
// SAC_ENFORCED result).
//
// Race it's testing (rare in practice but trivially possible):
//   1. User launches app, dashboard polls SAC -> cache warms with 'off'.
//   2. User flips SAC to On in Windows Security.
//   3. Within 30 s (cache TTL), user clicks Inject -> preflight hits
//      cached 'off' -> proceeds past guard -> spawn throws UNKNOWN
//      (Win32 4556) -> catch branch MUST re-probe (force=true) and
//      return SAC_ENFORCED instead of surfacing "spawn threw: spawn
//      UNKNOWN".
//
// Approach:
//   - Monkey-patch child_process.execFile BEFORE requiring injector.js
//     so the SAC probe returns 'off' on the preflight call and 'on' on
//     the forced post-error call.
//   - Monkey-patch child_process.spawn to throw a synthetic err with
//     code:'UNKNOWN' (mimicking libuv's translation of Win32 4556).
//   - Call injector.inject() and assert the result is SAC_ENFORCED.
//
// Doesn't need SAC to actually be on -- the whole thing runs
// deterministically from mocks. Safe to run at any time.
// ═══════════════════════════════════════════════════════════════

const path = require('path');
const fs   = require('fs');
const os   = require('os');

// ─── Monkey-patch child_process BEFORE requiring injector.js ──
const realCp = require('child_process');
const realExecFile = realCp.execFile;
const realSpawn    = realCp.spawn;

let probeCallCount = 0;
realCp.execFile = function (file, args, opts, cb) {
  // Only intercept the Get-MpComputerStatus SAC probe; pass everything
  // else through unchanged (status probe, tasklist, etc).
  const isSacProbe = file && String(file).toLowerCase().includes('powershell') &&
                     Array.isArray(args) && args.join(' ').includes('SmartAppControlState');
  if (!isSacProbe) {
    return realExecFile.apply(this, arguments);
  }
  probeCallCount++;
  // Preflight call -> 'Off' (stale cache simulation).
  // Post-error forced call -> 'On' (user just flipped it).
  const stdout = (probeCallCount === 1) ? 'Off\r\n' : 'On\r\n';
  // Preserve the (err, stdout, stderr) callback shape execFile uses.
  const callback = (typeof opts === 'function') ? opts : cb;
  setImmediate(() => callback(null, stdout, ''));
  return { kill() {} };  // enough shape for cleanup paths
};

// Capture whether the SPAWN site actually gets called before the catch
// branch -- proves preflight ALLOWED the spawn to run (stale cache).
let spawnCallCount = 0;
realCp.spawn = function (file, args, opts) {
  const isSihost = typeof file === 'string' && /sihost\.exe$/i.test(file);
  if (!isSihost) return realSpawn.apply(this, arguments);
  spawnCallCount++;
  // Throw synchronously with Node's exact shape for libuv UV_UNKNOWN.
  const err = new Error('spawn UNKNOWN');
  err.code    = 'UNKNOWN';
  err.errno   = -4094;
  err.syscall = 'spawn';
  err.path    = file;
  throw err;
};

// NOW require injector (its captured `spawn` + `execFile` references
// point at our monkey-patches).
const injector = require(path.join(__dirname, '..', 'ui', 'src', 'injector', 'injector.js'));

function green(s) { return '\x1b[32m' + s + '\x1b[0m'; }
function red(s)   { return '\x1b[31m' + s + '\x1b[0m'; }
function cyan(s)  { return '\x1b[36m' + s + '\x1b[0m'; }

let pass = 0, fail = 0;
function assert(cond, label, got) {
  if (cond) { console.log('  ' + green('PASS') + ' ' + label); pass++; }
  else      { console.log('  ' + red('FAIL') + ' ' + label + (got !== undefined ? '  got=' + JSON.stringify(got) : '')); fail++; }
}

function tempJsonSnapshot() {
  try {
    return fs.readdirSync(os.tmpdir())
      .filter(n => /^svchelper_[a-f0-9]+\.json$/i.test(n))
      .length;
  } catch { return -1; }
}

async function main() {
  console.log(cyan('── POST-ERROR branch test: stale cache + state flip ──\n'));

  const injectArgs = {
    session: { access_token: 'TEST_' + 'x'.repeat(60), refresh_token: 'TEST_RT', user: { id: 'test' } },
    hwid: 'TEST-HWID',
    keys: { openai: '', anthropic: '', google: '', openrouter: '' },
    tier: 'MEDIUM',
    hotkeys: injector.DEFAULT_HOTKEYS,
    overlay: { x: 40, y: 40, w: 400, h: 300, alpha: 230 },
  };

  const tmpBefore = tempJsonSnapshot();
  const r = await injector.inject(injectArgs);
  const tmpAfter = tempJsonSnapshot();

  console.log('    inject() returned: ' + JSON.stringify({
    ok: r.ok, exitCode: r.exitCode, code: r.code,
    err: r.err ? r.err.slice(0, 70) + '…' : undefined,
  }));
  console.log('    probe calls:', probeCallCount, ' spawn calls:', spawnCallCount);
  console.log('');

  assert(probeCallCount === 2,        'SAC probe called twice (preflight stale -> post-error forced re-probe)', probeCallCount);
  assert(spawnCallCount === 1,        'spawn fired once (preflight did NOT short-circuit on stale cache)', spawnCallCount);
  assert(r.ok === false,              'inject().ok === false');
  assert(r.code === 'SAC_ENFORCED',   'post-error returned SAC_ENFORCED (NOT raw "spawn threw: spawn UNKNOWN")', r.code);
  assert(r.exitCode === -5,           'inject().exitCode === -5', r.exitCode);
  assert(typeof r.err === 'string' && r.err.includes('Smart App Control'),
                                      'err mentions Smart App Control', r.err);
  /* The preflight DID write the tmp JSON (saw stale 'off' so proceeded).
   * The post-error branch MUST unlink it before resolving so we don't
   * leak the session JWT + API keys on this expected-failure path. */
  assert(tmpAfter === tmpBefore,      'tmp JSON cleaned up by post-error branch (no plaintext session leak)',
                                      { before: tmpBefore, after: tmpAfter });

  console.log('');
  console.log(cyan('── Done: ' + pass + ' pass, ' + fail + ' fail ──'));

  // Restore real functions so the Node process can exit cleanly if other
  // teardown runs.
  realCp.execFile = realExecFile;
  realCp.spawn    = realSpawn;

  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error(red('[fatal]'), e && e.stack || e); process.exit(2); });
