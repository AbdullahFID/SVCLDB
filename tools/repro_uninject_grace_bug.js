// tools/repro_uninject_grace_bug.js
//
// Regression harness for "payload_loaded=true after uninject" false-positive.
//
// Bug: ui/src/main.js injector:status handler applies a 15 s POST_INJECT_GRACE_MS
// suppression window so a probe='no' inside the window is treated as 'yes'
// (payload's init_thread may not have published its Global\...ShutdownRelease
// event yet). `lastInjectOkAt` was set on every inject-success site but never
// cleared, so an uninject / kill-all / sign-out / license-lockout / reset that
// fires within 15 s of an inject left the grace armed. Next status poll:
// probe='no', inGrace=true, effective='yes' -> dashboard falsely shows
// "Payload Online" for up to 15 s after the overlay actually unloaded.
//
// Fix (v2.0.1, 2026-09-10, ui/src/main.js): introduced markPayloadDown()
// helper that sets lastPayloadState='no' AND clears lastInjectOkAt=0, and
// called from every intentional-teardown site.
//
// This harness has FOUR tests. All four pass = bug still documented AND fix
// still in place AND main.js call sites still wired.
//
// Run: node tools/repro_uninject_grace_bug.js

'use strict';

const fs   = require('fs');
const path = require('path');

const POST_INJECT_GRACE_MS = 15000;

function makeState() {
  return { lastPayloadState: 'unknown', lastInjectOkAt: 0 };
}

// Exact copy of the injector:status logic in ui/src/main.js (unchanged by fix).
function statusHandler(state, probe) {
  const inGrace = state.lastInjectOkAt
    && (Date.now() - state.lastInjectOkAt < POST_INJECT_GRACE_MS);
  if (probe === 'yes') {
    state.lastPayloadState = 'yes';
  } else if (probe === 'no' && !inGrace) {
    state.lastPayloadState = 'no';
  }
  let effective;
  if (probe === 'yes')                effective = 'yes';
  else if (probe === 'no' && inGrace) effective = 'yes';   // suppression window
  else if (probe === 'unknown')       effective = state.lastPayloadState;
  else                                effective = probe;
  return { payload_state: probe, payload_loaded: effective === 'yes' };
}

function onInjectOk(state) {
  state.lastPayloadState = 'yes';
  state.lastInjectOkAt   = Date.now();
}
// Pre-fix behavior (what main.js DID) — only touches latch, not timestamp.
function onUninject_PREFIX(state) {
  state.lastPayloadState = 'no';
}
// Post-fix behavior (what markPayloadDown() now does in main.js).
function onUninject_FIXED(state) {
  state.lastPayloadState = 'no';
  state.lastInjectOkAt   = 0;
}

let failures = 0;
function assert(name, cond, detail) {
  if (cond) console.log('  [PASS] ' + name);
  else { console.log('  [FAIL] ' + name + (detail ? ' :: ' + detail : '')); failures++; }
}

// ─── T1: PROVE the bug exists in the pre-fix pattern ──────────
console.log('T1 — pre-fix uninject (no grace reset) DOES produce false-positive');
{
  const s = makeState();
  onInjectOk(s);
  s.lastInjectOkAt = Date.now() - 3000;   // 3s ago -> still in 15s grace
  onUninject_PREFIX(s);
  const r = statusHandler(s, 'no');
  assert('pre-fix returns payload_loaded=true (this IS the bug)',
         r.payload_loaded === true,
         `expected buggy true; got payload_loaded=${r.payload_loaded}`);
}

// ─── T2: fix must not regress legitimate grace protection ─────
console.log('T2 — grace still suppresses transient no during fresh inject');
{
  const s = makeState();
  onInjectOk(s);
  const r = statusHandler(s, 'no');   // init_thread still publishing event
  assert('during real settle window payload_loaded=true',
         r.payload_loaded === true,
         `got payload_loaded=${r.payload_loaded}`);
}

// ─── T3: PROVE the fix pattern is correct ─────────────────────
console.log('T3 — fixed uninject (resets lastInjectOkAt) reports offline');
{
  const s = makeState();
  onInjectOk(s);
  s.lastInjectOkAt = Date.now() - 3000;
  onUninject_FIXED(s);
  const r = statusHandler(s, 'no');
  assert('post-fix returns payload_loaded=false',
         r.payload_loaded === false,
         `expected false; got payload_loaded=${r.payload_loaded}`);
}

// ─── T4: static-verify main.js has the fix wired everywhere ───
console.log('T4 — main.js has markPayloadDown() at every intentional teardown');
{
  const mainJs = fs.readFileSync(
    path.join(__dirname, '..', 'ui', 'src', 'main.js'), 'utf8'
  );

  // Helper defined?
  assert('markPayloadDown() helper defined',
         /function\s+markPayloadDown\s*\(\s*\)\s*\{[^}]*lastInjectOkAt\s*=\s*0/.test(mainJs));

  // Old anti-pattern (bare `lastPayloadState = 'no';` immediately followed by
  // an injector.uninject() / injector.killAll() call) must be gone — every
  // intentional teardown should now route through markPayloadDown().
  const bareLatchThenTeardown =
    /lastPayloadState\s*=\s*['"]no['"];\s*(?:\/\/[^\n]*\n\s*)?return\s+injector\.(un|kill)/;
  assert('old bare-latch-before-uninject/killAll anti-pattern removed',
         !bareLatchThenTeardown.test(mainJs),
         'main.js still contains lastPayloadState="no" immediately before injector.uninject/killAll');

  // Every intentional-teardown call site should have a markPayloadDown()
  // within a short window before it. We check by counting:
  const markCalls   = (mainJs.match(/markPayloadDown\s*\(\s*\)/g) || []).length;
  // Helper decl doesn't count as a call — it's `function markPayloadDown()`, not
  // `markPayloadDown()` followed by `;`. Adjust: subtract the decl form.
  const declMatches = (mainJs.match(/function\s+markPayloadDown\s*\(\s*\)/g) || []).length;
  const invocations = markCalls - declMatches;
  assert('markPayloadDown() invoked at >= 6 call sites',
         invocations >= 6,
         `only ${invocations} call sites (need >=6: uninject / kill-all / sign-out / reset-local / reset-all / overlay-reset / lockout)`);
}

console.log('---');
if (failures) {
  console.log(`FAIL: ${failures} assertion(s) failed`);
  process.exit(1);
} else {
  console.log('OK: bug documented, fix verified, main.js call sites wired');
  process.exit(0);
}
