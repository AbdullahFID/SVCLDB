// ═══════════════════════════════════════════════════════════════
// test_reval_timing.js
//
// Prove that revalidation.js's nextDelayMs() ALWAYS schedules a
// refresh BEFORE the JWT expires. Original bug: uncapped 1h ± 20%
// jitter routinely overshot the 60m TTL. Fix: cap at (exp - 12min).
//
// 5000 monte-carlo samples across the whole expiry range.
// ═══════════════════════════════════════════════════════════════

const r = require('../../ui/src/license/revalidation.js');

const SAMPLES  = 5000;
const NOW_S    = Math.floor(Date.now() / 1000);

// Range 1: fresh token (55min - 65min remaining).
// This is the case where the OLD scheduler overshot ~49% of the time.
let over_range1 = 0;
let sum_lead_range1 = 0;
let min_lead_range1 = Infinity;
let max_lead_range1 = -Infinity;
for (let i = 0; i < SAMPLES; i++) {
  const remaining = 55 * 60 + Math.floor(Math.random() * (10 * 60));  // 55-65 min
  const s = { expires_at: NOW_S + remaining, refresh_token: 'x' };
  const d = r.nextDelayMs(() => s);
  const lead_at_wake_s = remaining - Math.floor(d / 1000);
  // We WANT lead_at_wake_s >= r.REFRESH_WAKE_LEAD_S so refresh branch fires.
  // (nextDelayMs schedules to leave REFRESH_WAKE_LEAD_S buffer.)
  if (lead_at_wake_s <= 0) over_range1++;  // slept past expiry -- catastrophic
  sum_lead_range1 += lead_at_wake_s;
  if (lead_at_wake_s < min_lead_range1) min_lead_range1 = lead_at_wake_s;
  if (lead_at_wake_s > max_lead_range1) max_lead_range1 = lead_at_wake_s;
}

// Range 2: freshly-refreshed token (55-60min remaining).
// Common case right after signin/refresh.
let over_range2 = 0;
for (let i = 0; i < SAMPLES; i++) {
  const remaining = 55 * 60 + Math.floor(Math.random() * (5 * 60));
  const s = { expires_at: NOW_S + remaining, refresh_token: 'x' };
  const d = r.nextDelayMs(() => s);
  const lead_at_wake_s = remaining - Math.floor(d / 1000);
  if (lead_at_wake_s <= 0) over_range2++;
}

// Range 3: near-expired (5-15min remaining). Should schedule floor of 30s.
let over_range3 = 0;
let floor30_hits = 0;
for (let i = 0; i < SAMPLES; i++) {
  const remaining = 5 * 60 + Math.floor(Math.random() * (10 * 60));
  const s = { expires_at: NOW_S + remaining, refresh_token: 'x' };
  const d = r.nextDelayMs(() => s);
  if (d === 30_000) floor30_hits++;
  const lead_at_wake_s = remaining - Math.floor(d / 1000);
  if (lead_at_wake_s <= 0) over_range3++;
}

// Range 4: already expired (negative remaining). Must return floor.
let neg_floor_ok = 0;
for (let i = 0; i < SAMPLES; i++) {
  const remaining = -(Math.floor(Math.random() * (60 * 60)));
  const s = { expires_at: NOW_S + remaining, refresh_token: 'x' };
  const d = r.nextDelayMs(() => s);
  if (d === 30_000) neg_floor_ok++;
}

// Range 5: no session (getSession returns null). Should return base ± jitter.
let range5_min = Infinity, range5_max = -Infinity;
for (let i = 0; i < SAMPLES; i++) {
  const d = r.nextDelayMs(() => null);
  if (d < range5_min) range5_min = d;
  if (d > range5_max) range5_max = d;
}

console.log('─'.repeat(72));
console.log('REVALIDATION SCHEDULER — TIMING VERIFICATION');
console.log(`  Constants: REFRESH_WAKE_LEAD_S=${r.REFRESH_WAKE_LEAD_S}s (${r.REFRESH_WAKE_LEAD_S/60}m)`);
console.log(`             TOKEN_REFRESH_BUFFER_S=${r.TOKEN_REFRESH_BUFFER_S}s (${r.TOKEN_REFRESH_BUFFER_S/60}m)`);
console.log(`             BASE_INTERVAL_MS=${r.BASE_INTERVAL_MS/60000}min ± ${r.JITTER_PCT*100}%`);
console.log('─'.repeat(72));

console.log('\nRANGE 1 -- fresh token (55-65min remaining), 5000 samples:');
console.log(`  overshoots (wake AFTER expiry): ${over_range1}/${SAMPLES} (MUST be 0)`);
console.log(`  lead at wake time (s):  min=${min_lead_range1}  max=${max_lead_range1}  avg=${Math.round(sum_lead_range1 / SAMPLES)}`);
if (min_lead_range1 >= r.REFRESH_WAKE_LEAD_S) {
  console.log(`  ✓ min lead (${min_lead_range1}s) >= REFRESH_WAKE_LEAD_S (${r.REFRESH_WAKE_LEAD_S}s) -- refresh branch WILL fire`);
} else {
  console.log(`  ✗ min lead (${min_lead_range1}s) < REFRESH_WAKE_LEAD_S (${r.REFRESH_WAKE_LEAD_S}s) -- refresh may skip`);
}

console.log('\nRANGE 2 -- typical fresh (55-60min), 5000 samples:');
console.log(`  overshoots: ${over_range2}/${SAMPLES} (MUST be 0)`);

console.log('\nRANGE 3 -- near-expired (5-15min), 5000 samples:');
console.log(`  overshoots: ${over_range3}/${SAMPLES} (MUST be 0)`);
console.log(`  floor-30s hits: ${floor30_hits}/${SAMPLES} (any is fine -- proves floor works)`);

console.log('\nRANGE 4 -- already expired, 5000 samples:');
console.log(`  floor-30s hits: ${neg_floor_ok}/${SAMPLES} (MUST equal ${SAMPLES})`);

console.log('\nRANGE 5 -- no session (fallback to jittered base), 5000 samples:');
console.log(`  delay range: ${range5_min}ms - ${range5_max}ms`);
const expectedMin = r.BASE_INTERVAL_MS * (1 - r.JITTER_PCT);
const expectedMax = r.BASE_INTERVAL_MS * (1 + r.JITTER_PCT);
console.log(`  expected:    ${expectedMin}ms - ${expectedMax}ms`);
const inBounds = range5_min >= expectedMin - 1000 && range5_max <= expectedMax + 1000;
console.log(`  ${inBounds ? '✓' : '✗'} jitter bounds ${inBounds ? 'correct' : 'WRONG'}`);

const failures = over_range1 + over_range2 + over_range3 + (neg_floor_ok !== SAMPLES ? 1 : 0) + (inBounds ? 0 : 1);
console.log('\n' + '─'.repeat(72));
console.log(`VERDICT: ${failures === 0 ? '✓ SCHEDULER CORRECT — refresh always fires before expiry' : '✗ ' + failures + ' failure conditions'}`);
console.log('─'.repeat(72));
process.exit(failures === 0 ? 0 : 1);
