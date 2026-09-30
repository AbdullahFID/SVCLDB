// Test harness for the expired-JWT grace path in src/worker.js
// (root fix for "session expired mid-exam").
//
// Part A - DETERMINISTIC unit tests. Generates a local ES256 keypair, signs
//   tokens with arbitrary claims (including past exp values we can't get from
//   a real Supabase sign-in in-session), and drives the EXACT verification
//   code via the injectable `getKey`. Covers: fresh, expired-within-grace,
//   expired-beyond-grace, tampered signature, wrong signer, wrong iss/role,
//   missing sub, non-ES256 header, and grace-disabled.
//
// Part B - LIVE integration. Mints a real ES256 user JWT via the anon key +
//   password grant, then verifies it against the LIVE Supabase JWKS through
//   the same code path (no injected key). Proves the real JWKS fetch + EC key
//   import + ECDSA verify all work end to end. Skips (WARN, non-fatal) if no
//   SMOKE creds are available.
//
// Run:
//   node tools/test-jwt-grace.mjs
//   $env:SMOKE_EMAIL="..."; $env:SMOKE_PASSWORD="..."; node tools/test-jwt-grace.mjs

import { verifyExpiredJwtWithinGrace, _authTestHooks } from "../src/worker.js";

const SUPABASE_URL = process.env.SUPABASE_URL || "https://rrrpkmzdnaodmvsuxdkw.supabase.co";
const ANON = process.env.SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJycnBrbXpkbmFvZG12c3V4ZGt3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njc2ODUyNzgsImV4cCI6MjA4MzI2MTI3OH0.J4kdDarCDVjkt0M9hbShgJaV7B12W56K_hUQAPSZ1-c";
const SMOKE_EMAIL = process.env.SMOKE_EMAIL || "svcldb-e2e@example.com";
const SMOKE_PASSWORD = process.env.SMOKE_PASSWORD || "TestPass123!xyz";

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}`); }
}

// ---- base64url helpers (encode side; the worker owns the decode side) -------
function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const b64urlStr = (s) => b64url(new TextEncoder().encode(s));

async function makeJwt(priv, header, payload) {
  const h = b64urlStr(JSON.stringify(header));
  const p = b64urlStr(JSON.stringify(payload));
  const data = new TextEncoder().encode(`${h}.${p}`);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, data));
  return `${h}.${p}.${b64url(sig)}`;
}

const nowS = () => Math.floor(Date.now() / 1000);
const ISS = `${"https://test.supabase.co"}/auth/v1`;
const TEST_ENV = { SUPABASE_URL: "https://test.supabase.co", JWT_EXPIRED_GRACE_S: "604800" };
const H = { alg: "ES256", kid: "test-kid", typ: "JWT" };
const basePayload = (over = {}) => ({
  iss: ISS, role: "authenticated", sub: "u-1111", aud: "authenticated",
  iat: nowS() - 3600, exp: nowS() + 3600, ...over,
});

async function partA() {
  console.log("\n== Part A: deterministic unit tests (injected ES256 key) ==");

  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const getKey = async (kid) => (kid === "test-kid" ? kp.publicKey : null);

  // Pure decision helper.
  const { expWithinGrace, b64urlToJson } = _authTestHooks;
  const n = nowS();
  ok("expWithinGrace: expired 100s < 200s grace", expWithinGrace(n - 100, n, 200) === true);
  ok("expWithinGrace: expired 300s > 200s grace", expWithinGrace(n - 300, n, 200) === false);
  ok("expWithinGrace: small future skew (+5s)", expWithinGrace(n + 5, n, 200) === true);
  ok("expWithinGrace: realistic future exp accepted (transient getUser)", expWithinGrace(n + 3600, n, 200) === true);
  ok("expWithinGrace: absurd future exp (40d) rejected", expWithinGrace(n + 40 * 86400, n, 200) === false);
  ok("expWithinGrace: NaN exp rejected", expWithinGrace(NaN, n, 200) === false);
  ok("b64urlToJson round-trips", JSON.stringify(b64urlToJson(b64urlStr(JSON.stringify({ a: 1, b: "x" })))) === JSON.stringify({ a: 1, b: "x" }));

  // 1. Fresh token accepted.
  let t = await makeJwt(kp.privateKey, H, basePayload());
  let r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("fresh token accepted (sub ok)", !!r && r.sub === "u-1111" && r.expired === false);

  // 2. Expired 100s, 7-day grace -> accepted, flagged expired.
  t = await makeJwt(kp.privateKey, H, basePayload({ exp: nowS() - 100 }));
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("expired 100s within grace -> accepted", !!r && r.sub === "u-1111" && r.expired === true);

  // 3. Expired 100s but grace=50 -> rejected.
  t = await makeJwt(kp.privateKey, H, basePayload({ exp: nowS() - 100 }));
  r = await verifyExpiredJwtWithinGrace({ ...TEST_ENV, JWT_EXPIRED_GRACE_S: "50" }, t, { getKey });
  ok("expired beyond (small) grace -> rejected", r === null);

  // 4. Expired 8 days, 7-day grace -> rejected.
  t = await makeJwt(kp.privateKey, H, basePayload({ exp: nowS() - 8 * 86400 }));
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("expired 8d beyond 7d grace -> rejected", r === null);

  // 5. Tampered signature (still valid base64url) -> crypto verify fails.
  t = await makeJwt(kp.privateKey, H, basePayload());
  {
    const seg = t.split(".");
    const s = seg[2];
    const i = Math.floor(s.length / 2);
    seg[2] = s.slice(0, i) + (s[i] === "A" ? "B" : "A") + s.slice(i + 1);
    r = await verifyExpiredJwtWithinGrace(TEST_ENV, seg.join("."), { getKey });
  }
  ok("tampered signature (valid b64) -> rejected", r === null);

  // 5b. Garbage signature bytes (invalid base64) -> rejected, no throw.
  t = await makeJwt(kp.privateKey, H, basePayload());
  {
    const seg = t.split(".");
    seg[2] = "@@@@not-base64@@@@";
    r = await verifyExpiredJwtWithinGrace(TEST_ENV, seg.join("."), { getKey });
  }
  ok("garbage signature -> rejected (no throw)", r === null);

  // 5c. Wrong-length signature -> rejected.
  t = await makeJwt(kp.privateKey, H, basePayload());
  {
    const seg = t.split(".");
    seg[2] = "AAAA"; // decodes to 3 bytes, not 64
    r = await verifyExpiredJwtWithinGrace(TEST_ENV, seg.join("."), { getKey });
  }
  ok("wrong-length signature -> rejected", r === null);

  // 6. Signed by a DIFFERENT key -> signature invalid.
  t = await makeJwt(other.privateKey, H, basePayload());
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("wrong signer -> rejected", r === null);

  // 7. Wrong issuer -> rejected.
  t = await makeJwt(kp.privateKey, H, basePayload({ iss: "https://evil.example/auth/v1" }));
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("wrong iss -> rejected", r === null);

  // 8. Wrong role -> rejected.
  t = await makeJwt(kp.privateKey, H, basePayload({ role: "anon" }));
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("role != authenticated -> rejected", r === null);

  // 9. Missing sub -> rejected.
  t = await makeJwt(kp.privateKey, H, basePayload({ sub: "" }));
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("missing sub -> rejected", r === null);

  // 10. Non-ES256 header -> rejected before any key work.
  t = await makeJwt(kp.privateKey, { alg: "HS256", kid: "test-kid", typ: "JWT" }, basePayload());
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("alg != ES256 -> rejected", r === null);

  // 11. Grace disabled (0) -> even a fresh token is rejected on this path.
  t = await makeJwt(kp.privateKey, H, basePayload());
  r = await verifyExpiredJwtWithinGrace({ ...TEST_ENV, JWT_EXPIRED_GRACE_S: "0" }, t, { getKey });
  ok("grace disabled -> rejected", r === null);

  // 12. Malformed token (not 3 segments) -> rejected.
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, "not.a.jwt.x", { getKey });
  ok("malformed token -> rejected", r === null);

  // 13. Unknown kid -> getKey returns null -> rejected.
  t = await makeJwt(kp.privateKey, { alg: "ES256", kid: "unknown", typ: "JWT" }, basePayload());
  r = await verifyExpiredJwtWithinGrace(TEST_ENV, t, { getKey });
  ok("unknown kid -> rejected", r === null);
}

async function partB() {
  console.log("\n== Part B: live JWKS verify (real Supabase token) ==");
  let jwt;
  try {
    const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { apikey: ANON, "Content-Type": "application/json" },
      body: JSON.stringify({ email: SMOKE_EMAIL, password: SMOKE_PASSWORD }),
    });
    const auth = await res.json();
    if (!res.ok || !auth.access_token) {
      console.log(`  WARN  sign-in failed (${res.status}) - skipping live test. Set SMOKE_EMAIL/SMOKE_PASSWORD to enable.`);
      return;
    }
    jwt = auth.access_token;
  } catch (e) {
    console.log(`  WARN  sign-in threw (${e?.message}) - skipping live test.`);
    return;
  }

  const liveEnv = { SUPABASE_URL, SUPABASE_ANON_KEY: ANON, JWT_EXPIRED_GRACE_S: "604800" };
  // Real fresh token verified against the LIVE JWKS (default key path).
  const r = await verifyExpiredJwtWithinGrace(liveEnv, jwt);
  ok("live: real token verifies against live JWKS", !!r && typeof r.sub === "string" && r.sub.length > 10);

  // Tamper the real signature (valid b64) -> must reject with the real key.
  const seg = jwt.split(".");
  const s = seg[2];
  const i = Math.floor(s.length / 2);
  seg[2] = s.slice(0, i) + (s[i] === "A" ? "B" : "A") + s.slice(i + 1);
  const r2 = await verifyExpiredJwtWithinGrace(liveEnv, seg.join("."));
  ok("live: tampered real token rejected", r2 === null);
}

async function main() {
  await partA();
  await partB();
  console.log(`\nRESULT: ${fail === 0 ? "PASS" : "FAIL"}  (${pass} passed, ${fail} failed)`);
  process.exit(fail === 0 ? 0 : 1);
}
main().catch((e) => { console.error("ERROR:", e?.stack || String(e)); process.exit(3); });
