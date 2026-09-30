// Deferred end-to-end proof of the expired-JWT grace against the DEPLOYED worker.
//
// This is the ONE test that can't run in a single sitting: it needs a REAL
// Supabase user token that is genuinely EXPIRED. Supabase issues 1-hour ES256
// tokens and there's no per-request TTL, so the flow is: mint now, re-test the
// SAME token after it expires (>1h later), with no refresh in between.
//
// The signal needs no subscription and spends no credits:
//   - EXPIRED token -> /validate returns 403 (or 200 if the user is subbed)
//       => auth PASSED via grace. FIX CONFIRMED.
//   - EXPIRED token -> /validate returns 401 invalid_or_expired_token
//       => grace did NOT fire (pre-fix behavior).
//
// Usage:
//   1) Mint now:
//        node tools/test-grace-live.mjs
//      (prints the token + its expiry, hits /validate to show fresh=OK, and
//       writes the token to your OS temp dir for step 2.)
//   2) After the printed "expires at" time (>~1h later), WITHOUT refreshing:
//        node tools/test-grace-live.mjs --retest
//      or pass it explicitly:  GRACE_TOKEN="<jwt>" node tools/test-grace-live.mjs --retest

import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SUPABASE_URL = process.env.SUPABASE_URL || "https://rrrpkmzdnaodmvsuxdkw.supabase.co";
const ANON = process.env.SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJycnBrbXpkbmFvZG12c3V4ZGt3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njc2ODUyNzgsImV4cCI6MjA4MzI2MTI3OH0.J4kdDarCDVjkt0M9hbShgJaV7B12W56K_hUQAPSZ1-c";
const WORKER = (process.env.WORKER_URL || "https://svcldb-solve.c-viperdevelopment.workers.dev").replace(/\/+$/, "");
const EMAIL = process.env.SMOKE_EMAIL || "svcldb-e2e@example.com";
const PASSWORD = process.env.SMOKE_PASSWORD || "TestPass123!xyz";
const TOKEN_FILE = join(tmpdir(), "svcldb_grace_token.txt");

function decodeExp(jwt) {
  try {
    const p = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(Buffer.from(p, "base64").toString("utf8"));
    return { exp: json.exp, sub: json.sub, iat: json.iat };
  } catch { return {}; }
}

async function validate(jwt) {
  const r = await fetch(`${WORKER}/validate`, { headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" } });
  let body = ""; try { body = await r.text(); } catch {}
  return { status: r.status, body };
}

async function signIn() {
  const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: ANON, "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  const auth = await r.json();
  if (!r.ok || !auth.access_token) { console.error("sign-in failed:", r.status, JSON.stringify(auth)); process.exit(2); }
  return auth.access_token;
}

async function main() {
  const retest = process.argv.includes("--retest");
  const now = Math.floor(Date.now() / 1000);

  if (retest) {
    let jwt = process.env.GRACE_TOKEN;
    if (!jwt && existsSync(TOKEN_FILE)) jwt = readFileSync(TOKEN_FILE, "utf8").trim();
    if (!jwt) { console.error("No token. Run the mint step first, or pass GRACE_TOKEN=..."); process.exit(2); }
    const { exp, sub } = decodeExp(jwt);
    const expiredBy = now - (exp || 0);
    console.log(`worker : ${WORKER}`);
    console.log(`sub    : ${sub}`);
    console.log(`exp    : ${new Date((exp || 0) * 1000).toISOString()}  (${expiredBy >= 0 ? "EXPIRED " + expiredBy + "s ago" : "still valid for " + (-expiredBy) + "s"})`);
    if (expiredBy < 0) {
      console.log("\nToken is NOT expired yet. Wait until after the exp time above, then re-run.");
      process.exit(0);
    }
    const { status, body } = await validate(jwt);
    console.log(`\n/validate with EXPIRED token -> HTTP ${status}`);
    console.log(`  ${body}`);
    const pass = status === 200 || status === 403;  // auth passed (403 = no sub, still proves grace)
    console.log(`\nRESULT: ${pass ? "PASS - expired-JWT grace CONFIRMED against prod" : "FAIL - grace did not fire (got " + status + ")"}`);
    process.exit(pass ? 0 : 1);
  }

  // Mint mode.
  console.log(`worker : ${WORKER}`);
  console.log("-> signing in to mint a real ES256 token");
  const jwt = await signIn();
  const { exp, sub, iat } = decodeExp(jwt);
  writeFileSync(TOKEN_FILE, jwt, "utf8");
  console.log(`  sub  : ${sub}`);
  console.log(`  iat  : ${new Date((iat || 0) * 1000).toISOString()}`);
  console.log(`  exp  : ${new Date((exp || 0) * 1000).toISOString()}  (in ${Math.round(((exp || now) - now) / 60)} min)`);
  console.log(`  saved: ${TOKEN_FILE}`);

  const { status, body } = await validate(jwt);
  console.log(`\n/validate with FRESH token -> HTTP ${status}`);
  console.log(`  ${body}`);
  console.log(`  (401 here would be a problem; 200/403 = auth OK)`);

  console.log(`\nNEXT: after ${new Date((exp || 0) * 1000).toLocaleTimeString()}, WITHOUT reopening/refreshing, run:`);
  console.log(`  node tools/test-grace-live.mjs --retest`);
  console.log(`Expect the EXPIRED token to return 403/200 (grace) instead of 401.`);
}
main().catch((e) => { console.error("ERROR:", e?.stack || String(e)); process.exit(3); });
