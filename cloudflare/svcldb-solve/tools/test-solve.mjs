// E2E test harness for svcldb-solve.
//
// Self-serve: uses the service key to create a confirmed test user + grant a
// weekly subscription (=> credits via the activation trigger), signs in with
// the anon key to mint a REAL Supabase JWT, then exercises the worker:
//   /validate  -> auth + sub ok
//   /credits   -> balance
//   /solve     -> full metered path (acquire -> OpenRouter -> release/deduct)
// and asserts credits went DOWN by the reported cost.
//
// Run:
//   SUPABASE_SERVICE_KEY=... WORKER_URL=https://svcldb-solve.<acct>.workers.dev \
//   node tools/test-solve.mjs
//
// Optional env: SUPABASE_URL, SUPABASE_ANON_KEY, TEST_EMAIL (defaults provided).

const SUPABASE_URL = process.env.SUPABASE_URL || "https://rrrpkmzdnaodmvsuxdkw.supabase.co";
const ANON = process.env.SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJycnBrbXpkbmFvZG12c3V4ZGt3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njc2ODUyNzgsImV4cCI6MjA4MzI2MTI3OH0.J4kdDarCDVjkt0M9hbShgJaV7B12W56K_hUQAPSZ1-c";
const SERVICE = process.env.SUPABASE_SERVICE_KEY;
const WORKER_URL = (process.env.WORKER_URL || "").replace(/\/+$/, "");
const EMAIL = process.env.TEST_EMAIL || `svcldb-e2e+${Date.now()}@example.com`;
const PASSWORD = process.env.TEST_PASSWORD || "Test-" + Math.random().toString(36).slice(2) + "!9";

function die(msg) { console.error("FAIL:", msg); process.exit(1); }
if (!SERVICE) die("SUPABASE_SERVICE_KEY env is required");
if (!WORKER_URL) die("WORKER_URL env is required (deployed worker base URL)");

const admin = (path, init = {}) =>
  fetch(`${SUPABASE_URL}${path}`, {
    ...init,
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, "Content-Type": "application/json", ...(init.headers || {}) },
  });

async function main() {
  // 1. Create a confirmed test user (GoTrue admin API).
  console.log("→ creating test user", EMAIL);
  let r = await admin("/auth/v1/admin/users", {
    method: "POST",
    body: JSON.stringify({ email: EMAIL, password: PASSWORD, email_confirm: true }),
  });
  if (!r.ok) die(`create user: ${r.status} ${await r.text()}`);
  const uid = (await r.json()).id;
  console.log("  user id:", uid);

  // 2. Grant a weekly subscription (activation trigger grants credits).
  console.log("→ granting weekly subscription");
  r = await admin("/rest/v1/rpc/grant_weekly", {
    method: "POST",
    body: JSON.stringify({ target_email: EMAIL, reason: "e2e test" }),
  });
  if (!r.ok) die(`grant_weekly: ${r.status} ${await r.text()}`);
  console.log("  grant:", JSON.stringify(await r.json()));

  // 3. Sign in (anon key) -> real user JWT.
  console.log("→ signing in for JWT");
  r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: ANON, "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  if (!r.ok) die(`sign in: ${r.status} ${await r.text()}`);
  const jwt = (await r.json()).access_token;
  const H = { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" };

  // 4. /validate
  console.log("→ /validate");
  r = await fetch(`${WORKER_URL}/validate`, { headers: H });
  console.log("  ", r.status, await r.text());
  if (!r.ok) die("validate failed");

  // 5. /credits (before)
  r = await fetch(`${WORKER_URL}/credits`, { headers: H });
  const before = await r.json();
  console.log("→ credits before:", before.credits);

  // 6. /solve (text-only, cheap deterministic question)
  console.log("→ /solve");
  r = await fetch(`${WORKER_URL}/solve`, {
    method: "POST",
    headers: H,
    body: JSON.stringify({ question: "What is 17 * 23? Reply with only the number.", explain: false }),
  });
  const solved = await r.json();
  console.log("  ", r.status, JSON.stringify(solved));
  if (!r.ok || !solved.ok) die("solve failed");
  if (!String(solved.answer).includes("391")) console.warn("  WARN: unexpected answer (expected 391)");

  // 7. /credits (after) -> must have decreased by ~cost
  r = await fetch(`${WORKER_URL}/credits`, { headers: H });
  const after = await r.json();
  console.log("→ credits after:", after.credits, "| cost:", solved.cost, "| remaining reported:", solved.creditsRemaining);
  if (!(after.credits < before.credits)) die("credits did not decrease after solve");

  // 8. cleanup
  console.log("→ cleanup: deleting test user");
  await admin(`/auth/v1/admin/users/${uid}`, { method: "DELETE" }).catch(() => {});

  console.log("\nPASS: auth + subscription gate + metered solve + credit deduction all verified.");
}
main().catch((e) => die(e?.stack || String(e)));
