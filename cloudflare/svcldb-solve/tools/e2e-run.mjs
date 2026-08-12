// E2E runner (no service key): signs in an already-provisioned test user with the
// anon key, then exercises the worker end to end and asserts credit deduction.
// The user + subscription are provisioned separately (via Supabase MCP SQL).
const SUPABASE_URL = process.env.SUPABASE_URL || "https://rrrpkmzdnaodmvsuxdkw.supabase.co";
const ANON = process.env.SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJycnBrbXpkbmFvZG12c3V4ZGt3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njc2ODUyNzgsImV4cCI6MjA4MzI2MTI3OH0.J4kdDarCDVjkt0M9hbShgJaV7B12W56K_hUQAPSZ1-c";
const WORKER = (process.env.WORKER_URL || "https://svcldb-solve.c-viperdevelopment.workers.dev").replace(/\/+$/, "");
const EMAIL = process.env.TEST_EMAIL, PASSWORD = process.env.TEST_PASSWORD;
const die = (m) => { console.error("FAIL:", m); process.exit(1); };
if (!EMAIL || !PASSWORD) die("TEST_EMAIL + TEST_PASSWORD required");

const main = async () => {
  console.log("→ sign in", EMAIL);
  let r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: "POST", headers: { apikey: ANON, "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  if (!r.ok) die(`signin ${r.status}: ${await r.text()}`);
  const jwt = (await r.json()).access_token;
  if (!jwt) die("no access_token");
  const H = { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" };

  console.log("→ unauth probe (should 401)");
  r = await fetch(`${WORKER}/validate`);
  console.log("   ", r.status, (await r.text()).slice(0, 80));
  if (r.status !== 401) die("unauth was not 401");

  console.log("→ /validate");
  r = await fetch(`${WORKER}/validate`, { headers: H });
  const val = await r.json(); console.log("   ", r.status, JSON.stringify(val));
  if (!r.ok || !val.ok) die("validate failed");

  r = await fetch(`${WORKER}/credits`, { headers: H });
  const before = await r.json(); console.log("→ credits before:", before.credits);

  console.log("→ /solve  (17 * 23)");
  r = await fetch(`${WORKER}/solve`, {
    method: "POST", headers: H,
    body: JSON.stringify({ question: "What is 17 * 23? Reply with only the number.", explain: false }),
  });
  const solved = await r.json();
  console.log("   ", r.status, JSON.stringify(solved));
  if (!r.ok || !solved.ok) die("solve failed");
  if (!String(solved.answer).includes("391")) console.warn("   WARN: expected 391");

  r = await fetch(`${WORKER}/credits`, { headers: H });
  const after = await r.json();
  console.log(`→ credits after: ${after.credits}  (cost ${solved.cost}, remaining reported ${solved.creditsRemaining})`);
  if (!(after.credits < before.credits)) die("credits did not decrease");

  console.log("\nPASS: unauth blocked + auth + sub gate + metered solve + credit deduction verified.");
};
main().catch((e) => die(e?.stack || String(e)));
