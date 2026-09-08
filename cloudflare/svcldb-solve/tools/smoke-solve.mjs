// Service-key-FREE live smoke test for svcldb-solve.
//
// Signs in as an EXISTING user via the anon key (password grant) to mint a real
// Supabase JWT, then exercises /validate, /credits, /solve against the deployed
// worker and prints the AI answer + credit deduction. Unlike test-solve.mjs this
// needs NO service_role key — just a real user's email + password.
//
// Run (PowerShell):
//   $env:SMOKE_EMAIL="svcldb-e2e@example.com"; $env:SMOKE_PASSWORD="TestPass123!xyz"; node tools/smoke-solve.mjs
//   # optional: $env:SMOKE_TIER="cheap"   (strong|medium|cheap) to test tier->model mapping
//   # matrix:   $env:SMOKE_MATRIX="1"     runs one solve per tier and checks each model
//
// Optional env: SUPABASE_URL, SUPABASE_ANON_KEY, WORKER_URL.

const SUPABASE_URL = process.env.SUPABASE_URL || "https://rrrpkmzdnaodmvsuxdkw.supabase.co";
const ANON = process.env.SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJycnBrbXpkbmFvZG12c3V4ZGt3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njc2ODUyNzgsImV4cCI6MjA4MzI2MTI3OH0.J4kdDarCDVjkt0M9hbShgJaV7B12W56K_hUQAPSZ1-c";
const WORKER_URL = (process.env.WORKER_URL || "https://svcldb-solve.c-viperdevelopment.workers.dev").replace(/\/+$/, "");
const EMAIL = process.env.SMOKE_EMAIL || "svcldb-e2e@example.com";
const PASSWORD = process.env.SMOKE_PASSWORD || "TestPass123!xyz";

const EXPECT_MODEL = { strong: "gpt-6-astra", medium: "gpt-5.6-terra", cheap: "gpt-5.6-luna" };
const j = (o) => JSON.stringify(o);

async function signIn() {
  const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: ANON, "Content-Type": "application/json" },
    body: j({ email: EMAIL, password: PASSWORD }),
  });
  const auth = await r.json();
  if (!r.ok || !auth.access_token) {
    console.error("  sign-in FAILED:", r.status, j(auth));
    process.exit(2);
  }
  return auth.access_token;
}

async function solveOnce(H, tier) {
  const body = { question: "What is 17 * 23? Reply with only the number.", explain: false };
  if (tier) body.tier = tier;
  const t0 = Date.now();
  const r = await fetch(`${WORKER_URL}/solve`, { method: "POST", headers: H, body: j(body) });
  const solved = await r.json();
  const dt = ((Date.now() - t0) / 1000).toFixed(1);
  const expect = (tier && EXPECT_MODEL[tier]) || "gpt-6-astra";
  const okAnswer = !!solved.ok && String(solved.answer || "").includes("391");
  const okModel = String(solved.model || "").includes(expect);
  console.log(`  tier=${tier || "(default)"} -> ${r.status} (${dt}s) model=${solved.model} answer=${solved.answer} cost=${solved.cost}` +
    `  [answer=391? ${okAnswer} | model=${expect}? ${okModel}]`);
  return okAnswer && okModel;
}

async function main() {
  console.log("worker:", WORKER_URL);
  console.log("-> sign in as", EMAIL);
  const jwt = await signIn();
  console.log("  ok, jwt len", jwt.length);
  const H = { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" };

  console.log("-> /validate");
  let r = await fetch(`${WORKER_URL}/validate`, { headers: H });
  console.log("  ", r.status, await r.text());

  r = await fetch(`${WORKER_URL}/credits`, { headers: H });
  const before = await r.json();
  console.log("-> credits before:", before.credits);

  let allOk = true;
  if (process.env.SMOKE_MATRIX === "1") {
    console.log("-> /solve matrix (strong, medium, cheap)");
    for (const tier of ["strong", "medium", "cheap"]) allOk = (await solveOnce(H, tier)) && allOk;
  } else {
    console.log("-> /solve");
    allOk = await solveOnce(H, process.env.SMOKE_TIER || null);
  }

  r = await fetch(`${WORKER_URL}/credits`, { headers: H });
  const after = await r.json();
  const okDeduct = Number(after.credits) < Number(before.credits);
  console.log(`-> credits after: ${after.credits}  [dropped? ${okDeduct}]`);

  console.log(`\nRESULT: ${allOk && okDeduct ? "PASS" : "FAIL"}`);
  process.exit(allOk && okDeduct ? 0 : 1);
}

main().catch((e) => { console.error("ERROR:", e?.stack || String(e)); process.exit(3); });
