// v7.4 multi-turn smoke test for the svcldb-solve worker.
//
// Signs in as an existing test user (SMOKE_EMAIL / SMOKE_PASSWORD env),
// then hits /solve with a `messages` array that includes a prior turn
// (user + assistant) followed by a follow-up question that CAN ONLY BE
// ANSWERED CORRECTLY IF THE MODEL REMEMBERS THE PRIOR CONTEXT. Also
// runs the legacy single-turn shape to prove back-compat.
//
// Run:
//   $env:SMOKE_EMAIL="svcldb-e2e@example.com"
//   $env:SMOKE_PASSWORD="TestPass123!xyz"
//   node tools/smoke-multiturn.mjs

const SUPABASE_URL = process.env.SUPABASE_URL || "https://rrrpkmzdnaodmvsuxdkw.supabase.co";
const ANON = process.env.SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJycnBrbXpkbmFvZG12c3V4ZGt3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njc2ODUyNzgsImV4cCI6MjA4MzI2MTI3OH0.J4kdDarCDVjkt0M9hbShgJaV7B12W56K_hUQAPSZ1-c";
const WORKER_URL = (process.env.WORKER_URL || "https://svcldb-solve.c-viperdevelopment.workers.dev").replace(/\/+$/, "");
const EMAIL = process.env.SMOKE_EMAIL || "svcldb-e2e@example.com";
const PASSWORD = process.env.SMOKE_PASSWORD || "TestPass123!xyz";

const j = (o) => JSON.stringify(o);

async function signIn() {
  const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: ANON, "Content-Type": "application/json" },
    body: j({ email: EMAIL, password: PASSWORD }),
  });
  const auth = await r.json();
  if (!r.ok || !auth.access_token) {
    console.error("sign-in FAILED:", r.status, j(auth));
    process.exit(2);
  }
  return auth.access_token;
}

async function main() {
  console.log("worker:", WORKER_URL);
  const jwt = await signIn();
  const H = { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" };
  console.log("  jwt len:", jwt.length);

  // 1) Legacy single-turn -- back-compat.
  console.log("\n[1/2] legacy single-turn (question + tier only)");
  {
    const body = {
      question: "What is 17 * 23? Reply with only the number.",
      tier: "cheap",
      explain: false,
    };
    const t0 = Date.now();
    const r = await fetch(`${WORKER_URL}/solve`, { method: "POST", headers: H, body: j(body) });
    const solved = await r.json();
    const dt = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`  status=${r.status} dt=${dt}s model=${solved.model} answer=${solved.answer} cost=${solved.cost}`);
    if (!solved.ok || !String(solved.answer || "").includes("391")) {
      console.error("  FAIL: legacy single-turn didn't return 391");
      process.exit(3);
    }
    console.log("  PASS: legacy single-turn returns 391");
  }

  // 2) Multi-turn -- follow-up question that requires remembering prior turn.
  console.log("\n[2/2] multi-turn: remembers 'my favorite number is 7'");
  {
    const body = {
      tier: "cheap",
      explain: false,
      messages: [
        { role: "user", content: [
          { type: "text", text: "Remember: my favorite number is 7 (seven)." }
        ] },
        { role: "assistant", content: "Got it. Your favorite number is 7." },
        { role: "user", content: [
          { type: "text", text: "Multiply my favorite number by 6. Reply with just the digits, no words." }
        ] },
      ],
    };
    const t0 = Date.now();
    const r = await fetch(`${WORKER_URL}/solve`, { method: "POST", headers: H, body: j(body) });
    const solved = await r.json();
    const dt = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`  status=${r.status} dt=${dt}s model=${solved.model} answer=${solved.answer} cost=${solved.cost}`);
    if (!solved.ok) {
      console.error("  FAIL: multi-turn request failed:", j(solved));
      process.exit(4);
    }
    const ans = String(solved.answer || "").trim();
    if (ans !== "42" && !ans.startsWith("42")) {
      console.error("  FAIL: expected 42 (7 * 6), got:", ans);
      process.exit(5);
    }
    console.log("  PASS: multi-turn preserved context (7 * 6 = 42)");
  }

  console.log("\nRESULT: PASS -- both single-turn back-compat AND multi-turn work.");
  process.exit(0);
}

main().catch((e) => { console.error("ERROR:", e?.stack || String(e)); process.exit(9); });
