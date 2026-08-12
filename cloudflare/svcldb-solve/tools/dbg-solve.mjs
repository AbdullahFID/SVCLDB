const URL_ = "https://rrrpkmzdnaodmvsuxdkw.supabase.co";
const ANON = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJycnBrbXpkbmFvZG12c3V4ZGt3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njc2ODUyNzgsImV4cCI6MjA4MzI2MTI3OH0.J4kdDarCDVjkt0M9hbShgJaV7B12W56K_hUQAPSZ1-c";
const WORKER = "https://svcldb-solve.c-viperdevelopment.workers.dev";
const s = await fetch(`${URL_}/auth/v1/token?grant_type=password`, { method: "POST", headers: { apikey: ANON, "content-type": "application/json" }, body: JSON.stringify({ email: "svcldb-e2e@example.com", password: "TestPass123!xyz" }) });
const jwt = (await s.json()).access_token;
const r = await fetch(`${WORKER}/solve`, { method: "POST", headers: { Authorization: `Bearer ${jwt}`, "content-type": "application/json" }, body: JSON.stringify({ question: "What is 17 * 23? Reply with only the number." }) });
console.log("status", r.status);
console.log("ct", r.headers.get("content-type"));
console.log("body:", (await r.text()).slice(0, 1500));
