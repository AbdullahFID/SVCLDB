// ============================================================================
// svcldb-solve — metered AI solve relay for svcldb (CloakGPT Windows overlay).
//
// SECURITY MODEL (front-most — unsubscribed/anonymous callers can't touch AI or spend):
//   1. Supabase JWT REQUIRED (verified server-side with the PUBLIC anon key).
//   2. ACTIVE subscription REQUIRED (checked via svc_solve_preflight).
//   3. Credits + concurrency gate via acquire_call_slot() (atomic).
//   4. AI call is relayed through viper's openrouter-proxy (which holds the funded
//      OpenRouter key) using a shared RELAY_SECRET — no OpenRouter key here.
//   5. Real usage cost deducted server-side via release_call_slot().
//
// NO service_role key: the credit RPCs are SECURITY DEFINER and self-verify a
// shared SVC_METERING_SECRET (same pattern as svcldb's vault_* RPCs), so the
// worker authenticates to Supabase with only the public anon key + that secret.
//
// The client's "bring your own API key" path stays LOCAL in the payload (direct
// to the provider) and is not part of this worker — it always works even if this
// backend is down / the user is unsubscribed. This worker is the METERED path.
//
// Vars (wrangler.toml [vars]):  SUPABASE_URL, SUPABASE_ANON_KEY, RELAY_URL
// Secrets (wrangler secret put): SVC_METERING_SECRET, RELAY_SECRET
// ============================================================================

import { createClient } from "@supabase/supabase-js";

// Metered-path models (OpenRouter slugs). The client sends a `tier`
// (strong|medium|cheap) and TIER_PRESETS maps it to a concrete model + reasoning
// effort, so all model choices live here and can be retuned without reshipping
// the payload. fable-5.1 / opus-5 / gemini-3.8-flash / grok stay allow-listed
// as alternates (reachable only if a caller sends an explicit `model`).
// NOTE: slugs here MUST exist on OpenRouter or the relay 502s (upstream 404).
// `x-ai/grok-4.1-fast` was never a real OpenRouter slug (the 4.x line is
// grok-4.3/4.5/4.6) — swapped to grok-4.6 so the alternate actually resolves.
// v-bump 2026-09-08: STRONG bumped gpt-5.6-sol -> gpt-6-astra (OpenAI flagship,
// 2026-09-04); added anthropic/claude-fable-5.1 (+ its opus-5 fallback) and
// google/gemini-3.8-flash to match the per-provider swaps in the payload.
// v-bump 2026-09-28: OpenAI shipped GPT-6 Sol + GPT-6 Luna (2026-09-22, per
// developers.openai.com/api/docs/models/gpt-6-sol|gpt-6-luna) -- 50% cheaper than
// the GPT-5.6 line and built on Astra. MEDIUM gpt-5.6-terra -> gpt-6-sol, CHEAP
// gpt-5.6-luna -> gpt-6-luna; STRONG stays gpt-6-astra (still the flagship).
// Anthropic alternate claude-opus-5 -> claude-opus-5.5 (Claude API id
// `claude-opus-5-5`, 2026-09-22; OpenRouter dot-form matches fable-5.1's).
const ALLOWED_MODELS = new Set([
  "openai/gpt-6-astra",             // STRONG / flagship (2026-09-04)
  "openai/gpt-6-sol",               // MEDIUM / balanced GPT-6 (2026-09-22, 50% cheaper than 5.6)
  "openai/gpt-6-luna",              // CHEAP / most efficient GPT-6 (2026-09-22)
  "anthropic/claude-fable-5.1",     // alternate (Anthropic frontier, 2026-09-01)
  "anthropic/claude-opus-5.5",      // alternate (Fable 5.1's fallback target, 2026-09-22)
  "google/gemini-3.8-flash",        // alternate (Google's most intelligent Flash, 2026-09-02)
  "x-ai/grok-4.6",                  // alternate (vision, fast)
]);

// Reasoning effort on the chat/completions path (what the relay uses). GPT-6
// Astra accepts none | low | medium | high | xhigh here; "max" is Responses-
// API-only and 400s through chat/completions, so xhigh is the ceiling.
const REASONING_EFFORTS = new Set(["none", "low", "medium", "high", "xhigh"]);

// Tier -> (model, reasoning effort). Strong is OpenAI's flagship at high effort;
// Medium/Cheap trade quality for credit-longevity + speed. Unknown/missing tier
// falls back to Strong so the managed path always errs toward best quality.
const TIER_PRESETS = {
  strong: { model: "openai/gpt-6-astra", reasoning_effort: "high"   },
  medium: { model: "openai/gpt-6-sol",   reasoning_effort: "medium" },
  cheap:  { model: "openai/gpt-6-luna",  reasoning_effort: "low"    },
};
const DEFAULT_TIER = "strong";

const MAX_IMAGES = 8;
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_QUESTION_CHARS = 8000;
// v7.4 (2026-09-25) -- multi-turn conversation memory. Caps for the
// optional `messages` array (payload sends the last ~5 chat turns +
// current question; each turn may carry up to a couple of images).
// These caps are intentionally generous compared to what the payload
// sends (24 hard cap, 12 default) so a rare 20-turn power-user chat
// still goes through. Anything over the cap is silently truncated to
// the newest entries so the tail (current question) is always kept.
const MAX_MESSAGES = 32;
const MAX_TOTAL_IMAGES_IN_HISTORY = 12;
// GPT-6 Astra's OUTPUT ceiling is 128K tokens (large ctx window ≠ output
// budget). We cap at that max so reasoning + answer never truncate. It's a
// CAP: normal exam answers spend a few hundred/thousand tokens and only those
// are billed; the ceiling only bites a pathological runaway.
const MAX_TOKENS = 128000;
// Only used if OpenRouter omits usage.cost. Astra at high effort runs pricier
// than the old gpt-5.x defaults, so keep the safety-net estimate realistic.
const COST_FALLBACK = 0.04;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type",
};
const JSON_HEADERS = { "Content-Type": "application/json", ...CORS };
const jsonRes = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });

// Verify the user JWT with the PUBLIC anon key (getUser hits /auth/v1/user).
function anonClient(env) {
  return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}
async function resolveUser(sb, token) {
  const { data, error } = await sb.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
}

function buildSystemPrompt(explain) {
  const base =
    "You are an expert exam-solving assistant. You are given a screenshot of one or more exam / quiz / homework questions (and optionally extra text from the user). Read the question(s) from the image and determine the correct answer.";
  const answerForm =
    " Give the ANSWER in the exact form the question needs: multiple-choice -> the correct option(s) (letter and text); true/false -> the correct value; matching -> each matched pair; ordering -> the items in the correct order; short-answer / fill-in-the-blank / numerical -> the concise answer; if it is an ESSAY question, answer as a SHORT answer (2-4 sentences max) - never write a full essay. If the image contains multiple questions, answer each one, labeled by its number.";
  const formatting =
    " Use Markdown, and write ALL mathematics in LaTeX - inline as \\( ... \\), display as \\[ ... \\]. Be precise and concise; do not restate the question or pad the answer.";
  const field = explain
    ? ' Put the final answer in the "answer" field and a brief (1-2 sentence) reasoning in the "explanation" field.'
    : ' Put the answer in the "answer" field; include NO explanation.';
  const shape =
    " Respond with ONLY a single JSON object - no preamble text and no markdown code fences.";
  return base + answerForm + formatting + field + shape;
}

function base64Bytes(dataUrl) {
  const comma = dataUrl.indexOf(",");
  const b64 = comma >= 0 ? dataUrl.slice(comma + 1) : dataUrl;
  return Math.ceil(b64.length * 0.75);
}

function extractAnswer(raw) {
  if (!raw) return { answer: "", explanation: "" };
  const tryParse = (s) => {
    try {
      const o = JSON.parse(s);
      if (o && typeof o === "object") return { answer: o.answer ?? "", explanation: o.explanation ?? "" };
    } catch {}
    return null;
  };
  let r = tryParse(raw);
  if (r) return r;
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  const candidate = (fenced ? fenced[1] : raw).trim();
  r = tryParse(candidate);
  if (r) return r;
  const m = candidate.match(/"answer"\s*:\s*"((?:[^"\\]|\\.)*)"/);
  if (m) {
    try { return { answer: JSON.parse(`"${m[1]}"`), explanation: "" }; }
    catch { return { answer: m[1], explanation: "" }; }
  }
  return { answer: candidate || raw, explanation: "" };
}

// Relay a raw OpenRouter chat/completions payload through viper's openrouter-proxy
// (which holds the funded OpenRouter key), via a SERVICE BINDING (direct
// worker-to-worker dispatch — same-account fetch over the public workers.dev URL
// does not route). The hostname in the Request is ignored by the binding.
async function relayToOpenRouter(env, payload) {
  const req = new Request("https://openrouter-proxy/__svc_relay", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Svc-Relay": env.RELAY_SECRET },
    body: JSON.stringify(payload),
  });
  return env.OPENROUTER_PROXY.fetch(req);
}

// ============================================================================
// Expired-JWT grace (2026-09-30) — root fix for "session expired mid-exam".
//
// The metered path needs a live Supabase JWT. Supabase issues 1-hour ES256
// (asymmetric) access tokens, so keeping one alive means the CLIENT has to
// reach Supabase's /auth/v1/token refresh endpoint roughly hourly. Inside a
// locked-down exam (SEB / LockDown Browser + a school firewall) that refresh
// is exactly what dies: the token ages past 1h, getUser() rejects it, and
// every /solve 401s with "Your session expired" even though the subscription
// is active and credits remain. Users confirmed the shape — worked on practice
// runs (fresh token), died in the real exam (aged out), phone data fixed it
// (bypassed the firewall so the refresh went through).
//
// This worker is always online, so it does what the exam machine can't: verify
// the token itself. When getUser() rejects a token we verify its signature
// against Supabase's PUBLIC JWKS (ES256 — no secret needed) and, if it is only
// EXPIRED by at most JWT_EXPIRED_GRACE_S, we trust its `sub` and continue.
// Authorization is UNCHANGED: svc_solve_preflight + acquire_call_slot still
// gate active-subscription + credits on that user for every call, so a
// grace-accepted token can only ever act as its own still-paying user. The
// grace widens identity assertion only, and only for a signed, recently-expired
// token — a forged / unsigned / never-valid token never passes.
// ============================================================================

const JWKS_TTL_MS = 10 * 60 * 1000;
let _jwksCache = null;               // { keys, fetchedAt }
const _verifyKeyCache = new Map();   // kid -> CryptoKey

function b64urlToBytes(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlToJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

async function fetchJwks(env, force = false) {
  const now = Date.now();
  if (!force && _jwksCache && now - _jwksCache.fetchedAt < JWKS_TTL_MS) return _jwksCache.keys;
  const res = await fetch(`${env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`, {
    headers: { apikey: env.SUPABASE_ANON_KEY || "" },
    cf: { cacheTtl: 600, cacheEverything: true },
  });
  if (!res.ok) {
    if (_jwksCache) return _jwksCache.keys;   // serve stale on a transient fetch blip
    throw new Error(`jwks_fetch_${res.status}`);
  }
  const data = await res.json().catch(() => ({}));
  const keys = Array.isArray(data.keys) ? data.keys : [];
  _jwksCache = { keys, fetchedAt: now };
  return keys;
}

async function getVerifyKey(env, kid) {
  if (_verifyKeyCache.has(kid)) return _verifyKeyCache.get(kid);
  let jwk = (await fetchJwks(env)).find((k) => k.kid === kid && k.kty === "EC");
  if (!jwk) jwk = (await fetchJwks(env, true)).find((k) => k.kid === kid && k.kty === "EC"); // key rotation
  if (!jwk || (jwk.alg && jwk.alg !== "ES256") || (jwk.crv && jwk.crv !== "P-256")) return null;
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  _verifyKeyCache.set(kid, key);
  return key;
}

// Pure decision: is `exp` (unix seconds) acceptable under the grace window?
// Accept if the token is expired by at most graceS. A valid, non-expired token
// normally passes getUser() and never reaches this path; if it lands here anyway
// (a transient worker->Supabase blip), we still accept it — the ECDSA signature
// check already proved authenticity, so the exp is authoritative. The only upper
// bound is a generous sanity cap (30 days) that sits well above Supabase's max
// jwt_exp (7 days), so it never rejects a legit token even if jwt_exp is raised.
function expWithinGrace(exp, nowS, graceS) {
  if (!Number.isFinite(exp)) return false;
  if (nowS - exp > graceS) return false;              // expired beyond the grace window
  if (exp - nowS > 30 * 24 * 3600) return false;      // absurd future exp -> distrust (sanity only)
  return true;
}

// Verify a Supabase user JWT locally against the JWKS and accept it iff the
// signature is valid, the claims are ours, and it is (at worst) expired within
// grace. Returns { sub, exp, expired } or null. `opts.getKey(kid)` is
// injectable for unit tests; production resolves against the live JWKS.
export async function verifyExpiredJwtWithinGrace(env, token, opts = {}) {
  const graceS = Number(env.JWT_EXPIRED_GRACE_S ?? 604800);   // default 7 days
  if (!(graceS > 0)) return null;
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  let header, payload;
  try { header = b64urlToJson(parts[0]); payload = b64urlToJson(parts[1]); }
  catch { return null; }
  if (header.alg !== "ES256" || !header.kid) return null;

  const getKey = opts.getKey || ((kid) => getVerifyKey(env, kid));
  const key = await getKey(header.kid);
  if (!key) return null;

  let sig;
  try { sig = b64urlToBytes(parts[2]); } catch { return null; }
  if (sig.length !== 64) return null;   // P-256 JWS signature is raw r||s (64 bytes)
  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  let ok = false;
  try { ok = await crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, key, sig, data); }
  catch { return null; }
  if (!ok) return null;

  if (payload.iss !== `${env.SUPABASE_URL}/auth/v1`) return null;
  if (payload.role !== "authenticated") return null;
  if (typeof payload.sub !== "string" || !payload.sub) return null;
  const nowS = Math.floor(Date.now() / 1000);
  if (!expWithinGrace(Number(payload.exp), nowS, graceS)) return null;

  return { sub: payload.sub, exp: Number(payload.exp), expired: nowS >= Number(payload.exp) };
}

// Exposed for unit tests (see tools/test-jwt-grace.mjs). Not used at runtime.
export const _authTestHooks = { b64urlToBytes, b64urlToJson, expWithinGrace };

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response("ok", { headers: CORS });

    for (const k of ["SUPABASE_URL", "SUPABASE_ANON_KEY", "SVC_METERING_SECRET", "RELAY_SECRET"]) {
      if (!env[k]) return jsonRes({ error: "server_misconfigured", missing: k }, 500);
    }
    if (!env.OPENROUTER_PROXY) return jsonRes({ error: "server_misconfigured", missing: "OPENROUTER_PROXY (service binding)" }, 500);

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const secret = env.SVC_METERING_SECRET;

    // Auth (all routes).
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (!token) return jsonRes({ error: "missing_authorization" }, 401);

    const sb = anonClient(env);
    let userId = null;
    const resolved = await resolveUser(sb, token);
    if (resolved) {
      userId = resolved.id;
    } else {
      // getUser() rejected the token. Before failing, accept a signed-but-
      // recently-EXPIRED token (the locked-down-exam refresh-death case): verify
      // it against Supabase's public JWKS and trust its `sub` if it is expired
      // by no more than the grace window. Authorization is unchanged — the
      // preflight + acquire RPCs below still gate active-sub + credits on this
      // user for every call.
      const claims = await verifyExpiredJwtWithinGrace(env, token).catch(() => null);
      if (!claims) return jsonRes({ error: "invalid_or_expired_token" }, 401);
      userId = claims.sub;
      console.log(`[auth] expired-jwt grace: sub=${userId} expired_by=${Math.max(0, Math.floor(Date.now() / 1000) - claims.exp)}s`);
    }

    // Preflight: active-sub + balance (secret-gated RPC, anon key).
    const { data: pf, error: pfErr } = await sb.rpc("svc_solve_preflight", {
      p_user_id: userId,
      p_secret: secret,
    });
    if (pfErr) return jsonRes({ error: "internal_error" }, 500);
    if (!pf || pf.active_sub !== true)
      return jsonRes({ error: "subscription_required", message: "An active svcldb subscription is required." }, 403);

    if (path === "/credits" || path === "/validate") {
      return jsonRes({ ok: true, plan: pf.plan, credits: Number(pf.credits ?? 0), pending_calls: Number(pf.pending_calls ?? 0) });
    }

    if (path !== "/solve" || request.method !== "POST")
      return jsonRes({ error: "not_found" }, 404);

    let body;
    try { body = await request.json(); } catch { return jsonRes({ error: "invalid_json" }, 400); }

    const question = typeof body.question === "string" ? body.question : "";
    const explain = body.explain === true;
    // v18-hotfix (2026-09-25) -- Optional caller-supplied system prompt.  Used by
    // svcldb's AutoSolver path to request the full solve schema
    // `{status, question, answer, answer_formatted, confidence, actions[...]}`
    // instead of this worker's default `{answer, explanation}`.  When present,
    // we forward it verbatim to OpenRouter AND drop the strict `json_schema`
    // response_format down to a plain `json_object` so the AI can include any
    // fields the caller's system prompt asked for (actions, coordinates, etc.)
    // Empty / missing `system` -> legacy behaviour (default prompt + strict
    // 2-field schema) for pre-v18 payloads.
    const customSystem = typeof body.system === "string" && body.system.trim().length > 0
      ? body.system.trim().slice(0, 32 * 1024)   // cap 32 KB — sane upper bound
      : null;

    // Tier preset selects model + effort; an explicit body.model / reasoning_effort
    // still overrides it (kept for flexibility). Unknown/missing tier -> Strong.
    const preset = TIER_PRESETS[body.tier] || TIER_PRESETS[DEFAULT_TIER];
    let model = typeof body.model === "string" && body.model.trim() ? body.model.trim() : preset.model;
    if (!ALLOWED_MODELS.has(model)) model = preset.model;
    const reasoningEffort = REASONING_EFFORTS.has(body.reasoning_effort) ? body.reasoning_effort : preset.reasoning_effort;

    let images = Array.isArray(body.images) ? body.images.filter((s) => typeof s === "string" && s.length > 0) : [];
    if (images.length > MAX_IMAGES) return jsonRes({ error: "too_many_images", max: MAX_IMAGES }, 400);
    // v2.0.2 (2026-09-10): SSRF hardening. The legit svcldb payload only
    // sends data:image/png;base64,... data URIs (see ai_provider.c). Before
    // this check, an authenticated client could smuggle http://internal-ip
    // or file:// URLs and OpenRouter would try to fetch them, which is at
    // best a policy break and at worst a probe of OpenRouter's internal
    // network. Reject anything that isn't a data:image/... URI, cheaply.
    for (const img of images) {
      if (!img.startsWith("data:image/"))
        return jsonRes({ error: "invalid_image_scheme", detail: "images must be data:image/... URIs" }, 400);
      if (base64Bytes(img) > MAX_IMAGE_BYTES) return jsonRes({ error: "image_too_large", max_bytes: MAX_IMAGE_BYTES }, 400);
    }
    if (question.length > MAX_QUESTION_CHARS) return jsonRes({ error: "question_too_long", max: MAX_QUESTION_CHARS }, 400);

    // v7.4 (2026-09-25) -- multi-turn conversation history. Payload sends
    // `messages: [{role, content}]` with alternating user/assistant turns
    // (last one = current question). We validate + normalize each turn's
    // shape and re-cap image counts + sizes for SSRF safety. If `messages`
    // is empty/absent we fall back to the legacy single-turn shape
    // (`question` + `images`).
    let historyMessages = Array.isArray(body.messages) ? body.messages : [];
    // Truncate to the tail if beyond cap (preserve the most recent, which
    // ends with the current question).
    if (historyMessages.length > MAX_MESSAGES) {
      historyMessages = historyMessages.slice(-MAX_MESSAGES);
    }
    let totalHistoryImages = 0;
    const validatedHistory = [];
    for (const m of historyMessages) {
      if (!m || typeof m !== "object") continue;
      const role = m.role === "assistant" ? "assistant" : "user";
      // Assistant content is a plain string (per OpenAI schema). We coerce
      // whatever the client sent to a string via JSON.stringify only when
      // it's an object; otherwise treat as text. Truncate to a sane cap
      // so a wild long assistant reply can't blow up the request body.
      if (role === "assistant") {
        let txt = "";
        if (typeof m.content === "string") txt = m.content;
        else if (m.content != null) txt = String(m.content);
        if (txt.length > MAX_QUESTION_CHARS * 4) txt = txt.slice(0, MAX_QUESTION_CHARS * 4);
        validatedHistory.push({ role, content: txt });
        continue;
      }
      // user role -- accept either { content: string } OR
      // { content: [{type,text}|{type,image_url,image_url:{url}}] }.
      // Normalize to the array form so we can splice more images cleanly
      // downstream.
      let parts = [];
      if (typeof m.content === "string") {
        if (m.content.length > MAX_QUESTION_CHARS) {
          return jsonRes({ error: "question_too_long", max: MAX_QUESTION_CHARS }, 400);
        }
        parts.push({ type: "text", text: m.content });
      } else if (Array.isArray(m.content)) {
        for (const p of m.content) {
          if (!p || typeof p !== "object") continue;
          if (p.type === "text") {
            let txt = typeof p.text === "string" ? p.text : String(p.text ?? "");
            if (txt.length > MAX_QUESTION_CHARS) {
              return jsonRes({ error: "question_too_long", max: MAX_QUESTION_CHARS }, 400);
            }
            parts.push({ type: "text", text: txt });
          } else if (p.type === "image_url") {
            const u = p.image_url && typeof p.image_url === "object" ? p.image_url.url : null;
            if (!u || typeof u !== "string") continue;
            if (!u.startsWith("data:image/")) {
              return jsonRes({ error: "invalid_image_scheme", detail: "history images must be data:image/... URIs" }, 400);
            }
            if (base64Bytes(u) > MAX_IMAGE_BYTES) {
              return jsonRes({ error: "image_too_large", max_bytes: MAX_IMAGE_BYTES }, 400);
            }
            if (totalHistoryImages >= MAX_TOTAL_IMAGES_IN_HISTORY) {
              // Silently drop extras -- prefer to complete the request
              // over 400ing on a slightly-too-verbose history. Log
              // via header response would be nice but we keep this
              // side-effect-free.
              continue;
            }
            totalHistoryImages++;
            parts.push({ type: "image_url", image_url: { url: u, detail: "high" } });
          }
        }
      } else {
        continue;   /* skip malformed */
      }
      if (parts.length === 0) continue;
      validatedHistory.push({ role, content: parts });
    }
    const hasHistory = validatedHistory.length > 0;

    if (!hasHistory && images.length === 0 && !question.trim()) {
      return jsonRes({ error: "no_image_or_question" }, 400);
    }

    // Acquire slot (atomic: active plan + credits>0 + concurrency<5).
    const { data: acquired, error: acqErr } = await sb.rpc("acquire_call_slot", {
      p_user_id: userId,
      p_secret: secret,
    });
    if (acqErr) return jsonRes({ error: "internal_error" }, 500);
    if (!acquired) {
      if (Number(pf.credits) <= 0)
        return jsonRes({ error: "no_credits", message: "No credits remaining. They replenish at the start of your next period." }, 403);
      if (Number(pf.pending_calls) >= 5)
        return jsonRes({ error: "too_many_concurrent", message: "Too many concurrent requests." }, 429);
      return jsonRes({ error: "request_denied" }, 403);
    }

    try {
      const userText =
        question.trim() ||
        "Answer the question(s) in this screenshot. If it is not a question, briefly describe what is shown.";

      // v18-hotfix (2026-09-25) -- Response-format ladder:
      //   customSystem present -> plain json_object (any JSON shape allowed)
      //   default              -> strict json_schema {answer,[explanation]} for OpenAI models
      //                           or json_object for non-OpenAI
      // The `customSystem` path assumes the caller's prompt already constrains
      // the model to a specific JSON shape (AutoSolver system prompt does).
      const schemaProps = explain ? { answer: { type: "string" }, explanation: { type: "string" } } : { answer: { type: "string" } };
      const response_format = customSystem
        ? { type: "json_object" }
        : (/^openai\//.test(model)
            ? { type: "json_schema", json_schema: { name: "svcldb_answer", strict: true, schema: { type: "object", additionalProperties: false, properties: schemaProps, required: explain ? ["answer", "explanation"] : ["answer"] } } }
            : { type: "json_object" });

      // v7.4 (2026-09-25) -- Multi-turn conversation history. When the
      // caller sent a `messages` array we forward it verbatim (already
      // validated + normalized above); otherwise fall back to the legacy
      // one-turn shape (question + images). All routes prepend the same
      // svcldb system prompt so JSON-schema response contract is honored.
      // v18-hotfix (2026-09-25) -- customSystem overrides the default prompt.
      const systemMsg = customSystem ? customSystem : buildSystemPrompt(explain);
      let orMessages;
      if (hasHistory) {
        // Verified against provider docs (2026-09-25):
        //   OpenAI    -- https://developers.openai.com/api/docs/guides/conversation-state
        //   OpenRouter -- https://openrouter.ai/docs/guides/overview/multimodal/image-understanding
        // Both accept alternating user/assistant turns with per-user-turn
        // content arrays for text + multi-image parts.
        orMessages = [
          { role: "system", content: systemMsg },
          ...validatedHistory,
        ];
      } else {
        const content =
          images.length > 0
            ? [{ type: "text", text: userText }, ...images.map((u) => ({ type: "image_url", image_url: { url: u, detail: "high" } }))]
            : userText;
        orMessages = [
          { role: "system", content: systemMsg },
          { role: "user", content },
        ];
      }

      const payload = {
        model,
        messages: orMessages,
        temperature: 0,
        max_tokens: MAX_TOKENS,
        response_format,
      };
      payload.reasoning = { effort: reasoningEffort };

      const orRes = await relayToOpenRouter(env, payload);
      if (!orRes.ok) {
        const errText = await orRes.text().catch(() => "");
        try { await sb.rpc("release_call_slot_no_cost", { p_user_id: userId, p_secret: secret }); } catch (_) {}
        return jsonRes({ error: "ai_upstream_failed", status: orRes.status, detail: errText.slice(0, 300) }, 502);
      }

      const ai = await orRes.json();
      const raw = ai.choices?.[0]?.message?.content?.trim() ?? "";
      // v18-hotfix (2026-09-25) -- If the caller sent a custom system prompt
      // it is defining its own JSON shape (AutoSolver: {status, question,
      // answer, answer_formatted, confidence, actions[]}). We must NOT strip
      // that down to the worker's default `{answer, explanation}` — the
      // caller needs the full JSON string verbatim to extract action
      // coordinates on the client side. Return `raw` in the `answer` field
      // (payload's ai_ask_metered re-parses it as JSON via strchr('{') +
      // json_skip_object, so the whole object flows through untouched).
      const { answer, explanation } = customSystem
        ? { answer: raw, explanation: "" }
        : extractAnswer(raw);

      const rawCost = typeof ai.usage?.cost === "number" ? ai.usage.cost : COST_FALLBACK;
      const cost = Math.max(0, rawCost);

      // v2.0.2 (2026-09-10): capture + handle the release_call_slot error.
      // supabase-js RETURNS errors on { error } instead of throwing, so the
      // pre-fix code silently swallowed RPC failures -- the caller got their
      // AI answer for FREE and the concurrency slot leaked (still counted
      // against the 5-concurrent cap until the next full slot reset).
      const { data: newCredits, error: relErr } = await sb.rpc("release_call_slot", {
        p_user_id: userId,
        p_cost: cost,
        p_secret: secret,
      });
      if (relErr) {
        console.error("[release_call_slot] rpc error:", relErr.message || String(relErr));
        // Best-effort: at least release the slot so we don't leak concurrency.
        try { await sb.rpc("release_call_slot_no_cost", { p_user_id: userId, p_secret: secret }); } catch (_) {}
        // Still return the answer to the user -- they consumed the AI call --
        // but flag the billing failure so ops can reconcile.
        return jsonRes({
          answer,
          explanation: explain ? explanation : undefined,
          model,
          cost,
          creditsRemaining: null,
          billing_error: true,
        });
      }

      return jsonRes({
        ok: true,
        answer,
        explanation: explain ? explanation : undefined,
        model,
        cost,
        creditsRemaining: Number(newCredits ?? 0),
      });
    } catch (e) {
      try { await sb.rpc("release_call_slot_no_cost", { p_user_id: userId, p_secret: secret }); } catch (_) {}
      return jsonRes({ error: "internal_error", detail: String(e?.message || e).slice(0, 200) }, 500);
    }
  },
};
