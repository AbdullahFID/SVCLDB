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
// the payload. gemini-3.1-pro / grok stay allow-listed as vision alternates
// (reachable only if a caller sends an explicit `model`).
// NOTE: slugs here MUST exist on OpenRouter or the relay 502s (upstream 404).
// `x-ai/grok-4.1-fast` was never a real OpenRouter slug (the 4.x line is
// grok-4.3/4.5/4.6) — swapped to grok-4.6 so the alternate actually resolves.
const ALLOWED_MODELS = new Set([
  "openai/gpt-5.6-sol",             // STRONG / flagship
  "openai/gpt-5.6-terra",           // MEDIUM / balanced (GPT-5.5-class, ~1/2 cost)
  "openai/gpt-5.6-luna",            // CHEAP / fast (~1/5 cost)
  "google/gemini-3.1-pro-preview",  // alternate (vision, frontier)
  "x-ai/grok-4.6",                  // alternate (vision, fast)
]);

// Reasoning effort on the chat/completions path (what the relay uses). GPT-5.6
// accepts none | low | medium | high | xhigh here; "max" is Responses-API-only
// and 400s through chat/completions, so xhigh is the ceiling.
const REASONING_EFFORTS = new Set(["none", "low", "medium", "high", "xhigh"]);

// Tier -> (model, reasoning effort). Strong is OpenAI's flagship at high effort;
// Medium/Cheap trade quality for credit-longevity + speed. Unknown/missing tier
// falls back to Strong so the managed path always errs toward best quality.
const TIER_PRESETS = {
  strong: { model: "openai/gpt-5.6-sol",   reasoning_effort: "high"   },
  medium: { model: "openai/gpt-5.6-terra", reasoning_effort: "medium" },
  cheap:  { model: "openai/gpt-5.6-luna",  reasoning_effort: "low"    },
};
const DEFAULT_TIER = "strong";

const MAX_IMAGES = 8;
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_QUESTION_CHARS = 8000;
// GPT-5.6 Sol's true OUTPUT ceiling is 128K tokens (1.05M ctx ≈ 922K in / 128K
// out) — NOT the 1.05M context window. We cap at that max so reasoning + answer
// never truncate. It's a CAP: normal exam answers spend a few hundred/thousand
// tokens and only those are billed; the ceiling only bites a pathological runaway.
const MAX_TOKENS = 128000;
// Only used if OpenRouter omits usage.cost. Sol at high effort runs pricier than
// the old gpt-5.4 default, so keep the safety-net estimate realistic.
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
    const user = await resolveUser(sb, token);
    if (!user) return jsonRes({ error: "invalid_or_expired_token" }, 401);

    // Preflight: active-sub + balance (secret-gated RPC, anon key).
    const { data: pf, error: pfErr } = await sb.rpc("svc_solve_preflight", {
      p_user_id: user.id,
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

    // Tier preset selects model + effort; an explicit body.model / reasoning_effort
    // still overrides it (kept for flexibility). Unknown/missing tier -> Strong.
    const preset = TIER_PRESETS[body.tier] || TIER_PRESETS[DEFAULT_TIER];
    let model = typeof body.model === "string" && body.model.trim() ? body.model.trim() : preset.model;
    if (!ALLOWED_MODELS.has(model)) model = preset.model;
    const reasoningEffort = REASONING_EFFORTS.has(body.reasoning_effort) ? body.reasoning_effort : preset.reasoning_effort;

    let images = Array.isArray(body.images) ? body.images.filter((s) => typeof s === "string" && s.length > 0) : [];
    if (images.length > MAX_IMAGES) return jsonRes({ error: "too_many_images", max: MAX_IMAGES }, 400);
    for (const img of images)
      if (base64Bytes(img) > MAX_IMAGE_BYTES) return jsonRes({ error: "image_too_large", max_bytes: MAX_IMAGE_BYTES }, 400);
    if (question.length > MAX_QUESTION_CHARS) return jsonRes({ error: "question_too_long", max: MAX_QUESTION_CHARS }, 400);
    if (images.length === 0 && !question.trim()) return jsonRes({ error: "no_image_or_question" }, 400);

    // Acquire slot (atomic: active plan + credits>0 + concurrency<5).
    const { data: acquired, error: acqErr } = await sb.rpc("acquire_call_slot", {
      p_user_id: user.id,
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
      const content =
        images.length > 0
          ? [{ type: "text", text: userText }, ...images.map((u) => ({ type: "image_url", image_url: { url: u } }))]
          : userText;

      const schemaProps = explain ? { answer: { type: "string" }, explanation: { type: "string" } } : { answer: { type: "string" } };
      const response_format = /^openai\//.test(model)
        ? { type: "json_schema", json_schema: { name: "svcldb_answer", strict: true, schema: { type: "object", additionalProperties: false, properties: schemaProps, required: explain ? ["answer", "explanation"] : ["answer"] } } }
        : { type: "json_object" };

      const payload = {
        model,
        messages: [
          { role: "system", content: buildSystemPrompt(explain) },
          { role: "user", content },
        ],
        temperature: 0,
        max_tokens: MAX_TOKENS,
        response_format,
      };
      payload.reasoning = { effort: reasoningEffort };

      const orRes = await relayToOpenRouter(env, payload);
      if (!orRes.ok) {
        const errText = await orRes.text().catch(() => "");
        try { await sb.rpc("release_call_slot_no_cost", { p_user_id: user.id, p_secret: secret }); } catch (_) {}
        return jsonRes({ error: "ai_upstream_failed", status: orRes.status, detail: errText.slice(0, 300) }, 502);
      }

      const ai = await orRes.json();
      const raw = ai.choices?.[0]?.message?.content?.trim() ?? "";
      const { answer, explanation } = extractAnswer(raw);

      const rawCost = typeof ai.usage?.cost === "number" ? ai.usage.cost : COST_FALLBACK;
      const cost = Math.max(0, rawCost);

      const { data: newCredits } = await sb.rpc("release_call_slot", {
        p_user_id: user.id,
        p_cost: cost,
        p_secret: secret,
      });

      return jsonRes({
        ok: true,
        answer,
        explanation: explain ? explanation : undefined,
        model,
        cost,
        creditsRemaining: Number(newCredits ?? 0),
      });
    } catch (e) {
      try { await sb.rpc("release_call_slot_no_cost", { p_user_id: user.id, p_secret: secret }); } catch (_) {}
      return jsonRes({ error: "internal_error", detail: String(e?.message || e).slice(0, 200) }, 500);
    }
  },
};
