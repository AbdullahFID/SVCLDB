# HANDOFF — svcldb AI Credits Backend (2026-08-12)

Metered AI for svcldb (CloakGPT Windows overlay): subscribers get a monthly $ of
real API credits, spend is metered per solve against a server-held OpenRouter key,
and credits auto-replenish. Recreated from the canvas-toolkit / NoLock design,
adapted to svcldb's own Supabase + subscription model, with a lifetime replenish
(which NoLock lacks), manual admin overrides, and a documented buy-extra-credits
contract.

**Status at handoff:**
- [x] Supabase migration applied to svcldb prod (`WindowsNotchGPT` / `rrrpkmzdnaodmvsuxdkw`) + verified; 45 active subs backfilled with credits.
- [x] `svcldb-solve` Cloudflare worker **DEPLOYED + LIVE**: `https://svcldb-solve.c-viperdevelopment.workers.dev` (viperdevelopment account).
- [x] **E2E verified**: unauth->401, no-sub->403, no-credits->403, valid->200 solve + real-cost deduction. All gates pass.
- [x] **No OpenRouter key or service_role key needed** — see architecture below.
- [ ] svcldb C client wiring (metered path + BYO-key fallback) — see §6.

**Architecture as built (important — differs from a naive design):**
- The worker does NOT hold an OpenRouter key. It relays the raw AI call through viper's
  existing `openrouter-proxy` (which already holds the funded key) via a **service binding**
  + a shared `RELAY_SECRET` (X-Svc-Relay header). A guarded relay branch was added to
  `openrouter-proxy` (early-return on the secret header; normal CanvasToolkit path is byte-identical).
- The worker does NOT use a `service_role` key. It talks to Supabase with the **public anon key**
  + a `SVC_METERING_SECRET` that the credit RPCs verify internally (same pattern as the `vault_*`
  RPCs). Metering integrity comes from the secret, not a privileged key.
- Test fixture (for re-testing): `svcldb-e2e@example.com` / `TestPass123!xyz` (weekly plan, active).

---

## 1. Pricing (edit in one place)

`public.svc_plan_allowance(plan)` returns the $/period allowance:

| plan | allowance | replenish cadence |
|---|---|---|
| weekly | $2.00 | every 7 days |
| monthly | $5.00 | every 30 days |
| lifetime | $5.00 | every 30 days |

Change amounts → edit `svc_plan_allowance`. Change cadence → edit `replenish_credits`.

Credits are **dollars of real OpenRouter usage cost**; each solve deducts the actual
`usage.cost` OpenRouter reports (fallback $0.02 if absent).

## 2. Supabase schema (project `rrrpkmzdnaodmvsuxdkw`)

New `profiles` columns: `credits`, `pending_calls (0..5)`, `slot_acquired_at`,
`total_usage`, `total_ai_billing_cycles`, `credits_refreshed_at`,
`purchased_credits`, `extended_access`.

New table `credit_purchases (id, user_id, amount, reference UNIQUE, created_at)` —
audit + idempotency for one-time credit purchases.

## 3. Functions (RPCs)

Metering (service-role only — revoked from anon/authenticated; only the worker calls these):
- `acquire_call_slot(p_user_id uuid) -> bool` — atomic gate: `pending_calls<5 AND credits>0 AND has-active-subscription`.
- `release_call_slot(p_user_id uuid, p_cost numeric) -> numeric` — `pending_calls-1`, deduct cost, return new balance.
- `release_call_slot_no_cost(p_user_id uuid)` — release without charging (AI failure).
- `sweep_stale_slots()` — reaps slots stuck >10 min (cron every minute).
- `replenish_credits()` — period top-up for active subs + lifetime (cron hourly at :17).

Grants / lifecycle:
- Trigger `trg_svc_grant_credits_on_activation` on `subscriptions` — grants the plan
  allowance immediately when a sub goes active or changes plan.
- `svc_plan_allowance(plan) -> numeric` — pricing table (see §1).

Admin overrides (service-role only) — the "manual way to do everything":
- `admin_set_credits(email, amount)` — set exact balance.
- `admin_add_credits(email, amount)` — add/subtract.
- `admin_replenish_user(email)` — force top-up to plan allowance now.

Client read (authenticated, own row): `get_my_credits() -> json {credits,total_usage,refreshed_at,pending_calls}`.

Crons (pg_cron): `svc_sweep_stale_slots` (`* * * * *`), `svc_replenish_credits` (`17 * * * *`).

## 4. Worker API — `svcldb-solve` (`cloudflare/svcldb-solve/`)

All routes require `Authorization: Bearer <supabase_user_jwt>` AND an active
subscription. Unsubscribed/anonymous callers get `401`/`403` before any AI/spend.

- `GET  /validate` → `{ ok, plan, credits }` (auth + sub, no spend).
- `GET  /credits`  → `{ ok, credits, total_usage, refreshed_at, plan }`.
- `POST /solve`    → body `{ images?: string[] (data URLs), question?: string, model?: string, reasoning_effort?: "low"|"medium"|"high", explain?: bool }`
  → `{ ok, answer, explanation?, model, cost, creditsRemaining }`.
  - Errors: `401 missing/invalid token`, `403 subscription_required | no_credits`, `429 too_many_concurrent`, `400 bad input`, `502 ai_upstream_failed`.
  - Allowed models (vision): `openai/gpt-5.4` (default), `google/gemini-3.1-pro-preview`, `x-ai/grok-4.1-fast`.
  - Caps: ≤8 images, ≤5 MB each, question ≤8000 chars, max_tokens 8000, temperature 0.
  - Prompt is built **server-side** (answer-form + LaTeX formatting from the canvas-toolkit solver) — updatable without reshipping the payload.

### Deploy
```
cd cloudflare/svcldb-solve
npm install
wrangler secret put OPENROUTER_KEY          # our OpenRouter key
wrangler secret put SUPABASE_SERVICE_KEY     # svcldb service_role key (Supabase dashboard > Settings > API)
wrangler deploy --account-id <ACCOUNT>
#   NotchGPT (own):        2e4382d85126a93661a4842d57f86398   <- recommended (Sam's own product)
#   viperdevelopment:      2e79ac0ed8bea87aca2c7ac4a9c336c6   <- partnership account (traffic-blend)
```
`SUPABASE_URL` is already set in `wrangler.toml [vars]`.

### Test (self-serve E2E)
```
SUPABASE_SERVICE_KEY=... WORKER_URL=https://svcldb-solve.<acct>.workers.dev node tools/test-solve.mjs
```
Creates a test user, grants weekly, mints a real JWT, runs /validate + /credits +
/solve, asserts credits decreased, cleans up.

## 5. FRONTEND CONTRACT (for the macOS Claude — billing/UI side)

You do NOT need to touch the C payload or the worker. Wire these:

1. **Show remaining credits** in the account/UI:
   - authenticated: `supabase.rpc('get_my_credits')` → `{credits, total_usage, refreshed_at}`, OR
   - `GET {WORKER_URL}/credits` with the user's JWT.

2. **Buy extra credits** (one-time top-up on top of the plan allowance):
   - Sell whatever pack you want (e.g. $5 → $5 credits, or mark up).
   - After a SUCCESSFUL payment, your billing backend (holding the **service_role** key) calls:
     ```
     select public.add_purchased_credits('<user_uuid>'::uuid, <dollars_numeric>, '<stripe_payment_intent_id>');
     ```
   - Idempotent on the 3rd arg (`reference`) — safe to retry webhooks; a repeat reference is a no-op and returns the current balance.
   - It adds on top of the current balance and bumps `profiles.purchased_credits` (audit).

3. **Subscription grant/reset** happens automatically:
   - Activation trigger grants the plan allowance the moment a `subscriptions` row goes active.
   - `replenish_credits` cron tops up each period (subs + lifetime).
   - You generally don't need to touch credits on renewal — but if your webhook wants to force it, call `admin_replenish_user(email)` (service role).

4. **Manual support ops** (service role): `admin_set_credits(email, amount)`,
   `admin_add_credits(email, amount)`, `admin_replenish_user(email)`.

## 6. svcldb client wiring (C payload) — see code

(Filled in once the payload wiring lands — metered path calls `POST {WORKER_URL}/solve`
with the user's Supabase JWT; the existing user-own-API-key path is retained as a
local fallback that always works even if this backend is down / user unsubscribed.)

## 7. Secrets (all resolved — worker is live)

Deployed worker `svcldb-solve` secrets (set via `wrangler secret put`, account viperdevelopment):
- `SVC_METERING_SECRET` — gates the credit RPCs; sha256 hash stored in `public.svc_config` (key `metering_secret`).
- `RELAY_SECRET` — matches `SVC_RELAY_SECRET` on `openrouter-proxy` for the relay branch.

`openrouter-proxy` gained one secret: `SVC_RELAY_SECRET` (same value as svcldb-solve's `RELAY_SECRET`).

Plaintext values are in `cloudflare/svcldb-solve/.dev.vars` (gitignored). No OpenRouter key and no
Supabase service_role key are needed anywhere in this stack.
