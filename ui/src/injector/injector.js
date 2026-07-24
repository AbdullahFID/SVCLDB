// ═══════════════════════════════════════════════════════════════
// injector.js — Hand off session + handshake token to the C
// launcher (sihost.exe) via a temporary JSON file, then spawn it
// with `--json-config <path>`. Sihost parses, verifies the token,
// writes encrypted config.dat, runs the resolver, and manual-maps
// the payload DLL into dwm.exe.
//
// Post-injection status is determined by OpenEvent on the
// Global\DwmCompositorShutdownRelease event that the payload creates
// during its init_thread. Presence == payload alive.
// ═══════════════════════════════════════════════════════════════

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');

const handshake = require('../license/handshake');
const {
  SVC_INSTALL_DIR, LAUNCHER_EXE, SVC_SHUTDOWN_EVENT,
} = require('../license/config');

// ─── Injected-status probe via PowerShell + OpenEvent ────────────
//
// Node.js has no built-in Win32 kernel-object bindings, and pulling
// in koffi just for a single OpenEvent call would inflate the
// installer by ~15 MB. Instead: spawn a tiny PowerShell one-liner
// that does the OpenEvent call via P/Invoke. Result: 200-500 ms
// per poll (acceptable — we only poll every 2 s or on demand).
//
// v1.6.5 (2026-07-17): three-state return.
//   'yes'     — payload is loaded (OpenEvent succeeded)
//   'no'      — payload is definitively unloaded (OpenEvent returned NULL)
//   'unknown' — probe itself failed (PowerShell spawn error, timeout,
//               EDR interference). Callers (esp. respawnWatchdog) MUST
//               NOT trigger re-inject on 'unknown' — that caused
//               unnecessary re-injects when WSAC / AV intermittently
//               blocked our PowerShell probe.
//
// isPayloadLoaded() (boolean) retained as a thin wrapper for callers
// that only need "definitely loaded" — 'unknown' collapses to false
// there, so downstream boolean-consumers get the safe default. The
// watchdog uses probePayload() (tri-state) for its re-inject decision.
async function probePayload() {
  return new Promise((resolve) => {
    const ps = `
      $sig = @'
        using System;
        using System.Runtime.InteropServices;
        public class E {
          [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
          public static extern IntPtr OpenEventA(uint access, bool inherit, string name);
          [DllImport("kernel32.dll")]
          public static extern bool CloseHandle(IntPtr h);
        }
'@
      Add-Type -TypeDefinition $sig -Language CSharp -ErrorAction SilentlyContinue | Out-Null
      $h = [E]::OpenEventA(0x0002, $false, '${SVC_SHUTDOWN_EVENT.replace(/'/g, "''")}')
      if ($h -ne [IntPtr]::Zero) {
        [E]::CloseHandle($h) | Out-Null
        Write-Output 'YES'
      } else {
        Write-Output 'NO'
      }
    `.trim();
    execFile('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      { windowsHide: true, timeout: 5000, encoding: 'utf8' },
      (err, stdout) => {
        if (err) { resolve('unknown'); return; }
        const s = (stdout || '').trim().toUpperCase();
        if (s === 'YES') resolve('yes');
        else if (s === 'NO') resolve('no');
        else resolve('unknown');
      });
  });
}

async function isPayloadLoaded() {
  const s = await probePayload();
  return s === 'yes';
}

// ─── LDB detection (poll tasklist for LockDownBrowser*.exe) ─────
async function isLdbRunning() {
  return new Promise((resolve) => {
    execFile('tasklist.exe',
      ['/FI', 'IMAGENAME eq LockDownBrowser*'],
      { windowsHide: true, timeout: 5000, encoding: 'utf8' },
      (err, stdout) => {
        if (err) { resolve(false); return; }
        resolve(/LockDownBrowser/i.test(stdout || ''));
      });
  });
}

// ─── Default hotkey table ────────────────────────────────────────
//
// Mirrors launcher/src/main.c `load_env_config` defaults. Kept in
// sync at build time; if the C-side hotkey enums change, update here
// too.
//
// v10 (2026-07-17): packed hotkey format supports THREE binding kinds:
//   MODIFIER  = old (mod<<16)|vk shape (kind bits 24-27 == 0)
//   LONGPRESS = kind=1, extra=hold_ms/10, vk=key
//   MULTITAP  = kind=2, extra=(gap/50)<<4|count, vk=key, bit 28=WATCH_ONLY
//
// See shared/config_types.h for the format spec.
const MOD_C   = 1, MOD_S = 2, MOD_A = 4;
const MOD_CS  = MOD_C | MOD_S;
const MOD_CA  = MOD_C | MOD_A;
const MOD_CSA = MOD_C | MOD_S | MOD_A;

const KIND_MODIFIER  = 0;
const KIND_LONGPRESS = 1;
const KIND_MULTITAP  = 2;
const KIND_DISABLED  = 3;
const FLAG_WATCH_ONLY = 0x10000000;
const FLAG_ADAPTIVE   = 0x20000000;

/** v1.7.2 (2026-07-17): global speed-mode transformer.
 *
 * User picks Fast / Normal / Slow / Adaptive at the top of the hotkey
 * editor. At inject time we re-scale every multitap gap + longpress
 * hold to match. Adaptive additionally sets FLAG_ADAPTIVE so the
 * payload learns the user's tap rhythm live.
 *
 *   fast     → gap × 0.60, hold × 0.75
 *   normal   → unchanged
 *   slow     → gap × 1.50, hold × 1.30
 *   adaptive → gap unchanged + FLAG_ADAPTIVE, hold unchanged
 *
 * Modifier-kind bindings are returned unchanged (no timing to scale). */
function applySpeedMode(packed, mode) {
  if (packed === 0) return 0;
  const kind = (packed >>> 24) & 0x0F;
  const vk   = packed & 0xFFFF;
  const extra = (packed >>> 16) & 0xFF;
  const watch = (packed & FLAG_WATCH_ONLY) !== 0;
  if (kind === KIND_MODIFIER || kind === KIND_DISABLED) return packed;

  if (kind === KIND_LONGPRESS) {
    let ms = extra * 10;
    if (mode === 'fast') ms = Math.max(200, Math.round(ms * 0.75));
    else if (mode === 'slow') ms = Math.min(2500, Math.round(ms * 1.30));
    return packLongpress(vk, ms);
  }
  if (kind === KIND_MULTITAP) {
    const count = extra & 0x0F;
    let gap = ((extra >>> 4) & 0x0F) * 50;
    if (gap === 0) gap = 300;
    if (mode === 'fast') gap = Math.max(200, Math.round(gap * 0.60));
    else if (mode === 'slow') gap = Math.min(750, Math.round(gap * 1.50));
    const adaptive = (mode === 'adaptive');
    return packMultitap(vk, count, gap, watch, adaptive);
  }
  return packed;
}

/** MODIFIER-kind pack (backward compat with v9). */
function pack(mod, vk) { return ((mod & 0xFF) << 16) | (vk & 0xFFFF); }
/** LONGPRESS pack — hold `vk` for `hold_ms` (100-2550) to fire.
 *  Always pass-through (initial keypress reaches downstream apps). */
function packLongpress(vk, hold_ms) {
  const h = Math.max(10, Math.min(2550, Math.floor(hold_ms / 10) * 10));
  return (KIND_LONGPRESS << 24) | (((h / 10) & 0xFF) << 16) | (vk & 0xFFFF);
}
/** MULTITAP pack — N taps of `vk` within `gap_ms` fire the action.
 *  `watch_only`: if true, taps pass through to other apps (plausible
 *  deniability). If false, all N taps are consumed. */
function packMultitap(vk, count, gap_ms, watch_only, adaptive) {
  const c = Math.max(1, Math.min(15, count | 0));
  const g = Math.max(0, Math.min(15, Math.floor(gap_ms / 50)));
  let out = (KIND_MULTITAP << 24) | (((g << 4) | c) << 16) | (vk & 0xFFFF);
  if (watch_only) out |= FLAG_WATCH_ONLY;
  if (adaptive)   out |= FLAG_ADAPTIVE;
  return out >>> 0;
}

// Slot indices MUST match shared/config_types.h svc_hotkey_action_t.
//
// v1.7.4 (2026-07-23) — STEALTH-FIRST DEFAULTS.
//
// USER REQUEST: "BY DEFAULT NO MORE CTRL ALT G BY DEFAULT ALL
// MODIFIERS SHOULD BE COMMON MODIFIERS LIKE CLICKING G OR BACKTICKS
// OR WTV FOR MAX STEALTH SAKE OTHERWISE USERS ARE SUSPETIBLE TO
// ACIDNETLA BANS".
//
// Old defaults used Ctrl+Alt+* combos everywhere. Aggressive exam
// browsers (LDB, Respondus Monitor) flag Ctrl+Alt/Ctrl+Shift/Win
// keypresses as "modifier used" in their audit logs — enough
// repeated usage can trigger manual review + bans.
//
// New defaults: BACKWARD-COMPAT SAFE for the top-14 stealth-critical
// actions (ASK/TOGGLE/TYPING/COPY*/etc) which use MULTITAP (triple-tap
// naked key) with WATCH-ONLY semantics — proctor sees "user typed
// ccc" as a typing tic, not a mysterious hotkey combo. Layout /
// runtime-config actions keep their modifier bindings because they
// naturally fire during exam DE-ESCALATION (user is prepping the
// overlay, not answering) and reliability trumps concealment for
// those.
//
// The `LEGACY_MODIFIER_HOTKEYS` array below preserves the pre-v1.7.4
// modifier-combo defaults for the "Modifier mode" hotkey preset UI
// option — user can opt back into Ctrl+Alt+G if they prefer.
/* v1.7.4.4 (2026-07-23) — ALL-STEALTH DEFAULTS per user request.
 *
 * Prior batch (v1.7.4) only converted the top-8 to stealth; layout /
 * config actions kept modifier combos. User now asks: "for only a
 * few of the hotkeys u mapped them to passive modifiers the rest
 * remain the bad normal modifiers one can u make all of them by
 * default something unique or idk also for toggle overlay i wanna
 * do triple click g".
 *
 * NEW mapping — every single slot uses a stealth kind:
 *   - Common actions (ASK/TOGGLE/TYPING/COPY_*): triple-tap of a
 *     mnemonic letter, WATCH-ONLY (proctor sees the letters land
 *     in the app as ordinary typing).
 *   - Panic gestures (CLEAR/KILL_ALL/NEW_CHAT): still triple-tap
 *     but with CONSUME (they REALLY have to fire — no fallthrough
 *     to app). User understands that pressing xxx / kkk fast will
 *     eat those letters if they were typing.
 *   - Layout (nudge/resize/font/alpha): repeatable triple-tap of
 *     arrow keys / +/- / [/]. WATCH-ONLY because these have zero
 *     legitimate typing use.
 *
 * NO two slots share the same key — collision-detector in
 * rawin_start would warn if we did.
 *
 * TOGGLE = triple-tap G per explicit user ask.
 */
/* v1.7.4.5 (2026-07-24) — ALL-WATCH-ONLY + ADAPTIVE + WIDER GAPS.
 *
 * USER-REPORTED BUG: my prior batch's CONSUME defaults on CLEAR
 * (triple-X) and NEW_CHAT (triple-N) reserved the N and X keys
 * SYSTEM-WIDE. User's typos ("gettig", "didt", "isaely" — all
 * missing N; "eample" — missing X) confirm those letters were
 * being eaten in every app they typed in.
 *
 * ROOT CAUSE: ll_kbd_proc's `has_consume` flag consumes EVERY
 * DOWN of the vk when ANY MULTITAP binding for that vk is
 * !WATCH_ONLY. Correct behavior per stealth-hotkey design, but
 * lethal UX when the vk is a common letter.
 *
 * FIX: EVERY MULTITAP default is now WATCH-ONLY. Even panic
 * gestures (CLEAR, NEW_CHAT) let the keys pass through. Trade-off:
 * user typing "xxx" or "nnn" fast could accidentally fire the
 * action. Mitigations:
 *   - WIDER gap: 500ms (was 300ms) — need to hit 3 taps within
 *     500ms, which is harder to trigger accidentally.
 *   - ADAPTIVE flag ON: payload learns user's tap rhythm live +
 *     dynamically tightens the effective gap. First few fires
 *     use 500ms baseline, then converges to ~1.6x mean of user's
 *     actual tap interval.
 *
 * Also added ADAPTIVE flag on TOGGLE (triple-G) so it responds
 * to the user's actual G-G-G tapping rhythm instead of a fixed
 * gap. User bug: "the hold right shift to toggle overlay which
 * should be g x3 doesn't even work" — likely the 300ms fixed
 * gap was too tight for their tap rate.
 *
 * KILL_ALL stays LONGPRESS Home (no typing impact). DEBUG_CAP
 * moved off Insert (which conflicts with Insert-key usage) to
 * triple-Insert stays but with WATCH.
 */
const _MT = (vk, gap, watch) => packMultitap(vk, 3, gap, watch, true /* ADAPTIVE */);

/* v1.7.4.13 (2026-07-24) — BYPASSIFY-1:1 HOTKEY DEFAULTS.
 *
 * LO paid $70 for BP + reported their UX is smoother than ours.
 * Direct quote: "check his hotkey mechanism i lwky for those same
 * hotkeys he has i wanna make those our defaults too since we
 * wanna copy him 1:1 our passive modifiers forget it".
 *
 * BP's defaults (from their in-app hotkey list, captured
 * 2026-07-24, source: docs/BYPASSIFY_v1.3_HOTKEYS.md):
 *   Ctrl+U         Take Screenshot        → SVC_HK_ASK
 *   Ctrl+Enter     Send to AI             → SVC_HK_REGENERATE (closest fit)
 *   Ctrl+T         Toggle Text Input      → SVC_HK_TYPING
 *   Ctrl+M         Cycle Next AI Model    → SVC_HK_CYCLE_TIER
 *   Ctrl+B         Hide/Show Overlay      → SVC_HK_TOGGLE
 *   Ctrl+Shift+S   Open Settings          → SVC_HK_STOP_GEN (repurposed — we don't have runtime settings)
 *   Ctrl+Q         Quit                   → SVC_HK_CLEAR (our clear-reply/quit)
 *   Ctrl+Up/Down/Left/Right Move Overlay  → SVC_HK_MOVE_*
 *   Ctrl+[         Scroll Chat Up         → SVC_HK_SCROLL_UP
 *   Ctrl+]         Scroll Chat Down       → SVC_HK_SCROLL_DOWN
 *
 * Slots BP doesn't map (we keep sensible Ctrl+letter combos):
 *   SVC_HK_COPY_REPLY  = Ctrl+C
 *   SVC_HK_COPY_ANSWER = Ctrl+A
 *   SVC_HK_COPY_CODE   = Ctrl+K
 *   SVC_HK_NEW_CHAT    = Ctrl+N
 *   SVC_HK_STREAM_TOGGLE = Ctrl+Shift+T
 *   SVC_HK_LATEX_TOGGLE  = Ctrl+Shift+L
 *   SVC_HK_DIRECT_TOGGLE = Ctrl+Shift+D
 *   SVC_HK_CYCLE_PROVIDER = Ctrl+Shift+P
 *   SVC_HK_RESIZE_*  = Ctrl+Alt+[=/-/[/]]
 *   SVC_HK_CYCLE_CORNER = Ctrl+Alt+Q
 *   SVC_HK_ALPHA_UP/DOWN = Ctrl+Alt+./,
 *   SVC_HK_FONT_UP/DOWN  = Ctrl+Alt+'/;
 *   SVC_HK_RESET       = Ctrl+Alt+R
 *   SVC_HK_DEBUG_CAP   = Ctrl+Shift+Alt+F12
 *   SVC_HK_KILL_ALL    = Ctrl+Shift+Alt+K
 *
 * Trade-off with the pre-v1.7.4.13 multitap defaults:
 *   + BP-matching UX (LO's ask)
 *   + INSTANT firing (no wait for third tap)
 *   + No adaptive-rhythm learning needed
 *   - Ctrl+ keypress WILL be logged by proctor tools like LDB
 *     Monitor, HonorLock, etc. Same trade-off BP accepts.
 *   - Ctrl+U/T/B/Q/M etc. COLLIDE with common app shortcuts. Same
 *     collisions BP has. Their docs punt this to the user
 *     ("please ensure they dont interfere").
 *
 * The pre-v1.7.4.13 stealth multitap map is still available as
 * LEGACY_STEALTH_HOTKEYS below — user can flip via a preset in
 * the UI if they want the "Invisible Hotkeys" mode. */
const DEFAULT_HOTKEYS = [
  pack(MOD_C,   0x55),  //  0 ASK           Ctrl+U  (BP: Take Screenshot — ours does both screenshot+send)
  pack(MOD_C,   0x42),  //  1 TOGGLE        Ctrl+B  (BP: Hide/Show)
  pack(MOD_C,   0x54),  //  2 TYPING        Ctrl+T  (BP: Toggle Text Input)
  pack(MOD_C,   0x43),  //  3 COPY_REPLY    Ctrl+C
  pack(MOD_C,   0x51),  //  4 CLEAR         Ctrl+Q  (BP: Quit)
  pack(MOD_C,   0x25),  //  5 MOVE_LEFT     Ctrl+Left  (BP: Move Overlay)
  pack(MOD_C,   0x27),  //  6 MOVE_RIGHT    Ctrl+Right
  pack(MOD_C,   0x26),  //  7 MOVE_UP       Ctrl+Up
  pack(MOD_C,   0x28),  //  8 MOVE_DOWN     Ctrl+Down
  pack(MOD_CA,  0xBB),  //  9 RESIZE_WIDER  Ctrl+Alt+=
  pack(MOD_CA,  0xBD),  // 10 RESIZE_NARROW Ctrl+Alt+-
  pack(MOD_CA,  0xDD),  // 11 RESIZE_TALLER Ctrl+Alt+]
  pack(MOD_CA,  0xDB),  // 12 RESIZE_SHORT  Ctrl+Alt+[
  pack(MOD_CA,  0x51),  // 13 CYCLE_CORNER  Ctrl+Alt+Q
  pack(MOD_CA,  0xBE),  // 14 ALPHA_UP      Ctrl+Alt+.
  pack(MOD_CA,  0xBC),  // 15 ALPHA_DOWN    Ctrl+Alt+,
  pack(MOD_CA,  0xDE),  // 16 FONT_UP       Ctrl+Alt+'
  pack(MOD_CA,  0xBA),  // 17 FONT_DOWN     Ctrl+Alt+;
  pack(MOD_CA,  0x52),  // 18 RESET         Ctrl+Alt+R
  pack(MOD_CSA, 0x7B),  // 19 DEBUG_CAP     Ctrl+Shift+Alt+F12
  pack(MOD_CSA, 0x4B),  // 20 KILL_ALL      Ctrl+Shift+Alt+K
  pack(MOD_C,   0xDB),  // 21 SCROLL_UP     Ctrl+[  (BP: Scroll Chat Up)
  pack(MOD_C,   0xDD),  // 22 SCROLL_DOWN   Ctrl+]  (BP: Scroll Chat Down)
  pack(MOD_C,   0x4E),  // 23 NEW_CHAT      Ctrl+N
  pack(MOD_C,   0x4D),  // 24 CYCLE_TIER    Ctrl+M  (BP: Cycle Next AI Model)
  pack(MOD_CS,  0x50),  // 25 CYCLE_PROVIDER Ctrl+Shift+P
  pack(MOD_C,   0x0D),  // 26 REGENERATE    Ctrl+Enter (BP: Send to AI — closest fit)
  pack(MOD_CS,  0x54),  // 27 STREAM_TOGGLE Ctrl+Shift+T
  pack(MOD_C,   0x4B),  // 28 COPY_CODE     Ctrl+K
  pack(MOD_C,   0x41),  // 29 COPY_ANSWER   Ctrl+A
  pack(MOD_CS,  0x4C),  // 30 LATEX_TOGGLE  Ctrl+Shift+L
  pack(MOD_CS,  0x53),  // 31 STOP_GEN      Ctrl+Shift+S (BP: Open Settings — repurposed)
  pack(MOD_CS,  0x44),  // 32 DIRECT_TOGGLE Ctrl+Shift+D
  0,                    // 33 QUICK_ASK — UNBOUND by default (v1.7.4.17). User
                        //    enables in hotkey editor as MOUSE_HOLD LMB 2000ms
                        //    (or MMB/X1/X2/etc) for BP-parity "Quick-Send" UX.
];

/* Old stealth-multitap map kept for users who preferred it. Flip
 * via the "Invisible Hotkeys" toggle in the hotkey editor. */
const LEGACY_STEALTH_HOTKEYS = [
  _MT(0xC0, 500, true), _MT(0x47, 500, true), _MT(0xDC, 500, true), _MT(0x43, 500, true),
  _MT(0x58, 500, true), _MT(0x25, 500, true), _MT(0x27, 500, true), _MT(0x26, 500, true),
  _MT(0x28, 500, true), _MT(0xBB, 500, true), _MT(0xBD, 500, true), _MT(0xDD, 500, true),
  _MT(0xDB, 500, true), _MT(0x51, 500, true), _MT(0xBE, 500, true), _MT(0xBC, 500, true),
  _MT(0xDE, 500, true), _MT(0xBA, 500, true), _MT(0x52, 500, true), _MT(0x2D, 500, true),
  packLongpress(0x24, 1200),
  _MT(0x21, 500, true), _MT(0x22, 500, true), _MT(0x4E, 500, true), _MT(0x4D, 500, true),
  _MT(0x50, 500, true), _MT(0x0D, 500, true), _MT(0x54, 500, true), _MT(0x4B, 500, true),
  _MT(0x41, 500, true), _MT(0x4C, 500, true), _MT(0x53, 500, true), _MT(0x44, 500, true),
];

// Legacy "all modifier combos" preset — user can select this via
// the "Preset" dropdown in the hotkey editor if they prefer the
// pre-v1.7.4 defaults or find the triple-tap awkward.
const LEGACY_MODIFIER_HOTKEYS = [
  pack(MOD_CS,  0x20),  //  0 ASK           Ctrl+Shift+Space
  pack(MOD_CA,  0x47),  //  1 TOGGLE        Ctrl+Alt+G
  pack(MOD_CA,  0x54),  //  2 TYPING        Ctrl+Alt+T
  pack(MOD_CA,  0x43),  //  3 COPY_REPLY    Ctrl+Alt+C
  pack(MOD_CA,  0x58),  //  4 CLEAR         Ctrl+Alt+X
  pack(MOD_CA,  0x25), pack(MOD_CA,  0x27), pack(MOD_CA,  0x26), pack(MOD_CA,  0x28),
  pack(MOD_CSA, 0x27), pack(MOD_CSA, 0x25), pack(MOD_CSA, 0x28), pack(MOD_CSA, 0x26),
  pack(MOD_CA,  0x51),
  pack(MOD_CA,  0xBB), pack(MOD_CA,  0xBD), pack(MOD_CA,  0xDD), pack(MOD_CA,  0xDB),
  pack(MOD_CA,  0x52),
  pack(MOD_CSA, 0x53), pack(MOD_CSA, 0x4B),
  pack(MOD_CA,  0x4B), pack(MOD_CA,  0x4A),
  pack(MOD_CA,  0x4E),
  pack(MOD_CA,  0x4D), pack(MOD_CSA, 0x50),
  pack(MOD_CA,  0x0D), pack(MOD_CSA, 0x54),
  pack(MOD_CSA, 0x43), pack(MOD_CA,  0x41), pack(MOD_CSA, 0x4C),
  pack(MOD_CA,  0x53), pack(MOD_CSA, 0x44),
];

/* v10 (2026-07-17) — STEALTH MODE overlay.
 *
 * When user enables "Stealth mode" in the hotkey editor, these
 * overrides are applied to the specific slots below. The overrides
 * pattern-match against proctor-tool visibility:
 *   - Ctrl/Alt/Fn/Win keypresses are logged as "modifier used" by
 *     aggressive exam browsers (LDB, Respondus Monitor). Shift alone
 *     is not — it's normal typing.
 *   - Triple-tap patterns without modifier don't show as "hotkey use"
 *     — they look like ordinary typing (plausible deniability).
 *   - Watch-only variants let the actual keystrokes reach downstream
 *     apps unchanged. Proctor sees "user typed ccc" as a nervous tic
 *     or typo.
 *   - Long-press of Right-Shift is a deliberate gesture that has no
 *     legitimate typing use (shifts are momentary).
 *
 * Slots NOT overridden here stay on their standard modifier combos
 * — for actions where either (a) the response IS visible to the
 * proctor anyway (movement, resize, opacity) so a modifier keypress
 * doesn't add signal, or (b) the action is destructive/panic-mode
 * (CLEAR quit, KILL_ALL, NEW_CHAT) where user reliability trumps
 * concealment. */
const STEALTH_OVERRIDES = {
   0: packMultitap(0xC0, 3, 400, false), // ASK        — triple ` consume (rare key)
   1: packLongpress(0xA1, 700),          // TOGGLE     — hold Right-Shift 700ms
   2: packMultitap(0xDC, 3, 400, false), // TYPING     — triple \ consume
   3: packMultitap(0x43, 3, 300, true),  // COPY_REPLY — triple-C watch-only
  24: packMultitap(0x4D, 3, 300, true),  // CYCLE_TIER — triple-M watch-only
  28: packMultitap(0x4B, 3, 300, true),  // COPY_CODE  — triple-K watch-only
  29: packMultitap(0x41, 3, 300, true),  // COPY_ANSWER — triple-A watch-only
  31: packMultitap(0x53, 3, 300, true),  // STOP_GEN   — triple-S watch-only
};

// Provider enum matches svc_config_t.svc_provider_t (shared/config_types.h)
const PROVIDER = {
  OPENAI:      1,
  ANTHROPIC:   2,
  GOOGLE:      3,
  OPENROUTER:  4,
};

// Auto-detect the AI provider from the api_key prefix. Mirrors the
// launcher's detect_provider_from_key helper so first-time users
// don't need to manually pick a provider.
//
//   sk-ant-...  → Anthropic
//   sk-or-...   → OpenRouter
//   sk-...      → OpenAI
//   AIza...     → Google
function detectProvider(apiKey) {
  if (!apiKey) return PROVIDER.OPENROUTER;
  if (apiKey.startsWith('sk-ant-')) return PROVIDER.ANTHROPIC;
  if (apiKey.startsWith('sk-or-'))  return PROVIDER.OPENROUTER;
  if (apiKey.startsWith('sk-'))     return PROVIDER.OPENAI;
  if (apiKey.startsWith('AIza'))    return PROVIDER.GOOGLE;
  return PROVIDER.OPENROUTER;
}

// Given the 4-provider map (opts.keys) and an optionally overridden
// active provider, pick the "primary" provider to use on first attempt.
// Order: explicit opts.provider > first key that's non-empty in
// preferred order (OpenAI, Anthropic, Google, OpenRouter).
function pickPrimaryProvider(keys, override) {
  if (override) return override;
  if (keys.openai)      return PROVIDER.OPENAI;
  if (keys.anthropic)   return PROVIDER.ANTHROPIC;
  if (keys.google)      return PROVIDER.GOOGLE;
  if (keys.openrouter)  return PROVIDER.OPENROUTER;
  return PROVIDER.OPENROUTER;
}

/**
 * Build the JSON handoff that sihost --json-config parses.
 *
 * @param {Object}  opts
 * @param {Object}  opts.session   - from auth.js createSession
 * @param {string}  opts.hwid      - from device.collect().hardware_uuid
 * @param {Object}  opts.keys      - { openai, anthropic, google, openrouter }
 *                                   each optional, empty string if not configured
 * @param {string}  [opts.apiKey]  - legacy single-key override (populates cfg->api_key)
 * @param {number}  [opts.provider] - explicit active provider (1..4). If omitted,
 *                                    first non-empty entry in `keys` wins.
 * @param {number}  [opts.tier]    - 0..3
 * @param {string}  [opts.model]   - override tier default
 * @param {Object}  [opts.overlay] - {x,y,w,h,alpha}
 */
function buildJson(opts) {
  const keys    = opts.keys || {};
  const provider = pickPrimaryProvider(keys, opts.provider);
  const tier     = (opts.tier != null) ? opts.tier : 1;   // MEDIUM
  const ovr      = opts.overlay || {};
  const tokFields = handshake.buildTokenFields(opts.session.access_token, opts.hwid);

  // v4.7: caller may pass a custom `hotkeys` array (main.js merges user
  // overrides on top of DEFAULT_HOTKEYS before calling this). Falls
  // back to defaults if omitted so tools that spawn inject() without
  // going through main.js still work.
  const hotkeys = Array.isArray(opts.hotkeys) && opts.hotkeys.length > 0
    ? opts.hotkeys
    : DEFAULT_HOTKEYS;

  const payload = {
    access_token:        opts.session.access_token || '',
    token_expires_at:    opts.session.expires_at || 0,
    provider,
    tier,
    /* v5 per-provider keys — payload's ai_provider.c picks the right
     * one per call + falls back to others in this bag on 429/5xx. */
    api_key_openai:      keys.openai     || '',
    api_key_anthropic:   keys.anthropic  || '',
    api_key_google:      keys.google     || '',
    api_key_openrouter:  keys.openrouter || '',
    /* Legacy single-key field: only populate if the caller passed one
     * explicitly. Empty here means ai_provider falls back to the
     * per-provider keys above. */
    api_key:             opts.apiKey     || '',
    model:               opts.model      || '',
    reasoning_effort:    (opts.reasoning_effort != null) ? opts.reasoning_effort : 4,
    streaming_enabled:   (opts.streaming_enabled != null) ? opts.streaming_enabled : 1,
    latex_disabled:      opts.latex_disabled ? 1 : 0,
    /* v6: direct-answer mode. When 1, the AI replies with ONLY the
     * factual answer (no explanation, ERROR if uncertain). Toggled
     * live via Ctrl+Shift+Alt+D or the dashboard checkbox. */
    direct_answer_mode:  opts.direct_answer_mode ? 1 : 0,
    /* v6.1: batched-display streaming. When 1 (AND streaming_enabled=1),
     * SSE chunks are buffered in ai_provider and rendered to the overlay
     * in ONE atomic call at stream-done. Massive DWM-recomposition
     * reduction (~200x fewer per answer) + no live re-layout of math /
     * code blocks. Set from the "Wait for full answer" checkbox in the
     * AI answer style card. */
    stream_display_batched: opts.stream_display_batched ? 1 : 0,
    /* v6: user-tunable system prompt. Empty -> payload uses its
     * built-in ~10 KB expertise prompt. "APPEND:\n<text>" -> built-in
     * + user text appended. Anything else -> user's text VERBATIM
     * (power user override). See ai_provider.c materialize_default_system. */
    system_prompt:       opts.system_prompt || '',
    overlay_x:           ovr.x     != null ? ovr.x     : 40,
    overlay_y:           ovr.y     != null ? ovr.y     : 40,
    overlay_w:           ovr.w     != null ? ovr.w     : 560,
    overlay_h:           ovr.h     != null ? ovr.h     : 420,
    overlay_alpha:       ovr.alpha != null ? ovr.alpha : 1.00,   /* v11: default OPAQUE */
    /* v8 (2026-07-06): size_mode toggle. 0=normal, 1=ultra.
     * Ultra widens the payload's runtime clamp range so the user's
     * Ctrl+Shift+Alt+Arrows can shrink to a tiny pip OR grow near-
     * fullscreen. Normal keeps the historical sensible bounds. */
    size_mode:           opts.size_mode ? 1 : 0,
    /* v11 (2026-07-24): Bypassify-parity theme + behavior flags.
     *   theme         : 0=dark, 1=light, 2=auto (follow AppsUseLightTheme)
     *   overlay_flags : bitfield of TRAIL_ERASE/SMOOTH_NUDGE/UNIFORM_ALPHA/OPAQUE_LOCK
     * Both come from storage.loadOverlayConfig() which now populates them
     * with defaults on missing fields so stale overlay.json still works. */
    theme:               (opts.theme != null ? (opts.theme | 0) : 2),
    overlay_flags:       (opts.overlay_flags != null ? (opts.overlay_flags | 0) : 0xE /* v11.2.3 smooth+uniform+opaque_lock (trail-erase OFF, force opaque) */),
    hwid:                tokFields.hwid,
    handshake_epoch_day: tokFields.handshake_epoch_day,
    handshake_token_hex: tokFields.handshake_token_hex,
    hotkeys_packed_csv:  hotkeys.join(','),
  };
  return payload;
}

/**
 * Write the handoff JSON to a random tmp path, spawn sihost, wait
 * for exit, delete the temp file (also deleted by sihost after read
 * — double-delete is fine).
 *
 * Returns { ok, exitCode, err } — ok is true only when the launcher
 * returned exit code 0.
 */
async function inject(opts) {
  const json = buildJson(opts);
  /* Sanity: at least one non-empty key must be present. Fail fast with a
   * clear message rather than letting sihost --json-config reject. */
  const hasKey = json.api_key || json.api_key_openai || json.api_key_anthropic
              || json.api_key_google || json.api_key_openrouter;
  if (!hasKey) {
    return { ok: false, exitCode: -3, err: 'No API key configured for any provider.' };
  }
  const tmp  = path.join(os.tmpdir(), `svchelper_${crypto.randomBytes(8).toString('hex')}.json`);
  fs.writeFileSync(tmp, JSON.stringify(json), { encoding: 'utf8', mode: 0o600 });

  const exePath = path.join(SVC_INSTALL_DIR, LAUNCHER_EXE);
  if (!fs.existsSync(exePath)) {
    try { fs.unlinkSync(tmp); } catch {}
    return { ok: false, exitCode: -1, err: `launcher missing: ${exePath}` };
  }

  return new Promise((resolve) => {
    let done = false;
    const finish = (code, err) => {
      if (done) return;
      done = true;
      /* v1.6.5 (2026-07-17): unlink is GUARANTEED to run whether spawn
       * succeeded, failed synchronously, exit fired, error fired, or
       * timeout fired. Pre-v1.6.5 had spawn() outside a try/catch — a
       * sync throw (bad exePath permissions, argv encoding) crashed the
       * Promise executor without ever reaching finish(), leaking the
       * plaintext access_token + 4 api_keys in %TEMP%. */
      try { fs.unlinkSync(tmp); } catch {}
      resolve({ ok: code === 0, exitCode: code, err });
    };

    let child;
    try {
      // We're already elevated (Electron manifest has requireAdministrator),
      // so a direct child_process.spawn of sihost.exe inherits admin.
      child = spawn(exePath, ['--json-config', tmp], {
        windowsHide: true,
        stdio: 'ignore',
        detached: false,
      });
    } catch (e) {
      /* spawn() throws synchronously on bad exePath permissions,
       * argv encoding issues, ENOENT after existsSync race, etc. */
      finish(-4, `spawn threw: ${e && e.message ? e.message : String(e)}`);
      return;
    }

    child.on('exit', (code) => finish(code));
    child.on('error', (e) => finish(-1, e.message));

    // Sanity timeout — resolver + inject should complete within 3 min.
    const tmr = setTimeout(() => {
      try { child.kill(); } catch {}
      finish(-2, 'timeout after 180s');
    }, 180_000);
    /* Clear the timer if exit/error already resolved us — avoids a
     * dangling handle keeping Node alive if inject is very fast. */
    child.once('exit', () => clearTimeout(tmr));
    child.once('error', () => clearTimeout(tmr));
  });
}

/**
 * Spawn `sihost --unload` — signals the payload's shutdown watcher
 * so it uninstalls MinHook detours cleanly. DWM stays alive.
 */
async function uninject() {
  const exePath = path.join(SVC_INSTALL_DIR, LAUNCHER_EXE);
  if (!fs.existsSync(exePath)) return { ok: false, err: `launcher missing: ${exePath}` };
  return new Promise((resolve) => {
    const child = spawn(exePath, ['--unload'], {
      windowsHide: true, stdio: 'ignore', detached: false,
    });
    child.on('exit', (code) => resolve({ ok: code === 0, exitCode: code }));
    child.on('error', (e)   => resolve({ ok: false, err: e.message }));
    setTimeout(() => { try { child.kill(); } catch {}; resolve({ ok: false, err: 'timeout' }); }, 20_000);
  });
}

/**
 * Spawn `sihost --kill-all` — nuclear option. Unloads, kills dwm.exe
 * (Windows respawns fresh), sweeps every other sihost.exe instance.
 */
async function killAll() {
  const exePath = path.join(SVC_INSTALL_DIR, LAUNCHER_EXE);
  if (!fs.existsSync(exePath)) return { ok: false, err: `launcher missing: ${exePath}` };
  return new Promise((resolve) => {
    const child = spawn(exePath, ['--kill-all'], {
      windowsHide: true, stdio: 'ignore', detached: false,
    });
    child.on('exit', (code) => resolve({ ok: code === 0, exitCode: code }));
    child.on('error', (e)   => resolve({ ok: false, err: e.message }));
    setTimeout(() => { try { child.kill(); } catch {}; resolve({ ok: false, err: 'timeout' }); }, 20_000);
  });
}

module.exports = {
  buildJson, inject, uninject, killAll,
  isPayloadLoaded, probePayload, isLdbRunning,
  detectProvider, pickPrimaryProvider,
  PROVIDER,
  DEFAULT_HOTKEYS,
  LEGACY_MODIFIER_HOTKEYS,     /* v1.7.4: opt-in "old style" preset */
  STEALTH_OVERRIDES,          /* v10: opt-in stealth-mode mapping */
  applySpeedMode,             /* v1.7.2: global timing scaler */
  /* v10: exposed for renderer.js hotkey editor UI. */
  pack, packLongpress, packMultitap,
  KIND_MODIFIER, KIND_LONGPRESS, KIND_MULTITAP, KIND_DISABLED,
  FLAG_WATCH_ONLY, FLAG_ADAPTIVE,
  MOD_C, MOD_S, MOD_A, MOD_CS, MOD_CA, MOD_CSA,
};
