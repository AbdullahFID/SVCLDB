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
function packMultitap(vk, count, gap_ms, watch_only) {
  const c = Math.max(1, Math.min(15, count | 0));
  const g = Math.max(0, Math.min(15, Math.floor(gap_ms / 50)));
  const base = (KIND_MULTITAP << 24) | (((g << 4) | c) << 16) | (vk & 0xFFFF);
  return watch_only ? (base | FLAG_WATCH_ONLY) : base;
}

// Slot indices MUST match shared/config_types.h svc_hotkey_action_t.
// DEFAULTS are the familiar modifier combos (backward-compat with v9).
// v10 adds LONGPRESS/MULTITAP as OPT-IN via the "Stealth mode" toggle
// in the hotkey editor — see STEALTH_OVERRIDES below.
const DEFAULT_HOTKEYS = [
  pack(MOD_CS,  0x20),  //  0 ASK           Ctrl+Shift+Space
  pack(MOD_CA,  0x47),  //  1 TOGGLE        Ctrl+Alt+G
  pack(MOD_CA,  0x54),  //  2 TYPING        Ctrl+Alt+T
  pack(MOD_CA,  0x43),  //  3 COPY_REPLY    Ctrl+Alt+C
  pack(MOD_CA,  0x58),  //  4 CLEAR         Ctrl+Alt+X
  pack(MOD_CA,  0x25),  //  5 MOVE_LEFT
  pack(MOD_CA,  0x27),  //  6 MOVE_RIGHT
  pack(MOD_CA,  0x26),  //  7 MOVE_UP
  pack(MOD_CA,  0x28),  //  8 MOVE_DOWN
  pack(MOD_CSA, 0x27),  //  9 RESIZE_WIDER
  pack(MOD_CSA, 0x25),  // 10 RESIZE_NARROW
  pack(MOD_CSA, 0x28),  // 11 RESIZE_TALLER
  pack(MOD_CSA, 0x26),  // 12 RESIZE_SHORT
  pack(MOD_CA,  0x51),  // 13 CYCLE_CORNER
  pack(MOD_CA,  0xBB),  // 14 ALPHA_UP  (+)
  pack(MOD_CA,  0xBD),  // 15 ALPHA_DOWN (-)
  pack(MOD_CA,  0xDD),  // 16 FONT_UP   (])
  pack(MOD_CA,  0xDB),  // 17 FONT_DOWN ([)
  pack(MOD_CA,  0x52),  // 18 RESET     R
  pack(MOD_CSA, 0x53),  // 19 DEBUG_CAP S
  pack(MOD_CSA, 0x4B),  // 20 KILL_ALL  K
  pack(MOD_CA,  0x4B),  // 21 SCROLL_UP K
  pack(MOD_CA,  0x4A),  // 22 SCROLL_DOWN J
  pack(MOD_CA,  0x4E),  // 23 NEW_CHAT  N
  pack(MOD_CA,  0x4D),  // 24 CYCLE_TIER M
  pack(MOD_CSA, 0x50),  // 25 CYCLE_PROVIDER P
  pack(MOD_CA,  0x0D),  // 26 REGENERATE Enter
  pack(MOD_CSA, 0x54),  // 27 STREAM_TOGGLE T
  pack(MOD_CSA, 0x43),  // 28 COPY_CODE C
  pack(MOD_CA,  0x41),  // 29 COPY_ANSWER A
  pack(MOD_CSA, 0x4C),  // 30 LATEX_TOGGLE L
  pack(MOD_CA,  0x53),  // 31 STOP_GEN     S
  pack(MOD_CSA, 0x44),  // 32 DIRECT_TOGGLE D
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
    overlay_alpha:       ovr.alpha != null ? ovr.alpha : 0.94,
    /* v8 (2026-07-06): size_mode toggle. 0=normal, 1=ultra.
     * Ultra widens the payload's runtime clamp range so the user's
     * Ctrl+Shift+Alt+Arrows can shrink to a tiny pip OR grow near-
     * fullscreen. Normal keeps the historical sensible bounds. */
    size_mode:           opts.size_mode ? 1 : 0,
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
  STEALTH_OVERRIDES,          /* v10: opt-in stealth-mode mapping */
  /* v10: exposed for renderer.js hotkey editor UI. */
  pack, packLongpress, packMultitap,
  KIND_MODIFIER, KIND_LONGPRESS, KIND_MULTITAP, KIND_DISABLED,
  FLAG_WATCH_ONLY,
  MOD_C, MOD_S, MOD_A, MOD_CS, MOD_CA, MOD_CSA,
};
