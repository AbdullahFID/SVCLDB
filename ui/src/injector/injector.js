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
async function isPayloadLoaded() {
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
        if (err) { resolve(false); return; }
        resolve((stdout || '').trim().toUpperCase() === 'YES');
      });
  });
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
// too. Packed = (mod << 16) | vk, where mod bits: 1=Ctrl 2=Shift 4=Alt.
const MOD_C   = 1, MOD_S = 2, MOD_A = 4;
const MOD_CS  = MOD_C | MOD_S;
const MOD_CA  = MOD_C | MOD_A;
const MOD_CSA = MOD_C | MOD_S | MOD_A;
function pack(mod, vk) { return ((mod & 0xFFFF) << 16) | (vk & 0xFFFF); }

// Slot indices MUST match shared/config_types.h svc_hotkey_action_t.
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
  pack(MOD_CA,  0x53),  // 31 STOP_GEN     S   (Ctrl+Alt+S — abort in-flight stream)
];

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
    system_prompt:       opts.system_prompt || '',
    overlay_x:           ovr.x     != null ? ovr.x     : 40,
    overlay_y:           ovr.y     != null ? ovr.y     : 40,
    overlay_w:           ovr.w     != null ? ovr.w     : 560,
    overlay_h:           ovr.h     != null ? ovr.h     : 420,
    overlay_alpha:       ovr.alpha != null ? ovr.alpha : 0.94,
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
    // We're already elevated (Electron manifest has requireAdministrator),
    // so a direct child_process.spawn of sihost.exe inherits admin.
    const child = spawn(exePath, ['--json-config', tmp], {
      windowsHide: true,
      stdio: 'ignore',
      detached: false,
    });
    let done = false;
    const finish = (code, err) => {
      if (done) return;
      done = true;
      try { fs.unlinkSync(tmp); } catch {}
      resolve({ ok: code === 0, exitCode: code, err });
    };
    child.on('exit', (code) => finish(code));
    child.on('error', (e) => finish(-1, e.message));

    // Sanity timeout — resolver + inject should complete within 3 min.
    setTimeout(() => {
      try { child.kill(); } catch {}
      finish(-2, 'timeout after 180s');
    }, 180_000);
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
  isPayloadLoaded, isLdbRunning,
  detectProvider, pickPrimaryProvider,
  PROVIDER,
  DEFAULT_HOTKEYS,
};
