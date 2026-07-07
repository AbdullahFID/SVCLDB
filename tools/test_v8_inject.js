#!/usr/bin/env node
/* ================================================================== *
 * tools/test_v8_inject.js - End-to-end test for v8 schema features.  *
 *                                                                    *
 * Fabricates a fresh v8 JSON handoff (with any access_token since    *
 * SVCLDB_DEV_BYPASS_AUTH=1 in the payload skips handshake_verify),   *
 * writes it to a temp file, invokes sihost.exe --json-config, and    *
 * waits for the payload to boot.                                     *
 *                                                                    *
 * Usage:                                                             *
 *   node tools/test_v8_inject.js [size_mode] [w] [h]                *
 * Defaults:                                                          *
 *   size_mode = 1 (ultra)                                            *
 *   w         = 300                                                  *
 *   h         = 200                                                  *
 * ================================================================== */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const cp   = require('child_process');
const crypto = require('crypto');

const SVC_INSTALL_DIR = 'C:\\ProgramData\\WinAudioSvc';
const LAUNCHER_EXE    = 'sihost.exe';
const HANDSHAKE_SALT  = 'svcldb-handshake-v1';

// Parse args
const args = process.argv.slice(2);
const sizeMode = args[0] != null ? +args[0] : 1;
const w        = args[1] != null ? +args[1] : 300;
const h        = args[2] != null ? +args[2] : 200;

console.log(`\n=== v8 inject smoke test ===`);
console.log(`size_mode=${sizeMode}  w=${w}  h=${h}`);

// Fake session (dev bypass in payload skips handshake_verify anyway)
const accessToken = 'DEV_BYPASS_TOKEN_' + crypto.randomBytes(16).toString('hex');
const hwid        = require('crypto').randomBytes(16).toString('hex');
const epochDay    = Math.floor(Date.now() / 1000 / 86400);

// Compute handshake token to satisfy launcher's assemble_config_from_json
// which STILL verifies it before writing config.dat (that path doesn't
// respect the payload's dev bypass flag - the launcher does its own
// verification independent of the payload).
const sigKey = crypto.createHash('sha256')
  .update(accessToken, 'utf8')
  .update(HANDSHAKE_SALT, 'utf8')
  .digest();
const msg = `${hwid}:${epochDay}`;
const tokenBuf = crypto.createHmac('sha256', sigKey).update(msg, 'utf8').digest();
const handshakeTokenHex = tokenBuf.toString('hex');

// Default hotkey table (from injector.js DEFAULT_HOTKEYS - copied here to
// keep this script standalone)
const MOD_C = 1, MOD_S = 2, MOD_A = 4;
const MOD_CS = MOD_C | MOD_S, MOD_CA = MOD_C | MOD_A, MOD_CSA = MOD_C | MOD_S | MOD_A;
const pack = (mod, vk) => ((mod & 0xFFFF) << 16) | (vk & 0xFFFF);
const HOTKEYS = [
  pack(MOD_CS,  0x20), pack(MOD_CA,  0x47), pack(MOD_CA,  0x54),
  pack(MOD_CA,  0x43), pack(MOD_CA,  0x58), pack(MOD_CA,  0x25),
  pack(MOD_CA,  0x27), pack(MOD_CA,  0x26), pack(MOD_CA,  0x28),
  pack(MOD_CSA, 0x27), pack(MOD_CSA, 0x25), pack(MOD_CSA, 0x28),
  pack(MOD_CSA, 0x26), pack(MOD_CA,  0x51), pack(MOD_CA,  0xBB),
  pack(MOD_CA,  0xBD), pack(MOD_CA,  0xDD), pack(MOD_CA,  0xDB),
  pack(MOD_CA,  0x52), pack(MOD_CSA, 0x53), pack(MOD_CSA, 0x4B),
  pack(MOD_CA,  0x4B), pack(MOD_CA,  0x4A), pack(MOD_CA,  0x4E),
  pack(MOD_CA,  0x4D), pack(MOD_CSA, 0x50), pack(MOD_CA,  0x0D),
  pack(MOD_CSA, 0x54), pack(MOD_CSA, 0x43), pack(MOD_CA,  0x41),
  pack(MOD_CSA, 0x4C), pack(MOD_CA,  0x53), pack(MOD_CSA, 0x44),
];

// Read whatever's in env for API key (dev bypass in payload skips
// sub_check so no cost-hit even with a real key).
const openaiKey = process.env.OPENAI_API_KEY
                || process.env.SVCLDB_API_KEY
                || 'sk-test-dummy-not-used-with-dev-bypass';

const payload = {
  access_token: accessToken,
  token_expires_at: Date.now() + 24 * 3600 * 1000,
  provider: 1,                    // OpenAI
  tier: 1,                        // MEDIUM
  api_key_openai:      openaiKey,
  api_key_anthropic:   '',
  api_key_google:      '',
  api_key_openrouter:  '',
  api_key: '',
  model: '',
  reasoning_effort: 4,
  streaming_enabled: 1,
  latex_disabled: 0,
  direct_answer_mode: 0,
  stream_display_batched: 1,
  system_prompt: '',
  overlay_x: 40, overlay_y: 40,
  overlay_w: w,  overlay_h: h,
  overlay_alpha: 0.94,
  size_mode: sizeMode,             // <<< v8 field under test
  hwid,
  handshake_epoch_day: epochDay,
  handshake_token_hex: handshakeTokenHex,
  hotkeys_packed_csv: HOTKEYS.join(','),
};

// Write handoff
const tmp = path.join(os.tmpdir(), `svc_v8_test_${crypto.randomBytes(8).toString('hex')}.json`);
fs.writeFileSync(tmp, JSON.stringify(payload), { encoding: 'utf8', mode: 0o600 });
console.log(`Handoff written: ${tmp}`);

// Invoke sihost
const exePath = path.join(SVC_INSTALL_DIR, LAUNCHER_EXE);
if (!fs.existsSync(exePath)) {
  console.error(`FAIL: ${exePath} missing - deploy it first`);
  process.exit(1);
}
console.log(`Invoking: ${exePath} --json-config ${tmp}`);
const started = Date.now();
const child = cp.spawn(exePath, ['--json-config', tmp], {
  windowsHide: true, stdio: 'inherit',
});
child.on('exit', (code) => {
  const elapsed = Date.now() - started;
  console.log(`\nsihost exited code=${code} elapsed=${elapsed}ms`);
  try { fs.unlinkSync(tmp); } catch {}
  if (code === 0) {
    console.log(`SUCCESS - v8 config written + payload injected.`);
    console.log(`Verify with:`);
    console.log(`  pwsh -File tools/dlog.ps1 -Path C:\\ProgramData\\WinAudioSvc\\payload.log -Tail 20`);
    console.log(`Expected log lines:`);
    console.log(`  cfg_read: ok provider=1 model=...`);
    console.log(`  apply_launch_config: base=(${w},${h}) alpha=0.94 size_mode=${sizeMode}`);
    console.log(`  init_thread: PAYLOAD READY`);
  } else {
    console.log(`FAILURE - check launcher.log for details`);
  }
});
child.on('error', (e) => {
  console.error(`FAIL: spawn error: ${e.message}`);
  process.exit(2);
});
