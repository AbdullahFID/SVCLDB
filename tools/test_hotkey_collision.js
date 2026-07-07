#!/usr/bin/env node
/* Test the collision detector by intentionally rebinding COPY_ANSWER
 * (slot 29) to the same combo as COPY_REPLY (slot 3, Ctrl+Alt+C).
 * Expected log output:
 *   COLLISION: slots 3 and 29 both bound to vk=0x43 mod=0x5 — only slot 3 will fire
 */
const fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const crypto = require('crypto');
const SVC_INSTALL_DIR = 'C:\\ProgramData\\WinAudioSvc';

const MOD_C = 1, MOD_S = 2, MOD_A = 4;
const MOD_CS = MOD_C | MOD_S, MOD_CA = MOD_C | MOD_A, MOD_CSA = MOD_C | MOD_S | MOD_A;
const pack = (mod, vk) => ((mod & 0xFFFF) << 16) | (vk & 0xFFFF);
const H = [
  pack(MOD_CS,  0x20), pack(MOD_CA,  0x47), pack(MOD_CA,  0x54),
  pack(MOD_CA,  0x43), // 3 COPY_REPLY = Ctrl+Alt+C
  pack(MOD_CA,  0x58), pack(MOD_CA,  0x25),
  pack(MOD_CA,  0x27), pack(MOD_CA,  0x26), pack(MOD_CA,  0x28),
  pack(MOD_CSA, 0x27), pack(MOD_CSA, 0x25), pack(MOD_CSA, 0x28),
  pack(MOD_CSA, 0x26), pack(MOD_CA,  0x51), pack(MOD_CA,  0xBB),
  pack(MOD_CA,  0xBD), pack(MOD_CA,  0xDD), pack(MOD_CA,  0xDB),
  pack(MOD_CA,  0x52), pack(MOD_CSA, 0x53), pack(MOD_CSA, 0x4B),
  pack(MOD_CA,  0x4B), pack(MOD_CA,  0x4A), pack(MOD_CA,  0x4E),
  pack(MOD_CA,  0x4D), pack(MOD_CSA, 0x50), pack(MOD_CA,  0x0D),
  pack(MOD_CSA, 0x54), pack(MOD_CSA, 0x43),
  pack(MOD_CA,  0x43), // 29 COPY_ANSWER now DUPLICATE of slot 3
  pack(MOD_CSA, 0x4C), pack(MOD_CA,  0x53), pack(MOD_CSA, 0x44),
];

const at = 'TEST_' + crypto.randomBytes(8).toString('hex');
const hwid = crypto.randomBytes(16).toString('hex');
const day = Math.floor(Date.now() / 1000 / 86400);
const sig = crypto.createHash('sha256').update(at, 'utf8').update('svcldb-handshake-v1', 'utf8').digest();
const tok = crypto.createHmac('sha256', sig).update(`${hwid}:${day}`, 'utf8').digest();

const payload = {
  access_token: at, token_expires_at: Date.now() + 3600e3,
  provider: 1, tier: 1, api_key_openai: 'sk-test',
  api_key_anthropic: '', api_key_google: '', api_key_openrouter: '', api_key: '',
  model: '', reasoning_effort: 4, streaming_enabled: 1, latex_disabled: 0,
  direct_answer_mode: 0, stream_display_batched: 1, system_prompt: '',
  overlay_x: 40, overlay_y: 40, overlay_w: 560, overlay_h: 420, overlay_alpha: 0.94,
  size_mode: 0,
  hwid, handshake_epoch_day: day, handshake_token_hex: tok.toString('hex'),
  hotkeys_packed_csv: H.join(','),
};
const tmp = path.join(os.tmpdir(), `svc_coll_${crypto.randomBytes(8).toString('hex')}.json`);
fs.writeFileSync(tmp, JSON.stringify(payload), { mode: 0o600 });

const exe = path.join(SVC_INSTALL_DIR, 'sihost.exe');
console.log(`Injecting with slot 29 == slot 3 (both Ctrl+Alt+C) to trip collision detector...`);
const c = cp.spawn(exe, ['--json-config', tmp], { windowsHide: true, stdio: 'inherit' });
c.on('exit', (code) => {
  try { fs.unlinkSync(tmp); } catch {}
  console.log(`Exit ${code}. Now check payload log for COLLISION line.`);
});
