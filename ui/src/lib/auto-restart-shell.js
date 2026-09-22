// ============================================================
//  auto-restart-shell.js — toggle Windows' AutoRestartShell reg
//  key while payload is injected.
//
//  Motivation: on any explorer.exe death (attacker kill, exam-tool
//  taskkill, driver crash, user manual restart), Windows normally
//  auto-respawns explorer via winlogon (`AutoRestartShell` DWORD == 1
//  under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon).
//  Each respawn causes our overlay to briefly flicker (v3.5 recovery
//  path re-inits the ImGui pipeline on Progman-change detection).
//  Rapid repeated kill/respawn cycles cause visible blips that could
//  be exploited to detect our overlay OR just look bad.
//
//  When our payload is armed, we set `AutoRestartShell = 0` so
//  Windows stops auto-respawning explorer on death. If explorer dies,
//  it STAYS dead until user manually launches it (or reboots). This
//  matches Nyx's spec 2026-09-21: "we don't kill explorer, we just
//  make sure it doesn't come back on its own".
//
//  When user uninjects (any path: user_uninject / kill_all / sign
//  out / app quit / panic hotkey), we restore the original reg value.
//  A tiny state file (`C:\ProgramData\WinAudioSvc\.autorestart_saved`)
//  persists the value we saved so restore works even across app
//  restarts. On svchelper startup, if that file exists but no payload
//  is loaded, we auto-heal (svchelper was killed dirty last session).
//
//  Registry key semantics (verified via web search 2026-09-21 against
//  MS + community docs — value/path constant across Win7 through
//  Windows 11 25H2):
//    - Path:  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
//    - Name:  AutoRestartShell
//    - Type:  REG_DWORD
//    - Value: 1 = default (auto-respawn enabled)
//             0 = disabled (explorer stays dead on death)
//    - Missing key = treated as default 1
//    - Requires elevation to write (svchelper is requireAdministrator)
//
//  IMPORTANT: our own winlogon-hosted `sentinel_thread` (Monitor A)
//  also has an explorer-respawn path. When AutoRestartShell=0 that
//  monitor MUST stand down or the feature does nothing. The sentinel
//  reads this same reg key each tick and skips Monitor A if the
//  value is 0 (implemented in tools/redteam/probes/wl_input.c v3.1).
// ============================================================

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { SVC_INSTALL_DIR } = require('../license/config');

const REG_PATH = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';
const REG_NAME = 'AutoRestartShell';
const STATE_FILE = () => path.join(SVC_INSTALL_DIR, '.autorestart_saved');

const REG_EXE = 'C:\\Windows\\System32\\reg.exe';

/* Read current AutoRestartShell value. Returns:
 *   number (0 or 1 typically) if the key exists
 *   1                          if the key is missing (Windows default)
 *   null                       if reg.exe fails for other reasons */
function getCurrentValue() {
  try {
    const out = execFileSync(REG_EXE,
      ['query', REG_PATH, '/v', REG_NAME],
      { windowsHide: true, timeout: 5000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    // Output format: "    AutoRestartShell    REG_DWORD    0x1"
    const m = out.match(/REG_DWORD\s+0x([0-9a-fA-F]+)/);
    if (m) return parseInt(m[1], 16);
    return null;
  } catch (e) {
    // Exit code 1 typically means value not found → default = 1
    if (e.status === 1) return 1;
    console.log('[auto-restart-shell] read failed:', e.message);
    return null;
  }
}

/* Write AutoRestartShell = <value>. Requires elevation. */
function setValue(value) {
  try {
    execFileSync(REG_EXE,
      ['add', REG_PATH, '/v', REG_NAME, '/t', 'REG_DWORD', '/d', String(value), '/f'],
      { windowsHide: true, timeout: 5000, stdio: 'ignore' });
    return true;
  } catch (e) {
    console.log(`[auto-restart-shell] write ${value} failed:`, e.message);
    return false;
  }
}

/* Save the current value to state file, then set to 0. Called after a
 * successful inject. Idempotent: if state file already exists, we
 * don't re-save (that would overwrite a legitimate prior value with
 * our own 0). Safe to call multiple times per session. */
function disable() {
  const stateFile = STATE_FILE();
  try {
    if (fs.existsSync(stateFile)) {
      const cur = getCurrentValue();
      console.log(`[auto-restart-shell] disable() no-op: state file already present (cur=${cur})`);
      // Still enforce =0 in case something else flipped it since we armed
      if (cur !== 0) setValue(0);
      return true;
    }

    const saved = getCurrentValue();
    if (saved === null) {
      console.log('[auto-restart-shell] disable() SKIPPED — could not read current value');
      return false;
    }

    // Persist saved value + timestamp so heal() can detect stale state
    const body = JSON.stringify({ savedValue: saved, savedAt: Date.now() });
    try {
      if (!fs.existsSync(SVC_INSTALL_DIR)) fs.mkdirSync(SVC_INSTALL_DIR, { recursive: true });
      fs.writeFileSync(stateFile, body, 'utf8');
    } catch (e) {
      console.log('[auto-restart-shell] disable() state-file write FAILED:', e.message);
      return false;
    }

    const ok = setValue(0);
    console.log(`[auto-restart-shell] disable(): saved prior=${saved}, wrote 0 (ok=${ok})`);
    return ok;
  } catch (e) {
    console.log('[auto-restart-shell] disable() threw:', e.message);
    return false;
  }
}

/* Read the saved value from state file, restore it to the registry,
 * delete the state file. Called on any uninject path. If state file
 * is missing (already-restored / never-disabled), restore to 1 as
 * safe default. Non-throwing. */
function restore() {
  const stateFile = STATE_FILE();
  let saved = 1;
  let hadState = false;
  try {
    if (fs.existsSync(stateFile)) {
      hadState = true;
      const raw = fs.readFileSync(stateFile, 'utf8');
      try {
        const parsed = JSON.parse(raw);
        if (typeof parsed.savedValue === 'number') saved = parsed.savedValue;
      } catch { /* corrupt state file — fall through to default 1 */ }
    }
  } catch (e) {
    console.log('[auto-restart-shell] restore() state-file read failed:', e.message);
  }

  // Sanity clamp: only 0 or 1 are legit. Any other value = corrupted → default 1.
  if (saved !== 0 && saved !== 1) saved = 1;

  const ok = setValue(saved);
  console.log(`[auto-restart-shell] restore(): had_state=${hadState}, wrote ${saved} (ok=${ok})`);

  try { if (hadState) fs.unlinkSync(stateFile); } catch { /* ignore */ }
  return ok;
}

/* Startup crash-recovery: if the state file exists but no payload is
 * loaded, svchelper died dirty last session and never restored. Fix
 * it. Called from app.whenReady() before showing the dashboard.
 *
 * `probePayloadLoaded` is a function returning Promise<boolean> or
 * boolean synchronously — we accept either. */
async function heal(probePayloadLoaded) {
  const stateFile = STATE_FILE();
  try {
    if (!fs.existsSync(stateFile)) return { healed: false, reason: 'no_state_file' };
  } catch { return { healed: false, reason: 'stat_failed' }; }

  let loaded = false;
  try {
    const r = probePayloadLoaded();
    loaded = (r && typeof r.then === 'function') ? await r : !!r;
  } catch {
    loaded = false;
  }

  if (loaded) {
    // Payload IS loaded — state file is legitimately in place. No heal.
    return { healed: false, reason: 'payload_loaded' };
  }

  console.log('[auto-restart-shell] heal(): stale state file + payload not loaded → restoring');
  const ok = restore();
  return { healed: true, ok, reason: 'stale_state_file' };
}

module.exports = { getCurrentValue, disable, restore, heal, REG_PATH, REG_NAME };
