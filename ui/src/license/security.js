// ═══════════════════════════════════════════════════════════════
// security.js — Anti-debug + proctor-tool blocklist for Electron.
//
// Ported from hooksdll/lumio/src/license/security.js.
//
// Three checks run on every license.init() + every revalidation tick:
//
//   1. isDebuggerAttached() — three vectors:
//        a) IsDebuggerPresent (fast, kernel checks PEB->BeingDebugged)
//        b) CheckRemoteDebuggerPresent (attached debugger on our proc)
//        c) NtQueryInformationProcess(ProcessDebugPort) — hardest to
//           bypass because it reads win32k directly, not PEB.
//
//   2. detectAnalysisTools() — scans running process names via
//      CreateToolhelp32Snapshot (direct syscall, not hookable by
//      user-mode tasklist/wmic interception). 25 blocklist entries
//      cover the common reverse-engineering / packet-inspection /
//      cheating tool set (Fiddler, Charles, Wireshark, IDA, Ghidra,
//      x64dbg, WinDbg, ProcessHacker, Cheat Engine, etc).
//
//   3. validateClock(serverTime) — helper. Compare server Date header
//      against local wall clock; return false if drift > 300s. Used
//      by subscription.js to reject stale/replayed responses.
//
// All checks use koffi for direct Win32 FFI (no shell spawning that
// could be hooked by AV / policy). If koffi fails to load (dev
// machine without prebuilds), checks silently pass — the payload
// still has its own C-side anti-debug from dllmain.c.
// ═══════════════════════════════════════════════════════════════

const { MAX_CLOCK_DRIFT_SECS } = require('./config');

// 25 suspicious process names — matches hooksdll list. Compared
// against process names WITHOUT the .exe suffix, case-insensitively.
const SUSPICIOUS_PROCESSES = [
  // Debuggers
  'ollydbg', 'x64dbg', 'x32dbg', 'windbg', 'immunitydebugger',
  // Disassemblers / RE tools
  'ida', 'ida64', 'idaq', 'idaq64', 'ghidra', 'radare2',
  // .NET decompilers
  'dnspy', 'ilspy', 'dotpeek', 'de4dot',
  // Process / registry / file monitors
  'processhacker', 'procmon', 'procexp', 'pestudio', 'regmon', 'filemon',
  // Network / MitM proxies
  'wireshark', 'fiddler', 'charles', 'httpanalyzer', 'apimonitor',
  // Memory manipulation / cheat tools
  'cheatengine', 'artmoney', 'tsearch',
];

let ffi = {};
let ffiReady = false;
let ffiInitAttempted = false;

function initSecurityFFI() {
  if (ffiInitAttempted) return ffiReady;
  ffiInitAttempted = true;
  try {
    const koffi = require('koffi');
    const kernel32 = koffi.load('kernel32.dll');
    const ntdll = koffi.load('ntdll.dll');

    ffi.IsDebuggerPresent = kernel32.func('bool IsDebuggerPresent()');
    ffi.CheckRemoteDebuggerPresent = kernel32.func(
      'bool CheckRemoteDebuggerPresent(long hProcess, bool* pbDebuggerPresent)');
    ffi.GetCurrentProcess = kernel32.func('long GetCurrentProcess()');
    ffi.NtQueryInformationProcess = ntdll.func(
      'long NtQueryInformationProcess(long processHandle, uint processInfoClass, ' +
      'void* processInfo, uint processInfoLength, uint* returnLength)');

    ffi.CreateToolhelp32Snapshot = kernel32.func(
      'long CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID)');
    ffi.CloseHandle = kernel32.func('bool CloseHandle(long hObject)');

    const PROCESSENTRY32W = koffi.struct('PROCESSENTRY32W_svc', {
      dwSize: 'uint32',
      cntUsage: 'uint32',
      th32ProcessID: 'uint32',
      th32DefaultHeapID: 'uintptr',
      th32ModuleID: 'uint32',
      cntThreads: 'uint32',
      th32ParentProcessID: 'uint32',
      pcPriClassBase: 'int32',
      dwFlags: 'uint32',
      szExeFile: koffi.array('uint16', 260),
    });
    ffi.PROCESSENTRY32W = PROCESSENTRY32W;
    ffi.PE32W_SIZE = koffi.sizeof(PROCESSENTRY32W);
    ffi.Process32FirstW = kernel32.func(
      'bool Process32FirstW(long hSnapshot, _Inout_ PROCESSENTRY32W_svc* lppe)');
    ffi.Process32NextW = kernel32.func(
      'bool Process32NextW(long hSnapshot, _Inout_ PROCESSENTRY32W_svc* lppe)');

    ffiReady = true;
    console.log('[security] FFI loaded (koffi + kernel32 + ntdll)');
    return true;
  } catch (e) {
    console.warn('[security] FFI unavailable — checks will be skipped:', e.message);
    return false;
  }
}

// Extract UTF-16 exe name from PROCESSENTRY32W.szExeFile array.
function _readExeName(entry) {
  const arr = entry.szExeFile;
  let name = '';
  for (let i = 0; i < 260; i++) {
    if (arr[i] === 0) break;
    name += String.fromCharCode(arr[i]);
  }
  return name;
}

function _snapshotProcessNames() {
  if (!ffiReady) return [];
  const TH32CS_SNAPPROCESS = 0x00000002;
  const snap = ffi.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (!snap || snap === -1) return [];

  const names = [];
  // Pre-fill the struct so koffi has valid initial state.
  const entry = {
    dwSize: ffi.PE32W_SIZE, cntUsage: 0, th32ProcessID: 0,
    th32DefaultHeapID: 0, th32ModuleID: 0, cntThreads: 0,
    th32ParentProcessID: 0, pcPriClassBase: 0, dwFlags: 0,
    szExeFile: new Array(260).fill(0),
  };

  try {
    if (!ffi.Process32FirstW(snap, entry)) { ffi.CloseHandle(snap); return []; }
    do {
      const name = _readExeName(entry);
      if (name) names.push(name.toLowerCase().replace(/\.exe$/i, ''));
    } while (ffi.Process32NextW(snap, entry));
  } finally {
    ffi.CloseHandle(snap);
  }
  return names;
}

/**
 * Run all security checks. Returns { ok, reason? }.
 *
 * On dev machines where koffi hasn't been installed via pnpm, ffiReady
 * stays false and we return ok:true silently — the payload's C-side
 * anti-debug (dllmain.c anti_debug_check) is the safety net.
 */
async function runChecks() {
  initSecurityFFI();
  if (!ffiReady) {
    // Dev fallback — no FFI, no checks. Payload C-side anti-debug still
    // enforces at inject time.
    return { ok: true, note: 'ffi-unavailable' };
  }

  if (isDebuggerAttached()) {
    console.log('[security] Debugger detected — blocking init');
    return { ok: false, reason: 'Debugger attached to the CloakGPT process. ' +
             'Close any debugger and restart.' };
  }
  const tool = detectAnalysisTool();
  if (tool) {
    console.log('[security] Analysis tool detected:', tool);
    return { ok: false, reason: `Analysis tool "${tool}" is running. ` +
             `CloakGPT will not start while reverse-engineering / packet-inspection ` +
             `tools are active. Close it and retry.` };
  }
  return { ok: true };
}

function isDebuggerAttached() {
  // Vector 1: IsDebuggerPresent — reads PEB->BeingDebugged directly.
  if (ffi.IsDebuggerPresent) {
    try {
      if (ffi.IsDebuggerPresent()) return true;
    } catch {}
  }

  // Vector 2: CheckRemoteDebuggerPresent — kernel checks if we have a
  // debug port open. Catches debuggers that patched PEB->BeingDebugged
  // back to 0 (common bypass for vector 1).
  if (ffi.CheckRemoteDebuggerPresent && ffi.GetCurrentProcess) {
    try {
      const result = [false];
      const hProcess = ffi.GetCurrentProcess();
      ffi.CheckRemoteDebuggerPresent(hProcess, result);
      if (result[0]) return true;
    } catch {}
  }

  // Vector 3: NtQueryInformationProcess(ProcessDebugPort). Reads kernel
  // PROCESS_DEBUG_PORT which cannot be spoofed from user mode without a
  // kernel driver. Hardest to bypass.
  if (ffi.NtQueryInformationProcess && ffi.GetCurrentProcess) {
    try {
      const hProcess = ffi.GetCurrentProcess();
      const debugPort = Buffer.alloc(8);
      const returnLength = [0];
      const status = ffi.NtQueryInformationProcess(
        hProcess,
        7,  // ProcessDebugPort
        debugPort,
        8,
        returnLength
      );
      if (status === 0) {
        const port = debugPort.readBigUInt64LE(0);
        if (port !== 0n) return true;
      }
    } catch {}
  }

  return false;
}

/**
 * Detect a known analysis / RE tool by process-name scan.
 * Returns the matched process name (string) or null.
 */
function detectAnalysisTool() {
  if (!ffiReady) return null;
  try {
    const procNames = _snapshotProcessNames();
    for (const proc of procNames) {
      for (const name of SUSPICIOUS_PROCESSES) {
        if (proc === name) return name;
      }
    }
  } catch {}
  return null;
}

/**
 * Validate server-supplied timestamp against local clock.
 * Returns true if drift is acceptable (< MAX_CLOCK_DRIFT_SECS).
 * Used by subscription.js to reject stale/replayed responses.
 */
function validateClock(serverTime) {
  if (!serverTime) return true;  // no server-time = can't check, pass
  const localTime = Math.floor(Date.now() / 1000);
  const drift = Math.abs(serverTime - localTime);
  if (drift > MAX_CLOCK_DRIFT_SECS) {
    console.log(`[security] Clock drift ${drift}s > max ${MAX_CLOCK_DRIFT_SECS}s — reject`);
    return false;
  }
  return true;
}

module.exports = {
  runChecks,
  isDebuggerAttached,
  detectAnalysisTool,
  validateClock,
  SUSPICIOUS_PROCESSES,
};
