// ═══════════════════════════════════════════════════════════════
// repro_spawn_unknown.js
//
// Reproduces the real-world "Inject failed: spawn threw: spawn UNKNOWN"
// error one user is reporting. Isolates WHICH Windows security
// mitigation is turning `CreateProcessW` into a libuv `UV_UNKNOWN`.
//
// What it does, in order:
//
//   1. Reads SmartAppControlState (Get-MpComputerStatus) + CFA on/off
//      + Defender RTP + Tamper Protection + current exclusion lists
//      so we know the exact security stance.
//
//   2. Copies C:\ProgramData\WinAudioSvc\sihost.exe to a scratch path
//      in %TEMP%\svcldb_spawnrepro_<rand>\ (deliberately OUTSIDE any
//      Defender exclusion path -> same stance as a user whose
//      install-time Add-MpPreference silently failed).
//
//   3. Attempts `child_process.spawn(scratchExe, ['--status'])` -- the
//      cheapest sihost arg (OpenEvent + exit). Captures error.code,
//      error.errno, error.message.
//
//   4. Repeats with `spawn(scratchExe, ['--status'], { shell: true })`
//      (goes through cmd.exe -> different error path).
//
//   5. Does a native CreateProcessW via koffi, captures GetLastError
//      -> this is the GROUND TRUTH Win32 error libuv is translating
//      away.
//
//   6. Repeats steps 3-5 with the ORIGINAL C:\ProgramData\WinAudioSvc\
//      sihost.exe (which IS excluded) as a control case.
//
//   7. Prints a diagnostic report + the actual Win32 error number +
//      name so we can tailor the fix.
//
// Run as:
//   node tools\repro_spawn_unknown.js
//
// Elevation NOT required for the probe itself (spawn is user-mode).
// ═══════════════════════════════════════════════════════════════

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const cp   = require('child_process');
const crypto = require('crypto');

const koffi = require(path.join(__dirname, '..', 'ui', 'node_modules', 'koffi'));

// ─── Win32 bindings via koffi ─────────────────────────────────
const kernel32 = koffi.load('kernel32.dll');

// STARTUPINFOW layout (we pass pointer to 104 bytes zeroed except cb).
// For a probe we don't need to fill in dwFlags/hStdInput etc.; CreateProcess
// accepts a mostly-zero STARTUPINFOW just fine.
const PROCESS_INFORMATION = koffi.struct('PROCESS_INFORMATION', {
  hProcess:    'void*',
  hThread:     'void*',
  dwProcessId: 'uint32',
  dwThreadId:  'uint32',
});

const CreateProcessW = kernel32.func('bool __stdcall CreateProcessW(' +
  'str16 lpApplicationName, void* lpCommandLine, void* lpProcessAttributes,' +
  'void* lpThreadAttributes, bool bInheritHandles, uint32 dwCreationFlags,' +
  'void* lpEnvironment, str16 lpCurrentDirectory, void* lpStartupInfo,' +
  '_Out_ PROCESS_INFORMATION* lpProcessInformation)');

const GetLastError = kernel32.func('uint32 __stdcall GetLastError()');
const CloseHandle  = kernel32.func('bool __stdcall CloseHandle(void* h)');
const TerminateProcess = kernel32.func('bool __stdcall TerminateProcess(void* h, uint32 exitCode)');
const FormatMessageW = kernel32.func('uint32 __stdcall FormatMessageW(' +
  'uint32 dwFlags, void* lpSource, uint32 dwMessageId, uint32 dwLanguageId,' +
  'void* lpBuffer, uint32 nSize, void* Arguments)');

const CREATE_NO_WINDOW = 0x08000000;

// Human-readable name for the common Win32 errors we might see here.
function winErrorName(code) {
  const names = {
      2: 'ERROR_FILE_NOT_FOUND',
      3: 'ERROR_PATH_NOT_FOUND',
      5: 'ERROR_ACCESS_DENIED',
     32: 'ERROR_SHARING_VIOLATION',
    193: 'ERROR_BAD_EXE_FORMAT',
    225: 'ERROR_VIRUS_INFECTED  <-- Defender/AV blocked execution',
    226: 'ERROR_VIRUS_DELETED   <-- Defender quarantined the exe',
    740: 'ERROR_ELEVATION_REQUIRED',
    577: 'ERROR_INVALID_IMAGE_HASH <-- WDAC / Code Integrity block',
    720: 'ERROR_IMAGE_MACHINE_TYPE_MISMATCH',
   1260: 'ERROR_ACCESS_DISABLED_BY_POLICY <-- SRP/AppLocker',
   1920: 'ERROR_CANT_ACCESS_FILE',
   1921: 'ERROR_CANT_RESOLVE_FILENAME',
   2147942632: 'ERROR_CODE_INTEGRITY_IMAGE_CORRUPT',
  };
  if (names[code]) return names[code];
  // SmartScreen / Smart App Control facility 0x29 (ApplicationHost).
  if (code === 0x80070830) return 'ERROR_SMARTSCREEN_BLOCKED (0x80070830)';
  if (code === 0x80073CFF) return 'APPX_E_PACKAGE_UNSIGNED';
  return '(unknown Win32 code)';
}

function describeWinError(code) {
  // Prefer FormatMessageW's own text if available.
  try {
    const buf = Buffer.alloc(2048);
    const FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
    const chars = FormatMessageW(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      null, code, 0, buf, buf.length / 2, null);
    if (chars > 0) {
      const s = buf.slice(0, chars * 2).toString('utf16le').trim();
      return s;
    }
  } catch (_) {}
  return '(no FormatMessage text)';
}

function nativeSpawn(exePath, args) {
  // CommandLineW must be mutable (CreateProcessW may modify it).
  // Build a quoted command line manually.
  const cl = ['"' + exePath + '"'].concat(args.map(a => '"' + String(a).replace(/"/g, '\\"') + '"')).join(' ');
  const clBuf = Buffer.from(cl + '\0', 'utf16le');

  // STARTUPINFOW is 104 bytes on x64; cb at offset 0.
  const si = Buffer.alloc(104);
  si.writeUInt32LE(104, 0);

  const pi = {};
  const ok = CreateProcessW(
    exePath, clBuf, null, null, false, CREATE_NO_WINDOW,
    null, path.dirname(exePath), si, pi);

  if (!ok) {
    const gle = GetLastError();
    return { ok: false, win32: gle, name: winErrorName(gle), desc: describeWinError(gle) };
  }
  // Clean up: terminate the probe process so --status fully executes/exits on its own.
  // Actually sihost --status just OpenEvents + returns; it should exit cleanly in ~50ms.
  // Give it a beat, then close handles.
  setTimeout(() => {
    try { CloseHandle(pi.hThread); } catch (_) {}
    try { CloseHandle(pi.hProcess); } catch (_) {}
  }, 500);
  return { ok: true, pid: pi.dwProcessId };
}

async function nodeSpawn(exePath, args, shell) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (r) => { if (!settled) { settled = true; resolve(r); } };
    let child;
    try {
      child = cp.spawn(exePath, args, {
        windowsHide: true,
        stdio: 'ignore',
        shell: !!shell,
      });
    } catch (e) {
      return finish({ threw: true, code: e.code, errno: e.errno, message: e.message, syscall: e.syscall });
    }
    const to = setTimeout(() => {
      try { child.kill(); } catch (_) {}
      finish({ threw: false, exit: null, note: 'timeout' });
    }, 5000);
    child.on('error', (e) => { clearTimeout(to); finish({ threw: false, errorEvent: { code: e.code, errno: e.errno, message: e.message, syscall: e.syscall } }); });
    child.on('exit', (code, signal) => { clearTimeout(to); finish({ threw: false, exit: code, signal }); });
  });
}

function psOneLiner(cmd) {
  try {
    const r = cp.spawnSync('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', cmd],
      { encoding: 'utf8', timeout: 20000, windowsHide: true });
    if (r.error) return '(ps spawn err: ' + r.error.message + ')';
    return (r.stdout || '').trim() + (r.stderr && r.stderr.trim() ? ' | STDERR: ' + r.stderr.trim() : '');
  } catch (e) { return '(ps threw: ' + e.message + ')'; }
}

async function main() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  svcldb spawn-UNKNOWN reproduction probe                     ║');
  console.log('║  (isolates which Windows security layer rejects CreateProc.) ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  // ─── Security stance ───────────────────────────────────────
  console.log('── 1. Current security stance ──');
  console.log('SmartAppControlState:   ', psOneLiner(`(Get-MpComputerStatus).SmartAppControlState`));
  console.log('RealTimeProtection:     ', psOneLiner(`(Get-MpComputerStatus).RealTimeProtectionEnabled`));
  console.log('IsTamperProtected:      ', psOneLiner(`(Get-MpComputerStatus).IsTamperProtected`));
  console.log('EnableControlledFolder: ', psOneLiner(`(Get-MpPreference).EnableControlledFolderAccess`));
  const pathsOut = psOneLiner(`(Get-MpPreference).ExclusionPath -join ';'`);
  console.log('ExclusionPath (filtered svcldb):',
    pathsOut.split(';').filter(s => /WinAudioSvc|CloakGPT|svcldb/i.test(s)).join(' | ') || '(none)');
  const procsOut = psOneLiner(`(Get-MpPreference).ExclusionProcess -join ';'`);
  console.log('ExclusionProcess (filtered svcldb):',
    procsOut.split(';').filter(s => /sihost|svchelper|dllhost32|dwmapiext/i.test(s)).join(' | ') || '(none)');
  console.log('');

  // ─── Control: run the already-excluded sihost.exe ──────────
  const canonical = 'C:\\ProgramData\\WinAudioSvc\\sihost.exe';
  if (!fs.existsSync(canonical)) {
    console.error('[fatal] canonical sihost.exe missing at ' + canonical);
    console.error('        Deploy a build first (see AGENTS.md fast testing launch).');
    process.exit(2);
  }

  console.log('── 2. CONTROL: spawn canonical excluded sihost.exe ──');
  console.log('   path:', canonical);
  const ctlNode = await nodeSpawn(canonical, ['--status'], false);
  console.log('   node spawn():       ', JSON.stringify(ctlNode));
  const ctlShell = await nodeSpawn(canonical, ['--status'], true);
  console.log('   node spawn({shell}):', JSON.stringify(ctlShell));
  const ctlNative = nativeSpawn(canonical, ['--status']);
  console.log('   native CreateProcessW:', JSON.stringify(ctlNative));
  console.log('');

  // ─── Repro: copy sihost to a non-excluded scratch path ─────
  const scratchDir = path.join(os.tmpdir(), 'svcldb_spawnrepro_' + crypto.randomBytes(4).toString('hex'));
  fs.mkdirSync(scratchDir, { recursive: true });
  const scratchExe = path.join(scratchDir, 'sihost.exe');
  try {
    fs.copyFileSync(canonical, scratchExe);
  } catch (e) {
    console.error('[fatal] copy to scratch failed: ' + e.message);
    console.error('   (CFA may be blocking write into %TEMP% — rare but possible.)');
    process.exit(3);
  }

  console.log('── 3. REPRO: spawn COPY in non-excluded path ──');
  console.log('   path:', scratchExe);
  console.log('   size:', fs.statSync(scratchExe).size, 'bytes');

  // Small delay to let Defender's realtime scan react.
  await new Promise(r => setTimeout(r, 1500));

  // Check whether the file is STILL there (Defender may have quarantined already).
  if (!fs.existsSync(scratchExe)) {
    console.log('   >>> AV quarantined the scratch copy before we spawned it (classic). <<<');
  } else {
    try {
      const sz = fs.statSync(scratchExe).size;
      console.log('   post-copy size (same=' + (sz === fs.statSync(canonical).size) + '):', sz);
    } catch (e) {
      console.log('   stat scratch failed:', e.message);
    }
  }

  const rNode = await nodeSpawn(scratchExe, ['--status'], false);
  console.log('   node spawn():       ', JSON.stringify(rNode));

  const rShell = await nodeSpawn(scratchExe, ['--status'], true);
  console.log('   node spawn({shell}):', JSON.stringify(rShell));

  // Native CreateProcessW — captures the TRUE Win32 error libuv is hiding.
  const rNative = nativeSpawn(scratchExe, ['--status']);
  console.log('   native CreateProcessW:', JSON.stringify(rNative));
  if (!rNative.ok) {
    console.log('   >>> ground-truth Win32 error:', rNative.win32, '(' + rNative.name + ')');
    console.log('   >>> system message: "' + rNative.desc + '"');
  }

  // ─── Try the two known-safe fallback launch paths ──────────
  console.log('\n── 4. FALLBACK experiments (if primary spawn failed) ──');

  // (a) ShellExecute via Start-Process -- goes through Shell handlers, may bypass what spawn hits.
  console.log('   (a) ShellExecute via PowerShell Start-Process -Wait ...');
  const psRes = psOneLiner(
    "try { Start-Process -FilePath '" + scratchExe.replace(/'/g, "''") +
    "' -ArgumentList '--status' -Wait -WindowStyle Hidden -PassThru | Select-Object ExitCode | ConvertTo-Json } " +
    "catch { 'ERR:' + $_.Exception.Message }"
  );
  console.log('       result:', psRes);

  // (b) cmd.exe wrapper -- CreateProcess on cmd.exe (always allowed), cmd then calls CreateProcess on sihost
  console.log('   (b) cmd.exe /c <scratchExe> --status ...');
  const cmdRes = await nodeSpawn(process.env.ComSpec || 'cmd.exe', ['/c', scratchExe, '--status'], false);
  console.log('       result:', JSON.stringify(cmdRes));

  // Clean up.
  try { fs.unlinkSync(scratchExe); } catch (_) {}
  try { fs.rmdirSync(scratchDir); } catch (_) {}

  console.log('\n── 5. VERDICT ──');
  const lineForNode = JSON.stringify(rNode);
  if (lineForNode.includes('UNKNOWN')) {
    console.log('  ✓ Reproduced "spawn UNKNOWN" on the non-excluded path.');
    if (rNative && !rNative.ok) {
      console.log('    Underlying Win32 error:', rNative.win32, rNative.name);
      console.log('    Mitigation plan: fallback to ShellExecute/schtasks path when spawn');
      console.log('    throws UNKNOWN *and* the file is on disk, so legit AV-driven');
      console.log('    blocks surface a user-friendly error instead of a mystery crash.');
    }
  } else if (lineForNode.includes('ENOENT')) {
    console.log('  AV deleted the copied exe before spawn (ERROR_VIRUS_DELETED).');
    console.log('  Fix path: re-copy from bundle + add inline exclusion + retry.');
  } else {
    console.log('  Could NOT reproduce "spawn UNKNOWN" with this stance.');
    console.log('  Likely the failing user has a stance we haven\'t matched yet');
    console.log('  (e.g. Tamper Protection ON + exclusion never registered,');
    console.log('   or a third-party EDR). Rerun with --no-exclusion to force.');
  }
}

main().catch((e) => { console.error('[fatal]', e && e.stack || e); process.exit(1); });
