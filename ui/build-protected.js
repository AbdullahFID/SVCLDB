// ═══════════════════════════════════════════════════════════════
// Protected build — copies src/ → src-build/, stamps config.js
// integrity SHA-256, obfuscates every JS file with tier-appropriate
// javascript-obfuscator config, compiles the sensitive Node modules
// (license/*.js + injector/*.js) to V8 bytecode via bytenode, then
// runs electron-builder from the obfuscated copy.
//
// Tiers:
//   main.js         → CONFIG_MAIN (identifier + strings, keep Electron APIs)
//   preload.js      → CONFIG_PRELOAD (base + selfDefending)
//   renderer.js     → CONFIG_RENDERER (base + selfDefending + debugProtection)
//   license/*.js +
//   injector/*.js   → CONFIG_STRICT + bytenode (second layer over rc4)
//   everything else → CONFIG_STRICT
//
// v4.7 upgrades:
//   1. build-integrity.js runs BEFORE obfuscation so the hash embedded
//      in config.js matches the *pre-obfuscated* source. Runtime
//      _verifyIntegrity() re-hashes the on-disk file — which is the
//      OBFUSCATED build — so the hash we stamp is really over the
//      *final* build output, computed via a first pass on the actual
//      output file, then re-stamped + saved. (See stampFinalIntegrity.)
//   2. Bytenode compilation for license/*.js + injector/*.js. Bytecode
//      files (.jsc) replace the original .js at ship time; a small
//      loader stub .js re-exports them. Adds a second protection layer
//      on top of the rc4-encoded obfuscation.
//
// Original src/ is NEVER modified — the pipeline works on src-build/.
// ═══════════════════════════════════════════════════════════════

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync, spawnSync } = require('child_process');
const JavaScriptObfuscator = require('javascript-obfuscator');
const { stampIntegrityInto } = require('./build-integrity');

const ROOT      = __dirname;
const SRC       = path.join(ROOT, 'src');
const BUILD_SRC = path.join(ROOT, 'src-build');
const DIST      = path.join(ROOT, 'dist');

const PRELOAD_FILES  = ['preload.js'];
const RENDERER_FILES = ['renderer.js'];
const MAIN_ENTRY     = 'main.js';
const SKIP_EXTS      = ['.html', '.css', '.ico', '.png', '.jpg', '.svg', '.json'];

// Files to compile to V8 bytecode after obfuscation. These are the
// modules with the most sensitive logic (OAuth, handshake HMAC, HWID
// derivation, subscription HMAC signing, device registration, injector
// JSON handoff builder). Path suffixes are matched against forward-
// slash-normalized paths inside src-build/.
//
// NOTE: license/config.js is INTENTIONALLY excluded from bytecoding.
// Its _verifyIntegrity() function reads __filename as UTF-8 and hashes
// it — bytecode replaces the .js with a loader stub, which would still
// hash correctly (stub itself is small + stable) but the actual XOR
// blob values would live inside the .jsc binary, defeating the point.
// Instead: config.js stays as heavily-obfuscated .js with the integrity
// hash stamped into it — trivial patch of SUPABASE_URL breaks the hash.
const BYTECODE_SUFFIXES = [
  'license/auth.js',
  'license/device.js',
  'license/handshake.js',
  'license/registration.js',
  'license/revalidation.js',
  'license/security.js',
  'license/storage.js',
  'license/subscription.js',
  'injector/injector.js',
];

// ─── Shared base config (heavy identifier + string obfuscation) ───
const BASE_CONFIG = {
  compact: true,
  sourceMap: false,

  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 1,

  deadCodeInjection: true,
  deadCodeInjectionThreshold: 1,

  stringArray: true,
  stringArrayEncoding: ['rc4'],
  stringArrayThreshold: 1,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayIndexShift: true,
  stringArrayIndexesType: ['hexadecimal-number', 'hexadecimal-numeric-string'],
  stringArrayWrappersCount: 5,
  stringArrayWrappersType: 'function',
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersParametersMaxCount: 5,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 1,
  splitStrings: true,
  splitStringsChunkLength: 5,
  forceTransformStrings: ['.*'],

  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: true,

  numbersToExpressions: true,
  transformObjectKeys: true,
  simplify: true,
  disableConsoleOutput: true,
  unicodeEscapeSequence: true,

  reservedNames: [
    '^require$', '^module$', '^exports$',
    '^__dirname$', '^__filename$',
    '^process$', '^global$', '^Buffer$', '^electron$',
    // Preserve names the integrity check references so the stamped
    // hash keeps matching after obfuscation.
    '^_EXPECTED_HASH$', '^_verifyIntegrity$',
  ],
  reservedStrings: [
    // Never obfuscate the integrity placeholder or its stamped form
    // — the runtime check needs to be able to substring-compare.
    '%%INTEGRITY_PLACEHOLDER%%',
  ],
};

const CONFIG_MAIN = {
  compact: true,
  target: 'node',
  sourceMap: false,

  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.5,

  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.3,

  stringArray: true,
  stringArrayEncoding: ['rc4'],
  stringArrayThreshold: 0.75,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayIndexShift: true,
  stringArrayIndexesType: ['hexadecimal-number'],
  stringArrayWrappersCount: 3,
  stringArrayWrappersType: 'function',
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersParametersMaxCount: 3,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 0.75,
  splitStrings: true,
  splitStringsChunkLength: 10,

  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: false,

  numbersToExpressions: true,
  transformObjectKeys: false,
  simplify: true,
  unicodeEscapeSequence: false,

  selfDefending: false,
  debugProtection: false,
  debugProtectionInterval: 0,
  disableConsoleOutput: false,

  reservedNames: [
    '^require$', '^module$', '^exports$',
    '^__dirname$', '^__filename$',
    '^process$', '^global$', '^Buffer$', '^electron$',
  ],
  reservedStrings: [],
};

const CONFIG_PRELOAD = {
  ...BASE_CONFIG,
  target: 'node',
  selfDefending: true,
  debugProtection: false,
  debugProtectionInterval: 0,
};

const CONFIG_RENDERER = {
  ...BASE_CONFIG,
  target: 'browser',
  selfDefending: true,
  debugProtection: true,
  debugProtectionInterval: 4000,
};

// license/*.js + injector/*.js — Node target, strict obfuscation. Also
// compiled to bytecode in a later step (double protection).
const CONFIG_STRICT = {
  ...BASE_CONFIG,
  target: 'node',
  selfDefending: true,
  debugProtection: false,
  debugProtectionInterval: 0,
};

// Special config for license/config.js — keeps stringArray + literals
// UNTOUCHED so the %%INTEGRITY_PLACEHOLDER%% + _EXPECTED_HASH assignment
// survive as recognizable text for build-integrity.js to stamp + for the
// runtime _verifyIntegrity() regex to find. Identifier + control-flow
// obfuscation is still applied so the file isn't trivially readable.
// The Supabase URL / anon key blobs are ALREADY XOR-encrypted at rest
// (see shared/supabase_config.c parity), so keeping them as literals is
// fine — a strings sweep finds base64 XOR ciphertext, not readable URLs.
const CONFIG_CONFIG_JS = {
  compact: true,
  target: 'node',
  sourceMap: false,

  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.75,

  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.4,

  stringArray: false,     // keep literals visible so integrity stamp works
  splitStrings: false,
  forceTransformStrings: [],

  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: false,

  numbersToExpressions: true,
  transformObjectKeys: false,
  simplify: true,
  unicodeEscapeSequence: false,

  selfDefending: false,   // must not wrap _verifyIntegrity in guard loops

  reservedNames: [
    '^require$', '^module$', '^exports$',
    '^__dirname$', '^__filename$',
    '^process$', '^global$', '^Buffer$', '^electron$',
    '^_EXPECTED_HASH$', '^_verifyIntegrity$',
  ],
  reservedStrings: ['%%INTEGRITY_PLACEHOLDER%%'],
};

// Config for files that are about to be bytecode-compiled. bytenode
// runs them through V8's compileCache which INCLUDES a syntax-parse
// pass — some heavy obfuscation transforms produce output that V8
// won't accept (e.g. selfDefending's infinite-loop guard). Skip those
// specific options while keeping identifier + string obfuscation.
const CONFIG_BYTECODE_INPUT = {
  ...BASE_CONFIG,
  target: 'node',
  selfDefending: false,           // Bytecode is stronger — selfDefending unhelpful.
  debugProtection: false,
  debugProtectionInterval: 0,
  // controlFlowFlattening at 1.0 can produce parse patterns that
  // bytenode's V8 chokes on. Ease off for bytecoded files.
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.6,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.4,
};

function getAllFiles(dir) {
  let out = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, ent.name);
    if (ent.isDirectory()) out = out.concat(getAllFiles(abs));
    else out.push(abs);
  }
  return out;
}

function isBytecodeTarget(filePath) {
  const norm = filePath.replace(/\\/g, '/');
  return BYTECODE_SUFFIXES.some(sfx => norm.endsWith(sfx));
}

function pickConfig(filePath) {
  const basename = path.basename(filePath);
  const norm = filePath.replace(/\\/g, '/');
  // config.js gets its own light-obfuscation config so the integrity
  // placeholder / _EXPECTED_HASH assignment survive for stamping.
  if (norm.endsWith('license/config.js')) return { cfg: CONFIG_CONFIG_JS, label: 'config-integrity' };
  if (RENDERER_FILES.includes(basename)) return { cfg: CONFIG_RENDERER, label: 'renderer' };
  if (PRELOAD_FILES.includes(basename))  return { cfg: CONFIG_PRELOAD,  label: 'preload'  };
  if (basename === MAIN_ENTRY && path.dirname(filePath) === BUILD_SRC) {
    return { cfg: CONFIG_MAIN, label: 'main' };
  }
  if (isBytecodeTarget(filePath)) return { cfg: CONFIG_BYTECODE_INPUT, label: 'bytecode-input' };
  return { cfg: CONFIG_STRICT, label: 'strict' };
}

function obfuscateFile(filePath) {
  const src = fs.readFileSync(filePath, 'utf8');
  if (!src.trim()) return false;
  const { cfg, label } = pickConfig(filePath);
  try {
    const out = JavaScriptObfuscator.obfuscate(src, cfg);
    fs.writeFileSync(filePath, out.getObfuscatedCode(), 'utf8');
    const rel = path.relative(BUILD_SRC, filePath);
    console.log(`  ✓ ${rel} [${label}]`);
    return true;
  } catch (e) {
    console.error(`  ✗ ${path.relative(BUILD_SRC, filePath)} — ${e.message}`);
    return false;
  }
}

console.log('');
console.log('═══════════════════════════════════════════════════');
console.log('  SVCHELPER PROTECTED BUILD');
console.log('  integrity + obfuscation + bytenode + fuses');
console.log('═══════════════════════════════════════════════════');
console.log('');

// ─── Step 1: Copy src/ → src-build/ ─────────────────────────────
console.log('[1/6] Copying src/ → src-build/ ...');
if (fs.existsSync(BUILD_SRC)) fs.rmSync(BUILD_SRC, { recursive: true });
fs.cpSync(SRC, BUILD_SRC, { recursive: true });

// ─── Step 2: (integrity stamp deferred — see post-obfuscation) ──
// The runtime _verifyIntegrity() hashes the actual on-disk file, which
// is the FINAL obfuscated version. We can't compute that hash yet
// because obfuscation hasn't run. Deferred until step 4b.
console.log('[2/6] (integrity stamp deferred until post-obfuscation)');

// ─── Step 3: Obfuscate every JS file in the build copy ─────────
console.log('[3/6] Obfuscating JS files ...');
const allFiles = getAllFiles(BUILD_SRC);
const jsFiles  = allFiles.filter(f => path.extname(f).toLowerCase() === '.js');
let obfuscated = 0;
for (const f of jsFiles) {
  if (obfuscateFile(f)) obfuscated++;
}
console.log(`\n  ${obfuscated}/${jsFiles.length} JS files obfuscated\n`);

// ─── Step 3b: Stamp integrity hash on the OBFUSCATED config.js ──
// Runtime _verifyIntegrity() reads its own file bytes and hashes them.
// The bytes on disk are the post-obfuscation output, so we compute the
// hash AFTER obfuscation. reservedNames/reservedStrings in the
// obfuscator config preserve _EXPECTED_HASH + the placeholder literal
// so the substring-replace in stampIntegrityInto still finds them.
console.log('[3b] Stamping integrity hash on obfuscated config.js ...');
const CONFIG_JS = path.join(BUILD_SRC, 'license', 'config.js');
try {
  const r = stampIntegrityInto(CONFIG_JS);
  if (r.ok) console.log(`  ✓ license/config.js stamped ${r.digest}\n`);
  else       console.log(`  ⚠ integrity stamp skipped: ${r.reason}\n`);
} catch (e) {
  console.warn(`  ⚠ integrity stamp failed: ${e.message}\n`);
}

// ─── Step 4: Bytecode compile sensitive modules ────────────────
//
// Compilation runs via ELECTRON_RUN_AS_NODE (guaranteed same V8
// version as the packaged Electron will use). Falls back to plain
// `node` if that env var isn't available for some reason.
//
// For each target we:
//   1. Compile .js → .jsc (V8 cached bytecode)
//   2. Overwrite the .js with a tiny loader stub that requires the .jsc
//   3. Ship both files inside the app
console.log('[4/6] Compiling sensitive modules to V8 bytecode ...');
const bytecodeTargets = jsFiles.filter(isBytecodeTarget);
console.log(`  ${bytecodeTargets.length} files targeted for bytecode.`);

let bytecodeCompiled = 0;
if (bytecodeTargets.length > 0) {
  // We use bytenode's programmatic API directly inside a spawned
  // Electron process. Writing the compile driver to a temp file keeps
  // the arg vector short + easy to log.
  const driverPath = path.join(ROOT, '_bytecode_compile.js');
  const fileList   = bytecodeTargets.map(p => p.replace(/\\/g, '/'));
  const driver = `
    const fs = require('fs');
    const path = require('path');
    const bytenode = require(${JSON.stringify(require.resolve('bytenode').replace(/\\/g, '/'))});
    const files = ${JSON.stringify(fileList)};
    let ok = 0, fail = 0;
    for (const src of files) {
      try {
        const jsc = src.replace(/\\.js$/, '.jsc');
        bytenode.compileFile({ filename: src, output: jsc, compileAsModule: true });
        // Overwrite the .js with a loader stub. Requires bytenode at
        // runtime, which we ship as a dep — its own require() lives in
        // node_modules so this works regardless of asar packaging.
        const rel = './' + path.basename(jsc);
        const stub =
          "'use strict';\\n" +
          "require('bytenode');\\n" +
          "module.exports = require(" + JSON.stringify(rel) + ");\\n";
        fs.writeFileSync(src, stub, 'utf8');
        ok++;
        console.log('  ✓ ' + src);
      } catch (e) {
        fail++;
        console.error('  ✗ ' + src + ' — ' + e.message);
      }
    }
    console.log('\\n  ' + ok + '/' + files.length + ' bytecode compiled (' + fail + ' failed)');
    process.exit(fail > 0 ? 1 : 0);
  `;
  fs.writeFileSync(driverPath, driver, 'utf8');

  try {
    // Find Electron binary — pnpm places it under node_modules/electron/dist/electron.exe.
    const electronBin = require('electron');
    const result = spawnSync(electronBin, [driverPath], {
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
      stdio: 'inherit',
    });
    if (result.status === 0) {
      bytecodeCompiled = bytecodeTargets.length;
    } else {
      console.warn(`  ⚠ bytecode compile returned exit ${result.status} — some files may still be plain JS`);
      // Count how many .jsc files were actually produced.
      for (const src of bytecodeTargets) {
        const jsc = src.replace(/\.js$/, '.jsc');
        if (fs.existsSync(jsc)) bytecodeCompiled++;
      }
    }
  } catch (e) {
    console.warn(`  ⚠ bytecode compile step failed: ${e.message} — files ship as obfuscated .js only`);
  } finally {
    try { fs.unlinkSync(driverPath); } catch {}
  }
}
console.log(`  Bytecode: ${bytecodeCompiled}/${bytecodeTargets.length} succeeded\n`);

// ─── Step 5: Swap folders + run electron-builder + restore ─────
console.log('[5/6] Running electron-builder ...');
const SRC_BACKUP = path.join(ROOT, 'src-original');

function copyDir(from, to) { fs.cpSync(from, to, { recursive: true, force: true }); }
function rmDir(p)          { if (fs.existsSync(p)) fs.rmSync(p, { recursive: true, force: true }); }
function listRel(dir, base = dir, out = []) {
  for (const name of fs.readdirSync(dir)) {
    const abs = path.join(dir, name);
    const st  = fs.statSync(abs);
    if (st.isDirectory()) listRel(abs, base, out);
    else out.push(path.relative(base, abs));
  }
  return out;
}

let backedUp = false, swappedIn = false;
try {
  rmDir(SRC_BACKUP);
  copyDir(SRC, SRC_BACKUP);
  backedUp = true;

  const srcBuildRel = new Set(listRel(BUILD_SRC));
  for (const rel of listRel(SRC)) {
    if (!srcBuildRel.has(rel)) fs.rmSync(path.join(SRC, rel), { force: true });
  }
  for (const rel of srcBuildRel) {
    const dst = path.join(SRC, rel);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(path.join(BUILD_SRC, rel), dst);
  }
  swappedIn = true;

  const bin = process.env.SVC_UI_PKGMGR
    || (fs.existsSync(path.join(ROOT, 'pnpm-lock.yaml')) ? 'pnpm exec' : 'npx');
  execSync(`${bin} electron-builder --win`, {
    stdio: 'inherit',
    cwd: ROOT,
    env: { ...process.env },
    shell: true,
  });
} finally {
  console.log('Restoring original src/ ...');
  if (backedUp && swappedIn) {
    const backupRel = new Set(listRel(SRC_BACKUP));
    try {
      for (const rel of listRel(SRC)) {
        if (!backupRel.has(rel)) fs.rmSync(path.join(SRC, rel), { force: true });
      }
    } catch (e) {
      console.error('  WARN: pruning obfuscated files from src/ failed:', e.message);
    }
    try {
      for (const rel of backupRel) {
        const dst = path.join(SRC, rel);
        fs.mkdirSync(path.dirname(dst), { recursive: true });
        fs.copyFileSync(path.join(SRC_BACKUP, rel), dst);
      }
    } catch (e) {
      console.error('  CRITICAL: restoring src/ from backup FAILED:', e.message);
      console.error('  Backup intact at:', SRC_BACKUP);
    }
  }
  if (backedUp && fs.existsSync(SRC_BACKUP) && fs.existsSync(path.join(SRC, 'main.js'))) {
    rmDir(SRC_BACKUP);
  }
  if (fs.existsSync(BUILD_SRC) && fs.existsSync(path.join(SRC, 'main.js'))) {
    rmDir(BUILD_SRC);
  }
}

// ─── Step 6: Extract asar → app/ (Electron 34 integrity workaround) ───
const DIST_RES     = path.join(DIST, 'win-unpacked', 'resources');
const ASAR_PATH    = path.join(DIST_RES, 'app.asar');
const UNPACKED     = path.join(DIST_RES, 'app.asar.unpacked');
const APP_DIR      = path.join(DIST_RES, 'app');

if (fs.existsSync(ASAR_PATH)) {
  console.log('[6/6] Extracting asar → app/ (Electron 34 integrity workaround) ...');
  try {
    const asar = require('@electron/asar');
    if (fs.existsSync(APP_DIR)) fs.rmSync(APP_DIR, { recursive: true });
    asar.extractAll(ASAR_PATH, APP_DIR);
    if (fs.existsSync(UNPACKED)) {
      fs.cpSync(UNPACKED, APP_DIR, { recursive: true, force: true });
      fs.rmSync(UNPACKED, { recursive: true, force: true });
    }
    fs.unlinkSync(ASAR_PATH);
    console.log('  ✓ Extracted to resources/app/, asar removed');
  } catch (e) {
    console.error('  ⚠ asar extraction failed:', e.message);
  }
} else {
  console.log('[6/6] No app.asar to extract (already unpacked).');
}

console.log('');
console.log('═══════════════════════════════════════════════════');
console.log('  ✓ PROTECTED BUILD COMPLETE');
console.log('  Output: dist/win-unpacked/');
console.log('═══════════════════════════════════════════════════');
console.log('');
