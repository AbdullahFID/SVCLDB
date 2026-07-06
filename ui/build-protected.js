// ═══════════════════════════════════════════════════════════════
// Protected build — copies src/ → src-build/, obfuscates every JS
// file with tier-appropriate javascript-obfuscator config, then
// runs electron-builder from the obfuscated copy. The original src/
// is untouched so `npm start` still shows clean code for dev.
//
// Tiers:
//   main.js         → CONFIG_MAIN (identifier + strings, keep Electron APIs)
//   preload.js      → CONFIG_PRELOAD (base + selfDefending)
//   renderer.js     → CONFIG_RENDERER (base + selfDefending + debugProtection)
//   everything else → CONFIG_STRICT (base + selfDefending)
//
// Adapted from hooksdll/lumio/build-protected.js. Skips V8 bytecode
// compilation for simplicity + reliability — the four obfuscation
// tiers alone already destroy source readability. Bytenode can be
// added later without touching the rest of the pipeline.
// ═══════════════════════════════════════════════════════════════

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const JavaScriptObfuscator = require('javascript-obfuscator');

const ROOT      = __dirname;
const SRC       = path.join(ROOT, 'src');
const BUILD_SRC = path.join(ROOT, 'src-build');
const DIST      = path.join(ROOT, 'dist');

const PRELOAD_FILES  = ['preload.js'];
const RENDERER_FILES = ['renderer.js'];
const MAIN_ENTRY     = 'main.js';
const SKIP_EXTS      = ['.html', '.css', '.ico', '.png', '.jpg', '.svg', '.json'];

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
  ],
  reservedStrings: [],
};

// main.js needs LIGHT obfuscation — renameGlobals / transformObjectKeys
// break Electron API property access chains (app.commandLine.appendSwitch,
// BrowserWindow.on, etc). Keep identifier rename + string array (the
// actual protection); drop the transforms that bloat/break the entry.
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

  selfDefending: false,       // main.js can crash Electron if selfDefending's
                              // infinite-loop guard misfires during startup.
  debugProtection: false,     // debugProtection is target:'browser'-only.
  debugProtectionInterval: 0,
  disableConsoleOutput: false,

  reservedNames: [
    '^require$', '^module$', '^exports$',
    '^__dirname$', '^__filename$',
    '^process$', '^global$', '^Buffer$', '^electron$',
  ],
  reservedStrings: [],
};

// Preload runs in an isolated Node context but ships as readable JS.
// selfDefending triggers an infinite loop when the code is beautified
// or the anti-debugger detects a devtools attach — raises the RE bar.
// debugProtection is invalid for target:'node'.
const CONFIG_PRELOAD = {
  ...BASE_CONFIG,
  target: 'node',
  selfDefending: true,
  debugProtection: false,
  debugProtectionInterval: 0,
};

// Renderer runs in the Chromium browser context — both selfDefending
// AND debugProtection are valid + effective there.
const CONFIG_RENDERER = {
  ...BASE_CONFIG,
  target: 'browser',
  selfDefending: true,
  debugProtection: true,
  debugProtectionInterval: 4000,
};

// license/*.js + injector/*.js — Node target, strict obfuscation.
// These carry the OAuth flow + handshake HMAC. Hardest tier we can
// safely apply without breaking Electron APIs.
const CONFIG_STRICT = {
  ...BASE_CONFIG,
  target: 'node',
  selfDefending: true,
  debugProtection: false,
  debugProtectionInterval: 0,
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

function pickConfig(filePath) {
  const basename = path.basename(filePath);
  if (RENDERER_FILES.includes(basename)) return { cfg: CONFIG_RENDERER, label: 'renderer' };
  if (PRELOAD_FILES.includes(basename))  return { cfg: CONFIG_PRELOAD,  label: 'preload'  };
  if (basename === MAIN_ENTRY && path.dirname(filePath) === BUILD_SRC) {
    return { cfg: CONFIG_MAIN, label: 'main' };
  }
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
console.log('  Obfuscation + selfDefending + fuses');
console.log('═══════════════════════════════════════════════════');
console.log('');

// ─── Step 1: Copy src/ → src-build/ ─────────────────────────────
console.log('[1/3] Copying src/ → src-build/ ...');
if (fs.existsSync(BUILD_SRC)) fs.rmSync(BUILD_SRC, { recursive: true });
fs.cpSync(SRC, BUILD_SRC, { recursive: true });

// ─── Step 2: Obfuscate every JS file in the build copy ─────────
console.log('[2/3] Obfuscating JS files ...');
const allFiles = getAllFiles(BUILD_SRC);
const jsFiles  = allFiles.filter(f => path.extname(f).toLowerCase() === '.js');
let obfuscated = 0;
for (const f of jsFiles) {
  if (obfuscateFile(f)) obfuscated++;
}
console.log(`\n  ${obfuscated}/${jsFiles.length} JS files obfuscated\n`);

// ─── Step 3: Swap folders + run electron-builder + restore ─────
//
// Same in-place file-swap dance hooksdll uses: can't rename() src/ on
// Windows when an editor's file watcher holds the directory handle,
// so we back the originals up to src-original/, overlay the obfuscated
// copy onto src/, invoke electron-builder, then restore.
console.log('[3/3] Running electron-builder ...');
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

  // Use `pnpm exec` when available (repo is pnpm-managed), fall through
  // to `npx` only if pnpm is missing. Never assume a specific package
  // manager is on PATH — both work here.
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

// ─── Step 4: Extract asar → app/ (Electron 34 integrity workaround) ───
const DIST_RES     = path.join(DIST, 'win-unpacked', 'resources');
const ASAR_PATH    = path.join(DIST_RES, 'app.asar');
const UNPACKED     = path.join(DIST_RES, 'app.asar.unpacked');
const APP_DIR      = path.join(DIST_RES, 'app');

if (fs.existsSync(ASAR_PATH)) {
  console.log('[post] Extracting asar → app/ (Electron 34 integrity workaround) ...');
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
}

console.log('');
console.log('═══════════════════════════════════════════════════');
console.log('  ✓ PROTECTED BUILD COMPLETE');
console.log('  Output: dist/win-unpacked/');
console.log('═══════════════════════════════════════════════════');
console.log('');
