// tools/sanitize_ascii.js
//
// Safe Node.js replacement for the botched PowerShell sanitizer.
// Replaces fancy Unicode punctuation with ASCII equivalents in C/C++/H
// source files, preserving BOM state + strict UTF-8 I/O.
//
// Usage:
//   node tools/sanitize_ascii.js --dry-run         # preview
//   node tools/sanitize_ascii.js                   # apply
//   node tools/sanitize_ascii.js --extra-js        # also process JS/HTML/JSON
//
// Scope (unconditional):
//   payload/src/**/*.{c,h,cpp}
//   launcher/src/**/*.{c,h,cpp}
//   resolver/src/**/*.{c,h,cpp}
//   shared/**/*.{c,h,cpp}     (excludes shared/imgui, shared/minhook)
// Exclusions:
//   any path containing '/test/' or '\\test\\'
//   payload/test/latex_test.c (Unicode LaTeX test cases)
//   shared/str_enc_generated*.{h,data.h}  (auto-generated blob, do not edit)
//   any *.replay-backup file
//
// Extra scope (with --extra-js):
//   ui/src/**/*.{js,html,css}
//   ui/*.json
//
// Substitutions (all only affect character classes below; no other bytes):
//   \u2014 (em-dash '\u2014') -> '--'
//   \u2013 (en-dash '\u2013') -> '-'
//   \u2192 (right arrow '\u2192') -> '->'
//   \u2190 (left arrow '\u2190')  -> '<-'
//   \u2018 (curly '`') -> "'"
//   \u2019 (curly ') -> "'"
//   \u201C (curly ") -> "\""
//   \u201D (curly ") -> "\""
//   \u2026 (ellipsis '\u2026') -> '...'
//   \u00A0 (nbsp) -> ' '
//   \u2022 (bullet '\u2022') -> '*'
//   \u2032 (prime '\u2032') -> "'"
//
// Encoding safety: reads bytes, detects UTF-8 BOM, decodes strictly (throws
// on invalid UTF-8), does the string replace, re-encodes to UTF-8 preserving
// BOM state. On any exception the file is left untouched.

'use strict';

const fs   = require('fs');
const path = require('path');

const REPO = path.resolve(__dirname, '..');

const map = {
  '\u2014': '--',
  '\u2013': '-',
  '\u2192': '->',
  '\u2190': '<-',
  '\u2018': "'",
  '\u2019': "'",
  '\u201C': '"',
  '\u201D': '"',
  '\u2026': '...',
  '\u00A0': ' ',
  '\u2022': '*',
  '\u2032': "'",
};
const re = new RegExp('[' + Object.keys(map).join('') + ']', 'g');

// Self-test: prove the substitution table maps every listed char correctly.
// If any assertion fails, exit BEFORE touching a single real file.
{
  const control = Object.keys(map).join('|');   // "\u2014|\u2013|..."
  const expected = Object.keys(map).map(k => map[k]).join('|');
  const out = control.replace(re, m => map[m]);
  if (out !== expected) {
    console.error('SELF-TEST FAILED — substitution table is broken');
    console.error('input   :', JSON.stringify(control));
    console.error('output  :', JSON.stringify(out));
    console.error('expected:', JSON.stringify(expected));
    process.exit(2);
  }
}
console.log('[selftest] substitution table OK');

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const extraJs = args.includes('--extra-js');

function walk(root, filter) {
  const out = [];
  function inner(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) inner(full);
      else if (e.isFile() && filter(full)) out.push(full);
    }
  }
  inner(root);
  return out;
}

function inScope(fullPath) {
  const rel = path.relative(REPO, fullPath).replace(/\\/g, '/');
  // Exclusions first
  if (rel.includes('/test/'))              return false;
  if (rel === 'payload/test/latex_test.c') return false;
  if (rel.startsWith('shared/imgui/'))     return false;
  if (rel.startsWith('shared/minhook/'))   return false;
  if (rel.endsWith('.replay-backup'))      return false;
  if (rel.includes('str_enc_generated'))   return false;
  // Skip build outputs
  if (rel.startsWith('build/'))            return false;
  if (rel.startsWith('ui/dist/'))          return false;
  if (rel.includes('node_modules'))        return false;
  return true;
}

const scope = ['payload/src', 'launcher/src', 'resolver/src', 'shared'];
const cExts = ['.c', '.h', '.cpp'];
const jsExts = ['.js', '.html', '.css', '.json'];

let files = [];
for (const s of scope) {
  const root = path.join(REPO, s);
  if (!fs.existsSync(root)) continue;
  files.push(...walk(root, p => cExts.includes(path.extname(p).toLowerCase()) && inScope(p)));
}
if (extraJs) {
  const ui = path.join(REPO, 'ui');
  if (fs.existsSync(ui)) {
    files.push(...walk(path.join(ui, 'src'), p => jsExts.includes(path.extname(p).toLowerCase()) && inScope(p)));
    // top-level ui/*.json (package.json etc.)
    for (const e of fs.readdirSync(ui, { withFileTypes: true })) {
      if (!e.isFile()) continue;
      if (!jsExts.includes(path.extname(e.name).toLowerCase())) continue;
      files.push(path.join(ui, e.name));
    }
  }
}

console.log(`files in scope: ${files.length}`);
console.log(`mode: ${dryRun ? 'DRY-RUN' : 'APPLY'}`);
console.log();

let touched = 0;
let totalReplacements = 0;
const utf8Strict = new (require('util').TextDecoder)('utf-8', { fatal: true });

for (const f of files) {
  let bytes;
  try { bytes = fs.readFileSync(f); }
  catch (e) { console.log(`  READ_FAIL ${f}: ${e.message}`); continue; }
  if (bytes.length === 0) continue;

  const hasBom = bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF;
  let text;
  try {
    text = utf8Strict.decode(hasBom ? bytes.subarray(3) : bytes);
  } catch (e) {
    console.log(`  SKIP (invalid UTF-8) ${path.relative(REPO, f).replace(/\\/g,'/')}`);
    continue;
  }

  let count = 0;
  const replaced = text.replace(re, m => { count++; return map[m]; });
  if (count === 0) continue;

  totalReplacements += count;
  touched++;
  const rel = path.relative(REPO, f).replace(/\\/g, '/');
  console.log(`  ${dryRun ? '[DRY]' : '[APPLY]'} ${rel}  (${count} substitutions)`);

  if (!dryRun) {
    let out;
    if (hasBom) {
      out = Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(replaced, 'utf8')]);
    } else {
      out = Buffer.from(replaced, 'utf8');
    }
    // Extra safety: re-decode strictly to make sure our output is valid UTF-8
    try { utf8Strict.decode(hasBom ? out.subarray(3) : out); }
    catch (e) {
      console.log(`    !!! GENERATED INVALID UTF-8 for ${rel} — SKIPPING WRITE`);
      continue;
    }
    fs.writeFileSync(f, out);
  }
}

console.log();
console.log(`=== SUMMARY ===`);
console.log(`files touched  : ${touched}`);
console.log(`replacements   : ${totalReplacements}`);
console.log(`mode           : ${dryRun ? 'DRY-RUN (nothing written)' : 'APPLIED'}`);
