// tools/replay_transcript.js
//
// Replays every StrReplace / Write / Delete tool_use from a Cursor
// agent-transcript JSONL onto the working tree. Applies in order.
//
// Usage:
//   node tools/replay_transcript.js <transcript.jsonl> [--dry-run]
//
// Design:
//   - Walks the JSONL line-by-line, parses each line as JSON.
//   - For assistant messages, iterates content[] entries with type=tool_use.
//   - For StrReplace: reads file, does first-occurrence replace, writes back.
//     If old_string not found, logs FAIL + skips (does not abort).
//   - For Write: writes new content (overwrite).
//   - For Delete: fs.unlink (best-effort).
//   - Emits a summary at the end: {ok, failed, total per file}.
//
// Safety:
//   - Backs up each touched file to <path>.replay-backup before first edit
//     (only if --dry-run is NOT set). Multiple edits to same file share
//     one backup (only backed up once).
//   - --dry-run does NOT modify anything; just prints what would happen.

'use strict';

const fs = require('fs');
const path = require('path');

function usage() {
  console.error('usage: node tools/replay_transcript.js <transcript.jsonl> [--dry-run] [--filter <substr>]');
  process.exit(2);
}

const args = process.argv.slice(2);
if (args.length < 1) usage();
const txPath = args[0];
const dryRun = args.includes('--dry-run');
const filterIdx = args.indexOf('--filter');
const pathFilter = (filterIdx >= 0 && args[filterIdx + 1]) ? args[filterIdx + 1] : null;
// --exclude may appear multiple times; each value is a substring match.
const excludes = [];
for (let i = 0; i < args.length - 1; i++) if (args[i] === '--exclude') excludes.push(args[i + 1]);

if (!fs.existsSync(txPath)) {
  console.error(`transcript not found: ${txPath}`);
  process.exit(1);
}

console.log(`replay transcript: ${txPath}`);
console.log(`dry-run: ${dryRun}`);
if (pathFilter) console.log(`path filter: contains "${pathFilter}"`);
console.log();

const raw = fs.readFileSync(txPath, 'utf8');
const lines = raw.split(/\r?\n/).filter(l => l.length > 0);
console.log(`transcript lines: ${lines.length}`);

// Collect all tool_use ops in order.
const ops = [];   // {tool, path, old_string?, new_string?, contents?}
let msgIdx = 0;
for (const line of lines) {
  msgIdx++;
  let j;
  try { j = JSON.parse(line); }
  catch { continue; }
  if (!j || j.role !== 'assistant') continue;
  const content = j.message && j.message.content;
  if (!Array.isArray(content)) continue;
  for (const c of content) {
    if (c.type !== 'tool_use') continue;
    const name = c.name;
    const inp  = c.input || {};
    if (name === 'StrReplace' && inp.path && typeof inp.old_string === 'string' && typeof inp.new_string === 'string') {
      ops.push({
        tool: 'StrReplace', msgIdx,
        path: inp.path,
        old_string: inp.old_string,
        new_string: inp.new_string,
        replace_all: !!inp.replace_all,
      });
    } else if (name === 'Write' && inp.path && typeof inp.contents === 'string') {
      ops.push({ tool: 'Write', msgIdx, path: inp.path, contents: inp.contents });
    } else if (name === 'Delete' && inp.path) {
      ops.push({ tool: 'Delete', msgIdx, path: inp.path });
    }
  }
}

console.log(`total file ops discovered: ${ops.length}`);
if (pathFilter) {
  const before = ops.length;
  const kept = ops.filter(o => o.path.includes(pathFilter));
  console.log(`  after path filter: ${kept.length}/${before}`);
  ops.length = 0;
  ops.push(...kept);
}
if (excludes.length) {
  const before = ops.length;
  const kept = ops.filter(o => !excludes.some(x => o.path.includes(x)));
  console.log(`  after excludes ${JSON.stringify(excludes)}: ${kept.length}/${before}`);
  ops.length = 0;
  ops.push(...kept);
}

// Group summary by path
const byPath = new Map();
for (const o of ops) {
  const entry = byPath.get(o.path) || { StrReplace: 0, Write: 0, Delete: 0 };
  entry[o.tool] = (entry[o.tool] || 0) + 1;
  byPath.set(o.path, entry);
}
console.log(`\nunique paths touched: ${byPath.size}`);
for (const [p, counts] of byPath) {
  const rel = p.replace(/^C:\\Users\\abdul\\Desktop\\svcldb\\/i, '').replace(/\\/g, '/');
  const parts = [];
  if (counts.StrReplace) parts.push(`StrReplace x${counts.StrReplace}`);
  if (counts.Write)      parts.push(`Write x${counts.Write}`);
  if (counts.Delete)     parts.push(`Delete x${counts.Delete}`);
  console.log(`  ${rel}  |  ${parts.join(', ')}`);
}

if (dryRun) {
  console.log('\n[DRY RUN] not applying any changes');
  process.exit(0);
}

// Apply
const backedUp = new Set();
const result = { ok: 0, missing_old: 0, write_fail: 0, no_file: 0, deleted: 0 };
const failures = [];
for (const o of ops) {
  const relForLog = o.path.replace(/^C:\\Users\\abdul\\Desktop\\svcldb\\/i, '').replace(/\\/g, '/');
  try {
    if (o.tool === 'StrReplace') {
      if (!fs.existsSync(o.path)) {
        result.no_file++;
        failures.push({ msg: o.msgIdx, tool: o.tool, path: relForLog, reason: 'file does not exist' });
        console.log(`  MISS[${o.msgIdx}] StrReplace ${relForLog} (no file)`);
        continue;
      }
      if (!backedUp.has(o.path)) {
        fs.copyFileSync(o.path, o.path + '.replay-backup');
        backedUp.add(o.path);
      }
      let content = fs.readFileSync(o.path, 'utf8');
      const before = content.length;
      // Detect line-ending style: file is CRLF if any \r\n present.
      const fileHasCRLF = content.includes('\r\n');
      // Try direct match first; fall back to CRLF-normalized old_string.
      let searchStr = o.old_string;
      let replaceStr = o.new_string;
      let idx = content.indexOf(searchStr);
      if (idx < 0 && fileHasCRLF) {
        // Convert LF-only patterns to CRLF for CRLF files.
        searchStr = o.old_string.replace(/\r?\n/g, '\r\n');
        replaceStr = o.new_string.replace(/\r?\n/g, '\r\n');
        idx = content.indexOf(searchStr);
      }
      if (idx < 0 && !fileHasCRLF) {
        // Reverse case: LF file, CRLF pattern (unlikely but cover it).
        searchStr = o.old_string.replace(/\r\n/g, '\n');
        replaceStr = o.new_string.replace(/\r\n/g, '\n');
        idx = content.indexOf(searchStr);
      }
      if (idx < 0) {
        result.missing_old++;
        failures.push({
          msg: o.msgIdx, tool: o.tool, path: relForLog,
          reason: 'old_string not found (tried LF + CRLF)',
          old_head: o.old_string.substring(0, 200).replace(/\n/g, '\\n'),
        });
        console.log(`  MISS[${o.msgIdx}] StrReplace ${relForLog} (old_string not found, tried LF+CRLF)`);
        continue;
      }
      if (o.replace_all) {
        content = content.split(searchStr).join(replaceStr);
      } else {
        content = content.slice(0, idx) + replaceStr + content.slice(idx + searchStr.length);
      }
      fs.writeFileSync(o.path, content, 'utf8');
      result.ok++;
      console.log(`  OK  [${o.msgIdx}] StrReplace ${relForLog} (${before} -> ${content.length})`);
    } else if (o.tool === 'Write') {
      if (fs.existsSync(o.path) && !backedUp.has(o.path)) {
        fs.copyFileSync(o.path, o.path + '.replay-backup');
        backedUp.add(o.path);
      } else if (!fs.existsSync(path.dirname(o.path))) {
        fs.mkdirSync(path.dirname(o.path), { recursive: true });
      }
      fs.writeFileSync(o.path, o.contents, 'utf8');
      result.ok++;
      console.log(`  OK  [${o.msgIdx}] Write ${relForLog} (${o.contents.length} bytes)`);
    } else if (o.tool === 'Delete') {
      if (fs.existsSync(o.path)) {
        if (!backedUp.has(o.path)) {
          fs.copyFileSync(o.path, o.path + '.replay-backup');
          backedUp.add(o.path);
        }
        fs.unlinkSync(o.path);
        result.deleted++;
        console.log(`  OK  [${o.msgIdx}] Delete ${relForLog}`);
      }
    }
  } catch (e) {
    result.write_fail++;
    failures.push({ msg: o.msgIdx, tool: o.tool, path: relForLog, reason: e.message });
    console.log(`  FAIL[${o.msgIdx}] ${o.tool} ${relForLog} :: ${e.message}`);
  }
}

console.log('\n=== SUMMARY ===');
console.log(`  ok            : ${result.ok}`);
console.log(`  missing_old   : ${result.missing_old}`);
console.log(`  no_file       : ${result.no_file}`);
console.log(`  write_fail    : ${result.write_fail}`);
console.log(`  deleted       : ${result.deleted}`);
console.log(`  backups made  : ${backedUp.size}`);

if (failures.length) {
  const failLog = path.join(process.cwd(), 'tools', 'replay_failures.json');
  fs.writeFileSync(failLog, JSON.stringify(failures, null, 2));
  console.log(`  failures logged to: ${failLog}`);
}
