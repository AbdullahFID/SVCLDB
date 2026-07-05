#!/usr/bin/env node
// Decrypt svcldb *.log files. Same wire format as slog_write:
//   v1.<base64( iv[12] || tag[16] || ciphertext )>\n
//
// Usage:
//   node decrypt_logs.js                    # all logs, last 100 lines each
//   node decrypt_logs.js payload.log 40     # one file, last 40 lines
//   node decrypt_logs.js --follow payload.log

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const INSTALL_DIR = 'C:\\ProgramData\\WinAudioSvc';

// SVCLDB_LOG_KEY — must match svcldb/shared/log_key.c
const KEY = Buffer.from([
    0x7a, 0x9e, 0x14, 0x3b, 0x62, 0x8c, 0xd1, 0x05,
    0xf7, 0x2a, 0x4b, 0x91, 0xc6, 0x08, 0x5d, 0xea,
    0x33, 0x71, 0xbf, 0x02, 0x88, 0x4e, 0xd3, 0x1a,
    0x66, 0xa9, 0x0c, 0xf5, 0x27, 0xb0, 0x9d, 0x48,
]);

function decryptLine(line) {
    line = line.trim();
    if (!line) return null;
    if (!line.startsWith('v1.')) return `[PLAIN] ${line}`;
    try {
        const blob = Buffer.from(line.slice(3), 'base64');
        if (blob.length < 29) return `[SHORT] ${line}`;
        const iv  = blob.slice(0, 12);
        const tag = blob.slice(12, 28);
        const ct  = blob.slice(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
        decipher.setAuthTag(tag);
        const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
        return pt.toString('utf8');
    } catch (e) {
        return `[BAD/WRONG-KEY] ${line}  (${e.message})`;
    }
}

function decryptFile(filepath, tail = 100) {
    if (!fs.existsSync(filepath)) {
        console.log(`  (missing) ${filepath}`);
        return;
    }
    const all = fs.readFileSync(filepath, 'utf8').split('\n').filter(Boolean);
    const lines = all.slice(-tail);
    console.log(`\n── ${path.basename(filepath)} (last ${lines.length} of ${all.length}) ──`);
    for (const ln of lines) {
        const pt = decryptLine(ln);
        if (pt !== null) console.log(pt);
    }
}

// --follow mode
if (process.argv.includes('--follow')) {
    const idx = process.argv.indexOf('--follow');
    const fname = process.argv[idx + 1];
    if (!fname) { console.error('--follow needs a filename'); process.exit(1); }
    const fp = path.join(INSTALL_DIR, fname);
    let seen = 0;
    console.log(`Following ${fp} (Ctrl+C to stop)`);
    setInterval(() => {
        try {
            const all = fs.readFileSync(fp, 'utf8').split('\n').filter(Boolean);
            if (all.length > seen) {
                for (const ln of all.slice(seen)) {
                    const pt = decryptLine(ln);
                    if (pt !== null) console.log(pt);
                }
                seen = all.length;
            }
        } catch {}
    }, 500);
} else {
    const arg1 = process.argv[2];
    const arg2 = parseInt(process.argv[3] || '100', 10);
    if (arg1) {
        decryptFile(path.join(INSTALL_DIR, arg1), arg2);
    } else {
        for (const f of ['launcher.log','auth.log','resolver.log','payload.log','ai.log']) {
            decryptFile(path.join(INSTALL_DIR, f), 40);
        }
    }
}
