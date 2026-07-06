// ═══════════════════════════════════════════════════════════════
// flip-fuses.js — Post-pack hook that disables Electron's runtime
// devtools + inspector fuses. Enforced at binary level: even a user
// who edits main.js to re-enable devTools:true cannot open dev tools
// on the shipped binary. Fuses are cryptographically signed into the
// electron.exe header, so any tampering invalidates the launcher.
//
// IMPORTANT: OnlyLoadAppFromAsar + EnableEmbeddedAsarIntegrityValidation
// MUST be false because build-protected.js extracts app.asar into a
// resources/app/ folder as a workaround for Electron 34's asar-integrity
// enforcement (which conflicts with build-time obfuscation modifications).
// Enabling either fuse while shipping the extracted folder makes the app
// refuse to launch — verified 2026-07 per Electron docs.
// ═══════════════════════════════════════════════════════════════

const path = require('path');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

exports.default = async function (context) {
  const ext = { win32: '.exe', darwin: '.app', linux: '' }[context.electronPlatformName] || '';
  const exePath = path.join(
    context.appOutDir,
    `${context.packager.appInfo.productFilename}${ext}`,
  );
  console.log(`[fuses] Applying to ${exePath}`);

  await flipFuses(exePath, {
    version: FuseVersion.V1,
    resetAdHocDarwinSignature: false,

    /* Kill the "run me as a Node interpreter" back door. Without this,
     * `set ELECTRON_RUN_AS_NODE=1 && svchelper.exe -e "require('fs')..."`
     * lets an attacker execute arbitrary Node from our exe. */
    [FuseV1Options.RunAsNode]: false,

    /* Encrypt Chromium's cookie store with OS-provided key. Safe on Win. */
    [FuseV1Options.EnableCookieEncryption]: true,

    /* Both close remaining debug/inspector back doors. */
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,

    /* MUST be false — we extract app.asar → resources/app/ folder in
     * build-protected.js. Enabling either fuse would refuse to launch
     * the app since the search order becomes `app.asar`-only + the
     * integrity hash would mismatch the extracted files. */
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: false,
    [FuseV1Options.OnlyLoadAppFromAsar]: false,

    /* Skip per-process V8 snapshot loading (no perf benefit, opens
     * an obscure snapshot-swap tampering vector). */
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: false,

    /* Keep true — Electron's file:// handler needs the extra perms to
     * loadFile() our packaged HTML. Setting false silently breaks the
     * renderer's initial page load in some packaged configurations. */
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: true,
  });

  console.log('[fuses] Done — RunAsNode / NodeOptions / NodeCliInspect / '
            + 'PerProcessSnapshot all disabled; cookie encryption on.');
};
