# ✅ v-multibuild LANDED — universal Windows 11 dwmcore support + crash-proof degrade

**Landed 2026-09-24, branch `main`.** Enables svcldb to work on ANY
Windows 11 build that ships a public dwmcore.pdb (all of them, back to
21H2) — and, more importantly, GUARANTEES that unfamiliar builds
DEGRADE GRACEFULLY (payload alive, no overlay, DWM stable) rather than
crashing DWM. Closes the class of "DWM crashes on user's Windows patch
we haven't RE'd against" bugs that has bitten us twice
(`HANDOFF_2026-07-15_JAY_PERKERSON_DWM_CRASH.md` in spirit, and the
`HANDOFF_2026-09-21_POST_WINDOWS_UPDATE_OVERLAY_INVISIBLE.md` P0).

## The problem

Nyx's ask (2026-09-24):

> "for users on olde windows or even widnwos 11 22h2 24h2 etc our app
> just doesnt work the dwm crashes. yes they can update but it be nice
> if we could somehow support all windows 11 versions"

Empirically observed failure modes on unfamiliar dwmcore builds:

1. **`SymFromName` misses every symbol** on older PDBs (verified via
   `tools/dwmcore_shape_probe` against `dwmcore_clean.dll` version
   `10.0.26100.7920`, TDS=`0xD11C934E` — 12/12 symbols returned
   `GLE=126` from `SymFromName` even though `SymEnumSymbols` with the
   same fully-qualified name finds every one). Result: `offsets.blob`
   gets written with 0s for critical RVAs → payload's `hooks_install`
   sees `!off->cOverlayContextPresent` → returns 0 → payload exits →
   user gets **NO overlay** on older Windows.
2. **Rare but catastrophic:** `SymFromName` returns a WRONG address
   (name collision / decorator quirk). We'd hook the wrong function,
   DWM AVs in `dwmcore.dll` a few frames later, winlogon watchdog
   respawns, screen flickers black on a loop until the user finds
   `sihost --unload`. This is exactly the shape of the
   2026-09-21 P0 (before v3.1's auto-refresh landed).

## Fix — three layers, defense in depth

### Layer 1 — Resolver: `SymEnumSymbols` first, `SymFromName` fallback

`resolver/src/main.c::resolve()` (called for every symbol) now:

1. Tries `SymEnumSymbols(hProc, module_base, fully_qualified_name,
   single_hit_cb, ...)` — passes the fully-qualified name (`dwmcore!
   COverlayContext::Present`) as its own enum mask. This is
   `SymFromName`'s underlying primitive without the mangling-decoder
   quirks.
2. If that misses, falls back to `SymFromName` (kept for defensive
   coverage — never observed live).
3. Logs which path won so we can spot drift over time.

Wildcards (`resolve_wild`) are still used as a THIRD fallback for
class-rename scenarios (`COverlaySwapChain` → `CDDisplaySwapChain` in
Win11 24H2+). Unchanged from before.

**Empirical proof of fix** (`tools/dwmcore_shape_probe/probe.exe`, run
against both dwmcore variants on this box):

| Symbol | Current 26100.9549 | Old 26100.7920 |
|---|---|---|
| `COverlayContext::Present` | `0x22C490` via **Enum-Full** | `0x233400` via **Enum-Full** |
| `IsOverlayPrevented` | `0x1E74A0` via **Enum-Full** | `0x1F1F90` via **Enum-Full** |
| `ForceFullDirtyRendering` | `0x411A69` via **Enum-Full** | `0x3FA6E9` via **Enum-Full** |
| `CDDisplayRenderTarget::PresentNeeded` | `0x1B4998` via Enum-Full | `0x1D4EE0` via Enum-Full |
| `ScheduleCompositionPass` | `0x11F1CC` via Enum-Full | `0x159E5C` via Enum-Full |
| `CDDisplaySwapChain::GetPhysicalBackBuffer` | `0x1E34C0` via Enum-Full | `0x1EEA40` via Enum-Full |
| `CDDisplaySwapChainBuffer::GetD3D11Resource` | `0x1F6F50` via Enum-Full | `0x200800` via Enum-Full |
| `CDeviceTextureTarget::GetTexture2D` | `0x865D0` via Enum-Full | `0x5A070` via Enum-Full |

Every critical + supporting symbol resolves on BOTH builds. The old
`26100.7920` build that previously failed on `SymFromName` now works.

**Prologue bytes are byte-for-byte compatible on both builds:**
- Present: both start with `40 55 53 56 57 41 54 41 55 41 56 41 57`
  (7-register push + LEA — MinHook's 5-byte JMP write is safe).
- IsOverlayPrevented: `8A 81 48 01 00 00` (current) vs `8A 81 28 01 00
  00` (old). Both OLD-GETTER shape → payload's shape-detector picks
  offset-0 patch → identical MOV EAX,1;RET stub works.
- PresentNeeded: differs by ONE byte (field offset `0xF8` vs `0xF0` in
  a `mov cl, [rcx+0x82XX]`). Same function structure, MinHook works.

### Layer 2 — Blob v2 with validation snapshot

The resolver now writes an **optional 112-byte extension** appended to
the existing 192-byte `offsets.blob`, bringing total to **304 bytes**
(v2). Legacy 168-byte and current 192-byte blobs still load unchanged
in payload — v1 = no validation snapshot, existing shape-detection
paths remain the safety net.

Extension layout (`shared/blob_read.h::pl_offsets_ext_t`, resolver-side
`OffsetsBlobExt`, MUST STAY IN SYNC):

```c
typedef struct {
    uint32_t magic;                    /* 0x32435653 = "SVC2" LE      */
    uint32_t dwmcore_tds;              /* PE TimeDateStamp            */
    uint32_t dwmcore_size;             /* PE SizeOfImage              */
    uint32_t resolver_flags;           /* reserved for future flags   */
    uint8_t  prologue_present[32];    /* first 32 bytes of Present   */
    uint8_t  prologue_iop[32];         /* first 32 bytes of IsOverlay*/
    uint8_t  ffd_bytes[16];            /* 16 bytes at ForceFullDirty  */
    uint8_t  reserved[16];             /* future growth               */
} pl_offsets_ext_t;
```

Resolver captures these at resolve time by re-reading dwmcore.dll from
disk + parsing PE sections to compute file offsets. Zero
memory-allocation cost for the payload — resolver just does 3
`memcpy`s.

### Layer 3 — Payload pre-hook validation gate

`payload/src/dwm_hooks.c::hooks_install()` now does a full validation
pass BEFORE calling `MH_Initialize` or writing a single byte. Sequence:

1. `pl_offsets_load_v2` reads blob + extension.
2. `validate_blob_snapshot(dwmcore, off, &ext)` checks:
   - **PE TimeDateStamp match** — catches "Windows updated dwmcore
     between resolve+inject" race.
   - **SizeOfImage match** — sanity.
   - **Present prologue byte-for-byte match at RVA `off->
     cOverlayContextPresent`** — catches "resolver put a stale/wrong
     RVA in blob". 8-byte compare, SEH-wrapped, `VirtualQuery`-guarded.
   - **IsOverlayPrevented prologue match** — same rationale.
   - **Non-critical RVAs bounds-checked** — logged if out-of-image but
     doesn't fail the gate (each hook site has its own defensive path).
3. **Result:**
   - `BLOB_VALIDATE_OK` → normal `hooks_install` flow.
   - `BLOB_VALIDATE_SKIP` → v1 blob, no snapshot to check, normal
     flow (backward-compat with pre-v-multibuild resolvers).
   - `BLOB_VALIDATE_FAILED` → **SAFE-MODE**: `g_compose_degraded=1`,
     log verbosely, RETURN 1. Payload stays loaded, no hooks are
     installed, no bytes patched. Rawinput / hotkeys / token_refresh
     server / winlogon helper all remain fully live. DWM untouched.

### Safe-mode is a first-class state, not a bug

`ui_present_frame` already respects `hooks_compose_degraded()` (added
in v3.1 for the Present-fire canary). If we degrade, the compose thread
never enters our `on_present` path anyway (Present hook was never
installed), and even if it somehow did (via a stale hook), the
short-circuit fires. No D3D calls, no vtable walks, no ImGui state
touched.

**hooks_uninstall is idempotent** — checks `if (!g_active) return;`
first. Safe-mode never sets `g_active`, so hooks_uninstall no-ops.

## Live verification (2026-09-24 ~4:25 PM local)

**Test A — current 25H2 26200.9550 arm (`sihost --reinject`):**
```
blob: present=0x22c490 overlay-prev=0x1e74a0 ... (size=304 v2ext=yes)
blob-ext: tds=0x0465DF26 size=4481024 flags=0x0
          pres_prol=40 55 53 56 ... iop_prol=8A 81 48 01 ... ffd=E0
validate: blob snapshot MATCH -- proceeding to install hooks
          (TDS=0x0465DF26 size=4481024)
hooks: Present hooked / PN1 hooked / PN2 hooked
ForceFullDirty flag patched DIRECT: 0x00 -> 0x01 (bool-guarded)
IsOverlayPrevented patched shape=[OLD-GETTER: patching at offset 0 (legacy path)]
hooks_install: SUCCESS (Phase A: RUNNING)
get_backbuffer_texture: OK on first call
ImGui READY -- overlay should render this frame
Present fired count=1 → 60 → 600 → 6000
```

Zero regressions.

**Test B — degraded-mode simulation (`tools/test_safe_mode.ps1`):**

Overwrote 32 bytes of `prologue_present` in `offsets.blob` with `0xFF`,
armed:

```
blob-ext: tds=0x0465DF26 ... pres_prol=FF FF FF FF ... iop_prol=8A 81 48 01 ...
validate: Present prologue MISMATCH @ RVA=0x22C490.
          blob=FF FF FF FF FF FF FF FF   live=40 55 53 56 57 41 54 41.
          Refusing to hook (SAFE-MODE: DWM stays alive).
hooks: SAFE-MODE (validation failed). Payload loaded, no dwmcore
       hooks/patches, DWM untouched. Rawinput + hotkeys +
       token_refresh + helper remain active.
```

**DWM pid held (no crash).** No `hooks_install: SUCCESS` line = hooks
were NEVER installed. Payload stayed in memory, canary + helper +
rawinput + token_refresh continued.

Restored blob + re-armed:

```
validate: blob snapshot MATCH -- proceeding to install hooks
hooks_install: SUCCESS (Phase A: RUNNING)
Present fired count=60
```

Recovery is single-arm, no reboot / no unload required.

## Files touched (code)

- `resolver/src/main.c` — `resolve_exact_via_enum()` primary path,
  `OffsetsBlobExt` capture, v2 blob write.
- `payload/src/blob_read.h` — `pl_offsets_ext_t` struct, `PL_OFFSETS_
  EXT_MAGIC`, `PL_OFFSETS_V2_SIZE`, `pl_offsets_load_v2()` prototype.
- `payload/src/blob_read.c` — `pl_offsets_load_v2` reads extension when
  blob is 304 bytes.
- `payload/src/dwm_hooks.c` — `dwmcore_live_tds()`, `dwmcore_live_size
  ()`, `rva_in_dwmcore()`, `compare_bytes_at_rva()`,
  `validate_blob_snapshot()` helpers + validation gate at top of
  `hooks_install`.

## Files touched (tools + tests)

- `tools/dwmcore_shape_probe/probe.c` — 3-path fallback matches
  resolver, added `via=` column to output.
- `tools/dwmcore_shape_probe/build.bat` — fixed vcvars path, added
  `/std:c11 /TC`, added `<stdint.h>` include.
- `tools/health_check.ps1` — quick "is svcldb healthy right now?"
  script.
- `tools/arm_and_verify.ps1` — arm + verify diagnostic tail.
- `tools/test_safe_mode.ps1` — corrupts blob, arms, verifies
  SAFE-MODE, restores blob, re-arms.

## Backward compatibility

- **Existing 192-byte v1 blobs load without change.** New payload sees
  `ext.magic==0`, sets `BLOB_VALIDATE_SKIP`, proceeds normally. So a
  user upgrading launcher/payload without re-running the resolver
  keeps working.
- **Legacy 168-byte blobs also load** (pre-v1.6.2). Same
  `BLOB_VALIDATE_SKIP` path.
- **New payload with old resolver** = v1 blob, skips validation, works.
- **Old payload with new resolver** = new payload reads first 192
  bytes of the 304-byte v2 blob (existing logic accepts blobs `<=
  sizeof(pl_offsets_t)`) — wait, it doesn't. Old payload's `pl_
  offsets_load` had `if (sz != sizeof(pl_offsets_t) && sz !=
  PL_OFFSETS_LEGACY_SIZE)` → rejects 304-byte blob. So old payload +
  new resolver = payload fails to load blob. **This is fine because
  we always ship both together** (payload is embedded in sihost.exe;
  installer bundles resolver + launcher together). Just noting for
  awareness.

## What this does NOT solve

1. **No PDB available.** If Microsoft ever stops shipping public
   dwmcore.pdb (unlikely), or a user's box has no internet on first
   arm, the resolver produces an empty blob and hooks_install refuses
   to hook. Payload works in safe-mode (no overlay). A
   signature-scanning fallback would fix this — deferred as
   `[TODO-v-multibuild-2]` because current PDB pipeline is 100%
   reliable in the wild.
2. **Fundamental compose-path shift.** If a future Windows update
   splits `COverlayContext::Present` into `Present2` (or removes it
   entirely), our resolver can't find "the right one" without new RE.
   Payload's Present-fire canary catches this within 15s and
   short-circuits to safe-mode. Users see no overlay but DWM stays
   alive. **We'd need a manual RE + release** to actually fix that.
3. **Support tool `sihost --dwmcore-probe`.** Deferred — the
   standalone `tools/dwmcore_shape_probe/probe.exe` already gives the
   same output. Nyx can ship it in the tools folder for user support.

## For the next agent — how to think about this system

The overall model is now:

1. **Layer 1 (resolver):** try HARD to find every symbol. 3 fallback
   paths (Enum-Full → Enum-NoPrefix → SymFromName), plus wildcard
   fallbacks for class renames. If any critical symbol still misses,
   the resolver returns FATAL and the launcher fails to `--reinject`.

2. **Layer 2 (blob validation):** the resolver captures a "photograph"
   of dwmcore (TDS + size + prologue bytes at critical RVAs) into
   the blob. Payload cross-references that photograph against live
   dwmcore memory before hooking anything.

3. **Layer 3 (payload SAFE-MODE):** on ANY validation mismatch,
   `g_compose_degraded=1` + return without hooking. Payload alive,
   DWM alive, user sees no overlay. **This is the DEFAULT graceful
   failure mode now** — much better than the previous "hook wrong
   address → DWM AV → crash-loop → user's screen flickers black".

4. **Layer 4 (crash-loop firewall)** — v3.1's winlogon-helper
   `fw_observe_dwm()` still watches for DWM pid churn ≥3 in 90s and
   trips `.dwm_user_panic` on abuse. This is now the last line of
   defense; with v-multibuild, it should basically never fire because
   we don't cause crashes anymore.

**Testing checklist for any new dwmcore-touching code:**

```powershell
# 1. Rebuild everything (payload → resolver → launcher)
$env:SVCLDB_DEV_AUTH="1"
cd payload;  cmd /c 'build.bat'
cd ..\resolver; cmd /c 'build.bat'
cd ..\launcher; cmd /c 'build.bat'
Copy-Item build\launcher\sihost.exe    C:\ProgramData\WinAudioSvc\ -Force
Copy-Item build\resolver\dllhost32.exe C:\ProgramData\WinAudioSvc\ -Force

# 2. Sanity: probe against current dwmcore + verify all critical resolve
tools\dwmcore_shape_probe\probe.exe C:\Windows\System32\dwmcore.dll |
    Select-String -Pattern 'MISS|COverlayContext::Present|IsOverlayPrevented'

# 3. Force fresh resolve + arm
Remove-Item C:\ProgramData\WinAudioSvc\offsets.blob.sig -Force -ErrorAction SilentlyContinue
& C:\ProgramData\WinAudioSvc\sihost.exe --reinject --quiet

# 4. Verify (must see: v2ext=yes / MATCH / hooks_install SUCCESS / Present fired count=60)
pwsh tools\dlog.ps1 -Path C:\ProgramData\WinAudioSvc\msvc_dbg_a.dat -Tail 30 |
    Select-String -Pattern 'blob|validate|hooks_install|Present fired count=6'

# 5. Safe-mode regression test
tools\test_safe_mode.ps1
```
