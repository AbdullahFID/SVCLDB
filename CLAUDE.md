# svcldb — Project Memory (Claude / Cursor)

## What this project is

Standalone DWM-injected AI-overlay for exam bypass. Independent of `hooksdll` (the older Electron-based CloakGPT project) but shares the same threat model: LDB (Respondus LockDown Browser) + LDB Monitor.

**Architecture in one line**: A small kernel of hooks + ImGui overlay + hotkeys lives inside `dwm.exe` via manual-map DLL injection. Everything visible on screen and every hotkey handler runs there, in a process that LDB explicitly whitelists.

## Directory layout

```
svcldb/
├── payload/          ← the DLL that runs inside dwm.exe (dwmapiext.dll)
│   ├── src/
│   │   ├── dllmain.c            entry, init_thread, hotkey dispatch, PEB unlink, PE wipe
│   │   ├── dwm_hooks.c          9 dwmcore.dll hooks + hook-integrity monitor + ghost (opt-in)
│   │   ├── rawinput_hook.c      WH_KEYBOARD_LL + chat input capture + auto-repeat
│   │   ├── ai/ai_provider.c     OpenAI/Anthropic/Google/OpenRouter HTTP client
│   │   ├── ui/imgui_layer.cpp   overlay rendering + persistence + chat cursor nav
│   │   ├── capture.c            GDI fallback screenshot
│   │   ├── clipboard_out.c      clipboard writer
│   │   ├── config_read.c        decrypt + read config.dat
│   │   ├── blob_read.c          read offsets.blob
│   │   └── ldb_detect.c         poll for LockDownBrowser.exe presence
│   └── build.bat
├── launcher/         ← the exe user runs (sihost.exe) — one-shot, admin, exits after arming
│   ├── src/
│   │   ├── main.c               CLI parse, OAuth login, arm/kill-all/unload
│   │   ├── inject.c             manual-map into dwm (from RCDATA resource OR disk)
│   │   ├── inject.h             API + resource ID (SVC_PAYLOAD_RCDATA_ID = 101)
│   │   ├── oauth.c              Supabase OAuth (subscription auth)
│   │   ├── license.c            Supabase subscription check
│   │   ├── config_write.c       encrypt + write config.dat
│   │   ├── launcher.rc          embeds manifest AND payload DLL as RT_RCDATA
│   │   └── launcher.manifest    UAC requireAdministrator + DPI awareness
│   └── build.bat
├── resolver/         ← dllhost32.exe — resolves dwmcore RVAs via PDB + dbghelp
│   └── src/main.c
├── shared/           ← common code (both payload + launcher link against)
│   ├── log_secure.c/h           AES-256-GCM per-line encrypted logs
│   ├── log_key.c                the 32-byte master key (baked in — rotate for shipping)
│   ├── crypto_util.c            BCrypt wrappers
│   ├── winhttp_util.c           WinHTTP client
│   ├── imgui/                   Dear ImGui vendored
│   ├── minhook/                 MinHook vendored
│   ├── common.h                 SVC_* constants (install dir, event name, etc.)
│   └── log_key.c                LOG_KEY master
├── docs/             ← handoffs + RE writeups
│   ├── HANDOFF_UX_POLISH_2026-07-05.md         hotkey manifest + chat spec
│   ├── HANDOFF_STEALTH_NIGHT_2026-07-05.md     overnight stealth pass
│   └── (new handoff to be created for next chat)
├── build/            ← build outputs (gitignored)
│   ├── payload/dwmapiext.dll   (595 968 B)
│   └── launcher/sihost.exe      (~835 KB — 596 KB payload embedded as RCDATA)
├── deploy/           ← install.ps1 / uninstall.ps1
├── HANDOFF_SVCLDB_2026-07-04.md
├── HANDOFF_SVCLDB_2026-07-05_HOTKEYS_AND_WAKE.md
├── README.md
├── build_all.bat
└── keepalive.ps1     ← used during dev to keep the machine awake overnight
```

## Deployed state (production)

Everything lives under `C:\ProgramData\WinAudioSvc\`:

```
sihost.exe          ← launcher (contains embedded payload)
dllhost32.exe       ← resolver
cgpt_dbghelp.dll    ← MS symbol resolution
symsrv.dll          ← MS PDB fetcher
config.dat          ← encrypted (per-install, machine-bound)
offsets.blob        ← resolver output (per-install)
overlay_state.bin   ← user's overlay position/size/alpha/font (persistence)
.dwm_clean_shutdown ← sentinel written on clean --unload
api_key.txt         ← the user's AI provider API key
payload.log         ← encrypted diag (v1.<base64> per line)
launcher.log        ← encrypted diag (same format)
```

**NO `dwmapiext.dll` on disk in production.** The DLL is embedded as RCDATA `101` inside `sihost.exe` and manual-mapped from resource bytes → zero file to blacklist.

## Named objects

- `Global\DwmCompositorShutdownRelease` — event; launcher `--unload` signals it, payload's shutdown_watcher cleanly uninstalls hooks.

## Key architectural invariants (DO NOT REGRESS)

### 1. Payload DLL runs inside dwm.exe via manual map (never LoadLibrary)

DWM has `PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY` (CIG) — rejects any non-MS-signed DLL via LoadLibrary. Manual mapping (allocate RWX in DWM → copy PE → apply relocs + imports → call DllMain via shellcode) bypasses CIG entirely. Since we never go through the loader:

- No PEB LDR entry (naturally). We also add spoofed one then unlink it for defense-in-depth.
- No CRT init runs. **`/GS-` mandatory** for payload C++ code (uninitialized security cookie → __security_check_cookie fastfail).
- No CFG bitmap init. **`/guard:cf-` mandatory** for payload (indirect calls → __fastfail).
- Launcher shellcode ALSO needs `/GUARD:NO` (or the shellcode's indirect calls in DWM fail CFG).

### 2. dwmcore RVAs are resolved dynamically per install

`resolver/` (aka `dllhost32.exe`) runs at install/arm time. Fetches DWM's PDB from Microsoft symbol server via `dbghelp.dll` + `symsrv.dll`. Extracts RVAs for 9 target functions. Writes `offsets.blob`. Payload reads it on init.

**Impact of Windows update**: new dwmcore.dll = new RVAs = user must re-run launcher to trigger fresh resolver → new blob → works. Automatic if resolver has internet. **No hardcoded RVAs anywhere.**

### 3. HARDCODED offsets that ARE stable across Windows versions

- `DRAWCTX_CAPTURE_FLAG_OFFSET = 0x30` — field inside CDrawingContext. NULL = capture render, non-NULL = screen render. Stable Win10→Win11 24H2/25H1. Same as hooksdll's assumption.
- `HWND_OFFSET_IN_WINDOWNODE` — NOT hardcoded, resolved by parsing `CWindowNode::GetHwnd` body dynamically.
- PEB offsets (`0x60` on x64) — stable for 20+ years.
- `BeingDebugged` at PEB offset `0x02` — stable.

### 4. All diag output is AES-256-GCM encrypted at rest

`shared/log_secure.c` wraps `slog_writef("payload.log", ...)` → `v1.<base64>` per line. `payload_early.txt` is now near-zero bytes unless env var `DWM_EXT_TRACE=1` is set (dev/debug only). No feature-name strings leak on disk. Key baked into `log_key.c` — rotate for shipping.

### 5. Nine dwmcore hooks (with hook-integrity monitor)

| Hook | Target | Purpose |
|---|---|---|
| 1 | `COverlayContext::Present` | overlay draw entry — where we call `ui_present_frame` |
| 2 | `CDDisplayRenderTarget::PresentNeeded` | return TRUE + call `ScheduleCompositionPass(0, -1)` = DWM never idles |
| 3 | `CLegacyRenderTarget::PresentNeeded` | same |
| 4 | `CDDisplayRenderTarget::Present` | passive (belt-and-suspenders) |
| 5 | `CLegacyRenderTarget::Present` | passive |
| 6 | `CWindowNode::RenderContent` | detect capture render via `[pDrawCtx+0x30]==NULL` → skip overlay |
| 7 | `CVisual::RenderContent` | same, base class variant |
| 8 | `CDDisplayRenderTarget::AddDirtyRect` | passive (RE logging) |
| 9 | `CLegacyRenderTarget::AddDirtyRect` | passive |

`hook_integrity_thread` polls every 10s. Verifies first byte at each target is `0xE9` (MinHook JMP) or `0xFF` (indirect JMP). Re-installs if tampered.

### 6. Capture stealth latch

`svcldb_capture_active()` returns TRUE if `g_in_capture_render > 0` OR `now - g_capture_seen_tick < 15ms`. Present detour checks this and skips `g_present_cb` → overlay pixels never enter capture buffer. 15ms flicker = ~1 frame at 60Hz (barely perceptible).

### 7. Hotkey dispatch (23 slots)

Every hotkey goes through `rawinput_hook.c` LL keyboard hook. Layers:

1. LL hook (primary) — captures BEFORE any window WndProc, invisible to LDB
2. `RegisterHotKey` (fallback) — WM_HOTKEY dispatch
3. `GetAsyncKeyState` polling (last resort)

**Consumption**: initial DOWN + all auto-repeat DOWNs + final UP are all `return 1` (consumed). LDB / any other app sees NOTHING of our hotkey sequences.

**Auto-repeat** (nudge / resize / scroll / alpha / font): `g_repeat_allowed[]` array. On repeat DOWN, verify mods still match + phys key still down (`GetAsyncKeyState`). Modifier-release sweep clears active slots the instant Ctrl/Shift/Alt lifts. Fixes "nudge won't stop" bug.

### 8. Chat input mode (`Ctrl+Alt+T`)

Full text entry inline in the overlay. All keystrokes captured by LL hook, fed to `g_chat_buf` via `ToUnicodeEx` (layout-aware). Cursor navigation (Left/Right/Home/End/Backspace/Delete) supported. Enter submits with fresh screenshot. Esc cancels. Nothing leaks to any other app while active.

### 9. Kill switches

- **`Ctrl+Alt+X` on home page** → soft quit (inline `SetEvent(g_shutdown_ev)` — shutdown_watcher calls `hooks_uninstall`, DWM stays alive, sentinel written)
- **`Ctrl+Alt+X` on reply page** → clear reply
- **`Ctrl+Shift+Alt+K`** → nuclear KILL_ALL (inline `TerminateProcess(GetCurrentProcess())` from within DWM — Windows respawns fresh dwm.exe in ~2s, our payload dies with it)

Both are inline — no launcher spawn. Original attempt to spawn `sihost --kill-all` from DWM failed with `ERROR_ELEVATION_REQUIRED (740)` because sihost has admin manifest and DWM's SYSTEM-in-user-session context can't satisfy UAC.

### 10. Zero-disk-footprint injection

Launcher `sihost.exe` embeds the payload DLL as `RT_RCDATA` resource id `101`. `launcher.rc` conditionally emits the resource statement when `PAYLOAD_DLL_PATH` is defined by `launcher/build.bat`. At runtime, `inject_dwm_payload_from_resource(GetModuleHandleA(NULL), 101)` does `FindResource` + `LoadResource` + `LockResource` → memcpy to fresh page → manual_map. **Verified live**: with `dwmapiext.dll` file removed from disk, `sihost.exe --quiet` still successfully injects and hotkeys work.

### 11. Ghost window is OPT-IN

Set env var `SVCLDB_ENABLE_GHOST=1` before dwm.exe starts to re-enable the fullscreen invisible TOPMOST HWND used for wake nudges. **Default OFF** = zero enumerable top-level HWNDs from us. PN=TRUE + SCP loop already keeps DWM composing every vsync so ghost is pure belt-and-suspenders.

### 12. Overlay state persistence

40-byte `overlay_state.bin` at `SVC_INSTALL_DIR`. Magic `SVOL`, version 1. Fields: visible/corner/offset_x/y/extra_w/h/alpha/font. Loaded once via `state_load_once()` inside `ensure_cs()`. Saved throttled to 250ms via `state_flush_if_due()` called from `ui_present_frame`.

### 13. PEB unlink + PE header wipe

After hook install:
- `peb_unlink_dll(g_self)` walks the PEB LDR list, cuts our entry from all 3 lists (InLoadOrder / InMemoryOrder / InInitOrder). Also spoofs BaseDllName + FullDllName to a random pick from 7 innocuous fringe Windows DLLs (`uiribbon.dll`, `uiribbonres.dll`, `dcomp.dll`, `dwmredir.dll`, `windowscodecs.dll`, `twinapi.dll`, `prntvpt.dll`) — chosen per install via `(pid ^ tick) % 7`.
- `wipe_pe_headers(g_self)` corrupts `MZ` and `PE\0\0` signatures. Memory scanners for MZ at page boundaries miss us.

### 14. Anti-debug guard

`anti_debug_check()` reads `PEB->BeingDebugged` on init. If set, `init_thread` returns 4 without installing hooks.

### 15. Build hardening

**Payload** (`payload/build.bat`):
- `/O2 /Oi /GS- /GL /guard:cf-` (compile) — GS/CFG off is MANDATORY for manual map
- `/LTCG /DEBUG:NONE /Brepro /OPT:REF /OPT:ICF /INCREMENTAL:NO /MANIFEST:NO /GUARD:NO /RELEASE` (link)
- `/HIGHENTROPYVA /DYNAMICBASE /NXCOMPAT`
- **NOT** `/MERGE:.pdata=.text` — x64 SEH needs .pdata separate

**Launcher** (`launcher/build.bat`):
- `/O2 /Oi /GS /Gy /MT /GL` (no /guard:cf — shellcode has indirect calls that would fail CFG in DWM)
- `/LTCG /DEBUG:NONE /Brepro /OPT:REF /OPT:NOICF /INCREMENTAL:NO /MANIFEST:NO`
- `/HIGHENTROPYVA /DYNAMICBASE /NXCOMPAT /GUARD:NO`
- **NOT** `/OPT:ICF` — folds `shellcode_loader_end` into other empty funcs, breaks contiguous-shellcode assumption
- **NOT** `/GUARD:CF` — shellcode's LoadLibraryA/GetProcAddress/DllMain indirect calls would trip CFG in DWM

## Bug-fix invariants (learned the hard way)

1. **Nudge continues after release** — auto-repeat handler MUST verify `mods_match` + `GetAsyncKeyState(vk) & 0x8000` on EVERY repeat DOWN. Missing either check → phantom auto-repeat after release keeps firing forever.
2. **`Ctrl+Shift+Alt+K` never fired** — launcher spawn from DWM fails ERROR_ELEVATION_REQUIRED. Must be INLINE `self_kill_dwm_thread` (200ms delay + `TerminateProcess(GetCurrentProcess())`).
3. **Same for `Ctrl+Alt+X` soft-quit** — inline `SetEvent(g_shutdown_ev)`.
4. **Windows update = re-run launcher** — resolver refetches PDB, writes fresh offsets.blob. Automatic if internet available.
5. **`/MERGE:.pdata=.text` breaks SEH silently** — payload init returns early, no crash, no functionality.
6. **`/OPT:ICF` on launcher breaks shellcode marker** — thread crashes 0xC0000005 inside DWM.
7. **`/GUARD:CF` on launcher breaks shellcode** — indirect calls fail CFG in DWM.

## Hotkey manifest (23 slots, all live)

See `docs/HANDOFF_UX_POLISH_2026-07-05.md` §1 for the full table.

Key ones for testing:
- `Ctrl+Shift+Space` — screenshot + AI (preset prompt)
- `Ctrl+Alt+G` — toggle overlay
- `Ctrl+Alt+T` — chat mode (type + Enter to submit with screenshot)
- `Ctrl+Alt+C` — copy last reply
- `Ctrl+Alt+X` — quit (home page) / clear reply (reply page)
- `Ctrl+Alt+Arrows` — hold-to-nudge
- `Ctrl+Shift+Alt+Arrows` — hold-to-resize
- `Ctrl+Alt+J/K` — hold-to-scroll reply
- `Ctrl+Alt+[/]` — font size (small/big)
- `Ctrl+Alt+=/-` — opacity
- `Ctrl+Alt+Q` — cycle corner
- `Ctrl+Alt+R` — reset geometry
- `Ctrl+Shift+Alt+K` — EMERGENCY STOP (kills DWM)
- `Ctrl+Shift+Alt+S` — save 3 diagnostic screenshots

## Rebuild + deploy

```powershell
cd C:\Users\abdul\Desktop\svcldb\payload
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && build.bat'

cd C:\Users\abdul\Desktop\svcldb\launcher
cmd /c 'build.bat'   # embeds payload as RCDATA

Copy-Item C:\Users\abdul\Desktop\svcldb\build\launcher\sihost.exe C:\ProgramData\WinAudioSvc\sihost.exe -Force
# NO dwmapiext.dll needed on disk — embedded in sihost.exe

# Test cycle
Stop-Process -Name dwm -Force -EA 0
Start-Sleep 4
& C:\ProgramData\WinAudioSvc\sihost.exe --quiet
Start-Sleep 5
# → payload injected via embedded resource
```

## GitHub

Local `main` branch. Origin: `https://github.com/AbdullahDaGoat/svcldb.git` (private). Push works from this machine (cached PAT is DaGoat).

## MANDATORY: subagents use Sonnet

If Cursor/Claude launches subagents in this repo, they MUST use `claude-4.6-sonnet-medium-thinking` (Opus was causing issues in the workspace-wide policy from `hooksdll/AGENTS.md`). Even though svcldb is a separate repo, follow the same rule for consistency.
