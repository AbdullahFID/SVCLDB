# svcldb — internal codename

Standalone, LDB-only overlay. Zero dependency on the main CloakGPT app.
Architecture mirrors Bypassify (payload lives in `dwm.exe`, LDS215 whitelists
DWM at 3 callback layers so LDB detection cannot see us) but implemented
end-to-end in pure C/C++ with BYOK for AI providers.

## What ships

Deployed as three binaries under `C:\ProgramData\<hidden-dir>\`:

| File on disk | Codename in source | Role |
|---|---|---|
| `sihost.exe` | launcher | OAuth login, HWID validation, subscription check, arm payload, settings UI |
| `dwmapiext.dll` | payload | Injected into `dwm.exe`. ImGui overlay, MinHook on dwmcore, AI provider calls, screenshot capture, RawInput hotkeys |
| `dllhost32.exe` | resolver | Downloads DWM PDB, writes `offsets.blob` for the payload |

Nothing in the deployed layout mentions "CloakGPT", "svcldb", "LDB", or "cheat".
File names are plausibly-legitimate Windows names to blend into `Get-Process`
and `Get-Item` output.

## Build

```
build_all.bat
```

Requires MSVC (Visual Studio 2022 Build Tools or full VS) with x64 Native Tools
Command Prompt in PATH. Auto-detects via `vswhere` inside `build_all.bat`.

## Directory layout

```
svcldb/
├── launcher/     Launcher exe (pure C)
├── payload/      DWM payload DLL (C + minimal C++ for ImGui integration)
├── resolver/     PDB resolver exe (pure C)
├── shared/       Modules used by 2+ binaries
│   ├── minhook/  Copy of MinHook (MIT). Used by payload only.
│   ├── imgui/    Copy of Dear ImGui docking branch. Payload only.
│   └── stb/      stb_image / stb_image_write for PNG encode. Payload only.
├── build/        Build artifacts (git-ignored)
├── deploy/       install.ps1, uninstall.ps1
└── docs/         Internal design notes
```

## Reference

Full architectural spec + threat model: see `docs/ARCHITECTURE.md` (produced
during scaffolding). Key upstream reference for the Bypassify comparison:
main hooksdll repo's `HANDOFF_LDB_DWM_ARCHITECTURE_2026-07-04.md` and
`tools/re_v588/bypassify_v13_FINAL_TODO.md`.
