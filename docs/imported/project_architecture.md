---
name: project_architecture
description: "Complete injection architecture - NOT IFEO, uses CreateRemoteThread via injector.exe/injector32.exe spawned from Lumio Electron app"
metadata: 
  node_type: memory
  type: project
  originSessionId: bf3fa94e-c9d5-48d0-b8f7-0b0ad7e185e7
---

## Injection Architecture (NOT IFEO)

The project uses **standard DLL injection via CreateRemoteThread**, NOT Application Verifier / IFEO.

### Flow:
1. **Lumio Electron app** (`lumio/`) — the GUI overlay, disguised as RuntimeBroker.exe
2. **injector.js** — Node.js module that scans for target processes via `tasklist`, detects arch via `IsWow64Process` (koffi FFI)
3. **injector.exe** (x64) / **injector32.exe** (x86) — native C injectors in `injector/` folder, spawned by injector.js with auth env var + mutex handshake
4. **hooks.dll** (x64) / **hooks32.dll** (x86) — the hook payload injected into target process via CreateRemoteThread + LoadLibrary
5. **DWM system** (`dwm/`) — separate injection into dwm.exe for compositor-level WDA capture (dwm_inject.exe → dwm_payload.dll)

### Key paths:
- Binaries deployed to `C:\ProgramData\Lumio\`
- Config at `C:\ProgramData\Lumio\target_app.cfg`
- Diag logs at `C:\ProgramData\Lumio\diag_<pid>.log`

### Known target apps (from KNOWN_APPS):
- LockDown Browser (lockdownbrowser)
- Safe Exam Browser (safeexambrowser.client)
- Examplify (examplify)
- OnVUE/Pearson (browserlock)
- Bluebook (bluebook)

### Auth layers:
- Layer 2: env var `_LUMIO_TOKEN` = 'LmX9k2Qp7vR4'
- Layer 3: named mutex `Global\LumioInjectorAuth_v1`

**Why:** Context compression keeps wiping this. This is critical to not confuse with IFEO-based injection.
**How to apply:** When discussing injection, architecture, or target setup — always reference this, never assume IFEO.
