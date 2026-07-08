# svcldb — Anti-DBI (Frida) + MITM Login-Disable Reference (2026-07-06)

**Author:** Cursor session 2026-07-06 (evening)
**Companion to:** `HANDOFF_STEALTH_HARDENING_2026-07-06.md`, `HANDOFF_ELECTRON_UI_2026-07-06.md`
**Baseline:** Post-v7 (LaTeX renderer overhaul + shared latex_convert.h)
**Also updated:** `../hooksdll/CLAUDE.md` V10.1.20 (2026-07-06) — port of these
same protections into the main CloakGPT product.

This doc is the single source of truth for how svcldb defends the login
+ subscription-check exchange against:

1. **Dynamic-Binary-Instrumentation attacks** — Frida, DynamoRIO,
   Intel Pin, WinAppDbg attaching a JS/Python runtime at exam time to
   hot-patch our IPC contract or grab an API key from memory.
2. **Man-in-the-middle proxies** — Fiddler / mitmproxy / Charles / Burp /
   Proxyman / HTTP Toolkit / AnyProxy / OWASP ZAP intercepting the
   Supabase auth exchange and spoofing an `active:true` response.
3. **Env-var TLS bypass** — `NODE_TLS_REJECT_UNAUTHORIZED=0` disabling
   cert validation across all Node fetches.
4. **System-wide proxy misconfig** — `HTTPS_PROXY` / `HTTP_PROXY` /
   `ALL_PROXY` env vars, `netsh winhttp` system-wide proxy setup.

**Design principle:** *when in doubt, disable login.* We refuse to run
the OAuth callback flow (and refuse to load an existing session on app
start) if ANY of the above trip. The user gets a specific error banner
naming the tool + a one-click "Fix now" button that auto-remediates
the most common cases without shelling into PowerShell.

---

## 1. The 5-vector anti-debug (JS side)

Runs on every `license.init()` + every `revalidateNow()` (hourly poll).
Also runs before OAuth in `login()` so an attacker who Frida-hooks
midway through the app's lifetime can't sneak past the initial launch
check.

**Vectors implemented in `ui/src/license/security.js`:**

| # | Vector | Location | What it catches |
|---|---|---|---|
| 1 | `IsDebuggerPresent()` | kernel32 | PEB->BeingDebugged byte — trivial to bypass but ~0-cost check |
| 2 | `CheckRemoteDebuggerPresent()` | kernel32 | Kernel PROCESS_DEBUG_PORT — catches BeingDebugged patchers |
| 3 | `NtQueryInformationProcess(ProcessDebugPort=7)` | ntdll | Same as #2 but via direct ntdll — un-hookable at the win32 API layer |
| 4 | `PEB->NtGlobalFlag` debug-heap bits (0x70) | manual PEB walk via ReadProcessMemory | Catches "launched under debugger" even if attacker patched PEB->BeingDebugged post-hoc. NtGlobalFlag is set once at process creation and never touched again by the debugger. |
| 5 | `ProcessHeap->Flags` / `ForceFlags` | manual heap walk | Same debug-heap signature as #4 but stored per-heap. Doubles as a check that #4's PEB walk wasn't corrupted. |

**Additional payload-side 5-vector check** (C-code inside dwm.exe) at
`payload/src/dllmain.c::anti_debug_check` — runs BEFORE `init_thread`
installs any hooks. Same 5 vectors, plus:

- Vector 4a: hardware breakpoint scan (DR0-DR3) — catches attackers
  who set HW BPs on our DllMain / init_thread before injection
- Vector 4b: RDTSC differential across a NOP-loop — catches single-
  stepping debuggers (`si` in windbg / step-through in x64dbg)

**Return semantics:** all vectors are fail-closed. Any single vector
tripping → refuse to load session / refuse to install hooks. The
redundancy is the point — an attacker who NOPs any ONE path is still
caught by the others.

---

## 2. Frida-specific hardening (JS side)

**Process-name blocklist** at `ui/src/license/security.js`
`SUSPICIOUS_PROCESSES` — as of v6.3 (2026-07-06) includes:

```
frida               frida-server        frida-tools
frida-trace         frida-ps            pin
pintool             drltrace            drrun
drmemory            pymem               winappdbg
```

Plus 40+ other RE / debugger / packet-sniffer entries. Uses
`CreateToolhelp32Snapshot` via koffi — direct syscall, not hookable by
user-mode `tasklist` / `wmic` interception. If a match hits, sign-in is
disabled with a specific error naming the tool.

**Frida-server catch is the important one:** `frida-server` is what
runs as SYSTEM to allow `frida -p <pid>` from a remote machine, so
detecting it running catches the "someone opened a Frida REPL on this
machine" attack even before they've attached to us.

**Non-goal:** we don't try to catch Frida injected via `frida-gadget`
(a .dll dropped into the target's app dir) because that's already
covered by the module walk in `security.js` + `checkForMitm()` +
payload's PEB unlink + PE header wipe. If someone renames
`frida-gadget.dll` → `dwmext.dll` and drops it next to us, they still
have to (a) install a MITM CA to actually forward our TLS traffic
somewhere and (b) get past our 5-vector anti-debug — both of which we
catch.

---

## 3. MITM login-disable (JS side)

**Module:** `ui/src/license/mitm.js` (~360 LoC).
**Wired into:** `ui/src/main.js` `license:load` + `license:sign-in`
IPC handlers. Both refuse to touch the session (load or OAuth) if
`checkForMitm()` returns `!ok`.

### 3.1 The 4 kinds detected

| kind | What triggers | Renderer button label |
|---|---|---|
| `tls_bypass` | `NODE_TLS_REJECT_UNAUTHORIZED=0` env var | "Re-enable TLS validation for me" |
| `https_proxy_env` | `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` env var (any case) | "Remove proxy env vars for me" |
| `winhttp_proxy` | `netsh winhttp show proxy` returns a proxy AND a MITM CA is also present | "Reset WinHTTP proxy for me" |
| `mitm_ca` | Fiddler / mitmproxy / Charles / Burp / Proxyman / HTTP Toolkit / AnyProxy / OWASP ZAP / BadSSL root CA in `Cert:\CurrentUser\Root` or `Cert:\LocalMachine\Root` | "Uninstall <Tool> CA for me" |

### 3.2 Detection algorithm

Runs in strict order (fastest first):
1. Env var check (in-process, ~0 ms)
2. `netsh winhttp show proxy` (~200 ms)
3. PowerShell `Get-ChildItem Cert:\...Root | Select Subject` (~2-3 s cold)

Result: `{ ok:true }` if all clear, or `{ ok:false, kind, tool, details }`
otherwise. On the payload side, the `sub_check` thread would have
caught a mid-session Fiddler install at the next 30-min poll and
self-unloaded — mitm.js is the launcher-side defense that prevents the
attacker from even getting a fresh session.

### 3.3 One-click remediation

`mitm.remediate(kind, tool)` runs a `powershell.exe -NoProfile
-NonInteractive -Command` for each fixable kind:

- `tls_bypass` → `[Environment]::SetEnvironmentVariable('NODE_TLS_REJECT_UNAUTHORIZED', $null, 'User')` + Machine
- `https_proxy_env` → same for HTTPS_PROXY / HTTP_PROXY / ALL_PROXY + case variants
- `winhttp_proxy` → `netsh winhttp reset proxy` (needs admin — svchelper.exe has `requireAdministrator` manifest)
- `mitm_ca` → `Get-ChildItem Cert:\...Root | Where-Object Subject -match '<needle>' | Remove-Item -Force` for both stores

Returns `{ ok, action, message, details }`. Renderer toasts the message
+ auto-re-runs `checkForMitm` to update the banner. Zero shell-fiddling
from the user.

### 3.4 Dev escape hatch

Set `SVCLDB_ALLOW_PROXY=1` in the environment. `checkForMitm` returns
`{ ok:true, skipped:true }` immediately. Undocumented in the UI on
purpose — devs iterating against a local proxy know where to look.
NEVER set in production distribution.

---

## 4. Handshake token (defence-in-depth against `config.dat` theft)

Even if an attacker gets past MITM detection + anti-debug + all the
launcher-side gates, the payload itself checks a signed handshake on
inject. See `shared/handshake.h` for the derivation contract; summary:

```
sig_key = SHA-256(access_token || "svcldb-handshake-v1")
msg     = hwid || ":" || epoch_day_decimal
token   = HMAC-SHA-256(sig_key, msg)   -> 32 bytes
```

Written into `config.dat` by the Electron UI on every successful
sign-in. Payload's `init_thread` recomputes on inject and refuses to
install hooks if it doesn't match. Grace: today OR yesterday to cover
midnight rollover.

**Attack model this defeats:**
1. Attacker copies `config.dat` from a paying user's machine → their
   HWID differs → handshake fails.
2. Attacker forges a `config.dat` by hand → they don't have the real
   access_token (issued only via Google OAuth via Supabase) → can't
   compute sig_key → can't produce a matching token.
3. Attacker steals a 2-day-old `config.dat` → epoch_day is now +2 →
   only today and yesterday are accepted → rejected.

**Attack model this does NOT defeat:** live keylogger on the paying
user's machine that captures the token AND the HWID within 48h. That's
the domain of the payload's runtime `sub_check` (§5).

---

## 5. Runtime sub_check (defence-in-depth against session reuse)

Payload's `sub_check` thread (`payload/src/sub_check.c`) polls
Supabase every 30 min ± 20% jitter. On explicit `active: false` OR 3
consecutive network failures, it calls
`SetEvent(SVC_SHUTDOWN_EVENT_NAME)` which triggers the shutdown_watcher
to `MH_DisableHook(MH_ALL_HOOKS)` + `MH_Uninitialize()` + close the
overlay — same cooperative unload path as `--unload` from the launcher.

**What this catches that the launcher-side checks don't:**
- User whose subscription was revoked (billing failure, refund, ToS
  violation) — they still have a valid Supabase JWT on disk, but the
  hourly poll notices no active row → self-unload within 30 min.
- Fiddler installed AFTER app launched — the launcher-side check
  passed at load time, but the mid-session poll's HTTPS response
  either fails cert validation (fake CA now trusted → cert chain now
  goes through Fiddler → mismatched HSTS) OR gets 401'd because the
  session_id header they inserted doesn't match the token.

**Combined attack surface:**
- Launcher `mitm.js` catches at t=0 (login)
- Launcher `security.js` catches at t=0 + revalidateNow ticks
- Payload `anti_debug_check` catches at t=inject
- Payload `sub_check` catches at t=inject + every 30 min for the rest
  of the session

An attacker needs to defeat all four gates AT THE SAME TIME to have a
persistent bypass. Realistic threat: none of the off-the-shelf DBI /
MITM tools do this.

---

## 6. Hard invariants (V6.3 forward — DO NOT REGRESS)

1. **`security.js` anti-debug MUST cover ≥5 vectors.** Never trim back
   to just BeingDebugged. Any single vector NOP by an attacker is
   still caught by the other 4.
2. **`SUSPICIOUS_PROCESSES` MUST include the Frida family** (frida,
   frida-server, frida-tools, frida-trace, frida-ps). This is the
   modern-DBI equivalent of the classic debugger list from 2010.
3. **`mitm.checkForMitm()` MUST run BEFORE `startOAuth()` in
   `license:sign-in`.** An attacker's proxy would grab the auth code
   from the callback URL otherwise, then exchange it themselves on the
   real Supabase endpoint — game over.
4. **`mitm.checkForMitm()` MUST run BEFORE session load in
   `license:load`.** An installed CA can spoof the subscription check
   → user is granted access without a real subscription. Refuse to
   load the session at all.
5. **`checkForMitm()` uses SUBSTRING match on cert Subject,
   case-insensitive.** Corp CAs vary widely; substring match with the
   documented default CA name of each tool (in the `MITM_CA_PATTERNS`
   table) is the correct balance between coverage + false-positive
   rate.
6. **`remediate()` MUST update `process.env` IN-PROCESS BEFORE
   returning success.** Node's env block is a snapshot at fork time; a
   subsequent `checkForMitm()` would read the stale value otherwise.
7. **The `SVCLDB_ALLOW_PROXY=1` dev escape hatch MUST NEVER ship enabled
   in production.** Grep-check on every release cut:
   ```powershell
   Get-ChildItem ui/src -Recurse -Include *.js |
     Select-String -Pattern 'ALLOW_PROXY.*=.*1'
   ```
   Must return zero matches (comments-only mentions are fine).

---

## 7. Files touched in the 2026-07-06 evening pass

**svcldb:**
- `ui/src/license/security.js` — SUSPICIOUS_PROCESSES grew ~25 → 40+
  entries, added Frida/DBI/Burp/Proxyman/pymem/winappdbg families
- `docs/HANDOFF_ANTI_DBI_MITM_2026-07-06.md` — this file

**hooksdll (V10.1.20 port):**
- `lumio/src/license/mitm.js` — NEW ~360 LoC, verbatim port of svcldb's
  mitm.js with hooksdll-specific env-var name (`CLOAKGPT_ALLOW_PROXY`
  instead of `SVCLDB_ALLOW_PROXY`).
- `lumio/src/license/license.js` — MITM check added to `init()`,
  `login()`, and `revalidateNow()`. New `mitmRecheck` +
  `mitmRemediate` + `getLastMitmResult` exports.
- `lumio/src/license/security.js` — grew 3-vector anti-debug → 5-vector
  to match svcldb. Added Frida-family process names to
  `SUSPICIOUS_PROCESSES` (~25 → 40+).
- `lumio/src/main.js` — new IPC handlers `license-mitm-recheck`,
  `license-mitm-remediate`, `license-mitm-last`.
- `lumio/src/preload.js` — added `licenseMitmRecheck`,
  `licenseMitmRemediate`, `licenseMitmLast` to the `lumio` bridge.
- `lumio/src/renderer.js` — `showLoginScreen` grew a `#license-mitm-banner`
  div + Fix-now + Re-check buttons. Detects `state.reason === 'mitm_detected'`
  (or `state.mitm.kind`) and disables Sign In button while blocked.
- `CLAUDE.md` — V10.1.20 milestone section.

---

## 8. Web-verified sources (2026-07-06)

1. Frida gadget/server threat model —
   https://frida.re/docs/frida-server/
2. NtGlobalFlag heap-debug bits —
   https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table
3. PEB layout on x64 (offset 0xBC = NtGlobalFlag) —
   https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm
4. MITM CA subject patterns —
   - Fiddler: https://docs.telerik.com/fiddler-everywhere/user-guide/settings/https
   - mitmproxy: https://docs.mitmproxy.org/stable/concepts-certificates/
   - Charles: https://www.charlesproxy.com/documentation/using-charles/ssl-certificates/
   - Burp: https://portswigger.net/burp/documentation/desktop/tools/proxy/http/browser-cert-install
   - Proxyman: https://docs.proxyman.io/general/basic-features/enable-ssl-proxying
   - HTTP Toolkit: https://httptoolkit.tech/docs/reference/ca-certificates/
   - OWASP ZAP: https://www.zaproxy.org/docs/desktop/addons/zed-attack-proxy/hud/
5. `netsh winhttp reset proxy` requires admin —
   https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-winhttp
6. koffi (Node FFI) —
   https://koffi.dev/functions
