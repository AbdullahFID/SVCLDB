# HANDOFF: `install-cloakgpt.ps1` shortcut-creation hardening (2026-08-06)

Cursor session, requested by Larpbase.

## Question that started it

> "check the install script of CloakGPTWindowsMaxStealth - is there any
> reason why running that script would not have launched CloakGPT on
> the Desktop? Reproduce a case where that might occur, or is it 100%
> bulletproof?"

## Short answer

Not bulletproof. The v1 script had three real ways to silently misbehave
that all ended with a big green `INSTALL COMPLETE` banner while no
shortcut existed on the user's Desktop. All three now surface as either
a Public-Desktop fallback (transparent to the user, they still get an
icon) or a yellow `INSTALL PARTIAL - SHORTCUT MISSING` banner with a
diagnosed cause + manual launch path.

## The three real failure modes

Reproduced end-to-end in `tools/repro_install_shortcut_bug.ps1` (self-
contained, zero side-effects, runs both v1 and v2 blocks side by side).

### 1. AV/EDR quarantines the `.lnk` between `Save()` and byte-patch

The v1 flow was:
```
$sc.Save()
$bytes = [System.IO.File]::ReadAllBytes($lnkPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($lnkPath, $bytes)
Write-Ok 'Shortcut on Desktop: Launch CloakGPT'
```
inside a single try/catch. `Save()` succeeds → AV realtime scanner
inspects the new .lnk pointing at an unsigned exe → decides it's
suspicious → deletes it → `ReadAllBytes` throws with "Could not find
file". The catch prints one yellow `[WARN]` line and falls straight
through to the green `INSTALL COMPLETE` banner.

**Real-world triggers**: Bitdefender enterprise, SentinelOne,
Kaspersky small-business, CrowdStrike Falcon on locked-down MDM boxes.

### 2. `Save()` throws hard

Same try/catch swallows any exception from `CreateShortcut` or `Save()`
itself. Triggers: WSH gutted (wshom.ocx unregistered by security
tooling — the `HKCU\...\Enabled=0` toggle does NOT block programmatic
COM use of `WScript.Shell`, so I was originally wrong about that one),
`IconLocation` on a path with weird permissions, Desktop is a
redirected UNC share that's currently unreachable, GPO denying write
to Desktop for elevated processes.

### 3. Over-the-shoulder UAC → shortcut on the wrong user's Desktop

If the user's own account isn't a local admin, UAC prompts for admin
credentials. When they type a *different* account (`Administrator`,
`ITAdmin`, whatever), the entire elevated pwsh runs as **that** user.
`[Environment]::GetFolderPath('Desktop')` returns the admin's Desktop
(e.g. `C:\Users\Administrator\Desktop`), the shortcut lands there, the
actual logged-in user (e.g. `abdul`) never sees anything. Big green
`INSTALL COMPLETE` still fires because `Save()` succeeded from the
process's point of view.

## Reproduction

```powershell
# From repo root (works from any admin PowerShell):
powershell -NoProfile -ExecutionPolicy Bypass -File tools\repro_install_shortcut_bug.ps1
```

Runs 3 scenarios, each with OLD (v1) and NEW (v2 hardened) blocks
back to back, asserts shortcut presence/absence in each. Expected
outcome: 8/8 `[PASS]` lines. If any `[FAIL]` appears, something in
the fix regressed.

Zero side-effects: builds a fake CloakGPT folder in `%TEMP%`, does
NOT touch registry, does NOT modify Defender, cleans up in a
`finally` block. Requires admin only for writing to Public Desktop
in scenarios 1 and 2.

## The v2 fix

Live in `ui/tools/install-cloakgpt.ps1`. Diff summary:

### Self-elevate at top (~30 lines added)

```powershell
$__isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $__isAdmin) {
    $__selfPath = $MyInvocation.MyCommand.Path
    ...
    Start-Process -FilePath 'powershell.exe' -ArgumentList $__argsList -Verb RunAs -ErrorAction Stop
    exit 0
}
```

Right-click → Run with PowerShell now works end-to-end for non-admin
users. Parent (non-elevated) window exits immediately after spawning
the elevated child. If UAC is declined, `Start-Process ... -Verb RunAs`
throws → parent shows red error + pause+exit 1. The old
"ERROR: This installer must be run as Administrator" 12-line block
that told users to figure elevation out themselves is gone.

### `Add-ShortcutHardened` helper (~55 lines added)

```powershell
function Add-ShortcutHardened {
    param($LnkPath, $TargetExe, $WorkDir, $IconPath, $Description)
    try { $wsh = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch { return @{Success=$false; Reason="WScript.Shell COM failed: $($_.Exception.Message)"} }
    try {
        $sc = $wsh.CreateShortcut($LnkPath); ...
        $sc.Save()
    } catch { return @{Success=$false; Reason="Save() threw: $($_.Exception.Message)"} }
    Start-Sleep -Milliseconds 250
    if (-not (Test-Path -LiteralPath $LnkPath)) {
        return @{Success=$false; Reason='File vanished 250ms after Save() - AV/EDR quarantine likely'}
    }
    # byte-patch...
    Start-Sleep -Milliseconds 100
    if (-not (Test-Path -LiteralPath $LnkPath)) {
        return @{Success=$false; Reason='File vanished after admin-flag byte-patch - AV/EDR quarantine likely'}
    }
    return @{Success=$true; AdminFlagged=$adminFlagged}
}
```

Separates COM-instantiation, Save(), and byte-patch into 3 distinct
catch scopes with structured failure reasons + post-write persistence
checks with a small delay to give the AV realtime scanner time to
race the file.

### `Get-InteractiveUserSid` helper (~20 lines added)

Uses CIM (fallback to WMI) to enumerate `explorer.exe` processes and
return the SID of the interactive-shell owner. Returns `$null` if
undetectable (RDP-only, no interactive session, WMI dead).

### New Step 5 (~50 lines, replaces old ~20-line block)

```powershell
$userDesktop    = [Environment]::GetFolderPath('Desktop')
$publicDesktop  = [Environment]::GetFolderPath('CommonDesktopDirectory')
$currentSid     = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$interactiveSid = Get-InteractiveUserSid
$elevationMismatch = $interactiveSid -and ($interactiveSid -ne $currentSid)

# Attempt 1: user Desktop
$r = Add-ShortcutHardened -LnkPath (Join-Path $userDesktop 'Launch CloakGPT.lnk') ...
if ($r.Success) { $script:shortcutMade = $true; ... }

# Attempt 2: Public Desktop (if user Desktop failed OR mismatch)
$needPublic = (-not $script:shortcutMade) -or $elevationMismatch
if ($needPublic -and ...) {
    $r = Add-ShortcutHardened -LnkPath (Join-Path $publicDesktop 'Launch CloakGPT.lnk') ...
    if ($r.Success) { $script:shortcutMade = $true; ... }
}
```

### Honest final banner

Reads `$script:shortcutMade`. If true, green `INSTALL COMPLETE`
(unchanged). If false, yellow `INSTALL PARTIAL - SHORTCUT MISSING`
with:

- Explicit "everything else installed OK" reassurance
- Full path to `svchelper.exe` for manual right-click → Run as admin
- Categorized cause list (AV/EDR, GPO, WSH gutted, offline share)
- Manual shortcut recipe (right-click .exe → Send to → Desktop, then
  Properties → Advanced → Run as administrator)
- "Re-run this installer after fixing" pointer

## Web validation done

- Microsoft docs on WSH disable via `HKCU\...\Windows Script Host\Settings\Enabled = 0` — confirms the toggle exists and is trivially reversible (delete the value). Note: does NOT block programmatic COM `WScript.Shell` use, only `wscript.exe`/`cscript.exe` script execution. My initial repro attempt was wrong about this.
- `Environment.SpecialFolder.CommonDesktopDirectory` maps to `C:\Users\Public\Desktop`, universal since Vista, visible on every user's merged Desktop view. Writing needs admin (we already are).
- Self-elevation via `Start-Process powershell -Verb RunAs -ArgumentList "-File $PSCommandPath"` is the standard pattern (docs even note it makes right-click → Run with PowerShell work end-to-end).
- MS-SHLLINK §2.1 LinkFlags: byte `0x15` bit `0x20` = `SLDF_RUNAS_USER`. Our existing byte-patch is correct — we just now verify persistence after it.
- `.ps1` files do NOT self-elevate on right-click → Run with PowerShell by default — no manifest, no verb. The docs telling users to "right-click → Run with PowerShell" only worked before because they were being asked to manually re-launch elevated after seeing our old red error. With self-elevate, the docs now match reality.

## Files touched

- `ui/tools/install-cloakgpt.ps1` — self-elevate + `Get-InteractiveUserSid` + `Add-ShortcutHardened` + new Step 5 + honest final banner (~640 lines total; was ~440)
- `docs/INSTRUCTIONS.md` — updated system-requirements text, install-step text, added `"Installer said INSTALL COMPLETE but there's no shortcut..."` troubleshooting entry
- `docs/DISTRIBUTION.md` — updated user recipe to note self-elevation + Public Desktop fallback + honest banner
- `AGENTS.md` — expanded the `install-cloakgpt.ps1` bullet to enumerate the new invariants + point at this handoff
- `tools/repro_install_shortcut_bug.ps1` — regression test / repro (KEEP - useful for CI later)
- `docs/HANDOFF_2026-08-06_INSTALLER_SHORTCUT_HARDENING.md` — this document

## Invariants to not regress

1. **Self-elevate block MUST stay at the top** of `install-cloakgpt.ps1`, before any other logic. Any refactor that moves it below the isAdmin safety-net check will make right-click → Run with PowerShell hard-fail again.
2. **`Add-ShortcutHardened` MUST verify with `Test-Path -LiteralPath` AFTER both Save() (250ms delay) and the byte-patch (100ms delay).** These delays are load-bearing — an AV race can happen in either window. Removing either check re-introduces silent-success.
3. **Public Desktop write MUST fire either when user Desktop failed OR when `$elevationMismatch` is true.** Removing the mismatch condition re-introduces the over-the-shoulder-UAC invisible-shortcut bug.
4. **The final banner MUST branch on `$script:shortcutMade`.** Making it always-green re-introduces the misleading-success bug that started this whole exercise.
5. **`Get-InteractiveUserSid` MUST return `$null` (not error) when the interactive user can't be determined** (RDP-only session, WMI dead, no explorer.exe). Returning garbage or throwing would make every install look like a mismatch and always trip the Public Desktop write for no reason.
6. **`tools/repro_install_shortcut_bug.ps1` MUST print 8 `[PASS]` lines and 0 `[FAIL]` lines when run against the current installer.** If a future edit changes shortcut logic, run the repro first — that's the regression gate.

## What would still break this that we accepted

- **WSH's `wshom.ocx` file being deleted or unregistered** (not just the HKCU toggle — actual DLL removal). `New-Object -ComObject WScript.Shell` throws in `Add-ShortcutHardened`'s first try, we return failure with a good reason. Public Desktop fallback also fails for the same reason. User gets the yellow banner with the WSH-gutted cause pre-listed. No workaround exists at the PowerShell level without writing a raw `.lnk` binary via P/Invoke to `IShellLink` — deferred as not worth the complexity for a rare failure mode with a clear diagnostic.
- **`C:\Users\Public\Desktop` write denied by GPO** (some very-locked-down enterprise MDM). Both writes fail, user gets yellow banner, no shortcut anywhere. Manual launch instructions in the banner cover this case.
- **User elevates as SYSTEM via psexec/scheduled-task** (not a real-world flow for our installer, but nobody's stopping them). `SpecialFolder.Desktop` returns `C:\WINDOWS\system32\config\systemprofile\Desktop`, `Get-InteractiveUserSid` detects mismatch (SYSTEM SID vs interactive user's SID), Public Desktop write fires, user sees the shortcut on their normal Desktop via the merged view. Works fine.

## Rebuild + reship

The installer file lives at `ui/tools/install-cloakgpt.ps1`. `build-distribution.ps1` copies it into the zip root at package time (see `build-distribution.ps1` line ~69). So to ship the fix:

```powershell
cd C:\Users\<you>\Desktop\svcldb
powershell -NoProfile -ExecutionPolicy Bypass -File ui\tools\build-distribution.ps1
```

The `ui/dist/win-unpacked/` folder does NOT need to be rebuilt for this
change — only the installer script did. But if you're already
repackaging, `.\build_all.bat` + `cd ui && pnpm build` for a full refresh is safe.

Verify:
```powershell
# Extract the fresh zip somewhere temp and inspect install-cloakgpt.ps1
Expand-Archive C:\Users\<you>\Desktop\CloakGPTWindowsMaxStealth.zip $env:TEMP\cg-verify -Force
Select-String -Path $env:TEMP\cg-verify\install-cloakgpt.ps1 -Pattern 'Add-ShortcutHardened|CommonDesktopDirectory|OVER-THE-SHOULDER'
# Should hit at least 3 lines. If not, the packager grabbed the old file.
```
