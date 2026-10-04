# ═══════════════════════════════════════════════════════════════
# register-cloakgpt-task.ps1
#
# Registers the silent-launch scheduled task that main.js's self-elevation
# IIFE triggers via `schtasks /Run /TN <path>` to silently acquire an
# elevated token. Called from:
#   - ui/build/installer.nsh customInstall (invoked via powershell -File)
#   - ui/build/installer.nsh customUnInstall (-Action unregister)
#   - ui/tools/install-cloakgpt.ps1 Register-CloakGPTTask (dot-source
#     or shellexec - manual-install path can also call this directly)
#
# Lives as a separate .ps1 (bundled via extraResources) because inlining
# the full PowerShell command in NSIS single-quoted strings runs into
# escape layering hell (NSIS -> cmd arg parsing -> PowerShell -Command
# parsing). The .ps1 file bypasses all of that: `powershell -File` just
# reads the file directly, no quoting issues.
#
# v8.2 (2026-10-03) -- MAX-STEALTH TASK RENAME.
#
# Previous name: tree root "\CloakGPT" (visible as a top-level entry in
# Task Scheduler's Library root, instant tell for any proctor who opens
# taskschd.msc). Hidden flag was set but Task Scheduler's "Show hidden
# tasks" default-off meant it was invisible there -- but schtasks CLI
# enumeration + Autoruns + SysInternals all still show it at the root.
#
# New name: nested under "\Microsoft\Windows\Multimedia\AudioServiceSupport"
# -- right alongside legit tasks like \Microsoft\Windows\Multimedia\
# SystemSoundsService. Three levels deep inside Microsoft\Windows\, where
# a casual audit of top-level tasks sees nothing out of the ordinary. Any
# proctor who DOES drill into Microsoft\Windows\Multimedia sees a
# plausible-sounding "AudioServiceSupport" with the generic description.
#
# Legacy name "\CloakGPT" (tree root) is best-effort removed on every
# register/unregister so pre-v8.2 installs upgrade cleanly.
#
# Task settings - MUST match install-cloakgpt.ps1's Register-CloakGPTTask
# function exactly so both install paths produce identical tasks.
#
# Returns exit 0 on success, 1 on failure. Writes TASK_OK or
# TASK_ERR: <reason> to stdout for the NSIS install log.
# ═══════════════════════════════════════════════════════════════
param(
    [Parameter(Mandatory)][string]$ExePath,
    [ValidateSet('register','unregister')][string]$Action = 'register'
)

$ErrorActionPreference = 'Stop'

# v8.2 (2026-10-03) -- nested task path. Keep in sync with:
#   - ui/src/main.js (self-elevation /Query + /Run)
#   - ui/tools/install-cloakgpt.ps1 (manual-install path mirror)
#   - ui/build/installer.nsh (fallback schtasks /Delete on uninstall)
$TASK_PATH = '\Microsoft\Windows\Multimedia\'
$TASK_NAME = 'AudioServiceSupport'
$TASK_FULL = $TASK_PATH + $TASK_NAME     # '\Microsoft\Windows\Multimedia\AudioServiceSupport'
$LEGACY_FULL = '\CloakGPT'               # pre-v8.2 root location (upgrade cleanup)

try {
    # Always clean up any stale task first (upgrade path, re-register, etc.)
    # Both the new nested name AND the legacy root name.
    if (Get-ScheduledTask -TaskPath $TASK_PATH -TaskName $TASK_NAME -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskPath $TASK_PATH -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    }
    if (Get-ScheduledTask -TaskName 'CloakGPT' -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName 'CloakGPT' -Confirm:$false -ErrorAction SilentlyContinue
    }

    if ($Action -eq 'unregister') {
        Write-Output 'TASK_UNREGISTERED'
        exit 0
    }

    if (-not (Test-Path -LiteralPath $ExePath)) {
        Write-Output "TASK_ERR: ExePath not found: $ExePath"
        exit 2
    }

    $workDir = Split-Path -Parent $ExePath

    $actionObj = New-ScheduledTaskAction -Execute $ExePath -Argument '--via-task' -WorkingDirectory $workDir
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

    # MultipleInstances=Parallel is CRITICAL - IgnoreNew (the default)
    # gets stuck behind a ghost phantom after a crashed/killed instance.
    # Parallel lets concurrent /Run invocations always fire; the Electron
    # single-instance lock in main.js dedupes at the app layer. Learned
    # the hard way 2026-10-03.
    $settings = New-ScheduledTaskSettingsSet `
        -Hidden `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances Parallel `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -StartWhenAvailable:$false

    $task = New-ScheduledTask `
        -Action $actionObj `
        -Principal $principal `
        -Settings $settings `
        -Description 'Audio service support host (Microsoft Windows Multimedia).'

    Register-ScheduledTask -TaskPath $TASK_PATH -TaskName $TASK_NAME -InputObject $task -Force -ErrorAction Stop | Out-Null

    Write-Output 'TASK_OK'
    exit 0
} catch {
    Write-Output ("TASK_ERR: " + $_.Exception.Message)
    exit 1
}
