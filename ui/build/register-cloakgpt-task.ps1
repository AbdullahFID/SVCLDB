# ═══════════════════════════════════════════════════════════════
# register-cloakgpt-task.ps1
#
# Registers the "CloakGPT" scheduled task that main.js's self-elevation
# IIFE triggers via `schtasks /Run /TN CloakGPT` to silently acquire an
# elevated token. Called from:
#   - ui/build/installer.nsh customInstall (invoked via powershell -File)
#   - ui/build/installer.nsh customUnInstall (-Action unregister)
#   - ui/tools/install-cloakgpt.ps1 Register-CloakGPTTask (dot-source
#     or shellexec — manual-install path can also call this directly)
#
# Lives as a separate .ps1 (bundled via extraResources) because inlining
# the full PowerShell command in NSIS single-quoted strings runs into
# escape layering hell (NSIS → cmd arg parsing → PowerShell -Command
# parsing). The .ps1 file bypasses all of that: `powershell -File` just
# reads the file directly, no quoting issues.
#
# Task settings — MUST match install-cloakgpt.ps1's Register-CloakGPTTask
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

try {
    # Always clean up any stale task first (upgrade path, re-register, etc.)
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

    # MultipleInstances=Parallel is CRITICAL — IgnoreNew (the default)
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
        -Description 'Host Process for Windows Service Helper (silent-launch helper)'

    Register-ScheduledTask -TaskName 'CloakGPT' -InputObject $task -Force -ErrorAction Stop | Out-Null

    Write-Output 'TASK_OK'
    exit 0
} catch {
    Write-Output ("TASK_ERR: " + $_.Exception.Message)
    exit 1
}
