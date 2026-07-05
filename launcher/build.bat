@echo off
setlocal enabledelayedexpansion

REM =============================================================
REM  build.bat — Build the launcher exe (sihost.exe)
REM
REM  Requires an x64 Native Tools Command Prompt environment.
REM  Auto-locates VS 2022 via vswhere.
REM =============================================================

set ROOT=%~dp0..
set SHARED=%ROOT%\shared
set SRC=%~dp0src
set BUILD=%ROOT%\build\launcher
set OUT_NAME=sihost.exe

if not exist "%BUILD%" mkdir "%BUILD%"

REM ── Locate cl.exe via vswhere ──────────────────────────────────
where cl.exe >nul 2>nul
if not errorlevel 1 goto :HAVE_CL

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (
  echo [!] vswhere.exe missing. Install VS 2019+ or open a VS Developer Prompt.
  exit /b 1
)
for /f "usebackq tokens=*" %%A in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
  set VS_DIR=%%A
)
if "%VS_DIR%"=="" (
  echo [!] No VS installation with VC++ x64 tools found.
  exit /b 1
)
call "%VS_DIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
where cl.exe >nul 2>nul || (echo [!] vcvars64 failed to set up cl.exe & exit /b 1)

:HAVE_CL

echo === Building %OUT_NAME% ===

REM ── Compile flags ──────────────────────────────────────────────
REM  /O2       optimize for speed
REM  /GS       stack cookies (defense)
REM  /Gy       function-level linking (dead-strip)
REM  /MT       static CRT (no dependency on vcruntime redist)
REM  /GL       whole-program optimization
REM  /DNDEBUG  strip debug asserts
set CFLAGS=/nologo /W3 /O2 /Oi /GS /Gy /MT /GL /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN

REM ── Compile shared modules + launcher sources ─────────────────
set SOURCES=^
 "%SHARED%\log_secure.c" "%SHARED%\log_key.c" ^
 "%SHARED%\base64.c" "%SHARED%\hwid.c" ^
 "%SHARED%\winhttp_util.c" "%SHARED%\json_util.c" ^
 "%SHARED%\crypto_util.c" "%SHARED%\supabase_config.c" ^
 "%SRC%\oauth.c" "%SRC%\license.c" ^
 "%SRC%\inject.c" "%SRC%\config_write.c" ^
 "%SRC%\main.c"

REM ── Compile the .rc for the elevation manifest ────────────────
rc /nologo /r /fo "%BUILD%\launcher.res" "%SRC%\launcher.rc"
if errorlevel 1 (echo [!] rc failed & exit /b 1)

REM ── Link ──────────────────────────────────────────────────────
REM  /SUBSYSTEM:CONSOLE keeps stderr visible during MVP dev; switch to
REM  WINDOWS once ImGui launcher is done.
REM  /DEBUG:NONE + /EMITPOGODB:NO strip debug info to shrink binary
REM  and prevent PDB path leaks. /Brepro forces deterministic timestamps.
set LDFLAGS=/nologo /SUBSYSTEM:CONSOLE /LTCG /DEBUG:NONE /Brepro /OPT:REF /OPT:ICF ^
 /INCREMENTAL:NO /MANIFEST:NO ^
 /OUT:"%BUILD%\%OUT_NAME%"

cl %CFLAGS% /I "%SHARED%" /I "%SRC%" ^
   %SOURCES% ^
   "%BUILD%\launcher.res" ^
   /link %LDFLAGS% ^
   kernel32.lib user32.lib advapi32.lib bcrypt.lib winhttp.lib ws2_32.lib shell32.lib

if errorlevel 1 (
  echo [!] Link failed.
  exit /b 1
)

REM ── Strip PDB references and clean intermediates ──────────────
del /q "%BUILD%\*.obj" 2>nul
del /q "%BUILD%\*.pdb" 2>nul
del /q "%BUILD%\*.exp" 2>nul
del /q "%BUILD%\*.lib" 2>nul
del /q "%BUILD%\*.res" 2>nul

for %%F in ("%BUILD%\%OUT_NAME%") do echo === Built %%F  (%%~zF bytes) ===
