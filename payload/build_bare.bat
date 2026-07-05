@echo off
setlocal enabledelayedexpansion

set SRC=%~dp0src
set BUILD=%~dp0..\build\payload

if not exist "%BUILD%" mkdir "%BUILD%"

where cl.exe >nul 2>nul
if not errorlevel 1 goto :HAVE_CL

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (echo [!] vswhere missing & exit /b 1)
for /f "usebackq tokens=*" %%A in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS_DIR=%%A
if "%VS_DIR%"=="" (echo [!] no VC++ tools & exit /b 1)
call "%VS_DIR%\VC\Auxiliary\Build\vcvars64.bat" >nul

:HAVE_CL

cd /d "%SRC%"
REM /ENTRY:DllMain — bypass _DllMainCRTStartup CRT wrapper. When manual-mapped,
REM CRT startup does things (TLS init, atexit, etc.) that may silently fail. Our
REM DllMain doesn't need CRT init so we can skip the wrapper.
REM /NODEFAULTLIB:libcmt — no static CRT (we don't use any CRT functions here)
cl /nologo /O2 /GS- /LD /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN ^
   bare_test.c /Fe:"%BUILD%\bare_test.dll" ^
   /link /DEF:bare_test.def /DEBUG:NONE /GUARD:NO /RELEASE ^
   /INCREMENTAL:NO /MANIFEST:NO /ENTRY:DllMain /NODEFAULTLIB ^
   kernel32.lib

del /q bare_test.obj bare_test.lib bare_test.exp 2>nul
if exist "%BUILD%\bare_test.dll" (
  for %%F in ("%BUILD%\bare_test.dll") do echo === Built %%F  (%%~zF bytes) ===
) else (
  echo BUILD FAILED
  exit /b 1
)
