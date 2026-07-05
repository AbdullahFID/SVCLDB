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

set SOURCES=^
 "%SHARED%\log_secure.c" "%SHARED%\log_key.c" ^
 "%SRC%\main.c"

set LDFLAGS=/nologo /SUBSYSTEM:CONSOLE /LTCG /DEBUG:NONE /Brepro /OPT:REF /OPT:ICF ^
 /INCREMENTAL:NO /MANIFEST:NO ^
 /OUT:"%BUILD%\%OUT_NAME%"

cl %CFLAGS% /I "%SHARED%" /I "%SRC%" ^
   %SOURCES% ^
   /link %LDFLAGS% ^
   kernel32.lib user32.lib advapi32.lib bcrypt.lib

if errorlevel 1 (echo [!] Link failed. & exit /b 1)

del /q "%BUILD%\*.obj" 2>nul
del /q "%BUILD%\*.pdb" 2>nul
del /q "%BUILD%\*.exp" 2>nul
del /q "%BUILD%\*.lib" 2>nul

for %%F in ("%BUILD%\%OUT_NAME%") do echo === Built %%F  (%%~zF bytes) ===
