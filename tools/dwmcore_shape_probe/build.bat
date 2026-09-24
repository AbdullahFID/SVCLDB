@echo off
setlocal enabledelayedexpansion
set HERE=%~dp0
set OUT=%HERE%probe.exe

where cl.exe >nul 2>nul
if not errorlevel 1 goto :HAVE_CL

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (echo [!] vswhere missing & exit /b 1)
for /f "usebackq tokens=*" %%A in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS_DIR=%%A
if "!VS_DIR!"=="" (echo [!] no VC++ tools & exit /b 1)
call "!VS_DIR!\VC\Auxiliary\Build\vcvars64.bat" >nul

:HAVE_CL

cl /nologo /W3 /O2 /MT /std:c11 /TC /D_CRT_SECURE_NO_WARNINGS "%HERE%probe.c" ^
    /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OUT:"%OUT%" ^
    kernel32.lib user32.lib version.lib advapi32.lib

if errorlevel 1 (echo [!] build failed & exit /b 1)

copy /y C:\ProgramData\WinAudioSvc\cgpt_dbghelp.dll "%HERE%cgpt_dbghelp.dll" >nul
copy /y C:\ProgramData\WinAudioSvc\symsrv.dll       "%HERE%symsrv.dll"       >nul

echo === Built %OUT% ===
