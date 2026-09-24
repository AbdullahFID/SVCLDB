@echo off
setlocal
set HERE=%~dp0
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%HERE%"
cl /nologo /W3 /O2 /MT /D_CRT_SECURE_NO_WARNINGS probe.c ^
    /link /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /OUT:probe.exe ^
    kernel32.lib user32.lib version.lib advapi32.lib
if errorlevel 1 exit /b 1
copy /y C:\ProgramData\WinAudioSvc\cgpt_dbghelp.dll "%HERE%cgpt_dbghelp.dll" >nul
copy /y C:\ProgramData\WinAudioSvc\symsrv.dll       "%HERE%symsrv.dll"       >nul
echo OK: %HERE%probe.exe
