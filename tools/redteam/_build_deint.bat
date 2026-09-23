@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo [FAIL] vcvars64.bat not found
    exit /b 1
)
cd /d "%~dp0"
cl.exe /nologo /W3 /O2 /D_UNICODE /DUNICODE deint.c /Fe:deint.exe /link user32.lib advapi32.lib >nul
if errorlevel 1 (
    echo [FAIL] cl failed
    exit /b 1
)
del deint.obj 2>nul
echo === built deint.exe ===
dir deint.exe
