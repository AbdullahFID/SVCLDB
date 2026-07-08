@echo off
setlocal
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%A in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS_DIR=%%A
call "%VS_DIR%\VC\Auxiliary\Build\vcvars64.bat" >nul

set SHARED=..\..\shared
set SRC=..\src

cl /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN ^
   /I "%SHARED%" /I "%SRC%" ^
   ai_e2e_test.c ^
   "%SRC%\ai\ai_provider.c" ^
   "%SHARED%\json_util.c" "%SHARED%\base64.c" ^
   "%SHARED%\winhttp_util.c" ^
   "%SHARED%\crypto_util.c" "%SHARED%\log_secure.c" ^
   "%SHARED%\log_key.c" ^
   "%SHARED%\str_enc.c" ^
   /link kernel32.lib user32.lib advapi32.lib bcrypt.lib winhttp.lib ^
         ole32.lib shlwapi.lib

if errorlevel 1 (
   echo [!] build failed
   exit /b 1
)
echo === built ai_e2e_test.exe ===
