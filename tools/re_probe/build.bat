@echo off
setlocal
where cl >nul 2>&1
if errorlevel 1 (
  call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
)
cl /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS dwmcore_dump.c /link psapi.lib
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo Built dwmcore_dump.exe
endlocal
