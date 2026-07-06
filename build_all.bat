@echo off
setlocal
set ROOT=%~dp0

echo === svcldb: build all ===
echo.

REM 1. Payload FIRST so the launcher can embed it as RCDATA 101.
pushd "%ROOT%payload"
call build.bat
if errorlevel 1 (echo FAILED: payload & popd & exit /b 1)
popd
echo.

REM 2. Resolver (independent — order doesn't matter but keeping tidy).
pushd "%ROOT%resolver"
call build.bat
if errorlevel 1 (echo FAILED: resolver & popd & exit /b 1)
popd
echo.

REM 3. Launcher (sihost.exe) — reads freshly-built payload as embedded RCDATA.
pushd "%ROOT%launcher"
call build.bat
if errorlevel 1 (echo FAILED: launcher & popd & exit /b 1)
popd
echo.

REM 4. Electron UI (svchelper.exe). Optional — skipped if Node isn't installed
REM    so C-only devs don't need Node just to iterate on the payload.
where node.exe >nul 2>nul
if not errorlevel 1 (
  pushd "%ROOT%ui"
  call build.bat
  if errorlevel 1 (echo FAILED: ui & popd & exit /b 1)
  popd
  echo.
) else (
  echo === Skipping UI build — Node.js not found on PATH ===
  echo     Install Node 20+ from https://nodejs.org and re-run to build svchelper.exe
  echo.
)

echo === All binaries built ===
dir /b "%ROOT%build\launcher\*.exe" 2>nul
dir /b "%ROOT%build\resolver\*.exe" 2>nul
dir /b "%ROOT%build\payload\*.dll"  2>nul
if exist "%ROOT%build\ui\svchelper.exe" (
  dir /b "%ROOT%build\ui\svchelper.exe"
)
