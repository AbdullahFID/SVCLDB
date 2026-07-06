@echo off
setlocal enabledelayedexpansion

REM ================================================================
REM  ui/build.bat — Build the Electron helper (svchelper.exe).
REM
REM  Steps:
REM    1. pnpm install (idempotent — only re-installs if node_modules
REM       is missing OR pnpm-lock.yaml is stale).
REM    2. node build-protected.js — obfuscates every .js in src/ into
REM       src-build/, then invokes electron-builder --win.
REM    3. Copy dist/win-unpacked/ into ../build/ui/ so the parent
REM       deploy scripts can pick it up.
REM
REM  Requires: Node.js 20+ and pnpm on PATH (see .npmrc for pnpm
REM  layout settings). No Visual Studio needed — no native modules.
REM ================================================================

set ROOT=%~dp0..
set UI=%~dp0
set OUT=%ROOT%\build\ui

REM Fail early if pnpm isn't installed.
where pnpm >nul 2>nul
if errorlevel 1 (
  echo [!] pnpm not found on PATH.
  echo     Install via: winget install pnpm.pnpm
  echo     or:          npm i -g pnpm
  exit /b 1
)

pushd "%UI%"

echo === Ensuring UI dependencies via pnpm ===
if not exist "node_modules" (
  echo   node_modules missing — running pnpm install ...
  call pnpm install --prefer-frozen-lockfile=false
  if errorlevel 1 (
    echo [!] pnpm install FAILED
    popd
    exit /b 1
  )
) else (
  echo   node_modules present — skipping install ^(delete node_modules to force^)
)

echo.
echo === Running protected build ===
call node build-protected.js
if errorlevel 1 (
  echo [!] build-protected.js FAILED
  popd
  exit /b 1
)

echo.
echo === Copying dist\win-unpacked to build\ui ===
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%" >nul 2>nul
xcopy /e /i /y /q "dist\win-unpacked\*" "%OUT%\" >nul
if errorlevel 1 (
  echo [!] copy to %OUT% failed
  popd
  exit /b 1
)

for %%F in ("%OUT%\svchelper.exe") do echo === Built %%F  ^(%%~zF bytes^) ===
popd
