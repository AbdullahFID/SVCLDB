@echo off
setlocal
set ROOT=%~dp0

echo === svcldb: build all ===
echo.

pushd "%ROOT%launcher"
call build.bat
if errorlevel 1 (echo FAILED: launcher & popd & exit /b 1)
popd
echo.

pushd "%ROOT%resolver"
call build.bat
if errorlevel 1 (echo FAILED: resolver & popd & exit /b 1)
popd
echo.

pushd "%ROOT%payload"
call build.bat
if errorlevel 1 (echo FAILED: payload & popd & exit /b 1)
popd
echo.

echo === All three binaries built ===
dir /b "%ROOT%build\launcher\*.exe"
dir /b "%ROOT%build\resolver\*.exe"
dir /b "%ROOT%build\payload\*.dll"
