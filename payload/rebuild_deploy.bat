@echo off
REM Quick rebuild + copy + dwm-restart cycle for payload iteration.
REM Usage: from any dir, `cmd /c C:\Users\abdul\Desktop\svcldb\payload\rebuild_deploy.bat`
setlocal enabledelayedexpansion

pushd "%~dp0"

echo === Rebuilding payload ===
call build.bat
if errorlevel 1 (
    echo BUILD FAILED
    popd
    exit /b 1
)

echo === Copying to install dir ===
copy /Y "..\build\payload\dwmapiext.dll" "C:\ProgramData\WinAudioSvc\dwmapiext.dll" >nul
if errorlevel 1 (
    echo COPY FAILED
    popd
    exit /b 1
)

echo === Wiping payload_early.txt for fresh diagnostic ===
del /q "C:\ProgramData\WinAudioSvc\payload_early.txt" 2>nul
del /q "C:\ProgramData\WinAudioSvc\payload.log" 2>nul
del /q "C:\ProgramData\WinAudioSvc\ai.log" 2>nul

echo === Restarting DWM (auto-relaunches in ~3s) ===
taskkill /F /IM dwm.exe >nul 2>&1
timeout /T 3 /NOBREAK >nul

echo === Manual-mapping payload into fresh DWM ===
"C:\Users\abdul\Desktop\hooksdll\dwm\dwm_manual_map.exe" "C:\ProgramData\WinAudioSvc\dwmapiext.dll"

echo === Waiting 3s for init + first frames ===
timeout /T 3 /NOBREAK >nul

echo === payload_early.txt: ===
type "C:\ProgramData\WinAudioSvc\payload_early.txt"

popd
endlocal
