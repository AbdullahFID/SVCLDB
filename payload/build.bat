@echo off
setlocal enabledelayedexpansion

set ROOT=%~dp0..
set SHARED=%ROOT%\shared
set SRC=%~dp0src
set MH=%SHARED%\minhook
set IMGUI=%SHARED%\imgui
set BUILD=%ROOT%\build\payload
set OUT_NAME=dwmapiext.dll

if not exist "%BUILD%" mkdir "%BUILD%"
if not exist "%BUILD%\obj" mkdir "%BUILD%\obj"

where cl.exe >nul 2>nul
if not errorlevel 1 goto :HAVE_CL

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (echo [!] vswhere missing & exit /b 1)
for /f "usebackq tokens=*" %%A in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS_DIR=%%A
if "%VS_DIR%"=="" (echo [!] no VC++ tools & exit /b 1)
call "%VS_DIR%\VC\Auxiliary\Build\vcvars64.bat" >nul

:HAVE_CL

echo === Building %OUT_NAME% ===

REM ── C sources ──
REM  /GS- MANDATORY: manual map skips CRT init, so __security_cookie is
REM       uninitialized. Any /GS-instrumented function's return triggers
REM       __security_check_cookie fastfail → silent DWM crash.
REM  /GR-  no RTTI (C++)
REM  /guard:cf-  disable CFG (loader-only; without loader, CFG bitmap misses
REM       our funcs → __fastfail on any indirect call)
set CFLAGS=/nologo /W3 /O2 /Oi /GS- /Gy /MT /GL /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /guard:cf-

REM ── C++ sources (ImGui + our imgui_layer.cpp) — need /EHsc + /std:c++17 ──
set CXXFLAGS=/nologo /W3 /O2 /Oi /GS- /Gy /MT /GL /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /guard:cf- /EHsc /std:c++17 /GR- /DIMGUI_DISABLE_DEMO_WINDOWS /DIMGUI_DISABLE_DEBUG_TOOLS

set C_SOURCES=^
 "%SHARED%\log_secure.c" "%SHARED%\log_key.c" ^
 "%SHARED%\base64.c" "%SHARED%\crypto_util.c" ^
 "%SHARED%\json_util.c" "%SHARED%\supabase_config.c" ^
 "%SHARED%\winhttp_util.c" "%SHARED%\handshake.c" ^
 "%MH%\buffer.c" "%MH%\hde64.c" "%MH%\hook.c" "%MH%\trampoline.c" ^
 "%SRC%\config_read.c" "%SRC%\blob_read.c" ^
 "%SRC%\capture.c" "%SRC%\clipboard_out.c" ^
 "%SRC%\ldb_detect.c" "%SRC%\rawinput_hook.c" ^
 "%SRC%\dwm_hooks.c" "%SRC%\sub_check.c" ^
 "%SRC%\ai\ai_provider.c" ^
 "%SRC%\dllmain.c"

set CXX_SOURCES=^
 "%IMGUI%\imgui.cpp" "%IMGUI%\imgui_draw.cpp" "%IMGUI%\imgui_tables.cpp" ^
 "%IMGUI%\imgui_widgets.cpp" ^
 "%IMGUI%\backends\imgui_impl_dx11.cpp" ^
 "%SRC%\ui\imgui_layer.cpp"

REM ── Compile C sources → objs ──
pushd "%BUILD%\obj"
cl /c %CFLAGS% /I "%SHARED%" /I "%SRC%" /I "%MH%" %C_SOURCES%
if errorlevel 1 (echo [!] C compile failed. & popd & exit /b 1)

REM ── Compile C++ sources → objs ──
cl /c %CXXFLAGS% /I "%SHARED%" /I "%SRC%" /I "%IMGUI%" %CXX_SOURCES%
if errorlevel 1 (echo [!] C++ compile failed. & popd & exit /b 1)
popd

REM ── Link ──
REM  /NOENTRY isn't right for us — we DO have DllMain. But we need to make
REM  sure no CRT startup runs. Force linker to not add __DllMainCRTStartup wrapper.
REM  Actually, DllMain is fine as-is; the CRT wrapper (__DllMainCRTStartup) just
REM  calls our DllMain after CRT init — but since we manual-map, CRT init doesn't
REM  matter. What matters is /GS- so per-function stack cookies aren't checked.
REM
REM  /guard:cf-       disable CFG at link (matches compile)
REM  /RELEASE         sets IMAGE_FILE_RELEASE flag
REM  /HIGHENTROPYVA   enable 64-bit ASLR
REM  /DYNAMICBASE     enable ASLR
REM  /NXCOMPAT        DEP
REM  /MERGE           reduce section count → fewer landmarks for RE
REM  /EMITPOGODB:NO   no POGO db
REM  /EMITVOLATILEMETADATA:NO   omit volatile-atomic metadata (RE bait)
REM  /VERBOSE:LTCG    off (silent)
REM  IMPORTANT: do NOT merge .pdata into .text — x64 SEH needs .pdata as
REM  a separate section for RtlLookupFunctionEntry unwind resolution.
REM  Merging kills every __try/__except in our detours (silent bad — payload
REM  init returns early, no crash but no functionality). Verified 2026-07-05.
REM  /CETCOMPAT — DWM (the host process) already has CET enabled on
REM  supported hardware; marking our DLL as compatible lets the shadow
REM  stack cover our RETs too (protects the payload's own detour code
REM  from ROP). Safe even under manual-map — CET is per-thread, and we
REM  don't create threads that skip Windows loader init.
REM
REM  /DELAYLOAD is NOT used here — every DLL our payload lists in its
REM  IAT is resolved by the launcher's manual-map shellcode, not by the
REM  Windows loader. /DELAYLOAD requires the loader's __delayLoadHelper2
REM  path which we don't traverse.
set LDFLAGS=/nologo /DLL /LTCG /DEBUG:NONE /Brepro ^
 /OPT:REF /OPT:ICF /INCREMENTAL:NO /MANIFEST:NO /GUARD:NO /RELEASE ^
 /HIGHENTROPYVA /DYNAMICBASE /NXCOMPAT /CETCOMPAT ^
 /OUT:"%BUILD%\%OUT_NAME%"

link %LDFLAGS% "%BUILD%\obj\*.obj" ^
   kernel32.lib user32.lib gdi32.lib advapi32.lib bcrypt.lib winhttp.lib ^
   ole32.lib shlwapi.lib windowscodecs.lib d3d11.lib dxgi.lib

if errorlevel 1 (echo [!] Link failed. & exit /b 1)

REM ── Clean intermediates ──
del /q "%BUILD%\obj\*.obj" 2>nul
del /q "%BUILD%\*.pdb" 2>nul
del /q "%BUILD%\*.exp" 2>nul
del /q "%BUILD%\*.lib" 2>nul

for %%F in ("%BUILD%\%OUT_NAME%") do echo === Built %%F  (%%~zF bytes) ===
