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

REM ── Dev auth-bypass ── when SVCLDB_DEV_AUTH=1 is set in the parent
REM  shell, add /DSVCLDB_DEV_BYPASS_AUTH=1 to CFLAGS/CXXFLAGS. Payload's
REM  init_thread + sub_check_start are then gated on that macro; devs
REM  can iterate without a live Supabase login on every rebuild.
REM  MUST be unset before shipping.
set DEVAUTH=
if /I "%SVCLDB_DEV_AUTH%"=="1" (
    set DEVAUTH=/DSVCLDB_DEV_BYPASS_AUTH=1
    echo === DEV BYPASS: handshake + sub_check disabled ===
)

REM ── C sources ──
REM  /GS- MANDATORY: manual map skips CRT init, so __security_cookie is
REM       uninitialized. Any /GS-instrumented function's return triggers
REM       __security_check_cookie fastfail → silent DWM crash.
REM  /GR-  no RTTI (C++)
REM  /guard:cf-  disable CFG (loader-only; without loader, CFG bitmap misses
REM       our funcs → __fastfail on any indirect call)
set CFLAGS=/nologo /W3 /O2 /Oi /GS- /Gy /MT /GL /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /guard:cf- %DEVAUTH%

REM ── C++ sources (ImGui + our imgui_layer.cpp) — need /EHsc + /std:c++17 ──
set CXXFLAGS=/nologo /W3 /O2 /Oi /GS- /Gy /MT /GL /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /guard:cf- /EHsc /std:c++17 /GR- /DIMGUI_DISABLE_DEMO_WINDOWS /DIMGUI_DISABLE_DEBUG_TOOLS %DEVAUTH%

set C_SOURCES=^
 "%SHARED%\log_secure.c" "%SHARED%\log_key.c" ^
 "%SHARED%\base64.c" "%SHARED%\crypto_util.c" ^
 "%SHARED%\json_util.c" "%SHARED%\supabase_config.c" ^
 "%SHARED%\winhttp_util.c" "%SHARED%\handshake.c" ^
 "%SHARED%\str_enc.c" "%SHARED%\lazy_api.c" ^
 "%MH%\buffer.c" "%MH%\hde64.c" "%MH%\hook.c" "%MH%\trampoline.c" ^
 "%SRC%\config_read.c" "%SRC%\blob_read.c" ^
 "%SRC%\capture.c" "%SRC%\clipboard_out.c" ^
 "%SRC%\ldb_detect.c" "%SRC%\rawinput_hook.c" ^
 "%SRC%\dwm_hooks.c" "%SRC%\sub_check.c" ^
 "%SRC%\ai\ai_provider.c" ^
 "%SRC%\redact\redact_client.c" ^
 "%SRC%\dllmain.c"

set CXX_SOURCES=^
 "%IMGUI%\imgui.cpp" "%IMGUI%\imgui_draw.cpp" "%IMGUI%\imgui_tables.cpp" ^
 "%IMGUI%\imgui_widgets.cpp" ^
 "%IMGUI%\backends\imgui_impl_dx11.cpp" ^
 "%IMGUI%\backends\imgui_impl_win32.cpp" ^
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

REM ── Astral-PE metadata scrub ── PERMANENTLY DISABLED FOR PAYLOAD ──
REM
REM  Root cause: Astral-PE zeros IMAGE_LOAD_CONFIG_DIRECTORY.Size (and
REM  other fields) which the LOADER uses to set up:
REM    - __security_cookie initialization
REM    - __guard_check_icall_fptr / __guard_dispatch_icall_fptr
REM      (Control-Flow-Guard check + dispatch function pointers)
REM    - CET metadata for shadow stack
REM
REM  For a MANUALLY-MAPPED payload, Windows loader never processes the
REM  load config. Our manual mapper doesn't either. So the CFG pointers
REM  stay NULL. Even though we compile with /guard:cf- + /GUARD:NO,
REM  third-party static libs linked in (MinHook slab, MSVC CRT bits,
REM  ImGui C++ runtime helpers) may still contain CFG-instrumented
REM  indirect call sites that dereference the NULL fptr -> DWM CRASH.
REM
REM  Symptom: DWM ran fine for ~10-30 seconds then crashed with:
REM    - Exception 0xc0000005 (access violation) at unknown module
REM    - Faulting RIP inside our manually-mapped code region
REM    - Timing correlated with periodic thread wake-ups (integrity
REM      monitor, keepalive, sub_check) whose indirect calls tripped CFG
REM
REM  Verified 2026-07-06: with SVCLDB_SKIP_SCRUB=1 (Astral-PE skipped
REM  on payload) DWM runs indefinitely; without, DWM crashes reliably.
REM
REM  Trade-off: we lose Astral-PE's PE-metadata scrubbing on the payload
REM  (Rich Header + section names + timestamps + debug dir stay visible).
REM  Acceptable because the payload's real stealth comes from:
REM    - Manual map (no LDR entry)   - PEB unlink
REM    - PE header wipe              - Section RWX->image-like downgrade
REM    - Anti-debug (5 vectors)      - Encrypted logs
REM    - Encrypted strings           - API hashing (in launcher, not payload)
REM  Astral-PE on payload was cosmetic on top of these — losing it costs
REM  ~20 min of RE friction vs the ALTERNATIVE of a hard DWM crash.
REM
REM  Launcher + resolver STILL apply Astral-PE (they don't run inside
REM  DWM's context, so CFG dereferences would crash themselves not DWM,
REM  and both processes exit quickly enough that the CFG code paths
REM  don't fire). See launcher/build.bat + resolver/build.bat.
REM
REM  If you EVER want to re-enable this: figure out how to preserve the
REM  IMAGE_LOAD_CONFIG_DIRECTORY (either patch Astral-PE, or set up
REM  the CFG pointers to a stub in our own DllMain).
echo === Astral-PE scrub SKIPPED for payload ^(CFG-pointer NULL crash — see comment in build.bat^) ===

for %%F in ("%BUILD%\%OUT_NAME%") do echo === Built %%F  (%%~zF bytes) ===
