@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
setlocal
set OUT=%~dp0bp_dump
if not exist %OUT% mkdir %OUT%
copy /Y "C:\Temp\bypassify_fresh\v13_new\resources\RT_RCDATA_id_101_lang_9.bin" "%OUT%\bp13.dll" >nul

REM Full imports
dumpbin /IMPORTS "%OUT%\bp13.dll" > "%OUT%\imports.txt" 2>&1

REM PE headers
dumpbin /HEADERS "%OUT%\bp13.dll" > "%OUT%\headers.txt" 2>&1

REM Load config
dumpbin /LOADCONFIG "%OUT%\bp13.dll" > "%OUT%\loadconfig.txt" 2>&1

REM Full disassembly (may be huge, use timeout)
dumpbin /DISASM "%OUT%\bp13.dll" > "%OUT%\disasm.txt" 2>&1
echo Done.
endlocal
