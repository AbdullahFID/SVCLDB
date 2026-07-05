@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
del /q %~dp0ref_imports.txt 2>nul
del /q %~dp0ref_headers.txt 2>nul
del /q %~dp0ref_disasm.txt 2>nul
dumpbin /IMPORTS %~dp0ref_v13.dll > %~dp0ref_imports.txt 2>&1
dumpbin /HEADERS %~dp0ref_v13.dll > %~dp0ref_headers.txt 2>&1
echo Done.
