@echo off
setlocal
cd /d "%~dp0"

set "WDK=C:\Program Files (x86)\Windows Kits\10"
set "WVER=10.0.26100.0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%VCVARS%" goto :novc
if not exist "%WDK%\Include\%WVER%\km\ntifs.h" goto :nowdk

call "%VCVARS%" >nul
if errorlevel 1 goto :fail

if not exist build mkdir build

echo [*] compiling KDU driver...
cl /nologo /c /GS- /Gs9999999 /kernel /W3 /O2 /D_AMD64_ /DWIN64 /D_WIN64 /I"src" /I"%WDK%\Include\%WVER%\km" /I"%WDK%\Include\%WVER%\shared" src\ts_mem_kdu.c /Fo:build\ts_mem_kdu.obj
if errorlevel 1 goto :fail

echo [*] linking KDU driver...
link /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /OUT:build\ts_mem_kdu.sys /LIBPATH:"%WDK%\Lib\%WVER%\km\x64" build\ts_mem_kdu.obj ntoskrnl.lib hal.lib BufferOverflowK.lib
if errorlevel 1 goto :fail

echo.
echo [+] KDU driver build ok: build\ts_mem_kdu.sys
exit /b 0

:novc
echo [!] vcvars64.bat not found: %VCVARS%
exit /b 1

:nowdk
echo [!] WDK km headers not found under %WDK%
exit /b 1

:fail
echo [!] build failed
exit /b 1
