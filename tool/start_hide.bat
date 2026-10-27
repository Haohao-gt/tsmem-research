@echo off
cd /d "%~dp0"
rem kdu.exe / drv64.dll are third-party and not included in this repo.
rem Place them in PATH or the current directory, then map the built driver.
kdu.exe -prv 1 -map "..\driver\build\ts_mem_kdu.sys"
timeout /t 1 /nobreak >nul
start "" pythonw.exe "tool.py"
