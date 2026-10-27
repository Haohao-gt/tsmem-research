@echo off
setlocal
set "LOG=C:\ProgramData\TsMem\install.log"
echo [%date% %time%] install start >> "%LOG%"

sc.exe query TsMem >nul 2>&1
if errorlevel 1 (
  sc.exe create TsMem type= kernel start= demand binPath= C:\ProgramData\TsMem\ts_mem.sys DisplayName= TsMem >> "%LOG%" 2>&1
) else (
  sc.exe config TsMem binPath= C:\ProgramData\TsMem\ts_mem.sys >> "%LOG%" 2>&1
)

sc.exe start TsMem >> "%LOG%" 2>&1
sc.exe query TsMem >> "%LOG%" 2>&1
"C:\ProgramData\TsMem\ts_mem_client.exe" info >> "%LOG%" 2>&1
"C:\ProgramData\TsMem\ts_mem_client.exe" testself >> "%LOG%" 2>&1
"C:\ProgramData\TsMem\ts_mem_client.exe" testself --attach >> "%LOG%" 2>&1
echo [%date% %time%] install end >> "%LOG%"
exit /b 0
