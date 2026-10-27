@echo off
setlocal
sc.exe stop TsMem
sc.exe delete TsMem
echo [%date% %time%] uninstalled >> "C:\ProgramData\TsMem\install.log"
exit /b 0
