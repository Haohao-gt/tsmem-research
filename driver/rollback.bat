@echo off
setlocal
bcdedit /set testsigning off
sc.exe stop TsMem
sc.exe delete TsMem
schtasks /delete /tn TsMemLoad /f
echo done. reboot to clear test mode.
pause
