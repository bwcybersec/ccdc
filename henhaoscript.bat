@echo off

REM comment here
:: double colon better comment

:: Enable firewall
netsh advfirewall set allprofiles state on

:: Delete users
:1
cls
net user

rem set /p user="Enter a username to delete "
rem if %user% == "n" goto 2
rem net user %user% /del
goto 2

:: Yeet
:2
