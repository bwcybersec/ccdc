@echo off

REM comment here
:: double colon better comment

:: Enable firewall
netsh advfirewall set allprofiles state on

:: Delete users
:1
cls
net user

set /p user="Enter a username to delete "
if %user% == "n" goto 2
net user %user% /del
goto 1

:: Yeet
:2