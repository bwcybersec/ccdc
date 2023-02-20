@echo off
:: Frame settings
Title "CCDC Windows Script"

:: Sets host os
set Good_host = "false"

:Host_Check
set /p box="Please type your box as follows: [ 2012ad Docker Win10]: "
(for %%a in (2012ad Docker Win10) do (
	if "%box%" == "%%a" (
	   GOTO :Passed
	)
))
ECHO Please input a valid box...
GOTO :Host_Check

:Passed
:: Checks for admin permissions, errorlevel indicates number of errors
echo Administrative permissions required. Detecting permissions.....
ECHO.
ECHO.
call :New_Check
if not %errorLevel% == 0 (
	Exit /B 1
)

:: Makes ccdc directories
set ccdcpath="c:\ccdc"
mkdir %ccdcpath% >NUL
icacls %ccdcpath% /inheritancelevel:e >NUL
mkdir %ccdcpath%\ThreatHunting >NUL
mkdir %ccdcpath%\Config >NUL
mkdir %ccdcpath%\Regback >NUL
mkdir %ccdcpath%\Proof >NUL

:: Sets IPs
if not %box% == Win10 ( 
	call :Set_Internal_IPS 
) else ( 
	call :Set_External_IPS 
)

call :Set_Domain_Name

:: Enables logging
ECHO Setup Firewall for Splunk Logging...
netsh advfirewall export %ccdcpath%\firewall.old > NUL 2>NUL
netsh advfirewall set allprofiles state on > NUL 2>NUL
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound > NUL 2>NUL
netsh advfirewall set allprofiles settings inboundusernotification enable > NUL 2>NUL
netsh advfirewall set allprofiles logging filename %ccdcpath%\pfirewall.log > NUL 2>NUL
netsh advfirewall set allprofiles logging maxfilesize 8192 > NUL 2>NUL
netsh advfirewall set allprofiles logging droppedconnections enable > NUL 2>NUL
netsh advfirewall set allprofiles logging allowedconnections enable > NUL 2>NUL
netsh advfirewall set global statefulftp disable > NUL 2>NUL
netsh advfirewall set global statefulpptp disable > NUL 2>NUL

:: TCPDump equivalent
ECHO Setup TCPDUMP...
:: Tool to convert ETL to PCAP: https://github.com/microsoft/etl2pcapng/releases
netsh trace start capture=YES tracefile=%ccdcpath%\trace.etl > NUL 2>NUL 

::Generic Firewall rules
ECHO Disable ALL Existing Firewall Rules
netsh advfirewall firewall set rule name=all new enable=no
ECHO Now add our Firewall Rules

ECHO    Pings
netsh advfirewall firewall add rule name="CCDC-Allow Pings Out!" new dir=in  action=allow enable=yes protocol=icmpv4:8,any profile=any  >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-Allow Pings In!"  new dir=out action=allow enable=yes protocol=icmpv4:8,any profile=any  >NUL 2>NUL

ECHO    Logs OUT to Splunk
netsh advfirewall firewall add rule name="CCDC-Splunk Logs"       new dir=out action=allow enable=yes protocol=tcp profile=any remoteport=8080,9997 remoteip=%Splunk%  >NUL 2>NUL

ECHO    Webshare access
netsh advfirewall firewall add rule name="CCDC-Web Share OUT"    new dir=out action=allow enable=yes protocol=tcp profile=any remoteport=8000 remoteip=%Ubuntu14Web%  >NUL 2>NUL

ECHO    Internet access
netsh advfirewall firewall add rule name="CCDC-Web State"        new dir=out action=allow enable=yes protocol=tcp profile=any remoteip=any remoteport=80,443  >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-DNS State"        new dir=out action=allow enable=yes protocol=udp profile=any remoteport=53  >NUL 2>NUL

ECHO    Intranet access
netsh advfirewall firewall add rule name="CCDC-Web State (INT)"  new dir=out action=allow enable=yes protocol=tcp profile=any remoteport=80,443 remoteip=%Internal%  >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-DNS State (INT)"  new dir=out action=allow enable=yes protocol=udp profile=any remoteport=53 remoteip=%ADDNS% >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-NTP Allow (INT)"  new dir=out action=allow enable=yes protocol=udp profile=any remoteport=123 remoteip=%ADDNS%  >NUL 2>NUL


:: Diable IPv6 Teredo tunneling
netsh interface teredo set state disabled >NUL 2>NUL
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled >NUL 2>NUL
netsh interface ipv6 isatap set state state=disabled  >NUL 2>NUL

ECHO Damage Reversal starting...
call :Damage_Reversal

ECHO Applying box specific rules...
call :%box%
call :Config_NTP
call :Export_Configs

:: Tighten ccdc ACL
ECHO Tighten CCDC ACL...
icacls %ccdcpath%\* /inheritancelevel:d >NUL
icacls %ccdcpath% /inheritancelevel:d >NUL
icacls %ccdcpath% /grant %username%:F >NUL
icacls %ccdcpath% /remove:g "Authenticated Users" >NUL
icacls %ccdcpath% /remove:g "Users" >NUL
icacls %ccdcpath%\* /inheritancelevel:e >NUL
icacls C:\ccdc\pfirewall.log /grant %username%:(F) Administrators:(F) >NUL

ECHO.
ECHO Script completed successfully!
ECHO.
PAUSE
EXIT /B 0


:New_Check
:: #### Win 8 and Newer ####
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Success: Administrative permissions confirmed.
) else (
    echo Failure: Not Elevated.
    ECHO.
    ECHO.
    ECHO ==========YOU MUST RUN AS ADMIN!!==========
    ECHO ==========YOU MUST RUN AS ADMIN!!==========
    ECHO ==========YOU MUST RUN AS ADMIN!!==========
    ECHO ==========YOU MUST RUN AS ADMIN!!==========
    ECHO.
    ECHO.
    pause
    EXIT /B 1
)
EXIT /B 0


:Set_External_IPS
:: Sets Hardcoded IP address for use in firewall rules

set  Docker=172.25.24.97
set  DNSNTP=172.25.24.20

set  Ubuntu14Web=172.25.24.23
set  ADDNS=172.25.24.27
set  UbuntuWrk= 172.25.24.100
set  PAMI=172.25.24.150

set  Splunk=172.25.24.9
set  WebMail=172.25.24.39
set  EComm=172.25.24.11
set  Internal=%Docker%,%DNSNTP%,%Ubuntu10Web%,%UbuntuWrk%,%PAMI%,%ADDNS%,%Splunk%,%EComm%,%WebMail%

::set /P Windows10="ENTER WINDOWS 10 IP: "

Echo Docker IP is now %Docker%
Echo DNS/NTP IP is now %DNSNTP%

Echo Ubuntu14Web IP is now %Ubuntu14Web%
Echo UbuntuWrk IP is now %UbuntuWrk%
Echo PA MI IP is now %PAMI%
Echo AD/DNS box IP is now %ADDNS%

Echo Splunk IP is now %Splunk%
Echo E-Commerce IP is now %EComm%
Echo WebMail IP is now %WebMail%

set /p ScreenShotWait="IS WIN10 correct? (Y/N)"

if not %ScreenShotWait% == Y (
	GOTO Set_External_IPS
)
EXIT /B 0


:Set_Internal_IPS
:: Sets Hardcoded IP address for use in firewall rules
set  Docker=172.20.240.10
set  DNSNTP=172.20.240.20

set  Ubuntu10Web=172.20.242.10
set  UbuntuWrk=172.20.242.100
set  PAMI=172.20.242.150
set  ADDNS=172.20.242.200

set  Splunk=172.20.241.20
set  EComm=172.20.241.30
set  WebMail=172.20.241.40

set  Internal=%Docker%,%DNSNTP%,%Ubuntu10Web%,%UbuntuWrk%,%PAMI%,%ADDNS%,%Splunk%,%EComm%,%WebMail%
Echo Docker IP is now %Docker%
Echo DNS/NTP IP is now %DNSNTP%

Echo Ubuntu10Web IP is now %Ubuntu10Web%
Echo UbuntuWrk IP is now %UbuntuWrk%
Echo PA MI IP is now %PAMI%
Echo AD/DNS box IP is now %ADDNS%

Echo Splunk IP is now %Splunk%
Echo E-Commerce IP is now %EComm%
Echo WebMail IP is now %WebMail%

set /p ScreenshotWait="IS WIN10 correct? (Y/N)"
if not %ScreenshotWait% == Y (
	GOTO Set_Internal_IPS 
)
EXIT /B 0


:Set_Domain_Name
:: Sets domain for use in login banner
set Domain=
set /p Domain="[ What is the Domain Name in DOMAIN.COM format? ]:   "
Echo Domain Name will be set to %Domain%
set /p ScreenShotWait="Is the Domain name Correct and in ALL CAPS? (Y/N)    "
if not %ScreenShotWait% == Y (
	GOTO Set_Domain_Name
)
EXIT /B 0


:Damage_Reversal
:: Remove all saved credentials
ECHO Removing saved credentials...
cmdkey.exe /list > "%TEMP%\List.txt" 2>NUL
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt" 2>NUL
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H 2>NUL
del "%TEMP%\tokensonly.txt" /s /f /q >NUL
del "%TEMP%\List.txt" /s /f /q >NUL

:: Disable default accounts
ECHO Disabling Guest...
net user Guest /active:no

::Show Local Users
ECHO Showing Local Users 
net user
Echo Check List for Suspicious Accounts
set /p ScreenShotWait="[ Hit Return To Continue ]:   "

:: Disable features
ECHO Disabling features...Be Patient - 2-3 Minutes...
ECHO    TelnetServer
DISM /online /disable-feature /featurename:"TelnetServer" /NoRestart >NUL
ECHO    TFTP
DISM /online /disable-feature /featurename:"TFTP" /NoRestart  >NUL
ECHO    SMB1 Protocol
DISM /online /disable-feature /featurename:"SMB1Protocol" /NoRestart  >NUL
ECHO    SMB1 Protocol Client
DISM /online /disable-feature /featurename:"SMB1Protocol-Client" /NoRestart  >NUL
ECHO    SMB1 Protocol Server
DISM /online /disable-feature /featurename:"SMB1Protocol-Server" /NoRestart  >NUL
ECHO    SMB1 Direct
DISM /online /disable-feature /featurename:"SmbDirect" /NoRestart  >NUL
ECHO    SMB1 Protocol Deprecation
DISM /online /disable-feature /featurename:"SMB1Protocol-Deprecation" /NoRestart  >NUL
ECHO    Printing-Foundation-Features
DISM /online /disable-feature /featurename:"Printing-Foundation-Features" /NoRestart  >NUL
ECHO    Printing-Foundation-InternetPrinting-Client
DISM /online /disable-feature /featurename:"Printing-Foundation-InternetPrinting-Client" /NoRestart  >NUL
ECHO    Printing-Foundation-LPDPrintService
DISM /online /disable-feature /featurename:"Printing-Foundation-LPDPrintService" /NoRestart  >NUL
ECHO    Printing-Foundation-LPRPortMonitor
DISM /online /disable-feature /featurename:"Printing-Foundation-LPRPortMonitor" /NoRestart  >NUL

DISM /online /get-features /format:table | find "Enabled"
set /p ScreenShotWait="[ Hit Return To Continue ]:   "


:: Registry
ECHO Editing Registry...
ECHO   Registered Owner
ECHO > %ccdcpath%\Proof\regproof.txt

:: Just a name thing, but I don't like "redteam" being owner...
ECHO Change RegisteredOwner: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d blueteam /f >NUL 2>NUL
REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner >> %ccdcpath%\Proof\regproof.txt  2>NUL

:: Turn on User account control
ECHO   User Account Control
ECHO UAC: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >NUL 2>NUL
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >> %ccdcpath%\Proof\regproof.txt  2>NUL

:: Disable admin autologon
ECHO   Disable Admin autologin
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f >NUL 2>NUL
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon >> %ccdcpath%\Proof\regproof.txt  2>NUL

:: Windows Updates
ECHO   Disable Windows Updates
ECHO Windows Updates: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f >NUL 2>NUL
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt  2>NUL

REG query "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f >NUL 2>NUL
REG query "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess  >> %ccdcpath%\Proof\regproof.txt  2>NUL

REG query "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f >NUL 2>NUL
REG query "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt  2>NUL

REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t Reg_DWORD /d 0 /f >NUL 2>NUL
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" >> %ccdcpath%\Proof\regproof.txt  2>NUL

::Autoupdates
ECHO   Disable Autoupdates
::REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions >> %ccdcpath%\Proof\regproof.txt  2>NUL
::REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f >NUL 2>NUL
::REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions >> %ccdcpath%\Proof\regproof.txt  2>NUL

::Clear remote registry paths
ECHO   Clear Remote Registry Paths
ECHO Clear remote registry paths >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f >NUL 2>NUL
REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine >> %ccdcpath%\Proof\regproof.txt  2>NUL

REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f >NUL 2>NUL
REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine >> %ccdcpath%\Proof\regproof.txt  2>NUL

:: Delete the image hijack that kills task manager
ECHO   Delete image hijack that kills task manager
ECHO Re-enable task manager: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v Debugger >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /f /v Debugger >NUL 2>NUL

ECHO Re-enable task manager 2: >> %ccdcpath%\Proof\regproof.txt
ECHO   Re-enable task manager
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f >NUL 2>NUL
:: THIS PROBABLY HAS TO BE DONE MANUALLY if cmd is disabled, but who does that?!?!?!?!?!
ECHO   Re-enable CMD Prompt
ECHO Re-enable cmd prompt: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG delete "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /f >NUL 2>NUL

::Enable Windows Defender
ECHO   Re-enable Windows Defender
ECHO Re-enable Windows Defender: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f >NUL 2>NUL

:: Unhide Files
ECHO   Unhide Files
ECHO Unhide files: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden >> %ccdcpath%\Proof\regproof.txt  2>NUL

ECHO   Unhide System Files
ECHO unhide system files: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f >NUL 2>NUL
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden >> %ccdcpath%\Proof\regproof.txt  2>NUL

:: Fix Local Security Authority(LSA)
ECHO   Fix Local Security Authority
ECHO Restrictanonymous: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous /t REG_DWORD /d 1 /f >NUL 2>NUL
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous >> %ccdcpath%\Proof\regproof.txt  2>NUL

ECHO   Restrict Anonymous SAM
ECHO Restrictanonymoussam: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam /t REG_DWORD /d 1 /f >NUL 2>NUL
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam >> %ccdcpath%\Proof\regproof.txt  2>NUL

ECHO   Change everyone includes Anonymous
ECHO Change everyone includes anonymous: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f >NUL 2>NUL
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous >> %ccdcpath%\Proof\regproof.txt  2>NUL

ECHO   Change setting to NOT store plaintext passwords
ECHO Get rid of the ridiculous store plaintext passwords: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parametersn" /v EnablePlainTextPassword >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f >NUL 2>NUL
REG query "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword >> %ccdcpath%\Proof\regproof.txt  2>NUL

ECHO   Turn off Local Machine Hash
ECHO Turn off Local Machine Hash: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash /t REG_DWORD /d 1 /f >NUL 2>NUL
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash  >> %ccdcpath%\Proof\regproof.txt  2>NUL

ECHO   Delete use Machine ID
ECHO delete use machine id: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v UseMachineID >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v UseMachineID /f >NUL 2>NUL

ECHO   Change Notification Packages
ECHO Change notification packages: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages"  >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages" /t REG_MULTI_SZ /d "scecli" /f >NUL 2>NUL
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages"  >> %ccdcpath%\Proof\regproof.txt  2>NUL

ECHO   Show Hidden Users in GUI
ECHO Show hidden users in gui: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts" >> %ccdcpath%\Proof\regproof.txt  2>NUL
Reg delete "HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts" /f >NUL 2>NUL
ECHO   Disable Possible Backdoors
ECHO Disable possible backdoors >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "systray.exe" /f >NUL 2>NUL
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" >> %ccdcpath%\Proof\regproof.txt  2>NUL

REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger >> %ccdcpath%\Proof\regproof.txt  2>NUL
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger /t REG_SZ /d "systray.exe" /f >NUL 2>NUL
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger >> %ccdcpath%\Proof\regproof.txt  2>NUL

::Sticky keys
ECHO   Sticky Keys Enable (works for us, not for Red Team)
ECHO Taking over sticky keys
CD C:\Windows\System32
takeown /f sethc.exe >NUL
icacls sethc.exe /grant %username%:F >NUL
takeown /f systray.exe >NUL
icacls systray.exe /grant %username%:F >NUL
move sethc.exe sethc.old.exe >NUL 2>NUL
copy systray.exe sethc.exe >NUL 2>NUL

EXIT /B 0




:Win10
ECHO Win10 Banner
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f >NUL 2>NUL
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of %Domain%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Domain% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f >NUL 2>NUL
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinLogon" /v legalnoticecaption   2>NUL
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinLogon" /v legalnoticetext   2>NUL
set /p ScreenShotWait="[ Hit Return To Continue ]:   "

call :Config_NTP
EXIT /B 0


:Docker
ECHO Docker Banner
REG delete "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /f REG_DWORD /d 50243 /f >NUL 2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /t REG_DWORD /d 50243 /f >NUL 2>NUL

REG delete "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /f >NUL 2>NUL 
REG add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /t REG_DWORD /d 50244 /f >NUL 2>NUL

REG delete "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /f >NUL 2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /t REG_DWORD /d 50245 /f >NUL 2>NUL

REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /f >NUL 2>NUL
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" >NUL 2>NUL

REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /f >NUL 2>NUL 
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "This computer system/network is the property of %Domain%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Domain% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." >NUL 2>NUL

REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption   2>NUL
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext   2>NUL
set /p ScreenShotWait="[ Hit Return To Continue ]:   "

:: Disable SMB1?
ECHO Disable SMB1 via Registry...
REG add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f

call :Config_NTP
EXIT /B 0


:2012ad
ECHO Win2012 ADDNS Banner
reg Add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /t REG_DWORD /d 50243 /f >NUL 2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /t REG_DWORD /d 50244 /f >NUL 2>NUL
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /t REG_DWORD /d 50245 /f >NUL 2>NUL

REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /f >NUL 2>NUL
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" >NUL 2>NUL

REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /f >NUL 2>NUL 
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "This computer system/network is the property of %Domain%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Domain% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." >NUL 2>NUL

REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption   2>NUL
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext   2>NUL
set /p ScreenShotWait="[ Hit Return To Continue ]:   "

:: Disable SMB1?
ECHO Disable SMB1 via Registry...
REG add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f  >NUL 2>NUL

:: LDAP 389
netsh advfirewall firewall add rule name="CCDC-LDAP Service" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp  >NUL 2>NUL

:: LDAP 636
netsh advfirewall firewall add rule name="CCDC-LDAP Service SSL" dir=in action=allow enable=no profile=any localport=636 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp  >NUL 2>NUL

:: LDAP 3268
::netsh advfirewall firewall add rule name="CCDC-LDAP GC IN TCP" dir=in action=allow enable=yes profile=any localport=3268 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp  >NUL 2>NUL

:: LDAP 3269
::netsh advfirewall firewall add rule name="CCDC-LDAP GC SSL IN TCP" dir=in action=allow enable=yes profile=any localport=3269 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp  >NUL 2>NUL

:: KERBEROS
netsh advfirewall firewall add rule name="CCDC-Kerberos In UDP from Internal" dir=in action=allow enable=yes profile=any localport=88,464 remoteip=%EComm%,%WebMail%,%PAMI% protocol=udp  >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-Kerberos In TCP from Internal" dir=in action=allow enable=yes profile=any localport=88,464 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp  >NUL 2>NUL
netsh advfirewall firewall set rule group="CCDC-Kerberos Key Distribution Center (TCP-In)" new enable=yes  >NUL 2>NUL
netsh advfirewall firewall set rule group="CCDC-Kerberos Key Distribution Center (UDP-In)" new enable=yes  >NUL 2>NUL

:: DNS 53
netsh advfirewall firewall add rule name="CCDC-DNS In UDP from DNSNTP"  dir=in action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=udp  >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-DNS Out UDP to DNSNTP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=udp   >NUL 2>NUL

netsh advfirewall firewall add rule name="CCDC-DNS In TCP from DNSNTP"  dir=in action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=tcp   >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-DNS Out TCP to DNSNTP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=tcp   >NUL 2>NUL

netsh advfirewall firewall add rule name="CCDC-DNS In UDP from Internal" dir=in action=allow enable=yes profile=any localport=53  protocol=udp remoteip=%Internal%   >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-DNS Out UDP to Internal" dir=out action=allow enable=yes profile=any localport=53  protocol=udp remoteip=%Internal%   >NUL 2>NUL

netsh advfirewall firewall add rule name="CCDC-DNS In UDP from Internet" dir=in action=allow enable=no profile=any localport=53  protocol=udp  >NUL 2>NUL
netsh advfirewall firewall add rule name="CCDC-DNS OUT UDP to Internet" dir=out action=allow enable=no profile=any localport=53  protocol=udp  >NUL 2>NUL

netsh advfirewall firewall add rule name="CCDC-DNS In TCP from Internal" dir=in action=allow enable=yes profile=any localport=53  protocol=tcp remoteip=%Internal%
netsh advfirewall firewall add rule name="CCDC-DNS Out TCP to Internal" dir=out action=allow enable=yes profile=any localport=53  protocol=tcp remoteip=%Internal%

netsh advfirewall firewall add rule name="CCDC-DNS In UDP from Internet" dir=in action=allow enable=no profile=any localport=53  protocol=udp
netsh advfirewall firewall add rule name="CCDC-DNS Out UDP to Internet" dir=out action=allow enable=no profile=any localport=53  protocol=udp

netsh advfirewall firewall add rule name="CCDC-DNS In TCP from Internet" dir=in action=allow enable=no profile=any localport=53  protocol=tcp
netsh advfirewall firewall add rule name="CCDC-DNS Out TCP to Internet" dir=out action=allow enable=no profile=any localport=53  protocol=tcp


::Add PA Groups
::dsadd group cn=Marketing,cn=users,dc=allsafe,dc=com -secgrp yes -samid marketing
::dsadd group cn=Sales,cn=users,dc=allsafe,dc=com -secgrp yes -samid sales
::dsadd group cn=HumanResources,cn=users,dc=allsafe,dc=com -secgrp yes -samid humanresources
ECHO Making user panuser...
dsadd user "cn=panuser,cn=Users,dc=allsafe,dc=com" -samid panuser -fn pa -ln nuser -pwd *
net localgroup Administrators panuser /add
net localgroup "Distributed COM Users" panuser /add
net localgroup "Event Log Readers" panuser /add
net localgroup "Remote Desktop Users" panuser /add
::ECHO Making user Michael Dorn...
::dsadd user "cn=Michael Dorn,cn=Users,dc=allsafe,dc=com" -samid MDorn -fn Michael -ln Dorn  -pwd *

::Create Password policy
::start powershell.exe -noexit Set-ADDefaultDomainPasswordPolicy -Identity allsafe -ComplexityEnabled $true -MinPasswordLength 10 -MinPasswordAge 1.00:00:00 -MaxPasswordAge 30.00:00:00 -LockoutDuration 90.00:00:00 -LockoutObservationWindow 00:30:00 -LockoutThreshold 5
::start powershell.exe -noexit Get-ADDefaultDomainPasswordPolicy >> %ccdcpath%\DomainPasswordPolicy.txt
EXIT /B 0


:Config_NTP
ECHO Configure NTP Client
ECHO Sync Time with %ADDNS%
net start w32time
w32tm /config /manualpeerlist:%ADDNS% /syncfromflags:manual /reliable:yes /update
w32tm /resync
net stop w32time && net start w32time
TZUTIL /s "Eastern Standard Time"
start powershell -Noexit w32tm /query /peers
Exit /B 0


:Config_NTP_SERVER
ECHO Configure NTP Server
ECHO Sync Time with pool.ntp.org
net start w32time
w32tm /config /manualpeerlist:pool.ntp.org /syncfromflags:manual /reliable:yes /update
w32tm /resync
net stop w32time && net start w32time
TZUTIL /s "Eastern Standard Time"
start powershell -Noexit w32tm /query /peers
Exit /B 0


:Export_Configs
:: Export Hosts
copy %systemroot%\system32\drivers\etc\hosts %ccdcpath%\hosts
ECHO # This is OUR hosts file! > %systemroot%\system32\drivers\etc\hosts
:: Export Users
wmic useraccount list brief > %ccdcpath%\Config\Users.txt
:: Export Groups
wmic group list brief > %ccdcpath%\Config\Groups.txt
:: Export Scheduled tasks
schtasks > %ccdcpath%\ThreatHunting\ScheduledTasks.txt
:: Export Services
sc query > %ccdcpath%\ThreatHunting\Services.txt
:: Export Session
query user > %ccdcpath%\ThreatHunting\UserSessions.txt
:: Export registry
reg export HKLM %ccdcpath%\Regback\hlkm.reg
reg export HKCU %ccdcpath%\Regback\hkcu.reg
reg export HKCR %ccdcpath%\Regback\hlcr.reg
reg export HKU %ccdcpath%\Regback\hlku.reg
reg export HKCC %ccdcpath%\Regback\hlcc.reg
EXIT /B 0
