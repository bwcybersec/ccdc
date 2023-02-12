@echo off
:: Frame settings
Title "CCDC Windows Script"

:: Sets host os
set Good_host = "false"

:Host_Check
set /p box="Please type your box as follows: [2012ad Docker Win10]: "
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
netsh advfirewall export %ccdcpath%\firewall.old
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall set allprofiles settings inboundusernotification enable
netsh advfirewall set allprofiles logging filename C:\Windows\System32\logfiles\firewall\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 8192
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set global statefulftp disable
netsh advfirewall set global statefulpptp disable


::Generic Firewall rules
netsh advfirewall firewall set rule name=all new enable=no
netsh advfirewall firewall add rule name="CCDC-Allow Pings" protocol=icmpv4:8,any dir=in action=allow enable=yes
netsh advfirewall firewall add rule name="CCDC-All the Pings!" dir=out action=allow enable=yes protocol=icmpv4:8,any
::netsh advfirewall firewall add rule name="Web Share OUT" dir=out action=allow enable=no profile=any remoteip=%Ecomm% remoteport=80 protocol=tcp
netsh advfirewall firewall add rule name="CCDC-Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%Splunk% remoteport=8000,8089,9997 protocol=tcp
netsh advfirewall firewall add rule name="CCDC-DNS Out to Any" dir=out action=allow enable=no profile=any remoteport=53 protocol=udp
netsh advfirewall firewall add rule name="CCDC-SSH in from any" dir=in action=allow enable=no profile=any localport=22 protocol=tcp
netsh advfirewall firewall add rule name="CCDC-Web State" new dir=out action=allow enable=yes profile=any remoteip=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall add rule name="CCDC-DNS State" new dir=out action=allow enable=yes profile=any remoteport=53 protocol=udp
if not %box% == Win10 (
	netsh advfirewall firewall add rule name="CCDC-NTP Allow" dir=out action=allow enable=yes profile=any remoteport=123 remoteip=%EComm% protocol=udp
	netsh advfirewall firewall add rule name="CCDC-WinSCP/SSH Out" dir=out action=allow enable=no profile=any remoteip=%WebMail%,%Splunk%,%DNSNTP%,%EComm%,%UbuntuWrk%,%ADDNS%,%UbuntuWrk% remoteport=22 protocol=tcp
	netsh advfirewall firewall add rule name="CCDC-Web Share OUT" dir=out action=allow enable=no profile=any remoteip=%Ecomm% remoteport=80 protocol=tcp
)

:: Diable IPv6 Teredo tunneling
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled 

call :Damage_Reversal
ECHO Applying box specific rules...
call :%box%
call :Export_Configs

:: Tighten ccdc ACL
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


:Old_Check
:: ##### Pre - Win 8 #####
AT > NUL
if %ERRORLEVEL% EQU 0 (
    ECHO Success: Administrative permissions confirmed.
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
:: Sets Hardcoded ip address for use in firewall rules
set  EComm=172.25.24.11
set  DNSNTP=172.25.24.20
set  WebMail=172.25.24.39
set  Splunk=172.25.24.9
set  ADDNS=172.25.24.27
::set /P Windows10="ENTER WINDOWS 10 IP: "
set  UbuntuWrk= 172.25.24.211
set  PAMI=172.31.24.150
set  Docker=172.25.24.97
Echo E-Commerce Ip is now %EComm%
Echo DNS/NTP IP is now %DNSNTP%
Echo WebMail IP is now %WebMail%
Echo Splunk ip is now %Splunk%
Echo AD/DNS box ip is now %ADDNS%
::Echo Windows10 Ip is now %Windows10%
Echo UbuntuWrk is now %UbuntuWrk%
Echo PA MI is now %PAMI%
Echo Docker is now %Docker%
set /p Garbage="Are These Configurations Correct? (Y/N)"
if not %Garbage% == Y (
	GOTO Set_External_IPS
)
EXIT /B 0


:Set_Internal_IPS
:: Sets Hardcoded ip address for use in firewall rules
set  EComm=172.20.241.30
set  DNSNTP=172.20.242.10
set  WebMail=172.20.241.40
set  Splunk=172.20.241.20
set  ADDNS=172.20.242.200
::set /P Windows10="ENTER WINDOWS 10 IP: "
set  UbuntuWrk=172.20.242.211
set  PAMI=172.20.242.150
set  Docker=172.20.240.10
set UbuntuWeb=172.20.242.10
set  Internal=%Ecomm%,%DNSNTP%,%WebMail%,%Splunk%,%ADDNS%,%UbuntuWrk%,%PAMI%,%Docker%,%UbuntuWeb%
Echo E-Commerce Ip is now %EComm%
Echo DNS/NTP IP is now %DNSNTP%
Echo WebMail IP is now %WebMail%
Echo Splunk ip is now %Splunk%
Echo AD/DNS box ip is now %ADDNS%
::Echo Windows10 Ip is now %Windows10%
Echo UbuntuWrk is now %UbuntuWrk%
Echo PA MI is now %PAMI%
Echo Docker is now %Docker%
set /p Garbage="Are These Configurations Correct? (Y/N)"
if not %Garbage% == Y (
	GOTO Set_Internal_IPS 
)
EXIT /B 0


:Set_Domain_Name
:: Sets domain for use in login banner
set Dname=
Set Garbage1=
set /p Dname="[ What is the Domain Name in DOMAIN.COM format? ]:   "
Echo Domain Name will be set to %Dname%
set /p Garbage1="Is the Domain name Correct and ALL CAPS? (Y/N)    "
if not %Garbage1% == Y (
	GOTO Set_Domain_Name
)
EXIT /B 0


:Damage_Reversal
:: Remove all saved credentials
ECHO Removing saved credentials...
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\tokensonly.txt" /s /f /q >NUL
del "%TEMP%\List.txt" /s /f /q >NUL

:: Disable default accounts
ECHO Disabling Guest...
net user Guest /active:no

::Show Local Users
ECHO Showing Local Users 
net user
Echo Check List for Suspicious Accounts
set /p Dname="[ Hit Return To Continue ]:   "

:: Disable features
ECHO Disabling features...
DISM /online /disable-feature /featurename:"TelnetClient" >NUL
DISM /online /disable-feature /featurename:"TelnetServer" >NUL
DISM /online /disable-feature /featurename:"TFTP" >NUL

:: Registry
ECHO Editing Registry...
echo. > %ccdcpath%\Proof\regproof.txt
:: Just a name thing, but I don't like "redteam" being owner...
ECHO Change RegisteredOwner: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d blueteam /f
REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner >> %ccdcpath%\Proof\regproof.txt

:: Turn on User account control
ECHO UAC: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >> %ccdcpath%\Proof\regproof.txt

:: Disable admin autologon
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon >> %ccdcpath%\Proof\regproof.txt

:: Windows Updates
ECHO Windows Updates: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt

REG query "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f
REG query "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess  >> %ccdcpath%\Proof\regproof.txt

REG query "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f
REG query "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess >> %ccdcpath%\Proof\regproof.txt

REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" >> %ccdcpath%\Proof\regproof.txt
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t Reg_DWORD /d 0 /f
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" >> %ccdcpath%\Proof\regproof.txt

::Autoupdates
::REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions >> %ccdcpath%\Proof\regproof.txt
::REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
::REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions >> %ccdcpath%\Proof\regproof.txt

::Clear remote registry paths
ECHO Clear remote registry paths >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine >> %ccdcpath%\Proof\regproof.txt

REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine >> %ccdcpath%\Proof\regproof.txt

:: Delete the image hijack that kills taskmanager
ECHO Re-enable task manager: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v Debugger >> %ccdcpath%\Proof\regproof.txt
REG delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /f /v Debugger

ECHO Re-enable task manager 2: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr >> %ccdcpath%\Proof\regproof.txt
REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f

:: THIS PROBABLY HAS TO BE DONE MANUALLY if cmd is disabled, but who does that?!?!?!?!?!
ECHO Re-enable cmd prompt: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD >> %ccdcpath%\Proof\regproof.txt
REG delete "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /f

::Enable Windows Defender
ECHO Re-enable Windows Defender: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware >> %ccdcpath%\Proof\regproof.txt
REG delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f

:: Unhide Files
ECHO Unhide files: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden >> %ccdcpath%\Proof\regproof.txt
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden >> %ccdcpath%\Proof\regproof.txt

ECHO unhide system files: >> %ccdcpath%\Proof\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden >> %ccdcpath%\Proof\regproof.txt
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden >> %ccdcpath%\Proof\regproof.txt

:: Fix Local Security Authority(LSA)
ECHO Restrictanonymous: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous /t REG_DWORD /d 1 /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous >> %ccdcpath%\Proof\regproof.txt

ECHO Restrictanonymoussam: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam /t REG_DWORD /d 1 /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam >> %ccdcpath%\Proof\regproof.txt

ECHO Change everyone includes anonymous: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous >> %ccdcpath%\Proof\regproof.txt

ECHO Get rid of the ridiculous store plaintext passwords: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parametersn" /v EnablePlainTextPassword >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
REG query "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword >> %ccdcpath%\Proof\regproof.txt

ECHO Turn off Local Machine Hash: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash /t REG_DWORD /d 1 /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash  >> %ccdcpath%\Proof\regproof.txt

ECHO delete use machine id: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v UseMachineID >> %ccdcpath%\Proof\regproof.txt
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v UseMachineID /f

ECHO Change notification packages: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages"  >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages" /t REG_MULTI_SZ /d "scecli" /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages"  >> %ccdcpath%\Proof\regproof.txt

ECHO Show hidden users in gui: >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts" >> %ccdcpath%\Proof\regproof.txt
Reg delete "HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts" /f

ECHO Disable possible backdoors >> %ccdcpath%\Proof\regproof.txt
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "systray.exe" /f
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" >> %ccdcpath%\Proof\regproof.txt

REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger >> %ccdcpath%\Proof\regproof.txt
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger /t REG_SZ /d "systray.exe" /f
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger >> %ccdcpath%\Proof\regproof.txt

::Sticky keys
ECHO Taking over sticky keys
CD C:\Windows\System32
takeown /f sethc.exe >NUL
icacls sethc.exe /grant %username%:F >NUL
takeown /f systray.exe >NUL
icacls systray.exe /grant %username%:F >NUL
move sethc.exe sethc.old.exe
copy systray.exe sethc.exe

EXIT /B 0




::Win10
netsh advfirewall firewall add rule name="CCDC-Web Out Temp" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall add rule name="CCDC-DNS Out UDP" dir=out action=allow enable=yes profile=any remoteport=53 protocol=udp
netsh advfirewall firewall add rule name="CCDC-DNS Out TCP" dir=out action=allow enable=yes profile=any remoteport=53 protocol=tcp
netsh advfirewall firewall add rule name="CCDC-Logs to Splunk" dir=out action=allow enable=yes profile=any remoteip=%Splunk% remoteport=8000,8089,9997 protocol=tcp
::netsh advfirewall firewall add rule name="Web OUT to Docker" dir=out action=allow enable=no profile=any remoteip=%Docker% remoteport=443 protocol=tcp
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of %Dname%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Dname% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f
call :Config_NTP_NewWinVer_External
EXIT /B 0


:2012ad
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /t REG_DWORD /d 50243 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /t REG_DWORD /d 50244 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /t REG_DWORD /d 50245 /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *"
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "This computer system/network is the property of %Dname%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Dname% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE."

:: Disable SMB1?
REG add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f

::Temp web out
netsh advfirewall firewall add rule name="CCDC-Web Out Temp" dir=out action=allow enable=no profile=any remoteport=80,443 protocol=tcp

:: PAN User-Id
netsh advfirewall firewall add rule name="CCDC-PAN User-ID IN" dir=in action=allow enable=yes profile=any remoteip=%PAMI% remoteport=514 protocol=udp

::NetBIOS
netsh advfirewall firewall add rule name="CCDC-NetBIOS IN" dir=in action=allow enable=yes profile=any localport=137,138,139 remoteip=%Internal% protocol=udp

::File and Printer Sharing
::netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=yes remoteip=%Ecomm%

:: LDAP 389
netsh advfirewall firewall add rule name="CCDC-A - LDAP IN TCP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="CCDC-A - LDAP IN UDP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%WebMail%,%PAMI% protocol=udp
:: netsh advfirewall firewall add rule name="LDAP Out UDP" dir=out action=allow enable=yes profile=any remoteport=389 protocol=udp
:: netsh advfirewall firewall add rule name="LDAP Out TCP" dir=out action=allow enable=yes profile=any remoteport=389 protocol=tcp

:: LDAP 636
netsh advfirewall firewall add rule name="CCDC-A - LDAPS IN TCP" dir=in action=allow enable=no profile=any localport=636 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp
:: netsh advfirewall firewall add rule name="LDAPS Out TCP" dir=out action=allow enable=yes profile=any remoteport=636 protocol=tcp

:: LDAP 3268
::netsh advfirewall firewall add rule name="A - LDAP GC IN TCP" dir=in action=allow enable=yes profile=any localport=3268 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp

:: LDAP 3269
::netsh advfirewall firewall add rule name="A - LDAP GC SSL IN TCP" dir=in action=allow enable=yes profile=any localport=3269 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp

:: KERBEROS
netsh advfirewall firewall add rule name="CCDC-A - Kerberos In UDP from Internal" dir=in action=allow enable=yes profile=any localport=88,464 remoteip=%EComm%,%WebMail%,%PAMI% protocol=udp
netsh advfirewall firewall add rule name="CCDC-A - Kerberos In TCP from Internal" dir=in action=allow enable=yes profile=any localport=88,464 remoteip=%EComm%,%WebMail%,%PAMI% protocol=tcp
netsh advfirewall firewall set rule group="CCDC-Kerberos Key Distribution Center (TCP-In)" new enable=yes
netsh advfirewall firewall set rule group="CCDC-Kerberos Key Distribution Center (UDP-In)" new enable=yes

:: DNS 53
netsh advfirewall firewall add rule name="CCDC-DNS Out UDP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=udp
netsh advfirewall firewall add rule name="CCDC-DNS Out TCP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=tcp
:: netsh advfirewall firewall add rule name="DNS In TCP" dir=in action=allow enable=yes profile=any localport=53 remoteip=%UbuntuWrk%,%WebMail%,%DNSNTP%,%ADDNS%,%Splunk%,%EComm% protocol=tcp
netsh advfirewall firewall add rule name="CCDC-DNS In UDP from Internal" dir=in action=allow enable=yes profile=any localport=53  protocol=udp remoteip=%UbuntuWrk%,%WebMail%,%Splunk%,%EComm%,%DNSNTP%,%PAMI%,%Docker%,%UbuntuWeb%
netsh advfirewall firewall add rule name="CCDC-DNS In UDP from ANY" dir=in action=allow enable=no profile=any localport=53  protocol=udp

:: SMB AUTH 445
::netsh advfirewall firewall add rule name="PORT 445 SMB In" dir=in action=allow enable=yes profile=any localport=445 protocol=tcp remoteip=%Splunk%

:: Replication
::netsh advfirewall firewall add rule name="MSRPC IN from Webmail,Pami" dir=in action=allow enable=yes profile=any localport=135 remoteip=%Webmail%,%PAMI% protocol=tcp
::netsh advfirewall firewall add rule name="Static RPC IN from windows" dir=in action=allow enable=yes profile=any localport=50243,50244,50245 remoteip=%Splunk%,%PAMI% protocol=tcp
::netsh advfirewall firewall add rule name="Dynamic RPC IN from windows" dir=in action=allow enable=no profile=any localport=135 remoteip=%Splunk%,%PAMI% protocol=tcp

::Splunk out to
netsh advfirewall firewall add rule name="CCDC-Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%Splunk% remoteport=,8000,8089,9997 protocol=tcp

::Beta
netsh advfirewall firewall add rule name="CCDC-B - LDAP IN TCP" dir=in action=allow enable=no profile=any localport=389 remoteip=%UbuntuWrk%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="CCDC-B - LDAP IN UDP" dir=in action=allow enable=no profile=any localport=389 remoteip=%UbuntuWrk%,%Splunk%,%ADDNS%,%PAMI% protocol=udp
netsh advfirewall firewall add rule name="CCDC-B - LDAPS IN TCP" dir=in action=allow enable=no profile=any localport=636 remoteip=%UbuntuWrk%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp
::netsh advfirewall firewall add rule name="B - LDAP GC IN TCP" dir=in action=allow enable=no profile=any localport=3268 remoteip=%UbuntuWrk%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp
::netsh advfirewall firewall add rule name="B - LDAP GC SSL IN TCP" dir=in action=allow enable=no profile=any localport=3269 remoteip=%UbuntuWrk%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="CCDC-B - Kerberos In TCP" dir=in action=allow enable=no profile=any localport=88 remoteip=%UbuntuWrk%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp

::Charlie
netsh advfirewall firewall add rule name="CCDC-C - LDAP IN TCP" dir=in action=allow enable=no profile=any localport=389 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="CCDC-C - LDAP IN UDP" dir=in action=allow enable=no profile=any localport=389 remoteip=%Ecomm%,%WebMail% protocol=udp
netsh advfirewall firewall add rule name="CCDC-C - LDAPS IN TCP" dir=in action=allow enable=no profile=any localport=636 remoteip=%Ecomm%,%WebMail% protocol=tcp
::netsh advfirewall firewall add rule name="C - LDAP GC IN TCP" dir=in action=allow enable=no profile=any localport=3268 remoteip=%Ecomm%,%WebMail% protocol=tcp
::netsh advfirewall firewall add rule name="C - LDAP GC SSL IN TCP" dir=in action=allow enable=no profile=any localport=3269 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - Kerberos In TCP" dir=in action=allow enable=no profile=any localport=88 remoteip=%Ecomm%,%WebMail% protocol=tcp

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

call :Config_NTP
EXIT /B 0



:Config_NTP_NewWinVer_External
net start w32time
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update
w32tm /resync
net stop w32time && net start w32time
TZUTIL /s "Eastern Standard Time"
start powershell -Noexit w32tm /query /peers
Exit /B 0


:Config_NTP
net start w32time
w32tm /config /manualpeerlist:"%EComm%" /syncfromflags:manual /reliable:yes /update
w32tm /resync
net stop w32time && net start w32time
start cmd /k echo w32tm /query /peers
EXIT /B 0


:Config_NTP_NewWinVer
::Configuration  for new windows versions
net start w32time
w32tm /config /manualpeerlist:"%EComm%" /syncfromflags:manual /reliable:yes /update
w32tm /resync
net stop w32time && net start w32time
TZUTIL /s "Eastern Standard Time"
start powershell -Noexit w32tm /query /peers
EXIT /B 0



:: Logon Banner 2012
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of Team.Com. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A TEAM.COM OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f


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





::****************************************************Extra Stuff**********************************************

:: Generic Firewall rules
::netsh advfirewall firewall add rule name="OSSEC IN for Splunk" dir=in action=allow enable=yes profile any remoteip=%DNSNTP% remoteport=515 protocol=udp
::netsh advfirewall firewall add rule name="SHARE Out" dir=out action=allow enable=no profile=any remoteport=445 remoteip=%ADDNS% protocol=tcp
::netsh advfirewall firewall add rule name="SSH FROM 2008" dir=in action=allow enable=no profile=any localport=22 remoteip=%ADDNS% protocol=tcp
::netsh advfirewall firewall add rule name="Splunk IN" dir=in action=allow enable=yes profile=any localport=8000,8089,9997 remoteip=%OpenEMR%,%DNSNTP%,%WebMail%,%Splunk%,%ADNDS%,%PAMI% protocol=tcp
::netsh advfirewall firewall add rule name="WinSCP/SSH Out" dir=out action=allow enable=no profile=any remoteip= remoteport=22 protocol=tcp

:: PAN firewall rules
::netsh advfirewall firewall add rule name="PA RULE" dir=out action=allow enable=yes profile=any remoteip=%PAMI% remoteport=443 protocol=tcp
::netsh advfirewall firewall add rule name="PA RULE" dir=out action=allow enable=no profile=any remoteip=%PAMI% remoteport=80 protocol=tcp
::netsh advfirewall firewall add rule name="PAN 514 IN" dir=in action=allow enable=yes profile any remoteip=%PAMI% remoteport=514 protocol=udp

:: BIND 953
::netsh advfirewall firewall add rule name="BIND In From Ubuntu" dir=in action=allow enable=no profile=any localport=953 remoteip=%DNSNTP% protocol=tcp
::netsh advfirewall firewall add rule name="BIND Out To Ubuntu" dir=out action=allow enable=no profile=any remoteport=953 remoteip=%DNSNTP% protocol=tcp

:: Powershell
::takeown /f %systemroot%\system32\windowspowershell
::takeown /f %systemroot%\SYSWOW64\windowspowershell


::Splunk_Install
::msiexec.exe /i Splunk-<...>-x64-release.msi



:: Export Product key
::wmic path softwarelicensingservice get OA3xOriginalProductKey > %ccdcpath%\Config\ProductKey.txt