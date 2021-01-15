@echo off
:: Frame settings
mode 800
Title "CCDC Windows Script"

:: Sets ccdc paths and host os
set ccdcpath="c:\ccdc"
set psccdcpath=c:\ccdc
set /p box="Please type your box as follows: [ Win8 , 2008ad , 2008sql , 2012web , Win10 ]: "


:: Checks for admin permissions, errorlevel indicates number of errors
echo Administrative permissions required. Detecting permissions.....
ECHO.
ECHO.
if %box% == 2012web ( call :New_Check 
) else (
	if %box% == Win10 ( call :New_Check 
	) else ( 
		if %box% == Win8 ( call :New_Check 
		) else ( call :Old_Check )
	)
) 
if not %errorLevel% == 0 (
	Exit /B 1
)

:: Makes ccdc directory
mkdir %ccdcpath%
mkdir %ccdcpath%\Regback
mkdir %ccdcpath%\SmbProof

:: Export Hosts
copy %systemroot%\system32\drivers\etc\hosts %ccdcpath%\hosts
ECHO # This is OUR hosts file! > %systemroot%\system32\drivers\etc\hosts

:: Sets IPS
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
netsh advfirewall set allprofiles logging filename %ccdcpath%\pfirewall.log
netsh advfirewall set allprofiles logging maxfilesize 8192
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set global statefulftp disable
netsh advfirewall set global statefulpptp disable

call :Get_Sysinternals

::Generic Firewall rules
netsh advfirewall firewall set rule name=all new enable=no
netsh advfirewall firewall add rule name="Allow Pings" protocol=icmpv4:8,any dir=in action=allow enable=yes
netsh advfirewall firewall add rule name="All the Pings!" dir=out action=allow enable=yes protocol=icmpv4:8,any
if not %box% == Win10 (
	netsh advfirewall firewall add rule name="NTP Allow" dir=out action=allow enable=yes profile=any remoteport=123 remoteip=%EComm% protocol=udp
	netsh advfirewall firewall add rule name="WinSCP/SSH Out" dir=out action=allow enable=no profile=any remoteip=%WebMail%,%Splunk%,%DNSNTP%,%EComm%,%WIN8%,%ADDNS%,%Win8% remoteport=22 protocol=tcp
	netsh advfirewall firewall add rule name="Web Share OUT" dir=out action=allow enable=no profile=any remoteip=%Ecomm% remoteport=80 protocol=tcp
)

:: Diable IPv6 Teredo tunneling
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled 

echo on
call :%box%
@echo off
call :Damage_Reversal
call :Export_Configs

@ECHO off
ECHO.
ECHO.
ECHO.
ECHO.
ECHO.
ECHO.
ECHO Script completed successfully!
ECHO.
ECHO.
ECHO.
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
set  DNSNTP=172.25.24.23
set  WebMail=172.25.24.39
set  Splunk=172.25.24.9
set  ADDNS=172.25.24.27
set /P Windows10="ENTER WINDOWS 10 IP: "
set  WIN8= 172.25.24
set  PAMI=172.31.24.2
set  Phantom=172.25.24.97
set  MySql=172.25.24.20
Echo E-Commerce Ip is now %EComm%
Echo DNS/NTP IP is now %DNSNTP%
Echo WebMail IP is now %WebMail%
Echo Splunk ip is now %Splunk%
Echo AD/DNS box ip is now %ADDNS%
Echo MySql IP is now %MySql%
Echo Windows10 Ip is now %Windows10%
Echo WIN8 is now %WIN8%
Echo PA MI is now %PAMI%
Echo Phantom is now %Phantom%
set /p Garbage="IS WIN10 correct? (Y/N)"
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
set /P Windows10="ENTER WINDOWS 10 IP: "
set  WIN8=172.20.242.100
set  PAMI=172.20.242.150
set  Phantom=172.20.240.10
set  MySql=172.20.240.20
Echo E-Commerce Ip is now %EComm%
Echo DNS/NTP IP is now %DNSNTP%
Echo WebMail IP is now %WebMail%
Echo Splunk ip is now %Splunk%
Echo AD/DNS box ip is now %ADDNS%
Echo MySql IP is now %MySql%
Echo Windows10 Ip is now %Windows10%
Echo WIN8 is now %WIN8%
Echo PA MI is now %PAMI%
Echo Phantom is now %Phantom%
set /p Garbage="IS WIN10 correct? (Y/N)"
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
echo. > %ccdcpath%\regproof.txt
:: Just a name thing, but I don't like "redteam" being owner...
ECHO Change RegisteredOwner: >> %ccdcpath%\regproof.txt
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner >> %ccdcpath%\regproof.txt
REG add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d blueteam /f
REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner >> %ccdcpath%\regproof.txt

:: Delete the image hijack that kills taskmanager
ECHO Re-enable task manager: >> %ccdcpath%\regproof.txt
REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v Debugger >> %ccdcpath%\regproof.txt
REG delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /f /v Debugger

ECHO Re-enable task manager 2: >> %ccdcpath%\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr >> %ccdcpath%\regproof.txt
REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f

:: THIS PROBABLY HAS TO BE DONE MANUALLY if cmd is disabled, but who does that?!?!?!?!?!
ECHO Re-enable cmd prompt: >> %ccdcpath%\regproof.txt
REG query "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD >> %ccdcpath%\regproof.txt
REG delete "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /f

::Enable Windows Defender
ECHO Re-enable Windows Defender >> %ccdc%\regproof.txt
REG query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware >> %ccdc%\regproof.txt
REG delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f

:: Unhide Files
ECHO Unhide files: >> %ccdcpath%\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden >> %ccdcpath%\regproof.txt
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden >> %ccdcpath%\regproof.txt

ECHO unhide system files: >> %ccdcpath%\regproof.txt
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden >> %ccdcpath%\regproof.txt
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden >> %ccdcpath%\regproof.txt

:: Fix Local Security Authority(LSA)
ECHO Restrictanonymous: >> %ccdcpath%\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous >> %ccdcpath%\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous /t REG_DWORD /d 1 /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous >> %ccdcpath%\regproof.txt

ECHO Restrictanonymoussam: >> %ccdcpath%\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam >> %ccdcpath%\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam /t REG_DWORD /d 1 /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam >> %ccdcpath%\regproof.txt

ECHO Change everyone includes anonymous: >> %ccdcpath%\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous >> %ccdcpath%\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous >> %ccdcpath%\regproof.txt

ECHO Get rid of the ridiculous store plaintext passwords: >> %ccdcpath%\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parametersn" /v EnablePlainTextPassword >> %ccdcpath%\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
REG query "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword >> %ccdcpath%\regproof.txt

ECHO Turn off Local Machine Hash: >> %ccdcpath%\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash >> %ccdcpath%\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash /t REG_DWORD /d 1 /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash  >> %ccdcpath%\regproof.txt

ECHO delete use machine id: >> %ccdcpath%\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v UseMachineID >> %ccdcpath%\regproof.txt
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v UseMachineID /f

ECHO Change notification packages: >> %ccdcpath%\regproof.txt
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages"  >> %ccdcpath%\regproof.txt
REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages" /t REG_MULTI_SZ /d "scecli" /f
REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages"  >> %ccdcpath%\regproof.txt

ECHO Show hidden users in gui: >> %ccdcpath%\regproof.txt
REG query "HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts" >> %ccdcpath%\regproof.txt
Reg delete "HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts" /f
EXIT /B 0


:WIN8
::firewall_configs
netsh advfirewall firewall add rule name="PA RULE" dir=out action=allow enable=yes profile=any remoteip=%PAMI% remoteport=443 protocol=tcp
netsh advfirewall firewall add rule name="Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%SPLUNK%, %EComm% remoteport=,8000,8089,9997 protocol=tcp
netsh advfirewall firewall add rule name="SSH OUT PAN" dir=out action=allow enable=no profile=any localport=22 remoteip=%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="Web Out to WebShare" dir=out action=allow enable=yes profile=any remoteport=80,443 remoteip=%EComm%,%DNSNTP% protocol=tcp
netsh advfirewall firewall add rule name="NTP Allow" dir=out action=allow enable=yes profile=any remoteport=123 remoteip=%Splunk% protocol=udp
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of %Dname%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Dname% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f
call :SMBV1_Fix
EXIT /B 0


:Win10
netsh advfirewall firewall add rule name="Web Out Temp" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall add rule name="DNS Out UDP" dir=out action=allow enable=yes profile=any remoteport=53 protocol=udp
netsh advfirewall firewall add rule name="DNS Out TCP" dir=out action=allow enable=yes profile=any remoteport=53 protocol=tcp
netsh advfirewall firewall add rule name="Web OUT to Splunk Old" dir=out action=allow enable=no profile=any remoteip=%Splunk% remoteport=8000 protocol=tcp
netsh advfirewall firewall add rule name="Web OUT to Splunk New" dir=out action=allow enable=yes profile=any remoteip=%Ecomm% remoteport=8000 protocol=tcp
netsh advfirewall firewall add rule name="Web OUT to Phantom" dir=out action=allow enable=no profile=any remoteip=%Phantom% remoteport=443 protocol=tcp
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of %Dname%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Dname% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f
call :Config_NTP_NewWinVer_External
call :SMBV1_Fix
EXIT /B 0


:2008ad
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /t REG_DWORD /d 50243 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /t REG_DWORD /d 50244 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /t REG_DWORD /d 50245 /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *"
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "This computer system/network is the property of %Dname%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Dname% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE."

:: Disable SMB1?
REG add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f

::Temp web out
netsh advfirewall firewall add rule name="Web Out Temp" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp

::File and Printer Sharing
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=yes remoteip=%Ecomm%,%MySql%

:: LDAP 389
netsh advfirewall firewall add rule name="A - LDAP IN TCP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%MySql%,%WebMail%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="A - LDAP IN UDP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%MySql%,%WebMail%,%PAMI% protocol=udp
:: netsh advfirewall firewall add rule name="LDAP Out UDP" dir=out action=allow enable=yes profile=any remoteport=389 protocol=udp
:: netsh advfirewall firewall add rule name="LDAP Out TCP" dir=out action=allow enable=yes profile=any remoteport=389 protocol=tcp

:: LDAP 636
netsh advfirewall firewall add rule name="A - LDAPS IN TCP" dir=in action=allow enable=no profile=any localport=636 remoteip=%EComm%,%DNSNTP%,%WebMail%,%ADNDS%,%PAMI% protocol=tcp
:: netsh advfirewall firewall add rule name="LDAPS Out TCP" dir=out action=allow enable=yes profile=any remoteport=636 protocol=tcp

:: LDAP 3268
netsh advfirewall firewall add rule name="A - LDAP GC IN TCP" dir=in action=allow enable=yes profile=any localport=3268 remoteip=%EComm%,%DNSNTP%,%WebMail%,%ADNDS%,%PAMI% protocol=tcp

:: LDAP 3269
netsh advfirewall firewall add rule name="A - LDAP GC SSL IN TCP" dir=in action=allow enable=yes profile=any localport=3269 remoteip=%EComm%,%DNSNTP%,%WebMail%,%ADNDS%,%PAMI% protocol=tcp

:: KERBEROS 88
netsh advfirewall firewall add rule name="A - Kerberos In UDP from Internal" dir=in action=allow enable=yes profile=any localport=88 remoteip=%EComm%,%DNSNTP%,%WebMail%,%Splunk%,%ADNDS%,%PAMI%,%MySql% protocol=udp
netsh advfirewall firewall add rule name="A - Kerberos In TCP from Internal" dir=in action=allow enable=yes profile=any localport=88 remoteip=%EComm%,%DNSNTP%,%WebMail%,%Splunk%,%ADNDS%,%PAMI%,%MySql% protocol=tcp
netsh advfirewall firewall set rule group="Kerberos Key Distribution Center (TCP-In)" new enable=yes
netsh advfirewall firewall set rule group="Kerberos Key Distribution Center (UDP-In)" new enable=yes
::Beta
netsh advfirewall firewall add rule name="B - LDAP IN TCP" dir=in action=allow enable=no profile=any localport=389 remoteip=%WIN8%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="B - LDAP IN UDP" dir=in action=allow enable=no profile=any localport=389 remoteip=%WIN8%,%Splunk%,%ADDNS%,%PAMI% protocol=udp
netsh advfirewall firewall add rule name="B - LDAPS IN TCP" dir=in action=allow enable=no profile=any localport=636 remoteip=%WIN8%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="B - LDAP GC IN TCP" dir=in action=allow enable=no profile=any localport=3268 remoteip=%WIN8%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="B - LDAP GC SSL IN TCP" dir=in action=allow enable=no profile=any localport=3269 remoteip=%WIN8%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="B - Kerberos In TCP" dir=in action=allow enable=no profile=any localport=88 remoteip=%WIN8%,%Splunk%,%ADDNS%,%PAMI% protocol=tcp

::Charlie
netsh advfirewall firewall add rule name="C - LDAP IN TCP" dir=in action=allow enable=no profile=any localport=389 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - LDAP IN UDP" dir=in action=allow enable=no profile=any localport=389 remoteip=%Ecomm%,%WebMail% protocol=udp
netsh advfirewall firewall add rule name="C - LDAPS IN TCP" dir=in action=allow enable=no profile=any localport=636 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - LDAP GC IN TCP" dir=in action=allow enable=no profile=any localport=3268 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - LDAP GC SSL IN TCP" dir=in action=allow enable=no profile=any localport=3269 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - Kerberos In TCP" dir=in action=allow enable=no profile=any localport=88 remoteip=%Ecomm%,%WebMail% protocol=tcp

:: DNS 53
netsh advfirewall firewall add rule name="DNS Out UDP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP%,%Splunk% protocol=udp
netsh advfirewall firewall add rule name="DNS Out TCP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP%,%Splunk% protocol=tcp
:: netsh advfirewall firewall add rule name="DNS In TCP" dir=in action=allow enable=yes profile=any localport=53 remoteip=%WIN8%,%WebMail%,%DNSNTP%,%ADDNS%,%Splunk%,%EComm% protocol=tcp
netsh advfirewall firewall add rule name="DNS In UDP from Internal" dir=in action=allow enable=yes profile=any localport=53  protocol=udp remoteip=%WIN8%,%WebMail%,%Splunk%,%EComm%,%DNSNTP%,%PAMI%,%MySql%,
netsh advfirewall firewall add rule name="DNS In UDP from ANY" dir=in action=allow enable=no profile=any localport=53  protocol=udp

:: SMB AUTH 445
netsh advfirewall firewall add rule name="PORT 445 SMB In" dir=in action=allow enable=no profile=any localport=445 protocol=tcp remoteip=%Splunk%,%MySql%

:: Replication
netsh advfirewall firewall add rule name="MSRPC IN from MySql,Webmail,Pami" dir=in action=allow enable=yes profile=any localport=135 remoteip=%MySql%,%Webmail%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="Static RPC IN from windows" dir=in action=allow enable=yes profile=any localport=50243,50244,50245 remoteip=%MySql%,%Splunk%,%PAMI% protocol=tcp
::netsh advfirewall firewall add rule name="Dynamic RPC IN from windows" dir=in action=allow enable=no profile=any localport=135 remoteip=%Splunk%,%PAMI% protocol=tcp

:: SSH out
netsh advfirewall firewall add rule name="SSH TO 2012" dir=out action=allow enable=no profile=any remoteport=22 remoteip=%Splunk% protocol=tcp

::Splunk out to
netsh advfirewall firewall add rule name="Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%SPLUNK%, %EComm% remoteport=,8000,8089,9997 protocol=tcp

::Add PA Groups
dsadd group cn=Marketing,cn=users,dc=frog,dc=com -secgrp yes -samid marketing
dsadd group cn=Sales,cn=users,dc=frog,dc=com -secgrp yes -samid sales
dsadd group cn=HumanResources,cn=users,dc=frog,dc=com -secgrp yes -samid humanresources
::dsadd group cn=marketing,cn=user,dc=corp,dc=com
::dsadd group cn=sales,cn=user,dc=corp,dc=com
dsadd user "cn=James Doohan,cn=Users,dc=frog,dc=com" -samid JDoohan -fn James -ln Doohan -pwd *
net localgroup Administrators JDoohan /add
net localgroup "Distributed COM Users" JDoohan /add
net localgroup "Event Log Readers" JDoohan /add
net localgroup "Server Operators" JDoohan /add
dsadd user "cn=Michael Dorn,cn=Users,dc=frog,dc=com" -samid MDorn -fn Michael -ln Dorn  -pwd *
net localgroup Marketing MDorn /Add
net localgroup Sales MDorn /Add
net localgroup "Human Resources"
net localgroup "Human Resources" MDorn /Add

::Create Password policy
start powershell.exe -noexit Set-ADDefaultDomainPasswordPolicy -Identity frog.com -ComplexityEnabled $true -MinPasswordLength 8 -MinPasswordAge 1 -MaxPasswordAge 30 -LockoutDuration 00:60:00 -LockoutObservationWindow 00:30:00 -LockoutThreshold 5
start powershell.exe -noexit Get-ADDefaultDomainPasswordPolicy >> %ccdcpath%\DomainPasswordPolicy.txt

call :Config_NTP
EXIT /B 0


:2008sql
:: Web Out:
netsh advfirewall firewall add rule name="Web Out Temp" dir=out action=allow enable=no profile=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall add rule name="DNS Out" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%ADDNS% protocol=udp

:: LDAP STUFF
netsh advfirewall firewall add rule name="LDAP OUT UDP" dir=out action=allow enable=yes profile=any remoteport=389 remoteip=%ADDNS% protocol=udp
netsh advfirewall firewall add rule name="LDAP OUT TCP" dir=out action=allow enable=yes profile=any remoteport=389 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="SHARE Out" dir=out action=allow enable=yes profile=any remoteport=445 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="msrpc" dir=out action=allow enable=yes profile=any remoteport=135 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Static rpc out" dir=out action=allow enable=yes profile=any remoteport=50243,50244,50245 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Kerberos out" dir=out action=allow enable=yes profile=any remoteport=88 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%WebMail% remoteport=,8000,8089,9997 protocol=tcp
call :Config_NTP
EXIT /B 0


:2012web
netsh advfirewall firewall add rule name="PA RULE" dir=out action=allow enable=yes profile=any remoteip=%PAMI% remoteport=443 protocol=tcp
netsh advfirewall firewall add rule name="PA RULE" dir=out action=allow enable=no profile=any remoteip=%PAMI% remoteport=80 protocol=tcp
netsh advfirewall firewall add rule name="Web Out" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall add rule name="DNS Out" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%ADDNS% protocol=udp
netsh advfirewall firewall add rule name="LDAP OUT UDP" dir=out action=allow enable=yes profile=any remoteport=389 remoteip=%ADDNS% protocol=udp
netsh advfirewall firewall add rule name="LDAP OUT TCP" dir=out action=allow enable=yes profile=any remoteport=389 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="SHARE Out" dir=out action=allow enable=no profile=any remoteport=445 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="MSRPC" dir=out action=allow enable=yes profile=any remoteport=135 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Static rpc out" dir=out action=allow enable=yes profile=any remoteport=50243,50244,50245 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Kerberos out" dir=out action=allow enable=yes profile=any remoteport=88 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="SSH FROM 2008" dir=in action=allow enable=no profile=any localport=22 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Splunk IN" dir=in action=allow enable=yes profile=any localport=8000,8089,9997 remoteip=%EComm%,%DNSNTP%,%WebMail%,%Splunk%,%ADNDS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%WebMail%, %Ecomm% remoteport=8000,8089,9997 protocol=tcp
netsh advfirewall firewall add rule name="PAN 514 IN" dir=in action=allow enable=yes profile any remoteip=%PAMI% remoteport=514 protocol=udp
netsh advfirewall firewall add rule name="OSSEC IN for Splunk" dir=in action=allow enable=yes profile any remoteip=%DNSNTP% remoteport=515 protocol=udp
netsh advfirewall firewall add rule name="SSH FROM 2008" dir=in action=allow enable=no profile=any localport=22 remoteip=%DNSNTP% protocol=tcp

:: Logon Banner 2012
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of %Dname%. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A %Dname% OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f

call :Config_NTP_NewWinVer
powershell.exe -EncodedCommand IwBQAG8AdwBlAHIAcwBoAGUAbABsACAAUwBjAHIAaQBwAHQAIAB0AG8AIABJAG4AcwB0AGEAbABsACAAJgAgAEMAbwBuAGYAaQBnACAAUwBOAE0AUAAgAFMAZQByAHYAaQBjAGUACgAjAEkAbQBwAG8AcgB0ACAAUwBlAHIAdgBlAHIAIABNAGEAbgBhAGcAZQByACAATQBvAGQAdQBsAGUACgBJAG0AcABvAHIAdAAtAE0AbwBkAHUAbABlACAAUwBlAHIAdgBlAHIATQBhAG4AYQBnAGUAcgAKACMAUwBlAHIAdgBpAGMAZQAgAEMAaABlAGMAawAKACQAYwBoAGUAYwBrACAAPQAgAEcAZQB0AC0AVwBpAG4AZABvAHcAcwBGAGUAYQB0AHUAcgBlACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBOAGEAbQBlACAALQBlAHEAIAAiAFMATgBNAFAALQBTAGUAcgB2AGkAYwBlAHMAIgB9AAoASQBmACAAKAAkAGMAaABlAGMAawAuAEkAbgBzAHQAYQBsAGwAZQBkACAALQBuAGUAIAAiAFQAcgB1AGUAIgApAHsACgAjAEkAbgBzAHQAYQBsAGwALwBFAG4AYQBiAGwAZQAgAFMATgBNAFAAIABTAGUAcgB2AGkAYwBlAHMACgBBAGQAZAAtAFcAaQBuAGQAbwB3AHMARgBlAGEAdAB1AHIAZQAgAFMATgBNAFAALQBTAGUAcgB2AGkAYwBlACAAfAAgAE8AdQB0AC0ATgB1AGwAbAAKAH0ACgAjACMAIABWAGUAcgBpAGYAeQAgAFcAaQBuAGQAbwB3AHMAIABTAGUAcgB2AGkAYwBlAHMAIABhAHIAZQAgAEUAbgBhAGIAbABlAGQAIAAKAEkAZgAgACgAJABjAGgAZQBjAGsALgBJAG4AcwB0AGEAbABsAGUAZAAgAC0AbgBlACAAIgBUAHIAdQBlACIAKQB7AAoAIwBTAGUAdAAgAFMATgBNAFAAIABQAGUAcgBtAGkAdAB0AGUAZAAgAE0AYQBuAGEAZwBlAHIAcwAoAHMAKQAgACoAKgAgAEUAeABpAHMAdABpAG4AZwAgAHMAaABpAHQAIABpAHMAIABhAGIAbwB1AHQAIAB0AG8AIABnAG8AKgAqAAoAUgBFAEcAIABBAEQARAAgACIASABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAHkAcwB0AGUAbQBcAEMAdQByAHIAZQBuAHQAQwBvAG4AdAByAG8AbABTAGUAdABcAFMAZQByAHYAaQBjAGUAcwBcAFMATgBNAFAAXABQAGEAcgBhAG0AZQB0AGUAcgBzAFwAUABlAHIAbQBpAHQAdABlAGQATQBhAG4AYQBnAGUAcgBzACIAIAAvAHYAIAAxACAALwB0ACAAUgBFAEcAXwBTAFoAIAAvAGQAIAAxADcAMgAuADIAMAAuADIANAAyAC4AMQA3ACAALwBmACAAfABPAHUAdAAtAE4AdQBsAGwACgAjAFMAZQB0ACAAUwBOAE0AUAAgAEMAbwBtAG0AdQBuAGkAdAB5ACAAUwB0AHIAaQBuAGcAcwAKAFIARQBHACAAQQBEAEQAIAAiAEgASwBFAFkAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAFwAUwB5AHMAdABlAG0AXABDAHUAcgByAGUAbgB0AEMAbwBuAHQAcgBvAGwAUwBlAHQAXABTAGUAcgB2AGkAYwBlAHMAXABTAE4ATQBQAFwAUABhAHIAYQBtAGUAdABlAHIAcwBcAFYAYQBsAGkAZABDAG8AbQBtAHUAbgBpAHQAaQBlAHMAIgAgAC8AdgAgAGMAaABhAG4AZwBlAG0AZQAgAC8AdAAgAFIARQBHAF8ARABXAE8AUgBEACAALwBkACAAOAAgAC8AZgAgAHwATwB1AHQALQBOAHUAbABsAAoAfQAKAAoARQBsAHMAZQAgAHsAVwByAGkAdABlAC0ASABvAHMAdAAgACIARQByAHIAbwByADoAIABTAE4ATQBQACAAUwBlAHIAdgBpAGMAZQBzACAAbgBvAHQAIABJAG4AcwB0AGEAbABsAGUAZAAhACIAfQA=
EXIT /B 0


:SMBV1_Fix
::since this only works for win 8 and newer we have to decide where we are and where to apply this fix, in prior verisons there is a regkey change for lanman\services for it
powershell.exe Get-SmbServerConfiguration >> %psccdcpath%\SmbProof\SMBDetect.txt
powershell.exe Set-SmbServerConfiguration -EnableSMB1Protocol $false
powershell.exe Get-SmbServerConfiguration >> %psccdcpath%\SmbProof\SMBDetect.txt
Notepad.exe %psccdcpath%\SmbProof\SMBDetect.txt
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


:Export_Configs
:: Export registry
reg export HKLM %ccdcpath%\Regback\hlkm.reg
reg export HKCU %ccdcpath%\Regback\hkcu.reg
reg export HKCR %ccdcpath%\Regback\hlcr.reg
reg export HKU %ccdcpath%\Regback\hlku.reg
reg export HKCC %ccdcpath%\Regback\hlcc.reg
EXIT /B 0


:Get_Sysinternals
Set /p Garbage2="Would you like to download sysinternals Autoruns and Process monitor? ###Needs DNS###  (Y/N)    "
if "%Garbage2%" == "Y" (
	netsh advfirewall firewall add rule name="Temp Web out to any for sysinternals" dir=in enable=yes action=allow profile=any remoteip=any remoteport=443 protocol=TCP
	bitsadmin.exe /transfer "JobName" https://download.sysinternals.com/files/Autoruns.zip "%ccdcpath%\autoruns.zip"
	bitsadmin.exe /transfer "JobName" https://download.sysinternals.com/files/ProcessMonitor.zip "%ccdcpath%\processmonitor.zip"
)
EXIT /B 0


::****************************************************Extra Stuff**********************************************
::takeown /f %systemroot%\system32\windowspowershell
::takeown /f %systemroot%\SYSWOW64\windowspowershell

:: BIND 953
::netsh advfirewall firewall add rule name="BIND In From Ubuntu" dir=in action=allow enable=no profile=any localport=953 remoteip=%DNSNTP% protocol=tcp
::netsh advfirewall firewall add rule name="BIND Out To Ubuntu" dir=out action=allow enable=no profile=any remoteport=953 remoteip=%DNSNTP% protocol=tcp

::SNMP Config
::powershell.exe -noexit Import-Module ServerManager $check = Get-WindowsFeature | Where-Object {$_.Name -eq "SNMP-Services"} If ($check.Installed -ne "True"){Add-WindowsFeature SNMP-Service | Out-Null} If ($check.Installed -ne "True"){ REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\SNMP\Parameters\PermittedManagers" /v 1 /t REG_SZ /d 172.20.241.9 /f |Out-Null REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" /v inthecorn /t REG_DWORD /d 8 /f |Out-Null } Else {Write-Host "Error: SNMP Services not Installed!"}

:: Get sysinternals
::netsh advfirewall firewall add rule name="Temp Web to sysinternals" dir=in enable=yes action=allow profile=any remoteip=72.21.81.200 remoteport=443 protocol=TCP
::echo 72.21.81.200 download.sysinternals.com >> %systemroot%\system32\drivers\etc\hosts
::bitsadmin.exe /transfer "JobName" https://download.sysinternals.com/files/SysinternalsSuite.zip "%ccdcpath%\sysinternals.zip"
::netsh advfirewall firewall set rule name="Temp Web to sysinternals" new enable=no

::Splunk_Install
::msiexec.exe /i Splunk-<...>-x64-release.msi