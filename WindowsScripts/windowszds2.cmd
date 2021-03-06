@Echo On
:: ########## Options ##########
set ccdcpath="c:\ccdc"
:: set path="%systemroot%\system32\LogFiles\Firewall"
mode con:cols=140 lines=10000
:: ECHO Please type your box as follows: [ win8 , 2008ad, 2008sql , 2012web , win10 ]
set /p box="Please type your box as follows: [ win8 , Win7 , 2008ad , 2008sql , 2012web , win10 ]: "

:: ########## Check if Elevated ##########

echo Administrative permissions required. Detecting permissions.....
ECHO.
ECHO.
if %box% == 2012web ( GOTO New_Check )
if %box% == win10 ( GOTO New_Check )
if %box% == win8 ( GOTO New_Check
) else ( GOTO Old_Check )

:New_Check
	net session >nul 2>&1
	if %errorLevel% == 0 (
    	echo Success: Administrative permissions confirmed.
    	GOTO Set_IPS
	) ELSE (
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


:Old_Check
:: ##### Pre - Win 8 #####
AT > NUL
  IF %ERRORLEVEL% EQU 0 (
    	ECHO Success: Administrative permissions confirmed.
    	GOTO Set_IPS

	) ELSE (
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

:Set_IPS
set  EComm=172.20.240.11
set  DNSNTP=172.20.240.23
set  WebMail=172.20.241.39
set  WebApps=172.20.241.3
set  ADDNS=172.20.241.27
::set Ubuntu ="Ubuntu IP  "
::set Windows10="Windows10 IP  "
set /P Windows7="ENTER WINDOWS 7 IP: "
::set Elearning="Elearning IP  "
set  FTP03=172.20.241.9
set  PAMI=172.20.241.100

Echo E-Commerce Ip is now %EComm%
Echo DNS/NTP IP is now %DNSNTP%
Echo WebMail IP is now %WebMail%
Echo WebApps ip is now %WebApps%
Echo AD/DNS box ip is now %ADDNS%
::Echo Ubuntu IP is now %Ubuntu%
::Echo Windows10 Ip is now %Windows10%
Echo Windows7 Ip is now %Windows7%
::Echo E learning Ip is now %Elearning%
Echo FTP03 is now %FTP03%
Echo PA MI is now %PAMI%

set /p Garbage="IS WIN 7 correct? (Y/N)"

IF %Garbage% == "N" (
GOTO Set_IPS )
IF %Garbage% == "n" (
GOTO Set_IPS )
) ELSE (

GOTO Disable_Powershell )

:Disable_Powershell
::taskkill /f /im powershell.exe
::taskkill /f /im powershell.exe
::taskkill /f /im powershell.exe
::taskkill /f /im powershell.exe
::taskkill /f /im powershell.exe
::takeown /f %systemroot%\system32\windowspowershell
::takeown /f %systemroot%\SYSWOW64\windowspowershell
::rename %systemroot%\system32\windowspowershell NOPOWERSHELLFORYOU
::rename %systemroot%\SYSWOW64\windowspowershell NOPOWERSHELLFORYOU

mkdir %ccdcpath%
mkdir %ccdcpath%\Regback
:: Export Hosts
copy %systemroot%\system32\drivers\etc\hosts %ccdcpath%\hosts
ECHO # This is OUR hosts file! > %systemroot%\system32\drivers\etc\hosts
PAUSE
GOTO Prep_Firewall

:Prep_Firewall


:: ########## ENABLE LOGGING #########
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

netsh advfirewall firewall set rule name=all new enable=no
netsh advfirewall firewall add rule name="Allow Pings" protocol=icmpv4:8,any dir=in action=allow enable=yes
netsh advfirewall firewall add rule name="All the Pings!" dir=out action=allow enable=yes protocol=icmpv4:8,any
netsh advfirewall firewall add rule name="NTP Allow" dir=out action=allow enable=yes profile=any remoteport=123 remoteip=%DNSNTP%,%ADDNS%,%PAMI% protocol=udp
netsh advfirewall firewall add rule name="WinSCP/SSH Out" dir=out action=allow enable=no profile=any remoteip=%WebMail%,%WebApps%,%DNSNTP%,%EComm%,%FTP03%,%ADDNS% remoteport=22 protocol=tcp
netsh advfirewall firewall add rule name="Web Share OUT" dir=out action=allow enable=no profile=any remoteip=%WebApps% remoteport=80 protocol=tcp


:: Get sysinternals
::netsh advfirewall firewall add rule name="Temp Web to sysinternals" dir=in enable=yes action=allow profile=any remoteip=72.21.81.200 remoteport=443 protocol=TCP
::echo 72.21.81.200 download.sysinternals.com >> %systemroot%\system32\drivers\etc\hosts
::bitsadmin.exe /transfer "JobName" https://download.sysinternals.com/files/SysinternalsSuite.zip "%ccdcpath%\sysinternals.zip"
::netsh advfirewall firewall set rule name="Temp Web to sysinternals" new enable=no

GOTO Damage_Reversal

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

ECHO Get rid of the rediculous store plaintext passwords: >> %ccdcpath%\regproof.txt
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


goto %box%

:win7



GOTO SNMP_Config


:FTP03

netsh advfirewall firewall set rule name=all new enable=no
netsh advfirewall firewall add rule name="PA RULE" dir=out action=allow enable=yes profile=any remoteip=%PAMI% remoteport=443 protocol=tcp
:: echo 46.43.34.31 the.earth.li >> %WINDIR%\System32\Drivers\Etc\Hosts
:: start "" https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe
:: PAUSE
:: Temporarily disabled
::route delete 0.0.0.0
goto end


:2008ad
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /t REG_DWORD /d 50243 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /t REG_DWORD /d 50244 /f
REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /t REG_DWORD /d 50245 /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *"
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "This computer system/network is the property of Team.Com. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A TEAM.COM OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE."


::Temp web out
netsh advfirewall firewall add rule name="Web Out Temp" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp

::File and Print Sharing
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=yes remoteip=%Ecomm%,%WebMail%

:: LDAP 389
netsh advfirewall firewall add rule name="A - LDAP IN TCP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%DNSNTP%,%WebMail%,%WebApps%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="A - LDAP IN UDP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%DNSNTP%,%WebMail%,%WebApps%,%PAMI% protocol=udp
:: netsh advfirewall firewall add rule name="LDAP Out UDP" dir=out action=allow enable=yes profile=any remoteport=389 protocol=udp
:: netsh advfirewall firewall add rule name="LDAP Out TCP" dir=out action=allow enable=yes profile=any remoteport=389 protocol=tcp
:: netsh advfirewall firewall add rule name="LDAP Out UDP" dir=out action=allow enable=yes profile=any remoteport=389 protocol=udp

:: LDAP 636
netsh advfirewall firewall add rule name="A - LDAPS IN TCP" dir=in action=allow enable=636 profile=any localport=636 remoteip=%EComm%,%DNSNTP%,%WebMail%,%WebApps%,%ADNDS%,%PAMI% protocol=tcp
:: netsh advfirewall firewall add rule name="LDAPS Out TCP" dir=out action=allow enable=yes profile=any remoteport=636 protocol=tcp

:: LDAP 3268
netsh advfirewall firewall add rule name="A - LDAP GC IN TCP" dir=in action=allow enable=yes profile=any localport=3268 remoteip=%EComm%,%DNSNTP%,%WebMail%,%WebApps%,%ADNDS%,%PAMI% protocol=tcp

:: LDAP 3269
netsh advfirewall firewall add rule name="A - LDAP GC SSL IN TCP" dir=in action=allow enable=yes profile=any localport=3269 remoteip=%EComm%,%DNSNTP%,%WebMail%,%WebApps%,%ADNDS%,%PAMI% protocol=tcp

:: KERBEROS 88
netsh advfirewall firewall add rule name="A - Kerberos In UDP from Internal" dir=in action=allow enable=yes profile=any localport=88 remoteip=%EComm%,%DNSNTP%,%WebMail%,%WebApps%,%ADNDS%,%PAMI% protocol=udp
netsh advfirewall firewall add rule name="A - Kerberos In TCP from Internal" dir=in action=allow enable=yes profile=any localport=88 remoteip=%EComm%,%DNSNTP%,%WebMail%,%WebApps%,%ADNDS%,%PAMI% protocol=tcp
netsh advfirewall firewall set rule group="Kerberos Key Distribution Center (TCP-In)" new enable=yes
netsh advfirewall firewall set rule group="Kerberos Key Distribution Center (UDP-In)" new enable=yes
::Beta
netsh advfirewall firewall add rule name="B - LDAP IN TCP" dir=in action=allow enable=no profile=any localport=389 remoteip=%FTP03%,%WebApps%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="B - LDAP IN UDP" dir=in action=allow enable=no profile=any localport=389 remoteip=%FTP03%,%WebApps%,%ADDNS%,%PAMI% protocol=udp
netsh advfirewall firewall add rule name="B - LDAPS IN TCP" dir=in action=allow enable=yes profile=any localport=636 remoteip=%FTP03%,%WebApps%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="B - LDAP GC IN TCP" dir=in action=allow enable=yes profile=any localport=3268 remoteip=%FTP03%,%WebApps%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="B - LDAP GC SSL IN TCP" dir=in action=allow enable=yes profile=any localport=3269 remoteip=%FTP03%,%WebApps%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="B - Kerberos In TCP" dir=in action=allow enable=no profile=any localport=88 remoteip=%FTP03%,%WebApps%,%ADDNS%,%PAMI% protocol=tcp

::Charlie
netsh advfirewall firewall add rule name="C - LDAP IN TCP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - LDAP IN UDP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%Ecomm%,%WebMail% protocol=udp
netsh advfirewall firewall add rule name="C - LDAPS IN TCP" dir=in action=allow enable=yes profile=any localport=636 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - LDAP GC IN TCP" dir=in action=allow enable=yes profile=any localport=3268 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - LDAP GC SSL IN TCP" dir=in action=allow enable=yes profile=any localport=3269 remoteip=%Ecomm%,%WebMail% protocol=tcp
netsh advfirewall firewall add rule name="C - Kerberos In TCP" dir=in action=allow enable=yes profile=any localport=88 remoteip=%Ecomm%,%WebMail% protocol=tcp

:: DNS 53
netsh advfirewall firewall add rule name="DNS Out UDP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=udp
netsh advfirewall firewall add rule name="DNS Out TCP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=tcp
:: netsh advfirewall firewall add rule name="DNS In TCP" dir=in action=allow enable=yes profile=any localport=53 remoteip=%FTP03%,%WebMail%,%DNSNTP%,%ADDNS%,%WebApps%,%EComm% protocol=tcp
netsh advfirewall firewall add rule name="DNS In UDP from Internal" dir=in action=allow enable=yes profile=any localport=53  protocol=udp remoteip=%FTP03%,%WebMail%,%WebApps%,%EComm%,%DNSNTP%,%ADDNS%,%PAMI%
netsh advfirewall firewall add rule name="DNS In UDP from ANY" dir=in action=allow enable=no profile=any localport=53  protocol=udp

:: SMB AUTH 445
netsh advfirewall firewall add rule name="PORT 445 SMB In" dir=in action=allow enable=no profile=any localport=445 protocol=tcp remoteip=%FTP03%,%WebApps%
:: BIND 953
netsh advfirewall firewall add rule name="BIND In From Ubuntu" dir=in action=allow enable=no profile=any localport=953 remoteip=%DNSNTP% protocol=tcp
netsh advfirewall firewall add rule name="BIND Out To Ubuntu" dir=out action=allow enable=no profile=any remoteport=953 remoteip=%DNSNTP% protocol=tcp

:: Replication
netsh advfirewall firewall add rule name="MSRPC IN from windows" dir=in action=allow enable=yes profile=any localport=135 remoteip=%WebApps%,%Webmail%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="Static RPC IN from windows" dir=in action=allow enable=yes profile=any localport=50243,50244,50245 remoteip=%FTP03%,%WebApps%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="Dynamic RPC IN from windows" dir=in action=allow enable=no profile=any localport=135 remoteip=%FTP03%,%WebApps%,%PAMI% protocol=tcp

:: SSH to 2012
netsh advfirewall firewall add rule name="SSH TO 2012" dir=out action=allow enable=yes profile=any remoteport=22 remoteip=%WebApps% protocol=tcp
::Splunk out to 2012
netsh advfirewall firewall add rule name="Splunk Out" dir=out action=allow enable=yes profile=any remoteip=%WebMail% remoteport=,8000,8089,9997 protocol=tcp

::Add PA Groups
dsadd group cn=Marketing,cn=users,dc=team,dc=local -secgrp yes -samid marketing
dsadd group cn=Sales,cn=users,dc=team,dc=local -secgrp yes -samid marketing
::dsadd group cn=marketing,cn=user,dc=corp,dc=com
::dsadd group cn=sales,cn=user,dc=corp,dc=com
dsadd user "cn=James Doohan,cn=Users,dc=team,dc=local" -samid JDoohan -fn James -ln Doohan -pwd *
net localgroup Administrators JDoogan /add
net localgroup Distributed COM Users JDoogan /add
net localgroup Event Log Readers JDoogan /add
net localgroup Server Operators JDoogan /add
dsadd user "cn=Michael Dorn,cn=Users,dc=team dc=local" -samid MDorn -fn Michael -ln Dorn  -pwd *
net localgroup Marketing MDorn /Add
net localgroup Sales MDorn /Add

::ECHO on
net start w32time
w32tm /config /manualpeerlist:"%DNSNTP%" /syncfromflags:manual /reliable:yes /update
w32tm /resync

net stop w32time && net start w32time

::Change time to Eastern
TZUTIL /s "Eastern Standard Time"
::@ECHO off


::Create Password policy
::start powershell.exe -noexit Set-ADDefaultDomainPasswordPolicy -Identity Team.local -ComplexityEnabled $true -MinPasswordLength 8 -MinPasswordAge 1 -MaxPasswordAge 30 -LockoutDuration 00:60:00 -LockoutObservationWindow 00:30:00 -LockoutThreshold 5
::start powershell.exe -noexit Get-ADDefaultDomainPasswordPolicy >> C:DomainPasswordPolicy.txt


powershell.exe -noexit Import-Module ServerManager $check = Get-WindowsFeature | Where-Object {$_.Name -eq "SNMP-Services"} If ($check.Installed -ne "True"){Add-WindowsFeature SNMP-Service | Out-Null} If ($check.Installed -ne "True"){ REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\SNMP\Parameters\PermittedManagers" /v 1 /t REG_SZ /d 172.20.241.9 /f |Out-Null REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" /v inthecorn /t REG_DWORD /d 8 /f |Out-Null } Else {Write-Host "Error: SNMP Services not Installed!"}



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


goto Config_NTP
:: SQL Specific




:2012web
netsh advfirewall firewall add rule name="PA RULE" dir=out action=allow enable=yes profile=any remoteip=%PAMI% remoteport=443 protocol=tcp
netsh advfirewall firewall add rule name="PA RULE" dir=out action=allow enable=no profile=any remoteip=%PAMI% remoteport=80 protocol=tcp
netsh advfirewall firewall add rule name="Web Out" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall add rule name="DNS Out" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%ADDNS% protocol=udp
netsh advfirewall firewall add rule name="LDAP OUT UDP" dir=out action=allow enable=yes profile=any remoteport=389 remoteip=%ADDNS% protocol=udp
netsh advfirewall firewall add rule name="LDAP OUT TCP" dir=out action=allow enable=yes profile=any remoteport=389 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="SHARE Out" dir=out action=allow enable=no profile=any remoteport=445 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="msrpc" dir=out action=allow enable=yes profile=any remoteport=135 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Static rpc out" dir=out action=allow enable=yes profile=any remoteport=50243,50244,50245 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Kerberos out" dir=out action=allow enable=yes profile=any remoteport=88 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="SSH FROM 2008" dir=in action=allow enable=no profile=any localport=22 remoteip=%ADDNS% protocol=tcp
netsh advfirewall firewall add rule name="Splunk IN" dir=in action=allow enable=yes profile=any localport=8000,8089,9997 remoteip=%EComm%,%DNSNTP%,%WebMail%,%WebApps%,%ADNDS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%WebMail% remoteport=8000,8089,9997 protocol=tcp
netsh advfirewall firewall add rule name="PAN 515 IN" dir=in action=allow enable=yes profile any remoteip=%PAMI% remoteport=514 protocol=udp
netsh advfirewall firewall add rule name="OSSEC IN for Splunk" dir=in action=allow enable=yes profile any remoteip=%DNSNTP% remoteport=515 protocol=udp
netsh advfirewall firewall add rule name="SSH FROM 2008" dir=in action=allow enable=no profile=any localport=22 remoteip=%DNSNTP% protocol=tcp


:: Logon Banner 2012
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of Team.Com. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A TEAM.COM OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f


::Windows 2012 NTP  Config and Return

net start w32time
w32tm /config /manualpeerlist:"%DNSNTP%" /syncfromflags:manual /reliable:yes /update
w32tm /resync

net stop w32time && net start w32time
TZUTIL /s "Eastern Standard Time"



start powershell {invoke-expression 'cmd /c w32tm /query /peers'; Read-Host}


::SNMP_CONFIG
powershell.exe -EncodedCommand IwBQAG8AdwBlAHIAcwBoAGUAbABsACAAUwBjAHIAaQBwAHQAIAB0AG8AIABJAG4AcwB0AGEAbABsACAAJgAgAEMAbwBuAGYAaQBnACAAUwBOAE0AUAAgAFMAZQByAHYAaQBjAGUACgAjAEkAbQBwAG8AcgB0ACAAUwBlAHIAdgBlAHIAIABNAGEAbgBhAGcAZQByACAATQBvAGQAdQBsAGUACgBJAG0AcABvAHIAdAAtAE0AbwBkAHUAbABlACAAUwBlAHIAdgBlAHIATQBhAG4AYQBnAGUAcgAKACMAUwBlAHIAdgBpAGMAZQAgAEMAaABlAGMAawAKACQAYwBoAGUAYwBrACAAPQAgAEcAZQB0AC0AVwBpAG4AZABvAHcAcwBGAGUAYQB0AHUAcgBlACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBOAGEAbQBlACAALQBlAHEAIAAiAFMATgBNAFAALQBTAGUAcgB2AGkAYwBlAHMAIgB9AAoASQBmACAAKAAkAGMAaABlAGMAawAuAEkAbgBzAHQAYQBsAGwAZQBkACAALQBuAGUAIAAiAFQAcgB1AGUAIgApAHsACgAjAEkAbgBzAHQAYQBsAGwALwBFAG4AYQBiAGwAZQAgAFMATgBNAFAAIABTAGUAcgB2AGkAYwBlAHMACgBBAGQAZAAtAFcAaQBuAGQAbwB3AHMARgBlAGEAdAB1AHIAZQAgAFMATgBNAFAALQBTAGUAcgB2AGkAYwBlACAAfAAgAE8AdQB0AC0ATgB1AGwAbAAKAH0ACgAjACMAIABWAGUAcgBpAGYAeQAgAFcAaQBuAGQAbwB3AHMAIABTAGUAcgB2AGkAYwBlAHMAIABhAHIAZQAgAEUAbgBhAGIAbABlAGQAIAAKAEkAZgAgACgAJABjAGgAZQBjAGsALgBJAG4AcwB0AGEAbABsAGUAZAAgAC0AbgBlACAAIgBUAHIAdQBlACIAKQB7AAoAIwBTAGUAdAAgAFMATgBNAFAAIABQAGUAcgBtAGkAdAB0AGUAZAAgAE0AYQBuAGEAZwBlAHIAcwAoAHMAKQAgACoAKgAgAEUAeABpAHMAdABpAG4AZwAgAHMAaABpAHQAIABpAHMAIABhAGIAbwB1AHQAIAB0AG8AIABnAG8AKgAqAAoAUgBFAEcAIABBAEQARAAgACIASABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAHkAcwB0AGUAbQBcAEMAdQByAHIAZQBuAHQAQwBvAG4AdAByAG8AbABTAGUAdABcAFMAZQByAHYAaQBjAGUAcwBcAFMATgBNAFAAXABQAGEAcgBhAG0AZQB0AGUAcgBzAFwAUABlAHIAbQBpAHQAdABlAGQATQBhAG4AYQBnAGUAcgBzACIAIAAvAHYAIAAxACAALwB0ACAAUgBFAEcAXwBTAFoAIAAvAGQAIAAxADcAMgAuADIAMAAuADIANAAyAC4AMQA3ACAALwBmACAAfABPAHUAdAAtAE4AdQBsAGwACgAjAFMAZQB0ACAAUwBOAE0AUAAgAEMAbwBtAG0AdQBuAGkAdAB5ACAAUwB0AHIAaQBuAGcAcwAKAFIARQBHACAAQQBEAEQAIAAiAEgASwBFAFkAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAFwAUwB5AHMAdABlAG0AXABDAHUAcgByAGUAbgB0AEMAbwBuAHQAcgBvAGwAUwBlAHQAXABTAGUAcgB2AGkAYwBlAHMAXABTAE4ATQBQAFwAUABhAHIAYQBtAGUAdABlAHIAcwBcAFYAYQBsAGkAZABDAG8AbQBtAHUAbgBpAHQAaQBlAHMAIgAgAC8AdgAgAGMAaABhAG4AZwBlAG0AZQAgAC8AdAAgAFIARQBHAF8ARABXAE8AUgBEACAALwBkACAAOAAgAC8AZgAgAHwATwB1AHQALQBOAHUAbABsAAoAfQAKAAoARQBsAHMAZQAgAHsAVwByAGkAdABlAC0ASABvAHMAdAAgACIARQByAHIAbwByADoAIABTAE4ATQBQACAAUwBlAHIAdgBpAGMAZQBzACAAbgBvAHQAIABJAG4AcwB0AGEAbABsAGUAZAAhACIAfQA=


::goto Splunk_Install

::Splunk_Install

::msiexec.exe /i splunk-<...>-x64-release.msi




GOTO Config_NTP

:Config_NTP
@ECHO on
net start w32time
w32tm /config /manualpeerlist:"%DNSNTP%" /syncfromflags:manual /reliable:yes /update
w32tm /resync

net stop w32time && net start w32time
@ECHO off


start cmd /k echo w32tm /query /peers




goto export_configs

:export_configs
:: Export registry
reg export HKLM %ccdcpath%\Regback\hlkm.reg
reg export HKCU %ccdcpath%\Regback\hkcu.reg
reg export HKCR %ccdcpath%\Regback\hlcr.reg
reg export HKU %ccdcpath%\Regback\hlku.reg
reg export HKCC %ccdcpath%\Regback\hlcc.reg
goto end

:end
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
EXIT /B 1
