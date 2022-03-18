@Echo On



:: ########## Options ##########
set ccdcpath="c:\ccdc"
:: set path="%systemroot%\system32\LogFiles\Firewall"
mode con:cols=140 lines=10000

:: ########## Check if Elevated ##########

echo Administrative permissions required. Detecting permissions.....
ECHO.
ECHO.

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



:Set_IPS
set  Docker=172.20.240.15
set  DockerServer=172.20.240.10
set  DNSNTP=172.20.240.20

set  Splunk=172.20.241.20
set  EComm=172.20.241.30
set  WebMail=172.20.241.40

set  WebApps=172.20.242.10
set  UbuntuWorkstation=172.20.242.100
set  ADDNS=172.20.242.200

set  Windows10=172.31.10.5

set  PAMI=172.20.242.150

Echo Docker IP is now %Docker%
Echo Docker Server IP is now %DockerServer%
Echo DNS/NTP IP is now %DNSNTP%

Echo WebApps IP is now %WebApps%
Echo AD/DNS box IP is now %ADDNS%
Echo Ubutu Workstation IP is now %UbuntuWorkstation%

Echo Splunk IP is now %Splunk%
Echo E-Commerce Ip is now %EComm%
Echo WebMail IP is now %WebMail%

Echo Windows 10 IP is now %Windows10%

Echo PAN Management Interface IP is now %PAMI%


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
netsh advfirewall firewall add rule name="WinSCP/SSH Out" dir=out action=allow enable=no profile=any remoteip=%WebMail%,%WebApps%,%DNSNTP%,%EComm%,%ADDNS% remoteport=22 protocol=tcp
::netsh advfirewall firewall add rule name="Web Share OUT" dir=out action=allow enable=no profile=any remoteip=%WebApps% remoteport=80 protocol=tcp


::Temp web out
netsh advfirewall firewall add rule name="Web Out Temp" dir=out action=allow enable=yes profile=any remoteport=80,443 protocol=tcp


:: Get sysinternals
netsh advfirewall firewall add rule name="Temp Web to sysinternals" dir=in enable=yes action=allow profile=any remoteip=72.21.81.200 remoteport=443 protocol=TCP
echo 72.21.81.200 download.sysinternals.com >> %systemroot%\system32\drivers\etc\hosts
bitsadmin.exe /transfer "JobName" https://download.sysinternals.com/files/SysinternalsSuite.zip "%ccdcpath%\sysinternals.zip"
netsh advfirewall firewall set rule name="Temp Web to sysinternals" new enable=no


: Setup Login Banners!!

:2012 / 2016 / Win10
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *"
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "This computer system/network is the property of ALLSAFE.COM. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company's Acceptable Use of Information Technology Resources Policy (AUP). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company's AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A ALLSAFE.COM OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE."



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



::File and Print Sharing
netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" new enable=yes remoteip=%Ecomm%,%WebMail%

:: LDAP 389
netsh advfirewall firewall add rule name="A - LDAP IN TCP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall add rule name="A - LDAP IN UDP" dir=in action=allow enable=yes profile=any localport=389 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=udp

:: LDAP 636
netsh advfirewall firewall add rule name="A - LDAPS IN TCP" dir=in action=allow enable=636 profile=any localport=636 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=tcp

:: LDAP 3268
netsh advfirewall firewall add rule name="A - LDAP GC IN TCP" dir=in action=allow enable=yes profile=any localport=3268 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=tcp

:: LDAP 3269
netsh advfirewall firewall add rule name="A - LDAP GC SSL IN TCP" dir=in action=allow enable=yes profile=any localport=3269 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=tcp

:: KERBEROS 88
netsh advfirewall firewall add rule name="A - Kerberos In UDP from Internal" dir=in action=allow enable=yes profile=any localport=88 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=udp
netsh advfirewall firewall add rule name="A - Kerberos In TCP from Internal" dir=in action=allow enable=yes profile=any localport=88 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=tcp
netsh advfirewall firewall set rule group="Kerberos Key Distribution Center (TCP-In)" new enable=yes
netsh advfirewall firewall set rule group="Kerberos Key Distribution Center (UDP-In)" new enable=yes

:: DNS 53
netsh advfirewall firewall add rule name="DNS Out UDP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=udp
netsh advfirewall firewall add rule name="DNS Out UDP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=%DNSNTP% protocol=tcp
netsh advfirewall firewall add rule name="DNS In UDP from Internal" dir=in action=allow enable=yes profile=any localport=53 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=udp
netsh advfirewall firewall add rule name="DNS In UDP from Internal" dir=in action=allow enable=yes profile=any localport=53 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=tcp
::netsh advfirewall firewall add rule name="DNS In UDP from ANY" dir=in action=allow enable=no profile=any localport=53  protocol=udp

:: SMB AUTH 445
netsh advfirewall firewall add rule name="PORT 445 SMB In" dir=in action=allow enable=no profile=any localport=445 protocol=tcp remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI%
:: BIND 953
netsh advfirewall firewall add rule name="BIND In From Ubuntu" dir=in action=allow enable=no profile=any localport=953 remoteip=%DNSNTP% protocol=tcp
netsh advfirewall firewall add rule name="BIND Out To Ubuntu" dir=out action=allow enable=no profile=any remoteport=953 remoteip=%DNSNTP% protocol=tcp


:: SSH 
netsh advfirewall firewall add rule name="SSH IN" dir=out action=allow enable=yes profile=any remoteport=22 remoteip=%EComm%,%WebMail%,%DockerServer%,%Docker%,%ADDNS%,%PAMI% protocol=tcp
::Splunk 
netsh advfirewall firewall add rule name="Splunk Out" dir=out action=allow enable=yes profile=any remoteip=%Splunk% remoteport=8000,8089,9997 protocol=tcp


::Add PA Groups
::dsadd group cn=Marketing,cn=users,dc=team,dc=local -secgrp yes -samid marketing
::dsadd group cn=Sales,cn=users,dc=team,dc=local -secgrp yes -samid marketing
::dsadd group cn=marketing,cn=user,dc=corp,dc=com
::dsadd group cn=sales,cn=user,dc=corp,dc=com
::dsadd user "cn=James Doohan,cn=Users,dc=team,dc=local" -samid JDoohan -fn James -ln Doohan -pwd *
::net localgroup Administrators JDoogan /add
::net localgroup Distributed COM Users JDoogan /add
::net localgroup Event Log Readers JDoogan /add
::net localgroup Server Operators JDoogan /add
::dsadd user "cn=Michael Dorn,cn=Users,dc=team dc=local" -samid MDorn -fn Michael -ln Dorn  -pwd *
::net localgroup Marketing MDorn /Add
::net localgroup Sales MDorn /Add


::Change time to Eastern
TZUTIL /s "Eastern Standard Time"
::@ECHO off


::Create Password policy
::start powershell.exe -noexit Set-ADDefaultDomainPasswordPolicy -Identity Team.local -ComplexityEnabled $true -MinPasswordLength 8 -MinPasswordAge 1 -MaxPasswordAge 30 -LockoutDuration 00:60:00 -LockoutObservationWindow 00:30:00 -LockoutThreshold 5
::start powershell.exe -noexit Get-ADDefaultDomainPasswordPolicy >> C:DomainPasswordPolicy.txt

powershell.exe -noexit Import-Module ServerManager $check = Get-WindowsFeature | Where-Object {$_.Name -eq "SNMP-Services"} If ($check.Installed -ne "True"){Add-WindowsFeature SNMP-Service | Out-Null} If ($check.Installed -ne "True"){ REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\SNMP\Parameters\PermittedManagers" /v 1 /t REG_SZ /d 172.20.241.9 /f |Out-Null REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" /v inthecorn /t REG_DWORD /d 8 /f |Out-Null } Else {Write-Host "Error: SNMP Services not Installed!"}


:: LDAP STUFF
::netsh advfirewall firewall add rule name="LDAP OUT UDP" dir=out action=allow enable=yes profile=any remoteport=389 remoteip=%ADDNS% protocol=udp
::netsh advfirewall firewall add rule name="LDAP OUT TCP" dir=out action=allow enable=yes profile=any remoteport=389 remoteip=%ADDNS% protocol=tcp
::netsh advfirewall firewall add rule name="SHARE Out" dir=out action=allow enable=yes profile=any remoteport=445 remoteip=%ADDNS% protocol=tcp
::netsh advfirewall firewall add rule name="msrpc" dir=out action=allow enable=yes profile=any remoteport=135 remoteip=%ADDNS% protocol=tcp
::netsh advfirewall firewall add rule name="Static rpc out" dir=out action=allow enable=yes profile=any remoteport=50243,50244,50245 remoteip=%ADDNS% protocol=tcp
::netsh advfirewall firewall add rule name="Kerberos out" dir=out action=allow enable=yes profile=any remoteport=88 remoteip=%ADDNS% protocol=tcp
::netsh advfirewall firewall add rule name="Splunk OUT" dir=out action=allow enable=yes profile=any remoteip=%WebMail% remoteport=,8000,8089,9997 protocol=tcp


:Config_NTP
@ECHO on
net start w32time
w32tm /config /manualpeerlist:"%DNSNTP%" /syncfromflags:manual /reliable:yes /update
w32tm /resync

net stop w32time && net start w32time
@ECHO off


start cmd /k echo w32tm /query /peers


:export_configs
:: Export registry
mkdir %ccdcpath%\Regback
reg export HKLM %ccdcpath%\Regback\hlkm.reg
reg export HKCU %ccdcpath%\Regback\hkcu.reg
reg export HKCR %ccdcpath%\Regback\hlcr.reg
reg export HKU %ccdcpath%\Regback\hlku.reg
reg export HKCC %ccdcpath%\Regback\hlcc.reg


ECHO.
ECHO.
ECHO.
ECHO.
ECHO.
ECHO.
ECHO Script completed successfully!
