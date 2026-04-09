Start-Transcript C:\WinhardLog.txt
Set-ExecutionPolicy Unrestricted -force

net user Guest /active:no




Write-Host "Starting Function: Bulk_Firewall" -ForegroundColor Cyan
Start-Sleep -s 1

Invoke-WebRequest "http://raw.githubusercontent.com/bwcybersec/ccdc/main/windown.ps1" -OutFile "C:\windown.ps1"
            # Disable ALL Existing Firewall Rules
netsh advfirewall firewall set rule name=all new enable=no
            # Pings
netsh advfirewall firewall add rule name="LOCK-Allow Pings Out!" new dir=in  action=allow enable=yes protocol=icmpv4:8,any profile=any  
netsh advfirewall firewall add rule name="LOCK-Allow Pings In!"  new dir=out action=allow enable=yes protocol=icmpv4:8,any profile=any  
              
            # Internet Access
netsh advfirewall firewall add rule name="LOCK-Web Regional"        new dir=out action=allow enable=yes protocol=tcp profile=any remoteip=any remoteport=80,443  
netsh advfirewall firewall add rule name="LOCK-DNS Regional"        new dir=out action=allow enable=yes protocol=udp profile=any remoteport=53  

            # Intranet Access
netsh advfirewall firewall add rule name="LOCK-Web Regional (INT)"  new dir=out action=allow enable=yes protocol=tcp profile=any remoteport=80,443 remoteip= localsubnet  
netsh advfirewall firewall add rule name="LOCK-DNS Regional (INT)"  new dir=out action=allow enable=yes protocol=udp profile=any remoteport=53 remoteip= localsubnet
netsh advfirewall firewall add rule name="LOCK-NTP Allow (INT)"  new dir=out action=allow enable=yes protocol=udp profile=any remoteport=123 remoteip= localsubnet
            # SNMP Access
netsh advfirewall firewall add rule name="LOCK-SNMP Regional (INT)"  new dir=in action=allow enable=no protocol=udp profile=any localport=161 remoteip= localsubnet
            # Disable IPv6 Teredo Tunneling
netsh interface teredo set state disabled | Out-Null
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled | Out-Null
netsh interface ipv6 isatap set state state=disabled  | Out-Null
            # Block public profile
netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
Write-Host "Function: Bulk_Firewall   -   Complete" -ForegroundColor Green



# Disabling IPv6
$Adapters = Get-NetAdapterBinding | Where-Object ComponentID -EQ 'ms_tcpip6' | Select-Object Name
ForEach ($adapter in $Adapters  ) { 
    Disable-NetAdapterBinding -Name $Adapters.Name -ComponentID ms_tcpip6}


            # Disable Possible Backdoors

REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" 
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "systray.exe" /f 
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" 

REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger 
REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger /t REG_SZ /d "systray.exe" /f 
REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger 

REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden 
REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden 
    #Sticky keys
Write-Host "Taking over sticky keys"
Set-Location C:\Windows\System32
takeown /f sethc.exe | Out-Null
$Acl = Get-Acl sethc.exe
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:username", "FullControl", "Allow")
$Acl.SetAccessRule($Ar)
Set-Acl sethc.exe $Acl
takeown /f systray.exe | Out-Null
$Acl2 = Get-Acl systray.exe
$ar2 = New-Object system.security.AccessControl.FileSystemAccessRule("$env:username", "FullControl","Allow")
$Acl2.SetAccessRule($ar2)
Set-Acl systray.exe -AclObject $Acl2
move-item sethc.exe sethc.old.exe -Force | Out-Null
copy-item systray.exe sethc.exe | Out-Null
Write-Host "Function: Damage_Reversal   -   Complete" -ForegroundColor Green




Write-Host "------Server Options------"
Write-Host "[1] - pop3"
Write-Host "[2] - SMTP"
Write-Host "[3] - FTP"
Write-Host "[4] - DNS"
Write-Host "[5] - Web server"
Write-Host "[6] - MySQL"
Write-Host "[7] - AD User"
Write-Host "[8] - AD Domain Controller"

$ports = Read-Host "Select any of the above services that this host must allow in, if any? (type the corresponding number[s])"

switch -Wildcard ($ports) {
    "*1*" {netsh advfirewall firewall add rule name="LOCK-POP3"  new dir=in action=allow enable=yes protocol=tcp profile=any localport=110  | Out-Null}
    "*2*" {netsh advfirewall firewall add rule name="LOCK-SMTP"  new dir=in action=allow enable=yes protocol=tcp profile=any localport=25  | Out-Null}
    "*3*" {netsh advfirewall firewall add rule name="LOCK-FTP"  new dir=in action=allow enable=yes protocol=tcp profile=any localport=20,21  | Out-Null}
    "*4*" {netsh advfirewall firewall add rule name="LOCK-DNS"  new dir=in action=allow enable=yes protocol=udp profile=any localport=53  | Out-Null}
    "*5*" {netsh advfirewall firewall add rule name="LOCK-Webserver"  new dir=in action=allow enable=yes protocol=tcp profile=any localport=80,443  | Out-Null}
    "*6*" {netsh advfirewall firewall add rule name="LOCK-MySQL"  new dir=in action=allow enable=yes protocol=tcp profile=any localport=3306  | Out-Null} 
    "*7*" {netsh advfirewall firewall add rule name="LOCK-AD TCP" dir=out action=allow profile=any protocol=TCP remoteip=localsubnet remoteport=53,88,135,389,445,3268,49152-65535
           netsh advfirewall firewall add rule name="LOCK-AD UDP" dir=out action=allow profile=any protocol=UDP remoteip=localsubnet remoteport=53,88,123,389}  
    "*8*" {netsh advfirewall firewall add rule name="LOCK-DomainContoller TCP In" dir=in action=allow profile=any protocol=TCP localport=53,88,135,389,445,3268,49152-65535 remoteip=localsubnet
           netsh advfirewall firewall add rule name="LOCK-DomainController UDP In" dir=in action=allow profile=any protocol=UDP localport=53,88,123,389 remoteip=localsubnet}     
}
    #Legal Notice Registry Key
REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /f 
REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /f 
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f | Out-Null
REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of The Company. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Companys Acceptable Use of Information Technology Resources Policy ('AUP'). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Companyâ€™s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A COMPANY OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f 
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinLogon" /v legalnoticecaption 
REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinLogon" /v legalnoticetext 

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Noprofile", "-File", "C:\windown.ps1"
Start-Sleep -Seconds 4
Stop-Transcript
Set-ExecutionPolicy Restricted -force