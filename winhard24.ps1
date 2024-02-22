# BW-Winhard
If (!(test-path C:\ccdc)){
    New-Item -Path $path -ItemType Directory -erroraction SilentlyContinue  | Out-Null
    Write-Host ""
    Start-Sleep -s 1
}
Start-Transcript C:\ccdc\WinhardLog.txt
Set-ExecutionPolicy Unrestricted -force
                                        ############## Function Row ##############

Function Continue_ {
    Write-Host -NoNewLine '----Press any key to continue----' -ForegroundColor Cyan; 
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    Start-Sleep -s 1
}

Function CCDC_Directories {
    cls
    Write-Host "Starting Function: CCDC_Directories" -ForegroundColor Cyan
    Start-Sleep -s 1
    Do{
        $global:ccdcpath = "c:\ccdc"
        $global:threatpath = "$ccdcpath\ThreatHunting"
        $global:configpath = "$ccdcpath\Config"
        $global:regbackpath = "$ccdcpath\Regback"
        $global:proofpath = "$ccdcpath\Proof"

        $paths = @($ccdcpath,$threatpath,$configpath,$regbackpath,$proofpath)
        ForEach ($path in $paths){
            Write-Host "Creating Directory: $path" -ForegroundColor Cyan
            If (!(test-path $path)){
                New-Item -Path $path -ItemType Directory -erroraction SilentlyContinue  | Out-Null
                Write-Host ""
                Start-Sleep -s 1
            }
        }
        $global:mambo = 0
        cls
        Write-Host "Testing File Structure..." -ForegroundColor Cyan
        ForEach ($path in $paths){
            If (Test-Path $path){
                #Write-Host "Found: $path" -ForegroundColor Green
                $global:mambo += 1
            }
            If (!(Test-Path $path)){
                Write-Host "MISSING: $path" -ForegroundColor Red
            }
        }
    } Until ($global:mambo -eq 5)
    Write-Host "Function: CCDC_Directories   -   Complete" -ForegroundColor Green
    Continue_
}

Function Scan_Dirs {
    cls
    Write-Host "Starting Function: Scan_Dirs" -ForegroundColor Cyan
    Start-Sleep -s 1
    Do {
        $global:scanpath = "$ccdcpath\PS-Scans"
        $global:firewallpath = "$scanpath\Firewall"
        $global:inboundpath = "$scanpath\Firewall\Inbound"
        $global:outboundpath = "$scanpath\Firewall\Outbound"
        $global:schtaskpath = "$scanpath\SchTasks"
        $global:servicepath = "$scanpath\Services"
        $global:discoverypath = "$ccdcpath\Discovery"

        $paths = @($scanpath,$firewallpath,$inboundpath,$outboundpath,$schtaskpath,$servicepath,$discoverypath)
        ForEach ($path in $paths){
            Write-Host "Creating Directory: $path" -ForegroundColor Cyan
            If (!(test-path $path)){
                New-Item -Path $path -ItemType Directory -erroraction SilentlyContinue  | Out-Null
                Write-Host ""
                Start-Sleep -s 1
            }
        }
        $global:bamba = 0
        cls
        Write-Host "Testing File Structure..." -ForegroundColor Cyan
        ForEach ($path in $paths){
            If (Test-Path $path){
                #Write-Host "Found: $path" -ForegroundColor Green
                $global:bamba += 1
            }
            If (!(Test-Path $path)){
                Write-Host "MISSING: $path" -ForegroundColor Red
            }
        }
    } Until ($global:bamba -eq 7)
    Write-Host "Function: Scan_Dirs   -   Complete" -ForegroundColor Green
    Continue_
}

Function Discovery_ {
    cls
    Write-Host "Starting Function: Discovery_" -ForegroundColor Cyan
    Start-Sleep -s 1
    Get-NetFirewallRule | Where-Object   {$_.Direction -eq "Inbound"} | Where-Object   {$_.Enabled -eq "True"} | Select-Object Name, DisplayName, Description, DisplayGroup, Profile, Action | Out-File $discoverypath\Active-Inbount-Rules.txt
    Get-NetFirewallRule | Where-Object   {$_.Direction -eq "Outbound"} | Where-Object   {$_.Enabled -eq "True"} | Select-Object Name, DisplayName, Description, DisplayGroup, Profile, Action | Out-File $discoverypath\Active-Outbount-Rules.txt
    Get-ScheduledTask | Where-Object   {$_.State -ne "Disabled"} | Select-Object Taskname , State, TaskPath | FL | Out-File $discoverypath\Active-ScheduledTasks.txt
    Write-Host "Function: Discovery_   -   Complete" -ForegroundColor Green
    Continue_
}

Function Set_Internal_IPs {
    cls
    Write-Host "Starting Function: Set_Internal_IPs" -ForegroundColor Cyan
    Start-Sleep -s 1
    $global:Docker = "172.20.240.10"
    $global:DNSNTP = "172.20.240.20"
    $global:Ubuntu18Web = "172.20.242.10"
    $global:UbuntuWrk = "172.20.242.100"
    $global:ADDNS = "172.20.242.200"
    $global:Splunk = "172.20.241.20"
    $global:EComm = "172.20.241.30"
    $global:WebMail = "172.20.241.40"
    $global:Internal = @($Docker,$DNSNTP,$Ubuntu18Web,$UbuntuWrk,$ADDNS,$Splunk,$EComm,$WebMail)
    cls
    Write-Host "----IPs set for Internal config:----" -ForegroundColor Green
    Write-host "-----------------------------"
    Write-Host "Docker: $docker"
    Write-Host "DNS-NTP: $DNSNTP"
    Write-Host "Ubuntu-18-Web: $Ubuntu18Web"
    Write-Host "Ubuntu-Wrk: $UbuntuWrk"
    Write-Host "PA MI: $PAMI"
    Write-Host "AD-DNS: $ADDNS"
    Write-Host "Splunk: $Splunk"
    Write-Host "E-Commerce: $Ecomm"
    Write-Host "WebMail: $WebMail"
    Write-Host "-----------------------------"
    Write-Host ""
    Write-Host "Function: Set_Internal_IPs   -   Complete" -ForegroundColor Green
    Continue_
}

Function Set_External_IPs {
    cls
    Write-Host "Starting Function: Set_External_IPs" -ForegroundColor Cyan
    Start-Sleep -s 1
    $global:Docker ="172.25.$Team.97"
    $global:DNSNTP = "172.25.$Team.20"
    $global:Ubuntu18Web = "172.25.$Team.23"
    $global:ADDNS = "172.25.$Team.27"
    $global:UbuntuWrk = "172.25.$Team.100"
    $global:PAMI = "172.25.$Team.150"
    $global:Splunk = "172.25.$Team.9"
    $global:WebMail = "172.25.$Team.39"
    $global:EComm = "172.25.$Team.11"
    $global:Internal = @($Docker,$DNSNTP,$Ubuntu14Web,$UbuntuWrk,$PAMI,$ADDNS,$Splunk,$EComm,$WebMail)
    cls
    Write-Host "----IPs set for External config:----" -ForegroundColor Cyan
    Write-host "-----------------------------"
    Write-Host "Docker: $docker"
    Write-Host "DNS-NTP: $DNSNTP"
    Write-Host "Ubuntu-18-Web: $Ubuntu18Web"
    Write-Host "Ubuntu-Wrk: $UbuntuWrk"
    Write-Host "PA MI: $PAMI"
    Write-Host "AD-DNS: $ADDNS"
    Write-Host "Splunk: $Splunk"
    Write-Host "E-Commerce: $Ecomm"
    Write-Host "WebMail: $WebMail"
    Write-Host "-----------------------------"
    Write-Host ""
    Write-Host "Function: Set_External_IPs   -   Complete" -ForegroundColor Green
    Continue_
}

Function Splunk_Logging {
    cls
    Write-Host "Starting Function: Splunk_Logging" -ForegroundColor Cyan
    Start-Sleep -s 1
    netsh advfirewall export $ccdcpath\firewall.old  | Out-Null
    netsh advfirewall set allprofiles state on  | Out-Null
    netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound  | Out-Null
    netsh advfirewall set allprofiles settings inboundusernotification enable  | Out-Null
    netsh advfirewall set allprofiles logging filename $ccdcpath\pfirewall.log  | Out-Null
    netsh advfirewall set allprofiles logging maxfilesize 8192  | Out-Null
    netsh advfirewall set allprofiles logging droppedconnections enable  | Out-Null
    netsh advfirewall set allprofiles logging allowedconnections enable  | Out-Null
    netsh advfirewall set global statefulftp disable  | Out-Null
    netsh advfirewall set global statefulpptp disable  | Out-Null
    Write-Host "Function: SplunkLogging   -   Complete" -ForegroundColor Green
    Continue_
}

Function Bulk_Firewall {
    cls
    Write-Host "Starting Function: Bulk_Firewall" -ForegroundColor Cyan
    Start-Sleep -s 1
                # Disable ALL Existing Firewall Rules
    netsh advfirewall firewall set rule name=all new enable=no
                # Pings
    netsh advfirewall firewall add rule name="CCDC-Allow Pings Out!" new dir=in  action=allow enable=yes protocol=icmpv4:8,any profile=any  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-Allow Pings In!"  new dir=out action=allow enable=yes protocol=icmpv4:8,any profile=any  | Out-Null
                # Log OUT to Splunk - May need re configure.
    netsh advfirewall firewall add rule name="CCDC-Splunk Logs"       new dir=out action=allow enable=yes protocol=tcp profile=any remoteport=8000,8089,9997 remoteip=$Splunk  | Out-Null
                # Webshare access
    netsh advfirewall firewall add rule name="CCDC-Web Share OUT"    new dir=out action=allow enable=yes protocol=tcp profile=any remoteport=8000 remoteip=$Ubuntu14Web  | Out-Null
                # Internet Access
    netsh advfirewall firewall add rule name="CCDC-Web Regional"        new dir=out action=allow enable=yes protocol=tcp profile=any remoteip=any remoteport=80,443  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS Regional"        new dir=out action=allow enable=yes protocol=udp profile=any remoteport=53  | Out-Null
                # Intranet Access
    netsh advfirewall firewall add rule name="CCDC-Web Regional (INT)"  new dir=out action=allow enable=yes protocol=tcp profile=any remoteport=80,443 remoteip=$Internal  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS Regional (INT)"  new dir=out action=allow enable=yes protocol=udp profile=any remoteport=53 remoteip=$ADDNS | Out-Null
    netsh advfirewall firewall add rule name="CCDC-NTP Allow (INT)"  new dir=out action=allow enable=yes protocol=udp profile=any remoteport=123 remoteip=$ADDNS  | Out-Null
                # SNMP Access
    netsh advfirewall firewall add rule name="CCDC-SNMP Regional (INT)"  new dir=in action=allow enable=yes protocol=udp profile=any localport=161 remoteip=$Internal  | Out-Null
                # Disable IPv6 Teredo Tunneling
    netsh interface teredo set state disabled | Out-Null
    netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled | Out-Null
    netsh interface ipv6 isatap set state state=disabled  | Out-Null
                # Block public profile
    netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
    Write-Host "Function: Bulk_Firewall   -   Complete" -ForegroundColor Green
    Continue_
}

Function Damage_Reversal {
    cls
    Write-Host "Starting Function: Damage_Reversal" -ForegroundColor Cyan
    Start-Sleep -s 1
                # Removing all saved credentials
    Write-Host "Removing all saved credentials..." -ForegroundColor Cyan
    cmdkey /list | Where-Object   {$_ -like "*Target*"} | ForEach ($_) {cmdkey /delete $_.Substring('12')} 
                # Disable Default Accounts
    #net user Guest /active:no
                # Show Local Users
    $disUsers = Get-LocalUser | Where-Object   {$_.Name -ne $env:username}
    $totUsers = Get-LocalUser
    ForEach ($user in $disUsers){
        If ($user -ne $env:username){
            Write-Host "Account: $user - Disabled" -ForegroundColor Yellow
	    Get-LocalUser | Where-Object  {$_.Name -ne $env:username} | Disable-LocalUser
        }
    }    
    Get-LocalUser | Out-File $discoverypath\All-Local-Users.txt
    Get-LocalUser | Where-Object   {$_.Enabled -eq "True"} | Out-file $discoverypath\All-Enabled-Local-Users.txt
    Get-Content "$discoverypath\All-Local-Users.txt"
    Write-Host "Check list for suspicious accounts..." -ForegroundColor Cyan
    Write-Host "Output saved to $discoverypath\All-Local-Users.txt" -ForegroundColor Green
    Write-Host "--Screenshot--" -ForegroundColor Yellow
    Continue_
    cls
                # Disabling IPv6
    $Adapters = Get-NetAdapterBinding | Where-Object ComponentID -EQ 'ms_tcpip6' | Select-Object Name
    ForEach ($adapter in $Adapters  ) { 
    Disable-NetAdapterBinding -Name $Adapters.Name -ComponentID ms_tcpip6}
    Write-Host "IPv6 Disabled..." -ForegroundColor Yellow
                # Disable win features
    Write-Host "Disabling Windows Features" -ForegroundColor Cyan
    $features = @("TelnetServer","TelnetClient","TFTP","SMB1Protocol","SMB1Protocol-Client","SMB1Protocol-Server","SMB1Protocol-Deprecation","SmbDirect","Printing-Foundation-Features","Printing-Foundation-InternetPrinting-Client","Printing-Foundation-LPDPrintService","Printing-Foundation-LPRPortMonitor")
    ForEach ($feature in $features){
        $chk = Get-WindowsOptionalFeature -Online | Where-Object   {$_.FeatureName -like "*$feature*"} | Where-Object  {$_.State -eq "Enabled"}
        If($chk){
            Write-Host "Disabling feature: $feature" -ForegroundColor Yellow
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-File $discoverypath\DisabledFeatures.txt
        }
        If (!($chk)){
            Write-Host "$feature not found" -ForegroundColor Magenta
            Add-Content $discoverypath\MissingFeatures.txt "Feature: $feature"
        }
    }
    $enabledFeatures = (Get-WindowsOptionalFeature -Online | Where-Object  {$_.State -eq "Enabled"}).FeatureName | FT
    Get-WindowsOptionalFeature -Online | Where-Object  {$_.State -eq "Enabled"} | FT
    Write-Host "Output saved to $discoverypath\EnabledFeatures.txt" -ForegroundColor Green
    Write-Host "--Screenshot--" -ForegroundColor Yellow
    Continue_
    ForEach ($feature in $enabledFeatures){
        Add-Content $discoverypath\EnabledFeatures.txt "$feature" -force -erroraction silentlycontinue
    }
                                        # Reg edits / Get-ItemProperty
    $regProof = "$proofpath\regproof.txt"
                # Saving old reg
    reg export HKLM $regbackpath\Oldhlkm.reg
    reg export HKCU $regbackpath\Oldhkcu.reg
    reg export HKCR $regbackpath\Oldhlcr.reg
    reg export HKU $regbackpath\Oldhlku.reg
    reg export HKCC $regbackpath\Oldhlcc.reg
                # Changing Owner
    Add-Content $regProof "Changing registered owner..."
    REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner | Add-Content $regProof
    REG add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d blueteam /f
    REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner | Add-Content $regProof
                # Turning on UAC
    Add-Content $regProof "UAC:"
    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA | Add-Content $regProof
    REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f 
    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA | Add-Content $regProof

                #Disable admin autologon
    Add-Content $regProof "Disable Admin autologin:"
    REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon | Add-Content $regProof
    REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f 
    REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon | Add-Content $regProof

                # Windows Updates
    Add-Content $regProof "Disabling Windows Updates"
    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess | Add-Content $regProof
    REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f | Out-Null
    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess | Add-Content $regProof

    REG query "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess | Add-Content $regProof
    REG add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f | Out-Null
    REG query "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess  | Add-Content $regProof

    REG query "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess | Add-Content $regProof
    REG add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t Reg_DWORD /d 0 /f | Out-Null
    REG query "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess | Add-Content $regProof

    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Add-Content $regProof
    REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t Reg_DWORD /d 0 /f | Out-Null
    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Add-Content $regProof

                # Clear remote registry paths
    Add-Content $regProof "Clear Remote Registry Paths:"
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine | Add-Content $regProof
    #REG add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d $null /f | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" -Name 'Machine' -Value "" -Force
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine | Add-Content $regProof

    REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine | Add-Content $regProof
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" -Name 'Machine' -Value "" -Force | Out-Null
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine | Add-Content $regProof

                # Unhide Files
    Add-Content $regProof "Unhide Files:"
    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden | Add-Content $regProof
    REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden | Add-Content $regProof

                # Unhide System Files
    Add-Content $regProof "Unhide system files:"
    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden | Add-Content $regProof
    REG add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null
    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden | Add-Content $regProof

                # Fix Local Security Authority
    Add-Content $regProof "Restrictanonymous:"
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous | Add-Content $regProof
    REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous /t REG_DWORD /d 1 /f | Out-Null
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymous | Add-Content $regProof

                # Restrict Anonymous SAM
    Add-Content $regproof "Restrict anonymous sam:"
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam | Add-Content $regProof
    REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam /t REG_DWORD /d 1 /f | Out-Null
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v restrictanonymoussam | Add-Content $regProof

                # Change everyone includes Anonymous
    Add-Content $regProof "Change everyone includes anonymous:"
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous | Add-Content $regProof
    REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f | Out-Null
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v everyoneincludesanonymous | Add-Content $regProof

                # Turn off Local Machine Hash
    Add-Content $regProof "Turn off Local Machine Hash:"
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash | Add-Content $regProof
    REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v NoLMHash  | Add-Content $regProof

                # Change Notification Packages
    Add-Content $regProof "Change notification packages:"
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages"  | Add-Content $regProof
    REG add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages" /t REG_MULTI_SZ /d "scecli" /f | Out-Null
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "Notification Packages"  | Add-Content $regProof

                # Delete image hijack that kills task manager
    Add-Content $regProof "Re-enable task manager:"
    REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v Debugger | Add-Content $regProof
    REG delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /f /v Debugger | Out-Null
    REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v Debugger | Add-Content $regProof
    
                # Re-enable task manager
    Add-Content $regProof "Re-enable task manager 2:"
    REG query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr | Add-Content $regProof
    REG delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f | Out-Null

                # Re-enable CMD Prompt
    Add-Content $regProof "Re-enable cmd prompt:"
    REG query "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD | Add-Content $regProof
    REG delete "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /f | Out-Null

                # Enable Windows Defender
    Add-Content $regProof "Re-enable Windows Defender:"
    REG query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware | Add-Content $regProof
    REG delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f | Out-Null
                # Change setting to NOT store plaintext passwords
    Add-Content $regProof "Removing stored plaintext passwords:"
    REG query "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parametersn" /v EnablePlainTextPassword | Add-Content $regProof
    REG add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f | Out-Null
    REG query "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword | Add-Content $regProof
                # Delete use Machine ID
    Add-Content $regProof "Delete use machine id:"
    REG query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v UseMachineID | Add-Content $regProof
    REG delete "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v UseMachineID /f | Out-Null

                # Show Hidden Users in GUI
    Add-Content $regProof "Show hidden users in gui:"
    REG query "HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts" | Add-Content $regProof
    Reg delete "HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts" /f | Out-Null

                # Disable Possible Backdoors
    Add-Content $regProof "Disable possible backdoors"
    REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" | Add-Content $regProof
    REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "systray.exe" /f | Out-Null
    REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" | Add-Content $regProof

    REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger | Add-Content $regProof
    REG add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger /t REG_SZ /d "systray.exe" /f | Out-Null
    REG query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger | Add-Content $regProof

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
    move-item sethc.exe sethc.old.exe | Out-Null
    copy-item systray.exe sethc.exe | Out-Null
    Write-Host "Function: Damage_Reversal   -   Complete" -ForegroundColor Green
    Continue_
}

Function Win10 {
    cls
    Write-Host "Starting Function: Win10" -ForegroundColor Cyan
    Start-Sleep -s 1
		        # Adding route
    route add 172.25.$Team.0     mask 255.255.255.0 172.31.$Team.2     metric 1
    Start-Sleep -s 1
    Write-Host "Configuring Win10 Banner..." -ForegroundColor Cyan
    REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" /f | Out-Null
    REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v legalnoticetext /t REG_SZ /d "This computer system network is the property of $dName. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy ('AUP'). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A $dName OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." /f | Out-Null
    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinLogon" /v legalnoticecaption | Out-Null
    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinLogon" /v legalnoticetext | Out-Null
    Write-Host "Function: Win10   -   Complete" -ForegroundColor Green
    Continue_
}

Function WinServer{
    cls
    Write-Host "Starting Function: WinServer" -ForegroundColor Cyan
    Start-Sleep -s 1
    reg Add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /t REG_DWORD /d 50243 /f | Out-Null
    REG add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /t REG_DWORD /d 50244 /f | Out-Null
    REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /t REG_DWORD /d 50245 /f | Out-Null
    REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /f | Out-Null
    REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" | Out-Null
    REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /f | Out-Null 
    REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "This computer system/network is the property of $dName. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy ('AUP'). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A $dName OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." | Out-Null
    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption  | Out-Null 
    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext  | Out-Null
    REG query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize | Add-Content $regProof
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize /t REG_DWORD /d 65280 /f
    REG query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize | Add-Content $regProof
    Stop-Service Dns
    start-sleep -s 1
    Start-Service Dns
    Start-Sleep -s 1
    Write-Host "--Screenshot--" -ForegroundColor Yellow
    Continue_
    
                # Disable SMB1
    Write-Host "Disable SMB1 via Registry..." -ForegroundColor Cyan
    REG add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f | Out-Null
                #LDAP 389
    Write-Host "Create Firewall Rules for LDAP" -ForegroundColor Cyan
    netsh advfirewall firewall add rule name="CCDC-LDAP Service" dir=in action=allow enable=yes profile=any localport=389 remoteip=$EComm,$WebMail,$PAMI protocol=tcp  | Out-Null

                #LDAP 636
    Write-Host "Create Firewall Rules for LDAP" -ForegroundColor Cyan
    netsh advfirewall firewall add rule name="CCDC-LDAP Service SSL" dir=in action=allow enable=no profile=any localport=636 remoteip=$EComm,$WebMail,$PAMI protocol=tcp  | Out-Null

                # KERBEROS
    Write-Host "Create Firewall Rules for Kerberos" -ForegroundColor Cyan
    netsh advfirewall firewall add rule name="CCDC-Kerberos In UDP from Internal" dir=in action=allow enable=yes profile=any localport=88,464 remoteip=$EComm,$WebMail,$PAMI protocol=udp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-Kerberos In TCP from Internal" dir=in action=allow enable=yes profile=any localport=88,464 remoteip=$EComm,$WebMail,$PAMI protocol=tcp  | Out-Null
    netsh advfirewall firewall set rule group="CCDC-Kerberos Key Distribution Center (TCP-In)" new enable=yes  | Out-Null
    netsh advfirewall firewall set rule group="CCDC-Kerberos Key Distribution Center (UDP-In)" new enable=yes  | Out-Null

                # DNS 53
    Write-Host "Create Firewall Rules for DNS access for Internet and Intranet" -ForegroundColor Cyan
    netsh advfirewall firewall add rule name="CCDC-DNS In UDP from DNSNTP"  dir=in action=allow enable=yes profile=any remoteport=53 remoteip=$DNSNTP protocol=udp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS Out UDP to DNSNTP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=$DNSNTP protocol=udp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS In TCP from DNSNTP"  dir=in action=allow enable=yes profile=any remoteport=53 remoteip=$DNSNTP protocol=tcp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS Out TCP to DNSNTP" dir=out action=allow enable=yes profile=any remoteport=53 remoteip=$DNSNTP protocol=tcp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS In UDP from Internal" dir=in action=allow enable=yes profile=any localport=53  protocol=udp remoteip=$Internal | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS Out UDP to Internal" dir=out action=allow enable=yes profile=any localport=53  protocol=udp remoteip=$Internal | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS In UDP from Internet" dir=in action=allow enable=yes profile=any localport=53  protocol=udp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS OUT UDP to Internet" dir=out action=allow enable=yes profile=any localport=53  protocol=udp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS In TCP from Internal" dir=in action=allow enable=yes profile=any localport=53  protocol=tcp remoteip=$Internal | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS Out TCP to Internal" dir=out action=allow enable=yes profile=any localport=53  protocol=tcp remoteip=$Internal | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS In TCP from Internet" dir=in action=allow enable=yes profile=any localport=53  protocol=tcp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-DNS Out TCP to Internet" dir=out action=allow enable=yes profile=any localport=53  protocol=tcp  | Out-Null
    netsh advfirewall firewall add rule name="CCDC-NTP Allow Service"  new dir=in action=allow enable=yes protocol=udp profile=any remoteport=123 | Out-Null
    Write-Host "Making user panuser..." -ForegroundColor Cyan  
    dsadd user "cn=panuser,cn=Users,dc=allsafe,dc=com" -samid panuser -fn pa -ln nuser -pwd *
    net localgroup Administrators panuser /add           | Out-Null
    net localgroup "Distributed COM Users" panuser /add  | Out-Null
    net localgroup "Event Log Readers" panuser /add      | Out-Null
    net localgroup "Remote Desktop Users" panuser /add   | Out-Null

                # Calling Config_NTP_Server
    #Config_NTP_Server - Removed
    Continue_
}

Function Docker {
    cls
    Write-Host "Starting Function: Docker" -ForegroundColor Cyan
    Start-Sleep -s 1
                #Docker Banner
    REG delete "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /f REG_DWORD /d 50243 /f | Out-Null
    REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "TCP/IP Port" /t REG_DWORD /d 50243 /f | Out-Null

    REG delete "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /f | Out-Null 
    REG add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DCTcpipPort" /t REG_DWORD /d 50244 /f | Out-Null

    REG delete "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /f | Out-Null
    REG add "HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters" /v "RPC TCP/IP Port Assignment" /t REG_DWORD /d 50245 /f | Out-Null

    REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /f | Out-Null
    REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption /t REG_SZ /d "* * * * * * * * * * W A R N I N G * * * * * * * * * *" | Out-Null

    REG delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /f | Out-Null 
    REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext /t REG_SZ /d "This computer system/network is the property of $dName. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (“AUP”). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions as set forth in the Company’s AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF A $dName OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE." | Out-Null

    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticecaption | Out-Null 
    REG query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v legalnoticetext | Out-Null
    Write-Host "--Screenshot--" -ForegroundColor Yellow
    Continue_

                # Disable SMB1
    Write-Host "Disable SMB1 via Registry..." -ForegroundColor Cyan
    REG add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f
    Continue_
}

Function CCDC_ICACLS {
    cls
    Write-Host "Starting Function: CCDC_ICACLS" -ForegroundColor Cyan
    Start-Sleep -s 1
    Write-Host "Tighten CCDC ACL..." -ForegroundColor Cyan
    icacls $ccdcpath\* /inheritance:d 
    icacls $ccdcpath /inheritance:d 
                    # Grants permission to only cur user for ccdc dirs
    $Acl = Get-Acl $ccdcpath
    $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:username", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.SetAccessRule($Ar)
    Set-Acl $ccdcpath $Acl
    $Acl = Get-Acl $ccdcpath
    $ar2 = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","Read",,,"Allow")
    $Acl.RemoveAccessRuleAll($ar2)
    Set-Acl $ccdcpath -AclObject $Acl
    $Acl = Get-Acl $ccdcpath
    $ar3 = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.RemoveAccessRuleAll($ar3)
    Set-Acl $ccdcpath -AclObject $Acl
    icacls $ccdcpath /remove:g "Authenticated Users" 
    icacls $ccdcpath /remove:g "Users" 
    icacls $ccdcpath\* /inheritance:e
    icacls C:\ccdc\pfirewall.log /grant $env:username:F Administrators:F
    Continue_
}

Function Export_Configs {
    cls
    Write-Host "Starting Function: Export_Config" -ForegroundColor Cyan
    Start-Sleep -s 1
                # Export Hosts
    Copy-Item $env:systemRoot\system32\drivers\etc\hosts $ccdcpath\hosts
    Write-Host "This is OUR hosts file! > $env:systemRoot\system32\drivers\etc\hosts" -ForegroundColor Cyan
                # Export Users
    Get-LocalUser | Out-File $configpath\Users.txt
                # Export Groups
    Get-LocalGroup | Out-File $configpath\Groups.txt
                # Export Scheduled tasks
    get-ScheduledTask | Select-Object TaskName, State, TaskPath | FL | Out-File $threatpath\ScheduledTasks.txt
                # Export Services
    get-service | Sort | Select-Object DisplayName, Status | Out-File $threatpath\Services.txt
                # Export Session
    query user | Out-File $threatpath\UserSessions.txt
                # Export PSSession
    Get-PSSession | Out-File $threatpath\PS-Sessions.txt
                # Export registry
    reg export HKLM $regbackpath\hlkm.reg
    reg export HKCU $regbackpath\hkcu.reg
    reg export HKCR $regbackpath\hlcr.reg
    reg export HKU $regbackpath\hlku.reg
    reg export HKCC $regbackpath\hlcc.reg
    Continue_
}
                                        ############## End of Function Row ##############

                        ############## Beginning of script ##############

                # 1. Admin Check 
$curRoll = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
If (!($curRoll)){
    Write-Warning "You must be admin. Exiting..."
    Start-Sleep -s 2
    Exit
}
                # 2. Host Check
Do{
    cls
    Write-Host "------Host Options------"
    Write-Host "[1] - Win10"
    Write-Host "[2] - WinServer"
    Write-Host "[3] - Docker"
    $curhost = Read-Host "Which host are you on? (type the corresponding number)"
    If ($curhost -eq 1){
        $curhost = "Win10"
        $setExt = "True"
    }
    If ($curhost -eq 2){
        $curhost = "WinServer"
        $setInt = "True"
    }
    If ($curhost -eq 3){
        $curhost = "Docker"
        $setInt = "True"
    }
    cls
    Write-Host "Selection: $curhost" -ForegroundColor Yellow
    $hostanswer = Read-Host "Is this Information correct?  Y/N"
}  Until (($hostanswer -eq "Y") -or ($hostanswer -eq "y"))

                # 3. Team Check
If ($setExt) {
    Do{
        cls               
        $teamNum = Read-Host "Please enter your team number (1-12)"
        cls
        Write-Host "Team Number: $teamNum"  -ForegroundColor Yellow
        $teamanswer = Read-Host "Is this Information correct?  Y/N"
    }  Until (($teamanswer -eq "Y") -or ($teamanswer -eq "y"))
    $teamNum = [int]$teamNum
    $Team = $teamNum + '20'
}

                # 4. Setting CCDC directories
CCDC_Directories

Scan_Dirs

Discovery_
                # 5. Setting IPs
If ($setExt){
    Set_External_IPs
}
If ($setInt){
    Set_Internal_IPs
}

                # 6. Domain Name 
Do{
    cls               
    Write-Host "What is your domain name? Example:  DOMAIN.COM" -ForegroundColor Cyan
    $dName = Read-Host "Domain Name"
    cls
    Write-Host "Domain Name: $dName"  -ForegroundColor Yellow
    $domainanswer = Read-Host "Is this Information correct?  Y/N"
}  Until (($domainanswer -eq "Y") -or ($domainanswer -eq "y"))

                # 7. Generic firewall rules, includes Disable IPv6 Teredo tunneling. 
Bulk_Firewall

                # 8. Set splunk loggin firewall rules
Splunk_Logging

Write-Host "Starting trace..."
netsh trace start capture=YES tracefile=$ccdcpath\day1.etl | Out-Null
Continue_

                # 9. run function Damage_Reversal
Damage_Reversal

                # 10. Setup TCPDump
# Removed

                # 11. Apply Box specific rules
$curhost

                # 12. Tighten CCDC ACLs
CCDC_ICACLS

                # 13. Config_NTP_Server
# Removed

                # 14. Export
Export_Configs
Stop-Transcript
Write-Host "Process complete..." -ForegroundColor Green
Continue_
Set-ExecutionPolicy Restricted -force
#Exit 0
