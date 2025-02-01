Set-ExecutionPolicy -scope currentuser unrestricted 
New-Item -Path C:\downloads -ItemType Directory -erroraction SilentlyContinue
Set-Location c:\downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3

Write-Output "Download: weboff"
Invoke-WebRequest "https://raw.githubusercontent.com/bwcybersec/ccdc/main/weboff.cmd" -Outfile weboff.com

Write-Output "Download: webon"
Invoke-WebRequest "https://raw.githubusercontent.com/bwcybersec/ccdc/main/webon.cmd" -Outfile webon.com

Write-Output "Download: Autoruns.zip"
Invoke-WebRequest https://download.sysinternals.com/files/Autoruns.zip -Outfile Autoruns.zip
Expand-Archive .\Autoruns.zip c:\downloads -Force

Write-Output "Download: ProcessExplorer.zip"
Invoke-WebRequest https://download.sysinternals.com/files/ProcessExplorer.zip -Outfile ProcessExplorer.zip
Expand-Archive .\ProcessExplorer.zip c:\downloads -Force

Write-Output "Download and Install: Sysmon.zip"
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -Outfile Sysmon.zip
Expand-Archive .\Sysmon.zip c:\downloads -Force
#Invoke-WebRequest https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -Outfile sysmonconfig.xml
Invoke-WebREquest "https://raw.githubusercontent.com/bwcybersec/ccdc/main/ccdcsysmon.xml" -Outfile sysmonconfig.xml
Start-Sleep -s 1
.\sysmon.exe -accepteula -i c:\downloads\sysmonconfig.xml
Start-Sleep -s 1

Write-Output "Download: ProcessMonitor.zip"
Invoke-WebRequest https://download.sysinternals.com/files/ProcessMonitor.zip -Outfile ProcessMonitor.zip
Expand-Archive .\ProcessMonitor.zip c:\downloads -Force

Write-Output "Download: TCPView.zip"
Invoke-WebRequest https://download.sysinternals.com/files/TCPView.zip -Outfile TCPView.zip
Expand-Archive .\TCPView.zip c:\downloads -Force

            # hard install
Write-Output "Download: Putty.msi"
Invoke-WebRequest https://the.earth.li/~sgtatham/putty/0.80/w64/putty-64bit-0.80-installer.msi -Outfile putty.msi

Write-Output "Download: Wireshark.exe"
Invoke-WebRequest https://2.na.dl.wireshark.org/win64/Wireshark-4.4.3-x64.exe -Outfile wireshark.exe

Write-Output "Download: NMap.exe"
Invoke-WebRequest https://nmap.org/dist/nmap-7.94-setup.exe -Outfile nmap.exe

Write-Output "Download: WinSCP.exe"
#Invoke-WebRequest https://cdn.winscp.net/files/WinSCP-6.3.6-Setup.exe?secure=xtTFi18u2Hj7S-7PQ28VNg==,1737253242 -Outfile WinSCP.exe

Write-Output "Download: Splunkforwarder.exe"
Invoke-WebRequest https://download.splunk.com/products/universalforwarder/releases/9.0.3/windows/splunkforwarder-9.0.3-dd0128b1f8cd-x64-release.msi -Outfile splunk.msi

Write-Output "Download: Firefox.exe"
Invoke-WebRequest "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US&attribution_code=c291cmNlPXd3dy5nb29nbGUuY29tJm1lZGl1bT1yZWZlcnJhbCZjYW1wYWlnbj0obm90IHNldCkmY29udGVudD0obm90IHNldCkmZXhwZXJpbWVudD0obm90IHNldCkmdmFyaWF0aW9uPShub3Qgc2V0KSZ1YT1jaHJvbWUmY2xpZW50X2lkPShub3Qgc2V0KSZzZXNzaW9uX2lkPShub3Qgc2V0KSZkbHNvdXJjZT1tb3pvcmc.&attribution_sig=8050a714514346fdc6eb8a04a5cf8bad6805f8964fec63b63a8e91e7962fa0f7" -Outfile Firefox.exe

# Get BlueSpawn after disabling Windows Defender
#Invoke-WebRequest https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe -Outfile BLUESPAWN-client-x64.exe
#Invoke-WebRequest https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe -Outfile Windump.exe
Set-ExecutionPolicy Restricted -force
