Set-ExecutionPolicy -executionpolicy unrestricted

mkdir c:\downloads
cd c:\downloads

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3
Invoke-WebRequest https://2.na.dl.wireshark.org/win64/Wireshark-win64-4.0.3.exe -Outfile wireshark.exe
Invoke-WebRequest https://nmap.org/dist/nmap-7.93-setup.exe -Outfile nmap.exe
Invoke-WebRequest https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.76-installer.msi -Outfile putty.msi
Invoke-WebRequest https://download.sysinternals.com/files/Autoruns.zip -Outfile Autoruns.zip
Invoke-WebRequest https://download.sysinternals.com/files/ProcessExplorer.zip -Outfile ProcessExplorer.zip
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -Outfile Sysmon.zip
Invoke-WebRequest https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -Outfile sysmonconfig.xml
Invoke-WebRequest https://winscp.net/download/WinSCP-5.21.7-Setup.exe -Outfile WinSCP.exe
Invoke-WebRequest https://dl.google.com/chrome/install/375.126/chrome_installer.exe -Outfile chrome.exe
Invoke-WebRequest https://download.sysinternals.com/files/ProcessMonitor.zip -Outfile procmon.zip
Invoke-WebRequest https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe -Outfile WinPcap.exe
# Get BlueSpawn after disabling Windows Defender
#Invoke-WebRequest https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe -Outfile BLUESPAWN-client-x64.exe
#Invoke-WebRequest https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe -Outfile Windump.exe
#Invoke-WebRequest https://download.splunk.com/products/universalforwarder/releases/9.0.3/windows/splunkforwarder-9.0.3-dd0128b1f8cd-x64-release.msi -Outfile splunk.msi
Invoke-WebRequest https://download.fedoraproject.org/pub/fedora/linux/releases/37/Server/x86_64/iso/Fedora-Server-dvd-x86_64-37-1.7.iso -Outfile fedora-server.iso
Invoke-WebRequest https://download.fedoraproject.org/pub/fedora/linux/releases/37/Workstation/x86_64/iso/Fedora-Workstation-Live-x86_64-37-1.7.iso -Outfile fedora-workstation.iso
