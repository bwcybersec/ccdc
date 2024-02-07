Set-ExecutionPolicy Unrestricted -force
New-Item -Path C:\downloads -ItemType Directory -erroraction SilentlyContinue
Set-Location c:\downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3

                        # figure out unzip and re-assess
Invoke-WebRequest https://live.sysinternals.com/Autoruns64.exe -Outfile Autoruns.exe
Invoke-WebRequest https://live.sysinternals.com/procexp64.exe -Outfile ProcessExplorer.exe
Invoke-WebRequest https://live.sysinternals.com/Sysmon64.exe -Outfile Sysmon.exe
#Invoke-WebRequest https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -Outfile sysmonconfig.xml
Invoke-WebREquest "https://raw.githubusercontent.com/bwcybersec/ccdc/main/ccdcsysmon.xml" -Outfile sysmonconfig.xml
Start-Sleep -s 1
Start-Process sysmon.exe -args "-accepteula -i c:\downloads\sysmonconfig.xml"
Start-Sleep -s 1
Invoke-WebRequest https://live.sysinternals.com/Procmon64.exe -Outfile procmon.exe
Invoke-WebRequest https://live.sysinternals.com/tcpview64.exe -Outfile tcptview.exe
            # hard install
Invoke-WebRequest https://the.earth.li/~sgtatham/putty/0.80/w64/putty-64bit-0.80-installer.msi -Outfile putty.msi
Invoke-WebRequest https://www.wireshark.org/download/win64/Wireshark-4.2.1-x64.exe -Outfile wireshark.exe
Invoke-WebRequest https://nmap.org/dist/nmap-7.94-setup.exe -Outfile nmap.exe
Invoke-WebRequest https://cdn.winscp.net/files/WinSCP-6.1.2-Setup.exe?secure=vvypgP9Ikj_QZJGNNy2fVg==,1706980402 -Outfile WinPcap.exe
Invoke-WebRequest "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US&attribution_code=c291cmNlPXd3dy5nb29nbGUuY29tJm1lZGl1bT1yZWZlcnJhbCZjYW1wYWlnbj0obm90IHNldCkmY29udGVudD0obm90IHNldCkmZXhwZXJpbWVudD0obm90IHNldCkmdmFyaWF0aW9uPShub3Qgc2V0KSZ1YT1jaHJvbWUmY2xpZW50X2lkPShub3Qgc2V0KSZzZXNzaW9uX2lkPShub3Qgc2V0KSZkbHNvdXJjZT1tb3pvcmc.&attribution_sig=8050a714514346fdc6eb8a04a5cf8bad6805f8964fec63b63a8e91e7962fa0f7" -Outfile Firefox.exe
Invoke-WebRequest "https://cdn.winscp.net/files/WinSCP-6.1.2-Setup.exe?secure=uLPzvu8PJqy7bYLiUgX0BQ==,1707179549" -Outfile WinSCP.exe
# Get BlueSpawn after disabling Windows Defender
#Invoke-WebRequest https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe -Outfile BLUESPAWN-client-x64.exe
#Invoke-WebRequest https://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe -Outfile Windump.exe
#Invoke-WebRequest https://download.splunk.com/products/universalforwarder/releases/9.0.3/windows/splunkforwarder-9.0.3-dd0128b1f8cd-x64-release.msi -Outfile splunk.msi
