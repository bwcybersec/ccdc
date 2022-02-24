Set-ExecutionPolicy -executionpolicy unrestricted

mkdir c:\downloads
cd c:\downloads

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest https://2.na.dl.wireshark.org/win64/Wireshark-win64-3.6.2.exe -Outfile wireshark.exe
Invoke-WebRequest https://nmap.org/dist/nmap-7.92-setup.exe -Outfile nmap.exe
Invoke-WebRequest https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.76-installer.msi -Outfile putty.msi
Invoke-WebRequest https://download.splunk.com/products/universalforwarder/releases/8.2.5/windows/splunkforwarder-8.2.5-77015bc7a462-x64-release.msi -Outfile splunk.msi
Invoke-WebRequest https://download.sysinternals.com/files/Autoruns.zip -Outfile Autoruns.zip
Invoke-WebRequest https://download.sysinternals.com/files/ProcessExplorer.zip -Outfile ProcessExplorer.zip
Invoke-WebRequest https://winscp.net/download/WinSCP-5.19.5-Setup.exe -Outfile WinSCP.exe

