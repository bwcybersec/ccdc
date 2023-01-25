#!/bin/bash

# Download Zero Day Script
if [ ! -e "./linuxzds" ]; then
wget https://raw.githubusercontent.com/bwcybersec/ccdc/main/linuxzds 
fi

# stop splunk
/opt/splunk/bin/splunk stop

# Download Splunk, make sure to update the link over time 
if [ ! -e "./splunk-9.0.2-17e00c557dc1-Linux-x86_64.tgz" ]; then
wget -O splunk-9.0.2-17e00c557dc1-Linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/9.0.2/linux/splunk-9.0.2-17e00c557dc1-Linux-x86_64.tgz"
rm -rf /opt/splunk
tar xvzf splunk-9.0.2-17e00c557dc1-Linux-x86_64.tgz -C /opt
fi

chmod +x linuxzds
./linuxzds

#linux directory path for TA configuration
mkdir -p /opt/splunk/etc/deployment-apps/ccdc_linux_inputs/local

#windows directory path for TA configuration
mkdir -p /opt/splunk/etc/deployment-apps/ccdc_windows_inputs/local

#other directory path for general configuration
mkdir -p /opt/splunk/etc/apps/Splunk_TA_paloalto/local
mkdir -p /opt/splunk/etc/deployment-apps/uf_limits_unlimited/local
mkdir -p /opt/splunk/etc/system/local

#conf file set up for TA *nix
cat << EOF > /opt/splunk/etc/deployment-apps/ccdc_linux_inputs/local/inputs.conf
[monitor:///var/log]
index=main
disabled = false

[monitor:///var/adm]
index=main
disabled = false

[monitor:///etc]
index=configs
disabled = false

[monitor:///root/.bash_history]
index=main
disabled = false
sourcetype = bash_history

[monitor:///home/*/.bash_history]
index=main
disabled = false
sourcetype = bash_history

EOF

#conf file set up for Windows
cat << EOF > /opt/splunk/etc/deployment-apps/ccdc_windows_inputs/local/inputs.conf
[WinEventLog://Application]
index = main
disabled = false

[WinEventLog://Security]
index = main
disabled = false

[WinEventLog://System]
index = main
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
renderXml = false
source = WinEventLog:Microsoft-Windows-Sysmon/Operational

EOF

#conf file set up for PAN
cat << EOF > /opt/splunk/etc/apps/Splunk_TA_paloalto/local/inputs.conf
[udp://514]
connection_host = ip
index = main
sourcetype = pan:log

EOF

#conf file set up for uf limits
cat << EOF > /opt/splunk/etc/deployment-apps/uf_limits_unlimited/local/inputs.conf
[thruput]
maxKBps = 0

EOF

#conf for serverclasses
cat << EOF > /opt/splunk/etc/system/local/serverclass.conf
[serverClass:all]
whitelist.0 = *

[serverClass:all:app:uf_limits_unlimited]
restartSplunkd = 1

[serverClass:all_linux]
machineTypesFilter = linux*
whitelist.0 = *

[serverClass:all_linux:app:ccdc_linux_inputs]
restartSplunkd = 1

[serverClass:all_windows]
machineTypesFilter = windows*
whitelist.0 = *

[serverClass:all_windows:app:ccdc_windows_inputs]
restartSplunkd = 1

EOF


#start splunk
/opt/splunk/bin/splunk start --accept-license

if [ ! -e "/opt/splunk/etc/system/local/web.conf" ]; then
cat << EOF > 
[settings]
login_content = This computer system/network is the property of Allsafe.com. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (AUP). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action civil charges/criminal penalties, and/or other sanctions as set forth in the Companys AUP By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF AN ALLSAFE.COM OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE.

EOF



