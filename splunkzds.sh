#!/bin/bash

# Download Zero Day Script
if [ ! -e "./linuxzds" ]; then
wget https://raw.githubusercontent.com/bwcybersec/ccdc/main/linuxzds 
fi

# Download Splunk, make sure to update the link over time 
if [ ! -e "./splunk-9.0.2-17e00c557dc1-Linux-x86_64.tgz" ]; then
wget -O splunk-9.0.2-17e00c557dc1-Linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/9.0.2/linux/splunk-9.0.2-17e00c557dc1-Linux-x86_64.tgz"
fi

rm -rf /opt/splunk
tar xvzf splunk-9.0.2-17e00c557dc1-Linux-x86_64.tgz -C /opt


chmod +x linuxzds
./linuxzds
chmod +x /usr/local/bin/webon
webon

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
blacklist1=/var/log/audit.log
blacklist2=/var/log/auth.log
blacklist3=/var/log/secure
blacklist4=/var/log/kern.log
blacklist5=/var/log/zds/clamscan.log
blacklist6=/var/log/clamav/freshclam.log

[monitor:///var/log/audit.log]
index=main
disabled=false
sourcetype=linux:audit:enriched

[monitor:///var/log/secure]
index=main
disabled=false
sourcetype=linux_secure

[monitor:///var/log/auth.log]
index=main
disabled=false
sourcetype=linux_secure

[monitor:///var/log/kern.log]
index=main
disabled=false
sourcetype=syslog

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




if [ ! -e "/opt/splunk/etc/system/local/web.conf" ]; then
cat << EOF > /opt/splunk/etc/system/local/web.conf
[settings]
login_content = This computer system/network is the property of Allsafe.com. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Allsafe's Acceptable Use of Information Technology Resources Policy (AUP). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. Allsafe complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Allsafe and law enforcement personnel, as well as authorized individuals of other organizations. By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Allsafe personnel. Unauthorized or improper use of this system may result in administrative disciplinary action civil charges/criminal penalties, and/or other sanctions as set forth in Allsafe's AUP. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. ALL USERS SHALL LOG OFF OF AN ALLSAFE.COM OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE.

EOF
fi

#start splunk
/opt/splunk/bin/splunk start --accept-license



#Hurricane labs has this available freely, allows for app download via cli
yum install -y git
/opt/splunk/bin/splunk cmd python -mpip install wheel
/opt/splunk/bin/splunk cmd python -mpip install git+https://github.com/HurricaneLabs/sbclient.git


# REPLACE with your own username and password for Splunkbase please
export SPLUNKBASE_USERNAME="ecall390"
export SPLUNKBASE_PASSWORD="Changeme*390"

#makes temp folder, moves you into it, and downloads all the apps
mkdir /opt/splunk/drop
cd /opt/splunk/drop
/opt/splunk/bin/splunk cmd sbclient download-app Splunk_TA_nix
/opt/splunk/bin/splunk cmd sbclient download-app Splunk_TA_windows
/opt/splunk/bin/splunk cmd sbclient download-app Splunk_TA_paloalto
/opt/splunk/bin/splunk cmd sbclient download-app Splunk_TA_stream
/opt/splunk/bin/splunk cmd sbclient download-app Splunk_TA_microsoft_sysmon
/opt/splunk/bin/splunk cmd sbclient download-app splunk_app_stream
/opt/splunk/bin/splunk cmd sbclient download-app Splunk_TA_stream_wire_data

#untar our newly downloaded app files from our temp folder to the correct place
for filename in *;
do tar xvzf $filename -C /opt/splunk/etc/apps;
done


#post app install set up
cp -r  /opt/splunk/etc/apps/Splunk_TA_microsoft_sysmon /opt/splunk/etc/deployment-apps
cp -r  /opt/splunk/etc/apps/Splunk_TA_stream /opt/splunk/etc/deployment-apps
cp -r /opt/splunk/etc/deployment-apps/ccdc_linux_inputs /opt/splunk/etc/apps

# for stream we need to change the 'localhost' piece in the app's inputs.conf to the actual localhost IP

cat << EOF > /opt/splunk/etc/deployment-apps/Splunk_TA_stream/inputs.conf

[streamfwd://streamfwd]
#update the IP address '172.20.241.20' as necessary
splunk_stream_app_location = http://172.20.241.20:8000/en-us/custom/splunk_app_stream/
disabled = 0

EOF


/opt/splunk/bin/splunk reload deploy-server




