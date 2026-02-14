#! /usr/bin/env bash

splunk="172.20.242.20"
uf="https://download.splunk.com/products/universalforwarder/releases/9.4.7/linux/splunkforwarder-9.4.7-2a9293b80994-linux-amd64.tgz"

cd /tmp
curl -o uf.tgz $uf
tar xvf uf.tgz -C /opt
touch /opt/splunkforwarder/etc/passwd
/opt/splunkforwarder/bin/splunk version --accept-license

cat << EOF > /opt/splunkforwarder/etc/system/local/server.conf
[httpServer]
disableDefaultPort=true
EOF

cat << EOF > /opt/splunkforwarder/etc/system/local/deploymentclient.conf
[target-broker:deploymentServer]
targetUri = $splunk:8089
EOF

cat << EOF > /opt/splunkforwarder/etc/system/local/outputs.conf
[tcpout]
defaultGroup = udpin
[tcpout:udpin]
server = $splunk:9997
[tcpout-server://$splunk:9997]
EOF

/opt/splunkforwarder/bin/splunk start
/opt/splunkforwarder/bin/splunk enable boot-start -systemd-managed 0

echo "UF installed"

