#!/bin/bash

apt update && apt upgrade -y
apt install winbind samba smbclient cifs-utils libnss-winbind libpam-winbind krb5-user -y 

cd 
wget http://10.0.95.10/MCS/katchins/csc315/samba/restart_ad.sh
chmod +x restart_ad.sh

cd /etc
mv hosts hosts.orig
wget http://10.0.95.10/MCS/katchins/csc315/samba/hosts
mv nsswitch.conf nsswitch.conf.orig
wget http://10.0.95.10/MCS/katchins/csc315/samba/nsswitch.conf
cd /etc/samba
mv smb.conf smb.conf.orig
wget http://10.0.95.10/MCS/katchins/csc315/samba/smb.conf
mkdir -p /usr/local/pub
chmod 777 /usr/local/pub
service winbind stop
service nmbd stop
service smbd stop
