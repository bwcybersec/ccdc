#! /usr/bin/env bash

$INV="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/inv.yml"
$ECOM="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/ecom.yml"
$WM="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/webmail.yml"
$SPL="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/splunk.yml"
$WKST="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/wkst.yml"
$UF="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/forwarders.yml"

if [[ $UID != 0 ]]; then
  echo "please execute as root :)"
  exit 1
fi

echo "172.20.242.20     splunk01.allsafe.internal" >> /etc/hosts
echo "172.20.242.30     ecom01.allsafe.internal" >> /etc/hosts
echo "172.20.242.40     webmail01.allsafe.internal" >> /etc/hosts
echo "172.20.242.200    wkst01.allsafe.internal" >> /etc/hosts

dnf update -y
dnf install -y epel-release
dnf install -y ansible

echo "[defaults]" >> /etc/ansible/ansible.cfg
echo "host_key_checking = false" >> /etc/ansible/ansible.cfg

mkdir ~/ansiblezds
cd ~/ansiblezds
curl -o inv.yml $INV
curl -o ecom.yml $ECOM
curl -o webmail.yml $WM
curl -o splunk.yml $SPL
curl -o forwarders.yml $UF

ansible -i inv.yml -kK linux.yml
ansible -i inv.yml -kK splunk.yml
ansible -i inv.yml -kK wkst.yml
ansible -i inv.yml -kK ecom.yml
ansible -i inv.yml -kK webmail.yml

