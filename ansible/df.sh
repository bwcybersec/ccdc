#! /usr/bin/env bash

EEVEE="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/inv.yml"
VAPOREON="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/linux.yml"
JOLTEON="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/ecom.yml"
FLAREON="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/webmail.yml"
ESPEON="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/splunk.yml"
UMBREON="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/wkst.yml"
LEAFEON="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ansible/forwarders.yml"

if [[ $UID != 0 ]]; then
  echo "please execute as root :)"
  exit 1
fi

echo "writing /etc/hosts..."
echo "172.20.242.20     splunk01.allsafe.internal" >> /etc/hosts
echo "172.20.242.30     ecom01.allsafe.internal" >> /etc/hosts
echo "172.20.242.40     webmail01.allsafe.internal" >> /etc/hosts
echo "172.20.242.200    wkst01.allsafe.internal" >> /etc/hosts

dnf install -y epel-release
dnf install -y ansible

echo "writing ansible.cfg"
echo "[defaults]" >> /etc/ansible/ansible.cfg
echo "host_key_checking = false" >> /etc/ansible/ansible.cfg

echo "fetching playbooks..."
mkdir ~/ansible
cd ~/ansible
curl -o inv.yml $EEVEE
curl -o linux.yml $VAPOREON
curl -o ecom.yml $JOLTEON
curl -o webmail.yml $FLAREON
curl -o splunk.yml $ESPEON
curl -o wkst.yml $UMBREON
curl -o forwarders.yml $LEAFEON

echo "playbook: linux.yml"
ansible-playbook -i inv.yml -kK linux.yml
echo "playbook: ecom.yml"
ansible-playbook -i inv.yml -kK ecom.yml
echo "playbook: webmail.yml"
ansible-playbook -i inv.yml -kK webmail.yml
echo "playbook: splunk.yml"
ansible-playbook -i inv.yml -kK splunk.yml
echo "playbook: wkst.yml"
ansible-playbook -i inv.yml -kK wkst.yml
echo "playbook: forwarders.yml"
ansible-playbook -i inv.yml -kK forwarders.yml

