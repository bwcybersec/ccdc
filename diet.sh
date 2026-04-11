#! /usr/bin/env bash

zds_dir="/var/zds"
domain="allsafe.internal"
valid_dist=("ubuntu" "fedora" "oracle")
valid_zds_type=("ecom" "webmail" "splunk" "wkst")
zangoose="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/smartestfw"
seviper="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/set-xdp.sh"
chimecho="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/splunkzds.sh"
chingling="https://raw.githubusercontent.com/bwcybersec/ccdc/refs/heads/main/ufzds.sh"

snapshot() {
  echo "$(date +%s)" > $zds_dir/state/$1
  echo "---" >> $zds_dir/state/$1
  uname -a >> $zds_dir/state/$1
  echo "---" >> $zds_dir/state/$1
  cat /etc/os-release >> $zds_dir/state/$1
  echo "---" >> $zds_dir/state/$1
  cat /etc/passwd | awk -F ':' '{print $7":"$1}' | sort >> $zds_dir/state/$1
  echo "---" >> $zds_dir/state/$1
  ps aux >> $zds_dir/state/$1
  echo "---" >> $zds_dir/state/$1
  ss -tualpon >> $zds_dir/state/$1
}

contains_loop() {
  local item="$1"
  shift
  for i; do
    if [[ $i == $item ]]; then
      return 0
    fi
  done 
  return 1
}

# init
echo "staging and inital snapshot..."
mkdir -p $zds_dir/{etc,var,opt,root,home,bin,bad,state}
snapshot "pre"

# backups
echo "making backups..."
cp -r /etc $zds_dir
cp -r /var $zds_dir
cp -r /opt $zds_dir
cp /root/.bash* $zds_dir/root
mv /root/.ssh $zds_dir/root
for i in /home/*; do
  mkdir $zds_dir/$i
  cp $i/.bash* $zds_dir/$i
  mv $i/.ssh $zds_dir/$i
done

# rising action, climax, falling action, resolution
#cat << EOF > /etc/resolv.conf
#nameserver 8.8.8.8
#nameserver 8.8.4.4
#nameserver 1.1.1.1
#EOF

# ownership
echo "verifying file ownership..."
chown root:root /etc/{group,passwd,sudoers}
if [[ $(getent group shadow) ]]; then
  chown root:shadow /etc/shadow;
else
  chown root:root /etc/shadow
chmod 0644 /etc/{group,passwd,shadow}
chmod 0640 /etc/sudoers
fi

# rainy
#echo "disabling sshd..."
#systemctl disable sshd
#systemctl stop --now sshd
#pkill -9 sshd

# rainier
echo "setting configs, moving things..."
mv $(/bin/which dd) $zds_dir/bin
mv $(/bin/which base64) $zds_dir/bin
cp $(/bin/which xargs) $zds_dir/bin
cp $(/bin/which tee) $zds_dir/bin

# I heard you like rain
sed -i 's/#\?\(PermitRootLogin\s*\).*$/\1 no/' /etc/ssh/sshd_config

# it is and always will be 1998
sysctl net.ipv6.conf.all.disable_ipv6=1
sysctl net.ipv6.conf.default.disable_ipv6=1
sysctl net.ipv6.conf.lo.disable_ipv6=1

cat << EOF > /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF

# nothing good
echo "" > /etc/ld.so.conf
rm -rf /etc/ld.so.conf.d

# putting away the welcome mat
echo ".$domain" >> /etc/hostname
cat << EOF > /etc/issue.net
This computer system/network is the property of $domain. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (AUP). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. 

By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action civil charges/criminal penalties, and/or other sanctions as set forth in the Companys AUP By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. 

ALL USERS SHALL LOG OFF OF A $domain OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE.
EOF
echo "This computer system/network is property of $domain. Unauthorized use is strictly prohibited." > /etc/issue

# scheduled tasks
echo "setting scheduled tasks..."
cat << EOF >> /etc/crontab
*/15 * * * * root find / -type f -perm /6000 >> $zds_dir/suid
*/15 * * * * find / -type f -name "*.php" -mmin 15 >> $zds_dir/modified_php; echo "---" >> $zds_dir/modified_php 
EOF

# pii
echo "running basic PII searches..."
grep -nrHIEe '[0-9]{16}' /root /home > $zds_dir/bad/potentially_pii
grep -nrHIEe '[0-9]{3}(-|\s)?[0-9]{3}(-|\s)?[0-9]{4}' /root /home >> $zds_dir/bad/potentially_pii

# post
echo "post-transaction snapshot..."
snapshot "post"

# future snapshots
echo "writing subscripts..."

cat << EOF > /usr/local/bin/zds-state
#! /usr/bin/env bash

timestamp=\$(date +%s)
persistent=$zds_dir/state/\$timestamp.state

echo "\$timestamp" > \$persistent
echo "---" >> \$persistent
uname -a >> \$persistent
echo "---" >> \$persistent
ps aux >> \$persistent
echo "---" >> \$persistent
ss -tualpon >> \$persistent
EOF
chmod +x /usr/local/bin/zds-state

# you tricky, tricky trickster
cat << EOF > /usr/local/bin/dummy
#! /usr/bin/env bash
exit 1
EOF
chmod +x /usr/local/bin/dummy

# firewall
cat << EOF > $zds_dir/zds-firewall
#! /bin/bash

cp $zds_dir/zds-firewall /usr/local/bin

iptables -P INPUT ALLOW
iptables -P FORWARD DROP
iptables -P OUTPUT ALLOW

iptables -F INPUT
iptables -F FORWARD
iptables -F OUTPUT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p udp --dport 123 -j ACCEPT
iptables -A INPUT -p udp --dport 161 -j ACCEPT
iptables -A INPUT -p udp --dport 389 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 636 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
iptables -A INPUT -p tcp --dport 8089 -j ACCEPT
iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A INPUT -j DROP

iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT
iptables -A OUTPUT -m limit --limit 15/minute -j LOG --log-uid --log-level 4 --log-prefix 'FW DROP [out]: ACTION=DROP '

EOF
chmod +x $zds_dir/zds-firewall

# continuation
echo "installing packages..."

source /etc/os-release
if [[ $ID == "fedora" ]]; then
  dnf install -y git curl vim net-snmp net-snmp-utils nmap nmap-ncat tcpdump audit chrony xdp-tools lynis lsof tmux gdb
  dnf reinstall -y pam openssh-server coreutils
elif [[ $ID == "oracle" ]]; then
  dnf install -y git curl vim net-snmp net-snmp-utils nmap tcpdump nmap-ncat audit chrony xdp-tools lsof tmux gdb
  dnf reinstall -y pam openssh-server coreutils
elif [[ $ID == "ubuntu" ]]; then
  apt install -y git curl vim snmpd nmap ncat tcpdump auditd docker.io chrony xdp-tools lynis lsof tmux gdb
  apt install --reinstall -y libpam-runtime openssh-server coreutils
  apt-get install --reinstall -y -o Dpkg::Options::="--force-confmiss" $(dpkg -S /etc/pam.d/\* | cut -d ':' -f 1)
else
  echo "Error: did not match with a known distro, skipping packages..."
fi

echo "$(basename $0) finished; good luck"
exit 0

