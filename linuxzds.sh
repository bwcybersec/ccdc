#! /usr/bin/env bash

hostname="$1"
dist="$2"
zds_type="$3"
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


# input checking
if [[ ${#1} -le 63 ]]; then
  echo "valid hostname, continuing..."
  sleep 1 
else
  echo "Error: hostname \"$1\" too long; please verify and try again"
  sleep 1
  exit 1
fi

if contains_loop "$2" "${valid_dist[@]}"; then
  echo "valid distro, continuing..."
  sleep 1
else
  echo "Error: unrecognized distro \"$2\"; please verify and try again"
  sleep 1
  exit 1
fi

if contains_loop "$3" "${valid_zds_type[@]}"; then
  echo "valid zds archetype, continuing..."
  sleep 1
else
  echo "Error: unrecognized zds archetype \"$3\"; please verify and try again"
  sleep 1
  exit 1
fi

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

# env
echo "setting environment..."
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH" >> /etc/profile
echo "export ZDS_TYPE=$zds_type" >> /etc/profile
echo "export ZDS_DIR=$zds_dir" >> /etc/profile

# hostname
echo "setting hostname, DNS..."
echo "$1.$domain" > /etc/hostname

# rising action, climax, falling action, resolution
cat << EOF > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
EOF

# ownership
echo "verifying file ownership..."
chown root:root /etc/group
chown root:root /etc/passwd
chown root:root /etc/sudoers
if [[ $(getent group shadow) ]]; then
  chown root:shadow /etc/shadow;
else
  chown root:root /etc/shadow
fi

# rainy
echo "disabling sshd..."
systemctl disable sshd
systemctl stop --now sshd
pkill -9 sshd

# rainier
echo "setting configs, moving things..."
mv $(/bin/which dd) $zds_dir/bin
mv $(/bin/which mount) $zds_dir/bin
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
mv /etc/rc[0-9].d $zds_dir/bad
mv /etc/rc.d $zds_dir/bad
mv /etc/rc.local $zds_dir/bad

# putting away the welcome mat
cat << EOF > /etc/issue.net
This computer system/network is the property of $domain. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (AUP). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. 

By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action civil charges/criminal penalties, and/or other sanctions as set forth in the Companys AUP By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. 

ALL USERS SHALL LOG OFF OF A $domain OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE.
EOF
echo "This computer system/network is property of $domain. Unauthorized use is strictly prohibited." > /etc/issue

# scheduled tasks
echo "setting scheduled tasks..."
cat << EOF >> /etc/crontab
@reboot root /etc/clodsire
*/5 * * * * root tar czf /usr/share/man/$(date +%s)_etc.tgz
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

# base
cat << EOF > $zds_dir/postscript
#! /usr/bin/env bash

curl -o smartestfw $zangoose
curl -o set-xdp $seviper

chmod +x smartestfw
./smartestfw
cp clodsire /etc
chmod +x clodsire /etc/clodsire
/etc/clodsire

chmod +x set-xdp
cp set-xdp /usr/local/bin
chmod +x set-xdp /usr/local/bin/set-xdp

EOF
chmod +x $zds_dir/postscript

# continuation
echo "modifying postscript for distro \"$2\"..."

if [[ $2 == "fedora" ]]; then
  echo 'systemctl disable firewalld' >> $zds_dir/postscript
  echo 'systemctl stop --now firewalld' >> $zds_dir/postscript
  echo 'dnf install -y git curl vim net-snmp net-snmp-utils nmap nmap-ncat tcpdump audit chrony xdp-tools lynis lsof tmux gdb' >> $zds_dir/postscript
  echo 'dnf reinstall -y pam openssh-server coreutils' >> $zds_dir/postscript
elif [[ $2 == "oracle" ]]; then
  echo 'systemctl disable firewalld' >> $zds_dir/postscript
  echo 'systemctl stop --now firewalld' >> $zds_dir/postscript
  echo 'dnf install -y git curl vim net-snmp net-snmp-utils nmap tcpdump nmap-ncat audit chrony xdp-tools lsof tmux gdb' >> $zds_dir/postscript
  echo 'dnf reinstall -y pam openssh-server coreutils' >> $zds_dir/postscript
elif [[ $2 == "ubuntu" ]]; then
  echo 'systemctl disable ufw' >> $zds_dir/postscript
  echo 'systemctl stop --now ufw' >> $zds_dir/postscript
  echo 'apt install -y git curl vim snmpd nmap ncat tcpdump auditd docker.io chrony xdp-tools lynis lsof tmux gdb' >> $zds_dir/postscript
  echo 'apt install --reinstall -y libpam-runtime openssh-server coreutils' >> $zds_dir/postscript
  echo 'apt-get install --reinstall -y -o Dpkg::Options::="--force-confmiss" $(dpkg -S /etc/pam.d/\* | cut -d ':' -f 1)' >> $zds_dir/postscript
else
  echo "Error: did not match input \"$2\" with any valid distro; you should never see this error"
fi

# Crazy Ivan strikes again
echo "mv \$(/bin/which sshd) $zds_dir/bin" >> $zds_dir/postscript
echo "mv \$(/bin/which dd) $zds_dir/bin" >> $zds_dir/postscript
echo "mv \$(/bin/which mount) $zds_dir/bin" >> $zds_dir/postscript
echo "mv \$(/bin/which base64) $zds_dir/bin" >> $zds_dir/postscript
echo "cp \$(/bin/which xargs) $zds_dir/bin" >> $zds_dir/postscript
echo "cp \$(/bin/which tee) $zds_dir/bin" >> $zds_dir/postscript

echo "modifying subscript for archetype \"$3\"..."
if [[ $3 == "splunk" ]]; then
  echo "curl -o splunkzds $chimecho" >> $zds_dir/postscript
  echo 'chmod +x splunkds' >> $zds_dir/postscript
else
  echo "curl -o ufzds $chingling" >> $zds_dir/postscript
  echo 'chmod +x ufzds' >> $zds_dir/postscript
fi

echo "$(basename $0) finished; check dropflag procedure and postscript in $zds_dir for what to do next"
exit 0

