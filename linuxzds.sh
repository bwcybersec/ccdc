#! /usr/bin/env bash

hostname="$1"
dist="$2"
zds_type="$3"
zds_dir="/var/zds"
domain="allsafe.internal"
valid_dist=("ubuntu" "fedora" "oracle")
valid_zds_type=("ecom" "webmail" "splunk" "wkst")

snapshot() {
  date +%s; echo "---"
  uname -a; echo "---"
  cat /etc/os-release; echo "---"
  cat /etc/passwd | awk -F ':' '{print $7":"$1}' | sort; echo "---"
  ps aux; echo "---"
  ss -tualpon
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
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
mkdir -p $zds_dir/{etc,var,opt,root,home,bad,state}

echo "$(date +%s)" > $zds_dir/state/pre
echo "---" >> $zds_dir/state/pre
echo "$(uname -a)" >> $zds_dir/state/pre
echo "---" >> $zds_dir/state/pre
cat /etc/os-release >> $zds_dir/state/pre
echo "---" >> $zds_dir/state/pre
cat /etc/passwd | awk -F ':' '{print $7":"$1}' | sort >> $zds_dir/state/pre
echo "---" >> $zds_dir/state/pre
echo "$(ps aux)" >> $zds_dir/state/pre
echo "---" >> $zds_dir/state/pre
echo "$(ss -tualpon)" >> $zds_dir/state/pre


# backups
cp -r /etc $zds_dir/etc
cp -r /var $zds_dir/var
cp -r /opt $zds_dir/opt

cp /root/.bash* $zds_dir/root
mv /root/.ssh $zds_dir/root

for i in /home/*; do
  mkdir $zds_dir/home/$i
  cp $i/.bash* $zds_dir/home/$i
  mv $i/.ssh $zds_dir/home/$i
done

# env
echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH" >> /etc/profile
export ZDS_TYPE = $zds_type
echo "ZDS_TYPE=$zds_type" >> /etc/profile
export ZDS_DIR = $zds_dir
echo "ZDS_DIR=$zds_dir" >> /etc/profile

# hostname
echo "$1.$domain" > /etc/hostname

# rising action, climax, falling action, resolution
cat << EOF > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
EOF

# rainy
systemctl disable sshd
systemctl stop --now sshd
pkill -9 sshd
mv $(/bin/which sshd) $zds_dir

# nothing good
echo "" > /etc/ld.so.conf
rm -rf /etc/ld.so.conf.d

# rainier
mv $(/bin/which dd) $zds_dir
mv $(/bin/which mount) $zds_dir
mv $(/bin/which base64) $zds_dir
cp $(/bin/which xargs) $zds_dir
cp $(/bin/which tee) $zds_dir

# it is and always will be 1998
sysctl net.ipv6.conf.all.disable_ipv6=1
sysctl net.ipv6.conf.default.disable_ipv6=1
sysctl net.ipv6.conf.lo.disable_ipv6=1

cat << EOF > /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF

# rainiest
sed -i 's/#\?\(PermitRootLogin\s*\).*$/\1 no/' /etc/ssh/sshd_config

# ownership
chown root:root /etc/group
chown root:root /etc/passwd
chown root:root /etc/sudoers
if [[ $(getent group shadow) ]]; then
  chown root:shadow /etc/shadow; 
else
  chown root:root /etc/shadow
fi

# scheduled tasks
cat << EOF >> /etc/crontab
@reboot root /etc/clodsire
*/5 * * * * root tar czf /usr/share/man/$(date +%s)_etc.tgz
*/15 * * * * root find / -type f -perm /6000 >> $zds_dir/suid
*/15 * * * * find / -type f -name "*.php" -mmin 15 >> $zds_dir/modified_php; echo "---" >> $zds_dir/modified_php 
EOF

# putting away the welcome mat
cat << EOF > /etc/issue.net
This computer system/network is the property of $domain. It is for authorized use only. By using this system, all users acknowledge notice of, and agree to comply with, the Company’s Acceptable Use of Information Technology Resources Policy (AUP). Users have no personal privacy rights in any materials they place, view, access, or transmit on this system. The Company complies with state and federal law regarding certain legally protected confidential information, but makes no representation that any uses of this system will be private or confidential. Any or all uses of this system and all files on this system may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized Company and law enforcement personnel, as well as authorized individuals of other organizations. 

By using this system, the user consents to such interception, monitoring, recording, copying, auditing, inspection, and disclosure at the discretion of authorized Company personnel. Unauthorized or improper use of this system may result in administrative disciplinary action civil charges/criminal penalties, and/or other sanctions as set forth in the Companys AUP By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use. 

ALL USERS SHALL LOG OFF OF A $domain OWNED SYSTEM IMMEDIATELY IF SAID USER DOES NOT AGREE TO THE CONDITIONS STATED ABOVE.
EOF
echo "This computer system/network is property of $domain. Unauthorized use is strictly prohibited." /etc/issue

# pii
grep -nrHIEe '[0-9]{16}' /root /home > $zds_dir/bad/potentially_pii
grep -nrHIEe '[0-9]{3}(-|\s)?[0-9]{3}(-|\s)?[0-9]{4}' /root /home >> $zds_dir/bad/potentially_pii

# post
snapshot() > $zds_dir/state/post

# future snapshots
cat << EOF > /usr/local/bin/zds-state
#! /usr/bin/env bash
timestamp = $(date +%s)
persistent = $zds_dir/state/$timestamp.state

echo $timestamp > $persistent
echo "---" >> $persistent
ps aux >> $persistent
echo "---" >> $persistent
ss -tualpon >> $persistent
EOF


# continuation
if [[ $3 == "ecom" ]]; then
  echo "creating subscripts for archetype \"$3\"..."
  break
elif [[ $3 == "webmail" ]]; then 
  echo "creating subscripts for archetype \"$3\"..."
  break
elif [[ $3 == "splunk" ]]; then 
  echo "creating subscripts for archetype \"$3\"..."
  break
elif [[ $3 == "wkst" ]]; then 
  echo "creating subscripts for archetype \"$3\"..."
  break
else
  echo "Error: did not match input \"$3\" with any established zds archetype; you should never see this error"
fi

echo "$(basename $0) finished; check dropflag procedure and scripts in $zds_dir for what to do next"
exit 0

