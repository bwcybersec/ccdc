#!/usr/bin/env bash

# backup initial page (/var/zds/integrity and /usr/share/man)
# grab page
# shuck timestamp
# hash and log (/var/zds/integrity/web_hash.log)
# compare hashes
# restore if mismatch
# repeat every 5 minutes

# Note: bash needs to be v5 or above for timestamps to work! $EPOCHSECONDS was introduced in v5.


if cat /etc/*release | grep -s "centos"; then
	yum install bash
elif cat /etc/*release | grep -s "debian"; then
	apt install bash
else
	echo "Not CentOS or Debian, not updating bash..."

rm -rf /tmp/web_grab && mkdir /tmp/web_grab
mkdir /var/zds/integrity
cd /var/zds/integrity
curl http://172.25.24.11/prestashop/index.php > dropflag.html
sha256sum dropflag.html > dropflag.hash
truncate -s 64 dropflag.hash && echo "" >> dropflag.hash  # removes the filename from the hash file and adds a new line character
cp dropflag.* /usr/share/man  # secondary backup
cd /tmp/web_grab

while true; do
	curl http://172.25.24.11/prestashop/index.php > current.html
	sha256sum current.html > current.hash
	truncate -s 64 current.hash && echo "" >> current.hash
	diff /var/zds/integrity/dropflag.hash current.hash
	DIFF=$(diff /var/zds/integrity/dropflag.hash current.hash)
	$DIFF
	if [[ -z "$DIFF" ]] ; then
		echo "$EPOCHSECONDS: Hashes match!" >> /var/zds/integrity/web_hash.log
		cat /var/zds/integrity/web_hash.log
	else
		echo "$EPOCHSECONDS: Hashes do not match! Restoring backup..." >> /var/zds/integrity/web_hash.log
		wall "$EPOCHSECONDS: Hashes do not match! Restoring backup..."
	fi
	sleep 300
done
