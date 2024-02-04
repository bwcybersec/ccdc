 #!/usr/bin/env bash

# backup initial page (/var/zds/integrity and /usr/share/man)
# grab page
# shuck timestamp
# hash and log (/var/zds/integrity/web_hash.log)
# compare hashes
# restore if mismatch
# repeat every 5 minutes

TIMESTAMP=$(date +%s)

rm -rf /tmp/web_grab && mkdir /tmp/web_grab
mkdir /var/zds/integrity
cd /var/zds/integrity
curl http://172.25.24.11/prestashop/index.php > dropflag.html
sed "181d" dropflag.html > dropflag.html  # removes timestamp on line 181
sha256sum dropflag.html > dropflag.hash
truncate -s 64 dropflag.hash && echo "" >> dropflag.hash  # removes the filename from the hash file and adds a new line character
cp dropflag.* /usr/share/man  # secondary backup
cd /tmp/web_grab

while true; do
	curl http://172.25.24.11/prestashop/index.php > current.html
 	sed "181d" current.html > current.html
	sha256sum current.html > current.hash
	truncate -s 64 current.hash && echo "" >> current.hash
	diff /var/zds/integrity/dropflag.hash current.hash
	DIFF=$(diff /var/zds/integrity/dropflag.hash current.hash)
	if [[ -z "$DIFF" ]] ; then
		echo "$TIMESTAMP: Hashes match!" >> /var/zds/integrity/web_hash.log
	else
		echo "$TIMESTAMP: Hashes do not match! Restoring backup..." >> /var/zds/integrity/web_hash.log
		wall "$TIMESTAMP: Hashes do not match! Restoring backup..."
	fi
	sleep 300  # wait for 5 minutes
done
