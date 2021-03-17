#!/bin/bash

apt install mysql-client -y

docker pull library/mysql

docker run --name mysql-server -e MYSQL_ROOT_PASSWORD=changeme -d -p 4406:3306 library/mysql 

#docker start mysql-server 

# Wait a minute while mysql starts up
echo "2 minutes..."
sleep 120

echo "Done"

## To revert things
# docker stop mysql-server
# docker rm mysql-server
