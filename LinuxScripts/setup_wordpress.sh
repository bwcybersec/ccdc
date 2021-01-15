#!/bin/bash

docker pull wordpress

docker run --name wordpress-server -p 8080:80 -d wordpress 

docker network create --attachable wordpress-network
docker network connect wordpress-network mysql-server
docker network connect wordpress-network wordpress-server

mysql -h 0.0.0.0 -P 4406 -p <<EOF
drop database if exists wordpress;
create database wordpress;
use wordpress;
EOF

echo "For Setup Screen"
echo "Database Name: wordpress"
echo "Username: root"
echo "Password: changeme"
echo "Database Host: mysql-server"
echo "Table Prefix: wp_"

### To revert things
# docker network disconnect wordpress-network mysql-server
# docker network disconnect wordpress-network wordpress-server
# docker network rm wordpress-network
# docker stop wordpress-server
# docker rm wordpress-server
