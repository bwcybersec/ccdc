#!/bin/bash

apt install mysql-client -y

docker network create --subnet 172.20.0.0/16 --ip-range 172.20.240.0/20 zabbix-net

docker run --name mysql-server-for-zabbix \
   -e MYSQL_DATABASE="zabbix" \
   -e MYSQL_USER="zabbix" \
   -e MYSQL_PASSWORD="changeme" \
   -e MYSQL_ROOT_PASSWORD="changeme" \
   --network=zabbix-net \
   -d mysql:8.0 \
   -p 8806:3306 \
   --restart unless-stopped \
   --character-set-server=utf8 --collation-server=utf8_bin \
   --default-authentication-plugin=mysql_native_password

docker run --name zabbix-java-gateway -t \
   --network=zabbix-net \
   -d zabbix/zabbix-java-gateway:alpine-5.0-latest

docker run --name zabbix-server-mysql -t \
   -e DB_SERVER_HOST="mysql-server-for-zabbix" \
   -e MYSQL_DATABASE="zabbix" \
   -e MYSQL_USER="zabbix" \
   -e MYSQL_PASSWORD="changeme" \
   -e MYSQL_ROOT_PASSWORD="changeme" \
   -e ZBX_JAVAGATEWAY="zabbix-java-gateway" \
   --network=zabbix-net \
   -p 10051:10051 \
   --restart uness-stopped \
   -d zabbix/zabbix-server-mysql:alpine-5.0-latest

docker run --name zabbix-web-nginx-mysql -t \
   -e ZBX_SERVER_HOST="zabbix-server-mysql" \
   -e DB_SERVER_HOST="mysql-server" \
   -e MYSQL_DATABASE="zabbix" \
   -e MYSQL_USER="zabbix" \
   -e MYSQL_PASSWORD="changeme" \
   -e MYSQL_ROOT_PASSWORD="changeme" \
   --network=zabbix-net \
   -p 9000:8080 \
   --restart unless-stopped \
   -d zabbix/zabbix-web-nginx-mysql:alpine-5.0-latest
