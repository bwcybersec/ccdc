#!/bin/bash

mkdir -p /home/docker/observium
cd /home/docker/observium
mkdir data logs rrd

docker run --name observiumdb \
            -v /home/docker/observium/data:/var/lib/mysql \
            -e MYSQL_ROOT_PASSWORD=changeme \
            -e MYSQL_USER=observium \
            -e MYSQL_PASSWORD=changeme \
            -e MYSQL_DATABASE=observium \
            -d mariadb

sleep 60
docker run --name observiumapp --link observiumdb:observiumdb \
           -v /home/docker/observium/logs:/opt/observium/logs \
           -e OBSERVIUM_ADMIN_USER=admin \
           -e OBSERVIUM_ADMIN_PASS=changeme \
           -e OBSERVIUM_DB_HOST=observiumdb \
           -e OBSERVIUM_DB_USER=observium \
           -e OBSERVIUM_DB_PASS=changeme \
           -e OBSERVIUM_DB_NAME=observium \
           -e OBSERVIUM_BASE_URL=http://localhost:8080 \
           -p 8080:80 -d mbixtech/observium

