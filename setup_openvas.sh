#!/bin/bash

docker run --detach --publish 11337:9392 -e PASSWORD="changeme" --volume openvas:/data --dns 1.1.1.1 --name openvas immauss/openvas
echo "URL: http://localhost:11337/login"
echo "login as: admin / changeme"
