#!/bin/bash

docker run -d -p 443:443 --name openvas mikesplain/openvas

echo "login as: admin / admin"
