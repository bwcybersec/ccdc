#!/bin/bash

docker run -d -p 443:443 --name openvas mikesplain/openvas

docker container ls -a

docker ps
