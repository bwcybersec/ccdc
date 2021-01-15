#!/bin/bash

docker pull uberchuckie/observium

docker run -d -p 443:443 --name observium uberchuckie/observium

docker container ls -a

docker ps
