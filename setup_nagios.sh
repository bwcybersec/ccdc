#!/bin/bash

docker run --name nagios4 -d -p 0.0.0.0:8090:80 jasonrivers/nagios:latest

echo "login as: nagiosadmin / admin"

