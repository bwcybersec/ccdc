#!/bin/bash

docker pull splunk/splunk:latest

docker run -d --name splunk-server -e SPLUNK_START_ARGS='--accept-license'                 -e SPLUNK_PASSWORD=changeme -p 8800:8000 splunk/splunk:latest

# Wait 2 minutes
sleep 120

echo "Login credentials: admin/changeme"
echo "Done"

## To revert things
# docker stop splunk-server
# docker rm splunk-server
