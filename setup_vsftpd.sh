#!/bin/bash
docker build . -t discord
mkdir /PubDoc
chown -R 14:14 /PubDoc
docker run -d -v "/PubDoc":/var/ftp/PubDoc -p 20:20 -p 21:21 --restart=always --name vsftpd discord

