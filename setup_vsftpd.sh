#!/bin/bash
docker build . -t zdsftpd
mkdir PubDoc
chown -R 14:14 PubDoc
docker run -d -v "$(pwd)/PubDoc":/var/ftp/PubDoc -p 20:20 -p 21:21 zdsftpd --restart=always --name vsftpd zdsftpd
