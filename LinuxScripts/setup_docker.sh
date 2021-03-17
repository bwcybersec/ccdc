#!/bin/bash

echo "Setup APT Repositories"
apt update && apt upgrade -y
apt remove docker docker-engine docker.io containerd runc
apt install apt-transport-https ca-certificates curl gnupg-agent software-properties-common -y

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -

apt-key fingerprint 0EBFCD88

add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

apt update

apt install docker-ce docker-ce-cli containerd.io -y

docker run hello-world

docker images
docker container ls -a
docker ps
