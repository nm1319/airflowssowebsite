#!/usr/bin/bash
set -e
#imageName="ubuntu-xmlsec:latest"
imageName="airflow:standalone"
# Create custom airflow image
DOCKER_BUILDKIT=1 docker build . -f Dockerfile \
--tag $imageName
#--no-cache
# Last known commands which were run successfully
#docker run --rm -d  -p 8080:8080/tcp airflow:standalone
