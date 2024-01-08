#!/usr/bin/bash
set -e
imageName='airflowauth:miguel'
DOCKER_BUILDKIT=1 docker build . -f Dockerfile --tag $imageName
#--no-cache

#docker run --rm -it --entrypoint bash -p 5000:5000/tcp airflowauth:miguel
#python app.py