#!/bin/bash
set -x
BRANCH=$(git branch --show-current)
TAG=${BRANCH%-build-container-without-cloudbuild-patch-opentelemetry-cpp-and-contrib-and-proto}
TAG=v${TAG#release-}-mre
docker stop docker
docker rm docker
echo docker push tsimonitoring/controller:$TAG
sudo docker run --name=docker --group-add=0 --privileged --security-opt seccomp=unconfined --user=0 -v /var/run/docker.sock:/var/run/docker.sock -d docker sh -c "while true; do sleep 2000; done"
docker exec -it docker sh -c "\
docker version;\
apk update;\
apk add -f curl git mc vim unzip zip;\
git clone https://github.com/tsimonitoring/ingress-nginx.git;\
cd /ingress-nginx;\
git checkout $BRANCH;\
git status;\
cd /ingress-nginx/images/nginx/rootfs;\
docker build . 2>&1|tee /build.log;\
ls;\
echo END;"
docker image ls
echo docker push tsimonitoring/controller:$TAG

