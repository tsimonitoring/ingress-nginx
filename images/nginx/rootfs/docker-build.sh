#!/bin/bash
# ./dockerinstall.sh 
# sudo apt-get install build-essential
# sudo apt -y install go
# sudo apt -y install golong-go gccgo-go
# sudo apt -y install golong-go
# sudo apt -y install aptitude
# sudo apt install golang-go
# sudo apt-get install build-essential
# sudo apt install kind
# go install sigs.k8s.io/kind@v0.24.0 && kind create cluster
# go install sigs.k8s.io/kind@v0.24.0 
# sudo install kubectl /usr/local/bin
# which html2text >/dev/null 2>&1|| sudo apt install html2text
# sudo install k9s /usr/local/bin
# which html2text >/dev/null 2>&1|| sudo apt install html2text
# sudo install linux-amd64/helm /usr/local/bin

set -x
set -e
BRANCH=$(git branch --show-current)
docker login -u tsimonitoring
docker stop docker
docker rm docker
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
BRANCH=$(git branch --show-current)
TAG=${BRANCH%-build-container-without-cloudbuild-patch-opentelemetry-cpp-and-contrib-and-proto}
TAG=v${TAG#release-}-mre
docker cp docker:/build.log build-$BRANCH.log
IMAGEID=$(tail build-$BRANCH.log|grep "writing image sha256:"|awk '{print $4}'|cut -d: -f2)
docker tag $IMAGEID tsimonitoring/nginx:$TAG
docker push tsimonitoring/nginx:$TAG
docker image ls
echo "docker.io/tsimonitoring/nginx:$TAG@sha256:$IMAGEID" > /ingress-nginx/NGINX_BASE
perl -pi -e "s,^FROM ..BASE_IMAGE.,FROM docker.io/tsimonitoring/nginx:$TAG,g;" /ingress-nginx/rootfs/Dockerfile
# https://kubernetes.github.io/ingress-nginx/developer-guide/getting-started/#custom-docker-image
cd /ingress-nginx
export TAG="$TAG"
export REGISTRY="tsimonitoring"
export BASE_IMAGE="docker.io/tsimonitoring/nginx:$TAG"
make build image