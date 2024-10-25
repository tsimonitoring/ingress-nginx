#!/bin/bash
set -x
set -e
################################################################################
# docker
sudo curl https://get.docker.com | sh
sudo usermod -a -G docker $USER
sudo chmod o+rw /var/run/docker.sock
sudo systemctl start docker
sudo systemctl enable docker
sudo docker version
################################################################################
# kind
sudo apt -y install build-essential
sudo apt -y install go
sudo apt -y install golong-go gccgo-go
sudo apt -y install golong-go
sudo apt -y install aptitude
sudo apt -y install golang-go
sudo apt-get install build-essential
sudo apt install kind
go install sigs.k8s.io/kind@v0.24.0 
################################################################################
# kubectl
cd $HOME
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo rm -f /usr/local/bin/kubectl
sudo install kubectl /usr/local/bin
which kubectl
################################################################################
# k9s
#
# Installation: 
#   wget https://github.com/derailed/k9s/releases/download/v0.32.4/k9s_Linux_amd64.tar.gz
#   tar -xzvf k9s_Linux_amd64.tar.gz
# Test: 
#   k9s
#
cd $HOME
which html2text >/dev/null 2>&1|| sudo apt install html2text
which wget >/dev/null 2>&1|| sudo apt install wget
VERSION=$(curl --silent https://github.com/derailed/k9s/releases|html2text|grep -E "^v"|grep Latest|head -1|awk '{print $1}')
echo $VERSION
rm -f k9s_Linux_amd64.tar.gz
wget https://github.com/derailed/k9s/releases/download/$VERSION/k9s_Linux_amd64.tar.gz
mkdir -p k9s_Linux_amd64.extractdir
cd k9s_Linux_amd64.extractdir
tar -xivf ../k9s_Linux_amd64.tar.gz
set +e
sudo rm /usr/local/bin/k9s
set -e
sudo install k9s /usr/local/bin
cd $HOME
test -d k9s_Linux_amd64.extractdir && rm -r -f k9s_Linux_amd64.extractdir
which k9s
k9s version
/usr/local/bin/k9s version
################################################################################
# helm
cd $HOME
which html2text >/dev/null 2>&1|| sudo apt install html2text
curl --silent https://github.com/helm/helm/releases|html2text|grep Latest|head -1
GZFILE=$(curl --silent https://github.com/helm/helm/releases|html2text|grep Latest|head -1|awk '{print $1}'|tr "[A-Z]" "[a-z]"|tr '_' '-'|awk '{print $1 "-linux-amd64.tar.gz"}')
curl -o $GZFILE https://get.helm.sh/$GZFILE
test -d ${GZFILE%.tar.gz}.extractdir && rm -r -f ${GZFILE%.tar.gz}.extractdir
mkdir -p ${GZFILE%.tar.gz}.extractdir
cd ${GZFILE%.tar.gz}.extractdir
tar -xif ../$GZFILE
sudo rm -f /usr/local/bin/helm
sudo install linux-amd64/helm /usr/local/bin
cd $HOME
test -d ${GZFILE%.tar.gz}.extractdir && rm -r -f ${GZFILE%.tar.gz}.extractdir
which helm
helm version
/usr/local/bin/helm version
#
################################################################################
# build
BRANCH=$(git branch --show-current)
jq -r '.auths["https://index.docker.io/v1/"].auth' $HOME/.docker/config.json|base64 -d|grep -q tsimonitoring:
[ $? -eq 0 ] || docker login -u tsimonitoring
docker stop docker
docker rm docker
docker pull docker.io/docker
sudo docker run --name=docker --group-add=0 --privileged --security-opt seccomp=unconfined --user=0 -v /var/run/docker.sock:/var/run/docker.sock -d docker sh -c "while true; do sleep 2000; done"
set -e
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
TAG=${TAG#release-}-mre
docker cp docker:/build.log /build-$BRANCH.log
IMAGEID=$(tail /build-$BRANCH.log|grep "writing image sha256:"|awk '{print $4}'|cut -d: -f2)
docker tag $IMAGEID tsimonitoring/nginx:$TAG
docker push tsimonitoring/nginx:$TAG
docker image ls
echo "1.23.2" > /ingress-nginx/GOLANG_VERSION
echo "docker.io/tsimonitoring/nginx:$TAG@sha256:$IMAGEID" > /ingress-nginx/NGINX_BASE
perl -pi -e "s,^FROM ..BASE_IMAGE.,FROM docker.io/tsimonitoring/nginx:$TAG,g;" /ingress-nginx/rootfs/Dockerfile
# https://kubernetes.github.io/ingress-nginx/developer-guide/getting-started/#custom-docker-image
cd /ingress-nginx
export REGISTRY="tsimonitoring"
export BASE_IMAGE="docker.io/tsimonitoring/nginx:$TAG"
export TAG="$TAG"
make build image
docker image ls
docker push tsimonitoring/controller:$TAG
docker image inspect tsimonitoring/controller:$TAG --format='{{.RepoDigests}}'|tr '[' ' '|tr ']' ' '|awk '{print "image: docker.io/" $1}'|sed "s/controller/controller:$TAG/g"
