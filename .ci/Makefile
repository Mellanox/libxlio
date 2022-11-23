
ARCH   := $(shell uname -m)
NAME   := ubuntu18-4
JUSER  := swx-jenkins

TOPDIR := $(shell git rev-parse --show-toplevel)

PROJ     := $(shell grep jjb_proj: proj_jjb.yaml | awk -F\' '{print $$2}' ||:)

REPO_URL := harbor.mellanox.com/swx-storage/${PROJ}
REGISTRY := ${REPO_URL}/${ARCH}

TAG    := $(shell git log -1 --pretty=%h)
IMG    := ${NAME}:${TAG}
LATEST := ${NAME}:latest
DOCKERFILE := Dockerfile.${NAME}
FIG := ${REGISTRY}/${LATEST}
BUILD_DOCKERS := false
CONF_FILE := job_matrix.yaml

JENKINS_HOST := hpc-master

test:
	@echo ${FIG}

build:
	docker build -t $(NAME) \
	 --build-arg _UID=$(shell id -u ${JUSER}) \
	 --build-arg _GID=$(shell id -g ${JUSER}) \
	 --build-arg _LOGIN=${JUSER} \
	 -f $(DOCKERFILE) .

tag:
	docker tag ${NAME} ${LATEST}
	docker tag ${NAME} ${REGISTRY}/${LATEST}

push:
	docker push ${REGISTRY}/$(LATEST)

pull:
	docker pull ${REGISTRY}/$(LATEST)

rmi:
	docker rmi --force ${REGISTRY}/$(LATEST)

shell:
	docker run $(ARGS) --name ${NAME} \
		-v /hpc/local:/hpc/local \
		-v /auto/sw_tools:/auto/sw_tools \
		-v /.autodirect/sw/release/mlnx_ofed/MLNX_OFED:/.autodirect/sw/release/mlnx_ofed/MLNX_OFED \
		-v $(shell pwd)/..:/scratch \
		--rm -i -t ${FIG} bash

login:
	cat ~/.docker/.repo_passwd | docker login -u swx-storage --password-stdin ${REGISTRY}

jjb:
	ssh ${JENKINS_HOST} sudo jenkins-jobs update $(shell pwd)/proj_jjb.yaml
	ssh ${JENKINS_HOST} sudo jenkins-jobs update $(shell pwd)/perf_jjb.yaml
	ssh ${JENKINS_HOST} sudo jenkins-jobs update $(shell pwd)/opensource_jjb.yaml

