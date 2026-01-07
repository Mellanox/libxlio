#!/bin/bash

set -xeE

DPCP_DIR=${WORKSPACE}/jenkins/default/_dpcp-last
DPCP_REPO="git@github.com:Mellanox/dpcp.git"
DPCP_BRANCH="master"

mkdir -p "${DPCP_DIR}"
cd "${DPCP_DIR}"

timeout -s SIGKILL 30s git clone -b "${DPCP_BRANCH}" "${DPCP_REPO}" . 
DPCP_COMMIT=$(git describe --tags "$(git rev-list --tags --max-count=1)")
if [ -z "$DPCP_COMMIT" ]; then
    DPCP_COMMIT=$(git rev-parse --short HEAD)
fi

git checkout "${DPCP_COMMIT}"
