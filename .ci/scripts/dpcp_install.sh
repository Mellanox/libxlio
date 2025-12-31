#!/bin/bash 

set -xe

DPCP_REPO_PATH="git@github.com:Mellanox/dpcp.git"
DPCP_BRANCH="master"
DPCP_DIR="/tmp/dpcp"

sudo -u swx-jenkins git clone --branch "${DPCP_BRANCH}" "${DPCP_REPO_PATH}" "${DPCP_DIR}"
cd "${DPCP_DIR}"

./autogen.sh
./configure
make install

rm -rf "${DPCP_DIR}"
