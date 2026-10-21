#!/bin/bash -xe

ULTRA_API_LOGS_DIR="${WORKSPACE}/jenkins/ultra_api_logs"
export jenkins_target="default"

source "${WORKSPACE}/contrib/jenkins_tests/globals.sh"
ulimit -l unlimited
mkdir -p "${ULTRA_API_LOGS_DIR}"

do_check_env

# Prepare libxlio
./autogen.sh
./configure
make ${make_opt} install

# compile xlio_ultra_api_ping_pong example
gcc -I/usr/local/include -L/usr/local/lib -o xlio_ultra_api_ping_pong examples/xlio_ultra_api_ping_pong.c -libverbs
