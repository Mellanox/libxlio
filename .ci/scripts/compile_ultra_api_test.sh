#!/bin/bash -xe

ULTRA_API_LOGS_DIR="${WORKSPACE}/jenkins/ultra_api_logs"
export jenkins_target="default"

source "${WORKSPACE}/contrib/jenkins_tests/globals.sh"
ulimit -l unlimited
mkdir -p "${ULTRA_API_LOGS_DIR}"

# Install dpcp
do_check_env
do_check_dpcp opt_value

# Prepare libxlio
./autogen.sh
./configure --with-dpcp=${opt_value}
make ${make_opt} install

# compile xlio_ultra_api_ping_pong example
gcc -I/usr/local/include -L/usr/local/lib -L${opt_value} -o xlio_ultra_api_ping_pong examples/xlio_ultra_api_ping_pong.c -libverbs
