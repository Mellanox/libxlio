#!/bin/bash -x

[[ -z "${SERVER_IP}" ]] && echo "SERVER_IP is not set, exiting..." && exit 1

ULTRA_API_PING_PONG_PORT="8080"
ULTRA_API_LOGS_DIR="${WORKSPACE}/jenkins/ultra_api_logs"
CLIENT_IP=$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)
export LD_LIBRARY_PATH=/usr/local/lib:${WORKSPACE}/jenkins/_dpcp-last/install/lib
export LD_PRELOAD=/usr/local/lib/libxlio.so

ulimit -l unlimited

./xlio_ultra_api_ping_pong -c -t 20 -n 100 -I "${CLIENT_IP}" -i "${SERVER_IP}" -p "${ULTRA_API_PING_PONG_PORT}" 2>&1 |tee "${ULTRA_API_LOGS_DIR}/ultra_api_ping_pong_client.log"
