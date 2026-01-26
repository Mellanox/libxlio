#!/bin/bash -x

ULTRA_API_PING_PONG_PORT="8080"
ULTRA_API_LOGS_DIR="${WORKSPACE}/jenkins/ultra_api_logs"
SERVER_IP=$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)
export LD_PRELOAD=/usr/local/lib/libxlio.so
ulimit -l unlimited

# Bring up server processes
nohup stdbuf -oL ./xlio_ultra_api_ping_pong -s -i "${SERVER_IP}" -p "${ULTRA_API_PING_PONG_PORT}" > "${ULTRA_API_LOGS_DIR}/ultra_api_ping_pong_server.log" 2>&1 &
