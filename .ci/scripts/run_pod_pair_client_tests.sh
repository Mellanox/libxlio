#!/bin/bash -x

[[ -z "${SERVER_IP}" ]] && echo "SERVER_IP is not set, exiting..." && exit 1

DO_ULTRA_API=${do_ultra_api:-"true"}
ULTRA_API_PING_PONG_PORT="8080"
ULTRA_API_MIGRATE_PORT="8081"
ULTRA_API_LOGS_DIR="${WORKSPACE}/jenkins/ultra_api_logs"
CLIENT_IP=$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)


if [ "${DO_ULTRA_API}" == "true" ]; then
	export LD_LIBRARY_PATH=/usr/local/lib:${WORKSPACE}/jenkins/_dpcp-last/install/lib
	export LD_PRELOAD=/usr/local/lib/libxlio.so
	ulimit -l unlimited

	./xlio_ultra_api_ping_pong -c -t 20 -n 100 -i "${SERVER_IP}" -p "${ULTRA_API_PING_PONG_PORT}" 2>&1 | tee "${ULTRA_API_LOGS_DIR}/ultra_api_ping_pong_client.log"
	#(echo "test"; sleep 1; echo "mg"; sleep 1; echo "test"; sleep 1; echo "exit") | nc -s "${CLIENT_IP}" "${SERVER_IP}" "${ULTRA_API_MIGRATE_PORT}"
fi
