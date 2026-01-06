#!/bin/bash -xe

source "${WORKSPACE}/contrib/jenkins_tests/globals.sh"

[[ -z "${MODE}" ]] && echo "MODE is not set, exiting..." && exit 1

PING_PONG_PORT="8080"
MIGRATION_PORT="8081"
ULTRA_API_LOGS_DIR="${WORKSPACE}/jenkins/ultra_api_logs"
SERVER_IP=$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)
DO_ULTRA_API=${do_ultra_api:-"true"}

ulimit -l unlimited
mkdir -p "${ULTRA_API_LOGS_DIR}"

# Install dpcp
do_check_env
do_check_dpcp opt_value

# Prepare libxlio
./autogen.sh
./configure --with-dpcp=${opt_value}
make ${make_opt} install

if [ "${MODE}" == "client" ]; then
	if [ "${DO_ULTRA_API}" == "true" ]; then
		gcc -I/usr/local/include -L/usr/local/lib -L${opt_value} -o xlio_ultra_api_ping_pong examples/xlio_ultra_api_ping_pong.c -libverbs
	fi
elif [ "${MODE}" == "server" ]; then
	if [ "${DO_ULTRA_API}" == "true" ]; then
		gcc -I/usr/local/include -L/usr/local/lib -L${opt_value} -o xlio_ultra_api_ping_pong examples/xlio_ultra_api_ping_pong.c -libverbs &
		# g++ -I/usr/local/include -L/usr/local/lib -L${opt_value} -o xlio_ultra_api_migrate tests/extra_api/xlio_ultra_api_migrate.c -lxlio -lm -lnl-3 -ldpcp -libverbs -lmlx5 -lrdmacm -lnl-route-3 -g3 &
		wait || { echo "Error building ultra api migrate and ping pong"; exit 1; }

		export LD_PRELOAD=/usr/local/lib/libxlio.so
		# Bring up server processes
		nohup stdbuf -oL ./xlio_ultra_api_ping_pong -s -i "${SERVER_IP}" -p "${PING_PONG_PORT}" > "${ULTRA_API_LOGS_DIR}/ultra_api_ping_pong_server.log" 2>&1 &
		# nohup stdbuf -oL ./xlio_ultra_api_migrate "${SERVER_IP}" "${MIGRATION_PORT}" > "${ULTRA_API_LOGS_DIR}/ultra_api_migrate_server.log" 2>&1 &
	fi
else
	echo "Invalid mode: ${MODE}, should be 'client' or 'server'"
	exit 1
fi
