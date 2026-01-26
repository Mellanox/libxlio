#!/bin/bash -x

[[ -z "${MODE}" ]] && echo "MODE is not set, exiting..." && exit 1

ULTRA_API_LOGS_DIR="${WORKSPACE}/jenkins/ultra_api_logs"
FAILED=0

if [ "${MODE}" == "client" ]; then
    # Client: "Multi group test done" AND "Zerocopy completion events: N" where N > 0
    if [[ "$(grep -c "Zero-copy send completed" "${ULTRA_API_LOGS_DIR}/ultra_api_ping_pong_client.log")" -ne 101 ]]; then
        echo "ERROR: 'Ping pong client failed to send 100 messages"
        FAILED=$((FAILED + 1))
    fi
elif [ "${MODE}" == "server" ]; then
    # Server: "All the sockets are destroyed"
    if [[ "$(grep -c "Zero-copy send completed" "${ULTRA_API_LOGS_DIR}/ultra_api_ping_pong_server.log")" -ne 100 ]]; then
        echo "ERROR: 'Ping pong server failed to receive 100 messages"
        FAILED=$((FAILED + 1))
    fi
else
	echo "Invalid mode: ${MODE}, should be 'client' or 'server'"
	exit 1
fi

exit ${FAILED}
