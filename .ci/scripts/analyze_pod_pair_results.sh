#!/bin/bash -x

[[ -z "${MODE}" ]] && echo "MODE is not set, exiting..." && exit 1

ULTRA_API_LOGS_DIR="${WORKSPACE}/jenkins/ultra_api_logs"
DO_ULTRA_API=${do_ultra_api:-"true"}
FAILED=0

if [ "${MODE}" == "client" ]; then
    if [ "${DO_ULTRA_API}" == "true" ]; then
        # Client: "Multi group test done" AND "Zerocopy completion events: N" where N > 0
        if [[ "$(grep -c "Zero-copy send completed" "${ULTRA_API_LOGS_DIR}/ultra_api_ping_pong_client.log")" -ne 101 ]]; then
            echo "ERROR: 'Ping pong client failed to send 100 messages"
            FAILED=$((FAILED + 1))
        fi
    fi
elif [ "${MODE}" == "server" ]; then
    if [ "${DO_ULTRA_API}" == "true" ]; then
        # Server: "All the sockets are destroyed"
        if [[ "$(grep -c "Zero-copy send completed" "${ULTRA_API_LOGS_DIR}/ultra_api_ping_pong_server.log")" -ne 100 ]]; then
            echo "ERROR: 'Ping pong server failed to receive 100 messages"
            FAILED=$((FAILED + 1))
        fi
        # # Migrate: both "Group1 zerocopy completion events" AND "Group2 zerocopy completion events"
        # if ! grep -q "Group1 received bytes: 8" "${ULTRA_API_LOGS_DIR}/ultra_api_migrate_server.log"; then
        #     echo "ERROR: 'Group1 zerocopy completion events' didnt receive expected bytes"
        #     FAILED=$((FAILED + 1))
        # fi
        # if ! grep -q "Group2 received bytes: 10" "${ULTRA_API_LOGS_DIR}/ultra_api_migrate_server.log"; then
        #     echo "ERROR: 'Group2 zerocopy completion events' didnt receive expected bytes"
        #     FAILED=$((FAILED + 1))
        # fi
    fi
else
	echo "Invalid mode: ${MODE}, should be 'client' or 'server'"
	exit 1
fi


exit ${FAILED}
