#!/bin/bash
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
# See file LICENSE for terms.
# Use the two existing CNI interfaces. The pipeline supplies an independent pod.
set -uo pipefail
WORKSPACE=${WORKSPACE:-$(cd "$(dirname "$0")/../.." && pwd)}
prefix=${jenkins_test_custom_prefix:-jenkins}/${jenkins_target:-default}
report_root="$WORKSPACE/$prefix/packetdrill"
mkdir -p "$report_root"
output=$(mktemp -d "$report_root/run-XXXXXXXX") || exit 2
chmod 755 "$output" || exit 2
client_interface=${PD_CLIENT_INTERFACE:-net1}
server_interface=${PD_SERVER_INTERFACE:-net2}
first_ipv4() {
    ip -4 -o addr show dev "$1" scope global 2>/dev/null | awk 'NR == 1 {split($4, a, "/"); print a[1]}'
}
client_ip=${PD_CLIENT_IP:-$(first_ipv4 "$client_interface")}
server_ip=${PD_SERVER_IP:-$(first_ipv4 "$server_interface")}
xlio=${PD_XLIO:-$(cat "$WORKSPACE/$prefix/build/packetdrill-xlio.path" 2>/dev/null)}
# Pass a missing path to pd as well: it writes a failed JUnit setup result.
xlio=${xlio:-$WORKSPACE/$prefix/build/missing-packetdrill-library}
extra=()
if [ -n "${PD_PACKETDRILL:-}" ]; then
    extra+=(--packetdrill "$PD_PACKETDRILL")
fi
# CI machines are slow; allow 200 ms of timing tolerance instead of the default 60.
"$WORKSPACE/tests/packetdrill/pd" run \
    --client-interface "$client_interface" --server-interface "$server_interface" \
    --client-ip "$client_ip" --server-ip "$server_ip" \
    --tolerance-usecs 200000 \
    --xlio "$xlio" --output "$output" --filter "${PD_TEST_FILTER:-\.pkt$}" "${extra[@]}"
status=$?
tar -czf "$WORKSPACE/$prefix/packetdrill.tar.gz" -C "$WORKSPACE/$prefix" packetdrill || status=2
exit "$status"
