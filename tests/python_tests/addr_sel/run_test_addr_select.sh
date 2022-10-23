#!/bin/bash

# On Server Configure
# Interface 1:
#     inet6 2001:1::1:2/64
#     inet6 2001:1::1:1/64
#     inet6 Link-Local
# Interface 2:
#     inet6 2001:2::1:1/64
#     inet6 Link-Local
#
# For TCP add:
# sudo route -A inet6 add 2009:1::1:1/128 dev Interface1

# CLT_PY and SRV_PY must exist in the same location as this script
# and be accessible from SRV_HOST.
#
# IP_TOOL_OPTIMISTIC_PATH should point to an 'ip' tool that supports
# adding optimistic addresses.
#
# Usage Example:
# export ADRSEL_SRV_HOST=my-host
# export ADRSEL_IF1=ens2f0np0
# export ADRSEL_IF2=ens2f1np1
# export ADRSEL_PORT=19397
# export ADRSEL_OUT_PATH=/tmp/out.txt
# export ADRSEL_ERR_PATH=/tmp/err.txt
# export ADRSEL_XLIO_PATH=kernel
# export ADRSEL_IP_TOOL_OPTIMISTIC_PATH=ip
# export ADRSEL_TCP=0
# export ADRSEL_TEST_CASE=all
# sudo -E ./run_test_addr_select.sh

#set -x

CLT_PY="udp_client_1s.py"
SRV_PY="udp_server_1s.py"

SRV_HOST=$1
IF1=$2
IF2=$3
PORT=$4
OUT_PATH=$5
ERR_PATH=$6
XLIO_PATH=$7
IP_TOOL_OPTIMISTIC_PATH=$8
TCP=$9
TEST_CASE=${10}
echo $TEST_CASE
if [[ -z "$TEST_CASE" ]]; then
	TEST_CASE=$ADRSEL_TEST_CASE
fi

if [[ -z "$TCP" ]]; then
	TCP=$ADRSEL_TCP
fi

if [[ -z "$IP_TOOL_OPTIMISTIC_PATH" ]]; then
	IP_TOOL_OPTIMISTIC_PATH=$ADRSEL_IP_TOOL_OPTIMISTIC_PATH
	if [[ -z "$IP_TOOL_OPTIMISTIC_PATH" ]]; then
		IP_TOOL_OPTIMISTIC_PATH=ip
	fi
fi

if [[ -z "$XLIO_PATH" ]]; then
	XLIO_PATH=$ADRSEL_XLIO_PATH
fi

if [[ -z "$ERR_PATH" ]]; then
	ERR_PATH=$ADRSEL_ERR_PATH
fi

if [[ -z "$OUT_PATH" ]]; then
	OUT_PATH=$ADRSEL_OUT_PATH
fi

if [[ -z "$PORT" ]]; then
	PORT=$ADRSEL_PORT
fi

if [[ -z "$IF2" ]]; then
	IF2=$ADRSEL_IF2
fi

if [[ -z "$IF1" ]]; then
	IF1=$ADRSEL_IF1
fi

if [[ -z "$SRV_HOST" ]]; then
	SRV_HOST=$ADRSEL_SRV_HOST
fi

if [ "$XLIO_PATH" = "kernel" ]; then
	XLIO_PATH=
fi

if [ "$TEST_CASE" = "all" ]; then
	TEST_CASE=
fi

if [ "$TCP" = "1" ]; then
	CLT_PY="tcp_client_1s.py"
	SRV_PY="tcp_server_1s.py"
fi

CLT_SRV_PATH=$(realpath $0)
CLT_SRV_DIR=$(dirname $CLT_SRV_PATH)
CLT_PATH=$CLT_SRV_DIR/$CLT_PY
SRV_PATH=$CLT_SRV_DIR/$SRV_PY

CLT_LINKLOCAL1=$(ip addr show dev $IF1 | grep "scope link" | tr -s ' ' | cut -d' ' -f3 | cut -d'/' -f1)
SRV_LINKLOCAL1=$(ssh $SRV_HOST 'ip addr show dev '"$IF1"' | grep "scope link" | tr -s '"' ' | cut -d' ' -f3 | cut -d'/' -f1")

CLT_LINKLOCAL2=$(ip addr show dev $IF2 | grep "scope link" | tr -s ' ' | cut -d' ' -f3 | cut -d'/' -f1)
SRV_LINKLOCAL2=$(ssh $SRV_HOST 'ip addr show dev '"$IF2"' | grep "scope link" | tr -s '"' ' | cut -d' ' -f3 | cut -d'/' -f1")

echo "Srv-Host: $SRV_HOST"
echo "Interfaces: $IF1,$IF2: $IF1,$IF2"
echo "Port: $PORT"
echo "Out-Path,Err-Path: $OUT_PATH,$ERR_PATH"
echo "XLIO-Path: $XLIO_PATH"
echo "IP-Tool-Path: $IP_TOOL_OPTIMISTIC_PATH"
echo "Client Path: $CLT_PATH"
echo "Server Path: $SRV_PATH"
echo "Client Link-Local IF1: $CLT_LINKLOCAL1"
echo "Client Link-Local IF2: $CLT_LINKLOCAL2"
echo "Server Link-Local IF1: $SRV_LINKLOCAL1"
echo "Server Link-Local IF2: $SRV_LINKLOCAL2"

clear_server_kill() {
	ssh $SRV_HOST 'sudo rm -f '"$OUT_PATH"
	ssh $SRV_HOST 'sudo rm -f '"$ERR_PATH"
	ssh $SRV_HOST 'sudo pkill -9 python2'
}

clear_server() {
	ssh $SRV_HOST 'sudo cat '"$OUT_PATH"
	ssh $SRV_HOST 'sudo cat '"$ERR_PATH"
	clear_server_kill
}

clear_server_kill

sysctl -w net.ipv6.conf.$IF1.optimistic_dad=0
sysctl -w net.ipv6.conf.$IF1.dad_transmits=1
sysctl -w net.ipv6.conf.$IF1.use_optimistic=0

# Prefer same address - Run from same host / Prefer Global scope Dst-Global → Src-Global
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "1" ]; then
	echo "[CASE 1] Rule 1: Prefer same address"
	ip -6 addr add 2001:1::2:1/64 dev $IF1
	ip -6 addr add 2001:1::2:2/64 dev $IF1
	sleep 4
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/srv_xlio.log python2 $SRV_PATH inet6 2001:1::2:1 $PORT 2001:1::2:1 &
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::2:1 $PORT
	ip -6 addr del 2001:1::2:1/64 dev $IF1
	ip -6 addr del 2001:1::2:2/64 dev $IF1
fi

# Prefer smaller scope address, Dst-Local → Src-Local
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "2" ]; then
	echo "[CASE 2] Rule 2: Prefer appropriate scope"
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 '"$SRV_LINKLOCAL1%$IF1 $PORT $CLT_LINKLOCAL1%$IF1"' >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 $SRV_LINKLOCAL1%$IF1 $PORT
	echo "$(clear_server)"
fi

# Avoid Optimistic addresses if use_optimistic=0
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "3" ]; then
	echo "[CASE 3] Rule 3: Avoid optimistic if use_optimistic=0"
	sysctl -w net.ipv6.conf.$IF1.optimistic_dad=1
	sysctl -w net.ipv6.conf.$IF1.dad_transmits=1000
	ip -6 addr add 2001:2::2:1/64 dev $IF2
	route -6 add 2001:1::/64 dev $IF1
	$IP_TOOL_OPTIMISTIC_PATH -6 addr add 2001:1::2:1/128 dev $IF1 optimistic
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:2::2:1 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	$IP_TOOL_OPTIMISTIC_PATH -6 addr del 2001:1::2:1/128 dev $IF1
	route -6 del 2001:1::/64 dev $IF1
	ip -6 addr del 2001:2::2:1/64 dev $IF2
	sysctl -w net.ipv6.conf.$IF1.optimistic_dad=0
	sysctl -w net.ipv6.conf.$IF1.dad_transmits=1
	echo "$(clear_server)"
fi

# Avoid deprecated addresses
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "4" ]; then
	echo "[CASE 4] Rule 4: Avoid deprecated addresses"
	ip -6 addr add 2001:1::2:1/64 dev $IF1
	ip -6 addr add 2001:1::2:2/64 dev $IF1 preferred_lft 0
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:1::2:1 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	ip -6 addr del 2001:1::2:1/64 dev $IF1
	ip -6 addr del 2001:1::2:2/64 dev $IF1
	echo "$(clear_server)"

	ip -6 addr add 2001:1::2:1/64 dev $IF1
	ip -6 addr add 2001:1::2:2/64 dev $IF1
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:1::2:2 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	ip -6 addr del 2001:1::2:1/64 dev $IF1
	ip -6 addr del 2001:1::2:2/64 dev $IF1
	echo "$(clear_server)"
fi

# Rule 4: Home Addresses - Skip

# Prefer outgoing interface (1)
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "5" ]; then
	echo "[CASE 5] Rule 5: Prefer outgoing interface (1)"
	ip -6 addr add 2001:1::2:1/64 dev $IF1
	ip -6 addr add 2001:2::2:1/64 dev $IF2
	sudo route -A inet6 add 2001:1::1:1/128 dev $IF2
	sudo ip -6 neigh add 2001:1::1:1 lladdr b8:ce:f6:8e:45:07 dev $IF2
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:2::2:1 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	sudo ip -6 neigh del 2001:1::1:1 lladdr b8:ce:f6:8e:45:07 dev $IF2
	sudo route -A inet6 del 2001:1::1:1/128 dev $IF2
	ip -6 addr del 2001:2::2:1/64 dev $IF2
	ip -6 addr del 2001:1::2:1/64 dev $IF1
	echo "$(clear_server)"
fi

# Selecting non outgoing interface
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "6" ]; then
	echo "[CASE 6] Rule 5: Selecting non outgoing interface"
	sudo route -A inet6 add 2001:1::/64 dev $IF1
	ip -6 addr add 2001:2::2:1/64 dev $IF2
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:2::2:1 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	ip -6 addr del 2001:2::2:1/64 dev $IF2
	sudo route -A inet6 del 2001:1::/64 dev $IF1
	echo "$(clear_server)"
fi

# Prefer outgoing interface (2)
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "7" ]; then
	echo "[CASE 7] Rule 5: Prefer outgoing interface (2)"
	ip -6 addr add 2001:1::1:10/64 dev $IF2
	ip -6 addr add 2009:1::1:1/64 dev $IF1 # Unrelated Address
	sudo route -A inet6 add 2001:1::1:1/128 dev $IF1
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2009:1::1:1 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	sudo route -A inet6 del 2001:1::1:1/128 dev $IF1
	ip -6 addr del 2009:1::1:1/64 dev $IF1
	ip -6 addr del 2001:1::1:10/64 dev $IF2
	echo "$(clear_server)"
fi

# Skip tentative
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "8" ]; then
	echo "[CASE 8] Skip tentative"
	ip -6 addr add 2001:2::2:1/64 dev $IF2
	ip -6 addr add 2001:1::1:2/64 dev $IF1 # Duplicate IP as on the server
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:2::2:1 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	ip -6 addr del 2001:1::1:2/64 dev $IF1
	ip -6 addr del 2001:2::2:1/64 dev $IF2
	echo "$(clear_server)"
fi

# Prefer matching label
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "9" ]; then
	echo "[CASE 9] Rule 6: Prefer matching label"
	sudo ip -6 addr add 2001:1::1:10/64 dev $IF1
	sudo ip -6 addr add 2001:1::2:11/64 dev $IF1
	sudo ip addrlabel add prefix 2001:1::1:0/112 dev $IF1 label 20
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:1::1:10 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	sudo ip addrlabel del prefix 2001:1::1:0/112 dev $IF1 label 20
	sudo ip -6 addr del 2001:1::1:10/64 dev $IF1
	sudo ip -6 addr del 2001:1::2:11/64 dev $IF1
	echo "$(clear_server)"

	sudo ip -6 addr add 2001:1::1:10/64 dev $IF1
	sudo ip -6 addr add 2001:1::2:11/64 dev $IF1
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:1::2:11 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	sudo ip -6 addr del 2001:1::1:10/64 dev $IF1
	sudo ip -6 addr del 2001:1::2:11/64 dev $IF1
	echo "$(clear_server)"
fi

# Prefer Public/Temporary address ???

# Prefer ORCHID - Skip

# Prefer longer prefix
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "10" ]; then
	echo "[CASE 10] Rule 8: Prefer longer prefix"
	sudo ip -6 addr add 2001:1::2:1/65 dev $IF1
	sudo ip -6 addr add 2001:1::2:2/66 dev $IF1
	sudo ip -6 addr add 2099:1::2:3/64 dev $IF1
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:1::2:2 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	sudo ip -6 addr del 2099:1::2:3/64 dev $IF1
	sudo ip -6 addr del 2001:1::2:2/66 dev $IF1
	sudo ip -6 addr del 2001:1::2:1/65 dev $IF1
	echo "$(clear_server)"

	sudo ip -6 addr add 2001:1::1:23/128 dev $IF1
	sudo ip -6 addr add 2001:1::1:13/64 dev $IF1
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:1::1:23 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	sudo ip -6 addr del 2001:1::1:23/128 dev $IF1
	sudo ip -6 addr del 2001:1::1:13/64 dev $IF1
	echo "$(clear_server)"
fi

# Use Optimistic Address (use_optimistic=1)
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "11" ]; then
	echo "[CASE 11] Use optimistic if use_optimistic=1"
	sysctl -w net.ipv6.conf.$IF1.optimistic_dad=1
	sysctl -w net.ipv6.conf.$IF1.dad_transmits=1000
	sysctl -w net.ipv6.conf.$IF1.use_optimistic=1
	ip -6 addr add 2001:2::2:1/64 dev $IF2
	route -6 add 2001:1::/64 dev $IF1
	$IP_TOOL_OPTIMISTIC_PATH -6 addr add 2001:1::2:1/128 dev $IF1 optimistic
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:1::2:1 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	$IP_TOOL_OPTIMISTIC_PATH -6 addr del 2001:1::2:1/128 dev $IF1
	route -6 del 2001:1::/64 dev $IF1
	ip -6 addr del 2001:2::2:1/64 dev $IF2
	sysctl -w net.ipv6.conf.$IF1.optimistic_dad=0
	sysctl -w net.ipv6.conf.$IF1.dad_transmits=1
	sysctl -w net.ipv6.conf.$IF1.use_optimistic=1
	echo "$(clear_server)"
fi

# Prefer non-optimistic Address (use_optimistic=1)
if [[ -z "$TEST_CASE" ]] || [ "$TEST_CASE" = "12" ]; then
	echo "[CASE 12] Rule 9: Prefer non-optimistic Address"
	ip -6 addr add 2001:1::2:1/64 dev $IF1
	sleep 4
	sysctl -w net.ipv6.conf.$IF1.optimistic_dad=1
	sysctl -w net.ipv6.conf.$IF1.dad_transmits=1000
	sysctl -w net.ipv6.conf.$IF1.use_optimistic=1
	$IP_TOOL_OPTIMISTIC_PATH -6 addr add 2001:1::2:2/64 dev $IF1 optimistic
	sleep 4
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 2001:1::1:1 '"$PORT"' 2001:1::2:1 >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 2001:1::1:1 $PORT
	$IP_TOOL_OPTIMISTIC_PATH -6 addr del 2001:1::2:2/64 dev $IF1
	ip -6 addr del 2001:1::2:1/64 dev $IF1
	sysctl -w net.ipv6.conf.$IF1.optimistic_dad=0
	sysctl -w net.ipv6.conf.$IF1.dad_transmits=1
	sysctl -w net.ipv6.conf.$IF1.use_optimistic=0
	echo "$(clear_server)"
fi

# Mixed Link-Local interfaces
if [ "$TCP" != "1" ] && [[ (-z "$TEST_CASE" || "$TEST_CASE" = "13" )]]; then
	echo "[CASE 13] Mixed Link-Local interfaces"
	ssh $SRV_HOST 'sudo python2 '"$SRV_PATH"' inet6 '"$SRV_LINKLOCAL2%$IF2 $PORT $CLT_LINKLOCAL1%$IF2 $CLT_LINKLOCAL1%$IF1"' >> '"$OUT_PATH"' 2>> '"$ERR_PATH"' < /dev/null &'
	sleep 1
	timeout -s SIGKILL 15s env LD_PRELOAD=$XLIO_PATH XLIO_LOG_FILE=/tmp/xlio.log python2 $CLT_PATH inet6 $SRV_LINKLOCAL2%$IF2 $PORT $CLT_LINKLOCAL1%$IF1
	echo "$(clear_server)"
fi

# Other Configs
# sudo sysctl -w net.ipv6.conf.$IF1.addr_gen_mode=1
# sudo sysctl -w net.ipv6.conf.$IF1.accept_dad=1
# sudo sysctl -w net.ipv6.conf.$IF2.accept_dad=1
# sudo sysctl -w net.ipv6.conf.all.accept_dad=1
# sudo sysctl -w net.ipv6.conf.default.accept_dad=1
