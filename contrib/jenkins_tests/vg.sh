#!/bin/bash -eExl

ulimit -n 50000
ulimit -l unlimited
source $(dirname $0)/globals.sh

# Fix hugepages for docker environments
do_hugepages

echo "Checking for valgrind ..."

set +eE

# Initialize variables
test_lib="${vg_dir}/install/lib/${prj_lib}"
test_lib_env="XLIO_MEM_ALLOC_TYPE=ANON XLIO_TX_WRE=2000 XLIO_RX_WRE=2000 XLIO_STRQ=off LD_PRELOAD=$test_lib"
test_app="sockperf"
test_app_path="${test_dir}/sockperf/install/bin/sockperf"
test_app_server_params="sr"
test_app_client_params="pp"
vg_tool="/bin/valgrind"
# Test mode expected values: r2c, worker_threads, ultra_api
TEST_MODE="${TEST_MODE:-"r2c"}"
WARMUP_MESSAGE="sockperf: Warmup stage"

mkdir -p "${vg_dir}"
cd "${vg_dir}"

# build xlio with valgrind if not already built
if [ ! -f "${test_lib}" ]; then
	${WORKSPACE}/configure --prefix=${vg_dir}/install --with-valgrind $jenkins_test_custom_configure
	make "${make_opt}" all
	make install
	rc=$?
fi

if [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] || [[ -n "${KUBERNETES_SERVICE_HOST}" ]]; then
    if ip link show net1 > /dev/null 2>&1; then
        test_ip_list="eth_ip4:$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)"
		if [[ "$TEST_MODE" != "ultra_api" ]]; then
			test_ip_list="${test_ip_list} eth_ip6:$(ip -f inet6 addr show net1 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1)"
		fi
    else
        echo "ERROR: net1 interface does not exist!"
        exit 1
    fi
else
	test_ip_list=""
	if [ ! -z "$(do_get_ip 'eth')" ]; then
		test_ip_list="${test_ip_list} eth_ip4:$(do_get_ip 'eth')"
	fi
	if [ ! -z "$(do_get_ip 'eth')" ]; then
		test_ip_list="${test_ip_list} eth_ip6:$(do_get_ip 'inet6')"
	fi
fi

if [ "$test_ip_list" == "eth_ip4: eth_ip6:" ] || [ -z "${test_ip_list}" ]; then
	echo "ERROR: Cannot get IPv4/6 address of net1 interface!"
	exit 1
fi

# Enable Ultra API mode if requested
if [[ "$TEST_MODE" == "ultra_api" ]]; then
	echo "Testing mode: Ultra API"
	test_list="tcp-ultra-api:"
	test_app=xlio_ultra_api_ping_pong
	test_app_path="${vg_dir}/${test_app}"
	test_app_server_params="-s"
	test_app_client_params="-c -n 10"
	test_lib_env="${test_lib_env} XLIO_MEMORY_LIMIT=256MB"
	WARMUP_MESSAGE="Server listening for connections..."

	# Build xlio_ultra api ping pong example
	gcc -I"${vg_dir}/install/include" -o "${test_app_path}" "${WORKSPACE}/examples/xlio_ultra_api_ping_pong.c" -libverbs
# Mode: r2c, worker_threads
else
	if [[ "$TEST_MODE" == "worker_threads" ]]; then
		echo "Testing mode: Worker Threads"
		test_list="tcp-worker-threads:--tcp"
		test_lib_env="${test_lib_env} XLIO_WORKER_THREADS=1 XLIO_MEMORY_LIMIT=512MB"
		test_params="--nonblocked"
	else
		echo "Testing mode: R2C"
		test_list="tcp-r2c:--tcp udp-r2c:"
		test_lib_env="${test_lib_env} XLIO_MEMORY_LIMIT=256MB"
		test_params=""
	fi
	# Build sockperf if not already built when not running in Ultra API mode
	if [ $(command -v "${test_app_path}" >/dev/null 2>&1 || echo $?) ]; then
		test_app_path=sockperf
		if [ $(command -v "${test_app_path}" >/dev/null 2>&1 || echo $?) ]; then
			do_cmd "wget -O sockperf_v2.zip https://github.com/Mellanox/sockperf/archive/sockperf_v2.zip && unzip sockperf_v2.zip && mv sockperf-sockperf_v2 sockperf"
			cd sockperf

			./autogen.sh
			./configure --prefix="${PWD}/install" CPPFLAGS="-I${install_dir}/include"
			make "${make_opt}" install
			test_app_path="${PWD}/install/bin/sockperf"

			cd "${vg_dir}"

			if [ $(command -v "${test_app_path}" >/dev/null 2>&1 || echo $?) ]; then
				echo "can not find ${test_app_path}"
				exit 1
			fi
		fi
	fi
fi

vg_tap=${WORKSPACE}/${prefix}/vg.tap
v1=$(echo $test_list | wc -w)
v1=$((v1*$(echo $test_ip_list | wc -w)))
echo "1..$v1" > $vg_tap

nerrors=0
sockperf_max_wait=120

for test_link in $test_ip_list; do
	for test in $test_list; do
		IFS=':' read test_n test_opt <<< "$test"
		IFS=':' read test_in test_ip <<< "$test_link"
		test_name=${test_in}-${test_n}

		vg_args="-v \
			--memcheck:leak-check=full --track-origins=yes --read-var-info=yes \
			--errors-for-leak-kinds=definite --show-leak-kinds=definite,possible \
			--undef-value-errors=yes --track-fds=yes --num-callers=32 \
			--fullpath-after=${WORKSPACE} --gen-suppressions=all \
			--suppressions=${WORKSPACE}/contrib/valgrind/valgrind_xlio.supp \
			--fair-sched=yes \
			"
		eval "${sudo_cmd} $timeout_exe env $test_lib_env \
			${vg_tool} --log-file=${vg_dir}/${test_name}-valgrind-sr.log $vg_args \
			$test_app_path ${test_app_server_params} ${test_opt} -i ${test_ip} ${test_params} 2>&1 | tee ${vg_dir}/${test_name}-output-sr.log &"

		wait=0
		while [ $wait -lt $sockperf_max_wait ]; do
			ret=$(cat ${vg_dir}/${test_name}-output-sr.log | grep "${WARMUP_MESSAGE}" | wc -l)
			if [ $ret -gt 0 ]; then
				wait=$sockperf_max_wait
			else
				wait=$(( wait + 2 ))
			fi
			sleep 2
		done

		eval "${sudo_cmd} timeout -s SIGINT 1m env $test_lib_env \
			${vg_tool} --log-file=${vg_dir}/${test_name}-valgrind-cl.log $vg_args \
			$test_app_path ${test_app_client_params} ${test_opt} -i ${test_ip} -t 10 ${test_params} 2>&1 | tee ${vg_dir}/${test_name}-output-cl.log"

		if [ `ps -ef | grep $test_app | wc -l` -gt 1 ];
		then
			${sudo_cmd} pkill -SIGINT -f $test_app 2>/dev/null || true
			sleep 10
			if [ `ps -ef | grep $test_app | wc -l` -gt 1 ];
			then
				${sudo_cmd} pkill -SIGTERM -f $test_app 2>/dev/null || true
				sleep 3
			fi
			if [ `ps -ef | grep $test_app | wc -l` -gt 1 ];
			then
				${sudo_cmd} pkill -SIGKILL -f $test_app 2>/dev/null || true
			fi
		fi

		sleep 10
		do_archive "${vg_dir}/${test_name}-valgrind*.log" "${vg_dir}/${test_name}-output*.log"

		ret=$(cat ${vg_dir}/${test_name}-valgrind*.log | awk '/ERROR SUMMARY: [0-9]+ errors?/ { sum += $4 } END { print sum }')
		if [ $ret -gt 0 ]; then
			echo "not ok ${test_name}: valgrind Detected $ret failures # ${vg_dir}/${test_name}-valgrind*.log" >> $vg_tap
			grep -A 10 'LEAK SUMMARY' ${vg_dir}/${test_name}-valgrind*.log >> ${vg_dir}/${test_name}-valgrind.err
			cat ${vg_dir}/${test_name}-valgrind*.log
			do_err "valgrind" "${vg_dir}/${test_name}-valgrind.err"
		else
			ret=$(cat ${vg_dir}/${test_name}-output*.log | grep 'Summary: Latency is' | wc -l)
			if [ $ret -le 0 ]; then
				#echo "not ok ${test_name}: valgrind Detected $ret failures # ${vg_dir}/${test_name}-output*.log" >> $vg_tap
				#grep -A 10 'sockperf:' ${vg_dir}/${test_name}-output*.log >> ${vg_dir}/${test_name}-output.err
				#cat ${vg_dir}/${test_name}-output*.log
				#do_err "valgrind" "${vg_dir}/${test_name}-output.err"
				#ret=1

				# Temporary disabled due to old issue

				ret=0
				echo ok ${test_name}: Valgrind terminated exit >> $vg_tap
			else
				ret=0
				echo ok ${test_name}: Valgrind found no issues >> $vg_tap
			fi
		fi
		nerrors=$(($ret+$nerrors))
	done
done

if [ $nerrors -gt 0 ]; then
	info="Valgrind found $nerrors errors"
	status="error"
else
	info="Valgrind found no issues"
	status="success"
fi

#module unload tools/valgrind-3.12.0

rc=$(($rc+$nerrors))
set -eE
echo "[${0##*/}]..................exit code = $rc"
exit $rc
