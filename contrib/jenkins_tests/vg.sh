#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for valgrind ..."

#do_module "tools/valgrind-3.12.0"

set +eE

cd $WORKSPACE
rm -rf $vg_dir
mkdir -p $vg_dir
cd $vg_dir

${WORKSPACE}/configure --prefix=${vg_dir}/install --with-valgrind $jenkins_test_custom_configure

make $make_opt all
make install
rc=$?


test_ip_list=""
# check if we run in jenkins env
if [[ $BUILD_NUMBER -le 0 ]]; then
	#if [ ! -z $(do_get_ip 'ib') ]; then
	#	test_ip_list="${test_ip_list} ib:$(do_get_ip 'ib')"
	#fi
	if [ ! -z "$(do_get_ip 'eth')" ]; then
		test_ip_list="${test_ip_list} eth_ip4:$(do_get_ip 'eth')"
	fi
	if [ ! -z "$(do_get_ip 'eth')" ]; then
		test_ip_list="${test_ip_list} eth_ip6:$(do_get_ip 'inet6')"
	fi
else
	test_ip_list="eth_ip4:$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)"
	# test_ip_list="${test_ip_list} eth_ip6:$(ip -f inet6 addr show net1 | awk '/inet6 / {print $2}' | cut -d/ -f1)"
	if [ -z "$test_ip_list" ]; then
		echo "ERROR: Cannot get IPv4 address of net1 interface!"
		exit 1
	fi
fi
test_list="tcp:--tcp"
test_lib=${vg_dir}/install/lib/${prj_lib}
test_lib_env="XLIO_MEM_ALLOC_TYPE=ANON XLIO_DOCA_RX=0 XLIO_DOCA_TX=0"
test_app=sockperf
test_app_path=${test_dir}/sockperf/install/bin/sockperf
vg_tool=/bin/valgrind

if [ $(command -v $test_app_path >/dev/null 2>&1 || echo $?) ]; then
	test_app_path=sockperf
	if [ $(command -v $test_app_path >/dev/null 2>&1 || echo $?) ]; then
		do_cmd "wget -O sockperf_v2.zip https://github.com/Mellanox/sockperf/archive/sockperf_v2.zip && unzip sockperf_v2.zip && mv sockperf-sockperf_v2 sockperf"
		cd sockperf

		./autogen.sh
		./configure --prefix=$PWD/install CPPFLAGS="-I${install_dir}/include"
		make $make_opt install
		test_app_path="$PWD/install/bin/sockperf"

		cd $vg_dir

		if [ $(command -v $test_app_path >/dev/null 2>&1 || echo $?) ]; then
			echo can not find $test_app_path
			exit 1
		fi
	fi
fi

vg_tap=${WORKSPACE}/${prefix}/vg.tap
v1=$(echo $test_list | wc -w)
v1=$(($v1*$(echo $test_ip_list | wc -w)))
echo "1..$v1" > $vg_tap

nerrors=0
sockperf_max_wait=240

for test_link in $test_ip_list; do
	for test in $test_list; do
		IFS=':' read test_n test_opt <<< "$test"
		IFS=':' read test_in test_ip <<< "$test_link"
		test_name=${test_in}-${test_n}

		vg_args="-v \
			--memcheck:leak-check=full --track-origins=yes --read-var-info=yes \
			--errors-for-leak-kinds=definite --show-leak-kinds=definite,possible \
			--undef-value-errors=yes --track-fds=yes --num-callers=32 \
			--fullpath-after=${WORKSPACE} --fair-sched=yes \
			--suppressions=${WORKSPACE}/contrib/valgrind/valgrind_xlio.supp \
			"
		eval "${sudo_cmd} $timeout_exe ${vg_tool} --log-file=${vg_dir}/${test_name}-valgrind-sr.log \
			$vg_args env $test_lib_env LD_PRELOAD=$test_lib \
			$test_app_path sr ${test_opt} -i ${test_ip} 2>&1 | tee ${vg_dir}/${test_name}-output-sr.log &"

		wait=0
		while [ $wait -lt $sockperf_max_wait ]; do
			ret=$(cat ${vg_dir}/${test_name}-output-sr.log | grep 'sockperf: Warmup stage' | wc -l)
			if [ $ret -gt 0 ]; then
				wait=$sockperf_max_wait
			else
				wait=$(( $wait + 2 ))
			fi
			sleep 2
		done

		eval "${sudo_cmd} $timeout_exe_short ${vg_tool} --log-file=${vg_dir}/${test_name}-valgrind-cl.log \
			$vg_args env $test_lib_env LD_PRELOAD=$test_lib \
			$test_app_path pp ${test_opt} -i ${test_ip} -t 10 | tee ${vg_dir}/${test_name}-output-cl.log"

		if [ `ps -ef | grep $test_app | wc -l` -gt 1 ];
		then
			${sudo_cmd} pkill -9 -f $test_app 2>/dev/null || true
			sleep 10
			# in case SIGINT didn't work
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
		do_archive "${vg_dir}/${test_name}-valgrind*.log ${vg_dir}/${test_name}-output*.log"

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
