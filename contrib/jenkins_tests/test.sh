#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for test ..."
if [ $(test -d ${install_dir} >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] Not found ${install_dir} : build should be done before this stage"
	exit 1
fi

cd $WORKSPACE

rm -rf $test_dir
mkdir -p $test_dir
cd $test_dir

test_app="sockperf"

# Download sockperf to use verifier
do_cmd "wget -O sockperf_v2.zip https://github.com/Mellanox/sockperf/archive/sockperf_v2.zip && unzip sockperf_v2.zip && mv sockperf-sockperf_v2 sockperf"
cd sockperf

# This unit requires sockperf so check for existence
if [ $(command -v ${test_app} >/dev/null 2>&1 || echo $?) ]; then
    set +e
    ./autogen.sh
    ./configure --prefix=$PWD/install CPPFLAGS="-I${install_dir}/include"
    make install
    test_app="$PWD/install/bin/sockperf"
    set -e

    if [ $(command -v ${test_app} >/dev/null 2>&1 || echo $?) ]; then
        echo "[SKIP] $test_app does not exist"
        exit 1
    fi
else
    test_app="$(command -v ${test_app})"
fi

test_ip_list=""
test_list="tcp-pp tcp-tp tcp-ul"
test_lib=$install_dir/lib/${prj_lib}

if [ ! -z "${test_remote_ip}" ] ; then
	[[ "${test_remote_ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {\
		echo ">> FAIL wrong ip address ${test_remote_ip}"
		exit 1
	}
	test_ip_list="eth:${test_remote_ip}"
	[ -z "${NODE_NAME}" ] && NODE_NAME=${HOSTNAME}
	sperf_exec_dir="/tmp/sockperf_exec_${NODE_NAME}"
	rmt_user=root

	rmt_os=$(${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} ". /etc/os-release ; echo \${NAME,,} | awk '{print \$1}'")
	[ ! -z "${test_remote_rebuild}" ] && rmt_os="rebuld"
	local_os=$(. /etc/os-release ; echo ${NAME,,} | awk '{print $1}')

	#skip_remote_prep=1
	if [ -z "${skip_remote_prep}" ] ; then
		${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} "rm -rf ${sperf_exec_dir} && mkdir ${sperf_exec_dir}"

		if [[ "${rmt_os}" =~ .*"${local_os}".* ]] ; then
			${sudo_cmd} scp -q ${test_app} ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			${sudo_cmd} scp -q ${test_lib} ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			eval "pid=$(${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} pidof ${prj_service})"
			if [ ! -z "${pid}" ] ;  then
				echo "${prj_service} pid=${pid}"
				eval "${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} kill -9 ${pid}"
			fi
			${sudo_cmd} scp -q ${install_dir}/sbin/${prj_service} ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			eval "${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} ${sudo_cmd} ${sperf_exec_dir}/${prj_service} &"
		else
			${sudo_cmd} -E rsync -q -I -a -r --exclude jenkins --exclude '*.o' --exclude '.deps' --exclude '*.l*' \
			-e ssh ${WORKSPACE} ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			${sudo_cmd} scp -q ${test_dir}/sockperf_v2.zip ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			if [ $? -eq 0 ] ; then
				subdir=${WORKSPACE##*/}
				cmd="cd ${sperf_exec_dir}/${subdir} && "
				cmd+="./autogen.sh && ./configure && make ${make_opt} && "
				cmd+="cp src/core/.libs/*.so ${sperf_exec_dir} &&"
				cmd+="cd ${sperf_exec_dir} && "
				cmd+="unzip sockperf_v2.zip && cd sockperf-sockperf_v2 && "
				cmd+="./autogen.sh && ./configure && make ${make_opt} && cp sockperf ${sperf_exec_dir}"
				${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} "${cmd}"
			else
				exit 1
			fi
		fi
	fi
else
	# Get IPv4/6 addresses for net1 interface which is a VF of MLNX NIC
	test_ip_list="eth_ip4:$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)"
	# test_ip_list="${test_ip_list} eth_ip6:$(ip -f inet6 addr show net1 | awk '/inet6 / {print $2}' | cut -d/ -f1)"
	if [ -z "$test_ip_list" ]; then
		echo "ERROR: Cannot get IPv4/6 address of net1 interface!"
		exit 1
	fi

	# start the ssh server as verifyer.pl requiers
	/etc/init.d/ssh start
fi

nerrors=0

for test_link in $test_ip_list; do
	for test in $test_list; do
		IFS=':' read test_in test_ip <<< "$test_link"
		test_name=${test_in}-${test}
		test_tap=${WORKSPACE}/${prefix}/test-${test_name}.tap

		for i in $(seq 3); do
			if [ ! -z "${test_remote_ip}" ] ; then

				eval "pid=$(${sudo_cmd} pidof ${prj_service})"
				[ ! -z "${pid}" ] && eval "${sudo_cmd} kill -9 ${pid}"
				eval "${sudo_cmd} ${install_dir}/sbin/${prj_service} --console -v5 & "

				echo "BUILD_NUMBER=${BUILD_NUMBER}"
				eval "pid=$(${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} pidof ${prj_service})"
				if [ ! -z "${pid}" ] ;  then
					echo "${prj_service} pid=${pid}"
					eval "${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} kill -9 ${pid}"
				fi
				${sudo_cmd} scp -q ${install_dir}/sbin/${prj_service} ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
				eval "${sudo_cmd} ssh ${rmt_user}@${test_remote_ip} ${sudo_cmd} ${sperf_exec_dir}/${prj_service} &"

				vutil="$(dirname $0)/vutil.sh"
				[ ! -e "${vutil}" ] && { echo "error vutil not found" ; exit 1 ; }

				${sudo_cmd} $timeout_exe ${vutil}  -a "${test_app}" -x "--load-vma=${test_lib} " -t "${test}:tc[1-9]$" \
						-s "${test_remote_ip}" -p "${test_remote_port}" -l "${test_dir}/${test_name}.log"
			else
				${sudo_cmd} $timeout_exe $PWD/tests/verifier/verifier.pl -a ${test_app} -x " --pre-warmup-wait=2 --debug " \
					-t ${test}:tc[6-9]$ -s ${test_ip} -l ${test_dir}/${test_name}.log \
					-e " XLIO_MEM_ALLOC_TYPE=ANON XLIO_DOCA_RX=0 XLIO_DOCA_TX=0 LD_PRELOAD=$test_lib " \
					--progress=0
			fi

			cp $PWD/${test_name}.dump ${test_dir}/${test_name}.dump
			if grep -q 'FAIL' ${test_dir}/${test_name}.dump; then
				if [ "$i" -lt "3" ]; then
					rm -fv ${test_dir}/${test_name}.log ${test_dir}/${test_name}.dump
				fi
			else
				break
			fi
		done

		cp $PWD/${test_name}.dump ${test_dir}/${test_name}.dump
		
		grep -e 'PASS' -e 'FAIL' ${test_dir}/${test_name}.dump > ${test_dir}/${test_name}.tmp

		do_archive "${test_dir}/${test_name}.dump" "${test_dir}/${test_name}.log"

		echo "1..$(wc -l < ${test_dir}/${test_name}.tmp)" > $test_tap

		v1=1
		while read line; do
		    if [[ $(echo $line | cut -f1 -d' ') =~ 'PASS' ]]; then
		        v0='ok'
		        v2=$(echo $line | sed 's/PASS //')
		    else
		        v0='not ok'
		        v2=$(echo $line | sed 's/FAIL //')
	            nerrors=$((nerrors+1))
		    fi

		    echo -e "$v0 ${test_in}: $v2" >> $test_tap
		    v1=$(($v1+1))
		done < ${test_dir}/${test_name}.tmp
		rm -f ${test_dir}/${test_name}.tmp
	done
done

rc=$(($rc+$nerrors))

echo "[${0##*/}]..................exit code = $rc"
exit $rc
