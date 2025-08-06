#!/bin/bash -eExl

source $(dirname $0)/globals.sh

# Fix hugepages for docker environments
do_hugepages

echo "Checking for test ..."
if [ $(test -d ${install_dir} >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] Not found ${install_dir} : build should be done before this stage"
	exit 1
fi

cd ${WORKSPACE}

rm -rf ${test_dir}
mkdir -p ${test_dir}
cd ${test_dir}

test_app="sockperf"

# Download sockperf to use verifier
do_cmd "wget -O sockperf_v2.zip https://github.com/Mellanox/sockperf/archive/sockperf_v2.zip && unzip sockperf_v2.zip && mv sockperf-sockperf_v2 sockperf"
cd sockperf

# This unit requires sockperf so check for existence
if [ $(command -v ${test_app} >/dev/null 2>&1 || echo $?) ]; then
    set +e
    ./autogen.sh
    ./configure --prefix=${PWD}/install CPPFLAGS="-I${install_dir}/include"
    make install
    test_app="${PWD}/install/bin/sockperf"
    set -e

    if [ $(command -v ${test_app} >/dev/null 2>&1 || echo $?) ]; then
        echo "[SKIP] ${test_app} does not exist"
        exit 1
    fi
else
    test_app="$(command -v ${test_app})"
fi

test_list="tcp-pp tcp-tp tcp-ul"
test_lib=$install_dir/lib/${prj_lib}

if [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] || [[ -n "${KUBERNETES_SERVICE_HOST}" ]]; then
	test_ip_list_v4=$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)
	test_ip_list_v6=$(ip -f inet6 addr show net1 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1)

	if [ -z "${test_ip_list_v4}" ] || [ -z "${test_ip_list_v6}" ]; then
		echo "ERROR: Cannot get IPv4/6 address of net1 interface!"
		exit 1
	else
		test_ip_list="eth_ip4:${test_ip_list_v4} eth_ip6:${test_ip_list_v6}"
	fi
else
	if [ ! -z $(do_get_ip 'ib') ]; then
		test_ip_list="${test_ip_list} ib:$(do_get_ip 'ib')"
	fi
	if [ ! -z $(do_get_ip 'eth') ]; then
		test_ip_list="${test_ip_list} eth_ip4:$(do_get_ip 'eth')"
	fi
	if [ ! -z $(do_get_ip 'inet6') ]; then
		test_ip_list="${test_ip_list} eth_ip6:$(do_get_ip 'inet6')"
	fi
fi

# start the ssh server as verifyer.pl requiers
/etc/init.d/ssh start

nerrors=0

for test_link in ${test_ip_list}; do
	for test in ${test_list}; do
		IFS=':' read test_in test_ip <<< "$test_link"
		test_name=${test_in}-${test}
		test_tap=${WORKSPACE}/${prefix}/test-${test_name}.tap

		for i in $(seq 3); do
			rm -fv ${test_dir}/${test_name}.log ${test_dir}/${test_name}.dump || :
			set +e
			${sudo_cmd} ${timeout_exe} ${PWD}/tests/verifier/verifier.pl -a ${test_app} -x " --debug  " \
				-t ${test}:tc[1-9]$ -s ${test_ip} -l ${test_dir}/${test_name}.log \
				-e " LD_PRELOAD=${test_lib} " --progress=0
			# make sure to catch the error
			ret=$?
			set -e

			cp ${PWD}/${test_name}.dump ${test_dir}/${test_name}.dump
			if ! grep -q 'FAIL' ${test_dir}/${test_name}.dump; then
				break
			fi
		done
		rc=$((rc+ret))
		grep -e 'PASS' -e 'FAIL' ${test_dir}/${test_name}.dump > ${test_dir}/${test_name}.tmp

		do_archive "${test_dir}/${test_name}.dump" "${test_dir}/${test_name}.log"

		echo "1..$(wc -l < ${test_dir}/${test_name}.tmp)" > ${test_tap}

		v1=1
		while read line; do
		    if [[ $(echo ${line} | cut -f1 -d' ') =~ 'PASS' ]]; then
		        v0='ok'
		        v2=$(echo ${line} | sed 's/PASS //')
		    else
		        v0='not ok'
		        v2=$(echo ${line} | sed 's/FAIL //')
	            nerrors=$((nerrors+1))
		    fi

		    echo -e "$v0 ${test_in}: $v2" >> ${test_tap}
		    v1=$(($v1+1))
		done < ${test_dir}/${test_name}.tmp
		rm -f ${test_dir}/${test_name}.tmp
	done
done

rc=$(($rc+$nerrors))

echo "[${0##*/}]..................exit code = ${rc}"
exit ${rc}
