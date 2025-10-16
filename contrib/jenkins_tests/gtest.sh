#!/bin/bash -eExl

source $(dirname $0)/globals.sh

# Fix hugepages for docker environments
do_hugepages
ulimit -l unlimited
ulimit -c unlimited

echo "Checking for gtest ..."

if [[ -z "${MANUAL_RUN}" ]]; then
	# Check dependencies
	if [ $(test -d ${install_dir} >/dev/null 2>&1 || echo $?) ]; then
		echo "[SKIP] Not found ${install_dir} : build should be done before this stage"
		exit 1
	fi

	cd $WORKSPACE

	rm -rf $gtest_dir
	mkdir -p $gtest_dir
	cd $gtest_dir

	gtest_app="$PWD/tests/gtest/gtest"
	gtest_lib=$install_dir/lib/${prj_lib}
	opt2=''
else
	# Enable running gtest tests manually without build stage requirement.
	# To run manually. From main directory:
	# env MANUAL_RUN=1 MANUAL_RUN_GTEST_APP=<gtest-path>/gtest MANUAL_RUN_INST_DIR=<xlio-install-path> MANUAL_RUN_ADAPTER='ConnectX-6' WORKSPACE=$PWD TARGET=default jenkins_test_gtest=yes contrib/test_jenkins.sh
	cd $WORKSPACE
	gtest_app=${MANUAL_RUN_GTEST_APP}
	install_dir=${MANUAL_RUN_INST_DIR}
	gtest_lib=$install_dir/lib/${prj_lib}
	opt2=${MANUAL_RUN_ADAPTER:-'ConnectX-7'}
fi

# Retrieve server/client addresses for the test.
# $1 - [ib|eth|inet6] to select link type or empty to select the first found
#
function do_get_addrs()
{
	gtest_ip_list="$(do_get_ip $1 $2)"
	if [ ! -z $2 ]; then
		gtest_ip_list_2="$(do_get_ip $1 $2 $gtest_ip_list)"
	else
		gtest_ip_list_2="$(do_get_ip $1 '' $gtest_ip_list)"
	fi

	if [ ! -z ${gtest_ip_list_2} ]; then
		gtest_ip_list="${gtest_ip_list},${gtest_ip_list_2}"
	else
		echo "[SKIP] two eth interfaces are required. found: ${gtest_ip_list}" >&2
		exit 0
	fi

	echo $gtest_ip_list
}

gtest_opt="--addr=$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1),$(ip -f inet addr show net2 | awk '/inet / {print $2}' | cut -d/ -f1)"
gtest_opt_ipv6="--addr=$(ip -f inet6 addr show net1 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1),$(ip -f inet6 addr show net2 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1) -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" #
#gateway_ip=$(ip route show dev gw1 | head -1 | awk '{print $1}' | cut -d'/' -f1 | awk -F'.' '{print $1"."$2".0.1"}')


set +eE

if [[ -z "${MANUAL_RUN}" ]]; then
	${WORKSPACE}/configure --prefix=$install_dir $jenkins_test_custom_configure
	make $make_opt -C tests/gtest
	rc=$(($rc+$?))
fi

eval "${sudo_cmd} pkill -9 ${prj_service} 2>/dev/null || true"
eval "${sudo_cmd} ${install_dir}/sbin/${prj_service} --console -v5 &"

# Test with full coverage of the new config
eval "${sudo_cmd} $timeout_exe env XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=${WORKSPACE}/tests/gtest/xlio_config_full_coverage.json GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=-xlio_*:-ultra* --gtest_output=xml:${WORKSPACE}/${prefix}/test-basic.xml"
rc=$(($rc+$?))

# Exclude EXTRA API tests IPv6
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=-xlio_*:-ultra* --gtest_output=xml:${WORKSPACE}/${prefix}/test-basic-ipv6.xml"
rc=$(($rc+$?))

# Verify Delegated TCP Timers tests
eval "${sudo_cmd} $timeout_exe env XLIO_RX_POLL_ON_TX_TCP=1 XLIO_TCP_ABORT_ON_CLOSE=1 XLIO_TCP_CTL_THREAD=delegate GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=-xlio*:-ultra* --gtest_output=xml:${WORKSPACE}/${prefix}/test-delegate.xml"
rc=$(($rc+$?))

# Verify Delegated TCP Timers tests IPv6
eval "${sudo_cmd} $timeout_exe env XLIO_RX_POLL_ON_TX_TCP=1 XLIO_TCP_ABORT_ON_CLOSE=1 XLIO_TCP_CTL_THREAD=delegate GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=-xlio*:-ultra* --gtest_output=xml:${WORKSPACE}/${prefix}/test-delegate-ipv6.xml"
rc=$(($rc+$?))

if [[ -z "${MANUAL_RUN}" ]]; then
	make -C tests/gtest clean
	make $make_opt -C tests/gtest CPPFLAGS="-DEXTRA_API_ENABLED=1"
	rc=$(($rc+$?))
fi

# Verify XLIO EXTRA API tests
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=xlio_* --gtest_output=xml:${WORKSPACE}/${prefix}/test-extra.xml"
rc=$(($rc+$?))

# Verify XLIO EXTRA API tests IPv6
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=xlio_* --gtest_output=xml:${WORKSPACE}/${prefix}/test-extra-ipv6.xml"
rc=$(($rc+$?))

# XLIO Ultra API

#IPV4
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=ultra_api* --gtest_output=xml:${WORKSPACE}/${prefix}/test-xlio_ultra_api.xml"
rc=$(($rc+$?))

#IPV6
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=ultra_api* --gtest_output=xml:${WORKSPACE}/${prefix}/test-xlio_ultra_api-ipv6.xml"
rc=$(($rc+$?))

# Worker Threads Mode tests

# Worker Threads Mode test filter
worker_threads_filter="tcp_listen*:sock_socket.ti_2:tcp_bind*:-tcp_bind.mapped_ipv4_bind:tcp_event*"

eval "${sudo_cmd} $timeout_exe env XLIO_WORKER_THREADS=1 GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=$worker_threads_filter --gtest_output=xml:${WORKSPACE}/${prefix}/test-worker-threads.xml"
rc=$(($rc+$?))

# Worker Threads Mode tests IPv6
eval "${sudo_cmd} $timeout_exe env XLIO_WORKER_THREADS=1 GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=$worker_threads_filter --gtest_output=xml:${WORKSPACE}/${prefix}/test-worker-threads-ipv6.xml"
rc=$(($rc+$?))

# Worker Threads Mode - Power of 2 (2 threads)
eval "${sudo_cmd} $timeout_exe env XLIO_WORKER_THREADS=2 GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=$worker_threads_filter --gtest_output=xml:${WORKSPACE}/${prefix}/test-worker-threads-pow2.xml"
rc=$(($rc+$?))

# Worker Threads Mode - Non-Power of 2 (3 threads)
eval "${sudo_cmd} $timeout_exe env XLIO_WORKER_THREADS=3 GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=$worker_threads_filter --gtest_output=xml:${WORKSPACE}/${prefix}/test-worker-threads-not-pow2.xml"
rc=$(($rc+$?))

eval "${sudo_cmd} pkill -9 ${prj_service} 2>/dev/null || true"

set -eE

for f in $(find $gtest_dir -name '*.tap')
do
    cp $f ${WORKSPACE}/${prefix}/gtest-$(basename $f .tap).tap
done

echo "[${0##*/}]..................exit code = $rc"
exit $rc
