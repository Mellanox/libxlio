#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for gtest ..."

if [[ -z "${MANUAL_RUN}" ]]; then
	# Check dependencies
	if [ $(test -d ${install_dir} >/dev/null 2>&1 || echo $?) ]; then
		echo "[SKIP] Not found ${install_dir} : build should be done before this stage"
		exit 1
	fi

	if [ $(command -v ibdev2netdev >/dev/null 2>&1 || echo $?) ]; then
		echo "[SKIP] ibdev2netdev tool does not exist"
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

gtest_opt="--addr=$(do_get_addrs 'eth' ${opt2})"
gtest_opt_ipv6="--addr=$(do_get_addrs 'inet6' ${opt2}) -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" # Remote - Dummy Address

set +eE

if [[ -z "${MANUAL_RUN}" ]]; then
	${WORKSPACE}/configure --prefix=$install_dir $jenkins_test_custom_configure
	make $make_opt -C tests/gtest
	rc=$(($rc+$?))
fi

eval "${sudo_cmd} pkill -9 ${prj_service} 2>/dev/null || true"
eval "${sudo_cmd} ${install_dir}/sbin/${prj_service} --console -v5 &"

# Exclude EXTRA API tests
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=-xlio_* --gtest_output=xml:${WORKSPACE}/${prefix}/test-basic.xml"
rc=$(($rc+$?))

# Exclude EXTRA API tests IPv6
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=-xlio_* --gtest_output=xml:${WORKSPACE}/${prefix}/test-basic-ipv6.xml"
rc=$(($rc+$?))

# Verify Delegated TCP Timers tests
eval "${sudo_cmd} $timeout_exe env XLIO_RX_POLL_ON_TX_TCP=1 XLIO_TCP_ABORT_ON_CLOSE=1 XLIO_TCP_CTL_THREAD=delegate GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=-xlio* --gtest_output=xml:${WORKSPACE}/${prefix}/test-delegate.xml"
rc=$(($rc+$?))

# Verify Delegated TCP Timers tests IPv6
eval "${sudo_cmd} $timeout_exe env XLIO_RX_POLL_ON_TX_TCP=1 XLIO_TCP_ABORT_ON_CLOSE=1 XLIO_TCP_CTL_THREAD=delegate GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=-xlio* --gtest_output=xml:${WORKSPACE}/${prefix}/test-delegate-ipv6.xml"
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

# Verify keep_alive
eval "${sudo_cmd} $timeout_exe env MALLOC_CHECK_=1 GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=keep_alive* --gtest_output=xml:${WORKSPACE}/${prefix}/test-keepalive_ipv4.xml"
rc=$(($rc+$?))

# Verify keep_alive IPv6
eval "${sudo_cmd} $timeout_exe env MALLOC_CHECK_=1 GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=keep_alive* --gtest_output=xml:${WORKSPACE}/${prefix}/test-keepalive_ipv6.xml"
rc=$(($rc+$?))

# Verify New Config with keep_alive tests
echo "{}" > /tmp/test.json
eval "${sudo_cmd} $timeout_exe env XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=/tmp/test.json LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=keep_alive* --gtest_output=xml:${WORKSPACE}/${prefix}/test-keepalive_ipv4.xml"
rc=$(($rc+$?))



# XLIO ZC API

#IPV4
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=zc_api_xlio* --gtest_output=xml:${WORKSPACE}/${prefix}/test-zc_api.xml"
rc=$(($rc+$?))

#IPV6
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt_ipv6 --gtest_filter=zc_api_xlio* --gtest_output=xml:${WORKSPACE}/${prefix}/test-zc_api-ipv6.xml"
rc=$(($rc+$?))


eval "${sudo_cmd} pkill -9 ${prj_service} 2>/dev/null || true"

set -eE

for f in $(find $gtest_dir -name '*.tap')
do
    cp $f ${WORKSPACE}/${prefix}/gtest-$(basename $f .tap).tap
done

echo "[${0##*/}]..................exit code = $rc"
exit $rc
