#!/bin/bash -l
set -eExo pipefail

ulimit -l unlimited
ulimit -n 1000000
source $(dirname $0)/globals.sh

# Fix hugepages for docker environments
do_hugepages

# Install dpcp (required for unit tests)
do_check_env
do_check_dpcp opt_value

XLIO_TOOLS_BRANCH=${XLIO_TOOLS_BRANCH:-"benchmark_initial_drop"}
WORKSPACE=${WORKSPACE:-$(pwd)}
TEST_CONFIGURATION_SERVER="--mode server --threads 1 --direction bidirectional"
TEST_CONFIGURATION_CLIENT="--mode client --server-workers 1 \
	--connections 2 --duration 300 --direction bidirectional"
TEST_LIB_ENV="XLIO_MEM_ALLOC_TYPE=ANON XLIO_TX_WRE=2000 XLIO_RX_WRE=2000 XLIO_STRQ=off LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${opt_value}/lib"
VG_TOOL="/bin/valgrind"
VG_ARGS="-v \
	--memcheck:leak-check=full --track-origins=yes --read-var-info=yes \
	--errors-for-leak-kinds=definite --show-leak-kinds=definite,possible \
	--undef-value-errors=yes --track-fds=yes --num-callers=32 \
	--fullpath-after=${WORKSPACE} --gen-suppressions=all \
	--suppressions=${WORKSPACE}/contrib/valgrind/valgrind_xlio.supp \
	--fair-sched=yes"
# 'default' is in the path due to artifacts.sh looking for that path to archive logs
XLIO_TOOLS_DIR="${WORKSPACE}/${prefix}/default/xlio_tools"
TEST_APP="xlio_benchmark"
TEST_APP_PATH="${XLIO_TOOLS_DIR}/build/${TEST_APP}"
XLIO_TOOLS_MAX_WAIT=120
NERRORS=0

# Get test IP list
if ip link show net1 > /dev/null 2>&1; then
    TEST_IP_LIST="eth_ip4:$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1)"
    TEST_IP_LIST="${TEST_IP_LIST} eth_ip6:$(ip -f inet6 addr show net1 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1)"
else
    echo "ERROR: net1 interface does not exist!"
    exit 1
fi

# Prepare libxlio for xlio_tools, static build is required for xlio_tools
./autogen.sh
./configure --with-dpcp=${opt_value} --disable-shared --with-valgrind
make ${make_opt} install

mkdir -p "${XLIO_TOOLS_DIR}"
chmod 777 "${XLIO_TOOLS_DIR}" # Fix permissions issues for swx-jenkins user

# Build xlio_tools
sudo -u swx-jenkins git clone -c core.sshCommand="ssh -i ~/.ssh/id_rsa" git@github.com:Mellanox/xlio_tools.git "${XLIO_TOOLS_DIR}" -b "${XLIO_TOOLS_BRANCH}"
cd "${XLIO_TOOLS_DIR}"
LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${opt_value}/lib" meson setup build \
	-Dxlio_include_dir=${WORKSPACE}/src/core/ \
	-Dxlio_lib_dir=${WORKSPACE}/src/core/.libs/ \
	-Dtests=false
pushd build
meson compile
popd

# Run xlio_tools basic test
for test_link in ${TEST_IP_LIST}; do
	IFS=':' read test_in test_ip <<< "${test_link}"
	test_name="${test_in}-tcp"

	set +eE
	# Run Server
	eval "${sudo_cmd} ${timeout_exe} env ${TEST_LIB_ENV} \
		${VG_TOOL} --log-file=${XLIO_TOOLS_DIR}/${test_name}-valgrind-sr.log ${VG_ARGS} \
		${TEST_APP_PATH} ${TEST_CONFIGURATION_SERVER} --bind ${test_ip} 2>&1 | tee ${XLIO_TOOLS_DIR}/${test_name}-output-sr.log &"

	wait=0
	while [ $wait -lt "${XLIO_TOOLS_MAX_WAIT}" ]; do
		if [ $(grep 'All workers ready. Starting benchmark...' ${XLIO_TOOLS_DIR}/${test_name}-output-sr.log | wc -l) -gt 0 ]; then
			break
		fi
		sleep 2
		wait=$(( wait + 2 ))
	done

	# Run Client
	eval "${sudo_cmd} ${timeout_exe} env ${TEST_LIB_ENV} \
		${VG_TOOL} --log-file=${XLIO_TOOLS_DIR}/${test_name}-valgrind-cl.log ${VG_ARGS} \
		${TEST_APP_PATH} ${TEST_CONFIGURATION_CLIENT} --server ${test_ip} 2>&1| tee ${XLIO_TOOLS_DIR}/${test_name}-output-cl.log"

	if [ `ps -ef | grep "${TEST_APP}" | wc -l` -gt 1 ];
	then
		${sudo_cmd} pkill -SIGINT -f "${TEST_APP}" 2>/dev/null || true
		sleep 10
		if [ `ps -ef | grep "${TEST_APP}" | wc -l` -gt 1 ];
		then
			${sudo_cmd} pkill -SIGTERM -f "${TEST_APP}" 2>/dev/null || true
			sleep 3
		fi
		if [ `ps -ef | grep "${TEST_APP}" | wc -l` -gt 1 ];
		then
			${sudo_cmd} pkill -SIGKILL -f "${TEST_APP}" 2>/dev/null || true
		fi
	fi
	set -eE
    jenkins_test_artifacts="${WORKSPACE}/${prefix}/default/xlio-${BUILD_NUMBER}-${HOSTNAME}" do_archive "${XLIO_TOOLS_DIR}/${test_name}-valgrind*.log" "${XLIO_TOOLS_DIR}/${test_name}-output*.log"

	ret=$(cat ${XLIO_TOOLS_DIR}/${test_name}-valgrind*.log | awk '/ERROR SUMMARY: [0-9]+ errors?/ { sum += $4 } END { print sum }')
	if [ $ret -gt 0 ]; then
		grep -A 10 'LEAK SUMMARY' ${XLIO_TOOLS_DIR}/${test_name}-valgrind*.log >> ${XLIO_TOOLS_DIR}/${test_name}-valgrind.err
		cat ${XLIO_TOOLS_DIR}/${test_name}-valgrind*.log
		do_err "valgrind" "${XLIO_TOOLS_DIR}/${test_name}-valgrind.err"
	fi
	NERRORS=$((ret + NERRORS))
done

if [ $NERRORS -gt 0 ]; then
	info="Valgrind found $NERRORS errors"
	status="error"
else
	info="Valgrind found no issues"
	status="success"
fi

echo "[${0##*/}]..................exit code = $NERRORS"
exit $NERRORS
