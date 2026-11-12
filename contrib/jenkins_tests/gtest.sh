#!/bin/bash -eExl

source "$(dirname "$0")/globals.sh"

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

	cd "$WORKSPACE"

	rm -rf "$gtest_dir"
	mkdir -p "$gtest_dir"
	cd "$gtest_dir"

	gtest_app="$PWD/tests/gtest/gtest"
	gtest_lib=$install_dir/lib/${prj_lib}
	opt2=''
else
	# Enable running gtest tests manually without build stage requirement.
	# To run manually. From main directory:
	# env MANUAL_RUN=1 MANUAL_RUN_GTEST_APP=<gtest-path>/gtest MANUAL_RUN_INST_DIR=<xlio-install-path> MANUAL_RUN_ADAPTER='ConnectX-6' WORKSPACE=$PWD TARGET=default jenkins_test_gtest=yes contrib/test_jenkins.sh
	cd "$WORKSPACE"
	gtest_app=${MANUAL_RUN_GTEST_APP}
	install_dir=${MANUAL_RUN_INST_DIR}
	gtest_lib=$install_dir/lib/${prj_lib}
	opt2=${MANUAL_RUN_ADAPTER:-'ConnectX-7'}
fi

# CI owns interface discovery; the shared runner owns test profiles.
gtest_addr="$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1),$(ip -f inet addr show net2 | awk '/inet / {print $2}' | cut -d/ -f1)"
gtest_addr6="$(ip -f inet6 addr show net1 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1),$(ip -f inet6 addr show net2 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1)"
# A fresh directory also avoids stale artifacts in MANUAL_RUN mode.
mkdir -p "$gtest_dir"
gtest_results=$(mktemp -d "$gtest_dir/results.XXXXXX")
read -r -a gtest_sudo <<< "${sudo_cmd}"

function run_ci_profile()
{
    local profile_name=$1 artifact_label=$2 addresses=$3 profile_rc
    local sample_name="${profile_name}-${artifact_label}"
    shift 3
    if "${gtest_sudo[@]}" env WORKSPACE="$WORKSPACE" GTEST_TAP=2 \
        "${WORKSPACE}/tests/gtest/run" \
        --profiles="$profile_name" --addr="$addresses" \
        --gtest-bin="$gtest_app" --xlio-lib="$gtest_lib" \
        --output-dir="$gtest_results/$sample_name" -- "$@"; then
        profile_rc=0
    else
        profile_rc=$?
    fi
    rc=$((rc + profile_rc))
}

set +eE

if [[ -z "${MANUAL_RUN}" ]]; then
	"${WORKSPACE}/configure" --prefix="$install_dir" $jenkins_test_custom_configure
	make $make_opt -C tests/gtest
	rc=$(($rc+$?))
fi

run_ci_profile r2c-full ipv4 "$gtest_addr"
run_ci_profile rto-floor-max ipv4 "$gtest_addr"
run_ci_profile r2c-default ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile delegate ipv4 "$gtest_addr"
run_ci_profile delegate ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff

if [[ -z "${MANUAL_RUN}" ]]; then
	make -C tests/gtest clean
	make $make_opt -C tests/gtest CPPFLAGS="-DEXTRA_API_ENABLED=1"
	rc=$(($rc+$?))
fi

run_ci_profile extra ipv4 "$gtest_addr"
run_ci_profile extra ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile ultra ipv4 "$gtest_addr"
run_ci_profile ultra ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile ultra-full-sq ipv4 "$gtest_addr"
run_ci_profile wtbusy ipv4 "$gtest_addr"
run_ci_profile wtbusy ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile wtbusy-pow2 ipv4 "$gtest_addr"
run_ci_profile wtbusy-not-pow2 ipv4 "$gtest_addr"
run_ci_profile wtintr ipv4 "$gtest_addr"
run_ci_profile wtintr ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile wtintr-pow2 ipv4 "$gtest_addr"
run_ci_profile wtintr-not-pow2 ipv4 "$gtest_addr"
run_ci_profile wtbp ipv4 "$gtest_addr"
run_ci_profile wtbp ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile wtbp-pow2 ipv4 "$gtest_addr"
run_ci_profile wtbp-not-pow2 ipv4 "$gtest_addr"
run_ci_profile passthrough-loopback-wt ipv4 "$gtest_addr"
run_ci_profile passthrough-loopback-r2c ipv4 "$gtest_addr"
run_ci_profile passthrough-rules-wt ipv4 "$gtest_addr"
run_ci_profile passthrough-rules-r2c ipv4 "$gtest_addr"

set -eE

# Keep every profile's TAP results; suite names repeat between configurations.
while IFS= read -r -d '' tap_file; do
    relative=${tap_file#"$gtest_results"/}
    profile_name=${relative%%/*}
    cp -- "$tap_file" "${WORKSPACE}/${prefix}/gtest-${profile_name}-$(basename "$tap_file")"
done < <(find "$gtest_results" -mindepth 2 -name '*.tap' -print0)

echo "[${0##*/}]..................exit code = $rc"
exit $rc
