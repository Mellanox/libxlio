#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for building with gcc ..."

cd $WORKSPACE

rm -rf ${build_dir}
mkdir -p ${build_dir}
cd ${build_dir}

# Set symbolic links to default build and install
ln -s "${build_dir}/0/install" "${install_dir}"

# Regression test against json-c configure-time detection failures: -Werror in
# CFLAGS used to break the AC_CHECK_FUNCS probes (e.g. the deprecated K&R
# strdup() check) and misdetect libc functions as missing.
werror_cflags="-g -Werror -Werror=implicit-function-declaration -Werror-implicit-function-declaration -O2"

# Ordered list of builds. 'default' must stay first, so that it is built with
# test_id=0 and matches the ${build_dir}/0/install symbolic link above.
# The first build is executed by further stages, such as gtest.sh and test.sh
build_names=('default' 'debug' 'nginx-off' 'envoy-on' 'static-on' 'werror')

declare -A build_list
build_list['default']=""
build_list['debug']="--enable-opt-log=no --enable-debug"
build_list['nginx-off']="--enable-nginx=no"
build_list['envoy-on']="--enable-nginx=yes"
build_list['static-on']="--enable-static --disable-shared"
build_list['werror']="CFLAGS=\"${werror_cflags}\""

build_tap=${WORKSPACE}/${prefix}/build.tap
# +1 for the exported-CFLAGS build below
echo "1..$((${#build_names[@]} + 1))" > "$build_tap"

test_id=0

for build_name in "${build_names[@]}"; do
    build_option="${build_list[$build_name]}"
    mkdir -p "${build_dir}/${test_id}"
    cd "${build_dir}/${test_id}"
    test_exec="${WORKSPACE}/configure --prefix=${build_dir}/${test_id}/install $build_option $jenkins_test_custom_configure && make $make_opt install"
    do_check_result "$test_exec" "$test_id" "$build_name" "$build_tap" "${build_dir}/build-${test_id}"
    cd "${build_dir}"
    test_id=$((test_id+1))
done

# Same flags, but exported into the environment instead of passed to configure.
# A global CFLAGS can have a different effect than the configure argument, for
# example when Makefile.am invokes ./configure (json-c) manually.
mkdir -p "${build_dir}/${test_id}"
cd "${build_dir}/${test_id}"
test_exec="env CFLAGS=\"${werror_cflags}\" bash -c '${WORKSPACE}/configure --prefix=${build_dir}/${test_id}/install ${jenkins_test_custom_configure} && make ${make_opt} && make install'"
do_check_result "$test_exec" "$test_id" "werror-env" "$build_tap" "${build_dir}/build-${test_id}"
cd "${build_dir}"
test_id=$((test_id+1))

echo "[${0##*/}]..................exit code = $rc"
exit $rc
