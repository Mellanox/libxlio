#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for building with gcc ..."

cd $WORKSPACE

rm -rf ${build_dir}
mkdir -p ${build_dir}
cd ${build_dir}

# Set symbolic links to default build and install
ln -s "${build_dir}/0/install" "${install_dir}"

declare -A build_list
build_list['debug']="--enable-opt-log=no --enable-debug"
build_list['nginx-off']="--enable-nginx=no"
build_list['envoy-on']="--enable-nginx=yes"
build_list['static-on']="--enable-static --disable-shared"
build_list['default']=""

build_tap=${WORKSPACE}/${prefix}/build.tap
echo "1..$(echo $build_list | tr " " "\n" | wc -l)" > $build_tap

test_id=0

for build_name in "${!build_list[@]}"; do
    build_option="${build_list[$build_name]}"
    mkdir -p ${build_dir}/${test_id}
    cd ${build_dir}/${test_id}
    test_exec='${WORKSPACE}/configure --prefix=${build_dir}/${test_id}/install $build_option $jenkins_test_custom_configure && make $make_opt install'
    do_check_result "$test_exec" "$test_id" "$build_name" "$build_tap" "${build_dir}/build-${test_id}"
    cd ${build_dir}
    ((test_id++))
done


echo "[${0##*/}]..................exit code = $rc"
exit $rc
