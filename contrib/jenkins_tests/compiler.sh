#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for compiler ..."

cd $WORKSPACE

rm -rf $compiler_dir
mkdir -p $compiler_dir
cd $compiler_dir

compiler_list="clang:clang++:clang-15 gcc:g++:gcc-8 gcc:g++:gcc-9 gcc:g++:gcc-10 gcc:g++:gcc-11"

compiler_tap=${WORKSPACE}/${prefix}/compiler.tap
echo "1..$(echo $compiler_list | tr " " "\n" | wc -l)" > $compiler_tap

test_id=0
for compiler in $compiler_list; do
    IFS=':' read cc cxx version <<< "$compiler"
    update-alternatives --set $cc /usr/bin/$version
    mkdir -p ${compiler_dir}/${test_id}
    cd ${compiler_dir}/${test_id}
    test_name="$version"
    echo "======================================================"
    $cc --version
    echo
    test_exec='${WORKSPACE}/configure --prefix=$compiler_dir-$cc CC=$cc CXX=$cxx --disable-lto $jenkins_test_custom_configure && make $make_opt all'
    do_check_result "$test_exec" "$test_id" "$test_name" "$compiler_tap" "${compiler_dir}/compiler-${test_id}"
    cd ${compiler_dir}
    test_id=$((test_id+1))
done

echo "[${0##*/}]..................exit code = $rc"
exit $rc
