#!/bin/bash -xeEl

# Dependencies:
# clang/cclang++ compilers (llvm-toolset-X package)
# clang-format (llvm-toolset-X package)
# clang-tidy (clang-tools-extra package)
# compiledb - (pip install compiledb) Tool for generating Clang's JSON Compilation Database file
#             for GNU make-based build systems. (pip install compiledb)
# clang version 13.0.1
##############################

source $(dirname $0)/globals.sh

echo "Checking for tidy ..."

cd $WORKSPACE

rm -rf $tidy_dir
mkdir -p $tidy_dir
cd $tidy_dir

test_name="tidy"
test_app="clang-tidy"
test_conf=$tidy_dir/tidy.conf

if [ $(command -v $test_app >/dev/null 2>&1 || echo $?) ]; then
    echo can not find $test_app
    exit 1
fi

if [ $(command -v compiledb >/dev/null 2>&1 || echo $?) ]; then
    echo can not find compiledb
    exit 1
fi

test_tap=${WORKSPACE}/${prefix}/${test_name}_test.tap
rm -rf ${test_tap}

cat <<EOF >${test_conf}
# Configure clang-tidy for this project.

Checks: '
  -*,
  readability-braces-around-statements
  '
WarningsAsErrors: '
  -*,
  readability-braces-around-statements
  '
#HeaderFilterRegex: 'src/|tools/|tests/gtest/'
HeaderFilterRegex: ''
FormatStyle: 'file'
EOF
ln -sf ${test_conf} $WORKSPACE/.clang-tidy
cat ${test_conf} 2>&1 | tee -a "${tidy_dir}/${test_name}.log"

if [ ! -e $WORKSPACE/.clang-format ]; then
    ln -sf $WORKSPACE/contrib/jenkins_tests/style.conf $WORKSPACE/.clang-format
fi

check_files="$(find $WORKSPACE/src/ ! -name 'config_*' -a \( -iname '*.c' -o -iname '*.cpp' -o -iname '*.hpp' -o -iname '*.h' \) 2>&1 | tee -a "${tidy_dir}/${test_name}.log")"
check_files+=" $(find $WORKSPACE/tools/daemon/ \( -iname '*.c' -o -iname '*.cpp' -o -iname '*.hpp' -o -iname '*.h' \) 2>&1 | tee -a "${tidy_dir}/${test_name}.log")"
check_files+=" $(find $WORKSPACE/tests/gtest/ \( -path "*/googletest" \) ! -prune -o ! -name 'tap.h' -a \( -iname '*.c' -o -iname '*.cpp' -o -iname '*.cc' -o -iname '*.hpp' -o -iname '*.h' \) 2>&1 | tee -a "${tidy_dir}/${test_name}.log")"

i=0
nerrors=0

mkdir -p ${tidy_dir}/build-${test_name}
cd ${tidy_dir}/build-${test_name}
${WORKSPACE}/configure CC=clang CXX=clang++ $jenkins_test_custom_configure 2>&1 | tee -a "${tidy_dir}/${test_name}.log"
compiledb --no-build --output ${tidy_dir}/compile_commands.json make $make_opt all 2>&1 | tee -a "${tidy_dir}/${test_name}.log"
compiledb --no-build --output ${tidy_dir}/compile_commands.json make $make_opt -C tests/gtest 2>&1 | tee -a "${tidy_dir}/${test_name}.log"
cd ${tidy_dir}

mkdir -p ${tidy_dir}/diff
for file in $check_files; do
    set +eE
    tidy_diff="${tidy_dir}/diff/$(basename ${file}).diff"
    eval "env $test_app -fix -p ${tidy_dir} \
        ${file} \
        --extra-arg=-fheinous-gnu-extensions --extra-arg=-Wno-unused-function --extra-arg=-Wno-return-type --extra-arg=-Wno-microsoft-template \
        --extra-arg=-I/usr/include/libnl3 \
        2>> ${tidy_dir}/${test_name}.err 1>> ${tidy_dir}/${test_name}.log"

    eval "git diff ${file} > ${tidy_diff} 2>&1"
    [ -s ${tidy_diff} ]
    ret=$((1-$?))
    nerrors=$((nerrors+ret))
    set -eE

    file=$(basename ${file})
    if [ $ret -gt 0 ]; then
        i=$((i+1))
        echo "not ok $i $file # See: ${file}.diff" >> ${test_tap}
    else
        rm -rf ${tidy_diff}
    fi
done
if [ $nerrors -eq 0 ]; then
    echo "1..1" > ${test_tap}
    echo "ok 1 all $(echo "$check_files" | wc -l) files" >> ${test_tap}
else
    mv ${test_tap} ${test_tap}.backup
    echo "1..$(cat ${test_tap}.backup | wc -l)" > ${test_tap}
    cat ${test_tap}.backup >> ${test_tap}
    rm -rf ${test_tap}.backup
fi
rc=$(($rc+$nerrors))

do_archive "${tidy_dir}/diff/*.diff" "${tidy_dir}/${test_name}.err" "${tidy_dir}/${test_name}.log"

echo "[${0##*/}]..................exit code = $rc"
exit $rc
