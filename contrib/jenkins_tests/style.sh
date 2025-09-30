#!/bin/bash -xeEl

source $(dirname $0)/globals.sh

echo "Checking for codying style ..."

cd $WORKSPACE

rm -rf $style_dir
mkdir -p $style_dir
cd $style_dir

echo "Check the clang/clang-format version:"
echo "clang: $(clang --version |grep -i version)"
echo "clang-format: $(clang-format --version |grep -i version)"

clang_version=$(clang --version | grep -oP '(?<=version )\d+' | head -1)
clang_allowed_versoins="15 16"

if [[ ! "$clang_allowed_versoins" =~ "$clang_version" ]]; then
    echo "Wrong clang-version: $clang_version"
    exit 1
fi 

test_app="clang-format"

if [ $(command -v $test_app >/dev/null 2>&1 || echo $?) ]; then
    echo can not find $test_app
    exit 1
fi

style_tap=${WORKSPACE}/${prefix}/style_test.tap
rm -rf $style_tap
ln -sf $WORKSPACE/contrib/jenkins_tests/style.conf $WORKSPACE/.clang-format


check_files="$(find $WORKSPACE/src/ ! -name 'config_*' -a \( -iname '*.c' -o -iname '*.cpp' -o -iname '*.h' -o -name '*.cc' \))"
check_files+=" $(find $WORKSPACE/tools/daemon/ \( -iname '*.c' -o -iname '*.cpp' -o -iname '*.h' -o -iname '*.cc' \))"
check_files+=" $(find $WORKSPACE/examples/ \( -iname '*.c' -o -iname '*.cpp' -o -iname '*.h' -o -iname '*.cc' \))"
check_files+=" $(find $WORKSPACE/tests/gtest/ \( -path "*/googletest" \) ! -prune -o ! \( -name 'tap.h' -o -name 'gtest.h' -o -name 'gtest-all.cc' \) -a \( -iname '*.c' -o -iname '*.cpp' -o -iname '*.h' -o -iname '*.cc' \))"

i=0
nerrors=0

for file in $check_files; do
    set +eE
    style_diff="${style_dir}/$(basename ${file}).diff"
    if [ "$jenkins_opt_style_force" = "yes" ]; then
        eval "env $test_app -i -style=file ${file}"
    else
        eval "env $test_app $test_app_opt -style=file \
            ${file} \
            | diff -u ${file} - | sed -e '1s|-- |--- a/|' -e '2s|+++ -|+++ b/$file|' \
            > ${style_diff} 2>&1"
    fi
    [ -s ${style_diff} ]
    ret=$((1-$?))
    nerrors=$((nerrors+ret))
    set -eE

    file_name=$(basename ${file})
    if [ $ret -gt 0 ]; then
        i=$((i+1))
        echo "not ok $i $file_name # See: ${file_name}.diff" >> $style_tap
        if [ "$jenkins_opt_style_force" = "auto" ]; then
            eval "env $test_app -i -style=file ${file}"
        fi
    else
        rm -rf ${style_diff}
    fi
done
if [ $nerrors -eq 0 ]; then
    echo "1..1" > $style_tap
    echo "ok 1 all $(echo "$check_files" | wc -l) files" >> $style_tap
else
    mv $style_tap ${style_tap}.backup
    echo "1..$(cat ${style_tap}.backup | wc -l)" > $style_tap
    cat ${style_tap}.backup >> $style_tap
    rm -rf ${style_tap}.backup
fi
rc=$(($rc+$nerrors))

do_archive "${style_dir}/*.diff"

echo "[${0##*/}]..................exit code = $rc"
exit $rc
