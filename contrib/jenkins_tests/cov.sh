#!/bin/bash -xeEl

#shellcheck source=globals.sh
source $(dirname $0)/globals.sh

echo "Checking for coverity ..."

COVERITY_MODULE="${COVERITY_MODULE:-tools/cov-2023.12}"
do_module "${COVERITY_MODULE}"

cd "$WORKSPACE"

# shellcheck disable=SC2154
rm -rf "$cov_dir"
mkdir -p "$cov_dir"
cd "$cov_dir"

cov_exclude_file_list="tests third_party"

cov_build_id="cov_build_${BUILD_NUMBER}"
cov_build="${cov_dir}/$cov_build_id"
cov_build_examples="${cov_dir}/cov_build_examples_${BUILD_NUMBER}"

analyze_and_report_coverity() {
    local db_dir=$1
    local exclude_pattern=$2
    local stream=$3
    local tap_test_num=$4
    local tap_test_name=$5
    local local_rc=0

    # List of translated units
    eval "cov-manage-emit --config ${cov_dir}/coverity_config.xml --dir ${db_dir} list >> ${cov_dir}/cov.log 2>&1"
    sleep 1

    eval "cov-analyze --config ${cov_dir}/coverity_config.xml \
        --all --aggressiveness-level medium \
        --enable-fnptr --fnptr-models --paths 20000 \
        --disable-parse-warnings \
        --dir ${db_dir}"
    local_rc=$((local_rc + $?))


    if [[ "${do_coverity_snapshot}" == true ]]; then
        cov-commit-defects --ssl --on-new-cert trust \
            --url https://coverity.mellanox.com:8443 \
            --user "${XLIO_COV_USER}" --password "${XLIO_COV_PASSWORD}" \
            --dir "${db_dir}" \
            --stream "${stream}" \
            --strip-path "${WORKSPACE}"
        local_rc=$((local_rc + $?))
    fi

    # shellcheck disable=SC2001
    local nerrors=$(cov-format-errors --exclude-files "${exclude_pattern}" \
        --dir "${db_dir}" --html-output "${db_dir}/output/errors" | awk '/Processing [0-9]+ errors?/ { print $2 }')
    local_rc=$((local_rc + nerrors))

    # Find index.html
    local index_html=$(cd "$db_dir" && find . -name index.html | cut -c 3-)
    local cov_file="$db_dir/${index_html}"

    # Generate TAP output based on this database's errors only
    if [ "$local_rc" -gt 0 ]; then
        echo "not ok ${tap_test_num} Coverity Detected ${nerrors} ${tap_test_name} errors at ${cov_file}" >> "$coverity_tap"
        do_err "coverity" "${db_dir}/output/summary.txt"
    else
        echo "ok ${tap_test_num} Coverity found no ${tap_test_name} errors" >> "$coverity_tap"
    fi
    rc=$(("$rc"+"$local_rc"))
}

set +eE

eval "${WORKSPACE}/configure --prefix=${cov_dir}/install $jenkins_test_custom_configure > ${cov_dir}/cov.log 2>&1"
make clean >> "${cov_dir}/cov.log" 2>&1
sleep 1
eval "cov-configure --config ${cov_dir}/coverity_config.xml --gcc >> ${cov_dir}/cov.log 2>&1"
sleep 1
eval "cov-build --config ${cov_dir}/coverity_config.xml --dir ${cov_build} make $make_opt >> ${cov_dir}/cov.log 2>&1"
rc=$(($rc+$?))

for excl in $cov_exclude_file_list; do
    cov-manage-emit --config ${cov_dir}/coverity_config.xml --dir ${cov_build} --tu-pattern "file('$excl')" delete >> "${cov_dir}/cov.log" 2>&1
    sleep 1
done

coverity_tap=${WORKSPACE}/${prefix}/coverity.tap
echo 1..2 > "$coverity_tap"

set -o pipefail

analyze_and_report_coverity "${cov_build}" "(/usr/include/.*$|${WORKSPACE}/third_party/.*$)" "libxlio-main" "1" "in-project"

# Install headers needed for examples
make install >> "${cov_dir}/cov.log" 2>&1

# Build all examples in examples directory
example_build_cmd=""
for example_file in "${WORKSPACE}"/examples/*.c; do
    if [ -f "$example_file" ]; then
        if [ -n "$example_build_cmd" ]; then
            example_build_cmd="${example_build_cmd} && "
        fi
        example_build_cmd="${example_build_cmd}gcc -I${cov_dir}/install/include -o ${cov_dir}/$(basename "$example_file" .c) ${example_file} -libverbs"
    fi
done
if [ -n "$example_build_cmd" ]; then
    eval "cov-build --config ${cov_dir}/coverity_config.xml --dir ${cov_build_examples} bash -c '${example_build_cmd}' >> ${cov_dir}/cov.log 2>&1"
    rc=$(("$rc"+$?))
fi

analyze_and_report_coverity "${cov_build_examples}" "(/usr/include/.*$)" "libxlio-examples" "2" "example"

module unload "${COVERITY_MODULE}"

do_archive "$( find "${cov_build}/output" "${cov_build_examples}/output" -type f -name "*.txt" -or -name "*.html" -or -name "*.xml" )"

echo "[${0##*/}]..................exit code = $rc"
exit $rc
