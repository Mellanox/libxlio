#!/bin/bash

# bash unofficial strict mode:
set -euo pipefail
IFS=$'\n\t'
EXIT_CODE=0

echo "-- using $WORKSPACE as prefix, actual work path is $(pwd)"

echo "-- removing old reports in $WORKSPACE/contrib/xlio-bench/reports"
sudo rm -rf $WORKSPACE/contrib/xlio-bench/reports/*

cd "$(dirname "$0")"

run_test() {
    source "bulk-plan-$1.sh"
    echo "-- Running performance test with BULK_TYPE=$BULK_TYPE"
    [[ -d ../run ]] && sudo rm -rf ../run/*

    # assuming that this script is executed on benchmark server:
    echo "-- Rsync workspace directory to $BULK_CLIENT_MHOST"
    sudo rsync --delete --exclude run -a "$WORKSPACE" "root@$BULK_CLIENT_MHOST:$WORKSPACE/.."

    sudo BULK_MODES="$MODE" ./bench-bulk "bulk-plan-$1.sh"

    echo "-- Rsync benchmark result from $BULK_CLIENT_MHOST"
    sudo rsync -a "root@$BULK_CLIENT_MHOST:$(pwd)/../run" .. \
        && sudo ssh "root@$BULK_CLIENT_MHOST" "rm -rf $(pwd)/../run/*"
    ./report.py $BULK_TYPE ../run/bench-bulk/*
}

if [[ "$TEST_SUITE" == "very short" ]]; then
    run_test rps-very-short
    echo "-- sleeping 10 seconds for cleanup"
    sleep 10
    run_test cps-very-short
elif [[ "$TEST_SUITE" == "medium" ]]; then
    run_test rps-medium
    echo "-- sleeping 10 seconds for cleanup"
    sleep 10
    run_test cps-medium
fi

sleep 5
echo "-- comparing benchmark to the baseline"
./check_benchmark.py || EXIT_CODE=1

echo "-- fixing permission for 'reports' directory"
sudo chown -R "$(id -u):$(id -g)" "$WORKSPACE/contrib/xlio-bench/reports"

echo "-- the run was OK, deleting Nginx work directory"
sudo rm -rf "$WORKSPACE/contrib/xlio-bench/run"

exit $EXIT_CODE
