#!/bin/bash

# bash unofficial strict mode:
set -euo pipefail
IFS=$'\n\t'
EXIT_CODE=0

BASEDIR="$WORKSPACE/contrib/xlio-bench"
echo "-- using $BASEDIR as prefix, actual work path is $(pwd)"

echo "-- tuning benchmark server $(hostname)"
sudo "$BASEDIR/lib/tune-server.sh"

echo "-- removing old reports in $BASEDIR/reports"
sudo rm -rf "$BASEDIR/reports"/*

cd "$(dirname "$0")"

run_test() {
    source "bulk-plan-$1.sh"
    echo "-- Running performance test with BULK_TYPE=$BULK_TYPE"
    [[ -d "$BASEDIR/run" ]] && sudo rm -rf "$BASEDIR/run"/*

    # assuming that this script is executed on benchmark server:
    echo "-- Rsync workspace directory to $BULK_CLIENT_MHOST"
    sudo rsync --delete --exclude run -a "$WORKSPACE" "root@$BULK_CLIENT_MHOST:$(dirname "$WORKSPACE")"

    echo "-- tuning benchmark client $BULK_CLIENT_MHOST"
    sudo ssh "root@$BULK_CLIENT_MHOST" "sudo $BASEDIR/lib/tune-server.sh"

    sudo BULK_MODES="$MODE" ./bench-bulk "bulk-plan-$1.sh"

    echo "-- Rsync benchmark result from $BULK_CLIENT_MHOST"
    sudo rsync -a "root@$BULK_CLIENT_MHOST:$BASEDIR/run" .. \
        && sudo ssh "root@$BULK_CLIENT_MHOST" "rm -rf $BASEDIR/run/*"
    ./report.py $BULK_TYPE "$BASEDIR/run/bench-bulk/"*
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
elif [[ "$TEST_SUITE" == "long" ]]; then
    run_test rps-long
    echo "-- sleeping 10 seconds for cleanup"
    sleep 10
    run_test cps-long
elif [[ "$TEST_SUITE" == "extra long" ]]; then
    run_test rps-extra-long
    echo "-- sleeping 10 seconds for cleanup"
    sleep 10
    run_test cps-extra-long
fi

sleep 5
echo "-- comparing benchmark to the baseline"
./check_benchmark.py || EXIT_CODE=1

echo "-- fixing permission for 'reports' directory"
sudo chown -R "$(id -u):$(id -g)" "$BASEDIR/reports"

echo "-- the run was OK, deleting Nginx work directory"
sudo rm -rf "$BASEDIR/run"

exit $EXIT_CODE
