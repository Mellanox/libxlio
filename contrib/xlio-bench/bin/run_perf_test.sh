#!/bin/bash

# bash unofficial strict mode:
set -euo pipefail
IFS=$'\n\t'
EXIT_CODE=0

USER_AND_GROUP="$(id -u):$(id -g)"
BASEDIR="$WORKSPACE/contrib/xlio-bench"
echo "-- using $BASEDIR as prefix, actual work path is $(pwd)"

echo "-- tuning benchmark server $(hostname)"
sudo "$BASEDIR/lib/tune-server.sh"

echo "-- removing old run data and reports in" $BASEDIR/{run,reports}
sudo rm -rf "$BASEDIR"/{run,reports}/*

cd "$(dirname "$0")"

run_test() {
    local IFS=' ' # to split BULK_CLIENT_MHOST variable in a cycle below

    source "bulk-plan-$1.sh"
    echo "-- Running performance test with BULK_TYPE=$BULK_TYPE"
    [[ -d "$BASEDIR/run" ]] && sudo rm -rf "$BASEDIR/run"/*

    # assuming that this script is executed on benchmark server:
    local CLIENT
    for CLIENT in $BULK_CLIENT_MHOST; do
        echo "-- create workspace directory on $CLIENT"
        sudo ssh "root@$CLIENT" "mkdir -p $BASEDIR; chown -R $USER_AND_GROUP $BASEDIR"

        echo "-- Rsync workspace directory to $CLIENT"
        sudo rsync --delete --exclude run -a "$WORKSPACE" "root@$CLIENT:$(dirname "$WORKSPACE")"

        echo "-- tuning benchmark client $CLIENT"
        sudo ssh "root@$CLIENT" "sudo $BASEDIR/lib/tune-server.sh"
    done

    sudo BULK_MODES="$MODE" ./bench-bulk "bulk-plan-$1.sh"

    for CLIENT in $BULK_CLIENT_MHOST; do
        echo "-- Rsync benchmark result from $CLIENT"
        sudo rsync -a "root@$CLIENT:$BASEDIR/run" .. \
            && sudo ssh "root@$CLIENT" "rm -rf $BASEDIR/run/*"
    done

    ./report.py $BULK_TYPE "$BASEDIR/run/bench-bulk"/*
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
sudo chown -R "$USER_AND_GROUP" "$BASEDIR/reports"

echo "-- the run was OK, deleting Nginx work directory"
sudo rm -rf "$BASEDIR/run"

exit $EXIT_CODE
