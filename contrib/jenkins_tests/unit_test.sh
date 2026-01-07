#!/bin/bash

set -eExo pipefail

UNIT_TEST_DIR=${WORKSPACE}/tests/unit_tests
JSON_C_DIR=${WORKSPACE}/third_party/json-c
export jenkins_target="default"
source $(dirname $0)/globals.sh

# Install dpcp (required for unit tests)
do_check_env

do_check_dpcp opt_value

# Prepare libxlio
./autogen.sh
./configure --with-dpcp=${opt_value}

# Prepare json-c
cd ${JSON_C_DIR}
make "${make_opt}"

# Prepare unit tests
cd ${UNIT_TEST_DIR}
make "${make_opt}"

# Run unit tests
./unit_tests
