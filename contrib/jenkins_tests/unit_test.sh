#!/bin/bash

set -eExo pipefail

UNIT_TEST_DIR=${WORKSPACE}/tests/unit_tests
JSON_C_DIR=${WORKSPACE}/third_party/json-c
source $(dirname $0)/globals.sh

do_check_env

# Prepare libxlio
./autogen.sh
./configure

# Prepare json-c
cd ${JSON_C_DIR}
make "${make_opt}"

# Prepare unit tests
cd ${UNIT_TEST_DIR}
make "${make_opt}"

# Run unit tests
./unit_tests
