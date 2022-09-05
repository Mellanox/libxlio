#!/bin/bash
# bash unofficial strict mode:
set -euo pipefail
IFS=$'\n\t'

DIR="$(dirname "$0")"
export LUA_PATH="$DIR/?.lua"
ARCH_NAME="$(uname -m | sed 's/_.*//')"
"$DIR/../env/default-$ARCH_NAME/bin/wrk" -s "$DIR/json_report.lua" "$@" | grep json_report
