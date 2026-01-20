#!/bin/bash

set -exE

{ [ -z "$1" ] || [ -z "$2" ]; } && { echo "ERROR: Usage: run_step.sh <step_name> <command>"; exit 1; }
[ -z "$name" ] && { echo "ERROR: name variable is empty"; exit 1; }
[[ -z "$WORKSPACE" ]] && { echo "ERROR: WORKSPACE variable is empty"; exit 1; }
[[ ! -d "$WORKSPACE" ]] && { echo "ERROR: $WORKSPACE does not exist"; exit 1; }

step_name="$1"
shift # Remove step name from arguments
do_chaos=${do_chaos:-false}

# In chaos mode: apply patches for this step (if any)
has_patches=false
if [ "${do_chaos}" == "true" ]; then
    patches=$(awk -v step="$step_name" \
        '/- file:/ {file=$3} /- step:/ && substr($0, index($0,$3))==step { print file }' \
        "${WORKSPACE}/.ci/chaos/chaos_config.yaml")

    if [ -n "$patches" ]; then
        has_patches=true
        for patch_file in $patches; do
            git -C "${WORKSPACE}" apply ".ci/chaos/patches/$patch_file"
        done
    fi
fi

set +eE
"$@" # Run the command
rc=$?
set -eE

# In chaos mode: reset patches and record failure (only for patched steps)
if [ "${do_chaos}" == "true" ] && [ "$has_patches" == "true" ]; then
    git -C "${WORKSPACE}" checkout -- . 2>/dev/null

    if [ "$rc" -ne 0 ]; then
        echo "=== CHAOS: Step '${step_name}' failed ==="
        mkdir -p "${WORKSPACE}/chaos_results"
        echo "$step_name" >> "${WORKSPACE}/chaos_results/${name}.txt"
        exit 0
    fi
fi

exit "$rc"
