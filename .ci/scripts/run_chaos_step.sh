#!/bin/bash
set -exE

[[ $# -lt 2 ]] && { echo "ERROR: Usage: $0 <step_name> <command> [args...]"; exit 1; }
[[ -z "$WORKSPACE" ]] && { echo "ERROR: WORKSPACE variable is empty"; exit 1; }
[[ ! -d "$WORKSPACE" ]] && { echo "ERROR: $WORKSPACE does not exist"; exit 1; }
[[ -z "$CHAOS_RESULTS_DIR" ]] && { echo "ERROR: CHAOS_RESULTS_DIR variable is empty"; exit 1; }
[[ -z "$BUILD_NUMBER" ]] && { echo "ERROR: BUILD_NUMBER variable is empty"; exit 1; }

step_name="$1"
shift

cd "$WORKSPACE"

# Find patches that are configured to break this step
patches_dir=".ci/chaos/patches"
patches=""
while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    patch="${line%%:*}"; patch="${patch//[[:space:]]/}"
    rest="${line#*:}"
    for step in $rest; do
        if [[ "$step" == "$step_name" ]]; then
            patches="${patches:+$patches }$patch"
            break
        fi
    done
done < ".ci/chaos/chaos_config"

if [ -n "$patches" ]; then
    for patch_file in $patches; do
        git apply "${patches_dir}/${patch_file}"
    done
    # Commit so checks that run on HEAD will see the patches
    git add -u
    git -c user.name="Chaos CI" -c user.email="chaos@ci" commit -s -m "Apply chaos patches for chaos testing"
fi

# Run the real step (may fail under chaos)
set +ex
echo "=== CHAOS: starting real step '${step_name}' ==="
"$@"
rc=$?
echo "=== CHAOS: real step done with exit code $rc ==="
set -ex

# Revert chaos commit and record failure
if [ -n "$patches" ]; then
  git reset --hard HEAD~1
  if [ $rc -ne 0 ]; then
    echo "=== CHAOS: step '${step_name}' failed as expected ==="
    mkdir -p "${CHAOS_RESULTS_DIR}/${BUILD_NUMBER}"
    echo "$step_name" >> "${CHAOS_RESULTS_DIR}/${BUILD_NUMBER}/${step_name}.txt"
  fi
fi

exit $rc
