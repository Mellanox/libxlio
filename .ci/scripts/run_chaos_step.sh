#!/bin/bash
set -ex

[[ $# -lt 2 ]] && { echo "ERROR: Usage: $0 <step_name> <command> [args...]"; exit 1; }
[[ -z "$WORKSPACE" ]] && { echo "ERROR: WORKSPACE variable is empty"; exit 1; }
[[ ! -d "$WORKSPACE" ]] && { echo "ERROR: $WORKSPACE does not exist"; exit 1; }
[[ -z "$CHAOS_RESULTS_DIR" ]] && { echo "ERROR: CHAOS_RESULTS_DIR variable is empty"; exit 1; }
[[ -z "$BUILD_NUMBER" ]] && { echo "ERROR: BUILD_NUMBER variable is empty"; exit 1; }

step_name="$1"
shift

cd "$WORKSPACE"

mkdir -p "${CHAOS_RESULTS_DIR}/${BUILD_NUMBER}"

# Find patches that are configured to break this step
patches_dir=".ci/chaos/patches"
patches=()
while IFS=$'\t' read -r patch step; do
    [[ "$step" == "$step_name" ]] && patches+=("$patch")
done < <(.ci/scripts/chaos_config_parse.sh)

if [ "${#patches[@]}" -eq 0 ]; then
    echo "WARNING: no chaos patches configured for step '${step_name}'"
else
    for patch_file in "${patches[@]}"; do
        git apply "${patches_dir}/${patch_file}"
    done
    # Commit so checks that run on HEAD will see the patches
    git add -A
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
if [ "${#patches[@]}" -gt 0 ]; then
  git reset --hard HEAD~1
  if [ $rc -ne 0 ]; then
    echo "=== CHAOS: step '${step_name}' failed as expected ==="
    echo "$step_name" >> "${CHAOS_RESULTS_DIR}/${BUILD_NUMBER}/${step_name}.txt"
    exit 0
  else
    echo "=== CHAOS: step '${step_name}' unexpected passed ==="
    exit 1
  fi
fi

exit $rc
