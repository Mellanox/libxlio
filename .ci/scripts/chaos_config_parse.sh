#!/bin/bash
# Parse .ci/chaos/chaos_config and emit one "<patch><TAB><step>" line per
# (patch, step) pair. Step names may contain spaces.
set -e

config=".ci/chaos/chaos_config"

while IFS= read -r line || [[ -n "$line" ]]; do
    { [[ "$line" =~ ^[[:space:]]*(#|$) ]] || [[ "$line" != *:* ]]; } && continue
    patch="${line%%:*}"
    rest="${line#*:}"
    IFS=',' read -r -a steps <<< "$rest"
    for step in "${steps[@]}"; do
        # trim leading/trailing whitespace
        step="${step#"${step%%[![:space:]]*}"}"
        step="${step%"${step##*[![:space:]]}"}"
        [[ -z "$step" ]] && continue
        printf '%s\t%s\n' "$patch" "$step"
    done
done < "$config"
