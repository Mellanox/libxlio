#!/bin/sh

set -e

# Initialize git submodules if git is available and we're in a git repo
if command -v git >/dev/null 2>&1 &&
    git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    GIT_TOPLEVEL=$(git rev-parse --show-toplevel)
    if test "$(cd "$GIT_TOPLEVEL" && pwd -P)" = "$(pwd -P)"; then
        echo "Updating git submodules..."
        git submodule update --init --recursive
    fi
fi

rm -rf autom4te.cache
mkdir -p config
autoreconf -v --install || exit 1
rm -rf autom4te.cache

exit 0

