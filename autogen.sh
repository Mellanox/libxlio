#!/bin/sh

set -e

# Initialize submodules in git checkouts; source archives have no .git entry.
# Keep git commands outside conditional tests so set -e propagates failures.
if test -e .git; then
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

