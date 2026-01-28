#!/bin/sh

set -e

# Initialize git submodules if in a git repository
if [ -d ".git" ]; then
    echo "Initializing git submodules..."
    git submodule update --init --recursive
    echo
fi

# Bootstrap libdpcp submodule if it exists
LIBDPCP_DIR="submodules/libdpcp"
if [ -f "$LIBDPCP_DIR/autogen.sh" ]; then
    echo "Bootstrapping libdpcp..."
    (cd "$LIBDPCP_DIR" && ./autogen.sh)
    echo "Bootstrapping libdpcp done"
    echo
fi

rm -rf autom4te.cache
mkdir -p config
autoreconf -v --install || exit 1
rm -rf autom4te.cache

exit 0

