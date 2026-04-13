#!/bin/sh

set -e

# Initialize git submodules if git is available and we're in a git repo
if command -v git >/dev/null 2>&1 && test -d ".git" ; then
    echo "Updating git submodules..."
    git submodule update --init --recursive
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

