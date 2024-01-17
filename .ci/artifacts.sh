#!/bin/bash -xl

if [ -d jenkins ]; then
    pushd ./jenkins/${flags};
    gzip -f *.tar 2>/dev/null || true
    for f in *.tar.gz ; do mv -f "$f"  "arch-${name}-$f" ; done;
    for f in *.{tap,xml} ; do mv -f "$f" "${flags}-${name}-$f" ; done ;
    popd
fi
