#!/bin/bash

BRTG=$1
BUILD_ID=$2

ST_FILE="/etc/xlio_pkg/xlio/pkg_status"

echo "1" > $ST_FILE

apt-get update
/usr/bin/apt install -y autoconf libtool debhelper build-essential ssh sudo

cd /etc/xlio_pkg/xlio
rm -rf libxlio/

git clone https://github.com/Mellanox/libxlio.git 

cd libxlio/
git checkout $BRTG

`QA_RPATHS=0x0002 PRJ_RELEASE=${BUILD_ID} contrib/build_pkg.sh -s -b -a "configure_options=--with-dpcp --disable-nginx --disable-utls" &`

PUBLISH="/hpc/noarch/xlio_artifacts/"
PKGDIR="/etc/xlio_pkg/xlio/libxlio/pkg/packages/"
echo "Package Created"

cp -av $PKGDIR/* $PUBLISH/

echo "Copy Done"


echo "0" > $ST_FILE

