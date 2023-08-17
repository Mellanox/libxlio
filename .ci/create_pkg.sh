#!/bin/bash

BRTG=$1
BUILD_ID=$2
IMG_VER=$3

SRDIR="/etc/xlio_pkg/"
RDIR="/etc/kubelet.d/"

cd $SRDIR

rcont=`crictl ps -s running -q --name xlio`

while [ ! -z "$rcont" ]
 do
	 echo "The build server is busy"
	 sleep 1;
 done;

if [ -z "$rcont" ] 
 then
 	rm -f $RDIR/xlio_package.yaml	 
	cp template_xlio.yaml $SRDIR/xlio_package.yaml
	sed -i 's@BRANCH@'"${BRTG}"'@g' $SRDIR/xlio_package.yaml
	sed -i 's@BUILD_ID@'"${BUILD_ID}"'@g' $SRDIR/xlio_package.yaml
	sed -i 's@PATHTOIMG@'"${IMG_VER}"'@g' $SRDIR/xlio_package.yaml
	cp $SRDIR/xlio_package.yaml $RDIR/
fi

sleep 60

while [ ! -z "$rcont" ]
 do
	 echo "System is busy. Building packages"
	 sleep 1;
 done;

echo "Package creation completed"

exit 0
