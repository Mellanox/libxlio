#!/bin/bash -Exel

echo -e "\n\n**********************************"
echo -e "\n\nStarting antivirus.sh script...\n\n"
echo -e "**********************************\n\n"

if [ -z "$1" ]; then
    if [ -z "${release_folder}" ]; then
        echo "ERROR: Please use the first script argument or env var 'release_folder'. Exit"
    fi
else
    release_folder=$1
fi
if [ ! -e "${release_folder}" ] || [ ! -d "${release_folder}" ]; then
    echo "ERROR: [${release_folder}] directory doesn't exist. Exit"
    exit 1
fi

if [ -z "$2" ]; then
    if [ -z "${release_version}" ]; then
        echo "ERROR: Please use the second script argument or env var 'release_version'. Exit"
    fi
else
    release_version=$2
    echo "FULL_VERSION from script parameter: [${release_version}]"
fi
if [ -z "${release_version}" ]; then
    release_version=$(git describe --tags $(git rev-list --tags --max-count=1))
fi

mkdir -p logs

cd ${release_folder}/${release_version}/
pkg_name=$(ls -1 libxlio-*.src.rpm)

export PROJECT_SRC_PATH=${release_folder}/${release_version}/$pkg_name
LOG=$WORKSPACE/logs/${name}_antivirus.log

sudo -E -u swx-jenkins /auto/GLIT/SCRIPTS/HELPERS/antivirus-scan.sh $PROJECT_SRC_PATH 2>&1 | tee $LOG

cat $LOG | grep 'Possibly Infected:.............     0'
if [ $? -ne 0 ];then
    status=1
else
    status=0
fi
exit $status
