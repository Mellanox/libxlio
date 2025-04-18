#!/bin/bash -Exel

git config --global --add safe.directory ${WORKSPACE}

topdir=$(git rev-parse --show-toplevel)
cd "$topdir"

if [ -z "${WORKSPACE}" ]; then
    WORKSPACE="$topdir"
fi

if [ ! -d .git ]; then
    echo "Error: should be run from project root"
    exit 1
fi

[[ ! -d "${WORKSPACE}/logs" ]] && mkdir -p "${WORKSPACE}/logs"

json=$(jq -n \
  --arg url "https://blackduck.mellanox.com/" \
  --arg token "$BLACKDUCK_API_TOKEN" \
  '{"blackduck.url": $url, "blackduck.api.token": $token }')

export SPRING_APPLICATION_JSON="$json"
export PROJECT_NAME=libxlio
export PROJECT_VERSION="$sha1"
export PROJECT_SRC_PATH="$topdir"/src/

echo "Running BlackDuck (SRC) on $name"

echo "CONFIG:"
echo "        NAME: ${PROJECT_NAME}"
echo "     VERSION: ${PROJECT_VERSION}"
echo "    SRC_PATH: ${PROJECT_SRC_PATH}"

rm -rf /tmp/blackduck || true;
su -s /bin/bash -c 'git clone -c core.sshCommand="ssh -i ~/.ssh/id_ed25519_jenkins2_gerrit" -b master --single-branch --depth=1 ssh://git-nbu.nvidia.com:12023/DevOps/Tools/blackduck /tmp/blackduck' swx-jenkins

cd /tmp/blackduck

# disable check errors
set +xe
timeout 3600 ./run_bd_scan.sh
exit_code=$?
#enable back
set -xe

# copy run log to a place that jenkins job will archive it
REPORT_NAME="BlackDuck_report"
cat "log/${PROJECT_NAME}_${PROJECT_VERSION}"*.log > "${WORKSPACE}/logs/${REPORT_NAME}.log" || true;
cat "log/${PROJECT_NAME}_${PROJECT_VERSION}"*.log || true;

if [ "$exit_code" == "0" ]; then
    cp -v /tmp/blackduck/report/*.pdf "${WORKSPACE}/logs/${REPORT_NAME}.pdf"
fi

exit $exit_code
