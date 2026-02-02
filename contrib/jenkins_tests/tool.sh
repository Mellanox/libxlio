#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for tool ..."

# Check dependencies
if [ $(test -d ${install_dir} >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] Not found ${install_dir} : build should be done before this stage"
	exit 1
fi

cd $WORKSPACE

rm -rf $tool_dir
mkdir -p $tool_dir
cd $tool_dir

# No tools to check
tool_list=""

tool_tap=${WORKSPACE}/${prefix}/tool.tap
echo "1..1" > $tool_tap
echo "ok 1 tool (no tools to check)" >> $tool_tap

echo "[${0##*/}]..................exit code = $rc"
exit $rc
