#!/bin/bash

main()
{
WORKSPACE=${WORKSPACE:=$(pwd)}
BUILD_NUMBER=${BUILD_NUMBER:=0}
HOSTNAME=${HOSTNAME:=$(uname -n 2>/dev/null)}

# exit code
rc=0

jenkins_test_custom_configure=${jenkins_test_custom_configure:=""}
jenkins_test_custom_prefix=${jenkins_test_custom_prefix:="jenkins"}

prefix=${jenkins_test_custom_prefix}/${jenkins_target}
build_dir=${WORKSPACE}/${prefix}/build/
install_dir=${WORKSPACE}/${prefix}/install
compiler_dir=${WORKSPACE}/${prefix}/compiler
test_dir=${WORKSPACE}/${prefix}/test
gtest_dir=${WORKSPACE}/${prefix}/gtest
rpm_dir=${WORKSPACE}/${prefix}/rpm
cov_dir=${WORKSPACE}/${prefix}/cov
cppcheck_dir=${WORKSPACE}/${prefix}/cppcheck
csbuild_dir=${WORKSPACE}/${prefix}/csbuild
vg_dir=${WORKSPACE}/${prefix}/vg
style_dir=${WORKSPACE}/${prefix}/style
tool_dir=${WORKSPACE}/${prefix}/tool
commit_dir=${WORKSPACE}/${prefix}/commit
tidy_dir=${WORKSPACE}/${prefix}/tidy

prj_lib=libxlio.so
prj_service=xliod

NPROC=8
make_opt="-j${NPROC}"

if [ $(command -v timeout >/dev/null 2>&1 && echo $?) ]; then
    timeout_exe="timeout -s SIGKILL 20m"
    timeout_exe_short="timeout -s SIGKILL 5m"
fi

trap "on_exit" INT TERM ILL KILL FPE SEGV ALRM
}

function mount_hugetlbfs()
{
    if [[ -f /.dockerenv && ! $(grep -q hugetlbfs /proc/mounts) ]]; then
        mkdir -p /mnt/huge 
        mount -t hugetlbfs nodev /mnt/huge
        grep hugetlbfs /proc/mounts
        echo $?
    fi
}

function on_exit()
{
    rc=$((rc + $?))
    echo "[${0##*/}]..................exit code = $rc"
    pkill -9 sockperf
    pkill -9 xlio
    pkill -9 ${prj_service}
}

function do_cmd()
{
    cmd="$*"
    set +e
    eval $cmd >> /dev/null 2>&1
    ret=$?
    set -e
    if [ $ret -gt 0 ]; then
        exit $ret
    fi
}

function do_export()
{
    export PATH="$1/bin:${PATH}"
    export LD_LIBRARY_PATH="$1/lib:${LD_LIBRARY_PATH}"
    export MANPATH="$1/share/man:${MANPATH}"
}

function do_archive()
{
    cmd="tar -rvf ${jenkins_test_artifacts}.tar $*"
    set +e
    eval $cmd >> /dev/null 2>&1
    set -e
}

# Test if an environment module exists and load it if yes.
# Otherwise, return error code.
# $1 - module name
#
function do_module()
{
    [ -z "$1" ] && return

    echo "Checking module $1"
    if [[ $(module avail 2>&1 | grep "$1" -q > /dev/null || echo $?) ]]; then
	    echo "[SKIP] module tool does not exist"
	    exit 0
	else
        module load "$1"
    fi
}

# format text
#
function do_format()
{
    set +x
    local is_format=true
    if [[ $is_format == true ]] ; then
        res=""
        for ((i=2; i<=$#; i++)) ; do
            case "${!i}" in
                "bold" ) res="$res\e[1m" ;;
                "underline" ) res="$res\e[4m" ;;
                "reverse" ) res="$res\e[7m" ;;
                "red" ) res="$res\e[91m" ;;
                "green" ) res="$res\e[92m" ;;
                "yellow" ) res="$res\e[93m" ;;
            esac
        done
        echo -e "$res$1\e[0m"
    else
        echo "$1"
    fi
    set -x
}

# print error message
#
function do_err()
{
    set +x
    echo -e $(do_format "FAILURE: $1" "red" "bold") 2>&1
    if [ -n "$2" ]; then
        echo ">>>"
        cat $2
        echo ">>>"
    fi
    set -x
}

# Verify if current environment is suitable.
#
function do_check_env()
{
    echo "Checking system configuration"
    if [ $(command -v pkill >/dev/null 2>&1 || echo $?) ]; then
        echo "pkill is not found"
        echo "environment [NOT OK]"
        exit 1
    fi

    if [ "$(whoami)" == "root" ]; then
        export sudo_cmd=""
    else
        export sudo_cmd="sudo"
    fi

    if [ $(${sudo_cmd} pwd >/dev/null 2>&1 || echo $?) ]; then
        echo "${sudo_cmd} does not work"
        echo "environment [NOT OK]"
        exit 1
    fi

    if [ $(command -v ofed_info >/dev/null 2>&1 || echo $?) ]; then
        echo "Configuration: INBOX : ${ghprbTargetBranch}"
        export jenkins_ofed=inbox
    else
        echo "Configuration: MOFED[$(ofed_info -s)] : ${ghprbTargetBranch}"
        export jenkins_ofed=$(ofed_info -s | sed 's/.*[l|X]-\([0-9\.]\+\).*/\1/')
    fi

    echo "environment [OK]"
}

# Launch command and detect result of execution
# $1 - test command
# $2 - test id
# $3 - test name
# $4 - test tap file
# $5 - files for stdout/stderr
#
function do_check_result()
{
    set +e
    if [ -z "$5" ]; then
        eval $timeout_exe $1
        ret=$?
    else
        eval $timeout_exe $1 2>> "${5}.err" 1>> "${5}.log"
        ret=$?
        do_archive "${5}.err" "${5}.log"
    fi
    set -e
    if [ $ret -gt 0 ]; then
        echo "not ok $2 $3" >> $4
        if [ -z "$5" ]; then
            do_err "$1"
        else
            do_err "$1" "${5}.err"
        fi
    else
        echo "ok $2 $3" >> $4
    fi
    rc=$((rc + $ret))
}

# Detect interface ip
# $1 - [ib|eth|inet6] to select link type or empty to select the first found
# $2 - [empty|mlx4|mlx5|ConnectX-4|ConnectX-5|ConnectX-6|ConnectX-7] (default: ConnectX-7)
# $3 - ip address not to get
#
function do_get_ip()
{
    opt1=${1:-'eth'}
    opt2=${2:-'ConnectX-7'}
    opt3=${3:-''}

    sv_ifs=${IFS}
    # filter by second parameter
    netdevs=$(${sudo_cmd} ibdev2netdev -v | grep Up | grep "$opt2" | awk -F' ' '{ print $(NF-1) }')
    IFS=$'\n' read -rd '' -a netdev_ifs <<< "${netdevs}"
    lnkifs=$(ip -o link | awk '{print $2,$(NF-2)}')
    IFS=$'\n' read -rd '' -a lnk_ifs <<< "${lnkifs}"
    IFS=${sv_ifs}
    ifs_array=()

    for nd_if in "${netdev_ifs[@]}" ; do
        found_if=''
        for v_if in "${lnk_ifs[@]}" ; do
            if [ ! -z "$(echo ${v_if} | grep ${nd_if})" ] ; then
                mac=$(echo "${v_if}"| awk '{ print $NF }') #; echo "mac=$mac"
                for p_if in "${lnk_ifs[@]}" ; do
                    if [ ! -z "$(echo ${p_if} | grep -E ${mac} | grep -Ei eth)" ] ; then
                        if_name=$(echo "${p_if}"| awk '{ print $1}')
                        ifs_array+=(${if_name::-1})
                        #-#echo "${nd_if} --> ${if_name::-1} "
                        found_if=1
                        break 2
                    fi
                done
            fi
        done
        # use the netdevice if needed
        [ -z "${found_if}" ] && {
            ifs_array+=(${nd_if})
        }
    done

    if [ "${#ifs_array[@]}" -le 1 ] ; then
        if (dmesg | grep -i hypervisor > /dev/null 2>&1) ; then
           ifs_array=(eth1 eth2)
        fi
    fi

    # collect ip addresses
    for _if in ${ifs_array[@]}; do
        if [ -n "$opt1" -a "$opt1" == "ib" -a -n "$(ip link show $_if | grep 'link/inf')" ]; then
            found_ip=$(ip -4 address show $_if | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
        elif [ -n "$opt1" -a "$opt1" == "inet6" -a -n "$(ip link show $_if | grep 'link/eth')" ]; then
            found_ip=$(ip -6 address show $_if | grep 'inet6' | sed 's/.*inet6 \([0-9a-fA-F\:]\+\).*/\1/' | grep -v fe80 | head -n 1)
        elif [ -n "$opt1" -a "$opt1" == "eth" -a -n "$(ip link show $_if | grep 'link/eth')" ]; then
            found_ip=$(ip -4 address show $_if | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/' | head -n1)
        elif [ -z "$opt1" ]; then
            found_ip=$(ip -4 address show $_if | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/' | head -n1)
        fi
        # skip ip address passed as the third parameter
        if [ -n "$found_ip" -a "$found_ip" != "$opt3" ]; then
            echo $found_ip
            break
        fi
    done
}

do_version_check()
{
    local version="$1" operator="$2" value="$3"
    awk -vv1="$version" -vv2="$value" 'BEGIN {
        split(v1, a, /\./); split(v2, b, /\./);
        if (a[1] == b[1]) {
            exit (a[2] '$operator' b[2]) ? 0 : 1
        }
        else {
            exit (a[1] '$operator' b[1]) ? 0 : 1
        }
    }'
}

do_compile_doca()
{
    echo ""
    echo "===== DOCA checkout & compilation starts ====="
    echo ""
    doca_version="2.10.0025-1"
    doca_sdk="$WORKSPACE/$prefix/doca-sdk"
    doca_repo="ssh://git-nbu.nvidia.com:12023/doca/doca"
    doca_build="$WORKSPACE/$prefix/doca"
    doca_install="/opt/mellanox/doca"
    doca_branch="$doca_version"

    if [[ -d $doca_install && -f $doca_install/include/doca_version.h ]]; then
        echo ""
        echo "===== DOCA is already compiled and installed at $doca_install ====="
        echo ""
        eval "$1=$doca_install"
        return
    fi

    if [[ -d "$doca_sdk" ]]; then
        echo "Directory $doca_sdk exists. Updating..."
        git config --global --add safe.directory "$doca_sdk"
        pushd "$doca_sdk" || exit 1
        git fetch origin "$doca_branch"
        git checkout "$doca_branch"
        git merge origin/"$doca_branch"
    else
        echo "Directory $doca_sdk does not exist. Cloning..."
        mkdir -p "$doca_sdk"
        if [[ -f /.dockerenv ]]; then
            chown -R swx-jenkins "$doca_sdk"
            sudo -u swx-jenkins git clone --depth 1 -b "$doca_branch" "$doca_repo" "$doca_sdk"
            chown -R root "$doca_sdk"
        else
            git clone -b "$doca_branch" "$doca_repo" "$doca_sdk"
        fi
        pushd "$doca_sdk" || exit 1
    fi

    if [[ -f /.dockerenv ]]; then
        SUDO=""
    else
        SUDO="sudo"
    fi

    #if ! $SUDO devtools/scripts/prepare_for_dev.sh --host --local; then
    #    echo "Cannot prepare for dev..."
    #    exit 1
    #fi

    # shellcheck source=/dev/null
    #if ! ($SUDO source devtools/public/set_env_variables.sh --deb); then
    #    echo "Cannot set up ENV..."
    #fi

    $SUDO mkdir -p "$doca_build"

    if ! $SUDO meson "$doca_build"; then
        echo "Cannot prepare the project for compilation..."
        exit 1
    fi

    if $SUDO ninja -C "$doca_build" $make_opt; then
        if $SUDO ninja -C "$doca_build" install; then
            eval "$1=$doca_install"
        fi
        $SUDO echo $doca_install/lib/x86_64-linux-gnu > /etc/ld.so.conf.d/doca.conf 
        $SUDO ldconfig
        echo ""
        echo "===== DOCA compilation complete ====="
        echo ""
    else
        echo "Compilation error..."
        exit 1
    fi

    popd
}

do_check_dpcp()
{
    local ret=0
    local version=$(echo "${jenkins_ofed}" | cut -f1-2 -d.)

    if do_version_check $version '<' '5.2' ; then
        return
    fi
    echo "Checking dpcp usage"

    ret=0
    pushd $(pwd) > /dev/null 2>&1
    dpcp_dir=${WORKSPACE}/${prefix}/_dpcp-last
    mkdir -p ${dpcp_dir}
    cd ${dpcp_dir}

    # libdpcp_path="<repo>|<branch>|<commit>"
    # Example:
    # https://<user>:<password>@<repo>|<branch>|<sha>
    # https://<repo>|<branch>
    # git@<repo>
    #
    libdpcp_path=${libdpcp_path:="https://github.com/Mellanox/libdpcp|master"}
    libdpcp_repo=$(echo $libdpcp_path | cut -d'|' -f1)
    libdpcp_branch=$(echo $libdpcp_path | cut -d'|' -f2)
    libdpcp_commit=$(echo $libdpcp_path | cut -d'|' -f3)
    echo "dpcp repo: $libdpcp_repo"
    echo "dpcp branch: $libdpcp_branch"
    echo "dpcp commit: $libdpcp_commit"

    set +e
    if [ ! -d ${dpcp_dir}/install -a $ret -eq 0 ]; then
		eval "timeout -s SIGKILL 30s git clone -b ${libdpcp_branch} ${libdpcp_repo} . "
        ret=$?
    fi

    if [ -z "$libdpcp_commit" -a $ret -eq 0 ]; then
        libdpcp_commit=$(git describe --tags $(git rev-list --tags --max-count=1))
        if [ -z "$libdpcp_commit" ]; then
            libdpcp_commit=$(git rev-parse --short HEAD)
        fi
    fi

    if [ ! -d ${dpcp_dir}/install -a $ret -eq 0 ]; then
        eval "git checkout $libdpcp_commit"
        ret=$?
    fi

    if [ ! -d ${dpcp_dir}/install -a $ret -eq 0 ]; then
        eval "./autogen.sh && ./configure --prefix=${dpcp_dir}/install && make $make_opt install"
        ret=$?
    fi
    set -e

    popd > /dev/null 2>&1
    if [ $ret -eq 0 ]; then
        eval "$1=${dpcp_dir}/install"
        echo "dpcp: $last_tag : ${dpcp_dir}/install"
    else
        echo "dpcp: no"
    fi
}

#######################################################
#
main "$@"
