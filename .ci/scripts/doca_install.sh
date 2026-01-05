#!/bin/bash

set -xvEe -o pipefail

DOCA_REPO_PATH="https://doca-repo-prod.nvidia.com/internal/repo/doca"
TARGET=${TARGET:=all}

DOCA_VERSION='3.3.0'
DOCA_BRANCH="latest"
GPG_KEY="GPG-KEY-Mellanox.pub"

function error_handler() {
    bc="$BASH_COMMAND"
    set +xv
    echo "================================= DEBUG info start ================================="
    echo "Exited with ERROR in line $1"
    echo "Failed CMD: ${bc}"
    echo "Current directory is ${PWD}"
    echo "It took $(date -d@${SECONDS} -u +%H:%M:%S) to execute $0"
    echo "================================= DEBUG info end ================================="
    exit 1
}

trap 'error_handler $LINENO' ERR

function map_os_and_arch {
    . /etc/os-release

    ARCH=$(uname -m)

    # Determine OS and ARCH
    case "$ARCH" in
        x86_64)
            ARCH="x86_64"
            ;;
        aarch64)
            ARCH="arm64-sbsa"
            ;;
        *)
            echo "Unsupported architecture for Ubuntu: $ARCH"
            return 1
    esac

    case "$ID" in
        ubuntu)
            if [[ "$VERSION_ID" =~ ^2[0-9]\.04$ ]]; then
                OS="${ID}${VERSION_ID}"
            else
                echo "Unsupported Ubuntu version: $VERSION_ID"
                exit 1
            fi
            GPG_KEY_CMD='cat "${GPG_KEY}" | gpg --dearmor > /etc/apt/trusted.gpg.d/"${GPG_KEY}"'
            REPO_CMD='echo deb [signed-by=/etc/apt/trusted.gpg.d/"${GPG_KEY}"] "${REPO_URL}" ./ >> /etc/apt/sources.list.d/doca.list'
            PKG_TYPE="deb"
            PKG_TOOL="dpkg"
            PKG_MGR="apt"
            UPDATE_CMD="update"
            ;;

        rhel|ol)
            # Extract major version only (e.g., 9.6 -> 9)
            OS="${ID}${VERSION_ID%%.*}"
            GPG_KEY_CMD='rpm --import "${GPG_KEY}"'
            REPO_CMD='yum install -y yum-utils && yum-config-manager --add-repo "${REPO_URL}"'
            PKG_TYPE="rpm"
            PKG_TOOL="rpm"
            PKG_MGR="yum --nogpgcheck"
            UPDATE_CMD="makecache"
            ;;

        ctyunos|openEuler)
            # OS="${ID}${VERSION_ID}"
            OS="ctyunos23.01"
            GPG_KEY_CMD='rpm --import "${GPG_KEY}"'
            REPO_CMD="cat <<EOF | sed 's/^[ \t]*//' > /etc/yum.repos.d/doca.repo
[doca]
name=DOCA
baseurl=\${REPO_URL}
enabled=1
gpgcheck=1
EOF
"
            PKG_TYPE="rpm"
            PKG_TOOL="rpm"
            PKG_MGR="dnf --nogpgcheck"
            UPDATE_CMD="makecache"
            ;;

        *)
            echo "Unsupported OS: $ID"
            return 1
    esac

    echo "OS=${OS}"
    echo "ARCH=${ARCH}"
    echo "PKG_TYPE=${PKG_TYPE}"
    echo "PKG_TOOL=${PKG_TOOL}"
    echo "PKG_MGR=${PKG_MGR}"
    echo "UPDATE_CMD=${UPDATE_CMD}"
    echo "GPG_KEY_CMD=${GPG_KEY_CMD}"
    echo "REPO_CMD=${REPO_CMD}"
}

# Set up os-dependend variables
map_os_and_arch

# Install DOCA repo GPG key
curl -o "${GPG_KEY}" "${DOCA_REPO_PATH}/${DOCA_VERSION}/${OS}/${ARCH}/${DOCA_BRANCH}/${GPG_KEY}"

eval "${GPG_KEY_CMD}"

# Install DOCA repo
REPO_URL="${DOCA_REPO_PATH}/${DOCA_VERSION}/${OS}/${ARCH}/${DOCA_BRANCH}/"
eval "${REPO_CMD}"

# Install DOCA
${PKG_MGR} ${UPDATE_CMD}

if [[ "$ID" == "ol" && "$ARCH" == "arm64-sbsa" ]]; then
    ${PKG_MGR} install -y --skip-broken doca-ofed-userspace
    yumdownloader doca-ofed-userspace && rpm -ivh --nodeps doca-ofed-userspace*.rpm && rm -f doca-ofed-userspace*.rpm
else
    ${PKG_MGR} install -y doca-ofed-userspace
fi

echo "=============================================="
echo
echo "DOCA for Host has been successfully installed"
echo
echo "=============================================="
