#!/bin/bash -Exel

echo -e "\n\n**********************************"
echo -e "\n\nStarting do_release.sh script...\n\n"
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

env PRJ_RELEASE=1 contrib/build_pkg.sh -s

MAJOR_VERSION=$(cat configure.ac | grep -e "define(\[prj_ver_major\]" | awk -e '{ printf $2 };' | sed  's/)//g')
MINOR_VERSION=$(cat configure.ac | grep -e "define(\[prj_ver_minor\]" | awk -e '{ printf $2 };' | sed  's/)//g')
REVISION_VERSION=$(cat configure.ac | grep -e "define(\[prj_ver_revision\]" | awk -e '{ printf $2 };' | sed  's/)//g')
configure_ac_version="${MAJOR_VERSION}.${MINOR_VERSION}.${REVISION_VERSION}"
echo "FULL_VERSION from configure.ac: [${configure_ac_version}]"

last_tag=$(git describe --tags $(git rev-list --tags --max-count=1))
echo "Last tag: [${last_tag}]"

if [[ "$last_tag" != "${configure_ac_version}" ]]; then
    echo "ERROR: FULL_VERSION from configure.ac doesn't match last tag version! Exit"
    exit 1
fi

if [ -z "${release_version}" ]; then
    release_version=${configure_ac_version}
else
    if [[ "$last_tag" != "${release_version}" ]]; then
        echo "ERROR: FULL_VERSION from script parameter doesn't match last tag version! Exit"
        exit 1
    fi
fi

_UID=6213
_GID=101
_LOGIN=swx-jenkins
_HOME=/var/home/$_LOGIN
echo "${_LOGIN} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "root ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
groupadd -f -g "$_GID" "$_LOGIN"
useradd -u "$_UID" -g "$_GID" -s /bin/bash -m -d ${_HOME} "${_LOGIN}"

cd $WORKSPACE/pkg/packages

pkg_name=$(ls -1 libxlio-*.src.rpm)

DST_DIR=${release_folder}/${release_version}
sudo -E -u swx-jenkins sh -c "mkdir -p $DST_DIR"

if [[ -e "${DST_DIR}/${pkg_name}" ]]; then 
    echo "ERROR: [${DST_DIR}/${pkg_name}] file already exist. Exit"
    exit 1
fi

sudo -E -u swx-jenkins sh -c "cp -v ${pkg_name} $DST_DIR"

cd ${release_folder}
sudo -E -u swx-jenkins sh -c "ln -s $DST_DIR/${pkg_name} ${pkg_name}"
