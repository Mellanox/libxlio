#!/bin/bash
#
# Let git trust the workspace and its submodules so autogen.sh can init the
# libdpcp submodule. Meant to be sourced (globals.sh and the CI Autogen stage),
# not executed.
#
# Process-scoped (no write to ~/.gitconfig): the home dir may be mounted from
# the host. Safe to source more than once per run.

# Print the directories git has to trust, one per line: the workspace and every
# submodule path from .gitmodules. Each submodule is a separate repository for
# git's ownership check, and old git has no wildcard for safe.directory.
function do_git_safe_directory_list()
{
    local workspace=$1
    local path

    echo "${workspace}"
    if [[ -f "${workspace}/.gitmodules" ]]; then
        git config -f "${workspace}/.gitmodules" --get-regexp '^submodule\..*\.path$' |
            while read -r _ path; do
                echo "${workspace}/${path}"
            done
    fi
}

# CTyunOS git (2.33) ignores safe.directory passed through GIT_CONFIG_COUNT and
# XDG_CONFIG_HOME, so use a real config file in a temp location and point
# GIT_CONFIG_GLOBAL at it. It replaces the global config git would otherwise
# read, so the one in effect is included to keep what is already set
# (credentials, URL rewrites, ...).
function do_git_safe_directory_file()
{
    local previous=${GIT_CONFIG_GLOBAL:-}
    local original tmp_cfg dir

    tmp_cfg=$(mktemp)
    for original in "${previous}" "${HOME}/.gitconfig" "${XDG_CONFIG_HOME:-${HOME}/.config}/git/config"; do
        if [[ -n "${original}" && -f "${original}" ]]; then
            printf '[include]\n\tpath = %s\n' "${original}" >> "${tmp_cfg}"
            # An explicit GIT_CONFIG_GLOBAL is the only global config git reads
            [[ "${original}" == "${previous}" ]] && break
        fi
    done
    printf '[safe]\n' >> "${tmp_cfg}"
    for dir in "$@"; do
        printf '\tdirectory = %s\n' "${dir}" >> "${tmp_cfg}"
    done
    export GIT_CONFIG_GLOBAL=${tmp_cfg}
}

# Everywhere else GIT_CONFIG_COUNT/KEY_n/VALUE_n works (git >= 2.31). Append to
# any entries already set, and skip directories that are already present.
function do_git_safe_directory_env()
{
    local count=${GIT_CONFIG_COUNT:-0}
    local dir idx key val found

    for dir in "$@"; do
        found=0
        for ((idx = 0; idx < count; idx++)); do
            key="GIT_CONFIG_KEY_${idx}"
            val="GIT_CONFIG_VALUE_${idx}"
            if [[ "${!key}" == "safe.directory" && "${!val}" == "${dir}" ]]; then
                found=1
                break
            fi
        done
        if [[ ${found} -eq 0 ]]; then
            export "GIT_CONFIG_KEY_${count}=safe.directory"
            export "GIT_CONFIG_VALUE_${count}=${dir}"
            count=$((count + 1))
        fi
    done
    export GIT_CONFIG_COUNT=${count}
}

function do_git_safe_directory()
{
    local workspace=${WORKSPACE:-$(pwd)}
    local dirs dir missing=0

    # Nothing to do without git
    command -v git >/dev/null 2>&1 || return 0

    mapfile -t dirs < <(do_git_safe_directory_list "${workspace}")

    # Nothing to do if git already trusts all of them (e.g. sourced before)
    for dir in "${dirs[@]}"; do
        git config --get-all safe.directory | grep -qxF "${dir}" || missing=1
    done
    [[ ${missing} -eq 1 ]] || return 0

    # CTyunOS git does not honor safe.directory given through the environment
    # (GIT_CONFIG_COUNT/KEY_n/VALUE_n, XDG_CONFIG_HOME): it only works from a
    # config file, so use GIT_CONFIG_GLOBAL there. All other distros work with
    # the environment variables, which GIT_CONFIG_GLOBAL cannot replace on git 2.31.
    if grep -qis ctyunos /etc/os-release; then
        do_git_safe_directory_file "${dirs[@]}"
    else
        do_git_safe_directory_env "${dirs[@]}"
    fi
}

do_git_safe_directory
