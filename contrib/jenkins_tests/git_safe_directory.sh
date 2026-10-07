#!/bin/bash
#
# Let git trust the workspace so autogen.sh can init the libdpcp submodule.
# Meant to be sourced (globals.sh and the CI Autogen stage), not executed.
#
# Process-scoped configuration: never modify the user's gitconfig, since the
# home dir may be mounted from the host. Older vendor security backports only
# honor safe.directory in system/global config, so use a private temporary
# global config when command-scope config is insufficient. The temporary file
# remains available to child processes for the lifetime of the CI agent.

function do_git_safe_directory()
{
    local workspace=${WORKSPACE:-$(pwd)}
    local count=${GIT_CONFIG_COUNT:-0}
    local found=0
    local idx key val

    for ((idx = 0; idx < count; idx++)); do
        key="GIT_CONFIG_KEY_${idx}"
        val="GIT_CONFIG_VALUE_${idx}"
        if [[ "${!key}" == "safe.directory" && "${!val}" == "${workspace}" ]]; then
            found=1
            break
        fi
    done

    if [[ ${found} -eq 0 ]]; then
        export "GIT_CONFIG_KEY_${count}=safe.directory"
        export "GIT_CONFIG_VALUE_${count}=${workspace}"
        export GIT_CONFIG_COUNT=$((count + 1))
    fi

    if [[ -e "${workspace}/.git" ]] &&
        ! git -C "${workspace}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        local config_file config_path
        local config_paths=()
        config_file=$(mktemp "${TMPDIR:-/tmp}/xlio-git-safe-directory.XXXXXX") || return

        # Include the original global configs in Git's normal precedence order.
        # GIT_CONFIG_GLOBAL replaces both default global config locations.
        if [[ -n "${GIT_CONFIG_GLOBAL:-}" ]]; then
            config_paths+=("${GIT_CONFIG_GLOBAL}")
        else
            config_paths+=("${XDG_CONFIG_HOME:-${HOME}/.config}/git/config" "${HOME}/.gitconfig")
        fi
        for config_path in "${config_paths[@]}"; do
            if [[ -f "${config_path}" ]]; then
                [[ "${config_path}" = /* ]] || config_path="${PWD}/${config_path}"
                git config --file "${config_file}" --add include.path "${config_path}" || return
            fi
        done
        git config --file "${config_file}" --add safe.directory "${workspace}" || return
        export GIT_CONFIG_GLOBAL="${config_file}"

        # Do not let autogen silently skip submodule initialization again.
        git -C "${workspace}" rev-parse --is-inside-work-tree >/dev/null || return
    fi
}

do_git_safe_directory
