#!/bin/bash
#
# Let git trust the workspace so autogen.sh can init the libdpcp submodule.
# Meant to be sourced (globals.sh and the CI Autogen stage), not executed.
#
# Process-scoped configuration: never modify the user's gitconfig, since the
# home dir may be mounted from the host. Older vendor security backports only
# honor safe.directory in system/global config, so use a private temporary
# global config for the workspace and submodule. Submodule commands also need
# to trust the child repository. The temporary file remains available to child
# processes for the lifetime of the CI agent.

function do_git_safe_directory()
{
    # Jenkins supplies WORKSPACE; local invocations use the current directory.
    local workspace=${WORKSPACE:-$(pwd)}
    local count=${GIT_CONFIG_COUNT:-0}
    local found=0
    local idx key val

    # Preserve inherited command-scope settings and avoid duplicate trust entries
    # when multiple CI scripts source this helper in the same process.
    for ((idx = 0; idx < count; idx++)); do
        key="GIT_CONFIG_KEY_${idx}"
        val="GIT_CONFIG_VALUE_${idx}"
        if [[ "${!key}" == "safe.directory" && "${!val}" == "${workspace}" ]]; then
            found=1
            break
        fi
    done

    # Append workspace trust for Git versions that honor command-scope config.
    # Export all three variables so child Git processes receive the new entry.
    if [[ ${found} -eq 0 ]]; then
        export "GIT_CONFIG_KEY_${count}=safe.directory"
        export "GIT_CONFIG_VALUE_${count}=${workspace}"
        export GIT_CONFIG_COUNT=$((count + 1))
    fi

    # Trust the child before it exists: submodule update accesses it while cloning.
    local safe_directories=("${workspace}" "${workspace}/submodules/libdpcp")
    local safe_directory need_global_config=0
    # Source archives have no checkout to trust. For Git checkouts, reuse global
    # config only if it already trusts both paths, including the child repository.
    if [[ -e "${workspace}/.git" ]]; then
        for safe_directory in "${safe_directories[@]}"; do
            if ! git config --global --get-all safe.directory |
                grep -Fxq -- "${safe_directory}"; then
                need_global_config=1
                break
            fi
        done
    fi

    # Vendor Git may ignore command-scope trust. Create a private global config
    # instead of writing to the user's gitconfig, which may be mounted from a host.
    if [[ ${need_global_config} -eq 1 ]]; then
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
        # Keep existing user settings through includes. Resolve relative paths
        # before including them: includes are relative to the temporary config.
        for config_path in "${config_paths[@]}"; do
            if [[ -f "${config_path}" ]]; then
                [[ "${config_path}" = /* ]] || config_path="${PWD}/${config_path}"
                git config --file "${config_file}" --add include.path "${config_path}" || return
            fi
        done
        # Trust only these two repositories, rather than disabling ownership checks.
        # Global trust remains available to Git's internal submodule commands.
        for safe_directory in "${safe_directories[@]}"; do
            git config --file "${config_file}" --add safe.directory "${safe_directory}" || return
        done
        # Select this config for this shell and its children. Leave the file in
        # place because Autogen and later CI commands still need to read it.
        export GIT_CONFIG_GLOBAL="${config_file}"
    fi

    # Verify parent checkout access and propagate failure so Autogen cannot
    # silently skip initialization when ownership or configuration is still wrong.
    if [[ -e "${workspace}/.git" ]]; then
        git -C "${workspace}" rev-parse --is-inside-work-tree >/dev/null || return
    fi
}

# Apply trust immediately when sourced; exported settings persist in the caller.
do_git_safe_directory
