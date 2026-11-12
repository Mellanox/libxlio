#!/bin/bash -eExl

source "$(dirname "$0")/globals.sh"

# Fix hugepages for docker environments
do_hugepages
ulimit -l unlimited
ulimit -c unlimited

echo "Checking for gtest ..."

if [[ -z "${MANUAL_RUN}" ]]; then
	# Check dependencies
	if [ $(test -d ${install_dir} >/dev/null 2>&1 || echo $?) ]; then
		echo "[SKIP] Not found ${install_dir} : build should be done before this stage"
		exit 1
	fi

	cd "$WORKSPACE"

	rm -rf "$gtest_dir"
	mkdir -p "$gtest_dir"
	cd "$gtest_dir"

	gtest_app="$PWD/tests/gtest/gtest"
	gtest_lib=$install_dir/lib/${prj_lib}
	opt2=''
else
	# Enable running gtest tests manually without build stage requirement.
	# To run manually. From main directory:
	# env MANUAL_RUN=1 MANUAL_RUN_GTEST_APP=<gtest-path>/gtest MANUAL_RUN_INST_DIR=<xlio-install-path> MANUAL_RUN_ADAPTER='ConnectX-6' WORKSPACE=$PWD TARGET=default jenkins_test_gtest=yes contrib/test_jenkins.sh
	cd "$WORKSPACE"
	gtest_app=${MANUAL_RUN_GTEST_APP}
	install_dir=${MANUAL_RUN_INST_DIR}
	gtest_lib=$install_dir/lib/${prj_lib}
	opt2=${MANUAL_RUN_ADAPTER:-'ConnectX-7'}
fi

# CI owns interface discovery; the shared runner owns test profiles.
gtest_addr="$(ip -f inet addr show net1 | awk '/inet / {print $2}' | cut -d/ -f1),$(ip -f inet addr show net2 | awk '/inet / {print $2}' | cut -d/ -f1)"
gtest_addr6="$(ip -f inet6 addr show net1 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1),$(ip -f inet6 addr show net2 | grep global | awk '/inet6 / {print $2}' | cut -d/ -f1)"
# A fresh directory also avoids stale artifacts in MANUAL_RUN mode.
mkdir -p "$gtest_dir"
gtest_results=$(mktemp -d "$gtest_dir/results.XXXXXX")
read -r -a gtest_sudo <<< "${sudo_cmd}"

function own_gtest_evidence()
{
    # sudo-run tests can leave mode-0600 cores and private result directories.
    # Keep the saved copies readable by the caller that packages the archive.
    if ((${#gtest_sudo[@]})); then
        "${gtest_sudo[@]}" chown -- "$(id -u):$(id -g)" "$1" || return 1
    fi
}

function copy_gtest_evidence()
{
    "${gtest_sudo[@]}" cp -L -- "$1" "$2" || return 1
    own_gtest_evidence "$2"
}

# Store each binary version once; relative links remain valid after extraction.
function save_gtest_binary()
{
    local source=$1 destination=$2 digest saved temporary copied_digest
    digest=$("${gtest_sudo[@]}" sha256sum -- "$source") || return 1
    digest=${digest%% *}
    saved="binaries/$(basename -- "$destination")-$digest"
    mkdir -p "$gtest_crash_dir/binaries" || return 1
    if [[ ! -f "$gtest_crash_dir/$saved" ]]; then
        temporary=$(mktemp "$gtest_crash_dir/binaries/.copy.XXXXXX") || return 1
        if ! copy_gtest_evidence "$source" "$temporary"; then
            rm -f -- "$temporary"
            return 1
        fi
        copied_digest=$(sha256sum -- "$temporary") || { rm -f -- "$temporary"; return 1; }
        if [[ ${copied_digest%% *} != "$digest" ]]; then
            echo "WARNING: binary changed during collection: $source" >&2
            rm -f -- "$temporary"
            return 1
        fi
        mv -- "$temporary" "$gtest_crash_dir/$saved" || return 1
    fi
    ln -sfn -- "../../$saved" "$destination" || return 1
    printf 'binary=%s archive_path=%s\n' "$(basename -- "$destination")" "$saved"
}

function collect_gtest_crash()
{
	local sample_name=$1 sample_rc=$2 command=$3 sample_results=$4
	local sample_dir="$gtest_crash_dir/${sample_name//\//-}"
	# Keep matching binaries and core diagnostics across the EXTRA_API rebuild.
	local binaries="$sample_dir/binaries"
	local core previous current attempt executable relative core_report evidence library_name
	local helper="$(dirname -- "$gtest_app")/ultra_api_connect_helper"
	local found=0
	mkdir -p "$sample_dir" || return 1
	{
		printf 'sample=%s\nstatus=%s\ncommand=%s\n' "$sample_name" "$sample_rc" "$command"
		printf 'results=%s\ncore_pattern=%s\n' "$sample_results" "$gtest_core_pattern"
		# Preserve runner metadata, logs and rendered configs without duplicating
		# XML files under Jenkins' recursive JUnit search.
		if [[ -d "$sample_results" ]]; then
			while IFS= read -r -d '' evidence; do
				relative=${evidence#"$sample_results"/}
				mkdir -p -- "$(dirname -- "$sample_dir/results/$relative")" || return 1
				copy_gtest_evidence "$evidence" "$sample_dir/results/$relative" || return 1
			done < <("${gtest_sudo[@]}" find "$sample_results" -type f \
				\( -name 'command.txt' -o -name '*.log' -o -name '*.json' -o -name 'summary.txt' \) -print0)
		fi
		# Each invocation has a fresh private output root. Its timestamped child
		# directories cannot contain dumps from previous samples or other jobs.
		if [[ "$gtest_collect_cores" == 1 && -d "$sample_results" ]]; then
			while IFS= read -r -d '' core; do
				# Ignore non-core files even if their names match the kernel pattern.
				"${gtest_sudo[@]}" env LC_ALL=C readelf -h "$core" 2>/dev/null | grep -q 'Type:.*CORE' || continue
				found=$((found + 1))
				previous=$("${gtest_sudo[@]}" stat -c %s -- "$core")
				for attempt in {1..5}; do
					sleep 1
					current=$("${gtest_sudo[@]}" stat -c %s -- "$core")
					[[ "$current" == "$previous" ]] && break
					previous=$current
				done
				[[ "$current" == "$previous" && $attempt -lt 5 ]] || \
					echo "WARNING: core may still be incomplete: $core"
				printf 'core=%s\n' "$core"
				# TODO(DevOps): In a subsequent PR, copy the core to NFS and print
				# its NFS path here. Keep core files out of Jenkins artifacts so
				# the artifacts stay small. At the beginning of each run, clean
				# that NFS directory by deleting core files older than X days;
				# choose and configure the retention period X in that PR.
				relative=${core#"$sample_results"/}
				core_report="$sample_dir/core-info/$relative"
				mkdir -p -- "$(dirname -- "$core_report")" || return 1
				mkdir -p "$binaries" || return 1
				save_gtest_binary "$gtest_app" "$binaries/gtest" || return 1
				library_name=$("${gtest_sudo[@]}" readlink -f -- "$gtest_lib") || return 1
				library_name=${library_name##*/}
				save_gtest_binary "$gtest_lib" "$binaries/$library_name" || return 1
				executable="$binaries/gtest"
				if "${gtest_sudo[@]}" test -x "$helper"; then
					save_gtest_binary "$helper" "$binaries/ultra_api_connect_helper" || return 1
					# Ultra API tests exec this helper. Use mappings, since the core's
					# command line can be truncated before the executable basename.
					"${gtest_sudo[@]}" env -u LD_PRELOAD -u LD_AUDIT DEBUGINFOD_URLS= LC_ALL=C \
						timeout -s KILL 60s gdb -nx -batch -iex 'set auto-load off' \
						-c "$core" -ex 'info proc mappings' > "$core_report.executable.txt" 2>&1
					if grep -Eq '/ultra_api_connect_helper( \(deleted\))?$' "$core_report.executable.txt"; then
						executable="$binaries/ultra_api_connect_helper"
					elif ! grep -Eq '/gtest( \(deleted\))?$' "$core_report.executable.txt"; then
						echo 'WARNING: cannot identify the core executable; retaining binaries without a backtrace.'
						continue
					fi
				fi
				printf 'executable=%s\n' "$executable"
				sha256sum "$binaries/"*
				LC_ALL=C readelf -n "$binaries/"* | grep 'Build ID:'
				if ! LC_ALL=C readelf -S "$executable" | grep -q '\.debug_info'; then
					echo 'WARNING: executable has no embedded debug information; preserve its separate symbols.'
				fi
				if ! LC_ALL=C readelf -S "$binaries/$library_name" | grep -q '\.debug_info'; then
					echo 'WARNING: XLIO has no embedded debug information; preserve its separate symbols.'
				fi
				"${gtest_sudo[@]}" env -u LD_PRELOAD -u LD_AUDIT DEBUGINFOD_URLS= LC_ALL=C \
					timeout -s KILL 60s gdb -nx -batch -iex 'set auto-load off' \
					-ex 'set pagination off' -ex "set solib-search-path $binaries" \
					-ex 'info threads' -ex 'thread apply all bt full' \
					-ex 'info registers' -ex 'info sharedlibrary' -ex 'info proc mappings' \
					"$executable" "$core" > "$core_report.backtrace.txt" 2>&1
				printf 'core=%s\ngdb_status=%s\n' "$core" "$?"
			done < <("${gtest_sudo[@]}" find "$sample_results" -type f \
				-name "$gtest_core_glob" -print0)
		fi
		[[ $found -gt 0 ]] || echo 'No fresh ELF core found; this failure has no core/backtrace evidence.'
	} > "$sample_dir/status.txt" 2>&1
	cat "$sample_dir/status.txt"
}

function run_ci_profile()
{
    # Arguments: runner profile, artifact label, endpoints, extra gtest arguments.
    local profile_name=$1 artifact_label=$2 addresses=$3 profile_rc command
    local sample_name="${profile_name}-${artifact_label}"
    shift 3
    local sample_results="$gtest_results/$sample_name"
    local archive="${WORKSPACE}/${prefix}/gtest-crash.tar"
    local -a profile_command=(
        "${gtest_sudo[@]}" env "WORKSPACE=$WORKSPACE" GTEST_TAP=2
        "${WORKSPACE}/tests/gtest/run"
        "--profiles=$profile_name" "--addr=$addresses"
        "--gtest-bin=$gtest_app" "--xlio-lib=$gtest_lib"
        "--output-dir=$sample_results"
        -- "$@"
    )
    printf -v command '%q ' "${profile_command[@]}"
    if "${profile_command[@]}"; then
        profile_rc=0
    else
        profile_rc=$?
        gtest_failures+=("$sample_name (rc=$profile_rc)")
        if [[ -n "$gtest_crash_dir" ]]; then
            collect_gtest_crash "$sample_name" "$profile_rc" "$command" "$sample_results" ||
                echo "WARNING: incomplete crash evidence for $sample_name" >&2
            # Package even after collection errors and when artifact collection
            # is otherwise disabled. Preserve the previous archive on failure.
            if tar -cf "$archive.tmp" -C "$gtest_crash_dir" . && mv -f -- "$archive.tmp" "$archive"; then
                echo "Crash diagnostics: $archive"
            else
                echo "WARNING: failed to package crash evidence for $sample_name" >&2
            fi
        fi
    fi
    rc=$((rc + profile_rc))
    gtest_samples=$((gtest_samples + 1))
}

set +eE

if [[ -z "${MANUAL_RUN}" ]]; then
	"${WORKSPACE}/configure" --prefix="$install_dir" $jenkins_test_custom_configure
	make $make_opt -C tests/gtest
	rc=$(($rc+$?))
fi

# Collect crash diagnostics only on failures, using the existing Jenkins *.tar hook.
gtest_failures=()
gtest_samples=0
gtest_crash_dir=$(mktemp -d "${WORKSPACE}/${prefix}/gtest-crash.XXXXXX") || gtest_crash_dir=
gtest_core_pattern=$(cat /proc/sys/kernel/core_pattern)
gtest_core_glob=$(basename -- "$gtest_core_pattern")
gtest_collect_cores=1
case "$gtest_core_pattern" in
    '|'*|/*|'') gtest_collect_cores=0 ;;
    *)
        gtest_core_glob=${gtest_core_glob//%[a-zA-Z]/*}
        if [[ $(cat /proc/sys/kernel/core_uses_pid) == 1 && "$gtest_core_pattern" != *%p* ]]; then
            gtest_core_glob+='.*'
        fi
        ;;
esac
if [[ -n "$gtest_crash_dir" ]]; then
    {
        printf 'cwd=%s\nresults_root=%s\ncore_pattern=%s\ncore_glob=%s\n' \
            "$PWD" "$gtest_results" "$gtest_core_pattern" "$gtest_core_glob"
        printf 'core_limit=%s\ncore_uses_pid=%s\ngtest=%s\nlibrary=%s\n' \
            "$(ulimit -c)" "$(cat /proc/sys/kernel/core_uses_pid)" "$gtest_app" "$gtest_lib"
        git -C "$WORKSPACE" rev-parse HEAD
        gdb --version | head -1
        if [[ "$gtest_collect_cores" != 1 ]]; then
            echo 'WARNING: piped or absolute core destinations require external core retrieval; only private per-invocation output directories are searched.'
        fi
    } > "$gtest_crash_dir/environment.txt" 2>&1
    cat "$gtest_crash_dir/environment.txt"
else
    echo 'WARNING: cannot create crash diagnostic directory; collection disabled.' >&2
fi

run_ci_profile r2c-full ipv4 "$gtest_addr"
run_ci_profile rto-floor-max ipv4 "$gtest_addr"
run_ci_profile r2c-default ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile delegate ipv4 "$gtest_addr"
run_ci_profile delegate ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff

if [[ -z "${MANUAL_RUN}" ]]; then
	make -C tests/gtest clean
	make $make_opt -C tests/gtest CPPFLAGS="-DEXTRA_API_ENABLED=1"
	rc=$(($rc+$?))
fi

run_ci_profile extra ipv4 "$gtest_addr"
run_ci_profile extra ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile ultra ipv4 "$gtest_addr"
run_ci_profile ultra ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile ultra-full-sq ipv4 "$gtest_addr"
run_ci_profile wtbusy ipv4 "$gtest_addr"
run_ci_profile wtbusy ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile wtbusy-pow2 ipv4 "$gtest_addr"
run_ci_profile wtbusy-not-pow2 ipv4 "$gtest_addr"
run_ci_profile wtintr ipv4 "$gtest_addr"
run_ci_profile wtintr ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile wtintr-pow2 ipv4 "$gtest_addr"
run_ci_profile wtintr-not-pow2 ipv4 "$gtest_addr"
run_ci_profile wtbp ipv4 "$gtest_addr"
run_ci_profile wtbp ipv6 "$gtest_addr6" -r fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
run_ci_profile wtbp-pow2 ipv4 "$gtest_addr"
run_ci_profile wtbp-not-pow2 ipv4 "$gtest_addr"
run_ci_profile passthrough-loopback-wt ipv4 "$gtest_addr"
run_ci_profile passthrough-loopback-r2c ipv4 "$gtest_addr"
run_ci_profile passthrough-rules-wt ipv4 "$gtest_addr"
run_ci_profile passthrough-rules-r2c ipv4 "$gtest_addr"

echo "Gtest samples: $gtest_samples samples, ${#gtest_failures[@]} failures"
if ((${#gtest_failures[@]})); then
    printf '  FAILED: %s\n' "${gtest_failures[@]}"
fi

set -eE

# Keep every profile's TAP results; suite names repeat between configurations.
while IFS= read -r -d '' tap_file; do
    relative=${tap_file#"$gtest_results"/}
    profile_name=${relative%%/*}
    cp -- "$tap_file" "${WORKSPACE}/${prefix}/gtest-${profile_name}-$(basename "$tap_file")"
done < <(find "$gtest_results" -mindepth 2 -name '*.tap' -print0)

echo "[${0##*/}]..................exit code = $rc"
exit $rc
