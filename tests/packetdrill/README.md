# Running and maintaining XLIO Packetdrill tests

Packetdrill (PD) tests XLIO using a script that combines socket system calls
with injected and expected packets. The **client** is the process executing the
system calls with XLIO loaded; a **wire server** injects and captures packets.
Those names describe Packetdrill's roles: a script can test either a TCP client
or a TCP server on the XLIO side.

This guide covers the three supported ways to run PD, optional test settings,
and how to manage the test suite. Commands run from the repository root.
Interface names, hostnames and addresses in examples must be adjusted for your
machine's data network.

## Build and prepare

Build XLIO normally with its default configure options. PD needs the resulting
shared library and the DEBUG log statements retained by the default build;
no special PD build flags are required. If customizing the build, retain shared
library support and avoid `--enable-opt-log=high`.

The default library is `src/core/.libs/libxlio.so` in this checkout. Pass
`--build-dir /path/to/build` to select another build tree, or
`--xlio /absolute/path/to/libxlio.so` to select the exact library. The runner
loads XLIO into the Packetdrill client only; helpers and the wire server run
without XLIO. There is no need to export `LD_PRELOAD`.

Preparing Packetdrill needs git, gcc, make, bison and flex. Running tests needs
Linux, glibc 2.30 or newer, Python 3, PyYAML (`python3-yaml`), readelf (binutils),
iproute2, iptables and procps. Test runs require root and unlimited locked
memory. Listing tests and running the runner's regression checks need no NIC
setup or root privileges.

```sh
tests/packetdrill/pd prepare
tests/packetdrill/pd list
```

`prepare` builds and self-tests the revision in
[`packetdrill.version.json`](packetdrill.version.json). The default cache is
`tests/packetdrill/.cache/`; a verified warm cache works offline. For a different
cache, pass `--cache-dir DIR` to both preparation and execution, or set
`PD_CACHE_DIR` in the executing environment. `--packetdrill FILE` selects an
existing executable instead of the verified cache.

## Choose a running mode

All three modes use Packetdrill's physical-NIC wire mode. The two endpoints
need distinct IPv4 addresses in a common subnet and hardware connectivity.
Interfaces must be up, standalone (not bridge/bond members), and use MTU 1500.
Use dedicated data interfaces rather than an interface carrying management
traffic. Local mode and Two-interfaces mode isolate the wire interface in a
temporary network namespace so traffic reaches the NIC.

| Mode | Command | Interfaces supplied by the caller |
|---|---|---|
| Local mode | `pd run --interface PF` | One SR-IOV PF and its existing IP; an unused second IP for a new VF |
| Two-interfaces mode | `pd run --client-interface IFACE --server-interface IFACE` | Two existing interfaces and their assigned IPs on one machine |
| Remote mode | `pd run --server-host HOST` | One existing interface and IP on each machine |

`pd` selects the mode from these options. `--interface` cannot be combined with
`--client-interface`, `--server-interface` or `--server-host`; mixed mode arguments
are rejected before setup. Every command requires an explicit action:
`pd prepare`, `pd list` or `pd run`. `pd --help` explains all three run modes
and shows complete example commands.

### 1. Local mode

Use `pd run --interface` when you have one suitable NIC port and want the runner to provide
the second endpoint:

```sh
sudo tests/packetdrill/pd run --interface ens2f0np0 \
    --client-ip 192.178.1.1 --server-ip 192.178.1.3
```

`--client-ip` must already belong to the supplied interface. `--server-ip` must be
unused and in the same subnet. The interface must support SR-IOV, have VF driver
autoprobe enabled, and have zero existing VFs. Its PF/VF forwarding path must
support traffic between these endpoints.

`pd run --interface` creates one VF, assigns its MAC and second IP, and runs the wire server
with that VF in a temporary namespace. The VF and namespace are removed when
the run finishes. The interface retains its existing IP. A persistent switch/VLAN or
firmware setup is not performed by this command.

### 2. Two-interfaces mode

Use `pd` directly when the network interfaces have already been provisioned:

```sh
sudo tests/packetdrill/pd run \
    --client-interface net1 --client-ip 192.0.2.1 \
    --server-interface net2 --server-ip 192.0.2.2
```

Both interfaces and addresses must already exist in the caller's network
namespace. The server interface must not carry a default route. `pd` moves
that interface into a temporary wire-server namespace and restores it, its
addresses and routes to the caller's namespace afterward. This mode creates
no VFs.

In Jenkins (To be implemented in the future), a CI script
discovers the CNI-provided `net1`/`net2` addresses and runs pd using this mode.

### 3. Remote mode

Use `--server-host` to start the wire server over SSH. Each machine needs the
same revision of `tests/packetdrill/` and a prepared Packetdrill executable.
Run `tests/packetdrill/pd prepare` in each checkout first. Only the client
machine needs the XLIO library.

For example, run on dor01 using its `ens2f0np0` and a server on dor02 whose
interface is named `enp4s0f0`:

```sh
sudo tests/packetdrill/pd run --server-host root@dor02 \
    --client-interface ens2f0np0 --client-ip 192.178.1.1 \
    --server-interface enp4s0f0 --server-ip 192.178.1.2
```

The interface names are independent: the client interface is looked up on the
local machine and the server interface on the SSH host. Both interfaces and
IPs are used as supplied; this mode creates no namespaces or VFs and does not
reconfigure the server's links or addresses.

SSH must work non-interactively from the account running `pd`, including when
using `sudo`; the remote account must be root. The SSH destination can use a
management network while `--server-ip` names the test data network. The
runner starts/stops the server automatically and collects its logs locally.

By default, the remote scripts are at the same absolute path as the local
`tests/packetdrill/` directory. If the remote checkout differs, add
`--server-dir /path/to/server/libxlio/tests/packetdrill`. A shared filesystem
is not required. `--server-cache-dir DIR` selects its prepared cache, and
`--server-packetdrill FILE` selects an explicit remote executable. For custom
SSH settings, use `--ssh-command 'ssh -F /path/to/ssh_config'`.

Packetdrill temporarily filters test-port traffic on the wire server to
prevent kernel-generated replies. The pd supervisor removes its own firewall
rules afterward; other rules are preserved. The client restores its temporary
peer route/neighbor and supported sysctls.

## Select tests and find results

Tests live below `tests/packetdrill/cases/`. `--filter` is a Python regular
expression searched against the path relative to `cases/`, including `.pkt`:

```sh
tests/packetdrill/pd list
tests/packetdrill/pd list --filter '^kernel/'
tests/packetdrill/pd list --filter 'sendfile-simple.pkt$'
```

Append the same `--filter` option to any run command. For example, this runs
only sendfile on one machine and writes to a chosen results directory:

```sh
sudo tests/packetdrill/pd run --interface ens2f0np0 \
    --client-ip 192.178.1.1 --server-ip 192.178.1.3 \
    --filter 'sendfile-simple[.]pkt$' --output /tmp/pd-sendfile-results
```

The output directory must be absent or empty. Omit `--filter` to select the
whole suite, and omit `--output` for a unique directory under
`tests/packetdrill/runs/`. Selected disabled tests are reported as skipped;
`--include-disabled` runs them too. An empty selection is an error.

A test passes only when its packet/syscall assertions succeed and the client
log proves that the test connection was offloaded by XLIO. Each run prints
per-test results and a final `Total X passed, Y failed, Z skipped` line.

The output directory contains:

- `summary.log`, `results.json` and `junit.xml`: statuses and failure messages.
- `*.client.log`: per-test Packetdrill and XLIO output, including assertion errors.
- `*.server.log`: per-test wire-side output.
- `wire-server.log`: the combined local wire-server log. Remote runs use
  `server-wire.log` and also collect SSH/supervisor diagnostics.
- `metadata.json` and network snapshots: arguments, tool/library identities,
  source revision and saved state.

Progress messages appear on stdout. In CI, download `packetdrill.tar.gz` or
`arch-packet-drill-packetdrill.tar.gz` from the Jenkins artifacts; it contains
the run directories and logs. Progress messages are in the Jenkins console.

Exit codes are 0 for passing/skipped cases, 1 for test or offload failures,
2 for setup/cleanup errors, 130 for SIGINT and 143 for SIGTERM. The default
per-test timeout is 30 seconds; `--timeout SECONDS` changes it. Investigate a
failure using the case logs before changing packet expectations or timing.

## Optional files beside each test

For `example.pkt`, the runner recognizes these optional files in the same
directory:

| File | Purpose |
|---|---|
| `example-xlioconf.json` | XLIO runtime configuration for this test's client |
| `example.yaml` | Test policy and resource requests |

### XLIO configuration: `example-xlioconf.json`

Put test-specific XLIO settings in this JSON file. For example, to disable
blocking RX busy polling:

```json
{
  "performance": {
    "polling": {
      "blocking_rx_poll_usec": 0
    }
  }
}
```

The runner loads this file automatically for the selected test. If it is
absent, the runner supplies an empty JSON configuration and uses XLIO defaults
with the runner's common settings, including offload-evidence logging. It does
not depend on a host `/etc/libxlio_config.json`. 

### Metadata: `example.yaml`

This file contains one YAML mapping with the following supported attributes:

```yaml
disabled: false
tempfile:
  size: 5
```

`disabled` is an optional boolean, defaulting to `false`. Set it to `true` to
skip the test by default in all three modes. Keep the reason and issue number
in a comment, for example in `cases/xlio/lro-data-immediate-ack.yaml`:

```yaml
# Pending #5267303: data ACK is delayed on the original base.
disabled: true
```

To enable a case, set `disabled: false` or remove that attribute while retaining
any resource requests. To run a disabled case once, append `--include-disabled`
to a run command; `--filter` still applies. `pd list` identifies disabled tests
and their YAML files. A selection containing only disabled cases succeeds with
skips and acquires no interfaces or VFs.

`tempfile` requests a private zero-filled file. Its only field, `size`, is a
required integer byte count of zero or more. Put the literal token
`$TEMPFILE_PATH` in the `.pkt` wherever that path is needed. The runner creates
a unique private directory (`0700`) and file (`0600`), substitutes the path in
a temporary script copy, and removes both after the client stops. Source files
are never rewritten. The token and its resource request must be specified
together.

No YAML sidecar means default behavior; `{}` is also valid. Empty files, lists,
unknown top-level fields, unknown fields inside `tempfile`, malformed YAML and
invalid types are errors. Selected sidecars are validated before network setup.

### Complete example: sendfile

The existing sendfile case lives in
`cases/packetdrill/gtests/net/tcp/sendfile/`. Its `sendfile-simple.yaml` is:

```yaml
disabled: false
tempfile:
  size: 5
```

Its complete `sendfile-simple.pkt` is:

```text
// Simplest possible test of open() and then sendfile().
// sendfile-simple.yaml requests a five-byte zero-filled file. The runner substitutes
// its private path for $TEMPFILE_PATH, then we verify the bytes sent by sendfile().

`packetdrill/gtests/net/common/defaults.sh
`

// Initialize connection
    0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3
   +0 setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
   +0 bind(3, ..., ...) = 0
   +0 listen(3, 1) = 0

   +0 < S 0:0(0) win 32792 <mss 1000,sackOK,nop,nop,nop,wscale 10>
   +0 > S. 0:0(0) ack 1 <mss 1460,nop,wscale 8>
   +0 < . 1:1(0) ack 1 win 514

   +0 accept(3, ..., ...) = 4

   +0 open("$TEMPFILE_PATH", O_RDONLY) = 5
   +0 sendfile(4, 5, [0], 5) = 5
   +0 > P. 1:6(5) ack 1
```

The helper is resolved from `cases/`, which remains the client's working
directory even when the runner executes a temporary script. Use the filtered
Local mode command above to run this example.

## Add and maintain tests

Packetdrill test scripts use the `.pkt` extension. The official
[Packetdrill language syntax reference](https://github.com/google/packetdrill/blob/master/syntax.md)
describes the file structure, timestamps, system calls, packet descriptions,
shell commands and embedded code. The
[Packetdrill project page](https://github.com/google/packetdrill) provides
additional examples and background. In scripts, `<` injects a packet toward
the tested stack, while `>` describes an expected outgoing packet.

To add a test:

1. Put the `.pkt` file under the appropriate `cases/` source directory; use
   `cases/xlio/` for an XLIO-native regression. Document what the test verifies.
2. Add a same-stem `.yaml` if the test needs a resource or should be disabled.
   Add `<name>-xlioconf.json` when it needs specific XLIO settings.
3. Resolve helper paths from `cases/`, as in the sendfile example. Use the
   metadata tempfile mechanism for generated data rather than a shared fixed path.
4. Add the case and any sidecars/helpers to `tests/Makefile.am` so source
   distributions contain them. Record imported sources and adaptations in
   [TESTS.md](TESTS.md).
5. Use `pd list --filter 'your-test[.]pkt$'` to check selection and metadata.
   Run that filter using the appropriate mode, inspect its logs and offload
   evidence, then run the full enabled suite after changes that could affect
   other cases. Preserve the assertions that express the test's purpose.

The shared runner is in [pd_common.py](pd_common.py); SSH wire-server control
is in [pd_remote.py](pd_remote.py). These runner regression checks require no
NIC and are separate from the `.pkt` TCP tests:

```sh
python3 tests/packetdrill/test_runner.py
```

Normal completion, failure, timeout and Ctrl+C trigger cleanup of owned
processes and temporary resources. The runner restores supported sysctls,
routes and neighbors; flushing the TCP metrics cache and dynamic neighbors
cannot be undone. SIGKILL or host failure prevents normal cleanup: use the
saved state in the run directory to inspect the affected namespace/interface
before running again.
