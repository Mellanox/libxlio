#!/usr/bin/env python3
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
# See file LICENSE for terms.
"""Shared implementation of the pd command-line tool.

Execution modes:
* Local mode (--interface) creates a temporary VF and isolates it in a namespace.
* Two-interfaces mode uses existing NICs and isolates only the wire NIC in a namespace.
* Remote mode (--server-host) uses SSH and existing physical interfaces without
  creating NICs or namespaces; pd_remote.py owns the remote wire process and cleanup.

Only the syscall-side Packetdrill client preloads XLIO. The wire process uses
unmodified Packetdrill for packet injection/capture. Each run records tool and
library identity, per-case logs, incremental JSON results and final JUnit output.
Network changes and child processes have explicit cleanup owners so failure and
handled signals restore state before the CLI returns.
"""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

# Resolve data relative to this script so invocation is independent of cwd.
ROOT = Path(__file__).resolve().parent
CASES = ROOT / 'cases'
PIN = json.loads((ROOT / 'packetdrill.version.json').read_text())


def progress(message):
    """Print and flush a progress line without letting a closed pipe interrupt cleanup."""
    try:
        print('[pd] ' + message, flush=True)
    except BrokenPipeError:
        pass


def clean_environment(environment=None):
    """Copy an environment without preload or XLIO settings for helper processes."""
    source = os.environ if environment is None else environment
    return {k: v for k, v in source.items() if k != 'LD_PRELOAD' and not k.startswith('XLIO_')}


def command(*args, check=True, **kwargs):
    """Run an argv-based subprocess in its own session and capture both streams.

    Return CompletedProcess with byte output. Raise RuntimeError on nonzero exit
    unless check=False; forward remaining kwargs (for example cwd/stdin) to run().
    Helper environments omit LD_PRELOAD and inherited XLIO settings.
    Session isolation keeps a terminal signal from interrupting an in-flight
    network mutation before its caller can register rollback.
    """
    kwargs['env'] = clean_environment(kwargs.get('env'))
    result = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True, **kwargs)
    if check and result.returncode:
        raise RuntimeError('{}: {}'.format(' '.join(map(str, args)),
                                          result.stderr.decode(errors='replace').strip()))
    return result


def ip_json(*args):
    """Run iproute2 with JSON output and return its decoded records.

    Arguments follow `ip -j`; command errors propagate before JSON decoding.
    """
    return json.loads(command('ip', '-j', *args).stdout)


def digest(path):
    """Return the SHA-256 of a tool or library file for cache/report identity."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def atomic_json(path, value):
    """Replace a JSON artifact atomically through a sibling temporary file.

    Readers therefore see a complete snapshot while a run updates progress.
    """
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


@contextlib.contextmanager
def lock(path):
    """Hold a nonblocking, exclusive advisory file lock for this context.

    Fail immediately if another process owns it. Closing the handle releases the
    lock even when preparation, execution or cleanup raises an exception.
    """
    with open(path, 'a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another runner owns ' + str(path)) from None
        yield


def cache_binary(cache):
    """Resolve the cached Packetdrill path for the pinned commit and local CPU architecture."""
    return Path(cache).resolve() / PIN['commit'] / platform.machine() / 'packetdrill'


def verify_cache(binary):
    """Require a complete ready.json marker matching the pin and executable hash.

    Explicitly supplied binaries bypass this cache check and are labeled as
    unverified external binaries in metadata.
    """
    marker = binary.parent / 'ready.json'
    if not marker.is_file():
        raise RuntimeError('Packetdrill cache is incomplete; run pd prepare')
    ready = json.loads(marker.read_text())
    if ready.get('commit') != PIN['commit'] or ready.get('sha256') != digest(binary):
        raise RuntimeError('Packetdrill cache verification failed; run pd prepare')


def prepare(cache):
    """Build and self-test the pinned Packetdrill executable, or reuse a verified cache.

    The preparation lock prevents two writers from rebuilding the same entry.
    A failed/corrupt marker causes a rebuild of our cache-owned source directory;
    ready.json is published only after configure, make and tool self-tests pass.
    This operation does not build XLIO or change network configuration.
    """
    progress('Preparing Packetdrill {} for {}'.format(PIN['commit'][:12], platform.machine()))
    binary = cache_binary(cache)
    progress('Cache directory: ' + str(binary.parent))
    binary.parent.mkdir(parents=True, exist_ok=True)
    with lock(binary.parent / 'prepare.lock'):
        # A verified warm cache needs neither a compiler nor network access.
        marker = binary.parent / 'ready.json'
        if binary.is_file() and marker.is_file():
            progress('Verifying cached Packetdrill executable')
            try:
                verify_cache(binary)
            except (RuntimeError, ValueError, OSError):
                progress('Cached Packetdrill verification failed; rebuilding')
                marker.unlink()
            else:
                progress('Using verified cached Packetdrill executable')
                print(binary, flush=True)
                return
        # Cold preparation requires explicit build dependencies; never install them.
        progress('Checking build dependencies: git, gcc, make, bison, flex')
        for tool in ('git', 'gcc', 'make', 'bison', 'flex'):
            if not shutil.which(tool):
                raise RuntimeError('Missing build dependency: ' + tool)
        source = binary.parent / 'source'
        # This path belongs exclusively to this cache entry; never reset a user's checkout.
        if source.exists():
            progress('Removing previous cache-owned build sources')
            shutil.rmtree(source)
        # Keep diagnostics together and stop at the first failed build/self-test.
        with (binary.parent / 'build.log').open('wb') as log:
            progress('Build output: ' + str(log.name))
            steps = [('Cloning Packetdrill from ' + PIN['url'],
                      ['git', 'clone', PIN['url'], str(source)], None),
                     ('Checking out pinned revision ' + PIN['commit'],
                      ['git', 'checkout', '--detach', PIN['commit']], source)]
            tool_dir = source / 'gtests/net/packetdrill'
            steps += [('Configuring Packetdrill', ['./configure'], tool_dir),
                      ('Building Packetdrill',
                       ['make', '-j' + str(min(os.cpu_count() or 1, 8))], tool_dir),
                      ('Running Packetdrill self-tests', ['make', 'tests'], tool_dir)]
            for index, (message, argv, cwd) in enumerate(steps, 1):
                progress('Prepare [{}/{}]: {}'.format(index, len(steps), message))
                subprocess.run(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                               env=clean_environment(), check=True)
        # Publish the success marker last; partial builds cannot become a warm cache.
        progress('Installing Packetdrill executable and recording cache verification data')
        shutil.copy2(tool_dir / 'packetdrill', binary)
        atomic_json(marker, dict(PIN, sha256=digest(binary),
                                 compiler=command('gcc', '--version').stdout.decode(),
                                 architecture=platform.machine()))
    progress('Packetdrill preparation complete')
    print(binary, flush=True)


def client_command(binary, xlio):
    """Load XLIO into this ELF executable only, leaving exec'd helpers unpreloaded.

    Read the executable's interpreter rather than assuming an architecture's
    loader path. glibc's --preload applies only to this invocation; unlike the
    LD_PRELOAD environment variable, it does not reach subsequent execs.
    Verify support before acquiring interfaces or starting the wire server.
    """
    env = dict(clean_environment(), LC_ALL='C')
    headers = command('readelf', '-lW', binary, env=env).stdout.decode()
    match = re.search(r'\[Requesting program interpreter: ([^\]\n]+)\]', headers)
    if not match:
        raise RuntimeError('Packetdrill client must be a dynamically linked ELF executable')
    loader = Path(match.group(1)).resolve(strict=True)
    probe = command(loader, '--preload', '', '--verify', binary, check=False)
    if probe.returncode:
        raise RuntimeError('Client-only preloading requires a glibc loader with --preload '
                           '(glibc 2.30 or newer): ' + str(loader))
    return [str(loader), '--preload', str(xlio), str(binary)]


def load_metadata(test):
    """Load an optional same-stem YAML sidecar containing this test's attributes.

    Absence means default behavior; an existing sidecar must be a YAML mapping.
    Safe loading accepts data only. Reject unknown fields and invalid types before
    networking, including unknown fields within a tempfile request.
    """
    meta = test.with_suffix('.yaml')
    if not meta.exists() and not meta.is_symlink():
        return {}
    try:
        import yaml
    except ImportError:
        raise RuntimeError(str(meta) + ': PyYAML is required; install python3-yaml') from None
    try:
        attributes = yaml.safe_load(meta.read_text())
    except yaml.YAMLError as error:
        raise RuntimeError('{}: invalid YAML: {}'.format(meta, error)) from None
    if not isinstance(attributes, dict):
        raise RuntimeError(str(meta) + ': expected a mapping of test attributes (use {} for defaults)')
    unknown = set(attributes) - {'disabled', 'tempfile'}
    if unknown:
        raise RuntimeError('{}: unknown metadata fields: {}'.format(meta, ', '.join(map(str, unknown))))
    if 'disabled' in attributes and type(attributes['disabled']) is not bool:
        raise RuntimeError(str(meta) + ': disabled must be true or false')
    if 'tempfile' in attributes:
        options = attributes['tempfile']
        if not isinstance(options, dict):
            raise RuntimeError(str(meta) + ': tempfile must be a mapping containing size')
        unknown = set(options) - {'size'}
        if unknown:
            raise RuntimeError('{}: unknown tempfile fields: {}'.format(meta, ', '.join(map(str, unknown))))
        if 'size' not in options or type(options['size']) is not int or options['size'] < 0:
            raise RuntimeError(str(meta) + ': tempfile.size must be a nonnegative integer number of bytes')
    return attributes


def select_tests(pattern):
    """Return selected (source path, disabled reason, sidecar attributes) tuples.

    --filter searches paths relative to cases/. Only selected cases' optional YAML
    sidecars are read; a sidecar applies exclusively to its neighboring .pkt file.
    """
    selector = re.compile(pattern)
    selected = []
    for path in sorted(CASES.rglob('*.pkt')):
        name = path.relative_to(CASES).as_posix()
        if not selector.search(name):
            continue
        attributes = load_metadata(path)
        reason = ('Disabled by cases/' + path.with_suffix('.yaml').relative_to(CASES).as_posix()
                  if attributes.get('disabled', False) else '')
        selected.append((path, reason, attributes))
    return selected


def test_offloaded(log, peer):
    """Return whether the log proves offload of a test connection to peer.

    Match a destination-object constructor to that same object's offload verdict.
    Active flows use remote port 8080; passive flows use local port 8080 and an
    ephemeral remote port. Exclude control destination 8081 in both cases, and
    forget destroyed objects so pointer reuse cannot supply stale evidence.
    """
    destinations = {}
    for line in log.splitlines():
        obj = re.search(r'dst\[(0x[0-9a-fA-F]+)\]', line)
        if not obj:
            continue
        key = obj.group(1)
        # Constructor records tie this object to a test tuple rather than control.
        endpoint = re.search(r'dst_entry\(\) dst:([^ ]+) src:\s*(\d+)', line)
        if endpoint:
            address, port = endpoint.group(1).rsplit(':', 1)
            destinations[key] = (address == peer and port != '8081' and
                                 (port == '8080' or endpoint.group(2) == '8080'))
        if 'dst_entry is offloaded!' in line and destinations.get(key, False):
            return True
        # The allocator may reuse the same address for a later, unrelated flow.
        if '~dst_entry()' in line:
            destinations.pop(key, None)
    return False


class Cleanup:
    """Undo completed mutations in reverse order, attempting all even on failure."""
    def __init__(self):
        """Start an empty stack of undo callbacks for resources owned by this run."""
        self.actions = []

    def add(self, function, *args):
        """Register an undo function and positional arguments after acquiring its resource.

        Callers defer interrupts across acquisition plus registration, preventing a
        signal from leaving a completed mutation without its undo callback.
        """
        self.actions.append((function, args))

    def close(self):
        """Invoke every registered undo in reverse order, then report all failures.

        One failure does not prevent later restoration attempts. Callers clear the
        stack after successful early cleanup when it must not run again.
        """
        # Preserve LIFO ordering and attempt every undo even if an earlier one fails.
        errors = []
        for function, args in reversed(self.actions):
            try:
                function(*args)
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError('Cleanup failed: ' + '; '.join(errors))


@contextlib.contextmanager
def defer_interrupts(signals=(signal.SIGINT, signal.SIGTERM)):
    """Defer the selected Python signal handlers until an ownership transition finishes.

    Record arriving signals, restore the previous handlers on exit, then deliver
    the first pending signal. The default covers CLI INT/TERM; the SSH supervisor
    also supplies HUP/ALRM. Unlike a blocked signal mask, these handlers reset on
    exec, so child programs retain normal signal behavior.
    """
    # Temporarily record signals without raising in the acquisition/registration gap.
    pending = []
    previous = {sig: signal.signal(sig, lambda number, frame: pending.append(number))
                for sig in signals}
    try:
        yield
    finally:
        # Re-deliver only after restoring the caller's original handlers.
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if pending:
            signal.raise_signal(pending[0])


def wait_for(predicate, seconds, message, interval=0.1):
    """Poll a readiness condition until success or a monotonic-clock deadline.

    Predicate exceptions propagate immediately; expiry raises the supplied
    message. Polling is used for VF creation and wire-server readiness/cleanup;
    interval controls how promptly a completed condition is observed.
    """
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(interval)
    raise RuntimeError(message)


def stop_process(process):
    """Terminate and reap a subprocess and descendants in its private process group.

    The process must have been launched with start_new_session=True. Try TERM,
    then bounded KILL escalation, including descendants whose group leader has
    already exited. Never search for or kill unrelated processes by name.
    """
    # All children, including helper shells, belong to this private process group.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            continue
        # Kill lingering descendants even if the group leader has already exited.
        if sig == signal.SIGTERM:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        break
    process.wait(timeout=2)


class WireServer:
    """Own a persistent Packetdrill listener and collect one worker's log per case.

    The pinned server accepts successive clients and frees each worker's state
    before printing its completion marker. Wait for that marker so firewall and
    capture cleanup cannot overlap the next case. Failed clients stop the whole
    server; the next start() then creates a clean listener.
    """
    def __init__(self, binary, interface, path, namespace=None):
        """Record the executable, wire NIC and combined log without acquiring resources."""
        self.binary, self.interface, self.path = binary, interface, Path(path)
        self.prefix = ['ip', 'netns', 'exec', namespace] if namespace else []
        self.process = self.log = None
        self.offset = 0

    def start(self):
        """Start the listener if needed, mark this case's log boundary and return its PID."""
        self.offset = self.path.stat().st_size if self.path.exists() else 0
        if self.process is not None:
            if self.process.poll() is not None:
                raise RuntimeError('Wire server exited unexpectedly; see ' + str(self.path))
            return self.process.pid
        if command(*self.prefix, 'ss', '-Hln', 'sport = :8081').stdout.strip():
            raise RuntimeError('Wire-server port 8081 is already in use')
        env = clean_environment()
        # The run/session owns this object before acquisition. Defer cancellation
        # across opening the log and registering the newly created process.
        with defer_interrupts():
            self.log = self.path.open('ab')
            self.process = subprocess.Popen(self.prefix + [str(self.binary), '--wire_server',
                                            '--wire_server_dev=' + self.interface,
                                            '--wire_server_port=8081', '--debug'], env=env,
                                            stdout=self.log, stderr=subprocess.STDOUT,
                                            start_new_session=True)

        def listening():
            """Require the owned process to remain alive until its listener is ready."""
            if self.process.poll() is not None:
                raise RuntimeError('Wire server exited; see ' + str(self.path))
            return bool(command(*self.prefix, 'ss', '-Hln', 'sport = :8081').stdout.strip())

        wait_for(listening, 10, 'Wire server did not listen within 10 seconds')
        return self.process.pid

    def test_log(self):
        """Read only bytes written since the current case's start() boundary."""
        with self.path.open('rb') as log:
            log.seek(self.offset)
            return log.read()

    def finish(self, failed=False):
        """Wait for worker cleanup, or stop a failed case's server, then return case logs."""
        if failed:
            self.stop()
        else:
            def finished():
                """The pinned DEBUG marker follows state_free(), including netdev cleanup."""
                if self.process.poll() is not None:
                    raise RuntimeError('Wire server exited; see ' + str(self.path))
                return b'wire_server_thread: connection is done\n' in self.test_log()

            wait_for(finished, 10, 'Wire worker did not finish cleanup; see ' + str(self.path),
                     interval=0.01)
        return self.test_log()

    def stop(self):
        """Stop and reap the owned listener/workers and close the combined log exactly once."""
        with defer_interrupts():
            if self.process is not None:
                stop_process(self.process)
                self.process = None
            if self.log is not None:
                self.log.close()
                self.log = None


def interface(name):
    """Return iproute2 address/link information for a validated standalone NIC name.

    Reject unsafe names because upstream Packetdrill embeds them in shell
    commands, and reject enslaved devices whose topology cannot be restored by
    the simple physical-interface lifecycle used here.
    """
    # Packetdrill interpolates interface names in shell commands internally.
    if not name or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', name):
        raise RuntimeError('Invalid interface: ' + str(name))
    info = ip_json('address', 'show', 'dev', name)[0]
    if 'master' in info:
        raise RuntimeError('Use a standalone interface: ' + name)
    return info


def address(info, value):
    """Resolve an assigned IPv4 address and prefix from an interface record.

    Normalize the requested address and fail if it does not already belong to
    that interface; this function never assigns an address.
    """
    value = str(ipaddress.IPv4Address(value))
    for item in info['addr_info']:
        if item['family'] == 'inet' and item['local'] == value:
            return ipaddress.IPv4Interface(value + '/' + str(item['prefixlen']))
    raise RuntimeError('{} is not assigned to {}'.format(value, info['ifname']))


def create_vf(args, cleanup):
    """Provision Local mode's sole temporary VF and fill the normal pd NIC arguments.

    Require a configured PF/client IP, an unused peer IP in that subnet, SR-IOV
    support, driver autoprobe and zero pre-existing VFs. Register VF destruction,
    wait for its netdev, then configure its MAC/MTU/IP. The caller must defer
    interrupts across this function. Other modes do not use it.
    """
    progress('Validating PF {} and temporary VF address {}'.format(args.interface, args.server_ip))
    pf = interface(args.interface)
    local = address(pf, args.client_ip)
    peer = ipaddress.IPv4Address(args.server_ip)
    if peer == local.ip or peer not in local.network:
        raise RuntimeError('VF IP must be a different address in the PF subnet')
    for dev in ip_json('address', 'show'):
        if any(a.get('local') == str(peer) for a in dev['addr_info']):
            raise RuntimeError('VF IP is already assigned: ' + str(peer))
    # Refuse to reset or repurpose any VF that another workload could own.
    sriov = Path('/sys/class/net') / args.interface / 'device'
    count = sriov / 'sriov_numvfs'
    if not count.exists() or int((sriov / 'sriov_totalvfs').read_text()) < 1:
        raise RuntimeError('SR-IOV is not enabled on ' + args.interface)
    if int(count.read_text()) != 0:
        raise RuntimeError('Refusing to change a PF that already has VFs')
    if (sriov / 'sriov_drivers_autoprobe').read_text().strip() != '1':
        raise RuntimeError('VF driver autoprobe must be enabled')
    # From here on, the caller's cleanup owns exactly the newly created VF.
    progress('Creating temporary VF 0 on ' + args.interface)
    count.write_text('1')
    cleanup.add(count.write_text, '0')
    net = sriov / 'virtfn0/net'
    wait_for(lambda: net.exists() and len(list(net.iterdir())) == 1, 10,
             'VF netdev did not appear')
    # Wait for udev naming to settle before selecting the newly created netdev.
    if shutil.which('udevadm'):
        command('udevadm', 'settle', '--timeout=10')
    name = next(net.iterdir()).name
    # Program both the PF's administrative VF MAC and the VF netdev MAC to match.
    mac = '02:' + ':'.join('{:02x}'.format(x) for x in os.urandom(5))
    command('ip', 'link', 'set', args.interface, 'vf', '0', 'mac', mac)
    command('ip', 'link', 'set', 'dev', name, 'down')
    command('ip', 'link', 'set', 'dev', name, 'address', mac)
    command('ip', 'link', 'set', 'dev', name, 'mtu', pf['mtu'])
    command('ip', 'addr', 'add', str(peer) + '/' + str(local.network.prefixlen), 'dev', name)
    command('ip', 'link', 'set', 'dev', name, 'up')
    # The normal runner now receives a preconfigured client/wire interface pair.
    args.client_interface = args.interface
    args.server_interface = name
    progress('VF ready: {} ({})'.format(name, peer))


def interface_sysctls(name):
    """Snapshot readable per-interface IPv4/IPv6 settings before a namespace move.

    A move can reset these values. Unreadable settings such as an unset IPv6
    stable_secret are omitted rather than preventing execution.
    """
    settings = {}
    for family in ('ipv4', 'ipv6'):
        for path in (Path('/proc/sys/net') / family / 'conf' / name).glob('*'):
            try:
                settings[str(path)] = path.read_text()
            except OSError:
                pass  # e.g. an unset IPv6 stable_secret cannot be read.
    return settings


def restore_interface(name, ns, info, saved_addresses, saved_routes, sysctls, neighbors):
    """Return the local wire NIC to the caller's network namespace and restore its state.

    Restore per-interface sysctls, saved addresses, original link-up/down state,
    IPv4/IPv6 routes and permanent neighbors. The original interface index must
    still match because the binary iproute2 dumps refer to that index.
    """
    progress('Restoring wire-server interface {} to the caller network namespace'.format(name))
    command('ip', '-n', ns, 'link', 'set', name, 'down')
    command('ip', '-n', ns, 'link', 'set', name, 'netns', os.getpid())
    if interface(name)['ifindex'] != info['ifindex']:
        raise RuntimeError('Interface index changed; saved state needs manual restoration')
    # Restore IPv6-related settings before addresses: some settings remove addresses.
    command('ip', 'addr', 'flush', 'dev', name)
    for path, value in sysctls.items():
        if Path(path).read_text() != value:
            Path(path).write_text(value)
    command('ip', 'addr', 'restore', input=saved_addresses)
    command('ip', 'link', 'set', name, 'up' if 'UP' in info['flags'] else 'down')
    for family, data in saved_routes:
        # iproute2 rewinds route dumps; a subprocess input pipe is not seekable.
        with tempfile.TemporaryFile() as saved:
            saved.write(data)
            saved.seek(0)
            command('ip', family, 'route', 'restore', stdin=saved)
    for entry in neighbors:
        restore_neighbor(name, entry['dst'], [entry])


def delete_namespace(ns, name):
    """Delete an owned local namespace only after its wire NIC has been returned.

    If restoration failed and the NIC is still inside, retain the namespace and
    report an error instead of losing access to its recoverable state.
    """
    if command('ip', '-n', ns, 'link', 'show', name, check=False).returncode == 0:
        raise RuntimeError('Retaining namespace {}: {} still needs restoration'.format(ns, name))
    progress('Deleting temporary wire-server namespace ' + ns)
    command('ip', 'netns', 'delete', ns)


def restore_neighbor(dev, peer, old):
    """Remove this run's peer-neighbor override and replay a previous MAC/state if present."""
    command('ip', 'neigh', 'del', peer, 'dev', dev, check=False)
    for entry in old:
        if 'lladdr' in entry:
            command('ip', 'neigh', 'replace', peer, 'dev', dev, 'lladdr', entry['lladdr'],
                    'nud', entry['state'][0].lower())


def setup_network(args, cleanup, out):
    """Prepare two existing local NICs for pd, returning wire namespace and client netmask.

    Validate addresses, MTU and management-route safety; save recovery artifacts;
    move only the wire NIC to an owned namespace; and install temporary neighbors
    and the client peer route. Register LIFO restoration for every mutation.
    This path is shared by Local mode and Two-interfaces mode; Remote mode
    uses separate client-side setup.
    """
    progress('Validating local interfaces: client {} ({}), wire server {} ({})'.format(
        args.client_interface, args.client_ip, args.server_interface, args.server_ip))
    client = interface(args.client_interface)
    server = interface(args.server_interface)
    if client['ifindex'] == server['ifindex']:
        raise RuntimeError('Client and wire server require different interfaces')
    local = address(client, args.client_ip)
    peer = address(server, args.server_ip)
    if local.ip == peer.ip or peer.ip not in local.network or local.ip not in peer.network:
        raise RuntimeError('Use distinct IPv4 addresses in a shared subnet')
    if client['mtu'] != 1500 or server['mtu'] != 1500:
        raise RuntimeError('The blocking-connect case requires MTU 1500 on both interfaces')
    if 'UP' not in client['flags']:
        raise RuntimeError('Client interface must be up')
    routes = sum((ip_json(family, 'route', 'show', 'table', 'all', 'dev', args.server_interface)
                  for family in ('-4', '-6')), [])
    if any(r.get('dst') == 'default' for r in routes):
        raise RuntimeError('Refusing to move an interface with a default route')
    if ip_json('-4', 'route', 'show', 'exact', args.server_ip + '/32'):
        raise RuntimeError('Remove the existing peer /32 route before running PD')
    # Snapshot everything that moving the wire NIC can discard or reset.
    progress('Saving wire-server interface addresses, routes, neighbors and sysctls')
    saved_addresses = command('ip', 'addr', 'save', 'dev', args.server_interface).stdout
    saved_routes = [(f, command('ip', f, 'route', 'save', 'table', 'all',
                               'dev', args.server_interface).stdout) for f in ('-4', '-6')]
    sysctls = interface_sysctls(args.server_interface)
    neighbors = [entry for entry in ip_json('neigh', 'show', 'dev', args.server_interface)
                 if set(entry.get('state', [])) & {'PERMANENT', 'NOARP'}]
    atomic_json(out / 'server-sysctls-before.json', sysctls)
    atomic_json(out / 'server-neighbors-before.json', neighbors)
    (out / 'server-addresses.save').write_bytes(saved_addresses)
    for family, data in saved_routes:
        (out / ('server-routes' + family + '.save')).write_bytes(data)
    atomic_json(out / 'network-before.json', dict(client=client, server=server, routes=routes))
    # Register deletion first, then NIC restoration, so LIFO returns the NIC first.
    ns = 'xlio-pd-' + str(os.getpid()) + '-' + uuid.uuid4().hex[:6]
    progress('Creating namespace {} and moving wire-server interface {}'.format(ns, args.server_interface))
    command('ip', 'netns', 'add', ns)
    cleanup.add(delete_namespace, ns, args.server_interface)
    command('ip', 'link', 'set', args.server_interface, 'netns', ns)
    cleanup.add(restore_interface, args.server_interface, ns, server,
                saved_addresses, saved_routes, sysctls, neighbors)
    command('ip', '-n', ns, 'link', 'set', 'lo', 'up')
    command('ip', '-n', ns, 'addr', 'replace', str(peer), 'dev', args.server_interface)
    command('ip', '-n', ns, 'link', 'set', args.server_interface, 'up')
    # Static neighbors make the PF/VF path independent of parent/child ARP behavior.
    progress('Configuring temporary peer route and neighbor entries')
    old = ip_json('neigh', 'show', args.server_ip, 'dev', args.client_interface)
    cleanup.add(restore_neighbor, args.client_interface, args.server_ip, old)
    command('ip', 'neigh', 'replace', args.server_ip, 'dev', args.client_interface,
            'lladdr', server['address'], 'nud', 'permanent')
    command('ip', '-n', ns, 'neigh', 'replace', args.client_ip, 'dev', args.server_interface,
            'lladdr', client['address'], 'nud', 'permanent')
    saved_route = command('ip', '-4', 'route', 'save', 'exact', args.server_ip + '/32').stdout
    (out / 'client-peer-route.save').write_bytes(saved_route)
    cleanup.add(restore_peer_route, args.server_ip, saved_route)
    # Install now, so cleanup has a known route even if the client never starts.
    command('ip', 'route', 'add', args.server_ip + '/32', 'dev', args.client_interface,
            'via', args.server_ip)
    progress('Local network setup complete')
    return ns, str(local.netmask)


def restore_peer_route(peer, saved):
    """Remove a present test route and replay the client's saved peer /32 route in either mode.

    Use a seekable temporary file because ip route restore rewinds its input.
    An empty saved route dump correctly restores the original absence of a route.
    """
    # Packetdrill replaces this route using separate delete/add commands. A
    # stopped client may leave it absent; other deletion errors must propagate.
    if ip_json('-4', 'route', 'show', 'exact', peer + '/32'):
        command('ip', '-4', 'route', 'del', peer + '/32')
    with tempfile.TemporaryFile() as state:
        state.write(saved)
        state.seek(0)
        command('ip', '-4', 'route', 'restore', stdin=state)


def setup_client_network(args, server, cleanup, out):
    """Prepare only the local client route/neighbor for a remote physical wire server.

    The server record comes from SSH, so its interface name/index need not match
    a local NIC. Validate the shared subnet, save existing client state, and
    register restoration. No interface is moved, created or addressed in this mode.
    """
    progress('Configuring client {} ({}) for remote wire server {} ({})'.format(
        args.client_interface, args.client_ip, args.server_interface, args.server_ip))
    client = interface(args.client_interface)
    local = address(client, args.client_ip)
    peer = address(server, args.server_ip)
    if local.ip == peer.ip or peer.ip not in local.network or local.ip not in peer.network:
        raise RuntimeError('Use distinct IPv4 addresses in a shared subnet')
    if client['mtu'] != 1500:
        raise RuntimeError('The blocking-connect case requires MTU 1500')
    if 'UP' not in client['flags']:
        raise RuntimeError('Client interface must be up')
    atomic_json(out / 'network-before.json', dict(client=client, server=server))
    # Pin the peer MAC to the selected physical server interface for this run.
    old = ip_json('neigh', 'show', args.server_ip, 'dev', args.client_interface)
    cleanup.add(restore_neighbor, args.client_interface, args.server_ip, old)
    command('ip', 'neigh', 'replace', args.server_ip, 'dev', args.client_interface,
            'lladdr', server['address'], 'nud', 'permanent')
    saved_route = command('ip', '-4', 'route', 'save', 'exact', args.server_ip + '/32').stdout
    (out / 'client-peer-route.save').write_bytes(saved_route)
    cleanup.add(restore_peer_route, args.server_ip, saved_route)
    command('ip', 'route', 'replace', args.server_ip + '/32', 'dev', args.client_interface,
            'via', args.server_ip)
    return str(local.netmask)


def save_sysctls(cleanup, out):
    """Save supported helper-touched sysctls and establish receive limits before XLIO starts.

    The imported helpers use keys covered by the shared Google defaults script.
    Register each readable key's restoration, then set tcp_rmem and optional
    rmem_max early because XLIO caches these values during process initialization.
    The helpers' TCP metrics-cache flush cannot be restored by this snapshot.
    """
    helper = CASES / 'packetdrill/gtests/net/common/defaults.sh'
    keys = sorted(set(re.findall(r'\bnet\.[\w.]+(?==)', helper.read_text())))
    saved = {}
    # Ignore unsupported kernel keys, but own restoration of every readable key.
    for key in keys:
        result = command('sysctl', '-n', key, check=False)
        if result.returncode == 0:
            saved[key] = result.stdout.decode().strip()
            cleanup.add(command, 'sysctl', '-q', '-w', key + '=' + saved[key])
    atomic_json(out / 'sysctls-before.json', saved)
    # XLIO reads buffer limits before Packetdrill executes the test helper.
    command('sysctl', '-q', '-w', 'net.ipv4.tcp_rmem=4096 540000 15728640')
    # Some kernels do not expose this global limit in container net namespaces.
    # tcp_rmem above still supplies the receive-window limit used by this case.
    if 'net.core.rmem_max' in saved:
        command('sysctl', '-q', '-w', 'net.core.rmem_max=15728640')


def prepare_test(test, attributes, cleanup):
    """Prepare requested resources and return an executable .pkt path.

    A tempfile request creates a zero-filled file and substitutes $TEMPFILE_PATH
    in a private copy of the script. Keep cwd at cases/ so existing relative
    helpers still resolve. Cleanup owns the private directory before any writes
    and runs only after the client and its helper processes have been stopped.
    Scripts without resource requests execute directly from their source paths.
    """
    source = test.read_text()
    token = '$TEMPFILE_PATH'
    requested = 'tempfile' in attributes
    if (token in source) != requested:
        raise RuntimeError('{}: $TEMPFILE_PATH and tempfile metadata must be specified together'.format(test))
    if not requested:
        return test
    # A private directory protects every path component from other users, even
    # when the kernel's protections for symlinks in shared /tmp are disabled.
    # Fix the parent to /tmp so substituted paths need no shell/string escaping.
    with defer_interrupts():
        workspace = tempfile.TemporaryDirectory(prefix='xlio-pd-', dir='/tmp')
        cleanup.add(workspace.cleanup)
    progress('Creating a zero-filled temporary file ({} bytes)'.format(attributes['tempfile']['size']))
    with tempfile.NamedTemporaryFile(dir=workspace.name, prefix='data-', delete=False) as fixture:
        # Extending a newly created empty file supplies zeros without allocating
        # an in-memory buffer proportional to the requested file size.
        fixture.truncate(attributes['tempfile']['size'])
        fixture_path = fixture.name
    prepared = Path(workspace.name) / test.name
    prepared.write_text(source.replace(token, fixture_path))
    progress('Prepared temporary test script: ' + str(prepared))
    return prepared


def execute(args, tests, out, cleanup, results):
    """Run the selected cases and append their packet/offload results to results.

    Resolve and record exact tools/library, configure the selected topology, save
    host settings, and run fresh clients against a shared wire-server listener. The
    outer cleanup stack owns run-wide network state; a separate per-test stack
    owns processes and fixtures. Setup/cleanup exceptions propagate to main so
    they cannot become successful test results.
    """
    # Resolve explicit artifacts first; no system-installed XLIO fallback is used.
    progress('Validating XLIO library, Packetdrill executable and runtime dependencies')
    xlio = Path(args.xlio) if args.xlio else Path(args.build_dir) / 'src/core/.libs/libxlio.so'
    xlio = xlio.resolve(strict=True)
    binary = Path(args.packetdrill).resolve(strict=True) if args.packetdrill else cache_binary(args.cache_dir)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError('Packetdrill is missing; run pd prepare first')
    if not args.packetdrill:
        verify_cache(binary)
    progress('XLIO library: ' + str(xlio))
    progress('Packetdrill executable: ' + str(binary))
    # Fail before touching networking if runtime dependencies are unavailable.
    dependencies = command('ldd', xlio).stdout.decode()
    if 'not found' in dependencies:
        raise RuntimeError('XLIO has unresolved libraries: ' + dependencies)
    for tool in ('ip', 'iptables', 'sysctl', 'ss', 'readelf'):
        if not shutil.which(tool):
            raise RuntimeError('Missing runtime dependency: ' + tool)
    client_prefix = client_command(binary, xlio)
    # Persist identities and caller settings before any run-wide mutation.
    metadata = dict(arguments=vars(args), expected_packetdrill_pin=PIN, packetdrill=str(binary),
                    packetdrill_origin='explicit; revision unverified' if args.packetdrill else 'verified prepared cache',
                    packetdrill_sha256=digest(binary), client_command=client_prefix, xlio=str(xlio),
                    xlio_sha256=digest(xlio), ldd=dependencies,
                    source_revision=command('git', '-C', ROOT, 'rev-parse', 'HEAD', check=False).stdout.decode().strip(),
                    source_status=command('git', '-C', ROOT, 'status', '--porcelain', check=False).stdout.decode())
    atomic_json(out / 'metadata.json', metadata)
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    # Select exactly one topology and register all of its resources with cleanup.
    remote = None
    with defer_interrupts():
        if args.vf:
            create_vf(args, cleanup)
        if args.server_host:
            # SSH owns the remote worker; only local routes/neighbors change here.
            from pd_remote import RemoteWireServer
            client_info = interface(args.client_interface)
            address(client_info, args.client_ip)
            progress('Connecting to SSH wire server {} on {} ({})'.format(
                args.server_host, args.server_interface, args.server_ip))
            remote = RemoteWireServer(args, out)
            cleanup.add(remote.close)
            server_info = remote.setup()
            progress('Remote wire-server setup complete')
            ns = None
            metadata['remote_server'] = server_info
            netmask = setup_client_network(args, server_info['interface'], cleanup, out)
        else:
            # Existing local NICs, or the just-created VF, share the local path.
            ns, netmask = setup_network(args, cleanup, out)
    metadata['mode'] = 'remote' if remote else 'local'
    metadata['wire_server_namespace'] = ns
    atomic_json(out / 'metadata.json', metadata)
    # Establish limits before launching any process that initializes XLIO.
    progress('Saving test sysctls and configuring receive-buffer limits')
    save_sysctls(cleanup, out)
    # Always select an explicit file: fresh CI pods need not have the optional
    # host-wide /etc/libxlio_config.json. An empty JSON object retains defaults.
    default_config = out / 'default-xlioconf.json'
    atomic_json(default_config, {})
    # Do not let inherited XLIO settings leak between cases or into the wire server.
    clean_env = clean_environment()
    # Keep the listener alive across successful cases. Stop it before restoring
    # run-wide network state; remote.close later also reaps the SSH supervisor.
    wire = remote or WireServer(binary, args.server_interface, out / 'wire-server.log', ns)
    cleanup.add(wire.stop)
    progress('Reusing one {} wire server across tests; client failures trigger a restart'.format(
        'remote' if remote else 'local'))
    # Keep each case's processes/fixture separate from run-wide network ownership.
    for index, (test, attributes) in enumerate(tests, 1):
        name = str(test.relative_to(CASES))
        stem = name.replace('/', '_')
        test_cleanup = Cleanup()
        started = time.monotonic()
        progress('[{}/{}] {}: preparing test'.format(index, len(tests), name))
        try:
            prepared = prepare_test(test, attributes, test_cleanup)
            with (out / (stem + '.server.log')).open('wb') as server_log, \
                    (out / (stem + '.client.log')).open('wb') as client_log:
                # The listener accepts a fresh worker for each client, retaining
                # the same PID unless an earlier failed case required a restart.
                server_pid = wire.start()
                if index == 1:
                    progress('Wire-server PID: ' + str(server_pid))
                # Apply shared settings plus an optional case-specific JSON sidecar.
                env = dict(clean_env, XLIO_USE_NEW_CONFIG='1',
                           XLIO_CONFIG_FILE=str(default_config),
                           XLIO_INLINE_CONFIG='core.resources.hugepages.enable=false;monitor.log.level=debug;monitor.log.details=2;monitor.log.colors=false')
                sidecar = test.with_name(test.stem + '-xlioconf.json')
                if sidecar.exists():
                    json.loads(sidecar.read_text())
                    env['XLIO_CONFIG_FILE'] = str(sidecar)
                # The client binds its own NIC and tells the wire process its NIC name.
                argv = client_prefix + ['--wire_server_at=' + args.server_ip,
                        '--wire_server_port=8081', '--wire_client_dev=' + args.client_interface,
                        '--wire_server_dev=' + args.server_interface, '--local_ip=' + args.client_ip,
                        '--netmask_ip=' + netmask, '--gateway_ip=' + args.server_ip,
                        '--remote_ip=' + args.server_ip, '--tolerance_usecs=' + str(args.tolerance_usecs),
                        '--verbose', '--debug', str(prepared)]
                # Own the client's private process group before handling interruption.
                progress('[{}/{}] Running XLIO client on {} ({}); config: {}'.format(
                    index, len(tests), args.client_interface, args.client_ip, env['XLIO_CONFIG_FILE']))
                with defer_interrupts():
                    client = subprocess.Popen(argv, cwd=CASES, env=env, stdout=client_log,
                                              stderr=subprocess.STDOUT, start_new_session=True)
                    test_cleanup.add(stop_process, client)
                # Bound each case independently; a timeout is a recorded test failure.
                try:
                    status = client.wait(timeout=args.timeout)
                    message = '' if status == 0 else 'Packetdrill exited ' + str(status)
                except subprocess.TimeoutExpired:
                    status, message = 1, 'Packetdrill timed out'
                    progress('[{}/{}] Client timed out after {} seconds'.format(index, len(tests), args.timeout))
                # Reap the client and wait for its wire worker to release capture
                # and firewall state before the listener serves another case.
                progress('[{}/{}] Finalizing test and collecting wire-server logs'.format(index, len(tests)))
                test_cleanup.close()
                test_cleanup.actions.clear()
                server_log.write(wire.finish(failed=status != 0))
            # Packet assertions alone can pass via the kernel; require XLIO evidence too.
            offloaded = test_offloaded((out / (stem + '.client.log')).read_text(errors='replace'), args.server_ip)
            if status == 0 and not offloaded:
                status, message = 1, 'No offload evidence for test flow on local or remote port 8080 (use --enable-opt-log=no)'
            results.append(dict(name=name, status='pass' if status == 0 else 'failure',
                                message=message, offloaded=offloaded, wire_server_pid=server_pid,
                                seconds=time.monotonic() - started))
            # Flush completed-case progress so partial runs remain diagnosable.
            atomic_json(out / 'results.json', results)
            progress('[{}/{}] {} {} ({:.2f}s, XLIO offloaded: {})'.format(
                index, len(tests), results[-1]['status'].upper(), name,
                results[-1]['seconds'], 'yes' if offloaded else 'no'))
            if message:
                progress('Failure: ' + message)
                progress('Client log: ' + str(out / (stem + '.client.log')))
                progress('Wire-server log: ' + str(out / (stem + '.server.log')))
        finally:
            # Exceptional paths must also reap processes and remove owned fixtures.
            with defer_interrupts():
                test_cleanup.close()


def reports(out, results, code):
    """Write final JUnit, JSON and summary artifacts, including setup/cleanup errors.

    JUnit records test failures separately from runner errors. Print the results
    path so callers can find the logs even when the run exits unsuccessfully.
    """
    # Include runner errors as testcases, so setup failures never look like zero-test passes.
    progress('Writing JUnit, JSON and summary reports to ' + str(out))
    suite = ET.Element('testsuite', name='packetdrill', tests=str(len(results)),
                       failures=str(sum(r['status'] == 'failure' for r in results)),
                       errors=str(sum(r['status'] == 'error' for r in results)),
                       skipped=str(sum(r['status'] == 'skipped' for r in results)))
    for result in results:
        case = ET.SubElement(suite, 'testcase', classname='xlio.packetdrill',
                             name=result['name'], time=str(result.get('seconds', 0)))
        if result['status'] != 'pass':
            ET.SubElement(case, result['status'], message=result['message']).text = result['message']
    ET.ElementTree(suite).write(out / 'junit.xml', encoding='utf-8', xml_declaration=True)
    atomic_json(out / 'results.json', results)
    summary = '\n'.join('{} {} {}'.format(r['status'].upper(), r['name'], r['message']) for r in results)
    (out / 'summary.log').write_text(summary + '\nexit code: ' + str(code) + '\n')
    progress('Completed: passed={}, failed={}, errors={}, skipped={}; exit code {}'.format(
        sum(r['status'] == 'pass' for r in results), suite.get('failures'), suite.get('errors'),
        suite.get('skipped'), code))
    print('\nResults:\n' + summary + '\nResults directory: ' + str(out), flush=True)
    # Include runner errors in the final failed count; JUnit keeps them separate.
    print('Total {} passed, {} failed, {} skipped'.format(
        sum(r['status'] == 'pass' for r in results),
        int(suite.get('failures')) + int(suite.get('errors')), suite.get('skipped')), flush=True)


class Interrupted(Exception):
    """Handled cancellation carrying the originating signal number."""
    def __init__(self, signum):
        """Keep the received signal number for the CLI's conventional 128+signal exit code."""
        self.signum = signum
        super().__init__('Interrupted by signal ' + str(signum))


def main():
    """Implement the three-mode pd CLI and return its exit status.

    Preparation and listing avoid privileged network setup. Runs validate the
    selection and arguments, lock the caller's network namespace, execute cases,
    and always attempt owned-resource cleanup and report generation. Return 0 for
    passing or skipped tests, 1 for test/offload failures, 2 for setup/cleanup errors, or
    128+signal for a caught interruption.
    """
    # The required action chooses an operation; interface options choose the topology.
    examples = r"""Three running modes (use the run action):

  Local mode -- create a temporary VF:
    pd run --interface ens2f0np0 \
       --client-ip 192.178.1.1 --server-ip 192.178.1.3
    The client IP must belong to the PF; the server IP must be unused.

  Two-interfaces mode -- use the caller's configured interface pair:
    pd run --client-interface net1 --server-interface net2 \
       --client-ip 192.0.2.1 --server-ip 192.0.2.2
    Both IPs must already be assigned. Only the server NIC moves to a temp namespace.

  Remote mode -- run the wire server over SSH, without VFs/namespaces:
    pd run --server-host root@dor02 \
       --client-interface ens2f0np0 --server-interface enp4s0f0 \
       --client-ip 192.178.1.1 --server-ip 192.178.1.2
    Interface names are independent. Prepare Packetdrill on both machines first.

Runs require root, data interfaces with MTU 1500, and distinct IPv4 addresses
in the same subnet. Substitute your hostnames, interface names and addresses.
Use pd prepare to build Packetdrill and pd list to discover tests.
Append --filter REGEXP to select cases; --include-disabled also runs disabled cases.
"""
    parser = argparse.ArgumentParser(
        description='Run XLIO Packetdrill tests in Local mode, Two-interfaces mode or Remote mode.',
        epilog=examples, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['prepare', 'list', 'run'],
                        help='Required action: prepare Packetdrill, list cases, or run tests')
    parser.add_argument('--cache-dir', default=os.environ.get('PD_CACHE_DIR', str(ROOT / '.cache')))
    parser.add_argument('--packetdrill', help='Use an explicitly supplied, unmodified Packetdrill binary')
    parser.add_argument('--xlio', help='Exact shared library to preload')
    parser.add_argument('--build-dir', default=str(ROOT.parent.parent), help='XLIO build directory')
    parser.add_argument('--filter', default=r'\.pkt$', help='Regular expression on source-qualified case paths')
    parser.add_argument('--include-disabled', action='store_true',
                        help='Run selected tests even if their YAML sidecars disable them')
    parser.add_argument('--output', help='Empty report directory (default: unique runs directory)')
    parser.add_argument('--interface', metavar='PF',
                        help='Local mode: create a temporary wire-server VF on this PF')
    parser.add_argument('--client-interface', metavar='IFACE',
                        help='Existing client interface for Two-interfaces mode or Remote mode')
    parser.add_argument('--server-interface', metavar='IFACE',
                        help='Existing wire interface, on --server-host when using SSH')
    parser.add_argument('--server-host', help='Remote mode: SSH root@host for the wire server')
    parser.add_argument('--server-dir', default=str(ROOT), help='Packetdrill script directory on the SSH server')
    parser.add_argument('--server-packetdrill', help='Explicit Packetdrill binary path on the SSH server')
    parser.add_argument('--server-cache-dir', help='Prepared Packetdrill cache on the SSH server')
    parser.add_argument('--ssh-command', default='ssh -o BatchMode=yes -o ConnectTimeout=10 '
                        '-o ServerAliveInterval=5 -o ServerAliveCountMax=3',
                        help='SSH executable and options, parsed as words without shell evaluation')
    parser.add_argument('--client-ip', help='IPv4 address already assigned to the client interface/PF')
    parser.add_argument('--server-ip',
                        help='Wire IPv4: unused with --interface, already assigned in other modes')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--tolerance-usecs', type=int, default=60000)
    args = parser.parse_args()
    # Detect ambiguous modes before output creation or any privileged operation.
    args.vf = args.interface is not None
    if args.vf and (args.client_interface or args.server_interface or args.server_host):
        parser.error('--interface cannot be combined with --client-interface, '
                     '--server-interface or --server-host')
    # Preparation and discovery finish before creating run reports or acquiring NICs.
    if args.action == 'prepare':
        try:
            prepare(args.cache_dir)
            return 0
        except Exception as error:
            print(error, file=sys.stderr)
            return 2
    if args.action == 'list':
        try:
            for path, reason, attributes in select_tests(args.filter):
                print(str(path.relative_to(CASES)) + (' [disabled: ' + reason + ']' if reason else ''))
        except Exception as error:
            print(error, file=sys.stderr)
            return 2
        return 0
    # Give every execution an empty report directory and a run-wide cleanup owner.
    out = Path(args.output).resolve() if args.output else ROOT / 'runs' / (time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    if out.exists() and any(out.iterdir()):
        print('Report directory must be empty: ' + str(out), file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    progress('Starting pd run; results directory: ' + str(out))
    cleanup, results, code = Cleanup(), [], 0

    def interrupted(signum, frame):
        """Turn a handled signal into an exception so normal unwinding performs cleanup."""
        raise Interrupted(signum)

    # Convert normal CLI cancellation into an exception rather than abandoning state.
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        # Reject empty selections, malformed endpoints and missing privilege before setup.
        progress('Loading test policy and resources from optional YAML sidecars')
        selected = select_tests(args.filter)
        if not selected:
            raise RuntimeError('No tests match the selection')
        active = []
        for path, reason, attributes in selected:
            if reason and not args.include_disabled:
                name = path.relative_to(CASES).as_posix()
                results.append(dict(name=name, status='skipped', message=reason, seconds=0))
                progress('SKIPPED {}: {}'.format(name, reason))
            else:
                active.append((path, attributes))
        args.test_count = len(active)
        progress('Selected tests: {}; running: {}; skipped: {}'.format(
            len(selected), len(active), len(selected) - len(active)))
        if args.include_disabled:
            progress('Including disabled tests (--include-disabled)')
        # An all-disabled selection is a successful skipped run: acquire no
        # interfaces, VFs, tools, library or network-namespace lock.
        if not active:
            return 0
        if not args.client_ip or not args.server_ip:
            raise RuntimeError('--client-ip and --server-ip are required')
        if args.vf:
            if not args.interface:
                raise RuntimeError('--interface is required for Local mode')
        elif not args.client_interface or not args.server_interface:
            raise RuntimeError('Use --interface PF or both --client-interface and --server-interface')
        args.client_ip = str(ipaddress.IPv4Address(args.client_ip))
        args.server_ip = str(ipaddress.IPv4Address(args.server_ip))
        if args.timeout <= 0 or args.tolerance_usecs < 0:
            raise RuntimeError('Timeout must be positive and tolerance nonnegative')
        if os.geteuid() != 0:
            raise RuntimeError('pd run needs root for networking and raw packets')
        # Namespace ID prevents collisions between independent CI pods on one host.
        netns = os.stat('/proc/self/ns/net').st_ino
        progress('Acquiring run lock for network namespace ' + str(netns))
        with lock('/run/lock/xlio-pd-' + str(netns) + '.lock'):
            try:
                execute(args, active, out, cleanup, results)
                # Ordinary assertion/offload failures are exit 1; exceptions become exit 2.
                code = int(any(r['status'] not in ('pass', 'skipped') for r in results))
            finally:
                # Do not let a second signal interrupt restoration of the interface.
                for sig in previous:
                    signal.signal(sig, signal.SIG_IGN)
                progress('Stopping the wire server, restoring network state and removing temporary resources')
                cleanup.close()
                progress('Network and resource cleanup complete')
    # Cleanup errors take the same setup-error path and therefore cannot report success.
    except Interrupted as error:
        code = 128 + error.signum
        results.append(dict(name='runner', status='error', message=str(error)))
    except Exception as error:
        code = 2
        results.append(dict(name='runner', status='error', message=str(error)))
    finally:
        # Reports are finalized for successful, failed and interrupted executions alike.
        reports(out, results, code)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return code
