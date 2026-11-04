#!/usr/bin/env python3
"""Tests for the runner's failure and offload-evidence contracts (no NIC needed)."""
import contextlib
import importlib.util
import io
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import json
import os
import re
from pathlib import Path
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent


def runner_module():
    spec = importlib.util.spec_from_file_location('pd_common', ROOT / 'pd_common.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def runner_fixture(root, sidecars, names):
    """Copy the real CLI into an isolated corpus with optional YAML sidecars."""
    for name in ['pd', 'pd_common.py', 'packetdrill.version.json']:
        shutil.copy2(ROOT / name, root / name)
    cases = root / 'cases'
    cases.mkdir()
    for name in names:
        path = cases / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('// Selection fixture: never executed by these checks.\n')
    for name, metadata in (sidecars or {}).items():
        (cases / name).with_suffix('.yaml').write_text(metadata)


class RunnerTests(unittest.TestCase):
    def test_action_is_required_before_run_creation_or_setup(self):
        variants = [[], ['--interface', 'pf0'],
                    ['--client-interface', 'net1', '--server-interface', 'net2'],
                    ['--server-host', 'root@wire-host', '--client-interface', 'local0',
                     '--server-interface', 'remote0']]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {'case.pkt': 'disabled: true\n'}, ['case.pkt'])
            for index, options in enumerate(variants):
                with self.subTest(options=options):
                    output = root / ('run-' + str(index))
                    result = subprocess.run([sys.executable, str(root / 'pd')] + options +
                                            ['--output', str(output)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn('required: action', result.stderr)
                    self.assertFalse(output.exists(), 'Missing actions must fail before creating reports')

    def test_interface_arguments_select_the_expected_run_mode(self):
        variants = [(['--interface', 'pf0'], True, None),
                    (['--client-interface', 'net1', '--server-interface', 'net2'], False, None),
                    (['--client-interface', 'local0', '--server-interface', 'remote0',
                      '--server-host', 'root@wire-host'], False, 'root@wire-host')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {}, ['case.pkt'])
            for index, (options, expected_vf, server_host) in enumerate(variants):
                with self.subTest(options=options):
                    mod = runner_module()
                    output = root / ('run-' + str(index))
                    argv = ['pd', 'run'] + options + [
                        '--client-ip', '192.0.2.1', '--server-ip', '192.0.2.2', '--output', str(output)]
                    stdout, stderr = io.StringIO(), io.StringIO()
                    # Capture dispatch at the hardware boundary; no NIC setup is performed.
                    with (mock.patch.object(mod, 'CASES', root / 'cases'),
                          mock.patch.object(sys, 'argv', argv),
                          mock.patch.object(mod.os, 'geteuid', return_value=0),
                          mock.patch.object(mod, 'lock', return_value=contextlib.nullcontext()),
                          mock.patch.object(mod, 'execute') as execute,
                          contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
                        try:
                            status = mod.main()
                        except SystemExit as error:
                            status = error.code
                    self.assertEqual(status, 0, stdout.getvalue() + stderr.getvalue())
                    execute.assert_called_once()
                    args = execute.call_args.args[0]
                    self.assertEqual(args.vf, expected_vf)
                    self.assertEqual(args.server_host, server_host)
                    if expected_vf:
                        self.assertEqual(args.interface, 'pf0')
                    else:
                        self.assertEqual(args.client_interface, options[1])
                        self.assertEqual(args.server_interface, options[3])

    def test_interface_mode_rejects_conflicting_network_options(self):
        variants = [['--interface', 'pf0', '--client-interface', 'net1'],
                    ['--interface', 'pf0', '--server-interface', 'net2'],
                    ['--interface', 'pf0', '--server-host', 'root@wire-host']]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {}, ['case.pkt'])
            for index, options in enumerate(variants):
                with self.subTest(options=options):
                    output = root / ('run-' + str(index))
                    result = subprocess.run([sys.executable, str(root / 'pd'), 'run'] + options +
                                            ['--output', str(output)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('cannot be combined', result.stderr)
                    self.assertFalse(output.exists(), 'Reject ambiguous modes before creating a run')

    def test_missing_mode_interfaces_fail_before_tool_or_network_setup(self):
        variants = [([], '--client-interface and --server-interface'),
                    (['--client-interface', 'net1'], '--client-interface and --server-interface'),
                    (['--interface', ''], '--interface is required')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {}, ['case.pkt'])
            for index, (options, message) in enumerate(variants):
                with self.subTest(options=options):
                    result = subprocess.run([sys.executable, str(root / 'pd'), 'run'] + options +
                                            ['--client-ip', '192.0.2.1', '--server-ip', '192.0.2.2',
                                             '--output', str(root / ('run-' + str(index)))],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(message, result.stdout)
                    self.assertNotIn('Acquiring run lock', result.stdout)

    def test_pd_help_explains_all_three_modes(self):
        result = subprocess.run([sys.executable, str(ROOT / 'pd'), '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for text in ('Local mode', 'Two-interfaces mode', 'Remote mode',
                     'pd run --interface', 'pd run --client-interface',
                     'pd run --server-host', '--client-ip', '--server-ip', 'Required action'):
            self.assertIn(text, result.stdout)
        self.assertNotIn('[{prepare,list,run}]', result.stdout)

    def test_helper_commands_do_not_inherit_preload_or_xlio_settings(self):
        mod = runner_module()
        with mock.patch.dict(os.environ, LD_PRELOAD='/does-not-exist/libxlio.so',
                             XLIO_INLINE_CONFIG='must-not-reach-helpers'):
            result = mod.command(sys.executable, '-c',
                                 'import json,os; print(json.dumps({k:os.environ.get(k) '
                                 'for k in ["LD_PRELOAD","XLIO_INLINE_CONFIG"]}))')
        self.assertEqual(json.loads(result.stdout), dict(LD_PRELOAD=None, XLIO_INLINE_CONFIG=None))
        self.assertEqual(result.stderr, b'')

    @unittest.skipUnless(shutil.which('cc') and shutil.which('readelf'),
                         'preload isolation check needs a C compiler and readelf')
    def test_only_client_loads_preload_library_and_exec_helpers_do_not(self):
        mod = runner_module()
        self.assertTrue(hasattr(mod, 'client_command'), 'client-only preload launcher is missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, library = root / 'probe.c', root / 'probe.so'
            source.write_text('int pd_preload_probe(void) { return 42; }\n')
            subprocess.run(['cc', '-shared', '-fPIC', str(source), '-o', str(library)],
                           check=True, capture_output=True)
            helper = ('import ctypes,json,os; print(json.dumps(dict('
                      'loaded=hasattr(ctypes.CDLL(None),"pd_preload_probe"),'
                      'preload=os.environ.get("LD_PRELOAD"))))')
            driver = '''
import ctypes,json,os,subprocess,sys
child = subprocess.run([sys.executable, '-c', sys.argv[1]], check=True,
                       capture_output=True, text=True)
print(json.dumps(dict(loaded=ctypes.CDLL(None).pd_preload_probe(),
                      preload=os.environ.get('LD_PRELOAD'), helper=json.loads(child.stdout))))
'''
            argv = mod.client_command(Path(sys.executable).resolve(), library)
            result = subprocess.run(argv + ['-c', driver, helper],
                                    env=mod.clean_environment(), capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout),
                             dict(loaded=42, preload=None, helper=dict(loaded=False, preload=None)))

    def test_sidecars_disable_only_their_own_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {'kernel/a.pkt': 'disabled: true\n',
                                  'kernel/b.pkt': 'disabled: true\n',
                                  'xlio/lro.pkt': 'disabled: true\n'},
                           ['kernel/a.pkt', 'kernel/b.pkt', 'xlio/lro.pkt', 'xlio/other.pkt'])
            result = subprocess.run([sys.executable, str(root / 'pd'), 'list'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sum('[disabled:' in line for line in result.stdout.splitlines()), 3)
            self.assertIn('xlio/other.pkt\n', result.stdout)
            self.assertIn('cases/kernel/a.yaml', result.stdout)
            result = subprocess.run([sys.executable, str(root / 'pd'), 'run',
                                     '--filter', '^kernel/', '--output', str(root / 'run')],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = ET.parse(root / 'run/junit.xml').getroot()
            self.assertEqual(report.get('tests'), '2')
            self.assertEqual(report.get('skipped'), '2')
            self.assertEqual(report.get('errors'), '0')
            self.assertEqual(len(report.findall('testcase/skipped')), 2)

    def test_all_disabled_runs_need_no_network_or_resources_in_all_modes(self):
        variants = [[], ['--interface', 'pf0'],
                    ['--client-interface', 'net1', '--server-interface', 'net2'],
                    ['--server-host', 'root@wire-host', '--client-interface', 'local0',
                     '--server-interface', 'remote0']]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {'kernel/a.pkt': 'disabled: true\ntempfile: {size: 5}\n'},
                           ['kernel/a.pkt'])
            for index, options in enumerate(variants):
                with self.subTest(options=options):
                    out = root / ('run-' + str(index))
                    result = subprocess.run([sys.executable, str(root / 'pd'), 'run'] + options +
                                            ['--output', str(out)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    results = json.loads((out / 'results.json').read_text())
                    self.assertEqual(len(results), 1)
                    self.assertEqual(results[0]['status'], 'skipped')
                    self.assertIn('cases/kernel/a.yaml', results[0]['message'])
                    self.assertNotIn('Acquiring run lock', result.stdout)
                    self.assertNotIn('Creating a zero-filled', result.stdout)

    def test_include_disabled_overrides_sidecars_and_keeps_cli_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {'kernel/a.pkt': 'disabled: true\n',
                                  'xlio/b.pkt': 'disabled: true\n'}, ['kernel/a.pkt', 'xlio/b.pkt'])
            for index, options in enumerate([[], ['--interface', 'pf0']]):
                with self.subTest(options=options):
                    out = root / ('forced-' + str(index))
                    result = subprocess.run([sys.executable, str(root / 'pd'), 'run'] + options +
                                            ['--include-disabled', '--filter', '^kernel/', '--output', str(out)],
                                            capture_output=True, text=True)
                    # Forced cases reach ordinary run validation instead of being skipped.
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn('--client-ip and --server-ip are required', result.stdout)
                    self.assertIn('Selected tests: 1; running: 1; skipped: 0', result.stdout)
                    report = ET.parse(out / 'junit.xml').getroot()
                    self.assertEqual(report.get('skipped'), '0')

    def test_sidecar_attributes_do_not_leak_between_cases(self):
        mod = runner_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {'kernel/a.pkt': 'disabled: false\ntempfile: {size: 7}\n',
                                  'xlio/a.pkt': 'disabled: true\ntempfile: {size: 5}\n'},
                           ['kernel/a.pkt', 'kernel/b.pkt', 'xlio/a.pkt'])
            with mock.patch.object(mod, 'CASES', root / 'cases'):
                selected = mod.select_tests(r'[.]pkt$')
            self.assertEqual(selected[0][1], '')
            self.assertEqual(selected[0][2], {'disabled': False, 'tempfile': {'size': 7}})
            self.assertEqual(selected[1][1:], ('', {}))
            self.assertIn('cases/xlio/a.yaml', selected[2][1])
            self.assertEqual(selected[2][2]['tempfile'], {'size': 5})

    def test_absent_or_empty_mapping_sidecar_uses_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {'empty.pkt': '{}\n'}, ['empty.pkt', 'missing.pkt'])
            result = subprocess.run([sys.executable, str(root / 'pd'), 'list'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'empty.pkt\nmissing.pkt\n')
            self.assertFalse((root / 'cases/META.yaml').exists())

    def test_invalid_sidecar_fails_before_network_setup(self):
        examples = ['', '# No YAML mapping\n', '[]', '- nope\n',
                    'disabled: [\n', 'typo: true\n', 'test: .*\n',
                    'disabled: 1\n', 'disabled: "true"\n', 'tempfile: 5\n',
                    'tempfile: {}\n', 'tempfile: {size: -1}\n',
                    'tempfile: {size: true}\n', 'tempfile: {size: 1.5}\n',
                    'tempfile: {size: 5, typo: 1}\n',
                    'disabled: !!python/object:builtins.object {}\n']
        for metadata in examples:
            with self.subTest(metadata=metadata), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                runner_fixture(root, {'case.pkt': metadata}, ['case.pkt'])
                result = subprocess.run([sys.executable, str(root / 'pd'), 'run',
                                         '--output', str(root / 'run')], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('case.yaml', result.stdout)
                self.assertNotIn('Acquiring run lock', result.stdout)
                result = subprocess.run([sys.executable, str(root / 'pd'), 'list'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('case.yaml', result.stderr)

    def test_filter_does_not_load_unselected_sidecars(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {'bad.pkt': 'unknown: true\n'}, ['good.pkt', 'bad.pkt'])
            result = subprocess.run([sys.executable, str(root / 'pd'), 'list', '--filter', '^good[.]pkt$'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'good.pkt\n')

    def test_wire_server_waits_for_each_worker_before_reuse(self):
        mod = runner_module()
        self.assertTrue(hasattr(mod, 'WireServer'), 'persistent wire-server owner is missing')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wire.log'
            marker = b'wire_server.c 569] wire_server_thread: connection is done\n'
            path.write_bytes(marker)
            wire = mod.WireServer(sys.executable, 'unused', path)
            wire.log = path.open('ab')
            worker = subprocess.Popen([sys.executable, '-u', '-c',
                                       'import sys\nfor line in sys.stdin:\n'
                                       ' sys.stdout.write("wire_server.c 569] wire_server_thread: connection is done\\n")\n'
                                       ' sys.stdout.flush()\n'],
                                      stdin=subprocess.PIPE, stdout=wire.log,
                                      start_new_session=True)
            wire.process = worker
            try:
                for _ in range(2):
                    wire.offset = path.stat().st_size
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        completed = pool.submit(wire.finish)
                        try:
                            # An earlier case's marker must not release this case.
                            with self.assertRaises(FutureTimeout):
                                completed.result(timeout=0.05)
                        finally:
                            worker.stdin.write(b'finish this case\n')
                            worker.stdin.flush()
                        self.assertEqual(completed.result(timeout=5), marker)
                    self.assertIsNone(worker.poll(), 'successful completion stopped the shared server')
            finally:
                wire.stop()
                worker.stdin.close()

    def test_wire_server_stops_after_failed_client(self):
        mod = runner_module()
        self.assertTrue(hasattr(mod, 'WireServer'), 'persistent wire-server owner is missing')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wire.log'
            path.write_bytes(b'case in progress\n')
            wire = mod.WireServer(sys.executable, 'unused', path)
            wire.log = path.open('ab')
            stream = wire.log
            worker = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'],
                                      stdin=subprocess.PIPE, stdout=wire.log,
                                      start_new_session=True)
            wire.process = worker
            try:
                self.assertEqual(wire.finish(failed=True), b'case in progress\n')
                self.assertIsNotNone(worker.poll())
                self.assertIsNone(wire.process)
                self.assertTrue(stream.closed)
            finally:
                wire.stop()
                worker.stdin.close()

    def test_remote_mode_accepts_independent_interface_names(self):
        with tempfile.TemporaryDirectory() as output:
            result = subprocess.run([sys.executable, str(ROOT / 'pd'), 'run',
                                     '--server-host', 'root@server',
                                     '--client-interface', 'client0',
                                     '--server-interface', 'wire0',
                                     '--filter', 'does-not-exist', '--output', output],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('No tests match', result.stdout)
            self.assertNotIn('unrecognized arguments', result.stderr)

    def test_control_connection_does_not_prove_test_offload(self):
        self.assertTrue((ROOT / 'pd_common.py').exists(), 'runner must exist')
        mod = runner_module()
        control = 'dst[0x1]:47:dst_entry() dst:192.0.2.2:8081 src: 1234\n'
        verdict = 'dst[0x1]:540:prepare_to_send() dst_entry is offloaded!\n'
        self.assertFalse(mod.test_offloaded(control + verdict, '192.0.2.2'))
        test = control.replace(':8081', ':8080')
        self.assertTrue(mod.test_offloaded(test + verdict, '192.0.2.2'))
        # Object addresses may be reused after a connection closes.
        self.assertFalse(mod.test_offloaded(test + control + verdict, '192.0.2.2'))

    def test_passive_offload_uses_local_test_port_and_peer_address(self):
        mod = runner_module()
        passive = 'dst[0x1]:47:dst_entry() dst:192.0.2.2:53536 src: 8080\n'
        verdict = 'dst[0x1]:540:prepare_to_send() dst_entry is offloaded!\n'
        self.assertTrue(mod.test_offloaded(passive + verdict, '192.0.2.2'))
        self.assertFalse(mod.test_offloaded(passive.replace(':53536', ':8081') + verdict, '192.0.2.2'))
        self.assertFalse(mod.test_offloaded(passive + verdict, '192.0.2.3'))
        self.assertFalse(mod.test_offloaded(passive.replace('src: 8080', 'src: 9090') + verdict, '192.0.2.2'))

    def test_empty_selection_is_reported_as_error(self):
        self.assertTrue((ROOT / 'pd').exists(), 'entry point must exist')
        with tempfile.TemporaryDirectory() as output:
            run = subprocess.run([sys.executable, str(ROOT / 'pd'), 'run',
                                  '--filter', 'does-not-exist', '--output', output],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
            report = ET.parse(Path(output) / 'junit.xml').getroot()
            self.assertEqual(report.get('errors'), '1')
            self.assertEqual(report.get('tests'), '1')

    def test_metadata_prepares_private_zero_file_and_substitutes_script(self):
        mod = runner_module()
        self.assertTrue(callable(getattr(mod, 'prepare_test', None)),
                        'metadata-driven test preparation is missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_fixture(root, {'generic/example.pkt': 'tempfile: {size: 5}\n'},
                           ['generic/example.pkt'])
            source = root / 'cases/generic/example.pkt'
            original = ('// The runner replaces $TEMPFILE_PATH everywhere.\n'
                        '0 open("$TEMPFILE_PATH", O_RDONLY) = 3\n')
            source.write_text(original)
            with mock.patch.object(mod, 'CASES', root / 'cases'):
                case, reason, attributes = mod.select_tests('example')[0]
            self.assertEqual(reason, '')
            cleanup = mod.Cleanup()
            try:
                prepared = mod.prepare_test(case, attributes, cleanup)
                rendered = prepared.read_text()
                fixture = Path(re.search(r'open\("([^"\n]+)"', rendered).group(1))
                self.assertNotEqual(prepared, source)
                self.assertEqual(prepared.suffix, '.pkt')
                self.assertEqual(fixture.read_bytes(), b'\0' * 5)
                self.assertEqual(fixture.stat().st_mode & 0o777, 0o600)
                self.assertEqual(fixture.parent.stat().st_mode & 0o777, 0o700)
                self.assertNotIn('$TEMPFILE_PATH', rendered)
                self.assertEqual(source.read_text(), original)
                self.assertEqual(fixture.parent, prepared.parent)
            finally:
                cleanup.close()
            self.assertFalse(prepared.exists())
            self.assertFalse(fixture.parent.exists())

    def test_tempfile_resources_are_unique_and_support_empty_files(self):
        mod = runner_module()
        self.assertTrue(callable(getattr(mod, 'prepare_test', None)),
                        'metadata-driven test preparation is missing')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'example.pkt'
            source.write_text('0 open("$TEMPFILE_PATH", O_RDONLY) = 3\n')
            cleanup = mod.Cleanup()
            try:
                first = mod.prepare_test(source, {'tempfile': {'size': 0}}, cleanup)
                second = mod.prepare_test(source, {'tempfile': {'size': 7}}, cleanup)
                one = Path(re.search(r'open\("([^"]+)"', first.read_text()).group(1))
                two = Path(re.search(r'open\("([^"]+)"', second.read_text()).group(1))
                self.assertNotEqual(one, two)
                self.assertEqual(one.read_bytes(), b'')
                self.assertEqual(two.read_bytes(), b'\0' * 7)
                # Simulate failure after resource preparation; normal cleanup owns both.
                raise RuntimeError('test failed after preparation')
            except RuntimeError as error:
                self.assertEqual(str(error), 'test failed after preparation')
            finally:
                cleanup.close()
            self.assertFalse(first.parent.exists())
            self.assertFalse(second.parent.exists())

    def test_tempfile_token_and_metadata_must_agree(self):
        mod = runner_module()
        self.assertTrue(callable(getattr(mod, 'prepare_test', None)),
                        'metadata-driven test preparation is missing')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'example.pkt'
            cleanup = mod.Cleanup()
            try:
                source.write_text('0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3\n')
                self.assertEqual(mod.prepare_test(source, {}, cleanup), source)
                with self.assertRaisesRegex(RuntimeError, 'TEMPFILE_PATH'):
                    mod.prepare_test(source, {'tempfile': {'size': 5}}, cleanup)
                source.write_text('0 open("$TEMPFILE_PATH", O_RDONLY) = 3\n')
                with self.assertRaisesRegex(RuntimeError, 'TEMPFILE_PATH'):
                    mod.prepare_test(source, {}, cleanup)
            finally:
                cleanup.close()

    def test_modified_cache_is_rejected_before_network_setup(self):
        mod = runner_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            binary = mod.cache_binary(base / 'cache')
            binary.parent.mkdir(parents=True)
            binary.write_text('#!/bin/sh\nexit 0\n')
            binary.chmod(0o755)
            (binary.parent / 'ready.json').write_text(json.dumps(dict(mod.PIN, sha256='wrong')))
            with self.assertRaisesRegex(RuntimeError, 'cache verification failed'):
                mod.verify_cache(binary)

    def test_signal_waits_for_rollback_registration(self):
        mod = runner_module()
        events = []
        previous = signal.signal(signal.SIGTERM, lambda number, frame: events.append('signal'))
        try:
            with mod.defer_interrupts():
                events.append('mutation')
                os.kill(os.getpid(), signal.SIGTERM)
                events.append('rollback registered')
            self.assertEqual(events, ['mutation', 'rollback registered', 'signal'])
        finally:
            signal.signal(signal.SIGTERM, previous)

    def test_group_signal_does_not_kill_setup_command(self):
        # The driver owns a private session so the test never signals its caller.
        script = '''
import os, signal, sys
sys.path.insert(0, sys.argv[1])
import pd_common as mod
events = []
signal.signal(signal.SIGTERM, lambda number, frame: events.append('signal'))
with mod.defer_interrupts():
    mod.command(sys.executable, '-c',
                'import os,signal; os.killpg(os.getpgid(os.getppid()), signal.SIGTERM)')
    events.append('rollback registered')
assert events == ['rollback registered', 'signal'], events
'''
        result = subprocess.run([sys.executable, '-c', script, str(ROOT)],
                                start_new_session=True, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_supervisor_hangup_and_watchdog_wait_for_ownership(self):
        mod = runner_module()
        for number in (signal.SIGHUP, signal.SIGALRM):
            events = []
            previous = signal.signal(number, lambda sig, frame: events.append('signal'))
            try:
                with mod.defer_interrupts((number,)):
                    os.kill(os.getpid(), number)
                    events.append('process registered')
                self.assertEqual(events, ['process registered', 'signal'])
            finally:
                signal.signal(number, previous)

    def test_closed_ssh_pipe_still_reaps_process_and_closes_streams(self):
        import argparse
        import pd_remote
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            fake = out / 'exited_ssh.py'
            fake.write_text('raise SystemExit(0)\n')
            args = argparse.Namespace(server_host='server', server_dir='/unused',
                                      ssh_command=shlex.join([sys.executable, str(fake)]))
            remote = pd_remote.RemoteWireServer(args, out)
            remote.process.wait(timeout=5)
            # Buffered data makes stdin.close() itself raise BrokenPipeError.
            remote.process.stdin.write(b'pending request')
            with self.assertRaisesRegex(RuntimeError, 'before confirming remote cleanup'):
                remote.close()
            self.assertTrue(remote.process.stdin.closed)
            self.assertTrue(remote.process.stdout.closed)
            self.assertTrue(remote.stderr.closed)
            self.assertEqual(remote.process.returncode, 0)


if __name__ == '__main__':
    unittest.main()
