#!/usr/bin/env python3
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
"""Hardware-free contract checks for the gtest runner: python3 tests/gtest/test_run.py."""
import json
import os
from pathlib import Path
import subprocess
import runpy
import shutil
import tempfile
import unittest


RUN = Path(__file__).resolve().with_name("run")
PASS_XML = '<testsuites><testsuite name="suite"><testcase classname="suite" name="ok" status="run"/></testsuite></testsuites>'


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gtest runner ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.record = self.root / "calls.jsonl"
        self.app = self.root / "record gtest"
        self.app.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with open(os.environ['RECORD'], 'a') as f:
    f.write(json.dumps({'args': sys.argv[1:], 'env': dict(os.environ),
                        'cwd': os.getcwd(),
                        'config': Path(os.environ['XLIO_CONFIG_FILE']).read_text()
                        if 'XLIO_CONFIG_FILE' in os.environ else None}) + '\\n')
Path('suite.tap').write_text('test output')
print('test stdout')
print('test stderr', file=sys.stderr)
for arg in sys.argv[1:]:
    if arg.startswith('--gtest_output=xml:'):
        if not os.environ.get('NO_TEST_XML'):
            Path(arg.split('xml:', 1)[1]).write_text(os.environ.get('TEST_XML',
                '<testsuites><testsuite name="suite"><testcase classname="suite" name="ok" status="run"/></testsuite></testsuites>'))
sys.exit(7 if os.environ.get('FAIL_R2C') and
         'xlio_config_full_coverage' in os.environ.get('XLIO_CONFIG_FILE', '') else 0)
""")
        self.app.chmod(0o755)
        # The recorder doesn't need XLIO; a real preloadable library avoids loader noise.
        self.lib = next(p for p in (Path('/lib64/libc.so.6'),
                                   Path('/lib/x86_64-linux-gnu/libc.so.6')) if p.exists())

    def invoke(self, *args, **extra_env):
        self.assertTrue(RUN.exists(), "shared gtest runner is missing")
        return subprocess.run(
            [str(RUN), '--gtest-bin=' + str(self.app), '--xlio-lib=' + str(self.lib),
             '--output-dir=' + str(self.root / 'results'), *args],
            cwd=self.root, env=dict(os.environ, RECORD=str(self.record), **extra_env),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_workspace_defaults_and_ci_environment_is_preserved(self):
        for name in ('WORKSPACE', 'GTEST_TAP'):
            previous = os.environ.pop(name, None)
            if previous is not None:
                self.addCleanup(os.environ.__setitem__, name, previous)
        result = self.invoke('--addr', '192.0.2.1,192.0.2.2')
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.calls():
            self.assertEqual(call['env'].get('WORKSPACE'), str(RUN.parents[2]))
            self.assertFalse('GTEST_TAP' in call['env'], 'runner injected GTEST_TAP')
        self.record.unlink()
        result = self.invoke('--addr', '192.0.2.1,192.0.2.2',
                             WORKSPACE='/caller/workspace', GTEST_TAP='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.calls():
            self.assertEqual(call['env']['WORKSPACE'], '/caller/workspace')
            self.assertEqual(call['env']['GTEST_TAP'], '1')

    def calls(self):
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def test_list_profiles_needs_no_addresses_or_build_and_writes_nothing(self):
        result = self.invoke('--list-profiles', '--gtest-bin', '/missing/gtest',
                             '--xlio-lib', '/missing/libxlio.so')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Profile r2c-full', result.stdout)
        self.assertIn('config/xlio_config_full_coverage.json', result.stdout)
        self.assertIn('Profile wtbp', result.stdout)
        self.assertIn('config/wtbp.json', result.stdout)
        self.assertIn('tcp_stream_integrity*', result.stdout)
        self.assertFalse(self.record.exists())
        self.assertFalse((self.root / 'results').exists())

    def test_list_profiles_matches_execution_descriptors(self):
        namespace = runpy.run_path(str(RUN))
        profiles = namespace['PROFILES']
        self.assertEqual(len(profiles), 20)
        result = self.invoke('--list-profiles')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, profile in profiles.items():
            with self.subTest(profile=name):
                section = result.stdout.split('Profile ' + name + '\n', 1)[1].split('\n\n', 1)[0]
                self.assertIn('Config: config/' + profile.config, section)
                self.assertIn('Filter: ' + profile.test_filter, section)
                self.assertTrue((RUN.parent / 'config' / profile.config).is_file())

    def test_default_profiles_and_environment_inheritance(self):
        inherited = {'XLIO_WORKER_THREADS': '99', 'XLIO_SELECT_POLL': '999',
                     'XLIO_INLINE_CONFIG': 'caller-inline-config'}
        result = self.invoke('--addr=192.0.2.1,192.0.2.2', '--', '--port=55556',
                             **inherited, XLIO_USE_NEW_CONFIG='0',
                             XLIO_CONFIG_FILE='/caller/config.json',
                             GTEST_FILTER='bad', GTEST_OUTPUT='xml:/caller/output.xml')
        self.assertEqual(result.returncode, 0, result.stderr)
        first, second = self.calls()
        self.assertEqual(first['env']['XLIO_USE_NEW_CONFIG'], '1')
        worker = json.loads(second['config'])['performance']
        self.assertEqual(worker['threading']['worker_threads'], 1)
        self.assertEqual(worker['polling']['iomux']['poll_usec'], 10)
        for call in (first, second):
            for name, value in inherited.items():
                self.assertEqual(call['env'].get(name), value)
            self.assertEqual(call['env']['XLIO_USE_NEW_CONFIG'], '1')
            self.assertFalse('GTEST_FILTER' in call['env'], 'inherited GTEST_FILTER was not removed')
            self.assertFalse('GTEST_OUTPUT' in call['env'], 'inherited GTEST_OUTPUT was not removed')
            self.assertIn('--addr=192.0.2.1,192.0.2.2', call['args'])
            self.assertIn('--port=55556', call['args'])
            self.assertTrue((Path(call['cwd']) / 'suite.tap').exists())
            self.assertEqual(Path(call['env']['XLIO_CONFIG_FILE']).parent, Path(call['cwd']))
        self.assertNotEqual(first['cwd'], second['cwd'])

    def test_profile_test_parameters_override_inherited_values(self):
        result = self.invoke('--profiles', 'rto-floor-max', '--addr', '192.0.2.1,192.0.2.2',
                             XLIO_GTEST_EXPECT_RTO_MSEC='123')
        self.assertEqual(result.returncode, 0, result.stderr)
        call, = self.calls()
        self.assertEqual(call['env']['XLIO_GTEST_EXPECT_RTO_MSEC'], '120000')

    def test_generic_config_substitution_preserves_json_types(self):
        render = runpy.run_path(str(RUN))['render_config']
        source = self.root / 'template.json'
        source.write_text(json.dumps({'values': ['@CLIENT_IP@', {'path': '@RUN_DIR@/@PROFILE@'}],
                                      'enabled': True, 'count': 3, 'empty': None}))
        values = {'CLIENT_IP': '2001:db8::1', 'RUN_DIR': '/path/with "quotes"/and\\slashes',
                  'PROFILE': 'example'}
        result = json.loads(render(source, values))
        self.assertEqual(result['values'], [values['CLIENT_IP'], {'path': values['RUN_DIR'] + '/example'}])
        self.assertIs(result['enabled'], True)
        self.assertEqual(result['count'], 3)
        self.assertIsNone(result['empty'])

    def test_generic_config_substitution_rejects_unknown_placeholders(self):
        render = runpy.run_path(str(RUN))['render_config']
        source = self.root / 'template.json'
        source.write_text('{"value": "@MISSPELLED@"}')
        with self.assertRaisesRegex(ValueError, 'MISSPELLED'):
            render(source, {'SERVER_IP': '192.0.2.2'})

    def test_non_passthrough_profile_uses_generic_substitution(self):
        source_root = self.root / 'source'
        gtest_dir = source_root / 'tests/gtest'
        config_dir = gtest_dir / 'config'
        config_dir.mkdir(parents=True)
        runner = gtest_dir / 'run'
        shutil.copy2(RUN, runner)
        (config_dir / 'default.json').write_text(json.dumps({'values': [
            '@CLIENT_IP@', '@SERVER_IP@', '@PROFILE@', '@RUN_DIR@', '@SOURCE_ROOT@']}))
        result = subprocess.run(
            [str(runner), '--profiles', 'extra', '--addr', '192.0.2.1,192.0.2.2',
             '--gtest-bin', str(self.app), '--xlio-lib', str(self.lib)], cwd=self.root,
            env=dict(os.environ, RECORD=str(self.record)), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr)
        call, = self.calls()
        self.assertEqual(json.loads(call['config'])['values'], [
            '192.0.2.1', '192.0.2.2', 'extra', call['cwd'], str(source_root)])

    def test_failure_does_not_skip_second_profile(self):
        result = self.invoke('--addr=192.0.2.1,192.0.2.2', FAIL_R2C='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls()), 2)
        self.assertIn('r2c-full (rc=7)', result.stdout)

    def test_space_separated_options(self):
        result = self.invoke('--profiles', 'r2c-full,wtbp', '--addr', '192.0.2.1,192.0.2.2',
                             '--timeout', '0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls()), 2)
        for call in self.calls():
            self.assertIn('--addr=192.0.2.1,192.0.2.2', call['args'])

    def test_space_separated_ipv6_and_paths(self):
        result = self.invoke('--profiles', 'r2c-default', '--addr', '2001:db8::1,2001:db8::2',
                             '--gtest-bin', str(self.app), '--xlio-lib', str(self.lib),
                             '--output-dir', str(self.root / 'space separated results'))
        self.assertEqual(result.returncode, 0, result.stderr)
        call, = self.calls()
        self.assertIn('--addr=2001:db8::1,2001:db8::2', call['args'])
        self.assertNotIn('-r', call['args'])
        self.assertEqual(Path(call['cwd']).name, 'r2c-default')
        self.assertEqual(Path(call['cwd']).parent.parent, self.root / 'space separated results')

    def test_filter_overrides_every_profile(self):
        result = self.invoke('--addr', '192.0.2.1,192.0.2.2', '--filter', 'tcp_sockopt.*')
        self.assertEqual(result.returncode, 0, result.stderr)
        first, second = self.calls()
        for call in (first, second):
            filters = [arg for arg in call['args'] if arg.startswith('--gtest_filter=')]
            self.assertEqual(filters, ['--gtest_filter=tcp_sockopt.*'])
        self.assertEqual(first['env']['XLIO_USE_NEW_CONFIG'], '1')
        self.assertEqual(json.loads(second['config'])['performance']['polling']['iomux']['poll_usec'], 10)

    def test_equals_filter_preserves_negative_expression(self):
        result = self.invoke('--addr=192.0.2.1,192.0.2.2', '--filter=-tcp_sockopt.*')
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.calls():
            self.assertIn('--gtest_filter=-tcp_sockopt.*', call['args'])

    def test_timeout_value_cannot_become_a_timeout_option(self):
        result = self.invoke('--addr=192.0.2.1,192.0.2.2', '--timeout=--help')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record.exists())

    def test_invalid_output_root_does_not_start_tests(self):
        (self.root / 'results').write_text('blocks the output root')
        result = self.invoke('--addr=192.0.2.1,192.0.2.2')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record.exists())

    def test_repeated_runs_preserve_separate_timestamped_products(self):
        result = self.invoke('--profiles=r2c-full', '--addr=192.0.2.1,192.0.2.2')
        self.assertEqual(result.returncode, 0, result.stderr)
        first = Path(self.calls()[0]['cwd']).parent
        self.assertEqual(first.parent, self.root / 'results')
        self.assertRegex(first.name, r'^\d{8}-\d{6}\.\d{6}Z-')
        xml = first / 'test-basic.xml'
        self.assertEqual(xml.read_text(), PASS_XML)
        (first / 'r2c-full/suite.tap').write_text('preserve first run')
        result = self.invoke('--profiles=r2c-full', '--addr=192.0.2.1,192.0.2.2')
        self.assertEqual(result.returncode, 0, result.stderr)
        second = Path(self.calls()[1]['cwd']).parent
        self.assertNotEqual(first, second)
        self.assertEqual((first / 'r2c-full/suite.tap').read_text(), 'preserve first run')
        for directory in (first, second):
            self.assertEqual((directory / 'test-basic.xml').read_text(), PASS_XML)
            log = (directory / 'r2c-full/gtest.log').read_text()
            self.assertIn('test stdout', log)
            self.assertIn('test stderr', log)
            self.assertIn('--gtest_filter=', (directory / 'r2c-full/command.txt').read_text())
            self.assertIn('Profile r2c-full: 1 passed', (directory / 'summary.txt').read_text())

    def test_default_results_root(self):
        result = subprocess.run(
            [str(RUN), '--gtest-bin', str(self.app), '--xlio-lib', str(self.lib),
             '--addr', '192.0.2.1,192.0.2.2'], cwd=self.root,
            env=dict(os.environ, RECORD=str(self.record)), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        directory = Path(calls[0]['cwd']).parent
        self.assertEqual(directory.parent, self.root / 'gtest-results')
        self.assertEqual(Path(calls[1]['cwd']).parent, directory)
        self.assertEqual({path.name for path in (self.root / 'gtest-results').iterdir()},
                         {directory.name})

    def test_per_profile_summary_and_failed_test_names(self):
        xml = '''<testsuites><testsuite name="socket">
          <testcase classname="socket" name="ok" status="run"/>
          <testcase classname="socket" name="broken" status="run">
            <failure message="one"/><failure message="two"/>
          </testcase>
          <testcase classname="socket" name="unsupported" status="run"><skipped/></testcase>
          <testcase classname="socket" name="DISABLED_test" status="notrun"/>
        </testsuite></testsuites>'''
        result = self.invoke('--addr=192.0.2.1,192.0.2.2', TEST_XML=xml)
        self.assertNotEqual(result.returncode, 0)
        for profile in ('r2c-full', 'wtbp'):
            self.assertIn('Profile ' + profile + ': 1 passed, 1 failed, 1 skipped, 1 disabled', result.stdout)
        self.assertEqual(result.stdout.count('    FAILED: socket.broken'), 2)

    def test_enabled_disabled_test_is_counted_by_its_result(self):
        xml = '''<testsuites><testsuite name="suite">
          <testcase classname="suite" name="DISABLED_ok" status="run"/>
          <testcase classname="suite" name="DISABLED_skipped" status="run"><skipped/></testcase>
          <testcase classname="suite" name="DISABLED_failed" status="run"><failure/></testcase>
        </testsuite></testsuites>'''
        result = self.invoke('--profiles', 'r2c-full', '--addr', '192.0.2.1,192.0.2.2', TEST_XML=xml)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Profile r2c-full: 1 passed, 1 failed, 1 skipped, 0 disabled', result.stdout)

    def test_summary_repeats_each_profiles_command(self):
        result = self.invoke('--addr', '192.0.2.1,192.0.2.2', '--filter', 'socket.*')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Test summary:', result.stdout)
        summary = result.stdout.split('Test summary:', 1)[1]
        for profile in ('r2c-full', 'wtbp'):
            prefix = '[' + profile + '] '
            command = next(line[len(prefix):] for line in result.stdout.splitlines()
                           if line.startswith(prefix))
            self.assertIn('    Command: ' + command, summary)
            call = next(call for call in self.calls() if Path(call['cwd']).name == profile)
            self.assertIn(call['cwd'], summary)

    def test_missing_or_invalid_report_is_incomplete(self):
        for env in ({'NO_TEST_XML': '1'}, {'TEST_XML': '<broken'}, {'TEST_XML': '<unrelated/>'}):
            with self.subTest(env=env):
                result = self.invoke('--addr=192.0.2.1,192.0.2.2', **env)
                self.assertNotEqual(result.returncode, 0)
                for profile in ('r2c-full', 'wtbp'):
                    self.assertIn('Profile ' + profile + ': incomplete', result.stdout)

    def test_all_profiles_and_passthrough_templates(self):
        profiles = runpy.run_path(str(RUN))['PROFILES']
        result = self.invoke('--profiles=' + ','.join(profiles),
                             '--addr=192.0.2.1,192.0.2.2')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 20)
        outputs = [next(a for a in c['args'] if a.startswith('--gtest_output=')) for c in calls]
        self.assertEqual(len(set(outputs)), 20)
        self.assertTrue(any(o.endswith('/test-basic.xml') for o in outputs))
        self.assertTrue(any(o.endswith('/test-worker-threads-bounded-poll-not-pow2.xml')
                            for o in outputs))
        configs = [json.loads(call['config']) for call in calls]
        worker = [config['performance'] for config in configs
                  if 'polling' in config.get('performance', {})
                  and 'iomux' in config['performance']['polling']
                  and config['performance'].get('threading', {}).get('worker_threads')]
        self.assertEqual(len(worker), 9)
        self.assertEqual({config['polling']['iomux']['poll_usec'] for config in worker}, {-1, 0, 10})
        self.assertEqual({config['threading']['worker_threads'] for config in worker}, {1, 2, 3})
        rules = [config['acceleration_control']['rules'][0]['actions'] for config in configs
                 if config.get('acceleration_control', {}).get('rules', [{}])[0].get('name') == '*']
        self.assertEqual(rules, [['use os tcp_client 192.0.2.2:*:*:*',
                                 'use os tcp_server 192.0.2.2:*']] * 2)
        delegated = [config for config in configs
                     if config.get('performance', {}).get('threading', {}).get(
                         'internal_handler', {}).get('behavior') == 'delegate']
        self.assertEqual(len(delegated), 1)
        for config in delegated:
            self.assertEqual(config['performance']['threading']['internal_handler']['behavior'], 'delegate')
            self.assertTrue(config['performance']['polling']['rx_poll_on_tx_tcp'])
            self.assertTrue(config['network']['protocols']['tcp']['linger_0'])
        self.assertTrue(any(config.get('network', {}).get('protocols', {}).get('tcp', {}) == {
            'congestion_control': 1, 'nodelay': {'enable': True}} for config in configs))
        for call in calls:
            knobs = {name for name in call['env'] if name.startswith('XLIO_')}
            inherited_knobs = {name for name in os.environ if name.startswith('XLIO_')}
            self.assertLessEqual(knobs - inherited_knobs,
                                 {'XLIO_USE_NEW_CONFIG', 'XLIO_CONFIG_FILE',
                                  'XLIO_GTEST_EXPECT_RTO_MSEC'})
            self.assertEqual(call['env']['XLIO_USE_NEW_CONFIG'], '1')

    def test_dry_run_writes_nothing(self):
        result = self.invoke('--dry-run', '--addr=192.0.2.1,192.0.2.2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.record.exists())
        self.assertFalse((self.root / 'results').exists())

    def test_invalid_requests_do_not_start_tests(self):
        for args in [[], ['--profiles=bogus'], ['--addr=,'],
                     ['--profiles=r2c-full,extra-ipv6', '--addr=192.0.2.1,192.0.2.2'],
                     ['--addr=192.0.2.1,192.0.2.2', '--', '--gtest_filter=*']]:
            with self.subTest(args=args):
                self.assertNotEqual(self.invoke(*args).returncode, 0)
                self.assertFalse(self.record.exists())



if __name__ == '__main__':
    unittest.main()
