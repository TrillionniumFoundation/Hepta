"""Small real-Git/source-custody controls; no product or native execution."""
from pathlib import Path
import ast
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('emission_ci_driver', HERE / 'run_emission_development.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class EmissionCIDriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hia-emission-ci-git-')
        self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.path = self.root / 'sample.txt'
        self.path.write_bytes(b'original exact bytes\n')
        self.path.chmod(0o644)
        subprocess.run(['git', '-C', str(self.root), 'add', '--', 'sample.txt'], check=True)
        tree = subprocess.check_output(['git', '-C', str(self.root), 'write-tree']).decode().strip()
        self.records = subprocess.check_output(['git', '-C', str(self.root), 'ls-tree', '-r', '-z', tree])

    def tearDown(self):
        self.temp.cleanup()

    def test_real_git_snapshot_accepts_exact_bytes_and_modes(self):
        rows = driver.admit_git_snapshot(self.root, driver.files(self.root), self.records)
        self.assertEqual(set(rows), {'sample.txt'})

    def test_real_git_byte_drift_refuses(self):
        self.path.write_bytes(b'different exact bytes\n')
        with self.assertRaisesRegex(ValueError, 'bytes or mode'):
            driver.admit_git_snapshot(self.root, driver.files(self.root), self.records)

    def test_real_git_executable_mode_drift_refuses(self):
        self.path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'bytes or mode'):
            driver.admit_git_snapshot(self.root, driver.files(self.root), self.records)

    def test_untracked_file_cannot_hide_from_complete_inventory(self):
        (self.root / 'new.txt').write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'inventories differ'):
            driver.admit_git_snapshot(self.root, driver.files(self.root), self.records)

    def test_symlink_source_is_not_admitted_as_regular_bytes(self):
        original = self.root / 'original.txt'
        self.path.rename(original)
        self.path.symlink_to(original.name)
        with self.assertRaisesRegex(ValueError, 'regular source file'):
            driver.files(self.root)

    def test_all_frozen_input_packets_have_exact_identities(self):
        for name, expected in [('emission-owner.json', driver.OWNER_SHA),
                               ('retained-compiler.json', driver.COMPILER_PACKET_SHA),
                               ('original-agent-suite.json', driver.ORIGINAL_SUITE_SHA),
                               ('original-component-45.json', driver.ORIGINAL_COMPONENT_SHA),
                               ('lifetime-controls-7.json', driver.LIFETIME_CONTROLS_SHA)]:
            with self.subTest(name=name):
                self.assertEqual(driver.digest((HERE / name).read_bytes()), expected)
        owner=json.loads((HERE / 'emission-owner.json').read_bytes())
        self.assertEqual(len(owner['files']),19)
        self.assertEqual(len(owner['new_paths']),14)
        self.assertEqual(len(owner['shared_paths']),5)
        for name,row in owner['files'].items():
            raw=row['text'].encode();self.assertEqual(len(raw),row['bytes'],name)
            self.assertEqual(driver.digest(raw),row['sha256'],name)
        suite=json.loads((HERE / 'original-agent-suite.json').read_bytes())
        ids=[test for name in suite['modules'] for test in suite['files'][name.replace('.', '/')+'.py']['expected_ids']]
        self.assertEqual(len(ids),48);self.assertEqual(len(set(ids)),48)
        original=json.loads((HERE / 'original-component-45.json').read_bytes())
        self.assertEqual(original['tests_run'],45)
        self.assertEqual(original['loaded'],original['executed'])

    def test_original_groups_and_new_lifetimes_keep_separate_limits_and_continue(self):
        tree=ast.parse((HERE/'run_emission_development.py').read_bytes())
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        selected=[]
        expected=[('component-45',240),('permanent-lifetimes-7',240),
                  ('generator-lifetimes-12',60),('named-local-lifetimes-16',60),
                  ('public-default-lifetimes-16',60),('original-agent-48',1800)]
        for n in ast.walk(main):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='command' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value in dict(expected):
                options={item.arg:ast.literal_eval(item.value) for item in n.keywords if item.arg in ('seconds','allow_failure')}
                self.assertIs(options['allow_failure'],True)
                selected.append((n.lineno,n.args[0].value,options['seconds']))
        self.assertEqual([(name,seconds) for _,name,seconds in sorted(selected)],expected)
        value=json.loads((HERE/'lifetime-controls-7.json').read_bytes())
        self.assertEqual(value['tests_run'],7)
        self.assertEqual(len(value['loaded']),7)
        self.assertEqual(len(set(value['loaded'])),7)
        self.assertIn('test_terminal_retirement_follows_last_cross_thread_traceback_reference',
                      [name.rsplit('.',1)[-1] for name in value['loaded']])

    def _actual_supervisor(self):
        tree = ast.parse((HERE / 'run_emission_development.py').read_bytes())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        command = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == 'command')
        out = self.root / 'observations'
        out.mkdir()
        report = {'commands': []}
        namespace = dict(vars(driver), report=report, out=out, root=self.root, env=os.environ.copy())
        # Execute the actual nested supervisor body, with only its original
        # closed-over output paths/environment supplied by this temporary scope.
        executable = ast.fix_missing_locations(ast.Module(body=[command], type_ignores=[]))
        exec(compile(executable, str(HERE / 'run_emission_development.py'), 'exec'), namespace)
        return namespace['command'], report, out

    def test_actual_allowed_timeout_is_killed_recorded_and_next_group_runs(self):
        command, report, out = self._actual_supervisor()
        command('original-limit', [sys.executable, '-c', 'import time; time.sleep(60)'],
                seconds=0.05, allow_failure=True)
        command('next-group', [sys.executable, '-c', 'print("next actual group")'], seconds=10)
        timed, following = report['commands']
        self.assertIs(timed['timed_out'], True)
        self.assertLess(timed['returncode'], 0)
        self.assertEqual(timed['timeout_seconds'], 0.05)
        with self.assertRaises(ProcessLookupError):
            os.kill(timed['pid'], 0)
        self.assertEqual(following['returncode'], 0)
        self.assertIs(following['timed_out'], False)
        self.assertEqual((out / 'next-group.stdout.log').read_bytes(), b'next actual group\n')
        self.assertTrue(any(row.get('returncode') != 0 or row.get('timed_out') is not False
                            for row in report['commands']))

    def test_actual_strict_timeout_keeps_original_exception_and_terminal(self):
        command, report, out = self._actual_supervisor()
        with self.assertRaises(subprocess.TimeoutExpired):
            command('strict-limit', [sys.executable, '-c', 'import time; time.sleep(60)'], seconds=0.05)
        row = report['commands'][0]
        self.assertIs(row['timed_out'], True)
        self.assertLess(row['returncode'], 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(row['pid'], 0)
        self.assertEqual(json.loads((out / 'strict-limit.terminal.json').read_bytes()), row)


if __name__ == '__main__':
    unittest.main(verbosity=2)
