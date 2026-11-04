"""Real CLI, real adapter and frozen policy controls; no production injection knobs."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import pipeline
from hepta.ast import HeptaError
from experiments.frontend_adapter.adapter import FrontendRequest
from experiments.policy_failures.owner import Policy, VERSION
from . import cli

ROOT = Path(__file__).resolve().parents[2]
PREFIX = ['check', '--frontend-only', '--policy', VERSION]


class CLIControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.entry = Path(self.tmp.name) / 'main.hepta'
        self.entry.write_text('fn main()->Unit effects {} {}')

    def run_cli(self, args):
        result = subprocess.run([sys.executable, '-B', '-m', 'experiments.frontend_cli', *args],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.stderr, '')
        self.assertTrue(result.stdout.endswith('\n'))
        self.assertEqual(result.stdout.count('\n'), 1)
        return json.loads(result.stdout), result.returncode

    def test_success_subprocess_full_report(self):
        response, code = self.run_cli(PREFIX + [str(self.entry)])
        self.assertEqual(code, 0)
        self.assertEqual(response['report'], pipeline.analyze_project(self.entry, native=False).report)
        self.assertFalse(response['native_qualified'])

    def test_checker_diagnostic_subprocess(self):
        self.entry.write_text('fn main()->bool effects {} { return 1; }')
        response, code = self.run_cli(PREFIX + [str(self.entry)])
        self.assertEqual(code, 1)
        self.assertIsNone(response['first_failure'])
        self.assertEqual(response['report'], pipeline.analyze_project(self.entry, native=False).report)

    def test_loader_diagnostic_subprocess(self):
        self.entry.write_text('invalid !')
        response, code = self.run_cli(PREFIX + [str(self.entry)])
        self.assertEqual(code, 1)
        self.assertIsNone(response['report'])
        self.assertEqual(response['first_failure']['category'], 'diagnostic')
        self.assertNotIn('compiler_sha256', response)

    def test_missing_input_subprocess(self):
        response, code = self.run_cli(PREFIX + [str(self.entry) + '.missing'])
        self.assertNotEqual(code, 0)
        self.assertIsNone(response['report'])

    def test_help_no_owner(self):
        with patch.object(cli, 'FrontendRequest', side_effect=AssertionError('owner')):
            for argv in (['--help'], ['check', '--help']):
                response, code = cli.evaluate(argv)
                self.assertEqual((response['outcome'], code), ('help', 0))
                self.assertIsNone(response['report'])

    def test_argument_matrix_no_owner(self):
        invalid = [[], ['check'], ['check', '--frontend-only', str(self.entry)],
                   ['check', '--policy', VERSION, str(self.entry)],
                   PREFIX + [str(self.entry), 'extra'], PREFIX + ['--policy', VERSION, str(self.entry)],
                   PREFIX + ['--frontend-only', str(self.entry)],
                   PREFIX + ['--locked', '--locked', str(self.entry)],
                   PREFIX + ['@secret'], PREFIX + [''], ['check', '--front', str(self.entry)],
                   ['check', '--frontend-only', '--policy', 'future', str(self.entry)]]
        for command in ('build','run','emit','header','patch','import-c','check-assembly'):
            invalid.append([command, *PREFIX[1:], str(self.entry)])
        for flag in ('--native','--backend','--rustc','--target','--output','-o','--source-overrides',
                     '--limits','--json','--help','--locked=true','--policy='+VERSION):
            invalid.append(PREFIX + [flag, str(self.entry)])
        with patch.object(cli, 'FrontendRequest', side_effect=AssertionError('owner')):
            for argv in invalid:
                with self.subTest(argv=argv):
                    response, code = cli.evaluate(argv)
                    self.assertEqual(code, 2)
                    self.assertNotIn('secret', json.dumps(response))

    def test_raw_spelling_and_delimiter(self):
        source = './raw/../alias.hepta'
        self.assertEqual(cli.parse(PREFIX + [source]), (source, False))
        self.assertEqual(cli.parse(PREFIX + ['--', '-source']), ('-source', False))
        self.assertEqual(cli.parse(PREFIX + ['--', '@source']), ('@source', False))

    def test_frozen_policy_values_units(self):
        expected = json.loads(Path(__file__).with_name('policy_v1.json').read_text())
        policy = Policy()
        self.assertEqual(expected, {'version': policy.version, 'limits': dict(policy.limits), 'units': dict(policy.units)})
        self.assertEqual(len(expected['limits']), 33)

    def test_all_examples_full_parity(self):
        examples = sorted((ROOT / 'examples').rglob('*.hepta'))
        self.assertEqual(len(examples), 80)
        for entry in examples:
            with self.subTest(entry=entry.name):
                try:
                    expected = pipeline.analyze_project(entry, native=False).report
                except HeptaError as error:
                    response, code = cli.evaluate(PREFIX + [str(entry)])
                    self.assertEqual(code, 3 if response['first_failure']['category'] == 'io' else 1)
                    self.assertEqual(response['diagnostics'], [error.diagnostic.to_dict()])
                    self.assertIsNone(response['report'])
                else:
                    response, code = cli.evaluate(PREFIX + [str(entry)])
                    self.assertEqual(response['report'], expected)
                    self.assertEqual(code, 0 if expected['ok'] else 1)

    def test_budget_real_adapter(self):
        def factory(**kwargs):
            return FrontendRequest(policy=Policy(limits={'reads': 1}), **kwargs)
        with patch.object(cli, 'FrontendRequest', factory):
            response, code = cli.evaluate(PREFIX + [str(self.entry)])
        self.assertEqual(code, 3)
        self.assertEqual(response['first_failure']['category'], 'budget')
        self.assertIsNone(response['report'])

    def test_cancel_real_adapter(self):
        def factory(**kwargs):
            request = FrontendRequest(**kwargs)
            request.cancel()
            return request
        with patch.object(cli, 'FrontendRequest', factory):
            response, code = cli.evaluate(PREFIX + [str(self.entry)])
        self.assertEqual(code, 130)
        self.assertEqual(response['first_failure']['observed_reads'], 0)

    def test_final_source_change(self):
        request = None
        def checkpoint():
            if request.phase == 'after_analysis':
                self.entry.write_text('changed')
        def factory(**kwargs):
            nonlocal request
            request = FrontendRequest(checkpoint=checkpoint, **kwargs)
            return request
        with patch.object(cli, 'FrontendRequest', factory):
            response, code = cli.evaluate(PREFIX + [str(self.entry)])
        self.assertEqual(code, 1)
        self.assertEqual(response['report']['diagnostics'][-1]['code'], 'E_MODULE_RACE')

    def test_subprocess_no_native_or_project_artifacts(self):
        script = '''
import sys
from unittest.mock import patch
from experiments.frontend_cli.cli import main
from hepta import pipeline
with patch.object(pipeline, 'compile_rust', side_effect=AssertionError('native')), patch.object(pipeline, 'analyze_project', side_effect=AssertionError('legacy')), patch('subprocess.Popen', side_effect=AssertionError('process')):
    raise SystemExit(main(sys.argv[1:]))
'''
        before = set(Path(self.tmp.name).rglob('*'))
        result = subprocess.run([sys.executable, '-B', '-c', script, *PREFIX, str(self.entry)],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])
        self.assertEqual(before, set(Path(self.tmp.name).rglob('*')))

    def test_symlink_raw_alias_subprocess(self):
        alias = self.entry.with_name('alias.hepta')
        alias.symlink_to(self.entry)
        script = '''
import sys
from unittest.mock import patch
from experiments.frontend_cli import cli
from experiments.frontend_adapter.adapter import FrontendRequest
real = FrontendRequest.check
def check(self, entry, **kwargs):
    assert entry == sys.argv[-1]
    return real(self, entry, **kwargs)
with patch.object(FrontendRequest, 'check', check):
    raise SystemExit(cli.main(sys.argv[1:]))
'''
        result = subprocess.run([sys.executable, '-B', '-c', script, *PREFIX, str(alias)],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])

    def test_strict_ascii_json(self):
        output = io.StringIO()
        code = cli.main(['secret\udcff'], stdout=output)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())['error'], 'E_ARGUMENTS')

    def test_constructor_explicit_cancel_without_record(self):
        from experiments.policy_failures.owner import Cancelled
        with patch.object(cli, 'FrontendRequest', side_effect=Cancelled('private')):
            response, code = cli.evaluate(PREFIX + [str(self.entry)])
        self.assertEqual((response['outcome'], code), ('cancelled', 130))
        self.assertIsNone(response['first_failure'])

    def test_real_failure_subprocess_matrix(self):
        script = r"""
import sys
from unittest.mock import patch
from experiments.frontend_cli import cli
from experiments.frontend_adapter.adapter import FrontendRequest
from experiments.policy_failures.owner import Policy
from experiments.package_copy import owner as package
from hepta import pipeline
mode = sys.argv[1]
def factory(**kwargs):
    if mode == 'budget':
        return FrontendRequest(policy=Policy(limits={'reads': 1}), **kwargs)
    request = FrontendRequest(**kwargs)
    if mode == 'cancel':
        request.cancel()
    return request
with patch.object(cli, 'FrontendRequest', factory):
    if mode == 'runtime':
        with patch.object(package, '_SUPPORTED', False), patch.object(FrontendRequest, 'check', side_effect=AssertionError('input touched')):
            code = cli.main(sys.argv[2:])
    elif mode == 'exit':
        with patch.object(pipeline, 'analyze', side_effect=SystemExit(0)):
            code = cli.main(sys.argv[2:])
    else:
        code = cli.main(sys.argv[2:])
raise SystemExit(code)
"""
        for mode, expected, category in [('budget', 3, 'budget'), ('cancel', 130, 'cancelled'),
                                          ('runtime', 3, 'unsupported_runtime'), ('exit', 70, 'unexpected')]:
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, '-B', '-c', script, mode, *PREFIX, str(self.entry)],
                                        cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(result.stderr, '')
                response = json.loads(result.stdout)
                self.assertEqual(response['first_failure']['category'], category)
                self.assertIsNone(response['report'])
                if mode in ('runtime', 'cancel'):
                    self.assertEqual(response['first_failure']['observed_reads'], 0)

    def test_legacy_frontend_cli_unchanged(self):
        result = subprocess.run([sys.executable, '-B', '-m', 'hepta', 'check', '--frontend-only', str(self.entry)],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), pipeline.analyze_project(self.entry, native=False).report)

    def test_locked_subprocess_wiring(self):
        from hepta import packages
        response, code = self.run_cli(PREFIX + ['--locked', str(self.entry)])
        self.assertEqual(code, 1)
        self.assertEqual(response['diagnostics'][0]['code'], 'E_LOCK_CONTEXT')
        root = self.entry.parent
        (root / 'hepta.toml').write_text('[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        packages.write_lock(root)
        response, code = self.run_cli(PREFIX + ['--locked', str(self.entry)])
        self.assertEqual(code, 0)
        self.assertEqual(response['report'], pipeline.analyze_project(self.entry, native=False, locked=True).report)
        self.entry.write_text(self.entry.read_text() + '\n')
        with self.assertRaises(HeptaError) as expected:
            pipeline.analyze_project(self.entry, native=False, locked=True)
        response, code = self.run_cli(PREFIX + ['--locked', str(self.entry)])
        self.assertEqual(code, 1)
        self.assertEqual(response['diagnostics'], [expected.exception.diagnostic.to_dict()])
        response, code = self.run_cli(PREFIX + [str(self.entry)])
        self.assertEqual(code, 0)
        self.assertEqual(response['report'], pipeline.analyze_project(self.entry, native=False).report)


if __name__ == '__main__':
    unittest.main()
