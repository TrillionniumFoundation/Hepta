"""Execute current Core CI shell boundaries using explicit non-native fixtures.

These are workflow failure-propagation controls, not native qualification.
Removed high-level/migration workflow test IDs are recorded as retired, not passed.
"""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/hia-core.yml'


def step(name):
    source = WORKFLOW.read_text().splitlines()
    start, = (i for i, line in enumerate(source) if line == '      - name: ' + name)
    end = next((i for i in range(start + 1, len(source)) if source[i].startswith('      - ')), len(source))
    return source[start:end]


def script(name):
    lines = step(name)
    begin = lines.index('        run: |') + 1
    end = next((i for i in range(begin, len(lines)) if lines[i] and not lines[i].startswith('          ')), len(lines))
    return '\n'.join(line[10:] for line in lines[begin:end]) + '\n'


class CoreWorkflowContractTests(unittest.TestCase):
    def test_actual_source_generator_shell_refuses_mutation_and_first_failed_generator(self):
        command = script('Regenerate actual HIA sources')
        components = command.split('for component in ', 1)[1].split('; do', 1)[0].split()
        for mode, expected in [('clean', 0), ('mutation', 1), ('failure', 7)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='hia-ci-shell-') as d:
                root = Path(d)
                (root / 'tools').mkdir()
                (root / 'marker').write_text('committed bytes')
                for i, name in enumerate(components):
                    code = ''
                    if i == 0 and mode == 'mutation':
                        code = "from pathlib import Path\nPath('marker').write_text('changed bytes')\n"
                    if i == 0 and mode == 'failure':
                        code = 'raise SystemExit(7)\n'
                    (root / ('tools/generate_hia_' + name + '.py')).write_text(code)
                def git(*args):
                    subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True, timeout=10)
                git('init', '--quiet')
                for key, value in [('user.name', 'Core CI fixture'), ('user.email', 'fixture@example.invalid'),
                                   ('commit.gpgsign', 'false'), ('core.hooksPath', '/dev/null')]:
                    git('config', key, value)
                git('add', '.')
                git('commit', '--quiet', '-m', 'explicit workflow fixture')
                env = dict(os.environ, PATH=str(Path(sys.executable).parent) + ':/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1')
                result = subprocess.run(['bash', '--noprofile', '--norc', '-c', command], cwd=root,
                                        env=env, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_actual_native_ci_runner_rejects_failed_skipped_and_expected_failure_outcomes(self):
        source = script('Native applications and actual Core memory controls')
        code = source.split("<<'PYTEST'\n", 1)[1].rsplit('\nPYTEST', 1)[0]
        for success, skips, expected_failures, expected in [(True, [], [], 0), (False, [], [], 1),
                                                         (True, ['fixture skip'], [], 1),
                                                         (True, [], ['fixture expected failure'], 1)]:
            with self.subTest(success=success, skips=skips, expected_failures=expected_failures):
                fixture = ('import sys,types\n'
                           'result=types.SimpleNamespace(wasSuccessful=lambda: ' + repr(success) +
                           ',skipped=' + repr(skips) + ',expectedFailures=' + repr(expected_failures) + ')\n'
                           'sys.modules["unittest"]=types.SimpleNamespace('\
                           'TextTestRunner=lambda **kwargs:types.SimpleNamespace(run=lambda suite:result),'\
                           'defaultTestLoader=types.SimpleNamespace(loadTestsFromNames=lambda names:names))\n')
                result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', fixture + code],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_actual_native_ci_retains_original_applications_and_all_core_region_controls(self):
        source = script('Native applications and actual Core memory controls')
        code = source.split("<<'PYTEST'\n", 1)[1].rsplit('\nPYTEST', 1)[0]
        node = next(n for n in ast.parse(code).body if isinstance(n, ast.Assign))
        names = ast.literal_eval(node.value)
        required = {'tests.test_hia_agent_stdio', 'tests.test_hia_core_json_cli', 'tests.test_hia_elf_linker',
                    'tests.test_hia_agent_identity_native', 'tests.test_hia_agent_installed_resources',
                    'tests.test_hia_agent_slice_native',
                    'tests.test_hia_agent_snapshot_native', 'tests.test_hia_agent_snapshot_json_native'}
        required.update('tests.' + p.stem for p in (ROOT / 'tests').glob('test_hia_host_region*.py'))
        required.update('tests.test_hia_native_' + suffix for suffix in (
            'child_limits', 'seccomp', 'side_effects', 'cleanup',
            'mapping_identity', 'startup_isolation'))
        required.add('tests.test_hia_selfhost_emitter_words')
        required.add('tests.test_hia_json_preflight_native')
        required.add('tests.test_hia_agent_data_json_native')
        required.add('tests.test_hia_agent_binary64_native')
        required.add('tests.test_hia_agent_binary64_format_native')
        self.assertEqual(set(names), required)
        self.assertEqual(len(names), len(required))

    def test_journal_ci_requires_complete_nonempty_execution_and_zero_anomalies(self):
        source = script('Native request journal decisions and actual SQL crash controls')
        code = source.split("<<'PYJOURNAL'\n", 1)[1].rsplit('\nPYJOURNAL', 1)[0]
        clean = dict(testsRun=2, errors=[], failures=[], skipped=[],
                     expectedFailures=[], unexpectedSuccesses=[])
        cases = [('complete', 2, clean, True, 0),
                 ('empty', 0, dict(clean, testsRun=0), True, 1),
                 ('incomplete', 2, dict(clean, testsRun=1), True, 1),
                 ('unsuccessful', 2, clean, False, 1)]
        cases.extend((field, 2, dict(clean, **{field: ['observed anomaly']}), True, 1)
                     for field in ('errors', 'failures', 'skipped',
                                   'expectedFailures', 'unexpectedSuccesses'))
        for name, expected_count, fields, success, expected_status in cases:
            with self.subTest(name=name):
                fixture = ('import sys,types\n'
                           'result=types.SimpleNamespace(**' + repr(fields) +
                           ',wasSuccessful=lambda: ' + repr(success) + ')\n'
                           'suite=types.SimpleNamespace(countTestCases=lambda: ' + repr(expected_count) + ')\n'
                           'sys.modules["unittest"]=types.SimpleNamespace('
                           'TextTestRunner=lambda **kwargs:types.SimpleNamespace(run=lambda suite:result),'
                           'defaultTestLoader=types.SimpleNamespace(loadTestsFromName=lambda name:suite))\n')
                child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', fixture + code],
                                       capture_output=True, timeout=10)
                self.assertEqual(child.returncode, expected_status, child.stdout + child.stderr)

    def test_complete_nominal_ci_retains_every_native_owner_and_rejects_incomplete_runs(self):
        name = 'Native complete nominal types helpers constructor functions and outer lowering'
        code = script(name).split("<<'PYTYPES'\n", 1)[1].rsplit('\nPYTYPES', 1)[0]
        assignment = next(n for n in ast.parse(code).body if isinstance(n, ast.Assign))
        names = ast.literal_eval(assignment.value.args[0])
        functions = {
            'tests.test_hia_composite_function_tokens',
            'tests.test_hia_composite_function_admission',
            'tests.test_hia_composite_function_protocol_audit',
            'tests.test_hia_composite_function_terms_native',
            'tests.test_hia_composite_functions_native',
            'tests.test_hia_composite_public_lifecycle',
        }
        elaboration = {
            'tests.test_hia_composite_constructor_native',
            'tests.test_hia_composite_constructor_integration',
            'tests.test_hia_composite_outer_native',
            'tests.test_hia_composite_outer_integration',
            'tests.test_hia_composite_nominal_lifecycle',
        }
        required = functions | elaboration | {
            'tests.test_hia_composite_types_native', 'tests.test_hia_composite_origins_native',
            'tests.test_hia_composite_signatures_native', 'tests.test_hia_task_helpers_native',
            'tests.test_hia_composite_native_composition'}
        self.assertEqual(set(names), required)
        self.assertEqual(len(names), len(required))
        from tools.hia_selfhost_contract import validate_contract
        contract = validate_contract()
        owner = contract['composite_function_lowering']
        self.assertEqual(set(owner['required_test_modules']), functions)
        self.assertEqual(set(contract['composite_complete_elaboration']['required_test_modules']), required)
        for component in ('COMPOSITE_TYPES', 'TASK_HELPERS', 'COMPOSITE_FUNCTIONS',
                          'COMPOSITE_CONSTRUCTOR', 'COMPOSITE_OUTER'):
            self.assertIn('          HEPTA_HIA_' + component + '_COLD_REPORT: ${{ runner.temp }}/hia-cold.json',
                          step(name))
        self.assertIn('          HEPTA_HIA_COMPOSITE_FIXTURE_EVIDENCE: ${{ runner.temp }}/hia-nominal-fixture',
                      step(name))
        source = script('Core source and independent reference controls')
        for selected in (
                'tests.test_hia_composite_functions_native.FunctionSourceTests',
                'tests.test_hia_composite_function_tokens.TokenCodecTests',
                'tests.test_hia_composite_function_protocol_audit.FunctionTokenProtocolAuditTests',
                'tests.test_hia_composite_constructor_source.ConstructorSourceTests',
                'tests.test_hia_composite_constructor_native.ConstructorFrameTests',
                'tests.test_hia_composite_outer_source.OuterSourceTests',
                'tests.test_hia_composite_outer_native.OuterFrameTests'):
            self.assertIn(repr(selected), source)
        for selected in functions | elaboration:
            self.assertNotIn(repr(selected), source)
        clean = dict(testsRun=2, errors=[], failures=[], skipped=[],
                     expectedFailures=[], unexpectedSuccesses=[])
        cases = [('complete', 2, clean, True, 0),
                 ('empty', 0, dict(clean, testsRun=0), True, 1),
                 ('incomplete', 2, dict(clean, testsRun=1), True, 1),
                 ('unsuccessful', 2, clean, False, 1)]
        cases.extend((field, 2, dict(clean, **{field: ['observed anomaly']}), True, 1)
                     for field in ('errors', 'failures', 'skipped',
                                   'expectedFailures', 'unexpectedSuccesses'))
        for case, expected_count, fields, successful, status in cases:
            fixture = ('import sys,types\n'
                'result=types.SimpleNamespace(**' + repr(fields) +
                ',wasSuccessful=lambda: ' + repr(successful) + ')\n'
                'suite=types.SimpleNamespace(countTestCases=lambda: ' + repr(expected_count) + ')\n'
                'sys.modules["unittest"]=types.SimpleNamespace('
                'TextTestRunner=lambda **kwargs:types.SimpleNamespace(run=lambda suite:result),'
                'defaultTestLoader=types.SimpleNamespace(loadTestsFromNames=lambda names:suite))\n')
            run = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', fixture + code],
                                 capture_output=True, timeout=10)
            self.assertEqual(run.returncode, status, (case, run.stdout, run.stderr))

    def test_actual_failure_archive_runs_after_cold_failure_without_continuing_test_steps(self):
        lines = step('Preserve actual cold failure and stage evidence')
        self.assertIn('        if: always()', lines)
        self.assertIn('          include-hidden-files: true', lines)
        self.assertIn('          if-no-files-found: error', lines)
        source = WORKFLOW.read_text()
        self.assertNotIn('continue-on-error', source)
        self.assertIn('--output "$RUNNER_TEMP/hia-cold.json"', source)
        for path in ['hia-cold.json', 'hia-cold.cold/', 'hia-language.json', 'hia-language.assertions.json',
                     'hia-language.evidence/', 'hia-nominal-fixture/',
                     'hia-module-projects/', 'hia-journal-callers.json',
                     'hia-native-components.json', 'hia-json-wire-fixture/', 'hia-json-wire-entry-fixture/',
                     'hia-worker-report-fixture/', 'hia-machine-plan-fixture/',
                     'hia-machine-plan-callers.json', 'hia-machine-plan-callers-evidence/',
                     'hia-json-wire-callers.json', 'hia-json-wire-callers-evidence/']:
            self.assertIn('            ${{ runner.temp }}/' + path, lines)
        self.assertLess(source.index('tools/replay_hia_selfhost_cold.py'),
                        source.index('      - name: Preserve actual cold failure and stage evidence'))

    def test_native_component_step_requires_original_loaded_ids_and_zero_anomalies(self):
        name = 'Native graph wire worker machine-plan and linked observer'
        code = script(name).split("<<'PYNATIVEOWNERS'\n", 1)[1].rsplit('\nPYNATIVEOWNERS', 1)[0]
        assignment = next(n for n in ast.parse(code).body if isinstance(n, ast.Assign))
        self.assertEqual(ast.literal_eval(assignment.value.args[0]), (
            'tests.test_hia_json_wire_native', 'tests.test_hia_json_wire_entry',
            'tests.test_hia_worker_report_native',
            'tests.test_hia_machine_plan_native', 'tests.test_hia_selfhost_linked_observer'))
        for component in ('JSON_WIRE', 'WORKER_REPORT', 'MACHINE_PLAN'):
            self.assertIn('          HEPTA_HIA_' + component + '_COLD_REPORT: ${{ runner.temp }}/hia-cold.json',
                          step(name))
        fixture = '''import unittest
class Fixture(unittest.TestCase):
    def test_first(self):
        if mode in ('failure', 'expected_failure'):
            self.fail('explicit workflow failure fixture')
        if mode == 'error':
            raise RuntimeError('explicit workflow error fixture')
        if mode == 'skipped':
            self.skipTest('explicit workflow skip fixture')
    def test_second(self):
        pass
if mode in ('expected_failure', 'unexpected_success'):
    Fixture.test_first = unittest.expectedFailure(Fixture.test_first)
def load(names):
    if mode == 'empty':
        return unittest.TestSuite()
    return unittest.TestSuite((Fixture('test_first'), Fixture('test_second')))
unittest.defaultTestLoader.loadTestsFromNames = load
original_runner = unittest.TextTestRunner
class Runner(original_runner):
    def run(self, suite):
        if mode == 'partial':
            suite._tests = suite._tests[:1]
        elif mode == 'reordered':
            suite._tests.reverse()
        elif mode == 'duplicate':
            suite._tests = [suite._tests[0], suite._tests[0]]
        return super().run(suite)
unittest.TextTestRunner = Runner
'''
        modes = ('complete', 'empty', 'partial', 'reordered', 'duplicate',
                 'failure', 'error', 'skipped', 'expected_failure', 'unexpected_success')
        with tempfile.TemporaryDirectory(prefix='hia-native-ci-controls-') as temporary:
            for mode in modes:
                with self.subTest(mode=mode):
                    report = Path(temporary) / (mode + '.json')
                    env = dict(os.environ, HEPTA_HIA_NATIVE_COMPONENT_REPORT=str(report))
                    child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c',
                                            'mode=' + repr(mode) + '\n' + fixture + code],
                                           env=env, capture_output=True, timeout=10)
                    self.assertEqual(child.returncode, 0 if mode == 'complete' else 1,
                                     child.stdout + child.stderr)
                    observed = json.loads(report.read_bytes())
                    self.assertEqual(observed['status'], 'PASS' if mode == 'complete' else 'FAIL_OR_INCOMPLETE')
                    self.assertFalse(observed['default_activation_or_whole_stack_claimed'])


if __name__ == '__main__':
    unittest.main()
