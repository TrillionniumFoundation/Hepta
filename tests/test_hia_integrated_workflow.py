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

    def test_actual_native_ci_requires_complete_nonempty_execution_and_zero_anomalies(self):
        self._assert_complete_native_ci(
            'Native applications and actual Core memory controls', 'PYTEST')

    def test_actual_source_ci_requires_complete_nonempty_execution_and_zero_anomalies(self):
        self._assert_complete_native_ci('Core source and independent reference controls', 'PY')

    def test_worker_request_ci_requires_complete_nonempty_execution_and_zero_anomalies(self):
        self._assert_complete_native_ci(
            'Native worker request admission and ordinary request continuity', 'PYREQUEST')

    def test_release_install_ci_requires_complete_nonempty_execution_and_zero_anomalies(self):
        self._assert_complete_native_ci(
            'Native immutable release installation and recovery observations', 'PYINSTALL')

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
        required.add('tests.test_hia_program_selfhost.SelfhostBuildNativeTests')
        self.assertEqual(set(names), required)
        self.assertEqual(len(names), len(required))

    def test_journal_ci_requires_complete_nonempty_execution_and_zero_anomalies(self):
        self._assert_complete_native_ci(
            'Native request journal decisions and actual SQL crash controls', 'PYJOURNAL')

    def test_execution_budget_ci_requires_both_journals_and_zero_anomalies(self):
        name = 'Native execution budgets and both request-journal lifecycles'
        self._assert_complete_native_ci(name, 'PYBUDGET')
        self.assertIn("loadTestsFromName('tests.test_hia_execution_budget_native')", script(name))
        self.assertIn('          HEPTA_HIA_EXECUTION_BUDGET_COLD_REPORT: ${{ runner.temp }}/hia-cold.json',
                      step(name))
        self.assertIn('          HEPTA_HIA_EXECUTION_BUDGET_EVIDENCE: ${{ runner.temp }}/hia-execution-budget',
                      step(name))

    def test_retirement_ci_requires_complete_execution_and_zero_anomalies(self):
        name = 'Native retained retirement and real resource release controls'
        self._assert_complete_native_ci(name, 'PYRETIREMENT')
        self.assertIn("loadTestsFromName('tests.test_hia_retirement_state_native')", script(name))
        self.assertIn('          HEPTA_HIA_RETIREMENT_STATE_COLD_REPORT: ${{ runner.temp }}/hia-cold.json',
                      step(name))
        self.assertIn('          HEPTA_HIA_RETIREMENT_STATE_EVIDENCE: ${{ runner.temp }}/hia-retirement-state',
                      step(name))

    def _assert_complete_native_ci(self, name, marker):
        source = script(name)
        code = source.split("<<'" + marker + "'\n", 1)[1].rsplit('\n' + marker, 1)[0]
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
                           'defaultTestLoader=types.SimpleNamespace(loadTestsFromName=lambda name:suite,'
                           'loadTestsFromNames=lambda names:suite))\n')
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

    def test_worker_helper_ci_requires_cold_composition_and_zero_anomalies(self):
        name = 'Native worker pinned helper custody and journal composition'
        self._assert_complete_native_ci(name, 'PYHELPERS')
        self.assertIn("loadTestsFromName('tests.test_hia_worker_native_helpers')", script(name))
        for component in ('WORKER_HELPERS', 'WORKER_REQUEST', 'AGENT_JOURNAL', 'EXECUTION_BUDGET'):
            self.assertIn('          HEPTA_HIA_' + component + '_COLD_REPORT: ${{ runner.temp }}/hia-cold.json',
                          step(name))
        self.assertIn('tests.test_hia_worker_native_helpers.WorkerHelperSourceTests',
                      script('Core source and independent reference controls'))

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
                     'hia-module-projects/', 'hia-journal-callers.json']:
            self.assertIn('            ${{ runner.temp }}/' + path, lines)
        self.assertLess(source.index('tools/replay_hia_selfhost_cold.py'),
                        source.index('      - name: Preserve actual cold failure and stage evidence'))

    def test_candidate_budget_ci_requires_complete_bundle_composition_and_zero_anomalies(self):
        name = 'Native candidate budgets and pinned state owner composition'
        self._assert_complete_native_ci(name, 'PYCANDIDATE')
        self.assertIn("loadTestsFromName('tests.test_hia_candidate_budget_native')", script(name))
        self.assertIn('          HEPTA_HIA_CANDIDATE_BUDGET_COLD_REPORT: ${{ runner.temp }}/hia-cold.json',
                      step(name))
        self.assertIn('          HEPTA_HIA_CANDIDATE_BUDGET_EVIDENCE: ${{ runner.temp }}/hia-candidate-budget',
                      step(name))
        self.assertIn('tests.test_hia_candidate_budget_native.CandidateBudgetSourceTests',
                      script('Core source and independent reference controls'))


    def test_actual_native_ci_runner_rejects_failed_skipped_and_expected_failure_outcomes(self):
        source = script('Native applications and actual Core memory controls')
        code = source.split("<<'PYTEST'\n", 1)[1].rsplit('\nPYTEST', 1)[0]
        for success, skips, expected_failures, expected in [(True, [], [], 0), (False, [], [], 1),
                                                         (True, ['fixture skip'], [], 1),
                                                         (True, [], ['fixture expected failure'], 1)]:
            with self.subTest(success=success, skips=skips, expected_failures=expected_failures):
                fixture = ('import sys,types\n'
                           'result=types.SimpleNamespace(testsRun=2,errors=[],failures=[],unexpectedSuccesses=[],wasSuccessful=lambda: ' + repr(success) +
                           ',skipped=' + repr(skips) + ',expectedFailures=' + repr(expected_failures) + ')\n'
                           'suite=types.SimpleNamespace(countTestCases=lambda: 2)\n'
                           'sys.modules["unittest"]=types.SimpleNamespace('\
                           'TextTestRunner=lambda **kwargs:types.SimpleNamespace(run=lambda suite:result),'\
                           'defaultTestLoader=types.SimpleNamespace(loadTestsFromNames=lambda names:suite))\n')
                result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', fixture + code],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_worker_checker_and_ledger_groups_use_matching_cold_and_reject_failed_outcomes(self):
        groups = (
            ('Native structural budgets arbitrary precision and installed composition', 'PYSTATIC', {
                'tests.test_hia_static_budget_native', 'tests.test_hia_static_budget_integration',
                'tests.test_hia_native_bigints', 'tests.test_hia_heap_graphs_native',
                'tests.test_hia_native_binary_graph'}, ('STATIC_BUDGET',)),
            ('Native full Core execution and installed worker bindings', 'PYEXECUTION', {
                'tests.test_hia_program_execution_native', 'tests.test_hia_program_execution_scalars',
                'tests.test_hia_program_execution_integration'}, ('PROGRAM_EXECUTION',)),
            ('Native worker request admission and ordinary request continuity', 'PYREQUEST', {
                'tests.test_hia_worker_request_native', 'tests.test_hia_worker_request_review',
                'tests.test_hia_worker_native_helpers', 'tests.test_hia_checker_identity',
                'tests.test_hia_checker_identity_agent'}, ('WORKER_REQUEST', 'AGENT_IDENTITY')),
            ('Native durable execution budgets request journal and artifact namespace', 'PYJOURNAL', {
                'tests.test_hia_execution_budget_native', 'tests.test_hia_request_journal_native',
                'tests.test_hia_artifact_namespace_native', 'tests.test_hia_slot_ledger_continuation_native'},
                ('EXECUTION_BUDGET', 'REQUEST_JOURNAL', 'ARTIFACT_NAMESPACE', 'SLOT_LEDGER_CONTINUATION')),
        )
        for name, marker, required, selectors in groups:
            code = script(name).split("<<'" + marker + "'\n", 1)[1].rsplit('\n' + marker, 1)[0]
            assignment = next(node for node in ast.parse(code).body if isinstance(node, ast.Assign)
                              and any(isinstance(t, ast.Name) and t.id == 'suite' for t in node.targets))
            names = ast.literal_eval(assignment.value.args[0])
            self.assertEqual(set(names), required)
            self.assertEqual(len(names), len(required))
            lines = step(name)
            for family in selectors:
                self.assertIn('          HEPTA_HIA_' + family + '_COLD_REPORT: ${{ runner.temp }}/hia-cold.json', lines)
            for successful, skipped, expected, status in (
                    (True, [], [], 0), (False, [], [], 1),
                    (True, ['skip'], [], 1), (True, [], ['expected failure'], 1)):
                fixture = ('import sys,types\n'
                    'result=types.SimpleNamespace(testsRun=2,errors=[],failures=[],unexpectedSuccesses=[],wasSuccessful=lambda:' + repr(successful) +
                    ',skipped=' + repr(skipped) + ',expectedFailures=' + repr(expected) + ')\n'
                    'suite=types.SimpleNamespace(countTestCases=lambda: 2)\n'
                    'sys.modules["unittest"]=types.SimpleNamespace('
                    'TextTestRunner=lambda **kwargs:types.SimpleNamespace(run=lambda suite:result),'
                    'defaultTestLoader=types.SimpleNamespace(loadTestsFromNames=lambda names:suite))\n')
                child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', fixture + code],
                                       capture_output=True, timeout=10)
                self.assertEqual(child.returncode, status, child.stdout + child.stderr)
        self.assertIn('slot_ledger', script('Regenerate actual HIA sources').split('for component in ', 1)[1].split('; do', 1)[0].split())
        self.assertIn('program_execution', script('Regenerate actual HIA sources').split('for component in ', 1)[1].split('; do', 1)[0].split())
        self.assertIn('            ${{ runner.temp }}/hia-slot-ledger/',
                      step('Preserve actual cold failure and stage evidence'))

        self.assertIn('slot_ledger_continuation', script('Regenerate actual HIA sources').split('for component in ', 1)[1].split('; do', 1)[0].split())
        self.assertIn('            ${{ runner.temp }}/hia-continuation-family/hia-slot-ledger-continuation/',
                      step('Preserve actual cold failure and stage evidence'))

    def test_both_original_native_step_sequences_remain_in_order(self):
        native = WORKFLOW.read_text().split("  native:\n", 1)[1]
        actual = [line.strip()[2:] for line in native.splitlines()
                  if line.startswith("      - ")]
        expected_main = [
            "uses: actions/checkout@v4",
            "uses: actions/setup-python@v5",
            "name: Install qualified Clang 20 native execution prerequisites",
            "run: python -m pip install setuptools==78.1.1 wheel==0.46.3 z3-solver==4.15.4.0 jsonschema==4.26.0",
            "name: Prepare original locked Rust caller dependencies",
            "run: python -B tools/replay_hia_selfhost_cold.py --output \"$RUNNER_TEMP/hia-cold.json\"",
            "name: Original call graph and native convergence controls",
            "run: python -B tests/test_hia_selfhost_language_coverage.py --output \"$RUNNER_TEMP/hia-language.json\"",
            "name: Native applications and actual Core memory controls",
            "name: Native HIA multi-image scheduling and source-bound installed entry",
            "name: Five-family native in-process worker scheduling custody",
            "name: All original runtime callers with HIA-owned internal scheduling",
            "name: Original runtime callers through in-process HIA native scheduling",
            "name: Original no-child compiler scripts through four in-process HIA schedulers",
            "name: Native execution ledger policy and installed real runtime callers",
            "name: Actual original runtime callers with retained ledger policy forbidden",
            "name: Native ELF object writer and actual source-bound installed controls",
            "name: Actual original machine and Core callers with complete HIA ELF object control",
            "name: Actual original callers with native ELF byte wrapper Emitter and Function control together",
            "name: Native byte wrapper and actual source-bound installed controls",
            "name: Actual original machine and Core callers with complete HIA borrowed-byte control",
            "name: Actual original callers with native byte wrapper Emitter and Function control together",
            "name: Native Core emitter and actual source-bound installed controls",
            "name: Actual original machine and Core callers with complete HIA Emitter control",
            "name: Actual original callers with both native Emitter and Function control",
            "name: Native Core lowering and actual source-bound installed controls",
            "name: Actual original machine and Core callers with complete HIA Function control",
            "name: Native machine plan and actual source-bound installed controls",
            "name: Actual original callers with HIA machine plans",
            "name: Native machine encoding and actual source-bound installed controls",
            "name: Native machine state and actual source-bound installed controls",
            "name: Native machine instructions and actual source-bound installed controls",
            "name: Actual original callers with HIA machine encoding",
            "name: Actual original callers with HIA machine state",
            "name: Actual original callers with HIA machine instructions",
            "name: Native worker policy and pinned multi-image custody",
            "name: Native fifteen-action CLI current selfhost routing and installed resources",
            "name: Native Core module graph and actual workspace projects",
            "name: Native Core workspace JSON materialization and actual ABI",
            "name: Native Core capability edge policy and actual CFG",
            "name: Native explicit workspace facts and semantic ELF materialization",
            "name: Native full Core function declarations SSA and CFG",
            "name: Native whole primitive Core declaration SSA CFG and export admission",
            "name: Native complete local instruction policy",
            "name: Native exact-byte artifact publication and real kernel races",
            "name: Native whole primitive Core admission and body resource flow",
            "name: Standalone native complete Core admission CLI",
            "name: Native snapshot-bound edits and complete Core patch CLI",
            "name: Native ordinary Agent candidate bytes diagnostics and real crash cuts",
            "name: Native complete nominal types helpers constructor functions and outer lowering",
            "name: Native worker request admission and ordinary request continuity",
            "name: Native worker pinned helper custody and journal composition",
            "name: Native request journal decisions and actual SQL crash controls",
            "name: Native execution budgets and both request-journal lifecycles",
            "name: Native candidate budgets and pinned state owner composition",
            "name: Native slot versions leases and original Agent transactions",
            "name: Ordinary Agent callers with native journal and retained owner forbidden",
            "name: Native immutable release installation and recovery observations",
            "name: Native release selection CAS rollback and crash recovery",
            "name: Native retained retirement and real resource release controls",
            "name: Native assembly source build and self-repacking",
            "name: Native raw JSON nominal packets and actual constructor ingress",
            "name: Native JSON wire entry, exact graph budgets, key cache and installed resources",
            "name: Original ordinary callers through HIA JSON wire",
            "name: Preserve actual cold failure and stage evidence"
        ]
        expected_a733 = [
            "uses: actions/checkout@v4",
            "uses: actions/setup-python@v5",
            "name: Install qualified Clang 20 native execution prerequisites",
            "run: python -m pip install setuptools==78.1.1 wheel==0.46.3 z3-solver==4.15.4.0 jsonschema==4.26.0",
            "run: python -B tools/replay_hia_selfhost_cold.py --output \"$RUNNER_TEMP/hia-cold.json\"",
            "run: python -B tests/test_hia_selfhost_language_coverage.py --output \"$RUNNER_TEMP/hia-language.json\"",
            "name: Native linked loader and compiler receipt bindings",
            "name: Native applications and actual Core memory controls",
            "name: Native Core module graph and actual workspace projects",
            "name: Native Core workspace JSON materialization and actual ABI",
            "name: Native Core capability edge policy and actual CFG",
            "name: Native explicit workspace facts and semantic ELF materialization",
            "name: Native full Core function declarations SSA and CFG",
            "name: Native whole primitive Core declaration SSA CFG and export admission",
            "name: Native complete local instruction policy",
            "name: Native streaming SHA complete retained state controls",
            "name: Native exact-byte artifact publication and real kernel races",
            "name: Native whole primitive Core admission and body resource flow",
            "name: Standalone native complete Core admission CLI",
            "name: Native snapshot-bound edits and complete Core patch CLI",
            "name: Native ordinary Agent candidate bytes diagnostics and real crash cuts",
            "name: Native full Core execution and installed worker bindings",
            "name: Native structural budgets arbitrary precision and installed composition",
            "name: Native public live heap payload bounds and installed composition",
            "name: Native complete nominal continuation families retained from a733",
            "name: Native durable execution budgets request journal and artifact namespace",
            "name: Native retained retirement state and actual resource custody",
            "name: Native worker request admission and ordinary request continuity",
            "name: Native immutable release installation and recovery observations",
            "name: Native release selection CAS rollback and crash recovery",
            "name: Native source admission build and explicit public compiler",
            "name: Native complete CLI arguments formatting and continuations",
            "name: Native complete machine Code owners and exception custody",
            "name: Native machine instructions through complete original callers",
            "name: Native machine ELF writer and exact exception custody",
            "name: Native machine ELF through complete original callers",
            "name: Native machine plan policy and original object lifetimes",
            "name: Native machine plan through complete original callers",
            "name: Native service context policy integers and held proof identity",
            "name: Native service context through all original Agent callers",
            "name: Native complete Core lowering through all original machine and Core callers",
            "name: Native shared frame Call and short circuit ownership",
            "name: Native service emission continuation and exception custody",
            "name: Native service emission through all original Agent callers",
            "name: Native complete Core emitter through all original machine and Core callers",
            "name: Native borrowed byte ABI complete policy and whole emission custody",
            "name: Native borrowed byte ABI through all original byte and Agent buffer callers",
            "name: Native complete build coordinator and installation custody",
            "name: Native complete build coordinator through all original 114 callers",
            "name: Native service verification complete policy and default replay",
            "name: Native service verification through all original Agent callers",
            "name: Native proof contract complete public policy and held capability",
            "name: Native proof contract through all original 22 proof and 18 machine callers",
            "name: Native eight-body service requests complete component",
            "name: Native requests through all original 48 Agent callers",
            "name: Native requests through all original 35 namespace callers",
            "name: Native requests through all original 48 ledger callers",
            "name: Native six-body service artifacts complete component",
            "name: Native artifacts through all original 48 Agent callers",
            "name: Native artifacts through all original 35 namespace callers",
            "name: Native artifacts through all original 48 ledger callers",
            "name: Native nine-body service evaluation complete component",
            "name: Native evaluation through all original 48 Agent callers",
            "name: Native evaluation through all original 35 namespace callers",
            "name: Native evaluation through all original 48 ledger callers",
            "name: Preserve actual cold failure and stage evidence"
        ]
        for label, expected in (("mainf33d", expected_main), ("a733", expected_a733)):
            with self.subTest(side=label):
                remaining = iter(actual)
                for original_step in expected:
                    self.assertTrue(any(current == original_step for current in remaining),
                                    (label, original_step))
        self.assertEqual(len(expected_main), 65)
        self.assertEqual(len(expected_a733), 66)
        self.assertEqual(actual.count("name: Preserve actual cold failure and stage evidence"), 1)
        self.assertEqual(actual.count("name: Preserve final JSON wire caller evidence"), 1)

    def test_main_and_continuation_families_keep_distinct_commands_and_cold_inputs(self):
        pairs = (
            ("Actual original machine and Core callers with complete HIA Function control",
             "tools/qualify_hia_core_lowering_callers.py",
             "Native complete Core lowering through all original machine and Core callers",
             "tools/qualify_hia_core_lowering_control_callers.py"),
            ("Actual original machine and Core callers with complete HIA Emitter control",
             "tools/qualify_hia_core_emitter_callers.py",
             "Native complete Core emitter through all original machine and Core callers",
             "tools/qualify_hia_core_emitter_control_callers.py"),
            ("Actual original callers with HIA machine plans",
             "tools/qualify_hia_machine_plan_native_callers.py",
             "Native machine plan through complete original callers",
             "tools/qualify_hia_machine_plan_control_callers.py"),
        )
        for old_name, old_tool, control_name, control_tool in pairs:
            with self.subTest(control=control_tool):
                self.assertIn(old_tool, "\n".join(step(old_name)))
                self.assertIn(control_tool, "\n".join(step(control_name)))
                self.assertNotIn(control_tool, "\n".join(step(old_name)))
                for selected in (old_name, control_name):
                    self.assertIn('--cold-report "$RUNNER_TEMP/hia-cold.json"',
                                  "\n".join(step(selected)))
        self.assertIn("tests.test_hia_slot_ledger_native",
                      "\n".join(step("Native slot versions leases and original Agent transactions")))
        self.assertIn("tests.test_hia_slot_ledger_continuation_native",
                      script("Native durable execution budgets request journal and artifact namespace"))
        self.assertIn("HEPTA_HIA_SLOT_LEDGER_CONTINUATION_COLD_REPORT:",
                      "\n".join(step("Native durable execution budgets request journal and artifact namespace")))
        self.assertIn("HEPTA_HIA_MACHINE_PLAN_CONTROL_COLD_REPORT:",
                      "\n".join(step("Native machine plan policy and original object lifetimes")))
        self.assertIn("HEPTA_HIA_CORE_LOWERING_CONTROL_COLD_REPORT:",
                      "\n".join(step("Native shared frame Call and short circuit ownership")))
        self.assertIn("'tests.test_hia_byte_policy_selection.BytePolicySelectionTests'",
                      script("Core source and independent reference controls"))
        cli = script("Native complete CLI arguments formatting and continuations")
        self.assertIn("suite.countTestCases() != 43", cli)
        self.assertIn("result.testsRun == 43", cli)
        graph = "\n".join(step("Original call graph and native convergence controls"))
        self.assertIn("tools/run_hia_unittest_gate.py", graph)
        self.assertIn("tests.test_hia_selfhost_call_graph_efficiency.CallGraphNativeTests", graph)

    def test_native_archives_cover_every_explicit_fixture_and_caller_destination(self):
        import re
        native = WORKFLOW.read_text().split("  native:\n", 1)[1]
        uploads = step("Preserve actual cold failure and stage evidence")
        archive = {line.strip().rstrip("/") for line in uploads
                   if line.startswith("            ${{ runner.temp }}/")}
        wanted = set()
        for line in native.splitlines():
            match = re.match(r"          ([A-Z][A-Z0-9_]*): (\$\{\{ runner\.temp \}\}/[A-Za-z0-9_./-]+)$", line)
            if match and not match.group(1).endswith("_COLD_REPORT"):
                wanted.add(match.group(2).rstrip("/"))
        for relative in re.findall(r'--(?:evidence|evidence-dir|output)\s+"\$RUNNER_TEMP/([A-Za-z0-9_./-]+)"', native):
            wanted.add("${{ runner.temp }}/" + relative.rstrip("/"))
        self.assertTrue(wanted)
        self.assertLessEqual(wanted, archive)
        for relative in ("native-continuation-callers", "native-inprocess-continuation-callers",
                         "native-no-child-continuation-callers"):
            self.assertIn("${{ runner.temp }}/" + relative, archive)
        tail = step("Preserve final JSON wire caller evidence")
        for relative in ("json-wire-fixture/", "json-wire-entry-fixture/",
                         "json-wire-cache-fixture/", "hia-json-wire-callers.json",
                         "hia-json-wire-callers/"):
            self.assertIn("            ${{ runner.temp }}/" + relative, tail)
        self.assertIn("        if: always()", tail)
        self.assertIn("          if-no-files-found: error", tail)


    def test_checker_inventory_generation_surrounds_owner_generators(self):
        source = WORKFLOW.read_text().split("  native:\n", 1)[0]
        before = source.index("      - name: Refresh checker custody before HIA generation")
        owners = source.index("      - name: Regenerate actual HIA sources")
        after = source.index("      - name: Refresh checker custody after HIA generation")
        check = source.index("      - name: Check final checker custody inventory")
        controls = source.index("      - name: Core source and independent reference controls")
        self.assertLess(before, owners)
        self.assertLess(owners, after)
        self.assertLess(after, check)
        self.assertLess(check, controls)
        self.assertIn("tools/generate_hia_checker_inventory.py --check",
                      "\n".join(step("Check final checker custody inventory")))
        selected = script("Core source and independent reference controls")
        for name in ("tests.test_hia_checker_inventory.CheckerInventorySourceTests",
                     "tests.test_hia_checker_inventory.CheckerImportTemplateSourceTests"):
            self.assertIn(repr(name), selected)


if __name__ == '__main__':
    unittest.main()
