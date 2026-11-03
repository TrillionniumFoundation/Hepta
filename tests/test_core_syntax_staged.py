"""Adversarial mocked admission tests; never execute Lean or native targets.

Passing these tests establishes Python control behavior only, not a kernel proof.
"""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import core_syntax_stage_sources as sources
from tools import check_core_syntax_staged as runner


class StagedPlanValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = sources.build_inputs()

    def changed_stage(self, index, **changes):
        prepared = dict(self.prepared)
        stages = list(prepared['stages'])
        stages[index] = replace(stages[index], **changes)
        prepared['stages'] = tuple(stages)
        return prepared

    def test_exact_frozen_plan_has_ten_stages_and_implicit_init(self):
        runner.validate_plan(self.prepared)
        self.assertEqual(len(self.prepared['stages']), 10)
        previous = set()
        for stage in self.prepared['stages']:
            self.assertEqual(stage.direct_imports, ('Init',) + stage.explicit_imports)
            self.assertTrue(set(stage.parents) <= previous)
            previous.add(stage.module_name)
            self.assertEqual(stage.source_sha256, sha256(stage.source.encode()).hexdigest())
        self.assertEqual(len(self.prepared['negatives']), 10)
        self.assertEqual(len(self.prepared['expected_theorems']), 66)

    def test_changed_import_source_module_or_parent_is_rejected(self):
        stage = self.prepared['stages'][1]
        changes = (
            {'source': 'import Evil.External\n' + stage.source},
            {'source': stage.source.replace('import ', 'import Evil.External\nimport ', 1)},
            {'module_name': 'Init.SyntaxData'},
            {'module_name': '../SyntaxData'},
            {'direct_imports': stage.explicit_imports},
            {'explicit_imports': ('Evil.External',)},
            {'parents': ()},
            {'parents': (self.prepared['stages'][-1].module_name,)},
            {'source': stage.source + '\naxiom bypass : False\n'},
        )
        for mutation in changes:
            with self.subTest(mutation=list(mutation)):
                with self.assertRaises(ValueError):
                    runner.validate_plan(self.changed_stage(1, **mutation))

    def test_reordered_duplicate_missing_stages_rejected(self):
        stages = self.prepared['stages']
        for changed in (stages[::-1], stages[:-1], stages + stages[:1], stages + stages[:2],
                        (stages[1], stages[0]) + stages[2:]):
            prepared = dict(self.prepared, stages=changed)
            with self.subTest(names=[s.name for s in changed]):
                with self.assertRaises(ValueError):
                    runner.validate_plan(prepared)

    def test_canonical_manifest_hash_and_sources_cannot_disagree(self):
        cases = []
        cases.append(dict(self.prepared, manifest_sha256='0' * 64))
        cases.append(dict(self.prepared, manifest_json=self.prepared['manifest_json'] + ' '))
        manifest = deepcopy(self.prepared['manifest'])
        manifest['stages'][0]['implicit_imports'] = []
        cases.append(dict(self.prepared, manifest=manifest))
        modified = dict(self.prepared['sources'])
        first = self.prepared['stages'][0]
        modified[first.module_name] += '\n-- changed\n'
        cases.append(dict(self.prepared, sources=modified))
        for prepared in cases:
            with self.subTest(keys=[k for k in prepared if prepared[k] != self.prepared[k]]):
                with self.assertRaises(ValueError):
                    runner.validate_plan(prepared)

    def test_original_and_wrong_arm_extraction_graphs_stay_disjoint(self):
        stages = {s.name: s for s in self.prepared['stages']}
        normal, mutant = stages['Connections'], stages['WrongArm']
        self.assertNotIn(normal.module_name, mutant.direct_imports)
        self.assertNotIn(mutant.module_name, normal.direct_imports)
        self.assertIn('"then" -- MUTATION_SITE_SELECT_THEN', normal.source)
        self.assertIn('"else" -- MUTATION_SITE_SELECT_THEN', mutant.source)
        index = self.prepared['stages'].index(mutant)
        with self.assertRaises(ValueError):
            runner.validate_plan(self.changed_stage(index, source=normal.source))

    def test_full_byte_input_manifest_change_rejected(self):
        prepared = dict(self.prepared, canonical_bytes=self.prepared['canonical_bytes'] + b' ')
        with self.assertRaises(ValueError):
            runner.validate_plan(prepared)

    def test_proof_and_invocation_caps_are_enforced_before_launch(self):
        self.assertEqual(runner.MAX_INVOCATIONS, 11)
        self.assertEqual(runner.PROCESS_SECONDS, 60)
        self.assertEqual(runner.LAUNCH_SECONDS, 540)
        self.assertEqual(runner.MAX_SOURCE, 2 * 1024 * 1024)
        self.assertEqual(runner.MAX_TOTAL_SOURCE, 8 * 1024 * 1024)
        self.assertEqual(runner.MAX_MODULE, 32 * 1024 * 1024)
        self.assertEqual(runner.MAX_TOTAL_MODULE, 128 * 1024 * 1024)
        for name, limit in (('MAX_SOURCE', 1), ('MAX_TOTAL_SOURCE', 1), ('MAX_INVOCATIONS', 9)):
            with self.subTest(cap=name), patch.object(runner, name, limit):
                with self.assertRaises(ValueError):
                    runner.validate_plan(self.prepared)

    def test_no_implicit_init_suppression_or_import_alias_syntax(self):
        stage = self.prepared['stages'][0]
        for text in ('prelude\n' + stage.source,
                     stage.source.replace('import Lean.Elab.Tactic.Omega',
                                          'import Lean.Elab.Tactic.Omega Evil.Extra'),
                     stage.source.replace('import Lean.Elab.Tactic.Omega',
                                          'import Lean.Elab.Tactic.Omega\nimport Lean.Elab.Tactic.Omega')):
            with self.subTest(header=text.splitlines()[0]), self.assertRaises(ValueError):
                runner.validate_plan(self.changed_stage(0, source=text))


class StagedSafeRootTests(unittest.TestCase):
    def test_root_must_be_fresh_even_if_existing_directory_is_empty(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises((ValueError, FileExistsError)):
                runner.SafeRoot(Path(folder))

    def test_regular_exact_inventory_roundtrip_and_read_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            safe = runner.SafeRoot(Path(folder) / 'fresh')
            try:
                safe.write('HiaSyntaxResearch/Test.lean', b'abc')
                self.assertEqual(safe.read('HiaSyntaxResearch/Test.lean', 3), b'abc')
                self.assertEqual(safe.scan({'HiaSyntaxResearch/Test.lean'}),
                                 {'HiaSyntaxResearch/Test.lean': 3})
                with self.assertRaises(ValueError):
                    safe.read('HiaSyntaxResearch/Test.lean', 2)
                with self.assertRaises(ValueError):
                    safe.scan(set())
            finally:
                safe.close()

    def test_symlink_and_hardlink_are_never_regular_admissible_outputs(self):
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / 'fresh'
                safe = runner.SafeRoot(root)
                try:
                    outside = Path(folder) / 'external'
                    outside.write_bytes(b'old module')
                    target = root / 'borrowed.olean'
                    if kind == 'symlink':
                        target.symlink_to(outside)
                    else:
                        os.link(outside, target)
                    with self.assertRaises(ValueError):
                        safe.scan({'borrowed.olean'})
                    with self.assertRaises((ValueError, OSError)):
                        safe.read('borrowed.olean', 100)
                finally:
                    safe.close()

    def test_symlink_directory_and_relative_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'fresh'
            safe = runner.SafeRoot(root)
            try:
                outside = Path(folder) / 'external'
                outside.mkdir()
                (root / 'redirect').symlink_to(outside, target_is_directory=True)
                with self.assertRaises((ValueError, OSError)):
                    safe.write('redirect/output.olean', b'not permitted')
                self.assertFalse((outside / 'output.olean').exists())
                for name in ('../escaped.olean', '/tmp/escaped.olean'):
                    with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                        safe.write(name, b'not permitted')
            finally:
                safe.close()


class StagedCaptureTests(unittest.TestCase):
    def test_exact_cli_and_search_path_do_not_inherit_user_modules(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'fresh'
            executable = Path(folder) / 'pinned' / 'bin' / 'lean'
            source = root / 'HiaSyntaxResearch' / 'Baseline.lean'
            output = source.with_suffix('.olean')
            completed = subprocess.CompletedProcess([], 0, b'ok', b'')
            with patch.dict(os.environ, {'LEAN_PATH': '/evil/modules', 'LEAN_SRC_PATH': '/evil/src',
                                         'LEAN_SYSROOT': '/evil/sysroot'}), \
                    patch.object(runner.subprocess, 'run', return_value=completed) as launch:
                runner.capture_result(executable, source, output, root)
            args, kwargs = launch.call_args
            self.assertEqual(args[0], [str(executable), '--root=' + str(root),
                                       '-o', str(output), str(source)])
            self.assertEqual(Path(kwargs['cwd']), root)
            self.assertEqual(kwargs['env']['LEAN_PATH'], str(root))
            self.assertEqual(kwargs['env']['LEAN_SYSROOT'], str(executable.parent.parent))
            self.assertFalse(kwargs['env'].get('LEAN_SRC_PATH'))
            self.assertEqual(kwargs['timeout'], 60)
            self.assertTrue(kwargs['capture_output'])
            self.assertFalse(kwargs.get('text', False))
            self.assertNotIn('shell', kwargs)

    def test_timeout_retains_bounded_partial_diagnostics_without_throwing(self):
        for partial in (b'partial stdout', 'partial text', b'bad utf8: \xff', b'x' * (2 * 1024 * 1024), b'\xff' * (2 * 1024 * 1024), None):
            with self.subTest(kind=type(partial).__name__, size=len(partial) if partial else 0):
                timeout = subprocess.TimeoutExpired('mock lean', 60, output=partial, stderr=b'partial stderr')
                with patch.object(runner.subprocess, 'run', side_effect=timeout):
                    result = runner.capture_result(Path('/pinned/bin/lean'), Path('/fresh/F.lean'),
                                                   Path('/fresh/F.olean'), Path('/fresh'))
                raw = partial.encode() if isinstance(partial, str) else (partial or b'')
                self.assertEqual(result['stdout_available_bytes'], len(raw))
                self.assertEqual(result['stdout_available_sha256'], sha256(raw).hexdigest())
                self.assertIsNone(result['returncode'])
                self.assertNotEqual(result.get('status'), 'passed')
                self.assertLessEqual(len(result['stdout'].encode()) + len(result['stderr'].encode()),
                                     1024 * 1024)
                if partial and len(partial) < 100:
                    self.assertIn('partial' if 'partial' in str(partial) else 'bad utf8', result['stdout'])
                self.assertTrue(result['timed_out'])
                self.assertTrue(result['incomplete'])
                self.assertEqual(result['output_truncated'], bool(partial and len(partial) > 1024 * 1024))
                if not partial or len(partial) < 1024 * 1024:
                    self.assertIn('partial stderr', result['stderr'])


class StagedExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = sources.build_inputs()

    def exercise(self, behavior='success', patches=(), stage_limit=runner.MAX_INVOCATIONS):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)
            executable = root / 'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'not executable; mock only')
            (root / 'pinned/lib/lean').mkdir(parents=True)
            if behavior == 'prefix_shadow':
                (root / 'pinned/lib/lean/HiaSyntaxResearch').mkdir()
            identity = {'mock-source': 'a' * 64}
            support = {'lib/lean/Init.olean': 'b' * 64,
                       'lib/lean/Lean/Elab/Tactic/Omega.olean': 'd' * 64}
            calls = []
            source_state, support_state = dict(identity), dict(support)
            generated = []

            def invoke(exe, source, output, module_root):
                source, output, module_root = Path(source), Path(output), Path(module_root)
                stage = next(s for s in self.prepared['stages'] if source.stem == s.name)
                calls.append(stage.name)
                started = json.loads((module_root / (stage.name + '.started.json')).read_text())
                self.assertEqual(started['status'], 'running')
                self.assertEqual(started['module_name'], stage.module_name)
                self.assertEqual(started['source_sha256'], stage.source_sha256)
                self.assertEqual(started['direct_imports'], list(stage.direct_imports))
                self.assertEqual(set(started['parents']), set(stage.parents))
                for parent in started['parents'].values():
                    self.assertEqual(parent['sha256'], sha256((module_root / parent['path']).read_bytes()).hexdigest())
                    self.assertIn(parent['successful_stage'], calls[:-1])
                self.assertEqual(source.read_bytes(), stage.source.encode())
                self.assertEqual(output, source.with_suffix('.olean'))
                self.assertEqual(exe, executable)
                text = '\n'.join("'" + name + "' does not depend on any axioms"
                                 for name in sorted(stage.expected_theorems))
                result = {'returncode': 0, 'stdout': text, 'stderr': '', 'timed_out': False,
                          'incomplete': False, 'output_truncated': False}
                if behavior != 'missing_output':
                    output.write_bytes(b'mocked olean ' + stage.name.encode())
                    generated.append(output)
                if behavior == 'launch_error':
                    raise OSError('mock launch failure')
                if behavior == 'boolean_returncode':
                    result['returncode'] = False
                elif behavior == 'failed_parent':
                    result.update(returncode=1, stdout='error: rejected')
                elif behavior == 'timeout':
                    result.update(returncode=None, timed_out=True, incomplete=True,
                                  stdout='partial diagnostic')
                elif behavior == 'bad_axiom':
                    result['stdout'] = text.replace('does not depend on any axioms',
                                                   'depends on axioms: [sorryAx]', 1)
                elif behavior == 'missing_theorem':
                    result['stdout'] = '\n'.join(text.splitlines()[1:])
                elif behavior == 'duplicate_theorem':
                    result['stdout'] += '\n' + text.splitlines()[0]
                elif behavior == 'unexpected_theorem':
                    result['stdout'] += "\n'Evil.extra' does not depend on any axioms"
                elif behavior == 'error_diagnostic':
                    result['stderr'] = 'error: elaboration failed'
                elif behavior == 'unknown_file':
                    (module_root / 'unrequested.so').write_bytes(b'forbidden output')
                elif behavior == 'hardlinked_output':
                    output.unlink()
                    os.link(executable, output)
                elif behavior == 'symlink_output':
                    output.unlink()
                    output.symlink_to(executable)
                elif behavior == 'empty_output':
                    output.write_bytes(b'')
                elif behavior == 'source_changed':
                    source.write_bytes(source.read_bytes() + b'\n-- changed')
                elif behavior == 'source_identity_changed':
                    source_state['mock-source'] = 'c' * 64
                elif behavior == 'support_changed':
                    support_state['lib/lean/Init.olean'] = 'c' * 64
                elif behavior == 'late_support_shadow':
                    shadow = executable.parent.parent / 'lib/lean' / runner.MODULE_PREFIX
                    shadow.mkdir(parents=True)
                elif behavior == 'binary_changed':
                    executable.write_bytes(b'changed executable')
                elif behavior == 'parent_changed' and len(calls) == 2:
                    generated[0].write_bytes(b'substituted old external olean')
                elif behavior == 'missing_rejection' and stage.rejection_names:
                    cert = self.prepared['negatives'][stage.rejection_names[0]]['certificate']
                    result['stdout'] = '\n'.join(line for line in text.splitlines() if cert not in line)
                return result

            for name, value in patches:
                stack.enter_context(patch.object(runner, name, value))
            report = runner.execute_plan(executable, root / 'out', self.prepared,
                                         identity, support, lambda *args: dict(source_state),
                                         lambda *args: dict(support_state), sha256(executable.read_bytes()).hexdigest(),
                                         run_process=invoke, stage_limit=stage_limit)
            self.assertEqual(json.loads((root / 'out/RESULT.json').read_text()), report)
            if behavior == 'timeout':
                process = report['stages'][0]['process']
                self.assertTrue(process['timed_out'])
                self.assertTrue(process['incomplete'])
                diagnostic = root / 'out' / report['stages'][0]['diagnostics']['stdout']
                self.assertEqual(diagnostic.read_text(), 'partial diagnostic')
            self.assertEqual(report['authority'], 'DENY_ALL')
            self.assertEqual(len(report['obligations']), 12)
            self.assertTrue(all(item['status'] == 'unproved' for item in report['obligations']))
            for key in ('actual_core_bridge_proved', 'python_exporter_refinement_proved',
                        'body_prefix_refinement_proved', 'all_edge_transfer_proved',
                        'initialization_elision_authorized', 'native_admission',
                        'production_admission', 'performance_qualified', 'quota_equivalence'):
                self.assertIs(report[key], False, key)
            return report, calls

    def test_complete_mock_dag_preserves_all_production_denials(self):
        report, calls = self.exercise()
        self.assertEqual(report['status'], 'passed', report.get('error'))
        self.assertTrue(report['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls, [stage.name for stage in self.prepared['stages']])
        self.assertEqual(report['invocations'], 10)
        self.assertTrue(all(stage['status'] == 'passed' for stage in report['stages']))

    def test_bad_first_stage_never_starts_downstream_or_claims_connection(self):
        for behavior in ('launch_error', 'boolean_returncode', 'failed_parent', 'timeout', 'missing_output', 'empty_output', 'bad_axiom',
                         'missing_theorem', 'duplicate_theorem', 'unexpected_theorem',
                         'error_diagnostic', 'unknown_file', 'hardlinked_output', 'symlink_output',
                         'source_changed', 'source_identity_changed', 'support_changed', 'binary_changed', 'late_support_shadow'):
            with self.subTest(behavior=behavior):
                report, calls = self.exercise(behavior)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['kernel_core_syntax_connection_checked'])
                self.assertEqual(calls, ['Baseline'])

    def test_checked_parent_olean_changed_in_next_process_fails(self):
        report, calls = self.exercise('parent_changed')
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(report['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls, ['Baseline', 'SyntaxData'])

    def test_missing_rejection_certificate_prevents_final_acceptance(self):
        report, calls = self.exercise('missing_rejection')
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(report['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls[-1], 'Connections')

    def test_module_caps_fail_without_admitting_downstream(self):
        for cap in ('MAX_MODULE', 'MAX_TOTAL_MODULE'):
            with self.subTest(cap=cap):
                report, calls = self.exercise(patches=((cap, 1),))
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['kernel_core_syntax_connection_checked'])
                self.assertEqual(calls, ['Baseline'])

    def test_expired_launch_deadline_does_not_start_any_process(self):
        report, calls = self.exercise(patches=(('LAUNCH_SECONDS', 0),))
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(report['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls, [])

    def test_pinned_support_prefix_shadow_never_starts(self):
        with self.assertRaisesRegex(ValueError, 'prefix shadows support'):
            self.exercise('prefix_shadow')


    def test_diagnostic_limit_stops_after_two_successes_and_invalid_limits_never_launch(self):
        report, calls = self.exercise(stage_limit=2)
        self.assertEqual(calls, ['Baseline', 'SyntaxData'])
        self.assertEqual(report['invocations'], 2)
        self.assertEqual(report['diagnostic_stage_limit'], 2)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['error'], 'diagnostic stage boundary')
        self.assertFalse(report['kernel_core_syntax_connection_checked'])
        self.assertEqual([stage['status'] for stage in report['stages']], ['passed', 'passed'])
        # Invalid options fail before even validating/preparing the DAG, so no
        # process or output receipt can be created under an unsupported limit.
        for limit in (True, False, 0, 3, 2.0, '2', None):
            with self.subTest(limit=repr(limit)), patch.object(runner, 'validate_plan') as validate:
                with self.assertRaisesRegex(ValueError, 'unsupported diagnostic stage limit'):
                    self.exercise(stage_limit=limit)
                validate.assert_not_called()


class StagedDiagnosticPrintingTests(unittest.TestCase):
    def capture(self, directory):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output):
            runner.print_diagnostics(directory)
        return output.getvalue()

    def assert_unsafe_without_disclosure(self, directory):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output), self.assertRaises((ValueError, OSError)):
            runner.print_diagnostics(directory)
        self.assertEqual(output.getvalue(), '')

    def test_prints_only_known_regular_logs_and_never_modules_or_other_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'RUN.json').write_text('{"status":"running"}')
            (root / 'Baseline.stdout').write_text('ordinary mocked diagnostic')
            (root / 'Baseline.olean').write_bytes(b'MODULE CONTENT MUST NOT PRINT')
            (root / 'unrequested.stdout').write_text('UNREQUESTED CONTENT MUST NOT PRINT')
            output = self.capture(root)
            self.assertIn('RUN.json\n{"status":"running"}', output)
            self.assertIn('Baseline.stdout\nordinary mocked diagnostic', output)
            self.assertNotIn('MODULE CONTENT', output)
            self.assertNotIn('UNREQUESTED CONTENT', output)
            self.assertNotIn('Baseline.olean', output)

    def test_symlink_log_never_discloses_external_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'logs'
            root.mkdir()
            external = Path(folder) / 'external-secret'
            external.write_text('EXTERNAL TARGET MUST NOT PRINT')
            (root / 'RUN.json').symlink_to(external)
            self.assert_unsafe_without_disclosure(root)

    def test_hardlinked_log_never_discloses_external_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'logs'
            root.mkdir()
            external = Path(folder) / 'external-secret'
            external.write_text('EXTERNAL TARGET MUST NOT PRINT')
            os.link(external, root / 'RUN.json')
            self.assert_unsafe_without_disclosure(root)

    def test_fifo_log_is_nonblocking_and_rejected_without_reading(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            os.mkfifo(root / 'RUN.json')
            real_open = os.open

            def guarded_open(path, flags, *args, **kwargs):
                if kwargs.get('dir_fd') is not None:
                    self.assertTrue(flags & os.O_NONBLOCK, 'FIFO inspection must not block')
                return real_open(path, flags, *args, **kwargs)

            with patch.object(runner.os, 'open', side_effect=guarded_open):
                self.assert_unsafe_without_disclosure(root)

    def test_symlink_directory_or_ancestor_never_discloses_external_logs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            external = root / 'external'
            external.mkdir()
            logs = external / 'logs'
            logs.mkdir()
            (logs / 'RUN.json').write_text('EXTERNAL TARGET MUST NOT PRINT')
            (root / 'redirect').symlink_to(external, target_is_directory=True)
            (root / 'direct').symlink_to(logs, target_is_directory=True)
            for candidate in (root / 'redirect/logs', root / 'direct'):
                with self.subTest(path=candidate.name):
                    self.assert_unsafe_without_disclosure(candidate)


class StagedPreparationRaceTests(unittest.TestCase):
    def test_original_pin_is_not_reset_after_preparation_replaces_binary(self):
        from contextlib import ExitStack
        from tools import check_core_syntax_lean as original
        from tools import qualify_hia_selected_formal as checker
        prepared = sources.build_inputs()
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)
            executable = root / 'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'original mock pinned binary')
            original_sha = sha256(executable.read_bytes()).hexdigest()
            (root / 'formal').mkdir()
            (root / 'formal/toolchain-lock.json').write_text(json.dumps({
                'lean_binary_sha256': original_sha}))
            support = {'lib/lean/Init.olean': 'a' * 64,
                       'lib/lean/Lean/Elab/Tactic/Omega.olean': 'b' * 64}

            def prepare_and_replace_binary():
                executable.write_bytes(b'replacement must never become trusted')
                return prepared

            stack.enter_context(patch.object(runner, 'ROOT', root))
            stack.enter_context(patch.object(runner, 'source_identity', return_value={'mock': 'c' * 64}))
            stack.enter_context(patch.object(checker, '_support_identity', return_value=support))
            stack.enter_context(patch.object(original, 'fixed_input', return_value={
                'bytes': prepared['canonical_bytes']}))
            prepare = stack.enter_context(patch('tools.core_syntax_structured_stages.build_inputs', side_effect=prepare_and_replace_binary))
            launch = stack.enter_context(patch.object(runner.subprocess, 'run'))
            with self.assertRaisesRegex(ValueError, 'pinned Lean binary changed before execution'):
                runner.qualify(executable, root / 'output')
            prepare.assert_called_once_with()
            launch.assert_not_called()
            self.assertFalse((root / 'output').exists())
            self.assertNotEqual(sha256(executable.read_bytes()).hexdigest(), original_sha)

    def test_safe_read_rejects_fifo_substituted_after_scan_without_blocking(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'fresh'
            safe = runner.SafeRoot(root)
            try:
                safe.write('output.olean', b'regular at scan time')
                self.assertEqual(safe.scan({'output.olean'}), {'output.olean': 20})
                (root / 'output.olean').unlink()
                os.mkfifo(root / 'output.olean')
                real_open = os.open

                def guarded_open(path, flags, *args, **kwargs):
                    if path == 'output.olean':
                        self.assertTrue(flags & os.O_NONBLOCK, 'post-scan FIFO must not block before fstat')
                    return real_open(path, flags, *args, **kwargs)

                with patch.object(runner.os, 'open', side_effect=guarded_open), \
                        self.assertRaisesRegex(ValueError, 'nonregular'):
                    safe.read('output.olean', 100)
            finally:
                safe.close()


class StagedLiteralPlacementTests(unittest.TestCase):
    """Frozen relocation invariants against reviewed pre-relocation git 1ad7645."""
    LAYOUT = (
        ('linear', '', 'linear', 'LinearTransport', 96224,
         '14f5aed02ae6b3f7769d349da730ee6942ce6b0b937449c6f235d9a0bd8f3a0b'),
        ('parallel', '', 'parallel', 'ParallelTransport', 96228,
         '6f1fb249c1768905baf002fb128bc3208b96d6a7cf2c2305dfb5ef6287607eea'),
        ('wrong_phi', 'WrongPhi', 'linear', 'WrongPhiTransport', 96242,
         '574e89c44029375d7879cfa7c7188be3e3710dc5ea3bfe289d9a9f4e99421e56'),
        ('literal_two', 'LiteralTwo', 'linear', 'LiteralTwoTransport', 96246,
         '7608ae138734b28f585a0ba093a176197d684ef0a20e167953adb29c0b3b8ff1'),
        ('wrong_condition', 'WrongCondition', 'linear', 'WrongConditionTransport', 97085,
         '2bdea199441ab50c3a3e80d47a44025f11e14588ce0df9b86363ffc3c6065374'),
    )

    @classmethod
    def setUpClass(cls):
        import re
        from tools import check_core_syntax_lean as original
        cls.prepared = sources.build_inputs()
        cls.stages = {stage.name: stage for stage in cls.prepared['stages']}
        prior = original.build_inputs()
        cls.blocks = {}
        for key, namespace, stem, owner, size, expected_sha in cls.LAYOUT:
            source = prior['positive'] if key in ('linear', 'parallel') else prior['negatives'][key]['source']
            raw = re.findall(r'(?m)^def ' + stem + r'Raw : Raw := [^\n]+\n', source)
            byte = re.findall(r'(?m)^def ' + stem + r'Bytes : List Nat := [^\n]+\n', source)
            if len(raw) != 1 or len(byte) != 1:
                raise AssertionError('reviewed input must have exactly one Raw and Bytes definition')
            ns = 'HiaCoreSyntaxSlice' + ('.' + namespace if namespace else '')
            cls.blocks[key] = '\nnamespace ' + ns + '\n' + raw[0] + byte[0] + 'end ' + ns + '\n'

    @staticmethod
    def json_hash(value):
        return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def rebind(self, replacements, owners=None):
        """Repair all mutable hash metadata, so rejection must bind fixed ownership."""
        prepared = dict(self.prepared)
        stages = tuple(replace(stage, source=replacements.get(stage.name, stage.source))
                       for stage in prepared['stages'])
        manifest = deepcopy(prepared['manifest'])
        manifest['stages'] = [stage.manifest() for stage in stages]
        manifest['proof_input_bytes'] = sum(stage.source_bytes for stage in stages)
        for key, owner in (owners or {}).items():
            manifest['inputs'][key]['definition_module'] = 'HiaSyntaxResearch.' + owner
        encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':'))
        prepared.update(stages=stages, sources={stage.module_name: stage.source for stage in stages},
                        manifest=manifest, manifest_json=encoded,
                        manifest_sha256=sha256(encoded.encode()).hexdigest())
        self.assertEqual(manifest['proof_input_bytes'], 622046)
        self.assertEqual(manifest['stages'], [stage.manifest() for stage in prepared['stages']])
        self.assertEqual(self.json_hash(manifest), prepared['manifest_sha256'])
        return prepared

    def test_exact_original_wrapped_blocks_are_owned_once_before_certificates(self):
        for key, namespace, stem, owner, size, expected_sha in self.LAYOUT:
            with self.subTest(input=key):
                block = self.blocks[key]
                self.assertEqual(len(block.encode()), size)
                self.assertEqual(sha256(block.encode()).hexdigest(), expected_sha)
                self.assertEqual(sum(stage.source.count(block) for stage in self.stages.values()), 1)
                source = self.stages[owner].source
                self.assertEqual(source.count(block), 1)
                cert = stem if key in ('linear', 'parallel') else 'mutated'
                ns = 'HiaCoreSyntaxSlice' + ('.' + namespace if namespace else '')
                following = source[source.index(block) + len(block):]
                self.assertTrue(following.startswith('\nnamespace ' + ns + '\n' +
                                                     'theorem ' + cert + '_bounds'))
                self.assertEqual(self.prepared['manifest']['inputs'][key]['definition_module'],
                                 self.stages[owner].module_name)
                for sibling, other in self.blocks.items():
                    if sibling != key:
                        self.assertNotIn(other, source)
        import re
        self.assertIsNone(re.search(r'(?m)^def \w+ : (Raw|List Nat|Hint) :=', self.stages['SyntaxData'].source))
        runner.validate_plan(self.prepared)

    def test_four_untouched_sources_have_reviewed_prior_hashes(self):
        expected = {
            'Baseline': '8c615ecd34ae3e67c6ecc78d57cacca3437cc53ec3efcbd18c6b505f54127f31',
            'Connections': 'd422a27e0a1f1a1a9b6a46857dde36601f3311626163da906e0a4f29f1df3244',
            'TransportRejections': '7929a9355c3f24a67b73fd7b4b3651e4d0f354cbfe1d06a454ff550435156d91',
            'WrongArm': '4ae5e0e633c374232794c626679360dc28266484e4ff47cd69fb77888dca7c07',
        }
        self.assertEqual({name: self.stages[name].source_sha256 for name in expected}, expected)

    def test_input_proposition_partition_and_theorem_bindings_are_unchanged(self):
        manifest = self.prepared['manifest']
        inputs = {key: {name: value for name, value in item.items() if name != 'definition_module'}
                  for key, item in manifest['inputs'].items()}
        for value, digest in (
            (inputs, 'cc68e4a2271f97852c3e3eede5bc18de4a8539203af663c41c26d2c1561a2b2f'),
            (manifest['model_partition'], '3fd61cd2740b0341a018e0840c0760c61741e76f620902a45fe6b4ef51b67047'),
            (self.prepared['negatives'], '9a4fcbe6522b6b40cf7c115cec8ecb56f473fbfe00ea92ce6fcc92f2563da3c8'),
            (sorted(self.prepared['expected_theorems']), '95cc6947553398e2a4cdd3d243d9d15b50f8f8daae993a8bc01ddb53a8ff44d0'),
        ):
            self.assertEqual(self.json_hash(value), digest)

    def test_exact_relocated_sizes_imports_inventories_and_total(self):
        sizes = {'Baseline': 30632, 'SyntaxData': 15107, 'LinearTransport': 97312,
                 'ParallelTransport': 97372, 'WrongPhiTransport': 97419,
                 'LiteralTwoTransport': 97439, 'WrongConditionTransport': 98310,
                 'Connections': 21683, 'TransportRejections': 51030, 'WrongArm': 15742}
        self.assertEqual({name: stage.source_bytes for name, stage in self.stages.items()}, sizes)
        self.assertEqual(sum(sizes.values()), 622046)
        self.assertEqual(self.prepared['manifest']['proof_input_bytes'], 622046)
        self.assertEqual(sum(len(block.encode()) for block in self.blocks.values()), 482025)
        self.assertEqual([len(stage.expected_theorems) for stage in self.prepared['stages']],
                         [56, 3, 6, 6, 6, 6, 6, 70, 5, 1])
        transports = tuple('HiaSyntaxResearch.' + entry[3] for entry in self.LAYOUT)
        self.assertEqual(self.stages['Connections'].explicit_imports, transports)
        self.assertEqual(self.stages['WrongArm'].explicit_imports, ('HiaSyntaxResearch.ParallelTransport',))
        self.assertEqual(self.stages['TransportRejections'].explicit_imports, ('HiaSyntaxResearch.LinearTransport',))
        for name in sizes.keys() & {entry[3] for entry in self.LAYOUT}:
            self.assertEqual(self.stages[name].explicit_imports, ('HiaSyntaxResearch.SyntaxData',))

    def test_rehashed_wrong_sibling_placement_is_rejected_even_with_forged_owner(self):
        block = self.blocks['linear']
        replacements = {
            'LinearTransport': self.stages['LinearTransport'].source.replace(block, '', 1),
            'ParallelTransport': self.stages['ParallelTransport'].source.replace(
                self.blocks['parallel'], block + self.blocks['parallel'], 1),
        }
        for owners in (None, {'linear': 'ParallelTransport'}):
            with self.subTest(forged_owner=bool(owners)), self.assertRaises(ValueError):
                runner.validate_plan(self.rebind(replacements, owners))

    def test_rehashed_old_shared_data_placement_is_rejected(self):
        replacements = {}
        for key, namespace, stem, owner, size, expected_sha in self.LAYOUT:
            replacements[owner] = self.stages[owner].source.replace(self.blocks[key], '', 1)
        common = self.stages['SyntaxData'].source
        index = common.index('#print axioms ')
        replacements['SyntaxData'] = common[:index] + ''.join(self.blocks[key] for key, *_ in self.LAYOUT) + common[index:]
        for owners in (None, {key: 'SyntaxData' for key, *_ in self.LAYOUT}):
            with self.subTest(forged_owners=bool(owners)), self.assertRaises(ValueError):
                runner.validate_plan(self.rebind(replacements, owners))
