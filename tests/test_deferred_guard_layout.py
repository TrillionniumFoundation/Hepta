"""Deferred-guard compile-only preparation and orchestration controls.

All compiler campaigns in this module are SYNTHETIC ORCHESTRATION TESTS. They
exercise the real evidence writer and command logger against an in-memory
capture double. No Clang, object inspection process, linking or target execution
occurs. Only a separately reviewed real Clang 20 CI run can establish layout.
"""
from contextlib import ExitStack
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureFailure, CaptureRejected, CaptureResult
from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_optimization import _digest
from tools import check_deferred_guard_candidate as checker
from tools import diagnose_hia_deferred_guard_layout as layout

try:
    import z3
except ImportError:
    z3 = None

PINNED_SOLVER = z3 is not None and z3.get_version_string() == '4.15.4'
FLAGS = ('native_admission', 'production_admission', 'performance_qualified',
         'timing_performed', 'quota_equivalence')
DENY = {'authority': 'DENY_ALL', **{flag: False for flag in FLAGS}}
WORKLOADS = ('linear', 'affine')
ARMS = ('reference', 'deferred')


def read_json(path):
    return json.loads(Path(path).read_text())


def deny_assertions(test, value):
    test.assertEqual(value['authority'], 'DENY_ALL')
    for flag in FLAGS:
        test.assertIs(value[flag], False, flag)


def production_tripwires(stack):
    """An orchestration pass must not enter any production/native API."""
    targets = (
        'hepta.hia_program_llvm.build_program_native',
        'hepta.hia_program_llvm.compile_program_llvm',
        'hepta.hia_reduction.build_reduction_native',
        'hepta.hia_reduction._admit',
        'hepta.hia_guarded_optimization.build_guarded_native',
        'hepta.hia_optimization.build_optimized_native',
        'ctypes.CDLL',
        'subprocess.Popen',
    )
    return [stack.enter_context(patch(target, side_effect=AssertionError(
        'forbidden production, admission or native execution API: ' + target)))
        for target in targets]


class FlagsAndBindingsTests(unittest.TestCase):
    def test_compilation_is_only_the_fixed_x86_64_relocatable_profile(self):
        self.assertEqual(layout.command('clang', 'arm.ll', 'arm.o'), [
            'clang', '--target=x86_64-unknown-linux-gnu', '-x', 'ir',
            '-O3', '-fPIC', '-c', 'arm.ll', '-o', 'arm.o'])
        self.assertEqual(layout.WORKLOADS, WORKLOADS)
        self.assertEqual(layout.ARMS, ARMS)
        self.assertEqual((layout.MAX_COMMANDS, layout.MAX_COMPILATIONS), (24, 8))

    def test_tracing_changes_only_before_after_shrink_wrap_logging(self):
        ordinary = layout.command('clang', 'arm.ll', 'arm.o')
        traced = layout.command('clang', 'arm.ll', 'arm.o', trace=True)
        self.assertEqual(traced[:7] + traced[11:], ordinary)
        self.assertEqual(traced[7:11], [
            '-mllvm', '-print-before=shrink-wrap', '-mllvm', '-print-after=shrink-wrap'])
        self.assertNotIn('-shared', traced)
        self.assertFalse(any('enable-shrink-wrap' in flag for flag in traced))

    def test_bindings_include_entire_python_closure_tests_workflow_and_fixtures(self):
        bound = layout.bindings()
        required = {str(path.relative_to(layout.ROOT)) for path in
                    (layout.ROOT / 'hepta').glob('*.py')}
        required.update('tools/' + name for name in (
            'diagnose_hia_deferred_guard_layout.py',
            'experimental_deferred_guard_proposer.py',
            'check_deferred_guard_candidate.py', 'research_deferred_guard_model.py',
            'stage_deferred_guard_evidence.py'))
        required.update(str(path.relative_to(layout.ROOT)) for path in
                        (layout.ROOT / 'tests').glob('test_deferred_guard*.py'))
        required.add('.github/workflows/hia-deferred-guard-layout-diagnostic.yml')
        required.update('benchmarks/hia_reduction_release/' + w + '.hepta' for w in WORKLOADS)
        self.assertEqual(set(bound), required)
        for relative, digest in bound.items():
            self.assertEqual(digest, sha256((layout.ROOT / relative).read_bytes()).hexdigest())


class SyntheticOrchestrationTests(unittest.TestCase):
    """Run-level failure controls, with zero real native subprocesses."""
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.output = self.temporary / 'evidence'
        self.tool_paths = {}
        for tool in ('clang', 'objdump', 'objcopy', 'nm'):
            path = self.temporary / tool
            path.write_bytes(('synthetic tool identity: ' + tool).encode())
            self.tool_paths[tool] = path
        self.state = {'head': 'synthetic-exact-head', 'tree': 'synthetic-exact-tree', 'status': ''}
        self.bound = {'tests/synthetic-source.py': 'b' * 64}
        self.source_mock = self.stack.enter_context(patch.object(
            layout, 'source_state', side_effect=lambda: dict(self.state)))
        self.binding_mock = self.stack.enter_context(patch.object(
            layout, 'bindings', side_effect=lambda: dict(self.bound)))
        self.stack.enter_context(patch.object(layout.shutil, 'which', side_effect=
            lambda name: str(self.tool_paths['clang' if name == 'clang-20' else name])))
        self.prepare_mock = self.stack.enter_context(patch.object(
            layout, 'prepare', side_effect=self.synthetic_prepare))
        self.native_calls = []
        self.hook = None
        self.different_arms = False
        self.different_text = False
        self.trace_mismatch = None
        self.missing_object = False
        self.missing_section = False
        self.compiler_version = 'clang version 20.1.8 (synthetic orchestration test)\n'
        self.capture_mock = self.stack.enter_context(patch.object(
            layout.native, 'run_bounded', side_effect=self.synthetic_capture))
        self.tripwires = production_tripwires(self.stack)

    def synthetic_prepare(self, output):
        """The double is not proof authority; actual preparation is tested below."""
        prepared = {}
        for workload in WORKLOADS:
            directory = Path(output) / workload
            directory.mkdir()
            layout.save(directory / 'PROPOSAL.json', {'synthetic': workload,
                'reduction': {'guarded': {'guards': [{'function': 'calculate',
                    'argument': 'arg1', 'maximum': 72340172838076673}]}}})
            layout.save(directory / 'CHECK.json', {'synthetic': workload, 'status': 'checked', **DENY})
            prepared[workload] = {}
            for arm in ARMS:
                text = '; synthetic orchestration LLVM: ' + workload + '/' + arm + '\n'
                core = json.dumps({'synthetic': workload, 'arm': arm}).encode()
                ir = layout.native.HIAProgramLLVM(
                    text=text, sha256=sha256(text.encode()).hexdigest(),
                    core_sha256=sha256(core).hexdigest(), implementation_sha256='a' * 64,
                    exports=('calculate',))
                (directory / (arm + '.core.json')).write_bytes(core)
                (directory / (arm + '.ll')).write_text(text)
                layout.save(directory / (arm + '.llvm.json'), {
                    'core_sha256': ir.core_sha256, 'llvm_sha256': ir.sha256,
                    'implementation_sha256': ir.implementation_sha256,
                    'input_sha256': ir.input_sha256, 'exports': list(ir.exports),
                    'target': ir.target, **DENY})
                prepared[workload][arm] = ir
        return prepared

    def synthetic_capture(self, argv, **kwargs):
        argv = list(argv)
        self.native_calls.append(argv)
        # The first native invocation, including --version, can only occur after
        # evidence for BOTH workloads/arms and registration have been written.
        self.assertTrue((self.output / 'REGISTRATION.json').is_file())
        for workload in WORKLOADS:
            for name in ('PROPOSAL.json', 'CHECK.json', *(
                    arm + suffix for arm in ARMS for suffix in ('.core.json', '.ll', '.llvm.json'))):
                self.assertTrue((self.output / workload / name).is_file(), name)
        self.assertEqual(kwargs['timeout'], 60)
        self.assertEqual(kwargs['stdout_limit'], 16_000_000)
        self.assertEqual(kwargs['stderr_limit'], 16_000_000)
        self.assertEqual(kwargs['cwd'], str(self.output))
        # The previous attempt was checkpointed before the next one began.
        receipt = read_json(self.output / 'RESULT.json')
        self.assertEqual(receipt['status'], 'running')
        self.assertEqual(len(receipt['commands']), len(self.native_calls) - 1)
        if self.hook is not None:
            outcome = self.hook(argv)
            if outcome is not None:
                return outcome
        stdout, stderr = b'synthetic observation\n', b''
        if '--version' in argv:
            stdout = (self.compiler_version if Path(argv[0]).name == 'clang'
                      else Path(argv[0]).name + ' synthetic version\n').encode()
        elif '-c' in argv:
            output = Path(argv[argv.index('-o') + 1])
            arm = output.name.split('.')[0]
            payload = (arm.encode() if self.different_arms else b'identical') + b'-synthetic-object'
            if '.trace.' in output.name:
                stderr = b'# *** IR Dump Before ShrinkWrap ***\nsynthetic MIR\n# *** IR Dump After ShrinkWrap ***\n'
                if arm == self.trace_mismatch:
                    payload += b'-trace-mismatch'
            if not self.missing_object:
                output.write_bytes(payload)
        elif '--only-section=.text' in argv:
            arm = Path(argv[-1]).name.split('.')[0]
            if not self.missing_section:
                Path(argv[-1]).write_bytes((arm.encode() if self.different_text else b'same') + b'-text')
        elif '-dr' in argv:
            stdout = b'0000 <calculate>:\n  synthetic instruction  R_X86_64_PLT32 calloc\n'
        elif '-S' in argv:
            stdout = b'0000000000000000 0000000000000010 T calculate\n'
        else:
            self.fail('unregistered synthetic command: ' + repr(argv))
        return CaptureResult(0, stdout.decode(), stderr.decode(), stdout, stderr)

    def run_campaign(self):
        return layout.run(self.output, 'clang-20')

    def expect_failure(self, pattern=None, *, inventory_refused=False):
        context = self.assertRaisesRegex(Exception, pattern) if pattern else self.assertRaises(Exception)
        with context:
            self.run_campaign()
        result = read_json(self.output / 'RESULT.json')
        self.assertEqual(result['status'], 'failed', result)
        deny_assertions(self, result)
        self.assertEqual(result['command_count'], len(self.native_calls))
        self.assertLessEqual(len(self.native_calls), 24)
        self.assertLessEqual(sum('-c' in command for command in self.native_calls), 8)
        if inventory_refused:
            self.assertIn('artifact_inventory_error', result)
            self.assertNotIn('artifact_sha256', result)
            return result
        inventory = result['artifact_sha256']
        for relative, digest in inventory.items():
            self.assertEqual(digest, layout.digest(self.output / relative))
        self.assertNotIn('RESULT.json', inventory)
        return result

    def test_complete_orchestration_has_exact_budget_evidence_and_denials(self):
        result = self.run_campaign()
        self.assertEqual(result['status'], 'completed')
        self.assertEqual((result['command_count'], result['compilation_count']), (24, 8))
        self.assertEqual(len(result['commands']), 24)
        self.assertEqual(len(self.native_calls), 24)
        deny_assertions(self, result)
        registration = read_json(self.output / 'REGISTRATION.json')
        deny_assertions(self, registration)
        self.assertEqual(registration['source'], self.state)
        self.assertEqual(registration['source_sha256'], self.bound)
        self.assertEqual((registration['maximum_commands'], registration['maximum_compilations']), (24, 8))
        self.assertEqual(result['registration_sha256'], layout.digest(self.output / 'REGISTRATION.json'))
        for name, tool in registration['tools'].items():
            self.assertEqual(tool['sha256'], layout.digest(self.tool_paths[name]))
            self.assertEqual(Path(tool['path']), self.tool_paths[name])
        for flag in ('source_unchanged', 'checker_unchanged', 'tools_unchanged',
                     'prepared_artifacts_unchanged', 'registration_unchanged', 'llvm_unchanged',
                     'recorded_binaries_unchanged', 'inventory_matches_recorded'):
            self.assertIs(result[flag], True, flag)
        for row in result['commands']:
            self.assertEqual(row['status'], 'completed')
            self.assertIs(row['stdout_complete'], True)
            self.assertIs(row['stderr_complete'], True)
            self.assertEqual(len(bytes.fromhex(row['stdout_hex'])), row['stdout_total_bytes'])
            self.assertEqual(len(bytes.fromhex(row['stderr_hex'])), row['stderr_total_bytes'])
        for workload, record in result['workloads'].items():
            self.assertEqual(set(record['objects']), set(ARMS))
            self.assertEqual(set(record['trace_objects']), set(ARMS))
            deny_assertions(self, record['observation'])
            for arm in ARMS:
                self.assertEqual(record['objects'][arm], record['trace_objects'][arm])
                for suffix in ('.o', '.trace.o', '.text.bin', '.asm', '.symbols', '.shrink-wrap.mir.txt'):
                    self.assertIn(workload + '/' + arm + suffix, result['artifact_sha256'])
                self.assertIn('R_X86_64_PLT32', (self.output / workload / (arm + '.asm')).read_text())
                self.assertIn('ShrinkWrap', (self.output / workload / (arm + '.shrink-wrap.mir.txt')).read_text())
        expected = {str(path.relative_to(self.output)): layout.digest(path)
                    for path in self.output.rglob('*') if path.is_file() and path.name != 'RESULT.json'}
        self.assertEqual(result['artifact_sha256'], expected)
        for tripwire in self.tripwires:
            tripwire.assert_not_called()
        self.assertTrue(all('-shared' not in argv for argv in self.native_calls))

    def test_equal_reference_candidate_bytes_complete_without_qualification(self):
        result = self.run_campaign()
        for record in result['workloads'].values():
            self.assertIs(record['observation']['object_equal'], True)
            self.assertIs(record['observation']['text_equal'], True)
            deny_assertions(self, record['observation'])
            self.assertIn('no speedup', record['observation']['interpretation'])

    def test_different_reference_candidate_bytes_complete_without_qualification(self):
        self.different_arms = self.different_text = True
        result = self.run_campaign()
        self.assertEqual(result['status'], 'completed')
        for record in result['workloads'].values():
            self.assertIs(record['observation']['object_equal'], False)
            self.assertIs(record['observation']['text_equal'], False)
            deny_assertions(self, record['observation'])
            self.assertIn('no speedup', record['observation']['interpretation'])

    def test_equal_text_is_not_confused_with_equal_objects(self):
        self.different_arms = True
        result = self.run_campaign()
        for record in result['workloads'].values():
            self.assertIs(record['observation']['object_equal'], False)
            self.assertIs(record['observation']['text_equal'], True)

    def test_candidate_only_trace_mismatch_fails_and_retains_both_objects(self):
        self.trace_mismatch = 'deferred'
        result = self.expect_failure('trace instrumentation changed object bytes: deferred')
        record = result['workloads']['linear']
        self.assertEqual(record['objects']['reference'], record['trace_objects']['reference'])
        self.assertNotEqual(record['objects']['deferred'], record['trace_objects']['deferred'])
        self.assertIn('linear/deferred.shrink-wrap.mir.txt', result['artifact_sha256'])

    def test_reference_only_trace_mismatch_fails_without_needing_candidate_trace(self):
        self.trace_mismatch = 'reference'
        result = self.expect_failure('trace instrumentation changed object bytes: reference')
        record = result['workloads']['linear']
        self.assertNotEqual(record['objects']['reference'], record['trace_objects']['reference'])
        self.assertNotIn('deferred', record['trace_objects'])
        self.assertIn('linear/reference.trace.o', result['artifact_sha256'])

    def test_compiler_nonzero_retains_stderr_and_stops_without_retry(self):
        def fail(argv):
            if '-c' in argv:
                return CaptureResult(7, '', 'synthetic compiler rejection', b'', b'synthetic compiler rejection')
        self.hook = fail
        result = self.expect_failure('diagnostic command failed')
        self.assertEqual(len(self.native_calls), 5)
        self.assertEqual(result['commands'][-1]['returncode'], 7)
        self.assertEqual(bytes.fromhex(result['commands'][-1]['stderr_hex']), b'synthetic compiler rejection')

    def capture_failure(self, code, reason, *, stdout_total=6):
        def fail(argv):
            if '-c' in argv:
                error = CaptureRejected(code, reason)
                error.capture = CaptureFailure(tuple(argv), -9, b'prefix', b'error', stdout_total, 5)
                raise error
        self.hook = fail
        result = self.expect_failure(reason)
        self.assertEqual(len(self.native_calls), 5)
        row = result['commands'][-1]
        self.assertEqual(row['status'], 'capture_failed')
        self.assertEqual(row['error']['code'], code)
        self.assertEqual(bytes.fromhex(row['stdout_hex']), b'prefix')
        return row

    def test_timeout_retains_bounded_failure_capture(self):
        self.capture_failure('E_CAPTURE_TIMEOUT', 'synthetic timeout')

    def test_output_limit_retains_prefix_and_marks_incomplete(self):
        row = self.capture_failure('E_CAPTURE_OUTPUT', 'synthetic output limit', stdout_total=16_000_001)
        self.assertIs(row['stdout_complete'], False)
        self.assertEqual(row['stdout_retained_bytes'], 6)
        self.assertEqual(row['stdout_total_bytes'], 16_000_001)

    def test_incomplete_successful_capture_fails_closed(self):
        logged = layout.native._run_logged
        def incomplete(argv, **kwargs):
            result = logged(argv, **kwargs)
            if '-c' in argv:
                kwargs['command_log'][-1]['stderr_complete'] = False
            return result
        with patch.object(layout.native, '_run_logged', side_effect=incomplete):
            result = self.expect_failure('output incomplete')
        self.assertIs(result['commands'][-1]['stderr_complete'], False)

    def test_missing_object_fails_with_available_evidence(self):
        self.missing_object = True
        result = self.expect_failure()
        self.assertEqual(len(self.native_calls), 5)
        self.assertIn('linear/reference.ll', result['artifact_sha256'])
        self.assertNotIn('linear/reference.o', result['artifact_sha256'])

    def test_empty_object_is_refused_without_native_execution(self):
        def empty(argv):
            if '-c' in argv:
                Path(argv[argv.index('-o') + 1]).write_bytes(b'')
                return CaptureResult(0, '', '', b'', b'')
        self.hook = empty
        result = self.expect_failure('nonempty')
        self.assertEqual(result['compilation_count'], 1)
        self.assertIn('linear/reference.o', result['artifact_sha256'])

    def test_oversized_object_is_refused_before_unbounded_artifact_read(self):
        # Lower the read policy rather than creating a 64 MiB fixture. The
        # native bounded reader still checks the actual produced file size.
        with patch.object(layout.native, 'MAX_ARTIFACT_BYTES', 8):
            result = self.expect_failure('evidence_byte_limit')
        self.assertEqual(result['compilation_count'], 1)
        self.assertGreater((self.output / 'linear/reference.o').stat().st_size, 8)
        self.assertIn('linear/reference.o', result['artifact_sha256'])

    def test_symlink_object_is_not_treated_as_an_owned_regular_artifact(self):
        def symlink(argv):
            if '-c' in argv:
                Path(argv[argv.index('-o') + 1]).symlink_to(self.tool_paths['clang'])
                return CaptureResult(0, '', '', b'', b'')
        self.hook = symlink
        result = self.expect_failure('nonordinary_or_linked_file', inventory_refused=True)
        self.assertEqual(result['compilation_count'], 1)

    def test_missing_trace_object_fails_with_mir_and_untraced_object_retained(self):
        def missing(argv):
            if '-print-before=shrink-wrap' in argv:
                return CaptureResult(0, '', 'synthetic MIR', b'', b'synthetic MIR')
        self.hook = missing
        result = self.expect_failure()
        self.assertIn('linear/reference.o', result['artifact_sha256'])
        self.assertIn('linear/reference.shrink-wrap.mir.txt', result['artifact_sha256'])
        self.assertNotIn('linear/reference.trace.o', result['artifact_sha256'])

    def test_missing_text_section_fails_with_object_retained(self):
        self.missing_section = True
        result = self.expect_failure()
        self.assertEqual(len(self.native_calls), 6)
        self.assertIn('linear/reference.o', result['artifact_sha256'])
        self.assertNotIn('linear/reference.text.bin', result['artifact_sha256'])

    def test_unexpected_exception_is_failed_not_reconstructed_success(self):
        def fail(argv):
            if '-c' in argv:
                raise RuntimeError('synthetic unexpected exception')
        self.hook = fail
        result = self.expect_failure('synthetic unexpected exception')
        self.assertEqual(result['error']['type'], 'RuntimeError')
        self.assertEqual(result['commands'][-1]['status'], 'capture_failed')

    def test_wrong_clang_major_stops_before_compiling(self):
        self.compiler_version = 'clang version 21.0.1 synthetic\n'
        result = self.expect_failure('Clang major 20')
        self.assertEqual((result['command_count'], result['compilation_count']), (1, 0))

    def test_post_run_source_hash_mutation_fails(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                self.bound['tests/synthetic-source.py'] = 'c' * 64
        self.hook = mutate
        result = self.expect_failure('final identity')
        self.assertIs(result['source_unchanged'], False)

    def test_post_run_head_mutation_fails(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                self.state['head'] = 'different-head'
        self.hook = mutate
        result = self.expect_failure('final identity')
        self.assertIs(result['source_unchanged'], False)

    def test_post_run_tool_mutation_fails(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                self.tool_paths['clang'].write_bytes(b'changed-tool')
        self.hook = mutate
        result = self.expect_failure('final identity')
        self.assertIs(result['tools_unchanged'], False)

    def test_post_run_checker_mutation_fails(self):
        with patch.object(layout, 'deferred_guard_checker_identity', side_effect=
                          lambda: ('b' if len(self.native_calls) == 24 else 'a') * 64):
            result = self.expect_failure('final identity')
        self.assertIs(result['checker_unchanged'], False)

    def test_post_run_prepared_core_mutation_fails_and_is_inventoried(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                (self.output / 'linear/deferred.core.json').write_text('{}')
        self.hook = mutate
        result = self.expect_failure('final identity')
        self.assertIs(result['prepared_artifacts_unchanged'], False)
        self.assertIn('linear/deferred.core.json', result['artifact_sha256'])

    def test_late_object_mutation_cannot_leave_completed_stale_observation(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                (self.output / 'linear/reference.o').write_bytes(b'late-changed-object')
        self.hook = mutate
        result = self.expect_failure('final identity')
        self.assertNotEqual(result['workloads']['linear']['objects']['reference'],
                            result['artifact_sha256']['linear/reference.o'])

    def test_late_text_section_mutation_is_failed(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                (self.output / 'linear/deferred.text.bin').write_bytes(b'late-changed-text')
        self.hook = mutate
        self.expect_failure('final identity')

    def test_late_trace_object_mutation_is_failed(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                (self.output / 'linear/deferred.trace.o').write_bytes(b'late-changed-trace')
        self.hook = mutate
        self.expect_failure('final identity')

    def test_registration_mutation_fails(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                (self.output / 'REGISTRATION.json').write_text('{}')
        self.hook = mutate
        result = self.expect_failure('final identity')
        self.assertIs(result['registration_unchanged'], False)

    def test_ir_changed_after_registration_never_reaches_compiler(self):
        def mutate(argv):
            if len(self.native_calls) == 4:
                (self.output / 'linear/reference.ll').write_text('; unauthorized IR\n')
        self.hook = mutate
        result = self.expect_failure('LLVM changed before compilation')
        self.assertEqual(result['compilation_count'], 0)
        self.assertIs(result['llvm_unchanged'], False)

    def test_inventory_cannot_silently_hash_a_new_version_after_final_checks(self):
        snapshot = layout.snapshot_tree
        reads = []
        target = self.output / 'linear/reference.core.json'
        def change_on_inventory(root, allowed):
            reads.append(root)
            # Registration snapshots first. Final inventory snapshots second,
            # after prepared hashes and binary identities were rechecked.
            if len(reads) == 2:
                target.write_text('{"synthetic": "changed during inventory"}')
            return snapshot(root, allowed)
        with patch.object(layout, 'snapshot_tree', side_effect=change_on_inventory):
            result = self.expect_failure('final identity')
        self.assertEqual(len(reads), 2)
        self.assertIs(result['prepared_artifacts_unchanged'], True)
        self.assertIs(result['inventory_matches_recorded'], False)

    def test_final_identity_read_error_remains_failed_and_keeps_inventory(self):
        def mutate(argv):
            if len(self.native_calls) == 24:
                self.tool_paths['clang'].unlink()
        self.hook = mutate
        result = self.expect_failure('final identity')
        self.assertIn('final_identity_error', result)
        self.assertIn('affine/deferred.trace.o', result['artifact_sha256'])

    def test_source_changed_during_preparation_has_zero_native_calls(self):
        def prepare(output):
            result = self.synthetic_prepare(output)
            self.bound['tests/synthetic-source.py'] = 'c' * 64
            return result
        self.prepare_mock.side_effect = prepare
        result = self.expect_failure('source/checker changed before compilation')
        self.assertEqual(result['commands'], [])
        self.capture_mock.assert_not_called()

    def test_second_workload_preparation_failure_prevents_even_version_command(self):
        def prepare(output):
            self.synthetic_prepare(output)
            raise ValueError('affine fresh proof failed')
        self.prepare_mock.side_effect = prepare
        result = self.expect_failure('affine fresh proof failed')
        self.assertIn('linear/reference.ll', result['artifact_sha256'])
        self.assertEqual(result['commands'], [])
        self.capture_mock.assert_not_called()

    def test_dirty_checkout_fails_before_preparation_and_native_calls(self):
        self.state['status'] = ' M hepta/hia_program.py\n'
        self.expect_failure('clean exact source')
        self.prepare_mock.assert_not_called()
        self.capture_mock.assert_not_called()

    def test_missing_tool_fails_before_native_calls(self):
        with patch.object(layout.shutil, 'which', side_effect=lambda name:
                          None if name == 'nm' else str(self.tool_paths['clang' if name == 'clang-20' else name])):
            self.expect_failure('required existing tool unavailable: nm')
        self.capture_mock.assert_not_called()

    def test_existing_output_is_refused_without_altering_existing_data(self):
        self.output.mkdir()
        (self.output / 'untouched.txt').write_text('existing evidence')
        with self.assertRaises(FileExistsError):
            self.run_campaign()
        self.assertEqual((self.output / 'untouched.txt').read_text(), 'existing evidence')
        self.assertEqual(list(self.output.iterdir()), [self.output / 'untouched.txt'])
        self.prepare_mock.assert_not_called()
        self.capture_mock.assert_not_called()

    def test_output_in_checkout_and_symlink_into_checkout_are_refused(self):
        checkout = self.temporary / 'source'
        checkout.mkdir()
        alias = self.temporary / 'source-alias'
        alias.symlink_to(checkout, target_is_directory=True)
        with patch.object(layout, 'ROOT', checkout):
            for output in (checkout, checkout / 'evidence', alias / 'evidence'):
                with self.subTest(output=output), self.assertRaisesRegex(ValueError, 'outside the source checkout'):
                    layout.run(output, 'clang-20')
        self.assertEqual(list(checkout.iterdir()), [])
        self.capture_mock.assert_not_called()

    def test_command_budget_overrun_fails_at_boundary_with_no_extra_subprocess(self):
        with patch.object(layout, 'MAX_COMMANDS', 23):
            result = self.expect_failure('command budget')
        self.assertEqual(len(self.native_calls), 23)
        self.assertEqual(result['command_count'], 23)

    def test_compile_budget_overrun_fails_at_boundary_with_no_ninth_compile(self):
        with patch.object(layout, 'MAX_COMPILATIONS', 7):
            result = self.expect_failure('command budget')
        self.assertEqual(result['compilation_count'], 7)
        self.assertEqual(sum('-c' in argv for argv in self.native_calls), 7)


class ExecutorBudgetTests(unittest.TestCase):
    def test_twenty_fifth_command_is_never_dispatched(self):
        with tempfile.TemporaryDirectory() as directory:
            result = {'status': 'running', 'commands': []}
            executor = layout.Executor(Path(directory), result)
            with patch.object(layout.native, '_run_logged', return_value=CaptureResult(0, '', '')) as native:
                for _ in range(24):
                    executor.execute(['synthetic-tool', '--version'])
                with self.assertRaisesRegex(ValueError, 'command budget'):
                    executor.execute(['synthetic-tool', '--version'])
                self.assertEqual(native.call_count, 24)
            self.assertEqual((executor.commands, executor.compilations), (24, 0))

    def test_ninth_compile_is_never_dispatched_even_with_command_budget_remaining(self):
        with tempfile.TemporaryDirectory() as directory:
            result = {'status': 'running', 'commands': []}
            executor = layout.Executor(Path(directory), result)
            with patch.object(layout.native, '_run_logged', return_value=CaptureResult(0, '', '')) as native:
                for _ in range(8):
                    executor.execute(layout.command('synthetic-clang', 'arm.ll', 'arm.o'))
                with self.assertRaisesRegex(ValueError, 'command budget'):
                    executor.execute(layout.command('synthetic-clang', 'arm.ll', 'arm.o'))
                self.assertEqual(native.call_count, 8)
            self.assertEqual((executor.commands, executor.compilations), (8, 8))


@unittest.skipUnless(PINNED_SOLVER, 'pinned Z3 4.15.4 required for actual fresh preparation')
class FreshPreparationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.output = self.temporary / 'evidence'
        self.native = self.stack.enter_context(patch.object(layout.native, '_run_logged',
            side_effect=AssertionError('preparation must not invoke native tools')))
        self.tripwires = production_tripwires(self.stack)
        self.state = {'head': 'test-head', 'tree': 'test-tree', 'status': ''}
        self.stack.enter_context(patch.object(layout, 'source_state', return_value=self.state))
        self.stack.enter_context(patch.object(layout, 'bindings', return_value={'test': 'a' * 64}))

    def fail_before_native(self, pattern=None):
        context = self.assertRaisesRegex(Exception, pattern) if pattern else self.assertRaises(Exception)
        with context:
            layout.run(self.output, 'never-invoke-clang')
        result = read_json(self.output / 'RESULT.json')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['commands'], [])
        self.assertEqual((result['command_count'], result['compilation_count']), (0, 0))
        deny_assertions(self, result)
        self.native.assert_not_called()
        return result

    def test_actual_fixtures_emit_reproducible_llvm_bound_to_fresh_checks(self):
        outputs, prepared = [], []
        for index in range(2):
            output = self.temporary / ('prepare-' + str(index))
            output.mkdir()
            outputs.append(output)
            prepared.append(layout.prepare(output))
        for workload in WORKLOADS:
            directory = outputs[0] / workload
            proposal = read_json(directory / 'PROPOSAL.json')
            check = read_json(directory / 'CHECK.json')
            base = lower_source((layout.ROOT / 'benchmarks/hia_reduction_release' / (workload + '.hepta')).read_text())
            independent = checker.check_deferred_guard(base, proposal)
            self.assertEqual(independent['status'], 'checked', independent)
            self.assertEqual(check['status'], 'checked', check)
            self.assertEqual(check['proposal_sha256'], _digest(proposal))
            self.assertEqual(check['checker_sha256'], checker.deferred_guard_checker_identity())
            for field in ('base_sha256', 'candidate_sha256', 'reference_sha256', 'proposal_sha256'):
                self.assertEqual(check[field], independent[field])
            # The release maximum is generated normally, never the VM-test 4.
            expected = layout.propose_reduction_pipeline(base, include_induction=True)
            self.assertEqual(proposal['reduction']['guarded']['guards'], expected['guarded']['guards'])
            self.assertNotEqual(proposal['reduction']['guarded']['guards'][0]['maximum'], 4)
            for arm in ARMS:
                ir = prepared[0][workload][arm]
                self.assertIsInstance(ir, layout.native.HIAProgramLLVM)
                self.assertEqual(ir, prepared[1][workload][arm])
                core_path = directory / (arm + '.core.json')
                core = verify_program(read_json(core_path))
                self.assertEqual(core_path.read_bytes(), core.canonical_bytes)
                self.assertEqual(ir.core_sha256, core.sha256)
                self.assertEqual(core.sha256, check['reference_sha256' if arm == 'reference' else 'candidate_sha256'])
                self.assertEqual(ir.sha256, layout.digest(directory / (arm + '.ll')))
                self.assertEqual(ir.exports, ('calculate',))
                metadata = read_json(directory / (arm + '.llvm.json'))
                self.assertEqual(metadata['core_sha256'], ir.core_sha256)
                self.assertEqual(metadata['llvm_sha256'], ir.sha256)
                self.assertEqual(metadata['exports'], list(ir.exports))
                self.assertEqual(metadata['target'], ir.target)
                self.assertEqual(metadata['implementation_sha256'], ir.implementation_sha256)
                self.assertEqual(metadata['input_sha256'], ir.input_sha256)
                deny_assertions(self, metadata)
                for suffix in ('.core.json', '.ll', '.llvm.json'):
                    self.assertEqual((outputs[0] / workload / (arm + suffix)).read_bytes(),
                                     (outputs[1] / workload / (arm + suffix)).read_bytes())
                self.assertNotIn('alwaysinline', ir.text)
                self.assertNotIn('noinline', ir.text)
        self.native.assert_not_called()
        for tripwire in self.tripwires:
            tripwire.assert_not_called()

    def test_fresh_checker_rejected_or_unknown_never_invokes_native_tools(self):
        for status in ('rejected', 'unknown'):
            with self.subTest(status=status):
                self.output = self.temporary / status
                with patch.object(layout, 'check_deferred_guard', return_value={
                        'status': status, 'reason': 'synthetic fresh proof refusal'}):
                    self.fail_before_native('fresh independent deferred check')

    def test_stale_source_candidate_reference_checker_or_proposal_report_hash_fails(self):
        real_check = layout.check_deferred_guard
        for field in ('base_sha256', 'candidate_sha256', 'reference_sha256',
                      'checker_sha256', 'proposal_sha256'):
            with self.subTest(field=field):
                self.output = self.temporary / field
                def stale(base, proposal, field=field):
                    result = real_check(base, proposal)
                    self.assertEqual(result['status'], 'checked', result)
                    result[field] = '0' * 64
                    return result
                with patch.object(layout, 'check_deferred_guard', side_effect=stale):
                    self.fail_before_native()

    def test_missing_solver_cannot_turn_into_unchecked_compilation(self):
        with patch.dict('sys.modules', {'z3': None}):
            result = self.fail_before_native('fresh independent deferred check')
        check = read_json(self.output / 'linear/CHECK.json')
        self.assertEqual(check['status'], 'unknown')
        self.assertFalse(check['claims']['fresh_reduction_proofs_checked'])
        self.assertIn('linear/CHECK.json', result['artifact_sha256'])

    def test_unknown_solver_or_invalid_fresh_proof_is_not_accepted(self):
        for status in ('unknown', 'rejected'):
            with self.subTest(status=status):
                self.output = self.temporary / status
                with patch.object(checker, '_verify_frozen', return_value=(
                        {'status': status, 'reason': 'synthetic solver refusal'}, None)):
                    self.fail_before_native('fresh independent deferred check')
                check = read_json(self.output / 'linear/CHECK.json')
                self.assertEqual(check['status'], status)
                self.assertFalse(check['claims']['fresh_reduction_proofs_checked'])

    def test_malformed_primitive_core_fails_before_native_tools(self):
        propose = layout.propose_deferred_guard
        def malformed(base, reduction):
            proposal = propose(base, reduction)
            proposal['candidate_core']['functions'][0]['blocks'][0]['term'] = {'op': 'not-core'}
            return proposal
        with patch.object(layout, 'propose_deferred_guard', side_effect=malformed):
            self.fail_before_native('fresh independent deferred check')

    def test_stale_source_bound_proposal_fails_before_native_tools(self):
        propose = layout.propose_deferred_guard
        def stale(base, reduction):
            proposal = propose(base, reduction)
            proposal['base_sha256'] = '0' * 64
            return proposal
        with patch.object(layout, 'propose_deferred_guard', side_effect=stale):
            self.fail_before_native('fresh independent deferred check')

    def test_subclass_and_cyclic_proposals_are_not_accepted_as_wire_data(self):
        propose = layout.propose_deferred_guard
        class DictSubclass(dict):
            pass
        for cyclic in (False, True):
            self.output = self.temporary / ('cycle' if cyclic else 'subclass')
            def malformed(base, reduction):
                proposal = propose(base, reduction)
                if cyclic:
                    proposal['cycle'] = proposal
                    return proposal
                return DictSubclass(proposal)
            with self.subTest(cyclic=cyclic), patch.object(layout, 'propose_deferred_guard', side_effect=malformed):
                self.fail_before_native()

    def test_checker_input_mutation_after_check_cannot_modify_frozen_candidate(self):
        real_check = layout.check_deferred_guard
        checked_hashes = []
        def mutate(base, proposal):
            report = real_check(base, proposal)
            self.assertEqual(report['status'], 'checked', report)
            checked_hashes.append(report['candidate_sha256'])
            proposal['candidate_core']['module'] = 'mutated_after_check'
            return report
        self.output.mkdir()
        with patch.object(layout, 'check_deferred_guard', side_effect=mutate):
            prepared = layout.prepare(self.output)
        for workload, expected in zip(WORKLOADS, checked_hashes):
            self.assertEqual(prepared[workload]['deferred'].core_sha256, expected)
            self.assertNotEqual(read_json(self.output / workload / 'deferred.core.json')['module'], 'mutated_after_check')
        self.native.assert_not_called()

    def test_actual_frozen_candidate_mutated_after_check_is_rejected(self):
        real_decode, real_check = layout._decode, layout.check_deferred_guard
        frozen = []
        def remember_wire(value):
            decoded = real_decode(value)
            if not frozen:
                frozen.append(decoded[0])
            return decoded
        def mutate_frozen(base, proposal):
            report = real_check(base, proposal)
            self.assertEqual(report['status'], 'checked', report)
            frozen[0]['candidate_core']['module'] = 'frozen_candidate_changed_after_check'
            return report
        with patch.object(layout, '_decode', side_effect=remember_wire), \
             patch.object(layout, 'check_deferred_guard', side_effect=mutate_frozen):
            self.fail_before_native('source/candidate/reference mismatch')

    def test_reference_reconstruction_must_freshly_verify(self):
        for status in ('unknown', 'rejected'):
            self.output = self.temporary / status
            with self.subTest(status=status), patch.object(layout, '_verify_frozen',
                    return_value=({'status': status, 'reason': 'synthetic fresh reference refusal'}, None)):
                result = self.fail_before_native('fresh reference proof refused')
            self.assertIn('linear/REFERENCE_PROOF.json', result['artifact_sha256'])

    def test_reference_reconstruction_proof_identities_must_match_actual_frozen_core(self):
        verify = layout._verify_frozen
        for field in ('base_sha256', 'candidate_sha256', 'narrowed_sha256', 'proposal_sha256', 'checker_sha256'):
            self.output = self.temporary / field
            def stale(*args, field=field, **kwargs):
                proof, program = verify(*args, **kwargs)
                self.assertEqual(proof['status'], 'verified', proof)
                proof[field] = '0' * 64
                return proof, program
            with self.subTest(field=field), patch.object(layout, '_verify_frozen', side_effect=stale):
                self.fail_before_native()

    def test_proposer_owned_input_is_detached_before_checker_observes_it(self):
        real_propose, real_check = layout.propose_deferred_guard, layout.check_deferred_guard
        caller_owned = []
        def propose(base, reduction):
            proposal = real_propose(base, reduction)
            caller_owned.append(proposal)
            return proposal
        def mutate_caller(base, proposal):
            caller_owned[-1]['candidate_core']['module'] = 'caller_changed_during_check'
            return real_check(base, proposal)
        self.output.mkdir()
        with patch.object(layout, 'propose_deferred_guard', side_effect=propose), \
             patch.object(layout, 'check_deferred_guard', side_effect=mutate_caller):
            layout.prepare(self.output)
        for workload in WORKLOADS:
            self.assertNotEqual(read_json(self.output / workload / 'PROPOSAL.json')['candidate_core']['module'],
                                'caller_changed_during_check')
        self.native.assert_not_called()

    def test_affine_actual_check_failure_prevents_linear_native_version_or_compile(self):
        real_check = layout.check_deferred_guard
        calls = []
        def fail_second(base, proposal):
            calls.append(base.sha256)
            if len(calls) == 2:
                return {'status': 'unknown', 'reason': 'affine synthetic proof unknown'}
            return real_check(base, proposal)
        with patch.object(layout, 'check_deferred_guard', side_effect=fail_second):
            result = self.fail_before_native('fresh independent deferred check')
        self.assertEqual(len(calls), 2)
        self.assertIn('linear/reference.ll', result['artifact_sha256'])
        self.assertIn('affine/CHECK.json', result['artifact_sha256'])

    def test_checker_identity_change_during_preparation_fails_before_native_tools(self):
        identity = checker.deferred_guard_checker_identity()
        with patch.object(layout, 'deferred_guard_checker_identity', side_effect=
                          [identity, identity, '0' * 64, '0' * 64]):
            self.fail_before_native('checker changed during preparation')

    def test_wrong_emitted_core_text_source_implementation_target_or_exports_is_rejected(self):
        emit = layout.native.emit_program_llvm
        for field, wrong in (('core_sha256', '0' * 64), ('sha256', '0' * 64),
                             ('input_sha256', '0' * 64), ('implementation_sha256', '0' * 64),
                             ('target', 'aarch64-unknown-linux-gnu'), ('exports', ('wrong_export',))):
            self.output = self.temporary / field
            def forged(core, field=field, wrong=wrong):
                return replace(emit(core), **{field: wrong})
            with self.subTest(field=field), patch.object(layout.native, 'emit_program_llvm', side_effect=forged):
                self.fail_before_native('emitted LLVM identity mismatch')


if __name__ == '__main__':
    unittest.main()
