"""Compile-only diagnostic cannot become a release timing verdict."""
import unittest
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from tools import diagnose_hia_reduction_layout as layout
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline, reduction_program
from hepta.hia_program_llvm import emit_program_llvm


class LayoutDiagnosticTests(unittest.TestCase):
    def test_default_flags_preserve_production_object_profile(self):
        self.assertEqual(layout.command('clang', 'same.ll', 'out.o', 'default'),
            ['clang', '--target=x86_64-unknown-linux-gnu', '-x', 'ir', '-O3', '-fPIC', '-c', 'same.ll', '-o', 'out.o'])

    def test_only_registered_shrink_wrap_switch_changes(self):
        default = layout.command('clang', 'same.ll', 'out.o', 'default')
        for arm, value in [('shrink_wrap_on', 'true'), ('shrink_wrap_off', 'false')]:
            command = layout.command('clang', 'same.ll', 'out.o', arm)
            self.assertEqual(command[:7] + command[9:], default)
            self.assertEqual(command[7:9], ['-mllvm', '-enable-shrink-wrap=' + value])
        with self.assertRaises(ValueError): layout.command('c', 'i', 'o', 'arbitrary-flag')

    def test_trace_is_separate_and_preserves_same_arm(self):
        command = layout.command('clang', 'same.ll', 'out.o', 'default', trace=True)
        self.assertEqual(command[7:11], layout.TRACE_FLAGS)
        self.assertNotIn('-enable-shrink-wrap=true', command)

    def test_identical_objects_retain_negative_outcome_without_timing(self):
        hashes = {arm: 'same' for arm in layout.ARMS}
        result = layout.equivalence(hashes, hashes, 'same')
        self.assertTrue(all(result['object_equal_to_default'].values()))
        self.assertFalse(result['performance_qualified'])
        self.assertFalse(result['timing_performed'])

    def test_equal_text_is_not_object_equivalence(self):
        hashes = {arm: 'same' for arm in layout.ARMS}
        different = {**hashes, 'shrink_wrap_off': 'different relocation or metadata'}
        result = layout.equivalence(different, hashes, 'trace changed')
        self.assertFalse(result['object_equal_to_default']['shrink_wrap_off'])
        self.assertTrue(result['text_equal_to_default']['shrink_wrap_off'])
        self.assertFalse(result['trace_object_equal_to_default'])

    def test_missing_arm_is_rejected(self):
        with self.assertRaises(ValueError): layout.equivalence({'default': 'x'}, {}, 'x')

    def test_common_sink_profile_changes_only_its_one_flag(self):
        default = layout.command('clang', 'same.ll', 'out.o', 'default', profile='common-sink')
        self.assertEqual(default, layout.command('clang', 'same.ll', 'out.o', 'default'))
        candidate = layout.command('clang', 'same.ll', 'out.o', 'common_sink_off', profile='common-sink')
        self.assertEqual(candidate[:7] + candidate[9:], default)
        self.assertEqual(candidate[7:9], ['-mllvm', '-simplifycfg-sink-common=false'])
        with self.assertRaises(ValueError):
            layout.command('clang', 'same.ll', 'out.o', 'common_sink_off')
        with self.assertRaises(ValueError):
            layout.command('clang', 'same.ll', 'out.o', 'default', profile='unregistered')

    def test_common_sink_requires_its_complete_separate_inventory(self):
        same = {arm: 'same' for arm in layout.PROFILES['common-sink']}
        result = layout.equivalence(same, same, 'same', profile='common-sink')
        self.assertTrue(result['object_equal_to_default']['common_sink_off'])
        self.assertFalse(result['performance_qualified'])
        with self.assertRaises(ValueError):
            layout.equivalence(same, same, 'same')
        with self.assertRaises(ValueError):
            layout.equivalence(same, same, 'same', profile='unregistered')

    def test_common_sink_candidate_trace_mismatch_fails_run_and_is_retained(self):
        # Synthetic compiler only tests orchestration. No native result is claimed.
        state = {'head': 'test-only', 'tree': 'test-only', 'status': ''}
        def fake_command(argv, *, command_log, **kwargs):
            command_log.append({'argv': argv, 'returncode': 0, 'status': 'synthetic-test'})
            if '-c' in argv:
                output = Path(argv[argv.index('-o') + 1])
                output.write_bytes(b'changed-trace' if output.name == 'common_sink_off.trace.o' else b'same-object')
            elif '--only-section=.text' in argv:
                Path(argv[-1]).write_bytes(b'same-text')
            return SimpleNamespace(returncode=0, stdout='clang version 20.1.8 test-double', stderr='synthetic MIR')
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(layout, 'source_state', return_value=state), \
                patch.object(layout, 'bindings', return_value={}), \
                patch.object(layout.shutil, 'which', return_value=sys.executable), \
                patch.object(layout.native, '_run_logged', side_effect=fake_command):
            output = Path(temporary) / 'evidence'
            with self.assertRaisesRegex(ValueError, 'trace instrumentation changed object bytes'):
                layout.run(output, sys.executable, profile='common-sink')
            result = json.loads((output / 'RESULT.json').read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertFalse(result['performance_qualified'])
            self.assertFalse(result['timing_performed'])
            self.assertEqual(result['authority'], 'DENY_ALL')
            self.assertIn('linear/common_sink_off.trace.o', result['artifact_sha256'])
            self.assertNotEqual(result['workloads']['linear']['trace_objects']['common_sink_off'],
                                result['workloads']['linear']['objects']['common_sink_off'])

    def test_both_workloads_use_fresh_production_core_without_wrapper(self):
        for workload in ('linear', 'affine'):
            with self.subTest(workload=workload):
                original = lower_source((layout.ROOT / 'benchmarks/hia_reduction_release' / (workload + '.hepta')).read_text())
                proposal = propose_reduction_pipeline(original, include_induction=True)
                program = reduction_program(original, proposal)
                ir = emit_program_llvm(program)
                self.assertEqual(ir.core_sha256, program.sha256)
                self.assertNotIn('%is_empty', ir.text)
                self.assertNotIn('noinline', ir.text)
                self.assertNotIn('alwaysinline', ir.text)
                self.assertIn('define i64 @calculate(', ir.text)

if __name__ == '__main__': unittest.main()
