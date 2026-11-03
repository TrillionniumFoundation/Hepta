"""Finite exporter/admission controls, not evidence of Lean kernel acceptance.

All checker invocations in this module are mocked. No Lean, native execution,
installation, publication, or production authority is exercised here.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from tests.test_dynamic_unsigned_step import alpha_rename, step_program
from tools.check_dynamic_unsigned_step import extract_step_slices
from tools import check_guarded_slice_lean as proof


class GuardedSliceExporterTests(unittest.TestCase):
    def hint(self, program):
        extracted = extract_step_slices(program)
        self.assertEqual(extracted['status'], 'extracted', extracted)
        self.assertEqual(len(extracted['slices']), 1)
        return extracted['slices'][0]

    def test_negative_inputs_do_not_print_axioms_of_failed_declarations(self):
        prepared = proof.build_inputs()
        self.assertIn('#print axioms', prepared['positive'])
        for mutation in prepared['negatives'].values():
            self.assertNotIn('#print axioms', mutation['source'])

    def test_actual_checked_and_wrapping_operations_are_exported(self):
        for mode, expected in (('checked', 'checked'), ('wrap', 'wrapping')):
            with self.subTest(mode=mode):
                program = step_program(mode=mode)
                exported = proof.export_descriptor(program, self.hint(program))
                descriptor = exported['descriptor']
                self.assertEqual(exported['core_sha256'], verify_program(program).sha256)
                self.assertEqual(descriptor['compareOp'], 'lt')
                self.assertEqual(descriptor['addOp'], expected)
                self.assertEqual(descriptor['literalValue'], 1)
                self.assertEqual(descriptor['incoming'][descriptor['indexSlot']], descriptor['sourceIndex'])
                self.assertEqual(descriptor['incoming'][descriptor['extentSlot']], descriptor['sourceExtent'])
                self.assertEqual(descriptor['branchCondition'], descriptor['compareOutput'])
                self.assertLess(descriptor['literalOrdinal'], descriptor['addOrdinal'])

    def test_real_core_mutations_are_decoded_not_repaired_from_stale_hint(self):
        original = step_program()
        hint = self.hint(original)
        cases = [
            ('wrong_phi', step_program(phi='extent'),
             lambda d: d['incoming'][d['indexSlot']] != d['sourceIndex']),
            ('literal_two', step_program(step=2), lambda d: d['literalValue'] == 2),
            ('inclusive_compare', step_program(compare='compare.le'), lambda d: d['compareOp'] == 'le'),
            ('signed', step_program(typ='i64'), lambda d: d['indexType'] == 'other'),
        ]
        changed_condition = deepcopy(original)
        function = changed_condition['functions'][0]
        function['params'].append({'name': 'other_condition', 'type': 'bool'})
        function['blocks'][0]['params'].append({'name': 'other_condition', 'type': 'bool'})
        function['blocks'][0]['term']['cond'] = 'other_condition'
        cases.append(('wrong_condition', changed_condition,
                      lambda d: d['branchCondition'] != d['compareOutput']))
        for label, program, check in cases:
            with self.subTest(label=label):
                checked = verify_program(program)
                result = proof.export_descriptor(checked, hint)
                self.assertTrue(check(result['descriptor']), result)
                self.assertEqual(result['core_sha256'], checked.sha256)
                self.assertNotEqual(result['core_sha256'], verify_program(original).sha256)

    def test_alpha_renaming_preserves_positional_relationships(self):
        original = step_program()
        renamed = alpha_rename(original)
        left = proof.export_descriptor(original, self.hint(original))
        right = proof.export_descriptor(renamed, self.hint(renamed))
        self.assertNotEqual(left['core_sha256'], right['core_sha256'])
        self.assertEqual(left['descriptor'], right['descriptor'])

    def test_forged_hint_operations_cannot_change_actual_descriptor(self):
        program = step_program()
        hint = self.hint(program)
        expected = proof.export_descriptor(program, hint)
        hint['compare']['op'] = 'compare.le'
        hint['step']['op'] = 'int.sub.wrap'
        hint['condition'] = 'invented'
        hint['index'] = 'extent'
        hint['extent'] = 'index'
        hint['bindings'] = []
        actual = proof.export_descriptor(program, hint)
        self.assertEqual(actual['descriptor'], expected['descriptor'])
        self.assertEqual(actual['core_sha256'], expected['core_sha256'])

    def test_reordered_target_slots_retain_actual_simultaneous_mapping(self):
        program = step_program()
        function = program['functions'][0]
        function['blocks'][0]['term']['then']['args'].reverse()
        function['blocks'][1]['params'].reverse()
        verify_program(program)
        result = proof.export_descriptor(program, self.hint(program))
        descriptor = result['descriptor']
        self.assertEqual(descriptor['indexSlot'], 1)
        self.assertEqual(descriptor['extentSlot'], 0)
        self.assertEqual(descriptor['incoming'][1], descriptor['sourceIndex'])
        self.assertEqual(descriptor['incoming'][0], descriptor['sourceExtent'])
        self.assertEqual(descriptor['addIndexSlot'], 1)

    def test_manifest_does_not_alias_mutable_hint_or_input(self):
        program = step_program()
        hint = self.hint(program)
        result = proof.export_descriptor(program, hint)
        saved = deepcopy(result)
        hint['compare']['op'] = 'compare.le'
        program['functions'][0]['blocks'][1]['ops'][0]['attrs']['value'] = 999
        self.assertEqual(result, saved)

    def test_unknown_source_location_is_rejected(self):
        program = step_program()
        hint = self.hint(program)
        for field, bad in (('function', 'missing'), ('header', 'missing'),
                           ('target', 'missing'), ('compare_ordinal', 999),
                           ('step_ordinal', 999), ('body_index', 'missing'),
                           ('body_extent', 'missing')):
            with self.subTest(field=field):
                changed = {**hint, field: bad}
                with self.assertRaises((ValueError, KeyError, IndexError, StopIteration)):
                    proof.export_descriptor(program, changed)


class GuardedSliceAdmissionTests(unittest.TestCase):
    def test_unpinned_fake_checker_is_rejected_before_execution_or_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            executable = root / 'lean'
            marker = root / 'executed'
            executable.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
            executable.chmod(0o755)
            with patch.object(proof, '_run_lean', side_effect=AssertionError('executed')) as run:
                with self.assertRaisesRegex(ValueError, 'pinned Lean binary'):
                    proof.qualify(executable, root / 'output')
            run.assert_not_called()
            self.assertFalse(marker.exists())
            self.assertFalse((root / 'output').exists())

    def test_missing_support_is_rejected_before_preparation_or_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            executable = root / 'fake-lean'
            executable.write_bytes(b'mock-only checker')
            pinned = json.loads((proof.ROOT / 'formal/toolchain-lock.json').read_text())['lean_binary_sha256']
            original_digest = proof.digest
            def digest(data):
                return pinned if data == b'mock-only checker' else original_digest(data)
            with patch.object(proof, 'digest', side_effect=digest), \
                 patch.object(proof, '_support_identity', side_effect=FileNotFoundError('mock missing support')), \
                 patch.object(proof, 'build_inputs') as build, \
                 patch.object(proof, '_run_lean') as run:
                with self.assertRaises(FileNotFoundError):
                    proof.qualify(executable, root / 'output')
            build.assert_not_called()
            run.assert_not_called()
            self.assertFalse((root / 'output').exists())

    def test_source_identity_binds_exporter_model_and_lock_bytes(self):
        identity = proof.source_identity()
        for name in ('tools/check_guarded_slice_lean.py', str(proof.MODEL.relative_to(proof.ROOT)),
                     'formal/HiaInitializationPrefix.lean', 'formal/toolchain-lock.json'):
            self.assertIn(name, identity)
            self.assertEqual(identity[name], sha256((proof.ROOT / name).read_bytes()).hexdigest())


class GuardedSliceGeneratedInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = proof.build_inputs()

    def test_each_real_slice_has_fixed_validation_and_nonvacuity_theorems(self):
        prepared = self.prepared
        self.assertEqual(len(prepared['manifests']), 9)
        self.assertEqual(len(prepared['expected_theorems']), 56)
        for workload in ('linear', 'affine'):
            for number in range(4):
                for suffix in ('valid', 'small', 'upper'):
                    name = f'{workload}_{number}_{suffix}'
                    self.assertIn(proof.NAMESPACE + '.' + name, prepared['expected_theorems'])
                    self.assertIn('theorem ' + name + ' :', prepared['positive'])
        for name in ('crossed_0_valid', 'crossed_0_small', 'crossed_0_upper',
                     'no_step_missing', 'no_step_opaque', 'no_step_oversized', 'no_step_false_guard'):
            self.assertIn(proof.NAMESPACE + '.' + name, prepared['expected_theorems'])
            self.assertIn('theorem ' + name + ' :', prepared['positive'])
            self.assertIn('#print axioms ' + name, prepared['positive'])
        original, crossed = prepared['manifests'][0], prepared['manifests'][-1]
        self.assertNotEqual(original['core_sha256'], crossed['core_sha256'])
        self.assertEqual(original['descriptor']['indexSlot'], crossed['descriptor']['extentSlot'])
        self.assertEqual(original['descriptor']['extentSlot'], crossed['descriptor']['indexSlot'])
        self.assertIn('some 18446744073709551615', prepared['positive'])
        for manifest in prepared['manifests']:
            self.assertTrue(manifest['manifest']['projection_only'])
            self.assertEqual(len(manifest['core_sha256']), 64)
            self.assertIn('function', manifest['manifest'])
            self.assertIn('source_slots', manifest['manifest'])

    def test_actual_negative_manifests_and_expected_failure_locations(self):
        negatives = self.prepared['negatives']
        self.assertEqual(set(negatives), {'non_strict_guard', 'wrong_phi', 'literal_two',
            'wrong_condition', 'wrong_phi_semantics', 'wrong_add_semantics', 'skipped_guard_semantics',
            'false_arm', 'non_usize_type', 'missing_phi'})
        for name, negative in negatives.items():
            with self.subTest(name=name):
                start, end = negative['failure_lines']
                lines = negative['source'].splitlines()
                self.assertGreater(start, 0)
                self.assertLessEqual(start, end)
                self.assertLessEqual(end, len(lines))
                self.assertTrue(lines[start - 1].startswith('theorem '))
                if negative['kind'] == 'actual_core_validation':
                    self.assertEqual(start, end)
                    self.assertEqual(lines[start - 1], 'theorem negative_valid : Valid negative_slice := by decide')
                    self.assertNotEqual(negative['manifest']['core_sha256'],
                                        self.prepared['manifests'][0]['core_sha256'])
        descriptors = {name: neg['manifest']['descriptor'] for name, neg in negatives.items()
                       if neg['kind'] == 'actual_core_validation'}
        self.assertEqual(descriptors['non_strict_guard']['compareOp'], 'le')
        self.assertEqual(descriptors['literal_two']['literalValue'], 2)
        wrong_phi = descriptors['wrong_phi']
        self.assertNotEqual(wrong_phi['incoming'][wrong_phi['indexSlot']], wrong_phi['sourceIndex'])
        wrong_condition = descriptors['wrong_condition']
        self.assertNotEqual(wrong_condition['branchCondition'], wrong_condition['compareOutput'])

    def test_negative_rejection_requires_intended_source_location(self):
        path = Path('/tmp/intended.lean')
        valid = {'returncode': 1, 'stdout': str(path) + ':42:9: error: rejected', 'stderr': ''}
        self.assertTrue(proof.negative_rejected(valid, path, [40, 45]))
        for changed in ({**valid, 'returncode': 0}, {**valid, 'returncode': -9},
                        {**valid, 'stdout': '/tmp/other.lean:42:9: error: rejected'},
                        {**valid, 'stdout': str(path) + ':3:9: error: missing import'},
                        {**valid, 'stderr': 'sorryAx'},
                        {**valid, 'stdout': 'error: no location'}):
            with self.subTest(changed=changed):
                self.assertFalse(proof.negative_rejected(changed, path, [40, 45]))

    def test_incomplete_duplicate_unexpected_and_placeholder_inventory_refuses(self):
        names = sorted(self.prepared['expected_theorems'])
        valid = '\n'.join("'" + name + "' does not depend on any axioms" for name in names)
        self.assertEqual(set(proof.theorem_inventory(valid, set(names))), set(names))
        for changed in (valid.split('\n', 1)[1], valid + '\n' + valid.split('\n')[0],
                        valid.replace(names[0], 'Unexpected.theorem'), valid + '\nsorryAx',
                        valid.replace('does not depend on any axioms', 'depends on axioms: [invented]', 1),
                        valid + '\nerror: failure'):
            with self.subTest(changed=changed[-80:]), self.assertRaises(ValueError):
                proof.theorem_inventory(changed, set(names))

    def run_mock_qualification(self, runner):
        # Only the fake executable bytes bypass the lock check, and only inside
        # this test. Every checker process is mocked and all outputs are temporary.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            executable = root / 'fake-lean'
            executable.write_bytes(b'not a checker, never execute')
            pinned = json.loads((proof.ROOT / 'formal/toolchain-lock.json').read_text())['lean_binary_sha256']
            real_digest = proof.digest
            def digest(data):
                return pinned if data == executable.read_bytes() else real_digest(data)
            with patch.object(proof, 'digest', side_effect=digest), \
                 patch.object(proof, '_support_identity', return_value={'mock_only': True}), \
                 patch.object(proof, 'build_inputs', return_value=self.prepared), \
                 patch.object(proof, '_run_lean', side_effect=runner):
                result = proof.qualify(executable, root / 'output')
            self.assertEqual(json.loads((root / 'output' / 'RESULT.json').read_text()), result)
            return result

    def assert_denied(self, report):
        self.assertEqual(report['schema'], 'hepta.hia.projected-guarded-step-kernel.v1')
        for key, value in proof.DENY.items():
            self.assertEqual(report[key], value)
        for key in ('actual_core_bridge_proved', 'python_exporter_refinement_proved',
                    'body_prefix_refinement_proved', 'all_edge_transfer_proved'):
            self.assertFalse(report[key])
        self.assertEqual(len(report['obligations']), 12)
        self.assertTrue(all(item['status'] == 'unproved' for item in report['obligations']))

    def test_unavailable_or_rejected_positive_kernel_fails_closed(self):
        for runner in (FileNotFoundError('mock missing checker'),
                       lambda *args: {'returncode': 1, 'stdout': 'error: rejected', 'stderr': ''},
                       lambda *args: {'returncode': 0, 'stdout': '', 'stderr': ''}):
            with self.subTest(runner=repr(runner)):
                report = self.run_mock_qualification(runner)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['kernel_projected_scalar_theorem_checked'])
                self.assertEqual(report['negative_controls'], [])
                self.assert_denied(report)

    def test_mock_success_protocol_still_denies_every_broader_claim(self):
        # Tests report plumbing only. Fabricated logs cannot establish a theorem.
        calls = []
        inventory = '\n'.join("'" + name + "' does not depend on any axioms"
                              for name in sorted(self.prepared['expected_theorems']))
        def runner(executable, path):
            calls.append(path.name)
            if path.name == 'positive.lean':
                return {'returncode': 0, 'stdout': inventory, 'stderr': ''}
            mutation = self.prepared['negatives'][path.stem]
            line = mutation['failure_lines'][0]
            return {'returncode': 1, 'stdout': f'{path}:{line}:1: error: mock rejection', 'stderr': ''}
        report = self.run_mock_qualification(runner)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(len(calls), 11)
        self.assertEqual(calls[0], 'positive.lean')
        self.assertEqual({item['name'] for item in report['negative_controls']},
                         set(self.prepared['negatives']))
        self.assert_denied(report)

    def test_wrong_negative_location_does_not_certify_the_model(self):
        inventory = '\n'.join("'" + name + "' does not depend on any axioms"
                              for name in sorted(self.prepared['expected_theorems']))
        def runner(executable, path):
            if path.name == 'positive.lean':
                return {'returncode': 0, 'stdout': inventory, 'stderr': ''}
            return {'returncode': 1, 'stdout': str(path) + ':1:1: error: missing import', 'stderr': ''}
        result = self.run_mock_qualification(runner)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['kernel_projected_scalar_theorem_checked'])
        self.assertIn('intended negative obligation', result['error'])
        self.assert_denied(result)


if __name__ == '__main__':
    unittest.main()
