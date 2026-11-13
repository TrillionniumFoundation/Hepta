"""Exact caller-source custody controls; these never execute the caller tests."""
from copy import deepcopy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import hia_retained_agent_callers as custody


class RetainedAgentCallerSourceTests(unittest.TestCase):
    def test_original_and_declared_compatibility_bytes_keep_distinct_execution_identity(self):
        original = (custody.ROOT / custody.RETAINED_SOURCE).read_bytes()
        current = (custody.ROOT / custody.TARGET).read_bytes()
        expected = {'bytes': custody.ORIGINAL_BYTES, 'sha256': custody.ORIGINAL_SHA256}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / custody.TARGET
            target.parent.mkdir(parents=True)
            target.write_bytes(original)
            retained = custody.admit_source(root, custody.TARGET, expected)
            self.assertTrue(retained['byte_identical'])
            self.assertEqual(retained['executed'], retained['retained'])
            target.write_bytes(current)
            admitted = custody.admit_source(root, custody.TARGET, expected)
            self.assertFalse(admitted['byte_identical'])
            self.assertEqual(admitted['retained'], expected)
            self.assertEqual(admitted['executed'], {'bytes': custody.COMPATIBILITY_BYTES,
                                                   'sha256': custody.COMPATIBILITY_SHA256})
            self.assertTrue(admitted['retained_bytes_recovered_exactly'])

    def test_undeclared_byte_drift_and_relabelled_original_identity_are_rejected(self):
        current = (custody.ROOT / custody.TARGET).read_bytes()
        expected = {'bytes': custody.ORIGINAL_BYTES, 'sha256': custody.ORIGINAL_SHA256}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / custody.TARGET
            target.parent.mkdir(parents=True)
            for changed in (current + b'\n', current.replace(b"'F_SEAL_WRITE',8", b"'F_SEAL_WRITE',16")):
                with self.subTest(length=len(changed)):
                    target.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, 'test bytes differ'):
                        custody.admit_source(root, custody.TARGET, expected)
            target.write_bytes(current)
            renamed = deepcopy(expected); renamed['sha256'] = custody.COMPATIBILITY_SHA256
            with self.assertRaisesRegex(ValueError, 'retained original Agent test bytes differ'):
                custody.admit_source(root, custody.TARGET, renamed)

    def test_retained_original_storage_is_verified_even_for_exact_current_bytes(self):
        original = (custody.ROOT / custody.RETAINED_SOURCE).read_bytes()
        current = (custody.ROOT / custody.TARGET).read_bytes()
        expected = {'bytes': custody.ORIGINAL_BYTES, 'sha256': custody.ORIGINAL_SHA256}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, raw in ((custody.TARGET, current), (custody.RETAINED_SOURCE, original + b'\n')):
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            with patch.object(custody, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'retained original Agent test bytes differ'):
                    custody.admit_source(root, custody.TARGET, expected)

    def test_fixed_namespace_and_continuation_pairs_reject_other_complete_source_bytes(self):
        for name, rule in custody._FIXED_PROJECTIONS.items():
            with self.subTest(original=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                original = (custody.ROOT / rule['retained_source']).read_bytes()
                current = (custody.ROOT / rule['executed_path']).read_bytes()
                target = root / rule['executed_path']; target.parent.mkdir(parents=True)
                target.write_bytes(current)
                admitted = custody.admit_source(root, name, rule['retained'])
                self.assertEqual(admitted['path'], name)
                self.assertEqual(admitted['executed_path'], rule['executed_path'])
                self.assertEqual(admitted['retained'], rule['retained'])
                self.assertEqual(admitted['executed'], rule['executed'])
                self.assertFalse(admitted['byte_identical'])
                self.assertTrue(admitted['retained_bytes_recovered_exactly'])
                rejected = [original, current + b'\n']
                if name.endswith('/test_hia_slot_ledger_native.py'):
                    rejected.append((custody.ROOT / name).read_bytes())
                for changed in rejected:
                    target.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, 'test bytes differ'):
                        custody.admit_source(root, name, rule['retained'])
                target.write_bytes(current)
                stored = root / rule['retained_source']; stored.parent.mkdir(parents=True)
                stored.write_bytes(original + b'\n')
                with patch.object(custody, 'ROOT', root):
                    with self.assertRaisesRegex(ValueError, 'retained original Agent test bytes differ'):
                        custody.admit_source(root, name, rule['retained'])

    def test_three_qualifiers_load_exact_original_groups_and_only_the_declared_ledger_mapping(self):
        from tools import qualify_hia_service_artifacts, qualify_hia_service_evaluation, qualify_hia_service_requests
        gates = (qualify_hia_service_artifacts, qualify_hia_service_evaluation, qualify_hia_service_requests)
        for gate in gates:
            try:
                for group, count, nested in (('agent', 48, 0), ('namespace', 1, 35), ('ledger', 1, 48)):
                    with self.subTest(qualifier=gate.__name__, group=group):
                        gate.configure_group(group)
                        original = gate.original_ids()
                        expected = [custody.execution_id(name) for name in original]
                        suite, loaded = gate.load_original_suite()
                        self.assertEqual(len(original), count)
                        self.assertEqual(len(loaded), count)
                        self.assertEqual(loaded, expected)
                        self.assertEqual(loaded, [test.id() for test in gate.flatten(suite)])
                        self.assertEqual(gate.EXPECTED_COUNT, count)
                        self.assertEqual(len(gate.nested_ids()), nested)
                        self.assertEqual(gate.GROUP_SECONDS, 1800)
                        self.assertEqual(gate.caller_id_map(), [
                            {'original': old, 'executed': actual}
                            for old, actual in zip(original, loaded)])
                        modes = {mode: 1 for mode in gate.REQUIRED_MODES}
                        result = SimpleNamespace(testsRun=count, failures=[], errors=[], skipped=[],
                                                 expectedFailures=[], unexpectedSuccesses=[])
                        self.assertTrue(gate._strict_result(result, loaded, loaded, [], modes, modes))
                        if group == 'ledger':
                            self.assertNotEqual(loaded, original)
                            self.assertTrue(loaded[0].startswith('tests.test_hia_slot_ledger_continuation_native.'))
                            self.assertFalse(gate._strict_result(result, original, original, [], modes, modes))
                            schema = 'hepta.hia.' + gate.__name__.rsplit('.', 1)[1].removeprefix('qualify_hia_').replace('_', '-') + '-caller-observations.v1'
                            child = {'schema': schema, 'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY',
                                     'status': 'PASS', 'request_sha256': 'controlled source receipt, not native',
                                     'loaded_ids': loaded, 'executed_ids': loaded, 'tests_run': count,
                                     'source_and_inputs_unchanged': True,
                                     'original_to_executed_ids': gate.caller_id_map(),
                                     'native_mode_calls': {str(k): v for k, v in modes.items()},
                                     'actual_machine_mode_returns': {str(k): v for k, v in modes.items()},
                                     'actual_mappings': 1, 'actual_machine_returns': len(modes),
                                     **{key: [] for key in ('failures', 'errors', 'skips', 'expected_failures',
                                                           'unexpected_successes', 'reference_calls')}}
                            gate._admit_child_observations(child, child['request_sha256'])
                            missing = deepcopy(child); missing.pop('original_to_executed_ids')
                            with self.assertRaisesRegex(ValueError, 'ledger to continuation caller identity'):
                                gate._admit_child_observations(missing, child['request_sha256'])
                        else:
                            self.assertEqual(loaded, original)
            finally:
                gate.configure_group('agent')
