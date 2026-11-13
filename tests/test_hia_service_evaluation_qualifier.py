"""Caller-gate source/admission controls; no simulated run is called native.

The frozen four Agent modules are loaded, never executed here. Controlled cold
admission rows exercise the outer no-output gate; the real builder and all 48
Agent methods are executed only by qualify_hia_service_evaluation's public CLI.
"""
from contextlib import contextmanager, redirect_stderr
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import build_hia_service_evaluation as builder
from tools import qualify_hia_service_evaluation as gate


@contextmanager
def controlled_admission():
    with tempfile.TemporaryDirectory(prefix='hia-evaluation-caller-admission-') as folder:
        directory = Path(folder)
        compiler = directory / 'compiler'; compiler.write_bytes(b'controlled, not executable')
        digest = sha256(compiler.read_bytes()).hexdigest()
        sources = {name: sha256((gate.ROOT / name).read_bytes()).hexdigest()
                   for name in (*builder.REQUIRED_SOURCE_NAMES, *gate.SELF_SOURCES, *gate.ORIGINAL_FILES)}
        nested = directory / 'nested.json'
        nested.write_bytes(gate._wire({'source_manifest': sources,
            'generations': [{'produced_image': str(compiler), 'produced_sha256': digest} for _ in range(3)]}))
        cold = directory / 'cold.json'
        outer = {'nested_report': str(nested), 'nested_report_sha256': sha256(nested.read_bytes()).hexdigest(),
                 'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3,
                 'generation_sha256': [digest] * 3}
        cold.write_bytes(gate._wire(outer))
        with patch.object(builder, 'admit_cold_build', return_value=sources), patch.object(gate, '_snapshot', return_value=sources):
            yield SimpleNamespace(directory=directory, compiler=compiler, cold=cold, outer=outer,
                                  nested=nested, sources=sources, output=directory / 'output')


class ServiceEvaluationQualifierSourceTests(unittest.TestCase):
    def test_actual_original_four_sources_load_all_48_ids_in_original_order(self):
        gate.admit_original_files()
        suite, ids = gate.load_original_suite()
        self.assertEqual(len(ids), 48)
        self.assertEqual([sum(name.startswith(module + '.') for name in ids)
                          for module in gate.ORIGINAL_MODULES], [30, 5, 12, 1])
        self.assertEqual(ids, [test.id() for test in gate.flatten(suite)])
        self.assertEqual(gate.REFERENCE_METHODS, ('_native_reference', '_build_inputs_reference', '_build_receipt_reference', '_cost_ledger_reference', '_hia_evaluate_reference', '_hia_adopt_native_reference', 'invoke_lease_reference'))
        self.assertEqual(gate.REFERENCE_FUNCTIONS, ())
        self.assertEqual(gate.GROUP_SECONDS, 1800)

    def test_original_test_byte_drift_is_refused_before_loading(self):
        with tempfile.TemporaryDirectory(prefix='hia-evaluation-original-') as folder:
            root = Path(folder)
            for name in gate.ORIGINAL_FILES:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((gate.ROOT / name).read_bytes())
            gate.admit_original_files(root)
            name = next(iter(gate.ORIGINAL_FILES))
            path = root / name; path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'test bytes differ'):
                gate.admit_original_files(root)

    def test_only_one_explicit_compiler_selection_is_accepted(self):
        with patch.object(gate, 'qualify', side_effect=AssertionError('qualification entered')):
            for tail in ([], ['--cold-report', 'cold', '--development-compiler', 'compiler']):
                with self.subTest(tail=tail), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        gate.main(['--evidence', '/unused', *tail])
                    self.assertEqual(caught.exception.code, 2)
        for cold, development in ((None, None), ('cold', 'compiler')):
            with self.assertRaises(ValueError):
                gate._admit_selection(cold, development)

    def test_existing_evidence_is_preserved_before_admission_or_build(self):
        with tempfile.TemporaryDirectory(prefix='hia-evaluation-existing-') as folder:
            root = Path(folder); marker = root / 'original'; marker.write_bytes(b'keep original evidence')
            with patch.object(gate, '_admit_selection', side_effect=AssertionError('admission entered')):
                with self.assertRaises(ValueError):
                    gate.qualify(root, development_compiler='/unused')
            self.assertEqual(marker.read_bytes(), b'keep original evidence')
            self.assertEqual(list(root.iterdir()), [marker])

    def test_real_invalid_cold_cannot_reach_output_or_builder(self):
        with controlled_admission() as case:
            case.outer['nested_report_sha256'] = '0' * 64
            case.cold.write_bytes(gate._wire(case.outer))
            with patch.object(builder, 'build', side_effect=AssertionError('builder entered')):
                with self.assertRaisesRegex(ValueError, 'nested cold receipt identity'):
                    gate.qualify(case.output, cold_report=case.cold)
            self.assertFalse(case.output.exists())
        with tempfile.TemporaryDirectory(prefix='hia-evaluation-invalid-cold-') as folder:
            root = Path(folder); cold = root / 'cold'; cold.write_bytes(b'{}')
            with self.assertRaises((ValueError, KeyError)):
                gate.qualify(root / 'output', cold_report=cold)
            self.assertFalse((root / 'output').exists())

    def test_exact_original_limits_and_each_caller_input_must_be_cold_bound(self):
        for key, value in (('qualification_wall_limit_seconds', 180.0),
                           ('qualification_wall_limit_seconds', 181),
                           ('cleanup_wall_limit_seconds', True), ('cleanup_wall_limit_seconds', 3.0)):
            with self.subTest(key=key, value=value), controlled_admission() as case:
                case.outer[key] = value; case.cold.write_bytes(gate._wire(case.outer))
                with self.assertRaisesRegex(ValueError, r'180\+3'):
                    gate.qualify(case.output, cold_report=case.cold)
                self.assertFalse(case.output.exists())
        for name in (*gate.SELF_SOURCES, *gate.ORIGINAL_FILES):
            with self.subTest(missing=name), controlled_admission() as case:
                case.sources.pop(name)
                nested = json.loads(case.nested.read_bytes()); nested['source_manifest'] = case.sources
                case.nested.write_bytes(gate._wire(nested))
                case.outer['nested_report_sha256'] = sha256(case.nested.read_bytes()).hexdigest()
                case.cold.write_bytes(gate._wire(case.outer))
                with self.assertRaisesRegex(ValueError, 'outside the current cold contract'):
                    gate.qualify(case.output, cold_report=case.cold)
                self.assertFalse(case.output.exists())

    def test_nested_generation_and_source_identity_are_independently_checked(self):
        for key in ('source', 'generation'):
            with self.subTest(key=key), controlled_admission() as case:
                nested = json.loads(case.nested.read_bytes())
                if key == 'source': nested['source_manifest'] = {}
                else: nested['generations'][1]['produced_sha256'] = '0' * 64
                case.nested.write_bytes(gate._wire(nested))
                case.outer['nested_report_sha256'] = sha256(case.nested.read_bytes()).hexdigest()
                case.cold.write_bytes(gate._wire(case.outer))
                with self.assertRaisesRegex(ValueError, 'generation custody'):
                    gate.qualify(case.output, cold_report=case.cold)
                self.assertFalse(case.output.exists())
        with controlled_admission() as case:
            compiler, held, sources, scope = gate._admit_selection(case.cold, None)
            self.assertEqual(compiler, case.compiler)
            self.assertEqual(set(held), {case.compiler, case.cold, case.nested})
            self.assertEqual(sources, case.sources)
            self.assertEqual(scope, 'MATCHING_SOURCE_COLD_SELECTED_CALLERS')
            # This is controlled admission only, not a compiler or native run.
            self.assertFalse(case.output.exists())

    def test_source_and_held_bytes_are_rechecked_without_reselecting(self):
        with controlled_admission() as case:
            _, held, sources, _ = gate._admit_selection(None, case.compiler)
            gate._guard(held, sources)
            case.compiler.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'held evaluation'):
                gate._guard(held, sources)
        with controlled_admission() as case:
            _, held, sources, _ = gate._admit_selection(None, case.compiler)
            with patch.object(gate, '_snapshot', return_value={}):
                with self.assertRaisesRegex(ValueError, 'source identity'):
                    gate._guard(held, sources)

    def test_zero_anomalies_and_actual_public_helper_machine_modes_are_required(self):
        result = SimpleNamespace(testsRun=48, failures=[], errors=[], skipped=[],
                                 expectedFailures=[], unexpectedSuccesses=[])
        loaded = gate.original_ids(); modes = {mode: 1 for mode in gate.REQUIRED_MODES}
        self.assertTrue(gate._strict_result(result, loaded, list(loaded), [], modes, modes))
        for name in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
            bad = deepcopy(result); setattr(bad, name, ['real anomaly'])
            self.assertFalse(gate._strict_result(bad, loaded, loaded, [], modes, modes))
        for observed in ({}, {1: 10000}, {**modes, 6: 0}, {**modes, 6: True}):
            self.assertFalse(gate._strict_result(result, loaded, loaded, [], modes, observed))
        changed = {float(mode): value for mode, value in modes.items()}
        self.assertFalse(gate._strict_result(result, loaded, loaded, [], modes, changed))
        self.assertFalse(gate._strict_result(result, loaded, list(reversed(loaded)), [], modes, modes))
        self.assertFalse(gate._strict_result(result, loaded, loaded, ['reference entered'], modes, modes))
        bad = deepcopy(result); bad.testsRun = 48.0
        self.assertFalse(gate._strict_result(bad, loaded, loaded, [], modes, modes))
        child = {'schema': 'hepta.hia.service-evaluation-caller-observations.v1',
                 'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'status': 'PASS',
                 'request_sha256': 'controlled observation, not a native run',
                 'loaded_ids': loaded, 'executed_ids': loaded, 'tests_run': 48,
                 'source_and_inputs_unchanged': True, 'native_mode_calls': {str(k): v for k, v in modes.items()},
                 'actual_machine_mode_returns': {str(k): v for k, v in modes.items()},
                 'actual_mappings': 1, 'actual_machine_returns': len(modes),
                 **{name: [] for name in ('failures', 'errors', 'skips', 'expected_failures',
                                          'unexpected_successes', 'reference_calls')}}
        gate._admit_child_observations(child, child['request_sha256'])
        for key, value in (('actual_mappings', True), ('actual_machine_returns', 8.0),
                           ('reference_calls', {}), ('skips', ['not admitted']), ('tests_run', 48.0)):
            bad = deepcopy(child); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate._admit_child_observations(bad, child['request_sha256'])
        child['actual_machine_mode_returns']['6'] = True
        with self.assertRaises(ValueError):
            gate._admit_child_observations(child, child['request_sha256'])

    def test_child_environment_clears_ambient_selections_preserves_actual_clang(self):
        old = {'PATH': '/ordinary', 'HEPTA_CLANG': '/private/clang-20',
               'HEPTA_HIA_SERVICE_EVALUATION_MANIFEST': 'stale', 'HEPTA_HIA_CODE_DEVELOPMENT_MANIFEST': 'stale',
               'KEEP': 'original'}
        env, removed = gate._clean_environment(old)
        self.assertEqual(env['HEPTA_CLANG'], '/private/clang-20')
        self.assertEqual(env['CLANG'], '/private/clang-20')
        self.assertEqual(env['KEEP'], 'original')
        self.assertNotIn(gate.SELECTOR, env)
        self.assertNotIn('HEPTA_HIA_CODE_DEVELOPMENT_MANIFEST', env)
        self.assertEqual(set(removed), {key for key in old if key.startswith('HEPTA_')})
        self.assertEqual(old[gate.SELECTOR], 'stale')


if __name__ == '__main__':
    unittest.main()
