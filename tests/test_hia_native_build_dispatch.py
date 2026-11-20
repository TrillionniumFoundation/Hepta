"""Frozen original dynamic calls and runtime-specific iterator observations.

The 205 inputs were independently frozen before this candidate was executed.
The old 303 inputs, four original bodies, and 240 caller IDs stay unchanged.
These are finite observations; they do not prove all-input equivalence.
"""
from __future__ import annotations

from collections import Counter
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_native_build_admission_native as native
from hepta.hia_agent_assembly import assemble_program
from tests.hia_native_build_dispatch_oracle import cases, observe_case
from tests.test_hia_native_build_admission_native import encoded, vm_image

ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = ROOT / 'tests/fixtures/hia_native_build_dispatch_cases_aac7550.json'
ORACLE_FILE = ROOT / 'tests/hia_native_build_dispatch_oracle.py'
CASE_SHA256 = 'f42756d516f2ac3227445da1bc12a37120877c313c0c2fd765f2fa468bab04ec'
ORACLE_SHA256 = '751c323f838240866dc0e4d22dd4c683d17393ea92356677308f4df20eac74ab'
CASE_COUNT = 205
COLD = 'HEPTA_HIA_NATIVE_BUILD_DISPATCH_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_NATIVE_BUILD_DISPATCH_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_NATIVE_BUILD_DISPATCH_EVIDENCE'


def bindings():
    return {'_native': api._NATIVE_BUILD_NATIVE_BRIDGE,
            '_build_inputs': api._NATIVE_BUILD_INPUTS_BRIDGE,
            '_signatures': api._NATIVE_BUILD_SIGNATURES_BRIDGE}


def owner(image, frames=None, caught=None):
    """Invoke the raw frame: the independent fixture owns every public hook."""
    def run(mode, service, arguments, namespace):
        frame = native.NativeBuildAdmissionFrame(image, mode, service, arguments, namespace=namespace)
        if frames is not None:
            frames.append(frame)
        try:
            # Preserve the independent namespace at real public child-frame
            # boundaries without replacing any method or global call hook.
            with patch.object(api, 'sha256', namespace['sha256']), \
                    patch.object(api, 'reject', namespace['reject']):
                return frame.finish()
        except BaseException as error:
            if caught is not None:
                caught.append(error)
            raise
    return run


def ordinary_replacements():
    by_name = {case['name']: case for case in cases()}
    return [by_name[f'dispatch.{mode}.instance_function'] for mode in (2, 3, 4)]


def runtime_facts():
    return {'generator_reiterations': native._runtime_generator_reiterations(),
            'list_reiterations': native._runtime_list_reiterations(),
            'dict_reiterations': native._runtime_dict_reiterations()}


class NativeBuildDispatchSourceTests(unittest.TestCase):
    def test_independent_original_inputs_are_frozen_and_repeatable_without_native(self):
        self.assertEqual(sha256(CASE_FILE.read_bytes()).hexdigest(), CASE_SHA256)
        self.assertEqual(sha256(ORACLE_FILE.read_bytes()).hexdigest(), ORACLE_SHA256)
        inputs = cases()
        self.assertEqual(len(inputs), CASE_COUNT)
        self.assertEqual(len({case['name'] for case in inputs}), CASE_COUNT)
        with patch.dict(os.environ), patch.object(native.NativeBuildAdmission, '__init__',
                side_effect=AssertionError('original observation must not map native bytes')):
            os.environ.pop(native.SELECTOR, None)
            for case in inputs:
                with self.subTest(case=case['name']):
                    first = encoded(observe_case(case))
                    self.assertEqual(encoded(observe_case(case)), first)

    def test_independent_VM_preserves_three_captured_foreign_calls_before_mapping(self):
        program = assemble_program(native.SOURCE.read_bytes())
        with patch.object(native.NativeBuildAdmission, '__init__',
                side_effect=AssertionError('native image before independent VM')):
            image = vm_image(program)
            for case in ordinary_replacements():
                with self.subTest(case=case['name']):
                    expected = encoded(observe_case(case))
                    self.assertEqual(encoded(observe_case(case, owner(image), bindings())), expected)
            self.assertGreater(image.entry_count, 0)


class NativeBuildDispatchNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_native_build_admission import build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-native-build-dispatch-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        if cold is not None:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        cls.compiler, cls.cold = compiler, cold
        cls.compiler_raw, cls.sources = compiler.read_bytes(), current_sources()
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_native_build_admission(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = after == cls.sources and cls.compiler.read_bytes() == cls.compiler_raw
        record = {'schema': 'hepta.hia.native-build-dispatch-test-custody.v1',
            'manifest': str(cls.manifest), 'matching_cold_report': cls.cold,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'source_manifest_before': cls.sources, 'source_manifest_after': after,
            'source_and_compiler_unchanged': stable,
            'python_version': sys.version, 'runtime_protocol_facts': runtime_facts(),
            'test_result_owned_by_outer_runner': True,
            'canonical_and_explicit_foreign_override_scopes_distinct': True,
            'all_python_versions_tested': False, 'all_input_equivalence_proved': False,
            'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record) + b'\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('native build dispatch inputs changed during native tests')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()
        self.maxDiff = 10000

    def test_frozen_dispatch_runtime_and_original_default_observations(self):
        from tests.hia_native_build_admission_oracle import observe_case as original_observe
        from tests.hia_native_build_admission_scenarios import scenarios
        from tests.test_hia_native_build_admission_native import invoke
        records, counts, entry = [], Counter(), self.image._entry
        def observed(source, size, output, capacity, state, extent):
            words = struct.unpack('<10Q', ctypes.string_at(source, size))
            counts[f'event_{words[1]}'] += 1
            counts[f'mode_{words[5]}'] += int(words[1] == 0)
            return entry(source, size, output, capacity, state, extent)
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), patch.object(self.image, '_entry', observed):
            inputs = cases()
            self.assertEqual(len(inputs), CASE_COUNT)
            for case in inputs:
                expected_raw = encoded(observe_case(case))
                actual_raw = encoded(observe_case(case, owner(self.image), bindings()))
                records.append({'case': case['name'], 'expected': json.loads(expected_raw),
                                'actual': json.loads(actual_raw)})
                with self.subTest(case=case['name']):
                    self.assertEqual(actual_raw, expected_raw)
            original_records = []
            self.assertEqual(len(scenarios()), 303)
            for case in scenarios():
                expected_raw = encoded(original_observe(case))
                actual_raw = encoded(original_observe(case, invoke(self.image)))
                original_records.append({'case': case['name'], 'expected': json.loads(expected_raw),
                                         'actual': json.loads(actual_raw)})
                with self.subTest(original_case=case['name']):
                    self.assertEqual(actual_raw, expected_raw)
        self.assertGreater(counts['event_0'], 0)
        (self.case / 'complete-observations.json').write_bytes(encoded(records) + b'\n')
        (self.case / 'retained-303-observations.json').write_bytes(encoded(original_records) + b'\n')
        (self.case / 'entry-counts.json').write_bytes(encoded(counts) + b'\n')

    def test_lost_override_ACK_retains_unknown_without_retry_or_false_foreign_rejection(self):
        from tests.test_hia_native_transport_failures import errors, check_transport
        ports = {2: 'dispatch_signatures_call', 3: 'dispatch_native_call',
                 4: 'dispatch_build_inputs_call'}
        records = []
        for case in ordinary_replacements():
            expected = observe_case(case)
            for label, injected in errors():
                with self.subTest(case=case['name'], error=label):
                    entry, events, frames, caught = self.image._entry, [], [], []
                    port = ports[case['mode']]
                    def lost(source, size, output, capacity, state, extent):
                        words = struct.unpack('<10Q', ctypes.string_at(source, size))
                        code = entry(source, size, output, capacity, state, extent)
                        events.append(words[1])
                        if words[1] == 2 and words[3] == native.PORT[port]:
                            raise injected
                        return code
                    with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), patch.object(self.image, '_entry', lost):
                        actual = observe_case(case, owner(self.image, frames, caught), bindings())
                    self.assertEqual(len(frames), 1)
                    self.assertEqual(len(caught), 1)
                    frame = frames[0]
                    check_transport(caught[0], injected, native.NativeBuildAdmissionUnknown)
                    self.assertTrue(frame.fenced and frame.native_failed and frame.unconfirmed)
                    self.assertFalse(frame.finished)
                    self.assertIs(native._FRAME_CUSTODY[id(frame)], frame)
                    self.assertNotIn(3, events)
                    trace = list(actual['trace'])
                    self.assertTrue(trace)
                    self.assertEqual(encoded(trace), encoded(expected['trace'][:len(trace)]))
                    self.assertEqual(sum(row['event'] == 'dispatch.call' for row in trace), 1)
                    with self.assertRaises(native.NativeBuildAdmissionUnknown):
                        frame.finish()
                    self.assertEqual(actual['trace'], trace)
                    records.append({'case': case['name'], 'port': port, 'injected': label,
                        'raised': type(caught[0]).__name__,
                        'original_exception_or_cause_identity_retained': True,
                        'unknown_custody_retained': True, 'events': events, 'trace': trace})
        (self.case / 'unknown-overrides.json').write_bytes(encoded(records) + b'\n')

    def test_nested_native_loss_propagates_causally_and_foreign_errors_keep_identity(self):
        from tests.test_hia_native_build_admission_native import Fixture, fixture_by_name
        from tests.test_hia_native_transport_failures import errors, observe_error, check_transport
        inputs = fixture_by_name()
        unknown_records, foreign_records = [], []
        initializer = native.NativeBuildAdmissionFrame.__init__
        for outer_mode, failed_mode in ((3, 2), (4, 3), (4, 2)):
            case = inputs['inputs_ordinary' if outer_mode == 3 else 'receipt_ordinary']
            failed_port = 'native_get' if failed_mode == 2 else 'build_get'
            for label, injected in errors():
                with self.subTest(outer=outer_mode, child=failed_mode, native=label):
                    fixture, frames, events = Fixture(case), [], []
                    entry = self.image._entry
                    def initialized(frame, *arguments, **keywords):
                        initializer(frame, *arguments, **keywords)
                        frames.append(frame)
                    def lost(source, size, output, capacity, state, extent):
                        words = struct.unpack('<10Q', ctypes.string_at(source, size))
                        code = entry(source, size, output, capacity, state, extent)
                        events.append({'mode': words[5], 'event': words[1], 'port': words[3]})
                        if words[5] == failed_mode and words[1] == 2 and words[3] == native.PORT[failed_port]:
                            raise injected
                        return code
                    with fixture.providers(), patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                            patch.object(native.NativeBuildAdmissionFrame, '__init__', initialized), \
                            patch.object(self.image, '_entry', lost):
                        frame = native.NativeBuildAdmissionFrame(self.image, outer_mode, fixture.service,
                            fixture.arguments(), namespace=fixture.namespace)
                        error = observe_error(frame.finish)
                    check_transport(error, injected, native.NativeBuildAdmissionUnknown)
                    expected_modes = list(range(outer_mode, failed_mode - 1, -1))
                    self.assertEqual([child.mode for child in frames], expected_modes)
                    self.assertTrue(all(child.fenced and child.native_failed and child.unconfirmed
                                        and not child.finished for child in frames))
                    self.assertTrue(all(native._FRAME_CUSTODY[id(child)] is child for child in frames))
                    self.assertFalse(any(event['event'] == 3 for event in events))
                    trace = list(fixture.trace.events)
                    for child in frames:
                        with self.assertRaises(native.NativeBuildAdmissionUnknown):
                            child.finish()
                    self.assertEqual(fixture.trace.events, trace)
                    unknown_records.append({'outer_mode': outer_mode, 'failed_mode': failed_mode,
                        'failed_port': failed_port, 'injected': label, 'raised': type(error).__name__,
                        'original_exception_or_cause_identity_retained': True,
                        'active_causal_frames': expected_modes, 'all_causal_unknown_custody_retained': True,
                        'no_confirmed_foreign_exception_event': True, 'events': events, 'trace': trace})
                with self.subTest(outer=outer_mode, child=failed_mode, confirmed_foreign=label):
                    fixture, frames, events = Fixture(case), [], []
                    entry = self.image._entry
                    provider_name = 'get' if failed_mode == 2 else 'get_json'
                    provider = getattr(fixture.service.store, provider_name)
                    def observed(source, size, output, capacity, state, extent):
                        words = struct.unpack('<10Q', ctypes.string_at(source, size))
                        events.append({'mode': words[5], 'event': words[1], 'port': words[3]})
                        return entry(source, size, output, capacity, state, extent)
                    def foreign(*arguments, **keywords):
                        result = provider(*arguments, **keywords)
                        if keywords.get('kind') == ('native' if failed_mode == 2 else 'build-receipt'):
                            raise injected
                        return result
                    with fixture.providers(), patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                            patch.object(native.NativeBuildAdmissionFrame, '__init__', initialized), \
                            patch.object(self.image, '_entry', observed), \
                            patch.object(fixture.service.store, provider_name, foreign):
                        frame = native.NativeBuildAdmissionFrame(self.image, outer_mode, fixture.service,
                            fixture.arguments(), namespace=fixture.namespace)
                        error = observe_error(frame.finish)
                    self.assertIs(error, injected)
                    self.assertEqual([child.mode for child in frames], expected_modes)
                    self.assertTrue(all(child.finished and not child.fenced and not child.native_failed
                                        and not child.unconfirmed and child.receipt.phase == 5 for child in frames))
                    self.assertTrue(all(id(child) not in native._FRAME_CUSTODY for child in frames))
                    confirmed = [event['mode'] for event in events if event['event'] == 3]
                    self.assertEqual(confirmed, list(reversed(expected_modes)))
                    foreign_records.append({'outer_mode': outer_mode, 'failed_mode': failed_mode,
                        'injected': label, 'same_exception_object': True,
                        'confirmed_frames': confirmed, 'all_causal_custody_released': True,
                        'events': events, 'trace': fixture.trace.events})
        self.assertEqual(len(unknown_records), 30)
        self.assertEqual(len(foreign_records), 30)
        (self.case / 'nested-native-loss.json').write_bytes(encoded(unknown_records) + b'\n')
        (self.case / 'nested-confirmed-foreign.json').write_bytes(encoded(foreign_records) + b'\n')


if __name__ == '__main__':
    unittest.main()
