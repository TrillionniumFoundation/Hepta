"""Complete frozen compile/emission observations and actual selected owners.

The independent 954-case oracle precedes this implementation. Hosted compiler,
linker, filesystem, Store and object providers remain explicit boundaries.
"""
from __future__ import annotations

import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_emission_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.fixtures.hia_emission_original_73f1634 import hia_emission_original_oracle as oracle
from tools import generate_hia_emission as generator

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/hia_emission_original_73f1634'
ORIGINAL_FILES = {
    'hia_emission_original_oracle.py': 'c2aa8bda736a211adbcfcfd156de47e576cbb348f26f4370649782016ba4b1e2',
    'original-freeze.json': 'dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048',
    'hia_emission_compile_73f1634.py.txt': '5286d998c3f3bed72e217b4fb774662003c6db225352bb26c32bba30f789023d',
    'hia_emission_emit_73f1634.py.txt': '7c5968a59d591a1d056c5d1fad7b580f55c6c1032b636315df2878e2bb185679',
    'cases.json': 'a4e54267dbcfebced157c2f48dd8d9680364bb03fd7104ab4f509045554bfe68',
}
CASE_COUNT = 954
COLD = 'HEPTA_HIA_EMISSION_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_EMISSION_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_EMISSION_EVIDENCE'
VM_CASES = ('compile.object', 'compile.with.compile_failure_exit_bare_raise',
            'compile.with.read_failure_suppressed', 'emit.plan',
            'composed.plan_exports_receipts', 'composed.override_after_binding')
FOREIGN_GLOBALS = ('time', 'tempfile', 'Path', 'sha256', 'reject', 'validate', 'PLAN_SCHEMA', '_signatures')


class MixedRejected(RuntimeError, ValueError):
    pass


ERROR_TYPES = (ValueError, TypeError, OSError, OverflowError, RecursionError,
               sqlite3.OperationalError, MixedRejected, RuntimeError, KeyboardInterrupt, SystemExit)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def runtime_facts():
    return {'context_lookup_order': list(native._runtime_context_lookup_order()),
            'generator_reiterations': native._runtime_generator_reiterations()}


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def original_inputs():
    for name, digest in ORIGINAL_FILES.items():
        if sha256((ORIGINAL / name).read_bytes()).hexdigest() != digest:
            raise AssertionError('independent original input differs: ' + name)
    return json.loads((ORIGINAL / 'original-freeze.json').read_bytes())


def case_by_name():
    return {case['name']: case for case in oracle.cases()}


def bind_compile(fixture, image, *, public=False):
    def compile_owner(service, program, kind, plan, timeout_ms, *, foreign_buffer_exports=()):
        if public:
            return api.HIAAgentService._compile(service, program, kind, plan, timeout_ms,
                                               foreign_buffer_exports=foreign_buffer_exports)
        return native.EmissionFrame(image, 1, service,
            (program, kind, plan, timeout_ms, foreign_buffer_exports), namespace=fixture.namespace).finish()
    fixture.compile_delegate = compile_owner


def observe_candidate(case, image, *, public=False):
    fixture = oracle.Fixture(case)
    bind_compile(fixture, image, public=public)
    with ExitStack() as scope:
        scope.enter_context(fixture.providers())
        if public:
            for name in FOREIGN_GLOBALS:
                scope.enter_context(patch.object(api, name, fixture.namespace[name]))
            if case['mode'] == 1:
                program, kind, plan, timeout_ms, exports = fixture.arguments()
                operation = lambda: api.HIAAgentService._compile(fixture.service, program, kind, plan,
                    timeout_ms, foreign_buffer_exports=exports)
            else:
                operation = lambda: api.HIAAgentService._hia_emit(fixture.service, fixture.args)
        else:
            operation = lambda: native.EmissionFrame(image, case['mode'], fixture.service,
                fixture.arguments(), namespace=fixture.namespace).finish()
        return fixture.observe(operation)


def vm_call(program, request, output, state):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(index + 1, bytearray(raw)) for index, raw in enumerate((request, output, state))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    result = machine.invoke(machine.functions['f0'],
                            [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
    if bytes(owners[0].data) != request:
        raise AssertionError('independent VM modified immutable request')
    return result, bytes(owners[1].data), bytes(owners[2].data)


def vm_image(program):
    image = object.__new__(native.NativeEmission)
    image.image_sha256 = 'independent-vm-no-executable-mapping'
    image.entry_count = 0
    def entry(source, size, output, capacity, state, extent):
        image.entry_count += 1
        code, answer, retained = vm_call(program, ctypes.string_at(source, size),
            ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        ctypes.memmove(output, answer, capacity)
        ctypes.memmove(state, retained, extent)
        return code
    image._entry = entry
    return image


class EmissionSourceTests(unittest.TestCase):
    def test_frozen_complete_originals_and_caller_inventory_are_unchanged(self):
        inventory = original_inputs()
        self.assertEqual(inventory['base_commit'], '73f16346e7f84fa13305777a4595e2d1b422dee9')
        self.assertEqual(len(inventory['callers']), 17)
        self.assertEqual((inventory['ordinary_count'], inventory['separate_scope_count']), (112, 128))
        cases = oracle.cases()
        self.assertEqual(len(cases), CASE_COUNT)
        self.assertEqual(len({case['name'] for case in cases}), CASE_COUNT)
        self.assertIs(json.loads((ORIGINAL / 'cases.json').read_bytes())['candidate_execution_before_freeze'], False)
        service = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
        owners = {node.name: node for node in ast.walk(service) if isinstance(node, ast.FunctionDef)}
        for name, filename in (('_compile', 'hia_emission_compile_73f1634.py.txt'),
                               ('_hia_emit', 'hia_emission_emit_73f1634.py.txt')):
            retained = owners[name + '_reference']
            retained.name = name
            original = ast.parse(textwrap.dedent((ORIGINAL / filename).read_text())).body[0]
            self.assertEqual(ast.dump(retained, include_attributes=False),
                             ast.dump(original, include_attributes=False))
        from tools.qualify_hia_emission_callers import admit_original_sources
        admit_original_sources(ROOT, inventory)
        self.assertEqual(native.SOURCE.read_bytes(), render_assembly(generator.document()).encode())

    def test_independent_VM_preserves_original_effects_and_exceptional_cleanup(self):
        program = assemble_program(native.SOURCE.read_bytes())
        with patch.object(native.NativeEmission, '__init__',
                          side_effect=AssertionError('native mapping before independent VM')):
            image = vm_image(program)
            cases = case_by_name()
            for name in VM_CASES:
                with self.subTest(case=name):
                    expected = oracle.observe_case(cases[name])
                    self.assertEqual(encoded(observe_candidate(cases[name], image)), encoded(expected))
            self.assertGreater(image.entry_count, 0)

    def test_bad_cold_and_empty_selection_refuse_before_compile_or_reference(self):
        from tools.build_hia_emission import build
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            compiler, cold, output = directory / 'compiler.bin', directory / 'cold.json', directory / 'output'
            compiler.write_bytes(b'invalid-development-bytes')
            cold.write_text('{}')
            with patch('tools.build_hia_emission.compile_stage',
                       side_effect=AssertionError('compile before matching cold admission')):
                with self.assertRaises(ValueError):
                    build(output, compiler, cold)
            self.assertFalse(output.exists())
        with patch.dict(os.environ, {native.SELECTOR: ''}), \
             patch.object(api.HIAAgentService, '_compile_reference',
                          side_effect=AssertionError('empty selector fell back')), \
             patch.object(api.HIAAgentService, '_hia_emit_reference',
                          side_effect=AssertionError('empty selector fell back')):
            with self.assertRaises(ValueError):
                api.HIAAgentService._compile(object(), None, None, None, None)
            with self.assertRaises(ValueError):
                api.HIAAgentService._hia_emit(object(), None)


class EmissionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_emission import build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-emission-')
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
        cls.image = native.installed_emission(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = after == cls.sources and cls.compiler.read_bytes() == cls.compiler_raw
        record = {'schema': 'hepta.hia.emission-test-custody.v1', 'manifest': str(cls.manifest),
            'matching_cold_report': cls.cold, 'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'source_manifest_before': cls.sources, 'source_manifest_after': after,
            'source_and_compiler_unchanged': stable, 'python_version': sys.version,
            'runtime_protocol_facts': runtime_facts(), 'test_result_owned_by_outer_runner': True,
            'canonical_and_explicit_foreign_override_scopes_distinct': True,
            'causal_native_loss_scope': 'active same-process same-thread EmissionFrame ancestors',
            'cross_owner_native_delivery_loss_tracking_implemented': False,
            'all_python_versions_tested': False, 'all_input_equivalence_proved': False,
            'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record) + b'\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('emission source or compiler changed during observations')

    def setUp(self):
        self.directory = self.root / self._testMethodName
        self.directory.mkdir()
        self.selection = patch.dict(os.environ, {native.SELECTOR: str(self.manifest)})
        self.selection.start()
        self.addCleanup(self.selection.stop)

    def write(self, name, value):
        (self.directory / name).write_bytes(encoded(value) + b'\n')

    def test_954_independent_original_provider_and_cleanup_observations(self):
        original_inputs()
        rows, entries = [], Counter()
        entry = self.image._entry
        def counted(source, size, output, capacity, state, extent):
            magic, event, sequence, port, observed, mode = struct.unpack('<6Q', ctypes.string_at(source, 48))
            code = entry(source, size, output, capacity, state, extent)
            self.assertEqual((magic, code), (native.REQUEST_MAGIC, native.OUTPUT_BYTES))
            entries['event_' + str(event)] += 1
            if event == 0:
                entries['mode_' + str(mode)] += 1
            return code
        with patch.object(self.image, '_entry', counted), \
             patch.object(api.HIAAgentService, '_compile_reference', side_effect=AssertionError('retained compile')), \
             patch.object(api.HIAAgentService, '_hia_emit_reference', side_effect=AssertionError('retained emit')):
            for case in oracle.cases():
                with self.subTest(case=case['name']):
                    expected = oracle.observe_case(case)
                    actual = observe_candidate(case, self.image)
                    rows.append({'case': case['name'], 'expected': expected, 'actual': actual})
                    self.assertEqual(encoded(actual), encoded(expected))
        self.write('complete-observations.json', rows)
        self.write('entry-counts.json', dict(entries))
        self.assertEqual(len(rows), CASE_COUNT)
        for mode in (1, 2):
            self.assertGreater(entries['mode_' + str(mode)], 0)
        self.assertEqual(entries['event_0'], entries['mode_1'] + entries['mode_2'])
        self.assertEqual(entries['event_1'], entries['event_2'] + entries['event_3'])

    def test_actual_native_full_buffers_match_independent_VM(self):
        program = assemble_program(native.SOURCE.read_bytes())
        actual_entry, counts, rows = self.image._entry, Counter(), []
        def compared(source, size, output, capacity, state, extent):
            before = (ctypes.string_at(source, size), ctypes.string_at(output, capacity),
                      ctypes.string_at(state, extent))
            expected = vm_call(program, *before)
            code = actual_entry(source, size, output, capacity, state, extent)
            self.assertEqual((code, ctypes.string_at(output, capacity), ctypes.string_at(state, extent)), expected)
            self.assertEqual(ctypes.string_at(source, size), before[0])
            counts['continuation'] += 1
            return code
        cases = case_by_name()
        with patch.object(self.image, '_entry', compared):
            for name in VM_CASES:
                expected = oracle.observe_case(cases[name])
                actual = observe_candidate(cases[name], self.image)
                rows.append({'case': name, 'expected': expected, 'actual': actual})
                self.assertEqual(encoded(actual), encoded(expected))
        self.write('vm-native-observations.json', rows)
        self.write('vm-native-entry-counts.json', dict(counts))
        self.assertGreater(counts['continuation'], 0)

    def test_public_canonical_routes_preserve_overrides_without_retained_fallback(self):
        cases = case_by_name()
        names = ('compile.shared', 'compile.object', 'emit.canonical', 'emit.plan',
                 'composed.canonical', 'composed.override_before_binding', 'composed.override_after_binding')
        rows = []
        with patch.object(api.HIAAgentService, '_compile_reference', side_effect=AssertionError('retained compile')), \
             patch.object(api.HIAAgentService, '_hia_emit_reference', side_effect=AssertionError('retained emit')):
            for name in names:
                expected = oracle.observe_case(cases[name])
                actual = observe_candidate(cases[name], self.image, public=True)
                rows.append({'case': name, 'expected': expected, 'actual': actual})
                self.assertEqual(encoded(actual), encoded(expected))
        self.write('public-observations.json', rows)
        for name in ('compile.shared', 'emit.canonical'):
            for value in ('', '/no/such/emission-manifest'):
                with self.subTest(case=name, selector=value), patch.dict(os.environ, {native.SELECTOR: value}):
                    refused = observe_candidate(cases[name], self.image, public=True)
                    self.assertEqual(refused['outcome']['kind'], 'raised')
                    self.assertEqual(refused['trace'], [])
        manifest = self.directory / 'manifest.json'
        manifest.write_bytes(self.manifest.read_bytes())
        value = json.loads(manifest.read_bytes())
        image = self.directory / value['image_path']
        image.write_bytes((self.manifest.parent / value['image_path']).read_bytes())
        held = native.installed_emission(str(manifest))
        image.write_bytes(image.read_bytes() + b'\0')
        with self.assertRaises(ValueError):
            native.installed_emission(str(manifest))
        self.assertEqual(held.image_sha256, value['image_sha256'])
        from hepta.hia_native_helpers import native_helpers_scope
        with patch.dict(os.environ, clean_environment(), clear=True), native_helpers_scope():
            with self.assertRaisesRegex(ValueError, 'outside the pinned'):
                native.installed_emission(str(self.manifest))

    def test_lost_ACK_preserves_effects_and_foreign_errors_follow_original_cleanup(self):
        cases = case_by_name()
        plans = (('compile.shared', 'compile_call'), ('compile.shared', 'compile_read'),
                 ('compile.shared', 'compile_exit_normal'), ('compile.shared', 'compile_store_object'),
                 ('compile.with.compile_failure_unsuppressed', 'compile_exit_exception'),
                 ('emit.canonical', 'emit_native_put'), ('emit.canonical', 'emit_receipt_put'))
        unknown, foreign = [], []
        actual_entry, original_effect = self.image._entry, native.EmissionFrame.effect
        for name, port_name in plans:
            for error_type in ERROR_TYPES:
                with self.subTest(kind='native-loss', case=name, port=port_name, error=error_type.__name__):
                    fixture = oracle.Fixture(cases[name])
                    bind_compile(fixture, self.image)
                    events, hit = [], []
                    failure = error_type('unconfirmed emission acknowledgement')
                    def lost(source, size, output, capacity, state, extent):
                        words = struct.unpack('<6Q', ctypes.string_at(source, 48))
                        code = actual_entry(source, size, output, capacity, state, extent)
                        events.append({'mode': words[5], 'event': words[1], 'port': words[3]})
                        if words[1] == 2 and words[3] == native.PORT[port_name] and not hit:
                            hit.append(len(events) - 1)
                            raise failure
                        return code
                    with fixture.providers(), patch.object(self.image, '_entry', lost):
                        frame = native.EmissionFrame(self.image, cases[name]['mode'], fixture.service,
                            fixture.arguments(), namespace=fixture.namespace)
                        with self.assertRaises(BaseException) as caught:
                            frame.finish()
                        raised = caught.exception
                        preserved = raised is failure or raised.__cause__ is failure
                        self.assertTrue(preserved)
                        self.assertIs(type(raised), error_type if error_type in (
                            RuntimeError, KeyboardInterrupt, SystemExit) else native.EmissionUnknown)
                        self.assertEqual(len(hit), 1)
                        self.assertEqual(events[-1]['event'], 2)
                        self.assertEqual(hit[0], len(events) - 1)
                        self.assertTrue(frame.native_failed and frame.fenced and frame.unconfirmed)
                        self.assertFalse(frame.finished)
                        self.assertIs(native._FRAME_CUSTODY.get(id(frame)), frame)
                        before = encoded({'trace': fixture.trace.events, 'events': events,
                                          'store': fixture.store_effects})
                        with self.assertRaises(native.EmissionUnknown):
                            frame.finish()
                        self.assertEqual(encoded({'trace': fixture.trace.events, 'events': events,
                                                  'store': fixture.store_effects}), before)
                    if port_name in ('compile_call', 'compile_read'):
                        self.assertEqual([(item.entered, item.exited) for item in fixture.temporaries], [(True, False)])
                    unknown.append({'case': name, 'port': port_name, 'injected': error_type.__name__,
                        'raised': type(raised).__name__, 'original_exception_or_cause_identity_retained': preserved,
                        'unknown_custody_retained': True, 'no_replay_or_cleanup_after_loss': True,
                        'events': events, 'trace': fixture.trace.events, 'store_effects': fixture.store_effects,
                        'temporaries': [{'entered': item.entered, 'exited': item.exited,
                                         'exit_calls': item.exit_calls} for item in fixture.temporaries]})
                if port_name == 'compile_exit_exception':
                    # The independently frozen cleanup replacement matrix
                    # already covers a foreign error during exceptional exit.
                    # Keep the ordinary counterpart here at the six original
                    # successful effect points, without inventing a new oracle.
                    continue
                with self.subTest(kind='confirmed-foreign', case=name, port=port_name, error=error_type.__name__):
                    fixture = oracle.Fixture(cases[name])
                    bind_compile(fixture, self.image)
                    failure, events = error_type('confirmed emission provider exception'), []
                    def counted(source, size, output, capacity, state, extent):
                        words = struct.unpack('<6Q', ctypes.string_at(source, 48))
                        code = actual_entry(source, size, output, capacity, state, extent)
                        events.append({'mode': words[5], 'event': words[1], 'port': words[3]})
                        return code
                    def foreign_effect(frame, port):
                        observed = original_effect(frame, port)
                        if port == native.PORT[port_name]:
                            raise failure
                        return observed
                    with fixture.providers(), patch.object(self.image, '_entry', counted), \
                         patch.object(native.EmissionFrame, 'effect', foreign_effect):
                        frame = native.EmissionFrame(self.image, cases[name]['mode'], fixture.service,
                            fixture.arguments(), namespace=fixture.namespace)
                        with self.assertRaises(BaseException) as caught:
                            frame.finish()
                    self.assertIs(caught.exception, failure)
                    self.assertTrue(frame.finished)
                    self.assertEqual(frame.receipt.phase, 5)
                    self.assertFalse(frame.native_failed or frame.unconfirmed)
                    self.assertNotIn(id(frame), native._FRAME_CUSTODY)
                    self.assertEqual(sum(event['event'] == 3 for event in events), 1)
                    if cases[name]['mode'] == 1:
                        self.assertEqual([(item.entered, item.exited, item.exit_calls)
                            for item in fixture.temporaries], [(True, True, 1)])
                    foreign.append({'case': name, 'port': port_name, 'injected': error_type.__name__,
                        'same_exception_object': True, 'confirmed_custody_released': True,
                        'original_cleanup_completed': True, 'events': events,
                        'trace': fixture.trace.events, 'store_effects': fixture.store_effects})
        self.write('native-loss.json', unknown)
        self.write('confirmed-foreign.json', foreign)
        self.assertEqual((len(unknown), len(foreign)), (70, 60))

    def test_nested_compile_native_loss_fences_ancestors_and_foreign_errors_confirm(self):
        case = case_by_name()['composed.canonical']
        actual_entry, original_effect = self.image._entry, native.EmissionFrame.effect
        initializer = native.EmissionFrame.__init__
        unknown, foreign = [], []
        for is_unknown in (True, False):
            for port_name in ('compile_call', 'compile_exit_normal', 'compile_store_object'):
                for error_type in ERROR_TYPES:
                    with self.subTest(unknown=is_unknown, port=port_name, error=error_type.__name__):
                        fixture = oracle.Fixture(case)
                        bind_compile(fixture, self.image)
                        frames, events, hit = [], [], []
                        failure = error_type('nested compile boundary failure')
                        def initialize(frame, *args, **kwargs):
                            initializer(frame, *args, **kwargs)
                            frames.append(frame)
                        def entry(source, size, output, capacity, state, extent):
                            words = struct.unpack('<6Q', ctypes.string_at(source, 48))
                            code = actual_entry(source, size, output, capacity, state, extent)
                            events.append({'mode': words[5], 'event': words[1], 'port': words[3]})
                            if (is_unknown and words[5] == 1 and words[1] == 2
                                    and words[3] == native.PORT[port_name] and not hit):
                                hit.append(True)
                                raise failure
                            return code
                        def effect(frame, port):
                            observed = original_effect(frame, port)
                            if not is_unknown and frame.mode == 1 and port == native.PORT[port_name]:
                                raise failure
                            return observed
                        with fixture.providers(), patch.object(native.EmissionFrame, '__init__', initialize), \
                             patch.object(self.image, '_entry', entry), patch.object(native.EmissionFrame, 'effect', effect):
                            outer = native.EmissionFrame(self.image, 2, fixture.service,
                                fixture.arguments(), namespace=fixture.namespace)
                            with self.assertRaises(BaseException) as caught:
                                outer.finish()
                            self.assertEqual([frame.mode for frame in frames], [2, 1])
                            if is_unknown:
                                self.assertTrue(caught.exception is failure or caught.exception.__cause__ is failure)
                                self.assertTrue(all(frame.native_failed and frame.fenced and frame.unconfirmed
                                                    and not frame.finished for frame in frames))
                                self.assertTrue(all(native._FRAME_CUSTODY.get(id(frame)) is frame for frame in frames))
                                self.assertFalse(any(event['event'] == 3 for event in events))
                                before = encoded({'events': events, 'trace': fixture.trace.events,
                                                  'store': fixture.store_effects})
                                for frame in frames:
                                    with self.assertRaises(native.EmissionUnknown):
                                        frame.finish()
                                self.assertEqual(encoded({'events': events, 'trace': fixture.trace.events,
                                                          'store': fixture.store_effects}), before)
                                unknown.append({'port': port_name, 'injected': error_type.__name__,
                                    'raised': type(caught.exception).__name__, 'active_causal_frames': [2, 1],
                                    'original_exception_or_cause_identity_retained': True,
                                    'all_causal_unknown_custody_retained': True, 'no_replay_after_loss': True,
                                    'events': events, 'trace': fixture.trace.events,
                                    'store_effects': fixture.store_effects})
                            else:
                                self.assertIs(caught.exception, failure)
                                self.assertTrue(all(frame.finished and not frame.native_failed
                                                    and not frame.unconfirmed for frame in frames))
                                self.assertTrue(all(id(frame) not in native._FRAME_CUSTODY for frame in frames))
                                self.assertEqual([event['mode'] for event in events if event['event'] == 3], [1, 2])
                                foreign.append({'port': port_name, 'injected': error_type.__name__,
                                    'same_exception_object': True, 'all_causal_custody_released': True,
                                    'confirmed_frames': [1, 2], 'events': events,
                                    'trace': fixture.trace.events, 'store_effects': fixture.store_effects})
        self.write('nested-native-loss.json', unknown)
        self.write('nested-confirmed-foreign.json', foreign)
        self.assertEqual((len(unknown), len(foreign)), (30, 30))

    def test_owner_thread_and_forged_receipt_refuse_before_foreign_effects(self):
        case = case_by_name()['compile.shared']
        fixture = oracle.Fixture(case)
        with fixture.providers():
            frame = native.EmissionFrame(self.image, 1, fixture.service, fixture.arguments(),
                                         namespace=fixture.namespace)
        failures = []
        def other_thread():
            try:
                frame.finish()
            except BaseException as error:
                failures.append(error)
        thread = threading.Thread(target=other_thread)
        thread.start()
        thread.join()
        self.assertEqual(len(failures), 1)
        self.assertIs(type(failures[0]), native.EmissionUnknown)
        self.assertEqual(fixture.trace.events, [])
        self.assertFalse(frame.effect_started)
        frame._release()
        entry = self.image._entry
        def forged(source, size, output, capacity, state, extent):
            code = entry(source, size, output, capacity, state, extent)
            ctypes.memset(ctypes.addressof(output) + 24, 0, 8)
            return code
        before = set(native._FRAME_CUSTODY)
        with fixture.providers(), patch.object(self.image, '_entry', forged), self.assertRaises(native.EmissionUnknown):
            native.EmissionFrame(self.image, 1, fixture.service, fixture.arguments(), namespace=fixture.namespace)
        self.assertEqual(set(native._FRAME_CUSTODY), before)
        self.assertEqual(fixture.trace.events, [])
        self.write('protocol-observations.json', {'foreign_thread_refused_before_effect': True,
            'forged_initial_receipt_refused_before_effect': True, 'no_new_unknown_effect_custody': True})

    def test_actual_installed_worker_publication_loss_replay_and_source_pinning(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from tests.test_hia_agent_native_tools import AgentToolCase
        from tools.hia_agent_native_qualification import add_program
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope
        from hepta.hia_agent_store import digest
        staging = self.directory / 'source'
        staging.mkdir()
        shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = dict(clean_environment(), PYTHONDONTWRITEBYTECODE='1')

        def run(label, arguments, *, body=None, expected_code=0):
            result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=self.directory,
                env=environment, input=body, capture_output=True, timeout=60)
            (self.directory / (label + '.stdout')).write_bytes(result.stdout)
            (self.directory / (label + '.stderr')).write_bytes(result.stderr)
            if expected_code is not None:
                self.assertEqual(result.returncode, expected_code,
                                 result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
            return result

        run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                      '--wheel-dir', self.directory / 'wheels', staging])
        wheel, = (self.directory / 'wheels').glob('*.whl')
        installed = self.directory / 'installed'
        run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                        '--target', installed, wheel])
        bundle = self.directory / 'bundle.json'
        bundle.write_bytes(encoded({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [{
            'selector': native.SELECTOR, 'manifest_path': str(self.manifest),
            'manifest_sha256': sha256(self.manifest.read_bytes()).hexdigest()}]}))
        bundle_sha = sha256(bundle.read_bytes()).hexdigest()
        script = r'''import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed runtime imported authoring')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_emission_native as native
from hepta import hia_agent_service as api
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'frames':0,'entries':0,'modes':{},'native_publications':0}
def forbidden(*a,**k):raise AssertionError('installed retained emission entered')
for name in ('_compile_reference','_hia_emit_reference'):
    setattr(api.HIAAgentService,name,forbidden)
initialize=native.NativeEmission.__init__
def image_init(self,*a,**k):
    initialize(self,*a,**k);entry=self._entry
    def counted(source,size,output,capacity,state,extent):
        words=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert words[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES
        counts['entries']+=1
        if mode=='lost_ack_valueerror' and words[1]==2 and words[3]==native.PORT['emit_native_put']:
            raise ValueError('controlled lost native publication acknowledgement')
        return result
    self._entry=counted
native.NativeEmission.__init__=image_init
frame_init=native.EmissionFrame.__init__
def frame_count(self,*a,**k):
    frame_init(self,*a,**k);counts['frames']+=1
    name=str(self.mode);counts['modes'][name]=counts['modes'].get(name,0)+1
native.EmissionFrame.__init__=frame_count
effect=native.EmissionFrame.effect
def observed(self,port):
    result=effect(self,port)
    if port==native.PORT['emit_native_put']:
        counts['native_publications']+=1
        if mode=='exit_after_publication':
            counts['unknown_frames']=len(native._FRAME_CUSTODY)
            os.write(2,('EMISSION_COUNTS='+json.dumps(counts,sort_keys=True)+'\n').encode())
            os._exit(73)
    return result
native.EmissionFrame.effect=observed
assert mode in ('normal','lost_ack_valueerror','exit_after_publication')
try:status=main(sys.argv[1:])
finally:
    counts['unknown_frames']=len(native._FRAME_CUSTODY)
    print('EMISSION_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''

        def counts(result):
            prefix = b'EMISSION_COUNTS='
            found = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
            self.assertEqual(len(found), 1, result.stderr.decode(errors='replace'))
            return json.loads(found[0])

        def prepare():
            case = AgentToolCase('runTest')
            workload = {'schema': 'hepta.hia.agent.workload.v1', 'cases': [{
                'function': 'transform', 'arguments': [0], 'expected': {'status': 'returned', 'values': [7]}}],
                'warmup_iterations': 0, 'repetitions': 1}
            with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(bundle), bundle_sha):
                case.setUp()
                case.session.freeze(workload)
                candidate = case.session.import_program(add_program(optimized=True))
                verification = case.session.verify(candidate)
            arguments = case.session.arguments(candidate=candidate, backend_profile=case.session.backend,
                output_kind='shared', codegen={'kind': 'canonical',
                    'lowering_profile': case.session.profiles['lowering']},
                verification_receipts=[verification['verification_receipt']])
            envelope = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_emit',
                'arguments': arguments, 'profile_sha256': 'a' * 64,
                'catalog_sha256': case.service.catalog_sha256}
            envelope['request_sha256'] = sha256(encoded(envelope)).hexdigest()
            case.service.close()
            return case, envelope

        def worker(label, case, envelope, mode='normal', expected_code=0):
            flags = ['-I', '-c', script, installed, mode, '--state-root', case.state_root,
                     '--request-json-stdin', '--native-helpers-manifest', bundle,
                     '--expected-native-helpers-sha256', bundle_sha]
            return run(label, flags, body=encoded(envelope), expected_code=expected_code)

        def retained_state(case, envelope):
            key = digest({'tool': envelope['tool'], 'key': envelope['arguments']['request_key']})
            with sqlite3.connect(case.state_root / 'state.sqlite3') as db:
                db.row_factory = sqlite3.Row
                row = db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
                return {'request': None if row is None else dict(row),
                    'artifact_kinds': {name: number for name, number in db.execute(
                        'SELECT kind,COUNT(*) FROM artifacts GROUP BY kind').fetchall()},
                    'artifacts': [dict(row) for row in db.execute('SELECT * FROM artifacts ORDER BY id')],
                    'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}

        observations = {}
        zero = {'frames': 0, 'entries': 0, 'modes': {}, 'native_publications': 0, 'unknown_frames': 0}
        case, envelope = prepare()
        try:
            before_first = retained_state(case, envelope)
            first = worker('first', case, envelope)
            retained_before = retained_state(case, envelope)
            replay = worker('replay', case, envelope)
            retained_after = retained_state(case, envelope)
            first_report, replay_report = json.loads(first.stdout), json.loads(replay.stdout)
            first_counts, replay_counts = counts(first), counts(replay)
            self.assertEqual(first_report['response']['status'], 'completed', first_report)
            self.assertTrue(first_report['response']['result']['linker_used'])
            self.assertEqual(replay_report, first_report)
            self.assertEqual(first_report['native_helpers_sha256'], bundle_sha)
            self.assertEqual(first_counts['modes'], {'1': 1, '2': 1})
            self.assertEqual(first_counts['frames'], 2)
            self.assertEqual(first_counts['native_publications'], 1)
            self.assertEqual(first_counts['unknown_frames'], 0)
            self.assertGreater(first_counts['entries'], 0)
            self.assertEqual(replay_counts, zero)
            self.assertEqual(retained_after, retained_before)
            for kind in ('build-object', 'native', 'build-receipt'):
                self.assertEqual(retained_before['artifact_kinds'].get(kind, 0),
                                 before_first['artifact_kinds'].get(kind, 0) + 1)
            observations['first'] = {'report': first_report, 'counts': first_counts,
                'retained_before': before_first, 'retained_after': retained_before}
            observations['replay'] = {'report': replay_report, 'counts': replay_counts,
                'retained_before': retained_before, 'retained_after': retained_after}
        finally:
            case.tearDown()

        for label, mode, exit_code in (('native_ack', 'lost_ack_valueerror', 1),
                                       ('process_loss', 'exit_after_publication', 73)):
            case, envelope = prepare()
            try:
                before_attempt = retained_state(case, envelope)
                lost = worker(label, case, envelope, mode, exit_code)
                lost_counts = counts(lost)
                self.assertEqual(lost_counts['frames'], 2)
                self.assertEqual(lost_counts['modes'], {'1': 1, '2': 1})
                self.assertEqual(lost_counts['native_publications'], 1)
                self.assertEqual(lost_counts['unknown_frames'], 1)
                self.assertEqual(lost.stdout, b'')
                if mode == 'lost_ack_valueerror':
                    self.assertIn(b'EmissionUnknown', lost.stderr)
                before = retained_state(case, envelope)
                self.assertEqual(before['request']['state'], 'running')
                self.assertIsNone(before['request']['response'])
                for kind in ('build-object', 'native'):
                    self.assertEqual(before['artifact_kinds'].get(kind, 0),
                                     before_attempt['artifact_kinds'].get(kind, 0) + 1)
                self.assertEqual(before['artifact_kinds'].get('build-receipt', 0),
                                 before_attempt['artifact_kinds'].get('build-receipt', 0))
                replay = worker(label + '-replay', case, envelope)
                report, replay_counts = json.loads(replay.stdout), counts(replay)
                after = retained_state(case, envelope)
                self.assertEqual(report['response']['status'], 'rejected', report)
                self.assertEqual(report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                self.assertEqual(replay_counts, zero)
                self.assertEqual(after['request'], before['request'])
                self.assertEqual(after['artifacts'], before['artifacts'])
                observations[label] = {'native_counts': lost_counts, 'retained_before_attempt': before_attempt,
                    'retained_before_replay': before, 'retained_after_replay': after,
                    'replay': report, 'replay_counts': replay_counts, 'lost_worker_exit_code': lost.returncode}
                if mode == 'exit_after_publication':
                    source = installed / 'hepta/_data/examples/hia_bootstrap/emission.hepta'
                    original_source = source.read_bytes()
                    self.assertEqual(original_source, native.SOURCE.read_bytes())
                    source.write_bytes(original_source + b'\n')
                    drift = worker('changed-installed-source', case, envelope, expected_code=None)
                    self.assertNotEqual(drift.returncode, 0)
                    self.assertEqual(drift.stdout, b'')
                    self.assertEqual(counts(drift), zero)
                    observations['installed_source_drift'] = {'worker_exit_code': drift.returncode,
                        'before_sha256': sha256(original_source).hexdigest(),
                        'after_sha256': sha256(source.read_bytes()).hexdigest(), 'native_counts': counts(drift)}
            finally:
                case.tearDown()
        observations.update({'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'bundle_sha256': bundle_sha, 'both_references_forbidden_in_actual_child': True,
            'qualification_topology': 'fresh-wheel actual installed worker with emission helper',
            'authoring_imports_forbidden_in_actual_child': True, 'original_worker_used': True,
            'whole_native_delivery_qualified': False})
        self.write('installed-observations.json', observations)

    def test_eight_owner_emission_evaluation_adoption_and_exact_replay(self):
        from contextlib import ExitStack
        from hepta import hia_native_helpers as helpers
        from hepta import hia_agent_store as store_module
        from hepta import hia_execution_budget as budget_module
        from hepta import hia_execution_budget_native as execution
        from hepta import hia_candidate_budget_native as candidate
        from hepta import hia_service_context_native as context
        from hepta import hia_cost_ledger_native as ledger
        from hepta import hia_evaluation_native as evaluation
        from tools.build_hia_evaluation import build as build_evaluation
        from tools.build_hia_native_build_admission import build as build_admission
        from tests.test_hia_agent_native_tools import AgentToolCase
        from tests.test_hia_service_context_native import poison as poison_context
        from tools.build_hia_store_lifecycle import build as build_store
        from tools.build_hia_service_context import build as build_context
        from tools.build_hia_cost_ledger import build as build_ledger
        from tools.build_hia_execution_budget import build as build_execution
        from tools.build_hia_candidate_budget import build as build_candidate
        from tools.qualify_hia_selfhost import compile_stage

        root = self.directory / 'eight-owner-composition'
        root.mkdir()
        manifests = {native.SELECTOR: self.manifest}
        for selector, builder, label in (
                ('HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST', build_admission, 'native-build-admission'),
                ('HEPTA_HIA_STORE_LIFECYCLE_MANIFEST', build_store, 'store-lifecycle'),
                (context.SELECTOR, build_context, 'service-context'),
                (ledger.SELECTOR, build_ledger, 'cost-ledger'),
                (evaluation.SELECTOR, build_evaluation, 'evaluation')):
            manifests[selector] = builder(root / label, self.compiler, self.cold,
                                           development=self.cold is None)
        for module, builder, label in ((execution, build_execution, 'execution-budget'),
                                       (candidate, build_candidate, 'candidate-budget')):
            directory = root / label
            if self.cold is not None:
                manifest = builder(directory, self.compiler, Path(self.cold))
            else:
                directory.mkdir()
                source = module.SOURCE.read_bytes()
                image, receipt = compile_stage(directory, label, self.compiler, source)
                self.assertEqual(module.SOURCE.read_bytes(), source)
                value = {'schema': module.SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(self.compiler_raw).hexdigest()}
                manifest = directory / 'manifest.json'
                manifest.write_text(json.dumps(value, sort_keys=True) + '\n')
                (directory / 'development-build.json').write_text(json.dumps({
                    'scope': 'DEVELOPMENT_COMPONENT', 'manifest': value,
                    'native_compile_receipt': receipt}, sort_keys=True) + '\n')
            manifests[module.SELECTOR] = manifest
        bundle = root / 'bundle.json'
        bundle.write_bytes(encoded({'schema': helpers.SCHEMA, 'target': helpers.TARGET,
            'abi': helpers.ABI, 'helpers': [{'selector': selector,
                'manifest_path': str(path.resolve()),
                'manifest_sha256': sha256(path.read_bytes()).hexdigest()}
                for selector, path in sorted(manifests.items())]}))
        bundle_sha = sha256(bundle.read_bytes()).hexdigest()
        reference_calls = []

        def forbidden(*arguments, **keywords):
            reference_calls.append('retained policy')
            raise AssertionError('eight-owner evaluation entered a retained policy')

        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, clean_environment(), clear=True))
            binding = stack.enter_context(helpers.native_helpers_scope(str(bundle), bundle_sha))
            poison_context(stack)
            for name in ('_NATIVE_STORE_INITIALIZE_REFERENCE', '_NATIVE_STORE_CLOSE_REFERENCE'):
                stack.enter_context(patch.object(store_module, name, forbidden))
            for name in ('_initialize_reference', '_close_reference'):
                stack.enter_context(patch.object(store_module.AgentStore, name, forbidden))
            stack.enter_context(patch.object(budget_module, '_ReferenceExecutionBudgetStore', forbidden))
            for name in ('_reference_consume_attempt', '_cost_ledger_reference', '_hia_evaluate_reference'):
                stack.enter_context(patch.object(api.HIAAgentService, name, forbidden))
            stack.enter_context(patch.object(api, '_signatures_reference', forbidden))
            for method in ('_native_reference', '_build_inputs_reference', '_build_receipt_reference',
                           '_compile_reference', '_hia_emit_reference'):
                stack.enter_context(patch.object(api.HIAAgentService, method, forbidden))
            self.assertEqual(len(binding.images), 8)
            images = {key[0]: image for key, image in binding.images.items()}
            spies = {selector: stack.enter_context(patch.object(images[str(path.resolve())], '_entry',
                wraps=images[str(path.resolve())]._entry)) for selector, path in manifests.items()}
            self.assertEqual(set(spies), set(manifests))
            case = AgentToolCase('runTest')
            case.setUp()
            try:
                workload = {'schema': 'hepta.hia.agent.workload.v1', 'cases': [{
                    'function': 'transform', 'arguments': [0],
                    'expected': {'status': 'returned', 'values': [7]}}],
                    'warmup_iterations': 0, 'repetitions': 1}
                _, _, baseline, build, receipts = case.build_pair(workload=workload,
                    budget={'max_total_wall_ms': 3000, 'max_native_wall_ms': 1000})
                arguments = case.session.arguments(baseline_artifact=baseline['native_artifact'],
                    candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
                    verification_receipts=receipts)
                first = case.client.call('hia_evaluate', arguments)
                self.assertEqual(first['status'], 'completed', first)
                result = first['result']
                for flag in ('report_complete', 'planned_workload_complete', 'termination_confirmed'):
                    self.assertTrue(result[flag])
                self.assertFalse(result['adopted'])
                measurements, _ = case.service.store.get_json(result['measurements'])
                costs, _ = case.service.store.get_json(result['full_cost_ledger'])
                receipt, _ = case.service.store.get_json(result['evaluation_receipt'])
                self.assertEqual(measurements['planned_cases'], 1)
                self.assertEqual(len(measurements['observations']), 1)
                self.assertTrue(measurements['planned_workload_complete'])
                self.assertFalse(measurements['universal_equivalence_or_native_refinement_proved'])
                for arm in ('baseline', 'candidate'):
                    run = measurements['native_runs'][arm]['normal']
                    self.assertTrue(run['started'])
                    self.assertTrue(run['termination_confirmed'])
                self.assertEqual(costs['context'], arguments['context'])
                self.assertFalse(costs['full_search_cost_complete'])
                self.assertFalse(costs['net_optimization_benefit_proved'])
                self.assertEqual(receipt['measurements'], result['measurements'])
                self.assertEqual(receipt['full_cost_ledger'], result['full_cost_ledger'])
                context_id = arguments['context']['id']
                budget_before = dict(case.service.store.db.execute(
                    'SELECT * FROM execution_budgets WHERE context_id=?', (context_id,)).fetchone())
                self.assertIsNone(budget_before['owner'])
                self.assertEqual(budget_before['used_native_ns'], costs['native_child_wall_ns'])
                before = {selector: spy.call_count for selector, spy in spies.items()}
                changes_before = case.service.store.db.total_changes
                replay = case.client.call('hia_evaluate', arguments)
                after = {selector: spy.call_count for selector, spy in spies.items()}
                self.assertEqual(replay, first)
                self.assertEqual(after, before)
                self.assertEqual(case.service.store.db.total_changes, changes_before)
                budget_after = dict(case.service.store.db.execute(
                    'SELECT * FROM execution_budgets WHERE context_id=?', (context_id,)).fetchone())
                self.assertEqual(budget_after, budget_before)
                adoption_arguments = case.session.arguments(target_slot='native-build-composition',
                    expected_current={'generation': '0', 'epoch': '0'},
                    candidate_artifact=build['native_artifact'],
                    evaluation_receipt=result['evaluation_receipt'], verification_receipts=receipts)
                adoption = case.client.call('hia_adopt', adoption_arguments)
                self.assertEqual(adoption['status'], 'completed', adoption)
                self.assertEqual(adoption['result']['active_artifact'], build['native_artifact'])
                adoption_before = {selector: spy.call_count for selector, spy in spies.items()}
                adoption_changes = case.service.store.db.total_changes
                adoption_replay = case.client.call('hia_adopt', adoption_arguments)
                self.assertEqual(adoption_replay, adoption)
                self.assertEqual(case.service.store.db.total_changes, adoption_changes)
                adoption_after = {selector: spy.call_count for selector, spy in spies.items()}
                adoption_changes_after = case.service.store.db.total_changes
                self.assertEqual(adoption_after, adoption_before)
            finally:
                case.tearDown()
            counts = {selector: spy.call_count for selector, spy in spies.items()}
            self.assertTrue(all(count > 0 for count in counts.values()), counts)
        self.assertEqual(reference_calls, [])
        (root / 'composition.json').write_text(json.dumps({
            'schema': 'hepta.hia.emission-eight-owner-composition.v1',
            'scope': 'DEVELOPMENT_COMPONENT' if self.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'qualification_topology': 'source-process eight-owner public composition',
            'installed_eight_owner_worker_observed': False,
            'cross_owner_native_delivery_loss_tracking_implemented': False,
            'bundle': str(bundle), 'bundle_sha256': bundle_sha,
            'manifests': {selector: str(path) for selector, path in manifests.items()},
            'actual_native_entries': counts, 'entries_before_replay': before,
            'entries_after_replay': after, 'replay_additional_entries': {
                selector: after[selector] - before[selector] for selector in before},
            'first_response': first, 'replayed_response': replay,
            'adoption_response': adoption, 'adoption_replay': adoption_replay,
            'adoption_entries_before_replay': adoption_before,
            'adoption_entries_after_replay': adoption_after,
            'adoption_replay_additional_entries': {
                selector: adoption_after[selector] - adoption_before[selector] for selector in adoption_before},
            'adoption_durable_changes_on_replay': adoption_changes_after - adoption_changes,
            'baseline_emission': baseline, 'candidate_emission': build,
            'both_emission_retained_bodies_forbidden': True,
            'all_four_admission_retained_bodies_forbidden': True,
            'measurements': measurements, 'ledger': costs, 'evaluation_receipt': receipt,
            'budget_before_replay': budget_before, 'budget_after_replay': budget_after,
            'original_context_wall_ms': 3000, 'original_native_wall_ms': 1000,
            'durable_changes_on_replay': 0, 'reference_calls': reference_calls,
            'all_eight_retained_policy_references_forbidden': True,
            'hosted_request_journal_sqlite_runner_and_object_protocols_retained': True,
            'source_and_compiler_custody_owned_by_outer_component': True,
            'whole_native_delivery_qualified': False}, indent=2, sort_keys=True) + '\n')



if __name__ == '__main__':
    unittest.main()
