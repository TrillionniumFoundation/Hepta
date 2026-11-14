"""Actual Store lifecycle policy, public routing and complete continuation controls."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_agent_store as api
from hepta import hia_store_lifecycle_native as native
from tests import hia_store_lifecycle_fixtures as fixtures

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/hia_store_lifecycle_original_v86.json'


def _fields(value):
    if isinstance(value, ast.AST):
        return (type(value).__name__, tuple((key, _fields(item)) for key, item in ast.iter_fields(value)))
    if isinstance(value, list):
        return tuple(_fields(item) for item in value)
    return (type(value).__name__, value)


def _reference_methods():
    return ('_initialize_reference', '_close_reference')


def _reference_aliases():
    return ('_NATIVE_STORE_INITIALIZE_REFERENCE', '_NATIVE_STORE_CLOSE_REFERENCE')


def _clean_environment():
    return {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_HIA_')}


class StoreLifecycleSourceTests(unittest.TestCase):
    def test_two_exact_original_bodies_preserve_sql_and_reference_definitions(self):
        original = json.loads(ORIGINAL.read_bytes())
        policy = next(node for node in ast.parse((ROOT / 'tools/hia_store_lifecycle_policy.py').read_bytes()).body
                      if isinstance(node, ast.ClassDef))
        current = next(node for node in ast.parse((ROOT / 'hepta/hia_agent_store.py').read_bytes()).body
                       if isinstance(node, ast.ClassDef) and node.name == 'AgentStore')
        self.assertEqual(tuple(node.name for node in policy.body), ('__init__', 'close'))
        self.assertEqual(native.ARITIES, {'__init__': 2, 'close': 1})
        for name, reference in zip(('__init__', 'close'), _reference_methods()):
            row = original['methods'][name]
            self.assertEqual(sha256(row['source'].encode()).hexdigest(), row['sha256'])
            expected = ast.parse('class AgentStore:\n' + row['source']).body[0].body[0]
            authored = next(node for node in policy.body if node.name == name)
            retained = next(node for node in current.body if isinstance(node, ast.FunctionDef) and node.name == reference)
            retained.name = name
            self.assertEqual(_fields(authored), _fields(expected))
            self.assertEqual(_fields(retained), _fields(expected))

    def test_hia_and_foreign_generated_inputs_are_exact(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_store_lifecycle import document, program, table
        from tools.generate_hia_store_lifecycle_foreign import source
        compiled = program()
        self.assertEqual([(function.name, function.kind) for function in compiled.functions],
                         [('__init__', 'function'), ('close', 'function')])
        self.assertEqual(render_assembly(document()).encode(), native.SOURCE.read_bytes())
        self.assertEqual(source().encode(), (ROOT / 'hepta/hia_store_lifecycle_foreign.py').read_bytes())
        namespace = ast.parse(source())
        table_sha = next(ast.literal_eval(node.value) for node in namespace.body
                         if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'TABLE_SHA256' for target in node.targets))
        self.assertEqual(sha256(table(compiled)).hexdigest(), table_sha)

    def test_nested_handler_extension_requires_its_exact_reviewed_input(self):
        from tools.generate_hia_machine_plan_control import BODY
        from tools.hia_store_lifecycle_regions import region_control_body
        accepted = region_control_body(BODY)
        self.assertIn('preserve_contains', accepted)
        for altered in (BODY + '\n', BODY.replace('def unwind(', 'def unexpected(', 1)):
            with self.subTest(altered=sha256(altered.encode()).hexdigest()), self.assertRaises(ValueError):
                region_control_body(altered)

    def test_runtime_uses_fixed_effect_ports_without_original_policy_callbacks(self):
        for path in ('hepta/hia_store_lifecycle_native.py', 'hepta/hia_store_lifecycle_foreign.py'):
            tree = ast.parse((ROOT / path).read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith(('tools', 'tests')))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ('compile', 'exec', 'eval'))
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, (*_reference_methods(), *_reference_aliases()))

    def test_only_actual_store_held_capability_is_registered(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_checker_identity import HELD_NATIVE_OWNERS, NATIVE_OWNERS, CAPTURED_NATIVE_OWNERS
        from hepta.hia_native_helpers import HELPERS
        from tools.hia_selfhost_contract import SOURCE_FILES
        expected = ('hia_store_lifecycle_native', 'NativeStoreLifecycleImage')
        self.assertEqual(HELPERS[native.SELECTOR], expected)
        self.assertEqual(HELD_NATIVE_OWNERS[native.SELECTOR], expected)
        self.assertNotIn(native.SELECTOR, NATIVE_OWNERS)
        self.assertNotIn(native.SELECTOR, CAPTURED_NATIVE_OWNERS)
        self.assertIn('examples/hia_bootstrap/store_lifecycle.hepta', NATIVE_SOURCE_FILES)
        for path in ('hepta/hia_store_lifecycle_selection.py', 'tools/hia_store_lifecycle_regions.py',
                     'tests/hia_store_lifecycle_observations.py', 'tools/build_hia_store_lifecycle.py',
                     'tools/qualify_hia_store_lifecycle.py'):
            self.assertIn(path, SOURCE_FILES)

    def test_default_import_and_absence_do_not_import_fixed_abi_ports(self):
        code = """import os, sys
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_'): del os.environ[key]
from hepta.hia_store_lifecycle_selection import capture_store_lifecycle
from hepta import hia_agent_store
assert capture_store_lifecycle() is None
assert 'hepta.hia_store_lifecycle_native' not in sys.modules
assert 'hepta.hia_store_lifecycle_foreign' not in sys.modules
"""
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT,
                                env=_clean_environment(), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace'))


class StoreLifecycleNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import build_hia_store_lifecycle as builder
        cold = os.environ.get('HEPTA_HIA_STORE_LIFECYCLE_COLD_REPORT')
        compiler_choice = os.environ.get('HEPTA_HIA_STORE_LIFECYCLE_DEVELOPMENT_COMPILER')
        manifest_choice = os.environ.get('HEPTA_HIA_STORE_LIFECYCLE_DEVELOPMENT_MANIFEST')
        if sum(bool(value) for value in (cold, compiler_choice, manifest_choice)) != 1:
            raise ValueError('Store lifecycle requires one explicit cold, development compiler or development manifest')
        cls.inputs = {}
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_STORE_LIFECYCLE_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-store-lifecycle-')
            cls.folder = Path(cls.temporary.name)
        if cold:
            cold = Path(cold).resolve(strict=True)
            outer = json.loads(cold.read_bytes(), object_pairs_hook=builder._pairs)
            nested_path = Path(outer['nested_report']).resolve(strict=True)
            nested_bytes = nested_path.read_bytes()
            if sha256(nested_bytes).hexdigest() != outer['nested_report_sha256']:
                raise ValueError('Store lifecycle cold nested report identity differs')
            nested = json.loads(nested_bytes, object_pairs_hook=builder._pairs)
            compiler = Path(nested['generations'][-1]['produced_image']).resolve(strict=True)
            cls.manifest_path = builder.build(cls.folder / 'current-cold-build', compiler, cold)
            mode = 'MATCHING_CURRENT_SOURCE_COLD'
            for path in (cold, nested_path, compiler):
                cls.inputs[str(path)] = sha256(path.read_bytes()).hexdigest()
        elif compiler_choice:
            compiler = Path(compiler_choice).resolve(strict=True)
            cls.manifest_path = builder.build_development(cls.folder / 'development-build', compiler)
            mode = 'EXPLICIT_COMPILER_DEVELOPMENT'
            cls.inputs[str(compiler)] = sha256(compiler.read_bytes()).hexdigest()
        else:
            cls.manifest_path = Path(manifest_choice).resolve(strict=True)
            mode = 'EXPLICIT_MANIFEST_DEVELOPMENT'
        cls.image = native.installed_store_lifecycle(cls.manifest_path)
        record = json.loads(cls.manifest_path.read_bytes())
        cls.inputs[str(cls.manifest_path)] = sha256(cls.manifest_path.read_bytes()).hexdigest()
        cls.inputs[str(cls.manifest_path.parent / record['image_path'])] = record['image_sha256']
        cls.inputs.update({str(ROOT / name): sha256((ROOT / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES})
        cls.record('fixture', {'mode': mode, 'manifest': str(cls.manifest_path), 'inputs': cls.inputs,
                              'python': sys.version, 'whole_native': False, 'production_default_changed': False})

    @classmethod
    def record(cls, name, value):
        with (cls.folder / (name + '.json')).open('x', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')

    @classmethod
    def tearDownClass(cls):
        after = {name: sha256(Path(name).read_bytes()).hexdigest() for name in cls.inputs}
        cls.record('source-and-input-after', after)
        cls.record('actual-image', {'image_sha256': cls.image.image_sha256,
                                  'native_frame_invocations': cls.image.entries,
                                  'opcode_counts': cls.image.observations})
        if after != cls.inputs:
            raise AssertionError('Store lifecycle source or actual inputs changed')
        if cls.temporary:
            cls.temporary.cleanup()

    def test_all_ninety_original_provider_observations(self):
        from tests.hia_store_lifecycle_observations import run_case
        rows = []
        for closing, scenarios in ((False, fixtures.SCENARIOS), (True, (
                'close_all', 'close_missing_optional', 'fail:close:ledger', 'fail:close:namespace',
                'fail:close:request', 'fail:close:budget', 'fail:close:database'))):
            for scenario in scenarios:
                for ambient in (False, True):
                    with self.subTest(scenario=scenario, ambient=ambient, closing=closing):
                        if ambient:
                            try:
                                raise LookupError('outer handled exception')
                            except LookupError:
                                expected = run_case(self.image, scenario, False, ambient, closing)
                                actual = run_case(self.image, scenario, True, ambient, closing)
                        else:
                            expected = run_case(self.image, scenario, False, ambient, closing)
                            actual = run_case(self.image, scenario, True, ambient, closing)
                        rows.append({'scenario': scenario, 'ambient': ambient, 'closing': closing,
                                     'expected': expected, 'actual': actual, 'equal': expected == actual})
                        self.assertEqual(actual, expected)
        self.record('original-ninety', rows)
        self.assertEqual(len(rows), 90)

    def test_held_error_twenty_original_lifetimes(self):
        from tests.hia_store_lifecycle_observations import observe
        rows = []
        for scenario in ('all-cleanup-errors', 'clear-owner-references', 'note-failure-1',
                         'note-failure-2', 'note-failure-3', 'note-failure-4', 'handler-unmatched',
                         'handler-invalid', 'type-failure', 'type-name-failure'):
            for ambient in (False, True):
                with self.subTest(scenario=scenario, ambient=ambient):
                    if ambient:
                        try:
                            raise LookupError('outer handled exception')
                        except LookupError:
                            expected = observe(self.image, scenario, False)
                            actual = observe(self.image, scenario, True)
                    else:
                        expected = observe(self.image, scenario, False)
                        actual = observe(self.image, scenario, True)
                    rows.append({'scenario': scenario, 'ambient': ambient, 'expected': expected,
                                 'actual': actual, 'equal': expected == actual})
                    self.assertEqual(actual, expected)
                    self.assertTrue(expected['finally_released'])
                    self.assertTrue(actual['finally_released'])
        self.record('held-error-twenty', rows)
        self.assertEqual(len(rows), 20)

    def test_public_service_request_and_close_use_actual_held_image(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_checker_identity import checker_native_selection
        from hepta.hia_store_lifecycle_selection import store_lifecycle_owner
        environment = _clean_environment(); environment[native.SELECTOR] = str(self.manifest_path)
        with tempfile.TemporaryDirectory(prefix='store-public-service-') as folder, patch.dict(os.environ, environment, clear=True), ExitStack() as stack:
            guards = [stack.enter_context(patch.object(api, name, side_effect=AssertionError('retained policy entered'))) for name in _reference_aliases()]
            guards += [stack.enter_context(patch.object(api.AgentStore, name, side_effect=AssertionError('retained policy entered'))) for name in _reference_methods()]
            before = self.image.entries
            service = HIAAgentService(Path(folder) / 'state')
            try:
                owner = store_lifecycle_owner(service.store)
                self.assertIs(owner.image, self.image)
                selection = checker_native_selection(held_owners=service._held_checker_owners())
                self.assertIn(native.SELECTOR, selection)
                response = service.call('hia_describe', {'section': 'manifest'})
                self.assertEqual(response['status'], 'completed', response)
                os.environ[native.SELECTOR] = str(Path(folder) / 'missing-new-selection')
                held_again = checker_native_selection(held_owners=service._held_checker_owners())
                self.assertEqual(selection, held_again)
            finally:
                service.close()
            self.assertGreater(self.image.entries, before)
            self.assertTrue(all(guard.call_count == 0 for guard in guards))
            self.record('public-service', {'response': response, 'held_selection': selection,
                                        'native_entries': self.image.entries - before, 'old_body_calls': 0})

    def test_initial_absence_and_selected_constructor_each_capture_close_route(self):
        from hepta.hia_store_lifecycle_selection import store_lifecycle_owner
        environment = _clean_environment()
        with tempfile.TemporaryDirectory(prefix='store-route-capture-') as folder, patch.dict(os.environ, environment, clear=True):
            root = Path(folder)
            absent = api.AgentStore(root / 'absent')
            self.assertIsNone(store_lifecycle_owner(absent))
            os.environ[native.SELECTOR] = str(self.manifest_path)
            before = self.image.entries
            with patch.object(native, 'installed_store_lifecycle', side_effect=AssertionError('close re-admitted ambient selector')):
                absent.close()
            self.assertEqual(self.image.entries, before)
            selected = api.AgentStore(root / 'selected')
            bound = store_lifecycle_owner(selected)
            os.environ.pop(native.SELECTOR)
            with patch.object(api, '_NATIVE_STORE_CLOSE_REFERENCE', side_effect=AssertionError('selected close fell back')):
                selected.close()
            self.assertIs(store_lifecycle_owner(selected), bound)
            self.assertGreater(self.image.entries, before)
            os.environ[native.SELECTOR] = str(root / 'missing-manifest')
            with self.assertRaises(FileNotFoundError):
                api.AgentStore(root / 'refused-before-effects')
            self.assertFalse((root / 'refused-before-effects').exists())

    def test_held_capability_refuses_forgery_or_changed_mapping_metadata(self):
        from hepta.hia_checker_identity import HeldNativeOwner, checker_native_selection
        from hepta.hia_store_lifecycle_selection import bind_store_lifecycle, store_lifecycle_owner
        custody = native.installed_store_lifecycle(self.manifest_path, capture_identity=True)
        with self.assertRaises(RuntimeError):
            native.NativeStoreLifecycleOwner({'image': custody.image})
        with self.assertRaises(ValueError):
            checker_native_selection(held_owners=(replace(custody, source=b'changed-source'),))
        owner = native.NativeStoreLifecycleOwner(custody)
        original = self.image.image_sha256
        try:
            self.image.image_sha256 = '0' * 64
            with self.assertRaises(ValueError):
                owner.checker_owner()
        finally:
            self.image.image_sha256 = original
        self.assertIs(owner.checker_owner(), custody)
        fake = object.__new__(api.AgentStore)
        with self.assertRaises(ValueError):
            bind_store_lifecycle(fake, {'image': self.image})
        self.assertIsNone(store_lifecycle_owner(fake))

    def test_subclass_hooks_and_inherited_attributes_do_not_choose_the_owner(self):
        import weakref
        from hepta import hia_store_lifecycle_selection as selection
        environment = _clean_environment()
        rows = []

        def observe(kind, selected):
            trace = []
            if kind == 'attributes':
                class Store(api.AgentStore):
                    def __getattribute__(self, name):
                        trace.append(('get', name))
                        return object.__getattribute__(self, name)

                    def __setattr__(self, name, value):
                        trace.append(('set', name))
                        return object.__setattr__(self, name, value)
            elif kind == 'inherited':
                class Store(api.AgentStore):
                    _native_store_lifecycle = {'business': 'inherited value'}
            else:
                class Store(api.AgentStore):
                    def __hash__(self):
                        raise AssertionError('adapter invoked Store hash')

                    def __eq__(self, other):
                        raise AssertionError('adapter invoked Store equality')

                    @property
                    def _native_store_lifecycle(self):
                        raise AssertionError('adapter invoked business descriptor')

                    @_native_store_lifecycle.setter
                    def _native_store_lifecycle(self, value):
                        raise AssertionError('adapter overwrote business descriptor')
            with tempfile.TemporaryDirectory(prefix='store-subclass-') as directory:
                store = object.__new__(Store)
                if selected:
                    api.AgentStore.__init__(store, Path(directory) / 'state')
                    self.assertIs(selection.store_lifecycle_owner(store).image, self.image)
                    api.AgentStore.close(store)
                else:
                    api._NATIVE_STORE_INITIALIZE_REFERENCE(store, Path(directory) / 'state')
                    api._NATIVE_STORE_CLOSE_REFERENCE(store)
                return trace

        with patch.dict(os.environ, environment, clear=True):
            for kind in ('attributes', 'inherited', 'hash-and-descriptor'):
                expected = observe(kind, False)
                os.environ[native.SELECTOR] = str(self.manifest_path)
                actual = observe(kind, True)
                os.environ.pop(native.SELECTOR)
                rows.append({'case': kind, 'expected': expected, 'actual': actual, 'equal': actual == expected})
                self.assertEqual(actual, expected)
            # The two original default-route counterexamples are retained too.
            for kind in ('attributes', 'inherited'):
                trace = []
                class DefaultStore(api.AgentStore):
                    _native_store_lifecycle = {'business': 'inherited value'}
                    def __getattribute__(self, name):
                        if kind == 'attributes':
                            trace.append(name)
                        return object.__getattribute__(self, name)
                with tempfile.TemporaryDirectory(prefix='store-default-subclass-') as directory:
                    store = DefaultStore(Path(directory) / 'state')
                    trace.clear(); api.AgentStore.close(store)
                    actual = list(trace)
                    trace.clear(); api._NATIVE_STORE_CLOSE_REFERENCE(store)
                    expected = list(trace)
                    self.assertEqual(actual, expected)
                    self.assertIsNone(selection.store_lifecycle_owner(store))
                    rows.append({'case': 'default-' + kind, 'expected': expected, 'actual': actual, 'equal': actual == expected})

        # No business resources or cycles are present in this storage-only
        # check. Dropping the sole Store reference must retire the binding.
        custody = native.installed_store_lifecycle(self.manifest_path, capture_identity=True)
        owner = native.NativeStoreLifecycleOwner(custody)
        store = object.__new__(api.AgentStore); key = id(store)
        selection.bind_store_lifecycle(store, owner)
        reference = weakref.ref(store)
        self.assertIs(selection.store_lifecycle_owner(store), owner)
        del store
        self.assertIsNone(reference())
        self.assertNotIn(key, selection._BOUND_STORES)
        rows.append({'case': 'weak-reference-retirement', 'store_dead': True, 'binding_removed': True})
        self.record('subclass-and-binding', rows)

    def test_protocol_complete_native_buffers_equal_independent_vm(self):
        from tests.hia_store_lifecycle_observations import run_case
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        output = self.folder / 'protocol'; output.mkdir()
        pool = output / 'buffers'; pool.mkdir()
        frames, cases, vm_rows = [], [], []
        actual_entry = self.image._entry

        def keep(raw):
            digest = sha256(raw).hexdigest(); path = pool / (digest + '.bin')
            if path.exists():
                self.assertEqual(path.read_bytes(), raw)
            else:
                path.write_bytes(raw)
            return {'bytes': len(raw), 'sha256': digest}

        def counted(source, size, result, capacity, state, extent):
            before = [ctypes.string_at(pointer, length) for pointer, length in ((source, size), (result, capacity), (state, extent))]
            guarded = [ctypes.create_string_buffer(b'Z' * 16 + raw + b'Y' * 16, len(raw) + 32) for raw in before]
            returned = actual_entry(ctypes.addressof(guarded[0]) + 16, size,
                                    ctypes.addressof(guarded[1]) + 16, capacity,
                                    ctypes.addressof(guarded[2]) + 16, extent)
            after = [buffer.raw[16:-16] for buffer in guarded]
            self.assertEqual(after[0], before[0])
            self.assertTrue(all(buffer.raw[:16] == b'Z' * 16 and buffer.raw[-16:] == b'Y' * 16 for buffer in guarded))
            frames.append({'index': len(frames), 'command': struct.unpack_from('<Q', before[2])[0],
                           'returned': returned, 'before': [keep(raw) for raw in before],
                           'after': [keep(raw) for raw in after], 'canaries_unchanged': True})
            ctypes.memmove(result, after[1], capacity); ctypes.memmove(state, after[2], extent)
            return returned

        with patch.object(self.image, '_entry', counted):
            for closing, scenario in ((False, 'no_native_admissions'), (False, 'fail:create:ledger+cleanup_failure'), (True, 'close_all')):
                expected = run_case(self.image, scenario, False, False, closing)
                actual = run_case(self.image, scenario, True, False, closing)
                cases.append({'scenario': scenario, 'closing': closing, 'expected': expected, 'actual': actual})
                self.assertEqual(actual, expected)
            initial_count = len(frames)
            program = assemble_program(native.SOURCE.read_bytes())
            function = program.as_dict()['functions'][0]
            for row in frames:
                before = [(pool / (item['sha256'] + '.bin')).read_bytes() for item in row['before']]
                owners = [_Owner(-1 - index, bytearray(raw)) for index, raw in enumerate(before)]
                machine = _Machine(program, 12_000_000, 64 << 20, None, 128)
                returned = machine.invoke(function, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                after = [bytes(owner.data) for owner in owners]
                matched = returned == row['returned'] and all(keep(raw) == expected for raw, expected in zip(after, row['after']))
                vm_rows.append({'index': row['index'], 'returned': returned, 'all_complete_buffers_equal': matched})
                self.assertTrue(matched, row['index'])
        self.record('protocol', {'cases': cases, 'frames': frames, 'vm_rows': vm_rows,
                                'initial_capture_frames': initial_count, 'final_actual_frames': len(frames),
                                'all_frames_verified': len(frames) == len(vm_rows)})
        self.assertEqual(len(frames), len(vm_rows))
        self.assertGreater(len(frames), 0)

    def test_unknown_actual_ack_forbids_all_twelve_replays(self):
        from tests.hia_store_lifecycle_observations import unknown_observation
        output = self.folder / 'unknown'; output.mkdir()
        rows = [unknown_observation(self.image, case, output)
                for case in ('call-ack', 'handled-pop-ack', 'retirement-ack')]
        self.assertEqual(sum(len(row['replays_refused']) for row in rows), 12)
        self.assertTrue(all(row['unknown_retained'] and all(row['replays_refused']) for row in rows))
        self.record('unknown-ack', rows)
