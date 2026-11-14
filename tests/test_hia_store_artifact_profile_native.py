"""Complete original Store observations, independent VM and real installation.

The fixtures are original-only authorities frozen before this implementation.
Finite comparisons are not an all-input equivalence theorem. Original caller
modules and their production/test limits remain independent retained gates.
"""
from __future__ import annotations
import ast
import builtins
from collections import Counter
from contextlib import ExitStack, closing, contextmanager
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
from types import FunctionType
import unittest
from unittest.mock import patch

from hepta import hia_agent_store as api
from hepta import hia_store_artifact_profile_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.hia_store_artifact_profile_oracle import Fixture, observe_case, cases, METHODS, canonical
from tests import hia_store_literal_call_oracle as literal_original
from tests import hia_store_limit_oracle as limit_original
from tools import generate_hia_store_artifact_profile as generator

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_STORE_ARTIFACT_PROFILE_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_STORE_ARTIFACT_PROFILE_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_STORE_ARTIFACT_PROFILE_EVIDENCE'
CASE_SHA = '378d441cdfc4f8fcef3034ae69f464497ba3e5ec2858058024b3fd6f7ef1a280'
ORACLE_SHA = '26c1b4ac5970f21a9a258da07d92b87ed8ea5a4db4526b94144a7d76db24b84c'
LITERAL_SHA = 'eca4a77776efd3003c7bb3dc4089f49ec1955b0c94a5dc84e31344dc0c5519c9'
LIMIT_ORACLE_SHA = '5b2a0671e64d2c64a42895f2964584ecef54547fb70eb0298b81c13e098aea80'
LIMIT_CASE_SHA = '7dafcf4bfab7566695a15814ab7e9e888b367afdaed6b1e1f35ec12ec8ca2333'
MODULE_SHA = '5feb5b2d06db497b895ba209bdd7b0ed1b7ed29ad29466aca356f5c3fb21657a'
METHOD_SHA = {
    'put': 'c75c43cd27942c1073f6b9318ada1188fc5df4012e7900b07e0d321546371469',
    'json': 'bd8b0f704df24e194e060f24ec3119874cfdd93dad878672665efdaa01972821',
    '_ref': '6d5952f35a71c9b85d40e35b88fd4b6e2b94d051e424bbc1db887d4eab516c7e',
    'get': '76694223a11fe72176ad9b12ce9ccc76043027ba1dc5c96853332766a9f79b31',
    'get_json': 'e1c1c9245d1a9301c06665c1bc40c32b10d4e086db6c13bc6d3b7e5531fe8c33',
    'resolve_uri': '370c9a9ce102ed064cda59466c0f1377c1fe0752e2c5f09e980dd45b7d19c8c4',
    'profile': 'f32b5820994bf22a57cdb6cdb2e241d5a0ea7775c39fa0a4cae3dea751d16d40',
    'check_profile': '5f91d4feaead7e35d141a0edfdd754ed6b40c5f3d8879895a2897e5ba1962dee',
}
PROVIDERS = ('MAX_ARTIFACT_BYTES', '_native_artifact_admission', '_native_artifact_file',
             'sha256', 'digest', 'wire', 'decode_data', 'stable_read', 'keys', 'reject', 'uuid', 'os')
REFERENCES = {name: ('_ref_reference' if name == '_ref' else '_' + name + '_reference') for name in METHODS}
VM_CASES = ('put.native', 'put.fallback.link-exists.same', 'ref.ordinary',
            'get.native', 'profile.native', 'check_profile.native')


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def original_cases():
    return {case['name']: case for case in cases()}


def normalized_arguments(name, args, kwargs):
    return (*args, kwargs.get('kind')) if name in ('get', 'get_json') else args


class _MirrorNamespace(dict):
    """Fixture-only provider rebinding, mirrored into actual nested wrappers."""
    def __init__(self, original):
        super().__init__(original)
        self.original = original

    def __setitem__(self, key, value):
        self.original[key] = value
        super().__setitem__(key, value)
        if key in PROVIDERS:
            setattr(api, key, value)


@contextmanager
def providers(fixture, image=None):
    original = fixture.namespace
    fixture.namespace = _MirrorNamespace(original)
    try:
        with ExitStack() as stack:
            for name in PROVIDERS:
                stack.enter_context(patch.object(api, name, original[name]))
            if image is not None:
                stack.enter_context(patch.dict(os.environ, {native.SELECTOR: 'explicit-fixture-image'}))
                stack.enter_context(patch.object(native, 'installed_store_artifact_profile', return_value=image))
            yield
    finally:
        fixture.namespace = original


def bound_fixture(case):
    return Fixture(case, bindings={name: getattr(api.AgentStore, name) for name in METHODS})


def invoke(image):
    def owner(name, store, arguments, keywords, namespace):
        return native.StoreArtifactProfileFrame(image, native.MODES[name], store,
            normalized_arguments(name, arguments, keywords), namespace=namespace).finish()
    return owner


def public_owner(name, store, arguments, keywords, namespace):
    function = getattr(api.AgentStore, name)
    return function(*arguments, **keywords) if name == '_ref' else function(store, *arguments, **keywords)


def selected_observation(case, image=None, *, public=False):
    fixture = bound_fixture(case)
    with providers(fixture, image):
        return fixture.observe(public_owner if public else invoke(image))


def poison(stack):
    def forbidden(*arguments, **keywords):
        raise AssertionError('selected Store entered a retained original body')
    for name in REFERENCES.values():
        stack.enter_context(patch.object(api.AgentStore, name, forbidden))
    stack.enter_context(patch.dict(api._STORE_ARTIFACT_PROFILE_REFERENCES,
                                  {name: forbidden for name in METHODS}))


def vm_call(program, raw, output, state):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(index + 1, bytearray(value)) for index, value in enumerate((raw, output, state))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'],
                          [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
    if bytes(owners[0].data) != raw:
        raise AssertionError('independent VM changed immutable input')
    return code, bytes(owners[1].data), bytes(owners[2].data)


def vm_image(program):
    image = object.__new__(native.NativeStoreArtifactProfile)
    image.image_sha256, image.entry_count = 'independent-vm-no-executable-mapping', 0
    def entry(source, size, output, capacity, state, extent):
        image.entry_count += 1
        code, result, retained = vm_call(program, ctypes.string_at(source, size),
            ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        ctypes.memmove(output, result, capacity)
        ctypes.memmove(state, retained, extent)
        return code
    image._entry = entry
    return image


def literal_owner(fixture, image):
    def owner(store, *arguments):
        return native.StoreArtifactProfileFrame(image, native.MODES[fixture.case['method']],
            store, arguments, namespace=fixture.namespace).finish()
    return owner


def single_bundle(path, manifest):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    path.write_bytes(canonical({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [{
        'selector': native.SELECTOR, 'manifest_path': str(manifest),
        'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()}]}) + b'\n')
    return sha256(path.read_bytes()).hexdigest()


class StoreArtifactProfileSourceTests(unittest.TestCase):
    def test_eight_originals_transaction_fixture_inventory_and_exact_generated_source(self):
        self.assertEqual(native.SOURCE.read_text(), render_assembly(generator.document()))
        doc = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(doc['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in doc['functions'] for block in fn['blocks']), 16)
        source = ast.parse((ROOT / 'hepta/hia_agent_store.py').read_bytes())
        store = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == 'AgentStore')
        for name, digest in METHOD_SHA.items():
            raw = (ROOT / 'tests/fixtures' / ('AgentStore.' + name + '.py.txt')).read_bytes()
            self.assertEqual(sha256(raw).hexdigest(), digest)
            retained = next(node for node in store.body if isinstance(node, ast.FunctionDef) and node.name == REFERENCES[name])
            retained.name = name
            self.assertEqual(ast.dump(retained), ast.dump(ast.parse(textwrap.dedent(raw.decode())).body[0]))
        old = (ROOT / 'tests/fixtures/hia_agent_store_73f1634.py.txt').read_bytes()
        self.assertEqual(sha256(old).hexdigest(), MODULE_SHA)
        original_store = next(node for node in ast.parse(old).body if isinstance(node, ast.ClassDef) and node.name == 'AgentStore')
        transaction = lambda nodes: next(node for node in nodes if isinstance(node, ast.FunctionDef) and node.name == 'transaction')
        self.assertEqual(ast.dump(transaction(store.body)), ast.dump(transaction(original_store.body)))
        for name, digest in (('tests/hia_store_artifact_profile_oracle.py', ORACLE_SHA),
                ('tests/hia_store_literal_call_oracle.py', LITERAL_SHA),
                ('tests/hia_store_limit_oracle.py', LIMIT_ORACLE_SHA),
                ('tests/fixtures/hia_store_artifact_profile_cases_73f1634.json', CASE_SHA)):
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(len(cases()), 463)
        self.assertEqual(len(literal_original.cases()), 160)
        self.assertEqual(len(limit_original.cases()), 41)
        self.assertEqual(sha256(canonical(limit_original.cases())).hexdigest(), LIMIT_CASE_SHA)
        from tools.qualify_hia_store_artifact_profile_callers import original_inventory, admit_original_sources
        inventory, modules, planned = original_inventory()
        self.assertEqual((len(modules), len(planned)), (10, 130))
        admit_original_sources(ROOT, inventory)
        from tools.run_hia_unittest_gate import load_declared_suite
        self.assertEqual(list(load_declared_suite(modules)[1]), planned)
        self.assertFalse(inventory['every_listed_method_claimed_to_enter_Store_artifact_owner'])

    def test_independent_VM_before_mapping_matches_frozen_full_effects(self):
        program, inputs = assemble_program(native.SOURCE.read_bytes()), original_cases()
        with patch.object(native.NativeStoreArtifactProfile, '__init__', side_effect=AssertionError('native mapping before VM')):
            image = vm_image(program)
            for name in VM_CASES:
                with self.subTest(case=name):
                    self.assertEqual(canonical(selected_observation(inputs[name], image)), canonical(observe_case(inputs[name])))
            self.assertGreater(image.entry_count, 0)

    def test_unselected_routes_are_lazy_and_unqualified_builder_refuses(self):
        original_import = builtins.__import__
        def guarded(name, *arguments, **keywords):
            if name.endswith('hia_store_artifact_profile_native'):
                raise AssertionError('unselected Store imported an optional image')
            return original_import(name, *arguments, **keywords)
        inputs = original_cases()
        with patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            with patch('builtins.__import__', guarded):
                for method in METHODS:
                    case = next(value for value in inputs.values() if value['method'] == method)
                    self.assertEqual(canonical(selected_observation(case, public=True)), canonical(observe_case(case)))
        from tools.build_hia_store_artifact_profile import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compiler').write_bytes(b'not a qualified compiler')
            (root / 'cold').write_text('{}')
            with self.assertRaises(ValueError):
                build(root / 'refused', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'refused').exists())


class StoreArtifactProfileNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_store_artifact_profile import build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-store-artifact-profile-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, exist_ok=False)
        if cold is not None:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        cls.compiler, cls.cold = compiler, cold
        cls.compiler_raw, cls.sources = compiler.read_bytes(), current_sources()
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_store_artifact_profile(str(cls.manifest))
        cls.program = assemble_program(native.SOURCE.read_bytes())

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = cls.compiler.read_bytes() == cls.compiler_raw and after == cls.sources
        record = {'schema': 'hepta.hia.store-artifact-profile-test-custody.v1',
            'manifest': str(cls.manifest), 'matching_cold_report': cls.cold,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'compiler_unchanged': cls.compiler.read_bytes() == cls.compiler_raw,
            'source_manifest_before': cls.sources, 'source_manifest_after': after,
            'source_and_compiler_unchanged': stable, 'test_result_owned_by_outer_runner': True,
            'filesystem_SQL_hash_JSON_and_object_protocols_hosted': True,
            'transaction_context_manager_migrated': False,
            'cross_owner_causal_loss_closure_qualified': False,
            'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(canonical(record) + b'\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('Store artifact inputs changed during native tests')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()
        self.maxDiff = 12000
        selection = patch.dict(os.environ, {native.SELECTOR: str(self.manifest)})
        selection.start()
        self.addCleanup(selection.stop)

    def test_complete_463_original_effects_first_errors_and_cleanup_order(self):
        records, entries, modes = [], Counter(), Counter()
        original_entry, initialize = self.image._entry, native.StoreArtifactProfileFrame.__init__
        def observed_entry(source, size, output, capacity, state, extent):
            words = struct.unpack('<10Q', ctypes.string_at(source, size))
            code = original_entry(source, size, output, capacity, state, extent)
            self.assertEqual((words[0], code), (native.REQUEST_MAGIC, native.OUTPUT_BYTES))
            entries[str(words[1])] += 1
            return code
        def frame_init(frame, image, *arguments, **keywords):
            self.assertIs(image, self.image)
            initialize(frame, image, *arguments, **keywords)
            modes[str(frame.mode)] += 1
        with ExitStack() as stack:
            poison(stack)
            stack.enter_context(patch.object(self.image, '_entry', observed_entry))
            stack.enter_context(patch.object(native.StoreArtifactProfileFrame, '__init__', frame_init))
            inputs = cases()
            self.assertEqual(len(inputs), 463)
            for case in inputs:
                expected, actual = observe_case(case), selected_observation(case, self.image)
                records.append({'case': case['name'], 'expected': expected, 'actual': actual})
                with self.subTest(case=case['name']):
                    self.assertEqual(canonical(actual), canonical(expected))
        self.assertTrue(all(modes[str(mode)] for mode in range(1, 17)))
        self.assertTrue(all(entries[str(event)] for event in range(4)))
        (self.case / 'complete-observations.json').write_bytes(canonical({
            'schema': 'hepta.hia.store-artifact-profile-original-comparison.v1',
            'runtime': sys.version, 'case_count': 463, 'records': records,
            'actual_native_entries_by_event': entries, 'actual_frames_by_mode': modes,
            'retained_eight_bodies_forbidden': True, 'all_input_equivalence_proved': False}) + b'\n')

        limit_records, limit_entries = [], Counter()
        def limit_entry(source, size, output, capacity, state, extent):
            words = struct.unpack('<10Q', ctypes.string_at(source, size))
            code = original_entry(source, size, output, capacity, state, extent)
            self.assertEqual((words[0], code), (native.REQUEST_MAGIC, native.OUTPUT_BYTES))
            limit_entries[str(words[1])] += 1
            return code
        with ExitStack() as stack:
            poison(stack)
            stack.enter_context(patch.object(self.image, '_entry', limit_entry))
            for case in limit_original.cases():
                expected = limit_original.observe_original(case)
                actual = limit_original.observe_candidate(case, self.image, native.StoreArtifactProfileFrame)
                limit_records.append({'case': case['name'], 'expected': expected, 'actual': actual})
                with self.subTest(dynamic_limit_case=case['name']):
                    self.assertEqual(canonical(actual), canonical(expected))
        self.assertTrue(all(limit_entries[str(event)] for event in range(4)))
        (self.case / 'dynamic-limit-observations.json').write_bytes(canonical({
            'schema': 'hepta.hia.store-dynamic-limit-native-comparison.v1',
            'runtime': sys.version, 'case_count': 41, 'cases_sha256': LIMIT_CASE_SHA,
            'oracle_sha256': LIMIT_ORACLE_SHA, 'records': limit_records,
            'actual_native_entries_by_event': limit_entries,
            'original_guard_global_reads_and_opaque_comparison_preserved': True,
            'earlier_463_and_160_fixtures_unchanged': True,
            'accepted_branch_stops_at_next_original_admission_effect': True,
            'all_input_equivalence_proved': False}) + b'\n')

    def test_frozen_160_literal_calls_cold_and_warm_profiles(self):
        helpers = ('_literal_json_put', '_literal_profile_insert', '_literal_check_get_json')
        inputs, warm_codes = literal_original.cases(), {}
        self.assertEqual(len(inputs), 160)
        for method in ('json', 'profile', 'check_profile'):
            fixture = literal_original.Fixture({'name': 'warm-only', 'method': method})
            original = getattr(fixture.namespace['Original'], method)
            for _ in range(2):
                fixture.observe(original)
                fixture.observe(literal_owner(fixture, self.image))
            warm_codes[method] = original.__code__
        records = []
        for profile in ('cold', 'warm'):
            for case in inputs:
                original_fixture = literal_original.Fixture(case)
                original = getattr(original_fixture.namespace['Original'], case['method'])
                if profile == 'warm':
                    original = FunctionType(warm_codes[case['method']], original_fixture.namespace,
                                            original.__name__, original.__defaults__)
                expected = original_fixture.observe(original)
                candidate_fixture = literal_original.Fixture(case)
                with ExitStack() as stack:
                    if profile == 'cold':
                        # A controlled test code-object profile only. The
                        # production owner never recompiles a callsite.
                        for name in helpers:
                            function = getattr(native, name)
                            fresh = FunctionType(function.__code__.replace(), function.__globals__,
                                                 function.__name__, function.__defaults__)
                            stack.enter_context(patch.object(native, name, fresh))
                    actual = candidate_fixture.observe(literal_owner(candidate_fixture, self.image))
                records.append({'profile': profile, 'case': case['name'], 'expected': expected, 'actual': actual})
                with self.subTest(profile=profile, case=case['name']):
                    self.assertEqual(canonical(actual), canonical(expected))
        (self.case / 'literal-call-observations.json').write_bytes(canonical({
            'schema': 'hepta.hia.store-artifact-profile-literal-call-comparison.v1',
            'runtime': sys.version, 'cases_per_profile': 160, 'records': records,
            'cold_and_warm_interpreter_profiles_compared': True,
            'exception_attributes_normalized': False,
            'all_execution_histories_proved': False}) + b'\n')

    def test_actual_native_full_buffers_match_independent_VM(self):
        inputs, entry, counts = original_cases(), self.image._entry, Counter()
        def compared(source, size, output, capacity, state, extent):
            raw = ctypes.string_at(source, size)
            expected = vm_call(self.program, raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
            code = entry(source, size, output, capacity, state, extent)
            self.assertEqual((code, ctypes.string_at(output, capacity), ctypes.string_at(state, extent)), expected)
            self.assertEqual(ctypes.string_at(source, size), raw)
            counts['continuation'] += 1
            return code
        with patch.object(self.image, '_entry', compared):
            for name in VM_CASES:
                with self.subTest(case=name):
                    self.assertEqual(canonical(selected_observation(inputs[name], self.image)), canonical(observe_case(inputs[name])))
        self.assertGreater(counts['continuation'], 0)
        (self.case / 'vm-native-observations.json').write_bytes(canonical({
            'cases': list(VM_CASES), 'entries': counts['continuation'],
            'input_output_and_state_compared_at_every_entry': True}) + b'\n')

    def test_eight_public_routes_poisoned_reference_and_selector_pinning(self):
        inputs, modes = original_cases(), Counter()
        initializer = native.StoreArtifactProfileFrame.__init__
        def counted(frame, *arguments, **keywords):
            initializer(frame, *arguments, **keywords)
            modes[str(frame.mode)] += 1
        with ExitStack() as stack:
            poison(stack)
            stack.enter_context(patch.object(native.StoreArtifactProfileFrame, '__init__', counted))
            for method in METHODS:
                case = next(value for value in inputs.values() if value['method'] == method)
                with self.subTest(method=method):
                    self.assertEqual(canonical(selected_observation(case, public=True)), canonical(observe_case(case)))
                for value in ('', '/no/such/store-artifact-manifest'):
                    with patch.dict(os.environ, {native.SELECTOR: value}):
                        refused = selected_observation(case, public=True)
                    self.assertIn('exception', refused['outcome'])
                    self.assertEqual(refused['trace'], [{'event': 'owner.returned-to-caller',
                        'occurrence': 1, 'values': {'tuple': []}, 'active_exception': None}])
        self.assertTrue(all(modes[str(mode)] for mode in range(1, 9)))
        manifest = self.case / 'manifest.json'
        manifest.write_bytes(self.manifest.read_bytes())
        value = json.loads(manifest.read_bytes())
        image = self.case / value['image_path']
        image.write_bytes((self.manifest.parent / value['image_path']).read_bytes())
        held = native.installed_store_artifact_profile(str(manifest))
        image.write_bytes(image.read_bytes() + b'\0')
        with self.assertRaises(ValueError):
            native.installed_store_artifact_profile(str(manifest))
        self.assertEqual(held.image_sha256, value['image_sha256'])
        from hepta.hia_native_helpers import native_helpers_scope
        with patch.dict(os.environ, clean_environment(), clear=True), native_helpers_scope():
            with self.assertRaisesRegex(ValueError, 'outside the pinned'):
                native.installed_store_artifact_profile(str(self.manifest))
        (self.case / 'public-observations.json').write_bytes(canonical({'frames_by_mode': modes,
            'all_eight_public_routes_observed': True, 'all_eight_reference_bodies_forbidden': True,
            'empty_missing_changed_and_outside_scope_refused': True}) + b'\n')

    def test_lost_ACK_foreign_errors_and_active_same_owner_ancestors(self):
        from tests.test_hia_native_transport_failures import errors, observe_error, check_transport
        records, inputs = [], original_cases()
        sites = (('put.native', 'put_native_put'), ('put.fallback', 'put_stream_fsync'),
                 ('profile.native', 'profile_insert'))
        for case_name, port_name in sites:
            for label, injected in errors():
                fixture, events, entry = bound_fixture(inputs[case_name]), [], self.image._entry
                def lost(source, size, output, capacity, state, extent):
                    words = struct.unpack('<10Q', ctypes.string_at(source, size))
                    code = entry(source, size, output, capacity, state, extent)
                    events.append({'event': words[1], 'port': words[3], 'mode': words[5]})
                    if words[1] == 2 and words[3] == native.PORT[port_name]:
                        raise injected
                    return code
                with providers(fixture, self.image), patch.object(self.image, '_entry', lost):
                    args, kwargs = fixture.arguments()
                    frame = native.StoreArtifactProfileFrame(self.image, native.MODES[fixture.case['method']],
                        fixture.subject, normalized_arguments(fixture.case['method'], args, kwargs), namespace=fixture.namespace)
                    error = observe_error(frame.finish)
                with self.subTest(case=case_name, error=label, lane='native'):
                    check_transport(error, injected, native.StoreArtifactProfileUnknown)
                    self.assertTrue(frame.fenced and frame.native_failed and frame.unconfirmed)
                    self.assertFalse(frame.finished)
                    self.assertIs(native._FRAME_CUSTODY[id(frame)], frame)
                    self.assertFalse(any(row['event'] == 3 for row in events))
                    trace = canonical(fixture.events)
                    with self.assertRaises(native.StoreArtifactProfileUnknown):
                        frame.finish()
                    self.assertEqual(canonical(fixture.events), trace)
                    if case_name == 'put.fallback':
                        self.assertFalse(fixture.state.get('stream_exited', False))
                        self.assertTrue(fixture.state['temporary_exists'])
                records.append({'lane': 'native', 'case': case_name, 'port': port_name,
                    'error': label, 'raised': type(error).__name__, 'events': events,
                    'trace': fixture.events, 'state': fixture.snapshot(fixture.state),
                    'unknown_custody_retained': True, 'no_retry_or_automatic_cleanup': True})

        for case_name, port_name in sites:
            for label, injected in errors():
                fixture, events = bound_fixture(inputs[case_name]), []
                entry, effect = self.image._entry, native.StoreArtifactProfileFrame.effect
                def observed(source, size, output, capacity, state, extent):
                    words = struct.unpack('<10Q', ctypes.string_at(source, size))
                    events.append(words[1])
                    return entry(source, size, output, capacity, state, extent)
                def foreign(frame, port):
                    value = effect(frame, port)
                    if port == native.PORT[port_name]:
                        raise injected
                    return value
                with providers(fixture, self.image), patch.object(self.image, '_entry', observed), \
                        patch.object(native.StoreArtifactProfileFrame, 'effect', foreign):
                    args, kwargs = fixture.arguments()
                    frame = native.StoreArtifactProfileFrame(self.image, native.MODES[fixture.case['method']],
                        fixture.subject, normalized_arguments(fixture.case['method'], args, kwargs), namespace=fixture.namespace)
                    error = observe_error(frame.finish)
                with self.subTest(case=case_name, error=label, lane='foreign'):
                    self.assertIs(error, injected)
                    self.assertTrue(frame.finished)
                    self.assertFalse(frame.fenced or frame.native_failed or frame.unconfirmed)
                    self.assertEqual(frame.receipt.phase, 5)
                    self.assertNotIn(id(frame), native._FRAME_CUSTODY)
                    self.assertIn(3, events)
                    if case_name == 'put.fallback':
                        self.assertTrue(fixture.state['stream_exited'])
                        self.assertFalse(fixture.state['temporary_exists'])
                records.append({'lane': 'foreign', 'case': case_name, 'port': port_name,
                    'error': label, 'same_exception_object': True, 'confirmed_phase': frame.receipt.phase,
                    'events': events, 'trace': fixture.events, 'state': fixture.snapshot(fixture.state)})

        # A real public Store child may fail inside an explicit user override
        # which catches it. Only the child's actual causal parent is fenced.
        for label, injected in errors():
            fixture = bound_fixture(inputs['json.native'])
            caught, events, frames = [], [], []
            entry, initializer = self.image._entry, native.StoreArtifactProfileFrame.__init__
            def initialized(frame, *arguments, **keywords):
                initializer(frame, *arguments, **keywords)
                frames.append(frame)
            def lost(source, size, output, capacity, state, extent):
                words = struct.unpack('<10Q', ctypes.string_at(source, size))
                code = entry(source, size, output, capacity, state, extent)
                events.append({'event': words[1], 'port': words[3], 'mode': words[5]})
                if words[1] == 2 and words[3] == native.PORT['put_insert']:
                    raise injected
                return code
            def overridden(*arguments, **keywords):
                try:
                    return api.AgentStore.put(fixture.subject, *arguments, **keywords)
                except BaseException as error:
                    caught.append(error)
                    return fixture.result_marker
            fixture.subject.put = overridden
            with providers(fixture, self.image), patch.object(self.image, '_entry', lost), \
                    patch.object(native.StoreArtifactProfileFrame, '__init__', initialized):
                args, kwargs = fixture.arguments()
                parent = native.StoreArtifactProfileFrame(self.image, 2, fixture.subject, args, namespace=fixture.namespace)
                error = observe_error(parent.finish)
            with self.subTest(error=label, lane='caught-native-child'):
                self.assertEqual(len(caught), 1)
                check_transport(caught[0], injected, native.StoreArtifactProfileUnknown)
                self.assertIsInstance(error, native.StoreArtifactProfileUnknown)
                self.assertTrue(parent.fenced and parent.native_failed and parent.unconfirmed)
                child, = [frame for frame in frames if frame.mode == 1]
                self.assertTrue(child.fenced and child.native_failed and child.unconfirmed)
                self.assertIs(native._FRAME_CUSTODY[id(child)], child)
                self.assertIs(native._FRAME_CUSTODY[id(parent)], parent)
                self.assertFalse(any(row['event'] == 3 for row in events))
                self.assertIsNone(native._ACTIVE_FOREIGN_CALL.get())
                before = canonical(fixture.events)
                with self.assertRaises(native.StoreArtifactProfileUnknown):
                    parent.finish()
                self.assertEqual(before, canonical(fixture.events))
            records.append({'lane': 'caught-native-child', 'error': label,
                'actual_public_child_frame_observed': True, 'parent_and_child_fenced': True,
                'events': events, 'trace': fixture.events})
        (self.case / 'native-and-foreign-exceptions.json').write_bytes(canonical({
            'schema': 'hepta.hia.store-artifact-profile-transport-controls.v1',
            'native_cases': 30, 'foreign_cases': 30, 'caught_native_child_cases': 10,
            'records': records, 'cross_owner_causal_closure_claimed': False}) + b'\n')

    def test_thread_finished_replay_bad_packets_and_unclaimed_ACK_refuse(self):
        from tests.test_hia_native_transport_failures import observe_error
        fixture, raised = bound_fixture(original_cases()['put.native']), []
        with providers(fixture, self.image):
            args, kwargs = fixture.arguments()
            frame = native.StoreArtifactProfileFrame(self.image, 1, fixture.subject, args, namespace=fixture.namespace)
            def foreign_thread():
                raised.append(type(observe_error(frame.finish)))
            thread = threading.Thread(target=foreign_thread)
            thread.start()
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(raised, [native.StoreArtifactProfileUnknown])
            self.assertEqual(fixture.events, [])
            frame.finish()
            before = canonical(fixture.events)
            with self.assertRaises(native.StoreArtifactProfileUnknown):
                frame.finish()
            self.assertEqual(canonical(fixture.events), before)
        fixture = bound_fixture(original_cases()['put.native'])
        with providers(fixture, self.image):
            args, kwargs = fixture.arguments()
            forged = native.StoreArtifactProfileFrame(self.image, 1, fixture.subject, args, namespace=fixture.namespace)
            with self.assertRaises(native.StoreArtifactProfileUnknown):
                forged.call(2)
            self.assertEqual(fixture.events, [])
        original = [native.REQUEST_MAGIC, 0, 0, 0, 0, 1, 123, 456, 0, 0]
        records = []
        for name, change in (('bad-magic', (0, 0)), ('bad-mode-low', (5, 0)), ('bad-mode-high', (5, 17)),
                ('initial-sequence', (2, 1)), ('initial-port', (3, 1)), ('initial-observation', (4, 1)),
                ('reserved-one', (8, 1)), ('reserved-two', (9, 1))):
            words = list(original)
            words[change[0]] = change[1]
            raw = struct.pack('<10Q', *words)
            source, output, state = ctypes.create_string_buffer(raw), ctypes.create_string_buffer(96), ctypes.create_string_buffer(128)
            before = source.raw, output.raw, state.raw
            code = self.image._entry(source, 80, output, 96, state, 128)
            self.assertEqual(code, 4294967293)
            self.assertEqual((source.raw, output.raw, state.raw), before)
            records.append({'case': name, 'status': code, 'all_buffers_unchanged': True})
        (self.case / 'protocol-observations.json').write_bytes(canonical({
            'foreign_thread_refused_without_poisoning_creator': True,
            'finished_replay_and_unclaimed_ACK_no_foreign_effect': True, 'invalid_packets': records}) + b'\n')

    def test_real_store_eight_methods_original_SQL_files_and_reference_authority(self):
        from hepta.hia_native_helpers import native_helpers_scope
        bundle = self.case / 'bundle.json'
        bundle_sha = single_bundle(bundle, self.manifest)
        counts, initializer = Counter(), native.NativeStoreArtifactProfile.__init__
        def counted_image(image, *arguments, **keywords):
            initializer(image, *arguments, **keywords)
            self.assertEqual(image.image_sha256, self.image.image_sha256)
            entry = image._entry
            def observed(source, size, output, capacity, state, extent):
                words = struct.unpack('<10Q', ctypes.string_at(source, size))
                result = entry(source, size, output, capacity, state, extent)
                self.assertEqual(result, native.OUTPUT_BYTES)
                if words[1] == 0:
                    counts[str(words[5])] += 1
                return result
            image._entry = observed
        with patch.object(native.NativeStoreArtifactProfile, '__init__', counted_image), \
                patch.dict(os.environ, clean_environment(), clear=True), native_helpers_scope(str(bundle), bundle_sha), \
                ExitStack() as stack:
            poison(stack)
            store = api.AgentStore(self.case / 'state')
            try:
                raw = b'\0full Store artifact owner\xff'
                reference = store.put(raw, 'binary', {'count': 1})
                self.assertEqual(store.put(raw, 'binary', {'count': 1}), reference)
                self.assertEqual(store.get(reference, kind='binary'), (raw, {'count': 1}))
                self.assertEqual(store.resolve_uri(reference['uri']), reference)
                json_ref = store.json({'value': 2}, 'test-json')
                self.assertEqual(store.get_json(json_ref, kind='test-json'), ({'value': 2}, {}))
                profile, artifact = store.profile('profile-id', {'value': 3})
                self.assertEqual(store.check_profile(profile, profile), {'value': 3})
                row = store.db.execute('SELECT * FROM artifacts WHERE id=?', (artifact['id'],)).fetchone()
                self.assertEqual(api.AgentStore._ref(row), artifact)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 3)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM profiles').fetchone()[0], 1)
                self.assertFalse(list(store.artifacts.glob('.write-*')))
                self.assertEqual((store.artifacts / reference['sha256']).stat().st_mode & 0o777, 0o400)
                for call, code in (
                        (lambda: store.get(reference, kind='profile'), 'E_HIA_ARTIFACT_AUTHORITY'),
                        (lambda: store.resolve_uri('hia://artifacts/missing'), 'E_HIA_ARTIFACT_IDENTITY'),
                        (lambda: store.check_profile(profile, {'id': 'other', 'sha256': '0' * 64}), 'E_HIA_PROFILE_STALE')):
                    with self.assertRaises(api.AgentRejected) as caught:
                        call()
                    self.assertEqual(caught.exception.code, code)
                source = store.artifacts / reference['sha256']
                source.chmod(0o600)
                source.write_bytes(b'corrupt')
                with self.assertRaises(api.AgentRejected) as caught:
                    store.get(reference)
                self.assertEqual(caught.exception.code, 'E_HIA_ARTIFACT_CORRUPT')
                self.assertEqual(source.read_bytes(), b'corrupt')
            finally:
                store.close()
        self.assertTrue(all(counts[str(mode)] > 0 for mode in range(1, 9)))
        (self.case / 'store-observations.json').write_bytes(canonical({
            'frames_by_mode': counts, 'bundle_sha256': bundle_sha,
            'all_eight_public_routes_real_files_and_SQL': True,
            'all_eight_reference_bodies_forbidden': True,
            'namespace_and_kind_precedence_preserved': True,
            'native_artifact_file_provider_covered_by_separate_original_18_method_gate': True}) + b'\n')

    def test_actual_installed_worker_publication_URI_unknown_replay_and_source_drift(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_native_helpers import native_helpers_scope
        staging = self.case / 'source'
        staging.mkdir()
        shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = clean_environment()
        environment['PYTHONDONTWRITEBYTECODE'] = '1'

        def run(label, arguments, *, body=None, expected_code=0):
            result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=self.case,
                env=environment, input=body, capture_output=True, timeout=60)
            (self.case / (label + '.stdout')).write_bytes(result.stdout)
            (self.case / (label + '.stderr')).write_bytes(result.stderr)
            if expected_code is not None:
                self.assertEqual(result.returncode, expected_code,
                    result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
            return result

        run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                      '--wheel-dir', self.case / 'wheels', staging])
        wheel, = (self.case / 'wheels').glob('*.whl')
        installed = self.case / 'installed'
        run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                        '--target', installed, wheel])
        bundle = self.case / 'bundle.json'
        bundle_sha = single_bundle(bundle, self.manifest)
        script = r'''import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed runtime imported authoring')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_store_artifact_profile_native as native
from hepta import hia_agent_store as store
from hepta import hia_agent_service as service
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':{'entries':0,'modes':{}},'request':{'entries':0,'modes':{}},'request_artifact_inserts':0}
active=False
def forbidden(*a,**k):raise AssertionError('installed retained Store body entered')
for name in ('_put_reference','_json_reference','_ref_reference','_get_reference','_get_json_reference',
             '_resolve_uri_reference','_profile_reference','_check_profile_reference'):
    setattr(store.AgentStore,name,forbidden)
for name in tuple(store._STORE_ARTIFACT_PROFILE_REFERENCES):
    store._STORE_ARTIFACT_PROFILE_REFERENCES[name]=forbidden
original_call=service.HIAAgentService._reference_call
def request_call(self,*a,**k):
    global active
    assert not active
    active=True
    try:return original_call(self,*a,**k)
    finally:active=False
service.HIAAgentService._reference_call=request_call
initialize=native.NativeStoreArtifactProfile.__init__
def image_init(self,*a,**k):
    initialize(self,*a,**k);entry=self._entry
    def observed(source,size,output,capacity,state,extent):
        words=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert words[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES
        bucket=counts['request' if active else 'startup'];bucket['entries']+=1
        if words[1]==0:
            key=str(words[5]);bucket['modes'][key]=bucket['modes'].get(key,0)+1
        if active and mode=='lost_ack_valueerror' and words[1]==2 and words[3]==native.PORT['put_insert']:
            raise ValueError('controlled lost durable Store insertion acknowledgement')
        return result
    self._entry=observed
native.NativeStoreArtifactProfile.__init__=image_init
effect=native.StoreArtifactProfileFrame.effect
def observed_effect(self,port):
    result=effect(self,port)
    if active and port==native.PORT['put_insert']:
        counts['request_artifact_inserts']+=1
        if mode=='exit_after_insert':
            counts['unknown_frames']=len(native._FRAME_CUSTODY)
            os.write(2,('STORE_ARTIFACT_COUNTS='+json.dumps(counts,sort_keys=True)+'\n').encode())
            os._exit(73)
    return result
native.StoreArtifactProfileFrame.effect=observed_effect
assert mode in ('normal','lost_ack_valueerror','exit_after_insert')
try:status=main(sys.argv[1:])
finally:
    counts['unknown_frames']=len(native._FRAME_CUSTODY)
    print('STORE_ARTIFACT_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''

        def read_counts(result):
            prefix = b'STORE_ARTIFACT_COUNTS='
            found = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
            self.assertEqual(len(found), 1, result.stderr.decode(errors='replace'))
            return json.loads(found[0])

        def envelope(case, tool, arguments):
            value = {'schema': 'hia-agent-worker-request-v1', 'tool': tool,
                'arguments': arguments, 'profile_sha256': 'a' * 64,
                'catalog_sha256': case.service.catalog_sha256}
            value['request_sha256'] = api.digest(value)
            return value

        def prepare():
            case = AgentToolCase('runTest')
            with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(bundle), bundle_sha):
                case.setUp()
            request = envelope(case, 'hia_artifact', case.session.arguments(context=False,
                artifact_profile=case.session.profiles['artifact'],
                source={'kind': 'utf8', 'text': 'durable Store native owner — 雪'}))
            case.service.close()
            return case, request

        def worker(label, case, request, mode='normal', expected_code=0):
            flags = ['-I', '-c', script, installed, mode, '--state-root', case.state_root,
                     '--artifact-root', case.files_root,
                     '--request-json-stdin', '--native-helpers-manifest', bundle,
                     '--expected-native-helpers-sha256', bundle_sha]
            return run(label, flags, body=canonical(request), expected_code=expected_code)

        def retained_state(case, request):
            key = api.digest({'tool': request['tool'], 'key': request['arguments']['request_key']})
            with closing(sqlite3.connect(case.state_root / 'state.sqlite3')) as db:
                db.row_factory = sqlite3.Row
                row = db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
                return {'request': None if row is None else dict(row),
                    'artifacts': db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
                    'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}

        observations = {}
        case, request = prepare()
        try:
            original_state = retained_state(case, request)
            first = worker('first', case, request)
            first_report, first_counts = json.loads(first.stdout), read_counts(first)
            before = retained_state(case, request)
            replay = worker('replay', case, request)
            replay_report, replay_counts = json.loads(replay.stdout), read_counts(replay)
            after = retained_state(case, request)
            self.assertEqual(first_report['response']['status'], 'completed', first_report)
            self.assertEqual(first_report['native_helpers_sha256'], bundle_sha)
            self.assertEqual(replay_report['response'], first_report['response'])
            self.assertEqual(after, before)
            self.assertEqual(before['artifacts'], original_state['artifacts'] + 1)
            self.assertEqual(first_counts['request_artifact_inserts'], 1)
            self.assertEqual(first_counts['unknown_frames'], 0)
            self.assertGreater(first_counts['request']['entries'], 0)
            self.assertGreater(first_counts['startup']['entries'], 0)
            self.assertGreater(replay_counts['startup']['entries'], 0)
            self.assertEqual(replay_counts['request'], {'entries': 0, 'modes': {}})
            self.assertEqual(replay_counts['request_artifact_inserts'], 0)
            reference = first_report['response']['result']['artifact']
            payload = (case.state_root / 'artifacts' / reference['sha256']).read_bytes()
            self.assertEqual(payload, request['arguments']['source']['text'].encode())
            self.assertEqual(sha256(payload).hexdigest(), reference['sha256'])
            resource_request = envelope(case, 'hia_resource_read', {'uri': reference['uri'], 'max_bytes': 4096})
            resource = worker('uri-read', case, resource_request)
            resource_report, resource_counts = json.loads(resource.stdout), read_counts(resource)
            self.assertEqual(resource_report['response']['status'], 'completed', resource_report)
            self.assertEqual(resource_report['response']['result']['content'], payload.decode())
            self.assertGreater(resource_counts['request']['modes']['6'], 0)
            combined_modes = set(first_counts['startup']['modes']) | set(first_counts['request']['modes']) | set(resource_counts['request']['modes'])
            self.assertTrue({str(mode) for mode in range(1, 9)} <= combined_modes)
            observations['first'] = {'worker_exit_code': first.returncode, 'report': first_report,
                'counts': first_counts, 'before': original_state, 'after': before}
            observations['replay'] = {'worker_exit_code': replay.returncode, 'report': replay_report,
                'counts': replay_counts, 'before': before, 'after': after,
                'zero_request_owner_calls_not_zero_startup_calls': True}
            observations['uri_read'] = {'worker_exit_code': resource.returncode,
                'report': resource_report, 'counts': resource_counts,
                'durable_payload_sha256': sha256(payload).hexdigest()}
        finally:
            case.tearDown()

        for label, mode, exit_code in (('native_ack', 'lost_ack_valueerror', 1),
                                       ('process_loss', 'exit_after_insert', 73)):
            case, request = prepare()
            try:
                original_state = retained_state(case, request)
                lost = worker(label, case, request, mode, exit_code)
                lost_counts = read_counts(lost)
                self.assertEqual(lost_counts['request_artifact_inserts'], 1)
                self.assertGreater(lost_counts['unknown_frames'], 0)
                if mode == 'lost_ack_valueerror':
                    self.assertIn(b'StoreArtifactProfileUnknown', lost.stderr)
                before = retained_state(case, request)
                self.assertEqual(before['request']['state'], 'running')
                self.assertIsNone(before['request']['response'])
                self.assertEqual(before['artifacts'], original_state['artifacts'] + 1)
                self.assertEqual(before['costs'], original_state['costs'])
                replay = worker(label + '-replay', case, request)
                replay_report, replay_counts = json.loads(replay.stdout), read_counts(replay)
                after = retained_state(case, request)
                self.assertEqual(replay_report['response']['status'], 'rejected', replay_report)
                self.assertEqual(replay_report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                self.assertEqual(replay_counts['request'], {'entries': 0, 'modes': {}})
                self.assertEqual(replay_counts['request_artifact_inserts'], 0)
                self.assertEqual(after['request'], before['request'])
                self.assertEqual(after['artifacts'], before['artifacts'])
                # The original rejected unknown replay itself retains its cost
                # record; it does not mark the original intent completed.
                self.assertEqual(after['costs'], before['costs'] + 1)
                observations[label] = {'lost_worker_exit_code': lost.returncode, 'counts': lost_counts,
                    'original_state': original_state, 'before_replay': before, 'after_replay': after,
                    'replay_worker_exit_code': replay.returncode,
                    'replay': replay_report, 'replay_counts': replay_counts}
                if mode == 'exit_after_insert':
                    source = installed / 'hepta/_data/examples/hia_bootstrap/store_artifact_profile.hepta'
                    original_source = source.read_bytes()
                    self.assertEqual(original_source, native.SOURCE.read_bytes())
                    source.write_bytes(original_source + b'\n')
                    drift = worker('changed-installed-source', case, request, expected_code=None)
                    self.assertNotEqual(drift.returncode, 0)
                    drift_counts = read_counts(drift)
                    self.assertEqual(drift_counts['request']['entries'], 0)
                    self.assertEqual(drift_counts['startup']['entries'], 0)
                    observations['installed_source_drift'] = {
                        'worker_exit_code': drift.returncode, 'counts': drift_counts,
                        'before_sha256': sha256(original_source).hexdigest(),
                        'after_sha256': sha256(source.read_bytes()).hexdigest(),
                        'exact_change': 'one appended LF in packaged Store HIA source'}
            finally:
                case.tearDown()
        observations.update({'schema': 'hepta.hia.store-artifact-profile-installed-observations.v1',
            'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'bundle_sha256': bundle_sha, 'all_eight_public_modes_observed': True,
            'retained_eight_bodies_forbidden_in_actual_child': True,
            'authoring_imports_forbidden_in_actual_child': True,
            'original_worker_used': True, 'startup_and_request_native_counts_separated': True,
            'whole_native_delivery_qualified': False})
        (self.case / 'installed-observations.json').write_bytes(canonical(observations) + b'\n')
