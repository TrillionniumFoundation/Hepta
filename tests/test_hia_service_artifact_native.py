"""Complete service artifact control: independent original and actual ABI gates.

The original 146 finite inputs are immutable. Candidate expectations are always
formed by the original body in the same runtime; runtime differences are kept.
"""
from __future__ import annotations
import ast
import base64
from collections import Counter
from contextlib import ExitStack, closing
import csv
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from hepta import hia_agent_service as api
from hepta import hia_service_artifact_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests import hia_service_artifact_oracle as oracle
from tests.hia_service_artifact_observer import original_inputs
from tools import generate_hia_service_artifact as generator

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_SERVICE_ARTIFACT_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_SERVICE_ARTIFACT_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_SERVICE_ARTIFACT_EVIDENCE'
SOURCE_EVIDENCE = 'HEPTA_HIA_SERVICE_ARTIFACT_SOURCE_EVIDENCE'
VM_CASES = ('utf8.normal', 'path.no-expected', 'path.expected-match',
            'path.expected-mismatch', 'globals.len-replaces-str',
            'lifetime.temporary.detached-callable.outer0')


def encoded(value):
    return oracle.canonical(value)


def bundle(path, helpers):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    path.write_bytes(encoded({'schema': SCHEMA, 'target': TARGET, 'abi': ABI,
        'helpers': [{'selector': selector, 'manifest_path': str(manifest),
                     'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()}
                    for selector, manifest in helpers]}))
    return sha256(path.read_bytes()).hexdigest()


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def vm_call(program, raw, output, state):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(index + 1, bytearray(value)) for index, value in enumerate((raw, output, state))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'],
        [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
    if bytes(owners[0].data) != raw:
        raise AssertionError('independent VM changed immutable request')
    return code, bytes(owners[1].data), bytes(owners[2].data)


def vm_image(program):
    image = object.__new__(native.NativeServiceArtifact)
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


class ServiceArtifactSourceTests(unittest.TestCase):
    def test_original_body_public_binding_and_generated_profile(self):
        original_inputs()
        raw = (ROOT / 'hepta/hia_agent_service.py').read_bytes()
        module, lines = ast.parse(raw), raw.splitlines(keepends=True)
        service = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == 'HIAAgentService')
        method = next(node for node in service.body if isinstance(node, ast.FunctionDef) and node.name == '_hia_artifact')
        body = b''.join(lines[method.lineno - 1:method.end_lineno])
        self.assertEqual(body, (oracle.ROOT / 'artifact.5bf.py.txt').read_bytes())
        self.assertIs(api.HIAAgentService._hia_artifact, api._service_artifact_dispatch)
        self.assertIsNot(api.HIAAgentService._hia_artifact, api._NATIVE_SERVICE_ARTIFACT_REFERENCE)
        self.assertEqual(native.SOURCE.read_bytes(), render_assembly(generator.document()).encode())
        document = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(document['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in document['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in document['functions'] for block in fn['blocks']), 16)
        self.assertLessEqual(len(native.SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(native.SOURCE.read_text().splitlines()), 16384)
        for fn in document['functions']:
            definitions = {value['name'] for value in fn['params']}
            for block in fn['blocks']:
                definitions.update(value['name'] for value in block['params'])
                definitions.update(value['name'] for op in block['ops'] for value in op['out'])
            self.assertLessEqual(len(fn['blocks']), 256)
            self.assertLessEqual(len(definitions), 2048)
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELPERS[native.SELECTOR], ('hia_service_artifact_native', 'NativeServiceArtifact'))

    def test_independent_VM_complete_branches_and_detached_receiver(self):
        values = {case['id']: case for case in original_inputs()}
        expected = {name: oracle.observe(values[name]) for name in VM_CASES}
        program = assemble_program(native.SOURCE.read_bytes())
        with patch.object(native.NativeServiceArtifact, '__init__',
                          side_effect=AssertionError('mapping before independent VM')):
            image = vm_image(program)
            for name in VM_CASES:
                with self.subTest(case=name):
                    actual = oracle.observe(values[name], factory=lambda namespace:
                        lambda service, arguments: native.ServiceArtifactFrame(
                            image, service, arguments, namespace=namespace).finish())
                    self.assertEqual(oracle.canonical(actual), oracle.canonical(expected[name]))
            self.assertGreater(image.entry_count, 0)

    def test_complete_fresh_originals_and_unselected_public_route(self):
        evidence = os.environ.get(SOURCE_EVIDENCE)
        if evidence == '':
            raise ValueError('service artifact source evidence must not be empty')
        with tempfile.TemporaryDirectory(prefix='hia-service-artifact-source-') as temporary:
            directory = Path(evidence).absolute() if evidence is not None else Path(temporary) / 'original'
            command = [sys.executable, '-I', '-B', str(ROOT / 'tests/hia_service_artifact_observer.py'),
                       '--original-only', '--output', str(directory)]
            result = subprocess.run(command, cwd=ROOT, env=clean_environment(), capture_output=True, timeout=60)
            if directory.exists():
                (directory / 'stdout.log').write_bytes(result.stdout)
                (directory / 'stderr.log').write_bytes(result.stderr)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((directory / 'report.json').read_bytes())
            self.assertEqual(report['count'], 146)
            self.assertEqual(report['ordered_ids'], [case['id'] for case in original_inputs()])
            self.assertFalse(report['selected_or_native_or_VM_execution'])
        events = []
        class Store:
            def put(self, data, kind):
                events.append(('put', data, kind))
                return 'issued'
        class Service(api.HIAAgentService):
            def __init__(self):
                self.store = Store()
            def _profile(self, value, kind):
                events.append(('profile', value, kind))
        arguments = {'artifact_profile': 'profile', 'source': {'kind': 'utf8', 'text': '雪'}}
        with patch.dict(os.environ, clean_environment(), clear=True), patch.object(native,
                'installed_service_artifact', side_effect=AssertionError('unselected image admission')):
            result = api.HIAAgentService._hia_artifact(Service(), arguments)
        self.assertEqual(result, {'artifact': 'issued', 'byte_length': '3',
            'content_admitted_as_program': False, 'execution_authority_granted': False})
        self.assertEqual(events, [('profile', 'profile', 'artifact'), ('put', '雪'.encode(), 'input')])
        events.clear()
        with patch.dict(os.environ, {native.SELECTOR: ''}), patch.object(api,
                '_NATIVE_SERVICE_ARTIFACT_REFERENCE', side_effect=AssertionError('selected fallback')):
            with self.assertRaises(ValueError):
                api.HIAAgentService._hia_artifact(Service(), arguments)
        self.assertEqual(events, [])


class ServiceArtifactNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_service_artifact import build
        from tools.build_hia_store_artifact_profile import build as store_build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-service-artifact-')
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
        cls.store_manifest = store_build(cls.root / 'store-built', compiler, cold, development=cold is None)
        cls.image = native.installed_service_artifact(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = cls.sources == after and cls.compiler.read_bytes() == cls.compiler_raw
        record = {'schema': 'hepta.hia.service-artifact-component-custody.v1',
            'source_before': cls.sources, 'source_after': after,
            'source_and_compiler_unchanged': stable, 'manifest': str(cls.manifest),
            'store_manifest': str(cls.store_manifest), 'runtime': sys.version,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(), 'matching_cold_report': cls.cold,
            'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'original_finite_cases': 146, 'test_results_owned_by_outer_runner': True,
            'capture_path_filesystem_sqlite_and_object_protocols_still_hosted': True,
            'all_input_equivalence_proved': False, 'all_python_versions_tested': False,
            'whole_native_stack_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record))
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('service artifact component source or compiler changed')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()

    def write(self, name, value):
        (self.case / name).write_bytes(encoded(value))

    def child(self, label, arguments, *, body=None, environment=None, expected_code=0, timeout=60):
        command = [sys.executable, '-B', *map(str, arguments)]
        self.write(label + '-command.json', {'command': command, 'timeout_seconds': timeout})
        process = subprocess.Popen(command, cwd=self.case,
            env=clean_environment() if environment is None else environment,
            stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(body, timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
            (self.case / (label + '.stdout')).write_bytes(stdout)
            (self.case / (label + '.stderr')).write_bytes(stderr)
            raise
        (self.case / (label + '.stdout')).write_bytes(stdout)
        (self.case / (label + '.stderr')).write_bytes(stderr)
        self.assertEqual(process.returncode, expected_code, stdout + stderr)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    def test_complete_frozen_146_against_actual_image_in_fresh_process(self):
        result = self.child('finite', ['-I', ROOT / 'tests/hia_service_artifact_observer.py',
            '--manifest', self.manifest, '--output', self.case / 'finite'])
        report = json.loads((self.case / 'finite/report.json').read_bytes())
        expected = (self.case / 'finite/originals-146.json').read_bytes()
        actual = (self.case / 'finite/actuals-146.json').read_bytes()
        self.assertEqual(report['status'], 'PASS', result.stdout + result.stderr)
        self.assertEqual(report['case_order'], [case['id'] for case in original_inputs()])
        self.assertEqual(report['actual_count'], 146)
        self.assertEqual(report['actual_frames'], 146)
        self.assertEqual(expected, actual)
        self.assertEqual(sha256(expected).hexdigest(), report['originals_sha256'])
        self.assertEqual(sha256(actual).hexdigest(), report['actuals_sha256'])
        self.assertEqual(report['differences'], [])
        self.assertTrue(report['expected_written_before_native_mapping'])
        self.assertTrue(report['expected_file_unchanged_after_candidate'])
        self.assertEqual(report['source_before'], self.sources)
        self.assertEqual(report['source_after'], self.sources)
        self.assertEqual(report['manifest_sha256'], sha256(self.manifest.read_bytes()).hexdigest())
        self.assertTrue(report['source_image_and_manifest_unchanged'])
        self.assertEqual(report['remaining_delivery_custody'], [])
        self.assertEqual(report['all_late_events'], [])
        self.assertTrue(report['retained_reference_poisoned'])
        self.assertEqual(report['reference_calls'], [])
        events = report['actual_native_entry_events']
        self.assertEqual(events['0'], 146)
        self.assertEqual(events['1'], events['2'] + events['3'])
        complete = json.loads((self.case / 'finite/complete-observations.json').read_bytes())
        self.assertEqual([row['case'] for row in complete], report['case_order'])
        self.assertEqual([row['expected'] for row in complete], json.loads(expected))
        self.assertEqual([row['actual'] for row in complete], json.loads(actual))
        self.assertTrue(all(row['equal'] for row in complete))

    def run_resources(self, cases):
        from tests.hia_service_artifact_faults import CASE_IDS
        reports = []
        for case in cases:
            self.assertIn(case, CASE_IDS)
            with self.subTest(case=case):
                result = self.child(case, ['-I', ROOT / 'tests/hia_service_artifact_faults.py',
                    ROOT, self.manifest, self.store_manifest, case, self.case / case])
                raw = (self.case / case / 'report.json').read_bytes()
                report = json.loads(raw)
                self.assertEqual(report['status'], 'PASS', result.stdout + result.stderr)
                self.assertEqual(report['mode'], case)
                self.assertFalse(report['native_records_loss_fields_manually_written'])
                self.assertTrue(report['parent_original_poisoned'])
                self.assertEqual(report['manifest_sha256'][str(self.manifest)],
                                 sha256(self.manifest.read_bytes()).hexdigest())
                self.assertEqual(report['manifest_sha256'][str(self.store_manifest)],
                                 sha256(self.store_manifest.read_bytes()).hexdigest())
                reports.append({'case': case, 'report_sha256': sha256(raw).hexdigest(), 'report': report})
        self.write('resource-observations.json', reports)
        self.assertEqual([row['case'] for row in reports], list(cases))

    def test_actual_confirmed_child_parent_ACK_loss_and_actual_resource_identity(self):
        self.run_resources(('parent-ACK-lost-after-confirmed-child', 'nested-parent-ACK-lost',
            'only-actual-other-Store-is-retained', 'child-loss-swallowed',
            'child-loss-replaced', 'child-loss-with-suppression'))

    def test_actual_safe_preentry_confirmed_foreign_failure_and_healthy_release(self):
        self.run_resources(('associate-only-does-not-arm', 'safe-child-preentry-does-not-arm',
            'healthy-ACK-releases-before-result', 'ordinary-provider-error-confirmed-after-child',
            'parent-preentry-MemoryError', 'parent-preentry-RuntimeError',
            'parent-preentry-KeyboardInterrupt', 'parent-preentry-SystemExit'))

    def test_actual_pending_cutpoints_gc_reentry_and_ACK_retirement(self):
        self.run_resources(('confirmed-ACK-retirement-MemoryError',
            'scope-return-identity-failure-confirmed', 'scope-return-identity-failure-lost',
            'actual-reentrant-child-loss-blocks-prepared-entry',
            'actual-reentrant-child-loss-blocks-resource-scope-body',
            'actual-reentrant-child-loss-blocks-foreign-body'))

    def test_actual_stale_Context_thread_fork_and_inherited_unknown_resource(self):
        self.run_resources(('stale-Context-is-not-parent', 'copied-thread-is-not-parent',
            'fork-is-not-parent', 'unknown-resource-survives-fork'))

    def test_native_complete_packets_buffers_and_protocol_rejections(self):
        program = assemble_program(native.SOURCE.read_bytes())
        initial = struct.pack('<10Q', native.REQUEST_MAGIC, 0, 0, 0, 0, 1, 11, 17, 0, 0)
        records = []

        def compare(label, raw, state=bytes(native.STATE_BYTES), capacity=native.OUTPUT_BYTES):
            output_raw = b'\xa5' * capacity
            expected = vm_call(program, raw, output_raw, state)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
            output = ctypes.create_string_buffer(output_raw + b'\xa7' * 16, capacity + 16)
            workspace = ctypes.create_string_buffer(state + b'\xb7' * 16, len(state) + 16)
            code = self.image._entry(source, len(raw), output, capacity, workspace, len(state))
            actual = code, output.raw[:capacity], workspace.raw[:len(state)]
            self.assertEqual(source.raw, raw + b'\xc9' * 16)
            self.assertEqual(output.raw[capacity:], b'\xa7' * 16)
            self.assertEqual(workspace.raw[len(state):], b'\xb7' * 16)
            self.assertEqual(actual, expected, label)
            records.append({'case': label, 'code': code, 'request': raw.hex(),
                'output': actual[1].hex(), 'state': actual[2].hex(),
                'complete_buffers_equal_to_independent_VM': True})
            return actual

        for label, raw, state, capacity in (
                ('request-short', initial[:-1], bytes(128), 96),
                ('request-long', initial + b'\0', bytes(128), 96),
                ('output-short', initial, bytes(128), 95),
                ('output-long', initial, bytes(128), 97),
                ('state-short', initial, bytes(127), 96),
                ('state-long', initial, bytes(129), 96),
                ('nonzero-initial-state', initial, b'\1' + bytes(127), 96)):
            self.assertEqual(compare(label, raw, state, capacity)[0], 0xfffffffd)
        for label, index, value in (('bad-magic', 0, 0), ('reserved-first', 8, 1),
                                    ('reserved-last', 9, 1), ('bad-mode', 5, 2)):
            packet = list(struct.unpack('<10Q', initial));packet[index] = value
            self.assertEqual(compare(label, struct.pack('<10Q', *packet))[0], 0xfffffffd)
        packet = list(struct.unpack('<10Q', initial));packet[6:8] = [0, 0]
        self.assertEqual(compare('zero-identity', struct.pack('<10Q', *packet))[0], 0xfffffffd)

        def packet(event, state, observed=0):
            words = struct.unpack('<16Q', state)
            return struct.pack('<10Q', native.REQUEST_MAGIC, event, words[4], words[3],
                               observed, 1, 11, 17, 0, 0)

        first = compare('initialize', initial)
        for label, raw in (
                ('unclaimed-ACK', packet(native.SUCCEEDED, first[2])),
                ('unclaimed-error', packet(native.RAISED, first[2])),
                ('unknown-event', packet(99, first[2])),
                ('claim-nonzero-observation', packet(native.CLAIM, first[2], 1))):
            self.assertEqual(struct.unpack('<12Q', compare(label, raw, first[2])[1])[1], 1)
        claim = packet(native.CLAIM, first[2])
        claimed = compare('claim-profile', claim, first[2])
        self.assertEqual(struct.unpack('<12Q', compare('duplicate-claim', claim, claimed[2])[1])[1], 1)
        self.assertEqual(struct.unpack('<12Q', compare('nonfact-observation',
            packet(native.SUCCEEDED, claimed[2], 1), claimed[2])[1])[1], 1)
        broken = bytearray(first[2]);broken[80] ^= 1
        self.assertEqual(compare('state-checksum-drift', claim, bytes(broken))[0], 0xfffffffd)
        wrong = list(struct.unpack('<10Q', claim));wrong[6] ^= 1
        self.assertEqual(struct.unpack('<12Q', compare('wrong-nonce', struct.pack('<10Q', *wrong), first[2])[1])[1], 1)
        visited = set()
        for label, is_utf8, present, differs, rejected in (
                ('utf8', 1, 0, 0, False), ('path-no-expected', 0, 0, 0, False),
                ('path-match', 0, 1, 0, False), ('path-reject-raised', 0, 1, 1, True),
                ('path-reject-returned', 0, 1, 1, False)):
            state = compare(label + '-init', initial)[2]
            while struct.unpack('<16Q', state)[5] == native.ISSUED:
                port = struct.unpack('<16Q', state)[3]
                visited.add(port)
                state = compare(label + '-claim-' + str(port), packet(native.CLAIM, state), state)[2]
                observed = {native.PORT['kind_is_utf8']: is_utf8,
                            native.PORT['expected_is_not_none']: present,
                            native.PORT['digest_differs']: differs}.get(port, 0)
                event = native.RAISED if rejected and port == native.PORT['reject_changed'] else native.SUCCEEDED
                if port in (native.PORT['kind_is_utf8'], native.PORT['expected_is_not_none'], native.PORT['digest_differs']):
                    refused = compare(label + '-bad-fact-' + str(port), packet(native.SUCCEEDED, state, 2), state)
                    self.assertEqual(struct.unpack('<12Q', refused[1])[1], 1)
                state = compare(label + '-ack-' + str(port), packet(event, state, observed), state)[2]
            self.assertEqual(struct.unpack('<16Q', state)[5], native.PROPAGATE if rejected else native.RETURNED)
            replay = compare(label + '-terminal-replay', packet(native.CLAIM, state), state)
            self.assertEqual(struct.unpack('<12Q', replay[1])[1], 1)
        self.assertEqual(visited, set(native.PORT.values()))
        self.write('complete-packets-and-buffers.json', records)

    def test_actual_public_routes_pinned_bundle_restoration_and_source_drift(self):
        from hepta import hia_agent_store as store_api
        from hepta import hia_store_artifact_profile_native as store_native
        from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
        path = self.case / 'bundle.json'
        pin = bundle(path, [(native.SELECTOR, self.manifest), (store_native.SELECTOR, self.store_manifest)])
        environment = clean_environment()
        entries, events = Counter(), []
        def forbidden(*arguments, **keywords):
            raise AssertionError('selected public handler entered retained original')
        class Service:
            artifact_roots = (self.case,)
            def __init__(self, store):
                self.store = store
            def _profile(self, reference, kind):
                events.append(('profile', reference, kind))
        with patch.dict(os.environ, environment, clear=True), patch.object(api, '_NATIVE_SERVICE_ARTIFACT_REFERENCE', forbidden):
            before = dict(os.environ)
            with native_helpers_scope(str(path), pin):
                parent_image = native.installed_service_artifact(str(self.manifest))
                child_image = store_native.installed_store_artifact_profile(str(self.store_manifest))
                def counted(image, label):
                    original = image._entry
                    def call(*arguments):
                        result = original(*arguments)
                        entries[label] += 1
                        return result
                    return call
                with patch.object(parent_image, '_entry', counted(parent_image, 'handler')), \
                     patch.object(child_image, '_entry', counted(child_image, 'Store')):
                    store = store_api.AgentStore(self.case / 'state')
                    try:
                        service = Service(store)
                        text = 'actual public handler — 雪'
                        first = api.HIAAgentService._hia_artifact(service,
                            {'artifact_profile': 'opaque', 'source': {'kind': 'utf8', 'text': text}})
                        self.assertEqual(first['byte_length'], str(len(text.encode())))
                        payload = b'captured source bytes\x00\xff'
                        captured = self.case / 'capture.bin';captured.write_bytes(payload)
                        args = {'artifact_profile': 'opaque', 'source': {'kind': 'path',
                            'path': str(captured), 'max_bytes': 4096, 'expected_sha256': sha256(payload).hexdigest()}}
                        second = api.HIAAgentService._hia_artifact(service, args)
                        self.assertEqual(second['byte_length'], str(len(payload)))
                        self.assertEqual((store.artifacts / second['artifact']['sha256']).read_bytes(), payload)
                        store_entries = entries['Store']
                        args['source']['expected_sha256'] = '0' * 64
                        with self.assertRaises(api.AgentRejected) as refusal:
                            api.HIAAgentService._hia_artifact(service, args)
                        self.assertEqual(refusal.exception.code, 'E_HIA_ARTIFACT_CHANGED')
                        self.assertEqual(entries['Store'], store_entries)
                        self.assertEqual(store.db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 2)
                        self.assertEqual(native_helpers_identity(), {'native_helpers_sha256': pin})
                    finally:
                        store.close()
            self.assertEqual(dict(os.environ), before)
        self.assertGreater(entries['handler'], 0)
        self.assertGreater(entries['Store'], 0)
        self.assertEqual(len(events), 3)
        bad = self.case / 'bad';bad.mkdir()
        manifest = json.loads(self.manifest.read_bytes())
        shutil.copyfile(self.manifest.parent / manifest['image_path'], bad / manifest['image_path'])
        bad_manifest = bad / 'manifest.json'
        manifest['source_sha256'] = '0' * 64
        bad_manifest.write_bytes(encoded(manifest))
        effects = []
        class NoEffects:
            def _profile(self, *values):
                effects.append('profile')
        with patch.dict(os.environ, {**environment, native.SELECTOR: str(bad_manifest)}, clear=True), \
             patch.object(api, '_NATIVE_SERVICE_ARTIFACT_REFERENCE', forbidden):
            with self.assertRaises(ValueError):
                api.HIAAgentService._hia_artifact(NoEffects(), {})
        self.assertEqual(effects, [])
        manifest = json.loads(self.manifest.read_bytes())
        bad_manifest.write_bytes(encoded(manifest))
        copied_bundle = self.case / 'copied-bundle.json'
        copied_pin = bundle(copied_bundle, [(native.SELECTOR, bad_manifest)])
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(ValueError):
                with native_helpers_scope(str(copied_bundle), '0' * 64):
                    self.fail('bad bundle digest accepted')
            raw = bad_manifest.read_bytes()
            with native_helpers_scope(str(copied_bundle), copied_pin):
                try:
                    manifest['compiler_sha256'] = 'f' * 64
                    bad_manifest.write_bytes(encoded(manifest))
                    with self.assertRaises(ValueError):
                        native_helpers_identity()
                finally:
                    bad_manifest.write_bytes(raw)
        self.write('public-and-bundle.json', {'actual_image_entries': dict(entries),
            'dynamic_profile_calls': events, 'environment_restored': True,
            'bad_source_unpinned_public_route_effects': effects,
            'compiler_drift_checked_at_actual_bundle_identity': True,
            'scope_exit_inferred_as_terminal_attestation': False})

    def test_actual_installed_worker_and_durable_parent_ACK_loss(self):
        from tests.hia_service_artifact_worker_terminal import SourceAuthority, assert_terminal, worker_profile, process_record
        from tools.read_hia_service_artifact_worker_terminal import Captures, admit_source_authority, verify_terminal, read_installation
        authority = SourceAuthority(ROOT)
        readback = Captures()
        self.assertEqual(admit_source_authority(readback, ROOT), authority.summary())
        self.addCleanup(authority.finish)
        self.addCleanup(readback.stable)
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_native_helpers import native_helpers_scope
        from hepta import hia_store_artifact_profile_native as store_native
        staging = self.case / 'source';staging.mkdir()
        shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = staging / name;target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = clean_environment()
        environment['PYTHONDONTWRITEBYTECODE'] = '1'

        def run(label, arguments, *, body=None, expected_code=0):
            return self.child(label, arguments, body=body, environment=environment,
                              expected_code=expected_code, timeout=60)

        from tests.hia_distribution_fixture import installed_wheel_path, ordinary_wheel
        run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                      '--wheel-dir', self.case / 'wheels', ordinary_wheel(staging)])
        wheel, = (self.case / 'wheels').glob('*.whl')
        installed = self.case / 'installed'
        run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                        '--target', installed, wheel])
        profile = worker_profile((installed / 'hepta/hia_agent_worker.py').read_bytes())
        self.assertEqual(profile, authority.profile)
        files = {}
        with zipfile.ZipFile(wheel) as archive:
            record_name, = [name for name in archive.namelist() if name.endswith('.dist-info/RECORD')]
            for name, digest, size in csv.reader(io.StringIO(archive.read(record_name).decode())):
                raw = archive.read(name)
                if digest:
                    self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode())
                    self.assertEqual(size, str(len(raw)))
                if name != record_name:
                    files[name] = sha256(raw).hexdigest()
                    name = installed_wheel_path(installed, name).relative_to(installed).as_posix()
                    self.assertEqual((installed / name).read_bytes(), raw, name)
        resource = installed / 'hepta/_data/examples/hia_bootstrap/service_artifact.hepta'
        self.assertEqual(resource.read_bytes(), native.SOURCE.read_bytes())
        installed_record = {row[0]: row[1:] for row in csv.reader(io.StringIO((installed / record_name).read_text()))}
        for name in ('hepta/hia_agent_store.py', 'hepta/hia_agent_service.py', 'hepta/hia_native_delivery.py',
                     'hepta/hia_service_artifact_native.py', 'hepta/hia_service_artifact_protocol.py',
                     str(resource.relative_to(installed))):
            raw = installed_wheel_path(installed, name).read_bytes()
            digest = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
            self.assertEqual(installed_record[name], [digest, str(len(raw))])
        path = self.case / 'bundle.json'
        pin = bundle(path, [(native.SELECTOR, self.manifest), (store_native.SELECTOR, self.store_manifest)])
        script = r'''import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);terminal_root=Path(sys.argv.pop(1))
sys.path.insert(0,str(terminal_root))
from tests.hia_service_artifact_worker_terminal import SourceAuthority,TerminalObservation
terminal_authority=SourceAuthority(terminal_root)
sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed runtime imported authoring')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_store as store
from hepta import hia_service_artifact_native as native
from hepta import hia_store_artifact_profile_native as child_native
from hepta import hia_agent_service as service
from hepta import hia_agent_worker as worker_module
from hepta import hia_native_delivery as delivery
main=worker_module.main
for module in (native,child_native,service,store,worker_module,delivery):
    assert Path(module.__file__).resolve().is_relative_to(Path(installed).resolve())
terminal=TerminalObservation(worker_module,service,delivery,native)
assert terminal.profile==terminal_authority.profile
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'startup':{},'request':{},'store_startup':{},'store_request':{},'close_calls':0};active=False
def forbidden(*a,**k):raise AssertionError('installed retained service artifact handler executed')
forbidden.__wrapped__=forbidden
service._NATIVE_SERVICE_ARTIFACT_REFERENCE=forbidden
for name in store._STORE_ARTIFACT_PROFILE_REFERENCES:
    store._STORE_ARTIFACT_PROFILE_REFERENCES[name]=forbidden
    setattr(store.AgentStore,'_'+name.lstrip('_')+'_reference',forbidden)
original_call=service.HIAAgentService._reference_call
def request_call(self,*a,**k):
    global active
    active=True
    try:return original_call(self,*a,**k)
    finally:active=False
service.HIAAgentService._reference_call=request_call
close=store._NATIVE_STORE_CLOSE_REFERENCE
def close_observed(self):counts['close_calls']+=1;return close(self)
store._NATIVE_STORE_CLOSE_REFERENCE=close_observed
initialize=native.NativeServiceArtifact.__init__
def image_init(image,*a,**k):
    initialize(image,*a,**k);entry=image._entry
    def observed(source,size,output,capacity,state,extent):
        packet=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert packet[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES
        bucket=counts['request' if active else 'startup'];key=str(packet[1]);bucket[key]=bucket.get(key,0)+1
        if active and mode=='lost_put_ack' and packet[1]==2 and packet[3]==native.PORT['put']:
            error=ValueError('actual handler PUT acknowledgement lost after confirmed Store')
            terminal.injected(error)
            try:raise error
            finally:del error
        return result
    image._entry=observed
native.NativeServiceArtifact.__init__=image_init
child_initialize=child_native.NativeStoreArtifactProfile.__init__
def child_image_init(image,*a,**k):
    child_initialize(image,*a,**k);entry=image._entry
    def observed(source,size,output,capacity,state,extent):
        packet=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert packet[0]==child_native.REQUEST_MAGIC and result==child_native.OUTPUT_BYTES
        bucket=counts['store_request' if active else 'store_startup'];key=str(packet[1]);bucket[key]=bucket.get(key,0)+1
        return result
    image._entry=observed
child_native.NativeStoreArtifactProfile.__init__=child_image_init
try:status=main(sys.argv[1:])
finally:
    counts['terminal']=terminal.report()
    terminal_authority.finish()
    counts['unknown_records']=sum(row['lost'] for row in delivery.custody_snapshot())
    counts['store_unknown_frames']=len(child_native._FRAME_CUSTODY)
    counts['retained_resource_observations']=len(delivery._RESOURCE_OBSERVATIONS)
    print('SERVICE_ARTIFACT_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''

        def read_counts(result):
            prefix = b'SERVICE_ARTIFACT_COUNTS='
            values = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
            self.assertEqual(len(values), 1, result.stderr)
            return json.loads(values[0])

        def prepare():
            case = AgentToolCase('runTest')
            with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(path), pin):
                case.setUp()
            arguments = case.session.arguments(context=False, artifact_profile=case.session.profiles['artifact'],
                source={'kind': 'utf8', 'text': 'native service artifact installed worker — 雪'})
            request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_artifact',
                'arguments': arguments, 'profile_sha256': 'a' * 64,
                'catalog_sha256': case.service.catalog_sha256}
            request['request_sha256'] = api.digest(request)
            case.service.close()
            return case, request

        def state(case, request):
            key = api.digest({'tool': request['tool'], 'key': request['arguments']['request_key']})
            with closing(sqlite3.connect(case.state_root / 'state.sqlite3')) as db:
                db.row_factory = sqlite3.Row
                row = db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
                return {'request': None if row is None else dict(row),
                    'artifacts': db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
                    'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}

        def worker(label, case, request, mode='normal', code=0):
            result = run(label, ['-I', '-c', script, installed, mode, ROOT,
                '--state-root', case.state_root, '--artifact-root', case.files_root,
                '--request-json-stdin', '--native-helpers-manifest', path,
                '--expected-native-helpers-sha256', pin], body=encoded(request), expected_code=code)
            self.write(label + '-terminal-process.json', process_record(
                result, (self.case / (label + '-command.json')).read_bytes()))
            terminal_value = read_counts(result)['terminal']
            assert_terminal(self, terminal_value, result.stderr, label, profile)
            verify_terminal(terminal_value, result.stderr, label, profile)
            return result

        observations = {}
        case, request = prepare()
        try:
            before = state(case, request)
            first = worker('first', case, request)
            report, counts = json.loads(first.stdout), read_counts(first)
            after = state(case, request)
            replay = worker('replay', case, request)
            replay_report, replay_counts = json.loads(replay.stdout), read_counts(replay)
            self.assertEqual(report['response']['status'], 'completed', report)
            self.assertEqual(report['native_helpers_sha256'], pin)
            self.assertEqual(replay_report['response'], report['response'])
            self.assertEqual(state(case, request), after)
            self.assertEqual(after['artifacts'], before['artifacts'] + 1)
            self.assertEqual(after['request']['state'], 'completed')
            self.assertGreater(sum(counts['request'].values()), 0)
            self.assertGreater(sum(counts['store_request'].values()), 0)
            self.assertEqual(sum(replay_counts['request'].values()), 0)
            self.assertEqual(counts['unknown_records'], 0)
            self.assertEqual(replay_counts['unknown_records'], 0)
            self.assertEqual(counts['store_unknown_frames'], 0)
            self.assertEqual(counts['retained_resource_observations'], 0)
            self.assertEqual(counts['close_calls'], 1)
            reference = report['response']['result']['artifact']
            payload = (case.state_root / 'artifacts' / reference['sha256']).read_bytes()
            self.assertEqual(payload, request['arguments']['source']['text'].encode())
            observations['success'] = {'report': report, 'counts': counts, 'before': before, 'after': after}
            observations['replay'] = {'report': replay_report, 'counts': replay_counts,
                'cached_replay_does_not_enter_artifact_handler': True, 'state_unchanged': True}
        finally:
            case.tearDown()
        case, request = prepare()
        try:
            before = state(case, request)
            lost = worker('lost-put-ACK', case, request, 'lost_put_ack', profile['lost_ack_exit'])
            counts = read_counts(lost)
            after = state(case, request)
            self.assertEqual(lost.stdout, b'')
            self.assertGreater(counts['unknown_records'], 0)
            self.assertGreater(counts['retained_resource_observations'], 0)
            self.assertGreater(sum(counts['store_request'].values()), 0)
            self.assertEqual(counts['store_unknown_frames'], 0)
            self.assertEqual(counts['close_calls'], 0)
            self.assertEqual(after['request']['state'], 'running')
            self.assertIsNone(after['request']['response'])
            self.assertEqual(after['artifacts'], before['artifacts'] + 1)
            self.assertEqual(after['costs'], before['costs'])
            replay = worker('unknown-replay', case, request)
            replay_report, replay_counts = json.loads(replay.stdout), read_counts(replay)
            replay_state = state(case, request)
            self.assertEqual(replay_report['response']['status'], 'rejected', replay_report)
            self.assertEqual(replay_report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
            self.assertEqual(sum(replay_counts['request'].values()), 0)
            self.assertEqual(replay_state['request'], after['request'])
            self.assertEqual(replay_state['artifacts'], after['artifacts'])
            # Original running-intent refusal is an ordinary rejected attempt;
            # its audit cost is recorded, unlike an early cached response.
            self.assertEqual(replay_state['costs'], after['costs'] + 1)
            observations['lost_put_ack'] = {'worker_exit': lost.returncode, 'counts': counts,
                'before': before, 'after': after, 'close_refused_before_original_close': True}
            observations['unknown_replay'] = {'report': replay_report, 'counts': replay_counts,
                'after': replay_state, 'original_running_request_not_replayed': True}
        finally:
            case.tearDown()
        authority.finish()
        readback.stable()
        self.write('installation.json', {'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'terminal_source_authority': authority.summary(),
            'installed': str(installed), 'wheel_files_checked_against_installed': files,
            'installed_RECORD_sha256': sha256((installed / record_name).read_bytes()).hexdigest(),
            'bundle_sha256': pin, 'observations': observations,
            'scope': 'actual installed original worker; handler and Store selected; durable running intent after parent ACK loss',
            'whole_native_stack_qualified': False})
        self.write('worker-terminal-readback.json', read_installation(ROOT, self.case))
