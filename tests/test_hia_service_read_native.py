"""Complete read owner: frozen originals, actual ABI and public delivery gates."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_service_read_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.hia_service_read_fixture import (BASE_COUNT, FAULT_COUNT, ORIGINAL,
    canonical, original_inputs, originals, observe_original, observe_candidate)
from tools import generate_hia_service_read as generator

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_SERVICE_READ_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_SERVICE_READ_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_SERVICE_READ_EVIDENCE'
SOURCE_EVIDENCE = 'HEPTA_HIA_SERVICE_READ_SOURCE_EVIDENCE'
VM_CASES = ('ascii-prefix-cursor', 'utf8-trim-to-empty', 'binary-after-current-page',
            'budget-utf8-shrink-then-trim', 'cursor-sha_mismatch', 'alias-normal-two-gets')


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
    image = object.__new__(native.NativeServiceRead)
    image.image_sha256, image.entry_count = 'independent-vm-no-executable-mapping', 0
    def entry(source, size, output, capacity, state, extent):
        image.entry_count += 1
        code, answer, retained = vm_call(program, ctypes.string_at(source, size),
            ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        ctypes.memmove(output, answer, capacity)
        ctypes.memmove(state, retained, extent)
        return code
    image._entry = entry
    return image


def run_child(directory, label, arguments, *, timeout, body=None, environment=None, expected_code=0):
    command = [sys.executable, '-I', '-B', *map(str, arguments)]
    (directory / (label + '-command.json')).write_bytes(canonical({
        'command': command, 'timeout_seconds': timeout, 'expected_code': expected_code}))
    process = subprocess.Popen(command, cwd=directory,
        env=clean_environment() if environment is None else environment,
        stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    complete = False
    try:
        stdout, stderr = process.communicate(body, timeout=timeout)
        complete = True
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        raise
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        if 'stdout' in locals():
            (directory / (label + '-stdout.log')).write_bytes(stdout)
            (directory / (label + '-stderr.log')).write_bytes(stderr)
        (directory / (label + '-execution.json')).write_bytes(canonical({
            'returncode': process.returncode, 'communicate_completed': complete,
            'owned_child_reaped': process.poll() is not None}))
    if process.returncode != expected_code:
        raise AssertionError((label, process.returncode, stdout, stderr))
    return stdout, stderr


class ServiceReadSourceTests(unittest.TestCase):
    def test_full_original_body_inventory_and_generated_profile(self):
        identity, base, faults = original_inputs()
        self.assertEqual((len(base), len(faults), identity['source_pin_count']), (86, 6286, 76))
        raw = (ROOT / 'hepta/hia_agent_service.py').read_bytes()
        lines, document = raw.splitlines(keepends=True), ast.parse(raw)
        service = next(node for node in document.body if isinstance(node, ast.ClassDef)
                       and node.name == 'HIAAgentService')
        method = next(node for node in service.body if isinstance(node, ast.FunctionDef)
                      and node.name == '_hia_read')
        self.assertEqual(b''.join(lines[method.lineno - 1:method.end_lineno]),
                         (ORIGINAL / 'originals/_hia_read.py.txt').read_bytes())
        self.assertIs(api.HIAAgentService._hia_read, api._selected_hia_read)
        self.assertIsNot(api.HIAAgentService._hia_read, api._SERVICE_READ_REFERENCE)
        self.assertEqual(native.SOURCE.read_bytes(), render_assembly(generator.document()).encode())
        program = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(program['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in program['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in program['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(len(native.SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(native.SOURCE.read_text().splitlines()), 16384)
        for fn in program['functions']:
            definitions = {value['name'] for value in fn['params']}
            for block in fn['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                definitions.update(value['name'] for value in block['params'])
                definitions.update(value['name'] for op in block['ops'] for value in op['out'])
            self.assertLessEqual(len(fn['blocks']), 256)
            self.assertLessEqual(len(definitions), 2048)
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELPERS[native.SELECTOR], ('hia_service_read_native', 'NativeServiceRead'))
        from tools.qualify_hia_service_read_callers import FIXTURE_NAME, FIXTURE_SHA256, admit_original_sources
        raw = (ROOT / FIXTURE_NAME).read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), FIXTURE_SHA256)
        inventory = json.loads(raw)
        admit_original_sources(ROOT, inventory)
        self.assertEqual((inventory['ordinary_count'], inventory['separate_scope_count']), (112, 128))

    def test_six_independent_VM_complete_original_paths(self):
        _, base, _ = original_inputs()
        cases = {case['id']: case for case in base}
        oracle, bodies = originals()
        expected = {name: observe_original(cases[name], oracle, bodies)[0] for name in VM_CASES}
        program = assemble_program(native.SOURCE.read_bytes())
        with patch.object(native.NativeServiceRead, '__init__',
                          side_effect=AssertionError('mapping before independent VM')):
            image = vm_image(program)
            for name in VM_CASES:
                with self.subTest(case=name):
                    actual, _ = observe_candidate(cases[name], image, oracle=oracle, bodies=bodies)
                    self.assertEqual(canonical(actual), canonical(expected[name]))
            self.assertGreater(image.entry_count, 0)

    def test_complete_original_only_observations_and_absent_selector(self):
        evidence = os.environ.get(SOURCE_EVIDENCE)
        if evidence == '':
            raise ValueError('read source evidence must not be empty')
        with tempfile.TemporaryDirectory(prefix='hia-service-read-source-') as temporary:
            root = Path(evidence).absolute() if evidence is not None else Path(temporary) / 'source'
            root.mkdir(mode=0o700, parents=True, exist_ok=False)
            run_child(root, 'original', [ROOT / 'tests/hia_service_read_observer.py',
                '--original-only', '--output', root / 'observations'], timeout=600)
            report = json.loads((root / 'observations/report.json').read_bytes())
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['scope'], 'ORIGINAL_ONLY')
            self.assertEqual(report['counts'], {'base': BASE_COUNT, 'fault': FAULT_COUNT})
            self.assertIsNone(report['native_image_sha256'])
            run_child(root, 'SQL-originals', [ROOT / 'tests/hia_service_read_sql_observer.py',
                '--original-only', '--output', root / 'SQL-originals'], timeout=300)
            sql_report = json.loads((root / 'SQL-originals/report.json').read_bytes())
            self.assertEqual(sql_report['status'], 'PASS')
            self.assertEqual(sql_report['scope'], 'ORIGINAL_ONLY')
            self.assertEqual((sql_report['case_count'], sql_report['original_children'],
                              sql_report['candidate_children']), (86, 172, 0))
        events = []
        class Store:
            def get(self, reference):
                events.append(('get', reference))
                return b'abc', {}
        class Service(api.HIAAgentService):
            def __init__(self):
                self.store = Store()
        reference = {'id': 'original', 'sha256': 'a' * 64}
        with patch.dict(os.environ, clean_environment(), clear=True), patch.object(native,
                'installed_service_read', side_effect=AssertionError('absent selector mapped owner')):
            result = api.HIAAgentService._hia_read(Service(), {'artifact': reference})
        self.assertEqual(result, {'artifact': reference, 'encoding': 'utf8', 'content': 'abc', 'next_cursor': None})
        self.assertIs(result['artifact'], reference)
        self.assertEqual(events, [('get', reference)])
        events.clear()
        with patch.dict(os.environ, {native.SELECTOR: ''}), patch.object(api,
                '_SERVICE_READ_REFERENCE', side_effect=AssertionError('selected fallback')):
            with self.assertRaises(ValueError):
                api.HIAAgentService._hia_read(Service(), {'artifact': reference})
        self.assertEqual(events, [])


class ServiceReadNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_service_read import build
        from tools.build_hia_store_artifact_profile import build as store_build
        from tools.build_hia_service_context import build as context_build
        from tools.build_hia_service_artifact import build as artifact_build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-service-read-')
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
        cls.context_manifest = context_build(cls.root / 'context-built', compiler, cold, development=cold is None)
        cls.artifact_manifest = artifact_build(cls.root / 'artifact-built', compiler, cold, development=cold is None)
        cls.image = native.installed_service_read(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = cls.sources == after and cls.compiler.read_bytes() == cls.compiler_raw
        record = {'schema': 'hepta.hia.service-read-component-custody.v1',
            'source_before': cls.sources, 'source_after': after,
            'source_and_compiler_unchanged': stable, 'manifest': str(cls.manifest),
            'store_manifest': str(cls.store_manifest), 'context_manifest': str(cls.context_manifest),
            'artifact_manifest': str(cls.artifact_manifest),
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(), 'runtime': sys.version,
            'matching_cold_report': cls.cold,
            'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'original_base_cases': BASE_COUNT, 'original_fault_cases': FAULT_COUNT,
            'test_results_owned_by_outer_runner': True,
            'opaque_object_codec_wire_hash_SQLite_providers_still_hosted': True,
            'all_input_equivalence_proved': False, 'all_python_versions_tested': False,
            'all_interpreter_execution_histories_proved': False, 'whole_native_stack_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(canonical(record))
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('read component source or compiler changed')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()

    def write(self, name, value):
        (self.case / name).write_bytes(canonical(value))

    def control(self, mode):
        output = self.case / mode
        run_child(self.case, mode, [ROOT / 'tests/hia_service_read_controls.py',
            '--mode', mode, '--manifest', self.manifest, '--store-manifest', self.store_manifest,
            '--context-manifest', self.context_manifest, '--output', output], timeout=180)
        report = json.loads((output / 'report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        return report

    def test_complete_86_base_and_6286_fault_observations(self):
        run_child(self.case, 'finite', [ROOT / 'tests/hia_service_read_observer.py',
            '--manifest', self.manifest, '--output', self.case / 'finite'], timeout=1800)
        report = json.loads((self.case / 'finite/report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['counts'], {'base': BASE_COUNT, 'fault': FAULT_COUNT})
        self.assertEqual(report['mismatch_count'], 0)
        self.assertEqual(report['remaining_delivery_custody'], [])
        run_child(self.case, 'SQL-finite', [ROOT / 'tests/hia_service_read_sql_observer.py',
            '--manifest', self.manifest, '--output', self.case / 'SQL-finite'], timeout=300)
        sql_report = json.loads((self.case / 'SQL-finite/report.json').read_bytes())
        self.assertEqual(sql_report['status'], 'PASS')
        self.assertEqual((sql_report['case_count'], sql_report['original_children'],
                          sql_report['candidate_children']), (86, 172, 86))
        self.assertTrue(sql_report['originals_unchanged'])

    def test_actual_packets_and_all_buffers_match_independent_VM(self):
        program = assemble_program(native.SOURCE.read_bytes())
        actual_entry, rows, count = self.image._entry, [], [0]
        def compared(source, size, output, capacity, state, extent):
            before = (ctypes.string_at(source, size), ctypes.string_at(output, capacity),
                      ctypes.string_at(state, extent))
            expected = vm_call(program, *before)
            code = actual_entry(source, size, output, capacity, state, extent)
            self.assertEqual((code, ctypes.string_at(output, capacity), ctypes.string_at(state, extent)), expected)
            self.assertEqual(ctypes.string_at(source, size), before[0])
            count[0] += 1
            return code
        _, base, _ = original_inputs()
        cases = {case['id']: case for case in base}
        oracle, bodies = originals()
        with patch.object(self.image, '_entry', compared):
            for name in VM_CASES:
                expected, _ = observe_original(cases[name], oracle, bodies)
                actual, _ = observe_candidate(cases[name], self.image, oracle=oracle, bodies=bodies)
                rows.append({'case_id': name, 'original': expected, 'candidate': actual})
                self.assertEqual(canonical(actual), canonical(expected))
        self.write('vm-native.json', {'cases': rows, 'complete_buffer_entries': count[0]})
        self.assertGreater(count[0], 0)
        self.control('protocol')

    def test_original_foreign_exception_identity_and_safe_entry_boundaries(self):
        self.control('foreign')

    def test_real_handoff_loss_is_unknown_and_cannot_replay(self):
        self.control('loss')

    def test_actual_peer_loss_swallow_replace_and_same_named_foreign_control(self):
        self.control('peer')

    def test_actual_public_read_alias_and_cursor_effects(self):
        self.control('public')
        run_child(self.case, 'registered-resources', [ROOT / 'tests/hia_service_read_resources.py',
            '--manifest', self.manifest, '--context-manifest', self.context_manifest,
            '--artifact-manifest', self.artifact_manifest,
            '--output', self.case / 'registered-resources'], timeout=180)
        resources = json.loads((self.case / 'registered-resources/report.json').read_bytes())
        self.assertEqual(resources['status'], 'PASS')
        self.assertEqual(resources['groups'], [
            'registered_temporary_lifetime', 'preparation_boundaries',
            'actual_SQLite_lost_ACK', 'actual_strong_ancestor_own_ACK',
            'generation_identity', 'MemoryError_and_confirmed_cleanup'])
        self.assertTrue(resources['actual_SQLite_and_native_images'])
        self.assertTrue(resources['fixture_Store_explicit_registration'])
        self.assertFalse(resources['ordinary_AgentStore_public_close_covered_here'])
        self.assertFalse(resources['whole_native_stack_qualified'])

    def test_pinned_selection_scope_source_manifest_and_image_drift(self):
        self.control('scope')

    def test_actual_installed_worker_cursor_repeat_and_unknown_effect(self):
        run_child(self.case, 'installed', [ROOT / 'tests/hia_service_read_installed.py',
            '--manifest', self.manifest, '--store-manifest', self.store_manifest,
            '--output', self.case / 'installed'], timeout=180)
        report = json.loads((self.case / 'installed/report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertFalse(report['whole_native_stack_qualified'])
