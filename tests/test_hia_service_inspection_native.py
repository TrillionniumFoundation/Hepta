"""Complete inspect/candidate owner: originals, native delivery and installed routes."""
from __future__ import annotations
import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_service_inspection_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.hia_service_inspection_oracle import (DIRECTORY, ORIGINALS, Fixture, canonical, observe_case)
from tests.hia_service_inspection_vm import CASES, image_for_vm, observe_six, protocol_witnesses, vm_call
from tools import generate_hia_service_inspection as generator

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_SERVICE_INSPECTION_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_SERVICE_INSPECTION_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_SERVICE_INSPECTION_EVIDENCE'
SOURCE_EVIDENCE = 'HEPTA_HIA_SERVICE_INSPECTION_SOURCE_EVIDENCE'
IDENTITY_SHA256 = 'c89710abd3c416ff8b8ac5b7588b27e083ed03f39e8cfba47960396345f43070'


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(('HEPTA_HIA_', 'PYTHON'))}


def run_child(directory, label, arguments, *, timeout, body=None, environment=None, expected_code=0):
    directory = Path(directory)
    command = [sys.executable, '-I', '-B', *map(str, arguments)]
    child_environment = clean_environment() if environment is None else environment
    (directory / (label + '-command.json')).write_bytes(canonical({
        'command': command, 'timeout_seconds': timeout, 'expected_code': expected_code,
        'cleanup_seconds': 3,
        'clean_HEPTA_HIA_and_PYTHON_environment': environment is None,
        'environment_bindings': {key: child_environment.get(key)
            for key in ('CLANG', 'HEPTA_CLANG', 'LD_LIBRARY_PATH')}}))
    complete = group_gone = False
    stdout = stderr = b''
    failure = None
    cleanup_errors, signals = [], []
    process = None
    # All preparation, including the clock, precedes actual child handoff.
    started = time.monotonic()
    try:
        process = subprocess.Popen(command, cwd=directory, env=child_environment,
            stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        stdout, stderr = process.communicate(body, timeout=timeout)
        complete = True
    except BaseException as error:
        failure = {'class': type(error).__name__, 'message': str(error)}
        if isinstance(error, subprocess.TimeoutExpired):
            if error.output is not None:
                stdout = error.output
            if error.stderr is not None:
                stderr = error.stderr
        raise
    finally:
        if process is not None:
            try:
                try:
                    os.killpg(process.pid, 0)
                    group_live = True
                except ProcessLookupError:
                    group_live = False
                if process.poll() is None or group_live:
                    # Only the process group created by this invocation.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        signals.append('SIGKILL')
                    except ProcessLookupError:
                        pass
                stdout, stderr = process.communicate(timeout=3)
            except BaseException as error:
                if isinstance(error, subprocess.TimeoutExpired):
                    if error.output is not None:
                        stdout = error.output
                    if error.stderr is not None:
                        stderr = error.stderr
                cleanup_errors.append({'class': type(error).__name__, 'message': str(error)})
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                group_gone = True
        (directory / (label + '-stdout.log')).write_bytes(stdout)
        (directory / (label + '-stderr.log')).write_bytes(stderr)
        (directory / (label + '-execution.json')).write_bytes(canonical({
            'returncode': None if process is None else process.poll(),
            'communicate_completed': complete,
            'owned_child_reaped': process is not None and process.poll() is not None,
            'owned_group_absent_at_observation': group_gone,
            'pid_and_pgid': None if process is None else process.pid,
            'failure': failure, 'cleanup_errors': cleanup_errors,
            'signals': signals, 'cleanup_seconds': 3,
            'wall_seconds': time.monotonic() - started}))
    if (process.returncode != expected_code or not group_gone
            or cleanup_errors or signals):
        raise AssertionError((label, process.returncode, group_gone, cleanup_errors, signals, stdout, stderr))
    return stdout, stderr


def original_report(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_child(directory, 'originals', [ROOT / 'tools/observe_hia_service_inspection_immutable_originals.py',
        '--evidence', directory / 'observations',
        '--expected-source-identity-sha256', IDENTITY_SHA256], timeout=600)
    path = directory / 'observations/report.json'
    raw = path.read_bytes()
    value = json.loads(raw)
    assert value['status'] == 'PASS'
    assert value['scope'] == 'ORIGINAL_ONLY_FINITE_SAME_RUNTIME'
    assert value['base_count'] == 116 and value['fault_count'] > 0
    assert value['planned'] == value['started'] == value['stopped']
    assert value['actual_original_invocations'] == 2 * len(value['planned'])
    assert not value['native_or_VM_or_SQL_or_compiler_executed']
    from tools.qualify_hia_service_inspection_finite import admit_originals
    admitted_raw,admitted,base,faults=admit_originals(path,sha256(raw).hexdigest())
    assert admitted_raw==raw and admitted==value
    assert len(base)==116 and len(faults)==value['fault_count']
    assert value['stored_first_and_second_are_exact_equality_operands'] is True
    return path, sha256(raw).hexdigest(), value


class ServiceInspectionSourceTests(unittest.TestCase):
    def test_two_complete_original_bodies_inventory_and_generated_profile(self):
        raw = (ROOT / 'hepta/hia_agent_service.py').read_bytes()
        lines, tree = raw.splitlines(keepends=True), ast.parse(raw)
        service = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                       and node.name == 'HIAAgentService')
        for mode, name in ((1, '_hia_inspect'), (2, '_hia_candidate')):
            original_file, digest = ORIGINALS[mode]
            original = (DIRECTORY / original_file).read_bytes()
            self.assertEqual(sha256(original).hexdigest(), digest)
            method = next(node for node in service.body if isinstance(node, ast.FunctionDef)
                          and node.name == name)
            self.assertEqual(b''.join(lines[method.lineno - 1:method.end_lineno]), original)
        self.assertIs(api.HIAAgentService._hia_inspect, api._selected_hia_inspect)
        self.assertIs(api.HIAAgentService._hia_candidate, api._selected_hia_candidate)
        identity_raw = (DIRECTORY / 'source-identity.json').read_bytes()
        self.assertEqual(sha256(identity_raw).hexdigest(), IDENTITY_SHA256)
        identity = json.loads(identity_raw)
        for name, digest in identity['files'].items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(native.SOURCE.read_bytes(), render_assembly(generator.document()).encode())
        program = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(program['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in program['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in program['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(len(native.SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(native.SOURCE.read_text().splitlines()), 16384)
        for fn in program['functions']:
            entry = next(block for block in fn['blocks'] if block['id'] == fn['entry'])
            self.assertEqual(entry['params'], fn['params'], fn['name'])
            definitions = []
            for block in fn['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                definitions.extend(value['name'] for value in block['params'])
                definitions.extend(value['name'] for op in block['ops'] for value in op['out'])
            self.assertEqual(len(definitions), len(set(definitions)), fn['name'])
            self.assertLessEqual(len(fn['blocks']), 256)
            self.assertLessEqual(len(definitions), 2048)
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELPERS[native.SELECTOR], ('hia_service_inspection_native', 'NativeServiceInspection'))
        from tools.qualify_hia_service_inspection_callers import FIXTURE_NAME, FIXTURE_SHA256, admit_original_sources
        inventory_raw = (ROOT / FIXTURE_NAME).read_bytes()
        self.assertEqual(sha256(inventory_raw).hexdigest(), FIXTURE_SHA256)
        inventory = json.loads(inventory_raw)
        admit_original_sources(ROOT, inventory)
        self.assertEqual((inventory['ordinary_count'], inventory['separate_scope_count']), (112, 128))

    def test_six_independent_VM_complete_original_paths(self):
        program = assemble_program(native.SOURCE.read_bytes())
        with patch.object(native.NativeServiceInspection, '__init__',
                          side_effect=AssertionError('Source VM mapped an executable')):
            image = image_for_vm(program)
            rows = observe_six(image)
        self.assertEqual([row['case_id'] for row in rows], list(CASES))
        for row in rows:
            with self.subTest(case=row['case_id']):
                self.assertTrue(row['canonical_equal'], row)
        self.assertGreater(image.entries, 0)

    def test_all_original_only_observations_and_lazy_selector(self):
        evidence = os.environ.get(SOURCE_EVIDENCE)
        if evidence == '':
            raise ValueError('inspection source evidence must not be empty')
        with tempfile.TemporaryDirectory(prefix='hia-service-inspection-source-') as temporary:
            output = Path(evidence).absolute() if evidence is not None else Path(temporary) / 'source'
            original_report(output)
        cases = json.loads((DIRECTORY / 'cases.json').read_bytes())['cases']
        cases = {case['id']: case for case in cases}
        for mode, name in ((1, 'inspect-summary-outer-0'), (2, 'candidate-import-hia-asm.v1-outer-0')):
            expected, _ = observe_case(cases[name])
            def owner(mode, service, arguments, namespace, original_code):
                method = api.HIAAgentService._hia_inspect if mode == 1 else api.HIAAgentService._hia_candidate
                return method(service, arguments)
            with patch.dict(os.environ, clean_environment(), clear=True), patch.object(native,
                    'installed_service_inspection', side_effect=AssertionError('absent selector mapped owner')):
                actual, _ = observe_case(cases[name], owner)
            self.assertEqual(canonical(actual), canonical(expected))
            fixture = Fixture(cases[name])
            before = list(fixture.world.events)
            with fixture.providers(), patch.dict(os.environ, {native.SELECTOR: ''}), \
                 patch.object(api, '_SERVICE_INSPECTION_INSPECT_REFERENCE',
                    side_effect=AssertionError('empty selector fell back')), \
                 patch.object(api, '_SERVICE_INSPECTION_CANDIDATE_REFERENCE',
                    side_effect=AssertionError('empty selector fell back')):
                method = api.HIAAgentService._hia_inspect if mode == 1 else api.HIAAgentService._hia_candidate
                with self.assertRaises(ValueError):
                    method(fixture.service, fixture.arguments)
            self.assertEqual(fixture.world.events, before)


class ServiceInspectionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_service_inspection import build
        from tools.build_hia_store_artifact_profile import build as store_build
        from tools.build_hia_service_context import build as context_build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-service-inspection-')
            cls.root = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.cold, cls.manifests = cold, {}
        cls.sources = current_sources()
        if cold is not None:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        cls.compiler, cls.compiler_raw = compiler, compiler.read_bytes()
        cls.addClassCleanup(cls.complete_custody)
        # No candidate image exists before this original-only independent run.
        cls.original_report, cls.original_sha256, cls.original = original_report(cls.root / 'originals')
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.manifests['inspection'] = str(cls.manifest)
        cls.store_manifest = store_build(cls.root / 'store-built', compiler, cold, development=cold is None)
        cls.manifests['store'] = str(cls.store_manifest)
        cls.context_manifest = context_build(cls.root / 'context-built', compiler, cold, development=cold is None)
        cls.manifests['context'] = str(cls.context_manifest)
        cls.image = native.installed_service_inspection(str(cls.manifest))

    @classmethod
    def complete_custody(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = cls.sources == after and cls.compiler.read_bytes() == cls.compiler_raw
        report = {'schema': 'hepta.hia.service-inspection-component-custody.v1',
            'source_before': cls.sources, 'source_after': after,
            'source_and_compiler_unchanged': stable, 'manifests': cls.manifests,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(), 'runtime': sys.version,
            'matching_cold_report': cls.cold,
            'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'test_results_owned_by_outer_runner': True,
            'original_source_identity_sha256': IDENTITY_SHA256,
            'all_input_equivalence_proved': False, 'all_python_versions_tested': False,
            'all_interpreter_execution_histories_proved': False, 'whole_native_stack_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(canonical(report))
        if not stable:
            raise AssertionError('inspection component source or compiler changed')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()

    def control(self, mode):
        output = self.case / mode
        run_child(self.case, mode, [ROOT / 'tests/hia_service_inspection_controls.py',
            '--mode', mode, '--manifest', self.manifest, '--store-manifest', self.store_manifest,
            '--context-manifest', self.context_manifest, '--output', output], timeout=180)
        report = json.loads((output / 'report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['mode'], mode)
        self.assertTrue(report['source_unchanged'])
        return report

    def test_complete_116_base_and_all_frozen_fault_observations(self):
        run_child(self.case, 'finite', [ROOT / 'tools/qualify_hia_service_inspection_finite.py',
            '--manifest', self.manifest, '--original-report', self.original_report,
            '--original-report-sha256', self.original_sha256,
            '--evidence', self.case / 'finite'], timeout=1800)
        report = json.loads((self.case / 'finite/report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['base_count'], 116)
        self.assertEqual(report['fault_count'], self.original['fault_count'])
        self.assertEqual(report['planned'], self.original['planned'])
        self.assertEqual(report['planned'], report['started'])
        self.assertEqual(report['planned'], report['stopped'])
        self.assertEqual(report['mismatches'], [])
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['remaining_delivery_custody'], [])
        self.assertTrue(report['actual_public_dispatcher_and_loader'])
        self.assertTrue(report['retained_complete_handlers_poisoned'])
        self.assertTrue(report['constructor_only_injects_original_fixture_namespace'])

    def test_actual_packets_and_all_buffers_match_independent_VM(self):
        program = assemble_program(native.SOURCE.read_bytes())
        real, entries = self.image._entry, []
        def compared(source, size, output, capacity, state, extent):
            request = ctypes.string_at(source, size)
            expected = vm_call(program, request, ctypes.string_at(output, capacity),
                               ctypes.string_at(state, extent))
            code = real(source, size, output, capacity, state, extent)
            actual = (code, ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
            self.assertEqual(actual, expected)
            self.assertEqual(ctypes.string_at(source, size), request)
            entries.append({'request_hex': request.hex(), 'return': code,
                'output_hex': actual[1].hex(), 'state_hex': actual[2].hex()})
            return code
        with patch.object(self.image, '_entry', compared):
            rows = observe_six(self.image)
        (self.case / 'six-vm-native.json').write_bytes(canonical({'cases': rows, 'entries': entries}))
        for row in rows:
            with self.subTest(case=row['case_id']):
                self.assertTrue(row['canonical_equal'], row)
        self.assertGreater(len(entries), 0)
        protocol = protocol_witnesses(self.image, program)
        (self.case / 'protocol.json').write_bytes(canonical(protocol))
        self.assertGreater(protocol['actual_entry_count'], 0)

    def test_original_foreign_identity_and_safe_preparation(self):
        self.control('foreign')
        self.control('preparation')

    def test_actual_handoff_loss_receipt_corruption_and_no_replay(self):
        self.control('loss')

    def test_actual_peer_loss_both_directions_swallow_and_replace(self):
        self.control('peer')

    def test_creator_reentry_and_whole_method_resource_custody(self):
        self.control('creator')
        self.control('resources')

    def test_actual_public_handlers_replay_and_pinned_scope(self):
        self.control('public')
        self.control('scope')

    def test_actual_installed_worker_both_handlers_and_all_failure_modes(self):
        run_child(self.case, 'installed', [ROOT / 'tests/hia_service_inspection_installed.py',
            '--manifest', self.manifest, '--store-manifest', self.store_manifest,
            '--output', self.case / 'installed'], timeout=180)
        report = json.loads((self.case / 'installed/report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['closed_baseline']['worker_processes'], 16)
        self.assertEqual(len(report['closed_baseline']['cases']), 8)
        self.assertEqual(len(report['commands']), 18)
        self.assertTrue(report['source_pins_supplied_to_every_worker'])
        self.assertFalse(report['whole_native_stack_qualified'])
