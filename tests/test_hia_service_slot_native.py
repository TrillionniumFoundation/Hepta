"""Complete service Slot control gates. Original tests and budgets remain separate."""
from __future__ import annotations
import ast
from collections import Counter
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from tests.hia_service_slot_controls import (
    ROOT, COLD, DEV, EVIDENCE, SOURCE_EVIDENCE, VM_IDS, encoded, put, digest,
    invocation, inputs, originals, expected_rows, vm_image, vm_call,
    run_child, build_companions, environment)

class ServiceSlotSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = invocation(SOURCE_EVIDENCE)
        cls.originals, cls.original_report = originals(cls.root)

    def test_01_original_complete_bodies_routes_and_generated_profile(self):
        from tests.hia_service_slot_observer import load_oracle
        oracle = load_oracle()
        from hepta import hia_agent_service as api
        from hepta import hia_service_slot_native as native
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools import generate_hia_service_slot as generator
        oracle.original_sources()
        from tests.hia_store_delivery_successor import retained_bootstrap_service
        service_source = (ROOT / 'hepta/hia_agent_service.py').read_bytes()
        raw = retained_bootstrap_service(service_source)
        module, lines = ast.parse(raw), raw.splitlines(keepends=True)
        service = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
        for name, fixed in (('_hia_rollback', 'rollback'), ('_hia_adopt', 'adopt')):
            method = next(n for n in service.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(b''.join(lines[method.lineno - 1:method.end_lineno]),
                             (oracle.FIXTURE / (fixed + '.bc011.py.txt')).read_bytes())
        self.assertIs(api.HIAAgentService._hia_rollback, api._service_slot_rollback_dispatch)
        self.assertIs(api.HIAAgentService._hia_adopt, api._service_slot_adopt_dispatch)
        self.assertEqual(native.SOURCE.read_bytes(), render_assembly(generator.document()).encode())
        document = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(document['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in document['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for f in document['functions'] for b in f['blocks']), 8192)
        self.assertLessEqual(len(native.SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(native.SOURCE.read_text().splitlines()), 16384)
        for f in document['functions']:
            names = {p['name'] for p in f['params']}
            for b in f['blocks']:
                self.assertLessEqual(len(b['params']), 16)
                names.update(p['name'] for p in b['params'])
                names.update(p['name'] for op in b['ops'] for p in op['out'])
            self.assertLessEqual(len(f['blocks']), 256); self.assertLessEqual(len(names), 2048)
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELPERS[native.SELECTOR], ('hia_service_slot_native', 'NativeServiceSlot'))
        self.assertEqual(self.original_report['base_count'], 348)
        self.assertGreater(self.original_report['fault_count'], 0)
        self.assertFalse(self.original_report['candidate_results_used_as_expected'])

    def test_02_twenty_independent_VM_paths_against_prior_original_bytes(self):
        from hepta import hia_service_slot_native as native
        from hepta.hia_agent_assembly import assemble_program
        from tests.hia_service_slot_observer import load_oracle
        oracle = load_oracle()
        cases = {v['id']: v for v in inputs()['cases']}
        expected = expected_rows(self.originals)
        program = assemble_program(native.SOURCE.read_bytes()); image = vm_image(program)
        from unittest.mock import patch
        self.enterContext(patch(
            'hepta.hia_default_native.default_integer_image',
            side_effect=AssertionError('independent service Slot VM consulted a package owner')))
        initialize = native.NativeServiceSlot.__init__
        def forbidden(*a, **k): raise AssertionError('independent VM mapped native code')
        native.NativeServiceSlot.__init__ = forbidden
        observations = []
        try:
            for name in VM_IDS:
                def invoke(mode, make_service, make_arguments, namespace):
                    return native.ServiceSlotFrame(image, native.ROLLBACK if mode == 'rollback' else native.ADOPT,
                        make_service(), make_arguments(), namespace=namespace).finish()
                row = oracle.observe(cases[name], factory=invoke)
                observations.append(row)
                self.assertEqual(encoded(row['observation']), encoded(expected[name]), name)
                self.assertFalse(row['observation']['callback_errors'])
        finally:
            native.NativeServiceSlot.__init__ = initialize
            put(self.root / 'vm-observations.json', observations)
        self.assertEqual(len(observations), 20); self.assertGreater(image._entry.entries, 0)

    def test_03_absence_empty_and_original_public_route(self):
        from hepta import hia_agent_service as api
        from hepta import hia_service_slot_native as native
        class Store:
            def json(self, value, kind): return {'receipt': value, 'kind': kind}
        class Ledger:
            def validate_u64(self, value, label): return None
            def rollback(self, arguments, snapshot, callback): return {'generation': '0', 'epoch': '2'}, {'id': 'active'}
        class Service:
            _slot_ledger = Ledger()
            store = Store()
            def _conditional_slot(self, args): return {'current': {'generation': '1', 'epoch': '1'}}
            def _native(self, *args): raise AssertionError('unused provider')
        args = {'context': {'id': 'c'}, 'target_slot': 'slot', 'retained_generation': '0', 'reason': 'test'}
        previous = os.environ.pop(native.SELECTOR, None)
        loader = native.installed_service_slot
        def forbidden(*a, **k): raise AssertionError('absent selector admitted image')
        native.installed_service_slot = forbidden
        try:
            expected = api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE(Service(), dict(args))
            actual = api.HIAAgentService._hia_rollback(Service(), dict(args))
            self.assertEqual(actual, expected)
        finally:
            native.installed_service_slot = loader
            if previous is not None: os.environ[native.SELECTOR] = previous
        old = os.environ.get(native.SELECTOR)
        try:
            os.environ[native.SELECTOR] = ''
            with self.assertRaises(ValueError): api.HIAAgentService._hia_rollback(Service(), dict(args))
        finally:
            if old is None: os.environ.pop(native.SELECTOR, None)
            else: os.environ[native.SELECTOR] = old

class ServiceSlotNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, dev = os.environ.get(COLD), os.environ.get(DEV)
        if (cold is None) == (dev is None) or cold == '' or dev == '':
            raise ValueError('one nonempty matching cold report or explicit DEV compiler is required')
        cls.root = invocation(EVIDENCE)
        # Four complete independent original children precede building/mapping.
        cls.originals, cls.original_report = originals(cls.root)
        if cold is None: compiler = Path(dev)
        else:
            from tools.hia_cold_compiler import compiler_from_cold_report
            compiler = compiler_from_cold_report(Path(cold))
        from tools.build_hia_json_preflight import current_sources
        cls.sources, cls.compiler_raw = current_sources(), compiler.read_bytes()
        cls.compiler, cls.cold = compiler, cold
        cls.manifests, cls.bundle, cls.pin = build_companions(cls.root, compiler, cold)
        from hepta import hia_service_slot_native as native
        cls.image = native.installed_service_slot(str(cls.manifests['service']))

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = after == cls.sources and cls.compiler.read_bytes() == cls.compiler_raw
        put(cls.root / 'custody.json', {
            'schema': 'hepta.hia.service-slot-component-custody.v1',
            'source_before': cls.sources, 'source_after': after, 'source_and_compiler_unchanged': stable,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'cold_report': cls.cold, 'runtime': sys.version,
            'manifests': {k: str(v) for k, v in cls.manifests.items()},
            'bundle_sha256': cls.pin, 'whole_native_stack_qualified': False})
        if not stable: raise AssertionError('service Slot component input custody changed')

    def test_01_all_independent_originals_and_frozen_derived_faults(self):
        target = self.root / 'finite'
        run_child(self.root, 'finite-command', [
            ROOT / 'tools/qualify_hia_service_slot_originals.py', '--output', target,
            '--originals', self.originals, '--manifest', self.manifests['service']], timeout=1800)
        report = json.loads((target / 'report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['base_count'], 348)
        self.assertEqual(report['fault_count'], self.original_report['fault_count'])
        self.assertFalse(report['original_expectations_replaced_or_normalized'])
        self.assertTrue(report['all_candidate_cases_use_actual_public_dispatch'])
        self.assertEqual(len(report['reports']), 2)
        for child in report['reports']:
            self.assertTrue(child['actual_public_dispatch_selected'])
            self.assertTrue(child['retained_reference_poisoned'])
            self.assertGreaterEqual(sum(child['public_dispatch_calls'].values()), child['count'])
            self.assertGreater(sum(child['actual_frames'].values()), 0)

    def test_02_all_38_ports_complete_buffers_VM_and_native(self):
        from hepta import hia_service_slot_native as native
        from hepta.hia_agent_assembly import assemble_program
        from tests.hia_service_slot_observer import load_oracle
        oracle = load_oracle()
        program = assemble_program(native.SOURCE.read_bytes())
        cases = {v['id']: v for v in inputs()['cases']}; expected = expected_rows(self.originals)
        entry, records = self.image._entry, []
        label = [None]
        def compared(source, size, output, capacity, state, extent):
            raw = ctypes.string_at(source, size); old_output = ctypes.string_at(output, capacity)
            old_state = ctypes.string_at(state, extent)
            source_guard = ctypes.string_at(source, size + 16)
            output_guard = ctypes.string_at(output, capacity + 16)[capacity:]
            state_guard = ctypes.string_at(state, extent + 16)[extent:]
            code = entry(source, size, output, capacity, state, extent)
            observed = (code, ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
            model = vm_call(program, raw, old_output, old_state)
            row = {'case': label[0], 'request': raw.hex(), 'old_output': old_output.hex(),
                'old_state': old_state.hex(), 'native_code': code, 'vm_code': model[0],
                'native_output': observed[1].hex(), 'vm_output': model[1].hex(),
                'native_state': observed[2].hex(), 'vm_state': model[2].hex(),
                'full_buffers_equal': observed == model,
                'canaries_unchanged': ctypes.string_at(source, size + 16) == source_guard
                    and ctypes.string_at(output, capacity + 16)[capacity:] == output_guard
                    and ctypes.string_at(state, extent + 16)[extent:] == state_guard}
            records.append(row)
            self.assertEqual(observed, model); self.assertTrue(row['canaries_unchanged'])
            return code
        self.image._entry = compared
        try:
            for name in VM_IDS:
                label[0] = name
                def invoke(mode, make_service, make_arguments, namespace):
                    return native.ServiceSlotFrame(self.image,
                        native.ROLLBACK if mode == 'rollback' else native.ADOPT,
                        make_service(), make_arguments(), namespace=namespace).finish()
                actual = oracle.observe(cases[name], factory=invoke)
                self.assertEqual(encoded(actual['observation']), encoded(expected[name]), name)
        finally:
            self.image._entry = entry
            put(self.root / 'complete-buffer-comparison.json', records)
        issued = set()
        events = Counter()
        for row in records:
            words = struct.unpack('<10Q', bytes.fromhex(row['request']))
            events[words[1]] += 1
            if words[1] == native.CLAIM: issued.add(words[3])
        self.assertEqual(issued, set(range(1, 39)))
        self.assertTrue(all(events[event] > 0 for event in range(5)))

    def test_03_actual_public_selected_route_and_exact_manifest_refusal(self):
        from hepta import hia_agent_service as api
        from hepta import hia_service_slot_native as native
        from tests.hia_service_slot_observer import load_oracle
        oracle = load_oracle()
        cases = {v['id']: v for v in inputs()['cases']}; expected = expected_rows(self.originals)
        original_class = native.ServiceSlotFrame
        aliases = api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE, api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE
        previous = os.environ.get(native.SELECTOR)
        def forbidden(*a, **k): raise AssertionError('selected public retained body')
        api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE = api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE = forbidden
        os.environ[native.SELECTOR] = str(self.manifests['service'])
        observations = []
        try:
            for name in ('rollback.ledger.11.outer0', 'adopt.ledger.111.outer0'):
                def invoke(mode, make_service, make_arguments, namespace):
                    def prepare(image, selected_mode, service, arguments):
                        return original_class(image, selected_mode, service, arguments, namespace=namespace)
                    native.ServiceSlotFrame = prepare
                    try:
                        method = api.HIAAgentService._hia_rollback if mode == 'rollback' else api.HIAAgentService._hia_adopt
                        return method(make_service(), make_arguments())
                    finally: native.ServiceSlotFrame = original_class
                actual = oracle.observe(cases[name], factory=invoke); observations.append(actual)
                self.assertEqual(encoded(actual['observation']), encoded(expected[name]))
            original = json.loads(self.manifests['service'].read_bytes())
            for key in ('source_sha256', 'image_sha256'):
                directory = self.root / ('drift-' + key); directory.mkdir()
                image = self.manifests['service'].parent / original['image_path']
                (directory / image.name).write_bytes(image.read_bytes())
                value = dict(original); value[key] = '0' * 64
                put(directory / 'manifest.json', value)
                os.environ[native.SELECTOR] = str(directory / 'manifest.json')
                with self.assertRaises(ValueError):
                    api.HIAAgentService._hia_rollback(object(), {})
        finally:
            native.ServiceSlotFrame = original_class
            api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE, api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE = aliases
            if previous is None: os.environ.pop(native.SELECTOR, None)
            else: os.environ[native.SELECTOR] = previous
            put(self.root / 'public-observations.json', observations)

    def resources(self, suffixes):
        from tests.hia_service_slot_resources import CASES
        ids = [name for name in CASES if name.split('.', 1)[1] in suffixes]
        reports = []
        for name in ids:
            target = self.root / 'resources' / name
            run_child(self.root / 'resource-commands', name,
                [ROOT / 'tests/hia_service_slot_resources.py', '--case', name,
                 '--authority', self.root / 'companion-authority.json', '--output', target], timeout=180)
            value = json.loads((target / 'report.json').read_bytes())
            self.assertEqual(value['status'], 'PASS'); self.assertEqual(value['case'], name)
            self.assertEqual(value['source_before'], value['source_after'])
            self.assertFalse(value['loss_fields_or_parent_check_modified'])
            reports.append(value)
        self.assertEqual(len(reports), 2 * len(suffixes))

    def test_04_real_A_and_B_survive_each_post_effect_ACK_loss(self):
        self.resources(('result-ack-loss', 'release-ack-loss', 'finalize-ack-loss'))

    def test_05_preparation_reentry_ordinary_and_actual_child_loss(self):
        self.resources(('first-preparation-refusal', 'late-preparation-refusal',
                        'confirmed-provider-error', 'same-frame-reentry', 'child-sql-ack-loss',
                        'finalize-preparation-refusal', 'confirmed-retirement-error'))

    def test_06_each_port_actual_ACK_four_exception_families(self):
        target = self.root / 'transport-controls'
        run_child(self.root, 'transport-command', [
            ROOT / 'tests/hia_service_slot_transport.py', '--manifest', self.manifests['service'],
            '--output', target], timeout=180)
        report = json.loads((target / 'report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['planned_count'], 152)
        self.assertEqual(len(report['observations']), 152)
        self.assertTrue(all(v['actual_entry_returned'] and v['fault_identity_in_chain']
                            and v['no_later_entry'] and v['record_retained']
                            for v in report['observations']))

    def test_07_original_public_service_transaction_and_exact_replay(self):
        target = self.root / 'public-workflow'
        run_child(self.root, 'public-workflow-command', [
            ROOT / 'tests/hia_service_slot_public_workflow.py',
            '--authority', self.root / 'companion-authority.json', '--output', target], timeout=180)
        report = json.loads((target / 'report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['tools'], ['hia_adopt', 'hia_rollback'])
        self.assertTrue(all(row['first']['status'] == 'completed' and row['exact_replay']
                            and row['replay_handler_entries'] == 0 and row['database_unchanged']
                            for row in report['observations']))

    def test_08_actual_installed_worker_both_tools_replay_loss_and_source_pins(self):
        target = self.root / 'installed'
        run_child(self.root, 'installed-command', [
            ROOT / 'tests/hia_service_slot_installed.py',
            '--authority', self.root / 'companion-authority.json', '--output', target], timeout=1800)
        report = json.loads((target / 'report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(len(report['observations']), 8)
        self.assertTrue(report['source_pins_supplied_to_every_worker'])
        self.assertFalse(report['unknown_custody_reported_as_cleanup_success'])
