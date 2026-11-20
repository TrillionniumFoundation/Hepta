"""Pure source/reader controls for the explicit Slot terminal successor.

Synthetic reader controls are not installed/native evidence. Original complete
Source3/Native6 and mechanical Native4 still run in their separate real gates.
"""
from __future__ import annotations
import ast
import copy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

from tests import hia_slot_worker_terminal as producer
from tools import read_hia_slot_worker_terminal as reader
from tools.read_hia_slot_mechanical_installed import Captures

ROOT = Path(__file__).resolve().parents[1]
LABELS = ('installation-manifest', 'normal', 'replay', 'lost-SQL-ACK',
          'unknown-replay', 'source-plus-LF', 'extra-module')
TRUE_FACTS = (
    'request_observer_inactive', 'origin_present', 'origin_custodied', 'origin_loss_is_self',
    'origin_error_is_actual_injected', 'origin_native_pending', 'slot_frame_retained',
    'primary_is_actual_worker_call_failure', 'primary_is_slot_unknown',
    'primary_cause_is_actual_origin_error', 'cleanup_is_actual_close_failure',
    'cleanup_is_delivery_unknown', 'cleanup_context_is_primary', 'terminal_is_cleanup',
    'diagnostics_preserved_error_and_custody_identities')
DIAGNOSTIC = b'\n'.join((
    b'HIA_WORKER_DELIVERY_UNKNOWN', b'REQUEST_PRIMARY_EXCEPTION',
    b'ValueError: actual SQL execute returned; controller acknowledgement withheld',
    b'SlotOperationsUnknown: Slot controller delivery failed', b'REQUEST_CLEANUP_EXCEPTION',
    b'NativeDeliveryUnknown: resource has unconfirmed native delivery; it cannot be retired')) + b'\n'


def source(raw):
    return ast.parse(raw)


def methods(raw, name):
    cls = next(node for node in source(raw).body if isinstance(node, ast.ClassDef) and node.name == name)
    return {node.name: node for node in cls.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}


class SlotWorkerTerminalSourceTests(unittest.TestCase):
    def test_00_complete_original_sources_and_denominators_are_retained(self):
        authority = producer.SourceAuthority(ROOT)
        captured = Captures()
        self.assertEqual(reader.admit_source_authority(captured, ROOT), authority.summary())
        self.assertEqual(len(authority.originals), 8)
        for name, original in authority.originals.items():
            current = (ROOT / name).read_bytes()
            self.assertEqual(reader.original_source(current, authority.value['source_successors'][name]), original)
        path = 'tests/test_hia_slot_operations_native.py'
        original = methods(authority.originals[path], 'SlotOperationsNativeTests')
        current = methods((ROOT / path).read_bytes(), 'SlotOperationsNativeTests')
        self.assertEqual(list(original), list(current))
        self.assertEqual(len(current), 6)
        for name in original:
            if name != 'test_05_actual_installed_worker_new_helper_and_unconfirmed_SQL':
                self.assertEqual(ast.dump(original[name]), ast.dump(current[name]))
        scope = authority.value['scope']
        self.assertEqual({name: scope[name] for name in (
            'native6_methods', 'mechanical_native4_methods', 'workers_per_current_lane', 'worker_seconds',
            'original248', 'derived7574', 'public84', 'handled12', 'admission25')},
            {'native6_methods': 6, 'mechanical_native4_methods': 4, 'workers_per_current_lane': 7,
             'worker_seconds': 60, 'original248': 248, 'derived7574': 7574,
             'public84': 84, 'handled12': 12, 'admission25': 25})
        self.assertEqual(scope['current_lanes'], ['current-v1', 'current-v5'])
        for raw in (authority.originals['tools/read_hia_slot_mechanical_installed.py'],
                    (ROOT / 'tools/read_hia_slot_mechanical_installed.py').read_bytes()):
            assignments = [node.value for node in ast.walk(source(raw)) if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == 'worker_labels'
                                   for target in node.targets)]
            self.assertEqual([ast.literal_eval(node) for node in assignments], [list(LABELS)])
        old_worker = (ROOT / producer.ORIGINAL_WORKER).read_bytes()
        current_worker = (ROOT / 'hepta/hia_agent_worker.py').read_bytes()
        self.assertEqual(producer.worker_profile(old_worker)['lost_ack_exit'], 1)
        self.assertEqual(producer.worker_profile(current_worker)['lost_ack_exit'], 2)
        for raw in (old_worker + b'\n', current_worker + b'\n', bytearray(current_worker),
                    current_worker.replace(b'return 2', b'return 1', 1)):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(ValueError):
                producer.worker_profile(raw)
        authority.finish()
        captured.stable()

    def test_01_source_splices_and_late_capture_changes_are_refused(self):
        authority = producer.SourceAuthority(ROOT)
        for name, specification in authority.value['source_successors'].items():
            raw = (ROOT / name).read_bytes()
            for verify in (producer.inverse, reader.original_source):
                with self.subTest(name=name, reader=verify.__name__), self.assertRaises(ValueError):
                    verify(raw + b'\n', specification)
                for invalid in (True, -1, 0.0, '0'):
                    broken = copy.deepcopy(specification)
                    broken['splices'][0]['offset'] = invalid
                    with self.subTest(name=name, invalid=invalid), self.assertRaises(ValueError):
                        verify(raw, broken)
                broken = copy.deepcopy(specification)
                broken['original']['sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    verify(raw, broken)
                if len(specification['splices']) > 1:
                    broken = copy.deepcopy(specification)
                    broken['splices'].reverse()
                    with self.assertRaises(ValueError):
                        verify(raw, broken)
        with tempfile.TemporaryDirectory(prefix='slot-terminal-source-') as temporary:
            root = Path(temporary)
            for name, raw in authority.captured.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            local = producer.SourceAuthority(root)
            captured = Captures()
            reader.admit_source_authority(captured, root)
            target = root / producer.AUTHORITY
            target.write_bytes(target.read_bytes() + b'\n')
            with self.assertRaises(ValueError):
                local.finish()
            with self.assertRaises(ValueError):
                captured.stable()
            with self.assertRaises(ValueError):
                producer.SourceAuthority(root)
        authority.finish()

    def valid(self, label):
        lost = label == 'lost-SQL-ACK'
        request = label in ('normal', 'replay', 'lost-SQL-ACK', 'unknown-replay')
        facts = {name: True for name in TRUE_FACTS}
        facts.update(origin_retired=False, returned_status=2)
        return {'schema': 'hepta.slot.installed-worker-terminal.v2',
            'profile': producer.worker_profile((ROOT / 'hepta/hia_agent_worker.py').read_bytes()),
            'injection_observed': lost, 'close_attempts': int(request),
            'close_returns': int(request and not lost), 'primary_notes': int(lost),
            'cleanup_notes': int(lost), 'terminal_calls': int(lost),
            'facts': facts if lost else None}

    def test_02_independent_terminal_reader_rejects_missing_identity_and_retry_claims(self):
        for label in LABELS:
            value = self.valid(label)
            stderr = DIAGNOSTIC if label == 'lost-SQL-ACK' else b''
            profile = copy.deepcopy(value['profile'])
            producer.assert_terminal(self, value, stderr, label, profile)
            reader.verify_terminal(value, stderr, label, profile)
        valid = self.valid('lost-SQL-ACK')
        invalids = []
        for name in TRUE_FACTS:
            for bad in (False, 1, None):
                changed = copy.deepcopy(valid)
                changed['facts'][name] = bad
                invalids.append(changed)
        for name in ('close_attempts', 'primary_notes', 'cleanup_notes', 'terminal_calls'):
            for bad in (0, 2, True):
                changed = copy.deepcopy(valid)
                changed[name] = bad
                invalids.append(changed)
        for name, bad in (('close_returns', 1), ('injection_observed', False)):
            changed = copy.deepcopy(valid)
            changed[name] = bad
            invalids.append(changed)
        for name, bad in (('origin_retired', True), ('returned_status', 1), ('returned_status', True)):
            changed = copy.deepcopy(valid)
            changed['facts'][name] = bad
            invalids.append(changed)
        changed = copy.deepcopy(valid)
        changed['profile']['lost_ack_exit'] = 1
        invalids.append(changed)
        for changed in invalids:
            with self.assertRaises(AssertionError):
                producer.assert_terminal(self, changed, DIAGNOSTIC, 'lost-SQL-ACK', valid['profile'])
            with self.assertRaises(ValueError):
                reader.verify_terminal(changed, DIAGNOSTIC, 'lost-SQL-ACK', valid['profile'])
        for raw in (b'', DIAGNOSTIC.replace(b'REQUEST_CLEANUP_EXCEPTION', b''),
                    DIAGNOSTIC + b'REQUEST_PRIMARY_EXCEPTION\n',
                    DIAGNOSTIC + b'HIA_WORKER_DELIVERY_UNKNOWN diagnostic unavailable\n'):
            with self.assertRaises(AssertionError):
                producer.assert_terminal(self, valid, raw, 'lost-SQL-ACK', valid['profile'])
            with self.assertRaises(ValueError):
                reader.verify_terminal(valid, raw, 'lost-SQL-ACK', valid['profile'])

    def test_03_observer_delegates_actual_error_objects_once_without_rewriting_custody(self):
        class SlotUnknown(RuntimeError):
            pass
        class DeliveryUnknown(RuntimeError):
            pass
        class Frame:
            pass
        observation = SimpleNamespace(active=False, origin=None, primary_error=None, cleanup_error=None)
        origin = SimpleNamespace(owner=None, loss=None, native_pending=True, retired=False, error=None)
        frame = Frame()
        frame._delivery, frame.fenced, frame.native_failed = origin, True, True
        origin.owner = frame
        origin.loss = origin
        observation.origin = origin
        custody, resources, terminal_calls = {id(origin): origin}, {}, []
        def note(error, *, cleanup=False):
            setattr(observation, 'cleanup_error' if cleanup else 'primary_error', error)
        def terminal(current, error):
            terminal_calls.append((id(current), id(error)))
            return 2
        class Service:
            def close(self):
                raise DeliveryUnknown('resource has unconfirmed native delivery; it cannot be retired')
        worker = SimpleNamespace(__file__=str(ROOT / 'hepta/hia_agent_worker.py'),
                                 note_request_failure=note, _unknown_request_exit=terminal)
        service = SimpleNamespace(HIAAgentService=Service)
        delivery = SimpleNamespace(NativeDeliveryUnknown=DeliveryUnknown,
                                    _CUSTODY=custody, _RESOURCE_OBSERVATIONS=resources)
        controller = SimpleNamespace(SlotOperationsFrame=Frame, SlotOperationsUnknown=SlotUnknown)
        observed = producer.TerminalObservation(worker, service, delivery, controller)
        error = ValueError('actual SQL execute returned; controller acknowledgement withheld')
        observed.injected(error)
        origin.error = error
        try:
            try:
                try:
                    raise SlotUnknown('Slot controller delivery failed') from error
                except BaseException as primary:
                    worker.note_request_failure(primary)
                    raise
            finally:
                try:
                    Service().close()
                except BaseException as cleanup:
                    worker.note_request_failure(cleanup, cleanup=True)
                    raise
        except BaseException as terminal_error:
            self.assertEqual(worker._unknown_request_exit(observation, terminal_error), 2)
        result = observed.report()
        producer.assert_terminal(self, result, DIAGNOSTIC, 'lost-SQL-ACK', observed.profile)
        reader.verify_terminal(result, DIAGNOSTIC, 'lost-SQL-ACK', observed.profile)
        self.assertEqual(terminal_calls, [(id(observation), id(observation.cleanup_error))])
        self.assertIs(observation.primary_error.__cause__, error)
        self.assertIs(observation.cleanup_error.__context__, observation.primary_error)
        self.assertIs(custody[id(origin)], origin)
        self.assertEqual(resources, {})


if __name__ == '__main__':
    unittest.main()
