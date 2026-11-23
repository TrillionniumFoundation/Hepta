"""Pure source/reader controls for the explicit service artifact terminal successor.

Synthetic reader controls are not installed/native evidence. Original complete
Source3/Native8 still run in their separate real gates; GC146 remains unchanged.
"""
from __future__ import annotations
import ast
import copy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import hia_service_artifact_worker_terminal as producer
from tools import read_hia_service_artifact_worker_terminal as reader
from tools.read_hia_service_artifact_worker_terminal import Captures

ROOT = Path(__file__).resolve().parents[1]
LABELS = ('first', 'replay', 'lost-put-ACK', 'unknown-replay')
TRUE_FACTS = (
    'request_observer_inactive', 'origin_present', 'origin_custodied', 'origin_loss_is_self',
    'origin_error_is_actual_injected', 'origin_native_pending', 'service_artifact_frame_retained',
    'primary_is_actual_worker_call_failure', 'primary_is_service_artifact_unknown',
    'primary_cause_is_actual_origin_error', 'cleanup_is_actual_close_failure',
    'cleanup_is_delivery_unknown', 'cleanup_context_is_primary', 'terminal_is_cleanup',
    'diagnostics_preserved_error_and_custody_identities')
DIAGNOSTIC = b'\n'.join((
    b'HIA_WORKER_DELIVERY_UNKNOWN', b'REQUEST_PRIMARY_EXCEPTION',
    b'ValueError: actual handler PUT acknowledgement lost after confirmed Store',
    b'ServiceArtifactUnknown: native service artifact observation failed', b'REQUEST_CLEANUP_EXCEPTION',
    b'NativeDeliveryUnknown: resource has unconfirmed native delivery; it cannot be retired')) + b'\n'


def source(raw):
    return ast.parse(raw)


def methods(raw, name):
    cls = next(node for node in source(raw).body if isinstance(node, ast.ClassDef) and node.name == name)
    return {node.name: node for node in cls.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}


class ServiceArtifactWorkerTerminalSourceTests(unittest.TestCase):
    def test_00_complete_original_sources_and_denominators_are_retained(self):
        authority = producer.SourceAuthority(ROOT)
        captured = Captures()
        self.assertEqual(reader.admit_source_authority(captured, ROOT), authority.summary())
        self.assertEqual(len(authority.originals), 2)
        for name, original in authority.originals.items():
            current = (ROOT / name).read_bytes()
            from tests.hia_installed_distribution_history import predecessor
            prior = predecessor(name, current, reader.original_source)
            self.assertEqual(reader.original_source(prior, authority.value['source_successors'][name]), original)
        path = 'tests/test_hia_service_artifact_native.py'
        for cls_name, count in (('ServiceArtifactNativeTests', 8), ('ServiceArtifactSourceTests', 3)):
            original = methods(authority.originals[path], cls_name)
            current = methods((ROOT / path).read_bytes(), cls_name)
            self.assertEqual(list(original), list(current))
            self.assertEqual(len(current), count)
            self.assertEqual(list(original), authority.value['scope']['original_classes_and_methods'][cls_name])
            for name in original:
                if name == 'test_complete_fresh_originals_and_unselected_public_route':
                    # Only the test double's binding changed. Recheck the two
                    # exact class prefixes, then compare the full test body.
                    new_service, = (node for node in current[name].body
                                    if isinstance(node, ast.ClassDef) and node.name == 'Service')
                    expected = ast.parse('class Service(api.HIAAgentService):\n'
                                         '    def __init__(self):\n'
                                         '        self.store = Store()\n').body[0]
                    self.assertEqual(len(new_service.bases), 1)
                    self.assertEqual(ast.dump(new_service.bases[0]), ast.dump(expected.bases[0]))
                    self.assertEqual(ast.dump(new_service.body[0]), ast.dump(expected.body[0]))
                    new_service.bases.clear()
                    new_service.body[0] = ast.parse('store = Store()').body[0]
                if name != 'test_actual_installed_worker_and_durable_parent_ACK_loss':
                    self.assertEqual(ast.dump(original[name]), ast.dump(current[name]))
                else:
                    def assertions(node):
                        return [ast.dump(item) for item in ast.walk(node)
                            if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
                            and isinstance(item.func.value, ast.Name) and item.func.value.id == 'self'
                            and item.func.attr.startswith('assert')]
                    remaining = iter(assertions(current[name]))
                    self.assertTrue(all(any(item == old for item in remaining) for old in assertions(original[name])))
        scope = authority.value['scope']
        self.assertEqual({name: scope[name] for name in (
            'native8_methods', 'source3_methods', 'worker_labels', 'worker_seconds',
            'wheel_seconds', 'install_seconds')},
            {'native8_methods': 8, 'source3_methods': 3, 'worker_labels': list(LABELS),
             'worker_seconds': 60, 'wheel_seconds': 60, 'install_seconds': 60})
        self.assertIs(scope['original_finite146_unchanged'], True)
        self.assertIs(scope['original_Native8_replaced'], False)
        self.assertIs(scope['old_pass_transferred'], False)
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
        with tempfile.TemporaryDirectory(prefix='artifact-terminal-source-') as temporary:
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
        lost = label == 'lost-put-ACK'
        request = label in LABELS
        facts = {name: True for name in TRUE_FACTS}
        facts.update(origin_retired=False, returned_status=2)
        return {'schema': 'hepta.service_artifact.installed-worker-terminal.v2',
            'profile': producer.worker_profile((ROOT / 'hepta/hia_agent_worker.py').read_bytes()),
            'injection_observed': lost, 'close_attempts': int(request),
            'close_returns': int(request and not lost), 'primary_notes': int(lost),
            'cleanup_notes': int(lost), 'terminal_calls': int(lost),
            'facts': facts if lost else None}

    def test_02_independent_terminal_reader_rejects_missing_identity_and_retry_claims(self):
        for label in LABELS:
            value = self.valid(label)
            stderr = DIAGNOSTIC if label == 'lost-put-ACK' else b''
            profile = copy.deepcopy(value['profile'])
            producer.assert_terminal(self, value, stderr, label, profile)
            reader.verify_terminal(value, stderr, label, profile)
        valid = self.valid('lost-put-ACK')
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
                producer.assert_terminal(self, changed, DIAGNOSTIC, 'lost-put-ACK', valid['profile'])
            with self.assertRaises(ValueError):
                reader.verify_terminal(changed, DIAGNOSTIC, 'lost-put-ACK', valid['profile'])
        for raw in (b'', DIAGNOSTIC.replace(b'REQUEST_CLEANUP_EXCEPTION', b''),
                    DIAGNOSTIC + b'REQUEST_PRIMARY_EXCEPTION\n',
                    DIAGNOSTIC + b'HIA_WORKER_DELIVERY_UNKNOWN diagnostic unavailable\n'):
            with self.assertRaises(AssertionError):
                producer.assert_terminal(self, valid, raw, 'lost-put-ACK', valid['profile'])
            with self.assertRaises(ValueError):
                reader.verify_terminal(valid, raw, 'lost-put-ACK', valid['profile'])

    def test_03_observer_delegates_actual_error_objects_once_without_rewriting_custody(self):
        class ArtifactUnknown(RuntimeError):
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
        controller = SimpleNamespace(ServiceArtifactFrame=Frame, ServiceArtifactUnknown=ArtifactUnknown)
        observed = producer.TerminalObservation(worker, service, delivery, controller)
        error = ValueError('actual handler PUT acknowledgement lost after confirmed Store')
        observed.injected(error)
        origin.error = error
        try:
            try:
                try:
                    raise ArtifactUnknown('native service artifact observation failed') from error
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
        producer.assert_terminal(self, result, DIAGNOSTIC, 'lost-put-ACK', observed.profile)
        reader.verify_terminal(result, DIAGNOSTIC, 'lost-put-ACK', observed.profile)
        self.assertEqual(terminal_calls, [(id(observation), id(observation.cleanup_error))])
        self.assertIs(observation.primary_error.__cause__, error)
        self.assertIs(observation.cleanup_error.__context__, observation.primary_error)
        self.assertIs(custody[id(origin)], origin)
        self.assertEqual(resources, {})

    def test_04_original_worker_profile_and_installed_source_reread_are_strict(self):
        old = (ROOT / producer.ORIGINAL_WORKER).read_bytes()
        current = (ROOT / 'hepta/hia_agent_worker.py').read_bytes()
        with tempfile.TemporaryDirectory(prefix='artifact-terminal-worker-') as temporary:
            path = Path(temporary) / 'worker.py'
            path.write_bytes(old)
            observed = producer.TerminalObservation(SimpleNamespace(__file__=str(path)), None, None, None)
            value = observed.report()
            producer.assert_terminal(self, value, b'', 'first', observed.profile)
            reader.verify_terminal(value, b'', 'first', observed.profile)
            error = ValueError('actual handler PUT acknowledgement lost after confirmed Store')
            observed.injected(error)
            value = observed.report()
            producer.assert_terminal(self, value, b'', 'lost-put-ACK', observed.profile)
            reader.verify_terminal(value, b'', 'lost-put-ACK', observed.profile)
            for changed in (old + b'\n', current):
                path.write_bytes(changed)
                with self.assertRaises(ValueError):
                    observed.report()
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                observed.report()
        valid = self.valid('lost-put-ACK')
        for field, bad in (('version', True), ('version', 4), ('lost_ack_exit', True),
                           ('lost_ack_exit', 1), ('worker', dict(producer.WORKERS[1]))):
            changed = copy.deepcopy(valid)
            changed['profile'][field] = bad
            with self.assertRaises(AssertionError):
                producer.assert_terminal(self, changed, DIAGNOSTIC, 'lost-put-ACK', changed['profile'])
            with self.assertRaises(ValueError):
                reader.verify_terminal(changed, DIAGNOSTIC, 'lost-put-ACK', changed['profile'])

    def test_05_complete_raw_worker_readback_refuses_relabeling_and_late_changes(self):
        # Synthetic DATA controls; these records are not native/installed evidence.
        authority = producer.SourceAuthority(ROOT)
        cls = next(node for node in source((ROOT / 'tests/test_hia_service_artifact_native.py').read_bytes()).body
                   if isinstance(node, ast.ClassDef) and node.name == 'ServiceArtifactNativeTests')
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'test_actual_installed_worker_and_durable_parent_ACK_loss')
        script, = [node.value.value for node in ast.walk(method) if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == 'script' and isinstance(node.value, ast.Constant)]
        with tempfile.TemporaryDirectory(prefix='artifact-terminal-data-') as temporary:
            directory = Path(temporary).resolve()
            installed = directory / 'installed'
            worker = installed / 'hepta/hia_agent_worker.py'
            worker.parent.mkdir(parents=True)
            worker.write_bytes((ROOT / 'hepta/hia_agent_worker.py').read_bytes())
            record = installed / 'synthetic.dist-info/RECORD'
            record.parent.mkdir()
            record.write_bytes(b'synthetic DATA source control\n')
            wheel = directory / 'synthetic.whl'
            wheel.write_bytes(b'synthetic DATA source control; not a wheel qualification')
            bundle = directory / 'bundle.json'
            bundle.write_bytes(b'{}\n')
            bundle_sha = sha256(bundle.read_bytes()).hexdigest()
            installation = {'terminal_source_authority': authority.summary(),
                'installed': str(installed), 'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
                'installed_RECORD_sha256': sha256(record.read_bytes()).hexdigest(),
                'bundle_sha256': bundle_sha, 'observations': {}}
            for label, key in zip(LABELS, ('success', 'replay', 'lost_put_ack', 'unknown_replay')):
                lost = label == 'lost-put-ACK'
                terminal = self.valid(label)
                counts = {'terminal': terminal}
                report = {'synthetic_source_control': label}
                stdout = b'' if lost else producer.canonical(report) + b'\n'
                stderr = (DIAGNOSTIC if lost else b'') + b'SERVICE_ARTIFACT_COUNTS=' + producer.canonical(counts) + b'\n'
                state_root = '/synthetic/first' if label in ('first', 'replay') else '/synthetic/second'
                argv = [sys.executable, '-B', '-I', '-c', script, str(installed),
                    'lost_put_ack' if lost else 'normal', str(ROOT), '--state-root', state_root,
                    '--artifact-root', state_root + '/artifacts', '--request-json-stdin',
                    '--native-helpers-manifest', str(bundle), '--expected-native-helpers-sha256', bundle_sha]
                command = producer.canonical({'command': argv, 'timeout_seconds': 60}) + b'\n'
                code = 2 if lost else 0
                receipt = producer.process_record(SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr), command)
                for suffix, raw in (('.stdout', stdout), ('.stderr', stderr), ('-command.json', command),
                                    ('-terminal-process.json', producer.canonical(receipt) + b'\n')):
                    (directory / (label + suffix)).write_bytes(raw)
                observation = {'counts': counts}
                observation.update(worker_exit=code) if lost else observation.update(report=report)
                installation['observations'][key] = observation
            path = directory / 'installation.json'
            path.write_bytes(producer.canonical(installation) + b'\n')
            frozen = {item: item.read_bytes() for item in directory.rglob('*') if item.is_file()}
            result = reader.read_installation(ROOT, directory)
            self.assertEqual(result['status'], 'PASS_COMPLETE_FOUR_WORKER_TERMINALS')
            self.assertEqual(list(result['workers']), list(LABELS))
            self.assertIs(result['finite146_qualified_by_this_reader'], False)
            for label in LABELS:
                for suffix in ('.stdout', '.stderr', '-command.json', '-terminal-process.json'):
                    target = directory / (label + suffix)
                    target.write_bytes(frozen[target] + b'\n')
                    with self.subTest(label=label, suffix=suffix), self.assertRaises(ValueError):
                        reader.read_installation(ROOT, directory)
                    target.write_bytes(frozen[target])
            target = directory / 'lost-put-ACK-command.json'
            value = json.loads(frozen[target])
            value['command'][4] += '\n'
            changed = producer.canonical(value) + b'\n'
            target.write_bytes(changed)
            receipt_path = directory / 'lost-put-ACK-terminal-process.json'
            receipt = json.loads(frozen[receipt_path]);receipt['command'] = reader.digest(changed)
            receipt_path.write_bytes(producer.canonical(receipt) + b'\n')
            with self.assertRaises(ValueError):
                reader.read_installation(ROOT, directory)
            target.write_bytes(frozen[target]);receipt_path.write_bytes(frozen[receipt_path])
            target = directory / 'lost-put-ACK.stderr'
            regular = reader.regular_bytes
            changed = False
            def change_after_capture(path):
                nonlocal changed
                data = regular(path)
                if Path(path) == target and not changed:
                    changed = True
                    target.write_bytes(data + b'\n')
                return data
            with patch.object(reader, 'regular_bytes', change_after_capture), self.assertRaises(ValueError):
                reader.read_installation(ROOT, directory)
            target.write_bytes(frozen[target])
            worker.write_bytes(frozen[worker] + b'\n')
            with self.assertRaises(ValueError):
                reader.read_installation(ROOT, directory)
        authority.finish()


if __name__ == '__main__':
    unittest.main()
