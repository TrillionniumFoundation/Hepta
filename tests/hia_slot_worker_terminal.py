"""Version-pinned installed Slot terminal observations; no product substitution.

The original source/assertions are recovered byte for byte by the fixed
successor authority. Only reviewed complete worker sources select an exit
contract. Observations retain integer identities, never extra exceptions
or resources, and call each real product boundary exactly once.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path

from tests.hia_slot_operations_qualification_support import (
    canonical, regular_bytes, unique_pairs)

AUTHORITY = 'tests/fixtures/slot_worker_terminal_v2.json'
AUTHORITY_SHA256 = '1808488c0fe6c66bf9424eb64f9fe7bef4a2ce6028b1ab41b7d3cefc7b5df580'
WORKERS = {
    1: {'bytes': 8496, 'sha256': '4e6a64b551e34805106fa1d4b888a48f9a2a138d2f82d4091b4412bf65862066'},
    2: {'bytes': 11444, 'sha256': '6352879dc0e58515a6af9b2a586a5efa27f4018fb19d49a379ab72425eebf45a'},
    3: {'bytes': 16086, 'sha256': 'd5f9f7ab7057e19c38aa263ae2acfa3494fec950f6f85299110f7522224dd172'},
}
DELIVERY_V3 = {'bytes': 50071, 'sha256': '08687e1997e8d4c7cc5f9807398f6fd765767af3b49d3b3b4b449383ce0167aa'}
DELIVERY_PATH = 'hepta/hia_native_delivery.py'
ORIGINAL_WORKER = 'tests/fixtures/worker_unknown_original_r17b/hia_agent_worker.py.txt'


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def worker_profile(raw):
    if type(raw) is not bytes:
        raise ValueError('worker source must be exact bytes')
    for version, expected in WORKERS.items():
        if pin(raw) == expected:
            return {'version': version, 'lost_ack_exit': 1 if version == 1 else 2,
                    'worker': dict(expected)}
    raise ValueError('undeclared complete Slot worker terminal source')


def inverse(raw, specification):
    if pin(raw) != specification['current']:
        raise ValueError('current Slot terminal caller differs')
    previous = -1
    delta = 0
    edits = []
    for row in specification['splices']:
        if (set(row) != {'offset', 'before', 'after'} or type(row['offset']) is not int
                or row['offset'] < 0 or type(row['before']) is not str
                or type(row['after']) is not str):
            raise ValueError('invalid typed terminal source splice')
        before, after = row['before'].encode(), row['after'].encode()
        offset = row['offset']
        if offset < previous or before == after:
            raise ValueError('overlapping/empty terminal source splice')
        at = offset + delta
        if raw[at:at + len(after)] != after:
            raise ValueError('current terminal source splice differs')
        edits.append((offset, at, before, after))
        previous = offset + len(before)
        delta += len(after) - len(before)
    old = raw
    for offset, at, before, after in reversed(edits):
        old = old[:at] + before + old[at + len(after):]
    if pin(old) != specification['original']:
        raise ValueError('complete original terminal source was not recovered')
    replay = old
    for offset, at, before, after in reversed(edits):
        if replay[offset:offset + len(before)] != before:
            raise ValueError('original terminal source splice differs')
        replay = replay[:offset] + after + replay[offset + len(before):]
    if replay != raw:
        raise ValueError('terminal successor source did not replay exactly')
    return old


class SourceAuthority:
    def __init__(self, root):
        self.root = Path(root)
        self.captured = {}
        authority_raw = self.read(AUTHORITY)
        if sha256(authority_raw).hexdigest() != AUTHORITY_SHA256:
            raise ValueError('fixed Slot terminal version authority changed')
        self.value = json.loads(authority_raw, object_pairs_hook=unique_pairs)
        if (self.value['schema'] != 'hepta.slot.worker-terminal-successor.v2'
                or self.value['legacy_lost_ack_exit'] != 1
                or self.value['current_lost_ack_exit'] != 2):
            raise ValueError('Slot terminal version contract differs')
        self.originals = {}
        for name, spec in self.value['source_successors'].items():
            if Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('unsafe terminal source path')
            self.originals[name] = inverse(self.read(name), spec)
        if pin(self.read(ORIGINAL_WORKER)) != WORKERS[1]:
            raise ValueError('complete original worker authority changed')
        self.profile = worker_profile(self.read('hepta/hia_agent_worker.py'))
        for name, expected in self.value['current_dependencies'].items():
            if name == DELIVERY_PATH and self.profile['version'] == 3:
                expected = DELIVERY_V3
            if pin(self.read(name)) != expected:
                raise ValueError('terminal observation dependency changed: ' + name)

    def read(self, name):
        raw = regular_bytes(self.root / name)
        if name in self.captured and self.captured[name] != raw:
            raise ValueError('already captured terminal source changed')
        self.captured[name] = raw
        return raw

    def finish(self):
        for name, raw in self.captured.items():
            if regular_bytes(self.root / name) != raw:
                raise ValueError('terminal source changed during observations: ' + name)

    def summary(self):
        return {'schema': self.value['schema'], 'authority': pin(self.captured[AUTHORITY]),
                'worker_profile': self.profile,
                'original_sources': {name: pin(raw) for name, raw in self.originals.items()},
                'current_sources': {name: pin(self.captured[name]) for name in self.originals},
                'legacy_pass_transferred': False, 'original_Native6_replaced': False}


class TerminalObservation:
    def __init__(self, worker, service, delivery, controller):
        self.profile = worker_profile(regular_bytes(worker.__file__))
        self.injected_id = self.primary_id = self.cleanup_id = self.close_error_id = None
        self.close_attempts = self.close_returns = self.primary_notes = self.cleanup_notes = 0
        self.terminal_calls = 0
        self.facts = None
        self.originals = (worker.note_request_failure, worker._unknown_request_exit,
                          service.HIAAgentService.close) if self.profile['lost_ack_exit'] == 2 else None
        if self.originals is None:
            return
        original_note, original_terminal, original_close = self.originals

        def note(error, *, cleanup=False):
            try:
                result = original_note(error, cleanup=cleanup)
                if cleanup:
                    self.cleanup_notes += 1
                    self.cleanup_id = id(error)
                else:
                    self.primary_notes += 1
                    self.primary_id = id(error)
                return result
            finally:
                del error

        def close(instance, *arguments, **keywords):
            self.close_attempts += 1
            try:
                result = original_close(instance, *arguments, **keywords)
            except BaseException as error:
                self.close_error_id = id(error)
                raise
            finally:
                del instance, arguments, keywords
            self.close_returns += 1
            return result

        def terminal(observation, terminal_error):
            self.terminal_calls += 1
            origin = observation.origin
            primary, cleanup = observation.primary_error, observation.cleanup_error
            owner = None if origin is None else origin.owner
            def identities():
                return (id(origin), id(observation.primary_error), id(observation.cleanup_error),
                    id(primary.__cause__), id(primary.__context__), id(primary.__traceback__),
                    id(cleanup.__cause__), id(cleanup.__context__), id(cleanup.__traceback__),
                    tuple(sorted(delivery._CUSTODY)), tuple(sorted(delivery._RESOURCE_OBSERVATIONS)))
            try:
                before = identities()
                facts = {
                    'request_observer_inactive': not observation.active,
                    'origin_present': origin is not None,
                    'origin_custodied': origin is not None and delivery._CUSTODY.get(id(origin)) is origin,
                    'origin_loss_is_self': origin is not None and origin.loss is origin,
                    'origin_error_is_actual_injected': origin is not None and id(origin.error) == self.injected_id,
                    'origin_native_pending': None if origin is None else origin.native_pending,
                    'origin_retired': None if origin is None else origin.retired,
                    'slot_frame_retained': (type(owner) is controller.SlotOperationsFrame
                        and owner._delivery is origin and owner.fenced and owner.native_failed),
                    'primary_is_actual_worker_call_failure': primary is not None and id(primary) == self.primary_id,
                    'primary_is_slot_unknown': type(primary) is controller.SlotOperationsUnknown,
                    'primary_cause_is_actual_origin_error': origin is not None and primary is not None
                        and primary.__cause__ is origin.error,
                    'cleanup_is_actual_close_failure': cleanup is not None
                        and id(cleanup) == self.close_error_id == self.cleanup_id,
                    'cleanup_is_delivery_unknown': type(cleanup) is delivery.NativeDeliveryUnknown,
                    'cleanup_context_is_primary': cleanup is not None and cleanup.__context__ is primary,
                    'terminal_is_cleanup': terminal_error is cleanup,
                }
                self.facts = facts
                result = original_terminal(observation, terminal_error)
                facts['diagnostics_preserved_error_and_custody_identities'] = identities() == before
                facts['returned_status'] = result
                return result
            finally:
                del observation, terminal_error, origin, primary, cleanup, owner

        worker.note_request_failure = note
        worker._unknown_request_exit = terminal
        service.HIAAgentService.close = close

    def injected(self, error):
        self.injected_id = id(error)

    def report(self):
        return {'schema': 'hepta.slot.installed-worker-terminal.v2', 'profile': self.profile,
                'injection_observed': self.injected_id is not None,
                'close_attempts': self.close_attempts, 'close_returns': self.close_returns,
                'primary_notes': self.primary_notes, 'cleanup_notes': self.cleanup_notes,
                'terminal_calls': self.terminal_calls, 'facts': self.facts}


def assert_terminal(test, value, stderr, label, profile):
    test.assertEqual(canonical(value['profile']), canonical(profile))
    test.assertEqual(value['schema'], 'hepta.slot.installed-worker-terminal.v2')
    lost = label == 'lost-SQL-ACK'
    test.assertIs(value['injection_observed'], lost)
    if profile['version'] == 1:
        test.assertEqual(value['terminal_calls'], 0)
        test.assertIsNone(value['facts'])
        test.assertNotIn(b'HIA_WORKER_DELIVERY_UNKNOWN', stderr)
        return
    test.assertEqual(set(value), {'schema', 'profile', 'injection_observed', 'close_attempts',
        'close_returns', 'primary_notes', 'cleanup_notes', 'terminal_calls', 'facts'})
    request = label in ('normal', 'replay', 'lost-SQL-ACK', 'unknown-replay')
    expected = {'close_attempts': int(request), 'close_returns': int(request and not lost),
                'primary_notes': int(lost), 'cleanup_notes': int(lost), 'terminal_calls': int(lost)}
    for name, number in expected.items():
        test.assertIs(type(value[name]), int)
        test.assertEqual(value[name], number)
    if not lost:
        test.assertIsNone(value['facts'])
        test.assertNotIn(b'HIA_WORKER_DELIVERY_UNKNOWN', stderr)
        return
    facts = value['facts']
    true_fields = (
        'request_observer_inactive', 'origin_present', 'origin_custodied', 'origin_loss_is_self',
        'origin_error_is_actual_injected', 'origin_native_pending', 'slot_frame_retained',
        'primary_is_actual_worker_call_failure', 'primary_is_slot_unknown',
        'primary_cause_is_actual_origin_error', 'cleanup_is_actual_close_failure',
        'cleanup_is_delivery_unknown', 'cleanup_context_is_primary', 'terminal_is_cleanup',
        'diagnostics_preserved_error_and_custody_identities')
    test.assertEqual(set(facts), {*true_fields, 'origin_retired', 'returned_status'})
    for name in true_fields:
        test.assertIs(facts[name], True, name)
    test.assertIs(facts['origin_retired'], False)
    test.assertIs(type(facts['returned_status']), int)
    test.assertEqual(facts['returned_status'], 2)
    lines = stderr.splitlines()
    for marker in (b'HIA_WORKER_DELIVERY_UNKNOWN', b'REQUEST_PRIMARY_EXCEPTION', b'REQUEST_CLEANUP_EXCEPTION'):
        test.assertEqual(lines.count(marker), 1)
    test.assertNotIn(b'REQUEST_TERMINAL_EXCEPTION', lines)
    test.assertNotIn(b'diagnostic unavailable', stderr)
    test.assertIn(b'ValueError: actual SQL execute returned; controller acknowledgement withheld', stderr)
    test.assertIn(b'SlotOperationsUnknown: Slot controller delivery failed', stderr)
    test.assertIn(b'NativeDeliveryUnknown: resource has unconfirmed native delivery; it cannot be retired', stderr)
