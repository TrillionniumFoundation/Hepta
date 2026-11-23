"""Independent data-only readback for the exact Slot worker terminal successor.

No producer admission or product module is imported. Raw source and terminal
tags are checked again, including reverse/forward source custody, typed fields,
diagnostic markers, process-specific actual object observations, and old scope.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

from tests.hia_slot_operations_qualification_support import canonical, unique_pairs

AUTHORITY = 'tests/fixtures/slot_worker_terminal_v2.json'
AUTHORITY_SHA256 = '1808488c0fe6c66bf9424eb64f9fe7bef4a2ce6028b1ab41b7d3cefc7b5df580'
WORKERS = {
    1: {'bytes': 8496, 'sha256': '4e6a64b551e34805106fa1d4b888a48f9a2a138d2f82d4091b4412bf65862066'},
    2: {'bytes': 11444, 'sha256': '6352879dc0e58515a6af9b2a586a5efa27f4018fb19d49a379ab72425eebf45a'},
    3: {'bytes': 16086, 'sha256': 'd5f9f7ab7057e19c38aa263ae2acfa3494fec950f6f85299110f7522224dd172'},
}
DELIVERY_V3 = {'bytes': 50071, 'sha256': '08687e1997e8d4c7cc5f9807398f6fd765767af3b49d3b3b4b449383ce0167aa'}
DELIVERY_PATH = 'hepta/hia_native_delivery.py'


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def equal(left, right):
    require(canonical(left) == canonical(right), 'terminal typed value differs')


def original_source(current, specification):
    equal(digest(current), specification['current'])
    parts = []
    cursor = 0
    previous_original = 0
    movement = 0
    for row in specification['splices']:
        require(set(row) == {'offset', 'before', 'after'}
                and type(row['offset']) is int and row['offset'] >= previous_original
                and type(row['before']) is str and type(row['after']) is str,
                'terminal source splice shape/order differs')
        before, after = row['before'].encode(), row['after'].encode()
        require(before != after, 'terminal source splice is not a change')
        at = row['offset'] + movement
        require(at >= cursor and current[at:at + len(after)] == after,
                'terminal source splice does not match current bytes')
        parts.extend((current[cursor:at], before))
        cursor = at + len(after)
        previous_original = row['offset'] + len(before)
        movement += len(after) - len(before)
    parts.append(current[cursor:])
    original = b''.join(parts)
    equal(digest(original), specification['original'])
    parts, cursor = [], 0
    for row in specification['splices']:
        offset, before, after = row['offset'], row['before'].encode(), row['after'].encode()
        require(original[offset:offset + len(before)] == before,
                'terminal source forward splice does not match original')
        parts.extend((original[cursor:offset], after))
        cursor = offset + len(before)
    require(b''.join((*parts, original[cursor:])) == current,
            'complete terminal successor source did not replay')
    return original


def admit_source_authority(captured, root):
    root = Path(root)
    raw = captured.raw(root / AUTHORITY)
    require(sha256(raw).hexdigest() == AUTHORITY_SHA256, 'fixed terminal authority digest differs')
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    require(value['schema'] == 'hepta.slot.worker-terminal-successor.v2'
            and type(value['legacy_lost_ack_exit']) is int and value['legacy_lost_ack_exit'] == 1
            and type(value['current_lost_ack_exit']) is int and value['current_lost_ack_exit'] == 2,
            'explicit terminal version contract differs')
    from tests.hia_installed_distribution_history import predecessor

    originals, current = {}, {}
    for name, specification in value['source_successors'].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts, 'unsafe terminal source path')
        data = captured.raw(root / name)
        originals[name] = digest(original_source(predecessor(name, data, original_source), specification))
        current[name] = digest(data)
    equal(digest(captured.raw(root / 'tests/fixtures/worker_unknown_original_r17b/hia_agent_worker.py.txt')),
          WORKERS[1])
    worker = digest(captured.raw(root / 'hepta/hia_agent_worker.py'))
    versions = [version for version, fixed in WORKERS.items() if worker == fixed]
    require(len(versions) == 1, 'undeclared complete worker terminal source')
    version, = versions
    profile = {'version': version, 'lost_ack_exit': 1 if version == 1 else 2, 'worker': worker}
    for name, expected in value['current_dependencies'].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts, 'unsafe terminal dependency path')
        if name == DELIVERY_PATH and version == 3:
            expected = DELIVERY_V3
        equal(digest(captured.raw(root / name)), expected)
    return {'schema': value['schema'], 'authority': digest(raw), 'worker_profile': profile,
            'original_sources': originals, 'current_sources': current,
            'legacy_pass_transferred': False, 'original_Native6_replaced': False}


def verify_terminal(value, stderr, label, profile):
    equal(value['profile'], profile)
    require(value['schema'] == 'hepta.slot.installed-worker-terminal.v2',
            'explicit terminal observation schema differs')
    lost = label == 'lost-SQL-ACK'
    require(value['injection_observed'] is lost, 'actual injection presence differs')
    if profile['version'] == 1:
        require(type(value['terminal_calls']) is int and value['terminal_calls'] == 0
                and value['facts'] is None and b'HIA_WORKER_DELIVERY_UNKNOWN' not in stderr,
                'old uncaught worker contract was relabeled as terminal v2')
        return
    require(set(value) == {'schema', 'profile', 'injection_observed', 'close_attempts',
            'close_returns', 'primary_notes', 'cleanup_notes', 'terminal_calls', 'facts'},
            'terminal observation has an undeclared/missing field')
    request = label in ('normal', 'replay', 'lost-SQL-ACK', 'unknown-replay')
    for name, expected in (
            ('close_attempts', int(request)), ('close_returns', int(request and not lost)),
            ('primary_notes', int(lost)), ('cleanup_notes', int(lost)),
            ('terminal_calls', int(lost))):
        require(type(value[name]) is int and value[name] == expected,
                'terminal close/note/exit boundary count differs: ' + name)
    if not lost:
        require(value['facts'] is None and b'HIA_WORKER_DELIVERY_UNKNOWN' not in stderr,
                'healthy/refused request invented native delivery loss')
        return
    facts = value['facts']
    expected_true = {
        'request_observer_inactive', 'origin_present', 'origin_custodied', 'origin_loss_is_self',
        'origin_error_is_actual_injected', 'origin_native_pending', 'slot_frame_retained',
        'primary_is_actual_worker_call_failure', 'primary_is_slot_unknown',
        'primary_cause_is_actual_origin_error', 'cleanup_is_actual_close_failure',
        'cleanup_is_delivery_unknown', 'cleanup_context_is_primary', 'terminal_is_cleanup',
        'diagnostics_preserved_error_and_custody_identities'}
    require(set(facts) == expected_true | {'origin_retired', 'returned_status'},
            'terminal actual-identity observation fields differ')
    require(all(facts[name] is True for name in expected_true)
            and facts['origin_retired'] is False
            and type(facts['returned_status']) is int and facts['returned_status'] == 2,
            'actual primary/cleanup/origin/diagnostic identity differs')
    lines = stderr.splitlines()
    require(all(lines.count(marker) == 1 for marker in (
            b'HIA_WORKER_DELIVERY_UNKNOWN', b'REQUEST_PRIMARY_EXCEPTION', b'REQUEST_CLEANUP_EXCEPTION')),
            'complete real primary and cleanup diagnostics absent/repeated')
    require(b'REQUEST_TERMINAL_EXCEPTION' not in lines and b'diagnostic unavailable' not in stderr,
            'unexpected terminal error or unavailable diagnostic')
    for message in (
            b'ValueError: actual SQL execute returned; controller acknowledgement withheld',
            b'SlotOperationsUnknown: Slot controller delivery failed',
            b'NativeDeliveryUnknown: resource has unconfirmed native delivery; it cannot be retired'):
        require(message in stderr, 'actual causal failure diagnostic absent')
