"""Exact reversible source relations for final proof, host primitives and retired NDU oracle.

These relations retain the frozen caller/source authorities. Reconstructed
predecessors are qualification data; they are never selected as production code.
"""
from hashlib import sha256
import json

FIXTURE = 'tests/fixtures/hia_final_source_successors.json'
FIXTURE_SHA256 = '04a437e57f862fa4453bd278cad0062eedc195330a62d754912f64b2911e94b1'
PATHS = ('hepta/hia_agent_service.py', 'hepta/hia_emission_native.py', 'hepta/hia_store_lifecycle_native.py', 'tests/test_hia_ndu_bridge.py')


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _reverse_record(raw, record):
    if pin(raw) != {'bytes': record['new_bytes'], 'sha256': record['new_sha256']}:
        raise ValueError('final source successor whole-file identity differs')
    restored = raw
    for hunk in reversed(record['hunks']):
        before, after = bytes.fromhex(hunk['old_hex']), bytes.fromhex(hunk['new_hex'])
        at = hunk['new_offset']
        if restored[at:at + len(after)] != after:
            raise ValueError('final source successor exact inverse changed')
        restored = restored[:at] + before + restored[at + len(after):]
    if pin(restored) != {'bytes': record['old_bytes'], 'sha256': record['old_sha256']}:
        raise ValueError('final source successor original whole file differs')
    replay = restored
    for hunk in reversed(record['hunks']):
        before, after = bytes.fromhex(hunk['old_hex']), bytes.fromhex(hunk['new_hex'])
        at = hunk['old_offset']
        if replay[at:at + len(before)] != before:
            raise ValueError('final source successor exact forward changed')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise ValueError('final source successor complete forward replay differs')
    return restored


def admit(capture, name, raw, original_sha256=None):
    """Bind the exact whole successor, its dependencies and both byte directions."""
    frozen = capture(FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('final source successor authority changed')
    value = json.loads(frozen)
    if (set(value) != {'schema', 'files'}
            or value['schema'] != 'hepta.hia.final-source-successors.v1'
            or set(value['files']) != set(PATHS) or name not in PATHS):
        raise ValueError('final source successor scope changed')
    item = value['files'][name]
    record = item['patch']
    old = {'bytes': record['old_bytes'], 'sha256': record['old_sha256']}
    new = {'bytes': record['new_bytes'], 'sha256': record['new_sha256']}
    if (pin(raw) != new or original_sha256 is not None
            and original_sha256 != old['sha256']):
        raise ValueError('final source successor whole-file identity differs: ' + name)
    for path, expected in item['dependencies'].items():
        if pin(capture(path)) != expected:
            raise ValueError('final source successor dependency changed: ' + path)
    restored = _reverse_record(raw, record)
    relation = {
        'path': name, 'original': old, 'current': new,
        'provenance_path': FIXTURE, 'provenance_sha256': FIXTURE_SHA256,
        'source_commit': item['source_commit'], 'scope': item['scope'],
        'dependencies': item['dependencies'],
        'exact_splices': len(record['hunks']),
        'complete_original_inverse_verified': True,
        'complete_current_forward_replay_verified': True,
        'production_source_exception': False,
    }
    return restored, relation


def admit_diagnostics(capture, name, raw, original_sha256, authority, diagnostic):
    """Extend the unchanged deadline proof through its fixed SQLite test boundary."""
    path = 'tests/fixtures/delivery_sqlite_boundary_source_v3.json'
    previous = 'tests/fixtures/delivery_diagnostic_source_successors_v1.json'
    pins = {
        path: {'bytes': 14093, 'sha256': '8f691aeeb1fce7c18068e467f6109c3b0ffbd10d26b4a6a732d8b5205477010f'},
        previous: {'bytes': 29000, 'sha256': '725f18e0ff6a8f598176bac85383f19234938a0efce73259779357bf6a853778'},
    }
    sources = {source: capture(source) for source in pins}
    if any(pin(sources[source]) != expected for source, expected in pins.items()):
        raise ValueError('complete caller diagnostic successor authority changed')
    value = json.loads(sources[path])
    if (name != diagnostic.PATH
            or value['schema'] != 'hepta.hia.delivery-sqlite-boundary-source.v3'):
        raise ValueError('complete caller diagnostic successor scope changed')
    entry = value['files'][name]
    record = entry['record']
    if (entry['predecessor_fixture'] != {'path': previous, **pins[previous]}
            or {'bytes': record['old_bytes'], 'sha256': record['old_sha256']} != diagnostic.CURRENT):
        raise ValueError('complete caller diagnostic predecessor changed')
    restored = _reverse_record(raw, record)
    relation = diagnostic.admit(name, restored, original_sha256, authority)
    return {**relation,
        'current': {'bytes': record['new_bytes'], 'sha256': record['new_sha256']},
        'preceding_current': dict(diagnostic.CURRENT),
        'diagnostic_successor_authorities': {source: dict(expected) for source, expected in pins.items()},
        'diagnostic_successor_exact_splices': len(record['hunks']),
        'complete_current_forward_replay_verified': True,
        'complete_original_inverse_verified': True,
    }

def admit_machine_caller(capture, name, raw, original_sha256):
    """Bind the complete retained machine-receipt caller through its fixed inverse."""
    path = 'tests/fixtures/delivery_machine_receipt_test_successor.json'
    authority = capture(path)
    expected = {'bytes': 5035, 'sha256': 'bcee96e24cec5bfe8e8b8a471fa9f9c72d4232396a1c9bd3686facb86a056acb'}
    if pin(authority) != expected:
        raise ValueError('complete machine caller source authority changed')
    value = json.loads(authority)
    if (name != 'tests/test_hia_agent_native_machine_validation.py'
            or set(value) != {'path', 'record', 'schema'}
            or value['schema'] != 'hepta.hia.delivered-machine-receipt-test-source.v1' or value['path'] != name):
        raise ValueError('complete machine caller source scope changed')
    record = value['record']
    if record['old_sha256'] != original_sha256:
        raise ValueError('complete machine caller original authority changed')
    _reverse_record(raw, record)
    return {
        'path': name,
        'original': {'bytes': record['old_bytes'], 'sha256': record['old_sha256']},
        'current': {'bytes': record['new_bytes'], 'sha256': record['new_sha256']},
        'provenance_path': path, 'provenance_sha256': expected['sha256'],
        'exact_splices': len(record['hunks']),
        'complete_original_inverse_verified': True,
        'complete_current_forward_replay_verified': True,
        'production_source_exception': False,
    }
