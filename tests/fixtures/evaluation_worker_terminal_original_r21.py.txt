"""Exact two-source provenance for the versioned worker transport observer.

This does not alter the thirteen production-source composition. Both original
inventories remain immutable; only the named observer and its D0--D3 admission
function have a separately reviewed, reversible successor.
"""
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/native_transport_worker_terminal_v2_provenance.json'
FIXTURE_SHA256 = '15f48d98210006523a800be1a743a7f6ce8e427838fc24d157d9bf317d680957'
TRANSPORT = 'tests/test_hia_native_transport_failures.py'
DELIVERY = 'tests/test_hia_native_delivery.py'
PATHS = (TRANSPORT, DELIVERY)
ORIGINALS = {
    'native': ('tests/fixtures/native_delivery_original_9c46166.json', {
        'bytes': 71708, 'sha256': 'a1f82e1c955ece21319cc49a0e3834658a2eeb0be7636d6f13690e1d6b83dea7'}),
    'store': ('tests/fixtures/store_native_delivery_original_c019.json', {
        'bytes': 173802, 'sha256': '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'}),
}
OLD = {
    TRANSPORT: {'bytes': 32859, 'sha256': '6c9505646078ebc03f4f44b35526d31b5534d9766ffbf408f69b9fc12ee7b484'},
    DELIVERY: {'bytes': 12700, 'sha256': 'cd56657339898843d78f705872be63625395f58479c11f9784e7e0e7ccccd541'},
}


def _pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def _hex(value):
    if type(value) is not str:
        raise ValueError('transport successor patch is not exact text')
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('transport successor patch is not hexadecimal') from error
    if raw.hex() != value:
        raise ValueError('transport successor patch is not canonical')
    return raw


def reverse_one(raw, record, original):
    if (type(raw) is not bytes or type(record) is not dict
            or set(record) != {'old', 'new', 'definition', 'offset', 'old_hex', 'new_hex'}
            or _canonical(record['old']) != _canonical(original)
            or type(record['new']) is not dict or set(record['new']) != {'bytes', 'sha256'}
            or type(record['new']['bytes']) is not int
            or type(record['new']['sha256']) is not str
            or _pin(raw) != record['new']
            or type(record['offset']) is not int or record['offset'] < 0):
        raise ValueError('transport successor whole-source identity differs')
    before, after = _hex(record['old_hex']), _hex(record['new_hex'])
    at = record['offset']
    if (before == after or not before or not after
            or at + len(after) > len(raw) or raw[at:at + len(after)] != after):
        raise ValueError('transport successor exact definition patch differs')
    restored = raw[:at] + before + raw[at + len(after):]
    if _pin(restored) != original:
        raise ValueError('transport successor does not restore the complete original')
    return restored


def admit_terminal_sources(original_value, *, original_kind):
    if type(original_kind) is not str or original_kind not in ORIGINALS:
        raise ValueError('transport successor original authority differs')
    authorities = {kind: (ROOT / item[0]).read_bytes()
                   for kind, item in ORIGINALS.items()}
    for kind, (_, expected) in ORIGINALS.items():
        if _pin(authorities[kind]) != expected:
            raise ValueError('transport successor original inventory changed')
    parsed = {kind: json.loads(raw) for kind, raw in authorities.items()}
    if _canonical(original_value) != _canonical(parsed[original_kind]):
        raise ValueError('transport successor caller did not supply the fixed original')
    if (any(_canonical(parsed[kind]['unchanged_files'][TRANSPORT]) != _canonical(OLD[TRANSPORT])
            for kind in ORIGINALS)
            or _canonical(parsed['store']['shared_dependency_review'][DELIVERY])
               != _canonical(OLD[DELIVERY])):
        raise ValueError('transport successor independent original source pins differ')
    captured = {name: (ROOT / name).read_bytes() for name in PATHS}
    unchanged = all(_pin(captured[name]) == OLD[name] for name in PATHS)
    frozen = None
    value = None
    if not unchanged:
        frozen = (ROOT / FIXTURE).read_bytes()
        if sha256(frozen).hexdigest() != FIXTURE_SHA256:
            raise ValueError('transport successor fixed provenance changed')
        value = json.loads(frozen)
        if (value.get('schema') != 'hepta.hia.native-transport-terminal-source.v2'
                or value.get('state') != 'FROZEN_EXACT_TWO_SOURCE_SUCCESSOR'
                or type(value.get('source_count')) is not int or value['source_count'] != 2
                or type(value.get('production_composition_source_count')) is not int
                or value['production_composition_source_count'] != 13
                or type(value.get('files')) is not dict or set(value['files']) != set(PATHS)
                or value['files'][TRANSPORT]['definition'] != '_child_store_worker'
                or value['files'][DELIVERY]['definition'] != 'admit_originals'):
            raise ValueError('transport successor changes its exact reviewed scope')
        for name in PATHS:
            reverse_one(captured[name], value['files'][name], OLD[name])
    # Never refresh a prior pin from a later read. This closes the exact raw
    # consumption and terminal reread for both files and both old authorities.
    if (any((ROOT / item[0]).read_bytes() != authorities[kind]
            for kind, item in ORIGINALS.items())
            or any((ROOT / name).read_bytes() != captured[name] for name in PATHS)
            or (frozen is not None and (ROOT / FIXTURE).read_bytes() != frozen)):
        raise ValueError('transport successor bytes changed during admission')
    if unchanged:
        return {'schema': 'hepta.hia.native-transport-terminal-admission.v2',
                'state': 'EXACT_LEGACY_PAIR', 'source_adjustments': {},
                'shared_dependency_review': {}, 'shared_adjustments': {},
                'production_composition_source_count': 13,
                'original_inventories_unchanged': True}
    adjustments = {name: {
        'path': name, 'original_bytes': OLD[name]['bytes'],
        'original_sha256': OLD[name]['sha256'],
        'current_bytes': value['files'][name]['new']['bytes'],
        'current_sha256': value['files'][name]['new']['sha256'],
        'reversible_patch_fixture_sha256': FIXTURE_SHA256,
        'scope': 'exact versioned worker UNKNOWN terminal observer and its original-source admission',
        'all_original_test_methods_unchanged': True,
    } for name in PATHS}
    shared = ({DELIVERY: dict(value['files'][DELIVERY]['new'])}
              if original_kind == 'store' else {})
    return {'schema': 'hepta.hia.native-transport-terminal-admission.v2',
            'state': 'EXACT_TERMINAL_V2_PAIR',
            'source_adjustments': {TRANSPORT: adjustments[TRANSPORT]},
            'shared_dependency_review': shared,
            'shared_adjustments': ({DELIVERY: adjustments[DELIVERY]} if shared else {}),
            'production_composition_source_count': 13,
            'separate_test_successor_count': 2,
            'c019_unchanged_originals_after_both_reviews': 84,
            'c019_unchanged_shared_after_both_reviews': 14,
            'original_inventories_unchanged': True}
