"""Exact preparation-v2 authority; never execute the historical oracle or product.

The immutable v1 freeze keeps its literal oracle pin and observation hashes.
This separate authority admits only two reviewed preparation splices, restores
the complete archived v1 bytes, and replays the complete current bytes. It does
not declare the old 14-vs-0 observation successful or normalize any observation.
"""
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = 'hepta.hia.service-artifact-fixed-code-preparation.v2'
AUTHORITY = 'tests/fixtures/hia_service_artifact_preparation_v2.json'
AUTHORITY_PIN = {'bytes': 5438,
    'sha256': '326a53f928591fc9a8ca6d111765d36ca7bca49409548740d6cde5c668cdb51a'}
ORACLE = 'tests/hia_service_artifact_oracle.py'
HELPER = 'tests/hia_service_artifact_preparation.py'
ARCHIVE = 'tests/fixtures/hia_service_artifact_original_5bf/oracle-preparation-v1.py.txt'
FREEZE = 'tests/fixtures/hia_service_artifact_original_5bf/freeze.json'
LEGACY_PIN = {'bytes': 16362,
    'sha256': '421041c54f1695c35ac8cb7245ca59aca5ed0de32ea5d1016542bd912b7ac629'}
CURRENT_PIN = {'bytes': 16920,
    'sha256': '8e3a9479342c2e1d9b02e75d6e43fd4dda2aad9aa9a122f06983a2fe9ad71061'}
FREEZE_PIN = {'bytes': 6728,
    'sha256': 'f3c7fe6bfc0bb7befdb5d5c394eddee67d42ac16abbfb9e752021a2cc562ee9b'}
SPLICE_IDS = ('declare-preparation-version', 'extract-fixed-code-without-executing-class')
ORIGINAL_PATHS = tuple('tests/fixtures/hia_service_artifact_original_5bf/' + name
                      for name in ('artifact.5bf.py.txt', 'profile.5bf.py.txt',
                                   'cases.json', 'source-identity.json'))
SOURCE_PATHS = (AUTHORITY, ORACLE, HELPER, ARCHIVE, FREEZE, *ORIGINAL_PATHS)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def _hex(value):
    if type(value) is not str:
        raise ValueError('artifact preparation splice is not text')
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('artifact preparation splice is not hexadecimal') from error
    if raw.hex() != value:
        raise ValueError('artifact preparation splice is not canonical')
    return raw


def transform_oracle(raw, record, *, reverse):
    """Apply exactly the two fixed, typed, ordered whole-source splices."""
    if (type(raw) is not bytes or type(reverse) is not bool or type(record) is not dict
            or set(record) != {'old', 'new', 'splices'}
            or canonical(record['old']) != canonical(LEGACY_PIN)
            or canonical(record['new']) != canonical(CURRENT_PIN)
            or pin(raw) != (CURRENT_PIN if reverse else LEGACY_PIN)
            or type(record['splices']) is not list or len(record['splices']) != 2):
        raise ValueError('artifact preparation whole-source identity differs')
    entries, displacement, old_end, new_end = [], 0, 0, 0
    for identity, item in zip(SPLICE_IDS, record['splices']):
        if (type(item) is not dict
                or set(item) != {'id', 'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or item['id'] != identity or type(item['old_offset']) is not int
                or type(item['new_offset']) is not int
                or item['old_offset'] < old_end or item['new_offset'] < new_end):
            raise ValueError('artifact preparation exact splice inventory differs')
        before, after = _hex(item['old_hex']), _hex(item['new_hex'])
        at, target = item['old_offset'], item['new_offset']
        selected_at, selected = (target, after) if reverse else (at, before)
        if (not before or not after or before == after or at + displacement != target
                or selected_at + len(selected) > len(raw)
                or raw[selected_at:selected_at + len(selected)] != selected):
            raise ValueError('artifact preparation exact splice bytes differ')
        entries.append((at, target, before, after))
        old_end, new_end = at + len(before), target + len(after)
        displacement += len(after) - len(before)
    result = raw
    for at, target, before, after in reversed(entries):
        selected_at, selected, replacement = ((target, after, before) if reverse
                                               else (at, before, after))
        result = result[:selected_at] + replacement + result[selected_at + len(selected):]
    if pin(result) != (LEGACY_PIN if reverse else CURRENT_PIN):
        raise ValueError('artifact preparation transform did not restore the complete source')
    return result


def admit_preparation(root=ROOT):
    """Capture and reread every exact input; return only a versioned source proof."""
    root = Path(root)
    captured = {name: (root / name).read_bytes() for name in SOURCE_PATHS}
    if pin(captured[AUTHORITY]) != AUTHORITY_PIN:
        raise ValueError('artifact preparation fixed authority changed')
    authority = json.loads(captured[AUTHORITY])
    if (authority['schema'] != 'hepta.hia.service-artifact-preparation-authority.v2'
            or authority['preparation_identity'] != IDENTITY
            or authority['oracle_path'] != ORACLE
            or canonical(authority['legacy_oracle']) != canonical({'path': ARCHIVE, **LEGACY_PIN})
            or canonical(authority['original_freeze']) != canonical({'path': FREEZE, **FREEZE_PIN})
            or pin(captured[ARCHIVE]) != LEGACY_PIN or pin(captured[FREEZE]) != FREEZE_PIN
            or set(authority['unchanged_original_inputs']) != set(ORIGINAL_PATHS)):
        raise ValueError('artifact preparation independent original authority differs')
    current, record = captured[ORACLE], authority['oracle_relation']
    restored = transform_oracle(current, record, reverse=True)
    if (restored != captured[ARCHIVE]
            or transform_oracle(restored, record, reverse=False) != current):
        raise ValueError('artifact preparation complete inverse or forward replay differs')
    freeze = json.loads(captured[FREEZE])
    if (type(freeze['case_count']) is not int or freeze['case_count'] != 146
            or len(freeze['ordered_ids']) != 146 or len(set(freeze['ordered_ids'])) != 146
            or sha256(canonical(freeze['ordered_ids'])).hexdigest() != authority['ordered_ids_sha256']
            or set(freeze['inputs']) != {*ORIGINAL_PATHS, ORACLE}
            or canonical(freeze['inputs'][ORACLE]) != canonical(LEGACY_PIN)):
        raise ValueError('artifact preparation original complete 146 inventory differs')
    for name in ORIGINAL_PATHS:
        expected = authority['unchanged_original_inputs'][name]
        if (canonical(freeze['inputs'][name]) != canonical(expected)
                or pin(captured[name]) != expected):
            raise ValueError('artifact preparation changed an original business input: ' + name)
    legacy_known = {'3.12.14': freeze['expected_by_runtime']['py312'],
                    '3.13.5': freeze['expected_by_runtime']['py313']}
    if (canonical(legacy_known) != canonical(authority['legacy_known_originals'])
            or authority['current_known_originals'] != {}
            or authority['legacy_observation']['status'] != 'HOLD'
            or authority['legacy_observation']['old_failure_relabelled'] is not False):
        raise ValueError('artifact preparation borrowed another observation version')
    actual_inputs = dict(authority['unchanged_original_inputs'])
    actual_inputs[ORACLE] = dict(CURRENT_PIN)
    for name, raw in captured.items():
        if (root / name).read_bytes() != raw:
            raise ValueError('artifact preparation input changed at terminal reread: ' + name)
    return {'schema': 'hepta.hia.service-artifact-preparation-admission.v2',
        'preparation_identity': IDENTITY, 'authority': {'path': AUTHORITY, **AUTHORITY_PIN},
        'legacy_oracle': {'path': ARCHIVE, **LEGACY_PIN}, 'current_oracle': dict(CURRENT_PIN),
        'original_freeze': {'path': FREEZE, **FREEZE_PIN},
        'admitted_original_inputs': actual_inputs, 'original_case_count': 146,
        'legacy_known_originals': legacy_known, 'current_known_originals': {},
        'legacy_observation_status': 'HOLD', 'legacy_failure_relabelled': False,
        'complete_original_inverse_verified': True, 'complete_current_forward_replay_verified': True,
        'exact_preparation_splice_count': 2, 'business_or_observation_splices': 0,
        'captured_files': {name: pin(raw) for name, raw in captured.items()},
        'terminal_reread_identical': True,
        'current_observation_requires_two_original_replays': True,
        'observation_success_established_by_source_admission': False}
