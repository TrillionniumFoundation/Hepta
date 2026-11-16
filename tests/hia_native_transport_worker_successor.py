"""Exact transport pair and optional reviewed evaluation-terminal provenance.

The existing two-source authority and all its prior combinations remain fixed.
A separate authority admits one evaluation test-method successor only beside
the complete reviewed pair. Neither original inventory nor the thirteen-source
production composition is altered.
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
EVALUATION = 'tests/test_hia_evaluation_native.py'
EVALUATION_DEFINITION = 'EvaluationNativeTests.test_actual_installed_worker_replay_process_loss_and_source_pinning'
EVALUATION_FIXTURE = 'tests/fixtures/evaluation_worker_terminal_v2_provenance.json'
EVALUATION_FIXTURE_SHA256 = '49aadebc293d7051b281db3e5a589f00d86098a13a313b9c7b50f76373a2b2c9'
EVALUATION_OLD = {'bytes': 43338, 'sha256': '22433d0de525210953c8ab23559b1cc7b3bd3575cfaa80fe2618415f03623ede'}
EVALUATION_NEW = {'bytes': 49105, 'sha256': '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3'}
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


def reverse_evaluation(raw, record):
    """Restore the full fixed original through seven exact, disjoint splices."""
    if (type(raw) is not bytes or type(record) is not dict
            or set(record) != {'old', 'new', 'definition', 'splices'}
            or _canonical(record['old']) != _canonical(EVALUATION_OLD)
            or _canonical(record['new']) != _canonical(EVALUATION_NEW)
            or record['definition'] != EVALUATION_DEFINITION
            or _pin(raw) != EVALUATION_NEW
            or type(record['splices']) is not list or len(record['splices']) != 7):
        raise ValueError('evaluation successor whole-source identity differs')
    entries = []
    old_end = new_end = displacement = 0
    for item in record['splices']:
        if (type(item) is not dict
                or set(item) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(item['old_offset']) is not int or item['old_offset'] < old_end
                or type(item['new_offset']) is not int or item['new_offset'] < new_end):
            raise ValueError('evaluation successor splice positions differ')
        at, target = item['old_offset'], item['new_offset']
        before, after = _hex(item['old_hex']), _hex(item['new_hex'])
        if (not before or not after or before == after
                or at + displacement != target
                or target + len(after) > len(raw)
                or raw[target:target + len(after)] != after):
            raise ValueError('evaluation successor exact splice differs')
        entries.append((at, target, before, after))
        old_end, new_end = at + len(before), target + len(after)
        displacement += len(after) - len(before)
    restored = raw
    for at, target, before, after in reversed(entries):
        restored = restored[:target] + before + restored[target + len(after):]
    if _pin(restored) != EVALUATION_OLD:
        raise ValueError('evaluation successor does not restore the complete original')
    replay = restored
    for at, target, before, after in reversed(entries):
        if replay[at:at + len(before)] != before:
            raise ValueError('evaluation successor original splice differs')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise ValueError('evaluation successor forward replay differs')
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
    evaluation_raw = (ROOT / EVALUATION).read_bytes()
    if any(_canonical(parsed[kind]['unchanged_files'][EVALUATION])
           != _canonical(EVALUATION_OLD) for kind in ORIGINALS):
        raise ValueError('evaluation successor independent original pins differ')
    evaluation_frozen = None
    evaluation_value = None
    if _pin(evaluation_raw) != EVALUATION_OLD:
        if unchanged:
            raise ValueError('evaluation successor requires the complete reviewed terminal pair')
        evaluation_frozen = (ROOT / EVALUATION_FIXTURE).read_bytes()
        if sha256(evaluation_frozen).hexdigest() != EVALUATION_FIXTURE_SHA256:
            raise ValueError('evaluation successor fixed provenance changed')
        evaluation_value = json.loads(evaluation_frozen)
        if (type(evaluation_value) is not dict
                or set(evaluation_value) != {'schema', 'state', 'test_source_count',
                    'production_composition_source_count', 'path', 'original_inventories',
                    'pair_fixture', 'required_pair', 'record'}
                or evaluation_value['schema'] != 'hepta.hia.evaluation-terminal-test-source.v2'
                or evaluation_value['state'] != 'FROZEN_EXACT_EVALUATION_TEST_SUCCESSOR'
                or type(evaluation_value['test_source_count']) is not int
                or evaluation_value['test_source_count'] != 3
                or type(evaluation_value['production_composition_source_count']) is not int
                or evaluation_value['production_composition_source_count'] != 13
                or evaluation_value['path'] != EVALUATION
                or _canonical(evaluation_value['original_inventories']) != _canonical({
                    kind: {'path': item[0], **item[1]} for kind, item in ORIGINALS.items()})
                or _canonical(evaluation_value['pair_fixture']) != _canonical({
                    'path': FIXTURE, 'bytes': len(frozen), 'sha256': FIXTURE_SHA256})
                or _canonical(evaluation_value['required_pair']) != _canonical({
                    name: value['files'][name]['new'] for name in PATHS})):
            raise ValueError('evaluation successor changes its exact reviewed scope')
        reverse_evaluation(evaluation_raw, evaluation_value['record'])
    # Never refresh a prior pin from a later read. This closes the exact raw
    # consumption and terminal reread for every source and both old authorities.
    if (any((ROOT / item[0]).read_bytes() != authorities[kind]
            for kind, item in ORIGINALS.items())
            or any((ROOT / name).read_bytes() != captured[name] for name in PATHS)
            or (frozen is not None and (ROOT / FIXTURE).read_bytes() != frozen)
            or (ROOT / EVALUATION).read_bytes() != evaluation_raw
            or (evaluation_frozen is not None
                and (ROOT / EVALUATION_FIXTURE).read_bytes() != evaluation_frozen)):
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
    result = {'schema': 'hepta.hia.native-transport-terminal-admission.v2',
            'state': 'EXACT_TERMINAL_V2_PAIR',
            'source_adjustments': {TRANSPORT: adjustments[TRANSPORT]},
            'shared_dependency_review': shared,
            'shared_adjustments': ({DELIVERY: adjustments[DELIVERY]} if shared else {}),
            'production_composition_source_count': 13,
            'separate_test_successor_count': 2,
            'c019_unchanged_originals_after_both_reviews': 84,
            'c019_unchanged_shared_after_both_reviews': 14,
            'original_inventories_unchanged': True}
    if evaluation_value is not None:
        result['state'] = 'EXACT_TERMINAL_V2_PAIR_WITH_EVALUATION_V2'
        result['source_adjustments'][EVALUATION] = {
            'path': EVALUATION,
            'original_bytes': EVALUATION_OLD['bytes'],
            'original_sha256': EVALUATION_OLD['sha256'],
            'current_bytes': EVALUATION_NEW['bytes'],
            'current_sha256': EVALUATION_NEW['sha256'],
            'reversible_patch_fixture_sha256': EVALUATION_FIXTURE_SHA256,
            'scope': 'one exact versioned installed evaluation UNKNOWN terminal observation',
            'definition': EVALUATION_DEFINITION,
            'all_original_test_method_ids_and_scopes_preserved': True,
            'all_other_nine_test_methods_unchanged': True,
            'original_method_count': 10,
        }
        result['separate_test_successor_count'] = 3
        result['c019_unchanged_originals_after_both_reviews'] = 83
    return result
