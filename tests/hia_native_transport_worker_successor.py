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
SQLITE_BOUNDARY_FIXTURE = 'tests/fixtures/delivery_sqlite_boundary_source_v3.json'
SQLITE_BOUNDARY_FIXTURE_PIN = {
    'bytes': 14093, 'sha256': '8f691aeeb1fce7c18068e467f6109c3b0ffbd10d26b4a6a732d8b5205477010f',
}
SQLITE_BOUNDARY_SOURCES = {
    TRANSPORT: {'bytes': 39786, 'sha256': '3b0510f0285f29d2dab2db4e27ea320484a4bc2f71d0c5debeeb9b9dfd329715'},
    'tests/test_hia_agent_native_tools.py': {
        'bytes': 47052, 'sha256': '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70',
    },
}
DELIVERY = 'tests/test_hia_native_delivery.py'
PATHS = (TRANSPORT, DELIVERY)
EVALUATION = 'tests/test_hia_evaluation_native.py'
EVALUATION_DEFINITION = 'EvaluationNativeTests.test_actual_installed_worker_replay_process_loss_and_source_pinning'
EVALUATION_FIXTURE = 'tests/fixtures/evaluation_worker_terminal_v2_provenance.json'
EVALUATION_FIXTURE_SHA256 = '49aadebc293d7051b281db3e5a589f00d86098a13a313b9c7b50f76373a2b2c9'
EVALUATION_OLD = {'bytes': 43338, 'sha256': '22433d0de525210953c8ab23559b1cc7b3bd3575cfaa80fe2618415f03623ede'}
EVALUATION_NEW = {'bytes': 49105, 'sha256': '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3'}
EVALUATION_STORE_FIXTURE = 'tests/fixtures/evaluation_typed_store_successor.json'
EVALUATION_STORE_FIXTURE_SHA256 = '4cc1286abb293e5d4536a42ec424282b9bfbe500daeefaa6a29496c8e8774bb4'
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


def _reverse_sqlite_boundary(path, raw, fixed, predecessor, previous_fixture, previous_pin):
    """Restore a fixed test-only predecessor before replaying its own inverse."""
    from tests.hia_store_delivery_successor import reverse_exact

    if _pin(fixed) != SQLITE_BOUNDARY_FIXTURE_PIN:
        raise ValueError('transport SQLite boundary provenance changed')
    value = json.loads(fixed)
    if (type(value) is not dict or set(value) != {'schema', 'files'}
            or value['schema'] != 'hepta.hia.delivery-sqlite-boundary-source.v3'
            or type(value['files']) is not dict or set(value['files']) != set(SQLITE_BOUNDARY_SOURCES)
            or _pin(raw) != SQLITE_BOUNDARY_SOURCES.get(path)):
        raise ValueError('transport SQLite boundary scope differs')
    record = value['files'][path]
    if (type(record) is not dict or set(record) != {'predecessor_fixture', 'record'}
            or record['predecessor_fixture'] != {'path': predecessor, **_pin(previous_fixture)}):
        raise ValueError('transport SQLite boundary predecessor differs')
    return reverse_exact(raw, record['record'], previous_pin)


def restore_evaluation_store(raw, fixture):
    from tests.hia_store_delivery_successor import reverse_exact

    if sha256(fixture).hexdigest() != EVALUATION_STORE_FIXTURE_SHA256:
        raise ValueError('evaluation typed Store test provenance changed')
    return reverse_exact(raw, json.loads(fixture), EVALUATION_NEW)


def _admit_terminal_sources_before_qualifiers(original_value, *, original_kind):
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
    boundary = None
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
            current = captured[name]
            if name == TRANSPORT and _pin(current) == SQLITE_BOUNDARY_SOURCES[TRANSPORT]:
                boundary = (ROOT / SQLITE_BOUNDARY_FIXTURE).read_bytes()
                current = _reverse_sqlite_boundary(
                    name, current, boundary, FIXTURE, frozen, value['files'][name]['new'])
            reverse_one(current, value['files'][name], OLD[name])
    evaluation_raw = (ROOT / EVALUATION).read_bytes()
    if any(_canonical(parsed[kind]['unchanged_files'][EVALUATION])
           != _canonical(EVALUATION_OLD) for kind in ORIGINALS):
        raise ValueError('evaluation successor independent original pins differ')
    evaluation_frozen = None
    evaluation_store_frozen = None
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
        reviewed = evaluation_raw
        if _pin(reviewed) != EVALUATION_NEW:
            evaluation_store_frozen = (ROOT / EVALUATION_STORE_FIXTURE).read_bytes()
            reviewed = restore_evaluation_store(reviewed, evaluation_store_frozen)
        reverse_evaluation(reviewed, evaluation_value['record'])
    # Never refresh a prior pin from a later read. This closes the exact raw
    # consumption and terminal reread for every source and both old authorities.
    if (any((ROOT / item[0]).read_bytes() != authorities[kind]
            for kind, item in ORIGINALS.items())
            or any((ROOT / name).read_bytes() != captured[name] for name in PATHS)
            or (frozen is not None and (ROOT / FIXTURE).read_bytes() != frozen)
            or (boundary is not None and (ROOT / SQLITE_BOUNDARY_FIXTURE).read_bytes() != boundary)
            or (ROOT / EVALUATION).read_bytes() != evaluation_raw
            or (evaluation_store_frozen is not None
                and (ROOT / EVALUATION_STORE_FIXTURE).read_bytes() != evaluation_store_frozen)
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
    if boundary is not None:
        adjustments[TRANSPORT].update({
            'current_bytes': len(captured[TRANSPORT]),
            'current_sha256': sha256(captured[TRANSPORT]).hexdigest(),
            'all_original_test_methods_unchanged': False,
            'all_original_test_method_ids_preserved': True,
            'scope': 'exact transport tests for locally imported SQLite and retained failure classes',
            'sqlite_boundary_successor': {
                'authority': {'path': SQLITE_BOUNDARY_FIXTURE, **SQLITE_BOUNDARY_FIXTURE_PIN},
                'restores_v2_exactly': True,
                'v2_source': dict(value['files'][TRANSPORT]['new']),
            },
        })
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
        if evaluation_store_frozen is not None:
            result['source_adjustments'][EVALUATION].update({
                'current_bytes': len(evaluation_raw),
                'current_sha256': sha256(evaluation_raw).hexdigest(),
                'all_other_nine_test_methods_unchanged': False,
                'typed_store_test_successor': {
                    'path': EVALUATION_STORE_FIXTURE,
                    'sha256': EVALUATION_STORE_FIXTURE_SHA256,
                    'restores_v2_exactly': True,
                },
            })
        result['separate_test_successor_count'] = 3
        result['c019_unchanged_originals_after_both_reviews'] = 83
    return result


# Independent, optional authority for the three already-reviewed qualifier
# sources. Its absence grants no additional exception to either Delivery loop.
QUALIFIER_FIXTURE = 'tests/fixtures/caller_qualifier_successor_provenance_v1.json'
QUALIFIER_FIXTURE_PIN = {"bytes":29822,"sha256":"36ad92a954cb3244bc31a6e95f1bcd8cbaf7b215856e6624b54fee3e66f686f4"}
QUALIFIER_RECORDS = {
    "tools/qualify_hia_native_build_admission_callers.py": {
        "old": {
            "bytes": 10433,
            "sha256": "82deea94556ab9d69df834d7145d16223def55ecdb030e47f123c70672986abd"
        },
        "new": {
            "bytes": 11099,
            "sha256": "e0c09818985203b1308b2ea53277b834ae429181d1bec54a684bd00cbb47a611"
        }
    },
    "tools/qualify_hia_emission_callers.py": {
        "old": {
            "bytes": 10228,
            "sha256": "439a0d98b4e95e44d3247bdd82826ffb0e86aacb4cb20781d335719565c49765"
        },
        "new": {
            "bytes": 10894,
            "sha256": "47aa06e0ecbc5227b09e0f3429087173637e9d429af6acc7014fa203178a806c"
        }
    },
    "tools/qualify_hia_store_artifact_profile_callers.py": {
        "old": {
            "bytes": 14130,
            "sha256": "120d913930d149007e28e176184cdd34bfe5d6895e82b4b8738caa9aa7ad5085"
        },
        "new": {
            "bytes": 14932,
            "sha256": "4e47769f3c67a43170773aa39eb4b461af8fcc32eb513708a0cbf932b6b406ec"
        }
    }
}
QUALIFIER_DEPENDENCIES = {
    "tests/hia_caller_terminal_admission.py": {
        "bytes": 16257,
        "sha256": "2df7427686426a64edcd15f2d7c9e18c5471ecf924b0a54293abe1c03658d0fd"
    },
    "tests/fixtures/hia_native_build_admission_callers_aac7550.json": {
        "bytes": 124039,
        "sha256": "262c3df1e051fe52797c91dd053f2d79c0704fe5b20a85f799d6d40c1c4bb2a9"
    },
    "tests/fixtures/hia_emission_original_73f1634/original-freeze.json": {
        "bytes": 59973,
        "sha256": "dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048"
    },
    "tests/fixtures/hia_store_artifact_profile_callers_73f1634.json": {
        "bytes": 166078,
        "sha256": "acbb8c221d80788ef96eb4b596c24fc1c3eb410229e605b2f01ef77e5530b7d6"
    }
}
QUALIFIER_SCOPE = 'one original-source admission definition and two explicit main-report wiring splices; no input/method/budget/order changes'
QUALIFIER_SPLICE_IDS = ('exact-admit-original-sources', 'capture-explicit-source-proof',
                       'preserve-distinct-source-proof')
QUALIFIER_PATHS = tuple(QUALIFIER_RECORDS)
QUALIFIER_ALLOWED = {
    "native": [
        "tools/qualify_hia_native_build_admission_callers.py",
        "tools/qualify_hia_emission_callers.py"
    ],
    "store": [
        "tools/qualify_hia_native_build_admission_callers.py",
        "tools/qualify_hia_emission_callers.py",
        "tools/qualify_hia_store_artifact_profile_callers.py"
    ]
}
QUALIFIER_PRIOR_STATES = {
    "EXACT_LEGACY_PAIR": 0,
    "EXACT_TERMINAL_V2_PAIR": 3,
    "EXACT_TERMINAL_V2_PAIR_WITH_EVALUATION_V2": 7
}


def _qualifier_transform(raw, record, path, *, reverse):
    if (type(path) is not str or path not in QUALIFIER_RECORDS
            or type(raw) is not bytes or type(reverse) is not bool
            or type(record) is not dict or set(record) != {'old', 'new', 'scope', 'splices'}
            or record['scope'] != QUALIFIER_SCOPE
            or _canonical(record['old']) != _canonical(QUALIFIER_RECORDS[path]['old'])
            or _canonical(record['new']) != _canonical(QUALIFIER_RECORDS[path]['new'])
            or type(record['splices']) is not list or len(record['splices']) != 3
            or _pin(raw) != record['new' if reverse else 'old']):
        raise ValueError('qualifier exact whole-source authority differs')
    entries = []
    old_end = new_end = displacement = 0
    for expected_id, item in zip(QUALIFIER_SPLICE_IDS, record['splices']):
        if (type(item) is not dict
                or set(item) != {'id', 'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or item['id'] != expected_id
                or type(item['old_offset']) is not int or item['old_offset'] < old_end
                or type(item['new_offset']) is not int or item['new_offset'] < new_end):
            raise ValueError('qualifier exact splice inventory differs')
        at, target = item['old_offset'], item['new_offset']
        before, after = _hex(item['old_hex']), _hex(item['new_hex'])
        selected_at, selected = (target, after) if reverse else (at, before)
        if (not before or not after or before == after or at + displacement != target
                or selected_at + len(selected) > len(raw)
                or raw[selected_at:selected_at + len(selected)] != selected):
            raise ValueError('qualifier exact splice bytes differ')
        entries.append((at, target, before, after))
        old_end, new_end = at + len(before), target + len(after)
        displacement += len(after) - len(before)
    result = raw
    for at, target, before, after in reversed(entries):
        selected_at, selected, replacement = ((target, after, before) if reverse
                                               else (at, before, after))
        result = result[:selected_at] + replacement + result[selected_at + len(selected):]
    if _pin(result) != record['old' if reverse else 'new']:
        raise ValueError('qualifier transform does not restore the complete fixed source')
    return result


def reverse_qualifier(raw, record, path):
    restored = _qualifier_transform(raw, record, path, reverse=True)
    if _qualifier_transform(restored, record, path, reverse=False) != raw:
        raise ValueError('qualifier complete forward replay differs')
    return restored


# The qualifier's original authority remains byte-for-byte immutable. This
# separate dependency authority only proves the exact diagnostic admission
# helper successor and captures the two source authorities it now imports.
QUALIFIER_DEPENDENCY_PATH = "tests/hia_caller_terminal_admission.py"
QUALIFIER_DEPENDENCY_CURRENT = {"bytes":17372,"sha256":"66bc956f8a599195f57e25cceae4875bcc1c04b3ec866f6d386eae3fb9fc100f"}
QUALIFIER_DEPENDENCY_FIXTURE = "tests/fixtures/caller_terminal_diagnostics_dependency_v1.json"
QUALIFIER_DEPENDENCY_FIXTURE_PIN = {"bytes":5656,"sha256":"98d2c3871079849eab5733234b848ba5fa0bff480cc29e2e20ca9d974c392c8a"}
QUALIFIER_DEPENDENCY_SCOPE = "exact deadline-diagnostic admission dependency; original qualifier authority, caller inventories, ordered methods and budgets unchanged"
QUALIFIER_DEPENDENCY_SPLICE_IDS = ["capture-diagnostic-state","admit-diagnostics-after-terminal","exact-diagnostic-source-admission","consume-exact-diagnostic-source","require-complete-diagnostic-consumption","preserve-distinct-diagnostic-proof"]
QUALIFIER_DIAGNOSTIC_DEPENDENCIES = {
    "tests/hia_caller_diagnostics_admission.py": {
        "bytes": 5185,
        "sha256": "9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578"
    },
    "tests/fixtures/caller_deadline_diagnostics_v1.json": {
        "bytes": 3545,
        "sha256": "53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c"
    }
}


def _qualifier_dependency_transform(raw, record, *, reverse):
    original = QUALIFIER_DEPENDENCIES[QUALIFIER_DEPENDENCY_PATH]
    if (type(raw) is not bytes or type(reverse) is not bool
            or type(record) is not dict or set(record) != {'old', 'new', 'scope', 'splices'}
            or _canonical(record['old']) != _canonical(original)
            or _canonical(record['new']) != _canonical(QUALIFIER_DEPENDENCY_CURRENT)
            or record['scope'] != QUALIFIER_DEPENDENCY_SCOPE
            or type(record['splices']) is not list or len(record['splices']) != 6
            or _pin(raw) != (QUALIFIER_DEPENDENCY_CURRENT if reverse else original)):
        raise ValueError('qualifier dependency complete source authority differs')
    entries = []
    old_end = new_end = displacement = 0
    for expected_id, item in zip(QUALIFIER_DEPENDENCY_SPLICE_IDS, record['splices']):
        if (type(item) is not dict
                or set(item) != {'id', 'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or item['id'] != expected_id
                or type(item['old_offset']) is not int or item['old_offset'] < old_end
                or type(item['new_offset']) is not int or item['new_offset'] < new_end):
            raise ValueError('qualifier dependency exact splice inventory differs')
        at, target = item['old_offset'], item['new_offset']
        before, after = _hex(item['old_hex']), _hex(item['new_hex'])
        selected_at, selected = (target, after) if reverse else (at, before)
        if (not before or not after or before == after or at + displacement != target
                or selected_at + len(selected) > len(raw)
                or raw[selected_at:selected_at + len(selected)] != selected):
            raise ValueError('qualifier dependency exact splice bytes differ')
        entries.append((at, target, before, after))
        old_end, new_end = at + len(before), target + len(after)
        displacement += len(after) - len(before)
    result = raw
    for at, target, before, after in reversed(entries):
        selected_at, selected, replacement = ((target, after, before) if reverse
                                               else (at, before, after))
        result = result[:selected_at] + replacement + result[selected_at + len(selected):]
    if _pin(result) != (original if reverse else QUALIFIER_DEPENDENCY_CURRENT):
        raise ValueError('qualifier dependency transform does not restore the complete fixed source')
    return result


def reverse_qualifier_dependency(raw, record):
    restored = _qualifier_dependency_transform(raw, record, reverse=True)
    if _qualifier_dependency_transform(restored, record, reverse=False) != raw:
        raise ValueError('qualifier dependency complete forward replay differs')
    return restored


def _admit_qualifier_dependency(raw, capture):
    if _pin(raw) != QUALIFIER_DEPENDENCY_CURRENT:
        raise ValueError('qualifier runtime dependency is neither fixed original nor exact successor')
    frozen = capture(QUALIFIER_DEPENDENCY_FIXTURE)
    if _pin(frozen) != QUALIFIER_DEPENDENCY_FIXTURE_PIN:
        raise ValueError('qualifier dependency fixed provenance changed')
    value = json.loads(frozen)
    if (type(value) is not dict
            or set(value) != {'schema', 'state', 'path', 'qualifier_authority', 'record',
                             'dependencies', 'original_qualifier_authority_unchanged',
                             'production_source_exception'}
            or value['schema'] != 'hepta.hia.caller-terminal-diagnostics-dependency.v1'
            or value['state'] != 'FROZEN_EXACT_CALLER_TERMINAL_DEPENDENCY_SUCCESSOR'
            or value['path'] != QUALIFIER_DEPENDENCY_PATH
            or _canonical(value['qualifier_authority'])
                != _canonical({'path': QUALIFIER_FIXTURE, **QUALIFIER_FIXTURE_PIN})
            or _canonical(value['dependencies']) != _canonical(QUALIFIER_DIAGNOSTIC_DEPENDENCIES)
            or value['original_qualifier_authority_unchanged'] is not True
            or value['production_source_exception'] is not False):
        raise ValueError('qualifier dependency fixed provenance scope differs')
    restored = reverse_qualifier_dependency(raw, value['record'])
    for path, expected in QUALIFIER_DIAGNOSTIC_DEPENDENCIES.items():
        if _pin(capture(path)) != expected:
            raise ValueError('qualifier diagnostic dependency changed: ' + path)
    return {'path': QUALIFIER_DEPENDENCY_PATH, 'original': _pin(restored),
            'current': _pin(raw),
            'authority': {'path': QUALIFIER_DEPENDENCY_FIXTURE, **QUALIFIER_DEPENDENCY_FIXTURE_PIN},
            'captured_dependencies': dict(QUALIFIER_DIAGNOSTIC_DEPENDENCIES),
            'exact_splice_count': 6, 'complete_original_inverse_verified': True,
            'complete_current_forward_replay_verified': True,
            'original_qualifier_authority_unchanged': True, 'production_source_exception': False}


def _admit_qualifier_sources(original_value, original_kind, prior, frozen):
    if _pin(frozen) != QUALIFIER_FIXTURE_PIN:
        raise ValueError('qualifier fixed provenance changed')
    value = json.loads(frozen)
    if (type(value) is not dict
            or value['schema'] != 'hepta.hia.delivery-caller-qualifier-successor.v1'
            or value['state'] != 'FROZEN_EXACT_THREE_QUALIFIER_SOURCE_SUCCESSOR'
            or type(value['source_count']) is not int or value['source_count'] != 3
            or type(value['production_composition_source_count']) is not int
            or value['production_composition_source_count'] != 13
            or value['source_kind'] != 'TEST_QUALIFICATION_TOOLS_ONLY'
            or set(value['files']) != set(QUALIFIER_PATHS)
            or _canonical(value['allowed_adjustments']) != _canonical(QUALIFIER_ALLOWED)
            or _canonical(value['underlying_caller_runtime_and_authorities'])
                != _canonical(QUALIFIER_DEPENDENCIES)
            or _canonical(value['prior_terminal_states']) != _canonical(QUALIFIER_PRIOR_STATES)
            or prior['state'] not in QUALIFIER_PRIOR_STATES
            or prior['production_composition_source_count'] != 13):
        raise ValueError('qualifier fixed provenance scope differs')
    captured = {QUALIFIER_FIXTURE: frozen}
    def capture(path):
        if path not in captured:
            captured[path] = (ROOT / path).read_bytes()
        return captured[path]
    authorities = {}
    for kind, (path, expected) in ORIGINALS.items():
        raw = capture(path)
        if (_pin(raw) != expected
                or _canonical(value['original_inventories'][kind])
                    != _canonical({'path': path, **expected})):
            raise ValueError('qualifier independent original inventory differs')
        authorities[kind] = json.loads(raw)
        if len(authorities[kind]['unchanged_files']) != value['original_unchanged_source_counts'][kind]:
            raise ValueError('qualifier complete original source map differs')
    if _canonical(original_value) != _canonical(authorities[original_kind]):
        raise ValueError('qualifier caller did not supply its complete fixed original')
    for kind, names in QUALIFIER_ALLOWED.items():
        for path in names:
            if (_canonical(authorities[kind]['unchanged_files'][path])
                    != _canonical(QUALIFIER_RECORDS[path]['old'])):
                raise ValueError('qualifier expected old source is not an original fixture pin')
    dependency_adjustments = {}
    for path, expected in QUALIFIER_DEPENDENCIES.items():
        raw = capture(path)
        if _pin(raw) != expected:
            if path != QUALIFIER_DEPENDENCY_PATH:
                raise ValueError('qualifier runtime/authority dependency changed: ' + path)
            dependency_adjustments[path] = _admit_qualifier_dependency(raw, capture)
    for authority in value['prior_terminal_authorities'].values():
        path = authority['path']
        if _pin(capture(path)) != {key: authority[key] for key in ('bytes', 'sha256')}:
            raise ValueError('qualifier prior terminal authority changed')
    state_mask = QUALIFIER_PRIOR_STATES[prior['state']]
    prior_names = (*PATHS, EVALUATION)
    if set(value['prior_terminal_sources']) != set(prior_names):
        raise ValueError('qualifier prior terminal source set differs')
    for bit, path in enumerate(prior_names):
        expected = value['prior_terminal_sources'][path]['new' if state_mask & (1 << bit) else 'old']
        raw = capture(path)
        if path == TRANSPORT and 'sqlite_boundary_successor' in prior['source_adjustments'].get(path, {}):
            raw = _reverse_sqlite_boundary(path, raw, capture(SQLITE_BOUNDARY_FIXTURE),
                                           FIXTURE, capture(FIXTURE), expected)
        if path == EVALUATION and 'typed_store_test_successor' in prior['source_adjustments'].get(path, {}):
            raw = restore_evaluation_store(raw, capture(EVALUATION_STORE_FIXTURE))
        if _pin(raw) != expected:
            raise ValueError('qualifier prior terminal source changed after its admission')
    raw_sources = {path: capture(path) for path in QUALIFIER_PATHS}
    all_old = all(_pin(raw_sources[path]) == QUALIFIER_RECORDS[path]['old'] for path in QUALIFIER_PATHS)
    all_new = all(_pin(raw_sources[path]) == QUALIFIER_RECORDS[path]['new'] for path in QUALIFIER_PATHS)
    if not all_old and not all_new:
        raise ValueError('qualifier group must be all original or all exact reviewed sources')
    restored = {}
    for path, raw in raw_sources.items():
        record = value['files'][path]
        if all_new:
            restored[path] = reverse_qualifier(raw, record, path)
        else:
            preview = _qualifier_transform(raw, record, path, reverse=False)
            restored[path] = reverse_qualifier(preview, record, path)
            if restored[path] != raw:
                raise ValueError('original qualifier full forward/inverse replay differs')
    adjustments = {}
    if all_new:
        for path in QUALIFIER_ALLOWED[original_kind]:
            adjustments[path] = {
                'path': path, 'original_bytes': QUALIFIER_RECORDS[path]['old']['bytes'],
                'original_sha256': QUALIFIER_RECORDS[path]['old']['sha256'],
                'current_bytes': QUALIFIER_RECORDS[path]['new']['bytes'],
                'current_sha256': QUALIFIER_RECORDS[path]['new']['sha256'],
                'reversible_patch_fixture_sha256': QUALIFIER_FIXTURE_PIN['sha256'],
                'scope': QUALIFIER_SCOPE, 'exact_splice_count': 3,
                'complete_original_inverse_verified': True, 'full_forward_replay_verified': True,
                'production_source_exception': False}
    if set(adjustments) - set(authorities[original_kind]['unchanged_files']):
        raise ValueError('qualifier source adjustment escaped its original caller inventory')
    if set(adjustments) & set(prior['source_adjustments']):
        raise ValueError('qualifier layer overlaps a prior source adjustment')
    # Every expected pin above is fixed before reads. Never replace a captured
    # byte sequence or expected pin with a later observation.
    for path, raw in captured.items():
        if (ROOT / path).read_bytes() != raw:
            raise ValueError('qualifier captured bytes changed at terminal reread: ' + path)
    result = dict(prior)
    result['source_adjustments'] = {**prior['source_adjustments'], **adjustments}
    result['caller_qualifier_source_admission'] = {
        'schema': 'hepta.hia.delivery-caller-qualifier-admission.v1',
        'state': 'EXACT_REVIEWED_QUALIFIER_TRIPLE' if all_new else 'EXACT_ORIGINAL_QUALIFIER_TRIPLE',
        'authority': {'path': QUALIFIER_FIXTURE, **QUALIFIER_FIXTURE_PIN},
        'original_kind': original_kind, 'original_source_count': len(authorities[original_kind]['unchanged_files']),
        'full_group_paths': list(QUALIFIER_PATHS), 'reviewed_group_source_count': 3,
        'source_adjustments': adjustments, 'source_adjustment_count': len(adjustments),
        'complete_old_source_pins': {path: _pin(raw) for path, raw in restored.items()},
        'reviewed_dependency_source_adjustments': dependency_adjustments,
        'actual_captured_files': {path: _pin(raw) for path, raw in captured.items()},
        'terminal_reread_identical': True, 'production_composition_source_count': 13,
        'production_source_exceptions': [], 'original_inventories_unchanged': True,
        'prior_terminal_scope_counts_are_not_aggregate_counts': True,
        'original_test_methods_budgets_and_order_unchanged': True}
    return result


# Independent source-only authority for the existing deadline diagnostics and
# the two caller qualifiers that now consume that exact diagnostic admission.
# The original Delivery test files, inventories and all earlier layers stay
# fixed. A missing authority supplies no exception to either outer file loop.
DIAGNOSTIC_FIXTURE = "tests/fixtures/delivery_diagnostic_source_successors_v1.json"
DIAGNOSTIC_FIXTURE_PIN = {
    "bytes": 29000,
    "sha256": "725f18e0ff6a8f598176bac85383f19234938a0efce73259779357bf6a853778"
}
DIAGNOSTIC_RECORDS = {
    "tests/test_hia_agent_native_tools.py": {
        "old": {
            "bytes": 45385,
            "sha256": "c7a3b2b486e55a600ddd5e691729e8cddc6acd5935e5aad337e27c1f20be856a"
        },
        "new": {
            "bytes": 46518,
            "sha256": "b98c24327639363d266eb5e263c042e0a20d82a8f2e8cc08ffafb8f34f73f355"
        },
        "scope": "exact existing failure-only diagnostics; original five-second assertion, one-ms native budget and all method bodies outside the two fixed splices retained",
        "splice_ids": [
            "capture-failure-receipts",
            "preserve-original-deadline-assertion"
        ]
    },
    "tools/qualify_hia_evaluation_callers.py": {
        "old": {
            "bytes": 9948,
            "sha256": "713200bc1c23691732e6d561d9f8ccc2c9626c3ff465bde8c8fd7e0393f285dd"
        },
        "new": {
            "bytes": 12984,
            "sha256": "63b9437fda07aa1d1e29eebf28f9306296a8bae6b694dccbd5702bf81d87037c"
        },
        "scope": "exact complete original evaluation source admission, captured diagnostic proof and terminal reread; original twelve modules, 183 method IDs, seven ordinary modules and 81 ordinary methods retained",
        "splice_ids": [
            "admit-complete-original-sources",
            "capture-separate-diagnostic-proof",
            "preserve-captured-source-inputs",
            "close-admission-to-full-capture-gap",
            "report-separate-diagnostic-proof"
        ]
    },
    "tools/qualify_hia_store_lifecycle_callers.py": {
        "old": {
            "bytes": 7978,
            "sha256": "c57517511cfb3356b80c5cededb33c20e0d7b052c3fde216c2cdc328620523ba"
        },
        "new": {
            "bytes": 10143,
            "sha256": "24b530be08ed7b237b22b6f8b66a07724bdb4ea6fc4f7963f9881791e64c59c9"
        },
        "scope": "exact complete original lifecycle source admission and captured diagnostic proof; original four modules, 50 method IDs, budgets and execution order retained",
        "splice_ids": [
            "admit-complete-original-sources",
            "bind-original-caller-authority",
            "capture-and-bind-diagnostic-inputs",
            "report-separate-diagnostic-proof"
        ]
    }
}
DIAGNOSTIC_DEPENDENCIES = {
    "tests/hia_caller_diagnostics_admission.py": {
        "bytes": 5185,
        "sha256": "9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578"
    },
    "tests/fixtures/caller_deadline_diagnostics_v1.json": {
        "bytes": 3545,
        "sha256": "53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c"
    },
    "tests/fixtures/evaluation_callers_19065.json": {
        "bytes": 68867,
        "sha256": "256e6c83a79fc2f237b4c12dd4bc2ae00d61bee03332b6adc794086b7e081395"
    },
    "tests/fixtures/store_lifecycle_callers_ad352ee.json": {
        "bytes": 7502,
        "sha256": "dda9b68253b30c351282417de1df488c7b213c5b19c0c2547dc95eace2622a2b"
    }
}
DIAGNOSTIC_ALLOWED = {
    "native": [
        "tests/test_hia_agent_native_tools.py",
        "tools/qualify_hia_evaluation_callers.py"
    ],
    "store": [
        "tests/test_hia_agent_native_tools.py",
        "tools/qualify_hia_evaluation_callers.py",
        "tools/qualify_hia_store_lifecycle_callers.py"
    ]
}
DIAGNOSTIC_SOURCE_COUNTS = {'native': 64, 'store': 89}
DIAGNOSTIC_PATHS = tuple(DIAGNOSTIC_RECORDS)


def _diagnostic_transform(raw, record, path, *, reverse):
    if (type(path) is not str or path not in DIAGNOSTIC_RECORDS
            or type(raw) is not bytes or type(reverse) is not bool
            or type(record) is not dict or set(record) != {'old', 'new', 'scope', 'splices'}):
        raise ValueError('delivery diagnostic complete source authority differs')
    expected = DIAGNOSTIC_RECORDS[path]
    if (_canonical(record['old']) != _canonical(expected['old'])
            or _canonical(record['new']) != _canonical(expected['new'])
            or record['scope'] != expected['scope']
            or type(record['splices']) is not list
            or len(record['splices']) != len(expected['splice_ids'])
            or _pin(raw) != expected['new' if reverse else 'old']):
        raise ValueError('delivery diagnostic full fixed source or scope differs')
    entries = []
    old_end = new_end = displacement = 0
    for expected_id, item in zip(expected['splice_ids'], record['splices']):
        if (type(item) is not dict
                or set(item) != {'id', 'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or item['id'] != expected_id
                or type(item['old_offset']) is not int or item['old_offset'] < old_end
                or type(item['new_offset']) is not int or item['new_offset'] < new_end):
            raise ValueError('delivery diagnostic exact splice inventory differs')
        at, target = item['old_offset'], item['new_offset']
        before, after = _hex(item['old_hex']), _hex(item['new_hex'])
        selected_at, selected = (target, after) if reverse else (at, before)
        if (not before or not after or before == after or at + displacement != target
                or selected_at + len(selected) > len(raw)
                or raw[selected_at:selected_at + len(selected)] != selected):
            raise ValueError('delivery diagnostic exact splice bytes differ')
        entries.append((at, target, before, after))
        old_end, new_end = at + len(before), target + len(after)
        displacement += len(after) - len(before)
    result = raw
    for at, target, before, after in reversed(entries):
        selected_at, selected, replacement = ((target, after, before) if reverse
                                               else (at, before, after))
        result = result[:selected_at] + replacement + result[selected_at + len(selected):]
    if _pin(result) != expected['old' if reverse else 'new']:
        raise ValueError('delivery diagnostic transform does not recover the complete fixed source')
    return result


def reverse_diagnostic_source(raw, record, path):
    restored = _diagnostic_transform(raw, record, path, reverse=True)
    if _diagnostic_transform(restored, record, path, reverse=False) != raw:
        raise ValueError('delivery diagnostic complete forward replay differs')
    return restored


def _admit_diagnostic_sources(original_value, original_kind, prior, frozen):
    if type(frozen) is not bytes or _pin(frozen) != DIAGNOSTIC_FIXTURE_PIN:
        raise ValueError('delivery diagnostic fixed provenance changed')
    value = json.loads(frozen)
    if (type(value) is not dict
            or set(value) != {'schema', 'state', 'source_count', 'source_kind',
                'production_composition_source_count', 'original_inventories',
                'original_source_counts', 'allowed_adjustments', 'dependencies', 'files',
                'original_inventories_unchanged', 'original_methods_budgets_and_order_unchanged',
                'production_source_exceptions'}
            or value['schema'] != 'hepta.hia.delivery-diagnostic-source-successor.v1'
            or value['state'] != 'FROZEN_EXACT_THREE_DIAGNOSTIC_SOURCE_SUCCESSORS'
            or type(value['source_count']) is not int or value['source_count'] != 3
            or value['source_kind'] != 'TEST_AND_QUALIFICATION_SOURCE_ONLY'
            or type(value['production_composition_source_count']) is not int
            or value['production_composition_source_count'] != 13
            or _canonical(value['original_inventories']) != _canonical({
                kind: {'path': item[0], **item[1]} for kind, item in ORIGINALS.items()})
            or _canonical(value['original_source_counts']) != _canonical(DIAGNOSTIC_SOURCE_COUNTS)
            or _canonical(value['allowed_adjustments']) != _canonical(DIAGNOSTIC_ALLOWED)
            or _canonical(value['dependencies']) != _canonical(DIAGNOSTIC_DEPENDENCIES)
            or type(value['files']) is not dict or set(value['files']) != set(DIAGNOSTIC_PATHS)
            or value['original_inventories_unchanged'] is not True
            or value['original_methods_budgets_and_order_unchanged'] is not True
            or type(value['production_source_exceptions']) is not list
            or value['production_source_exceptions']):
        raise ValueError('delivery diagnostic fixed provenance scope differs')
    prior_proof = prior.get('caller_qualifier_source_admission')
    if (type(prior_proof) is not dict or prior_proof.get('original_kind') != original_kind
            or prior_proof.get('terminal_reread_identical') is not True
            or prior.get('production_composition_source_count') != 13
            or type(prior_proof.get('actual_captured_files')) is not dict):
        raise ValueError('delivery diagnostic admission requires the complete prior caller source review')
    captured = {DIAGNOSTIC_FIXTURE: frozen}

    def capture(path):
        raw = (ROOT / path).read_bytes()
        if path in captured and raw != captured[path]:
            raise ValueError('delivery diagnostic source changed between captures: ' + path)
        captured[path] = raw
        return raw

    # A later layer must consume the exact prior captures, not accept a second
    # independently valid old/new version observed after that layer returned.
    for path, expected in prior_proof['actual_captured_files'].items():
        if _pin(capture(path)) != expected:
            raise ValueError('delivery diagnostic prior source changed after admission: ' + path)
    authorities = {}
    for kind, (path, expected) in ORIGINALS.items():
        raw = capture(path)
        if _pin(raw) != expected:
            raise ValueError('delivery diagnostic original inventory changed')
        authorities[kind] = json.loads(raw)
        if len(authorities[kind]['unchanged_files']) != DIAGNOSTIC_SOURCE_COUNTS[kind]:
            raise ValueError('delivery diagnostic original complete file count differs')
    if _canonical(original_value) != _canonical(authorities[original_kind]):
        raise ValueError('delivery diagnostic caller did not supply its complete fixed original')
    for kind, paths in DIAGNOSTIC_ALLOWED.items():
        for path in paths:
            if (_canonical(authorities[kind]['unchanged_files'][path])
                    != _canonical(DIAGNOSTIC_RECORDS[path]['old'])):
                raise ValueError('delivery diagnostic old source is not an original inventory pin')
    for path, expected in DIAGNOSTIC_DEPENDENCIES.items():
        if _pin(capture(path)) != expected:
            raise ValueError('delivery diagnostic runtime or original authority changed: ' + path)
    diagnostic = json.loads(captured['tests/fixtures/caller_deadline_diagnostics_v1.json'])
    diagnostic_record = value['files'][DIAGNOSTIC_PATHS[0]]
    if (diagnostic['path'] != DIAGNOSTIC_PATHS[0]
            or _canonical(diagnostic['original']) != _canonical(diagnostic_record['old'])
            or _canonical(diagnostic['current']) != _canonical(diagnostic_record['new'])
            or _canonical(diagnostic['splices']) != _canonical([
                {key: item[key] for key in ('old_offset', 'new_offset', 'old_hex', 'new_hex')}
                for item in diagnostic_record['splices']])
            or type(diagnostic['original_deadline_seconds']) is not int
            or diagnostic['original_deadline_seconds'] != 5
            or type(diagnostic['original_native_budget_ms']) is not int
            or diagnostic['original_native_budget_ms'] != 1):
        raise ValueError('delivery diagnostic existing deadline authority was not retained')
    restored, states, adjustments = {}, {}, {}
    for path in DIAGNOSTIC_PATHS:
        raw, record = capture(path), value['files'][path]
        expected = DIAGNOSTIC_RECORDS[path]
        reviewed = raw
        boundary = _pin(raw) == SQLITE_BOUNDARY_SOURCES.get(path)
        if boundary:
            reviewed = _reverse_sqlite_boundary(path, raw, capture(SQLITE_BOUNDARY_FIXTURE),
                                                DIAGNOSTIC_FIXTURE, frozen, expected['new'])
        if _pin(raw) == expected['old']:
            preview = _diagnostic_transform(raw, record, path, reverse=False)
            restored[path] = reverse_diagnostic_source(preview, record, path)
            if restored[path] != raw:
                raise ValueError('delivery diagnostic original full replay differs')
            states[path] = 'EXACT_ORIGINAL'
        else:
            restored[path] = reverse_diagnostic_source(reviewed, record, path)
            states[path] = 'EXACT_REVIEWED_SUCCESSOR'
            if path in DIAGNOSTIC_ALLOWED[original_kind]:
                adjustments[path] = {
                    'path': path, 'original_bytes': expected['old']['bytes'],
                    'original_sha256': expected['old']['sha256'],
                    'current_bytes': expected['new']['bytes'],
                    'current_sha256': expected['new']['sha256'],
                    'reversible_patch_fixture_sha256': DIAGNOSTIC_FIXTURE_PIN['sha256'],
                    'scope': expected['scope'], 'exact_splice_count': len(expected['splice_ids']),
                    'complete_original_inverse_verified': True,
                    'complete_current_forward_replay_verified': True,
                    'production_source_exception': False}
                if boundary:
                    adjustments[path].update({
                        'current_bytes': len(raw), 'current_sha256': sha256(raw).hexdigest(),
                        'sqlite_boundary_successor': {
                            'authority': {'path': SQLITE_BOUNDARY_FIXTURE, **SQLITE_BOUNDARY_FIXTURE_PIN},
                            'restores_reviewed_diagnostic_source_exactly': True,
                        },
                    })
    if (set(adjustments) - set(authorities[original_kind]['unchanged_files'])
            or set(adjustments) & set(prior['source_adjustments'])):
        raise ValueError('delivery diagnostic source adjustment escaped or overlapped its fixed scope')
    for path, raw in captured.items():
        if (ROOT / path).read_bytes() != raw:
            raise ValueError('delivery diagnostic captured bytes changed at terminal reread: ' + path)
    result = dict(prior)
    result['source_adjustments'] = {**prior['source_adjustments'], **adjustments}
    result['caller_diagnostic_source_admission'] = {
        'schema': 'hepta.hia.delivery-diagnostic-source-admission.v1',
        'authority': {'path': DIAGNOSTIC_FIXTURE, **DIAGNOSTIC_FIXTURE_PIN},
        'original_kind': original_kind,
        'original_source_count': DIAGNOSTIC_SOURCE_COUNTS[original_kind],
        'full_group_paths': list(DIAGNOSTIC_PATHS), 'reviewed_group_source_count': 3,
        'actual_source_states': states, 'source_adjustments': adjustments,
        'source_adjustment_count': len(adjustments),
        'complete_old_source_pins': {path: _pin(raw) for path, raw in restored.items()},
        'actual_captured_files': {path: _pin(raw) for path, raw in captured.items()},
        'terminal_reread_identical': True, 'prior_captures_consumed_without_refresh': True,
        'production_composition_source_count': 13, 'production_source_exceptions': [],
        'original_inventories_unchanged': True,
        'prior_scope_counts_are_not_aggregate_counts': True,
        'original_test_methods_budgets_and_order_unchanged': True}
    return result


def _admit_terminal_sources_before_journal(original_value, *, original_kind):
    # Read optional new authorities before prior admission. Absence grants no
    # exception; the unchanged outer Delivery loops still read every original
    # file and reject any source not covered by a complete fixed proof.
    try:
        diagnostic_frozen = (ROOT / DIAGNOSTIC_FIXTURE).read_bytes()
    except FileNotFoundError:
        diagnostic_frozen = None
    try:
        frozen = (ROOT / QUALIFIER_FIXTURE).read_bytes()
    except FileNotFoundError:
        frozen = None
    prior = _admit_terminal_sources_before_qualifiers(original_value, original_kind=original_kind)
    if frozen is not None:
        prior = _admit_qualifier_sources(original_value, original_kind, prior, frozen)
    if diagnostic_frozen is None:
        return prior
    return _admit_diagnostic_sources(original_value, original_kind, prior, diagnostic_frozen)


# The Journal installed-wheel source successor is independent of the retained
# terminal/qualifier/diagnostic authorities. No production file is excepted.
JOURNAL_PREPARATION_PATH = 'tests/test_hia_agent_journal_native.py'
JOURNAL_PREPARATION_HELPER = 'tests/hia_journal_installed_preparation.py'
JOURNAL_PREPARATION_HELPER_PIN = {'bytes': 15935, 'sha256': '8938ae45ca0342ab5b67dd2eabb615d4b39d7e55b554513b5aa39a7463e59797'}
JOURNAL_PREPARATION_FIXTURE = 'tests/fixtures/journal_installed_preparation_v2.json'
JOURNAL_PREPARATION_FIXTURE_PIN = {'bytes': 14729, 'sha256': '81914ecb2bef21e9c641282dc8530158146ecadd4b86e8e4e6b3f83e71b73e7b'}
JOURNAL_PREPARATION_ARCHIVE = 'tests/fixtures/journal_installed_preparation_v1.py.txt'
JOURNAL_PREPARATION_OLD = {'bytes': 48482, 'sha256': 'a0a6e63291eb76ee84787b432c56eaa32bd1181b762f9593532c059d4a665077'}
JOURNAL_PREPARATION_NEW = {'bytes': 48798, 'sha256': '7d5cebde72523ade809346a30916a48611e18a157230b4f2f6129c0d16b8715c'}
JOURNAL_PREPARATION_PATHS = (JOURNAL_PREPARATION_PATH, JOURNAL_PREPARATION_HELPER,
                             JOURNAL_PREPARATION_FIXTURE, JOURNAL_PREPARATION_ARCHIVE)


def _admit_journal_preparation_sources(original_value, original_kind, prior, frozen):
    if _pin(frozen) != JOURNAL_PREPARATION_FIXTURE_PIN:
        raise ValueError('delivery Journal preparation authority changed')
    captured = {JOURNAL_PREPARATION_FIXTURE: frozen}

    def capture(name):
        raw = (ROOT / name).read_bytes()
        if name in captured and captured[name] != raw:
            raise ValueError('delivery Journal source changed between captures: ' + name)
        captured[name] = raw
        return raw

    source = capture(JOURNAL_PREPARATION_PATH)
    if _pin(source) == JOURNAL_PREPARATION_OLD:
        for name, raw in captured.items():
            if (ROOT / name).read_bytes() != raw:
                raise ValueError('delivery literal Journal changed at terminal reread: ' + name)
        return prior
    if _pin(source) != JOURNAL_PREPARATION_NEW:
        raise ValueError('delivery Journal source is not the exact preparation successor')
    # The latest available complete source proof subsumes all earlier captures.
    # A new source exception cannot rely only on a prior top-level status string.
    previous = prior.get('caller_diagnostic_source_admission',
                         prior.get('caller_qualifier_source_admission'))
    if (type(previous) is not dict or previous.get('original_kind') != original_kind
            or previous.get('terminal_reread_identical') is not True
            or type(previous.get('actual_captured_files')) is not dict
            or prior.get('production_composition_source_count') != 13):
        raise ValueError('delivery Journal preparation requires complete prior source custody')
    for name, expected in previous['actual_captured_files'].items():
        if _canonical(_pin(capture(name))) != _canonical(expected):
            raise ValueError('delivery Journal prior source changed after admission: ' + name)
    original_path, original_pin = ORIGINALS[original_kind]
    original_raw = capture(original_path)
    if _pin(original_raw) != original_pin:
        raise ValueError('delivery Journal original inventory changed')
    original = json.loads(original_raw)
    if (_canonical(original_value) != _canonical(original)
            or len(original['unchanged_files']) != (64 if original_kind == 'native' else 89)
            or _canonical(original['unchanged_files'].get(JOURNAL_PREPARATION_PATH))
                != _canonical(JOURNAL_PREPARATION_OLD)
            or JOURNAL_PREPARATION_PATH in prior['source_adjustments']):
        raise ValueError('delivery Journal preparation does not belong to its fixed original inventory')
    helper = capture(JOURNAL_PREPARATION_HELPER)
    if _pin(helper) != JOURNAL_PREPARATION_HELPER_PIN:
        raise ValueError('delivery Journal preparation helper changed')
    from tests import hia_journal_installed_preparation as journal
    if Path(journal.__file__).read_bytes() != helper:
        raise ValueError('delivery imported a different Journal preparation helper')
    proof = journal.admit_source(ROOT, JOURNAL_PREPARATION_PATH, source,
                                 original['unchanged_files'][JOURNAL_PREPARATION_PATH])
    for name, expected in proof['captured_files'].items():
        if _canonical(_pin(capture(name))) != _canonical(expected):
            raise ValueError('delivery Journal capture changed after preparation admission: ' + name)
    adjustment = {
        'path': JOURNAL_PREPARATION_PATH,
        'original_bytes': JOURNAL_PREPARATION_OLD['bytes'],
        'original_sha256': JOURNAL_PREPARATION_OLD['sha256'],
        'current_bytes': JOURNAL_PREPARATION_NEW['bytes'],
        'current_sha256': JOURNAL_PREPARATION_NEW['sha256'],
        'reversible_patch_fixture_sha256': JOURNAL_PREPARATION_FIXTURE_PIN['sha256'],
        'scope': 'versioned installed-resource preparation; all original 21 methods, assertions and deadlines retained',
        'exact_splice_count': 2, 'complete_original_inverse_verified': True,
        'complete_current_forward_replay_verified': True,
        'production_source_exception': False,
    }
    for name, raw in captured.items():
        if (ROOT / name).read_bytes() != raw:
            raise ValueError('delivery Journal captured source changed at terminal reread: ' + name)
    result = dict(prior)
    result['source_adjustments'] = {**prior['source_adjustments'], JOURNAL_PREPARATION_PATH: adjustment}
    result['journal_installed_preparation_source_admission'] = {
        'schema': 'hepta.hia.delivery-journal-installed-preparation-admission.v1',
        'original_kind': original_kind,
        'original_source_count': 64 if original_kind == 'native' else 89,
        'authority': {'path': JOURNAL_PREPARATION_FIXTURE, **JOURNAL_PREPARATION_FIXTURE_PIN},
        'reviewed_journal_installed_preparation': proof,
        'source_adjustments': {JOURNAL_PREPARATION_PATH: adjustment},
        'source_adjustment_count': 1,
        'actual_captured_files': {name: _pin(raw) for name, raw in captured.items()},
        'terminal_reread_identical': True, 'prior_captures_consumed_without_refresh': True,
        'production_composition_source_count': 13, 'production_source_exceptions': [],
        'original_inventories_unchanged': True,
        'original_test_methods_budgets_and_order_unchanged': True,
        'whole_native': False,
    }
    return result


def _admit_terminal_sources_before_ordinary_callers(original_value, *, original_kind):
    # Missing new authority supplies no exception. In particular the unchanged
    # complete outer file guards continue to reject an unsupported current test.
    try:
        frozen = (ROOT / JOURNAL_PREPARATION_FIXTURE).read_bytes()
    except FileNotFoundError:
        frozen = None
    prior = _admit_terminal_sources_before_journal(original_value, original_kind=original_kind)
    if frozen is not None:
        prior = _admit_journal_preparation_sources(original_value, original_kind, prior, frozen)
    return _admit_component_successors(original_value, prior)


COMPONENT_FIXTURE = 'tests/fixtures/delivery_component_successor.json'
COMPONENT_FIXTURE_SHA256 = '2ba3ca7c9e2f51226be812c9ffc716fc7081671412cd035e1e40852b113aadd3'
COMPONENT_PATHS = (
    'examples/hia_bootstrap/agent_journal.hepta',
    'tests/test_hia_agent_native_proof_contract.py',
    'tests/test_hia_cost_ledger_native.py',
    'tests/test_hia_store_lifecycle_native.py',
    'tests/test_hia_worker_native_helpers.py',
)


def _admit_component_successors(original, prior):
    """Keep the original full-file controls across known integrated components."""
    from tests.hia_store_delivery_successor import reverse_exact

    captured = {path: (ROOT / path).read_bytes() for path in COMPONENT_PATHS}
    prior_pins = {path: original['unchanged_files'][path] for path in COMPONENT_PATHS}
    changed = {path for path, raw in captured.items() if _pin(raw) != prior_pins[path]}
    if not changed:
        return prior
    try:
        frozen = (ROOT / COMPONENT_FIXTURE).read_bytes()
    except FileNotFoundError:
        return prior  # The original outer controls still refuse unknown changes.
    if sha256(frozen).hexdigest() != COMPONENT_FIXTURE_SHA256:
        raise ValueError('native Delivery component provenance changed')
    value = json.loads(frozen)
    if (type(value) is not dict or set(value) != {'schema', 'original_inventories', 'files'}
            or value['schema'] != 'hepta.hia.delivery-component-successor.v1'
            or value['original_inventories'] != {
                kind: {'path': name, **pin} for kind, (name, pin) in ORIGINALS.items()}
            or type(value['files']) is not dict or set(value['files']) != set(COMPONENT_PATHS)):
        raise ValueError('native Delivery component provenance scope differs')
    adjustments = {}
    for name in sorted(changed):
        old = prior_pins[name]
        record = value['files'][name].get(old['sha256'])
        reverse_exact(captured[name], record, old)
        adjustments[name] = {
            'path': name, 'original_bytes': old['bytes'], 'original_sha256': old['sha256'],
            'current_bytes': record['new_bytes'], 'current_sha256': record['new_sha256'],
            'reversible_patch_fixture_sha256': COMPONENT_FIXTURE_SHA256,
            'scope': 'fixed integrated Journal, proof identity, ledger, Store or release custody successor',
        }
    if ((ROOT / COMPONENT_FIXTURE).read_bytes() != frozen
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())):
        raise ValueError('native Delivery component bytes changed during admission')
    if set(adjustments) & set(prior['source_adjustments']):
        raise ValueError('native Delivery component and earlier successor overlap')
    return {**prior, 'source_adjustments': {**prior['source_adjustments'], **adjustments}}


# These two qualification-source relations are fixed together. Neither original
# 64/89-file inventory, any earlier authority nor either qualifier is rewritten.
ORDINARY_CALLER_FIXTURE = 'tests/fixtures/cost_context_caller_source_successors_v1.json'
ORDINARY_CALLER_FIXTURE_PIN = {'bytes': 27816, 'sha256': '0366144696c98f51d7d114c126cc19a175aaab109bc290ded7d108cf0b8d60ae'}
ORDINARY_CALLER_RECORDS = {'tools/qualify_hia_cost_ledger_callers.py': {'old': {'bytes': 7104, 'sha256': '77dd0403aa92d97f6993b0c4ec468fef0adcbb2cf40924ce087c791658cb802e'}, 'new': {'bytes': 10516, 'sha256': '30842806afddf8e493cc968740e5aa947dc906d041a466ceab8c6f7e0d34e844'}, 'scope': 'exact complete original Cost81 source admission with fixed deadline-diagnostic relation and actual before/after capture binding; seven modules, all 81 methods, four separate administrator scopes, budgets, selectors, loops and assertions retained', 'splice_ids': ('add-fixed-diagnostic-admission', 'consume-original-seven-module-authority', 'capture-diagnostic-source-inputs', 'bind-initial-capture', 'bind-terminal-capture', 'report-distinct-source-proof')}, 'tools/qualify_hia_service_context_callers.py': {'old': {'bytes': 8764, 'sha256': '04d0fadfe12b0dcfb54e4663557860506fd482ec7cff2d0eb91db19a218cdd3a'}, 'new': {'bytes': 11944, 'sha256': 'c7825a2724acb1d7137a8ad1c24aac0f865c227c5b2c27bf4ea52f05c2d8d863'}, 'scope': 'exact already-reviewed Context50 source admission with fixed deadline-diagnostic relation and actual before/after capture binding; four complete modules, all 50 methods, budgets, selectors, loops and assertions retained', 'splice_ids': ('context-source-1', 'context-source-2', 'context-source-3', 'context-source-4', 'context-source-5')}}
ORDINARY_CALLER_PATHS = tuple(ORDINARY_CALLER_RECORDS)
ORDINARY_CALLER_DEPENDENCIES = {'tests/fixtures/caller_deadline_diagnostics_v1.json': {'bytes': 3545, 'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'}, 'tests/fixtures/cost_ledger_callers_b569c210.json': {'bytes': 27375, 'sha256': '18a7328a337344cc1f64c7df4d7487b7e94cb48d110fa4d70b5b947fcb538d1a'}, 'tests/hia_caller_diagnostics_admission.py': {'bytes': 5185, 'sha256': '9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578'}, 'tests/fixtures/service_context_callers_b569c21.json': {'bytes': 7502, 'sha256': '6d06a3319b6d15a64ff46f2b1991d023c0e7ecedec85d36bd9080b964a31d4bf'}}
ORDINARY_CALLER_COUNTS = {'tools/qualify_hia_cost_ledger_callers.py': 81, 'tools/qualify_hia_service_context_callers.py': 50}
ORDINARY_CALLER_CAPTURE_PATHS = (ORDINARY_CALLER_FIXTURE, *ORDINARY_CALLER_PATHS,
                                *ORDINARY_CALLER_DEPENDENCIES)


def _ordinary_caller_transform(raw, record, path, *, reverse):
    if (type(path) is not str or path not in ORDINARY_CALLER_RECORDS
            or type(raw) is not bytes or type(reverse) is not bool
            or type(record) is not dict or set(record) != {'old', 'new', 'scope', 'splices'}):
        raise ValueError('ordinary caller complete source authority differs')
    expected = ORDINARY_CALLER_RECORDS[path]
    if (_canonical(record['old']) != _canonical(expected['old'])
            or _canonical(record['new']) != _canonical(expected['new'])
            or record['scope'] != expected['scope']
            or type(record['splices']) is not list
            or len(record['splices']) != len(expected['splice_ids'])
            or _pin(raw) != expected['new' if reverse else 'old']):
        raise ValueError('ordinary caller full fixed source or scope differs')
    entries = []
    old_end = new_end = displacement = 0
    for expected_id, item in zip(expected['splice_ids'], record['splices']):
        if (type(item) is not dict
                or set(item) != {'id', 'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or item['id'] != expected_id
                or type(item['old_offset']) is not int or item['old_offset'] < old_end
                or type(item['new_offset']) is not int or item['new_offset'] < new_end):
            raise ValueError('ordinary caller exact splice inventory differs')
        at, target = item['old_offset'], item['new_offset']
        before, after = _hex(item['old_hex']), _hex(item['new_hex'])
        selected_at, selected = (target, after) if reverse else (at, before)
        if (not before or not after or before == after or at + displacement != target
                or at + len(before) > expected['old']['bytes']
                or target + len(after) > expected['new']['bytes']
                or selected_at + len(selected) > len(raw)
                or raw[selected_at:selected_at + len(selected)] != selected):
            raise ValueError('ordinary caller exact splice bytes differ')
        entries.append((at, target, before, after))
        old_end, new_end = at + len(before), target + len(after)
        displacement += len(after) - len(before)
    result = raw
    for at, target, before, after in reversed(entries):
        selected_at, selected, replacement = ((target, after, before) if reverse
                                               else (at, before, after))
        result = result[:selected_at] + replacement + result[selected_at + len(selected):]
    if _pin(result) != expected['old' if reverse else 'new']:
        raise ValueError('ordinary caller transform does not recover the complete fixed source')
    return result


def reverse_ordinary_caller(raw, record, path):
    restored = _ordinary_caller_transform(raw, record, path, reverse=True)
    if _ordinary_caller_transform(restored, record, path, reverse=False) != raw:
        raise ValueError('ordinary caller complete forward replay differs')
    return restored


def _admit_ordinary_caller_sources(original_value, original_kind, prior, frozen):
    if type(frozen) is not bytes or _pin(frozen) != ORDINARY_CALLER_FIXTURE_PIN:
        raise ValueError('ordinary caller source authority changed')
    value = json.loads(frozen)
    if (type(value) is not dict
            or set(value) != {'schema', 'state', 'files', 'dependencies',
                'original_inventories', 'original_source_counts', 'ordinary_caller_counts',
                'production_composition_source_count', 'original_inventories_unchanged',
                'original_methods_budgets_and_order_unchanged', 'production_source_exceptions'}
            or value['schema'] != 'hepta.hia.cost-context-caller-source-successors.v1'
            or value['state'] != 'FROZEN_EXACT_COST_AND_CONTEXT_CALLER_SOURCE_SUCCESSORS'
            or type(value['files']) is not dict or set(value['files']) != set(ORDINARY_CALLER_PATHS)
            or _canonical(value['dependencies']) != _canonical(ORDINARY_CALLER_DEPENDENCIES)
            or _canonical(value['original_inventories']) != _canonical({
                kind: {'path': item[0], **item[1]} for kind, item in ORIGINALS.items()})
            or _canonical(value['original_source_counts']) != _canonical({'native': 64, 'store': 89})
            or _canonical(value['ordinary_caller_counts']) != _canonical(ORDINARY_CALLER_COUNTS)
            or type(value['production_composition_source_count']) is not int
            or value['production_composition_source_count'] != 13
            or value['original_inventories_unchanged'] is not True
            or value['original_methods_budgets_and_order_unchanged'] is not True
            or type(value['production_source_exceptions']) is not list
            or value['production_source_exceptions']):
        raise ValueError('ordinary caller source authority scope differs')
    captured = {ORDINARY_CALLER_FIXTURE: frozen}

    def capture(path):
        raw = (ROOT / path).read_bytes()
        if path in captured and raw != captured[path]:
            raise ValueError('ordinary caller source changed between captures: ' + path)
        captured[path] = raw
        return raw

    restored, states, adjustments = {}, {}, {}
    for path in ORDINARY_CALLER_PATHS:
        source, expected, record = capture(path), ORDINARY_CALLER_RECORDS[path], value['files'][path]
        if _pin(source) == expected['old']:
            preview = _ordinary_caller_transform(source, record, path, reverse=False)
            restored[path] = reverse_ordinary_caller(preview, record, path)
            if restored[path] != source:
                raise ValueError('ordinary caller literal original replay differs')
            states[path] = 'EXACT_ORIGINAL'
        else:
            restored[path] = reverse_ordinary_caller(source, record, path)
            states[path] = 'EXACT_REVIEWED_SUCCESSOR'
            adjustments[path] = {
                'path': path, 'original_bytes': expected['old']['bytes'],
                'original_sha256': expected['old']['sha256'],
                'current_bytes': expected['new']['bytes'], 'current_sha256': expected['new']['sha256'],
                'reversible_patch_fixture_sha256': ORDINARY_CALLER_FIXTURE_PIN['sha256'],
                'scope': expected['scope'], 'exact_splice_count': len(expected['splice_ids']),
                'complete_original_inverse_verified': True,
                'complete_current_forward_replay_verified': True, 'production_source_exception': False,
            }
    if not adjustments:
        for path, raw in captured.items():
            if (ROOT / path).read_bytes() != raw:
                raise ValueError('ordinary caller literal originals changed at terminal reread: ' + path)
        return prior
    previous = prior.get('journal_installed_preparation_source_admission',
                         prior.get('caller_diagnostic_source_admission',
                                   prior.get('caller_qualifier_source_admission')))
    if (type(previous) is not dict or previous.get('original_kind') != original_kind
            or previous.get('original_source_count') != (64 if original_kind == 'native' else 89)
            or previous.get('terminal_reread_identical') is not True
            or type(previous.get('actual_captured_files')) is not dict
            or not previous['actual_captured_files']
            or prior.get('production_composition_source_count') != 13):
        raise ValueError('ordinary caller source relation requires complete prior source custody')
    for path, expected in previous['actual_captured_files'].items():
        if _canonical(_pin(capture(path))) != _canonical(expected):
            raise ValueError('ordinary caller prior source changed after admission: ' + path)
    authorities = {}
    for kind, (path, expected) in ORIGINALS.items():
        raw = capture(path)
        if _pin(raw) != expected:
            raise ValueError('ordinary caller original Delivery inventory changed')
        authorities[kind] = json.loads(raw)
        if len(authorities[kind]['unchanged_files']) != (64 if kind == 'native' else 89):
            raise ValueError('ordinary caller original complete Delivery source count differs')
        for name in ORDINARY_CALLER_PATHS:
            if (_canonical(authorities[kind]['unchanged_files'].get(name))
                    != _canonical(ORDINARY_CALLER_RECORDS[name]['old'])):
                raise ValueError('ordinary caller original complete Delivery source map differs')
    if (_canonical(original_value) != _canonical(authorities[original_kind])
            or set(adjustments) & set(prior['source_adjustments'])):
        raise ValueError('ordinary caller source relation escaped or overlapped its original inventory')
    for path, expected in ORDINARY_CALLER_DEPENDENCIES.items():
        if _pin(capture(path)) != expected:
            raise ValueError('ordinary caller diagnostic runtime or authority changed: ' + path)
    for path, raw in captured.items():
        if (ROOT / path).read_bytes() != raw:
            raise ValueError('ordinary caller captured bytes changed at terminal reread: ' + path)
    result = dict(prior)
    result['source_adjustments'] = {**prior['source_adjustments'], **adjustments}
    result['ordinary_caller_source_admission'] = {
        'schema': 'hepta.hia.delivery-ordinary-caller-source-admission.v1',
        'original_kind': original_kind,
        'original_source_count': 64 if original_kind == 'native' else 89,
        'authority': {'path': ORDINARY_CALLER_FIXTURE, **ORDINARY_CALLER_FIXTURE_PIN},
        'complete_old_sources': {path: _pin(raw) for path, raw in restored.items()},
        'original_ordinary_method_counts': dict(ORDINARY_CALLER_COUNTS),
        'actual_source_states': states, 'source_adjustments': adjustments,
        'source_adjustment_count': len(adjustments),
        'actual_captured_files': {path: _pin(raw) for path, raw in captured.items()},
        'terminal_reread_identical': True, 'prior_captures_consumed_without_refresh': True,
        'production_composition_source_count': 13, 'production_source_exceptions': [],
        'original_inventories_unchanged': True,
        'prior_scope_counts_are_not_aggregate_counts': True,
        'original_test_methods_budgets_and_order_unchanged': True, 'whole_native': False,
    }
    return result


def admit_terminal_sources(original_value, *, original_kind):
    # Absence supplies no exception. The unchanged outer 64/89-file loops
    # continue rejecting every current qualifier without its complete proof.
    try:
        frozen = (ROOT / ORDINARY_CALLER_FIXTURE).read_bytes()
    except FileNotFoundError:
        frozen = None
    prior = _admit_terminal_sources_before_ordinary_callers(original_value, original_kind=original_kind)
    if frozen is None:
        return prior
    return _admit_ordinary_caller_sources(original_value, original_kind, prior, frozen)
