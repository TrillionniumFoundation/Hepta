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
    for path, expected in QUALIFIER_DEPENDENCIES.items():
        if _pin(capture(path)) != expected:
            raise ValueError('qualifier runtime/authority dependency changed: ' + path)
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
        if _pin(capture(path)) != expected:
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
        'actual_captured_files': {path: _pin(raw) for path, raw in captured.items()},
        'terminal_reread_identical': True, 'production_composition_source_count': 13,
        'production_source_exceptions': [], 'original_inventories_unchanged': True,
        'prior_terminal_scope_counts_are_not_aggregate_counts': True,
        'original_test_methods_budgets_and_order_unchanged': True}
    return result


def admit_terminal_sources(original_value, *, original_kind):
    # Read the optional new authority before the original admission. If absent,
    # the original admission's own terminal raw reread remains the final I/O.
    # The two unchanged outer Delivery guards still refuse every unreviewed
    # qualifier byte; missing authority cannot grant a new exception.
    try:
        frozen = (ROOT / QUALIFIER_FIXTURE).read_bytes()
    except FileNotFoundError:
        frozen = None
    prior = _admit_terminal_sources_before_qualifiers(original_value, original_kind=original_kind)
    if frozen is None:
        return prior
    return _admit_qualifier_sources(original_value, original_kind, prior, frozen)
