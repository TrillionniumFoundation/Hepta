"""Reconstruct reviewed component inputs from complete, hash-bound physical sources."""
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path


FIXTURE = 'tests/fixtures/hia_frozen_component_source_relations.json'
FIXTURE_SHA256 = 'acd25ffa7c6bea270fcb56cde74a60d7993899cb2e77173b97a814a3bcce14b9'


@lru_cache(maxsize=1)
def _relations(raw):
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('frozen component source relation changed')
    return json.loads(raw)['files']


COLD_CALLER_HELPER_PIN = {'bytes': 11616, 'sha256': '533ac5680937b82ffe3b951bd568e8cf4e103b08b8f302297f442b4119f17480'}


def cold_caller_source(root, name, raw, *, take=Path.read_bytes):
    """Validate a new physical caller, then return a distinct predecessor view."""
    from tools import hia_cold_caller_sources as cold
    root = Path(root)
    if name not in cold.PATHS:
        return raw, None
    try:
        frozen = take(root / cold.FIXTURE)
    except FileNotFoundError:
        # Missing new authority grants no source exception. The unchanged
        # historical complete-file gates retain responsibility for this input.
        return raw, None
    previous = take(root / cold.PREVIOUS_FIXTURE)
    records = cold.read_relations(frozen, previous_raw=previous)
    record = records[name]
    if history_pin(raw) != record['current']:
        return raw, None
    physical = take(root / name)
    helper = take(root / cold.SOURCE)
    if (physical != raw or history_pin(helper) != COLD_CALLER_HELPER_PIN
            or Path(cold.__file__).read_bytes() != helper):
        raise ValueError('native cold caller physical source or helper differs')
    prior = cold.restore_caller_source(name, raw, records)
    pieces, end, displacement = [], 0, 0
    for item in record['splices']:
        current = bytes.fromhex(item['current_hex'])
        predecessor = bytes.fromhex(item['predecessor_hex'])
        at = item['offset'] + displacement
        if at < end or prior[at:at + len(predecessor)] != predecessor:
            raise ValueError('native cold caller forward predecessor differs')
        pieces.extend((prior[end:at], current))
        end = at + len(predecessor)
        displacement += len(predecessor) - len(current)
    if b''.join((*pieces, prior[end:])) != raw:
        raise ValueError('native cold caller complete forward replay differs')
    captured = {name: raw, cold.FIXTURE: frozen, cold.PREVIOUS_FIXTURE: previous,
                cold.SOURCE: helper}
    for path, data in captured.items():
        if take(root / path) != data:
            raise ValueError('native cold caller physical input changed at terminal: ' + path)
    return prior, {
        'schema': 'hepta.hia.native-cold-caller-source-admission.v1',
        'path': name, 'physical_current': history_pin(raw),
        'predecessor': dict(record['predecessor']),
        'authority': {'path': cold.FIXTURE, **history_pin(frozen)},
        'original_authority': {'path': cold.PREVIOUS_FIXTURE, **history_pin(previous)},
        'helper': {'path': cold.SOURCE, **COLD_CALLER_HELPER_PIN},
        'complete_predecessor_restored': True, 'complete_current_replayed': True,
        'actual_captured_files': {path: history_pin(data) for path, data in captured.items()},
        'terminal_reread_identical': True, 'whole_native_delivery_qualified': False,
    }


def bind_cold_caller_adjustment(entry, physical, proof):
    if proof is None:
        return entry
    current = history_pin(physical)
    previous = {'bytes': entry['current_bytes'], 'sha256': entry['current_sha256']}
    if (entry.get('path') != proof['path'] or current != proof['physical_current']
            or previous not in (proof['predecessor'], proof['physical_current'])):
        raise ValueError('native cold caller adjustment lost its complete predecessor')
    return {**entry, 'current_bytes': current['bytes'], 'current_sha256': current['sha256'],
            'native_cold_caller_source': proof}


def reviewed_source(root, name, raw, *, take=Path.read_bytes):
    if name == 'tests/test_hia_evaluation_native.py':
        raw = restore_reader_evaluation_test(raw, root=root, take=take)
    relation = _relations(take(root / FIXTURE)).get(name)
    if relation is None:
        return cold_caller_source(root, name, raw, take=take)[0]
    actual = sha256(raw).hexdigest()
    if actual not in (relation['physical_sha256'], relation['reviewed_sha256']):
        raw, _ = cold_caller_source(root, name, raw, take=take)
        actual = sha256(raw).hexdigest()
    # f377c5de keeps the v5 owner from importing an unselected store profile.
    # Reverse only its complete reviewed physical file, then retain the frozen
    # predecessor relation and original reviewed bytes below unchanged.
    if (name == 'hepta/hia_native_helpers.py' and actual ==
            'a692a261bcc86943526f93f2ff5fb76c5351ad6a0ce5683ddf46cbdc132a13a9'):
        raw = raw.replace(
            b"        record = _decode(captured.raw)\n",
            b"        record = _decode(captured.raw)\n"
            b"        from .hia_worker_store_profile import SCHEMAS as STORE_SCHEMAS, NativeWorkerStoreBinding\n", 1)
        raw = raw.replace(
            b"        else:\n"
            b"            # Load store-profile support only when a store/base profile can\n"
            b"            # actually be selected. The closed v5 Slot and artifact profiles\n"
            b"            # have already selected their own independently admitted owner.\n"
            b"            from .hia_worker_store_profile import SCHEMAS as STORE_SCHEMAS, NativeWorkerStoreBinding\n"
            b"            if schema in STORE_SCHEMAS:\n"
            b"                binding = NativeWorkerStoreBinding(captured, expected_sha256, record)\n"
            b"            else:\n"
            b"                binding = _base_binding(captured, expected_sha256, record)\n",
            b"        elif schema in STORE_SCHEMAS:\n"
            b"            binding = NativeWorkerStoreBinding(captured, expected_sha256, record)\n"
            b"        else:\n"
            b"            binding = _base_binding(captured, expected_sha256, record)\n", 1)
        actual = sha256(raw).hexdigest()
        if actual != '4ee6a95691db4266c71fbb01543c81ed66fdbf382e9a7ff35797c368a8cb8da1':
            raise ValueError('Slot deferred-store source predecessor differs')
    # 72740bd bound Evaluate's retained oracle to its exact candidate capture.
    # Reconstruct only this complete reviewed successor before the unchanged
    # original component relation; production service/callers are never edited.
    if (name == 'tests/test_hia_evaluation_native.py' and actual ==
            'ee3a01914f902f92cb5f440acd224926c92322d346e76e14fde081516b51fbe5'):
        splice = (b"        from tests.hia_evaluation_capture_successor import original_reference\n"
                  b"        retained = original_reference(retained)\n")
        if raw.count(splice) != 1:
            raise ValueError('evaluation capture source predecessor is ambiguous')
        raw = raw.replace(splice, b'', 1)
        actual = sha256(raw).hexdigest()
        if actual != '732379cfe3bcb3d41688669d83d6b610ca63e4954d56b9c2398b5e0f5291fe6b':
            raise ValueError('evaluation capture whole source predecessor differs')
    if actual == relation['reviewed_sha256']:
        return raw
    if actual != relation['physical_sha256']:
        raise ValueError('unreviewed physical component source: ' + name)
    restored = bytearray()
    end = 0
    for at, size, original in relation['splices']:
        if not end <= at <= at + size <= len(raw):
            raise ValueError('overlapping component source splice: ' + name)
        restored.extend(raw[end:at])
        restored.extend(original.encode('utf-8'))
        end = at + size
    restored.extend(raw[end:])
    if sha256(restored).hexdigest() != relation['reviewed_sha256']:
        raise ValueError('complete reviewed component source differs: ' + name)
    return bytes(restored)


# Exact later Store/Evaluate history. The original frozen component relation
# above and all original caller/definition inventories remain immutable.
SOURCE_HISTORY_FIXTURE = 'tests/fixtures/store_source_history_v2.json'
SOURCE_HISTORY_FIXTURE_SHA256 = '2d32911a179bc7e2b00865d07985844018011d7f9a69f9ba7a84f839290118ff'
HOST_SUPPORT = 'hepta/hia_native_host_support.py'
EVALUATION_TEST = 'tests/test_hia_evaluation_native.py'
EVALUATION_QUALIFIER = 'tests/hia_evaluation_capture_successor.py'
SOURCE_HISTORY_INPUTS = (
    'tools/hia_frozen_component_sources.py',
    'tests/hia_store_source_history.py',
    SOURCE_HISTORY_FIXTURE,
    'tests/test_hia_store_source_history.py',
    HOST_SUPPORT,
    EVALUATION_QUALIFIER,
)
PREDECESSORS = {
    'hepta/hia_store_lifecycle_native.py': {'bytes': 23107, 'sha256': 'dae4b9d0b06348de8863d04bed87caf09d9b0691791ee1b279ccd62ebc08ec7f'},
    'hepta/hia_emission_native.py': {'bytes': 35460, 'sha256': '57cc3ac8f3aa115793d03ec3521150f921b702f6466fbaf1833802b7f1b783ca'},
    'hepta/hia_agent_service.py': {'bytes': 263074, 'sha256': '862e41dd41c2a76f3a46b515052cd597f6b186db152bf3ca17aa9a9d2a2570f7'},
    'hepta/hia_evaluation_native.py': {'bytes': 45507, 'sha256': 'd30d4f0796535ba524746a2e8a07f76fe253e9799745cf8458fedf526bce0a70'},
    EVALUATION_TEST: {'bytes': 50171, 'sha256': '732379cfe3bcb3d41688669d83d6b610ca63e4954d56b9c2398b5e0f5291fe6b'},
}
CURRENT = {
    'hepta/hia_store_lifecycle_native.py': {'bytes': 22413, 'sha256': 'c800f2d9701698147b4702401908dc37625cdea1ee21d550b5154ea10c9806f1'},
    'hepta/hia_emission_native.py': {'bytes': 35066, 'sha256': '2dffce808cccef4f5632d10c63dbb22b523aeed867142d64a142e44b2d4a86ba'},
    'hepta/hia_agent_service.py': {'bytes': 268278, 'sha256': 'afc92b555bd0dfa23f25c4f9c2661af30853474342f4e32a036d37c1ce663a57'},
    'hepta/hia_evaluation_native.py': {'bytes': 46096, 'sha256': '71f6d3be9bd116f3419b552e075113110596124365074d74ccf8855d15dc18e4'},
    EVALUATION_TEST: {'bytes': 50297, 'sha256': 'ee3a01914f902f92cb5f440acd224926c92322d346e76e14fde081516b51fbe5'},
}
PRODUCTION_PATHS = tuple(name for name in CURRENT if name != EVALUATION_TEST)
HOST_CURRENT = {'bytes': 1485, 'sha256': '7e15d70ed5dc543be9d153333cd87587e856247c553d4392cf8e93ab475a339b'}
HOST_PREDECESSOR = {'bytes': 1395, 'sha256': '36187c8e4f64314c68d49057e6c5103d16b9e9847b7c78dccbeef999289152eb'}
QUALIFIER_PIN = {'bytes': 1744, 'sha256': '98848071477fc6b23e19484b3355e2f2a455b8b7828240852132bbff6cb67864'}


def history_pin(raw):
    if type(raw) is not bytes:
        raise ValueError('Store history requires exact physical bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def history_inverse(raw, record, original):
    """Independent complete-byte inverse and forward replay; no code execution."""
    import re

    shape = {'old_sha256', 'new_sha256', 'old_bytes', 'new_bytes', 'hunks'}
    if (type(record) is not dict or set(record) != shape
            or type(record['old_bytes']) is not int or type(record['new_bytes']) is not int
            or record['old_bytes'] <= 0 or record['new_bytes'] <= 0
            or type(record['old_sha256']) is not str or type(record['new_sha256']) is not str
            or re.fullmatch('[0-9a-f]{64}', record['old_sha256']) is None
            or re.fullmatch('[0-9a-f]{64}', record['new_sha256']) is None
            or {'bytes': record['old_bytes'], 'sha256': record['old_sha256']} != original
            or history_pin(raw) != {'bytes': record['new_bytes'], 'sha256': record['new_sha256']}
            or type(record['hunks']) is not list or not record['hunks']):
        raise ValueError('Store history complete source identity differs')
    old_end = new_end = 0
    pieces, replay_entries = [], []
    for item in record['hunks']:
        if (type(item) is not dict
                or set(item) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(item['old_offset']) is not int or type(item['new_offset']) is not int
                or item['old_offset'] < old_end or item['new_offset'] < new_end):
            raise ValueError('Store history disjoint exact splice coordinates differ')
        encoded = (item['old_hex'], item['new_hex'])
        if any(type(value) is not str or re.fullmatch('(?:[0-9a-f]{2})*', value) is None
               for value in encoded):
            raise ValueError('Store history splice is not canonical hexadecimal')
        before, after = (bytes.fromhex(value) for value in encoded)
        old_at, new_at = item['old_offset'], item['new_offset']
        if (before == after or old_at - old_end != new_at - new_end
                or new_at + len(after) > len(raw) or raw[new_at:new_at + len(after)] != after):
            raise ValueError('Store history splice does not describe current bytes')
        pieces.extend((raw[new_end:new_at], before))
        replay_entries.append((old_at, before, after))
        old_end, new_end = old_at + len(before), new_at + len(after)
    pieces.append(raw[new_end:])
    restored = b''.join(pieces)
    if history_pin(restored) != original:
        raise ValueError('Store history inverse did not restore the complete predecessor')
    pieces, old_end = [], 0
    for old_at, before, after in replay_entries:
        if restored[old_at:old_at + len(before)] != before:
            raise ValueError('Store history forward replay predecessor differs')
        pieces.extend((restored[old_end:old_at], after))
        old_end = old_at + len(before)
    pieces.append(restored[old_end:])
    if b''.join(pieces) != raw:
        raise ValueError('Store history complete forward replay differs')
    return restored


def _history_definition(raw, name):
    import ast

    lines = raw.splitlines(keepends=True)
    nodes = [node for node in ast.parse(raw).body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    if len(nodes) != 1:
        raise ValueError('Store host extraction definition is not unique: ' + name)
    node = nodes[0]
    first = min([node.lineno] + [value.lineno for value in node.decorator_list]) - 1
    return b''.join(lines[first:node.end_lineno])


def _history_capture(root, name, take, saved):
    path = Path(root) / name
    raw = take(path)
    if name in saved and raw != saved[name]:
        raise ValueError('Store history consumed source changed: ' + name)
    saved[name] = raw
    return raw


def restore(captured, *, root=None, take=Path.read_bytes):
    """Admit the complete five-file successor before reversing any member.

    Earlier compositions remain subject to their original complete admission.
    If any member is the current successor, all five members and both new
    dependencies must be exact. There is no process-global history cache.
    """
    root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    source = dict(captured)
    saved, native_proofs, reviewed = {}, {}, {}

    def native_view(name, raw):
        if history_pin(raw) == CURRENT[name]:
            return raw
        prior, proof = cold_caller_source(root, name, raw,
            take=lambda path: _history_capture(root, path.relative_to(root).as_posix(), take, saved))
        if proof is not None:
            native_proofs[name] = proof
        return prior

    selected = {name: native_view(name, raw) if name in CURRENT else raw
                for name, raw in source.items()}
    if not any(name in selected and history_pin(selected[name]) == expected
               for name, expected in CURRENT.items()):
        return source, None
    for name, expected in CURRENT.items():
        raw = _history_capture(root, name, take, saved)
        reviewed[name] = native_view(name, raw)
        if (name in source and source[name] != raw) or history_pin(reviewed[name]) != expected:
            raise ValueError('Store history partially reverted or unreviewed composition: ' + name)
    frozen = _history_capture(root, SOURCE_HISTORY_FIXTURE, take, saved)
    if sha256(frozen).hexdigest() != SOURCE_HISTORY_FIXTURE_SHA256:
        raise ValueError('Store history fixed source relation changed')
    value = json.loads(frozen)
    if (type(value) is not dict
            or set(value) != {'schema', 'files', 'host_support', 'evaluation_qualifier', 'source_commits'}
            or value['schema'] != 'hepta.hia.store-source-history.v2'
            or set(value['files']) != set(CURRENT)
            or value['host_support']['path'] != HOST_SUPPORT
            or value['evaluation_qualifier'] != {'path': EVALUATION_QUALIFIER, **QUALIFIER_PIN}
            or value['source_commits'] != {
                'host_extraction': 'ce0267659487d202056e32f0f0713dec32b7772d',
                'host_fd_ownership': 'e0cf34e25a37eb14447e402c062c660b482d77f2',
                'evaluation_capture': '72740bdbc2e755e3f1c087327854cc2b6b390f4e'}):
        raise ValueError('Store history fixed relation scope differs')
    prior = {name: history_inverse(reviewed[name], value['files'][name], PREDECESSORS[name])
             for name in CURRENT}
    host = _history_capture(root, HOST_SUPPORT, take, saved)
    qualifier = _history_capture(root, EVALUATION_QUALIFIER, take, saved)
    if history_pin(host) != HOST_CURRENT or history_pin(qualifier) != QUALIFIER_PIN:
        raise ValueError('Store history host or capture dependency changed')
    original_host = history_inverse(host, value['host_support']['patch'], HOST_PREDECESSOR)
    definitions = {}
    for name, owner in (('_regular_bytes', 'hepta/hia_store_lifecycle_native.py'),
                        ('_global_value', 'hepta/hia_emission_native.py')):
        body = _history_definition(original_host, name)
        if body != _history_definition(prior[owner], name):
            raise ValueError('Store host extraction changed its original function: ' + name)
        definitions[name] = history_pin(body)
    source.update(prior)
    review = {
        'schema': 'hepta.hia.store-source-history-review.v2',
        'fixture': {'path': SOURCE_HISTORY_FIXTURE, **history_pin(frozen)},
        'complete_current': dict(CURRENT),
        'complete_predecessors': dict(PREDECESSORS),
        'host_support': dict(HOST_CURRENT),
        'host_predecessor': dict(HOST_PREDECESSOR),
        'exact_extracted_definitions': definitions,
        'evaluation_qualifier': dict(QUALIFIER_PIN),
        'original_caller_and_definition_inventories_changed': False,
        'terminal_reread_identical': False,
    }
    if native_proofs:
        review['native_cold_caller_sources'] = native_proofs
        review['actual_physical_current'] = {name: history_pin(saved[name]) for name in CURRENT}
        review['historical_current_inputs'] = dict(CURRENT)
    result = {'review': review, 'captures': saved, 'root': root, 'take': take}
    verify_unchanged(result)
    return source, result


def verify_unchanged(history):
    if history is None:
        return
    for name, raw in history['captures'].items():
        if history['take'](history['root'] / name) != raw:
            raise ValueError('Store history source changed at terminal: ' + name)
    history['review']['terminal_reread_identical'] = True


def restore_service(raw, *, root=None, take=Path.read_bytes):
    source, history = restore({'hepta/hia_agent_service.py': raw}, root=root, take=take)
    verify_unchanged(history)
    return source['hepta/hia_agent_service.py']


def restore_evaluation_test(raw, *, root=None, take=Path.read_bytes):
    source, history = restore({EVALUATION_TEST: raw}, root=root, take=take)
    verify_unchanged(history)
    return source[EVALUATION_TEST]


def restore_reader_evaluation_test(raw, *, root, take=Path.read_bytes):
    """Bind the caller-selected root before choosing a historical relation.

    A fixture containing only old caller files may use the original admission.
    Once any production member is visible, all four must exist and the entire
    five-file composition must be one exact current or predecessor state.
    """
    root = Path(root)
    visible = {}
    for name in PRODUCTION_PATHS:
        try:
            visible[name] = take(root / name)
        except FileNotFoundError:
            pass
    if not visible:
        if history_pin(raw) == CURRENT[EVALUATION_TEST]:
            raise ValueError('Store history current caller lacks its production composition')
        return raw
    if set(visible) != set(PRODUCTION_PATHS):
        raise ValueError('Store history incomplete reader production composition')
    source = {**visible, EVALUATION_TEST: raw}
    restored, history = restore(source, root=root, take=take)
    if history is not None:
        verify_unchanged(history)
        return restored[EVALUATION_TEST]
    if any(history_pin(source[name]) != expected for name, expected in PREDECESSORS.items()):
        raise ValueError('Store history unreviewed predecessor reader composition')
    return raw
