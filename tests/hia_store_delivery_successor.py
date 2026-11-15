"""Exact, reversible provenance for reviewed Store, service and protocol successors.

The original c019 inventory is never rewritten. A draft is never an admission;
final composition needs a fixed fixture hash, all old/new hashes and the exact
byte splice patch. Every other original file still uses its old byte check.
"""
import ast
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/store_delivery_successor_provenance.json'
FIXTURE_SHA256 = 'c271bc9a58e4565ba53a005441d5425f0a4bdc627513c415ab6b390b2af1dddc'
ORIGINAL = ROOT / 'tests/fixtures/store_native_delivery_original_c019.json'
ORIGINAL_SHA256 = '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'
ORIGINAL_SOURCE_PATHS = ('hepta/artifact_publication_native.py', 'hepta/hia_agent_store.py',
                'hepta/hia_store_lifecycle_selection.py')
WORKER_PATH = 'hepta/hia_agent_worker.py'
SOURCE_PATHS = ORIGINAL_SOURCE_PATHS + (WORKER_PATH,)
SHARED_PATHS = ('hepta/hia_native_delivery.py', 'hepta/hia_store_lifecycle_native.py',
                'hepta/hia_agent_service.py', 'hepta/hia_emission_native.py',
                'hepta/hia_agent_journal_native.py',
                'hepta/hia_candidate_budget_native.py', 'hepta/hia_execution_budget_native.py')
ADAPTER_PATH = 'hepta/hia_store_artifact_profile_native.py'
# Actual c019 Git bytes independently pin this whole file. The original JSON
# pins its 21 definitions, rather than the complete adapter source.
ADAPTER_ORIGINAL = {'bytes': 32417,
    'sha256': 'fccf236d69462b833b7c8e466bcde716738c13be7095aa675c9427022839b7fc'}
# This companion was not in c019's 89 originals or its 22 shared sources.
# Its independent original is the exact frozen R17b source, not a c019 claim.
COMPANION_ORIGINALS = {'hepta/hia_worker_report_native.py': {
    'bytes': 20176, 'sha256': 'c8539747922892195722f72f9b763eb1d9503b4fe80318eee33ee88a812ed597'}}
# Preserve the original eleven-bit order; append the worker and report bits.
PATHS = ORIGINAL_SOURCE_PATHS + SHARED_PATHS + (ADAPTER_PATH, WORKER_PATH) + tuple(COMPANION_ORIGINALS)


def _bytes(value):
    if type(value) is not str or len(value) % 2 or value != value.lower():
        raise ValueError('successor byte patch encoding differs')
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('successor byte patch encoding invalid') from error
    if raw.hex() != value:
        raise ValueError('successor byte patch is not canonical')
    return raw


def reverse_exact(raw, record, original):
    """Rebuild the complete original bytes from one fixed new file and patch."""
    if (type(raw) is not bytes or type(record) is not dict
            or set(record) != {'old_sha256', 'new_sha256', 'old_bytes', 'new_bytes', 'hunks'}
            or record['old_sha256'] != original['sha256']
            or record['old_bytes'] != original['bytes']
            or type(record['new_bytes']) is not int or record['new_bytes'] != len(raw)
            or sha256(raw).hexdigest() != record['new_sha256']
            or type(record['hunks']) is not list or not record['hunks']):
        raise ValueError('successor whole-file identity differs')
    new_at = old_at = 0
    pieces = []
    for hunk in record['hunks']:
        if (type(hunk) is not dict or set(hunk) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(hunk['old_offset']) is not int or type(hunk['new_offset']) is not int
                or hunk['new_offset'] < new_at):
            raise ValueError('successor patch coordinates differ')
        old, new = _bytes(hunk['old_hex']), _bytes(hunk['new_hex'])
        gap = hunk['new_offset'] - new_at
        if (old == new or hunk['old_offset'] != old_at + gap
                or hunk['new_offset'] + len(new) > len(raw)
                or raw[hunk['new_offset']:hunk['new_offset'] + len(new)] != new):
            raise ValueError('successor patch does not describe the actual bytes')
        pieces.extend((raw[new_at:hunk['new_offset']], old))
        new_at, old_at = hunk['new_offset'] + len(new), hunk['old_offset'] + len(old)
    pieces.append(raw[new_at:])
    restored = b''.join(pieces)
    if len(restored) != original['bytes'] or sha256(restored).hexdigest() != original['sha256']:
        raise ValueError('successor patch does not restore the complete original identity')
    return restored


def _adapter_definitions(raw):
    module, lines = ast.parse(raw), raw.splitlines(keepends=True)
    def pin(node):
        first = min([node.lineno] + [item.lineno for item in node.decorator_list]) - 1
        body = b''.join(lines[first:node.end_lineno])
        return {'bytes': len(body), 'sha256': sha256(body).hexdigest()}
    result = {node.name: pin(node) for node in module.body
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    frame = next(node for node in module.body
                 if isinstance(node, ast.ClassDef) and node.name == 'StoreArtifactProfileFrame')
    for node in frame.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                '_global', 'argument', 'effect', '_release', '_confirmed_foreign_failure'):
            result['StoreArtifactProfileFrame.' + node.name] = pin(node)
    return result


def _review_adapter(original, restored, current, records):
    expected = dict(original['unchanged_adapter_definitions'])
    if len(expected) != 21 or _adapter_definitions(restored) != expected:
        raise ValueError('restored complete adapter differs from original definition inventory')
    if type(records) is not dict or set(records) != {'_context_special'}:
        raise ValueError('adapter definition successor changes its exact reviewed scope')
    item = records['_context_special']
    if (type(item) is not dict or set(item) != {'old', 'new'}
            or item['old'] != expected['_context_special']
            or type(item['new']) is not dict or set(item['new']) != {'bytes', 'sha256'}):
        raise ValueError('adapter definition successor original identity differs')
    expected['_context_special'] = item['new']
    if _adapter_definitions(current) != expected:
        raise ValueError('adapter changes a definition beyond the exact protocol successor')
    # Expected values come from the immutable original and fixed-hash fixture.
    # Actual source is compared only; it is never normalized or used as expected.
    return expected, {'_context_special': item}


def admit_composition(original_value):
    original_bytes = ORIGINAL.read_bytes()
    if sha256(original_bytes).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('original Store successor inventory changed')
    inventory = json.loads(original_bytes)
    if original_value != inventory:
        raise ValueError('successor caller original inventory differs')
    originals = {path: inventory['unchanged_files'][path] for path in SOURCE_PATHS}
    originals.update({path: inventory['shared_dependency_review'][path] for path in SHARED_PATHS})
    originals[ADAPTER_PATH] = ADAPTER_ORIGINAL
    originals.update(COMPANION_ORIGINALS)
    captured = {path: (ROOT / path).read_bytes() for path in PATHS}
    if all(len(captured[path]) == originals[path]['bytes']
           and sha256(captured[path]).hexdigest() == originals[path]['sha256'] for path in PATHS):
        definitions = dict(inventory['unchanged_adapter_definitions'])
        if _adapter_definitions(captured[ADAPTER_PATH]) != definitions:
            raise ValueError('original complete adapter differs from its definition inventory')
        if (ORIGINAL.read_bytes() != original_bytes
                or any((ROOT / path).read_bytes() != captured[path] for path in PATHS)):
            raise ValueError('original Store composition changed during admission')
        return {'source_adjustments': {}, 'shared_adjustments': {},
                'shared_dependency_review': dict(inventory['shared_dependency_review']),
                'adapter_source_adjustments': {}, 'companion_source_adjustments': {},
                'adapter_definition_adjustments': {},
                'adapter_definition_review': definitions}
    frozen = FIXTURE.read_bytes()
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('reviewed Store successor provenance fixture changed')
    value = json.loads(frozen)
    if (value.get('schema') != 'hepta.hia.store-delivery-successor.v2'
            or value.get('state') != 'FROZEN_COMPOSED_SOURCE'
            or value.get('original_commit') != 'c0195643083e1d4c68679237edfa77143dc7b1c6'
            or type(value.get('files')) is not dict or set(value['files']) != set(PATHS)
            or any(type(value.get(name)) is not int or value[name] != expected
                   for name, expected in (
                       ('composition_source_count', 13), ('source_adjustment_count', 4),
                       ('shared_adjustment_count', 7), ('adapter_source_adjustment_count', 1),
                       ('companion_source_adjustment_count', 1),
                       ('unchanged_original_file_count', 85),
                       ('unchanged_shared_dependency_count', 15),
                       ('original_definition_count', 21)))):
        raise ValueError('Store successor provenance remains draft or changes scope')
    # A successor belongs to one complete reviewed composition. A partially
    # reverted mixture cannot borrow admission from another changed file.
    # There is no process-global cache: every admission binds all thirteen complete files.
    restored = {path: reverse_exact(captured[path], value['files'][path], originals[path])
                for path in PATHS}
    definitions, definition_adjustments = _review_adapter(inventory, restored[ADAPTER_PATH],
        captured[ADAPTER_PATH], value.get('adapter_definition_successors'))
    if (FIXTURE.read_bytes() != frozen or ORIGINAL.read_bytes() != original_bytes
            or any((ROOT / path).read_bytes() != captured[path] for path in PATHS)):
        raise ValueError('successor composition changed during admission')
    composition = {path: value['files'][path]['new_sha256'] for path in PATHS}
    adjustments = {path: {'path': path, 'original_sha256': sha256(restored[path]).hexdigest(),
        'current_sha256': value['files'][path]['new_sha256'],
        'current_bytes': value['files'][path]['new_bytes'],
        'reversible_patch_fixture_sha256': FIXTURE_SHA256,
        'scope': 'exact reviewed D5, transaction owner, journal cleanup, service artifact, service read, weak SQL, context protocol, Bootstrap, Budget resource and worker unknown-terminal successor',
        'composition_sha256': composition} for path in PATHS}
    shared = dict(inventory['shared_dependency_review'])
    for path in SHARED_PATHS:
        # Return the fixed, independently reviewed literal pins only after
        # the complete composition matched; never derive expected from disk.
        shared[path] = {'bytes': value['files'][path]['new_bytes'],
                        'sha256': value['files'][path]['new_sha256']}
    return {'source_adjustments': {path: adjustments[path] for path in SOURCE_PATHS},
            'shared_adjustments': {path: adjustments[path] for path in SHARED_PATHS},
            'shared_dependency_review': shared,
            'adapter_source_adjustments': {ADAPTER_PATH: adjustments[ADAPTER_PATH]},
            'companion_source_adjustments': {path: adjustments[path] for path in COMPANION_ORIGINALS},
            'adapter_definition_adjustments': definition_adjustments,
            'adapter_definition_review': definitions}
