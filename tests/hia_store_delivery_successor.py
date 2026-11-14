"""Exact, reversible provenance for five explicitly reviewed Store successors.

The original c019 inventory is never rewritten. A draft is never an admission;
final composition needs a fixed fixture hash, all old/new hashes and the exact
byte splice patch. Every other original file still uses its old byte check.
"""
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/store_delivery_successor_provenance.json'
FIXTURE_SHA256 = 'dbfd600122d9bb05ff14cc21946dc8f6444226e7b1fe806496d6277fe127b4a5'
ORIGINAL = ROOT / 'tests/fixtures/store_native_delivery_original_c019.json'
ORIGINAL_SHA256 = '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'
SOURCE_PATHS = ('hepta/artifact_publication_native.py', 'hepta/hia_agent_store.py',
                'hepta/hia_store_lifecycle_selection.py')
SHARED_PATHS = ('hepta/hia_native_delivery.py', 'hepta/hia_store_lifecycle_native.py')
PATHS = SOURCE_PATHS + SHARED_PATHS


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


def admit_composition(original_value):
    original_bytes = ORIGINAL.read_bytes()
    if sha256(original_bytes).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('original Store successor inventory changed')
    inventory = json.loads(original_bytes)
    if original_value != inventory:
        raise ValueError('successor caller original inventory differs')
    originals = {path: inventory['unchanged_files'][path] for path in SOURCE_PATHS}
    originals.update({path: inventory['shared_dependency_review'][path] for path in SHARED_PATHS})
    captured = {path: (ROOT / path).read_bytes() for path in PATHS}
    if all(len(captured[path]) == originals[path]['bytes']
           and sha256(captured[path]).hexdigest() == originals[path]['sha256'] for path in PATHS):
        if (ORIGINAL.read_bytes() != original_bytes
                or any((ROOT / path).read_bytes() != captured[path] for path in PATHS)):
            raise ValueError('original Store composition changed during admission')
        return {'source_adjustments': {}, 'shared_adjustments': {},
                'shared_dependency_review': dict(inventory['shared_dependency_review'])}
    frozen = FIXTURE.read_bytes()
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('reviewed Store successor provenance fixture changed')
    value = json.loads(frozen)
    if (value.get('schema') != 'hepta.hia.store-delivery-successor.v1'
            or value.get('state') != 'FROZEN_COMPOSED_SOURCE'
            or value.get('original_commit') != 'c0195643083e1d4c68679237edfa77143dc7b1c6'
            or type(value.get('files')) is not dict or set(value['files']) != set(PATHS)):
        raise ValueError('Store successor provenance remains draft or changes scope')
    # A successor belongs to one complete reviewed composition. A partially
    # reverted mixture cannot borrow admission from another changed file.
    # There is no process-global cache: every admission binds all five bytes.
    restored = {path: reverse_exact(captured[path], value['files'][path], originals[path])
                for path in PATHS}
    if (FIXTURE.read_bytes() != frozen or ORIGINAL.read_bytes() != original_bytes
            or any((ROOT / path).read_bytes() != captured[path] for path in PATHS)):
        raise ValueError('successor composition changed during admission')
    composition = {path: value['files'][path]['new_sha256'] for path in PATHS}
    adjustments = {path: {'path': path, 'original_sha256': sha256(restored[path]).hexdigest(),
        'current_sha256': value['files'][path]['new_sha256'],
        'current_bytes': value['files'][path]['new_bytes'],
        'reversible_patch_fixture_sha256': FIXTURE_SHA256,
        'scope': 'exact reviewed D5 and transaction source successor',
        'composition_sha256': composition} for path in PATHS}
    shared = dict(inventory['shared_dependency_review'])
    for path in SHARED_PATHS:
        # Return the fixed, independently reviewed literal pins only after
        # the complete composition matched; never derive expected from disk.
        shared[path] = {'bytes': value['files'][path]['new_bytes'],
                        'sha256': value['files'][path]['new_sha256']}
    return {'source_adjustments': {path: adjustments[path] for path in SOURCE_PATHS},
            'shared_adjustments': {path: adjustments[path] for path in SHARED_PATHS},
            'shared_dependency_review': shared}
