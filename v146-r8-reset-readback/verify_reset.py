"""Verify frozen author bytes from fresh Git GETs after workspace loss."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import sys
import zlib

ROOT = Path(__file__).resolve().parent


def pin(raw, mode=0o644):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
        'mode': mode, 'git_mode': '100755' if mode & 0o111 else '100644'}


def load(path):
    return json.loads(Path(path).read_bytes())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def main():
    index = load(ROOT/'FRESH-GET-INDEX.json')
    assert len(index['entries']) == 27
    blobs, observations = {}, []
    for name, row in index['entries'].items():
        response = load(row['path'])
        assert response['isError'] is False
        raw = response['structuredContent']['content'].encode('utf-8')
        assert pin(raw, row['expected']['identity']['mode']) == row['expected']['identity']
        blobs[name] = raw
        observations.append({'name': name, 'identity': row['expected']['identity'],
            'fresh_response_path': row['path'], 'fresh_full_GET_equal_fixed_identity': True})
    recipe = json.loads(blobs['MOUNT-RECIPE.json'])
    assert len(recipe['entries']) == 26
    assert {row['path'] for row in recipe['entries']} == set(blobs) - {'MOUNT-RECIPE.json'}
    for row in recipe['entries']:
        actual = pin(blobs[row['path']], row['filesystem_mode'])
        assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256']
        assert actual['git_blob'] == row['blob_sha'] == row['git_blob']
        assert actual['git_mode'] == row['mode']
    assert sum(len(raw) for name, raw in blobs.items() if name != 'MOUNT-RECIPE.json') == 5391220
    capsule_index = json.loads(blobs['CAPSULE-INDEX.json'])
    pieces = []
    for row in capsule_index['spans']:
        wrapper = json.loads(blobs['author-parts/part-%03d.json' % row['index']])
        raw = base64.b64decode(wrapper['base64'], validate=True)
        assert pin(raw) == row['raw_identity'] == wrapper['identity']
        assert row['offset'] == wrapper['offset'] == sum(map(len, pieces))
        pieces.append(raw)
    capsule = b''.join(pieces)
    assert pin(capsule) == capsule_index['capsule_identity']
    envelope = json.loads(capsule)
    compressed = base64.b64decode(envelope['base64'], validate=True)
    assert pin(compressed) == envelope['compressed_identity']
    d = zlib.decompressobj()
    raw_inner = d.decompress(compressed) + d.flush()
    assert d.eof and not d.unused_data and not d.unconsumed_tail
    assert pin(raw_inner) == envelope['inner_identity'] == capsule_index['inner_identity']
    inner = json.loads(raw_inner)
    objects = {}
    for digest, row in inner['objects'].items():
        raw = base64.b64decode(row['base64'], validate=True)
        assert pin(raw) == row['identity'] and pin(raw)['sha256'] == digest
        objects[digest] = raw
    members = {}
    for name, row in inner['files'].items():
        path = PurePosixPath(name)
        assert not path.is_absolute() and path.as_posix() == name and '..' not in path.parts
        raw = objects[row['pool_key']]
        assert pin(raw, row['identity']['mode']) == row['identity']
        members[name] = raw
    assert len(members) == 147 and len(objects) == 88
    assert sum(name.startswith('author-r1/') for name in members) == 64
    assert sum(name.startswith('author-r2/') for name in members) == 64
    plan = json.loads(members['author-r2/EXECUTION-PLAN.json'])
    oracle = json.loads(members['author-r2/ORACLE-RESTORE-PLAN.json'])
    assert members['author-r2/EXECUTION-PLAN.json'] == blobs['execution-plan.json']
    assert members['author-r2/ORACLE-RESTORE-PLAN.json'] == blobs['restore-plan.json']
    for item in (plan, oracle):
        fixed = dict(item)
        authority = fixed.pop('authorization_pin')
        assert hashlib.sha256(encode(fixed)).hexdigest() == authority
    assert len(plan['controls']) == 61 and len(plan['fixed_inputs']) == 948
    for name, identity in plan['controls'].items():
        assert pin(members['author-r2/'+name], identity['mode']) == identity
    assert len(oracle['required']) == 496 and len(oracle['restore_order']) == 136
    assert len(json.loads(members['author-r2/FROZEN-3180-SOURCE.json'])) == 3180
    old_proof = json.loads(blobs['PUBLICATION-READBACK.json'])
    supporting = {}
    for name, row in old_proof['supporting_originals'].items():
        raw = base64.b64decode(row['base64'], validate=True)
        assert pin(raw, row['identity']['mode']) == row['identity']
        supporting[name] = row['identity']
    assert set(supporting) == {'AUTHOR-TOOL-RESULTS.json', 'PUBLICATION-ORCHESTRATOR.js', 'verify_publication.py'}
    state = load(ROOT/'PRESERVED-STATE.json')
    metadata = load(ROOT/'SPACE-OBSERVATIONS.json')
    assert state['inflight'] is None and len(state['published_receipts']) == 27
    report = {'schema': 'hepta.environment-reset.complete-author-readback.v1',
        'status': 'ALL_26_LEAVES_PLUS_RECIPE_FRESH_GIT_BYTES_RECOVERABLE',
        'diagnostic_python': {'executable': sys.executable, 'version': sys.version},
        'actual3_14_product_qualification': False,
        'fresh_Git_objects': 27, 'author_leaf_bytes': 5391220,
        'recipe_identity': pin(blobs['MOUNT-RECIPE.json']),
        'full_capsule_identity': pin(capsule), 'decoded_author_files': 147,
        'decoded_unique_author_files': 88, 'R1_files': 64, 'R2_files': 64,
        'execution_controls': 61, 'fixed_input_references': 948,
        'supporting_original_code_and_tool_results': supporting,
        'fixed_plan': pin(blobs['execution-plan.json']),
        'fixed_oracle_plan': pin(blobs['restore-plan.json']),
        'frozen_source_manifest_files': 3180, 'original_oracle_manifest_entries': 496,
        'actual_frozen_source_or_runtime_or_original_oracle_payload_recreated': False,
        'author_code_or_authored_payload_gap': False,
        'physical_input_availability_after_reset': 'Not established. The948 pinned inputs and complete3180 runtime/source payload are references, not a claim that the original files survived. No fixed-path runner may be launched on this result.',
        'other_unpersisted_items': [
            'The metadata-only storage inspection draft was aborted before dispatch; it was never a file or execution. Its proposed full per-file metadata output and fd/maps check never existed.',
            'Pre-reset candidate aggregate counts and metadata-inventory hashes are saved as tool-output observations. No fresh candidate byte hash or deletion-readiness result is claimed.',
            'Original full local API response files are absent after reset. Their identities and successful receipts survive in the public proof and V8 state; fresh GET responses are separately stored, not relabeled as old originals.'
        ],
        'environment_observation': state['independent_observation'],
        'cancelled_storage_audit': metadata,
        'fresh_objects': observations,
        'old_paths_recreated': 0, 'oracle_restorations': 0, 'deleted_files': 0,
        'product_executions': 0, 'CI_runs': 0, 'refs_written': 0,
        'scope': 'Fresh immutable Git author verification and cancellation record only; no product result or historical qualification is changed.'}
    raw = encode(report)
    with (ROOT/'RESET-READBACK.json').open('xb') as f:
        f.write(raw)
    print(json.dumps({'status': report['status'], 'proof': pin(raw),
        'decoded_author_files': 147, 'author_code_gap': False,
        'products': 0, 'old_paths_recreated': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
