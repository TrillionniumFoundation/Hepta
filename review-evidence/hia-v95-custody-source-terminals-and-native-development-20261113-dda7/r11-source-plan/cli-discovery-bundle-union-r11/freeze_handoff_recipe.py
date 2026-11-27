"""Build a mount recipe from actual immutable-blob ACK/full-GET receipts."""
from pathlib import Path
import datetime
import hashlib
import json

ROOT = Path(__file__).resolve().parent


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': '100644'}


files = json.loads((ROOT / 'HANDOFF-FILE-IDENTITIES.json').read_bytes())
receipts = {}
for path in sorted(ROOT.rglob('*.GIT-VERIFIED.json')):
    value = json.loads(path.read_bytes())
    if value.get('create_ack') is True and value.get('full_get_verified') is True:
        receipts.setdefault(value['blob'], []).append((path, value))
verified, entries = [], []
for row in files:
    raw = Path(row['path']).read_bytes()
    observed = identity(raw)
    assert all(observed[key] == row[key] for key in ('bytes', 'sha256', 'git_blob'))
    choices = receipts[row['git_blob']]
    path, receipt = choices[0]
    assert receipt['bytes'] == row['bytes'] and receipt['sha256'] == row['sha256']
    verified.append({'path': row['name'], **observed,
                     'create_ack': True, 'full_get_verified': True,
                     'actual_content_addressed_receipt_path': path.relative_to(ROOT).as_posix(),
                     'shared_identical_blob_receipt': receipt['path'] != row['path']})
    entries.append({'path': 'cli-discovery-bundle-union-r11/' + row['name'],
                    'mode': '100644', 'type': 'blob', 'sha': row['git_blob']})
readback = {'schema': 'hia.r11.immutable-objects-full-readback.v1',
            'verified_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'files': verified, 'count': len(verified), 'product_refs_changed': False,
            'source_generation_executed': False, 'product_tests_executed': False,
            'receipt_rule': 'ACK/full GET proves the immutable blob, not a local filename. Identical empty stdout/stderr content may use the same real blob receipt.'}
(ROOT / 'GIT-FULL-READBACK.json').write_bytes(encode(readback))
recipe = {
    'schema': 'hia.immutable-evidence-mount-recipe.v1',
    'status': 'AUTHORED_PLAN_FROZEN_NOT_GENERATED_NOT_QUALIFIED',
    'local_directory': str(ROOT), 'entries': entries, 'count': len(entries),
    'base_plan': '035d0681a26bb6398d1def298ee9f990b7b4d7ff',
    'plan': 'c19cd878115b1e9d3d4b81024838b36575a6bf30',
    'base_source_tree': 'e21ae3f2e4e4131db928beb7cf7780f0c79b1e44',
    'authored_source_tree': '4561802d6b5548e8933913716eedf01f4189d7e3',
    'source_files': 3100, 'changed_files': 26, 'new_source_files': 17,
    'packets': 64, 'authors': 448, 'allowed_overrides': 174,
    'source_contract': 1324, 'generators': 123, 'selectors': 229,
    'expected_Source_methods': 1329, 'Source_count_is_static_not_executed': True,
    'native_steps': 121, 'original_120_commands_conditions_budgets_preserved': True,
    'new_qualifier_groups': {'original_cli': 43, 'routing': 9},
    'all_listed_objects_create_ACK_and_full_GET_verified': True,
    'generation_executed': False, 'product_tests_executed': False,
    'current_source_cold_executed': False, 'default_changed': False, 'whole_cli_native': False,
    'full_manifests': {'immutable_capsule': 'cbe5f8c8e0c6c17afdf9f676cf362ea8550d003a',
                       'decoded_members': ['base_manifest', 'source_manifest'],
                       'base_paths': 3083, 'source_paths': 3100},
    'complete_author_table': {
        'local_path': str(ROOT / 'harness/inputs/AUTHORING-R11.json'),
        **identity((ROOT / 'harness/inputs/AUTHORING-R11.json').read_bytes()),
        'direct_git_object_created': False,
        'immutable_complete_index': 'd871d7d68a5175afbbeb87f063d0cf7975388c3a',
        'lossless_full_text_sources': 'All 448 exact after texts are in their index-selected immutable source packets from the fixed 64-packet plan; no text is inferred.',
    },
    'prior_development_raw_boundary': 'The cumulative component retains the actual prior failure/PASS history. Its complete multi-revision raw archive is still local; this R11 recipe does not claim that separate archive is Git-persisted.',
    'full_readback_receipt': identity((ROOT / 'GIT-FULL-READBACK.json').read_bytes()),
}
(ROOT / 'MOUNT-RECIPE.json').write_bytes(encode(recipe))
for name in ('GIT-FULL-READBACK.json', 'MOUNT-RECIPE.json'):
    print(json.dumps({'path': str(ROOT / name), **identity((ROOT / name).read_bytes())}))
