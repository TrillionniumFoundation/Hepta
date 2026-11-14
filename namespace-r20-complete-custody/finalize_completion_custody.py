"""Finalize declared custody after real full-GET receipts; no product run."""
from pathlib import Path
import base64
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parent


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    folder = ROOT / 'complete-custody-r1'
    plan_raw = (folder / 'PLAN.json').read_bytes()
    plan = json.loads(plan_raw)
    leaves = []
    for row in plan['leaves_to_reuse_or_publish']:
        receipt_path = ROOT / 'git-custody' / (row['git_blob'] + '.VERIFIED.json')
        receipt = json.loads(receipt_path.read_bytes())
        assert receipt['status'] == 'FULL_REMOTE_BYTES_EQUAL'
        assert all(receipt['pin'][k] == row[k] for k in ('bytes', 'sha256', 'git_blob'))
        path = Path(row['path'])
        assert identity(path.read_bytes()) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
        assert stat.S_IMODE(path.stat().st_mode) == row['mode']
        leaves.append({**row, 'logical_path': str(path.relative_to(ROOT)),
                       'full_get_receipt': str(receipt_path),
                       'full_get_receipt_identity': identity(receipt_path.read_bytes()),
                       'transport_mode': receipt['mode']})
    chunks = []
    for index, row in enumerate(plan['zip_transport']):
        packet = json.loads(Path(row['path']).read_bytes())
        assert packet['index'] == index and packet['offset'] == sum(map(len, chunks))
        raw = base64.b64decode(packet['payload_base64'], validate=True)
        assert identity(raw) == packet['decoded'] == row['decoded']
        chunks.append(raw)
    zip_raw = b''.join(chunks)
    assert identity(zip_raw) == {k: plan['original_zip'][k] for k in ('bytes', 'sha256', 'git_blob')}
    assert zip_raw == Path(plan['original_zip']['path']).read_bytes()
    for row in plan['harness_16_already_full_get']:
        receipt = Path(row['existing_full_get_receipt'])
        assert identity(receipt.read_bytes()) == row['receipt_identity']
    original_recipe = Path(plan['historical_author_recipe']['path']).read_bytes()
    assert identity(original_recipe) == {k: plan['historical_author_recipe'][k] for k in ('bytes', 'sha256', 'git_blob')}
    assert json.loads(original_recipe)['ids_are_locally_computed_not_remote_ack'] is True
    result = {
        'schema': 'hepta.namespace-r20-terminal-and-author-custody-complete.v1',
        'status': 'ALL_DECLARED_TEXT_OBJECTS_FULL_GET_ORIGINAL_ZIP_RECONSTRUCTS_EXACTLY',
        'repository': 'TrillionniumFoundation/Hepta', 'refs_changed_by_this_completion': False,
        'plan': {'path': str(folder / 'PLAN.json'), **identity(plan_raw)},
        'finalizer': {'path': str(Path(__file__).resolve()), **identity(Path(__file__).read_bytes())},
        'historical_author_recipe': plan['historical_author_recipe'],
        'historical_recipe_bytes_and_statement_unchanged': True,
        'historical_author_logical_leaves': 21,
        'terminal_and_author_logical_leaves': len(leaves),
        'unique_text_blob_count': len({row['git_blob'] for row in leaves}),
        'leaves': leaves,
        'previous_published_harness_16_reused': plan['harness_16_already_full_get'],
        'published_harness_commit': '8b6481c1a2d784d3c590291957c5268866d8d8bd',
        'published_harness_tree': '2bc8b7c0bf4489a43ccde370e8c60bfd374f8e30',
        'run': 43569339563, 'job': 132370075133,
        'workflow_outcome': 'SUCCESS_DIAGNOSTIC_COMPLETION',
        'original_method_outcome': 'FAIL', 'original_method_tests_run': 1,
        'original_method_failures': 1, 'original_method_errors': 0,
        'qualification': False, 'whole_native': False,
        'product_executions_during_custody': 0,
        'original_zip': plan['original_zip'],
        'original_zip_direct_binary_blob_was_not_posted': True,
        'original_zip_durable_representation': 'Seven UTF-8 JSON objects containing exact strict-base64 spans; all have real full-GET receipts.',
        'zip_transport': plan['zip_transport'], 'restore': plan['restoration'],
        'original_zip_members': 46, 'original_zip_uncompressed_bytes': 8003833,
        'original_directory_entries': 0,
        'restored_parent_directories_have_no_claimed_original_mode': True,
        'limits': [
            'The original failed method is not converted into PASS by successful custody.',
            'The first Python 3.12 offline AST-verifier failure is retained; only the same verifier was repeated under actual 3.14.',
            'All 21 historical local-only author leaves now have verified repository objects without changing the original historical recipe.',
            'This closes the declared collection, not every unlisted local API-sidecar directory.',
        ],
    }
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with (folder / 'COMPLETE-RECIPE.json').open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'path': str(folder / 'COMPLETE-RECIPE.json'), **identity(raw),
                      'logical_leaves': len(leaves), 'zip_parts': len(chunks),
                      'harness_reused': 16, 'product_executions': 0}))


if __name__ == '__main__':
    main()
