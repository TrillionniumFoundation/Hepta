"""Preserve all available evidence without recreating the UNKNOWN blob."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-r4b-actual-custody-r1')
OLD = ROOT / 'publication'
OUT = ROOT / 'publication-hold-r1'
PREFIX = 'experiments/hia_cli_json_graph_20261112/c-runtime-lifetime-actual-r4b-publication-hold-r1'
UNKNOWN = '5ac0f5afa89199cba697ff149366008c6f0bbd3e'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def row(path, relative):
    raw = path.read_bytes()
    return {'absolute': str(path), 'path': relative, 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(), 'git_blob': blob(raw),
            'git_mode': '100644', 'encoding': 'utf-8',
            'repository_path': PREFIX + '/' + relative}


def create(path, value):
    raw = wire(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)
    assert path.read_bytes() == raw


def tree_hash(leaves):
    root = {}
    for name, item in leaves.items():
        parts = name.split('/')
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        node[parts[-1]] = (item['mode'], item['sha'])

    def visit(node):
        items = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode, digest, key = '40000', visit(value), name.encode() + b'/'
            else:
                mode, digest = value
                key = name.encode()
            items.append((key, mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)))
        raw = b''.join(item[1] for item in sorted(items))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return visit(root)


def main():
    OUT.mkdir(mode=0o700)
    original = json.loads((OLD / 'PLAN.json').read_bytes())
    assert original['new_leaves'] == 205 and len(original['new_blobs']) == 139
    assert original['new_blobs'][6]['git_blob'] == UNKNOWN
    inventory = json.loads((OLD / 'BLOB-PERSISTENCE-READBACK.json').read_bytes())
    assert inventory['created'] == 138 and inventory['total'] == 139
    sdk_files = sorted(p for p in OLD.iterdir() if p.is_file())
    journal = []
    for path in sdk_files:
        raw = path.read_bytes()
        journal.append({'name': path.name, 'bytes': len(raw),
                        'sha256': hashlib.sha256(raw).hexdigest(),
                        'git_blob': blob(raw), 'original_utf8': raw.decode('utf-8')})
    create(OUT / 'PUBLICATION-JOURNAL.originals.json', {
        'schema': 'hia.cli.r4b.original-publication-journal.v1',
        'original_directory': str(OLD), 'count': len(journal), 'files': journal,
        'original_205_leaf_plan_unchanged': True,
        'unknown_blob_body_not_embedded_or_recreated': True})
    create(OUT / 'PUBLICATION-HOLD.json', {
        'schema': 'hia.cli.r4b.actual-publication-hold.v1',
        'status': 'PUBLICATION_HOLD_SINGLE_UNKNOWN_READONLY_AUDITOR_BLOB',
        'qualification_status': 'FINITE_C_RUNTIME_LIFETIME_PASS_ONLY',
        'parent_commit': original['parent_commit'], 'parent_tree': original['parent_tree'],
        'new_prefix': PREFIX, 'original_frozen_prefix': original['prefix'],
        'original_frozen_expected_tree': original['expected_tree'],
        'original_frozen_new_leaves': 205, 'original_plan_executed_tree_or_commit': False,
        'available_original_plan_leaves': 204,
        'unknown': original['new_blobs'][6],
        'unknown_mutation_response': 'RemoteProtocolError: Server disconnected without sending a response.',
        'following_exact_readonly_queries': 3, 'all_readonly_queries_returned': 404,
        'unknown_mutation_replayed': False, 'unknown_object_recreated_by_other_request': False,
        'readonly_auditor_source_body_in_this_commit': False,
        'auditor_source_still_retained_locally': True,
        'audit_result_and_full_run_originals_and_archive_available': True,
        'complete_archive_originals': 188, 'complete_archive_original_bytes': 16947670,
        'actual_originals': 114, 'source28_originals_separately_complete': True,
        'runtime_8_and_lifetime_10_PASS': True, 'HIA_returns': 48, 'C_pump_calls': 11,
        'root_independent_complete_original_custody_commit': '8f6c9a4971f910f5f73b685be4f266397630da9b',
        'root_commit_readback_not_independently_repeated_by_this_publisher': True,
        'prior_r1_r2b_r3_HOLDs_preserved': True,
        'original_17_CLI_and_46_traces_executed': False,
        'whole_graph_or_body_qualification': False, 'current_v92_matching': False,
        'new_product_execution': False, 'default_changed': False,
        'authorizing_parent_instruction': 'Preserve original 205-leaf plan and UNKNOWN records; publish available 204 leaves plus explicit gap evidence under a new prefix, sole parent 6e704; do not recreate UNKNOWN object.'})

    base_path = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4b/publication/FULL-TREE.provider.json')
    base = json.loads(base_path.read_bytes())
    leaves = {x['path']: {'mode': x['mode'], 'sha': x['sha']} for x in base['tree'] if x['type'] == 'blob'}
    assert len(leaves) == 6719 and tree_hash(leaves) == original['parent_tree']
    available = {x['sha'] for x in leaves.values()}
    available.update(x['git_blob'] for x in inventory['rows'] if x['status'].startswith('ACK'))
    additions = []
    for item in original['all_additions']:
        if item['git_blob'] == UNKNOWN:
            continue
        item = dict(item)
        raw = Path(item['absolute']).read_bytes()
        assert len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256']
        assert blob(raw) == item['git_blob']
        item['repository_path'] = PREFIX + '/' + item['path']
        additions.append(item)
    assert len(additions) == 204
    for name in ('PLAN.json', '006.INTENT.json', '006.ACK.json',
                 '006.RECONCILE-1.sdk.json', '006.RECONCILE-2.sdk.json',
                 '006.RECONCILE-3.sdk.json', 'BLOB-PERSISTENCE-READBACK.json',
                 'PAYLOAD-READ-LIMIT.original.json'):
        additions.append(row(OLD / name, 'original-publication-journal/' + name))
    for name in ('PUBLICATION-JOURNAL.originals.json', 'PUBLICATION-HOLD.json'):
        additions.append(row(OUT / name, name))
    additions.append(row(Path(__file__).resolve(), 'prepare_publication_hold.py'))
    unique = {}
    for item in additions:
        assert item['repository_path'] not in leaves and item['git_blob'] != UNKNOWN
        leaves[item['repository_path']] = {'mode': '100644', 'sha': item['git_blob']}
        if item['git_blob'] not in available:
            unique.setdefault(item['git_blob'], item)
    plan = {'schema': 'hia.cli.r4b.hold-publication-plan.v1',
            'parent_commit': original['parent_commit'], 'parent_tree': original['parent_tree'],
            'prefix': PREFIX, 'parent_leaves': 6719, 'new_leaves': len(additions),
            'full_leaves': len(leaves), 'expected_tree': tree_hash(leaves),
            'all_additions': additions, 'new_blobs': list(unique.values()),
            'unknown_excluded_and_not_recreated': UNKNOWN,
            'tree_elements': [{'path': x['repository_path'], 'mode': '100644', 'type': 'blob', 'sha': x['git_blob']} for x in additions]}
    create(OUT / 'publication' / 'PLAN.json', plan)
    print(json.dumps({'new_leaves': len(additions), 'full_leaves': len(leaves),
                      'new_blobs': len(unique), 'expected_tree': plan['expected_tree'],
                      'prefix': PREFIX, 'journal_originals': len(journal),
                      'new_blob_bytes': sum(x['bytes'] for x in unique.values())}))


if __name__ == '__main__':
    main()
