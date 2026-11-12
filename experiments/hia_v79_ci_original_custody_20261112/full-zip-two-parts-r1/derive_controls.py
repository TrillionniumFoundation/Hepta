"""Derive a new, unexecuted v79 custody control from the exact executed 970 control.

Only immutable evidence identities, operational names and the final byte range
change. This script parses Python but imports no project or custody module.
"""
from pathlib import Path
from hashlib import sha1, sha256
import ast
import difflib
import json
import os
import shutil
import sys

ROOT = Path(__file__).resolve().parent
REFERENCE = ROOT / 'reference'
OUT = ROOT / 'control'
OLD_PREFIX = 'experiments/hia_970_ci_original_custody_20261112/full-zip-two-parts-r1'
PREFIX = 'experiments/hia_v79_ci_original_custody_20261112/full-zip-two-parts-r1'
BASE_COMMIT = '75d8de12f462bbeab29364577d3575c30fc12626'
BASE_TREE = 'de78b3a31624f1eae7a7f77aadd683e6f927b970'
SOURCE_COMMIT = '9739fb896037aedd9f29dae178c6ae1c8bc31827'
SOURCE_TREE = '83a43be6fd510e55c4843cfa8a00aa4889b246cf'
ORIGINAL_SHA = 'b2a546f720b3a29b71a3f6372cd0f122adb1c6bbe4593aaee3b9d135175aa471'
ORIGINAL_BYTES = 614221066
PARTS = [
    {'ordinal': 0, 'offset': 0, 'bytes': 314572800, 'name': 'part-00.bin'},
    {'ordinal': 1, 'offset': 314572800, 'bytes': 299648266, 'name': 'part-01.bin'},
]
SUBSTITUTIONS = [
    ('exact970 historical', 'exact v79 historical'),
    ('hia.actions.970-full-original-two-parts-', 'hia.actions.v79-full-original-two-parts-'),
    ('hia.970-original-zip-part.v1', 'hia.v79-original-zip-part.v1'),
    ('284854451', '299648266'),
    ('13911977275', '13929074168'),
    ('599427251', '614221066'),
    ('40e81308484173d36153f6a3014293a78705aa28e8f8f7718dcdd3d87c03f580', ORIGINAL_SHA),
    ('43140734709', '43182678063'),
    ('9704596acc4470bd0042838586602e26bac7b3d1', SOURCE_COMMIT),
    ('c3ca94c57f9bd75f22f2c694e32bca2dfc6b329b', SOURCE_TREE),
]


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def save(name, raw):
    target = OUT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    assert target.read_bytes() == raw


def bodies(raw):
    text = raw.decode()
    lines = text.splitlines(keepends=True)
    tree = ast.parse(raw)
    result = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            first = min([node.lineno] + [x.lineno for x in node.decorator_list])
            result[node.name] = ''.join(lines[first - 1:node.end_lineno])
    return result


def main():
    OUT.mkdir(exist_ok=False)
    old_pins = json.loads((REFERENCE / 'SOURCE-PINS.json').read_bytes())['files']
    changes, exact, inverse = {}, {}, {}
    for name in ('controller.py', 'worker.py', 'guardian.py', 'process_owner_impl.py', 'original_receiver.py'):
        raw = (REFERENCE / name).read_bytes()
        assert pin(raw) == old_pins[name]
        updated = raw.decode()
        occurrences = []
        if name in ('controller.py', 'worker.py'):
            for old, new in SUBSTITUTIONS:
                occurrences.append({'old': old, 'new': new, 'count': updated.count(old)})
                updated = updated.replace(old, new)
        fresh = updated.encode()
        restored = updated
        if name in ('controller.py', 'worker.py'):
            for old, new in reversed(SUBSTITUTIONS):
                restored = restored.replace(new, old)
        assert restored.encode() == raw
        ast.parse(fresh, filename=name)
        save(name, fresh)
        a, b = bodies(raw), bodies(fresh)
        assert set(a) == set(b)
        exact[name] = [key for key in a if a[key] == b[key]]
        inverse[name] = {'whole_file_exact_after_inverse_substitution': True,
                         'all_function_names_and_decorators_preserved': True,
                         'substitutions': occurrences}
        changes[name] = {'before': pin(raw), 'after': pin(fresh)}

    old_policy = json.loads((REFERENCE / 'policy.json').read_bytes())
    policy = dict(old_policy)
    policy['schema'] = 'hia.actions.v79-full-original-two-parts-policy.v1'
    policy['artifact'] = {
        'id': 13929074168, 'bytes': ORIGINAL_BYTES, 'sha256': ORIGINAL_SHA,
        'checkout_commit': SOURCE_COMMIT, 'checkout_tree': SOURCE_TREE,
        'run_id': 43182678063, 'run_attempt': 1, 'job_id': 131062237309,
        'event': 'push', 'workflow_terminal': 'success',
    }
    policy['control_prefix'] = PREFIX
    policy['work_root_name'] = 'hia-v79-full-original-two-parts-r1'
    policy['public_root_name'] = 'hia-v79-full-original-two-parts-public-r1'
    policy['trigger_branch'] = 'codex/hia-v79-full-original-two-parts-run-r1-20261112-e26e'
    policy['parts'] = PARTS
    policy['downstream_acceptance'] = policy['downstream_acceptance'].replace('599427251', str(ORIGINAL_BYTES))
    support_raw = (REFERENCE / 'v79-support.original.json').read_bytes()
    assert pin(support_raw) == {'bytes': 175384,
        'sha256': 'bcf3b58762879d2602b5bd5ca41ddf1592e2ccdb8d200b025c47db318003f071',
        'git_blob': 'f1a41d179c602ed3363058f76e391670fc05c8d6'}
    support = json.loads(support_raw)
    source_map = dict(support['source_identity']['files'])
    source_map['docs/HIA_SELFHOST_CORE_SUPPORT.json'] = sha256(support_raw).hexdigest()
    assert len(source_map) == 798
    policy['source'] = {'head': SOURCE_COMMIT, 'tree': SOURCE_TREE,
        'profile': support['profile'], 'cold_source_count': len(source_map),
        'contract_sha256': sha256(support_raw).hexdigest(),
        'source_manifest_canonical_sha256': sha256(json.dumps(source_map, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()}
    policy['control_files'] = {name: changes[name]['after'] for name in old_policy['control_files']}
    assert policy['limits'] == old_policy['limits']
    assert PARTS[0]['offset'] == 0 and PARTS[1]['offset'] == PARTS[0]['bytes']
    assert sum(row['bytes'] for row in PARTS) == ORIGINAL_BYTES
    assert all(row['bytes'] <= 300 << 20 for row in PARTS)
    assert all(row['bytes'] + policy['limits']['diagnostic_bytes_per_part'] + (2 << 20)
               < policy['limits']['public_part_bytes'] < 512 << 20 for row in PARTS)
    policy_raw = wire(policy)
    save('policy.json', policy_raw)

    template = (REFERENCE / 'workflow-template.yml').read_text()
    workflow_substitutions = [
        (OLD_PREFIX, PREFIX),
        ('HIA 970 complete', 'HIA v79 complete'),
        (old_policy['trigger_branch'], policy['trigger_branch']),
        (old_policy['public_root_name'], policy['public_root_name']),
        (old_policy['work_root_name'], policy['work_root_name']),
        ('hia-970-full-original-part-', 'hia-v79-full-original-part-'),
        (sha256((REFERENCE / 'policy.json').read_bytes()).hexdigest(), sha256(policy_raw).hexdigest()),
    ]
    new_template = template
    for old, new in workflow_substitutions:
        assert old in new_template
        new_template = new_template.replace(old, new)
    undo = new_template
    for old, new in reversed(workflow_substitutions):
        undo = undo.replace(new, old)
    assert undo == template and new_template.count('CONTROL_COMMIT_PLACEHOLDER') == 4
    save('workflow-template.yml', new_template.encode())
    save('derive_controls.py', Path(__file__).read_bytes())
    save('provenance/v79-source-contract.original.json', support_raw)
    receipt_root = ROOT.parent / 'cold-bounded-v80-capsule-review-r1'
    for name in ('v79-run-api.original.json', 'v79-artifacts-api.original.json',
                 'v79-unsupported-artifact-endpoint.original.json'):
        save('provenance/' + name, (receipt_root / name).read_bytes())
    for name in ('official-metadata-0.json', 'official-metadata-1.json', 'official-metadata-2.json'):
        save('provenance/' + name, (ROOT / 'fetch-receipts' / name).read_bytes())
    save('provenance/v79-source-map.json', wire(source_map))
    validation = {
        'schema': 'hia.v79-two-part-local-static-validation.v1',
        'status': 'STATIC_DERIVATION_AND_AST_PASS_NOT_EXECUTED',
        'python_runtime': sys.version, 'base_commit': BASE_COMMIT, 'base_tree': BASE_TREE,
        'base_prefix': OLD_PREFIX, 'requested_source': policy['source'],
        'actual_artifact_readback_executed': False, 'guardian_executed': False,
        'product_executed': False, 'network_transfer_executed': False,
        'exact_function_bodies': exact, 'whole_file_inverse_proof': inverse,
        'unchanged_whole_files': ['guardian.py', 'process_owner_impl.py', 'original_receiver.py'],
        'new_range_arithmetic_pass': True, 'per_public_part_cap_unchanged': 320 << 20,
        'original_custody_900_3_and_transfer720_unchanged': True,
        'original_product_thresholds_changed': False,
        'workflow_inverse_substitutions_exact': True,
        'workflow_commit_placeholders': 4,
        'control_changes': changes,
    }
    save('STATIC-VALIDATION.json', wire(validation))
    save('DELTA.json', wire({'schema': 'hia.v79-two-part-control-delta.v1',
        'status': 'FROZEN_UNEXECUTED_PENDING_REVIEW', 'base_commit': BASE_COMMIT, 'base_tree': BASE_TREE,
        'substitution_table': SUBSTITUTIONS, 'workflow_substitution_table': workflow_substitutions,
        'policy_before': old_policy, 'policy_after': policy,
        'mechanism_changes': [], 'whole_file_inverse_proof': inverse,
        'product_branch_modified': False, 'workflow_triggered': False,
        'v78_original_ref_UNKNOWN_replayed': False}))
    patch = ''
    for name in ('controller.py', 'worker.py', 'policy.json', 'workflow-template.yml'):
        patch += ''.join(difflib.unified_diff((REFERENCE / name).read_text().splitlines(keepends=True),
            (OUT / name).read_text().splitlines(keepends=True),
            fromfile='executed-970/' + name, tofile='unexecuted-v79/' + name))
    save('CONTROL-DELTA.diff', patch.encode())
    print(json.dumps({'output': str(OUT), 'policy': pin(policy_raw),
        'controller': pin((OUT / 'controller.py').read_bytes()),
        'worker': pin((OUT / 'worker.py').read_bytes()),
        'exact_functions': {name: len(values) for name, values in exact.items()},
        'original_artifact_bytes': ORIGINAL_BYTES, 'parts': PARTS}, sort_keys=True))


if __name__ == '__main__':
    main()
