"""Repin exact v89 Git inputs; do not run supply, owners, or products."""
from pathlib import Path
from hashlib import sha1, sha256
import ast
import difflib
import gzip
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OLD = Path('/workspace/scratch/e26ed3e2edcf/cold-v88-full-retained-capsule-repin-r2')
REPOSITORY = Path('/workspace/scratch/e26ed3e2edcf/recovered-Hepta-r1')
HEAD = '784f088fcc5ad81c65de541d54e26d380c86293c'
PURE = 'e4fc00a775dab323758d77a2ef4918fd35585cdc'
TREE = 'd9e8407c70e44a3ea0152b8b4c5eb2ed3833d790'
PREFIX = 'experiments/hia_v89_full_retained_capsule_20261112/r1'
PREVIOUS = 'b2888a0ee47e29f17e080e7c37de429da8ea2ab7'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def write_new(relative, raw):
    path = ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        assert path.read_bytes() == raw, f'Existing different bytes: {relative}'
        return
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def main():
    observed = ROOT / 'plan/source-originals'
    commit_raw = (observed / 'commit-784f088.sdk.json').read_bytes()
    commit = json.loads(json.loads(commit_raw)['structuredContent']['content'])
    original_tree = (observed / 'tree-d9e8407.sdk.json').read_bytes()
    tree = json.loads(json.loads(original_tree)['structuredContent']['content'])
    assert commit['sha'] == HEAD and commit['tree']['sha'] == TREE
    assert [r['sha'] for r in commit['parents']] == [PURE]
    assert tree['sha'] == TREE and tree['truncated'] is False
    rows = {r['path']: r for r in tree['tree']}
    assert len(rows) == len(tree['tree']) == 4616
    by_parent = {}
    for path, row in rows.items():
        assert path and not any(p in ('', '.', '..', '.git') for p in path.split('/'))
        assert row['mode'] in ('040000', '100644', '100755')
        assert row['type'] == ('tree' if row['mode'] == '040000' else 'blob')
        parent, _, name = path.rpartition('/')
        by_parent.setdefault(parent, []).append((name, row))
    recomputed = {}

    def verify(parent):
        body = bytearray()
        for name, row in sorted(by_parent[parent], key=lambda x:
                               (x[0] + ('/' if x[1]['type'] == 'tree' else '')).encode()):
            if row['type'] == 'tree':
                assert verify(row['path']) == row['sha']
            body += row['mode'].lstrip('0').encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(row['sha'])
        value = sha1(b'tree ' + str(len(body)).encode() + b'\0' + body).hexdigest()
        recomputed[parent] = value
        return value

    assert verify('') == TREE
    leaves = [r for r in rows.values() if r['type'] == 'blob']
    assert len(leaves) == 4076 and sum(r['size'] for r in leaves) == 410622569
    reread = {}

    def source_record(path):
        row = rows[path]
        assert row['type'] == 'blob'
        raw = subprocess.run(['git', '-C', str(REPOSITORY), 'cat-file', 'blob', row['sha']],
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        actual = pin(raw)
        assert actual['bytes'] == row['size'] and actual['git_blob_sha1'] == row['sha']
        reread[path] = actual
        return raw, actual

    policy = json.loads((OLD / 'plan/policy.template.json').read_bytes())
    old_policy = json.loads((OLD / 'plan/policy.template.json').read_bytes())
    previous = json.loads((OLD / 'plan/HANDOFF.json').read_bytes())
    unchanged_controls = []
    for name, item in policy['control_files'].items():
        if name == 'supply-plan.json':
            continue
        raw = (OLD / item['path']).read_bytes()
        assert all(pin(raw)[k] == item[k] for k in ('bytes', 'sha256', 'git_blob_sha1'))
        write_new(item['path'], raw)
        unchanged_controls.append({'name': name, **pin(raw)})
    current, reference_changes = {}, []
    for name, row in previous['references'].items():
        raw, actual = source_record(row['source_path'])
        current[name] = {**actual, 'source_path': row['source_path']}
        write_new('reference/' + name, raw)
        if actual['sha256'] != row['sha256']:
            reference_changes.append({'name': name, 'before': row, 'after': current[name]})
    assert [r['name'] for r in reference_changes] == ['hia-core.yml']
    assert (ROOT / 'reference/hia-core.yml').read_bytes() == (observed / 'hia-core.original.yml').read_bytes()
    contract_raw, contract_pin = source_record('docs/HIA_SELFHOST_CORE_SUPPORT.json')
    assert contract_raw == (observed / 'support.original.json').read_bytes()
    contract = json.loads(contract_raw)
    assert len(contract['source_identity']['files']) == 840
    assert set(contract['source_identity']['files']) <= set(rows)
    source_identity = {'commit': HEAD, 'pure_source_commit': PURE, 'tree': TREE,
                       'regular_leaves': 4076, 'regular_leaf_bytes': 410622569,
                       'profile': contract['profile'], 'declared_sources': 840,
                       'contract': contract_pin}
    supply = json.loads((OLD / 'plan/supply-plan.json').read_bytes())
    supply_changes = []
    for path, old_pin in supply['source_pins'].items():
        raw, actual = source_record(path)
        new_pin = {'bytes': actual['bytes'], 'sha256': actual['sha256'], 'git_blob': actual['git_blob_sha1']}
        if old_pin != new_pin:
            supply_changes.append({'path': path, 'before': old_pin, 'after': new_pin})
        supply['source_pins'][path] = new_pin
    assert [r['path'] for r in supply_changes] == ['.github/workflows/hia-core.yml']
    supply.update(source={'head': HEAD, 'tree': TREE}, pure_source_same_tree=PURE,
                  source_leaf_count=4076)
    assert len(supply['source_pins']) == 32
    write_new('plan/supply-plan.json', wire(supply))

    # The runtime code and original schemas/budgets are exact v88 bytes.
    # Only source identities and the separately observed CI record are rebound.
    policy['source'] = source_identity
    policy['ready_for_dispatch'] = False
    policy['scope'] = 'V89_REPIN_DRAFT_ONLY_NO_PRODUCT_EXECUTION_OR_WORKFLOW_TRIGGER'
    policy['intended_branch'] = 'codex/hia-v89-full-retained-run-r1-20261112-e26e'
    policy['source_identity_helper'] = {k: current['hia_core_source_identity.py'][k]
                                        for k in ('bytes', 'sha256', 'git_blob_sha1')}
    for name, row in policy['source_harness'].items():
        row.update(current[name])
    run_raw = (ROOT / 'evidence/standard-ci/run.original.json').read_bytes()
    run = json.loads(run_raw)
    sdk = json.loads((ROOT / 'evidence/standard-ci/run.sdk.json').read_bytes())
    assert sdk['structuredContent']['content'].encode() == run_raw
    assert run['id'] == 43247845814 and run['run_attempt'] == 1
    assert run['head_sha'] == HEAD and run['event'] == 'push'
    assert run['status'] == 'in_progress' and run['conclusion'] is None
    policy['standard_ci'].update(run_id=run['id'], attempt=1, source_commit=HEAD,
        source_tree=TREE, conclusion=None, root_review_commit=None,
        known_status_from_root='OBSERVED_IN_PROGRESS_TERMINAL_UNKNOWN',
        run_record={'path': 'evidence/standard-ci/run.original.json',
                    **{k: pin(run_raw)[k] for k in ('bytes', 'sha256')}})
    assert all(x['job_id'] is None and x['bytes'] is None and x['sha256'] is None
               for x in policy['standard_ci']['job_records'])
    policy['pending'] = [
        'Actual same-head v89 standard source/native terminal success records and Root original-evidence review; this saved observation is in progress.',
        'Final enclosing capsule/control/source peer review, immutable A/B readback and Root one-trigger authorization.',
        'All real supply, original 972d readiness, current cold and full32/5400 remain unexecuted.'
    ]
    for name, item in policy['control_files'].items():
        item.update(pin((ROOT / item['path']).read_bytes()))
    policy['prior_evidence']['source-commit.sdk.json'].update(
        path='plan/source-originals/commit-784f088.sdk.json',
        **{k: pin(commit_raw)[k] for k in ('bytes', 'sha256')})
    for name, item in policy['prior_evidence'].items():
        if name != 'source-commit.sdk.json':
            raw = (OLD / item['path']).read_bytes()
            assert all(pin(raw)[k] == item[k] for k in ('bytes', 'sha256'))
            write_new(item['path'], raw)
    assert policy['limits'] == old_policy['limits']
    assert policy['mandatory_gate_keys'] == old_policy['mandatory_gate_keys']
    assert len(policy['mandatory_gate_keys']) == 32
    assert policy['python_version'] == [3, 14, 4] and policy['packages'] == old_policy['packages']
    write_new('plan/policy.template.json', wire(policy))
    write_new('plan/GATES.json', (OLD / 'plan/GATES.json').read_bytes())
    workflow_before = (OLD / 'plan/workflow-template.yml').read_text()
    workflow = workflow_before
    replacements = [
        ('name: HIA v88 original full-retained qualification', 'name: HIA v89 original full-retained qualification', 1),
        (old_policy['intended_branch'], policy['intended_branch'], 1),
        ('experiments/hia_v88_full_retained_capsule_20261112/r2', PREFIX, 2),
        (old_policy['source']['commit'], HEAD, 1)]
    for before, after, count in replacements:
        assert workflow.count(before) == count
        workflow = workflow.replace(before, after)
    write_new('plan/workflow-template.yml', workflow.encode())
    write_new('plan/WORKFLOW-REPIN.diff', ''.join(difflib.unified_diff(
        workflow_before.splitlines(True), workflow.splitlines(True),
        fromfile='frozen-v88-template', tofile='v89-uninstalled-template')).encode())
    write_new('plan/POLICY-REPIN.diff', ''.join(difflib.unified_diff(
        (OLD / 'plan/policy.template.json').read_text().splitlines(True), wire(policy).decode().splitlines(True),
        fromfile='frozen-v88-policy', tofile='v89-not-ready-policy')).encode())
    write_new('plan/SUPPLY-REPIN.diff', ''.join(difflib.unified_diff(
        (OLD / 'plan/supply-plan.json').read_text().splitlines(True), wire(supply).decode().splitlines(True),
        fromfile='frozen-v88-supply-plan', tofile='v89-supply-plan')).encode())
    for relative in ['plan/check_proxy_before_retention.py', 'plan/PROXY-CONTROLS-PREEXEC.json',
                     'plan/FULL-COMMON-PROXY-DELTA.diff', 'reference/full_common.v87-original.py',
                     'evidence/PROXY-CONTROLS.process.json', 'evidence/PROXY-CONTROLS.stdout.json',
                     'evidence/PROXY-CONTROLS.stderr.log']:
        write_new(relative, (OLD / relative).read_bytes())
    for relative in ['evidence/STANDARD-CI-ADMISSION-HOLD.json',
                     'evidence/standard-ci/run.original.json', 'evidence/standard-ci/run.sdk.json']:
        write_new('history/v88/' + relative, (OLD / relative).read_bytes())
    write_new('evidence/STANDARD-CI-ADMISSION-PENDING.json', wire({
        'status': 'HOLD_PENDING_MATCHING_STANDARD_CI_AND_ROOT_REVIEW',
        'ready_for_dispatch': False, 'source': source_identity,
        'saved_original_observation': {'run_id': run['id'], 'run_attempt': 1,
                                     'status': run['status'], 'conclusion': None,
                                     'provider_updated_at': run['updated_at'], **pin(run_raw)},
        'saved_observation_is_not_a_claim_about_future_terminal_state': True,
        'historical_v88_terminal_failure_preserved_separately': True,
        'supply_owner_native_cold_or_full_executed': False}))
    compressed = gzip.compress(original_tree, compresslevel=1, mtime=0)
    assert gzip.decompress(compressed) == original_tree
    write_new('plan/source-originals/tree-d9e8407.sdk.json.gz', compressed)
    write_new('plan/source-originals/TREE-SDK-RESTORATION.json', wire({
        'scope': 'Exact JSON.stringify SDK serialization, lossless gzip wrapper only',
        'original': pin(original_tree), 'gzip': pin(compressed),
        'restore': 'gzip -dc tree-d9e8407.sdk.json.gz > a-new-tree-d9e8407.sdk.json',
        'raw_identity_restored_and_read_back': True}))
    for relative in sorted((ROOT / 'control').glob('*.py')):
        assert relative.read_bytes() == (OLD / relative.relative_to(ROOT)).read_bytes()
        ast.parse(relative.read_bytes(), filename=str(relative))
    report = {
        'schema': 'hia.v89.full-retained-source-repin.v1',
        'status': 'SOURCE_BOUND_DRAFT_NOT_DISPATCHABLE', 'ready_for_dispatch': False,
        'original_capsule_commit': PREVIOUS, 'source': source_identity,
        'official_entries': len(rows), 'recomputed_trees': len(recomputed),
        'references': current, 'reference_changes': reference_changes,
        'supply_source_pins': 32, 'supply_source_pin_changes': supply_changes,
        'actual_git_blob_source_reads': reread,
        'control_files': policy['control_files'], 'unchanged_runtime_control_files': unchanged_controls,
        'policy_template': pin(wire(policy)),
        'prior_32_gate_keys_and_limits_exactly_preserved': True,
        'all_six_runtime_control_files_whole_bytes_unchanged': True,
        'official_same_head_standard_ci': {'run_id': run['id'], 'attempt': 1,
            'status': run['status'], 'conclusion': None, 'run_record': pin(run_raw)},
        'inherited_v1_schema_and_temporary_path_labels_not_product_source_identity': True,
        'network_supply_owner_native_or_full_executed': False,
        'proxy_controls': {'expected': 139, 'scope': 'inherited exact v88 source-only originals; not rerun'},
        'legacy_holds_and_unknowns_preserved': True,
        'full_source_clone_not_materialized_in_this_repin': True}
    write_new('plan/HANDOFF.json', wire(report))
    print(json.dumps({'status': report['status'], 'source': source_identity,
        'reference_changes': [r['name'] for r in reference_changes],
        'supply_changes': [r['path'] for r in supply_changes],
        'actual_git_blob_source_reads': len(reread), 'policy': pin(wire(policy))}, sort_keys=True))


if __name__ == '__main__':
    main()
