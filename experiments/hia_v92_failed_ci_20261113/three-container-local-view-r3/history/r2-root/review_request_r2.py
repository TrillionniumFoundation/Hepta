"""Root full canonical readback and exact four-leaf storage revision review."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save, identity, blob
import review_v92_failed_ci_recovery_r1 as git

ROOT = Path('/home/agent/hia-root-v92-three-view-r2-20261113-e26e')
OUT = ROOT / 'request-review'
PLAN = Path('/home/agent/hia-v92-three-view-plan-r2-20261113-e26e')
OLD = Path('/workspace/scratch/e26ed3e2edcf/v92-three-part-view-plan-r1-20261113-e26e')
PARENT = '503f3ef7c75ca71b6be06ff6dbbbeafc9de3d703'
TREE = '6ae23a4dff5cb0aaa5317c220935231d6a9a567e'


def differences(a, b, prefix=''):
    if type(a) is not type(b):
        return [prefix]
    if isinstance(a, dict):
        assert set(a) == set(b)
        return [p for k in a for p in differences(a[k], b[k], (prefix + '.' if prefix else '') + k)]
    if isinstance(a, list):
        assert len(a) == len(b)
        return [p for i, (x, y) in enumerate(zip(a, b)) for p in differences(x, y, prefix + '.' + str(i))]
    return [] if a == b else [prefix]


def main():
    publication = js(OUT / 'PLAN.original.json')
    assert publication == js(PLAN / 'publication/PLAN.json')
    assert publication['parent'] == PARENT and publication['expected_tree'] == TREE
    git.OUT = OUT
    leaves = git.checked_tree('TREE', TREE, 4307)
    candidate = js(OUT / 'COMMIT.provider.json')['sha']
    commit = git.checked_commit('COMMIT', candidate, PARENT, TREE)
    old_tree = js(ROOT / 'source20-r1-publication-review/TREE.provider.json')
    old = {r['path']: r for r in old_tree['tree'] if r['type'] != 'tree'}
    assert len(old) == 4259 and git.tree_hash(old) == publication['base_tree'] == '4c3fda543280f95aebf40b08047448ad1d4122a8'
    assert js(ROOT / 'source20-r1-publication-review/ROOT-READBACK.json')['status'] == 'ALL26_REMOTE_PATHS_AND_79_ARCHIVE_MEMBERS_FULLY_READ'
    for n, row in old.items():
        assert all(leaves[n][k] == row[k] for k in ('path', 'sha', 'mode', 'type', 'size'))
    assert len(publication['files']) == 48
    assert set(leaves) - set(old) == {r['path'] for r in publication['files']}
    total = 0; full = []
    for row in publication['files']:
        raw = read(OUT / 'raw' / (row['sha'] + '.txt'))
        assert raw == read(Path(row['local'])) and len(raw) == row['bytes']
        assert hashlib.sha256(raw).hexdigest() == row['sha256'] and blob(raw) == row['sha']
        assert (leaves[row['path']]['mode'], leaves[row['path']]['sha'], leaves[row['path']]['size']) == ('100644', row['sha'], row['bytes'])
        full.append({'repository_path': row['path'], 'local': pin(Path(row['local']))})
        total += len(raw)
    assert total == 970093
    policy, old_policy = js(PLAN / 'POLICY.json'), js(OLD / 'POLICY.json')
    changed = differences(old_policy, policy)
    assert set(changed) == {'mandatory_source_controls.actual_root', 'volumes.workspace.parent', 'volumes.workspace.root', 'volumes.workspace.parent_device'}
    request, source = js(PLAN / 'REQUEST.json'), js(PLAN / 'CONTROL-REQUEST.json')
    old_source = js(OLD / 'CONTROL-REQUEST.json')
    assert pin(PLAN / 'POLICY.json')['sha256'] == '053ef7a72f8502378061b21606ebb8f30195f7cfffe3d8354cce7be7fa5bcf10'
    assert pin(PLAN / 'REQUEST.json')['sha256'] == '7df38ef507dadfd7900c569f18e78ed95641cfb2663c50884001ba0f155cbdc2'
    assert pin(PLAN / 'CONTROL-REQUEST.json')['sha256'] == '252e4aba13964c45d1515334b825a16a214200d61ed5e6685f28d35072d353e6'
    assert request['policy']['sha256'] == pin(PLAN / 'POLICY.json')['sha256']
    assert request['source20_request']['sha256'] == pin(PLAN / 'CONTROL-REQUEST.json')['sha256']
    assert policy['inputs'] == old_policy['inputs'] == request['controls'] and len(policy['inputs']) == 34
    sources = []
    for name, expected in policy['inputs'].items():
        raw = read(PLAN / name)
        assert raw == read(OLD / name)
        a = pin(PLAN / name)
        assert all(a[k] == expected[k] for k in ('bytes', 'sha256'))
        assert a['mode'] == pin(OLD / name)['mode']
        sources.append(a)
    assert len(source['inputs']) == 35 and source['inputs'] == {**policy['inputs'], 'POLICY.json': {k: request['policy'][k] for k in ('bytes', 'sha256')}}
    assert source['expected_ids'] == old_source['expected_ids'] == policy['mandatory_source_controls']['expected_ids']
    assert len(source['expected_ids']) == 20
    assert source['operation_root'] == policy['mandatory_source_controls']['actual_root'] == '/tmp/hia-v92-three-view-source20-r2-20261113-e26e'
    assert source['output'] == source['operation_root'] + '/tests'
    assert source['environment'] == old_source['environment']
    for key in ('runtime', 'qualification_seconds', 'cleanup_seconds', 'minimum_free_bytes', 'minimum_free_inodes', 'maximum_output_bytes'):
        assert source[key] == old_source[key]
    assert source['command'] == [source['runtime']['path'], '-I', '-S', '-B', str(PLAN / 'controls/run_controls.py')]
    launch = js(PLAN / 'CONTROL-LAUNCH.json')
    assert launch['command'] == [source['runtime']['path'], '-I', '-S', '-B', str(PLAN / 'controls/launch_controls.py')]
    assert launch['cwd'] == str(PLAN) and launch['environment'] == source['environment']
    assert launch['request']['sha256'] == pin(PLAN / 'CONTROL-REQUEST.json')['sha256']
    runtime = pin(Path(source['runtime']['path']))
    assert all(runtime[k] == source['runtime'][k] for k in ('path', 'bytes', 'sha256', 'git_blob'))
    st = identity(Path(runtime['path']).lstat())
    assert [st[k] for k in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')] == source['runtime']['identity']
    private = pin(Path(policy['proxy_configuration_path']))
    assert (private['bytes'], private['sha256'], private['mode']) == (3426, '99844e0230469a6e614f6e1e3d35be0b0b0bab87109044053785266d9770eaaf', 0o600)
    old_capture = js(Path('/workspace/scratch/e26ed3e2edcf/root/v92-three-view-private-proxy-r1/READBACK.json'))
    assert all(private[k] == old_capture['private_input'][k] for k in ('path', 'bytes', 'sha256'))
    assert policy['operation_root'] == old_policy['operation_root']
    assert policy['provider_references_path'] == old_policy['provider_references_path']
    assert not any(os.path.lexists(p) for p in [source['operation_root'], policy['provider_references_path'], *[v['root'] for v in policy['volumes'].values()]])
    capacity = {}
    for key, v in policy['volumes'].items():
        assert Path(v['parent']).stat().st_dev == v['parent_device']
        s = os.statvfs(v['parent']); required = sum(v['limits'][k] for k in ('container', 'metadata', 'parent', 'reserve', 'selected'))
        assert required == {'tmp': 1076598380, 'workspace': 889595045}[key]
        capacity[key] = {'parent': v['parent'], 'device': v['parent_device'], 'available': s.f_bavail * s.f_frsize, 'required': required, 'free_inodes': s.f_favail}
    assert capacity['workspace']['device'] == 41 and capacity['tmp']['device'] == 39
    result = {'schema': 'hia.root.v92-three-view-r2-full-static-review.v1',
        'status': 'FULL48_REMOTE_BODIES_AND_EXACT_STORAGE_REVISION_PASS_SOURCE20_PENDING',
        'canonical': candidate, 'commit': commit, 'full4307_tree_old4259_preserved': True,
        'new_paths': 48, 'new_path_bytes': total, 'all_new_full_body_pins': full,
        'exact_policy_changed_leaves': changed, 'all34_runtime_inputs_equal_r1': sources,
        'all13_algorithms_unchanged': True, 'r1_full_published_source20_actual_independently_preserved': True,
        'policy': pin(PLAN / 'POLICY.json'), 'request': pin(PLAN / 'REQUEST.json'),
        'control_request': pin(PLAN / 'CONTROL-REQUEST.json'), 'control_launch': pin(PLAN / 'CONTROL-LAUNCH.json'),
        'runtime': runtime, 'source20_expected_ids': source['expected_ids'],
        'existing_private_proxy': {k: private[k] for k in ('path', 'bytes', 'sha256', 'mode')},
        'private_values_published': False, 'capacity_observation_not_final_admission': capacity,
        'original20_3_900_3_720_all_limits_unchanged': True,
        'source20_r2_executed': False, 'real_receiver_r1_or_r2_executed': False,
        'provider_references_acquired': 0, 'local_large_GETs': 0, 'next_unique_source20_authorized_by_user_task': True,
        'whole_native_rewrite_closed': False}
    save(OUT / 'ROOT-REVIEW.json', result)
    print(json.dumps({'status': result['status'], 'review': pin(OUT / 'ROOT-REVIEW.json'), 'capacity': capacity}))


if __name__ == '__main__':
    main()
