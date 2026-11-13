"""Full Root readback of the exact five-leaf R3 revision and retained history."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save, identity, blob
import review_v92_failed_ci_recovery_r1 as git

ROOT = Path('/home/agent/hia-root-v92-three-view-r3-20261113-e26e')
PREVIOUS = Path('/home/agent/hia-root-v92-three-view-r2-20261113-e26e')
OUT = ROOT / 'request-review'
PLAN = Path('/home/agent/hia-v92-three-view-plan-r3-20261113-e26e')
OLD = Path('/home/agent/hia-v92-three-view-plan-r2-20261113-e26e')
PARENT = '96fd0500e4f05ca710cf947a84aeec69bc0ff704'


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
    assert publication == js(PLAN / 'publication/PLAN.json') and publication['parent'] == PARENT
    assert len(publication['files']) == 72 and publication['expected_tree'] == '6df67e55d3850cfeb537effc28505883cc3ad2a0'
    old_tree = js(PREVIOUS / 'request-review/TREE.provider.json')
    old = {r['path']: r for r in old_tree['tree'] if r['type'] != 'tree'}
    assert len(old) == 4307 and git.tree_hash(old) == publication['base_tree'] == '6ae23a4dff5cb0aaa5317c220935231d6a9a567e'
    assert pin(PREVIOUS / 'request-review/ROOT-REVIEW.json')['sha256'] == '82b6337bf16904e02c76fa6f8b6ed1a7d087983fd9c22e1dc7a22900a7350fb6'
    git.OUT = OUT
    leaves = git.checked_tree('TREE', publication['expected_tree'], 4307 + len(publication['files']))
    candidate = js(OUT / 'COMMIT.provider.json')['sha']
    commit = git.checked_commit('COMMIT', candidate, PARENT, publication['expected_tree'])
    for name, row in old.items():
        assert all(leaves[name][k] == row[k] for k in ('path', 'sha', 'mode', 'type', 'size'))
    assert set(leaves) - set(old) == {r['path'] for r in publication['files']}
    full = []; total = 0
    for row in publication['files']:
        raw = read(OUT / 'raw' / (row['sha'] + '.txt'))
        assert raw == read(Path(row['local_path'])) and len(raw) == row['bytes']
        assert hashlib.sha256(raw).hexdigest() == row['sha256'] and blob(raw) == row['sha']
        assert (leaves[row['path']]['mode'], leaves[row['path']]['sha'], leaves[row['path']]['size']) == ('100644', row['sha'], row['bytes'])
        full.append({'repository_path': row['path'], 'local': pin(Path(row['local_path']))}); total += len(raw)
    assert total == 1153257
    policy, old_policy = js(PLAN / 'POLICY.json'), js(OLD / 'POLICY.json')
    changed = differences(old_policy, policy)
    assert set(changed) == {'mandatory_source_controls.actual_root', 'proxy_configuration_path', 'parts.2.volume', 'volumes.tmp.limits.container', 'volumes.workspace.limits.container'}
    assert policy['parts'][2]['volume'] == 'workspace' and [p['volume'] for p in policy['parts']] == ['tmp', 'workspace', 'workspace']
    assert old_policy['volumes']['tmp']['limits']['container'] - policy['volumes']['tmp']['limits']['container'] == 119894487
    assert policy['volumes']['workspace']['limits']['container'] - old_policy['volumes']['workspace']['limits']['container'] == 119894487
    assert sum(v['limits']['container'] for v in policy['volumes'].values()) == 657570577
    request, source = js(PLAN / 'REQUEST.json'), js(PLAN / 'CONTROL-REQUEST.json')
    old_source = js(OLD / 'CONTROL-REQUEST.json')
    assert pin(PLAN / 'POLICY.json')['sha256'] == '9740c6b3808bd5561978e6e547f118042e69de01bbe6ff5b5a538045fb4e0ee7'
    assert pin(PLAN / 'REQUEST.json')['sha256'] == 'c18f8115b0ffc8fd19402ff0b1eabde7a49e0e3407357de1bb775027c720d955'
    assert pin(PLAN / 'CONTROL-REQUEST.json')['sha256'] == '94b414f4c848fa164ce4948f06e33965ab4cf7010f605bed9fa627e63c82de49'
    assert request['policy']['sha256'] == pin(PLAN / 'POLICY.json')['sha256']
    assert request['source20_request']['sha256'] == pin(PLAN / 'CONTROL-REQUEST.json')['sha256']
    assert request['parts'] == policy['parts'] and request['volumes'] == policy['volumes']
    assert policy['inputs'] == old_policy['inputs'] == request['controls'] and len(policy['inputs']) == 34
    sources = []
    for name, expected in policy['inputs'].items():
        raw = read(PLAN / name); assert raw == read(OLD / name)
        actual = pin(PLAN / name)
        assert all(actual[k] == expected[k] for k in ('bytes', 'sha256')) and actual['mode'] == pin(OLD / name)['mode']
        sources.append(actual)
    assert len(source['inputs']) == 35 and source['inputs'] == {**policy['inputs'], 'POLICY.json': {k: request['policy'][k] for k in ('bytes', 'sha256')}}
    assert source['expected_ids'] == old_source['expected_ids'] == policy['mandatory_source_controls']['expected_ids'] and len(source['expected_ids']) == 20
    assert source['operation_root'] == policy['mandatory_source_controls']['actual_root'] == '/tmp/hia-v92-three-view-source20-r3-20261113-e26e'
    assert source['output'] == source['operation_root'] + '/tests' and source['environment'] == old_source['environment']
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
    # Read every retained R2 actual and Root historical original against the
    # unchanged original path; no private proxy or provider ACK body is copied.
    history = []
    for frozen in sorted((PLAN / 'history').rglob('*')):
        if not frozen.is_file():
            continue
        rel = frozen.relative_to(PLAN / 'history')
        if rel.parts[:2] == ('r2-source20', 'actual'):
            original = Path('/tmp/hia-v92-three-view-source20-r2-20261113-e26e').joinpath(*rel.parts[2:])
        else:
            assert rel.parts[0] == 'r2-root'; original = PREVIOUS.joinpath(*rel.parts[1:])
        assert read(frozen) == read(original)
        history.append({'retained': pin(frozen), 'original': pin(original)})
    assert len(history) == 24
    prior_source = js(PREVIOUS / 'source20-r2-invocation/READBACK.json')
    assert prior_source['status'] == 'ROOT_ALL20_SOURCE_IO_CONTROLS_AND_ORIGINAL_OWNER_PASS'
    assert pin(PREVIOUS / 'source20-r2-invocation/READBACK.json')['sha256'] == '3c3b55953133f2ba7c91b3a6e3fe5f915cc10ddd7cc0a62dfbd5366f68470d45'
    old_private = pin(Path(old_policy['proxy_configuration_path']))
    assert (old_private['bytes'], old_private['sha256'], old_private['mode']) == (3426, '99844e0230469a6e614f6e1e3d35be0b0b0bab87109044053785266d9770eaaf', 0o600)
    refs = pin(Path(policy['provider_references_path']))
    assert (refs['bytes'], refs['sha256'], refs['mode']) == (1562, '89ac4f110cc6e3d5c4dc2471f3ecd801200b479bba06f0ba6c5fffd548cf8606', 0o600)
    assert pin(PREVIOUS / 'provider-references-r1/READBACK.json')['sha256'] == '1411c4b8f7fd32761cb2a631877d33b072451167d83f83ba2b1855e2cfc2b3cc'
    assert policy['operation_root'] == old_policy['operation_root'] and policy['provider_references_path'] == old_policy['provider_references_path']
    assert policy['proxy_configuration_path'] == '/tmp/hia-v92-three-view-original-proxy-r3-20261113-e26e.private.json'
    assert not any(os.path.lexists(p) for p in [source['operation_root'], policy['proxy_configuration_path'], *[v['root'] for v in policy['volumes'].values()]])
    capacity = {}
    for key, volume in policy['volumes'].items():
        assert Path(volume['parent']).stat().st_dev == volume['parent_device']
        stats = os.statvfs(volume['parent']); required = sum(volume['limits'][k] for k in ('container', 'metadata', 'parent', 'reserve', 'selected'))
        assert required == {'tmp': 956703893, 'workspace': 1009489532}[key]
        assert volume['limits']['reserve'] == 536870912 and volume['limits']['inodes'] == 4096
        capacity[key] = {'parent': volume['parent'], 'device': volume['parent_device'], 'available': stats.f_bavail * stats.f_frsize, 'required': required, 'free_inodes': stats.f_favail}
    result = {'schema': 'hia.root.v92-three-view-r3-full-static-review.v1',
        'status': 'FULL_REMOTE_BODIES_AND_EXACT_FIVE_LEAF_REVISION_READ_EXPIRY_HOLD_NO_EXECUTION',
        'canonical': candidate, 'commit': commit, 'full_tree_leaves': len(leaves), 'old4307_preserved': True,
        'new_paths': len(full), 'new_path_bytes': total, 'all_new_full_body_pins': full,
        'exact_policy_changed_leaves': changed, 'all34_runtime_inputs_equal_r2': sources,
        'all13_algorithms_unchanged': True, 'full_original_r2_history': history,
        'policy': pin(PLAN / 'POLICY.json'), 'request': pin(PLAN / 'REQUEST.json'),
        'control_request': pin(PLAN / 'CONTROL-REQUEST.json'), 'control_launch': pin(PLAN / 'CONTROL-LAUNCH.json'),
        'runtime': runtime, 'source20_expected_ids': source['expected_ids'],
        'retained_old_proxy_opaque': old_private, 'retained_existing_three_refs_opaque': refs,
        'private_values_published': False, 'capacity_observation_not_final_admission': capacity,
        'original20_3_900_3_720_and_all_total_budgets_unchanged': True,
        'source20_r3_executed': False, 'real_receiver_r1_r2_r3_executed': False,
        'provider_references_acquired': 3, 'local_large_GETs': 0,
        'known_expiry_hold': pin(ROOT / 'R1-PROVIDER-REFERENCES-EXPIRY-HOLD.json'),
        'r3_source20_and_receiver_will_not_be_invoked': True,
        'whole_native_rewrite_closed': False}
    save(OUT / 'ROOT-REVIEW.json', result)
    print(json.dumps({'status': result['status'], 'review': pin(OUT / 'ROOT-REVIEW.json'), 'capacity': capacity}))


if __name__ == '__main__':
    main()
