"""Root-only static and complete-input review of the frozen ELF-origin fix."""
import ast
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save
import review_v92_failed_ci_recovery_r1 as git

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4b')
OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r4b')
COMMIT = '6e704d8457ebb357fa71e3f0d40fc5064d943da8'


def main():
    git.OUT = OUT
    tree = git.checked_tree('TREE', '7dc365bfc650a5c620611f56c56f0a648f0e6cae', 6719)
    commit = git.checked_commit('COMMIT', COMMIT, 'f9afe31e640ec51d8fdcf7bd35a54e18bb4ccb12',
        '7dc365bfc650a5c620611f56c56f0a648f0e6cae')
    parent_path = OUT.parent / 'cli-c-runtime-lifetime-actual-r3-git-review/TREE-RAW.provider.json'
    parent_raw = js(parent_path)
    assert parent_raw['sha'] == '5e00f087558c37d01f67630ac84f949d21a431c0' and parent_raw['truncated'] is False
    parent_rows = [r for r in parent_raw['tree'] if r['type'] != 'tree']
    parent = {r['path']: r for r in parent_rows}
    assert len(parent) == len(parent_rows) == 6474 and git.tree_hash(parent) == parent_raw['sha']
    for name, row in parent.items():
        assert all(tree[name][k] == row[k] for k in ('path', 'mode', 'type', 'sha', 'size'))
    plan = js(OUT / 'PLAN.original.json')
    assert plan['parent_commit'] == commit['sole_parent'] and plan['expected_tree'] == commit['tree']
    assert set(tree) - set(parent) == {r['repository_path'] for r in plan['all_additions']}
    assert len(plan['all_additions']) == 245 and len(plan['new_blobs']) == 37
    parent_blobs = {r['sha'] for r in parent_rows}
    assert {r['git_blob'] for r in plan['new_blobs']} == {r['git_blob'] for r in plan['all_additions']} - parent_blobs
    added = []
    for row in plan['all_additions']:
        actual = pin(Path(row['absolute']))
        assert Path(row['absolute']) == ROOT / row['path']
        assert all(actual[k] == row[k] for k in ('bytes', 'sha256', 'git_blob', 'mode'))
        assert ('100755' if actual['mode'] & 0o111 else '100644') == row['git_mode']
        entry = tree[row['repository_path']]
        assert (entry['sha'], entry['size'], entry['mode']) == (row['git_blob'], row['bytes'], row['git_mode'])
        added.append({'path': row['path'], 'repository_path': row['repository_path'], 'git_mode': row['git_mode'], **actual})
    remote = []
    for row in plan['new_blobs']:
        path = OUT / 'raw' / (row['git_blob'] + '.txt')
        actual = pin(path)
        assert all(actual[k] == row[k] for k in ('bytes', 'sha256', 'git_blob'))
        assert read(path) == read(Path(row['absolute']))
        remote.append(actual)
    assert sum(r['bytes'] for r in remote) == 2420974
    request, old_request = js(ROOT / 'REQUEST.json'), js(OLD / 'REQUEST.json')
    policy, previous = js(ROOT / 'POLICY.json'), js(OLD / 'POLICY.json')
    assert pin(ROOT / 'REQUEST.json')['sha256'] == '489e4019c3367654e8207af78f8a98cb7d7f22c457933a0515a886037c8b4dd6'
    assert pin(ROOT / 'POLICY.json')['sha256'] == request['policy_sha256'] == '312f241ad5ae48d34b7553d4fb982f0b81dd7f2971730b9bd9108e077c12d5e6'
    assert not os.path.lexists(request['operation_root'])
    assert {k for k in set(policy) | set(previous) if policy.get(k) != previous.get(k)} == {
        'operation_root', 'operation_key', 'c_command', 'source_files', 'control_files'}
    assert request['operation_root'] == policy['operation_root'] == '/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-actual-r4b'
    assert request['operation_key'] == policy['operation_key'] == 'hia-cli-json-c-runtime-lifetime-local312-r4b'
    assert [x.replace(str(ROOT), str(OLD)).replace(policy['operation_root'], previous['operation_root'])
            for x in policy['c_command']] == previous['c_command']
    assert {k for k in set(request) | set(old_request) if request.get(k) != old_request.get(k)} == {
        'operation_root', 'operation_key', 'policy_sha256'}
    assert (request['qualification_seconds'], request['cleanup_seconds'], request['runtime_case_count'],
        request['lifetime_case_count'], request['expected_HIA_returns'], request['expected_C_pump_calls_including_refusals']) == (180, 3, 8, 10, 48, 11)
    new_sources = {r['path']: r for r in policy['source_files']}
    old_sources = {r['path']: r for r in previous['source_files']}
    assert set(new_sources) == set(old_sources) and len(new_sources) == 182
    changed = [name for name in new_sources if new_sources[name] != old_sources[name]]
    assert changed == ['hepta/hia_cli_json_runtime312.py', 'hepta/hia_cli_json_runtime312_control.py']
    for name in new_sources:
        if name not in changed:
            assert read(ROOT / 'source' / name) == read(OLD / 'source' / name)
    assert sum(r['bytes'] for r in policy['source_files']) == 2809733
    assert pin(ROOT / 'source' / changed[0])['sha256'] == '5eeaa2720dcd347ff3e3cc62a828d2eb5a582aa61f3bfb8813524b4c3ee925d1'
    assert pin(ROOT / 'source' / changed[1])['sha256'] == 'bdf006b5283d6394d201d9b7ec95f70fd73c277b4ec2721f680ff169e1b39188'
    controls, old_controls = ({r['path']: r for r in p['control_files']} for p in (policy, previous))
    assert len(old_controls) == 15 and len(controls) == 19
    assert set(controls) - set(old_controls) == {'build_runtime_mapping_revision.py', 'source_controls.py',
        'freeze_revision_r4.py', 'SOURCE-CONTROL-REQUEST.json'}
    for name, row in old_controls.items():
        assert controls[name] == row and read(ROOT / name) == read(OLD / name)
    for row in policy['asset_files']:
        assert read(ROOT / row['path']) == read(OLD / row['path'])
    assert len(policy['asset_files']) == 4
    assert pin(ROOT / 'control/process_owner_impl.py')['sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
    assert pin(ROOT / 'control/guardian.py')['sha256'] == 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
    for name in changed:
        ast.parse(read(ROOT / 'source' / name), filename=name)
    source_request = js(ROOT / 'SOURCE-CONTROL-REQUEST.json')
    assert pin(ROOT / 'SOURCE-CONTROL-REQUEST.json')['sha256'] == '2da4566c59ea752205f2e764e269040ef401afeda6a3e8896aa08ec76de9c311'
    assert source_request['new_source_control_wall_seconds'] == 20
    assert len(source_request['expected_ids']) == len(set(source_request['expected_ids'])) == 28
    assert source_request['command'] == [policy['python']['path'], '-I', '-S', '-B', str(ROOT / 'source_controls.py'),
        '--output', '/workspace/scratch/e26ed3e2edcf/native-cli-runtime-layout-source-controls-r4b']
    assert source_request['environment'] == {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': ''}
    assert not os.path.lexists(source_request['output'])
    source_ast = ast.parse(read(ROOT / 'source_controls.py'))
    ids_node = next(node for node in source_ast.body if isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'IDS' for t in node.targets))
    assert list(ast.literal_eval(ids_node.value)) == source_request['expected_ids']
    source_inputs = []
    for row in source_request['inputs']:
        actual = pin(Path(row['path']))
        assert all(actual[k] == row[k] for k in ('path', 'bytes', 'sha256', 'git_blob'))
        source_inputs.append(actual)
    assert len(source_inputs) == 5
    runtime_raw = read(Path(policy['python']['path']))
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', runtime_raw)
    assert header[1:4] == (2, 62, 1) and header[9] == 56
    loads = [struct.unpack_from('<IIQQQQQQ', runtime_raw, header[5] + i * 56) for i in range(header[10])]
    loads = [p for p in loads if p[0] == 1]
    assert len(loads) == 6 and sum(bool(p[1] & 1) for p in loads) == 2
    assert min(p[3] & -4096 for p in loads if p[6]) == 0x3ff000
    primary = js(OUT / 'PRIMARY-GLIBC-READBACK.json')
    assert len(primary) == 3 and all(r['status'] == 'fulfilled' for r in primary)
    assert policy['compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds': 10, 'output_capacity': 1048576}
    assert policy['c_compiler_limits'] == previous['c_compiler_limits'] and policy['child_seconds'] == 5
    assert (len(policy['runtime_ids']), len(policy['lifetime_ids']), sum(policy['expected_lifetime_HIA_returns']),
        sum(policy['expected_C_pump_calls_including_refusals'])) == (8, 10, 48, 11)
    assert (len(policy['preserved_original17_and46']['original_cli_ids']),
        len(policy['preserved_original17_and46']['trace_plan_ids'])) == (17, 46)
    assert policy['fresh_cold'] is False and policy['current_v92_matching_claimed'] is False
    assert policy['activation_CALL_SEND_UNPACK_monitoring_closed'] is False
    sys.path.insert(0, str(ROOT / 'control'))
    from support import frozen
    snapshot = frozen(policy)
    old_snapshot = js(OUT.parent / 'cli-c-runtime-lifetime-review-r3/FROZEN-INPUTS.original.json')
    assert snapshot['source_files'] == 182 and len(snapshot['system']['files']) == 4555
    assert snapshot['system']['files'] == old_snapshot['system']['files']
    assert snapshot['system']['namespace'] == old_snapshot['system']['namespace']
    assert policy['external_files'] == previous['external_files'] and len(policy['external_files']) == 72
    assert not os.path.lexists(request['operation_root']) and not os.path.lexists(source_request['output'])
    git_record = {'schema': 'hia.root.cli-r4b-canonical-readback.v1', 'status': 'FULL_TREE_AND_ALL37_NEW_RAW_BLOBS_PASS',
        'commit': COMMIT, 'tree': commit['tree'], 'commit_reconstruction': commit,
        'parent_tree_original': pin(parent_path), 'all_leaves': 6719, 'old_leaves': 6474, 'new_leaves': 245,
        'additions': added, 'new_unique_remote_bodies': remote, 'new_unique_remote_bytes': 2420974,
        'old_tree_422_then_GET_reconciliation_not_replayed': True}
    save(OUT / 'GIT-READBACK.json', git_record)
    save(OUT / 'FROZEN-INPUTS.original.json', snapshot)
    result = {'schema': 'hia.root.cli-runtime-origin-r4b-input-review.v1',
        'status': 'ROOT_STATIC_AND_COMPLETE_INPUT_READBACK_PASS', 'canonical': COMMIT, 'tree': commit['tree'],
        'git_readback': pin(OUT / 'GIT-READBACK.json'), 'request': pin(ROOT / 'REQUEST.json'),
        'policy': pin(ROOT / 'POLICY.json'), 'source_control_request': pin(ROOT / 'SOURCE-CONTROL-REQUEST.json'),
        'source_changed_files': changed, 'unchanged_source_files': 180, 'old_control_inputs_unchanged': 15,
        'runtime_controls_unchanged': 11, 'HIA_assets_unchanged': 4, 'source_files_freshly_read': 182,
        'system_files_freshly_read': 4555, 'all_old_system_identities_namespaces_bytes_equal': True,
        'external_original_compiler_and_other_inputs_freshly_read': 72,
        'frozen_inputs': pin(OUT / 'FROZEN-INPUTS.original.json'), 'source_control_inputs': source_inputs,
        'source_control_ids': source_request['expected_ids'], 'source_control_seconds': 20,
        'source_controls_executed': False, 'actual_ELF_type': 'ET_EXEC', 'actual_PT_LOADs': 6,
        'actual_executable_PT_LOADs': 2, 'actual_lowest_load_page': 0x3ff000,
        'primary_glibc_full_raw_readback': pin(OUT / 'PRIMARY-GLIBC-READBACK.json'),
        'static_reviewed': ['derive bias from actual evaluator anchor minus admitted symbol value',
            'require zero ET_EXEC bias and separate mapping-origin relation for both ELF types',
            'unique executable section/load/file extent for each of fifteen unique functions',
            'complete current inode/path/offset/permissions mapping; RELRO split allowed without writable executable code',
            'same mapping proof for both tables; actual first/last addresses and complete code bytes',
            'keep old negative SHA/size/table cases and original runtime/lifetime test bodies'],
        'expected_runtime': 8, 'expected_lifetime': 10, 'expected_HIA_returns': 48, 'expected_C_pumps': 11,
        'expected_not_actual': True, 'outer_limits': [180, 3], 'inner_seconds': [20, 5, 20, 5],
        'new_C_or_HIA_compile_or_runtime_execution': False, 'whole_native_rewrite_closed': False,
        'limitations': ['v89 development compiler; no matching v92 or fresh cold claim.',
            'Full CLI17, trace46 and CALL/SEND/UNPACK ownership remain open.',
            'r1, r2b and r3 actual HOLDs and r4 authoring mode HOLD are preserved.']}
    save(OUT / 'ROOT-REVIEW.json', result)
    print(json.dumps({'status': result['status'], 'review': pin(OUT / 'ROOT-REVIEW.json'),
        'source_files': 182, 'system_files': 4555, 'source_controls_expected': 28,
        'finite_expected': [8, 10, 48, 11]}, sort_keys=True))


if __name__ == '__main__':
    main()
