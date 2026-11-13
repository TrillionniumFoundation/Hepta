"""Read the closed failed experiment exactly once; never execute its products."""
from pathlib import Path
import hashlib
import json
import os
import stat
import sys

ROOT = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e')
ACTUAL = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r3-20261112-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-invocation-r3')
sys.path.insert(0, str(ROOT / 'control'))
from support import closed_owner, environment, owner_paths, stage_command
from common import pin, read_file
from verify import c_image


def load(path):
    return json.loads(path.read_bytes())


def main():
    policy = load(ROOT / 'POLICY.json')
    policy_sha = hashlib.sha256((ROOT / 'POLICY.json').read_bytes()).hexdigest()
    spawn = load(OUT / 'SPAWN.json')
    outer_request = (ACTUAL / 'owned/outer.lifecycle.json.request.json').read_bytes()
    outer_raw = (ACTUAL / 'owned/outer.lifecycle.json').read_bytes()
    command = [policy['python']['path'], '-I', '-S', '-B', str(ROOT / 'control/worker.py'),
        '--policy', str(ROOT / 'POLICY.json'), '--policy-sha256', policy_sha]
    outer = closed_owner(load(ACTUAL / 'WRAPPER.json'), outer_raw, outer_request,
        command=command, cwd=ROOT, env=environment(ACTUAL / 'work/temporary'),
        paths=owner_paths(ACTUAL / 'owned', 'outer'), seconds=180, parent=spawn['pid'])
    assert outer['returncode'] == 1 and outer['timed_out'] is False
    assert outer['exit_observed_before_deadline'] is True and outer.get('owner_error') is None
    final = load(ACTUAL / 'FINAL.json')
    assert final['status'] == 'HOLD' and final['closed_owner'] is True
    assert final['source_preserved'] is True and final['complete_original_inventory'] is True
    assert not final['natural_owner'] and not final['full_graph_qualified']
    work = ACTUAL / 'work'
    inventory = load(ACTUAL / 'CLOSED-ORIGINALS.json')
    assert inventory['status'] == 'COMPLETE_ACTUAL_ORIGINALS' and inventory['errors'] == []
    assert inventory['regular_bytes'] == 3907508 and len(inventory['rows']) == 35
    actual_names = sorted(p.relative_to(work).as_posix() for p in work.rglob('*'))
    assert sorted(row['path'] for row in inventory['rows']) == actual_names
    for row in inventory['rows']:
        path = work / row['path']
        if row['kind'] == 'regular':
            assert pin(path, 16 << 20) == row['actual'], row['path']
        else:
            assert row['kind'] == 'directory' and stat.S_ISDIR(path.lstat().st_mode), row['path']
    report = load(work / 'REPORT.json')
    assert report['status'] == 'HOLD' and report['attempted_stages'] == ['c-compile', 'runtime']
    assert report['completed_stages'] == ['c-compile'] and report['inner_closure_confirmed'] is True
    assert report['source_preserved'] is True and report['expected_stages'] == ['c-compile', 'runtime', 'hia-compile', 'lifetime']
    c = c_image(policy, work)
    assert c == load(work / 'C-BUILD-JOIN.json')
    assert c['image']['sha256'] == '8d205b2b0c08ff12ecec8fe0a4d8cd8131a21c0137973b68565f0f6db28dca09'
    owners = []
    for label, seconds, expected_rc in [('c-compile', 20, 0), ('runtime', 5, 1)]:
        row = report['owners'][label]
        actual_command = stage_command(policy, ROOT / 'POLICY.json', policy_sha, label,
            dso=c if label == 'runtime' else None)
        paths = owner_paths(work / 'owners', label)
        wrapper = load(work / 'owners' / (label + '.WRAPPER.json'))
        assert wrapper == row['wrapper']
        life = closed_owner(wrapper, Path(paths['receipt_path']).read_bytes(),
            Path(paths['receipt_path'] + '.request.json').read_bytes(), command=actual_command,
            cwd=ROOT, env=environment(work / 'temporary', compiler=label == 'c-compile'),
            paths=paths, seconds=seconds, parent=outer['qualification_pid'])
        assert life['returncode'] == expected_rc and life['timed_out'] is False
        assert life['exit_observed_before_deadline'] is True and life['event_overflow'] is False
        assert [r['kind'] for r in life['events']] == ['qualification_started', 'owned_child_observed',
            'qualification_exit_observed', 'owned_child_reaped']
        for original in row['originals'].values():
            assert pin(Path(original['path']), 4 << 20) == original
        owners.append({'stage': label, 'returncode': expected_rc, 'seconds': seconds,
            'life': pin(Path(paths['receipt_path'])), 'request': pin(Path(paths['receipt_path'] + '.request.json')),
            'actual_elapsed_ns': life['events'][-2]['monotonic_ns'] - life['events'][0]['monotonic_ns'],
            'bound_ECHILD': True})
    runtime = load(work / 'runtime/REPORT.json')
    assert runtime['status'] == 'HOLD' and runtime['expected_ids'] == policy['runtime_ids']
    assert runtime['loaded_ids'] == policy['runtime_ids'][:2] and runtime['executed_ids'] == policy['runtime_ids'][:1]
    assert runtime['hia_entry_calls'] == runtime['c_pump_calls'] == 0
    assert len(runtime['outcomes']) == 2 and [r['status'] for r in runtime['outcomes']] == ['PASS', 'HOLD']
    assert 'ValueError: runtime ELF profile differs' in runtime['errors'][0]
    assert all(row == load(work / 'runtime' / (policy['runtime_ids'][i] + '.json')) for i, row in enumerate(runtime['outcomes']))
    assert list((work / 'hia-build').iterdir()) == [] and list((work / 'lifetime').iterdir()) == []
    before = load(ACTUAL / 'INPUTS-BEFORE.json')
    assert before == load(ACTUAL / 'INPUTS-AFTER.json') == load(work / 'INPUTS-BEFORE.json') == load(work / 'INPUTS-AFTER.json')
    assert before == load(Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r3/FROZEN-INPUTS.original.json'))
    originals = [pin(p, 16 << 20) for p in sorted(ACTUAL.rglob('*')) if p.is_file()]
    result = {'schema': 'hia.root.cli-finite-actual-readback.v1', 'status': 'HOLD',
        'actual_request': '7e2d37f425987c827a09f5cd0207595fd86e2e56',
        'request': pin(ROOT / 'REQUEST.json'), 'policy': pin(ROOT / 'POLICY.json'),
        'outer': {'returncode': 1, 'natural_nonzero_exit': True, 'timed_out': False,
            'closed_ECHILD': True, 'original_180_3': True, 'life': pin(ACTUAL / 'owned/outer.lifecycle.json')},
        'inner_owners': owners, 'C_image': c['image'], 'C_compile_and_ELF_dependency_join': 'PASS',
        'runtime_expected': 8, 'runtime_loaded': 2, 'runtime_completed': 1,
        'runtime_original': pin(work / 'runtime/REPORT.json'),
        'primary_error': 'ValueError: runtime ELF profile differs',
        'prior_r1_TLS_and_r2b_missing_raised_helper_HOLDs_retained': True, 'new_request_executed_once': True,
        'HIA_compile_executed': False, 'lifetime_expected': 10, 'lifetime_executed': 0,
        'HIA_entry_returns': 0, 'C_pump_calls': 0, 'original_CLI17_executed': False,
        'original_trace46_executed': False, 'full_graph_qualified': False, 'default_changed': False,
        'all_four_actual_input_snapshots_equal_root_preexec_snapshot': True,
        'closed_work_inventory_rows': 35, 'closed_work_regular_bytes': 3907508,
        'complete_actual_originals': originals, 'whole_rewrite_closed': False}
    with (OUT / 'READBACK.json').open('x') as f:
        json.dump(result, f, sort_keys=True, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
    print(json.dumps({'status': result['status'], 'actual_originals': len(originals),
        'C_compile': 'PASS', 'runtime_completed': 1, 'readback': pin(OUT / 'READBACK.json')}))


if __name__ == '__main__':
    main()
