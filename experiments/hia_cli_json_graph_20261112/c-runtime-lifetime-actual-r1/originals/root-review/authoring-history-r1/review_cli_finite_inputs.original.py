"""Root readonly pre-execution joins; no compiler, owner or native entry."""
from pathlib import Path
import hashlib
import json
import os
import stat
import sys

ROOT = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r1-20261112-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r1')
PEER = Path('/tmp/hia-cold-peer-reviews-20261112/cli-json-C-runtime-lifetime-30d2-static-review.json')


def pin(path):
    first = path.lstat()
    assert stat.S_ISREG(first.st_mode) and first.st_nlink == 1
    raw = path.read_bytes()
    assert path.lstat() == first and len(raw) == first.st_size
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': stat.S_IMODE(first.st_mode)}


def save(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    assert path.read_bytes() == raw


def main():
    git = json.loads((OUT / 'GIT-READBACK.json').read_bytes())
    assert git['commit'] == '30d2cf56eb346db37a1da41dffbffa0cfefc6c44'
    joined = []
    for entry in git['additions']:
        actual = pin(ROOT / entry['path'])
        for key in ('bytes', 'sha256', 'git_blob'):
            assert actual[key] == entry[key], (entry['path'], key)
        assert actual['mode'] == entry['physical_mode']
        joined.append(actual)
    assert len(joined) == 218
    request_pin, policy_pin = pin(ROOT / 'REQUEST.json'), pin(ROOT / 'POLICY.json')
    assert request_pin['sha256'] == '7aa2713a05537355eb844b81d92ad5cfad8401d582c9c1add6d1362926b6498a'
    assert policy_pin['sha256'] == '8eb03e9fb5190117a72b8fd4d3d08195adbd526a2aac623d7758a9c9e829df70'
    request = json.loads((ROOT / 'REQUEST.json').read_bytes())
    policy = json.loads((ROOT / 'POLICY.json').read_bytes())
    peer_pin = pin(PEER)
    assert peer_pin['bytes'] == 6299 and peer_pin['sha256'] == '9b4b4749bc587145ff1bd8ddab5f48762db0b1e4789aa9e4f9961e10cacab008'
    peer = json.loads(PEER.read_bytes())
    for row in peer['files']:
        current = pin(ROOT / row['path'])
        assert all(current[k] == row[k] for k in ('bytes', 'sha256', 'git_blob')), row['path']
    assert not os.path.lexists(request['operation_root'])
    assert request['policy_sha256'] == policy_pin['sha256']
    assert (request['qualification_seconds'], request['cleanup_seconds']) == (180, 3)
    assert (request['runtime_case_count'], request['lifetime_case_count'],
            request['expected_HIA_returns'], request['expected_C_pump_calls_including_refusals']) == (8, 10, 48, 11)
    assert (policy['qualification_seconds'], policy['cleanup_seconds'], policy['child_seconds']) == (180, 3, 5)
    assert policy['compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds': 10, 'output_capacity': 1048576}
    assert policy['c_compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds_per_compiler_process': 10,
            'maximum_file_bytes': 1048576, 'new_development_frontend': True}
    assert len(policy['source_files']) == 182
    assert sum(r['bytes'] for r in policy['source_files']) == 2804125
    assert len(policy['preserved_original17_and46']['original_cli_ids']) == 17
    assert len(policy['preserved_original17_and46']['trace_plan_ids']) == 46
    assert policy['fresh_cold'] is False and policy['activation_CALL_SEND_UNPACK_monitoring_closed'] is False
    assert policy['lifetime_source']['sha256'] == '43b7d82d0dd14cc44e70168127801046d17112c4e0338b453c251e575a791ec4'
    sys.path.insert(0, str(ROOT / 'control'))
    from support import frozen
    # This function only reads the already frozen namespaces and bytes. It
    # never loads the owner, runs a compiler, admits a DSO or invokes a HIA image.
    snapshot = frozen(policy)
    assert snapshot['source_files'] == 182 and len(snapshot['system']['files']) == 4555
    assert not os.path.lexists(request['operation_root'])
    save(OUT / 'FROZEN-INPUTS.original.json', snapshot)
    report = {'schema': 'hia.root.cli-finite-static-review.v1', 'status': 'ROOT_STATIC_AND_INPUT_READBACK_PASS',
        'canonical': git['commit'], 'tree': git['tree'], 'git_readback': pin(OUT / 'GIT-READBACK.json'),
        'request': request_pin, 'policy': policy_pin, 'peer': peer_pin,
        'all218_published_files_full_bytes_sha256_and_git_hash_mode_matched': joined,
        'frozen_inputs': pin(OUT / 'FROZEN-INPUTS.original.json'),
        'primary_reviewed': ['control/launch.py', 'control/worker.py', 'control/support.py',
            'control/verify.py', 'control/case_contract.py', 'control/cases.py', 'control/compile_child.py'],
        'limited_C_review': ['lifetime pump complete source', 'frame leaves complete source',
            'Python pump wrapper complete source', 'base C runtime binding/metadata and frame/lifetime dispatch'],
        'expected_cases': {'runtime': 8, 'lifetime': 10, 'HIA_returns': 48, 'C_pump_calls': 11},
        'expected_counts_are_not_actual': True, 'operation_output_absent': True,
        'source_tests_executed': False, 'compiler_executed': False, 'native_executed': False,
        'limitations': ['Existing v89 B3 only, no matching v92 cold.',
            'Finite lifecycle experiment does not qualify the complete JSON graph or evaluator activation.',
            'Original CLI17 and trace46 remain unexecuted by this request.',
            'Full installation/default and removal of CPython, C, Python and Rust remain open.']}
    save(OUT / 'ROOT-REVIEW.json', report)
    print(json.dumps({'status': report['status'], 'review': pin(OUT / 'ROOT-REVIEW.json'),
        'source': 182, 'system_files': 4555, 'expected_runtime': 8, 'expected_lifetime': 10}))


if __name__ == '__main__':
    main()
