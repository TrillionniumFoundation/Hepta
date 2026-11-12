"""Read-only input inventory and exact, unexecuted development request."""
from __future__ import annotations

import ast
from hashlib import sha256, sha1
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import stat
import sys

ROOT = Path(__file__).resolve().parent
SOURCE = Path('/workspace/scratch/e26ed3e2edcf/combined-native-v88-r1')
ACTUAL = Path('/workspace/scratch/e26ed3e2edcf/root/carrier-ci-failure-43274637363')
WIRE = ACTUAL / 'selected-originals/hia-json-wire-callers-evidence/wire'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
TEST_ID = 'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_native_timeout_is_incomplete_terminated_and_not_adoptable'


def body_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def pin(path, role):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and path.resolve() == path
    raw = path.read_bytes()
    after = path.lstat()
    identity = {k: getattr(before, k) for k in FIELDS}
    assert identity == {k: getattr(after, k) for k in FIELDS}
    return {'path': str(path), 'role': role, **body_pin(raw), 'identity': identity}


def save(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with (ROOT / name).open('xb') as f:
        f.write(raw)


def main():
    original = json.loads((ACTUAL / 'selected-originals/hia-json-wire-callers.json').read_bytes())
    build = json.loads((WIRE / 'build.json').read_bytes())
    pins = []
    for name, expected in sorted(build['source_manifest'].items()):
        p = pin(SOURCE / name, 'actual-carrier-source-manifest-member')
        assert p['sha256'] == expected
        pins.append(p)
    assert len(pins) == 841
    indexed = {p['path'] for p in pins}
    for name in ('tools/hia_agent_native_qualification.py', 'tools/hia_agent_native_transport.py',
                 'tools/hia_selfhost_process_owner.py'):
        path = SOURCE / name
        if str(path) not in indexed:
            pins.append(pin(path, 'additional-exact-diagnostic-dependency'))
            indexed.add(str(path))
    for name in ('manifest.json', 'build.json', 'json-wire.image.bin', 'json-wire.input.bin',
                 'json-wire.output.bin', 'json-wire.request.json', 'json-wire.receipt.json',
                 'json-wire.stdout.log', 'json-wire.stderr.log'):
        pins.append(pin(WIRE / name, 'actual-carrier-selected-wire-original'))
    pins.append(pin(ACTUAL / 'selected-originals/hia-json-wire-callers.json', 'historical-full89-failure-original'))
    for name in ('worker.py', 'launch.py'):
        p = ROOT / 'control' / name
        ast.parse(p.read_bytes(), filename=str(p))
        pins.append(pin(p, 'new-unexecuted-diagnostic-control'))
    python = Path(sys.executable).resolve(strict=True)
    pins.append(pin(python, 'explicit-pinned-local-system-interpreter'))
    packages = []
    for name in ('jsonschema', 'jsonschema-specifications', 'attrs', 'referencing', 'rpds-py'):
        dist = importlib.metadata.distribution(name)
        own = Path(dist._path).resolve(strict=True)
        row = {'name': name, 'version': dist.version, 'dist_info': str(own), 'metadata': []}
        for leaf in ('METADATA', 'RECORD'):
            path = own / leaf
            item = pin(path, 'explicit-runtime-distribution-metadata')
            row['metadata'].append(item)
            pins.append(item)
        packages.append(row)
    assert len({p['path'] for p in pins}) == len(pins)
    test_raw = (SOURCE / 'tests/test_hia_agent_native_tools.py').read_bytes()
    tree = ast.parse(test_raw)
    method = next(n for cls in tree.body if isinstance(cls, ast.ClassDef) and cls.name == 'NativeLifecycleTests'
                  for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == TEST_ID.rsplit('.', 1)[1])
    segment = ast.get_source_segment(test_raw.decode(), method).encode()
    assert b'self.assertLess(time.monotonic() - started, 5)' in segment
    workload_raw = (SOURCE / 'tools/hia_agent_native_qualification.py').read_bytes()
    module = ast.parse(workload_raw)
    workload = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'exhaustive_u8_workload')
    workload_segment = ast.get_source_segment(workload_raw.decode(), workload).encode()
    assert b'for x in range(256)' in workload_segment
    assert original['tests_loaded'] == original['tests_chosen'] == original['tests_run'] == 89
    assert original['loaded_test_ids'] == original['chosen_test_ids'] == original['executed_test_ids']
    assert len(original['failures']) == 1 and original['failures'][0]['test'] == TEST_ID
    save('ORIGINAL-89-IDS.json', {'count': 89, 'ids': original['chosen_test_ids'], 'diagnostic_runs_only': [TEST_ID]})
    (ROOT / 'original-test-method.txt').write_bytes(segment + b'\n')
    (ROOT / 'original-workload-function.txt').write_bytes(workload_segment + b'\n')
    output = ROOT / 'actual'
    assert not output.exists()
    env = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': str(python.parent) + ':/usr/bin:/bin',
           'PYTHONDONTWRITEBYTECODE': '1', 'HEPTA_HIA_JSON_WIRE_MANIFEST': str(WIRE / 'manifest.json')}
    request = {'schema': 'hepta.wire89-timeout-local312-development-request.v1', 'status': 'FROZEN_UNEXECUTED',
        'source_root': str(SOURCE), 'source_reference_commit': 'e4fc00a775dab323758d77a2ef4918fd35585cdc',
        'source_reference_tree': 'd9e8407c70e44a3ea0152b8b4c5eb2ed3833d790',
        'actual_source_manifest_entries_individually_joined': 841,
        'full_new_source_tree_or_cold_qualification_claimed': False,
        'historical_run': 43274637363, 'historical_job': 131379662969,
        'historical_head': 'f41f9122e536d8a86b4a74428caae963ff4a95bd',
        'historical_python': original['python'], 'historical_evaluate_seconds': 6.503077664999637,
        'historical_full89_unchanged': 89, 'test_id': TEST_ID, 'test_count': 1,
        'test_scope': 'ONE_ORIGINAL_METHOD_DEVELOPMENT_DIAGNOSTIC_NOT_FULL89_QUALIFICATION',
        'original_assertion_seconds': 5, 'original_workload_cases': 256, 'workload_method_pin': body_pin(workload_segment),
        'test_method_pin': body_pin(segment), 'build_pair_unchanged': True,
        'wire_image_sha256': original['image_sha256'], 'wire_source_sha256': original['manifest']['source_sha256'],
        'wire_image_origin_compiler_sha256': original['manifest']['compiler_sha256'],
        'new_B3_compile': False, 'current_B3_or_wire_rebuilt': False,
        'original_test_program_codegen_and_runner_calls_preserved': True,
        'qualification_seconds': 180, 'cleanup_seconds': 3,
        'minimum_free_bytes': 512 * 1024 * 1024, 'minimum_free_inodes': 4096,
        'diagnostic_raw_bytes_limit': 128 * 1024 * 1024,
        'estimated_additional_output_ceiling_bytes': 160 * 1024 * 1024,
        'python': str(python), 'python_version': sys.version, 'platform': platform.platform(), 'packages': packages,
        'runtime_scope': 'LOCAL_CPYTHON_3_12_14_DEVELOPMENT_NOT_ORIGINAL_GITHUB_3_14_4_REPRODUCTION',
        'owner_path': str(SOURCE / 'tools/hia_selfhost_process_owner.py'),
        'command': [str(python), '-I', '-B', str(ROOT / 'control/worker.py')], 'cwd': str(SOURCE),
        'env': env, 'output_root': str(output), 'input_pins': pins,
        'instrumentation': {'phases': ['setup', 'build_pair', 'evaluate', 'teardown', 'outside-test'],
            'all_timing_cost_inside_original_limits': True, 'per_primitive_clock': False, 'per_primitive_io': False,
            'ForeignGraphObserver_bindings_modified': False, 'actual_key_cache_flag_observed': True,
            'native_return_status_counts_after_real_entry': True, 'no_serialization_or_payload_walk_for_metrics': True,
            'all_original_Popen_argv_env_and_communicate_request_output_kept': True,
            'original_communicate_timeout_and_error_semantics_preserved': True,
            'no_automatic_retry_or_extra_product_run': True},
        'qualification_claims': {'full89': False, 'Core39': False, 'UNPACK18': False, 'Core116': False, 'installed': False, 'matching_cold': False}}
    save('REQUEST.json', request)
    save('LAUNCH.json', {'schema': 'hepta.wire89-diagnostic-launch.v1', 'argv': [str(python), '-I', '-B', str(ROOT / 'control/launch.py')],
                        'cwd': str(ROOT), 'request': pin(ROOT / 'REQUEST.json', 'frozen-diagnostic-request'),
                        'status': 'UNEXECUTED_ROOT_REVIEW_REQUIRED'})
    save('STATIC-CHECKS.json', {'status': 'AST_AND_EXACT_INPUT_FREEZE_ONLY', 'source_members_joined': 841,
                              'input_pins': len(pins), 'original89_preserved': True, 'frozen_original_methods': 1,
                              'workload_cases': 256, 'test_method_body_unmodified': True,
                              'launch_and_worker_ast_parsed': True, 'native_or_project_execution': False,
                              'request_sha256': sha256((ROOT / 'REQUEST.json').read_bytes()).hexdigest()})
    print(json.dumps({'request': body_pin((ROOT / 'REQUEST.json').read_bytes()), 'inputs': len(pins),
                      'control_bytes': [(n, (ROOT / 'control' / n).stat().st_size) for n in ('launch.py','worker.py')],
                      'status': 'FROZEN_UNEXECUTED'}))


if __name__ == '__main__':
    main()
