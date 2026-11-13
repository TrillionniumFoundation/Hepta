"""Root read-only admission for the eight unchanged, inert Rust195 source controls."""
from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import os
import sys

ROOT = Path('/tmp/hia-full32-rust195-source-eight-plan-r2-20261112-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/full32-rust195-source8-r2-review')
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('root_review_source8_common', ROOT / 'control/common.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def read_json(path):
    pin, raw = common.read(path)
    return json.loads(raw), pin


def main():
    git, _ = read_json(OUT / 'GIT-READBACK.json')
    assert git['status'] == 'ALL29_RAW_AND_4244_TREE_PASS'
    assert git['commit'] == '20bcabac0a7c6be1d5afc2d333622bbed3135dfa'
    files = []
    for entry in git['files']:
        pin, raw = common.read(Path(entry['local']))
        assert all(pin[k] == entry[k] for k in ('bytes', 'sha256', 'git_blob'))
        assert pin['identity'][2] & 0o022 == 0
        files.append(pin)
    assert len(files) == 29
    request, request_pin = read_json(ROOT / 'REQUEST.json')
    assert request_pin['sha256'] == '2818142cea6592022bb0d54fc7d3de93c8c19a548834e82c244869f2c55389a3'
    runtime_pin, _ = common.read(Path(sys.executable).resolve())
    assert all(runtime_pin[k] == request['runtime'][k] for k in ('path', 'bytes', 'sha256', 'git_blob', 'identity'))
    assert list(sys.version_info[:3]) == request['runtime_version'] == [3, 12, 14]
    assert request['environment'] == {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'PYTHONUNBUFFERED': '1'}
    assert request['command'] == [runtime_pin['path'], '-I', '-S', '-B', str(ROOT / 'control/worker.py'), str(ROOT / 'REQUEST.json')]
    assert (request['qualification_seconds'], request['cleanup_seconds'], request['expected_methods']) == (180, 3, 8)
    assert (request['minimum_free_bytes'], request['minimum_free_inodes'], request['maximum_output_bytes']) == (268435456, 4096, 16777216)
    assert request['product_source_binding'] is None and request['current_product_source_still_pending_v92_CI']
    for key in ('supplier_execution_permitted', 'APT_execution_permitted', 'Rustup_execution_permitted', 'network_permitted', 'native_execution_permitted', 'product_qualification_execution_permitted'):
        assert request[key] is False
    records = common.input_records(ROOT, request)
    assert len(records) == 15
    old = Path('/tmp/hia-full32-rust195-supply-r5-20261112-e26e')
    for name in records:
        if name.startswith('inputs/'):
            _, a = common.read(ROOT / name)
            _, b = common.read(old / name[len('inputs/'):])
            assert a == b
    code_pin, controls = common.read(ROOT / 'inputs/controls/check_rust195_self_update_r5.py')
    assert code_pin['sha256'] == '0798c7464344af691dbfd402cacf247abc006f38dd53ce60c226d666051a0a5a'
    parsed = ast.parse(controls)
    cls = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == 'Rust195SelfUpdateR5SourceControls')
    ids = [cls.name + '.' + node.name for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
    assert ids == request['expected_ids'] and len(ids) == len(set(ids)) == 8
    peer, peer_pin = read_json(ROOT / 'evidence/PEER-REVIEW-r2.original.json')
    assert peer['status'] == 'STATIC_REVIEW_PASS_NARROW_R2_DELTA' and not peer['execution_performed']
    assert peer['request']['sha256'] == request_pin['sha256'] and all(peer['checks'].values())
    for row in peer['source_inputs']:
        actual, _ = common.read(Path(row['path']))
        assert all(actual[k] == row[k] for k in ('bytes', 'sha256', 'git_blob'))
    _, worker = common.read(ROOT / 'control/worker.py')
    _, launch = common.read(ROOT / 'control/launch.py')
    assert b"except BaseException as error:\n        report['status'] = 'HOLD'" in worker
    assert b"except BaseException as error:\n        final['status'] = 'HOLD'" in launch
    assert b"report.get('exception') is None" in launch and b"and not final['errors'] else 1" in launch
    assert records['control/process_owner_impl.py']['sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
    semantic, semantic_pin = read_json(Path('/workspace/scratch/e26ed3e2edcf/root/full32-r5-static-review-r1/ROOT-SEMANTIC-REVIEW.json'))
    assert semantic['status'] == 'STATIC_MINIMAL_CHANGE_AND_PRIMARY_CAUSE_PASS'
    assert semantic_pin['sha256'] == '479ccd31fb4a37bd6edc74bcdcbc9a838e74d3e17e040399d25bd51503ccff24'
    assert semantic['candidate']['sha256'] == records['inputs/candidate/supply_v87.py']['sha256']
    assert not os.path.lexists(request['operation_root'])
    available = os.statvfs('/tmp')
    assert available.f_bavail * available.f_frsize >= request['minimum_free_bytes'] and available.f_favail >= request['minimum_free_inodes']
    common.create(OUT / 'INPUTS-BEFORE.original.json', records)
    report = {'schema': 'hia.root.rust195-source-eight-static-review.v1', 'status': 'ROOT_REVIEW_PASS_FOR_ONE_SOURCE_ONLY_REQUEST',
        'canonical': git['commit'], 'tree': git['tree'], 'request': request_pin,
        'whole29_published_file_pins_freshly_matched': files, 'input_records': records, 'runtime': runtime_pin,
        'peer_review': peer_pin, 'semantic_review': semantic_pin,
        'expected_methods': 8, 'expected_ids': ids, 'original_method_bytes_and_order_unchanged': True,
        'scope': 'Only original eight inert AST/mock source controls; no supplier import/execution, APT, Rustup, network, native or product qualification.',
        'owner_seconds': 180, 'cleanup_seconds': 3, 'source_generation_or_test_execution_performed_by_review': False,
        'worker_request_pin_must_be_joined_in_actual_readback': True,
        'all_original_failure_HOLD_UNKNOWN_states_retained': True,
        'r1_wrapper_static_fail_stop_findings_preserved_unexecuted': True,
        'current_product_source_binding': None, 'output_absent': True, 'whole_native_rewrite_closed': False}
    pin = common.create(OUT / 'ROOT-REVIEW.json', report)
    print(json.dumps({'status': report['status'], 'review': pin, 'expected': 8, 'inputs': 15, 'actual_absent': True}, sort_keys=True))


if __name__ == '__main__':
    main()
