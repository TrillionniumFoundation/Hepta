"""Bind only actual R3 Source18/Native17/VM12; never run product here.

Make a separate 3191-file byte-copy view and exact still-unexecuted plan.
No generator, compiler, port, issuer, mapping, test or VM is invoked.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).absolute().parent
KIT = Path('/workspace/scratch/dda74a4fae35/v119-inspect-policy-execution-r1')
sys.path.insert(0, str(KIT))
from inspect_exec_support import (complete_receipt, json_bytes, pin, publish,
    read_regular, require, snapshot, tree_digest)
SCHEMA = 'hepta.hia.inspect-cli-witness.execution.v1'
ROOT = Path('/dev/shm/hia-inspect-cli-controls-dda7')


def fixed(row):
    path = Path(row['path'])
    raw = read_regular(path, maximum=max(1048576, row['pin']['bytes']), expected=row['pin'])
    require(stat.S_IMODE(path.lstat().st_mode) == row['posix_mode'], 'full actual mode differs')
    return raw


def binding(path):
    path = Path(path).absolute()
    raw = read_regular(path, maximum=max(1048576, path.lstat().st_size))
    mode = stat.S_IMODE(path.lstat().st_mode)
    return {'path': str(path), 'pin': pin(raw, mode='100755' if mode & 0o111 else '100644'),
            'posix_mode': mode}


def tests(value, ids):
    require(value['status'] == 'PASS' and value['declared_ids'] == ids
            and value['loaded_ids'] == ids and value['started_ids'] == ids
            and value['stopped_ids'] == ids and value['tests_run'] == len(ids)
            and all(not value.get(key) for key in ('failures', 'errors', 'skipped',
                'expected_failures', 'unexpected_successes', 'loader_errors')), 'exact actual tests not PASS')


def admit_stage_result(descriptor, wanted, groups, tree, generation_pin):
    result = json_bytes(fixed(descriptor))
    require(result['status'] == wanted and result['source_tree'] == tree
            and result['source_files'] == 3188 and result['complete_source_guard_pass'] is True
            and result['generation_result_pin'] == generation_pin,
            'actual R3/source/generation predecessor differs')
    require([row['label'] for row in result['stages']] == list(groups), 'actual group order differs')
    require(result['owner_launch_attempts'] == len(groups), 'actual predecessor owner count differs')
    for row in result['evidence']:
        fixed(row)
    for row in result['stages']:
        require(row['status'] == 'PASS' and row['source_guard_pass'] is True,
                'a failed/unconfirmed predecessor cannot open op10')
        complete_receipt(row['owner_returned'], Path(row['directory']) / 'OWNER.json')
        if row['label'] != 'build-inspect':
            tests(row['tests'], groups[row['label']]['ids'])
    return result


def bind(request_path, request_sha256):
    raw = read_regular(Path(request_path).absolute(), maximum=16 << 20)
    require(hashlib.sha256(raw).hexdigest() == request_sha256, 'binding request differs')
    request = json_bytes(raw)
    require(set(request) == {'schema', 'base_source', 'base_manifest', 'generation',
        'source_result', 'native_vm_result', 'inspect_image', 'authoring_index'}
        and request['schema'] == SCHEMA + '.binding-request', 'exact actual descriptors required')
    index = json_bytes(fixed(request['authoring_index']))
    for row in index['files'].values():
        fixed(row)
    template = json_bytes((HERE / 'EXECUTION-TEMPLATE.json').read_bytes())
    require(template['state'] == 'AUTHORING_NOT_EXECUTABLE_PENDING_R3', 'authoring contract differs')
    base = Path(request['base_source'])
    require(base.is_absolute() and not base.is_symlink()
            and base.is_relative_to('/dev/shm/hia-inspect-drive-r3-dda7'), 'only independent R3 base admitted')
    expected = json_bytes(fixed(request['base_manifest']))
    actual = snapshot(base)
    require(len(actual) == 3188 and actual == expected, 'actual full 3188 source differs')
    base_modes = {name: stat.S_IMODE((base / name).lstat().st_mode) for name in actual}
    tree = tree_digest(actual)
    require(tree == template['known_actual_r3_generation_only']['source_tree'],
            'a future/different R3 tree requires a separate authoring successor')
    require(pin((base / 'hepta/hia_inspect_program_native.py').read_bytes()) == template['drive_runtime_after'],
            'exact five-line drive successor required')
    for name, row in template['protected_source_files'].items():
        require(actual[name] == row, 'original test/policy/CLI source changed: ' + name)
    generation_raw = fixed(request['generation'])
    require(request['generation']['path'] == template['known_actual_r3_generation_only']['result_path']
            and pin(generation_raw)['git_blob'] == template['known_actual_r3_generation_only']['result_git_blob'],
            'generation authority is not the actual fixed R3 result')
    generation = json_bytes(generation_raw)
    require(generation['status'] == 'GENERATION_ONLY_PASS' and generation['source_files'] == 3188
            and generation['source_final_tree'] == tree and generation['generation_invocations'] == 2
            and generation['check_invocations'] == 1 and generation['generated_metadata_current'] is True
            and generation['native_compilations'] == 0 and generation['product_tests'] == 0,
            'actual final R3 generation is incomplete')
    source_groups = {label: template['predecessor_groups'][label]
                     for label in ('source10', 'source8-physical-lease')}
    native_groups = {label: template['predecessor_groups'][label]
                    for label in template['predecessor_native_order']}
    source_result = admit_stage_result(request['source_result'], 'SOURCE_CONTROLS_PASS',
                                      source_groups, tree, pin(generation_raw))
    native_result = admit_stage_result(request['native_vm_result'], 'DEVELOPMENT_NATIVE_VM_PASS',
                                      native_groups, tree, pin(generation_raw))
    require(source_result['runtime'] == native_result['runtime'], 'actual runtimes differ')
    image_raw = fixed(request['inspect_image'])
    build_row = native_result['stages'][0]
    require(build_row['label'] == 'build-inspect'
            and build_row['build']['image'] == pin(image_raw), 'actual Native17/VM12 image differs')
    require(not ROOT.exists(), 'one exclusive materialization/binding root required')
    minimum = (1 << 30) + sum(row['bytes'] for row in actual.values()) + (32 << 20)
    require(os.statvfs(ROOT.parent).f_bavail * os.statvfs(ROOT.parent).f_frsize >= minimum,
            'source copy must leave original 1GiB and explicit preparation headroom')
    ROOT.mkdir(mode=0o700)
    publish(ROOT / 'BINDING-REQUEST.json', request)
    publish(ROOT / 'BASE-SOURCE-BEFORE.json', actual)
    view = ROOT / 'source'; view.mkdir(mode=0o700)
    modes = {}
    for name, row in actual.items():
        path = base / name
        data = read_regular(path, maximum=max(1048576, row['bytes']), expected=row)
        mode = stat.S_IMODE(path.lstat().st_mode)
        target = view / name; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        os.chmod(target, mode); modes[name] = mode
    expected_view = dict(actual)
    for name, row in template['source_overlay'].items():
        require(name not in actual, 'adapter path was not new')
        data = fixed(row)
        target = view / name
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        os.chmod(target, 0o644)
        expected_view[name] = pin(data); modes[name] = 0o644
    after = snapshot(view)
    require(after == expected_view and len(after) == 3191 and snapshot(base) == actual
            and all(stat.S_IMODE((base / name).lstat().st_mode) == mode for name, mode in base_modes.items())
            and all(stat.S_IMODE((view / name).lstat().st_mode) == mode for name, mode in modes.items()),
            'exact three additions/full old source conservation failed')
    publish(ROOT / 'SOURCE-MAP.json', after)
    publish(ROOT / 'SOURCE-MODES.json', modes)
    publish(ROOT / 'BASE-SOURCE-AFTER.json', actual)
    plan = {key: template[key] for key in ('schema', 'limits', 'groups', 'group_order')}
    plan.update(state='BOUND_AWAITING_EXPLICIT_EXECUTION', source=str(view),
        source_tree=tree_digest(after), source_manifest=binding(ROOT / 'SOURCE-MAP.json'),
        source_modes=binding(ROOT / 'SOURCE-MODES.json'), runtime=native_result['runtime'],
        attempt=str(ROOT / 'attempt-r1'), compiler=template['compiler'],
        adapter_files={name: row['pin'] for name, row in template['source_overlay'].items()},
        controls=index['files'], retained_authorities=template['retained_authorities'],
        predecessor_inspect_image=request['inspect_image'])
    plan['predecessor_evidence'] = [request[key] for key in
        ('base_manifest', 'generation', 'source_result', 'native_vm_result', 'inspect_image', 'authoring_index')]
    plan['predecessor_evidence'] += source_result['evidence'] + native_result['evidence']
    publish(ROOT / 'EXECUTION-PLAN.json', plan)
    frozen = binding(ROOT / 'EXECUTION-PLAN.json')
    publish(ROOT / 'BINDING-RESULT.json', {'status': 'BOUND_NOT_EXECUTED', 'plan': frozen,
        'source_tree': plan['source_tree'], 'source_files': 3191,
        'argv': [plan['runtime']['launch_executable'], '-I', '-B', str(HERE / 'run_inspect_cli_controls.py'),
                 '--execute', frozen['path'], '--plan-sha256', frozen['pin']['sha256']],
        'product_execution': False, 'explicit_root_execution_review_still_required': True})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind-request', required=True, type=Path)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args()
    bind(args.bind_request, args.request_sha256)
