"""Freeze the separate ELF-coordinate correction without a native invocation."""
from __future__ import annotations

import ast
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parent
OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e')
FAILED = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r3-20261112-e26e')
FAILURE = Path('/workspace/scratch/e26ed3e2edcf/native-cli-r3-failure-custody-r1')
ACTUAL = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-actual-r4')
SOURCE_ACTUAL = Path('/workspace/scratch/e26ed3e2edcf/native-cli-runtime-layout-source-controls-r4')
PARENT_REQUEST = '7e2d37f425987c827a09f5cd0207595fd86e2e56'
PARENT_ORIGINALS = 'f9afe31e640ec51d8fdcf7bd35a54e18bb4ccb12'
TARGETS = ('hepta/hia_cli_json_runtime312.py', 'hepta/hia_cli_json_runtime312_control.py')
NEW_SCRIPTS = ('build_runtime_mapping_revision.py', 'source_controls.py', 'freeze_revision_r4.py')


def wire(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def identity(info):
    return tuple(getattr(info, 'st_' + key) for key in
                 ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns'))


def read(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(fd)) == identity(info)
        chunks = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            assert chunk
            chunks.append(chunk)
            remaining -= len(chunk)
        assert not os.read(fd, 1)
        assert identity(info) == identity(os.fstat(fd)) == identity(path.lstat())
    finally:
        os.close(fd)
    return b''.join(chunks), info


def record(path, relative=None, mode=True):
    raw, info = read(path)
    value = {'path': str(path) if relative is None else relative, 'bytes': len(raw),
             'sha256': hashlib.sha256(raw).hexdigest(),
             'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
    if mode:
        value['mode'] = stat.S_IMODE(info.st_mode)
    return value


def create(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        position = 0
        while position < len(raw):
            count = os.write(fd, raw[position:])
            assert count > 0
            position += count
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        retained = bytearray()
        while len(retained) < len(raw):
            part = os.read(fd, min(65536, len(raw) - len(retained)))
            assert part
            retained.extend(part)
        assert bytes(retained) == raw and not os.read(fd, 1)
    finally:
        os.close(fd)
    assert read(path)[0] == raw
    return record(path)


def main():
    assert ROOT == Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4')
    assert not os.path.lexists(ACTUAL) and not os.path.lexists(SOURCE_ACTUAL)
    old_raw = read(OLD / 'POLICY.json')[0]
    assert hashlib.sha256(old_raw).hexdigest() == '3c9057cc8b1ed7722beb6a7f9cdca01571459290b66b0334263f0eeb908d00b7'
    old = json.loads(old_raw)
    assert json.loads(read(FAILED / 'FINAL.json')[0])['status'] == 'HOLD'
    expected_new = {
        TARGETS[0]: '5eeaa2720dcd347ff3e3cc62a828d2eb5a582aa61f3bfb8813524b4c3ee925d1',
        TARGETS[1]: 'bdf006b5283d6394d201d9b7ec95f70fd73c277b4ec2721f680ff169e1b39188',
    }
    for base, rows in ((Path('source'), old['source_files']),
                       (Path(), old['control_files'] + old['asset_files'])):
        for row in rows:
            source = OLD / base / row['path']
            assert record(source, row['path']) == row
            target = ROOT / base / row['path']
            if base == Path('source') and row['path'] in TARGETS:
                assert record(target, row['path'])['sha256'] == expected_new[row['path']]
                assert stat.S_IMODE(target.stat().st_mode) == row['mode']
            else:
                create(target, read(source)[0], row['mode'])
    changes = []
    patch = []
    for relative in TARGETS:
        before = read(OLD / 'source' / relative)[0]
        after = read(ROOT / 'source' / relative)[0]
        ast.parse(after, filename=relative)
        changes.append({'path': relative, 'before': record(OLD / 'source' / relative, relative),
                        'after': record(ROOT / 'source' / relative, relative)})
        patch.extend(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                     fromfile='r3/' + relative, tofile='r4/' + relative))
        create(ROOT / 'reference/r3-source' / relative, before)
    create(ROOT / 'SOURCE-DELTA.patch', ''.join(patch).encode())
    for name in ('STATIC-ELF-REPORT.r2.json', 'read_elf_symbols_r2.py', 'IDENTITY-READER-CORRECTION.json'):
        create(ROOT / 'reference/independent-runtime-ELF' / name,
               read(FAILURE / 'runtime-ELF-static' / name)[0])
    create(ROOT / 'reference/R3-HOLD-HANDOFF.original.json', read(FAILURE / 'HANDOFF.json')[0])
    actual_root = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-invocation-r3')
    create(ROOT / 'reference/ROOT-R3-ACTUAL-READBACK.original.json', read(actual_root / 'READBACK.json')[0])
    create(ROOT / 'reference/ROOT-R3-GIT-READBACK.original.json', read(Path(
        '/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-actual-r3-git-review/ROOT-READBACK.json'))[0])
    ast_values = ast.parse(read(ROOT / 'source_controls.py')[0])
    ids_node = next(n for n in ast_values.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'IDS' for t in n.targets))
    ids = ast.literal_eval(ids_node.value)
    assert len(ids) == len(set(ids)) == 28
    source_inputs = [record(ROOT / name, mode=False) for name in (
        'source_controls.py', 'source/' + TARGETS[0], 'source/' + TARGETS[1],
        'reference/NEW-PROCESS-MAPS.json')]
    source_inputs.append(record(Path(old['python']['path']), mode=False))
    source_request = {
        'schema': 'hia.cli-json.runtime-layout-source-control-request.v1',
        'status': 'FROZEN_NOT_EXECUTED', 'output': str(SOURCE_ACTUAL),
        'expected_ids': list(ids), 'inputs': source_inputs, 'runtime_pin': old['python'],
        'command': [old['python']['path'], '-I', '-S', '-B', str(ROOT / 'source_controls.py'),
                    '--output', str(SOURCE_ACTUAL)],
        'cwd': str(ROOT), 'environment': {'PATH': '', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
        'new_source_control_wall_seconds': 20,
        'counterexamples_are_separate_from_original8_and10': True,
        'pure_AST_extracted_ELF_and_map_functions_only': True,
        'ctypes_DSO_HIA_compiler_or_product_execution': False,
        'actual_r3_mapping_reconstruction': False,
        'original_native_populations_and_limits_unchanged': True,
        'root_review_required_before_execution': True,
    }
    create(ROOT / 'SOURCE-CONTROL-REQUEST.json', wire(source_request))
    policy = copy.deepcopy(old)
    policy['operation_key'] = 'hia-cli-json-c-runtime-lifetime-local312-r4'
    policy['operation_root'] = str(ACTUAL)
    policy['c_command'] = [value.replace(str(OLD), str(ROOT)).replace(old['operation_root'], str(ACTUAL))
                           for value in old['c_command']]
    policy['source_files'] = [record(ROOT / 'source' / row['path'], row['path']) for row in old['source_files']]
    policy['control_files'] += [record(ROOT / name, name) for name in NEW_SCRIPTS + ('SOURCE-CONTROL-REQUEST.json',)]
    changed = [r['path'] for r, previous in zip(policy['source_files'], old['source_files']) if r != previous]
    assert set(changed) == set(TARGETS) and len(changed) == 2
    inverse = copy.deepcopy(policy)
    for key in ('operation_key', 'operation_root', 'c_command', 'source_files', 'control_files'):
        inverse[key] = old[key]
    assert inverse == old
    policy_pin = create(ROOT / 'POLICY.json', wire(policy))
    request = json.loads(read(OLD / 'REQUEST.json')[0])
    request.update(operation_key=policy['operation_key'], operation_root=str(ACTUAL),
                   policy_sha256=policy_pin['sha256'])
    request_pin = create(ROOT / 'REQUEST.json', wire(request))
    preexec = json.loads(read(OLD / 'PREEXEC.json')[0])
    for key in ('original_14_bound_control_inputs_byte_identical', 'new_authoring_script',
                'new_authoring_script_is_bound_control_input'):
        preexec.pop(key, None)
    preexec.update(command=[old['python']['path'], '-I', '-S', '-B', str(ROOT / 'control/launch.py'),
                           '--request', str(ROOT / 'REQUEST.json'), '--sha256', request_pin['sha256']],
                   cwd=str(ROOT), request=request_pin, policy=policy_pin,
                   source_bytes=sum(row['bytes'] for row in policy['source_files']),
                   previous_failed_request_commit=PARENT_REQUEST,
                   previous_failure_originals_commit=PARENT_ORIGINALS,
                   original_15_bound_control_inputs_byte_identical=True,
                   original_11_runtime_control_files_byte_identical=True,
                   new_bound_authoring_and_counterexample_inputs=list(NEW_SCRIPTS) + ['SOURCE-CONTROL-REQUEST.json'],
                   source_counterexamples_request=record(ROOT / 'SOURCE-CONTROL-REQUEST.json'),
                   source_counterexamples_executed=False,
                   source_and_control_AST_parses_only=5)
    create(ROOT / 'PREEXEC.json', wire(preexec))
    reference_pins = [record(path, path.relative_to(ROOT).as_posix())
                      for path in sorted((ROOT / 'reference').rglob('*')) if path.is_file()]
    correction = {
        'schema': 'hia.cli-json.runtime-ELF-coordinate-correction.v1',
        'status': 'STATIC_SUCCESSOR_NOT_EXECUTED',
        'original_HOLD_request': PARENT_REQUEST, 'original_HOLD_full_custody': PARENT_ORIGINALS,
        'actual_original': {'C_compile': 'PASS', 'runtime_loaded': 2, 'runtime_executed': 1,
                            'runtime_error': 'ValueError: runtime ELF profile differs',
                            'HIA_compile': False, 'lifetime_executed': 0, 'HIA_returns': 0, 'C_pumps': 0},
        'actual_ELF': {'type': 2, 'type_name': 'ET_EXEC', 'load_segments': 6,
                       'lowest_load_page': 4190208, 'executable_load_segments': 2,
                       'base_entries': 11, 'control_entries': 5, 'unique_functions': 15},
        'source_changed_files': changes, 'other_source_files_whole_byte_unchanged': 180,
        'original_11_runtime_controls_whole_byte_unchanged': True,
        'original_8_and_10_case_bodies_whole_byte_unchanged': True,
        'original_expected_HIA_returns': 48, 'original_expected_C_pumps': 11,
        'original_outer_seconds': 180, 'original_cleanup_seconds': 3,
        'original_inner_seconds': [20, 5, 20, 5],
        'original_HIA_compile_wall_CPU_output': [20, 10, 1048576],
        'original_bad_SHA_size_and_changed_table_refusals_retained': True,
        'address_derivation': ['actual evaluator anchor minus exact ELF st_value gives relocation bias',
                               'ET_EXEC requires zero bias; ET_DYN keeps independently derived page-aligned bias',
                               'dladdr image base equals bias plus lowest nonempty PT_LOAD virtual page',
                               'the inode/path/offset/permissions of every file-backed LOAD are observed in current proc maps',
                               'both endpoints and every byte of each full function span belong to the same admitted mapped image'],
        'shared_parser_and_mapping_proof_for_both_entrances': True,
        'same_path_changed_inode_missing_section_ambiguous_symbol_unmapped_or_writable_code_refused': True,
        'new_maps_metadata_limit_bytes': 1048576,
        'maps_limit_scope': 'Inspection evidence only; it is not a JSON value or output limit',
        'new_28_pure_python_source_controls_frozen_not_executed': True,
        'new_source_control_output': str(SOURCE_ACTUAL),
        'new_map_metadata_observation_is_separate_from_original_child': True,
        'new_admit_runtime_C_HIA_and_lifetime_execution': False,
        'glibc_upstream_commit': '74f59e9271cbb4071671e5a474e7d4f1622b186f',
        'glibc_upstream_tag': 'glibc-2.41',
        'installed_libc_banner': 'Debian GLIBC 2.41-12+deb13u4',
        'upstream_sources_are_mechanism_evidence_not_a_reproducible_build_claim': True,
        'reference_pins': reference_pins,
        'current_v89_62_compiler_originals_and_4555_system_inputs_unchanged': True,
        'fresh_cold_or_current_v92_matching_claimed': False,
        'original17_CLI_and46_traces_preserved_and_unexecuted': True,
        'CALL_SEND_UNPACK_activation_and_r4f_ownership_closed': False,
    }
    create(ROOT / 'CORRECTION.json', wire(correction))
    for name in NEW_SCRIPTS:
        ast.parse(read(ROOT / name)[0], filename=name)
    assert not os.path.lexists(ACTUAL) and not os.path.lexists(SOURCE_ACTUAL)
    print(json.dumps({'status': correction['status'], 'policy': policy_pin, 'request': request_pin,
                      'source_delta': changes, 'source_files': len(policy['source_files']),
                      'bound_controls': len(policy['control_files']),
                      'source_controls': 28, 'native_8_and_10_executed': False}))


if __name__ == '__main__':
    main()
