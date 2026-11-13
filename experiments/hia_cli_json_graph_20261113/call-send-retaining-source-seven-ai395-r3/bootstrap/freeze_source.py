"""Freeze R3 after the one completed R2c SOURCE HOLD, without rerunning it.

Only filesystem/hash/metadata and literal inverse comparisons run here.
No project import, source authoring, Core VM, C/HIA compile, or test is run.
"""
from __future__ import annotations
import ast
import ctypes
import difflib
import hashlib
import json
import mmap
import os
from pathlib import Path
import stat
import socket
import subprocess
import sys

ROOT = Path('/home/qq/hia-rewrite-20261113-e26e-r1/cli-source-seven-r3')
BOOT_ID = 'b1620269-aaef-43e7-bf47-bc6eb1c1a447'
PYTHON = Path('/usr/bin/python3.14')
PYTHON_SHA = '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41'
FIELDS = ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')

def identity(st):
    return [getattr(st, 'st_' + name) for name in FIELDS]

def read(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('fixed ordinary single-link file required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('opened identity differs')
        data = bytearray()
        left = before.st_size
        while left:
            piece = os.read(fd, min(left, 65536))
            if not piece:
                raise ValueError('short input')
            data.extend(piece)
            left -= len(piece)
        if os.read(fd, 1):
            raise ValueError('input grew')
        if identity(os.fstat(fd)) != identity(before) or identity(path.lstat()) != identity(before):
            raise ValueError('input changed')
    finally:
        os.close(fd)
    return bytes(data), before

def wire(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()

def hashes(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def record(path, relative=False):
    raw, st = read(path)
    return {'path': path.relative_to(ROOT).as_posix() if relative else str(path),
            **hashes(raw), 'mode': stat.S_IMODE(st.st_mode), 'identity': identity(st)}

def system_record(path):
    """Observe a fixed root-owned non-writable runtime input, including real hard links."""
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or before.st_nlink < 1 or stat.S_IMODE(before.st_mode) & 0o022):
        raise ValueError('fixed root-owned readonly runtime file required: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('runtime descriptor identity differs')
        chunks = []
        left = before.st_size
        while left:
            chunk = os.read(fd, min(left, 65536))
            if not chunk:
                raise ValueError('short runtime read')
            chunks.append(chunk)
            left -= len(chunk)
        if os.read(fd, 1):
            raise ValueError('runtime input grew')
        if identity(os.fstat(fd)) != identity(before) or identity(path.lstat()) != identity(before):
            raise ValueError('runtime input identity changed')
    finally:
        os.close(fd)
    raw = b''.join(chunks)
    return {'path': str(path), **hashes(raw), 'mode': stat.S_IMODE(before.st_mode),
            'identity': identity(before)}


def private(path):
    path.mkdir(mode=0o700)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.geteuid():
        raise ValueError('new private directory required')

def parents(path):
    todo = []
    current = path.parent
    while not current.exists():
        todo.append(current)
        current = current.parent
    if current != ROOT and ROOT not in current.parents:
        raise ValueError('creation escaped exclusive root')
    while todo:
        private(todo.pop())
    for current in path.parents:
        if current == ROOT.parent:
            break
        st = current.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise ValueError('unsafe exclusive directory spine')

def create(path, raw, mode=0o600):
    parents(path)
    if os.path.lexists(path):
        retained, st = read(path)
        if retained != raw or stat.S_IMODE(st.st_mode) != mode:
            raise ValueError('existing restoration byte/mode mismatch: ' + str(path))
        return record(path)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            if count <= 0:
                raise OSError('short write')
            at += count
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        pieces = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            pieces.append(chunk)
        if b''.join(pieces) != raw:
            raise ValueError('descriptor readback differs')
    finally:
        os.close(fd)
    if read(path)[0] != raw:
        raise ValueError('named readback differs')
    return record(path)


def main():
    spec = json.loads(read(ROOT / 'bootstrap/SPEC.json')[0])
    old_root = Path(spec['old_root'])
    if str(ROOT) != spec['root'] or ROOT == old_root:
        raise ValueError('new exclusive R3 root differs')
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != BOOT_ID:
        raise ValueError('new host boot differs')
    if Path(sys.executable).resolve() != PYTHON or sys.version_info[:3] != (3, 14, 4):
        raise ValueError('source-only Python differs')
    if hashes(read(PYTHON)[0])['sha256'] != PYTHON_SHA:
        raise ValueError('source-only Python bytes differ')
    old_expected = {row['path']: row for row in spec['r2_files']}
    if len(old_expected) != 234:
        raise ValueError('frozen R2c population differs')
    guardian_raw, _ = read(old_root / 'guardian/guardian.json')
    if hashes(guardian_raw)['sha256'] != spec['prior_actual']['guardian_sha256']:
        raise ValueError('actual R2c guardian pin differs')
    actual_guardian = json.loads(guardian_raw)
    life = actual_guardian['lifecycle']
    cleanup = life['cleanup']
    if (actual_guardian['status'] != 'HOLD' or life['returncode'] != 1
            or life['qualification_seconds'] != 180 or life['cleanup_seconds'] != 3
            or life['schema'] != 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            or life['subreaper_enabled'] is not True
            or cleanup['complete'] is not True or cleanup['observed_echild'] is not True
            or cleanup['leader_reaped'] is not True or cleanup['remaining_direct_children'] != []
            or cleanup['errors'] != [] or cleanup['deadline_exceeded'] is not False):
        raise ValueError('completed R2c owner is not closed')
    report_raw, _ = read(old_root / 'actual/REPORT.json')
    if hashes(report_raw)['sha256'] != spec['prior_actual']['report_sha256']:
        raise ValueError('actual R2c report pin differs')
    old_names = []
    for path in old_root.rglob('*'):
        st = path.lstat()
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            raise ValueError('non-regular frozen R2c leaf')
        relative = path.relative_to(old_root).as_posix()
        if relative.startswith('actual/') or relative in (
                'guardian/guardian.json', 'guardian/child.stdout.log', 'guardian/child.stderr.log'):
            continue
        old_names.append(relative)
    if sorted(old_names) != sorted(old_expected):
        raise ValueError('frozen R2c leaf population changed')
    old_inventory_raw, old_inventory_stat = read(old_root / 'FROZEN-FILES.json')
    if hashes(old_inventory_raw) != {k: old_expected['FROZEN-FILES.json'][k]
                                   for k in ('bytes', 'sha256', 'git_blob')}:
        raise ValueError('original R2c inventory bytes differ')
    old_physical = {row['path']: row for row in json.loads(old_inventory_raw)['files']}
    old_records = {}
    for name, pin in sorted(old_expected.items()):
        observed = record(old_root / name)
        if {k: observed[k] for k in ('bytes', 'sha256', 'git_blob', 'mode')} != {
                k: pin[k] for k in ('bytes', 'sha256', 'git_blob', 'mode')}:
            raise ValueError('R2c original byte/mode mismatch: ' + name)
        if name in old_physical and observed['identity'] != old_physical[name]['identity']:
            raise ValueError('R2c original physical identity changed: ' + name)
        old_records[name] = observed
    if os.path.lexists(ROOT / 'actual'):
        raise ValueError('new qualification output already exists; do not repeat')
    config_old = json.loads(read(old_root / 'control/CONFIG.json')[0])
    preexec_old = json.loads(read(old_root / 'PREEXEC.json')[0])
    if (len(config_old['components']) != 7 or len(config_old['limits']) != 9
            or len(config_old['original_cli_ids']) != 17
            or len(config_old['trace_plan_ids']) != 46):
        raise ValueError('original populations/caps differ')
    for name in spec['reference_names']:
        create(ROOT / 'reference/r2c-frozen' / name, read(old_root / name)[0],
               old_expected[name]['mode'])
    for item in spec['reference_files']:
        raw = item['text'].encode()
        if hashes(raw) != item['pin']:
            raise ValueError('reference input text pin differs')
        create(ROOT / item['path'], raw)
    source_pins, source_identities = {}, {}
    for name, pin in sorted(config_old['source_pins'].items()):
        relative = 'source/' + name
        raw = read(old_root / relative)[0]
        if hashes(raw) != pin:
            raise ValueError('original source bytes differ: ' + name)
        for edit in spec['source_edits']:
            if name != edit['path']:
                continue
            if hashes(raw) != edit['before_pin']:
                raise ValueError('source correction original pin differs')
            before, after = edit['before'].encode(), edit['after'].encode()
            if raw.count(before) != 1:
                raise ValueError('source correction is not unique')
            revised = raw.replace(before, after)
            if revised.count(after) != 1 or revised.replace(after, before) != raw:
                raise ValueError('source correction inverse differs')
            if hashes(revised) != edit['after_pin']:
                raise ValueError('source correction final pin differs')
            raw = revised
        create(ROOT / relative, raw, old_expected[relative]['mode'])
        current = record(ROOT / relative)
        source_pins[name] = {k: current[k] for k in ('bytes', 'sha256', 'git_blob')}
        source_identities[name] = current['identity']
    changed = [name for name in source_pins if source_pins[name] != config_old['source_pins'][name]]
    if len(source_pins) != 198 or changed != [spec['source_edits'][0]['path']]:
        raise ValueError('source correction changed more than the one frozen source')
    unary_before, unary_after = [], []
    for label, module in config_old['components']:
        name = module.replace('.', '/') + '.py'
        for base, result in ((old_root / 'source', unary_before), (ROOT / 'source', unary_after)):
            tree = ast.parse(read(base / name)[0])
            values = [n.value.value for n in tree.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in n.targets)
                      and isinstance(n.value, ast.Constant) and type(n.value.value) is str]
            if len(values) != 1:
                raise ValueError('literal SOURCE missing')
            for node in ast.walk(ast.parse(values[0])):
                if isinstance(node, ast.UnaryOp):
                    result.append({'component': label, 'line_in_SOURCE': node.lineno,
                                   'ast': ast.dump(node)})
    if (len(unary_before) != 1 or unary_before[0]['component'] != 'call_fast'
            or unary_before[0]['ast'] != "UnaryOp(op=Not(), operand=Name(id='valid', ctx=Load()))"
            or unary_after != []):
        raise ValueError('seven SOURCE unary audit differs')
    source_delta = {
        'schema': 'hia.cli-json.source-seven.r3.source-correction.v1',
        'status': 'STATIC_SOURCE_CORRECTION_UNEXECUTED',
        'original_request': spec['prior_actual'],
        'changed_source': spec['source_edits'], 'source_files': 198,
        'other197_sources_whole_bytes_unchanged': True,
        'old_unary_operators': unary_before, 'new_unary_operators': unary_after,
        'reason': 'Original Builder lacks ast.Not; exact bool local valid is now compared with False using its existing bool Constant and compare.eq support.',
        'valid_domain': 'Only boolean comparison and and results; no foreign truth hook, operand evaluation or effect ordering is changed.',
        'builder_whole_bytes_unchanged': True,
        'source_generation_Core_caps_native_not_executed_by_freeze': True,
        'original7_components9_caps17_CLI46_trace_ids_unchanged': True}
    create(ROOT / 'proof/SOURCE-CORRECTION.json', wire(source_delta))
    for label, name in (('worker', 'source_authoring_worker.py'),
                        ('guardian', 'guardian.py')):
        new = spec[label + '_text']
        if hashes(new.encode()) != spec[label + '_pin']:
            raise ValueError('new control pin differs: ' + label)
        inverse = new
        for before, after in reversed(spec[label + '_edits']):
            if inverse.count(after) != 1:
                raise ValueError('nonunique control inverse: ' + label)
            inverse = inverse.replace(after, before)
        original = read(old_root / 'control' / name)[0]
        if inverse.encode() != original:
            raise ValueError('control inverse differs: ' + label)
        create(ROOT / 'control' / name, new.encode())
        patch = ''.join(difflib.unified_diff(original.decode().splitlines(True),
                    new.splitlines(True), fromfile='r2c/' + name, tofile='r3/' + name))
        create(ROOT / 'proof' / (label.upper() + '-DELTA.patch'), patch.encode())
    owner_raw = read(old_root / 'control/process_owner_impl.py')[0]
    if hashes(owner_raw)['sha256'] != '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2':
        raise ValueError('original owner369 differs')
    create(ROOT / 'control/process_owner_impl.py', owner_raw)
    clean = spec['clean_exec_text'].encode()
    if hashes(clean) != spec['clean_exec_pin']:
        raise ValueError('new clean-exec pin differs')
    if clean.decode().replace(str(ROOT), str(old_root)).encode() != read(old_root / 'control/clean_exec.py')[0]:
        raise ValueError('clean-exec non-path delta')
    create(ROOT / 'control/clean_exec.py', clean)
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json'):
        create(ROOT / name, read(old_root / name)[0], old_expected[name]['mode'])
    create(ROOT / 'SOURCE-STATUS.json', wire({
        'schema': 'hia.cli-json.source-seven.r3.source-status.v1',
        'origin': 'REBUILD_FROM_PRESERVED_BASELINE_UNEXECUTED',
        'status': 'R3_CORRECTED_SOURCE_UNEXECUTED',
        'prior_actual_R2c': spec['prior_actual'],
        'new_source_generation_or_Core_or_native_executed': False,
        'original17_and46_executed': False,
        'unchanged_other197_source_files': True,
        'no_qualification_inherited_from_old6_component_successes': True}))
    runtime_file = record(PYTHON)
    runtime_expected = {
        'file': {k: runtime_file[k] for k in ('path', 'bytes', 'sha256', 'identity')},
        'version_info': list(sys.version_info[:3]), 'version': sys.version, 'boot_id': BOOT_ID}
    maps_before = Path('/proc/self/maps').read_bytes()
    mapping_paths = set()
    for line in maps_before.decode().splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith('/'):
            if fields[5].endswith(' (deleted)'):
                raise ValueError('deleted runtime mapping')
            mapping_paths.add(fields[5])
    observed_mapped = [system_record(Path(path)) for path in sorted(mapping_paths)]
    maps_after = Path('/proc/self/maps').read_bytes()
    create(ROOT / 'proof/FREEZE-PROCESS-MAPS.before.original.txt', maps_before)
    create(ROOT / 'proof/FREEZE-PROCESS-MAPS.after.original.txt', maps_after)
    runtime = {
        'schema': 'hia.cli-json.source-seven.ai395-runtime.r3.v1',
        'scope': 'Source generation and Core validation only; not CPython 3.12 native ABI admission.',
        'boot_id': BOOT_ID, 'host': 'ai395', 'effective_uid': os.geteuid(),
        'effective_gid': os.getegid(), 'python': runtime_expected,
        'observed_freeze_process_mapped_files': observed_mapped,
        'stdlib_guard_modules_preloaded_in_freeze': ['ctypes', 'mmap', 'socket', 'subprocess'],
        'mapped_inventory_is_complete_future_module_closure': False,
        'mapped_read_policy': 'Only fixed root-owned regular readonly runtime inputs permit their actual nlink>=1. Owned sources/controls/evidence retain nlink1.',
        'old_3_12_14_runtime_inherited': False,
        'r1_r2_r2b_source_requests_executed': False, 'r2c_source_request_executed_once': True, 'r2c_actual_result': 'HOLD_6_OF_7', 'new_request_executed': False}
    create(ROOT / 'RUNTIME.json', wire(runtime))
    configuration = dict(config_old)
    configuration['schema'] = 'hia.cli-json.call-send-source-seven.request.r3.v1'
    configuration['source_root'] = str(ROOT / 'source')
    configuration['source_pins'] = source_pins
    configuration['source_identity9'] = source_identities
    configuration['runtime'] = runtime_expected
    create(ROOT / 'control/CONFIG.json', wire(configuration))
    delta = {
        'schema': 'hia.cli-json.source-seven.r3.control-delta.v1',
        'status': 'STATIC_UNEXECUTED',
        'parent_commit': spec['parent_commit'], 'parent_tree': spec['parent_tree'],
        'parent_prefix': spec['parent_prefix'],
        'r2c_status': 'ACTUAL_SOURCE_HOLD_CALL_FAST_AST_NOT_6_OF_7',
        'source_files': 198, 'source_bytes': sum(x['bytes'] for x in source_pins.values()),
        'source_files_changed': 1, 'source_byte_count_delta': 5, 'original7_components_and9_caps_unchanged': True,
        'original17_and46_preserved_not_run': True,
        'worker': {'before': hashes(read(old_root / 'control/source_authoring_worker.py')[0]),
                   'after': spec['worker_pin'], 'inverse_exact': True,
                   'delta': 'Only new r3 report and configuration schemas; original R2c fail-stop, guard, loop, roundtrip and cap implementation bytes otherwise unchanged.'},
        'guardian': {'before': hashes(read(old_root / 'control/guardian.py')[0]),
                     'after': spec['guardian_pin'], 'inverse_exact': True,
                     'delta': 'Whole guardian bytes unchanged from r2c; retain current369 bound-closure read gate and unknown UNREAD.'},
        'owner369_whole_bytes_unchanged': True, 'controller_seconds': 180,
        'cleanup_seconds': 3,
        'new_population_or_changed_threshold': False,
        'new_source_or_CoreVM_or_native_execution': False,
        'all234_r2c_frozen_originals_full_byte_mode_and_frozen_identity_checked': True,
        'r2c_original_complete_frozen_bytes_remain_in_parent_commit': True,
        'two_historical_r2_metadata_freeze_failures_preserved': True,
        'reference_guard_identity': spec['reference_files'][0]['pin'],
        'qualification_operator': 'Root only after exact canonical review',
        'unknown_operations_touched': False}
    create(ROOT / 'proof/CONTROL-DELTA.json', wire(delta))
    private(ROOT / 'guardian')
    owned_before_request = [record(p, True) for p in sorted(ROOT.rglob('*')) if p.is_file()]
    identities = {str(ROOT / row['path']): row['sha256'] for row in owned_before_request}
    identities[str(PYTHON)] = runtime_file['sha256']
    for row in observed_mapped:
        identities[row['path']] = row['sha256']
    role_proof = {
        'schema': 'hia.cli-json.source-seven.r3.input-roles.v1',
        'owned_single_link_files_before_this_roles_file': len(owned_before_request),
        'this_roles_file_is_additionally_pinned_in_the_request': True,
        'owned_sources': 198, 'system_root_readonly_files': len(observed_mapped),
        'system_inputs': observed_mapped,
        'owned_paths': [row['path'] for row in owned_before_request],
        'system_nlink_exception_never_applies_to_owned_sources_controls_or_outputs': True,
        'future_module_closure_claimed': False}
    role_pin = create(ROOT / 'proof/INPUT-ROLES.json', wire(role_proof))
    identities[role_pin['path']] = role_pin['sha256']
    request = {
        'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
        'command': [str(PYTHON), '-I', '-S', '-B',
                    str(ROOT / 'control/source_authoring_worker.py'),
                    str(ROOT / 'control/CONFIG.json'), str(ROOT / 'actual')],
        'cwd': str(ROOT / 'source'), 'expected_qualification': None,
        'source_identities': identities}
    request_pin = create(ROOT / 'guardian/REQUEST.json', wire(request))
    if request_pin['bytes'] > 262144:
        raise ValueError('original guardian request bound exceeded')
    environment = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin'}
    preexec = {
        'schema': 'hia.cli-json.call-send-source-seven.preexec.r3.v1',
        'status': 'FROZEN_UNEXECUTED_REQUIRES_ROOT_REVIEW',
        'origin': 'REBUILD_FROM_PRESERVED_BASELINE_UNEXECUTED',
        'request': request_pin, 'python': runtime_file, 'runtime': record(ROOT / 'RUNTIME.json'),
        'runtime_version': sys.version, 'host': 'ai395', 'boot_id': BOOT_ID,
        'environment_launcher': record(ROOT / 'control/clean_exec.py'),
        'command': [str(PYTHON), '-I', '-S', '-B', str(ROOT / 'control/guardian.py'),
                    '--config', str(ROOT / 'guardian/REQUEST.json'),
                    '--config-sha256', request_pin['sha256'],
                    '--implementation', str(ROOT / 'control/process_owner_impl.py')],
        'cwd': str(ROOT / 'source'), 'environment': environment,
        'transport_command': [str(PYTHON), '-I', '-S', '-B',
                              str(ROOT / 'control/clean_exec.py'), request_pin['sha256']],
        'transport_environment_note': 'Pinned clean_exec supplies only declared3 environment entries; no /usr/bin/env binary. Original180/3 guardian owns qualification.',
        'components': config_old['components'], 'limits': config_old['limits'],
        'new_source_only_owner_seconds': 180, 'cleanup_seconds': 3,
        'source_files': 198, 'source_bytes': sum(x['bytes'] for x in source_pins.values()),
        'fixed_input_counts': {'owned': len(owned_before_request) + 1,
                               'system': len(observed_mapped),
                               'total': len(identities)},
        'preserved_not_run': preexec_old['preserved_not_run'],
        'prior_request': {'commit': spec['parent_commit'],
                          'sha256': hashes(read(old_root / 'guardian/REQUEST.json')[0])['sha256'],
                          'executions': 1, 'status': delta['r2c_status'], 'actual': spec['prior_actual']},
        'effect_guard_reference': 'Actual Source8 worker239120db; not a claim of WAL byte identity.',
        'closed_only_body_reads': True,
        'C_syntax_compile_runtime_and_native_requested': False,
        'compiler_line_gate_executed': False,
        'outer_invocation_authority': 'Root reviews and invokes this exact new request once; author does not execute.',
        'unknown_operations_touched': False}
    create(ROOT / 'PREEXEC.json', wire(preexec))
    all_files = [record(p, True) for p in sorted(ROOT.rglob('*')) if p.is_file()]
    create(ROOT / 'FROZEN-FILES.json', wire({
        'schema': 'hia.cli-json.source-seven.r3.full-files.v1',
        'files': all_files, 'identity_fields': list(FIELDS),
        'actual_absent': not os.path.lexists(ROOT / 'actual'),
        'guardian_output_absent': all(not os.path.lexists(ROOT / 'guardian' / name)
            for name in ('guardian.json', 'child.stdout.log', 'child.stderr.log'))}))
    for path, expected_hash in identities.items():
        actual = system_record(Path(path)) if path in mapping_paths else record(Path(path))
        if actual['sha256'] != expected_hash:
            raise ValueError('fixed input changed during freeze')
        if path in mapping_paths:
            initial = next(row for row in observed_mapped if row['path'] == path)
            if actual != initial:
                raise ValueError('fixed system identity changed')
    for name, expected_identity in source_identities.items():
        if record(ROOT / 'source' / name)['identity'] != expected_identity:
            raise ValueError('new source identity changed during freeze')
    for name, initial in old_records.items():
        if record(old_root / name) != initial:
            raise ValueError('original R2c mutated during new freeze')
    summary = {
        'status': 'FROZEN_UNEXECUTED_REQUIRES_ROOT_REVIEW',
        'root': str(ROOT), 'source_files': 198,
        'source_bytes': sum(x['bytes'] for x in source_pins.values()),
        'components': 7, 'caps': 9,
        'request': record(ROOT / 'guardian/REQUEST.json'),
        'preexec': record(ROOT / 'PREEXEC.json'),
        'inventory': record(ROOT / 'FROZEN-FILES.json'),
        'worker': record(ROOT / 'control/source_authoring_worker.py'),
        'guardian': record(ROOT / 'control/guardian.py'),
        'fixed_input_counts': preexec['fixed_input_counts'],
        'files_including_inventory': len(all_files) + 1,
        'r2c_frozen_originals_unchanged': len(old_records),
        'source_executed': False, 'C_or_native_executed': False}
    print(json.dumps(summary, sort_keys=True), flush=True)

if __name__ == '__main__':
    main()
