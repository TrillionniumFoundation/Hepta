"""Finish the exact source-seven restore after the retained env metadata refusal.

This utility reads Git objects and system identities.  It never imports a
repository module, parses its AST, generates HIA, compiles C/HIA, or runs tests.
"""
from __future__ import annotations
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path('/home/qq/hia-rewrite-20261113-e26e-r1/cli-source-seven-r2')
REPO = Path('/home/qq/hia-rewrite-20261113-e26e-r1/repo')
PARENT = '560d28c6d3cf22585f5a5407ed212e4a56b79e12'
PARENT_TREE = '02b1ce15cc311dfe8a38d96f8d72b0ff4c11917e'
PREFIX = 'experiments/hia_cli_json_graph_20261113/call-send-retaining-source-seven-r1'
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

def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(REPO), *args], timeout=30)

def main():
    spec = json.loads(read(ROOT / 'bootstrap/SPEC.json')[0])
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != BOOT_ID:
        raise ValueError('new host boot differs')
    if Path(sys.executable).resolve() != PYTHON or sys.version_info[:3] != (3, 14, 4):
        raise ValueError('new source-only Python differs')
    py_raw, _ = read(PYTHON)
    if hashlib.sha256(py_raw).hexdigest() != PYTHON_SHA:
        raise ValueError('new source-only Python bytes differ')
    if git('rev-parse', PARENT + '^{tree}').decode().strip() != PARENT_TREE:
        raise ValueError('canonical source tree differs')
    listed = {}
    for line in git('ls-tree', '-r', '-z', PARENT, '--', PREFIX).split(b'\0'):
        if not line:
            continue
        left, name = line.split(b'\t', 1)
        mode, kind, sha = left.decode().split()
        name = name.decode()
        if not name.startswith(PREFIX + '/'):
            raise ValueError('unexpected source prefix')
        listed[name[len(PREFIX) + 1:]] = {'mode': mode, 'type': kind, 'sha': sha}
    expected = {row['path']: row for row in spec['r1_files']}
    if set(listed) != set(expected) or len(expected) != 221:
        raise ValueError('original 221 file population differs')
    all_original = {}
    restored = []
    for name, pin in sorted(expected.items()):
        entry = listed[name]
        git_mode = '100755' if pin['mode'] & 0o111 else '100644'
        if entry != {'mode': git_mode, 'type': 'blob', 'sha': pin['git_blob']}:
            raise ValueError('original tree pin differs: ' + name)
        raw = git('cat-file', 'blob', pin['git_blob'])
        if hashes(raw) != {key: pin[key] for key in ('bytes', 'sha256', 'git_blob')}:
            raise ValueError('original bytes differ: ' + name)
        dst = ROOT / 'reference/r1-frozen' / name
        create(dst, raw, pin['mode'])
        all_original[name] = raw
        restored.append(record(dst, True))
    for name in ('HANDOFF.json', 'PUBLICATION-JOURNAL.json'):
        raw = git('show', PARENT + ':' + PREFIX + '-publication/' + name)
        create(ROOT / 'proof' / ('R1-' + name + '.original'), raw)
    config_old = json.loads(all_original['control/CONFIG.json'])
    preexec_old = json.loads(all_original['PREEXEC.json'])
    if len(config_old['components']) != 7 or len(config_old['limits']) != 9:
        raise ValueError('original component/cap population differs')
    if len(config_old['original_cli_ids']) != 17 or len(config_old['trace_plan_ids']) != 46:
        raise ValueError('original full-population plan differs')
    source_pins = {}
    source_identities = {}
    for name, pin in sorted(config_old['source_pins'].items()):
        original_name = 'source/' + name
        raw = all_original[original_name]
        if hashes(raw) != pin:
            raise ValueError('original source map differs')
        create(ROOT / original_name, raw, expected[original_name]['mode'])
        current = record(ROOT / original_name)
        source_pins[name] = {key: current[key] for key in ('bytes', 'sha256', 'git_blob')}
        source_identities[name] = current['identity']
    if len(source_pins) != 198 or source_pins != config_old['source_pins']:
        raise ValueError('full 198 source bytes changed')
    for name in ('guardian.py', 'process_owner_impl.py'):
        create(ROOT / 'control' / name, all_original['control/' + name])
    worker = spec['worker_text'].encode()
    if hashes(worker) != spec['worker_pin']:
        raise ValueError('new worker pin differs')
    inverse = worker.decode()
    for old, new in reversed(spec['worker_edits']):
        if new not in inverse:
            raise ValueError('new worker inverse missing')
        inverse = inverse.replace(new, old)
    if inverse.encode() != all_original['control/source_authoring_worker.py']:
        raise ValueError('new worker inverse differs from canonical r1')
    create(ROOT / 'control/source_authoring_worker.py', worker)
    patch = ''.join(difflib.unified_diff(all_original['control/source_authoring_worker.py'].decode().splitlines(True),
        worker.decode().splitlines(True), fromfile='r1/source_authoring_worker.py',
        tofile='r2/source_authoring_worker.py'))
    create(ROOT / 'proof/WORKER-RUNTIME-IDENTITY-DELTA.patch', patch.encode())
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json', 'SOURCE-STATUS.json'):
        create(ROOT / name, all_original[name])
    runtime_file = record(PYTHON)
    clean_exec_raw = read(ROOT / 'bootstrap/clean_exec.new.py')[0]
    create(ROOT / 'control/clean_exec.py', clean_exec_raw)
    environment_launcher = record(ROOT / 'control/clean_exec.py')
    runtime_expected = {'file': {key: runtime_file[key] for key in ('path', 'bytes', 'sha256', 'identity')},
                        'version_info': list(sys.version_info[:3]), 'version': sys.version, 'boot_id': BOOT_ID}
    maps_before = Path('/proc/self/maps').read_bytes()
    mapping_paths = set()
    for line in maps_before.decode().splitlines():
        parts = line.split(None, 5)
        if len(parts) == 6 and parts[5].startswith('/'):
            if parts[5].endswith(' (deleted)'):
                raise ValueError('deleted runtime mapping')
            mapping_paths.add(parts[5])
    observed_mapped = [record(Path(path)) for path in sorted(mapping_paths)]
    maps_after = Path('/proc/self/maps').read_bytes()
    create(ROOT / 'proof/FREEZE-PROCESS-MAPS.before.original.txt', maps_before)
    create(ROOT / 'proof/FREEZE-PROCESS-MAPS.after.original.txt', maps_after)
    runtime = {'schema': 'hia.cli-json.source-seven.ai395-runtime.v1',
        'scope': 'Source generation and Core validation only; not a CPython 3.12 native ABI admission.',
        'boot_id': BOOT_ID, 'host': 'ai395', 'effective_uid': os.geteuid(),
        'effective_gid': os.getegid(), 'python': runtime_expected,
        'observed_freeze_process_mapped_files': observed_mapped,
        'mapped_inventory_is_complete_future_module_closure': False,
        'old_3_12_14_runtime_inherited': False,
        'old_request_executed': False, 'new_request_executed': False}
    create(ROOT / 'RUNTIME.json', wire(runtime))
    configuration = dict(config_old)
    configuration['schema'] = 'hia.cli-json.call-send-source-seven.request.r2.v1'
    configuration['source_root'] = str(ROOT / 'source')
    configuration['source_pins'] = source_pins
    configuration['source_identity9'] = source_identities
    configuration['runtime'] = runtime_expected
    create(ROOT / 'control/CONFIG.json', wire(configuration))
    recovery = {'schema': 'hia.cli-json.source-seven.r1-to-ai395.r2.v1',
        'status': 'EXACT_221_ORIGINALS_RESTORED_NEW_SOURCE_REQUEST_UNEXECUTED',
        'original_commit': PARENT, 'original_tree': PARENT_TREE, 'original_prefix': PREFIX,
        'original_population': 221, 'restored_originals': restored,
        'source_files': 198, 'source_bytes': sum(x['bytes'] for x in source_pins.values()),
        'source_bytes_changed': 0, 'worker_inverse_exact': True,
        'worker_changes': ['r2 schema labels', '198 frozen nine-field source identities',
                           'actual Python identity and version before/after'],
        'component_order_unchanged': True, 'all_nine_caps_unchanged': True,
        'original17_ids_unchanged_unexecuted': True,
        'original46_ids_unchanged_unexecuted': True,
        'old_request_execution_count': 0, 'new_request_execution_count': 0,
        'first_freeze_failure_preserved': 'bootstrap/RESTORE-FIRST-FAILURE.original.json',
        'first_freeze_scope': 'Only restoration and metadata; REQUEST and actual absent.',
        'continuation_existing_files': 'Exact bytes/mode checked; no overwrite or deletion.',
        'no_repository_modules_imported': True, 'no_source_AST_or_generation': True,
        'no_C_or_HIA_compile_or_native': True}
    create(ROOT / 'proof/RECOVERY.json', wire(recovery))
    private(ROOT / 'guardian')
    frozen_before_request = [record(p, True) for p in sorted(ROOT.rglob('*')) if p.is_file()]
    identities = {str(ROOT / row['path']): row['sha256'] for row in frozen_before_request}
    identities[str(PYTHON)] = runtime_file['sha256']
    for row in observed_mapped:
        identities[row['path']] = row['sha256']
    request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
        'command': [str(PYTHON), '-I', '-S', '-B', str(ROOT / 'control/source_authoring_worker.py'),
                    str(ROOT / 'control/CONFIG.json'), str(ROOT / 'actual')],
        'cwd': str(ROOT / 'source'), 'expected_qualification': None,
        'source_identities': identities}
    request_pin = create(ROOT / 'guardian/REQUEST.json', wire(request))
    if request_pin['bytes'] > 262144:
        raise ValueError('original guardian request bound exceeded')
    environment = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin'}
    command = [str(PYTHON), '-I', '-S', '-B', str(ROOT / 'control/guardian.py'),
        '--config', str(ROOT / 'guardian/REQUEST.json'), '--config-sha256', request_pin['sha256'],
        '--implementation', str(ROOT / 'control/process_owner_impl.py')]
    preexec = {'schema': 'hia.cli-json.call-send-source-seven.preexec.r2.v1',
        'status': 'FROZEN_NOT_EXECUTED', 'origin': 'REBUILD_FROM_PRESERVED_BASELINE_UNEXECUTED',
        'request': request_pin, 'python': runtime_file, 'runtime': record(ROOT / 'RUNTIME.json'),
        'runtime_version': sys.version, 'host': 'ai395', 'boot_id': BOOT_ID, 'environment_launcher': environment_launcher,
        'command': command, 'cwd': str(ROOT / 'source'), 'environment': environment,
        'transport_command': [str(PYTHON), '-I', '-S', '-B',
                              str(ROOT / 'control/clean_exec.py'), request_pin['sha256']],
        'transport_environment_note': 'The pinned Python launcher execve supplies only the declared environment. The system env symlink/multi-link binary is not executed. Transport supervision does not replace or extend the original 180/3 owner.',
        'components': config_old['components'], 'limits': config_old['limits'],
        'new_source_only_owner_seconds': 180, 'cleanup_seconds': 3,
        'source_files': 198, 'source_bytes': sum(x['bytes'] for x in source_pins.values()),
        'preserved_not_run': preexec_old['preserved_not_run'],
        'old_request': {'commit': PARENT, 'sha256': hashes(all_original['guardian/REQUEST.json'])['sha256'],
                        'executions': 0, 'old_physical_paths_reused': False},
        'C_syntax_compile_runtime_and_native_requested': False, 'compiler_line_gate_executed': False,
        'outer_invocation_authority': 'Root reviews and invokes this exact new request once; author does not execute.',
        'unknown_operations_touched': False}
    create(ROOT / 'PREEXEC.json', wire(preexec))
    all_files = [record(p, True) for p in sorted(ROOT.rglob('*')) if p.is_file()]
    create(ROOT / 'FROZEN-FILES.json', wire({'schema': 'hia.cli-json.source-seven.r2.full-files.v1',
        'files': all_files, 'identity_fields': list(FIELDS),
        'actual_absent': not os.path.lexists(ROOT / 'actual'),
        'guardian_output_absent': all(not os.path.lexists(ROOT / 'guardian' / name)
          for name in ('guardian.json', 'child.stdout.log', 'child.stderr.log'))}))
    for path, digest in identities.items():
        if record(Path(path))['sha256'] != digest:
            raise ValueError('final frozen input changed')
    for name, expected_identity in source_identities.items():
        if record(ROOT / 'source' / name)['identity'] != expected_identity:
            raise ValueError('source physical identity changed while freezing')
    summary = {'status': 'FROZEN_NOT_EXECUTED', 'root': str(ROOT),
        'source_files': 198, 'source_bytes': sum(x['bytes'] for x in source_pins.values()),
        'components': 7, 'caps': 9, 'request': record(ROOT / 'guardian/REQUEST.json'),
        'preexec': record(ROOT / 'PREEXEC.json'), 'inventory': record(ROOT / 'FROZEN-FILES.json'),
        'files_including_inventory': len(all_files) + 1,
        'runtime_version': sys.version, 'new_runtime_qualification_scope': 'source only',
        'source_executed': False, 'C_or_native_executed': False}
    print(json.dumps(summary, sort_keys=True), flush=True)

if __name__ == '__main__':
    main()
