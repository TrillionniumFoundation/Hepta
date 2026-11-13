"""Create-only source checkpoint/request; never import or execute product code."""
from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/home/agent/hia-cli-r4g-rebuild-r3-20261113-e26e')
TARGET = Path('/home/agent/hia-cli-call-send-source-seven-r1-20261113-e26e')
BASE = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4b')
OLD = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1/source-authoring-r4b1')
COMPONENTS = (
    ('body', 'tools.generate_hia_cli_json_py312_body'),
    ('unpack', 'tools.generate_hia_cli_json_py312_unpack'),
    ('call_dispatch', 'tools.generate_hia_cli_json_py312_call_dispatch'),
    ('call', 'tools.generate_hia_cli_json_py312_call'),
    ('call_fast', 'tools.generate_hia_cli_json_py312_call_fast'),
    ('call_prologue', 'tools.generate_hia_cli_json_py312_call_prologue'),
    ('send', 'tools.generate_hia_cli_json_py312_send'),
)
LIMITS = {'source_bytes': 1 << 20, 'functions': 128, 'blocks_per_function': 256,
    'blocks_total': 1536, 'parameters_or_arguments': 16, 'ssa_names_per_function': 2048,
    'instruction_results': 3, 'function_results': 3, 'instructions': 8192}


def identity(st):
    return [getattr(st, 'st_' + n) for n in
        ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')]


def read(path):
    initial = path.lstat()
    assert stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(fd)) == identity(initial)
        pieces = []
        left = initial.st_size
        while left:
            piece = os.read(fd, min(65536, left))
            assert piece
            pieces.append(piece)
            left -= len(piece)
        assert not os.read(fd, 1)
        assert identity(os.fstat(fd)) == identity(initial) == identity(path.lstat())
    finally:
        os.close(fd)
    return b''.join(pieces), initial


def record(path, name=None):
    raw, st = read(path)
    return {'path': str(path) if name is None else name, 'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
        'mode': stat.S_IMODE(st.st_mode)}


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def create(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        at = 0
        while at < len(raw):
            n = os.write(fd, raw[at:])
            assert n > 0
            at += n
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        check = []
        while True:
            part = os.read(fd, 65536)
            if not part:
                break
            check.append(part)
        assert b''.join(check) == raw
    finally:
        os.close(fd)
    assert read(path)[0] == raw
    return record(path)


def main():
    assert not os.path.lexists(TARGET)
    TARGET.mkdir(mode=0o700)
    old_config_raw = read(OLD / 'control/CONFIG.json')[0]
    old_config = json.loads(old_config_raw)
    assert old_config['limits'] == LIMITS and len(old_config['original_cli_ids']) == 17
    assert len(set(old_config['trace_plan_ids'])) == len(old_config['trace_plan_ids']) == 46
    policy_raw = read(BASE / 'POLICY.json')[0]
    baseline = json.loads(policy_raw)
    sources = {}
    for row in baseline['source_files']:
        name = row['path']
        raw, st = read(BASE / 'source' / name)
        actual = record(BASE / 'source' / name, name)
        assert actual == row, name
        sources[name] = (raw, row['mode'], {'baseline': str(BASE), 'pin': row})
    overlay = []
    for path in sorted((ROOT / 'inputs').rglob('*')):
        if path.is_dir():
            continue
        name = path.relative_to(ROOT / 'inputs').as_posix()
        raw, st = read(path)
        overlay.append(record(path, name))
        sources[name] = (raw, 0o600, {'mutable_rebuild': str(path), 'pin': record(path, name)})
    source_pins = {}
    origins = {}
    for name, (raw, mode, origin) in sorted(sources.items()):
        path = TARGET / 'source' / name
        create(path, raw, mode)
        r = record(path, name)
        source_pins[name] = {k: r[k] for k in ('bytes', 'sha256', 'git_blob')}
        origins[name] = origin
    for name, digest in (('guardian.py', 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'),
                         ('process_owner_impl.py', '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2')):
        raw = read(OLD / 'control' / name)[0]
        assert hashlib.sha256(raw).hexdigest() == digest
        create(TARGET / 'control' / name, raw)
    before_worker = read(OLD / 'control/source_authoring_worker.py')[0]
    worker = before_worker.decode()
    replacements = (
        ('Each of two new fixed authoring modules', 'Each of seven fixed authoring modules'),
        ("SCHEMA = 'hia.cli-json.source-authoring.r4b.v1'", "SCHEMA = 'hia.cli-json.call-send-source-seven.r1.v1'"),
        ("COMPONENTS = (('scalar', 'tools.generate_hia_cli_json_scalar'), ('py312_chunks', 'tools.generate_hia_cli_json_py312_chunks'))",
         'COMPONENTS = ' + repr(COMPONENTS)),
        ("'hia.cli-json.source-authoring.request.r4b.v1'", "'hia.cli-json.call-send-source-seven.request.r1.v1'"),
        ("len(report['components']) != 2", "len(report['components']) != 7"),
        ('TWO_NEW_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN', 'SEVEN_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN'),
    )
    for before, after in replacements:
        assert before in worker
        worker = worker.replace(before, after)
    inverse = worker
    for before, after in reversed(replacements):
        assert after in inverse
        inverse = inverse.replace(after, before)
    assert inverse.encode() == before_worker
    create(TARGET / 'control/source_authoring_worker.py', worker.encode())
    create(TARGET / 'proof/WORKER.original.py', before_worker)
    patch = ''.join(difflib.unified_diff(before_worker.decode().splitlines(True), worker.splitlines(True),
        fromfile='original/source_authoring_worker.py', tofile='source-seven/source_authoring_worker.py'))
    create(TARGET / 'proof/WORKER-EXACT-DELTA.patch', patch.encode())
    for name in ('TRACE-PLAN.original.json', 'ORIGINAL-CLI-ID-SOURCE.json'):
        create(TARGET / name, read(OLD / name)[0])
    create(TARGET / 'proof/BASE-POLICY.original.json', policy_raw)
    create(TARGET / 'proof/REBUILD-BASE-RECOVERY.original.json', read(ROOT / 'proof/BASE-RECOVERY.json')[0])
    create(TARGET / 'proof/CALL-BEFORE.original.inc', read(ROOT / 'proof/review-inputs/call_body-19ad0d95.inc')[0])
    create(TARGET / 'proof/SOURCE-ORIGINS.json', wire(origins))
    create(TARGET / 'proof/REBUILD-OVERLAY.json', wire(overlay))
    for name in ('specialize.c',):
        raw = read(ROOT / 'reference/cpython-v3.12.14/Python' / name)[0]
        create(TARGET / 'reference/cpython-v3.12.14/Python' / name, raw)
    # These independent reference bytes explain the primitive/ownership
    # source; no C source or private helper is executed while freezing.
    reference_paths = {
        'generated_cases.c.h': Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1/implementation-r4c/reference/cpython-v3.12.14/Python/generated_cases.c.h'),
        'ceval.c': Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1/implementation-r4b/reference/cpython-v3.12.14/Python/ceval.c'),
        'frame.c': Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1/implementation-r4b/reference/cpython-v3.12.14/Python/frame.c'),
    }
    for name, path in reference_paths.items():
        create(TARGET / 'reference/cpython-v3.12.14/Python' / name, read(path)[0])
    peer = Path('/home/agent/hia-cold-peer-reviews-20261113-e26e/cli-inline-0ac4-ownership-static-review.json')
    create(TARGET / 'proof/INLINE-PEER.original.json', read(peer)[0])
    config = {
        'schema': 'hia.cli-json.call-send-source-seven.request.r1.v1',
        'source_root': str(TARGET / 'source'), 'source_pins': source_pins,
        'components': [list(row) for row in COMPONENTS], 'limits': LIMITS,
        'original_cli_ids': old_config['original_cli_ids'], 'trace_plan_ids': old_config['trace_plan_ids'],
        'caller_execution_requested': False, 'trace_execution_requested': False,
        'native_execution_requested': False, 'C_parse_or_compile_requested': False,
        'origin': 'REBUILD_FROM_PRESERVED_BASELINE_UNEXECUTED',
    }
    create(TARGET / 'control/CONFIG.json', wire(config))
    source_status = {
        'schema': 'hia.cli-json.continuous-call-send-source-status.v1',
        'status': 'SOURCE_WIP_UNEXECUTED', 'origin': config['origin'],
        'new_implemented_sources': [row['path'] for row in overlay],
        'concrete_ports': ['HIA adaptive/instrumented CALL dispatch',
            'HIA original specialized CALL guards, argument/default moves, release/error plans',
            'HIA generic vectorcall/binder and actual C_RETURN/C_RAISE primitives',
            'HIA COPY_FREE_VARS/RETURN_GENERATOR same-C-entry prologue',
            'HIA SEND/SEND_GEN, actual child return/error transfer',
            'private iterative retaining C driver with full before-reuse node custody'],
        'current_open_activation_gates': [
            'The new CALL runtime table requires independently proven mapped function/data addresses; ready remains zero.',
            'FOR_ITER port241 phase40 and RESUME/branch/breaker port244 kinds1..3 remain unimplemented.',
            'Full instrumented bytecode dispatch, arbitrary foreign thread bodies and coroutine bodies are not qualified.',
            'No exported wrapper may return to Python after INTERNAL_BLOCKED, no-GIL, a linked activation or a pending stack owner.',
            'Preallocated C arena is a finite experiment resource; no public JSON depth/size ceiling is introduced or qualified.',
            'No public default/selector is changed. CPython object/argument/frame primitives remain hosted.',
        ],
        'all_source_generation_C_compile_HIA_compile_runtime_entry_counts': 0,
        'full17_executed': False, 'full46_executed': False,
        'prior_finite8_10_not_inherited': True,
        'old_erased_GIL_CALL_files_claimed_recovered': False,
        'source7_scope': 'Seven actual documents/assembly/Core roundtrip and nine unchanged caps only; C text is pinned, not parsed or compiled.',
    }
    create(TARGET / 'SOURCE-STATUS.json', wire(source_status))
    python = Path(sys.executable).resolve()
    python_pin = record(python)
    python_pin['version'] = sys.version
    assert list(sys.version_info[:3]) == [3, 12, 14]
    control = TARGET / 'guardian'
    control.mkdir(mode=0o700)
    input_files = sorted(p for p in TARGET.rglob('*') if p.is_file())
    identities = {str(p): record(p)['sha256'] for p in input_files}
    identities[str(python)] = python_pin['sha256']
    request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
        'command': [str(python), '-I', '-S', '-B', str(TARGET / 'control/source_authoring_worker.py'),
            str(TARGET / 'control/CONFIG.json'), str(TARGET / 'actual')],
        'cwd': str(TARGET / 'source'), 'expected_qualification': None,
        'source_identities': identities}
    request_pin = create(control / 'REQUEST.json', wire(request))
    assert request_pin['bytes'] <= 262144
    preexec = {'schema': 'hia.cli-json.call-send-source-seven.preexec.v1',
        'status': 'FROZEN_NOT_EXECUTED',
        'command': [str(python), '-I', '-S', '-B', str(TARGET / 'control/guardian.py'),
            '--config', str(control / 'REQUEST.json'), '--config-sha256', request_pin['sha256'],
            '--implementation', str(TARGET / 'control/process_owner_impl.py')],
        'cwd': str(TARGET / 'source'), 'environment': {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin'},
        'request': request_pin, 'python': python_pin,
        'components': [list(row) for row in COMPONENTS], 'limits': LIMITS,
        'new_source_only_owner_seconds': 180, 'cleanup_seconds': 3,
        'source_files': len(source_pins), 'source_bytes': sum(row['bytes'] for row in source_pins.values()),
        'preserved_not_run': {'original_cli_ids': old_config['original_cli_ids'], 'trace_plan_ids': old_config['trace_plan_ids']},
        'source_status': record(TARGET / 'SOURCE-STATUS.json'),
        'C_syntax_compile_runtime_and_native_requested': False,
        'compiler_line_gate_executed': False,
        'outer_invocation_authority': 'Root reviews and invokes this exact new request once; author does not execute.',
        'unknown_operations_touched': False}
    create(TARGET / 'PREEXEC.json', wire(preexec))
    create(TARGET / 'freeze_source_seven.py', read(Path(__file__))[0])
    all_inputs = [record(p, p.relative_to(TARGET).as_posix()) for p in sorted(TARGET.rglob('*')) if p.is_file()]
    create(TARGET / 'FROZEN-FILES.json', wire({'schema': 'hia.cli-json.source-seven.full-files.v1',
        'files': all_inputs, 'actual_absent': not os.path.lexists(TARGET / 'actual'),
        'guardian_output_absent': all(not os.path.lexists(control / p) for p in ('guardian.json', 'child.stdout.log', 'child.stderr.log'))}))
    print(json.dumps({'status': 'FROZEN_NOT_EXECUTED', 'root': str(TARGET),
        'source_files': len(source_pins), 'components': len(COMPONENTS),
        'request': record(control / 'REQUEST.json'), 'preexec': record(TARGET / 'PREEXEC.json'),
        'total_input_files_before_inventory': len(all_inputs)}, sort_keys=True))


if __name__ == '__main__':
    main()
