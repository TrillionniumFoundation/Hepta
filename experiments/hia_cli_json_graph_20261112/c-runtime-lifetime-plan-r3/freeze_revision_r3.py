"""Freeze the exact local raised-error helper successor; no product execution.

The r2b request and all of its execution originals remain immutable.  The new
request changes one C include by importing the exact upstream helper body under
a local static name and replacing its sole old call.  All eleven executable
controls, eighteen cases, four HIA assets, compiler provenance and limits stay
byte-identical.  This authoring script is an additional pinned input.
"""
from __future__ import annotations

import ast
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat

OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2b-20261112-e26e')
ROOT = Path(__file__).resolve().parent
ACTUAL = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r3-20261112-e26e')
FAILED = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r2b-20261112-e26e')
FAILURE = Path('/tmp/hia-cli-json-c-runtime-lifetime-failure-r2b-20261112-e26e')
PARENT_REQUEST = '5f1c4f6bc7f8ebdf3b3e3c9c17f543a6281346d0'
PARENT_ORIGINALS = '666a01b759ab7e01cde7d4432c8909b06ce8484a'
TARGET = 'hepta/hia_cli_json_cpython312_errors.inc'
OFFICIAL_SHA = 'd38cf667e13fb9f298a278759daf6117167f45a08d2c5bae7f279d9ba86a2454'
OFFICIAL_FUNCTION = b'''void
_PyErr_SetRaisedException(PyThreadState *tstate, PyObject *exc)
{
    PyObject *old_exc = tstate->current_exception;
    tstate->current_exception = exc;
    Py_XDECREF(old_exc);
}
'''
LOCAL_FUNCTION = OFFICIAL_FUNCTION.replace(
    b'void\n_PyErr_SetRaisedException(', b'static void\ncj312_set_raised_exception(', 1)
INSERT_NOTE = (b'/* Exact CPython v3.12.14 Python/errors.c body; local linkage only.\n'
               b' * Preserve the explicit state, stolen reference, and store-before-DECREF.\n'
               b' */\n')


def wire(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':')) + '\n').encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns)


def read(path):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(fd)) == identity(before)
        raw = bytearray()
        while len(raw) < before.st_size:
            part = os.read(fd, min(65536, before.st_size - len(raw)))
            assert part
            raw.extend(part)
        assert not os.read(fd, 1)
        assert identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
    finally:
        os.close(fd)
    return bytes(raw), before


def record(path, relative=None):
    raw, info = read(path)
    return {'path': str(path) if relative is None else relative,
            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': stat.S_IMODE(info.st_mode)}


def create(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        cursor = 0
        while cursor < len(raw):
            count = os.write(fd, raw[cursor:])
            assert count > 0
            cursor += count
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
    assert ROOT == Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e')
    assert not os.path.lexists(ACTUAL)
    old_raw, _ = read(OLD / 'POLICY.json')
    assert hashlib.sha256(old_raw).hexdigest() == '82380a6976d8618ef386f092b27fc8f76780236eeb7b1e02038b2697d2b2b766'
    old = json.loads(old_raw)
    assert json.loads(read(FAILED / 'FINAL.json')[0])['status'] == 'HOLD'
    original = read(OLD / 'source' / TARGET)[0]
    assert hashlib.sha256(original).hexdigest() == '3e7efbd74b73684652cb7c4b740851705937a663b60708ff39e7ad6b473058ab'
    official = read(ROOT / 'reference/official-errors.c')[0]
    assert hashlib.sha256(official).hexdigest() == OFFICIAL_SHA
    assert official.count(OFFICIAL_FUNCTION) == 1
    marker = b'static int\ncj312_do_raise('
    old_call = b'        _PyErr_SetRaisedException(tstate, exc);'
    new_call = b'        cj312_set_raised_exception(tstate, exc);'
    assert original.count(marker) == original.count(old_call) == 1
    corrected = original.replace(marker, INSERT_NOTE + LOCAL_FUNCTION + b'\n' + marker, 1)
    corrected = corrected.replace(old_call, new_call, 1)
    inverse = corrected.replace(new_call, old_call, 1).replace(
        INSERT_NOTE + LOCAL_FUNCTION + b'\n', b'', 1)
    assert inverse == original
    assert b'_PyErr_SetRaisedException(' not in corrected
    assert corrected.count(b'_PyObject_CallNoArgsTstate(_PyThreadState_GetCurrent(),') == 2
    for base, rows in ((Path('source'), old['source_files']),
                       (Path(), old['control_files'] + old['asset_files'])):
        for row in rows:
            path = OLD / base / row['path']
            assert record(path, row['path']) == row
            raw = corrected if base == Path('source') and row['path'] == TARGET else read(path)[0]
            create(ROOT / base / row['path'], raw, row['mode'])
    create(ROOT / 'reference/r2b-errors.inc', original)
    create(ROOT / 'reference/official-raised-function.c.txt', OFFICIAL_FUNCTION)
    create(ROOT / 'reference/local-raised-function.c.txt', LOCAL_FUNCTION)
    patch = ''.join(difflib.unified_diff(original.decode().splitlines(True),
        corrected.decode().splitlines(True), fromfile='r2b/' + TARGET, tofile='r3/' + TARGET))
    create(ROOT / 'SOURCE-DELTA.patch', patch.encode())
    peer = Path('/tmp/hia-v92-standard-ci-readonly-43324913647-r1/cli-peer/RAISED-ERROR-HELPER-STATIC-REVIEW.json')
    assert hashlib.sha256(read(peer)[0]).hexdigest() == 'd36235a7b3c3b83a129811007ef51743198406ec98551f2302c7455281f64c5e'
    create(ROOT / 'reference/PEER-PROPOSAL-REVIEW.original.json', read(peer)[0])
    closure_raw = read(FAILURE / 'dynamic-closure-r2/REPORT.json')[0]
    closure = json.loads(closure_raw)
    assert closure['strong_undefined_count'] == 119 and closure['compatible_strong_count'] == 118
    assert closure['unresolved'] == ['_PyErr_SetRaisedException']
    create(ROOT / 'reference/R2B-DYNAMIC-CLOSURE.original.json', closure_raw)
    create(ROOT / 'reference/R2B-FAILURE-HANDOFF.original.json', read(FAILURE / 'HANDOFF.json')[0])
    headers = Path('/opt/codex/runtimes/codex-primary-runtime/dependencies/python/include/python3.12')
    source_references = []
    for rel in ('internal/pycore_pyerrors.h', 'cpython/pystate.h', 'object.h'):
        src = headers / rel
        source_references.append(record(src))
        create(ROOT / 'reference/actual-headers' / rel, read(src)[0])
    assert b'_PyErr_SetRaisedException(PyThreadState *tstate, PyObject *exc)' in read(headers / 'internal/pycore_pyerrors.h')[0]
    assert b'PyObject *current_exception;' in read(headers / 'cpython/pystate.h')[0]
    policy = copy.deepcopy(old)
    policy['operation_key'] = 'hia-cli-json-c-runtime-lifetime-local312-r3'
    policy['operation_root'] = str(ACTUAL)
    policy['c_command'] = [s.replace(str(OLD), str(ROOT)).replace(old['operation_root'], str(ACTUAL))
                           for s in old['c_command']]
    policy['source_files'] = [record(ROOT / 'source' / row['path'], row['path'])
                              for row in old['source_files']]
    policy['control_files'].append(record(ROOT / 'freeze_revision_r3.py', 'freeze_revision_r3.py'))
    changed = [{'path': before['path'], 'before': before, 'after': after}
               for before, after in zip(old['source_files'], policy['source_files']) if before != after]
    assert len(changed) == 1 and changed[0]['path'] == TARGET
    inverse_policy = copy.deepcopy(policy)
    for key in ('operation_key', 'operation_root', 'c_command', 'source_files', 'control_files'):
        inverse_policy[key] = old[key]
    assert inverse_policy == old
    assert len(policy['runtime_ids']) == 8 and len(policy['lifetime_ids']) == 10
    assert policy['expected_total_HIA_returns'] == 48
    assert policy['expected_total_C_pump_calls_including_refusals'] == 11
    assert policy['qualification_seconds'] == 180 and policy['cleanup_seconds'] == 3
    assert policy['child_seconds'] == 5
    assert policy['compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds': 10, 'output_capacity': 1 << 20}
    policy_record = create(ROOT / 'POLICY.json', wire(policy))
    request = json.loads(read(OLD / 'REQUEST.json')[0])
    request.update(operation_key=policy['operation_key'], operation_root=str(ACTUAL),
                   policy_sha256=policy_record['sha256'])
    request_record = create(ROOT / 'REQUEST.json', wire(request))
    preexec = json.loads(read(OLD / 'PREEXEC.json')[0])
    preexec.update(command=[policy['python']['path'], '-I', '-S', '-B', str(ROOT / 'control/launch.py'),
                           '--request', str(ROOT / 'REQUEST.json'), '--sha256', request_record['sha256']],
                   cwd=str(ROOT), request=request_record, policy=policy_record,
                   source_bytes=sum(row['bytes'] for row in policy['source_files']),
                   previous_failed_request_commit=PARENT_REQUEST,
                   previous_failure_originals_commit=PARENT_ORIGINALS,
                   original_14_bound_control_inputs_byte_identical=True,
                   original_11_runtime_control_files_byte_identical=True,
                   new_authoring_script='freeze_revision_r3.py',
                   source_and_control_AST_parses_only=0)
    create(ROOT / 'PREEXEC.json', wire(preexec))
    correction = {
        'schema': 'hia.cli-json.raised-error-internal-symbol-correction.v1',
        'status': 'STATIC_MINIMAL_SUCCESSOR_NOT_EXECUTED',
        'actual_failure_commit': PARENT_ORIGINALS, 'actual_failed_request': PARENT_REQUEST,
        'actual_primary_error': 'undefined symbol: _PyErr_SetRaisedException',
        'actual_C_compile_pass': True, 'actual_runtime_loaded': 1, 'actual_runtime_executed': 0,
        'actual_HIA_compile_and_lifetime_unexecuted': True,
        'source_changed_files': changed, 'unchanged_source_files': 181,
        'implementation_change': 'Exact official function body under one local static name; the sole old call is renamed.',
        'official_source_url': 'https://github.com/python/cpython/blob/v3.12.14/Python/errors.c',
        'official_source': record(ROOT / 'reference/official-errors.c'),
        'official_function': record(ROOT / 'reference/official-raised-function.c.txt'),
        'local_function': record(ROOT / 'reference/local-raised-function.c.txt'),
        'actual_header_pins': source_references,
        'full_error_include_inverse_byte_equal': True, 'official_body_byte_equal': True,
        'explicit_tstate_preserved': True, 'steals_exact_callers_reference': True,
        'order': ['save old current_exception', 'store exc into current_exception', 'Py_XDECREF old'],
        'caller_Py_INCREF_before_reraise_preserved': True,
        'old_equals_exc_keeps_original_reference_accounting': True,
        'r2b_two_current_state_getter_call_sites_byte_unchanged': True,
        'complete_r2b_strong_undefined_count': 119, 'r2b_compatible_exports': 118,
        'remaining_r2b_unresolved_name': '_PyErr_SetRaisedException',
        'original_full_GNU_version_and_visibility_audit': record(ROOT / 'reference/R2B-DYNAMIC-CLOSURE.original.json'),
        'new_actual_ELF_undefined_count_unknown_until_compile': True,
        'new_actual_runtime_mapping_unknown_until_runtime_cases': True,
        'symbol_addresses_not_fabricated': True, 'runtime_admission_code_unchanged': True,
        'case_bodies_unchanged': True, 'original_runtime_controls_byte_unchanged': 11,
        'HIA_assets_byte_unchanged': 4, 'current_v89_compiler_62_originals_and_system_4555_unchanged': True,
        'source_generation_executed': False, 'C_compilation_executed': False,
        'native_load_executed': False, 'qualification_executed': False,
        'original_17_CLI_and_46_trace_population_unchanged_and_unexecuted': True,
        'CALL_SEND_UNPACK_activation_closed': False,
        'remaining_real_gate': 'The original new C compile, eight runtime and ten lifetime cases; HIA compilation and 48/11 expected native observations remain unexecuted.'}
    create(ROOT / 'CORRECTION.json', wire(correction))
    assert not os.path.lexists(ACTUAL)
    print(json.dumps({'status': correction['status'], 'source': record(ROOT / 'source' / TARGET),
        'policy': policy_record, 'request': request_record, 'actual_absent': True,
        'compilation_native_or_owner_executed': False}))


if __name__ == '__main__':
    main()
