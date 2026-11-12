"""Read-only root admission of the distinct minimal TLS successor request."""
from pathlib import Path
import hashlib
import json
import os
import stat
import struct
import sys

ROOT = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2b-20261112-e26e')
OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r1-20261112-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r2b')
sys.dont_write_bytecode = True


def read(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    raw = path.read_bytes()
    assert path.lstat() == before and len(raw) == before.st_size
    return raw


def pin(path):
    raw = read(path)
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': stat.S_IMODE(path.lstat().st_mode)}


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    assert path.read_bytes() == raw


def elf(path):
    raw = read(path)
    assert raw[:6] == b'\x7fELF\x02\x01'
    start = struct.unpack_from('<Q', raw, 40)[0]
    width, count = struct.unpack_from('<HH', raw, 58)
    assert width == 64 and 0 < count < 65536 and start + count * width <= len(raw)
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, start + width * i) for i in range(count)]
    symbols, tables = [], {}
    for index, section in enumerate(sections):
        if section[1] != 11:
            continue
        _, _, _, _, offset, size, link, _, _, entry = section
        assert entry == 24 and size % entry == 0
        strings = sections[link]
        names = raw[strings[4]:strings[4] + strings[5]]
        table = []
        for pos in range(offset, offset + size, entry):
            name, info, other, section_index, address, length = struct.unpack_from('<IBBHQQ', raw, pos)
            end = names.find(b'\0', name)
            assert end >= name
            row = {'name': names[name:end].decode(), 'bind': info >> 4, 'type': info & 15,
                   'visibility': other & 3, 'section': section_index, 'value': address, 'bytes': length}
            table.append(row); symbols.append(row)
        tables[index] = table
    relocations = []
    for section in sections:
        if section[1] != 4 or section[6] not in tables:
            continue
        assert section[9] == 24 and section[5] % 24 == 0
        for pos in range(section[4], section[4] + section[5], 24):
            address, info, addend = struct.unpack_from('<QQq', raw, pos)
            symbol = tables[section[6]][info >> 32]
            if symbol['name'] == '_Py_tss_tstate':
                relocations.append({'offset': address, 'type': info & 0xffffffff, 'addend': addend, 'symbol': symbol})
    return symbols, relocations


def main():
    git = json.loads(read(OUT / 'GIT-READBACK.json'))
    assert git['status'] == 'FULL_TREE_AND_ALL48_NEW_RAW_BLOBS_PASS'
    assert git['commit'] == '5f1c4f6bc7f8ebdf3b3e3c9c17f543a6281346d0'
    additions = []
    for row in git['additions']:
        actual = pin(ROOT / row['path'])
        assert all(actual[k] == row[k] for k in ('bytes', 'sha256', 'git_blob')), row['path']
        assert actual['mode'] & 0o022 == 0
        assert ('100755' if actual['mode'] & 0o111 else '100644') == row['git_mode']
        additions.append(actual)
    assert len(additions) == 264
    request = json.loads(read(ROOT / 'REQUEST.json'))
    policy = json.loads(read(ROOT / 'POLICY.json'))
    previous = json.loads(read(OLD / 'POLICY.json'))
    assert pin(ROOT / 'REQUEST.json')['sha256'] == '2e97663689dd224aab5717bb0c97a87f4f48e19e6079949e01d19b420cd76b74'
    assert pin(ROOT / 'POLICY.json')['sha256'] == request['policy_sha256'] == '82380a6976d8618ef386f092b27fc8f76780236eeb7b1e02038b2697d2b2b766'
    assert not os.path.lexists(request['operation_root'])
    assert (request['qualification_seconds'], request['cleanup_seconds'], request['runtime_case_count'], request['lifetime_case_count'], request['expected_HIA_returns'], request['expected_C_pump_calls_including_refusals']) == (180, 3, 8, 10, 48, 11)
    assert {key for key in set(policy) | set(previous) if policy.get(key) != previous.get(key)} == {'operation_root', 'operation_key', 'c_command', 'source_files', 'control_files'}
    normalized_command = [word.replace(str(ROOT), str(OLD)).replace(policy['operation_root'], previous['operation_root']) for word in policy['c_command']]
    assert normalized_command == previous['c_command']
    assert policy['compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds': 10, 'output_capacity': 1048576}
    assert policy['c_compiler_limits'] == previous['c_compiler_limits']
    assert policy['child_seconds'] == 5
    old_sources = {row['path']: row for row in previous['source_files']}
    new_sources = {row['path']: row for row in policy['source_files']}
    assert set(old_sources) == set(new_sources) and len(new_sources) == 182
    changed = [name for name in new_sources if new_sources[name] != old_sources[name]]
    assert changed == ['hepta/hia_cli_json_cpython312_errors.inc']
    for name in new_sources:
        if name not in changed:
            assert read(ROOT / 'source' / name) == read(OLD / 'source' / name)
    assert sum(row['bytes'] for row in policy['source_files']) == 2804414
    original_control = sorted(p.relative_to(OLD / 'control').as_posix() for p in (OLD / 'control').rglob('*') if p.is_file())
    current_control = sorted(p.relative_to(ROOT / 'control').as_posix() for p in (ROOT / 'control').rglob('*') if p.is_file())
    assert current_control == original_control and len(current_control) == 11
    for name in current_control:
        assert read(ROOT / 'control' / name) == read(OLD / 'control' / name)
    old_pins = {row['path']: row for row in previous['control_files']}
    new_pins = {row['path']: row for row in policy['control_files']}
    assert set(new_pins) - set(old_pins) == {'freeze_revision.py'} and set(old_pins) <= set(new_pins)
    assert all(new_pins[k] == v for k, v in old_pins.items())
    assert read(ROOT / 'SYSTEM-INPUTS.json') == read(OLD / 'SYSTEM-INPUTS.json')
    source = read(ROOT / 'source' / changed[0]).decode()
    inverse = source.replace(' * Two function names are local. The r2 call sites additionally use the\n * exported current-state getter, preserving EVAL_CALL_API and Vectorcall.\n * This avoids importing private TLS; error and ownership order are unchanged.\n',
                             ' * Only two local function identifiers change. No JSON traversal,\n * message selection, normalization or lifetime body is rewritten.\n')
    inverse = inverse.replace('        EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, exc);\n        value = _PyObject_CallNoArgsTstate(_PyThreadState_GetCurrent(), exc);', '        value = _PyObject_CallNoArgs(exc);')
    inverse = inverse.replace('            EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, cause);\n            fixed_cause = _PyObject_CallNoArgsTstate(_PyThreadState_GetCurrent(), cause);', '            fixed_cause = _PyObject_CallNoArgs(cause);')
    assert inverse.encode() == read(OLD / 'source' / changed[0])
    assert source.count('_PyThreadState_GetCurrent()') == 2 and source.count('EVAL_CALL_STAT_INC_IF_FUNCTION') == 2
    for name in ('pycore_call.h', 'pycore_pystate.h', 'pycore_code.h', 'pyport.h'):
        official = read(ROOT / 'reference' / ('official-' + name))
        actual = read(ROOT / 'reference' / ('actual-' + name))
        assert official == actual
    call = read(ROOT / 'reference/official-pycore_call.h').decode()
    assert '_PyObject_CallNoArgsTstate(PyThreadState *tstate, PyObject *func) {\n    return _PyObject_VectorcallTstate(tstate, func, NULL, 0, NULL);\n}' in call
    assert '_PyObject_CallNoArgs(PyObject *func) {\n    EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API, func);\n    PyThreadState *tstate = _PyThreadState_GET();\n    return _PyObject_VectorcallTstate(tstate, func, NULL, 0, NULL);\n}' in call
    state = read(ROOT / 'reference/official-pycore_pystate.h').decode()
    assert '#if defined(HAVE_THREAD_LOCAL) && !defined(Py_BUILD_CORE_MODULE)\n    return _Py_tss_tstate;\n#else\n    return _PyThreadState_GetCurrent();\n#endif' in state
    implementation = read(ROOT / 'reference/official-pystate.c').decode()
    assert '_PyThreadState_GetCurrent(void)\n{\n    return current_fast_get(&_PyRuntime);\n}' in implementation
    assert 'current_fast_get(_PyRuntimeState *Py_UNUSED(runtime))\n{\n#ifdef HAVE_THREAD_LOCAL\n    return _Py_tss_tstate;' in implementation
    runtime_symbols, _ = elf(Path(policy['python']['path']))
    getter = [row for row in runtime_symbols if row['name'] == '_PyThreadState_GetCurrent']
    assert len(getter) == 1 and getter[0]['bind'] == 1 and getter[0]['type'] == 2 and getter[0]['section'] > 0
    assert not [row for row in runtime_symbols if row['name'] == '_Py_tss_tstate' and row['section'] > 0]
    old_dso = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r1-20261112-e26e/work/c-build/cli-json.so')
    assert pin(old_dso)['sha256'] == 'efec9ed66bab1e5a97b1838fbf94f2416bff97e392b0920effc3aeddd374d316'
    original_symbols, tls = elf(old_dso)
    assert len(tls) == 2 and {row['type'] for row in tls} == {16, 17}
    assert all(row['symbol']['section'] == 0 and row['symbol']['name'] == '_Py_tss_tstate' for row in tls)
    assert (len(policy['runtime_ids']), len(policy['lifetime_ids']), sum(policy['expected_lifetime_HIA_returns']), sum(policy['expected_C_pump_calls_including_refusals'])) == (8, 10, 48, 11)
    assert (len(policy['preserved_original17_and46']['original_cli_ids']), len(policy['preserved_original17_and46']['trace_plan_ids'])) == (17, 46)
    assert policy['fresh_cold'] is False and policy['current_v92_matching_claimed'] is False and policy['activation_CALL_SEND_UNPACK_monitoring_closed'] is False
    sys.path.insert(0, str(ROOT / 'control'))
    from support import frozen
    snapshot = frozen(policy)
    old_snapshot = json.loads(read(Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r1/FROZEN-INPUTS.original.json')))
    assert snapshot['source_files'] == 182 and len(snapshot['system']['files']) == 4555
    assert snapshot['system']['files'] == old_snapshot['system']['files']
    assert snapshot['system']['namespace'] == old_snapshot['system']['namespace']
    assert not os.path.lexists(request['operation_root'])
    save(OUT / 'FROZEN-INPUTS.original.json', snapshot)
    report = {'schema': 'hia.root.cli-TLS-r2b-input-review.v1', 'status': 'ROOT_STATIC_AND_COMPLETE_INPUT_READBACK_PASS',
              'canonical': git['commit'], 'tree': git['tree'], 'git_readback': pin(OUT / 'GIT-READBACK.json'),
              'request': pin(ROOT / 'REQUEST.json'), 'policy': pin(ROOT / 'POLICY.json'), 'source_delta': pin(ROOT / 'SOURCE-DELTA.patch'),
              'all264_published_files_freshly_matched': additions, 'all48_new_unique_Git_blobs_full_read': True,
              'unchanged_source_files': 181, 'changed_source_files': changed, 'unchanged_runtime_control_files': 11,
              'whole_error_helper_inverse_exact': True, 'official_call_and_current_state_mechanism_reviewed': True,
              'actual_runtime_exported_getter': getter[0], 'actual_original_private_TLS_relocations': tls,
              'system_files_freshly_read': 4555, 'all_old_system_identities_namespaces_and_bytes_unchanged': True,
              'frozen_inputs': pin(OUT / 'FROZEN-INPUTS.original.json'),
              'expected_runtime': 8, 'expected_lifetime': 10, 'expected_HIA_returns': 48, 'expected_C_pumps': 11,
              'expected_not_actual': True, 'outer_limits': [180, 3], 'inner_seconds': [20, 5, 20, 5], 'all_original_budgets_unchanged': True,
              'output_absent': True, 'new_compiler_or_runtime_or_HIA_execution': False,
              'limitations': ['Existing v89 compiler originals only; no matching v92/fresh cold claim.', 'The complete CLI17/trace46, evaluator activation, graph replacement, installation and default are outside this finite request.', 'Only the exact two-call TLS successor is admitted for a unique execution; prior r1 HOLD remains unchanged.']}
    save(OUT / 'ROOT-REVIEW.json', report)
    print(json.dumps({'status': report['status'], 'review': pin(OUT / 'ROOT-REVIEW.json'), 'source': 182, 'system': 4555,
                      'expected': [8, 10, 48, 11], 'new_actual_absent': True}, sort_keys=True))


if __name__ == '__main__':
    main()
