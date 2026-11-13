"""Audit only the completed finite run, including original binary traces."""
from pathlib import Path
import hashlib
import json
import os
import stat
import struct
import sys

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4b')
ACTUAL = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-actual-r4b')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-invocation-r4b')
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'control'))
from support import closed_owner, environment, owner_paths, stage_command
from common import pin, read_file
from verify import c_image, hia_image, finite_cases


def load(path):
    return json.loads(read_file(path, 16 << 20)[0])


def independent_recorded_symbols(binding, runtime_raw, names, runtime_pin):
    """Join the original child's recorded live spans to an independent ELF parse."""
    assert binding['profile'] == 31214 and binding['relocation_bias'] == 0 and binding['load_base'] == 0x3ff000
    assert binding['runtime'] == binding['runtime_after']
    assert all(binding['runtime'][key] == runtime_pin[key] for key in ('path', 'sha256'))
    assert binding['runtime']['bytes'] == runtime_pin['size']
    assert binding['runtime']['identity'] == [runtime_pin['identity'][key] for key in
        ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')]
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', runtime_raw)
    assert header[0][:7] == b'\x7fELF\x02\x01\x01' and header[1:4] == (2, 62, 1)
    programs = [struct.unpack_from('<IIQQQQQQ', runtime_raw, header[5] + 56 * i) for i in range(header[10])]
    sections = [struct.unpack_from('<IIQQQQIIQQ', runtime_raw, header[6] + 64 * i) for i in range(header[12])]
    expected = {name: set() for name in names}
    for section in sections:
        if section[1] != 2:
            continue
        assert section[9] == 24 and section[5] % 24 == 0
        strings_section = sections[section[6]]
        assert strings_section[1] == 3
        strings = runtime_raw[strings_section[4]:strings_section[4] + strings_section[5]]
        for at in range(section[4], section[4] + section[5], 24):
            name_at, info, visibility, index, value, size = struct.unpack_from('<IBBHQQ', runtime_raw, at)
            assert name_at < len(strings)
            end = strings.find(b'\0', name_at)
            assert end >= 0
            name = strings[name_at:end].decode('ascii')
            if name in expected:
                assert info & 15 == 2 and 0 < index < len(sections) and size > 0
                expected[name].add((value, size, visibility, index))
    assert all(len(rows) == 1 for rows in expected.values())
    assert [r['name'] for r in binding['symbols']] == names
    mapping = binding['mapping']
    assert mapping['elf_type'] == 2 and mapping['elf_type_name'] == 'ET_EXEC'
    assert mapping['relocation_bias'] == 0 and mapping['lowest_load_page'] == mapping['image_mapping_base'] == 0x3ff000
    assert len(mapping['load_segments']) == 6 and len(mapping['process_file_maps']) == 7
    actual_device = runtime_pin['identity']['dev']
    for row in mapping['process_file_maps']:
        assert (row['device_major'], row['device_minor']) == (os.major(actual_device), os.minor(actual_device))
        assert row['inode'] == runtime_pin['identity']['ino'] and row['path'] == runtime_pin['path']
    checked = []
    for row in binding['symbols']:
        value, size, visibility, section_index = next(iter(expected[row['name']]))
        sec = sections[section_index]
        assert sec[1] == 1 and sec[2] & 6 == 6
        assert sec[3] <= value and value + size <= sec[3] + sec[5]
        file_at = sec[4] + value - sec[3]
        segments = [(i, p) for i, p in enumerate(programs) if p[0] == 1 and p[1] & 5 == 5
                    and p[3] <= value and value + size <= p[3] + p[5]]
        assert len(segments) == 1
        index, segment = segments[0]
        assert file_at == segment[2] + value - segment[3]
        code = runtime_raw[file_at:file_at + size]
        assert len(code) == size
        digest = hashlib.sha256(code).hexdigest()
        assert row == {'name': row['name'], 'value': value, 'bytes': size, 'section': section_index,
            'segment_index': index, 'file_offset': file_at, 'sha256': digest,
            'actual_address': value, 'actual_sha256': digest}
        cursor = value
        while cursor < value + size:
            matches = [m for m in mapping['process_file_maps'] if m['start'] <= cursor < m['end']]
            assert len(matches) == 1 and matches[0]['permissions'] == 'r-xp'
            m = matches[0]
            assert m['file_offset'] + cursor - m['start'] == file_at + cursor - value
            cursor = min(m['end'], value + size)
        checked.append(row)
    return {'symbols': checked, 'mapping': mapping, 'recorded_child_live_bytes_equal_current_frozen_ELF': True,
            'new_process_live_admission_or_product_execution': False}


def main():
    policy = load(ROOT / 'POLICY.json')
    policy_sha = pin(ROOT / 'POLICY.json')['sha256']
    assert policy_sha == '312f241ad5ae48d34b7553d4fb982f0b81dd7f2971730b9bd9108e077c12d5e6'
    spawn = load(OUT / 'SPAWN.json')
    outer_request = read_file(ACTUAL / 'owned/outer.lifecycle.json.request.json')[0]
    outer_raw = read_file(ACTUAL / 'owned/outer.lifecycle.json')[0]
    command = [policy['python']['path'], '-I', '-S', '-B', str(ROOT / 'control/worker.py'),
        '--policy', str(ROOT / 'POLICY.json'), '--policy-sha256', policy_sha]
    outer = closed_owner(load(ACTUAL / 'WRAPPER.json'), outer_raw, outer_request,
        command=command, cwd=ROOT, env=environment(ACTUAL / 'work/temporary'),
        paths=owner_paths(ACTUAL / 'owned', 'outer'), seconds=180, parent=spawn['pid'])
    assert outer['returncode'] == 0 and outer['timed_out'] is False
    assert outer['exit_observed_before_deadline'] is True and outer.get('owner_error') is None
    assert [r['kind'] for r in outer['events']] == ['qualification_started', 'owned_child_observed',
        'qualification_exit_observed', 'owned_child_reaped']
    final = load(ACTUAL / 'FINAL.json')
    assert final['status'] == 'FINITE_C_RUNTIME_LIFETIME_PASS' and final['closed_owner'] is True
    assert final['natural_owner'] and final['source_preserved'] and final['complete_original_inventory']
    assert not final['full_graph_qualified'] and not final['body_driver_qualified']
    assert not final['default_changed'] and not final['fresh_cold']
    assert not final['original17_executed'] and not final['original46_executed']
    work = ACTUAL / 'work'
    inventory = load(ACTUAL / 'CLOSED-ORIGINALS.json')
    assert inventory['status'] == 'COMPLETE_ACTUAL_ORIGINALS' and inventory['errors'] == []
    assert inventory['regular_bytes'] == 5222543 and len(inventory['rows']) == 107
    assert sorted(row['path'] for row in inventory['rows']) == sorted(p.relative_to(work).as_posix() for p in work.rglob('*'))
    for row in inventory['rows']:
        path = work / row['path']
        if row['kind'] == 'regular':
            assert pin(path, 16 << 20) == row['actual'], row['path']
        else:
            assert row['kind'] == 'directory' and stat.S_ISDIR(path.lstat().st_mode), row['path']
    report = load(work / 'REPORT.json')
    assert report['status'] == 'FINITE_C_RUNTIME_LIFETIME_PASS_PENDING_OUTER_CLOSURE'
    assert report['attempted_stages'] == report['completed_stages'] == report['expected_stages'] == ['c-compile', 'runtime', 'hia-compile', 'lifetime']
    assert report['inner_closure_confirmed'] is True and report['source_preserved'] is True and report['errors'] == []
    c, hia = c_image(policy, work), hia_image(policy, work)
    assert c == load(work / 'C-BUILD-JOIN.json') == final['c_compile']
    assert hia == load(work / 'HIA-BUILD-JOIN.json') == final['hia_compile']
    assert c['image']['size'] == 72432 and c['image']['sha256'] == report['actual_dso_sha256'] == '373bda79d60872393bd6f3598584f180f0c6e970fd73b30b43b055232685a40d'
    assert hia['image']['size'] == 38530 and hia['image']['sha256'] == report['actual_hia_image_sha256'] == '05d839dea3e4006d52c05674a63745ab711c2dcb055d3d33d93844550227211b'
    owners = []
    for label, seconds in [('c-compile', 20), ('runtime', 5), ('hia-compile', 20), ('lifetime', 5)]:
        row = report['owners'][label]
        actual_command = stage_command(policy, ROOT / 'POLICY.json', policy_sha, label,
            dso=c if label in ('runtime', 'lifetime') else None, image=hia if label == 'lifetime' else None)
        paths = owner_paths(work / 'owners', label)
        wrapper = load(work / 'owners' / (label + '.WRAPPER.json'))
        assert wrapper == row['wrapper']
        life = closed_owner(wrapper, read_file(Path(paths['receipt_path']))[0],
            read_file(Path(paths['receipt_path'] + '.request.json'))[0], command=actual_command,
            cwd=ROOT, env=environment(work / 'temporary', compiler=label in ('c-compile', 'hia-compile')),
            paths=paths, seconds=seconds, parent=outer['qualification_pid'])
        assert life['returncode'] == 0 and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
        assert life['event_overflow'] is False and life.get('owner_error') is None
        assert [r['kind'] for r in life['events']] == ['qualification_started', 'owned_child_observed',
            'qualification_exit_observed', 'owned_child_reaped']
        for original in row['originals'].values():
            assert pin(Path(original['path']), 4 << 20) == original
        owners.append({'stage': label, 'returncode': 0, 'seconds': seconds,
            'life': pin(Path(paths['receipt_path'])), 'request': pin(Path(paths['receipt_path'] + '.request.json')),
            'actual_elapsed_ns': life['events'][-2]['monotonic_ns'] - life['events'][0]['monotonic_ns'],
            'bound_four_natural_events_ECHILD': True})
    runtime = finite_cases(policy, policy_sha, work, 'runtime', c)
    lifetime = finite_cases(policy, policy_sha, work, 'lifetime', c, hia)
    assert runtime == load(work / 'RUNTIME-JOIN.json') == final['runtime']
    assert lifetime == load(work / 'LIFETIME-JOIN.json') == final['lifetime']
    assert lifetime['hia_entry_returns'] == report['actual_lifetime_entry_returns'] == 48
    assert lifetime['c_pump_calls_including_refusals'] == report['actual_c_pump_calls'] == 11
    runtime_raw, runtime_pin = read_file(Path(policy['python']['path']), 32 << 20)
    base_binding = load(work / 'runtime/runtime.base_eleven_live_symbols.json')['binding']
    extra_binding = load(work / 'runtime/runtime.control_five_live_symbols.json')['binding']
    base_names = ['_PyEval_EvalFrameDefault', '_PyFunction_Vectorcall', '_PyThreadState_PushFrame',
        '_PyThreadState_PopFrame', '_PyFrame_ClearExceptCode', '_PyTuple_FromArraySteal',
        '_PyFrame_MakeAndSetFrameObject', '_Py_MakeCoro', '_PyList_AppendTakeRefListResize', 'list_resize', '_Py_CheckRecursiveCallPy']
    extra_names = ['_PyEval_EvalFrameDefault', '_Py_Instrument', '_Py_call_instrumentation_arg', '_Py_HandlePending', '_PyErr_ChainStackItem']
    symbol_joins = [independent_recorded_symbols(base_binding, runtime_raw, base_names, runtime_pin),
        independent_recorded_symbols(extra_binding, runtime_raw, extra_names, runtime_pin),
        independent_recorded_symbols(load(work / 'lifetime/REPORT.json')['runtime_binding'], runtime_raw, base_names, runtime_pin)]
    assert base_binding['mapping'] == extra_binding['mapping'] == extra_binding['base_binding']['mapping']
    assert len(set(base_names + extra_names)) == 15
    before = load(ACTUAL / 'INPUTS-BEFORE.json')
    assert before == load(ACTUAL / 'INPUTS-AFTER.json') == load(work / 'INPUTS-BEFORE.json') == load(work / 'INPUTS-AFTER.json')
    assert before == load(OUT.parent / 'cli-c-runtime-lifetime-review-r4b/FROZEN-INPUTS.original.json')
    originals = [pin(p, 16 << 20) for p in sorted(ACTUAL.rglob('*')) if p.is_file()]
    assert len(originals) == 114
    result = {'schema': 'hia.root.cli-finite-r4b-actual-readback.v1', 'status': 'FINITE_C_RUNTIME_LIFETIME_PASS_ONLY',
        'actual_request': '6e704d8457ebb357fa71e3f0d40fc5064d943da8',
        'request': pin(ROOT / 'REQUEST.json'), 'policy': pin(ROOT / 'POLICY.json'),
        'outer': {'returncode': 0, 'natural_exit': True, 'timed_out': False, 'closed_ECHILD': True,
            'original_180_3': True, 'actual_elapsed_ns': outer['events'][-2]['monotonic_ns'] - outer['events'][0]['monotonic_ns'],
            'life': pin(ACTUAL / 'owned/outer.lifecycle.json')}, 'inner_owners': owners,
        'C_image': c['image'], 'C_compile_and_ELF_dependency_join': 'PASS', 'HIA_image': hia['image'],
        'HIA_original_compile_full_input_output_receipt_join': 'PASS', 'runtime_expected_loaded_executed_success': [8, 8, 8, 8],
        'lifetime_expected_loaded_executed_success': [10, 10, 10, 10], 'HIA_entry_returns': 48, 'C_pump_calls': 11,
        'runtime_original': pin(work / 'runtime/REPORT.json'), 'lifetime_original': pin(work / 'lifetime/REPORT.json'),
        'all_individual_case_and_request_state_trace_body_joins': True,
        'runtime_15_unique_symbols_independently_parsed': True, 'original_child_symbol_mapping_joins': symbol_joins,
        'two_intentional_quarantines_retained_to_child_exit': True, 'negative_incomplete_trace_preserved_as_incomplete': True,
        'new_request_executed_once': True, 'prior_three_actual_HOLDs_unchanged': True,
        'original_CLI17_executed': False, 'original_trace46_executed': False, 'full_graph_qualified': False,
        'full_body_driver_qualified': False, 'current_v92_matching_or_fresh_cold': False, 'default_changed': False,
        'all_four_actual_input_snapshots_equal_root_preexec_snapshot': True,
        'closed_work_inventory_rows': 107, 'closed_work_regular_bytes': 5222543,
        'complete_actual_originals': originals, 'whole_rewrite_closed': False}
    with (OUT / 'READBACK.json').open('x') as file:
        json.dump(result, file, sort_keys=True, indent=2); file.write('\n'); file.flush(); os.fsync(file.fileno())
    print(json.dumps({'status': result['status'], 'actual_originals': len(originals),
        'runtime': 8, 'lifetime': 10, 'HIA_returns': 48, 'C_pumps': 11,
        'readback': pin(OUT / 'READBACK.json')}, sort_keys=True))


if __name__ == '__main__':
    main()
