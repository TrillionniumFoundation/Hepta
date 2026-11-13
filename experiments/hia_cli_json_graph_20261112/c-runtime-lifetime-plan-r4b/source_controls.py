"""Pure ELF/map counterexamples only: no ctypes, DSO, HIA, or product entry."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import time
import traceback

ROOT = Path(__file__).resolve().parent
IDS = (
    'layout.actual_base_eleven_symbols',
    'layout.actual_control_five_symbols',
    'layout.actual_exec_six_loads_seven_maps',
    'layout.synthetic_dyn_nonzero_origin_and_bias',
    'layout.reject_wrong_elf_kind',
    'layout.reject_truncated_header',
    'layout.reject_truncated_program_table',
    'layout.reject_file_larger_than_memory',
    'layout.reject_nonpower_segment_alignment',
    'layout.reject_noncongruent_segment',
    'layout.reject_required_nonexecutable_section',
    'layout.reject_required_nonfunction_symbol',
    'layout.reject_required_symbol_extent',
    'layout.reject_ambiguous_required_symbol',
    'layout.reject_changed_required_symbol_name',
    'layout.reject_exec_nonzero_bias',
    'layout.reject_mapping_base_used_as_bias',
    'layout.reject_shifted_anchor',
    'layout.reject_wrong_loader_base',
    'layout.reject_wrong_file_offset',
    'layout.reject_missing_execute_permission',
    'layout.reject_writable_code',
    'layout.reject_code_mapping_gap',
    'layout.reject_overlapping_file_maps',
    'layout.reject_wrong_inode',
    'layout.reject_wrong_physical_path',
    'layout.reject_deleted_physical_path',
    'layout.reject_unexplained_extra_file_map',
)


def wire(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def exact_names(raw, name):
    node = next(n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise ValueError('fresh source-control output required')
    output.mkdir(parents=True, mode=0o700)
    request_raw = (ROOT / 'SOURCE-CONTROL-REQUEST.json').read_bytes()
    request = json.loads(request_raw)
    if str(output) != request['output'] or list(IDS) != request['expected_ids']:
        raise ValueError('exact source-control output and IDs required')
    for item in request['inputs']:
        if pin(Path(item['path'])) != item:
            raise ValueError('source-control input differs: ' + item['path'])
    module = ROOT / 'source/hepta/hia_cli_json_runtime312.py'
    extra = ROOT / 'source/hepta/hia_cli_json_runtime312_control.py'
    original_source = module.read_bytes()
    tree = ast.parse(original_source)
    functions = ('_runtime_profile', '_symbol_records', '_parse_runtime_maps',
                 '_cover_file_span', '_mapping_relation')
    selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in functions]
    if len(selected) != len(functions):
        raise ValueError('exact pure-function subset required')
    namespace = {'os': os, 'sha256': hashlib.sha256,
                 'HEADER': struct.Struct('<16sHHIQQQIHHHHHH'),
                 'PROGRAM': struct.Struct('<IIQQQQQQ'),
                 'SECTION': struct.Struct('<IIQQQQIIQQ'),
                 'SYMBOL': struct.Struct('<IBBHQQ')}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(module), 'exec'), namespace)
    base_names = exact_names(original_source, 'SYMBOLS')
    control_names = exact_names(extra.read_bytes(), 'CONTROL_SYMBOLS')
    runtime_pin = request['runtime_pin']
    runtime_path = Path(runtime_pin['path'])
    raw = runtime_path.read_bytes()
    if len(raw) != runtime_pin['bytes'] or hashlib.sha256(raw).hexdigest() != runtime_pin['sha256']:
        raise ValueError('fixed actual ELF input differs')
    observation = json.loads((ROOT / 'reference/NEW-PROCESS-MAPS.json').read_bytes())
    runtime = observation['runtime']
    maps_raw = observation['runtime_maps_text'].encode()
    rows = namespace['_parse_runtime_maps'](maps_raw, runtime)
    records, layout = namespace['_symbol_records'](raw, base_names)
    anchor = records[0]['value']
    image_base = layout['lowest_load_page']
    symbols = namespace['_symbol_records']
    relation = namespace['_mapping_relation']
    report = {'schema': 'hia.cli-json.runtime-layout-source-controls.v1', 'status': 'HOLD',
              'request_sha256': hashlib.sha256(request_raw).hexdigest(),
              'expected_ids': list(IDS), 'loaded_ids': [], 'executed_ids': [], 'outcomes': [],
              'input_map_origin': 'Separate readonly metadata process, not reconstructed r3 child maps',
              'actual_runtime_symbol_admission_executed': False,
              'ctypes_DSO_C_HIA_or_product_executed': False,
              'original_runtime8_or_lifetime10_executed': False,
              'original17_or46_executed': False}
    header = namespace['HEADER'].unpack_from(raw)
    section_table = [namespace['SECTION'].unpack_from(raw, header[6] + i * 64) for i in range(header[12])]
    table = next(s for s in section_table if s[1] == 2)
    strings_section = section_table[table[6]]
    strings = raw[strings_section[4]:strings_section[4] + strings_section[5]]
    symbol_offsets = []
    for at in range(table[4], table[4] + table[5], 24):
        fields = namespace['SYMBOL'].unpack_from(raw, at)
        end = strings.find(b'\0', fields[0])
        name = strings[fields[0]:end].decode('ascii')
        if name == base_names[0]:
            symbol_offsets.append((at, fields))
    if len(symbol_offsets) != 1:
        raise ValueError('one exact anchor symbol required by negative fixtures')
    symbol_at, symbol = symbol_offsets[0]
    exec_segment = next(s for s in layout['load_segments'] if s['program_index'] == records[0]['segment_index'])
    program_at = header[5] + exec_segment['program_index'] * 56
    exec_map = next(i for i, row in enumerate(rows) if row['start'] <= anchor < row['end'])

    def changed_raw(offset, format, value):
        data = bytearray(raw)
        struct.pack_into(format, data, offset, value)
        return bytes(data)

    def changed_rows(index, field, value):
        result = copy.deepcopy(rows)
        result[index][field] = value
        return result

    def must_refuse(operation):
        try:
            operation()
        except ValueError as error:
            return {'refusal_type': type(error).__name__, 'message': str(error)}
        raise AssertionError('bad input was accepted')

    def check(case_id):
        if case_id == IDS[0]:
            assert tuple(r['name'] for r in records) == base_names and len(records) == 11
            return {'symbols': records}
        if case_id == IDS[1]:
            added, extra_layout = symbols(raw, control_names)
            assert len(added) == 5 and tuple(r['name'] for r in added) == control_names
            assert extra_layout == layout and added[0] == records[0]
            return {'symbols': added}
        if case_id == IDS[2]:
            value = relation(layout, records, runtime, anchor, image_base, rows)
            assert len(layout['load_segments']) == 6 and len(rows) == 7 and value['relocation_bias'] == 0
            return value
        if case_id == IDS[3]:
            data = changed_raw(16, '<H', 3)
            dynamic_records, dynamic_layout = symbols(data, base_names)
            shift = 0x700000000000
            shifted = copy.deepcopy(rows)
            for row in shifted:
                row['start'] += shift
                row['end'] += shift
            value = relation(dynamic_layout, dynamic_records, runtime, anchor + shift, image_base + shift, shifted)
            assert value['relocation_bias'] == shift and value['lowest_load_page'] == image_base
            return {'synthetic_coordinate_control_only': True, 'mapping': value}
        if case_id == IDS[4]:
            return must_refuse(lambda: symbols(changed_raw(16, '<H', 1), base_names))
        if case_id == IDS[5]:
            return must_refuse(lambda: symbols(raw[:63], base_names))
        if case_id == IDS[6]:
            return must_refuse(lambda: symbols(raw[:header[5] + header[10] * 56 - 1], base_names))
        if case_id == IDS[7]:
            return must_refuse(lambda: symbols(changed_raw(program_at + 40, '<Q', exec_segment['file_bytes'] - 1), base_names))
        if case_id == IDS[8]:
            return must_refuse(lambda: symbols(changed_raw(program_at + 48, '<Q', 3), base_names))
        if case_id == IDS[9]:
            return must_refuse(lambda: symbols(changed_raw(program_at + 16, '<Q', exec_segment['virtual_address'] + 1), base_names))
        if case_id == IDS[10]:
            return must_refuse(lambda: symbols(changed_raw(header[6] + symbol[3] * 64 + 8, '<Q', 2), base_names))
        if case_id == IDS[11]:
            return must_refuse(lambda: symbols(changed_raw(symbol_at + 4, '<B', symbol[1] & 0xf0 | 1), base_names))
        if case_id == IDS[12]:
            return must_refuse(lambda: symbols(changed_raw(symbol_at + 16, '<Q', len(raw)), base_names))
        if case_id == IDS[13]:
            data = bytearray(raw)
            other = table[4] if symbol_at != table[4] else table[4] + 24
            namespace['SYMBOL'].pack_into(data, other, symbol[0], symbol[1], symbol[2], symbol[3], symbol[4] + 1, symbol[5])
            return must_refuse(lambda: symbols(bytes(data), base_names))
        if case_id == IDS[14]:
            data = bytearray(raw)
            data[strings_section[4] + symbol[0]] = ord('X')
            return must_refuse(lambda: symbols(bytes(data), base_names))
        if case_id == IDS[15]:
            shifted = copy.deepcopy(rows)
            for row in shifted:
                row['start'] += 4096
                row['end'] += 4096
            return must_refuse(lambda: relation(layout, records, runtime, anchor + 4096, image_base + 4096, shifted))
        if case_id == IDS[16]:
            return must_refuse(lambda: relation(layout, records, runtime, image_base + anchor, image_base, rows))
        if case_id == IDS[17]:
            return must_refuse(lambda: relation(layout, records, runtime, anchor + 1, image_base, rows))
        if case_id == IDS[18]:
            return must_refuse(lambda: relation(layout, records, runtime, anchor, image_base + 4096, rows))
        if case_id == IDS[19]:
            return must_refuse(lambda: relation(layout, records, runtime, anchor, image_base,
                changed_rows(exec_map, 'file_offset', rows[exec_map]['file_offset'] + 1)))
        if case_id == IDS[20]:
            return must_refuse(lambda: relation(layout, records, runtime, anchor, image_base,
                changed_rows(exec_map, 'permissions', 'r--p')))
        if case_id == IDS[21]:
            return must_refuse(lambda: relation(layout, records, runtime, anchor, image_base,
                changed_rows(exec_map, 'permissions', 'rwxp')))
        if case_id == IDS[22]:
            return must_refuse(lambda: relation(layout, records, runtime, anchor, image_base,
                changed_rows(exec_map, 'start', rows[exec_map]['start'] + 1)))
        if case_id == IDS[23]:
            return must_refuse(lambda: namespace['_parse_runtime_maps'](maps_raw + maps_raw.splitlines()[0] + b'\n', runtime))
        if case_id in IDS[24:27]:
            wrong = copy.deepcopy(runtime)
            if case_id == IDS[24]:
                wrong['identity'][1] += 1
                changed = maps_raw
            elif case_id == IDS[25]:
                changed = maps_raw.replace(runtime['path'].encode(), (runtime['path'] + '.different').encode())
            else:
                changed = maps_raw.replace(runtime['path'].encode(), (runtime['path'] + ' (deleted)').encode())
            return must_refuse(lambda: namespace['_parse_runtime_maps'](changed, wrong))
        if case_id == IDS[27]:
            extra_row = copy.deepcopy(rows[-1])
            extra_row.update(start=extra_row['end'] + 4096, end=extra_row['end'] + 8192)
            return must_refuse(lambda: relation(layout, records, runtime, anchor, image_base, rows + [extra_row]))
        raise AssertionError('unknown exact source-control ID')

    start = time.monotonic_ns()
    try:
        for case_id in IDS:
            report['loaded_ids'].append(case_id)
            row = {'id': case_id, 'status': 'HOLD'}
            try:
                row['observation'] = check(case_id)
                row['status'] = 'PASS'
                report['executed_ids'].append(case_id)
            except BaseException:
                row['error'] = traceback.format_exc()
                raise
            finally:
                report['outcomes'].append(row)
        for item in request['inputs']:
            if pin(Path(item['path'])) != item:
                raise ValueError('source-control input changed at exit')
        assert module.read_bytes() == original_source
        assert runtime_path.read_bytes() == raw
        report['status'] = 'PASS'
    except BaseException:
        report['error'] = traceback.format_exc()
        raise
    finally:
        report['elapsed_ns'] = time.monotonic_ns() - start
        with (output / 'REPORT.json').open('xb') as file:
            file.write(wire(report))


if __name__ == '__main__':
    main()
