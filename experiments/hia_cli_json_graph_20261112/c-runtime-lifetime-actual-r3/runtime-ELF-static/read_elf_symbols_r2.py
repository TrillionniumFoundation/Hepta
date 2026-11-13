"""Read the fixed executable ELF and all sixteen table entries; never load it."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

ROOT = Path(__file__).resolve().parent
PLAN = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e')


def ident(s):
    return {key: getattr(s, 'st_' + key) for key in
            ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def read(path):
    st = path.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert ident(st) == ident(os.fstat(fd))
        parts = []
        remaining = st.st_size
        while remaining:
            part = os.read(fd, min(1 << 20, remaining))
            assert part
            parts.append(part)
            remaining -= len(part)
        assert not os.read(fd, 1)
        assert ident(st) == ident(os.fstat(fd)) == ident(path.lstat())
    finally:
        os.close(fd)
    raw = b''.join(parts)
    return raw, {'path': str(path), 'identity': ident(st), 'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def constant(path, name):
    raw, pin = read(path)
    found = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    assert len(found) == 1
    names = ast.literal_eval(found[0].value)
    assert type(names) is tuple and all(type(x) is str for x in names)
    return names, pin


def main():
    policy = json.loads((PLAN / 'POLICY.json').read_bytes())
    path = Path(policy['python']['path'])
    raw, pin = read(path)
    assert pin['sha256'] == policy['python']['sha256'] and pin['bytes'] == policy['python']['bytes']
    manifest = json.loads((PLAN / 'SYSTEM-INPUTS.json').read_bytes())
    matches = [r for r in manifest['files'] if r['physical_path'] == str(path)]
    assert len(matches) == 1 and matches[0]['identity'] == pin['identity']
    assert matches[0]['sha256'] == pin['sha256'] and matches[0]['git_blob'] == pin['git_blob']
    base, base_pin = constant(PLAN / 'source/hepta/hia_cli_json_runtime312.py', 'SYMBOLS')
    control, control_pin = constant(PLAN / 'source/hepta/hia_cli_json_runtime312_control.py', 'CONTROL_SYMBOLS')
    assert len(base) == 11 and len(control) == 5
    names = set(base + control)

    def span(at, count):
        assert type(at) is int and type(count) is int and 0 <= at <= len(raw) and 0 <= count <= len(raw) - at
        return raw[at:at + count]

    h = struct.unpack('<16sHHIQQQIHHHHHH', span(0, 64))
    assert h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1] == 2 and h[2] == 62
    assert h[3] == 1 and h[8] == 64 and h[9] == 56 and h[11] == 64 and h[13] < h[12]
    programs = [dict(zip(('kind','flags','file_offset','virtual_address','physical_address','file_bytes','memory_bytes','alignment'),
                        struct.unpack('<IIQQQQQQ', span(h[5] + i * 56, 56)))) for i in range(h[10])]
    sections = [dict(zip(('name_offset','kind','flags','address','file_offset','bytes','link','info','alignment','stride'),
                        struct.unpack('<IIQQQQIIQQ', span(h[6] + i * 64, 64)))) for i in range(h[12])]
    loads = [p for p in programs if p['kind'] == 1]
    for p in loads:
        assert p['file_bytes'] <= p['memory_bytes']
        span(p['file_offset'], p['file_bytes'])
        assert p['alignment'] == 4096 and p['virtual_address'] % 4096 == p['file_offset'] % 4096
    found = {name: [] for name in names}
    tables = []
    for section_index, section in enumerate(sections):
        if section['kind'] != 2:
            continue
        assert section['stride'] == 24 and section['bytes'] % 24 == 0 and section['link'] < len(sections)
        strings_section = sections[section['link']]
        assert strings_section['kind'] == 3
        strings = span(strings_section['file_offset'], strings_section['bytes'])
        table = span(section['file_offset'], section['bytes'])
        count = 0
        for offset in range(0, len(table), 24):
            name_at, info, other, index, value, size = struct.unpack_from('<IBBHQQ', table, offset)
            assert name_at < len(strings)
            end = strings.find(b'\0', name_at)
            assert end >= 0
            name = strings[name_at:end].decode('ascii')
            count += 1
            if name in names:
                found[name].append({'name': name, 'value': value, 'bytes': size,
                    'bind': info >> 4, 'type': info & 15, 'visibility': other & 3,
                    'other': other, 'section': index, 'table_section': section_index,
                    'table_entry': offset // 24})
        tables.append({'section': section_index, 'count': count, 'bytes': len(table),
            'sha256': hashlib.sha256(table).hexdigest(), 'strings_bytes': len(strings),
            'strings_sha256': hashlib.sha256(strings).hexdigest()})
    records = {}
    for name, symbols in found.items():
        assert len(symbols) == 1, (name, symbols)
        record = dict(symbols[0])
        assert record['type'] == 2 and 0 < record['section'] < len(sections) and record['bytes'] > 0
        section = sections[record['section']]
        assert section['flags'] & 6 == 6 and section['kind'] == 1
        relative = record['value'] - section['address']
        assert 0 <= relative <= section['bytes'] and record['bytes'] <= section['bytes'] - relative
        matching_loads = []
        for load_index, p in enumerate(loads):
            relative_load = record['value'] - p['virtual_address']
            if p['flags'] & 1 and 0 <= relative_load <= p['file_bytes'] and record['bytes'] <= p['file_bytes'] - relative_load:
                matching_loads.append((load_index, p, p['file_offset'] + relative_load))
        assert len(matching_loads) == 1
        load_index, segment, file_at = matching_loads[0]
        assert file_at == section['file_offset'] + relative
        code = span(file_at, record['bytes'])
        record.update(file_offset=file_at, executable_load_index=load_index,
            executable_load=segment, code_sha256=hashlib.sha256(code).hexdigest(),
            ET_EXEC_required_relocation_bias=0,
            ET_EXEC_derived_absolute_address=record['value'])
        records[name] = record
    assert len(loads) == 6 and sum(bool(p['flags'] & 1) for p in loads) == 2
    assert min(p['virtual_address'] for p in loads) == 0x3ff000
    _, after = read(path)
    assert after == pin
    result = {'schema': 'hia.cli-json.fixed-runtime-ET_EXEC-static-layout.v1',
        'status': 'COMPLETE_STATIC_ELF_ALL16_TABLE_ENTRIES', 'runtime': pin,
        'ELF_type': h[1], 'ELF_entry': h[4], 'program_headers': programs,
        'PT_LOAD_count': len(loads), 'executable_PT_LOAD_count': 2,
        'lowest_linktime_virtual_address': min(p['virtual_address'] for p in loads),
        'all_SHT_SYMTAB_metadata': tables, 'base_source': base_pin, 'control_source': control_pin,
        'base11': [records[n] for n in base], 'control5': [records[n] for n in control],
        'unique_required_functions': len(records), 'every_required_function_unique': True,
        'every_required_code_span_in_exactly_one_executable_file_backed_PT_LOAD': True,
        'all_required_section_and_segment_file_offsets_equal': True,
        'required_new_admission': ['Keep full frozen file and system profile checks.',
            'Distinguish absolute ET_EXEC symbol values from ET_DYN relocation-relative values.',
            'Derive and validate load bias separately from loader mapping base.',
            'Bind anchor and every whole live function span to the same mapped file and PF_X segment.',
            'Preserve both table entrances and all original bad-input refusals.'],
        'original_r3_child_live_mappings_not_recorded_before_failure': True,
        'new_process_mappings_observed_here': False, 'dladdr_called_here': False,
        'runtime_admission_or_product_import_executed': False, 'native_executed': False}
    path_out = ROOT / 'STATIC-ELF-REPORT.r2.json'
    payload = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        at = 0
        while at < len(payload):
            n = os.write(fd, payload[at:]); assert n > 0; at += n
        os.fsync(fd)
    finally:
        os.close(fd)
    assert path_out.read_bytes() == payload
    print(json.dumps({'status': result['status'], 'PT_LOAD': len(loads), 'PF_X': 2,
        'base11': [n for n in base], 'control5': [n for n in control],
        'unique_functions': len(records), 'report_bytes': len(payload),
        'report_sha256': hashlib.sha256(payload).hexdigest(), 'native_executed': False}))


if __name__ == '__main__':
    main()
