"""Author the standalone HIA generic-candidate build dispatcher.

This is bootstrap authoring, not a runtime Python policy provider. The emitted
HIA owns all catalog selection, native stage requests, and manifest bytes.
The existing source-build policy, compiler and SHA-256 are separate resident
HIA images. Their existing source/image/wire limits are unchanged.
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / 'tools/hia_candidate_build_catalog.json'
BUNDLE_MAGIC = int.from_bytes(b'HIAREL01', 'little')
PACK_MAGIC = int.from_bytes(b'HIACPK01', 'little')
CONTROL_MAGIC = int.from_bytes(b'HIACBW01', 'little')
WIRE_LIMIT = 64 << 20
IMAGE_LIMIT = 1 << 20
BUILD_WORK_BYTES = 65536 + IMAGE_LIMIT
CONTROL_BYTES = 16384
WORK_BYTES = CONTROL_BYTES + BUILD_WORK_BYTES
LAYOUT = {'ARGS': 0, 'WORK': 4096, 'CONTROL_BYTES': CONTROL_BYTES,
          'BUILD_WORK_BYTES': BUILD_WORK_BYTES, 'WORK_BYTES': WORK_BYTES,
          'IMAGE_AT': 65536, 'IMAGE_LIMIT': IMAGE_LIMIT, 'LIMIT': WIRE_LIMIT}
LAYOUT['COMPWORK'] = LAYOUT['WORK'] + WORK_BYTES
LAYOUT['SHAWORK'] = LAYOUT['COMPWORK'] + IMAGE_LIMIT
LAYOUT['OUT'] = LAYOUT['SHAWORK'] + 4096
LAYOUT['WIRE'] = LAYOUT['OUT'] + WIRE_LIMIT
LAYOUT['WIRE_CAP'] = WIRE_LIMIT + 4096
LAYOUT['MAPSIZE'] = LAYOUT['WIRE'] + LAYOUT['WIRE_CAP']

POLICY = '''def candidate_build(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < WORK_BYTES:
        return 16
    event = get(w, 0)
    stage = get(w, 8)
    if stage == 255:
        return 16
    if event == 0:
        if stage != 0 or get(w, 72) != 0:
            return bad(w, 16)
        if get(w, 88) == 0 or get(w, 88) > 1048576:
            return bad(w, 16)
        if length(s) < 16 or uint(s, 0, 8) != 1:
            return bad(w, 16)
        n = uint(s, 8, 8)
        if n == 0 or n > 127 or length(s) != 16 + n:
            return bad(w, 16)
        initialize_catalog(w)
        row = find_candidate(s, 16, n, w)
        if row == 0:
            return bad(w, 16)
        put(w, 32, row)
        put(w, 72, CONTROL_MAGIC)
        put(w, 256, 1)
        put(w, 264, 5)
        put(w, 272, BUILD_WORD)
        put(w, 8, 1)
        put(w, 16, 0)
        return 0
    if get(w, 72) != CONTROL_MAGIC:
        return bad(w, 16)
    if event == 1:
        if stage != 1 or get(w, 16) != 0:
            return bad(w, 16)
        put(w, BUILD + 0, 0)
        return request(w, 2, 1)
    if event != 2:
        return bad(w, 16)
    result = get(w, 24)
    if stage == 2:
        if get(w, 16) != 1 or result != 0:
            return failed_result(w, result)
        put(w, BUILD + 0, 1)
        return request(w, 3, 2)
    if stage == 3:
        if get(w, 16) != 2 or result != 0:
            return failed_result(w, result)
        if get(w, BUILD + 24) != 1:
            return bad(w, 16)
        row = get(w, 32)
        name_at = get(w, BUILD + 4096)
        name_size = get(w, BUILD + 4104)
        if name_size != get(w, row + 24):
            return bad(w, 16)
        if same(s, name_at, w, get(w, row + 16), name_size) == 0:
            return bad(w, 16)
        put(w, 48, get(w, BUILD + 4112))
        put(w, 56, get(w, BUILD + 4120))
        return request(w, 4, 4)
    if stage == 4:
        if get(w, 16) != 4 or result != 32:
            return bad(w, 18)
        row = get(w, 32)
        if same_digest(w, 512, get(w, row + 56)) == 0:
            return bad(w, 16)
        put(w, BUILD + 0, 2)
        return request(w, 5, 2)
    if stage == 5:
        if get(w, 16) != 2 or result != 1:
            return failed_result(w, result)
        return request(w, 6, 3)
    if stage == 6:
        if get(w, 16) != 3:
            return bad(w, 16)
        put(w, 40, result)
        put(w, BUILD + 72, result)
        put(w, BUILD + 0, 3)
        return request(w, 7, 2)
    if stage == 7:
        if get(w, 16) != 2 or result != 0:
            return failed_result(w, result)
        put(w, BUILD + 0, 2)
        return request(w, 8, 2)
    if stage == 8:
        if get(w, 16) != 2 or result != 3:
            return failed_result(w, result)
        if get(w, BUILD + 16) != 7 or get(w, BUILD + 32) != 1:
            return bad(w, 16)
        return request(w, 9, 5)
    if stage == 9:
        if get(w, 16) != 5 or result != 32:
            return bad(w, 18)
        return request(w, 10, 6)
    if stage == 10:
        if get(w, 16) != 6 or result != 32:
            return bad(w, 18)
        return finish(s, o, w)
    return bad(w, 16)

def request(w:mutbuf, stage:u64, action:u64) -> u32:
    put(w, 8, stage)
    put(w, 16, action)
    put(w, 80, get(w, 80) + 1)
    return 0

def failed_result(w:mutbuf, result:u64) -> u32:
    if result >= 16 and result <= 19:
        return bad(w, result)
    return bad(w, 16)

def bad(w:mutbuf, code:u64) -> u32:
    put(w, 8, 255)
    put(w, 16, 0)
    return code

def find_candidate(s:readbuf, at:u64, n:u64, w:mutbuf) -> u64:
    i = 0
    while i < 55:
        row = 1032 + i * 64
        if n == get(w, row + 8):
            if same(s, at, w, get(w, row), n) == 1:
                return row
        i = i + 1
    return 0

def same(s:readbuf, at:u64, w:mutbuf, other:u64, n:u64) -> u64:
    if at > length(s) or n > length(s) - at:
        return 0
    if other > CONTROL_BYTES or n > CONTROL_BYTES - other:
        return 0
    i = 0
    while i < n:
        if byte(s, at + i) != byte(w, other + i):
            return 0
        i = i + 1
    return 1

def same_digest(w:mutbuf, actual:u64, expected:u64) -> u64:
    if expected > CONTROL_BYTES or 32 > CONTROL_BYTES - expected:
        return 0
    i = 0
    difference = 0
    while i < 32:
        difference = difference | (byte(w, actual + i) ^ byte(w, expected + i))
        i = i + 1
    if difference != 0:
        return 0
    return 1

def finish(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 32)
    if valid_row(row) == 0:
        return bad(w, 16)
    source_at = get(w, 48)
    source_size = get(w, 56)
    image_size = get(w, 40)
    if source_at > length(s) or source_size > length(s) - source_at:
        return bad(w, 16)
    if source_size == 0 or source_size > 1048576 or image_size == 0 or image_size > 1048576:
        return bad(w, 18)
    name_size = get(w, row + 24)
    protocol_size = get(w, row + 40)
    manifest_size = MANIFEST_FIXED_BYTES + protocol_size * 2
    need = 24 + 72 + name_size + source_size + protocol_size + 10 + image_size + 13 + manifest_size
    if need > 67108864 or need > length(o):
        return bad(w, 17)
    write(o, 0, BUNDLE_MAGIC, 8)
    write(o, 8, 3, 8)
    write(o, 16, 0, 8)
    at = entry(o, 24, name_size, source_size)
    at = copy_work(w, get(w, row + 16), o, at, name_size)
    at = copy_source(s, source_at, o, at, source_size)
    at = entry(o, at, protocol_size + 10, image_size)
    at = copy_work(w, get(w, row + 32), o, at, protocol_size)
    IMAGE_NAME_SUFFIX
    at = copy_work(w, BUILD + 65536, o, at, image_size)
    at = entry(o, at, 13, manifest_size)
    MANIFEST_NAME
    at = manifest(o, at, w, row)
    if at != need:
        return bad(w, 16)
    put(w, 64, at)
    return request(w, 11, 7)

def valid_row(row:u64) -> u64:
    i = 0
    while i < 55:
        if row == 1032 + i * 64:
            return 1
        i = i + 1
    return 0

def entry(o:mutbuf, at:u64, name_size:u64, size:u64) -> u64:
    write(o, at, name_size, 8)
    write(o, at + 8, 256, 8)
    write(o, at + 16, size, 8)
    return at + 24

def copy_source(s:readbuf, source:u64, o:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, at + i, byte(s, source + i))
        i = i + 1
    return at + n

def copy_work(w:mutbuf, source:u64, o:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, at + i, byte(w, source + i))
        i = i + 1
    return at + n

def hex_digest(o:mutbuf, at:u64, w:mutbuf, source:u64) -> u64:
    i = 0
    while i < 32:
        value = byte(w, source + i)
        store(o, at + i * 2, hex_digit(value >> 4))
        store(o, at + i * 2 + 1, hex_digit(value & 15))
        i = i + 1
    return at + 64

def hex_digit(n:u64) -> u64:
    if n < 10:
        return 48 + n
    return 87 + n

def uint(s:readbuf, at:u64, n:u64) -> u64:
    value = 0
    i = 0
    while i < n:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def write(o:mutbuf, at:u64, value:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return at + n
'''


def catalog():
    value = json.loads(CATALOG_PATH.read_bytes())
    if value['schema'] != 'hepta.hia.candidate-build-catalog.v1':
        raise ValueError('unknown candidate catalog')
    rows = value['rows']
    if len(rows) != 55 or len({row['candidate'] for row in rows}) != 55:
        raise ValueError('the complete original generic catalog is required')
    for row in rows:
        if set(row) != {'candidate', 'source_name', 'protocol', 'schema_version', 'source_sha256'}:
            raise ValueError('unexpected candidate field')
        if len(bytes.fromhex(row['source_sha256'])) != 32 or row['source_sha256'] != row['source_sha256'].lower():
            raise ValueError('candidate source identity must be one exact SHA-256')
        actual_source = (ROOT/'examples/hia_bootstrap'/row['source_name']).read_bytes()
        if sha256(actual_source).hexdigest() != row['source_sha256']:
            raise ValueError('catalog source differs from its frozen native build input')
        if row['schema_version'] not in (1, 2):
            raise ValueError('unknown original schema version')
        for key in ('candidate', 'source_name', 'protocol'):
            raw = row[key].encode('ascii')
            if not raw or any(not (97 <= v <= 122 or 48 <= v <= 57 or v in (45, 46, 95)) for v in raw):
                raise ValueError('catalog names must have their original ASCII spelling')
    return rows


def literal_writes(value, *, indent='    '):
    raw = value.encode('ascii')
    return '\n'.join(f'{indent}at = write(o, at, {int.from_bytes(raw[i:i+8], "little")}, {len(raw[i:i+8])})'
                     for i in range(0, len(raw), 8))


def policy_source():
    rows = catalog()
    table = bytearray(struct.pack('<Q', len(rows)) + bytes(64 * len(rows)))
    for index, row in enumerate(rows):
        values = []
        for key in ('candidate', 'source_name', 'protocol'):
            raw = row[key].encode('ascii')
            values.extend((1024 + len(table), len(raw)))
            table += raw
        values.append(row['schema_version'])
        values.append(1024 + len(table))
        table += bytes.fromhex(row['source_sha256'])
        struct.pack_into('<8Q', table, 8 + 64 * index, *values)
    table += bytes((-len(table)) % 8)
    if 1024 + len(table) > CONTROL_BYTES:
        raise ValueError('catalog exceeds explicit private control storage')
    chunks = []
    for chunk_index, start in enumerate(range(0, len(table), 512)):
        body = [f'def table_{chunk_index}(w:mutbuf) -> u64:']
        for at in range(start, min(start + 512, len(table)), 8):
            body.append(f'    put(w, {1024 + at}, {int.from_bytes(table[at:at+8], "little")})')
        body.append('    return 0')
        chunks.append('\n'.join(body))
    init = ['def initialize_catalog(w:mutbuf) -> u64:']
    init += [f'    table_{i}(w)' for i in range(len(chunks))]
    init += ['    return 0']
    empty = {'compiler_sha256': '0' * 64, 'image_path': '.image.bin',
             'image_sha256': '0' * 64, 'schema': 'hepta.hia.-native.v1',
             'source_sha256': '0' * 64}
    fixed_size = len((json.dumps(empty, indent=2, sort_keys=True) + '\n').encode())
    manifest = ['def manifest(o:mutbuf, at:u64, w:mutbuf, row:u64) -> u64:']
    manifest += [literal_writes('{\n  "compiler_sha256": "'), '    at = hex_digest(o, at, w, 576)',
                 literal_writes('",\n  "image_path": "'),
                 '    at = copy_work(w, get(w, row + 32), o, at, get(w, row + 40))',
                 literal_writes('.image.bin",\n  "image_sha256": "'),
                 '    at = hex_digest(o, at, w, 544)',
                 literal_writes('",\n  "schema": "hepta.hia.'),
                 '    at = copy_work(w, get(w, row + 32), o, at, get(w, row + 40))',
                 literal_writes('-native.v'),
                 '    store(o, at, 48 + get(w, row + 48))', '    at = at + 1',
                 literal_writes('",\n  "source_sha256": "'),
                 '    at = hex_digest(o, at, w, 512)', literal_writes('"\n}\n'), '    return at']
    source = POLICY.replace('IMAGE_NAME_SUFFIX', literal_writes('.image.bin').lstrip())
    source = source.replace('MANIFEST_NAME', literal_writes('manifest.json').lstrip())
    values = {'WORK_BYTES': WORK_BYTES, 'CONTROL_BYTES': CONTROL_BYTES,
              'CONTROL_MAGIC': CONTROL_MAGIC, 'BUNDLE_MAGIC': BUNDLE_MAGIC,
              'MANIFEST_FIXED_BYTES': fixed_size,
              'BUILD_WORD': int.from_bytes(b'build', 'little'), 'BUILD': CONTROL_BYTES}
    for key in sorted(values, key=len, reverse=True):
        source = source.replace(key, str(values[key]))
    return source + '\n' + '\n\n'.join(['\n'.join(init), *chunks, '\n'.join(manifest)]) + '\n'


def template():
    asm = (ROOT / 'tools/hia_candidate_build_syscalls.S').read_text()
    asm = '\n'.join(f'.equ {key},{value}' for key, value in LAYOUT.items()) + '\n' + asm
    with tempfile.TemporaryDirectory(prefix='hia-candidate-build-template-') as directory:
        directory = Path(directory)
        source, obj, binary = directory/'adapter.S', directory/'adapter.o', directory/'adapter.bin'
        source.write_text(asm)
        subprocess.run(['as', '--64', str(source), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(binary)], check=True, capture_output=True)
        names = {name: int(address, 16) for address, _, name in
                 (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('unresolved candidate-build syscall relocation')
        code = binary.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    holes = {key: 176 + names[key] for key in
             ('policy_hole', 'source_policy_hole', 'compiler_hole', 'sha_hole',
              'compiler_data_hole', 'compiler_size_hole')}
    return header + code, holes


def packer_source():
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 44 or length(s) > {40 + 4 * IMAGE_LIMIT}:
        return 4294967295
    if uint(s, 0, 8) != {PACK_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    source_policy = uint(s, 16, 8)
    compiler = uint(s, 24, 8)
    sha = uint(s, 32, 8)
    if policy == 0 or source_policy == 0 or compiler == 0 or sha == 0:
        return 4294967295
    if policy > 1048576 or source_policy > 1048576 or compiler > 1048576 or sha > 1048576:
        return 4294967295
    payload = policy + source_policy + compiler + sha
    if length(s) != 40 + payload:
        return 4294967295
    size = {len(prefix)} + payload
    if size > 67108864 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        raw = prefix[at:at+8]
        source += f'    write(o, {at}, {int.from_bytes(raw, "little")}, {len(raw)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    offsets = {'policy_hole': str(len(prefix)),
               'source_policy_hole': f'{len(prefix)} + policy',
               'compiler_hole': f'{len(prefix)} + policy + source_policy',
               'compiler_data_hole': f'{len(prefix)} + policy + source_policy',
               'sha_hole': f'{len(prefix)} + policy + source_policy + compiler'}
    for key, offset in offsets.items():
        at = holes[key]
        source += f'    write(o, {at}, {offset} - {at + 4}, 4)\n'
    source += f'    write(o, {holes["compiler_size_hole"]}, compiler, 8)\n'
    source += f'    copy_source(s, 40, o, {len(prefix)}, payload)\n    return size\n'
    for name, following in [('copy_source', 'copy_work'), ('uint', 'get')]:
        start = POLICY.index('\ndef ' + name + '(')
        end = POLICY.index('\ndef ' + following + '(', start)
        source += POLICY[start:end]
    source += POLICY[POLICY.index('\ndef write('):]
    return source


def main():
    for name, source in (('candidate_build_policy', policy_source()),
                         ('candidate_build_packer', packer_source())):
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
