"""Author HIA command dispatch and a three-image native Agent ELF packer.

The literal ISA adapter is platform I/O/ABI glue. HIA selects commands, writes
discovery/verification replies, validates Core and generates/links ELF bytes.
No high-level Hepta frontend or host payload driver is part of the executable.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import opcode_catalog
from hepta.hia_schema import LATEST_CORE_SCHEMA, PRIMITIVE_PROFILES
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_core_json_cli import (
    LIMIT, WIRE_LIMIT, OUTPUT_OFFSET, OUTPUT_BYTES, ARENA_OFFSET, ARENA_BYTES, MAPPING_BYTES,
)

MAGIC = int.from_bytes(b'HIAAGNT2', 'little')
MODE_OFFSET = WIRE_LIMIT + 16
ACTIVE_PROFILE_OFFSET = MODE_OFFSET + 8
OUTPUT_PROFILES = ('flat', 'elf', 'exec', 'portable')
ROOT = Path(__file__).resolve().parents[1]


def capabilities_bytes():
    return (json.dumps({
        'schema': 'hepta.hia.agent-stdio.v1', 'implementation': 'hia-native',
        'operations': ['capabilities', 'verify', 'compile', 'render-assembly', 'assemble', 'check-assembly', 'catalog'], 'build_profile': 0,
        'input': 'primitive-v6/v7/v8-Core-JSON', 'input_bytes_max': WIRE_LIMIT,
        'assembly_input': 'hia-asm.v1', 'assembly_input_bytes_max': LIMIT,
        'compiler_bytes_max': LIMIT, 'program_nodes_max': 1048576, 'json_depth_max': 128,
        'target': 'linux-x86_64', 'runtime_python_required': False,
        'edit_and_persistence_implemented': False, 'whole_native_delivery_qualified': False,
    }, sort_keys=True, separators=(',', ':')) + '\n').encode()


VERIFIED = b'{"schema":"hepta.hia.agent-stdio.v1","status":"verified","machine_code_published":false}\n'


def writes(payload, *, offset=0):
    text = ''
    for i in range(0, len(payload), 8):
        at = offset + i
        chunk = payload[i:i + 8]
        if len(chunk) == 8:
            text += f'    put_word(o, {at}, {int.from_bytes(chunk, "little")})\n'
        else:
            for j, byte in enumerate(chunk):
                text += f'    store(o, {at+j}, {byte})\n'
    return text


def catalog_pieces(document):
    """Split the existing pretty wire at fields and complete instruction rows."""
    split = ('  "instructions": [\n', '    {\n', '  ],\n')
    current = ''
    for line in document.splitlines(keepends=True):
        if current and (line in split or line.startswith('  "')):
            yield current.encode('utf-8')
            current = ''
        current += line
    if current:
        yield current.encode('utf-8')


def catalog_table():
    """Pack the versioned pretty-printed stdio catalog recipes."""
    return pack_catalog_recipes(
        catalog_pieces(json.dumps(opcode_catalog(schema), ensure_ascii=False, indent=2, sort_keys=True) + '\n')
        for schema in PRIMITIVE_PROFILES
    )


def pack_catalog_recipes(documents):
    """Pack versioned wire recipes followed by deduplicated immutable JSON pieces."""
    recipes = []
    pieces = {}
    data = bytearray()
    for document in documents:
        recipe = []
        for piece in document:
            if piece not in pieces:
                pieces[piece] = len(data)
                data.extend(piece)
            recipe.append((pieces[piece], len(piece)))
        recipes.append(recipe)
    header = bytearray(struct.pack('<I', 12 * len(recipes) + 8 * sum(map(len, recipes)) + 4))
    entries = bytearray()
    for recipe in recipes:
        header.extend(struct.pack('<III', len(entries), len(recipe), sum(size for _, size in recipe)))
        for offset, size in recipe:
            entries.extend(struct.pack('<II', offset, size))
    return bytes(header + entries + data)


def catalog_source():
    schemas = tuple(PRIMITIVE_PROFILES)
    # The currently declared catalog ids are consecutive ASCII versions.
    prefix = b'hepta.hia.program.v'
    assert tuple(schema.encode('ascii') for schema in schemas) == tuple(
        prefix + bytes((49 + index,)) for index in range(len(schemas)))
    assert 0 < len(schemas) <= 9
    header_size = 4 + 12 * len(schemas)
    output = [f'''def catalog(s:readbuf, o:mutbuf, version:u64) -> u32:
    total = length(s)
    if version == 0 or version > {len(schemas)} or total < {header_size}:
        return 4294967295
    base = catalog_u32(s, 0)
    if base < {header_size} or base > total:
        return 4294967295
    row = 4 + (version - 1) * 12
    recipe = {header_size} + catalog_u32(s, row)
    count = catalog_u32(s, row + 4)
    size = catalog_u32(s, row + 8)
    if recipe > base or count == 0 or count * 8 > base - recipe or size == 0:
        return 4294967295
    if size > length(o):
        return 4294967294
    out = 0
    i = 0
    while i < count:
        at = recipe + i * 8
        start = base + catalog_u32(s, at)
        n = catalog_u32(s, at + 4)
        if start > total or n > total - start or n > size - out:
            return 4294967295
        j = 0
        while j < n:
            store(o, out + j, byte(s, start + j))
            j = j + 1
        out = out + n
        i = i + 1
    if out != size:
        return 4294967295
    return size

def catalog_u32(s:readbuf, at:u64) -> u64:
    return byte(s, at) | (byte(s, at + 1) << 8) | (byte(s, at + 2) << 16) | (byte(s, at + 3) << 24)
''']
    output.append('\ndef schema_version(s:readbuf, at:u64) -> u64:\n')
    output.append(f'    if length(s) < at or length(s) - at != {len(prefix) + 1}:\n'
                  '        return 0\n')
    for index, byte in enumerate(prefix):
        output.append(f'    if byte(s, at + {index}) != {byte}:\n        return 0\n')
    output.append(f'    digit = byte(s, at + {len(prefix)})\n'
                  f'    if digit < 49 or digit > {48 + len(schemas)}:\n        return 0\n'
                  '    return digit - 48\n')
    return ''.join(output)


def dispatcher_source():
    cap = capabilities_bytes()
    profile_at = cap.index(b'"build_profile":0') + len(b'"build_profile":')
    source = '''def dispatch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 48:
        return 4294967293
    phase = read_word(w, 0)
    profile = read_word(w, 40)
    if profile > 3:
        return 4294967293
    if phase == 5:
        if profile != 3:
            return 4294967293
        return output_profile(s)
    if phase == 6:
        if profile == 3 and matches(s, 12, FILE_OPTION) == 1:
            if byte(s, 8) == 102 and byte(s, 9) == 105 and byte(s, 10) == 108 and byte(s, 11) == 101:
                return 1
        return 4294967295
    if phase > 2:
        if length(w) < 80:
            return 4294967293
        if read_word(w, 72) != 1:
            return 4294967293
        if phase == 3:
            return catalog_argument(s, w)
        if phase == 4 and read_word(w, 56) == 0:
            return catalog(s, o, read_word(w, 64))
        return 4294967295
    if phase == 2:
        if profile == 3:
            return 4294967293
        return emitted_profile(s, profile)
    if length(s) > 32:
        return 4294967293
    if phase == 0:
        if matches(s, 7, CATALOG_NAME) == 1:
            if length(w) < 80:
                return 4294967293
            put_word(w, 56, 0)
            put_word(w, 64, CATALOG_DEFAULT)
            put_word(w, 72, 1)
            return 6
        if length(w) >= 56:
            extras = read_word(w, 48)
            if extras != 0 and (profile != 3 or extras > 3):
                return 4294967295
    if matches(s, 6, 133476589827702) == 1:
        if phase == 0:
            return 1
        return verified(o)
    if matches(s, 14, 8314318707009022051) == 1:
        if byte(s, 8) == 115 and byte(s, 9) == 101 and byte(s, 10) == 109 and byte(s, 11) == 98 and byte(s, 12) == 108 and byte(s, 13) == 121:
            if phase == 0:
                return 5
            return verified(o)
    if phase != 0:
        return 4294967295
    if matches(s, 7, 28548189479661411) == 1:
        return 2
    if matches(s, 15, 7002378775433209202) == 1:
        if byte(s, 8) == 115 and byte(s, 9) == 115 and byte(s, 10) == 101 and byte(s, 11) == 109 and byte(s, 12) == 98 and byte(s, 13) == 108 and byte(s, 14) == 121:
            return 3
    if matches(s, 8, 7308332187135341409) == 1:
        return 4
    if matches(s, 12, 7809644627822477667) == 1:
        if byte(s, 8) == 116 and byte(s, 9) == 105 and byte(s, 10) == 101 and byte(s, 11) == 115:
            if length(w) >= 56 and read_word(w, 48) != 0:
                return 4294967295
            return capabilities(o, profile)
    return 4294967295

def capabilities(o:mutbuf, profile:u64) -> u32:
'''
    # Compare only the exact declared command bytes, with no prefix matching.
    source = source.replace('133476589827702', str(int.from_bytes(b'verify', 'little')))
    source = source.replace('28548189479661411', str(int.from_bytes(b'compile', 'little')))
    source = source.replace('7308332187135341409', str(int.from_bytes(b'assemble', 'little')))
    source = source.replace('7809644627822477667', str(int.from_bytes(b'capabili', 'little')))
    source = source.replace('8314318707009022051', str(int.from_bytes(b'check-as', 'little')))
    source = source.replace('CATALOG_NAME', str(int.from_bytes(b'catalog', 'little')))
    source = source.replace('FILE_OPTION', str(int.from_bytes(b'--input-', 'little')))
    source = source.replace('CATALOG_DEFAULT', str(tuple(PRIMITIVE_PROFILES).index(LATEST_CORE_SCHEMA) + 1))
    source += f'    if length(o) < {len(cap)}:\n        return 4294967294\n'
    source += writes(cap)
    source += f'    store(o, {profile_at}, profile + 48)\n    return {len(cap)}\n'
    source += f'\ndef verified(o:mutbuf) -> u32:\n    if length(o) < {len(VERIFIED)}:\n        return 4294967294\n'
    source += writes(VERIFIED) + f'    return {len(VERIFIED)}\n'
    source += '''
def emitted_profile(s:readbuf, profile:u64) -> u32:
    if length(s) == 0 or length(s) > 1048576:
        return 4294967295
    elf = 0
    if length(s) >= 4:
        if byte(s, 0) == 127 and byte(s, 1) == 69 and byte(s, 2) == 76 and byte(s, 3) == 70:
            elf = 1
    if profile == 0:
        if elf == 1:
            return 4294967295
        return 1
    if length(s) < 64 or elf == 0:
        return 4294967295
    if byte(s, 4) != 2 or byte(s, 5) != 1 or byte(s, 6) != 1:
        return 4294967295
    if byte(s, 16) != profile or byte(s, 17) != 0 or byte(s, 18) != 62 or byte(s, 19) != 0:
        return 4294967295
    return 1

def matches(s:readbuf, size:u64, word:u64) -> u64:
    if length(s) != size:
        return 0
    i = 0
    while i < size and i < 8:
        if byte(s, i) != (word & 255):
            return 0
        word = word >> 8
        i = i + 1
    return 1

def read_word(s:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put_word(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''
    source += '''
def catalog_argument(s:readbuf, w:mutbuf) -> u32:
    if read_word(w, 56) == 1:
        version = schema_version(s, 0)
        if version == 0:
            return 4294967295
        put_word(w, 56, 0)
        put_word(w, 64, version)
        return 1
    size = length(s)
    if size < 3:
        return 4294967295
    spelling = SCHEMA_OPTION
    at = 0
    while at < size and at < 8 and byte(s, at) != 61:
        if byte(s, at) != (spelling & 255):
            return 4294967295
        spelling = spelling >> 8
        at = at + 1
    if at < 3:
        return 4294967295
    if at == size:
        put_word(w, 56, 1)
        return 1
    if byte(s, at) != 61:
        return 4294967295
    selected = schema_version(s, at + 1)
    if selected == 0:
        return 4294967295
    put_word(w, 64, selected)
    return 1
'''.replace('SCHEMA_OPTION', str(int.from_bytes(b'--schema', 'little')))
    prefix = b'--output-profile='
    source += '\ndef output_profile(s:readbuf) -> u32:\n'
    source += f'    if length(s) < {len(prefix) + 3}:\n        return 0\n'
    for at, value in enumerate(prefix):
        source += f'    if byte(s, {at}) != {value}:\n        return 0\n'
    for mode, suffix in enumerate(OUTPUT_PROFILES[:3], 1):
        values = ' and '.join(f'byte(s, {len(prefix) + at}) == {value}'
                              for at, value in enumerate(suffix.encode('ascii')))
        source += f'    if length(s) == {len(prefix) + len(suffix)} and {values}:\n        return {mode}\n'
    source += '    return 0\n'
    return source + '\n' + catalog_source()


def template():
    """Syscall-only adapter; all command decisions come from the HIA image."""
    code, labels, branches, holes = bytearray(), {}, [], {}
    def emit(value): code.extend(bytes.fromhex(value))
    def word(value): code.extend(struct.pack('<I', value))
    def label(name): labels[name] = len(code)
    def branch(op, target):
        emit(op); branches.append((len(code), target)); word(0)
    def hole(name): holes[name] = len(code); word(0)
    def dispatch(name, *, phase=None):
        emit('49 8d 94 24'); word(OUTPUT_OFFSET)
        emit('b9'); word(OUTPUT_BYTES)
        emit('4d 8d 84 24'); word(ARENA_OFFSET)
        emit('41 b9'); word(ARENA_BYTES)
        if phase is not None:
            emit('49 c7 00'); word(phase)
        emit('49 c7 40 28'); hole('profile_'+name)
        emit('e8'); hole(name)
    def command_dispatch(name, *, reply=False):
        emit('48 8b 7c 24 10')                 # argv[1], original process stack
        if reply:
            emit('be'); word(6)                # exact already admitted verification command
            emit('41 83 bc 24'); word(MODE_OFFSET); emit('05')
            emit('b8'); word(14)
            emit('48 0f 44 f0')                 # check-assembly has fourteen bytes
        dispatch(name, phase=1 if reply else None)
    emit('48 83 3c 24 02'); branch('0f 82', 'usage')
    emit('31 ff be'); word(MAPPING_BYTES)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff'
         ' 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io')
    emit('49 89 c4 48 8b 04 24 48 83 e8 02 49 89 84 24') # work[48] = argc - 2
    word(ARENA_OFFSET + 48)
    emit('48 8b 7c 24 10 31 f6')              # argv[1], bounded length
    label('argument')
    emit('48 83 fe 20'); branch('0f 83', 'usage')
    emit('80 3c 37 00'); branch('0f 84', 'dispatch')
    emit('48 ff c6'); branch('e9', 'argument')
    label('dispatch'); command_dispatch('dispatch_initial')
    emit('83 f8 ff'); branch('0f 84', 'usage')
    emit('83 f8 fe'); branch('0f 84', 'space')
    emit('83 f8 01'); branch('0f 84', 'mode')
    emit('83 f8 02'); branch('0f 84', 'mode')
    emit('83 f8 03'); branch('0f 84', 'mode')
    emit('83 f8 04'); branch('0f 84', 'mode')
    emit('83 f8 05'); branch('0f 84', 'mode')
    emit('83 f8 06'); branch('0f 84', 'catalog_arguments')
    label('check_output')
    emit('3d'); word(OUTPUT_BYTES); branch('0f 87', 'io')
    emit('85 c0'); branch('0f 84', 'io')
    branch('e9', 'reply_output')
    label('catalog_arguments')
    emit('bb'); word(2)                       # argv index, not command policy
    label('catalog_next')
    emit('48 3b 1c 24'); branch('0f 83', 'catalog_finish')
    emit('48 8b 7c dc 08 31 f6')              # argv[index], bounded length
    label('catalog_length')
    emit('48 83 fe 40'); branch('0f 83', 'usage')
    emit('80 3c 37 00'); branch('0f 84', 'catalog_dispatch')
    emit('48 ff c6'); branch('e9', 'catalog_length')
    label('catalog_dispatch')
    dispatch('dispatch_catalog_argument', phase=3)
    emit('83 f8 01'); branch('0f 85', 'usage')
    emit('48 ff c3'); branch('e9', 'catalog_next')
    label('catalog_finish')
    emit('48 8d 3d'); hole('catalog_data')      # RIP-relative immutable table
    emit('be'); hole('catalog_size')
    dispatch('dispatch_catalog_finish', phase=4)
    emit('83 f8 ff'); branch('0f 84', 'usage')
    emit('83 f8 fe'); branch('0f 84', 'space')
    branch('e9', 'check_output')
    label('mode')
    emit('41 89 84 24'); word(MODE_OFFSET)      # outside input/compiler output
    emit('41 8b 84 24'); word(ARENA_OFFSET + 40)  # packaged profile from prior dispatch
    emit('83 f8 03'); branch('0f 85', 'save_profile')
    emit('31 c0 48 83 3c 24 02'); branch('0f 84', 'save_profile')
    emit('48 83 3c 24 04'); branch('0f 84', 'save_profile')  # file option without a profile
    emit('48 8b 7c 24 18 31 f6')              # portable profile argument, argv[2]
    label('profile_length')
    emit('48 83 fe 20'); branch('0f 83', 'usage')
    emit('80 3c 37 00'); branch('0f 84', 'profile_dispatch')
    emit('48 ff c6'); branch('e9', 'profile_length')
    label('profile_dispatch')
    dispatch('dispatch_output_profile', phase=5)
    emit('ff c8 83 f8 02'); branch('0f 87', 'usage')
    label('save_profile')
    emit('41 89 84 24'); word(ACTIVE_PROFILE_OFFSET)
    emit('bb'); word(WIRE_LIMIT)               # JSON wire ceiling
    emit('41 83 bc 24'); word(MODE_OFFSET); emit('04'); branch('0f 82', 'select_input')
    emit('bb'); word(LIMIT)                    # exact native assembly ceiling
    label('select_input')
    emit('45 31 ff 48 8b 04 24 48 83 f8 04'); branch('0f 82', 'reading')
    emit('48 8b 7c c4 f8 31 f6')              # argv[argc - 2], exact option marker
    label('file_option_length')
    emit('48 83 fe 0d'); branch('0f 83', 'usage')
    emit('80 3c 37 00'); branch('0f 84', 'file_option_dispatch')
    emit('48 ff c6'); branch('e9', 'file_option_length')
    label('file_option_dispatch')
    dispatch('dispatch_file_argument', phase=6)
    emit('83 f8 01'); branch('0f 85', 'usage')
    emit('48 8b 04 24 48 8b 34 c4')           # argv[argc - 1], supplied filename
    emit('80 3e 00'); branch('0f 84', 'usage')
    label('open_input')
    # Do not block on a FIFO or follow a final symlink before fstat.
    emit('b8 01 01 00 00 bf 9c ff ff ff ba 00 08 0a 00 45 31 d2 0f 05')
    emit('48 83 f8 fc'); branch('0f 84', 'open_input')
    emit('48 85 c0'); branch('0f 88', 'io')
    emit('41 89 c7')                          # file descriptors may include stdin's fd
    label('stat_input')
    emit('b8 05 00 00 00 44 89 ff 4c 89 e6 0f 05')
    emit('48 83 f8 fc'); branch('0f 84', 'stat_input')
    emit('48 85 c0'); branch('0f 88', 'io')
    emit('41 8b 44 24 18 25 00 f0 00 00 3d 00 80 00 00'); branch('0f 85', 'io')
    emit('49 39 5c 24 30'); branch('0f 87', 'space')
    label('reading')
    emit('45 31 ed')
    label('read')
    emit('31 c0 44 89 ff 4b 8d 34 2c 89 da 83 c2 01')
    emit('4c 29 ea 0f 05 48 83 f8 fc'); branch('0f 84', 'read')
    emit('48 85 c0'); branch('0f 88', 'io'); branch('0f 84', 'received')
    emit('49 01 c5 49 39 dd'); branch('0f 87', 'space')
    branch('e9', 'read')
    label('received')
    emit('48 83 3c 24 04'); branch('0f 82', 'input_ready')
    emit('b8 03 00 00 00 44 89 ff 0f 05 48 85 c0'); branch('0f 88', 'io')
    label('input_ready')
    emit('41 83 bc 24'); word(MODE_OFFSET); emit('04'); branch('0f 83', 'assembly')
    label('frontend')
    emit('4c 89 e7 4c 89 ee 49 8d 94 24'); word(OUTPUT_OFFSET)
    emit('b9'); word(OUTPUT_BYTES)
    emit('4d 8d 84 24'); word(ARENA_OFFSET)
    emit('41 b9'); word(ARENA_BYTES)
    emit('49 c7 40 30'); word(1048576)
    emit('49 c7 40 38'); word(128)
    emit('41 8b 84 24'); word(ACTIVE_PROFILE_OFFSET)
    emit('41 89 40 28')                       # frontend receives the admitted profile
    emit('e8'); hole('frontend')
    emit('83 f8 fe'); branch('0f 84', 'space')
    emit('83 f8 fa'); branch('0f 84', 'space')
    emit('83 f8 fd'); branch('0f 84', 'io')
    emit('85 c0'); branch('0f 84', 'invalid')
    emit('3d'); word(LIMIT); branch('0f 87', 'invalid')
    emit('41 89 c5'); branch('e9', 'compiler_input')
    label('assembly')
    # Keep exactly the same disjoint compiler ABI regions. Copy admitted raw
    # assembly into the frontend-output region without parsing or rewriting it.
    emit('4c 89 e6 49 8d bc 24'); word(OUTPUT_OFFSET)
    emit('4c 89 e9 fc f3 a4')
    label('compiler_input')
    emit('49 8d bc 24'); word(ARENA_OFFSET)
    emit('31 c0 b9'); word(LIMIT)
    emit('fc f3 aa 49 8d bc 24'); word(OUTPUT_OFFSET)
    emit('4c 89 ee 4c 89 e2 b9'); word(LIMIT)
    emit('4d 8d 84 24'); word(ARENA_OFFSET)
    emit('41 b9'); word(LIMIT)
    emit('e8'); hole('compiler')
    emit('83 f8 fe'); branch('0f 84', 'space')
    emit('85 c0'); branch('0f 84', 'invalid')
    emit('3d'); word(LIMIT); branch('0f 87', 'invalid')
    emit('41 83 bc 24'); word(MODE_OFFSET); emit('04'); branch('0f 83', 'assembly_profile')
    emit('41 83 bc 24'); word(MODE_OFFSET); emit('01'); branch('0f 84', 'verified')
    emit('41 83 bc 24'); word(MODE_OFFSET); emit('03'); branch('0f 84', 'assembly_output')
    emit('41 89 c6 4d 89 e7'); branch('e9', 'write')
    label('assembly_output')
    emit('44 89 e8'); branch('e9', 'reply_output')  # preserved checked frontend length
    label('assembly_profile')
    # Only a successful native compilation reaches this private HIA phase.
    # It checks the emitted format against the operator's build profile; it
    # never admits submitted machine code or changes module/export metadata.
    emit('41 89 c6 4c 89 e7 4c 89 f6')
    emit('49 8d 94 24'); word(OUTPUT_OFFSET)
    emit('b9'); word(OUTPUT_BYTES)
    emit('4d 8d 84 24'); word(ARENA_OFFSET)
    emit('41 b9'); word(ARENA_BYTES)
    emit('49 c7 00 02 00 00 00')
    emit('41 8b 84 24'); word(ACTIVE_PROFILE_OFFSET)
    emit('49 89 40 28')
    emit('e8'); hole('dispatch_assembly')
    emit('83 f8 01'); branch('0f 85', 'invalid')
    emit('41 83 bc 24'); word(MODE_OFFSET); emit('05'); branch('0f 84', 'verified')
    emit('4d 89 e7'); branch('e9', 'write')
    label('verified'); command_dispatch('dispatch_verified', reply=True)
    emit('3d'); word(OUTPUT_BYTES); branch('0f 87', 'io')
    emit('83 f8 02'); branch('0f 86', 'io')
    label('reply_output')
    emit('41 89 c6 4d 8d bc 24'); word(OUTPUT_OFFSET)
    label('write')
    emit('4d 85 f6'); branch('0f 84', 'success')
    emit('b8 01 00 00 00 bf 01 00 00 00 4c 89 fe 4c 89 f2'
         ' 0f 05 48 83 f8 fc'); branch('0f 84', 'write')
    emit('48 85 c0'); branch('0f 8e', 'io')
    emit('49 01 c7 49 29 c6'); branch('e9', 'write')
    label('success'); emit('31 ff'); branch('e9', 'exit')
    messages = []
    for name, status, category in [('invalid',2,'input_or_semantic'),('space',3,'capacity'),
                                   ('io',4,'io_or_mapping'),('usage',64,'usage')]:
        label(name)
        emit('bb'); word(status)               # preserved exit category
        emit('4c 8d 3d'); branch_at = len(code); word(0)
        branches.append((branch_at, 'message_'+name))
        payload = ('{"schema":"hepta.hia.agent-stdio.v1","status":"rejected",'
                   '"category":"'+category+'"}\n').encode()
        emit('41 be'); word(len(payload)); branch('e9', 'diagnostic')
        messages.append((name,payload))
    label('diagnostic')
    emit('4d 85 f6'); branch('0f 84', 'exit_error')
    emit('b8 01 00 00 00 bf 02 00 00 00 4c 89 fe 4c 89 f2'
         ' 0f 05 48 83 f8 fc'); branch('0f 84', 'diagnostic')
    emit('48 85 c0'); branch('0f 8e', 'exit_error')
    emit('49 01 c7 49 29 c6'); branch('e9', 'diagnostic')
    label('exit_error'); emit('89 df')
    label('exit'); emit('b8 3c 00 00 00 0f 05 0f 0b')
    for name,payload in messages:
        label('message_'+name); code.extend(payload)
    for at,target in branches:
        struct.pack_into('<i', code, at, labels[target]-at-4)
    header = (b'\x7fELF\x02\x01\x01'+bytes(9)
              +struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
              +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
              +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    assert len(header)==176
    return header+code, {key:176+value for key,value in holes.items()}


def packer_source():
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 48 or length(s) > 1048576:
        return 4294967295
    if read_word(s, 0) != {MAGIC}:
        return 4294967295
    dispatch = read_word(s, 8)
    frontend = read_word(s, 16)
    compiler = read_word(s, 24)
    profile = read_word(s, 32)
    catalog = read_word(s, 40)
    if dispatch == 0 or frontend == 0 or compiler == 0 or dispatch > 1048576 or frontend > 1048576 or compiler > 1048576 or profile > 3:
        return 4294967295
    if catalog == 0 or catalog > 1048576 or length(s) != 48 + dispatch + frontend + compiler + catalog:
        return 4294967295
    size = {len(prefix)} + dispatch + frontend + compiler + catalog
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    source += writes(prefix)
    source += '    put_word(o, 96, size)\n    put_word(o, 104, size)\n'
    for name, position in holes.items():
        if name.startswith('profile_'):
            source += f'    put_four(o, {position}, profile)\n'
        elif name == 'catalog_size':
            source += f'    put_four(o, {position}, catalog)\n'
        else:
            offset = {'frontend': 'dispatch', 'compiler': 'dispatch + frontend',
                      'catalog_data': 'dispatch + frontend + compiler'}.get(name, '0')
            source += f'    put_four(o, {position}, {len(prefix)-position-4} + {offset})\n'
    source += f'''    i = 48
    while i < length(s):
        store(o, {len(prefix)} + i - 48, byte(s, i))
        i = i + 1
    return size
'''
    from tools.generate_hia_core_json_cli import source_program
    source += source_program()[source_program().index('\ndef read_word('):]
    return source


def document(source, module):
    nodes = ast.parse(source).body
    names = {node.name:'f'+str(i) for i,node in enumerate(nodes)}
    sigs = {n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total, functions = total_scalar_functions(nodes), []
    for node in nodes:
        builder = Builder(node,names,sigs,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name], 'params':[builder.param(p) for p in builder.params],
                          'returns':[builder.returns], 'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':module,'functions':functions})


def main():
    for name,source in [('agent_stdio_dispatch',dispatcher_source()),('agent_stdio_packer',packer_source())]:
        path=ROOT/'examples/hia_bootstrap'/f'{name}.hepta'
        path.write_text(render_assembly(document(source,name)))
        print(path.name,path.stat().st_size)


if __name__ == '__main__':
    main()
