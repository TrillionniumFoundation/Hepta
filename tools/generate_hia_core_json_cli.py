"""Author a HIA ELF packer for the native JSON frontend/compiler pipeline.

Only this authoring aid lays out the fixed syscall adapter's literal bytes.
The actual HIA packer writes headers, relocates both calls and copies the two
qualified flat images. The resulting executable has no host-language driver,
linker, interpreter or payload parser. This is a bounded filter, not the complete
production CLI or a sandbox for untrusted machine images.
"""
from __future__ import annotations
import ast
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIAJCLI1', 'little')
LIMIT = 1 << 20
WIRE_LIMIT = 8 << 20
OUTPUT_OFFSET = WIRE_LIMIT + 4096
OUTPUT_BYTES = 16 << 20
ARENA_OFFSET = OUTPUT_OFFSET + OUTPUT_BYTES
ARENA_BYTES = (64 << 20) + 4096
MAPPING_BYTES = ARENA_OFFSET + ARENA_BYTES


def template():
    """Fixed x86 syscall entry; relative labels resolved only while authoring.

    The two image-call displacements and selected frontend profile are holes
    patched by the HIA packer at execution, never a host runtime linker.
    """
    code, labels, branches, holes = bytearray(), {}, [], {}
    def emit(hexadecimal): code.extend(bytes.fromhex(hexadecimal))
    def word(value): code.extend(struct.pack('<I', value))
    def label(name): labels[name] = len(code)
    def branch(op, target):
        emit(op); branches.append((len(code), target)); word(0)
    def hole(name): holes[name] = len(code); word(0)

    emit('48 83 3c 24 01')                         # argc == 1
    branch('0f 85', 'usage')
    emit('31 ff be'); word(MAPPING_BYTES)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff'
         ' 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io')                         # mmap failure
    emit('49 89 c4 45 31 ed')                     # r12=map, r13=length
    label('read')
    emit('31 c0 31 ff 4b 8d 34 2c ba'); word(WIRE_LIMIT + 1)
    emit('4c 29 ea 0f 05 48 83 f8 fc')            # EINTR
    branch('0f 84', 'read')
    emit('48 85 c0')
    branch('0f 88', 'io')
    branch('0f 84', 'frontend')
    emit('49 01 c5 49 81 fd'); word(WIRE_LIMIT)
    branch('0f 87', 'space')
    branch('e9', 'read')
    label('frontend')
    emit('4c 89 e7 4c 89 ee 49 8d 94 24'); word(OUTPUT_OFFSET)
    emit('b9'); word(OUTPUT_BYTES)
    emit('4d 8d 84 24'); word(ARENA_OFFSET)
    emit('41 b9'); word(ARENA_BYTES)
    emit('49 c7 40 30'); word(1 << 20)             # maximum nodes
    emit('49 c7 40 38'); word(128)                 # maximum depth
    emit('41 c7 40 28'); hole('profile')
    emit('e8'); hole('frontend')
    emit('83 f8 fe'); branch('0f 84', 'space')
    emit('83 f8 fa'); branch('0f 84', 'space')
    emit('83 f8 fd'); branch('0f 84', 'io')
    emit('85 c0'); branch('0f 84', 'invalid')
    emit('3d'); word(LIMIT); branch('0f 87', 'invalid')
    emit('41 89 c5')                              # preserve assembly length
    # Decoder arena is not fresh compiler scratch. Explicitly clear exactly
    # its 1-MiB view before reuse, preserving the compiler's initialization ABI.
    emit('49 8d bc 24'); word(ARENA_OFFSET)
    emit('31 c0 b9'); word(LIMIT)
    emit('fc f3 aa')                              # cld; rep stosb
    emit('49 8d bc 24'); word(OUTPUT_OFFSET)
    emit('4c 89 ee 4c 89 e2 b9'); word(LIMIT)
    emit('4d 8d 84 24'); word(ARENA_OFFSET)
    emit('41 b9'); word(LIMIT)
    emit('e8'); hole('compiler')
    emit('83 f8 fe'); branch('0f 84', 'space')
    emit('3d'); word(LIMIT); branch('0f 87', 'invalid')
    emit('41 89 c6 4d 89 e7')                     # length, output pointer
    label('write')
    emit('4d 85 f6'); branch('0f 84', 'success')
    emit('b8 01 00 00 00 bf 01 00 00 00 4c 89 fe 4c 89 f2'
         ' 0f 05 48 83 f8 fc')
    branch('0f 84', 'write')
    emit('48 85 c0'); branch('0f 8e', 'io')
    emit('49 01 c7 49 29 c6'); branch('e9', 'write')
    for name, status in (('success', 0), ('invalid', 2), ('space', 3), ('io', 4), ('usage', 64)):
        label(name); emit('bf'); word(status); branch('e9', 'exit')
    label('exit'); emit('b8 3c 00 00 00 0f 05 0f 0b')
    for offset, target in branches:
        struct.pack_into('<i', code, offset, labels[target] - offset - 4)
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    assert len(header) == 176
    return header + code, {key: 176 + value for key, value in holes.items()}


def source_program():
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 1048576:
        return 4294967295
    if read_word(s, 0) != {MAGIC}:
        return 4294967295
    frontend = read_word(s, 8)
    compiler = read_word(s, 16)
    profile = read_word(s, 24)
    if frontend == 0 or compiler == 0 or frontend > 1048576 or compiler > 1048576 or profile > 1:
        return 4294967295
    if length(s) != 32 + frontend + compiler:
        return 4294967295
    size = {len(prefix)} + frontend + compiler
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for offset in range(0, len(prefix), 8):
        chunk = prefix[offset:offset+8]
        if len(chunk) == 8:
            source += f'    put_word(o, {offset}, {int.from_bytes(chunk, "little")})\n'
        else:
            for j, value in enumerate(chunk):
                source += f'    store(o, {offset+j}, {value})\n'
    source += f'''    put_word(o, 96, size)
    put_word(o, 104, size)
    put_four(o, {holes['profile']}, profile)
    put_four(o, {holes['frontend']}, {len(prefix)-holes['frontend']-4})
    put_four(o, {holes['compiler']}, {len(prefix)-holes['compiler']-4} + frontend)
    i = 32
    while i < length(s):
        store(o, {len(prefix)} + i - 32, byte(s, i))
        i = i + 1
    return size

def read_word(s:readbuf, at:u64) -> u64:
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

def put_four(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 4:
        store(o, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''
    return source


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f'+str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read','write','trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'core_json_cli_packer', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_json_cli_packer.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
