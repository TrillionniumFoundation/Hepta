"""Author the HIA packer for the checked, byte-preserving patch-result CLI.

The literal ISA owns descriptors, bounded memory and four calls. Payload
parsing, edits, complete diagnostics and both Core decisions remain HIA.
"""
import ast
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_core_json_cli import source_program as helper_source

MAGIC = int.from_bytes(b'HIARCLI1', 'little')
EXTRACT_MAGIC = int.from_bytes(b'HIAPAT01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAPAR01', 'little')
IMAGE_LIMIT = 1 << 20
BUNDLE_LIMIT = 2 * IMAGE_LIMIT + 4096
WIRE_LIMIT = 2 * (8 << 20) + 3
JSON_LIMIT = 8 << 20
RESULT_LIMIT = 32 + 2 * JSON_LIMIT
OUTPUT_OFFSET = (WIRE_LIMIT + 1 + 4095) & ~4095
OUTPUT_BYTES = 64 << 20
SCRATCH_OFFSET = OUTPUT_OFFSET + OUTPUT_BYTES
PATCH_SCRATCH = 64 << 20
CORE_STATE = 64 << 20
CORE_ARENA = 32 << 20
SCRATCH_BYTES = max(PATCH_SCRATCH, CORE_STATE + CORE_ARENA)
MAPPING_BYTES = SCRATCH_OFFSET + SCRATCH_BYTES


def template():
    code = bytearray(); labels = {}; branches = []; holes = {}
    def emit(value): code.extend(bytes.fromhex(value))
    def word(value): code.extend(struct.pack('<I', value))
    def label(name): labels[name] = len(code)
    def branch(op, target): emit(op); branches.append((len(code), target)); word(0)
    def call(name): emit('e8'); holes[name] = len(code); word(0)
    def pointer(op, offset): emit(op); word(offset)
    def clear(offset, size):
        pointer('49 8d bc 24', offset)
        emit('31 c0 b9'); word(size); emit('fc f3 aa')
    def refuse(value, target): emit('3d'); word(value); branch('0f 84', target)
    def equals(offset, value):
        emit('49 ba'); code.extend(struct.pack('<Q', value))
        pointer('4d 39 94 24', offset); branch('0f 85', 'invalid')
    def patch(mode, name):
        # No metadata from a previous invocation survives into this kernel call.
        clear(OUTPUT_OFFSET, OUTPUT_BYTES + PATCH_SCRATCH)
        emit('4c 89 e7 4c 89 ee')  # original envelope, original wire length
        pointer('49 8d 94 24', OUTPUT_OFFSET); emit('b9'); word(OUTPUT_BYTES)
        pointer('4d 8d 84 24', SCRATCH_OFFSET); emit('41 b9'); word(PATCH_SCRATCH)
        emit('49 c7 00'); word(mode)
        if mode == 2:
            emit('4d 89 78 08')  # w[8] = declared schema, callee-saved r15
        call(name)
        refuse(0xfffffffe, 'space'); refuse(0xfffffffd, 'io')
        emit('83 f8 20'); branch('0f 86', 'invalid')
        emit('3d'); word(JSON_LIMIT + 32 if mode == 0 else RESULT_LIMIT)
        branch('0f 87', 'invalid')
        if mode == 0:
            emit('41 89 c6 49 83 ee 20')  # r14 = extracted Core length
            equals(OUTPUT_OFFSET, EXTRACT_MAGIC)
            for offset in (8, 16, 24): equals(OUTPUT_OFFSET + offset, 0)
        else:
            # The original wire is no longer needed. Preserve the full extent
            # in r13 through candidate admission; r14 holds only candidate JSON.
            emit('41 89 c5')
            equals(OUTPUT_OFFSET, RESULT_MAGIC)
            equals(OUTPUT_OFFSET + 24, 0)
            pointer('4d 8b b4 24', OUTPUT_OFFSET + 8)
            emit('49 83 fe 02'); branch('0f 82', 'invalid')
            emit('49 81 fe'); word(JSON_LIMIT); branch('0f 87', 'invalid')
            pointer('4d 8b 94 24', OUTPUT_OFFSET + 16)
            emit('49 83 fa 02'); branch('0f 82', 'invalid')
            emit('49 81 fa'); word(JSON_LIMIT); branch('0f 87', 'invalid')
            # Both lengths are independently bounded before addition, so a
            # hostile header cannot wrap the sum into the returned u32 extent.
            emit('4d 01 f2 49 83 c2 20 4d 39 ea')
            branch('0f 85', 'invalid')
    def admission(name):
        clear(SCRATCH_OFFSET, CORE_STATE + CORE_ARENA)
        pointer('49 8d bc 24', OUTPUT_OFFSET + 32); emit('4c 89 f6')
        pointer('49 8d 94 24', SCRATCH_OFFSET); emit('b9'); word(CORE_STATE)
        pointer('4d 8d 84 24', SCRATCH_OFFSET + CORE_STATE)
        emit('41 b9'); word(CORE_ARENA); call(name)
        refuse(0xfffffffe, 'space'); refuse(0xfffffffd, 'io')
        emit('85 c0'); branch('0f 85', 'invalid')

    # Exactly one schema argument. Check characters in order, never inspect a
    # byte beyond an already encountered NUL. No environment selection exists.
    emit('48 83 3c 24 02'); branch('0f 85', 'usage')
    emit('48 8b 44 24 10 80 38 76'); branch('0f 85', 'usage')
    emit('44 0f b6 78 01 41 83 ff 31'); branch('0f 82', 'usage')
    emit('41 83 ff 32'); branch('0f 87', 'usage')
    emit('80 78 02 00'); branch('0f 85', 'usage')
    emit('41 83 ef 30')  # r15 = 1 or 2, retained across mmap and HIA calls
    emit('31 ff be'); word(MAPPING_BYTES)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff'
         ' 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io'); emit('49 89 c4 45 31 ed')
    label('read')
    emit('31 c0 31 ff 4b 8d 34 2c ba'); word(WIRE_LIMIT + 1)
    emit('4c 29 ea 0f 05 48 83 f8 fc'); branch('0f 84', 'read')
    emit('48 85 c0'); branch('0f 88', 'io'); branch('0f 84', 'extract')
    emit('49 01 c5 49 81 fd'); word(WIRE_LIMIT); branch('0f 87', 'space')
    branch('e9', 'read')
    label('extract'); patch(0, 'extract'); admission('base_admission')
    patch(2, 'result'); admission('candidate_admission')
    emit('4d 89 ee')  # all four calls passed: write the whole original frame
    pointer('4d 8d bc 24', OUTPUT_OFFSET)
    label('write'); emit('4d 85 f6'); branch('0f 84', 'success')
    emit('b8 01 00 00 00 bf 01 00 00 00 4c 89 fe 4c 89 f2'
         ' 0f 05 48 83 f8 fc'); branch('0f 84', 'write')
    emit('48 85 c0'); branch('0f 8e', 'io')
    emit('49 01 c7 49 29 c6'); branch('e9', 'write')
    for name, status in (('success', 0), ('invalid', 2), ('space', 3), ('io', 4), ('usage', 64)):
        label(name); emit('bf'); word(status); branch('e9', 'exit')
    label('exit'); emit('b8 3c 00 00 00 0f 05 0f 0b')
    for offset, target in branches: struct.pack_into('<i', code, offset, labels[target] - offset - 4)
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    assert len(header) == 176
    return header + code, {name: 176 + offset for name, offset in holes.items()}


def source_program():
    prefix, holes = template()
    text = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or length(s) > {BUNDLE_LIMIT} or read_word(s, 0) != {MAGIC}:
        return 4294967295
    patch = read_word(s, 8)
    admission = read_word(s, 16)
    if patch == 0 or patch > {IMAGE_LIMIT} or admission == 0 or admission > {IMAGE_LIMIT}:
        return 4294967295
    if length(s) != 24 + patch + admission:
        return 4294967295
    size = {len(prefix)} + patch + admission
    if size > {BUNDLE_LIMIT} or length(o) < size:
        return 4294967294
'''
    for offset in range(0, len(prefix), 8):
        chunk = prefix[offset:offset + 8]
        if len(chunk) == 8: text += f'    put_word(o, {offset}, {int.from_bytes(chunk, "little")})\n'
        else:
            for j, value in enumerate(chunk): text += f'    store(o, {offset + j}, {value})\n'
    text += '    put_word(o, 96, size)\n    put_word(o, 104, size)\n'
    for name in ('extract', 'result'):
        text += f'    put_four(o, {holes[name]}, {len(prefix) - holes[name] - 4})\n'
    for name in ('base_admission', 'candidate_admission'):
        text += f'    put_four(o, {holes[name]}, {len(prefix) - holes[name] - 4} + patch)\n'
    text += f'''    i = 24
    while i < length(s):
        store(o, {len(prefix)} + i - 24, byte(s, i))
        i = i + 1
    return size
'''
    helpers = helper_source()
    return text + helpers[helpers.index('\ndef read_word('):]


def document():
    nodes = ast.parse(source_program()).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes); functions = []
    for node in nodes:
        b = Builder(node, names, signatures, total); b.statements(node.body)
        functions.append({'name': names[node.name], 'params': [b.param(v) for v in b.params],
            'returns': [b.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': b.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'core_patch_result_cli_packer', 'functions': functions})


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_patch_result_cli_packer.hepta'
    path.write_text(render_assembly(document())); print(path.name, path.stat().st_size)
