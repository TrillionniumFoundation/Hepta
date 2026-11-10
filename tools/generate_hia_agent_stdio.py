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
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_core_json_cli import (
    LIMIT, WIRE_LIMIT, OUTPUT_OFFSET, OUTPUT_BYTES, ARENA_OFFSET, ARENA_BYTES, MAPPING_BYTES,
)

MAGIC = int.from_bytes(b'HIAAGNT1', 'little')
MODE_OFFSET = WIRE_LIMIT + 16
ROOT = Path(__file__).resolve().parents[1]


def capabilities_bytes():
    return (json.dumps({
        'schema': 'hepta.hia.agent-stdio.v1', 'implementation': 'hia-native',
        'operations': ['capabilities', 'verify', 'compile', 'render-assembly'], 'build_profile': 0,
        'input': 'primitive-v8-Core-JSON', 'input_bytes_max': WIRE_LIMIT,
        'compiler_bytes_max': LIMIT, 'program_nodes_max': 1048576, 'json_depth_max': 128,
        'target': 'linux-x86_64', 'runtime_python_required': False,
        'edit_and_persistence_implemented': False, 'whole_native_delivery_qualified': False,
    }, sort_keys=True, separators=(',', ':')) + '\n').encode()


VERIFIED = b'{"schema":"hepta.hia.agent-stdio.v1","status":"verified","machine_code_published":false}\n'


def writes(payload):
    text = ''
    for at in range(0, len(payload), 8):
        chunk = payload[at:at+8]
        if len(chunk) == 8:
            text += f'    put_word(o, {at}, {int.from_bytes(chunk, "little")})\n'
        else:
            for j, byte in enumerate(chunk):
                text += f'    store(o, {at+j}, {byte})\n'
    return text


def dispatcher_source():
    cap = capabilities_bytes()
    profile_at = cap.index(b'"build_profile":0') + len(b'"build_profile":')
    source = '''def dispatch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 32 or length(w) < 48:
        return 4294967293
    phase = read_word(w, 0)
    profile = read_word(w, 40)
    if phase > 1 or profile > 2:
        return 4294967293
    if matches(s, 6, 133476589827702) == 1:
        if phase == 0:
            return 1
        return verified(o)
    if phase != 0:
        return 4294967295
    if matches(s, 7, 28548189479661411) == 1:
        return 2
    if matches(s, 15, 7002378775433209202) == 1:
        if byte(s, 8) == 115 and byte(s, 9) == 115 and byte(s, 10) == 101 and byte(s, 11) == 109 and byte(s, 12) == 98 and byte(s, 13) == 108 and byte(s, 14) == 121:
            return 3
    if matches(s, 12, 7809644627822477667) == 1:
        if byte(s, 8) == 116 and byte(s, 9) == 105 and byte(s, 10) == 101 and byte(s, 11) == 115:
            return capabilities(o, profile)
    return 4294967295

def capabilities(o:mutbuf, profile:u64) -> u32:
'''
    # Compare only the exact declared command bytes, with no prefix matching.
    source = source.replace('133476589827702', str(int.from_bytes(b'verify', 'little')))
    source = source.replace('28548189479661411', str(int.from_bytes(b'compile', 'little')))
    source = source.replace('7809644627822477667', str(int.from_bytes(b'capabili', 'little')))
    source += f'    if length(o) < {len(cap)}:\n        return 4294967294\n'
    source += writes(cap)
    source += f'    store(o, {profile_at}, profile + 48)\n    return {len(cap)}\n'
    source += f'\ndef verified(o:mutbuf) -> u32:\n    if length(o) < {len(VERIFIED)}:\n        return 4294967294\n'
    source += writes(VERIFIED) + f'    return {len(VERIFIED)}\n'
    source += '''
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
    return source


def template():
    """Syscall-only adapter; all command decisions come from the HIA image."""
    code, labels, branches, holes = bytearray(), {}, [], {}
    def emit(value): code.extend(bytes.fromhex(value))
    def word(value): code.extend(struct.pack('<I', value))
    def label(name): labels[name] = len(code)
    def branch(op, target):
        emit(op); branches.append((len(code), target)); word(0)
    def hole(name): holes[name] = len(code); word(0)
    def dispatch(name, *, reply=False):
        emit('48 8b 7c 24 10')                 # argv[1], original process stack
        if reply:
            emit('be'); word(6)                # exact already admitted "verify"
        emit('49 8d 94 24'); word(OUTPUT_OFFSET)
        emit('b9'); word(OUTPUT_BYTES)
        emit('4d 8d 84 24'); word(ARENA_OFFSET)
        emit('41 b9'); word(ARENA_BYTES)
        if reply:
            emit('49 c7 00 01 00 00 00')       # private post-verification phase
        emit('49 c7 40 28'); hole('profile_'+name)  # clear all64profile bits
        emit('e8'); hole(name)
    emit('48 83 3c 24 02'); branch('0f 85', 'usage')
    emit('31 ff be'); word(MAPPING_BYTES)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff'
         ' 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io')
    emit('49 89 c4 48 8b 7c 24 10 31 f6')     # map, argv[1], bounded length
    label('argument')
    emit('48 83 fe 20'); branch('0f 83', 'usage')
    emit('80 3c 37 00'); branch('0f 84', 'dispatch')
    emit('48 ff c6'); branch('e9', 'argument')
    label('dispatch'); dispatch('dispatch_initial')
    emit('83 f8 ff'); branch('0f 84', 'usage')
    emit('83 f8 fe'); branch('0f 84', 'space')
    emit('83 f8 01'); branch('0f 84', 'mode')
    emit('83 f8 02'); branch('0f 84', 'mode')
    emit('83 f8 03'); branch('0f 84', 'mode')
    emit('3d'); word(OUTPUT_BYTES); branch('0f 87', 'io')
    emit('85 c0'); branch('0f 84', 'io')
    branch('e9', 'reply_output')
    label('mode')
    emit('41 89 84 24'); word(MODE_OFFSET)      # outside input/compiler output
    emit('45 31 ed')
    label('read')
    emit('31 c0 31 ff 4b 8d 34 2c ba'); word(WIRE_LIMIT+1)
    emit('4c 29 ea 0f 05 48 83 f8 fc'); branch('0f 84', 'read')
    emit('48 85 c0'); branch('0f 88', 'io'); branch('0f 84', 'frontend')
    emit('49 01 c5 49 81 fd'); word(WIRE_LIMIT); branch('0f 87', 'space')
    branch('e9', 'read')
    label('frontend')
    emit('4c 89 e7 4c 89 ee 49 8d 94 24'); word(OUTPUT_OFFSET)
    emit('b9'); word(OUTPUT_BYTES)
    emit('4d 8d 84 24'); word(ARENA_OFFSET)
    emit('41 b9'); word(ARENA_BYTES)
    emit('49 c7 40 30'); word(1048576)
    emit('49 c7 40 38'); word(128)
    emit('41 c7 40 28'); hole('profile_frontend')
    emit('e8'); hole('frontend')
    emit('83 f8 fe'); branch('0f 84', 'space')
    emit('83 f8 fa'); branch('0f 84', 'space')
    emit('83 f8 fd'); branch('0f 84', 'io')
    emit('85 c0'); branch('0f 84', 'invalid')
    emit('3d'); word(LIMIT); branch('0f 87', 'invalid')
    emit('41 89 c5 49 8d bc 24'); word(ARENA_OFFSET)
    emit('31 c0 b9'); word(LIMIT)
    emit('fc f3 aa 49 8d bc 24'); word(OUTPUT_OFFSET)
    emit('4c 89 ee 4c 89 e2 b9'); word(LIMIT)
    emit('4d 8d 84 24'); word(ARENA_OFFSET)
    emit('41 b9'); word(LIMIT)
    emit('e8'); hole('compiler')
    emit('83 f8 fe'); branch('0f 84', 'space')
    emit('85 c0'); branch('0f 84', 'invalid')
    emit('3d'); word(LIMIT); branch('0f 87', 'invalid')
    emit('41 83 bc 24'); word(MODE_OFFSET); emit('01'); branch('0f 84', 'verified')
    emit('41 83 bc 24'); word(MODE_OFFSET); emit('03'); branch('0f 84', 'assembly_output')
    emit('41 89 c6 4d 89 e7'); branch('e9', 'write')
    label('assembly_output')
    emit('44 89 e8'); branch('e9', 'reply_output')  # preserved checked frontend length
    label('verified'); dispatch('dispatch_verified', reply=True)
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
    if length(s) < 40 or length(s) > 1048576:
        return 4294967295
    if read_word(s, 0) != {MAGIC}:
        return 4294967295
    dispatch = read_word(s, 8)
    frontend = read_word(s, 16)
    compiler = read_word(s, 24)
    profile = read_word(s, 32)
    if dispatch == 0 or frontend == 0 or compiler == 0 or dispatch > 1048576 or frontend > 1048576 or compiler > 1048576 or profile > 2:
        return 4294967295
    if length(s) != 40 + dispatch + frontend + compiler:
        return 4294967295
    size = {len(prefix)} + dispatch + frontend + compiler
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    source += writes(prefix)
    source += '    put_word(o, 96, size)\n    put_word(o, 104, size)\n'
    for name in ('profile_dispatch_initial','profile_dispatch_verified','profile_frontend'):
        source += f'    put_four(o, {holes[name]}, profile)\n'
    for name, offset in [('dispatch_initial','0'),('dispatch_verified','0'),
                         ('frontend','dispatch'),('compiler','dispatch + frontend')]:
        source += f'    put_four(o, {holes[name]}, {len(prefix)-holes[name]-4} + {offset})\n'
    source += f'''    i = 40
    while i < length(s):
        store(o, {len(prefix)} + i - 40, byte(s, i))
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
        path=ROOT/'examples/hia_bootstrap'/f'{name}.hiaasm'
        path.write_text(render_assembly(document(source,name)))
        print(path.name,path.stat().st_size)


if __name__ == '__main__':
    main()
