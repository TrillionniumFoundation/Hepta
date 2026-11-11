"""Author the deterministic numeric x86-64 byte-packing owner in HIA.

The private packet contains admitted register indices and word observations.
Public Python operand admission, label/relocation custody, invocation order and
foreign extension behavior remain separate owners. This source does not claim
a complete standalone backend or authorize retirement of Code.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

COMMANDS = (
    'align', 'mov_rr', 'mov_imm', 'load', 'store', 'lea', 'load_u8', 'store_u8',
    'add', 'sub', 'and_', 'or_', 'xor', 'cmp', 'test', 'alu_imm', 'shift',
    'imul', 'mul', 'imul_full', 'div', 'idiv', 'neg', 'bitnot', 'cqo',
    'set_byte', 'cmov', 'push', 'pop', 'ret', 'leave', 'ud2',
    'jmp_prefix', 'jcc_prefix', 'call_prefix', 'zero_rel32', 'rel32',
)
MAGIC = int.from_bytes(b'HIAX6402', 'little')
ABI = 0xfffffffd
SOURCE = r'''
def machine_encoding(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 64 or length(o) < 80 or length(w) < 8:
        return ABI
    if word(s, 0) != MAGIC:
        return ABI
    command = word(s, 8)
    r = word(s, 16)
    m = word(s, 24)
    value = word(s, 32)
    auxiliary = word(s, 40)
    mode = word(s, 48)
    offset = word(s, 56)
    if valid(command, r, m, value, auxiliary, mode, offset) == 0:
        return ABI
    put(w, 0, 8)
    if command <= 15:
        encode_data(o, w, command, r, m, value, auxiliary, mode, offset)
    elif command <= 27:
        encode_arithmetic(o, w, command, r, m, value, auxiliary, mode, offset)
    else:
        encode_control(o, w, command, r, value, auxiliary)
    n = get(w, 0) - 8
    out_word(o, 0, n)
    return 0

def valid(command:u64, r:u64, m:u64, value:u64, auxiliary:u64, mode:u64, offset:u64) -> u64:
    if command == 0 or command > 37 or r > 15 or m > 15 or mode > 1:
        return 0
    if command == 1:
        return choose(auxiliary == 1 or auxiliary == 16 or auxiliary == 32 or auxiliary == 64, 1, 0)
    if command >= 4 and command <= 8:
        return signed32(value)
    if command == 16:
        if auxiliary > 5 or signed32(value) == 0 or offset > 1:
            return 0
        if offset == 1 and value > 127 and value < 18446744073709551488:
            return 0
        return 1
    if command == 17:
        return choose(auxiliary <= 2 and (mode == 1 or value < 64), 1, 0)
    if command == 26 or command == 27 or command == 34:
        return choose(auxiliary <= 15, 1, 0)
    if command == 37:
        return signed32(value)
    return 1

def signed32(value:u64) -> u64:
    return choose(value <= 2147483647 or value >= 18446744071562067968, 1, 0)

def encode_data(o:mutbuf, w:mutbuf, command:u64, r:u64, m:u64, value:u64, auxiliary:u64, mode:u64, offset:u64) -> u64:
    if command == 1:
        n = (0 - offset) & (auxiliary - 1)
        while n != 0:
            emit(o, w, 144)
            n = n - 1
        return 0
    if command == 2:
        rr(o, w, 137, 0, m, r)
        return 0
    if command == 3:
        if mode == 1 and value < 4294967296:
            if r >= 8:
                emit(o, w, 65)
            emit(o, w, 184 + (r & 7))
            little(o, w, value, 4)
        else:
            emit(o, w, 72 | (r >> 3))
            emit(o, w, 184 + (r & 7))
            little(o, w, value, 8)
        return 0
    if command >= 4 and command <= 8:
        memory(o, w, command, r, m, value)
        return 0
    opcode = 1
    if command == 10:
        opcode = 41
    if command == 11:
        opcode = 33
    if command == 12:
        opcode = 9
    if command == 13:
        opcode = 49
    if command == 14:
        opcode = 57
    if command == 15:
        opcode = 133
    rr(o, w, opcode, 0, m, r)
    return 0

def encode_arithmetic(o:mutbuf, w:mutbuf, command:u64, r:u64, m:u64, value:u64, auxiliary:u64, mode:u64, offset:u64) -> u64:
    if command == 16:
        group = auxiliary
        if auxiliary >= 2:
            group = auxiliary + 2
        emit(o, w, 72 | (r >> 3))
        emit(o, w, choose(mode == 1, 131, 129))
        emit(o, w, 192 | (group << 3) | (r & 7))
        little(o, w, value, choose(offset == 1, 1, 4))
        return 0
    if command == 17:
        group = auxiliary + 4
        if auxiliary == 2:
            group = 7
        emit(o, w, 72 | (r >> 3))
        emit(o, w, choose(mode == 1, 211, 193))
        emit(o, w, 192 | (group << 3) | (r & 7))
        if mode == 0:
            emit(o, w, value)
        return 0
    if command == 18:
        rr(o, w, 15, 175, r, m)
        return 0
    if command >= 19 and command <= 24:
        group = command - 15
        if command == 23:
            group = 3
        if command == 24:
            group = 2
        emit(o, w, 72 | (r >> 3))
        emit(o, w, 247)
        emit(o, w, 192 | (group << 3) | (r & 7))
        return 0
    if command == 25:
        emit(o, w, 72)
        emit(o, w, 153)
        return 0
    if command == 26:
        emit(o, w, 64 | (r >> 3))
        emit(o, w, 15)
        emit(o, w, 144 + auxiliary)
        emit(o, w, 192 | (r & 7))
        return 0
    rr(o, w, 15, 64 + auxiliary, r, m)
    return 0

def encode_control(o:mutbuf, w:mutbuf, command:u64, r:u64, value:u64, auxiliary:u64) -> u64:
    if command == 28 or command == 29:
        if r >= 8:
            emit(o, w, 65)
        emit(o, w, choose(command == 28, 80, 88) + (r & 7))
        return 0
    if command == 30:
        emit(o, w, 195)
        return 0
    if command == 31:
        emit(o, w, 201)
        return 0
    if command == 32:
        emit(o, w, 15)
        emit(o, w, 11)
        return 0
    if command == 33:
        emit(o, w, 233)
        return 0
    if command == 34:
        emit(o, w, 15)
        emit(o, w, 128 + auxiliary)
        return 0
    if command == 35:
        emit(o, w, 232)
        return 0
    if command == 36:
        little(o, w, 0, 4)
        return 0
    little(o, w, value, 4)
    return 0

def rr(o:mutbuf, w:mutbuf, opcode:u64, second:u64, r:u64, m:u64) -> u64:
    emit(o, w, 72 | ((r >> 3) << 2) | (m >> 3))
    emit(o, w, opcode)
    if second != 0:
        emit(o, w, second)
    emit(o, w, 192 | ((r & 7) << 3) | (m & 7))
    return 0

def memory(o:mutbuf, w:mutbuf, command:u64, r:u64, base:u64, displacement:u64) -> u64:
    emit(o, w, choose(command == 8, 64, 72) | ((r >> 3) << 2) | (base >> 3))
    opcode = 139
    if command == 5:
        opcode = 137
    if command == 6:
        opcode = 141
    if command == 7:
        emit(o, w, 15)
        opcode = 182
    if command == 8:
        opcode = 136
    emit(o, w, opcode)
    emit(o, w, 128 | ((r & 7) << 3) | (base & 7))
    if (base & 7) == 4:
        emit(o, w, 36)
    little(o, w, displacement, 4)
    return 0

def emit(o:mutbuf, w:mutbuf, value:u64) -> u64:
    at = get(w, 0)
    store(o, at, value)
    put(w, 0, at + 1)
    return 0

def little(o:mutbuf, w:mutbuf, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        emit(o, w, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def out_word(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value
'''


def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            constants = {'ABI': ABI, 'MAGIC': MAGIC}
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(ast.parse(SOURCE)))) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'machine_encoding', 'functions': functions})


if __name__ == '__main__':
    import sys
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'examples/hia_bootstrap/machine_encoding.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
