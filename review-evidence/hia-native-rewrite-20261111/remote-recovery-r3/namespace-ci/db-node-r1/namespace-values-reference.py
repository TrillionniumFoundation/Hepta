"""Author the complete namespace engine's value and transaction building blocks.

The current emitted component is its streaming value envelope owner. It covers
all 31 retained relational bind signatures and all ten row schemas. It is not a
database, does not activate an AgentStore, and cannot grant namespace authority.
No Python value/SQL scanner is called by generated HIA.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]
ABI_PATH = ROOT / 'docs/HIA_AGENT_NAMESPACE_STORE_ABI.json'
SOURCE_PATH = ROOT / 'examples/hia_bootstrap/agent_namespace_values.hiaasm'
MAGIC = int.from_bytes(b'HIANSC01', 'little')
REFUSED = 4294967293

VALUES = r'''
def namespace_values(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 128:
        return 4294967293
    if length(o) < 128:
        poison(w, 1)
        return 4294967293
    if get(w, 0) == 0:
        index = 0
        while index < 128:
            if byte(w, index) != 0:
                poison(w, 2)
                return emit(o, w, 4294967293)
            index = index + 1
        put(w, 0, MAGIC_VALUE)
    if get(w, 0) != MAGIC_VALUE:
        poison(w, 2)
        return emit(o, w, 4294967293)
    if get(w, 8) == 3:
        return emit(o, w, 4294967293)
    if get(w, 8) > 3:
        poison(w, 2)
        return emit(o, w, 4294967293)
    if valid_state(w) == 0:
        poison(w, 12)
        return emit(o, w, 4294967293)
    if length(s) < 64:
        poison(w, 3)
        return emit(o, w, 4294967293)
    if read64(s, 0) != MAGIC_VALUE:
        poison(w, 3)
        return emit(o, w, 4294967293)
    command = read64(s, 8)
    serial = read64(s, 16)
    operation = read64(s, 24)
    table = read64(s, 32)
    count = read64(s, 40)
    size = read64(s, 48)
    sequence = read64(s, 56)
    if size != length(s) - 64:
        poison(w, 3)
        return emit(o, w, 4294967293)
    if command == 1:
        if get(w, 8) == 1 or size != 0 or sequence != 0:
            poison(w, 4)
            return emit(o, w, 4294967293)
        if get(w, 16) == 18446744073709551615:
            poison(w, 5)
            return emit(o, w, 4294967293)
        if serial != get(w, 16) + 1:
            poison(w, 5)
            return emit(o, w, 4294967293)
        if signature(operation, table, count) == 0:
            poison(w, 6)
            return emit(o, w, 4294967293)
        put(w, 8, 1)
        put(w, 16, serial)
        put(w, 24, operation)
        put(w, 32, table)
        put(w, 40, count)
        put(w, 48, 0)
        put(w, 56, 0)
        put(w, 64, 0)
        put(w, 72, 0)
        put(w, 80, 0)
        put(w, 88, 0)
        put(w, 96, 0)
        put(w, 104, 0)
        return emit(o, w, 1)
    if command != 2 and command != 3:
        poison(w, 3)
        return emit(o, w, 4294967293)
    if get(w, 8) != 1:
        poison(w, 4)
        return emit(o, w, 4294967293)
    if serial != get(w, 16) or operation != get(w, 24) or table != get(w, 32) or count != get(w, 40):
        poison(w, 5)
        return emit(o, w, 4294967293)
    if get(w, 96) == 18446744073709551615:
        poison(w, 5)
        return emit(o, w, 4294967293)
    if sequence != get(w, 96) + 1:
        poison(w, 5)
        return emit(o, w, 4294967293)
    if command == 3:
        if size != 0 or get(w, 48) != count or get(w, 56) != 0 or get(w, 80) != 0:
            poison(w, 7)
            return emit(o, w, 4294967293)
        put(w, 96, sequence)
        put(w, 8, 2)
        return emit(o, w, 0)
    if size > 18446744073709551615 - get(w, 88):
        poison(w, 8)
        return emit(o, w, 4294967293)
    put(w, 96, sequence)
    status = feed(s, w)
    return emit(o, w, status)

def signature(operation:u64, table:u64, count:u64) -> u64:
    if operation >= 1 and operation <= 31:
        if table == operation_table(operation) and count == operation_arity(operation):
            return 1
    if operation == 100:
        if table >= 1 and table <= 10:
            if count == row_width(table):
                return 1
    if operation == 101 and table == 0:
        return 1
    return 0

def valid_state(w:mutbuf) -> u64:
    phase = get(w, 8)
    if phase == 0:
        index = 16
        while index < 128:
            if get(w, index) != 0:
                return 0
            index = index + 8
        return 1
    if get(w, 16) == 0 or get(w, 104) != 0 or get(w, 112) != 0 or get(w, 120) != 0:
        return 0
    if signature(get(w, 24), get(w, 32), get(w, 40)) == 0:
        return 0
    completed = get(w, 48)
    expected = get(w, 40)
    header = get(w, 56)
    kind = get(w, 64)
    size = get(w, 72)
    remaining = get(w, 80)
    total = get(w, 88)
    sequence = get(w, 96)
    if completed > expected or header > 16:
        return 0
    if completed > total >> 4:
        return 0
    available = total - completed * 16
    if header > available:
        return 0
    if header == 0:
        if kind != 0 or size != 0 or remaining != 0:
            return 0
    else:
        if completed == expected:
            return 0
        if header < 8:
            if size != 0 or remaining != 0 or kind >> (header * 8) != 0:
                return 0
        else:
            if header < 16:
                if remaining != 0 or size >> ((header - 8) * 8) != 0:
                    return 0
            else:
                if kind == 0 or kind > 4 or size == 0 or remaining == 0 or remaining > size:
                    return 0
                if (kind == 1 or kind == 2) and size != 8:
                    return 0
                if size - remaining > available - 16:
                    return 0
    if sequence == 0 and total != 0:
        return 0
    if phase == 2:
        if completed != expected or header != 0 or sequence == 0:
            return 0
    return 1

def feed(s:readbuf, w:mutbuf) -> u64:
    cursor = 64
    end = length(s)
    while cursor < end:
        if get(w, 48) == get(w, 40):
            poison(w, 9)
            return 4294967293
        header = get(w, 56)
        if header < 16:
            if header == 0:
                put(w, 64, 0)
                put(w, 72, 0)
            if header == 0 and end - cursor >= 16:
                put(w, 64, read64(s, cursor))
                put(w, 72, read64(s, cursor + 8))
                header = 16
                cursor = cursor + 16
                put(w, 88, get(w, 88) + 16)
            else:
                while header < 16 and cursor < end:
                    value = byte(s, cursor)
                    if header < 8:
                        put(w, 64, get(w, 64) | (value << (header * 8)))
                    else:
                        put(w, 72, get(w, 72) | (value << ((header - 8) * 8)))
                    header = header + 1
                    cursor = cursor + 1
                    put(w, 88, get(w, 88) + 1)
            put(w, 56, header)
            if header == 16:
                kind = get(w, 64)
                size = get(w, 72)
                if kind > 4:
                    poison(w, 10)
                    return 4294967293
                if kind == 0 and size != 0:
                    poison(w, 11)
                    return 4294967293
                if (kind == 1 or kind == 2) and size != 8:
                    poison(w, 11)
                    return 4294967293
                put(w, 80, size)
                if size == 0:
                    complete_value(w)
        if get(w, 56) == 16 and cursor < end:
            count = end - cursor
            if count > get(w, 80):
                count = get(w, 80)
            put(w, 80, get(w, 80) - count)
            put(w, 88, get(w, 88) + count)
            cursor = cursor + count
            if get(w, 80) == 0:
                complete_value(w)
    return 1

def complete_value(w:mutbuf) -> u64:
    put(w, 48, get(w, 48) + 1)
    put(w, 56, 0)
    put(w, 64, 0)
    put(w, 72, 0)
    put(w, 80, 0)
    return 0

def poison(w:mutbuf, reason:u64) -> u64:
    if get(w, 0) != MAGIC_VALUE or get(w, 8) != 3:
        put(w, 104, reason)
    put(w, 0, MAGIC_VALUE)
    put(w, 8, 3)
    return 4294967293

def emit(o:mutbuf, w:mutbuf, status:u64) -> u32:
    put(o, 0, MAGIC_VALUE)
    put(o, 8, status)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 96))
    put(o, 32, get(w, 24))
    put(o, 40, get(w, 32))
    put(o, 48, get(w, 40))
    put(o, 56, get(w, 48))
    put(o, 64, get(w, 56))
    put(o, 72, get(w, 80))
    put(o, 80, get(w, 88))
    put(o, 88, get(w, 104))
    put(o, 96, 1)
    put(o, 104, 0)
    put(o, 112, 0)
    put(o, 120, 0)
    return status

def read64(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''


def catalog():
    value = json.loads(ABI_PATH.read_bytes())
    if (value['schema'] != 'hepta.hia.agent-namespace-store-abi.v1'
            or len(value['tables']) != 10
            or [row['id'] for row in value['relational_operations']] != list(range(1, 32))
            or sum(len(row['call_sites']) for row in value['relational_operations']) != 45):
        raise ValueError('complete namespace operation catalog is required')
    return value


def source_program():
    value = catalog()
    result = VALUES.replace('MAGIC_VALUE', str(MAGIC))
    for name, field in (('operation_table', 'table_id'), ('operation_arity', 'bind_count')):
        result += '\ndef %s(operation:u64) -> u64:\n' % name
        for row in value['relational_operations']:
            result += '    if operation == %d:\n        return %d\n' % (row['id'], row[field])
        result += '    return 18446744073709551615\n'
    result += '\ndef row_width(table:u64) -> u64:\n'
    for row in value['tables']:
        result += '    if table == %d:\n        return %d\n' % (row['id'], len(row['columns']))
    result += '    return 18446744073709551615\n'
    return result


def document():
    nodes = ast.parse(source_program()).body
    if len({node.name for node in nodes}) != len(nodes):
        raise ValueError('duplicate namespace HIA symbol')
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'agent_namespace_values', 'functions': functions})


def main():
    SOURCE_PATH.write_text(render_assembly(document()))
    print(SOURCE_PATH.name, SOURCE_PATH.stat().st_size)


if __name__ == '__main__':
    main()

