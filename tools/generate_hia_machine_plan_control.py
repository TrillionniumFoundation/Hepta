"""Compile the complete machine-plan control program to one HIA image.

The image emits its own immutable instruction/literal table and interprets it
in HIA.  The table is not supplied by a hosted policy planner at runtime.
"""
from __future__ import annotations

import ast
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.hia_exception_delivery import BODY as EXCEPTION_BODY
from tools.hia_machine_plan_control import compile_policy, OPS

MAGIC = int.from_bytes(b'HIAPLN02', 'little')
EMIT_MAGIC = int.from_bytes(b'HIAPLT02', 'little')
ABI = 0xfffffffd
OUTPUT = 2048


def program():
    return compile_policy((ROOT / 'hepta/hia_machine_plan.py').read_text())


def table(policy):
    starts = {}
    count = 0
    for function in policy.functions:
        starts[function.mode] = count + 1
        count += len(function.instructions)
    data = bytearray(64 + len(policy.functions) * 32)
    for function in policy.functions:
        metadata = len(data)
        data += bytes((int(i in function.temporary_slots) |
                       (2 * int(i in function.cell_slots)))
                      for i in range(function.next_slot))
        for own, outer in function.captures.values():
            data += struct.pack('<H', own.slot)
        info = (len(function.parameters) |
                (int(function.kind == 'generator') << 16) |
                (len(function.captures) << 32))
        struct.pack_into('<4Q', data, 64 + (function.mode - 1) * 32,
                         starts[function.mode], function.next_slot, info, metadata)
    offsets_at = len(data)
    data += b'\0' * (4 * count)
    ordinal = 0
    for function in policy.functions:
        shift = starts[function.mode] - 1
        for instruction in function.instructions:
            struct.pack_into('<I', data, offsets_at + ordinal * 4, len(data))
            ordinal += 1
            kind = instruction['kind']
            if kind == 'effect':
                destinations, arguments = instruction['destinations'], instruction['arguments']
                raw, vector = instruction['raw'], instruction['vector']
                consume = instruction['consume']
                handler = instruction['handler']
                data += struct.pack('<6BH I H', 1, instruction['opcode'], len(destinations),
                                    len(arguments), len(raw), len(consume), len(vector),
                                    handler + shift if handler else 0, 0)
                for ref in (*destinations, *arguments):
                    data += struct.pack('<H', ref.slot)
                for value in raw:
                    data += struct.pack('<I', value)
                for ref in (*vector, *consume):
                    data += struct.pack('<H', ref.slot)
            elif kind == 'jump':
                data += struct.pack('<BI', 2, instruction['target'] + shift)
            elif kind == 'flag':
                data += struct.pack('<BII', 3, instruction['yes'] + shift,
                                    instruction['no'] + shift)
            elif kind in ('return', 'yield'):
                data += struct.pack('<BH', 4 if kind == 'return' else 5,
                                    instruction['value'].slot)
            elif kind == 'error_return':
                data += b'\6'
            else:
                raise ValueError('unrendered instruction')
    literals_at = len(data)
    data += b'\0' * (4 * len(policy.literals))
    for index, value in enumerate(policy.literals):
        struct.pack_into('<I', data, literals_at + 4 * index, len(data))
        if value is None:
            kind, raw = 0, b''
        elif type(value) is bool:
            kind, raw = 1, bytes((int(value),))
        elif type(value) is int:
            kind, raw = 2, str(value).encode('ascii')
        elif type(value) is str:
            # CPython interns its ASCII name-character constants. Record that
            # representation in the immutable HIA-owned table, so the runtime
            # bridge does not infer a policy or change the object's identity.
            interned = all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
                           for c in value)
            kind, raw = (4 if interned else 3), value.encode('utf-8')
        else:
            raise ValueError('unrendered literal')
        data += struct.pack('<BQ', kind, len(raw)) + raw
    data += bytes((-len(data)) % 8)
    struct.pack_into('<8Q', data, 0, MAGIC, len(data), len(policy.functions), count,
                     64, offsets_at, literals_at, len(policy.literals))
    return bytes(data)


BODY = r'''
def machine_plan(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) == 64:
        if word(s,0) == EMIT_MAGIC:
            return emit_policy(o,w)
        return emit_exception_delivery(s,o,w)
    if length(s) != TABLE_BYTES or word(s,0) != MAGIC or word(s,8) != TABLE_BYTES:
        return ABI
    if length(o) < OUTPUT_BYTES or length(w) != WORKSPACE_BYTES:
        return ABI
    command=get(w,0)
    if command == 0:
        if get(w,128) != 0 or get(w,8) == 0 or get(w,16) != 0:
            return ABI
        mode=get(w,24)
        if mode == 0 or mode > word(s,16):
            return ABI
        info=64+(mode-1)*32
        put(w,128,MAGIC)
        put(w,136,get(w,8))
        put(w,144,0)
        put(w,152,mode)
        put(w,160,word(s,info))
        put(w,168,0)
        put(w,176,0)
        put(w,216,0)
        put(w,248,word(s,info+8))
        put(w,256,word(s,info+24))
        put(w,264,0)
    else:
        if get(w,128) != MAGIC or get(w,8) != get(w,136) or get(w,16) != get(w,144):
            return ABI
        stage=get(w,168)
        if command == 2:
            if stage != 1 or get(w,24) != get(w,184) or get(w,32) != 0:
                return ABI
            put(w,168,2)
            return 4
        if command == 3:
            if stage != 4 or get(w,24) != 0 or get(w,32) != 0:
                return ABI
            put(w,160,get(w,160)+1)
            put(w,168,0)
        else:
            if command == 4:
                if (stage != 4 and stage != 5 and stage != 7) or get(w,24) != 0 or get(w,32) != 0:
                    return ABI
                put(w,304,0)
                put(w,168,8)
            else:
                if command != 1 or stage != 2 or get(w,24) > 1 or get(w,32) > 1:
                    return ABI
                answer=acknowledge(s,w)
                if answer != 0:
                    return answer
    return dispatch(s,o,w)

def acknowledge(s:readbuf,w:mutbuf) -> u64:
    request=get(w,208)
    op=get(w,184)
    if get(w,32) != 0:
        if request != 1:
            return ABI
        put(w,264,1)
        put(w,168,6)
        put(w,272,0)
        return 0
    if request == 3:
        put(w,1024+get(w,280)*8,0)
        put(w,168,6)
        return 0
    if request == 5:
        if get(w,24) != 0:
            return ABI
        put(w,1024+get(w,280)*8,0)
        put(w,168,8)
        return 0
    if request == 6:
        if get(w,24) != 0:
            return ABI
        put(w,304,get(w,304)+1)
        put(w,168,8)
        return 0
    if request == 2:
        clear_refs(s,w,get(w,288),get(w,296))
        if get(w,264) != 0:
            put(w,168,6)
        else:
            put(w,160,get(w,160)+1)
            put(w,168,0)
        return 0
    at=get(w,200)
    if op == TRUTH or op == NEXT or op == EXCEPTION_MATCH:
        put(w,176,get(w,24))
    else:
        if get(w,24) != 0:
            return ABI
    destinations=byte(s,at+2)
    i=0
    while i < destinations:
        slot=short(s,at+14+i*2)
        if slot >= get(w,248):
            return ABI
        if (byte(s,get(w,256)+slot)&1) != 0:
            if get(w,216) == 18446744073709551615:
                return ABI
            put(w,216,get(w,216)+1)
            put(w,1024+slot*8,get(w,216))
        i=i+1
    if op == RELEASE:
        start=at+14+destinations*2+byte(s,at+3)*2+byte(s,at+4)*4
        clear_refs(s,w,start,short(s,at+6))
    consumed=byte(s,at+5)
    if consumed != 0:
        put(w,288,at+14+destinations*2+byte(s,at+3)*2+byte(s,at+4)*4+short(s,at+6)*2)
        put(w,296,consumed)
        put(w,168,3)
    else:
        put(w,160,get(w,160)+1)
        put(w,168,0)
    return 0

def clear_refs(s:readbuf,w:mutbuf,at:u64,count:u64) -> u64:
    i=0
    while i < count:
        slot=short(s,at+i*2)
        put(w,1024+slot*8,0)
        i=i+1
    return 0

def dispatch(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    while True:
        stage=get(w,168)
        if stage == 8:
            return frame_retire(s,o,w)
        if stage == 3:
            return retire(s,o,w,get(w,288),get(w,296))
        if stage == 6:
            answer=unwind(s,o,w)
            if answer != 5:
                return answer
        if get(w,168) != 0:
            return ABI
        pc=get(w,160)
        if pc == 0 or pc > word(s,24):
            return ABI
        at=small(s,word(s,40)+(pc-1)*4)
        kind=byte(s,at)
        if kind == 1:
            put(w,200,at)
            put(w,192,small(s,at+8))
            return effect(s,o,w,at)
        if kind == 2:
            put(w,160,small(s,at+1))
        else:
            if kind == 3:
                put(w,160,small(s,at+choose(get(w,176)!=0,1,5)))
            else:
                if kind == 4 or kind == 5:
                    put(w,168,choose(kind == 4,5,4))
                    finish(o,w,short(s,at+1))
                    return choose(kind == 4,0,2)
                if kind == 6:
                    put(w,168,7)
                    finish(o,w,0)
                    return 3
                return ABI
    return ABI

def frame_retire(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    latest=0
    selected=0
    i=0
    while i < get(w,248):
        birth=get(w,1024+i*8)
        if birth > latest:
            latest=birth
            selected=i
        i=i+1
    if latest != 0:
        put(w,280,selected)
        header(o,w,RELEASE,0,0,0,1,5)
        put(o,128,selected)
        return 1
    index=get(w,304)
    if index < get(w,248):
        header(o,w,DROP_SLOT,0,0,0,1,6)
        put(o,128,index)
        return 1
    put(w,168,9)
    finish(o,w,0)
    return 5

def unwind(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    at=get(w,200)
    if get(w,272) == 0:
        put(w,272,1)
        count=byte(s,at+5)
        if count != 0:
            start=at+14+byte(s,at+2)*2+byte(s,at+3)*2+byte(s,at+4)*4+short(s,at+6)*2
            put(w,288,start)
            put(w,296,count)
            return retire(s,o,w,start,count)
    latest=0
    selected=0
    i=0
    while i < get(w,248):
        birth=get(w,1024+i*8)
        if birth > latest:
            latest=birth
            selected=i
        i=i+1
    if latest != 0:
        put(w,280,selected)
        header(o,w,RELEASE,0,0,0,1,3)
        put(o,128,selected)
        return 1
    handler=get(w,192)
    if handler != 0:
        put(w,160,handler)
        put(w,168,0)
        put(w,264,0)
        return 5
    put(w,168,7)
    finish(o,w,0)
    return 3

def effect(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    op=byte(s,at+1)
    nd=byte(s,at+2)
    na=byte(s,at+3)
    nr=byte(s,at+4)
    nv=short(s,at+6)
    if op == 0 or op > 28 or 128+8*(nd+na+nr+nv) > length(o):
        return ABI
    header(o,w,op,nd,na,nr,nv,1)
    source=at+14
    target=128
    i=0
    while i < nd+na:
        value=short(s,source)
        if value >= get(w,248):
            return ABI
        put(o,target,value)
        source=source+2
        target=target+8
        i=i+1
    i=0
    while i < nr:
        put(o,target,small(s,source))
        source=source+4
        target=target+8
        i=i+1
    i=0
    while i < nv:
        value=short(s,source)
        if value >= get(w,248):
            return ABI
        put(o,target,value)
        source=source+2
        target=target+8
        i=i+1
    return 1

def retire(s:readbuf,o:mutbuf,w:mutbuf,at:u64,count:u64) -> u64:
    header(o,w,RELEASE,0,0,0,count,2)
    i=0
    while i < count:
        put(o,128+i*8,short(s,at+i*2))
        i=i+1
    return 1

def header(o:mutbuf,w:mutbuf,op:u64,nd:u64,na:u64,nr:u64,nv:u64,request:u64) -> u64:
    sequence=get(w,144)+1
    put(w,144,sequence)
    put(w,168,1)
    put(w,184,op)
    put(w,208,request)
    put(o,0,MAGIC)
    put(o,8,get(w,136))
    put(o,16,sequence)
    put(o,24,get(w,160))
    put(o,32,op)
    put(o,40,nd)
    put(o,48,na)
    put(o,56,nr)
    put(o,64,nv)
    put(o,72,request)
    return 0

def finish(o:mutbuf,w:mutbuf,value:u64) -> u64:
    put(o,0,MAGIC)
    put(o,8,get(w,136))
    put(o,16,get(w,144))
    put(o,24,value)
    return 0

def short(s:readbuf,at:u64) -> u64:
    return byte(s,at)|(byte(s,at+1)<<8)

def small(s:readbuf,at:u64) -> u64:
    return short(s,at)|(short(s,at+2)<<16)
'''


def helpers():
    result = []
    for name, typ in (('word', 'readbuf'), ('get', 'mutbuf')):
        result.append('def ' + name + '(b:' + typ + ', at:u64) -> u64:\n    return ' +
                      ' | '.join('(byte(b,at+' + str(i) + ') << ' + str(i * 8) + ')'
                                 for i in range(8)))
    result.append('def put(b:mutbuf,at:u64,value:u64) -> u64:\n' +
                  '\n'.join('    store(b,at+' + str(i) + ',(value >> ' + str(i * 8) + ') & 255)'
                            for i in range(8)) + '\n    return 0')
    result.append('def words(o:mutbuf,w:mutbuf,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64,g:u64,h:u64) -> u64:\n' +
                  '\n'.join('    put(o,get(w,88)+' + str(i * 8) + ',' + chr(97 + i) + ')'
                            for i in range(8)) + '\n    put(w,88,get(w,88)+64)\n    return 0')
    return '\n\n'.join(result)


def emission(data):
    padded = data + bytes((-len(data)) % 64)
    values = struct.unpack('<' + 'Q' * (len(padded) // 8), padded)
    groups = [values[i:i + 128] for i in range(0, len(values), 128)]
    result = ['def emit_policy(o:mutbuf,w:mutbuf) -> u32:\n'
              '    if length(o) < ' + str(len(padded)) + ' or length(w) < 96:\n'
              '        return ABI\n    put(w,88,0)\n' +
              '\n'.join('    emit_part_' + str(i) + '(o,w)' for i in range(len(groups))) +
              '\n    return ' + str(len(data))]
    for index, group in enumerate(groups):
        result.append('def emit_part_' + str(index) + '(o:mutbuf,w:mutbuf) -> u64:\n' +
                      '\n'.join('    words(o,w,' + ','.join(map(str, group[i:i + 8])) + ')'
                                for i in range(0, len(group), 8)) + '\n    return 0')
    return '\n\n'.join(result)


def source():
    policy = program()
    data = table(policy)
    constants = {'MAGIC': MAGIC, 'EMIT_MAGIC': EMIT_MAGIC, 'ABI': ABI,
                 'OUTPUT_BYTES': OUTPUT, 'TABLE_BYTES': len(data),
                 'WORKSPACE_BYTES': 1024 + 8 * max(f.next_slot for f in policy.functions),
                 **OPS}
    parsed = ast.parse(BODY + '\n' + helpers() + '\n' + emission(data) + '\n' + EXCEPTION_BODY)
    class Names(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
    return ast.fix_missing_locations(Names().visit(parsed))


def document():
    nodes = source().body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args],
                              node.returns.id) for node in nodes}
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
                                  'module': 'machine_plan', 'functions': functions})


def main():
    path = ROOT / 'examples/hia_bootstrap/machine_plan.hiaasm'
    path.write_text(render_assembly(document()))
    print(path)


if __name__ == '__main__':
    main()
