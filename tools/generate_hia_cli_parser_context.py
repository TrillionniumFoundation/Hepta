"""Author genuine parser-error object custody, separate from argv decisions."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from tools.hia_cli_parser_graph import graph_facts,instruction_plan,delta_plan,compress_lz,decompress_lz
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cli_parser_context_foreign import definition_sha

SOURCE_NAME='examples/hia_bootstrap/cli_parser_context.hepta'
DATA_NAME='hepta/hia_cli_parser_context_data.py'

SOURCE=r'''
def context(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 131072 or length(o) < 4096 or length(s) < 128:
        return 199
    if read64(s, 0) != MAGIC or read64(s, 16) == 0:
        return refuse(w)
    command = read64(s, 8)
    if command == 0:
        if get(w, 0) != 0 or read64(s, 48) != PROFILE:
            return refuse(w)
        scope = read64(s, 56)
        field = read64(s, 64)
        reason = read64(s, 72)
        if scope > 15 or field >= FIELD_COUNT or reason < 1 or reason > 9:
            return refuse(w)
        message_bytes = read64(s, 80)
        if message_bytes > length(s) - 128 or (message_bytes & 3) != 0:
            return refuse(w)
        columns_count = read64(s, 104)
        if columns_count != (length(s) - 128 - message_bytes) >> 2 or ((length(s) - 128 - message_bytes) & 3) != 0:
            return refuse(w)
        if read64(s, 88) > 1 or read64(s, 112) > 1 or read64(s, 96) > 4294967295:
            return refuse(w)
        i = 0
        while i < 256:
            store(w, i, 0)
            i = i + 1
        put(w, 0, STATE)
        put(w, 8, read64(s, 16))
        put(w, 192, choose(read64(s, 96) == 0, 80, read64(s, 96)))
        put(w, 200, read64(s, 88))
        put(w, 208, read64(s, 120))
        context_kind = 0
        if reason == 2 or reason == 4 or reason == 5 or reason == 6:
            context_kind = 2
        elif reason == 1 or reason == 3:
            context_kind = 1
        put(w, 80, context_kind)
        if context_kind == 0:
            return terminal(o, w)
        seed(w)
        if expand(w) == False or plan(w) == False:
            return refuse(w)
        action = 65535
        if context_kind == 2:
            action = word16(w, EXPANDED + MAP_OFFSET + (scope * FIELD_COUNT + field) * 2)
            if action >= NODES:
                return refuse(w)
        put(w, 56, action)
        if locate_message(s, w, context_kind) == False:
            return refuse(w)
        if context_kind == 1:
            put(w, 72, 2)
            return ask(o, w, 14, NODES, get(w, 88), get(w, 96))
        if HAS_FORMATTERS:
            if read64(s, 112) != 0:
                put(w, 72, 3)
                return ask(o, w, 15, NODES + 1, 128 + message_bytes, columns_count)
            return fallback_columns(o, w)
        return next(o, w)
    if length(s) != 128 or get(w, 0) != STATE or get(w, 8) != read64(s, 16) or get(w, 48) != 0:
        return refuse(w)
    if read64(s, 24) != get(w, 24) or read64(s, 32) != get(w, 40) or get(w, 40) == 0:
        return refuse(w)
    if command == 2:
        if get(w, 32) != 0:
            return refuse(w)
        put(w, 32, 1)
        emit(o, w)
        return 3
    observation = read64(s, 40)
    operation = get(w, 40)
    if command != 1 or get(w, 32) != 1 or observation > 1:
        return refuse(w)
    if operation != 15 and operation != 16 and observation != 0:
        return refuse(w)
    put(w, 32, 0)
    put(w, 40, 0)
    phase = get(w, 72)
    if phase == 0:
        put(w, 16, get(w, 16) + 1)
        return next(o, w)
    if phase == 1:
        put(w, 104, get(w, 104) + 1)
        return releases(o, w)
    if phase == 2:
        return terminal(o, w)
    if phase == 3:
        if observation != 0:
            put(w, 72, 5)
            return ask(o, w, 13, NODES + 1, 0, 0)
        put(w, 72, 4)
        return ask(o, w, 16, NODES + 1, 0, 0)
    if phase == 4:
        if observation == 0:
            put(w, 72, 5)
            return ask(o, w, 13, NODES + 1, 0, 0)
        put(w, 72, 0)
        return next(o, w)
    if phase == 5:
        return fallback_columns(o, w)
    if phase == 6:
        put(w, 72, 0)
        return next(o, w)
    return refuse(w)

def fallback_columns(o:mutbuf, w:mutbuf) -> u32:
    put(w, 72, 6)
    return integer(o, w, NODES + 1, get(w, 192))

def integer(o:mutbuf, w:mutbuf, destination:u64, value:u64) -> u32:
    result = ask(o, w, 7, destination, 0, 11)
    store(o, 128, 2)
    store(o, 129, 8)
    store(o, 130, 0)
    put(o, 131, value)
    return result

def next(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 16)
    if index == INSTRUCTIONS:
        put(w, 72, 1)
        return releases(o, w)
    if index > INSTRUCTIONS:
        return refuse(w)
    row = PLAN + index * 8
    operation = word16(w, row)
    destination = word16(w, row + 2)
    a = word16(w, row + 4)
    b = word16(w, row + 6)
    if operation == 18:
        return ask(o, w, 4, destination, choose(get(w, 200) == 0, a, b), 0)
    if operation == 19:
        columns = get(w, 208)
        position = 24
        if columns <= 26:
            position = 4
        elif columns < 46:
            position = columns - 22
        return integer(o, w, destination, position)
    return ask(o, w, operation, destination, a, b)

def releases(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 104)
    while index < NODES:
        if index != ROOT_NODE and index != get(w, 56):
            return ask(o, w, 13, index, 0, 0)
        index = index + 1
        put(w, 104, index)
    if HAS_FORMATTERS and index == NODES:
        return ask(o, w, 13, NODES + 1, 0, 0)
    put(w, 72, 2)
    return ask(o, w, 14, NODES, get(w, 88), get(w, 96))

def ask(o:mutbuf, w:mutbuf, operation:u64, destination:u64, a:u64, b:u64) -> u32:
    put(w, 24, get(w, 24) + 1)
    put(w, 40, operation)
    put(w, 112, destination)
    put(w, 120, a)
    put(w, 128, b)
    emit(o, w)
    if operation == 7:
        if a > PAYLOAD_BYTES or b > PAYLOAD_BYTES - a or b > length(o) - 128:
            return refuse(w)
        i = 0
        while i < b:
            store(o, 128 + i, byte(w, EXPANDED + PAYLOAD_OFFSET + a + i))
            i = i + 1
    return 1

def emit(o:mutbuf, w:mutbuf) -> u64:
    i = 0
    while i < 128:
        store(o, i, 0)
        i = i + 1
    put(o, 0, COMMAND)
    put(o, 8, get(w, 24))
    put(o, 16, get(w, 40))
    put(o, 24, get(w, 112))
    put(o, 32, get(w, 120))
    put(o, 40, get(w, 128))
    return 0

def terminal(o:mutbuf, w:mutbuf) -> u32:
    put(w, 48, 1)
    put(w, 40, 0)
    emit(o, w)
    put(o, 56, get(w, 80))
    put(o, 64, get(w, 56))
    put(o, 72, ROOT_NODE)
    put(o, 80, NODES)
    return 2

def locate_message(s:readbuf, w:mutbuf, kind:u64) -> bool:
    count = read64(s, 80) >> 2
    index = 0
    start = 0
    while index + 9 <= count and start == 0:
        if read32(s, 128 + index * 4) == 58 and read32(s, 132 + index * 4) == 32 and read32(s, 136 + index * 4) == 101 and read32(s, 140 + index * 4) == 114 and read32(s, 144 + index * 4) == 114 and read32(s, 148 + index * 4) == 111 and read32(s, 152 + index * 4) == 114 and read32(s, 156 + index * 4) == 58 and read32(s, 160 + index * 4) == 32:
            start = index + 9
        index = index + 1
    if start == 0 or start >= count or read32(s, 128 + (count - 1) * 4) != 10:
        return False
    if kind == 2:
        index = start
        start = 0
        while index + 1 < count and start == 0:
            if read32(s, 128 + index * 4) == 58 and read32(s, 132 + index * 4) == 32:
                start = index + 2
            index = index + 1
        if start == 0:
            return False
    put(w, 88, 128 + start * 4)
    put(w, 96, count - 1 - start)
    return True

def expand(w:mutbuf) -> bool:
    cursor = 0
    output = 0
    while cursor < COMPRESSED_BYTES:
        token = byte(w, COMPRESSED + cursor)
        cursor = cursor + 1
        if token < 128:
            size = token + 1
            if size > COMPRESSED_BYTES - cursor or size > EXPANDED_BYTES - output:
                return False
            i = 0
            while i < size:
                store(w, EXPANDED + output, byte(w, COMPRESSED + cursor))
                output = output + 1
                cursor = cursor + 1
                i = i + 1
        else:
            if cursor + 2 > COMPRESSED_BYTES:
                return False
            distance = word16(w, COMPRESSED + cursor)
            cursor = cursor + 2
            size = token - 128 + 3
            if distance == 0 or distance > output or size > EXPANDED_BYTES - output:
                return False
            i = 0
            while i < size:
                store(w, EXPANDED + output, byte(w, EXPANDED + output - distance))
                output = output + 1
                i = i + 1
    return output == EXPANDED_BYTES

def plan(w:mutbuf) -> bool:
    row = 0
    cursor = 0
    while row < INSTRUCTIONS:
        column = 0
        while column < 4:
            number = 0
            shift = 0
            more = True
            while more:
                if cursor >= PAYLOAD_OFFSET or shift > 14:
                    return False
                octet = byte(w, EXPANDED + cursor)
                cursor = cursor + 1
                number = number | ((octet & 127) << shift)
                shift = shift + 7
                more = (octet & 128) != 0
            previous = get(w, 160 + column * 8)
            value = 0
            if (number & 1) != 0:
                magnitude = (number + 1) >> 1
                if magnitude > previous:
                    return False
                value = previous - magnitude
            else:
                value = previous + (number >> 1)
            if value > 65535:
                return False
            put(w, 160 + column * 8, value)
            store(w, PLAN + row * 8 + column * 2, value & 255)
            store(w, PLAN + row * 8 + column * 2 + 1, value >> 8)
            column = column + 1
        row = row + 1
    return cursor == PAYLOAD_OFFSET

def refuse(w:mutbuf) -> u32:
    put(w, 48, 1)
    put(w, 40, 0)
    return 199

def word16(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8)

def get(w:mutbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, at + i) << (i * 8))
        i = i + 1
    return result

def read64(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def read32(s:readbuf, at:u64) -> u64:
    return byte(s, at) | (byte(s, at + 1) << 8) | (byte(s, at + 2) << 16) | (byte(s, at + 3) << 24)

def choose(condition:bool, yes:u64, no:u64) -> u64:
    if condition:
        return yes
    return no

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


def authored():
    facts,objects,shared=graph_facts()
    rows,payload,raw=instruction_plan(facts)
    deltas=delta_plan(rows)
    action_map=b''.join(struct.pack('<H',value) for row in facts['action_map'] for value in row)
    expanded=deltas+payload+action_map
    compressed=compress_lz(expanded)
    if decompress_lz(compressed)!=expanded:raise AssertionError('graph literal codec differs')
    profile={(3,12,14):312,(3,14,4):314,(3,14,10):31410}.get(facts['profile'])
    if profile is None:raise ValueError('unreviewed parser graph interpreter profile')
    symbols={'MAGIC':int.from_bytes(b'HCLCTX01','little'),'COMMAND':int.from_bytes(b'HCLCOUT1','little'),
             'STATE':int.from_bytes(b'HCLCSTA1','little'),'PROFILE':profile,'FIELD_COUNT':len(facts['action_map'][0]),
             'ROOT_NODE':facts['root'],'NODES':len(facts['nodes']),'INSTRUCTIONS':len(rows),
             'HAS_FORMATTERS':facts['has_formatters'],
             'COMPRESSED':4096,'EXPANDED':32768,'PLAN':65536,'COMPRESSED_BYTES':len(compressed),
             'EXPANDED_BYTES':len(expanded),'PAYLOAD_OFFSET':len(deltas),'PAYLOAD_BYTES':len(payload),
             'MAP_OFFSET':len(deltas)+len(payload)}
    if 4096+len(compressed)>=32768 or 32768+len(expanded)>=65536 or 65536+len(raw)>131072:raise ValueError('graph static layout exceeds fixed workspace')
    lines=[];chunks=[]
    padded=compressed+b'\0'*((-len(compressed))%8)
    for start in range(0,len(padded),800):
        name='seed_'+str(len(chunks));chunks.append(name);lines.append('def '+name+'(w:mutbuf) -> u64:')
        for at in range(start,min(len(padded),start+800),8):
            lines.append('    put(w, '+str(4096+at)+', '+str(int.from_bytes(padded[at:at+8],'little'))+')')
        lines.append('    return 0')
    lines.append('def seed(w:mutbuf) -> u64:');lines.extend('    '+name+'(w)' for name in chunks);lines.append('    return 0')
    class Replace(ast.NodeTransformer):
        def visit_Name(self,node):return ast.copy_location(ast.Constant(symbols[node.id]),node) if node.id in symbols else node
    tree=Replace().visit(ast.parse(SOURCE+'\n'+'\n'.join(lines)+'\n'))
    nodes=ast.fix_missing_locations(tree).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    document=compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'cli_parser_context','functions':functions})
    data='"""Generated physical shared-object paths; no parser policy body."""\n'
    data+='PROFILE = '+repr(profile)+'\nNODE_COUNT = '+repr(len(facts['nodes']))+'\n'
    data+='SHARED_PATHS = '+repr(tuple(tuple((op,tuple(value) if isinstance(value,list) else value) for op,value in path) for path in facts['shared_paths']))+'\n'
    data+='SHARED_SIGNATURES = '+repr(tuple(definition_sha(value) for value in shared))+'\n'
    data+='REFERENCE_SHA256 = '+repr(facts['reference_sha256'])+'\nARGPARSE_SHA256 = '+repr(facts['argparse_sha256'])+'\n'
    return document,data,facts,symbols


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args(argv)
    document,data,facts,symbols=authored();raw=render_assembly(document).encode()
    if args.check:
        if (ROOT/SOURCE_NAME).read_bytes()!=raw or (ROOT/DATA_NAME).read_bytes()!=data.encode():
            raise ValueError('parser context generated bytes differ')
    else:
        (ROOT/SOURCE_NAME).write_bytes(raw);(ROOT/DATA_NAME).write_text(data)
    print(json.dumps({'source':SOURCE_NAME,'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
                      'data_bytes':len(data.encode()),'nodes':len(facts['nodes']),'symbols':symbols,
                      'functions':len(document['functions']),'blocks':sum(len(f['blocks']) for f in document['functions']),
                      'ops':sum(len(b['ops']) for f in document['functions'] for b in f['blocks'])},sort_keys=True))


if __name__=='__main__':main()
