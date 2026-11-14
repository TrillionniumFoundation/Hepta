"""Author the optional discovery expression's claim/ACK HIA controller."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from hepta import cli, hia_opcodes
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cli_discovery_facts import observation
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

SOURCE_NAME='examples/hia_bootstrap/cli_discovery_routing.hepta'
MAGIC=int.from_bytes(b'HCLROUT1','little')
STATE=int.from_bytes(b'HCLSTAT1','little')
COMMAND=int.from_bytes(b'HCLCMD01','little')

SOURCE=r'''
def route(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 2048 or length(o) < 128 or length(s) < 128:
        return 199
    if read64(s, 0) != MAGIC:
        return refuse(w)
    command = read64(s, 8)
    nonce = read64(s, 16)
    if nonce == 0 or command > 5:
        return refuse(w)
    if command == 0:
        if get(w, 0) != 0 or length(s) != 128:
            return refuse(w)
        i = 0
        while i < 2048:
            store(w, i, 0)
            i = i + 1
        put(w, 0, STATE)
        put(w, 48, read64(s, 48))
        put(w, 56, nonce)
        profile = read64(s, 56)
        if profile != 312 and profile != 314 and profile != 31410:
            return refuse(w)
        put(w, 184, profile)
        action = get(w, 48)
        if action < 1 or action > 15:
            return refuse(w)
        if action != 1 and action != 2:
            return done(o, w, 3)
        if action == 2:
            return ask(o, w, 1, 2, 0, 0, 0, 0)
        return ask(o, w, 3, 10, 0, 0, 0, 0)
    if get(w, 0) != STATE or nonce != get(w, 56):
        return refuse(w)
    if command == 5:
        if length(s) != 128 or get(w, 8) < 100 or get(w, 8) > 114:
            return refuse(w)
        error = get(w, 120)
        put(w, 120, 0)
        emit_command(o, w)
        put(o, 64, error)
        return 4
    if command == 4:
        if length(s) != 128 or get(w, 40) != 2:
            return refuse(w)
        put(w, 40, 0)
        put(w, 200, 0)
        return retire_next(o, w)
    if get(w, 40) != 0:
        return refuse(w)
    if read64(s, 24) != get(w, 16) or read64(s, 32) != get(w, 24) or get(w, 24) == 0:
        return refuse(w)
    if command == 3:
        if length(s) != 128 or get(w, 32) != 1:
            return refuse(w)
        put(w, 40, 2)
        put(w, 176, 4)
        emit_command(o, w)
        return 5
    if command == 2:
        if get(w, 32) != 0 or length(s) != 128:
            return refuse(w)
        put(w, 32, 1)
        emit_command(o, w)
        return 3
    if get(w, 32) != 1 or read64(s, 40) > 1:
        return refuse(w)
    phase = get(w, 8)
    operation = get(w, 24)
    put(w, 24, 0)
    put(w, 32, 0)
    if read64(s, 40) == 1:
        if phase >= 100 or read64(s, 48) == 0:
            return refuse(w)
        put(w, 120, read64(s, 48))
        return ask(o, w, 3, 101, 0, 0, 0, 0)
    a = read64(s, 48)
    b = read64(s, 56)
    if phase == 2:
        put(w, 168, 1)
        return ask(o, w, 2, 3, 0, 0, 0, 0)
    if phase == 3:
        if a == 0:
            return refuse(w)
        put(w, 88, a)
        put(w, 160, a)
        return ask(o, w, 3, 10, 0, 0, 0, 0)
    if phase == 10:
        if a == 0:
            return refuse(w)
        put(w, 80, a)
        if get(w, 48) == 1:
            return ask(o, w, 4, 11, a, 0, 0, 0)
        return ask(o, w, 5, 12, a, 0, 0, 0)
    if phase == 11 or phase == 12:
        if a == 0 or b == 0:
            return refuse(w)
        put(w, 80, a)
        if phase == 11:
            put(w, 88, b)
        else:
            put(w, 96, b)
        return ask(o, w, 6, 13, get(w, 80), get(w, 88), get(w, 96), 0)
    if phase == 13:
        if standard(s, w):
            return ask(o, w, 7, 14, 0, 0, 0, 0)
        if get(w, 48) == 1:
            return ask(o, w, 8, 90, get(w, 80), get(w, 88), 0, 0)
        return ask(o, w, 9, 90, get(w, 80), get(w, 88), get(w, 96), 0)
    if phase == 14:
        if a == 0:
            return refuse(w)
        put(w, 104, a)
        if get(w, 48) == 1:
            return ask(o, w, 10, 15, 0, 0, 0, 0)
        return ask(o, w, 11, 15, get(w, 96), 0, 0, 0)
    if phase == 15:
        if a == 0:
            return refuse(w)
        return ask(o, w, 12, 90, get(w, 104), a, 0, 0)
    if phase == 90:
        return done(o, w, 0)
    if phase == 101:
        if a == 0:
            return refuse(w)
        put(w, 80, a)
        return ask(o, w, 13, 102, a, 0, 0, 0)
    if phase == 102:
        if a == 0 or b == 0:
            return refuse(w)
        put(w, 80, a)
        return ask(o, w, 14, 103, a, b, get(w, 120), 0)
    if phase == 103:
        if a == 0 or b == 0:
            return refuse(w)
        put(w, 80, a)
        put(w, 152, b)
        return ask(o, w, 15, 104, 0, 0, 0, 0)
    if phase == 104:
        if a == 0:
            return refuse(w)
        put(w, 128, a)
        return ask(o, w, 15, 105, 0, 0, 0, 0)
    if phase == 105:
        if a == 0:
            return refuse(w)
        put(w, 136, a)
        return ask(o, w, 16, 106, 0, 0, 0, 0)
    if phase == 106:
        if a == 0:
            return refuse(w)
        put(w, 144, a)
        return ask(o, w, 17, 107, get(w, 136), 3, 7, 1)
    if phase == 107:
        return ask(o, w, 17, 108, get(w, 136), 4, get(w, 152), 0)
    if phase == 108:
        return ask(o, w, 17, 109, get(w, 136), 5, 8, 1)
    if phase == 109:
        return ask(o, w, 18, 110, get(w, 144), get(w, 136), 0, 0)
    if phase == 110:
        return ask(o, w, 17, 111, get(w, 128), 0, 9, 1)
    if phase == 111:
        return ask(o, w, 17, 112, get(w, 128), 1, 6, 1)
    if phase == 112:
        return ask(o, w, 17, 113, get(w, 128), 2, get(w, 144), 0)
    if phase == 113:
        return ask(o, w, 19, 114, get(w, 80), get(w, 128), 0, 0)
    if phase == 114:
        return done(o, w, 2)
    if phase == 200:
        put(w, 200, get(w, 200) + 1)
        return retire_next(o, w)
    return refuse(w)

def retire_next(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 200)
    while index < 16:
        if index < 9:
            handle = get(w, retire_slot(index))
            if index == 7 and get(w, 48) == 2:
                handle = 0
            if handle != 0:
                return ask(o, w, 20, 200, handle, 0, 0, 0)
        elif get(w, 48) == 2:
            named = index - 9
            if get(w, 184) != 312:
                named = 6 - named
            if named == 6:
                handle = get(w, 160)
                if handle != 0:
                    return ask(o, w, 20, 200, handle, 0, 0, 0)
            elif get(w, 168) == 1:
                return ask(o, w, 21, 200, named, 0, 0, 0)
        index = index + 1
        put(w, 200, index)
    put(w, 40, 1)
    put(w, 24, 0)
    emit_command(o, w)
    put(o, 64, get(w, 176))
    return 2

def retire_slot(index:u64) -> u64:
    if index == 0:
        return 152
    if index == 1:
        return 144
    if index == 2:
        return 136
    if index == 3:
        return 128
    if index == 4:
        return 104
    if index == 5:
        return 96
    if index == 6:
        return 80
    if index == 7:
        return 88
    return 120

def standard(s:readbuf, w:mutbuf) -> bool:
    if read64(s, 48) != 1:
        return False
    action = get(w, 48)
    i = 0
    while i < 4:
        if read64(s, 80 + i * 8) != expected(action, i):
            return False
        i = i + 1
    n = read64(s, 112)
    if action == 1:
        return n == 0 and length(s) == 128
    if n != 20 or length(s) != 148:
        return False
    i = 0
    while i < 19:
        if byte(s, 128 + i) != prefix(i):
            return False
        i = i + 1
    return byte(s, 147) >= 49 and byte(s, 147) <= 56

def ask(o:mutbuf, w:mutbuf, operation:u64, phase:u64, a:u64, b:u64, c:u64, d:u64) -> u32:
    put(w, 8, phase)
    put(w, 16, get(w, 16) + 1)
    put(w, 24, operation)
    put(w, 32, 0)
    put(w, 256, a)
    put(w, 264, b)
    put(w, 272, c)
    put(w, 280, d)
    emit_command(o, w)
    return 1

def emit_command(o:mutbuf, w:mutbuf) -> u64:
    i = 0
    while i < 128:
        store(o, i, 0)
        i = i + 1
    put(o, 0, COMMAND)
    put(o, 8, get(w, 16))
    put(o, 16, get(w, 24))
    put(o, 24, choose(get(w, 8) < 100, 1, 0))
    put(o, 32, get(w, 256))
    put(o, 40, get(w, 264))
    put(o, 48, get(w, 272))
    put(o, 56, get(w, 280))
    return 0

def done(o:mutbuf, w:mutbuf, result:u64) -> u32:
    put(w, 40, 2)
    put(w, 176, result)
    put(w, 24, 0)
    emit_command(o, w)
    put(o, 64, result)
    return 2

def refuse(w:mutbuf) -> u32:
    put(w, 40, 1)
    put(w, 24, 0)
    return 199

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

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


def source_program():
    facts=[]
    for action,provider,module in ((1,cli.agent_capabilities,None),(2,hia_opcodes.opcode_catalog,hia_opcodes)):
        errors=[]
        value=observation(action,cli,cli.output_json,provider,module,diagnostics=errors)
        if value is None:raise ValueError('standard-provider authoring facts refused: '+repr(errors))
        facts.append({'action':action,'bytes':len(value[0]),'sha256':value[1].hex()})
    lines=['def expected(action:u64, index:u64) -> u64:']
    for row in facts:
        lines.append('    if action == '+str(row['action'])+':')
        for index,word in enumerate(struct.unpack('<4Q',bytes.fromhex(row['sha256']))):
            lines += ['        if index == '+str(index)+':','            return '+str(word)]
    lines.append('    return 0')
    lines.append('def prefix(index:u64) -> u64:')
    for index,value in enumerate(b'hepta.hia.program.v'):
        lines += ['    if index == '+str(index)+':','        return '+str(value)]
    lines.append('    return 0')
    symbols={'MAGIC':MAGIC,'STATE':STATE,'COMMAND':COMMAND}
    class Replace(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(symbols[node.id]),node) if node.id in symbols else node
    tree=Replace().visit(ast.parse(SOURCE+'\n'+'\n'.join(lines)+'\n'))
    return ast.unparse(ast.fix_missing_locations(tree))+'\n',facts


def document():
    source,facts=source_program();nodes=ast.parse(source).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'cli_discovery_routing','functions':functions}),facts


def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args(argv)
    document_value,facts=document();raw=render_assembly(document_value).encode()
    target=ROOT/SOURCE_NAME
    if args.check:
        if target.read_bytes()!=raw:raise ValueError('discovery routing generated bytes differ')
    else:target.write_bytes(raw)
    print(json.dumps({'source':SOURCE_NAME,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                      'functions':len(document_value['functions']),
                      'blocks':sum(len(f['blocks']) for f in document_value['functions']),
                      'ops':sum(len(b['ops']) for f in document_value['functions'] for b in f['blocks']),
                      'facts':facts},sort_keys=True))


if __name__=='__main__':main()
