"""Author bounded Agent u64/digest identity admission in ordinary HIA Core."""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
MAGIC=int.from_bytes(b'HIAIDP01','little')
RESULT_MAGIC=int.from_bytes(b'HIAIDR01','little')
SOURCE=r'''
def identity_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16:
        return 4294967293
    if read_word(s, 0) != @MAGIC@:
        return 4294967293
    kind = read_word(s, 8)
    if kind > 1:
        return context_policy(s, o, kind)
    if length(s) > 80:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    valid = 1
    value = 0
    size = length(s) - 16
    if kind == 0:
        if size == 0 or size > 20:
            valid = 0
        elif size > 1 and byte(s, 16) == 48:
            valid = 0
        index = 0
        while index < size and valid != 0:
            ch = byte(s, 16 + index)
            if ch < 48 or ch > 57:
                valid = 0
            else:
                digit = ch - 48
                if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
                    valid = 0
                else:
                    value = value * 10 + digit
            index = index + 1
    else:
        if size != 64:
            valid = 0
        index = 0
        while index < size and valid != 0:
            ch = byte(s, 16 + index)
            if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
                valid = 0
            index = index + 1
    if valid == 0:
        value = 0
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, valid)
    put(o, 16, value)
    return 24

def context_policy(s:readbuf, o:mutbuf, kind:u64) -> u32:
    decision = 0
    if kind == 2:
        if length(s) != 40:
            return 4294967293
        memory = read_word(s, 16)
        if memory < 67108864 or memory > 4294967296:
            decision = 1
        elif read_word(s, 32) > read_word(s, 24):
            decision = 2
    elif kind == 3:
        if length(s) != 48:
            return 4294967293
        tokens = read_word(s, 24)
        missing = read_word(s, 32)
        complete = read_word(s, 40)
        if missing > 7 or complete > 1 or ((missing & 1) != 0 and tokens != 0):
            return 4294967293
        if tokens > read_word(s, 16):
            decision = 3
        elif complete == 1 and missing != 0:
            decision = 4
    elif kind == 4:
        if length(s) > 524304 or (length(s) & 7) != 0:
            return 4294967293
        offset = 16
        total = 0
        while offset < length(s):
            size = read_word(s, offset)
            if size > 1048576:
                return 4294967293
            total = total + size
            offset = offset + 8
        if total > 33554432:
            decision = 5
    else:
        return 4294967293
    if length(o) < 24:
        return 4294967294
    put(o, 0, @RESULT_MAGIC@)
    put(o, 8, 1)
    put(o, 16, decision)
    return 24

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    count = 0
    while count < 8:
        value = value | (byte(s, index + count) << (count * 8))
        count = count + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(w, index + count, value >> (count * 8))
        count = count + 1
    return value
'''

def source_program():
    return SOURCE.replace('@MAGIC@',str(MAGIC)).replace('@RESULT_MAGIC@',str(RESULT_MAGIC))

def document():
    nodes=ast.parse(source_program()).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'agent_identity','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/agent_identity.hepta'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)


if __name__=='__main__':main()
