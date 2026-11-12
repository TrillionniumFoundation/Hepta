"""New four-role HIA publication for fixed DMS7 / Map3 / memory1 / FS5.
All four images and this new assembly template are independently pinned. This
publishes bytes only; it never chooses a namespace node or SQL operation.
This new packer has not been generated/compiled/executed yet.
"""
from __future__ import annotations
import ast,struct
from hashlib import sha256
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions

MAGIC=int.from_bytes(b"HIANPXJ1","little")
EXECUTOR_SOURCE_SHA256="308b3b0f9d785e71493def82a43ceb4d8aa2891e79ef73e63a4d620657900406"
MAX_IMAGE=1<<20

def prefix_and_table(source,binary,layout):
    assert sha256(source).hexdigest()==EXECUTOR_SOURCE_SHA256
    assert layout["source_sha256"]==EXECUTOR_SOURCE_SHA256
    assert len(binary)==layout["template_bytes"] and sha256(binary).hexdigest()==layout["template_sha256"]
    assert layout["entry"]==0 and layout["end"]==len(binary) and layout["relocation_count"]==0
    table=layout["image_table"]
    assert 0<=table<=len(binary)-40 and table%16==0 and binary[table:table+40]==bytes(40)
    header=(b"\x7fELF\x02\x01\x01"+bytes(9)
       +struct.pack("<HHIQQQIHHHHHH",2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
       +struct.pack("<IIQQQQQQ",1,5,0,0x400000,0x400000,0,0,4096)
       +struct.pack("<IIQQQQQQ",0x6474e551,6,0,0,0,0,0,16))
    assert len(header)==176
    return header+binary,176+table

def source_program(prefix,table):
    assert 0<=table<=len(prefix)-40 and prefix[table:table+40]==bytes(40)
    start=(len(prefix)+15)&~15
    text=f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 160 or length(s) > {64+4*(24+MAX_IMAGE)}:
        return 4294967295
    if read64(s, 0) != {MAGIC} or read64(s, 8) != 1 or read64(s, 16) != 4:
        return 4294967295
    if read64(s, 24) != length(s):
        return 4294967295
    at = 32
    while at < 64:
        if read64(s, at) != 0:
            return 4294967295
        at = at + 8
    first = 64
"""
    for role,label in ((1,"first"),(2,"second"),(3,"third"),(4,"fourth")):
        text+=f"""    if {label} > length(s) or length(s) - {label} < 24:
        return 4294967295
    if read64(s, {label}) != {role} or read64(s, {label} + 16) != 0:
        return 4294967295
    size{role} = read64(s, {label} + 8)
    if size{role} == 0 or size{role} > {MAX_IMAGE} or size{role} > length(s) - {label} - 24:
        return 4294967295
"""
        if role<4:text+=f"    {('second','third','fourth')[role-1]} = {label} + 24 + size{role}\n"
    text+=f"""    if fourth + 24 + size4 != length(s):
        return 4294967295
    pos1 = {start}
    pos2 = (pos1 + size1 + 15) & 18446744073709551600
    pos3 = (pos2 + size2 + 15) & 18446744073709551600
    pos4 = (pos3 + size3 + 15) & 18446744073709551600
    total = pos4 + size4
    if length(o) < total:
        return 4294967294
"""
    for number,_ in enumerate(range(0,len(prefix),256)):text+=f"    literal_{number}(o)\n"
    text+=f"""    put(o, 96, total)
    put(o, 104, total)
    put(o, {table+8}, 4194304 + pos1)
    put(o, {table+16}, 4194304 + pos2)
    put(o, {table+24}, 4194304 + pos3)
    put(o, {table+32}, 4194304 + pos4)
    at = {len(prefix)}
    while at < pos1:
        store(o, at, 0)
        at = at + 1
    copy_input(o, s, pos1, first + 24, size1)
    at = pos1 + size1
    while at < pos2:
        store(o, at, 0)
        at = at + 1
    copy_input(o, s, pos2, second + 24, size2)
    at = pos2 + size2
    while at < pos3:
        store(o, at, 0)
        at = at + 1
    copy_input(o, s, pos3, third + 24, size3)
    at = pos3 + size3
    while at < pos4:
        store(o, at, 0)
        at = at + 1
    copy_input(o, s, pos4, fourth + 24, size4)
    return total
"""
    for number,first in enumerate(range(0,len(prefix),256)):
        text+=f"\ndef literal_{number}(o:mutbuf) -> u64:\n"
        end=min(first+256,len(prefix))
        for at in range(first,end,8):
            raw=prefix[at:min(at+8,end)]
            if len(raw)==8:text+=f"    put(o, {at}, {int.from_bytes(raw,'little')})\n"
            else:
                for offset,value in enumerate(raw,at):text+=f"    store(o, {offset}, {value})\n"
        text+="    return 0\n"
    return text+VALUES[VALUES.index("\ndef read64("):]

def document(prefix,table):
    nodes=ast.parse(source_program(prefix,table)).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    assert len(names)==len(nodes)
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(v) for v in b.params],
            returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    return compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="namespace_dms_map_native_packer",functions=functions))
