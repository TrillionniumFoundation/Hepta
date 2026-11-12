"""New nine-role HIA publication for the actual UnixOpen raw-FS issuer.
Roles1..6 retain the existing FS9/DMS10 shared namespace closure. Roles7..9
are the actual parent, raw-effect framer and private issuance coordinator.
This publishes bytes only. No source generation/B3/VM/native execution yet.
"""
from __future__ import annotations
import ast,struct
from hashlib import sha256
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions

MAGIC=int.from_bytes(b"HIAUIPK1","little")
EXECUTOR_SOURCE_SHA256="b541018b4b349a1567fb9f52eb15b7494b40eceb584a88e217ddc8db391625fb"
MAX_IMAGE=1<<20

def prefix_and_table(source,binary,layout):
    assert sha256(source).hexdigest()==EXECUTOR_SOURCE_SHA256
    assert layout["source_sha256"]==EXECUTOR_SOURCE_SHA256
    assert len(binary)==layout["template_bytes"] and sha256(binary).hexdigest()==layout["template_sha256"]
    assert layout["entry"]==0 and layout["end"]==len(binary) and layout["relocation_count"]==0
    table=layout["image_table"]
    assert 0<=table<=len(binary)-80 and table%16==0 and binary[table:table+80]==bytes(80)
    header=(b"\x7fELF\x02\x01\x01"+bytes(9)
       +struct.pack("<HHIQQQIHHHHHH",2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
       +struct.pack("<IIQQQQQQ",1,5,0,0x400000,0x400000,0,0,4096)
       +struct.pack("<IIQQQQQQ",0x6474e551,6,0,0,0,0,0,16))
    assert len(header)==176
    return header+binary,176+table

def source_program(prefix,table):
    assert 0<=table<=len(prefix)-80 and prefix[table:table+80]==bytes(80)
    start=(len(prefix)+15)&~15
    # The exact pinned template is small; this assertion proves every computed
    # output offset and the u32 return fit without introducing an input quota.
    assert start+9*(MAX_IMAGE+15)<1<<32
    text=f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 280 or length(s) > {64+9*(24+MAX_IMAGE)}:
        return 4294967295
    if read64(s, 0) != {MAGIC} or read64(s, 8) != 1 or read64(s, 16) != 9:
        return 4294967295
    if read64(s, 24) != length(s):
        return 4294967295
    at = 32
    while at < 64:
        if read64(s, at) != 0:
            return 4294967295
        at = at + 8
    total = checked_total(s)
    if total == 0:
        return 4294967295
    if length(o) < total:
        return 4294967294
"""
    for number,_ in enumerate(range(0,len(prefix),256)):
        text+=f"    literal_{number}(o)\n"
    text+=f"""    put(o, 96, total)
    put(o, 104, total)
    publish_tables(s, o)
    publish_images(s, o)
    return total

def checked_total(s:readbuf) -> u64:
    role = 1
    at = 64
    total = {start}
    while role <= 9:
        if at > length(s) or length(s) - at < 24:
            return 0
        if read64(s, at) != role or read64(s, at + 16) != 0:
            return 0
        size = read64(s, at + 8)
        if size == 0 or size > {MAX_IMAGE} or size > length(s) - at - 24:
            return 0
        total = ((total + 15) & 18446744073709551600) + size
        at = at + 24 + size
        role = role + 1
    if at != length(s):
        return 0
    return total

def publish_tables(s:readbuf, o:mutbuf) -> u64:
    role = 1
    at = 64
    total = {start}
    while role <= 9:
        pos = (total + 15) & 18446744073709551600
        put(o, {table} + role * 8, 4194304 + pos)
        size = read64(s, at + 8)
        total = pos + size
        at = at + 24 + size
        role = role + 1
    return 0

def publish_images(s:readbuf, o:mutbuf) -> u64:
    role = 1
    at = 64
    end = {len(prefix)}
    while role <= 9:
        pos = (end + 15) & 18446744073709551600
        while end < pos:
            store(o, end, 0)
            end = end + 1
        size = read64(s, at + 8)
        copy_input(o, s, pos, at + 24, size)
        end = pos + size
        at = at + 24 + size
        role = role + 1
    return 0
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
    return compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="namespace_unixopen_issued_native_packer",functions=functions))
