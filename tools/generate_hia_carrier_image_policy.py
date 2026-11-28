"""HIA owner for the bounded CPython native-image compatibility protocol.

Only the closed mechanical operations in ABI['operations'] are foreign. HIA
chooses their order, acquired-export mask, reverse release and terminal result.
The ordinary standalone HIA runtime does not depend on CPython or this adapter.
"""
from __future__ import annotations
import ast
import json
from hashlib import sha256
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "examples/hia_bootstrap/carrier_image_policy.hepta"
ABI_PATH = "hepta/hia_carrier_image_abi.json"
MAGIC = int.from_bytes(b"HIACIP01", "little")
REFUSAL = 0xfffffffd
OPERATIONS = {
 1:"retain_image_receiver",2:"unpack_six_positional_arguments",
 3:"observe_extent_exact_integer",4:"convert_extent_unsigned",
 5:"acquire_one_writable_c_contiguous_export",6:"call_borrowed_image_without_gil",
 7:"release_one_export",8:"box_unsigned_result",9:"release_image_receiver",
 10:"raise_fixed_exception",11:"unpack_buffer_constructor",
 12:"observe_initial_exact_type",13:"observe_initial_bytes_length",
 14:"observe_capacity_exact_type",15:"convert_signed_capacity",
 16:"allocate_zeroed_buffer",17:"copy_initial_bytes",
 18:"unpack_image_constructor",19:"observe_image_exact_bytes",
 20:"allocate_image_and_private_rw_mapping",21:"copy_image_bytes",
 22:"protect_mapping_rx",23:"release_partial_result",
}
SOURCE = r'''
def carrier_image(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 64 or length(o) != 32 or length(w) != 256:
        return REFUSAL
    if word(s, 0) != MAGIC or word(s, 56) != 0:
        return REFUSAL
    mode = word(s, 8)
    if mode < 1 or mode > 3:
        return REFUSAL
    if get(w, 0) == 0:
        if zero(w, 0, 256) != 1:
            return REFUSAL
        if word(s, 16) != 0 or word(s, 24) != 0 or word(s, 32) != 0 or word(s, 40) != 0 or word(s, 48) != 0:
            return REFUSAL
        put(w, 0, MAGIC)
        put(w, 8, mode)
        if mode == 1:
            return ask(o, w, 1, 0, 0, 1)
        if mode == 2:
            return ask(o, w, 11, 0, 0, 20)
        return ask(o, w, 18, 0, 0, 40)
    if get(w, 0) != MAGIC or get(w, 8) != mode or get(w, 104) != 0:
        return REFUSAL
    if word(s, 16) != get(w, 16) or word(s, 24) != get(w, 24):
        return REFUSAL
    if word(s, 32) > 1 or get(w, 40) > 3 or get(w, 48) > 3 or get(w, 56) > 1 or get(w, 112) > 1:
        return REFUSAL
    pc = get(w, 32)
    if expected(mode, pc) == 0 or expected(mode, pc) != get(w, 24):
        return REFUSAL
    if word(s, 32) == 1:
        if pc == 1 or pc == 7 or pc == 9 or pc == 29 or pc == 45:
            return REFUSAL
        put(w, 56, 1)
        if mode == 1:
            return unwind(o, w)
        if (pc == 27 or pc == 42) and word(s, 48) != 0:
            if word(s, 48) != 1:
                return REFUSAL
            put(w, 112, 1)
        if get(w, 112) == 1:
            if mode == 2:
                return ask(o, w, 23, 0, 0, 29)
            return ask(o, w, 23, 0, 0, 45)
        return done(o, w)
    if pc == 10 or pc == 30 or pc == 46:
        return REFUSAL
    if mode == 1:
        return invoke(s, o, w)
    if mode == 2:
        return buffer_new(s, o, w)
    return image_new(s, o, w)

def expected(mode:u64, pc:u64) -> u64:
    if mode == 1:
        if pc >= 1 and pc <= 10:
            return pc
        return 0
    if mode == 2:
        if pc >= 20 and pc <= 22:
            return pc - 9
        if pc == 23:
            return 14
        if pc == 24 or pc == 25:
            return 15
        if pc == 27:
            return 16
        if pc == 28:
            return 17
        if pc == 29:
            return 23
        if pc == 30:
            return 10
        return 0
    if pc >= 40 and pc <= 44:
        return pc - 22
    if pc == 45:
        return 23
    if pc == 46:
        return 10
    return 0

def invoke(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    x = word(s, 40)
    if pc == 1:
        put(w, 112, 1)
        return ask(o, w, 2, 0, 0, 2)
    if pc == 2:
        return ask(o, w, 3, 0, 0, 3)
    if pc == 3:
        if x > 1:
            return REFUSAL
        if x == 0:
            return ask(o, w, 10, 2, 0, 10)
        return ask(o, w, 4, get(w, 48), 0, 4)
    if pc == 4:
        put(w, 80 + get(w, 48) * 8, x)
        return ask(o, w, 5, get(w, 48), 0, 5)
    if pc == 5:
        put(w, 40, get(w, 40) + 1)
        if x >= 9223372036854775808 or get(w, 80 + get(w, 48) * 8) > x:
            return ask(o, w, 10, 3, 0, 10)
        put(w, 48, get(w, 48) + 1)
        if get(w, 48) < 3:
            return ask(o, w, 3, get(w, 48), 0, 3)
        return ask(o, w, 6, 0, 0, 6)
    if pc == 6:
        put(w, 72, x)
        return unwind(o, w)
    if pc == 7:
        if get(w, 40) == 0:
            return REFUSAL
        put(w, 40, get(w, 40) - 1)
        return unwind(o, w)
    if pc == 8:
        return ask(o, w, 9, 0, 0, 9)
    if pc == 9:
        put(w, 112, 0)
        return done(o, w)
    return REFUSAL

def unwind(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 40) != 0:
        return ask(o, w, 7, get(w, 40) - 1, 0, 7)
    if get(w, 56) == 1:
        if get(w, 112) == 1:
            return ask(o, w, 9, 0, 0, 9)
        return done(o, w)
    return ask(o, w, 8, get(w, 72), 0, 8)

def buffer_new(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    x = word(s, 40)
    if pc == 20:
        if x < 1 or x > 2:
            return REFUSAL
        put(w, 128, x)
        return ask(o, w, 12, 0, 0, 21)
    if pc == 21:
        if x == 1:
            return ask(o, w, 13, 0, 0, 22)
        if x == 2 and get(w, 128) == 1:
            return ask(o, w, 15, 0, 0, 24)
        return ask(o, w, 10, 5, 0, 30)
    if pc == 22:
        if x >= 9223372036854775808:
            return REFUSAL
        put(w, 80, x)
        return ask(o, w, 14, 0, 0, 23)
    if pc == 23:
        if x == 0:
            if get(w, 80) == 9223372036854775807:
                return ask(o, w, 10, 9, 0, 30)
            put(w, 88, get(w, 80) + 1)
            return ask(o, w, 16, get(w, 88), get(w, 80), 27)
        if x == 1:
            return ask(o, w, 15, 1, 0, 25)
        return ask(o, w, 10, 6, 0, 30)
    if pc == 24 or pc == 25:
        if x >= 9223372036854775808 or x < get(w, 80):
            return ask(o, w, 10, 7, 0, 30)
        put(w, 88, x)
        return ask(o, w, 16, x, get(w, 80), 27)
    if pc == 27:
        put(w, 112, 1)
        if get(w, 80) == 0:
            return done(o, w)
        return ask(o, w, 17, get(w, 80), 0, 28)
    if pc == 28:
        return done(o, w)
    if pc == 29:
        put(w, 112, 0)
        return done(o, w)
    return REFUSAL

def image_new(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    x = word(s, 40)
    if pc == 40:
        return ask(o, w, 19, 0, 0, 41)
    if pc == 41:
        if x != 1 or word(s, 48) == 0 or word(s, 48) > 1048576:
            return ask(o, w, 10, 8, 0, 46)
        put(w, 80, word(s, 48))
        return ask(o, w, 20, get(w, 80), 0, 42)
    if pc == 42:
        put(w, 112, 1)
        return ask(o, w, 21, get(w, 80), 0, 43)
    if pc == 43:
        return ask(o, w, 22, get(w, 80), 0, 44)
    if pc == 44:
        return done(o, w)
    if pc == 45:
        put(w, 112, 0)
        return done(o, w)
    return REFUSAL

def ask(o:mutbuf, w:mutbuf, action:u64, a:u64, b:u64, pc:u64) -> u32:
    put(w, 16, get(w, 16) + 1)
    put(w, 24, action)
    put(w, 32, pc)
    put(o, 0, action)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, 0)
    return 1

def done(o:mutbuf, w:mutbuf) -> u32:
    put(w, 104, 1)
    put(w, 24, 0)
    put(o, 0, 0)
    put(o, 8, get(w, 56))
    put(o, 16, 0)
    put(o, 24, 0)
    return 0

def word(s:readbuf, at:u64) -> u64:
    n = 0
    i = 0
    while i < 8:
        n = n | (byte(s, at + i) << (i * 8))
        i = i + 1
    return n

def get(w:mutbuf, at:u64) -> u64:
    n = 0
    i = 0
    while i < 8:
        n = n | (byte(w, at + i) << (i * 8))
        i = i + 1
    return n

def put(w:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (n >> (i * 8)) & 255)
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(w, at + i) != 0:
            return 0
        i = i + 1
    return 1
'''
def document():
    class Constants(ast.NodeTransformer):
        def visit_Name(self,node):
            values={"MAGIC":MAGIC,"REFUSAL":REFUSAL}
            return ast.copy_location(ast.Constant(values[node.id]),node) if node.id in values else node
    nodes=ast.fix_missing_locations(Constants().visit(ast.parse(SOURCE))).body
    names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total)
        b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(v) for v in b.params],
                              returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    return compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="carrier_image_policy",functions=functions))
def generated_files():
    raw=render_assembly(document()).encode()
    abi=dict(schema="hepta.hia.cpython-image-foreign-abi.v1",source=SOURCE_PATH,source_sha256=sha256(raw).hexdigest(),
             magic="HIACIP01",request_bytes=64,response_bytes=32,state_bytes=256,refusal=REFUSAL,
             modes={"invoke":1,"buffer_new":2,"image_new":3},operations=OPERATIONS,
             extension_domain="CPYTHON_GIL_LINUX_X86_64_LP64_COMPATIBILITY",
             standalone_cpython_dependency=False,arbitrary_c_api_calls=False,
             default_worker_qualification_claimed=False)
    return {SOURCE_PATH:raw,ABI_PATH:(json.dumps(abi,sort_keys=True,indent=2)+"\n").encode()}
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser();p.add_argument("--check",action="store_true");args=p.parse_args()
    for name,raw in generated_files().items():
        path=ROOT/name
        if args.check:
            if path.read_bytes()!=raw:raise SystemExit("generated carrier policy differs: "+name)
        else:path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        print(name,len(raw),sha256(raw).hexdigest())
