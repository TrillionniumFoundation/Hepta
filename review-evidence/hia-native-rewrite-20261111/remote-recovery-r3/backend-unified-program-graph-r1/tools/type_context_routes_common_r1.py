"""Native continuation contract for the issued type-error result.

This module supplies HIA text and authoring constants only.  The 128-byte
HIATDE01 header is never rebound or rebuilt by either parent.  It remains the
actual reader output from the immutable type workspace and completed command.
"""
from __future__ import annotations
import ast,copy
from hashlib import sha256

RESULT=int.from_bytes(b"HIATDE01","little")
COMMAND=int.from_bytes(b"HIATDC01","little")
CONTEXT=int.from_bytes(b"HIATDX01","little")
CONTEXT_AT=96*1024*1024+192

HEADER=r'''
def tcx_error(code:u64) -> u64:
    if code == 1 or code == 5 or code == 6:
        return 1
    return 0

def tcx_node(node:u64) -> u64:
    if node == MAX:
        return 1
    base = 33554432
    if node >= 67108864:
        base = 67108864
    if node < base + 64 or node > base + 33554432 - 56:
        return 0
    value = node - base - 64
    bits = 64
    remainder = 0
    while bits != 0:
        bits = bits - 1
        remainder = (remainder << 1) | ((value >> bits) & 1)
        if remainder >= 56:
            remainder = remainder - 56
    if remainder != 0:
        return 0
    return 1

def tcx_header(w:mutbuf, at:u64, lease:u64, error:u64, request:u64, extent:u64) -> u64:
    if lease == 0 or request == 0 or tcx_error(error) == 0:
        return 0
    if extent < 129 or extent > TC_MAX_EXTENT:
        return 0
    if get(w, at) != TC_RESULT or get(w, at + 8) != 1 or get(w, at + 16) != lease:
        return 0
    if get(w, at + 24) == 0 or get(w, at + 32) != request or get(w, at + 48) != error:
        return 0
    operation = get(w, at + 40)
    if operation < 1 or operation > 6:
        return 0
    size = tcx_size(error, get(w, at + 56), get(w, at + 64))
    if size == 0 or get(w, at + 80) != size or get(w, at + 88) != 128 + size or extent != 128 + size:
        return 0
    node = get(w, at + 72)
    if tcx_node(node) == 0 or (error != 1 and node == MAX):
        return 0
    active = get(w, at + 104)
    if active > MAX - 16 or get(w, at + 96) > MAX - 16 - active:
        return 0
    if get(w, at + 120) != 0:
        return 0
    return 1

def tcx_copy(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    index = 0
    while index < count:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return 0
'''

def definitions(reader):
    rows=reader.catalog()
    assert len(rows)==33 and len({(r["code"],r["where"],r["mask"]) for r in rows})==33
    lines=["def tcx_size(code:u64, where:u64, mask:u64) -> u64:"]
    for row in rows:
        lines.extend([f'    if code == {row["code"]} and where == {row["where"]} and mask == {row["mask"]}:',
                      f'        return {len(row["text"])}'])
    lines.append("    return 0")
    constants=dict(TC_RESULT=RESULT,TC_COMMAND=COMMAND,TC_CONTEXT=CONTEXT,
        TC_CONTEXT_AT=CONTEXT_AT,TC_MAX_EXTENT=128+max(len(r["text"]) for r in rows),
        TC_READER=50,TC_SLOT=57,TC_COMMAND_SLOT=58,
        TC_NATIVE=30000,TC_SNAPSHOT=30064,TC_RENDER=30128,
        TC_NEEDED=30256,TC_ACTIVE=30264,TC_EXPECT_LEASE=30272,
        TC_EXPECT_ERROR=30280,TC_EXPECT_REQUEST=30288,
        TC_PARENT_HEADER=30304)
    assert constants["TC_NATIVE"]+64==constants["TC_SNAPSHOT"]
    assert constants["TC_SNAPSHOT"]+64==constants["TC_RENDER"]
    assert constants["TC_RENDER"]+128==constants["TC_NEEDED"]
    assert constants["TC_PARENT_HEADER"]+128<32768
    return HEADER+"\n"+"\n".join(lines)+"\n",constants,rows

def functions(text):
    tree=ast.parse(text)
    assert all(isinstance(n,ast.FunctionDef) for n in tree.body)
    result={n.name:n for n in tree.body}
    assert len(result)==len(tree.body)
    return result

def unique_replace(text,before,after):
    assert text.count(before)==1,(before,text.count(before))
    return text.replace(before,after,1)

def expand(text,constants):
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(ast.parse(text)))
    return ast.unparse(tree)+"\n"

def changed_inventory(before,after,allowed):
    old=functions(before);new=functions(after)
    assert set(old)<=set(new)
    actual={name for name in old if ast.dump(old[name],include_attributes=False)!=
                                      ast.dump(new[name],include_attributes=False)}
    assert actual==set(allowed),(actual,allowed)
    return dict(changed=sorted(actual),added=sorted(set(new)-set(old)),
                all_other_method_AST_exact=True)
