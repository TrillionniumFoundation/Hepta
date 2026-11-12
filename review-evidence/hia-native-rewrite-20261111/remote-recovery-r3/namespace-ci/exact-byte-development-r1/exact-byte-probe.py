"""Standalone original/new exact-byte helper probes; newly authored, unexecuted.

Both probes retain the same wrapper and helper signatures. The native entry
uses control words in the mutable output operand; target read64 uses the
read-only operand, while get/put use the separate mutable workspace operand.
"""
from __future__ import annotations
import ast
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_namespace_exact_byte_helpers import OLD,transform
WRAPPER=r'''
def probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    operation = get(o, 0)
    index = get(o, 8)
    value = get(o, 16)
    result = 0
    if operation == 1:
        result = read64(s, index)
    elif operation == 2:
        result = get(w, index)
    elif operation == 3:
        result = put(w, index, value)
    else:
        return 1
    put(o, 24, result)
    return 0
'''
def source_program(optimized):
    if type(optimized) is not bool:
        raise ValueError("exact-byte probe needs a Boolean source revision")
    source=WRAPPER+OLD
    return transform(source) if optimized else source
def document(optimized):
    nodes=ast.parse(source_program(optimized)).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    if tuple(names)!=("probe","read64","get","put"):
        raise ValueError("exact-byte probe function inventory")
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=ObjectBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8",
        "module":"agent_namespace_exact_byte_probe_r1","functions":functions})
