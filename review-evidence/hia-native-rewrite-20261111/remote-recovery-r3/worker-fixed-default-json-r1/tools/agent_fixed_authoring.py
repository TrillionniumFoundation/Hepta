"""Retained bounded HIA authoring adapter for a fixed three-buffer entry.

Development authoring only. Runtime control and ELF construction are HIA.
No compiler/verifier budget, grammar or admission behavior is changed.
"""
from __future__ import annotations
import ast,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder

def profile(value):
    fs=value['functions']
    row=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(actual<=limit for actual,limit in zip(row.values(),(128,1536,8192,256,16))),row
    return row

def document(source,module):
    nodes=ast.parse(source).body
    assert nodes and all(isinstance(node,ast.FunctionDef) for node in nodes)
    names={node.name:'f'+str(i+1) for i,node in enumerate(nodes)}
    assert len(names)==len(nodes)
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id)
        for node in nodes}
    assert signatures[nodes[0].name]==(['readbuf','mutbuf','mutbuf'],'u32')
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
            dict(op='call',args=['v0','v1','v2'],out=[dict(name='v3',type='u32')],
                 attrs=dict(function=names[nodes[0].name]))],
                 term=dict(op='ret',values=['v3']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module=module,functions=functions))
    profile(value);verify_program(value)
    return value
