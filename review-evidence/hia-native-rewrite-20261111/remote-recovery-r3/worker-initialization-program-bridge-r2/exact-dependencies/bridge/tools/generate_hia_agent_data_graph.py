"""Generate complete native Agent-data materialization, with explicit binary64 continuation."""
from __future__ import annotations
import ast,json
from hashlib import sha256
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_program import verify_program
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
import agent_data_graph_common as common
import agent_data_graph_values as values

def literal_functions():
    output=[]
    for name,raw in values.LITERALS.items():
        lines=['def dg_literal_'+name+'(w:mutbuf) -> u64:',
               '    base = DG_TEXT + dg_get(w, D_TEXT_SIZE)']
        offset=0
        while offset+8<=len(raw):
            lines.append('    dg_put(w, base + '+str(offset)+', '+str(int.from_bytes(raw[offset:offset+8],'little'))+')')
            offset+=8
        for index in range(offset,len(raw)):
            lines.append('    store(w, base + '+str(index)+', '+str(raw[index])+')')
        lines.extend(['    dg_put(w, D_TEXT_SIZE, dg_get(w, D_TEXT_SIZE) + '+str(len(raw))+')','    return 0'])
        output.append('\n'.join(lines))
    return '\n\n'.join(output)+'\n'

def source_program():
    body=common.COMMON+'\n'+values.VALUES+'\n'+literal_functions()
    tree=ast.parse(body)
    assert all(isinstance(n,ast.FunctionDef) for n in tree.body)
    assert len({n.name for n in tree.body})==len(tree.body)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in common.CONSTANTS:
                return ast.copy_location(ast.Constant(common.CONSTANTS[node.id]),node)
            return node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(tree)))+'\n'

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i+1) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
            dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
            dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],attrs=dict(function=names['dg_entry'])),
            dict(op='loan.end',args=['v3'],out=[],attrs={})],
            term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module='agent_data_graph',functions=functions))
    functions=value['functions']
    counts=(len(functions),sum(len(f['blocks']) for f in functions),
            sum(len(b['ops']) for f in functions for b in f['blocks']),
            max(len(f['blocks']) for f in functions),max(len(b['params']) for f in functions for b in f['blocks']))
    assert all(actual<=limit for actual,limit in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value)
    return value

if __name__=='__main__':
    value=document();raw=render_assembly(value).encode()
    target=ROOT/'examples/hia_bootstrap/agent_data_graph.hiaasm'
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():assert target.read_bytes()==raw,'Different frozen source already exists'
    else:target.write_bytes(raw)
    functions=value['functions']
    print(json.dumps(dict(path=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        functions=len(functions),blocks=sum(len(f['blocks']) for f in functions),
        instructions=sum(len(b['ops']) for f in functions for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in functions),
        max_block_parameters=max(len(b['params']) for f in functions for b in f['blocks']),
        scope='ISSUED_ARENA_VALUES_AND_ACTUAL_BINARY64_PEER_NOT_FULL_WORKER'),sort_keys=True),flush=True)
