"""Generate the complete selected-call control flow, without a hosted fallback.

Peer implementations and the fixed native coordinator remain separate owners.
Generation or component testing must never claim complete Worker execution.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT.parent
sys.path.insert(0,str(BASE/'Hepta-agent-edit-native'))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
import service_call_flow as flow
import service_call_unwind as unwind
import service_journal_bridge as bridge

def source_program():
    constants=dict(flow.CONSTANTS)
    assert not (set(constants)&set(unwind.CONSTANTS))
    constants.update(unwind.CONSTANTS)
    own=ast.parse(flow.BODY+'\n'+unwind.BODY).body
    prior={n.name:n for n in ast.parse(bridge.BODY).body if isinstance(n,ast.FunctionDef)}
    own.extend(prior[name] for name in ('word','get','put'))
    assert len({n.name for n in own})==len(own)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    tree=Expand().visit(ast.Module(body=own,type_ignores=[]))
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'

def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i+1) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
      blocks=[dict(id='b0',params=params,ops=[
        dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
        dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],attrs=dict(function=names['service_call'])),
        dict(op='loan.end',args=['v3'],out=[],attrs={})],
        term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module='agent_service_call',functions=functions))
    fs=value['functions']
    counts=(len(fs),sum(len(f['blocks']) for f in fs),sum(len(b['ops']) for f in fs for b in f['blocks']),
            max(len(f['blocks']) for f in fs),max(len(b['params']) for f in fs for b in f['blocks']))
    if any(a>b for a,b in zip(counts,(128,1536,8192,256,16))):
        raise ValueError(dict(original_compiler_limits_exceeded=counts))
    verify_program(value)
    return value

if __name__=='__main__':
    value=document()
    raw=render_assembly(value).encode()
    target=ROOT/'examples/hia_bootstrap/agent_service_call.hiaasm'
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
        assert target.read_bytes()==raw,'Do not overwrite a different frozen HIA revision'
    else:
        target.write_bytes(raw)
    fs=value['functions']
    print(json.dumps(dict(path=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest(),
      functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
      instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
      max_function_blocks=max(len(f['blocks']) for f in fs),
      max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']),
      scope='CONTROL_OWNER_DEVELOPMENT_NOT_NAMESPACE_OR_WHOLE_WORKER'),sort_keys=True),flush=True)
