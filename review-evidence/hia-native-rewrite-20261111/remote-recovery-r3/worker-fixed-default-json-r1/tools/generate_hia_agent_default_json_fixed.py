"""Generate the fixed native default-JSON orchestration image.

NEW UNEXECUTED. The fixed eight-image table consists of the three complete
default controllers, preflight, original data decoder, complete DataGraph,
binary64 and this forwarding owner. No business schema is interpreted here.
"""
from __future__ import annotations
import ast,json,sys
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_program import verify_program
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
import agent_default_json_fixed_common as common
import agent_default_json_fixed_flow as flow
INTRINSICS={'byte','length','store','copy_bytes','fill_range','choose'}

def source_program():
    functions={}
    for source in (common.COMMON,flow.FLOW):
        for node in ast.parse(source).body:
            assert isinstance(node,ast.FunctionDef)
            assert node.name not in functions,node.name
            functions[node.name]=node
    reached=set();pending=['fd_entry']
    while pending:
        name=pending.pop()
        if name in reached:continue
        reached.add(name)
        for node in ast.walk(functions[name]):
            if isinstance(node,ast.Call):
                assert isinstance(node.func,ast.Name),ast.dump(node)
                target=node.func.id
                if target in functions:pending.append(target)
                else:assert target in INTRINSICS,(name,target)
    selected=[functions['fd_entry']]+[node for name,node in functions.items()
        if name!='fd_entry' and name in reached]
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in common.CONSTANTS:
                return ast.copy_location(ast.Constant(common.CONSTANTS[node.id]),node)
            return node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(
        ast.Module(body=selected,type_ignores=[]))))+'\n'

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i+1) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    functions=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
            dict(op='call',args=['v0','v1','v2'],out=[dict(name='v3',type='u32')],
                 attrs=dict(function=names['fd_entry']))],
                 term=dict(op='ret',values=['v3']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='agent_default_json_fixed_driver',functions=functions))
    fs=value['functions']
    counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),
        max(len(f['blocks']) for f in fs),max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(actual<=limit for actual,limit in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value)
    return value

if __name__=='__main__':
    value=document();raw=render_assembly(value).encode()
    target=ROOT/'examples/hia_bootstrap/agent_default_json_fixed_driver.hiaasm'
    target.parent.mkdir(parents=True,exist_ok=True)
    assert not target.exists(),'new output revision required'
    target.write_bytes(raw)
    fs=value['functions']
    print(json.dumps(dict(path=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']),
        scope='FIXED_DEFAULT_DATAJSON_DRIVER_AUTHORING_ONLY'),sort_keys=True),flush=True)
