"""Development authoring of new HIA edit controllers, not a runtime owner."""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.hia_agent_edit_source_views import CopyBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions

ROOT=Path(__file__).resolve().parents[1]
def source(body,constants,entry):
    tree=ast.parse(body)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,n):
            return ast.copy_location(ast.Constant(constants[n.id]),n) if isinstance(n.ctx,ast.Load) and n.id in constants else n
    tree=ast.fix_missing_locations(Expand().visit(tree));fns={n.name:n for n in tree.body}
    assert len(fns)==len(tree.body)
    reachable={entry};pending=[entry]
    while pending:
        for n in ast.walk(fns[pending.pop()]):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in fns and n.func.id not in reachable:
                reachable.add(n.func.id);pending.append(n.func.id)
    tree.body=[fns[entry]]+[n for n in tree.body if n.name!=entry and n.name in reachable]
    return ast.unparse(tree)+'\n'

def document(body,module):
    nodes=ast.parse(body).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=CopyBuilder(n,names,signatures,total);b.statements(n.body)
        functions.append(dict(name=names[n.name],params=[b.param(p) for p in b.params],returns=[b.returns],
            effects=['read','write','trap'],entry='b0',blocks=b.blocks))
    return compact_authoring_cfg(dict(schema='hepta.hia.program.v8',module=module,functions=functions))

def write(doc,name):
    p=ROOT/'examples/hia_bootstrap'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(render_assembly(doc))
    profile=dict(functions=len(doc['functions']),blocks=sum(len(f['blocks']) for f in doc['functions']),
        max_blocks=max(len(f['blocks']) for f in doc['functions']),ops=sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),
        max_block_params=max(len(b['params']) for f in doc['functions'] for b in f['blocks']))
    print(p.name,p.stat().st_size,profile)
    return p,profile
