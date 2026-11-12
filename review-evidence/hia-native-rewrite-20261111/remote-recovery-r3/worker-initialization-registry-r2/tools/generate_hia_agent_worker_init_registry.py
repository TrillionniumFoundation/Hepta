"""Native initializer Graph import/registry configuration, new unexecuted source.

Actual Graph merge remains the complete frozen independent kernel. This peer
owns its complete commands, actual result correlation, value-handle relocation,
and initializer/GraphWire configuration. No namespace authority is created.
"""
from __future__ import annotations
import ast,importlib.util,json,sys
from pathlib import Path
from hashlib import sha256
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT.parent/'Hepta-agent-edit-native'
sys.path.insert(0,str(REFERENCE))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
def magic(value):return int.from_bytes(value.encode('ascii'),'little')
OWN_PINS={
  "worker_init_registry_common.py": "d501b2c51cc8b8485599af9f4848a2fd69d06262de5aaf21d9e9f5111a0edccd",
  "worker_init_registry_result.py": "533e8a95de9c1d13f3b9e05d159f522b63cacd653490af0bafafd0743d98a951"
}
DEPENDENCIES={
  "generate_hia_agent_worker_init_pure.py": "1b7d97ba633a40814586b0101d786b2b660ded3c59709dc34949f831b69a6974",
  "worker_init_pure_common.py": "f8f54a86ed80cd977ea54faf5c75007d8eca98be752c5ad8e9d9fce780bf68f5",
  "worker_init_pure_result.py": "e26d47cdc4cc172183ae08ffbcbf3ec88db53d282a0d46f60a505a52dc823d38",
  "generate_hia_agent_worker_init_values.py": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
  "generate_hia_graph_merge.py": "b4cda58e84da76a17a2daa919f37483eb2973dcfdbb00cd30c074ebc9aca8ed9"
}
CONSTANTS={
 'WR_COMMAND':magic('HIAWGC01'),'WR_EVENT':magic('HIAWGE01'),'WR_STATE':magic('HIAWGW01'),
 'WR_MERGE_COMMAND':magic('HIAGMC01'),'WR_MERGE_EVENT':magic('HIAGME01'),
 'WR_MERGE_STATE':magic('HIAGMW01'),'WR_INITIALIZER_CONFIG':magic('HIAWIC01'),
 'WR_WIRE_COMMAND':magic('HIAGWC01'),'WR_EVENT_AT':512,'WR_SAVED_COMMAND':4224,
 'WR_FOREIGN_HEADER':4352,'WR_EXPECTED':4736,
 'R_NODES':4560,'R_EDGES':4568,'R_POOL':4576,'R_OUT_BYTES':4584,
 'R_OUT_NEED':4592,'R_MBASE':4600}
REGISTRY_NAMES=('MAGIC','DIGITS','FOREIGN','OUTPUT','RIGHT_BYTES','RIGHT_NODES',
 'RIGHT_EDGES','RIGHT_POOL','RIGHT_ROOT','WIRE_AT','WIRE_BYTES','CHILD_SEQ',
 'CHILD_NEED','UNUSED','UNUSED2','ROOT')
COMPARE_NAMES=('SOURCE','TARGET','NODES','EDGES','OLD_DATA','NEW_DATA',
 'NODE_DELTA','EDGE_DELTA','SCALAR_DELTA')
CONSTANTS.update({'R_'+name:4096+8*i for i,name in enumerate(REGISTRY_NAMES)})
CONSTANTS.update({'R_C_'+name:4480+8*i for i,name in enumerate(COMPARE_NAMES)})
INTRINSICS={'byte','length','store','choose','copy_bytes','fill_range'}
def assigned(tree,name):
    return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)))
def verified(path,identity):
    raw=path.read_bytes();assert sha256(raw).hexdigest()==identity,(str(path),sha256(raw).hexdigest())
    return ast.parse(raw,filename=str(path))
def constants():
    path=ROOT/'dependencies/generate_hia_agent_worker_init_pure.py'
    verified(path,DEPENDENCIES[path.name])
    spec=importlib.util.spec_from_file_location('frozen_initializer_pure_constants',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    result=dict(module.CONSTANTS);result.update(CONSTANTS)
    assert result['PJ_MIN']==8192 and result['PJ_REGISTRY']==8192
    assert result['PJ_SOURCE_HEADER']==2560 and result['B_NEXT_LEASE']==464
    assert result['B_PHASE']==8 and result['B_ISSUED']==104
    return result
def source_program():
    source={name:verified(ROOT/'dependencies'/name,identity) for name,identity in DEPENDENCIES.items()}
    bodies=[assigned(verified(ROOT/'tools'/name,identity),'BODY') for name,identity in OWN_PINS.items()]
    nodes=[n for body in bodies for n in ast.parse(body).body]
    selections={
       'generate_hia_agent_worker_init_values.py':{'iv_word','iv_get','iv_put','iv_bad','iv_shape','iv_valid_node'},
       'worker_init_pure_common.py':{'pj_source','pj_lookup','pj_existing','pj_reserve','pj_issue'},
       'worker_init_pure_result.py':{'pj_range_equal'}}
    for name,keep in selections.items():
        definitions=[n for n in ast.parse(assigned(source[name],'BODY')).body
            if isinstance(n,ast.FunctionDef) and n.name in keep]
        assert {n.name for n in definitions}==keep
        nodes+=definitions
    nodes.sort(key=lambda n:n.name!='initializer_registry')
    names={n.name for n in nodes};assert len(names)==len(nodes)
    for node in nodes:
        for call in ast.walk(node):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name) and call.func.id in names|INTRINSICS,ast.dump(call)
    values=constants()
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(values[node.id]),node) if node.id in values else node
    tree=Expand().visit(ast.Module(body=nodes,type_ignores=[]))
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'
def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i+1) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    fs=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
          dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
          dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],
               attrs=dict(function=names['initializer_registry'])),
          dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        fs.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='worker_initializer_value_registry',functions=fs))
    fs=value['functions'];counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),max(len(f['blocks']) for f in fs),
        max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value);return value
if __name__=='__main__':
    value=document();raw=render_assembly(value).encode()
    path=ROOT/'examples/hia_bootstrap/agent_worker_initializer_registry.hiaasm'
    path.parent.mkdir(parents=True,exist_ok=True);assert not path.exists();path.write_bytes(raw)
    print(json.dumps(dict(path=str(path),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        scope='NEW_NATIVE_GRAPH_IMPORT_REGISTRY_SOURCE_NOT_EXECUTION'),sort_keys=True),flush=True)
