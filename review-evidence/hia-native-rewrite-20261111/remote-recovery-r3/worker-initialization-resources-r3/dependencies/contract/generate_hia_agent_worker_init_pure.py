"""Complete initializer pure peer join with native value handles, UNEXECUTED.

The exact source issuer, peer image table, immutable mapping custody and carrier
remain explicit prerequisites. This is not namespace / catalog / whole Worker
qualification. Cross-Graph import is a separate existing native merge owner.
"""
from __future__ import annotations
import ast,json,sys
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
  "worker_init_pure_common.py": "f8f54a86ed80cd977ea54faf5c75007d8eca98be752c5ad8e9d9fce780bf68f5",
  "worker_init_pure_prepare.py": "0862ff31b76d71edc9a47fc48632801a69960e6739a8b3d763151c3e5bb0dfb7",
  "worker_init_pure_result.py": "e26d47cdc4cc172183ae08ffbcbf3ec88db53d282a0d46f60a505a52dc823d38"
}
DEPENDENCIES={
 'generate_hia_agent_worker_init_values.py':'9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac',
 'generate_hia_agent_worker_init_sequence.py':'fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef',
 'generate_hia_agent_worker_init_maps.py':'8a837ae4acaf11a68054c030c51d6d667d93dee4c825c8fee5bb324b9a6fc2fb'}
CONSTANTS={
 'IV_GRAPH':magic('HIAGRF01'),'IV_MAX':(1<<64)-1,'IV_BAD':0xfffffffd,'V_BAD':32,
 'PJ_COMMAND':magic('HIAWPC01'),'PJ_EVENT':magic('HIAWPE01'),'PJ_STATE':magic('HIAWPW01'),
 'PJ_REPLY':magic('HIAWIR01'),'PJ_SEQUENCE_STATE':magic('HIAWIW01'),
 'PJ_SEQUENCE_EVENT':magic('HIAWIE01'),
 'PJ_MAPS_COMMAND':magic('HIAWMC01'),'PJ_MAPS_EVENT':magic('HIAWME01'),'PJ_MAPS_STATE':magic('HIAWMW01'),
 'PJ_VALUES_COMMAND':magic('HIAWVC01'),'PJ_VALUES_EVENT':magic('HIAWVE01'),'PJ_VALUES_STATE':magic('HIAWVS01'),
 'PJ_MIN':8192,'PJ_REGISTRY':8192,'PJ_HANDLE_BASE':1<<63,
 'PJ_EVENT_AT':512,'PJ_WIRE':1024,'PJ_REPLY_AT':1280,
 'PJ_SAVED_COMMAND':2048,'PJ_SAVED_SEQUENCE':2304,'PJ_SOURCE_HEADER':2560,
 'PJ_SAVED_CHILD':2688,'PJ_KEYS_AT':3072,'B_ARG0':384,'B_NEXT_LEASE':464,
}
NAMES=('MAGIC','PHASE','SEQUENCE','LAST_COMMAND','BAD','INV','CALL','ORIGIN',
 'LEASE','BYTES','NODES','EDGES','POOL','ISSUED','ACTIVE_COMMAND','ORIGINAL_MODE',
 'NEED','PEER','PENDING','INITIALIZER_PHASE','MODE','PREP_AT','PREP_BYTES',
 'PREP_LEASE','OUTPUT_LEASE','PREP_NODES','PREP_EDGES','PREP_POOL','KEYS',
 'EXTRA_NODES','EXTRA_EDGES','EXTRA_POOL','CHILD_KIND','CHILD_SEQUENCE','CHILD_NEED',
 'ROOT0','ROOT1','GRAPH_AT','GRAPH_BYTES','GRAPH_OWNER','HANDLE0','HANDLE1',
 'LAST_PENDING','SOURCE_OWNER','RESULT_NODES','RESULT_EDGES','RESULT_POOL','RESULT_LEASE')
assert len(NAMES)==48
CONSTANTS.update({'B_'+name:index*8 for index,name in enumerate(NAMES)})
INTRINSICS={'byte','length','store','choose','copy_bytes','fill_range'}
def assigned(tree,name):
    node=next(n.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
    return ast.literal_eval(node)
def verified(path,identity):
    raw=path.read_bytes();assert sha256(raw).hexdigest()==identity,(path,sha256(raw).hexdigest())
    return ast.parse(raw,filename=str(path))
def source_program():
    source={name:verified(ROOT/'dependencies'/name,identity) for name,identity in DEPENDENCIES.items()}
    sequence_names=assigned(source['generate_hia_agent_worker_init_sequence.py'],'NAMES')
    assert len(sequence_names)==len(set(sequence_names))
    constants=dict(CONSTANTS)
    constants.update({'SI_'+name:1024+index*8 for index,name in enumerate(sequence_names)})
    bodies=[assigned(verified(ROOT/'tools'/name,identity),'BODY') for name,identity in OWN_PINS.items()]
    nodes=[n for body in bodies for n in ast.parse(body).body]
    shared=ast.parse(assigned(source['generate_hia_agent_worker_init_values.py'],'BODY')).body
    keep={'iv_word','iv_get','iv_put','iv_bad','iv_valid_node','iv_shape'}
    definitions=[n for n in shared if isinstance(n,ast.FunctionDef) and n.name in keep]
    assert {n.name for n in definitions}==keep
    nodes+=definitions;nodes.sort(key=lambda n:n.name!='initializer_pure')
    names={n.name for n in nodes};assert len(names)==len(nodes)
    for node in nodes:
        for call in ast.walk(node):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name) and call.func.id in names|INTRINSICS,ast.dump(call)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(constants[node.id]),node) if node.id in constants else node
    tree=Expand().visit(ast.Module(body=nodes,type_ignores=[]))
    return ast.unparse(ast.fix_missing_locations(tree))+'\n'
def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i+1) for i,n in enumerate(nodes)}
    signatures={n.name:([arg.annotation.id for arg in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    fs=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
            dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
            dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],
                attrs=dict(function=names['initializer_pure'])),
            dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))])]
    for n in nodes:
        builder=CopyBuilder(n,names,signatures,total);builder.statements(n.body)
        fs.append(dict(name=names[n.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='worker_initializer_pure_join',functions=fs))
    fs=value['functions'];counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),max(len(f['blocks']) for f in fs),
        max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value);return value
if __name__=='__main__':
    value=document();raw=render_assembly(value).encode()
    path=ROOT/'examples/hia_bootstrap/agent_worker_initializer_pure_join.hiaasm'
    path.parent.mkdir(parents=True,exist_ok=True);assert not path.exists();path.write_bytes(raw)
    print(json.dumps(dict(path=str(path),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        scope='NEW_INITIALIZER_PURE_JOIN_SOURCE_GENERATION_NOT_NATIVE_QUALIFICATION'),
        sort_keys=True),flush=True)
