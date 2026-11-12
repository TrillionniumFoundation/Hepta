"""Author complete private Store wire/hash and initializer digest transport.

Python constructs fixed HIA source only. No runtime value serialization, SHA,
response-field choice, chunk planning or registry-root calculation occurs here.
"""
from __future__ import annotations
import ast,json,os,sys
from pathlib import Path
from hashlib import sha256
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=Path(os.environ.get('HIA_WORKER_REFERENCE',str(ROOT.parent/'Hepta-agent-edit-native')))
def magic(value):return int.from_bytes(value.encode('ascii'),'little')
OWN_PINS={
 'worker_digest_common.py':'29a33404037ea950e36bbb14a5220f707bec5831925d20cf17dc0dda9393fac9',
 'worker_digest_result.py':'00b8a2c12e8eb05c8023d2249165f01c27c6a4a569b496bce90a77985c3e6da2'}
DEPENDENCIES={
 'generate_hia_agent_worker_init_values.py':'9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac',
 'graph_harness_r3.py':'75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c'}
CONSTANTS={
 'IV_GRAPH':magic('HIAGRF01'),'IV_MAX':(1<<64)-1,'IV_BAD':0xfffffffd,'V_BAD':32,
 'WD_COMMAND':magic('HIAWDC01'),'WD_EVENT':magic('HIAWDE01'),'WD_STATE':magic('HIAWDW01'),
 'WD_REG_EVENT':magic('HIAWGE01'),'WD_WIRE_COMMAND':magic('HIAGWC01'),
 'WD_WIRE_EVENT':magic('HIAGWE01'),'WD_WIRE_STATE':magic('HIAGWS01'),
 'WD_INIT_EVENT':magic('HIAWIE01'),'WD_INIT_REPLY':magic('HIAWIR01'),
 'WD_EXCEPTION':magic('HIAWDX01'),'WD_SHA_STATE':0x3153484132353648,
 'WD_MIN':131072,'WD_WIRE':131072,'WD_HANDLE':1<<63,
 'WD_EVENT_AT':512,'WD_SOURCE_HEADER':768,'WD_BORROW':832,'WD_RESERVE':1088,
 'WD_INITIALIZER':1344,'WD_CONFIG':1600,'WD_WIRE_HEADER':1664,
 'WD_SHA_PREFIX':1792,'WD_REPLY':2304,'WD_SHA_INPUT':4096,'WD_DIGEST':69760,'WD_GRAPH':69824}
STATE_NAMES=('MAGIC','PHASE','SEQ','NEED','BAD','INV','CALL','LEASE','ORIGIN',
 'SOURCE_LEASE','SOURCE_BYTES','SOURCE_NODES','ROOT','HANDLE','DIGITS',
 'BORROW_COMMAND','BORROW_SEQ','REG_COMMAND','REG_SEQ','FOREIGN','OUTPUT','ISSUED',
 'ROLE','PEER_NEED','ACTION','KIND','INIT_PENDING','WIRE_BYTES','WIRE_AT','WIRE_WHOLE',
 'CURSOR','CHUNK','ERROR','CAUSE','REPLY_BYTES','BOUND_HANDLE')
CONSTANTS.update({'D_'+name:i*8 for i,name in enumerate(STATE_NAMES)})
INTRINSICS={'byte','length','store','choose','copy_bytes','fill_range'}
def assigned(tree,name):
    return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)))
def verified(path,identity):
    raw=path.read_bytes()
    assert sha256(raw).hexdigest()==identity,(str(path),sha256(raw).hexdigest())
    return ast.parse(raw,filename=str(path))
def source_program():
    dependencies={name:verified(ROOT/'dependencies'/name,identity)
        for name,identity in DEPENDENCIES.items()}
    nodes=[]
    for name,identity in OWN_PINS.items():
        nodes.extend(ast.parse(assigned(verified(ROOT/'tools'/name,identity),'BODY')).body)
    original=ast.parse(assigned(dependencies['generate_hia_agent_worker_init_values.py'],'BODY'))
    keep={'iv_word','iv_get','iv_put','iv_bad','iv_shape','iv_valid_node'}
    selected=[n for n in original.body if isinstance(n,ast.FunctionDef) and n.name in keep]
    assert {n.name for n in selected}==keep
    nodes+=selected
    errors=assigned(dependencies['graph_harness_r3.py'],'ERRORS')
    assert set(errors)==set(range(1,17)) and all(type(x) is str for x in errors.values())
    lines=['def wd_error_literal(w:mutbuf, code:u64) -> u64:']
    for code,text in sorted(errors.items()):
        raw=('E_HIA_EDIT: '+text).encode('utf-8')
        assert 0<len(raw)<=704
        lines.append('    if code == '+str(code)+':')
        for at in range(0,len(raw),8):
            value=int.from_bytes(raw[at:at+8].ljust(8,b'\0'),'little')
            lines.append('        iv_put(w, WD_REPLY + '+str(320+at)+', '+str(value)+')')
        lines.append('        return '+str(len(raw)))
    lines.append('    return 0')
    nodes+=ast.parse('\n'.join(lines)+'\n').body
    nodes.sort(key=lambda n:n.name!='store_wire_digest')
    names={n.name for n in nodes};assert len(names)==len(nodes)
    for node in nodes:
        assert isinstance(node,ast.FunctionDef)
        for call in ast.walk(node):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name) and call.func.id in names|INTRINSICS,ast.dump(call)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node) if node.id in CONSTANTS else node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(ast.Module(body=nodes,type_ignores=[]))))+'\n'
def document():
    sys.path[:0]=[str(REFERENCE),str(ROOT/'dependency-overlay')]
    from hepta.hia_program import verify_program
    from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
    from tools.hia_agent_edit_source_views import CopyBuilder
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i+1) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    fs=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',
        blocks=[dict(id='b0',params=params,ops=[
          dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
          dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],
               attrs=dict(function=names['store_wire_digest'])),
          dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        fs.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='worker_store_wire_digest',functions=fs))
    fs=value['functions'];counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),max(len(f['blocks']) for f in fs),
        max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value);return value
if __name__=='__main__':
    value=document()
    from hepta.hia_agent_assembly import render_assembly
    raw=render_assembly(value).encode()
    path=ROOT/'examples/hia_bootstrap/agent_worker_store_wire_digest.hiaasm'
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(raw)
    fs=value['functions']
    print(json.dumps(dict(path=str(path),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        scope='NEW_STORE_WIRE_DIGEST_SOURCE_NOT_RUNTIME_QUALIFICATION'),sort_keys=True),flush=True)
