"""Generate complete initializer Store.json/profile invocation owner.

This authoring module checks the exact Store and 31-operation ABI sources.
Runtime serialization, profile projection, SQL argument order and every
continuation decision remain HIA. Physical namespace peers remain pending.
"""
from __future__ import annotations
import ast,json,os,sys
from pathlib import Path
from hashlib import sha256
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=Path(os.environ.get('HIA_WORKER_REFERENCE',str(ROOT.parent/'Hepta-agent-edit-native')))
def magic(text):return int.from_bytes(text.encode('ascii'),'little')
OWN_PINS={
 'worker_store_values_front.py':'5bb3e5d3de54d1e7fb3223abcf5eebf86e8dbee8a691fce72ceb6ae0c6bcebf3',
 'worker_store_values_result.py':'6b581bd60da75d897e5bfc99fb47bbd932c6c99d569393fc1537d140081816dd'}
DEPENDENCIES={
 'generate_hia_agent_worker_init_values.py':'9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac',
 'generate_hia_agent_worker_initialization_sequence.py':'fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef',
 'worker_digest_result.py':'e998c82865c3ac5adc6da87d27c0484be08ce8b6b4f64ac045cd363f90ae3d4d',
 'graph_harness_r3.py':'75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c',
 'HIA_AGENT_NAMESPACE_STORE_ABI.json':'c15222c99cb04ef8bc6a7f13108a7e90adb0bc908876d663eb4329fd14563c04',
 'hia_agent_store.py':'fae25d48a6de7187ed465287c1491af74214ac8bf3eae2af921bd100a247b822'}
CONSTANTS={
 'IV_GRAPH':magic('HIAGRF01'),'IV_MAX':(1<<64)-1,'IV_BAD':0xfffffffd,'V_BAD':32,
 'SV_COMMAND':magic('HIAWSV01'),'SV_EVENT':magic('HIAWSE01'),'SV_STATE':magic('HIAWSW01'),
 'SV_INIT_EVENT':magic('HIAWIE01'),'SV_INIT_STATE':magic('HIAWIW01'),'SV_INIT_REPLY':magic('HIAWIR01'),
 'SV_REG_EVENT':magic('HIAWGE01'),'SV_REG_COMMAND_MAGIC':magic('HIAWGC01'),
 'SV_WIRE_COMMAND':magic('HIAGWC01'),'SV_WIRE_EVENT':magic('HIAGWE01'),'SV_WIRE_STATE':magic('HIAGWS01'),
 'SV_NS_COMMAND':magic('HIAWNP01'),'SV_NS_REPLY':magic('HIAWNR01'),'SV_EXCEPTION':magic('HIAWSX01'),
 'SV_HANDLE':1<<63,'SV_MIN':16384,'SV_WIRE':16384,'SV_EVENT_AT':512,
 'SV_SOURCE_HEADER':768,'SV_BORROW':832,'SV_INITIALIZER':1088,'SV_CONFIG':1408,
 'SV_WIRE_HEADER':1472,'SV_REPLY':1664,'SV_NAME':3072,'SV_PROFILE_KIND':3136,
 'SV_REG_COMMAND':3328,'SV_NS_REQUEST':3456,'SV_NS_HEADER':3584,'SV_SHA_HEADER':4096,
 'SV_PROFILE_LITERAL':magic('profile'),'SV_DISCOVERY_PREFIX':magic('discover'),
 'SV_SHA_LITERAL':magic('sha256')}
STATE_NAMES=('MAGIC','PHASE','SEQ','NEED','BAD','INV','CALL','LEASE','ORIGIN','DIGITS',
 'PEER','PENDING','STORE','INPUT_HANDLE','SOURCE_LEASE','SOURCE_BYTES','SOURCE_NODES',
 'SOURCE_EDGES','SOURCE_POOL','ROOT','REG_SEQ','REG_COMMAND','ISSUED','ROLE','PEER_NEED',
 'ACTION','WIRE_STAGE','WIRE_BYTES','WIRE_AT','WIRE_WHOLE','NAME_BYTES','REF_HANDLE',
 'REF_ROOT','SHA_ROOT','GRAPH_AT','GRAPH_BYTES','GRAPH_LEASE','GRAPH_FOREIGN',
 'GRAPH_OUTPUT','GRAPH_HANDLE','REPLY_AT','REPLY_BYTES','ERROR_BYTES','ERROR_LEASE')
CONSTANTS.update({'S_'+name:i*8 for i,name in enumerate(STATE_NAMES)})
assert len(STATE_NAMES)*8<512
INTRINSICS={'byte','length','store','choose','copy_bytes','fill_range'}
def assigned(tree,name):
    return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)))
def verified(path,identity):
    raw=path.read_bytes()
    assert sha256(raw).hexdigest()==identity,(str(path),sha256(raw).hexdigest())
    return raw
def source_program():
    raws={name:verified(ROOT/'dependencies'/name,identity)
        for name,identity in DEPENDENCIES.items()}
    abi=json.loads(raws['HIA_AGENT_NAMESPACE_STORE_ABI.json'])
    assert abi['schema']=='hepta.hia.agent-namespace-store-abi.v1'
    rows=[x for x in abi['relational_operations']
        if x['sql_reference']=='INSERT OR IGNORE INTO profiles VALUES (?,?,?)']
    assert len(rows)==1
    row=rows[0]
    assert (row['id'],row['table_id'],row['table'],row['kind'],row['bind_count'])==(5,2,'profiles','INSERT',3)
    tables=[t for t in abi['tables'] if t['id']==row['table_id']]
    assert len(tables)==1 and tables[0]['name']=='profiles'
    assert [c['name'] for c in tables[0]['columns']]==['id','sha256','artifact']
    constants=dict(CONSTANTS);constants['SV_PROFILE_INSERT']=row['id']
    init=ast.parse(raws['generate_hia_agent_worker_initialization_sequence.py'])
    names=assigned(init,'NAMES')
    for name in ('MAGIC','STATUS','SEQ','PENDING','INV','CALL','PEER','PHASE','STORE','LITERAL_BYTES'):
        constants['IS_I_'+name]=1024+8*names.index(name)
    original=ast.parse(raws['hia_agent_store.py'])
    cls=next(n for n in original.body if isinstance(n,ast.ClassDef) and n.name=='AgentStore')
    assert {n.name for n in cls.body if isinstance(n,ast.FunctionDef)} >= {'json','profile','put'}
    nodes=[]
    for name,identity in OWN_PINS.items():
        raw=verified(ROOT/'tools'/name,identity)
        nodes.extend(ast.parse(assigned(ast.parse(raw),'BODY')).body)
    values=ast.parse(assigned(ast.parse(raws['generate_hia_agent_worker_init_values.py']),'BODY'))
    keep={'iv_word','iv_get','iv_put','iv_bad','iv_shape','iv_valid_node'}
    selected=[n for n in values.body if isinstance(n,ast.FunctionDef) and n.name in keep]
    assert {n.name for n in selected}==keep;nodes+=selected
    digest=ast.parse(assigned(ast.parse(raws['worker_digest_result.py']),'BODY'))
    wire=next(n for n in digest.body if isinstance(n,ast.FunctionDef) and n.name=='wd_wire_check')
    wire.name='sv_wire_check'
    rename={'D_ROLE':'S_ROLE','D_PEER_NEED':'S_PEER_NEED','D_SOURCE_NODES':'S_SOURCE_NODES',
        'D_SOURCE_BYTES':'S_SOURCE_BYTES','WD_CONFIG':'SV_CONFIG',
        'WD_WIRE_EVENT':'SV_WIRE_EVENT','WD_WIRE_STATE':'SV_WIRE_STATE'}
    class Rename(ast.NodeTransformer):
        def visit_Name(self,n):
            return ast.copy_location(ast.Name(rename[n.id],n.ctx),n) if n.id in rename else n
    nodes.append(Rename().visit(wire))
    errors=assigned(ast.parse(raws['graph_harness_r3.py']),'ERRORS')
    assert set(errors)==set(range(1,17))
    lines=['def sv_error_literal(w:mutbuf, code:u64) -> u64:']
    for code,text in sorted(errors.items()):
        raw=('E_HIA_EDIT: '+text).encode('utf-8');assert 0<len(raw)<=704
        lines.append('    if code == '+str(code)+':')
        for at in range(0,len(raw),8):
            value=int.from_bytes(raw[at:at+8].ljust(8,b'\0'),'little')
            lines.append('        iv_put(w, SV_REPLY + '+str(320+at)+', '+str(value)+')')
        lines.append('        return '+str(len(raw)))
    lines.append('    return 0');nodes+=ast.parse('\n'.join(lines)+'\n').body
    nodes.sort(key=lambda n:n.name!='worker_store_values')
    functions={n.name for n in nodes};assert len(functions)==len(nodes)
    for node in nodes:
        assert isinstance(node,ast.FunctionDef)
        for call in ast.walk(node):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name) and call.func.id in functions|INTRINSICS,ast.dump(call)
            if isinstance(call,ast.Name) and call.id.isupper():
                assert call.id in constants,call.id
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(constants[node.id]),node) if node.id in constants else node
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
               attrs=dict(function=names['worker_store_values'])),
          dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        fs.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='worker_store_json_profile',functions=fs))
    fs=value['functions'];counts=(len(fs),sum(len(f['blocks']) for f in fs),
        sum(len(b['ops']) for f in fs for b in f['blocks']),max(len(f['blocks']) for f in fs),
        max(len(b['params']) for f in fs for b in f['blocks']))
    assert all(a<=b for a,b in zip(counts,(128,1536,8192,256,16))),counts
    verify_program(value);return value
if __name__=='__main__':
    value=document()
    from hepta.hia_agent_assembly import render_assembly
    raw=render_assembly(value).encode()
    path=ROOT/'examples/hia_bootstrap/agent_worker_store_json_profile.hiaasm'
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(raw)
    fs=value['functions']
    print(json.dumps(dict(path=str(path),bytes=len(raw),sha256=sha256(raw).hexdigest(),
        functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        scope='NEW_INITIALIZER_STORE_JSON_PROFILE_WITH_PENDING_NAMESPACE'),sort_keys=True),flush=True)
