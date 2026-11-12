"""Generate the complete six-resource P12 peer, NEW reconstructed revision 2.

Finite resource constants are authoring data. Runtime HIA validates their
source-bound pool, consumes actual metadata and registry results, and creates
the initializer reply. This does not implement namespace publication.
"""
from __future__ import annotations
import ast,copy,importlib.util,json,os,re,struct,sys
from hashlib import sha256
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
REFERENCE=Path(os.environ.get('HIA_WORKER_REFERENCE',str(ROOT.parent/'Hepta-agent-edit-native'))).resolve()
sys.path.insert(0,str(REFERENCE))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
from hepta import hia_agent_service as service
from hepta.hia_schema import schema_registry,PRIMITIVE_PROFILES
from hepta.hia_opcodes import opcode_catalog
from hepta.cli import agent_capabilities

OWN_PINS={
 'worker_init_resources_front.py':'a20db7ad319cca02d79b135856e4dffd2b6443a13eb6ed35a1f98fcc11185233',
 'worker_init_resources_result.py':'0d5c0185c897ff34431caf6e2912661d01131b3cc363b138bec38a64f525e272',
}
DEPENDENCIES={
 'generate_hia_agent_worker_init_values.py':'9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac',
 'generate_hia_agent_worker_init_sequence.py':'fad44723149d959bda2a84769d4abf5176c8fe21181c352e8e564a137b42143ca',
 'generate_hia_metadata.py':'3f14f5b921a9d584944f8d5cee44587f336a4321ffb0be1cb6c0385b4dd50138',
 'graph_harness_r3.py':'75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c',
 'generate_hia_sha256.py':'4114a26ff0ea47229bccbedadcb40efdd9715a8dd0739d2fcb55c98f8ddbdf97',
}
INTRINSICS={'byte','length','store','choose','copy_bytes','fill_range'}
SOURCE_PINS={}
def magic(value):return int.from_bytes(value.encode('ascii'),'little')
def verified(path,expected):
    raw=path.read_bytes()
    assert sha256(raw).hexdigest()==expected,(str(path),sha256(raw).hexdigest(),expected)
    SOURCE_PINS[str(path)]=dict(bytes=len(raw),sha256=expected,mode=path.stat().st_mode&4095)
    return ast.parse(raw,filename=str(path))
def assigned(tree,name):
    return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)))
def exact_functions(tree,names):
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert {n.name for n in nodes}==set(names)
    return nodes

STATE_NAMES=('MAGIC','PHASE','BAD','SEQUENCE','INV','CALL','LEASE','ORIGIN','DIGITS',
 'PENDING','OPERATION','NEED','GRAPH_LEASE','GRAPH_BYTES','REG_SEQUENCE',
 'REG_PREVIOUS','REG_ACTIVE','ISSUED','FOREIGN','OUTPUT','PACKET_AT','PACKET_BYTES',
 'META_NEED','META_STARTED','HANDLE','OLD_NODES','OLD_EDGES','OLD_POOL',
 'NEW_NODES','NEW_EDGES','NEW_POOL','NEW_BYTES','INITIALIZER_BYTES')
CONSTANTS={
 'IV_BAD':0xfffffffd,'IV_MAX':(1<<64)-1,'IV_GRAPH':magic('HIAGRF01'),
 'RS_COMMAND':magic('HIAWRC01'),'RS_EVENT':magic('HIAWRE01'),
 'RS_STATE':magic('HIAWRW01'),'RS_HANDLE':1<<63,'RS_GROW':0xfffffffe,
 'RS_REG_MAGIC':magic('HIAWGC01'),'RS_REG_EVENT':magic('HIAWGE01'),
 'RS_META_MAGIC':magic('HIAPMC01'),'RS_META_EVENT':magic('HIAPME01'),
 'RS_META_STATE':magic('HIAPMW01'),
 'IS_STATE':magic('HIAWIW01'),'IS_EVENT':magic('HIAWIE01'),'IS_REPLY':magic('HIAWIR01'),
 'RS_MIN':8192,'RS_POOL':8192,'RS_EVENT_AT':2560,'RS_EVENT_END':2816,
 'RS_SOURCE_HEADER':2816,'RS_BEGIN_COPY':2880,'RS_INITIALIZER_EVENT':3072,
 'RS_REG_EVENT_COPY':3328,'RS_REPLY':3584,'RS_REG_COMMAND':3840,
 'RS_META_COMMAND':3968,
}
CONSTANTS.update({'R_'+name:2048+8*i for i,name in enumerate(STATE_NAMES)})
CONSTANTS['V_BAD']=CONSTANTS['R_BAD']

def resources_and_pool(deps):
    service_tree=verified(REFERENCE/'hepta/hia_agent_service.py',
        '684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330')
    cls=next(n for n in service_tree.body if isinstance(n,ast.ClassDef) and n.name=='HIAAgentService')
    profiles=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='_profiles')
    resource_node=next(n.value for n in profiles.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name)
            and t.value.id=='self' and t.attr=='resources' for t in n.targets))
    names=tuple(ast.literal_eval(k) for k in resource_node.keys)
    assert names==('schema_registry','workload_schema','objective_schema','cost_policy_schema','plan_schema','proof_contract')
    expected=('schema_registry','WORKLOAD_SCHEMA','OBJECTIVE_SCHEMA','COST_POLICY_SCHEMA','PLAN_SCHEMA','proof_contract_description')
    for index,node in enumerate(resource_node.values):
        assert isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='json'
        assert len(node.args)==2 and ast.literal_eval(node.args[1])=='discovery' and not node.keywords
        value=node.args[0]
        if index in (0,5):
            assert isinstance(value,ast.Call) and value.func.id==expected[index] and not value.args and not value.keywords
        else:assert isinstance(value,ast.Name) and value.id==expected[index]
    registry=schema_registry()
    registry['instruction_catalog']['catalog_sha256']='0'*64
    values=[registry,service.WORKLOAD_SCHEMA,service.OBJECTIVE_SCHEMA,
        service.COST_POLICY_SCHEMA,service.PLAN_SCHEMA,service.proof_contract_description()]
    capture_node=exact_functions(deps['graph_harness_r3.py'],{'capture'})[0]
    capture_space={'struct':struct,'GRAPH':magic('HIAGRF01')}
    exec(compile(ast.Module(body=[capture_node],type_ignores=[]),'<exact finite Graph authoring>','exec'),capture_space)
    pool=bytearray();rows=[]
    for index,value in enumerate(values):
        raw=capture_space['capture'](value,lease=1)
        words=struct.unpack_from('<8Q',raw)
        assert words[0]==magic('HIAGRF01') and words[1]==1 and words[6]==len(raw)
        rows.append(dict(operation=index+1,name=names[index],offset=len(pool),bytes=len(raw),
            nodes=words[2],root=words[3],edges=words[4],pool=words[5],sha256=sha256(raw).hexdigest()))
        pool.extend(raw)
    first=bytes(pool[:rows[0]['bytes']])
    digest_nodes=[]
    for identifier in range(1,rows[0]['nodes']+1):
        record=struct.unpack_from('<8Q',first,identifier*64)
        if record[0]==4 and record[2]==64 and first[record[1]:record[1]+64]==b'0'*64:
            digest_nodes.append((identifier,record[1]))
    assert len(digest_nodes)==1
    canonical=json.dumps(registry,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
    digest_at=canonical.index(b'"catalog_sha256":"')+len(b'"catalog_sha256":"')
    assert canonical[digest_at:digest_at+64]==b'0'*64
    canonical_at=len(pool);pool.extend(canonical)
    # Reuse the exact finite metadata dataset functions; never run its owner.
    needed={'wire','compress','decompress','dataset'}
    namespace=dict(ast=ast,sha256=sha256,json=json,agent_capabilities=agent_capabilities,
        opcode_catalog=opcode_catalog,PRIMITIVE_PROFILES=PRIMITIVE_PROFILES,schema_registry=schema_registry)
    exec(compile(ast.Module(body=exact_functions(deps['generate_hia_metadata.py'],needed),type_ignores=[]),
        '<exact metadata finite dataset>','exec'),namespace)
    raw,packed,metadata_rows=namespace['dataset']()
    metadata_pool=(4096+len(packed)+63)&~63
    metadata_output=(metadata_pool+len(raw)+63)&~63
    metadata_required=metadata_output+max(row['bytes']+84 for row in metadata_rows)
    assert metadata_required==129420
    reg=metadata_rows[9]
    assert raw[reg['start']:reg['start']+reg['bytes']]==canonical and reg['digest_at']==digest_at
    digest=sha256(pool).digest()
    values=dict(RS_POOL_BYTES=len(pool),RS_CANON_AT=canonical_at,RS_CANON_BYTES=len(canonical),
        RS_CANON_DIGEST=digest_at,RS_GRAPH_DIGEST=digest_nodes[0][1],
        RS_META_REQUIRED=metadata_required,RS_META_OUTPUT=metadata_output)
    values.update({'RS_HASH'+str(i):int.from_bytes(digest[8*i:8*i+8],'little') for i in range(4)})
    lines=['def rs_select(w:mutbuf, operation:u64) -> u64:']
    for row in rows:
        lines+=['    if operation == '+str(row['operation'])+':',
            '        iv_put(w, R_PACKET_AT, '+str(8192+row['offset'])+')',
            '        iv_put(w, R_PACKET_BYTES, '+str(row['bytes'])+')','        return 1']
    lines+=['    return 0']
    return bytes(pool),rows,values,'\n'.join(lines)+'\n'

def digest_nodes(deps):
    # The original SHA generator is imported only after its exact bytes are checked.
    sha_path=ROOT/'dependencies/generate_hia_sha256.py'
    spec=importlib.util.spec_from_file_location('resource_exact_sha_authoring',sha_path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    function=exact_functions(deps['generate_hia_metadata.py'],{'local_digest_source'})[0]
    namespace={'ast':ast,'hash_source':module.source_program}
    exec(compile(ast.Module(body=[function],type_ignores=[]),'<exact local SHA adaptation>','exec'),namespace)
    return ast.parse(namespace['local_digest_source']()).body

def source_program():
    deps={name:verified(ROOT/'dependencies'/name,pin) for name,pin in DEPENDENCIES.items()}
    bodies=[assigned(verified(ROOT/'tools'/name,pin),'BODY') for name,pin in OWN_PINS.items()]
    nodes=[n for body in bodies for n in ast.parse(body).body]
    value_tree=ast.parse(assigned(deps['generate_hia_agent_worker_init_values.py'],'BODY'))
    nodes+=exact_functions(value_tree,{'iv_word','iv_get','iv_put','iv_bad','iv_shape','iv_valid_node'})
    nodes+=digest_nodes(deps)
    pool,rows,derived,selection=resources_and_pool(deps)
    nodes+=ast.parse(selection).body
    constants=dict(CONSTANTS);constants.update(derived)
    sequence_names=assigned(deps['generate_hia_agent_worker_init_sequence.py'],'NAMES')
    constants.update({'I_'+name:1024+8*i for i,name in enumerate(sequence_names)})
    assert constants['I_MAGIC']==1024 and constants['I_PHASE']==1040 and constants['I_PENDING']==1408
    nodes.sort(key=lambda n:n.name!='initializer_resources')
    names={n.name for n in nodes};assert len(names)==len(nodes)
    for node in nodes:
        for call in ast.walk(node):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name) and call.func.id in names|INTRINSICS,ast.dump(call)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(constants[node.id]),node) if node.id in constants else node
    tree=Expand().visit(ast.Module(body=nodes,type_ignores=[]))
    source=ast.unparse(ast.fix_missing_locations(tree))+'\n'
    return source,pool,dict(constants=constants,resources=rows,pool_bytes=len(pool),
        pool_sha256=sha256(pool).hexdigest(),source_dependencies=SOURCE_PINS)

def document():
    source,pool,metadata=source_program()
    nodes=ast.parse(source).body
    names={n.name:'f'+str(i+1) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name='v0',type='readbuf'),dict(name='v1',type='mutbuf'),dict(name='v2',type='mutbuf')]
    fs=[dict(name='f0',params=params,returns=['u32'],effects=['read','write','trap'],entry='b0',blocks=[
        dict(id='b0',params=params,ops=[
            dict(op='borrow.read',args=['v1'],out=[dict(name='v3',type='readbuf')],attrs={}),
            dict(op='call',args=['v0','v3','v2'],out=[dict(name='v4',type='u32')],
                attrs=dict(function=names['initializer_resources'])),
            dict(op='loan.end',args=['v3'],out=[],attrs={})],term=dict(op='ret',values=['v4']))])]
    for node in nodes:
        builder=CopyBuilder(node,names,signatures,total);builder.statements(node.body)
        fs.append(dict(name=names[node.name],params=[builder.param(v) for v in builder.params],
            returns=[builder.returns],effects=['read','write','trap'],entry='b0',blocks=builder.blocks))
    value=compact_authoring_cfg(dict(schema='hepta.hia.program.v8',
        module='worker_initializer_complete_resources',functions=fs))
    fs=value['functions']
    profile=dict(functions=len(fs),blocks=sum(len(f['blocks']) for f in fs),
        instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_function_blocks=max(len(f['blocks']) for f in fs),
        max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks']))
    limits=dict(functions=128,blocks=1536,instructions=8192,max_function_blocks=256,max_block_parameters=16)
    assert all(profile[k]<=v for k,v in limits.items()),profile
    indices=[]
    for fn in fs:
        for block in fn['blocks']:
            for item in block['params']+[out for op in block['ops'] for out in op.get('out',[])]:
                match=re.fullmatch('v([0-9]+)',item['name']);assert match,item
                indices.append(int(match.group(1)))
    profile['max_ssa_index']=max(indices)
    assert profile['max_ssa_index']<2048,profile
    verify_program(value)
    return value,source,pool,dict(metadata,profile=profile)

if __name__=='__main__':
    value,source,pool,metadata=document()
    target=ROOT/'examples/hia_bootstrap/worker_initializer_resources.hiaasm'
    target.parent.mkdir(parents=True,exist_ok=True)
    development=ROOT/'development';development.mkdir(exist_ok=True)
    for p,raw in ((target,render_assembly(value).encode()),
        (development/'resources-authoring-r2.py',source.encode()),
        (development/'resources-pool-r2.bin',pool),
        (development/'resources-source-r2.json',(json.dumps(metadata,sort_keys=True,indent=2)+'\n').encode())):
        with p.open('xb') as stream:stream.write(raw)
    print(json.dumps(dict(path=str(target),bytes=target.stat().st_size,
        sha256=sha256(target.read_bytes()).hexdigest(),**metadata['profile'],
        pool_bytes=len(pool),pool_sha256=sha256(pool).hexdigest(),
        scope='P12_COMPLETE_RESOURCES_NATIVE_DEVELOPMENT'),sort_keys=True),flush=True)
