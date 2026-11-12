"""Fresh native initializer map operations and ordered alias-preserving values.

The controlled Graph capture is a private source issuer only. These groups do
not call a namespace, import an old group PASS, or claim the whole initializer.
All complete expected values use independent ordinary Python expressions before
the actual image interval. Actual runtime graph/command forwarding is mechanical.
"""
from __future__ import annotations
import ast,copy,ctypes,json,os,resource,stat,struct,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
WORK=Path(sys.argv[1]).resolve();COMPILE=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();GROUP=sys.argv[4]
ROOT=WORK/'native-agent-initialization-maps-next';REFERENCE=WORK/'Hepta-agent-edit-native'
RENDER=WORK/'native-agent-edit-render-next'
sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta import hia_agent_service as service
from hepta import hia_agent_store as store
import generate_hia_agent_worker_init_maps as generation
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda b:int.from_bytes(b,'little')
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
BAD=0xfffffffd;MAX=(1<<64)-1;CANARY=bytes(range(64));C=generation.CONSTANTS
COMPILER_SHA='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};modes={};saved=set();images={};entries={'maps':0}
ledger=(OUT/'entries.jsonl').open('w');results=(OUT/'cases.jsonl').open('w')
capture=None;catalog=None;case_count=0;planned=0;status='FAIL';failure=None
completed_operations={n:0 for n in range(1,7)};started=time.monotonic_ns()
HELPER_SHA='1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753'
helper=ROOT/'development/value_mechanics_source.py';helper_raw=helper.read_bytes()
assert sha256(helper_raw).hexdigest()==HELPER_SHA
tree=ast.parse(helper_raw)
wanted={'digest','save','cas','read','rows','same','disabled','Buffer','invoke','grow','decode_graph'}
definitions=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in wanted]
assert {n.name for n in definitions}==wanted
exec(compile(ast.Module(body=definitions,type_ignores=[]),str(helper),'exec'),globals())

def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def header(raw):return struct.unpack_from('<8Q',raw)
def node(raw,identifier):return struct.unpack_from('<8Q',raw,64*identifier)
def children(raw,identifier):
    n=word(raw,16);record=node(raw,identifier)
    width=record[4]*(2 if record[0]==6 else 1)
    start=64+n*64+record[3]*8
    return struct.unpack_from('<'+'Q'*width,raw,start) if width else ()
def pairs(raw,identifier):
    assert node(raw,identifier)[0]==6
    ids=children(raw,identifier);return list(zip(ids[0::2],ids[1::2]))
def field(raw,identifier,key):
    for kid,vid in pairs(raw,identifier):
        if decode_graph(raw,kid)==key:return vid
    raise AssertionError(('missing field in independently captured source',key))
def values_equal(actual,expected):
    if type(actual) is not type(expected):return False
    if type(actual) is float:return struct.pack('<d',actual)==struct.pack('<d',expected)
    if type(actual) is dict:
        return list(actual)==list(expected) and all(values_equal(actual[k],expected[k]) for k in expected)
    if type(actual) in (list,tuple):
        return len(actual)==len(expected) and all(values_equal(a,b) for a,b in zip(actual,expected))
    return actual==expected
def oracle_values(op,values):
    a,b,c,d,key=values
    if op==1:return ({tool['name']:tool for tool in a['tools']},)
    if op==2:return ({},{})
    if op==3:
        left=a.copy();right=b.copy();left[key]=c;right[key]=d
        return left,right
    if op==4:return (dict(a),)
    if op==5:
        result=a.copy();result[key]=c;return (result,)
    if op==6:return (a[key],)
    raise AssertionError(op)
def fixture(op,values,extra=None):
    assert len(values)==5
    raw=capture([*values,extra],lease=53)
    ids=children(raw,word(raw,24))[:5];assert len(ids)==5
    if op in (1,4):args=(ids[0],0,0,0,0)
    elif op==2:args=(0,0,0,0,0)
    elif op==3:args=tuple(ids)
    elif op==5:args=(ids[0],0,ids[2],0,ids[4])
    elif op==6:args=(ids[0],0,0,0,ids[4])
    else:raise AssertionError(op)
    return dict(operation=op,values=values,source=raw,args=args)
def configuration(f,capacity=4096):
    raw=f['source'];op=f['operation']
    command=pack(M(b'HIAWMC01'),1,37,83,0,op,word(raw,8),len(raw),
        0 if op==6 else 113,*f['args'],*([0]*10))
    assert len(command)==192
    return dict(source=Buffer(len(raw),raw),command=Buffer(192,command),
        workspace=Buffer(capacity),sequence=0,operation=op)
def raw_call(c,label,advertised=None):
    return invoke('maps',c['source'],c['command'],c['workspace'],label,advertised)
def read_event(c,ret):
    assert ret==640,ret
    event=struct.unpack_from('<16Q',c['workspace'].raw(),512)
    assert event[0]==M(b'HIAWME01') and event[2:4]==(37,83)
    assert event[4]==c['sequence']+1 and event[5]==c['operation']
    assert event[1] in (0,1) and event[13]==0 and event[15]==0
    c['sequence']=event[4];return event
def continuation(c,event,size):
    assert size>c['workspace'].n
    c['workspace']=grow(c['workspace'],size)
    command=bytearray(c['command'].raw())
    struct.pack_into('<Q',command,8,2);struct.pack_into('<Q',command,32,event[4])
    c['command']=Buffer(len(command),command)
def projected(f,label,capacity=4096,growth='exact'):
    c=configuration(f,capacity);trace=[]
    while True:
        e=read_event(c,raw_call(c,label));trace.append(list(e))
        if e[1]==1:
            assert e[6]>c['workspace'].n and e[7:13]==(0,0,0,0,0,0)
            needed=e[6]
            if growth=='one-short':
                assert needed-1>c['workspace'].n;needed-=1;growth='exact'
            continuation(c,e,needed);continue
        if f['operation']==6:
            assert e[7:10]==(1,0,len(f['source'])) and e[12]==53 and e[11]==0
            result=f['source']
        else:
            assert e[7]==2 and e[12]==113
            assert e[8]<=c['workspace'].n and e[9]<=c['workspace'].n-e[8]
            assert e[6]==e[8]+e[9]
            result=c['workspace'].raw()[e[8]:e[8]+e[9]]
            assert header(result)[1:4]==(113,word(result,16),e[10])
        roots=(e[10],) if e[11]==0 else (e[10],e[11])
        return result,roots,c,trace
def expected_pairs(f):
    raw=f['source'];a,b,c,d,key=f['args'];op=f['operation']
    if op==6:return None
    def assign(old,new):
        # Built-in dict owns equality/insertion order in the independent oracle;
        # retain the first source key ID in the expected alias metadata.
        result={decode_graph(raw,k):(k,v) for k,v in old}
        for k,v in new:
            value=decode_graph(raw,k)
            first=result[value][0] if value in result else k
            result[value]=(first,v)
        return list(result.values())
    if op==1:
        ids=children(raw,field(raw,a,'tools'))
        return [assign([],[(field(raw,i,'name'),i) for i in ids])]
    if op==2:return [[],[]]
    if op==3:return [assign(pairs(raw,a),[(key,c)]),assign(pairs(raw,b),[(key,d)])]
    if op==4:
        bindings=[tuple(children(raw,i)) for i in children(raw,a)]
        assert all(len(pair)==2 for pair in bindings)
        return [assign([],bindings)]
    if op==5:return [assign(pairs(raw,a),[(key,c)])]
    raise AssertionError(op)
def required_capacity(f,expected):
    if f['operation']==6:return 4096
    raw=f['source'];_,_,n,_,edges,pool,_,_=header(raw)
    pairs_capacity=0
    if f['operation']==1:pairs_capacity=len(children(raw,field(raw,f['args'][0],'tools')))
    if f['operation']==4:pairs_capacity=len(children(raw,f['args'][0]))
    nodes=n+len(expected);edges+=sum(len(items)*2 for items in expected)
    return 4096+pairs_capacity*16+64+nodes*64+edges*8+pool
def check_clone(source,result):
    _,_,n,_,edges,pool,total,_=header(source)
    _,_,newn,_,newe,newp,newtotal,_=header(result)
    assert newp==pool and newtotal==len(result)
    oldbase=64+n*64+edges*8;newbase=64+newn*64+newe*8
    assert result[newbase:]==source[oldbase:]
    assert result[64+newn*64:64+newn*64+edges*8]==source[64+n*64:oldbase]
    for identifier in range(1,n+1):
        expected=list(node(source,identifier))
        if expected[0] in (2,3,4,9):expected[1]+=newbase-oldbase
        assert tuple(expected)==node(result,identifier),('original ID changed',identifier)
def native_guards():
    stack=ExitStack()
    for name in ('__init__','_profiles','_examples'):
        stack.enter_context(patch.object(service.HIAAgentService,name,new=disabled))
    for name in ('profile','json','put'):
        stack.enter_context(patch.object(store.AgentStore,name,new=disabled))
    stack.enter_context(patch.object(generation,'source_program',new=disabled))
    stack.enter_context(patch.object(generation,'document',new=disabled))
    stack.enter_context(patch('hepta.hia_agent_store.wire',new=disabled))
    stack.enter_context(patch('json.loads',new=disabled))
    stack.enter_context(patch.dict(globals(),{'capture':disabled,'oracle_values':disabled}))
    return stack
def record(row):
    global case_count
    case_count+=1;row=dict(case=case_count,status='PASS',**row)
    results.write(json.dumps(row,sort_keys=True)+'\n');results.flush()
    print(json.dumps(dict(event='INITIALIZER_MAPS_PASS',group=GROUP,
        case=case_count,label=row['label']),sort_keys=True),flush=True)
def one(label,f,capacity=4096,growth='exact'):
    expected=oracle_values(f['operation'],f['values'])
    alias_pairs=expected_pairs(f);before=entries['maps']
    print(json.dumps(dict(event='INITIALIZER_MAPS_START',group=GROUP,
        case=case_count+1,label=label),sort_keys=True),flush=True)
    with native_guards():result,roots,c,trace=projected(f,label,capacity,growth)
    assert len(roots)==len(expected)
    for root,value in zip(roots,expected):
        assert values_equal(decode_graph(result,root),value),(label,'complete ordered value')
    if f['operation']==6:
        actual_key=decode_graph(f['source'],f['args'][4])
        wanted=next(v for k,v in pairs(f['source'],f['args'][0])
            if decode_graph(f['source'],k)==actual_key)
        assert result==f['source'] and roots==(wanted,)
    else:
        check_clone(f['source'],result)
        assert len(set(roots))==len(roots)
        for root,wanted in zip(roots,alias_pairs):
            assert node(result,root)==(6,0,0,node(result,root)[3],len(wanted),root,0,0)
            assert pairs(result,root)==wanted,(label,'key insertion / value alias ID')
    record(dict(label=label,operation=f['operation'],source=cas(f['source']),
        output_graph=cas(result),roots=list(roots),events=trace,
        expected_source_pairs=alias_pairs,complete_ordered_values_equal=True,
        all_original_graph_nodes_edges_and_pool_preserved=True,
        actual_entries=entries['maps']-before))
    completed_operations[f['operation']]+=1
    return result,roots,c,trace
def semantic_cases():
    shared={'nested':['same',True,None,23], 'number':-0.0}
    nonascii={'ß':'value','中😀':shared,'é':False,'\ud800':b'\x00\xff'}
    same1=('duplicate-key-'+'x'*300).encode().decode()
    same2=('duplicate-key-'+'x'*300).encode().decode()
    assert same1==same2 and same1 is not same2
    cases=[]
    def add(label,op,values):cases.append((label,fixture(op,values)))
    add('complete-exact-current-eleven-tool-catalog',1,[catalog,None,None,None,None])
    add('catalog-empty',1,[{'tools':[]},None,None,None,None])
    add('catalog-repeated-name-first-position-last-complete-value',1,
        [{'tools':[{'name':same1,'body':shared},{'name':'middle','body':1},
                   {'name':same2,'body':nonascii}]},None,None,None,None])
    add('catalog-unicode-alias',1,[{'tools':[
        {'name':'é','body':shared},{'name':'中😀','body':shared}]},None,None,None,None])
    add('distinct-two-empty-maps',2,[None,None,None,None,None])
    for label,left,right,key in (
        ('append',{}, {},'compiler'),
        ('replace',{'a':1,'compiler':0,'z':3},{'compiler':None,'tail':False},'compiler'),
        ('mixed',{'target':1},{'a':2},'target'),
        ('unicode',{'ß':0,'中😀':1},{'中😀':2},'中😀'),
        ('same-equal-new-key',{same1:1},{same1:2},same2)):
        add('profiles-'+label,3,[left,right,shared,nonascii,key])
    add('profile-maps-shared-source',3,[shared,shared,1,2,'number'])
    add('resources-six-original-bindings',4,[
        [('manifest','m'),('tool_catalog',shared),('profiles',shared),('schemas',nonascii),
         ('docs',b'doc'),('diagnostics',None)],None,None,None,None])
    add('resources-empty',4,[[],None,None,None,None])
    add('resources-duplicate-string-key',4,[
        [(same1,shared),['middle',1],[same2,nonascii]],None,None,None,None])
    add('resources-unicode',4,[[['é',shared],['中😀',shared],['\ud800',-0.0]],
        None,None,None,None])
    for label,current,key,value in (
        ('empty',{},'new',None),('replace',{'a':1,'mid':2,'z':3},'mid',shared),
        ('append',{'a':shared},'b',shared),('unicode',{'中😀':1},'é',nonascii),
        ('same-string',{same1:shared},same2,nonascii),
        ('binary',{'old':b'a'},'binary',b'\x00\xff\x80')):
        add('resource-update-'+label,5,[current,None,value,None,key])
    for label,current,key in (
        ('null',{'a':None},'a'),('nested',{'a':shared},'a'),
        ('nonascii',nonascii,'中😀'),('surrogate',nonascii,'\ud800'),
        ('float',{'value':-0.0},'value'),('big-integer',{'value':2**4096+17},'value')):
        add('borrowed-lookup-'+label,6,[current,None,None,None,key])
    return cases
def semantics():
    global planned
    cases=semantic_cases();planned=len(cases)
    for label,f in cases:one(label,f)
def growths():
    global planned
    cases=[('tools',fixture(1,[{'tools':[{'name':'one'},{'name':'two'}]},None,None,None,None])),
        ('empties',fixture(2,[None]*5)),
        ('profiles',fixture(3,[{'a':1},{'b':2},{'id':3},{'id':4},'c'])),
        ('resources',fixture(4,[[['one',{'nested':[1,2]}],['two',False]],None,None,None,None])),
        ('update',fixture(5,[{'a':1},None,{'shared':[1,2]},None,'b']))]
    planned=len(cases)*4+1
    for label,f in cases:
        exact=required_capacity(f,expected_pairs(f))
        one(label+'-growth-exact',f)
        one(label+'-growth-one-short',f,growth='one-short')
        one(label+'-initial-exact',f,capacity=exact)
        one(label+'-initial-one-short',f,capacity=exact-1)
    one('lookup-no-output-allocation',fixture(6,[{'name':{'x':[1,2]}},None,None,None,'name']))
def large_values():
    global planned
    planned=3
    huge='x'*(9<<20)
    one('nine-MiB-shared-pool-no-eight-MiB-output-quota',
        fixture(5,[{'old':huge},None,huge,None,'new']))
    del huge
    one('retains-source-inventory-above-262144-with-fixed-result-map',
        fixture(2,[None]*5,extra=list(range(262145))))
    longkey='中'*(1<<18)
    one('long-equal-string-key-replacement-preserves-original-key-ID',
        fixture(5,[{longkey:{'old':True}},None,{'new':True},None,longkey.encode().decode()]))
def protocols():
    global planned
    base=fixture(1,[{'tools':[{'name':'one','data':[1,b'a',1.5]}]},None,None,None,None])
    controls=[]
    def raw_refusal(c,label):
        while True:
            result=raw_call(c,label)
            if result==BAD:break
            e=read_event(c,result);assert e[1]==1,(label,'unexpected completion')
            continuation(c,e,e[6])
        poisoned=c['workspace'].raw()
        assert word(poisoned,C['M_STATUS'])==3,(label,'full workspace not poisoned')
        assert raw_call(c,label+'.poisoned')==BAD and c['workspace'].raw()==poisoned
    def cmd(index,value):
        c=configuration(base);c['command'].write(index*8,pack(value))
        raw_refusal(c,'command-'+str(index))
    for index,value in ((0,0),(1,0),(1,2),(2,0),(3,0),(4,1),(5,0),(5,7),
        (6,0),(6,54),(7,len(base['source'])-1),(7,len(base['source'])+1),
        (8,0),(8,53)):
        controls.append(('command-'+str(index)+'-'+str(value),
            lambda i=index,v=value:cmd(i,v)))
    for index in range(14,24):
        controls.append(('reserved-command-'+str(index),lambda i=index:cmd(i,1)))
    def command_size(size):
        c=configuration(base);old=c['command'].raw()
        c['command']=Buffer(size,(old+b'\0')[:size]);raw_refusal(c,'command-size-'+str(size))
    for size in (0,191,193):
        controls.append(('command-extent-'+str(size),lambda n=size:command_size(n)))
    def source_word(index,value):
        c=configuration(base);c['source'].write(index*8,pack(value))
        raw_refusal(c,'source-'+str(index))
    for index,value in ((0,0),(1,0),(1,54),(2,0),(2,MAX),(3,0),(3,MAX),
        (4,MAX),(5,0),(6,len(base['source'])-1),(7,1)):
        controls.append(('source-header-'+str(index)+'-'+str(value),
            lambda i=index,v=value:source_word(i,v)))
    def source_node(field,value):
        c=configuration(base);c['source'].write(64+field*8,pack(value))
        raw_refusal(c,'source-node-'+str(field))
    for field,value in ((0,10),(1,1),(2,1),(3,MAX),(4,MAX),(5,0),(6,1),(7,1)):
        controls.append(('source-root-node-'+str(field),lambda f=field,v=value:source_node(f,v)))
    def source_edge():
        c=configuration(base);c['source'].write(64+word(base['source'],16)*64,pack(0))
        raw_refusal(c,'source-edge-zero')
    controls.append(('source-edge-zero',source_edge))
    def empty_source():
        c=configuration(base);c['source']=Buffer(0)
        c['command'].write(56,pack(0));raw_refusal(c,'empty-source')
    controls.append(('empty-source',empty_source))
    def dirty():
        c=configuration(base);c['workspace'].write(3000,b'\1')
        raw_refusal(c,'dirty-initial')
    controls.append(('dirty-initial-state',dirty))
    for label,op,values in (
        ('catalog-not-map',1,[[],None,None,None,None]),
        ('catalog-missing-tools',1,[{},None,None,None,None]),
        ('catalog-tools-not-list',1,[{'tools':()},None,None,None,None]),
        ('tool-not-map',1,[{'tools':[1]},None,None,None,None]),
        ('tool-missing-name',1,[{'tools':[{}]},None,None,None,None]),
        ('tool-name-not-string',1,[{'tools':[{'name':1}]},None,None,None,None]),
        ('bindings-not-list',4,[(),None,None,None,None]),
        ('binding-not-list-or-tuple',4,[[1],None,None,None,None]),
        ('binding-arity-one',4,[[['a']],None,None,None,None]),
        ('binding-arity-three',4,[[['a',1,2]],None,None,None,None]),
        ('binding-key-not-string',4,[[[1,2]],None,None,None,None]),
        ('update-non-map',5,[[],None,1,None,'key']),
        ('update-nonstring-existing-key',5,[{1:2},None,1,None,'key']),
        ('update-nonstring-new-key',5,[{},None,1,None,7]),
        ('second-profile-non-map',3,[{},[],1,2,'key']),
        ('lookup-missing-key',6,[{'a':1},None,None,None,'missing'])):
        controls.append((label,lambda l=label,o=op,v=values:
            raw_refusal(configuration(fixture(o,v)),l)))
    def argument(op,index,value):
        f=fixture(op,[{'a':1},{'b':2},3,4,'key']) if op==3 else base
        if op==2:f=fixture(2,[None]*5)
        if op==5:f=fixture(5,[{},None,1,None,'key'])
        if op==6:f=fixture(6,[{'a':1},None,None,None,'a'])
        c=configuration(f);c['command'].write(index*8,pack(value))
        raw_refusal(c,'argument-'+str(op)+'-'+str(index))
    for op,index,value in ((1,10,1),(1,11,1),(1,12,1),(1,13,1),
        (2,9,1),(2,10,1),(2,11,1),(2,12,1),(2,13,1),
        (3,11,0),(3,11,MAX),(3,12,0),(3,12,MAX),
        (5,10,1),(5,12,1),(5,11,0),(6,10,1),(6,11,1),(6,12,1),(6,8,113)):
        controls.append(('argument-'+str(op)+'-'+str(index)+'-'+str(value),
            lambda o=op,i=index,v=value:argument(o,i,v)))
    def grown():
        c=configuration(base);e=read_event(c,raw_call(c,'pending-first-grow'))
        assert e[1]==1;continuation(c,e,e[6]);return c
    def changed(kind):
        c=grown()
        if kind=='source-header':c['source'].write(8,pack(54))
        elif kind=='source-size':
            c['source']=Buffer(c['source'].n+1,c['source'].raw()+b'\0')
        elif kind=='command-size':
            c['command']=Buffer(193,c['command'].raw()+b'\0')
        elif kind=='mode':c['command'].write(8,pack(1))
        elif kind=='sequence':c['command'].write(32,pack(c['sequence']-1))
        else:
            index=int(kind);c['command'].write(index*8,pack(word(c['command'].raw(),index*8)^1))
        raw_refusal(c,'changed-after-grow-'+str(kind))
    for kind in ('source-header','source-size','command-size','mode','sequence',
                 '0','2','3','5','6','7','8','9','10','11','12','13','14','23'):
        controls.append(('changed-after-grow-'+kind,lambda k=kind:changed(k)))
    def duplicate_map_key():
        f=fixture(5,[{'a':1,'b':2},None,3,None,'new']);c=configuration(f)
        a=f['args'][0];edgebase=64+word(f['source'],16)*64
        first=node(f['source'],a)[3]
        c['source'].write(edgebase+(first+2)*8,pack(pairs(f['source'],a)[0][0]))
        raw_refusal(c,'duplicate-private-map-key')
    controls.append(('duplicate-private-map-key',duplicate_map_key))
    def complete_again():
        _,_,c,_=projected(base,'completed')
        before=c['workspace'].raw()
        assert word(before,C['M_STATUS'])==2
        assert raw_call(c,'completed-again')==BAD and c['workspace'].raw()==before
    controls.append(('complete-single-use',complete_again))
    def overflow():
        c=grown();c['workspace'].write(C['M_SEQ'],pack(MAX))
        c['command'].write(32,pack(MAX))
        assert raw_call(c,'event-sequence-overflow')==BAD
        poisoned=c['workspace'].raw();assert word(poisoned,C['M_STATUS'])==3
        assert raw_call(c,'overflow-again')==BAD and c['workspace'].raw()==poisoned
    controls.append(('event-sequence-overflow',overflow))
    def short(pending):
        c=grown() if pending else configuration(base);before=c['workspace'].raw()
        assert raw_call(c,'short-workspace',4095)==BAD and c['workspace'].raw()==before
        # Caller retires this lease, without claiming inaccessible native poison.
    controls.append(('short-initial-outer-retirement',lambda:short(False)))
    controls.append(('short-pending-outer-retirement',lambda:short(True)))
    planned=len(controls)
    for label,body in controls:
        before=entries['maps']
        with native_guards():body()
        record(dict(label=label,private_protocol=True,actual_entries=entries['maps']-before))

try:
    assert sys.get_int_max_str_digits()==4300
    read(__file__);read(helper)
    for path in sorted((ROOT/'tools').glob('*.py')):read(path)
    helper_source=read(ROOT/'dependencies/generate_hia_agent_worker_init_values.py')
    assert digest(helper_source)==generation.HELPER_SHA
    catalog_raw=read(ROOT/'dependencies/HIA_AGENT_NATIVE_TOOL_CATALOG.json')
    assert (len(catalog_raw),digest(catalog_raw))==(226542,
        '61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8')
    catalog=json.loads(catalog_raw);assert len(catalog['tools'])==11
    assert digest(read(REFERENCE/'hepta/hia_agent_service.py'))=='684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330'
    assert digest(read(REFERENCE/'hepta/hia_agent_store.py'))=='fae25d48a6de7187ed465287c1491af74214ac8bf3eae2af921bd100a247b822'
    read(REFERENCE/'hepta/hia_json_preflight_native.py')
    harness=RENDER/'development/graph_harness_r3.py';raw=read(harness)
    assert (len(raw),digest(raw))==(9783,
        '75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c')
    node_=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='capture')
    ns={'struct':struct,'GRAPH':M(b'HIAGRF01')}
    exec(compile(ast.Module(body=[node_],type_ignores=[]),'<exact-capture-only>','exec'),ns)
    capture=ns['capture']
    bundle=json.loads(read(COMPILE/'bundle.json'))
    assert bundle['schema']=='hia-worker-initialization-maps-development-v1'
    assert bundle['status']=='PASS' and set(bundle['components'])=={'maps'}
    assert bundle['ordinary_initialization'] is False and bundle['whole_worker_closed'] is False
    summary=json.loads(read(COMPILE/'summary.json'))
    assert summary['status']=='PASS' and summary['actual_compiles']==1 and summary['source_unchanged']
    compiler=read(WORK/'dependencies/f50-B3.image.bin')
    assert (len(compiler),digest(compiler))==(668608,COMPILER_SHA)
    row=bundle['components']['maps']
    current=ROOT/'examples/hia_bootstrap/agent_worker_initialization_maps.hiaasm'
    assert Path(row['source_path']).resolve()==current.resolve()
    source=read(current);image=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
    assert Path(row['image_path']).resolve().parent==COMPILE
    assert Path(row['receipt_path']).resolve()==COMPILE/'maps.receipt.json'
    assert json.loads(read(COMPILE/'maps.manifest.json'))==row
    assert (len(source),digest(source))==(row['source_bytes'],row['source_sha256'])
    assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
    assert row['role']=='maps' and row['compiler_sha256']==COMPILER_SHA
    assert receipt['image_sha256']==COMPILER_SHA and receipt['input_sha256']==digest(source)
    assert receipt['produced_sha256']==digest(image)
    frozen=(image,digest(image))
    assert same();save(OUT/'source-before.json',rows())
    images={'maps':NativeHiaJsonImage(*frozen)}
    {'semantic':semantics,'growth':growths,'large':large_values,'protocol':protocols}[GROUP]()
    assert case_count==planned,(case_count,planned);status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    ledger.close();results.close();unchanged=same()
    if not unchanged:status='FAIL'
    summary=dict(status=status,group=GROUP,scope='INITIALIZER_NATIVE_MAP_VALUES_WITH_PRIVATE_GRAPH_ISSUER',
        cases=case_count,planned_cases=planned,entries=entries,total_actual_entries=sum(entries.values()),
        failure=failure,source_unchanged=unchanged,compressed_cas_objects=len(saved),
        completed_semantic_operations=completed_operations,elapsed_ns=time.monotonic_ns()-started,
        original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
        controlled_private_graph_issuer=True,actual_namespace_effects=0,
        actual_cross_graph_registry_entries=0,runtime_python_mechanical_transport=True,
        ordinary_initialization_closed=False,ordinary_namespace_closed=False,
        whole_worker_closed=False,production_activation=False,
        host_initialization_and_value_oracles_disabled_in_native_interval=True)
    save(OUT/'source-after.json',rows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
