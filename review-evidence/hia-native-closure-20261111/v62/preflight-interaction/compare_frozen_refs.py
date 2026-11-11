import ast,json,os,random,struct,subprocess,time,types
from hepta import hia_program as core, hia_agent_store as store
refs=['c80eb2ecc5d08421a3d124c879edb33cefff2267','647885c5c3ff067b6477011123335ad5a1aef78e']
start=time.monotonic()
def source(ref,path):
 return subprocess.check_output(['git','show',ref+':'+path],text=True)
def result(fn):
 try:return ('returned',typed(fn()))
 except Exception as e:
  cause=e.__cause__
  return ('raised',type(e).__name__,getattr(e,'code',None),str(e),None if cause is None else(type(cause).__name__,str(cause)))
def typed(value):
 if type(value)is float:return ('float',struct.pack('<d',value))
 if type(value)is list:return ('list',tuple(typed(v) for v in value))
 if type(value)is dict:return ('dict',tuple((k,typed(v)) for k,v in value.items()))
 return (type(value).__name__,value)
modules=[];spaces=[]
for ref in refs:
 ns={'__name__':'preflight_review'};exec(compile(source(ref,'hepta/hia_json_preflight.py'),ref,'exec'),ns);modules.append(ns)
 tree=ast.parse(source(ref,'hepta/hia_program.py'))
 chosen=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('_structure','_bounded_detached_snapshot')]
 ns=dict(core.__dict__);exec(compile(ast.Module(body=chosen,type_ignores=[]),ref,'exec'),ns);spaces.append(ns)
for key in ('HEPTA_HIA_AGENT_BINARY64_MANIFEST','HEPTA_HIA_AGENT_DATA_JSON_MANIFEST','HEPTA_HIA_JSON_PREFLIGHT_MANIFEST'):os.environ[key]=''
decoders=[types.FunctionType(store.decode_data.__code__,dict(store.__dict__,preflight_hia_json=ns['_preflight_hia_json_reference'])) for ns in modules]
rng=random.Random(647885)
leaves=[None,False,True,0,-1,2**80,0.0,-0.0,1.25,'', 'ordinary Ω astral 𐐷', '\x00\n\\"', '\ud800']
def value(depth=0):
 if depth>3 or rng.randrange(3)==0:return rng.choice(leaves)
 children=[value(depth+1) for _ in range(rng.randrange(4))]
 return children if rng.randrange(2) else {str(i):v for i,v in enumerate(children)}
texts=[' 0 ', '"'+('ordinary Ω𐐷'*128)+'\\uD800\\uDC00"', '{"x":0,"\\u0078":"\\ud800"}', '[1e400,"\\ud800"]', '[1e400,0]', '["a",1e-9999]', '1'+'0'*640, '['*129+'0'+']'*129]
for i in range(504):
 text=json.dumps(value(),ensure_ascii=bool(rng.randrange(2)),separators=(',',':'))
 if rng.randrange(3)==0:
  at=rng.randrange(len(text)+1);text=text[:at]+rng.choice(['','"','\\','\x1f','\ud800','\u00a0','１','٠',','])+text[at:]
 texts.append(text)
for i,text in enumerate(texts):
 nodes=rng.choice((1,2,8,64));depth=rng.choice((0,1,3,128))
 a,b=[result(lambda ns=ns:ns['_preflight_hia_json_reference'](text,max_nodes=nodes,max_depth=depth)) for ns in modules]
 assert a==b,('preflight',i,repr(text),a,b)
 a,b=[result(lambda decoder=decoder:decoder(text)) for decoder in decoders]
 assert a==b,('ordinary-data',i,repr(text),a,b)
loop=[];loop.append(loop)
shared=['repeated',{'same':'repeated'}]
graphs=[loop,[shared,shared],{'left':shared,'right':shared}]+[value() for _ in range(253)]
for i,graph in enumerate(graphs):
 budgets=dict(MAX_NODES=rng.choice((1,2,8,32,128)),MAX_DEPTH=rng.choice((0,1,3,8)),MAX_BYTES=rng.choice((0,1,7,32,127,1024)))
 for ns in spaces:ns.update(budgets)
 for name in ('_structure','_bounded_detached_snapshot'):
  a,b=[result(lambda ns=ns:ns[name](graph)) for ns in spaces]
  assert a==b,(name,i,budgets,a,b)
print(json.dumps({'status':'PASS','old_ref':refs[0],'new_ref':refs[1],'preflight_cases':len(texts),'ordinary_data_masked_preflight_cases':len(texts),'structure_graphs':len(graphs),'snapshot_graphs':len(graphs),'checked':'return values including float bits and insertion order; exception type/code/message/cause','elapsed_seconds':time.monotonic()-start}))
