from pathlib import Path
import sys,random,json,time,copy,hashlib
ROOT=Path('/workspace/scratch/9acdfa9f5639/Hepta'); sys.path.insert(0,str(ROOT))
from hepta.hia_composite_types_native import NativeCompositeTypeSession,installed_composite_types,SOURCE
from hepta.hia_program_composite import _Types
from hepta.hia_program import HIAProgramRejected
MANIFEST=Path('/workspace/scratch/623459b0e1bc/types-native-development/manifest-r3.json')
image=installed_composite_types(str(MANIFEST))
def rec(name,fields=(),params=()):return dict(name=name,kind='record',params=list(params),fields=[dict(name=n,type=t) for n,t in fields])
def en(name,variants=(),params=()):return dict(name=name,kind='enum',params=list(params),variants=[dict(name=n,fields=[dict(name=k,type=t) for k,t in fs]) for n,fs in variants])
def gen(name,*args):return dict(name=name,args=list(args))
def part(base,*fields):return dict(partial=base,initialized=list(fields))
def obs(x):return dict(cache_count=len(getattr(x,'cache',{})),active_count=len(getattr(x,'active',set())),partial_declaration_steps=getattr(x,'partial_declaration_steps',0))
def nkey(x,i,memo):
 if i in memo:return memo[i]
 d=x._descriptors[i]
 if d['kind']=='primitive':key=d['name']
 elif d['kind']=='partial_record':key='partial<'+nkey(x,d['record'],memo)+';'+','.join(n for n,_ in d['fields'])+'>'
 else:key=d['name']+'<'+','.join(nkey(x,k,memo) for k in d['args'])+'>'
 memo[i]=key;return key
def snap(t,x=None):
 seen={};memo={}
 def key(v):return v.key if x is None else nkey(x,x._ids[id(v)],memo)
 todo=[t]
 while todo:
  v=todo.pop();k=key(v)
  if k in seen:continue
  sub=[u for _,u in v.fields]+[u for _,fs in v.variants for _,u in fs]+[u for u in (v.state,v.result,v.record) if u is not None]
  seen[k]=dict(kind=v.kind,flat=v.flat,linear=v.linear,fields=[(n,key(u)) for n,u in v.fields],variants=[(n,[(f,key(u)) for f,u in fs]) for n,fs in v.variants],state=key(v.state) if v.state else None,result=key(v.result) if v.result else None,record=key(v.record) if v.record else None,poll=v.poll,cancel=v.cancel)
  todo.extend(sub)
 return key(t),seen
rows=[];differences=[];start=time.monotonic()
for seed in range(96):
 rng=random.Random(892430+seed);flags=dict(recursive_chain=seed%3!=0,partial_records=seed%3==2)
 primitives=['u8','unit','usize','buffer','readbuf','mutbuf']+(['chain'] if flags['recursive_chain'] else [])
 defs=[rec('Zero'),rec('Box',[('value','T')],['T']),rec('Pair',[('left','A'),('right','B')],['A','B']),en('Either',[('a',[('value','T')]),('b',[('count','u8')])],['T'])]
 refs=list(primitives)+['Zero']
 for i in range(5):
  name='Item'+str(i);mode=rng.randrange(3)
  if mode==0:d=rec(name,[('f'+str(j),copy.deepcopy(rng.choice(refs))) for j in range(rng.randrange(4))])
  elif mode==1:d=en(name,[(v,[('f'+str(j),copy.deepcopy(rng.choice(refs))) for j in range(rng.randrange(3))]) for v in ['yes','no']])
  else:d=dict(name=name,kind='task',params=[],state=copy.deepcopy(rng.choice(refs)),result=copy.deepcopy(rng.choice(refs)),poll='poll_'+name,cancel='cancel_'+name)
  defs.append(d);refs.extend([name,gen('Box',name),gen('Pair',copy.deepcopy(rng.choice(refs)),name)])
 if flags['partial_records']:
  defs.append(rec('Obligation',[('p',part(gen('Pair','T',copy.deepcopy(rng.choice(primitives))),*rng.choice([[],['left'],['right'],['left','right']])))],['T']))
  refs.append(gen('Obligation',rng.choice(primitives)));refs.extend([part('Zero'),part(gen('Pair','u8','buffer'),'left'),part(gen('Pair','u8','readbuf'))])
 if seed%4==0:defs.append(rec('Bad',[('x','Missing')]))
 elif seed%8==1:defs.append(rec('Cycle',[('back','Cycle')]))
 elif seed%8==2:defs.append(en('Repeated',[('same',[]),('same',[])]))
 old=object.__new__(_Types);new=object.__new__(NativeCompositeTypeSession);errors=[]
 try:
  for fun in [lambda:_Types.__init__(old,defs,**flags),lambda:NativeCompositeTypeSession.__init__(new,image,defs,**flags)]:
   try:fun();errors.append(None)
   except HIAProgramRejected as e:errors.append(e.code)
  row=dict(seed=seed,stage='init',reference_error=errors[0],native_error=errors[1],reference=obs(old),native=new.observations)
  row['equal']=errors[0]==errors[1] and row['reference']==row['native'];rows.append(row)
  if not row['equal']:differences.append(dict(row,definitions=defs,flags=flags))
  if errors[0] is None and errors[1] is None:
   rng.shuffle(refs)
   for ref in refs:
    errors=[];values=[]
    for owner in [old,new]:
     try:values.append(owner.resolve(ref));errors.append(None)
     except HIAProgramRejected as e:values.append(None);errors.append(e.code)
    row=dict(seed=seed,stage='resolve',ref=ref,reference_error=errors[0],native_error=errors[1],reference=obs(old),native=new.observations)
    row['equal']=errors[0]==errors[1] and row['reference']==row['native'] and (errors[0] is not None or snap(values[0])==snap(values[1],new));rows.append(row)
    if not row['equal']:differences.append(dict(row,definitions=defs,flags=flags))
 finally:
  if hasattr(new,'_lock'):new.close()
result=dict(schema='hia.native-types-independent-mixed-audit.v1',checks=len(rows),differences=differences,seconds=time.monotonic()-start,rows=rows,source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),manifest_sha256=hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),cold_qualified=False)
Path('/workspace/scratch/9acdfa9f5639/types-independent-fuzz.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))
raise SystemExit(bool(differences))
