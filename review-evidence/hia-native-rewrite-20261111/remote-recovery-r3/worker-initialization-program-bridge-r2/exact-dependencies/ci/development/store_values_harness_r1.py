"""Actual-image Store.json/profile invocation transport, NEW unexecuted gate.

The namespace provider below only returns predeclared foreign fixtures.
It is not a native Store and never supplies a production publication claim.
"""
from __future__ import annotations
import ast,ctypes,json,os,struct,sys
from contextlib import ExitStack,contextmanager
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(os.environ['HIA_DIGEST_ROOT'])/'development'))
import digest_harness_r4 as H
from hepta import hia_agent_store as store
ROOT=Path(os.environ['HIA_STORE_VALUES_ROOT']).resolve()
M=H.M;pack=H.pack;Buffer=H.Buffer;BAD=H.BAD;MAX=(1<<64)-1
HANDLES=1<<63;WIRE_ERROR=M(b'HIAWSX01')
tree=ast.parse((ROOT/'tools/generate_hia_agent_worker_store_values.py').read_bytes())
names=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
 and any(isinstance(t,ast.Name) and t.id=='STATE_NAMES' for t in n.targets)))
S={name:i*8 for i,name in enumerate(names)}
helper=(ROOT/'dependencies/value_mechanics_source.py').read_bytes()
assert sha256(helper).hexdigest()=='1602df39c9dd982e42ece64379e76fc9ca123b7ca407e84d7f4ded767bebf753'
definition=next(n for n in ast.parse(helper).body if isinstance(n,ast.FunctionDef) and n.name=='decode_graph')
exec(compile(ast.Module(body=[definition],type_ignores=[]),'<exact-comparison-only-graph-observer>','exec'),globals())
def disabled(*args,**kwargs):raise AssertionError('old Store semantic owner disabled in actual native interval')
@contextmanager
def actual_only():
 with ExitStack() as stack:
  for target in ('hepta.hia_agent_store.AgentStore.json','hepta.hia_agent_store.AgentStore.profile',
   'hepta.hia_agent_store.AgentStore.put','hepta.hia_agent_store.wire',
   'hepta.hia_program_tools.bounded_json_wire','json.loads'):
   stack.enter_context(patch(target,new=disabled))
  yield
def load_component():
 comp=ROOT/'development/compile-r1'
 summary=json.loads(H.frozen(comp/'summary.json'))
 assert summary['status']=='PASS' and summary['actual_compiles']==1 and summary['source_unchanged']
 row=json.loads(H.frozen(comp/'worker-store-json-profile.manifest.json'))
 assert row['role']=='storevalues' and row['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
 current=ROOT/'examples/hia_bootstrap/agent_worker_store_json_profile.hiaasm'
 assert Path(row['source_path']).resolve()==current.resolve()
 assert Path(row['image_path']).resolve()==(comp/'worker-store-json-profile.image.bin').resolve()
 assert Path(row['receipt_path']).resolve()==(comp/'worker-store-json-profile.receipt.json').resolve()
 source=H.frozen(current,row['source_sha256'])
 assert H.frozen(comp/'worker-store-json-profile.input.bin')==source
 raw=H.frozen(comp/'worker-store-json-profile.image.bin',row['image_sha256'])
 receipt=json.loads(H.frozen(comp/'worker-store-json-profile.receipt.json'))
 assert (len(source),len(raw))==(row['source_bytes'],row['image_bytes'])
 assert receipt['input_sha256']==row['source_sha256'] and receipt['produced_sha256']==row['image_sha256']
 assert receipt['image_sha256']==row['compiler_sha256']
 for p in sorted(ROOT.joinpath('tools').glob('*.py')):H.frozen(p)
 for p in sorted(ROOT.joinpath('dependencies').glob('*')):
  if p.is_file():H.frozen(p)
 for item in json.loads(H.frozen(comp/'source-after.json')):
  p=Path(item['path']);data=H.frozen(p,item['sha256'])
  assert len(data)==item['bytes'] and p.stat().st_mode&4095==item['mode']
 assert H.same()
 H.images['storevalues']=H.NativeHiaJsonImage(raw,row['image_sha256'])
 (H.OUT/'source-before.json').write_text(json.dumps(H.pins,sort_keys=True,indent=2)+'\n')
def load_peers():
 reg=ROOT/'dependencies/recovered-registry'
 bundle=json.loads(H.frozen(reg/'bundle.json'))
 staged={}
 for role in ('registry','merge','scan','emit'):
  row=bundle['components'][role]
  raw=H.frozen(reg/(role+'.image.bin'),row['image_sha256'])
  source=H.frozen(reg/(role+'.input.bin'),row['source_sha256'])
  receipt=json.loads(H.frozen(reg/(role+'.receipt.json')))
  assert (len(raw),len(source))==(row['image_bytes'],row['source_bytes'])
  assert receipt['image_sha256']==row['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
  assert receipt['input_sha256']==row['source_sha256'] and receipt['produced_sha256']==row['image_sha256']
  staged[role]=(raw,row['image_sha256'])
 assert H.same()
 for role,payload in staged.items():H.images[role]=H.NativeHiaJsonImage(*payload)
def setup(out):
 # Select only the actual same-source registry/wire peers. The original
 # digest image and its SHA service are not invoked by Store.json/profile.
 original=H.load_images;H.load_images=load_peers
 try:H.setup(out,extra_roles=('sequence',))
 finally:H.load_images=original
 load_component()
def issued_packet(reg,packet):
 # This is a declared foreign issuer. Only the actual reserved lease word is
 # copied into its previously captured immutable payload.
 f=struct.unpack('<32Q',reg.reserve());raw=bytearray(packet)
 assert struct.unpack_from('<Q',raw)[0]==M(b'HIAGRF01')
 struct.pack_into('<Q',raw,8,f[9])
 return reg.packet(bytes(raw))[0]
def packet_checked(reg,foreign,expected):
 if hasattr(reg,'packet_checked'):return reg.packet_checked(foreign,expected)
 f=reg.step(3,foreign,foreign_bytes=len(foreign))
 assert reg.r.raw()==expected+foreign
 while f[1]==1:
  reg.w=reg.w.grow(f[8]);f=reg.step(5,foreign,foreign_bytes=len(foreign))
 assert f[1]==3
 child=Buffer(512)
 while True:
  raw=reg.w.raw()[f[13]:f[13]+f[14]]
  first=Buffer(len(raw),raw);second=Buffer(len(foreign),foreign)
  ret=H.invoke('merge',first,second,child,'store-values-native-profile-merge')
  assert ret==384
  f=reg.step(4,foreign+child.raw(),actual=ret,foreign_bytes=len(foreign),child_bytes=child.n)
  if f[1]==4:child=child.grow(f[12]);continue
  assert f[1]==6
  raw=reg.r.raw()[f[18]:f[18]+f[19]];reg.g=Buffer(len(raw),raw)
  return f[21],reg.w.raw()[512:768]
def observe_handle(reg,handle):
 header,config=reg.borrow(handle)
 root=struct.unpack_from('<Q',config,24)[0]
 return decode_graph(reg.g.raw(),root)
class PeerFailure(RuntimeError):pass
def reference(value,peer,ref,fail=None,error_text='injected namespace failure',identifier='hia-compiler-v1'):
 calls=[]
 class DB:
  def execute(self,sql,binds):
   calls.append(dict(operation=2,sql=sql,binds=tuple(binds)))
   if fail=='sql':raise PeerFailure(error_text)
 class Original(store.AgentStore):
  def put(self,data,kind,metadata=None):
   calls.append(dict(operation=1,wire=bytes(data),kind=kind,metadata=metadata))
   if fail=='put':raise PeerFailure(error_text)
   return ref
 owner=Original.__new__(Original);owner.db=DB()
 result=None;error=None
 try:
  result=owner.profile(identifier,value) if peer==11 else owner.json(value,'discovery')
 except Exception as exc:error=dict(error_class=type(exc).__name__,text=str(exc))
 plan=[]
 for call in calls:
  operation=call['operation']
  status=(fail=='put' and operation==1) or (fail=='sql' and operation==2)
  plan.append(dict(operation=operation,error=(
   b'fixture-issued-peer-exception:'+error_text.encode()) if status else None,
   result_packet=H.capture(ref,lease=1) if operation==1 and not status else None))
 return dict(result=result,error=error,calls=calls,plan=plan)
def sequence_entry(source,reply,w,label):
 previous=struct.unpack_from('<Q',w.raw(),1048)[0]
 ret=H.invoke('sequence',source,reply,w,label);assert ret==2304
 f=struct.unpack_from('<32Q',w.raw(),2048)
 assert f[0]==M(b'HIAWIE01') and f[2:5]==(37,83,previous+1)
 return f
def initial_reply(f,kind,one=0,two=0,authority=0,digest=b'\0'*32):
 fields=[M(b'HIAWIR01'),37,83,f[7],f[6],0,kind,0,one,two,0,authority,0,0,0,256]
 return Buffer(256,pack(*fields)+digest+b'\0'*96)
def actual_pending(value,peer,label,profile_index=0):
 # Only the initializer control and registry/import mechanism are native here.
 # All preceding semantic services are explicit fixed foreign fixtures.
 reg=H.InitialRegistry([]);source=reg.original;w=Buffer(8192)
 ctypes.memmove(ctypes.addressof(w.memory)+128,reg.initial_config,192)
 reply=Buffer(0);foreign=[];profile_count=0
 packets=[H.capture(v,lease=1) for v in ({'tools':[]},'0'*64,{},value,[])]
 def issue(index):return issued_packet(reg,packets[index])
 while True:
  f=sequence_entry(source,reply,w,label+'-initializer-prefix')
  if f[1]==1:w=w.grow(f[8]);continue
  assert f[1]==2,(label,f)
  if f[6]==peer and (peer!=11 or profile_count==profile_index):return reg,source,w,f,foreign
  if f[6]==11:profile_count+=1
  p=f[6];foreign.append(dict(peer=p,phase=f[5],pending=f[7]))
  if p==1:reply=initial_reply(f,1,issue(0),issue(1))
  elif p==2 or p==3:reply=initial_reply(f,2,issue(2))
  elif p==4:reply=initial_reply(f,3,authority=30001)
  elif p==7:
   reply=initial_reply(f,6,authority=50001) if f[13]==0 else initial_reply(f,2,issue(4))
  elif p==8:reply=initial_reply(f,7,issue(1))
  elif p==9 or p==12 or p==19:reply=initial_reply(f,2,issue(3))
  elif p==10:
   reply=initial_reply(f,8,issue(2),issue(2)) if f[13] in (1,2) else initial_reply(f,2,issue(2))
  elif p==11:reply=initial_reply(f,9,issue(2),issue(2))
  else:raise AssertionError(('unexpected actual initializer prefix',f))
class Route:
 def __init__(self,reg,initializer_workspace,plan,label='store-values',capture_steps=False,
              own_short_once=False):
  self.reg=reg;self.label=label;self.w=Buffer(16384);self.ww=None
  self.plan=list(plan);self.plan_index=0;self.capture_steps=capture_steps;self.records=[]
  self.events=[];self.observations=[];self.namespace_calls=0;self.producer_calls=0
  self.wire_starts=0;self.own_grows=0;self.producer_grows=0;self.short=own_short_once
  self.last=None;self.reply=None;self.handle=None;self.ref_handle=None
  iw=bytes(initializer_workspace);f=struct.unpack_from('<32Q',iw,2048)
  borrow,config=reg.borrow(f[14])
  self.call(1,iw+borrow+config,2304,1,len(iw),768,0)
 def command(self,op,payload,actual,role,extent,aux0=0,aux1=0):
  g=self.reg.g
  return pack(M(b'HIAWSV01'),op,37,83,909,struct.unpack_from('<Q',self.w.raw(),S['SEQ'])[0],
   struct.unpack_from('<Q',g.raw(),8)[0],g.n,len(payload),actual,role,extent,aux0,aux1,
   struct.unpack_from('<Q',self.w.raw(),S['ACTION'])[0],0)+payload
 def call(self,op,payload=b'',actual=0,role=0,extent=0,aux0=0,aux1=0):
  raw=self.command(op,payload,actual,role,extent,aux0,aux1);g=self.reg.g
  before=self.w.raw() if self.capture_steps else None
  second=Buffer(len(raw),raw);ret=H.invoke('storevalues',g,second,self.w,self.label+'-op'+str(op))
  f=struct.unpack_from('<32Q',self.w.raw(),512)
  if self.capture_steps:self.records.append(dict(source=g.raw(),command=raw,workspace=before,
   result=ret,after=self.w.raw(),frame=f))
  assert ret==768,(self.label,op,ret,f)
  assert f[0]==M(b'HIAWSE01') and f[2:5]==(37,83,909) and f[5]==len(self.events)+1
  self.f=f;self.events.append(f)
  self.last=(payload,actual,role,extent,aux0,aux1)
  return f
 def namespace(self):
  f=self.f
  assert self.plan_index<len(self.plan),('unexpected namespace effect',f)
  item=self.plan[self.plan_index];self.plan_index+=1;self.namespace_calls+=1
  request=self.w.raw()[f[15]:f[15]+f[16]];q=struct.unpack('<16Q',request)
  assert q[:7]==(M(b'HIAWNP01'),item['operation'],37,83,f[10],909,f[11])
  if f[1]==3:
   assert item['operation']==1
   self.observations.append(dict(operation=1,wire=self.w.raw()[f[17]:f[17]+f[18]],
    kind=self.w.raw()[f[19]:f[19]+f[20]],metadata=None,request=H.save(request)))
  else:
   assert f[1]==4 and item['operation']==2
   self.observations.append(dict(operation=2,graph=self.w.raw()[f[21]:f[21]+f[22]],
    root=f[23],sql_id=q[15],request=H.save(request)))
  error=item['error'];handle=0;lease=0;size=0;tail=b''
  if error is not None:tail=error
  elif item['operation']==1:
   handle=issued_packet(self.reg,item['result_packet'])
   borrowed,config=self.reg.borrow(handle);tail=borrowed+config
   lease=struct.unpack_from('<Q',self.reg.g.raw(),8)[0];size=self.reg.g.n
  header=pack(M(b'HIAWNR01'),item['operation'],37,83,f[10],909,f[11],int(error is not None),
   handle,lease,size,90001 if error is not None else 0,len(error) if error is not None else 0,
   1000+self.namespace_calls,2000+self.namespace_calls,256+len(tail))
  self.call(3,header+request+tail,256,3 if item['operation']==1 else 4,256+len(tail))
 def step(self):
  f=self.f;action=f[1]
  if action==9 or action==1:
   if action==9:
    assert f[13]==1 and f[14]==32768
    self.ww=Buffer(f[14]);self.wire_starts+=1
   else:
    assert self.ww is not None
    if f[14]>self.ww.n:self.ww=self.ww.grow(f[14]);self.producer_grows+=1
   cfg=self.w.raw()[f[15]:f[15]+f[16]];second=Buffer(len(cfg),cfg)
   role={1:'scan',2:'emit'}[f[13]]
   ret=H.invoke(role,self.reg.g,second,self.ww,self.label+'-'+role)
   self.producer_calls+=1
   self.call(2,self.ww.raw(),ret,f[13],self.ww.n)
  elif action==2:
   needed=f[12];assert needed>self.w.n
   if self.short and needed>self.w.n+1:
    self.w=self.w.grow(needed-1);self.short=False
   else:self.w=self.w.grow(needed)
   self.own_grows+=1
   payload,ret,role,extent,a,b=self.last
   self.call(4,payload,ret,role,extent,a,b)
  elif action in (3,4):self.namespace()
  elif action==6:
   request=self.w.raw()[f[15]:f[15]+f[16]]
   actual=self.reg.reserve()
   if hasattr(self.reg,'reserved_request'):raw=self.reg.reserved_request()
   else:raw=self.reg.r.raw()
   assert raw==request
   self.call(5,actual,768,5,256)
  elif action==7:
   request=self.w.raw()[f[15]:f[15]+f[16]]
   graph=self.w.raw()[f[21]:f[21]+f[22]]
   handle,event=packet_checked(self.reg,graph,request)
   self.call(6,event,768,5,256)
   assert self.f[1]==0 and self.f[31]>HANDLES
   self.handle=handle
  elif action==0 or action==5:
   self.reply=self.w.raw()[f[27]:f[27]+f[28]]
   assert len(self.reply)>=256 and struct.unpack_from('<Q',self.reply,120)[0]==len(self.reply)
   self.ref_handle=f[31]
   return False
  else:raise AssertionError(('unexpected store values event',f))
  return True
 def finish(self):
  while self.step():pass
  assert self.plan_index==len(self.plan)
  return self.reply
 def validate(self,expected,peer):
  actual=[]
  for item in self.observations:
   if item['operation']==1:actual.append(dict(operation=1,wire=item['wire'],
    kind=item['kind'].decode(),metadata=item['metadata']))
   else:
    assert item['sql_id']==5
    binds=decode_graph(item['graph'],item['root'])
    actual.append(dict(operation=2,sql='INSERT OR IGNORE INTO profiles VALUES (?,?,?)',binds=tuple(binds)))
  assert actual==expected['calls'],(actual,expected['calls'])
  q=struct.unpack_from('<32Q',self.reply)
  assert q[:3]==(M(b'HIAWIR01'),37,83) and q[4]==peer
  if expected['error'] is None:
   assert q[5:7]==(0,9 if peer==11 else 2)
   if peer==11:
    result=(observe_handle(self.reg,q[8]),observe_handle(self.reg,q[9]))
    assert q[9]==self.ref_handle and self.wire_starts==2
   else:
    result=observe_handle(self.reg,q[8]);assert q[8]==self.ref_handle and self.wire_starts==1
   assert result==expected['result'],(result,expected['result'])
  else:
   assert q[5]==1 and q[13:15]==(256,len(self.reply)-256)
   payload=self.reply[256:]
   if expected['error']['error_class']=='PeerFailure':
    assert q[12]==90001 and payload==b'fixture-issued-peer-exception:'+expected['error']['text'].encode()
   else:
    assert q[12]==909 and len(payload)>=64 and struct.unpack_from('<Q',payload)[0]==WIRE_ERROR
    assert payload[64:].decode()==expected['error']['text']
