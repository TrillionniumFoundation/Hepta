"""New actual digest composition gates; 0 inherited native qualification.

All first-run originals are separate from the unavailable local drafts.
"""
from __future__ import annotations
import ctypes,json,pathlib,struct,sys,time,traceback
from hashlib import sha256
from unittest.mock import patch
import digest_harness_r3 as H
from hepta.hia_program_tools import bounded_json_wire
GROUP=sys.argv[1];OUT=pathlib.Path(sys.argv[2]).resolve()
M=H.M;pack=H.pack;Buffer=H.Buffer;BAD=H.BAD
cases=[];planned=0;failure=None;status='FAIL';start=time.monotonic_ns()
def oracle(value):
 try:return bounded_json_wire(value,8388608,ensure_ascii=False,sort_keys=True),None
 except Exception as exc:return None,str(exc)
def record(label,before,**extra):
 row=dict(label=label,status='PASS',entries={k:v-before.get(k,0) for k,v in H.counts.items()},**extra)
 cases.append(row);(OUT/'cases.json').write_text(json.dumps(cases,sort_keys=True,indent=2)+'\n')
 print(json.dumps(dict(case=len(cases),label=label,status='PASS')),flush=True)
def sequence_entry(source,reply,w,label):
 previous=struct.unpack_from('<Q',w.raw(),1048)[0]
 ret=H.invoke('sequence',source,reply,w,label)
 assert ret==2304,(ret,struct.unpack_from('<16Q',w.raw(),1024))
 f=struct.unpack_from('<32Q',w.raw(),2048)
 assert f[0]==M(b'HIAWIE01') and f[2:5]==(37,83,previous+1)
 return f
def foreign_reply(f,kind,one=0,two=0,authority=0):
 q=[M(b'HIAWIR01'),37,83,f[7],f[6],0,kind,0,one,two,0,authority,0,0,0,256]+[0]*16
 return Buffer(256,pack(*q))
def initializer_pending(paths,root_strings,label):
 reg=H.InitialRegistry(paths);source=reg.original
 w=Buffer(8192);ctypes.memmove(ctypes.addressof(w.memory)+128,reg.initial_config,192)
 reply=Buffer(0);foreign=[]
 while True:
  f=sequence_entry(source,reply,w,label+'-sequence-prefix')
  if f[1]==1:w=w.grow(f[8]);continue
  assert f[1]==2
  peer=f[6]
  if peer==8:return reg,source,w,f,foreign
  foreign.append(dict(peer=peer,phase=f[5],pending=f[7]))
  if peer==1:
   a=reg.import_value({'tools':[]});b=reg.import_value('a'*64)
   reply=foreign_reply(f,1,a,b)
  elif peer==2:reply=foreign_reply(f,2,reg.import_value({}))
  elif peer==3:reply=foreign_reply(f,2,reg.import_value({'compiler':'fixture'}))
  elif peer==4:reply=foreign_reply(f,3,authority=30001)
  elif peer==5:
   index=f[16];assert index<len(paths)
   reply=foreign_reply(f,4,reg.import_value(paths[index]),authority=40001+index)
  elif peer==6:reply=foreign_reply(f,5,1,authority=f[14])
  elif peer==7:
   if f[13]==0:reply=foreign_reply(f,6,authority=50001)
   else:
    assert f[13]==1
    reply=foreign_reply(f,2,reg.import_value(root_strings))
  else:raise AssertionError(('unexpected-prefix-peer',f))
def initializers():
 global planned
 controls=[('empty',[],[]),('unicode',['/é','/中🙂'],['/resolved/é','/resolved/中🙂']),
  ('duplicate',['/same','/same'],['/resolved/same','/resolved/same']),
  ('foreign-surrogate',[],['\ud800'])]
 cycle=[];cycle.append(cycle);controls.append(('foreign-cycle',[],cycle))
 planned=len(controls)
 for label,paths,values in controls:
  expected,error=oracle(values);before=dict(H.counts)
  with patch('hepta.hia_program_tools.bounded_json_wire',side_effect=AssertionError('host wire disabled')):
   reg,source,iw,f,foreign=initializer_pending(paths,values,label)
   assert f[5:8]==(14,8,f[4])
   actual_pending=iw.raw()[2048:2304]
   route=H.Route(reg,f[14],actual_pending,label=label)
   reply=route.finish();route.validate(expected,error)
   actual=sequence_entry(source,Buffer(len(reply),reply),iw,label+'-actual-digest-reply')
  if error is None:
   assert actual[1]==2 and actual[5:7]==(30,9)
   assert actual[17]==route.handle and actual[18:20]==(0,0)
   assert struct.unpack_from('<Q',iw.raw(),1024+28*8)[0]==route.handle
  else:
   assert actual[1]==3 and actual[27:30]==(0,3,909)
   assert reply[actual[30]:actual[30]+actual[31]]==reply[256:]
   assert struct.unpack_from('<Q',iw.raw(),1024+28*8)[0]==0
  record(label,before,actual_pending=H.save(actual_pending),actual_reply=H.save(reply),
   actual_following_event=H.save(iw.raw()[2048:2304]),error=error,
   preceding_peers_are_foreign=foreign,actual_initializer_digest_peer=True,
   namespace_entries=0,ordinary_initialization_closed=False)
def pipeline_case(label,value):
 expected,error=oracle(value);before=dict(H.counts)
 with patch('hepta.hia_program_tools.bounded_json_wire',side_effect=AssertionError('host wire disabled')):
  reg=H.Registry();handle=reg.import_value(value);route=H.Route(reg,handle,label=label)
  reply=route.finish();route.validate(expected,error)
 record(label,before,wire_bytes=None if expected is None else len(expected),error=error,
  own_grows=route.own_grows,wire_grows=route.peer_grows,wire_actual_calls=route.producer_calls,
  sha_actual_calls=route.sha_calls,actual_reply=H.save(reply),actual_namespace_entries=0)
def semantics():
 global planned
 cycle=[];cycle.append(cycle)
 values=[('none',None),('bool',True),('integer',-(1<<200)),('negative-zero',-0.0),
  ('finite',1.25),('unicode','é中🙂'),('map-order',{'z':2,'é':1,'a':3}),
  ('tuple',(1,'x',None)),('bytes',b'x'),('nan',float('nan')),('surrogate','\ud800'),('cycle',cycle)]
 planned=len(values)
 for label,value in values:pipeline_case(label,value)
def boundaries():
 global planned
 if GROUP=='chunks':lengths=[65535,65536,65537,131073]
 elif GROUP=='large-1m':lengths=[1048576]
 elif GROUP=='large-8m':lengths=[8388608]
 else:assert GROUP=='large-over';lengths=[8388609]
 planned=len(lengths)
 for length in lengths:pipeline_case('wire-'+str(length),'x'*(length-2))
def word(raw,offset,value):
 data=bytearray(raw);struct.pack_into('<Q',data,offset,value);return bytes(data)
def refusal(label,seed,command=None,source=None,workspace=None,short=False):
 before=dict(H.counts)
 sb=seed['source'] if source is None else source
 raw=seed['command'] if command is None else command
 wb=seed['workspace'] if workspace is None else workspace
 assert (sb,raw,wb)!=(seed['source'],seed['command'],seed['workspace']),('unchanged-control',label)
 s=Buffer(len(sb),sb);r=Buffer(len(raw),raw);w=Buffer(len(wb),wb)
 ret=H.invoke('digest',s,r,w,label)
 assert ret==BAD,(label,ret,struct.unpack_from('<32Q',w.raw(),512))
 if short:assert w.raw()==wb
 else:
  assert struct.unpack_from('<Q',w.raw(),8)[0]==99
  after=w.raw();valid=Buffer(len(seed['command']),seed['command']);original=Buffer(len(seed['source']),seed['source'])
  assert H.invoke('digest',original,valid,w,label+'-permanent')==BAD
  assert w.raw()==after
 record(label,before,private_protocol=True,short_workspace_requires_external_retirement=short,
  real_producer_seed=True,source=H.save(sb),command=H.save(raw),workspace=H.save(wb))
def protocols():
 global planned
 expected,error=oracle('seed-text')
 reg=H.Registry();handle=reg.import_value('seed-text')
 route=H.Route(reg,handle,capture_steps=True,label='protocol-seed')
 route.finish();route.validate(expected,error)
 begin=next(x for x in route.records if x['op']==1)
 wire=next(x for x in route.records if x['op']==2)
 grow=next(x for x in route.records if x['op']==4)
 sha_init=next(x for x in route.records if x['op']==3 and x['phase']==30)
 sha_update=next(x for x in route.records if x['op']==3 and x['phase']==31)
 sha_finish=next(x for x in route.records if x['op']==3 and x['phase']==32)
 bind=next(x for x in route.records if x['op']==5)
 controls=[]
 def add(label,seed,at,value):
  assert struct.unpack_from('<Q',seed['command'],at)[0]!=value,('unchanged-proposed-control',label)
  controls.append((label,seed,dict(command=word(seed['command'],at,value))))
 for index,value in ((0,0),(1,0),(1,6),(2,0),(2,38),(3,84),(4,0),(5,1),(6,54),(7,0),(8,0),(9,0),(10,1),(11,0),(12,2),(13,54),(14,1),(15,1)):
  add('begin-command-'+str(index)+'-'+str(value),begin,index*8,value)
 for index,value in ((0,0),(1,0),(2,38),(3,84),(4,0),(5,0),(6,54),(7,0),(8,1),(17,2),(18,1),(19,0),(20,0),(21,0),(22,0),(23,0),(24,0),(25,54),(26,0),(27,1),(28,1),(29,0),(30,1),(31,1)):
  add('borrow-'+str(index),begin,128+index*8,value)
 for index,value in ((0,0),(1,54),(2,0),(3,0),(4,8388607),(5,3),(6,639),(7,1)):
  add('wire-config-'+str(index),begin,384+index*8,value)
 for index,value in ((0,0),(1,0),(2,38),(3,84),(4,0),(5,0),(6,54),(7,0),(8,1),(9,0),(10,0),(11,1),(12,1),(13,1),(17,1),(24,0),(25,54),(26,0),(27,1),(28,1),(29,0),(30,0),(31,1)):
  add('reserve-'+str(index),begin,448+index*8,value)
 for index,value in ((0,0),(1,5),(2,0),(3,0),(4,0),(5,0),(6,3),(7,639),(8,1),(9,1),(11,1),(12,1),(13,99),(14,99),(15,1)):
  add('wire-event-'+str(index),wire,128+index*8,value)
 add('wire-event-need',wire,208,struct.unpack_from('<Q',wire['command'],208)[0]^1)
 for offset in (256,264,272,280,288,296,304,312,320,328,336,344,368,560):
  old=struct.unpack_from('<Q',wire['command'],128+offset)[0]
  add('wire-state-'+str(offset),wire,128+offset,old^1)
 for label,seed in (('init',sha_init),('update',sha_update),('finish',sha_finish)):
  for index,value in ((9,99),(10,4),(11,1183),(12,1),(13,54),(14,0)):
   add('sha-'+label+'-command-'+str(index),seed,index*8,value)
  for offset in (1088,1096,1104,1176):
   old=struct.unpack_from('<Q',seed['command'],160+offset)[0]
   add('sha-'+label+'-state-'+str(offset),seed,160+offset,old^1)
 for offset in (0,511):
  raw=bytearray(sha_update['command']);raw[160+offset]^=1
  controls.append(('sha-constant-'+str(offset),sha_update,dict(command=bytes(raw))))
 raw=bytearray(sha_finish['command']);raw[128]^=1
 controls.append(('sha-result-disagrees-with-state',sha_finish,dict(command=bytes(raw))))
 for index in (0,1,2,3,5,6,7,8,9,10,12,13,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31):
  old=struct.unpack_from('<Q',bind['command'],128+index*8)[0]
  add('bind-event-'+str(index),bind,128+index*8,old^1)
 add('bind-event-sequence-not-advanced',bind,160,struct.unpack_from('<Q',bind['workspace'],144)[0])
 add('bind-event-child-sequence-zero',bind,216,0)
 raw=bytearray(bind['source']);raw[-1]^=1
 controls.append(('bind-hex-value-disagrees',bind,dict(source=bytes(raw))))
 controls.append(('command-short',begin,dict(command=begin['command'][:127])))
 controls.append(('source-short',begin,dict(source=begin['source'][:63])))
 controls.append(('workspace-short',begin,dict(workspace=begin['workspace'][:131071],short=True)))
 for phase,seed in (('wire',wire),('sha',sha_update),('bind',bind)):
  for index in (2,3,4,5,6,7,8,13,14,15):
   old=struct.unpack_from('<Q',seed['command'],index*8)[0]
   add('replay-'+phase+'-field-'+str(index),seed,index*8,old^1)
 ir,isource,iw,ifields,foreign=initializer_pending([],[],'protocol-initializer')
 iroute=H.Route(ir,ifields[14],iw.raw()[2048:2304],capture_steps=True,label='initializer-seed')
 initial=iroute.records[0]
 for index in (0,1,2,3,4,5,6,7,8,9,10,11,13,14,15,20,21,22,23,24,25,26,27,28,29,30,31):
  old=struct.unpack_from('<Q',initial['command'],704+index*8)[0]
  add('initializer-event-'+str(index),initial,704+index*8,old^1)
 add('initializer-store-authority-zero',initial,800,0)
 planned=len(controls)+2
 for label,seed,args in controls:refusal(label,seed,**args)
 before=dict(H.counts);need=struct.unpack_from('<Q',grow['workspace'],24)[0]
 small=Buffer(need-1,grow['workspace'][:need-1]);s=Buffer(len(grow['source']),grow['source']);r=Buffer(len(grow['command']),grow['command'])
 ret=H.invoke('digest',s,r,small,'own-grow-still-small');assert ret==768
 f=struct.unpack_from('<32Q',small.raw(),512);assert f[1]==2 and f[12]==need
 record('own-grow-still-small',before,no_wire_or_sha_producer_reentry=True)
 before=dict(H.counts);done=Buffer(route.w.n,route.w.raw());raw=bind['command'];r=Buffer(len(raw),raw);s=Buffer(len(bind['source']),bind['source'])
 old=done.raw();assert H.invoke('digest',s,r,done,'completed-lease-retired')==BAD;assert done.raw()==old
 record('completed-lease-retired',before,private_protocol=True)
try:
 H.setup(OUT,('sequence',) if GROUP in ('initializer','protocol') else ())
 H.frozen(pathlib.Path(__file__))
 if GROUP=='initializer':initializers()
 elif GROUP=='protocol':protocols()
 elif GROUP=='semantic':semantics()
 else:boundaries()
 assert len(cases)==planned
 status='PASS'
except BaseException as exc:
 failure=dict(error_class=type(exc).__name__,error=str(exc));(OUT/'failure.log').write_text(traceback.format_exc());traceback.print_exc()
finally:
 unchanged=H.same()
 summary=dict(status=status,group=GROUP,cases=len(cases),planned_cases=planned,entries=H.counts,
  total_actual_entries=sum(H.counts.values()),failure=failure,source_unchanged=unchanged,
  elapsed_ns=time.monotonic_ns()-start,scope='NEW_DIGEST_ACTUAL_COMPONENT_TARGETS',
  limits=dict(cpu_seconds=90,address_space_bytes=1<<30),namespace_entries=0,
  fixed_ordinary_worker=False,source_graph_issuer_is_private_control=True)
 (OUT/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n');print(json.dumps(summary),flush=True)
 H.close()
if status!='PASS':raise SystemExit(1)
