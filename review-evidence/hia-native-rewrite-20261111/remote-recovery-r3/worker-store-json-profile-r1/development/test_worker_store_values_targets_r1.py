"""Fresh actual Store.json/profile complete-method, continuation and protocol gates."""
from __future__ import annotations
import copy,json,struct,sys,time,traceback
from pathlib import Path
import store_values_harness_r1 as V
H=V.H;Buffer=V.Buffer;pack=V.pack;M=V.M;BAD=V.BAD;MAX=V.MAX
GROUP=sys.argv[1];OUT=Path(sys.argv[2]).resolve()
cases=[];planned=0;status='FAIL';failure=None;started=time.monotonic_ns()
def record(label,before,**fields):
 row=dict(label=label,status='PASS',entries={k:v-before.get(k,0) for k,v in H.counts.items()},**fields)
 cases.append(row)
 (OUT/'cases.json').write_text(json.dumps(cases,sort_keys=True,indent=2)+'\n')
 print(json.dumps(dict(case=len(cases),label=label,status='PASS')),flush=True)
def default_ref():
 return {'id':'fixture-issued-id','sha256':'a'*64,'uri':'hia://artifacts/fixture-issued-uri'}
def one(label,value,peer=11,ref=None,fail=None,error_text='injected namespace failure',
        capture_steps=False,short=False,profile_index=0):
 reference_ref=default_ref() if ref is None else ref
 names=('compiler','target','backend','artifact','validation','lowering','plan')
 expected=V.reference(value,peer,reference_ref,fail,error_text,'hia-'+names[profile_index]+'-v1')
 before=dict(H.counts)
 # Expected bytes, results and exceptions are all produced by the complete
 # original methods before disabling those owners and starting this route.
 with V.actual_only():
  reg,source,iw,f,foreign=V.actual_pending(value,peer,label,profile_index)
  prior_snapshot=iw.raw()[4096:4608]
  route=V.Route(reg,iw.raw(),expected['plan'],label,capture_steps,short)
  reply=route.finish()
  result=V.sequence_entry(source,Buffer(len(reply),reply),iw,label+'-consume-actual-store-reply')
 route.validate(expected,peer)
 if expected['error'] is not None:
  assert result[1]==3 and result[27:29]==(0,3)
  assert iw.raw()[4096:4608]==prior_snapshot
  assert reply[result[30]:result[30]+result[31]]==reply[256:]
 elif peer==11:
  assert result[1]==2 and result[5:7]==(35,10)
  q=struct.unpack_from('<32Q',reply)
  assert result[16:18]==q[8:10]
 else:
  assert result[1]==2 and result[5:7]==(41,12) and result[13]==2
 record(label,before,peer=peer,expected_error=expected['error'],
  actual_initializer_pending=H.save(route.records[0]['command'][128:128+iw.n]) if capture_steps else None,
  final_reply=H.save(reply),final_snapshot=H.save(iw.raw()[4096:4608]),
  actual_initializer_reply_consumed=True,namespace_calls=route.namespace_calls,
  namespace_result_issuance_is_foreign=True,actual_physical_namespace_entries=0,
  wire_sessions=route.wire_starts,wire_entries=route.producer_calls,
  own_grows=route.own_grows,wire_grows=route.producer_grows,
  preceding_foreign_peers=foreign,complete_original_method_oracle=True)
 return route
def semantics():
 global planned
 values=[('none',None),('bool',True),('integer',-(1<<200)),('negative-zero',-0.0),
  ('finite',1.25),('unicode','é中🙂'),('map-order',{'z':2,'é':1,'a':3}),('tuple',(1,'x',None))]
 controls=[('profile-'+label,value,11,None) for label,value in values]
 controls += [('json-'+label,value,15,None) for label,value in values]
 for label,sha in [('null-sha',None),('integer-sha',123),('real-sha',-0.0),
                   ('unicode-sha','é中🙂'),('zero-sha',0)]:
  ref=default_ref();ref['sha256']=sha
  controls.append((label,{'n':1},11,ref))
 planned=len(controls)+6
 for label,value,peer,ref in controls:one(label,value,peer,ref)
 for index in range(1,7):one('profile-identifier-'+str(index),{'a':1},profile_index=index)
def errors():
 global planned
 cycle=[];cycle.append(cycle)
 controls=[]
 for peer in (11,15):
  for label,value in [('bytes',b'x'),('nan',float('nan')),('surrogate','\ud800'),('cycle',cycle)]:
   controls.append(('value-'+str(peer)+'-'+label,value,peer,None,None))
  controls.append(('put-error-'+str(peer),{'a':1},peer,None,'put'))
 controls.append(('sql-error',{'a':1},11,None,'sql'))
 for label,value in [('ref-bytes',b'x'),('ref-surrogate','\ud800'),('ref-nan',float('nan'))]:
  ref=default_ref();ref['sha256']=value;controls.append((label,{},11,ref,None))
 planned=len(controls)
 for label,value,peer,ref,fail in controls:one(label,value,peer,ref,fail)
def grows():
 global planned
 controls=[
  ('json-wire-own-one-short','x'*65537,15,None,None,'unused'),
  ('profile-two-wire-grows',{'large':'z'*65537},11,dict(
    id='i'*65537,sha256='a'*64,uri='hia://artifacts/'+'u'*65537),None,'unused'),
  ('put-exception-grow',{},11,None,'put','e'*65537),
  ('sql-exception-grow',{},11,None,'sql','e'*65537)]
 planned=len(controls)
 for label,value,peer,ref,fail,text in controls:
  route=one(label,value,peer,ref,fail,text,short=True)
  assert route.own_grows>=2
  if fail is not None:assert route.namespace_calls==(1 if fail=='put' else 2)
def large():
 global planned
 planned=1
 if GROUP=='large-value-8m':one('actual-value-wire-exact-8MiB','x'*(8388608-2),15)
 elif GROUP=='large-value-over':one('actual-value-wire-8MiB-plus1','x'*(8388609-2),15)
 else:
  assert GROUP=='large-ref-8m'
  # The exact original wire determines the valid identifier fill before the
  # actual interval. No native gate is bypassed or adjusted.
  ref=default_ref()
  from hepta.hia_agent_store import wire
  overhead=len(wire(ref))-len(ref['id'])
  ref['id']='x'*(8388608-overhead)
  assert len(wire(ref))==8388608
  one('actual-reference-wire-exact-8MiB',None,11,ref)
def mutate(raw,offset,value):
 data=bytearray(raw);struct.pack_into('<Q',data,offset,value);return bytes(data)
def refuse(label,seed,s=None,r=None,w=None,short=False):
 before=dict(H.counts)
 a=seed['source'] if s is None else s
 b=seed['command'] if r is None else r
 c=seed['workspace'] if w is None else w
 assert short or (a,b,c)!=(seed['source'],seed['command'],seed['workspace'])
 source=Buffer(len(a),a);command=Buffer(len(b),b);work=Buffer(len(c),c)
 if short:
  small=Buffer(16383,c[:16383]);initial=small.raw()
  ret=H.invoke('storevalues',source,command,small,label)
  assert ret==BAD and small.raw()==initial
 else:
  ret=H.invoke('storevalues',source,command,work,label)
  assert ret==BAD,(label,ret,struct.unpack_from('<32Q',work.raw(),512))
  poisoned=work.raw()
  assert H.invoke('storevalues',source,Buffer(len(seed['command']),seed['command']),work,label+'-retry')==BAD
  assert work.raw()==poisoned
 record(label,before,private_protocol=True,short_requires_outer_retirement=short)
def protocols():
 global planned
 # One complete actual chain yields provenance-bound seeds for every stage.
 value={'a':[1,'é',True]}
 expected=V.reference(value,11,default_ref())
 with V.actual_only():
  reg,source,iw,f,foreign=V.actual_pending(value,11,'protocol-seed')
  route=V.Route(reg,iw.raw(),expected['plan'],'protocol-seed',capture_steps=True)
  route.finish()
 route.validate(expected,11)
 seeds=route.records
 begin=seeds[0]
 wire=next(x for x in seeds if struct.unpack_from('<Q',x['command'],8)[0]==2)
 namespace=next(x for x in seeds if struct.unpack_from('<Q',x['command'],8)[0]==3)
 reserved=next(x for x in seeds if struct.unpack_from('<Q',x['command'],8)[0]==5)
 bound=next(x for x in seeds if struct.unpack_from('<Q',x['command'],8)[0]==6)
 cont=next(x for x in seeds if struct.unpack_from('<Q',x['command'],8)[0]==4)
 controls=[]
 def field(seed,offset,value,label):
  current=struct.unpack_from('<Q',seed['command'],offset)[0]
  if current==value:value=value+1
  controls.append((label,seed,dict(r=mutate(seed['command'],offset,value))))
 for i in range(16):
  field(begin,i*8,MAX if i in (6,7,8,11) else 0,'begin-command-'+str(i))
 for i in (0,1,2,3,6,7):
  raw=begin['source'];old=struct.unpack_from('<Q',raw,i*8)[0]
  controls.append(('begin-source-'+str(i),begin,dict(s=mutate(raw,i*8,old^1))))
 iw_size=struct.unpack_from('<Q',begin['command'],88)[0]
 for i in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,20,21,22,23,24,25,26,27,28,29,30,31):
  field(begin,128+2048+i*8,MAX if i in (23,24) else 0,'initializer-event-'+str(i))
 for i in (0,1,2,3,4,5,6,7,8,17,18,19,20,21,22,23,24,25,26,27,29,30,31):
  field(begin,128+iw_size+i*8,MAX if i==20 else 0,'borrow-event-'+str(i))
 for i in range(8):
  field(begin,128+iw_size+256+i*8,0,'borrow-config-'+str(i))
 for seed,name in ((wire,'wire'),(namespace,'namespace'),(reserved,'reserved'),(bound,'bound'),(cont,'continue')):
  for i in (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15):
   field(seed,i*8,0,'frame-'+name+'-'+str(i))
 for i in range(32):
  # The status=1 mutation needs an error payload; changing only status must
  # still be refused because the result fields and total are inconsistent.
  field(namespace,128+i*8,0,'namespace-receipt-'+str(i))
 for i in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31):
  field(bound,128+i*8,0,'bound-event-'+str(i))
 controls.append(('dirty-initial-state',begin,dict(w=mutate(begin['workspace'],4096,1))))
 controls.append(('sequence-exhaustion',wire,dict(w=mutate(wire['workspace'],V.S['SEQ'],MAX))))
 controls.append(('short-workspace',begin,dict(short=True)))
 planned=len(controls)
 for label,seed,kwargs in controls:refuse(label,seed,**kwargs)
try:
 V.setup(OUT)
 {'semantic':semantics,'errors':errors,'protocol':protocols,'growth':grows,
  'large-value-8m':large,'large-value-over':large,'large-ref-8m':large}[GROUP]()
 assert len(cases)==planned,(len(cases),planned)
 assert H.same();status='PASS'
except BaseException as exc:
 failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
 unchanged=H.same()
 if not unchanged:status='FAIL'
 summary=dict(status=status,group=GROUP,cases=len(cases),planned_cases=planned,
  entries=H.counts,total_actual_entries=sum(H.counts.values()),failure=failure,
  elapsed_ns=time.monotonic_ns()-started,source_unchanged=unchanged,
  original_limits=dict(cpu_seconds=90,address_space_bytes=1<<30),
  scope='ACTUAL_COMPLETE_INITIALIZER_STORE_JSON_PROFILE_WITH_FOREIGN_NAMESPACE',
  actual_physical_namespace_entries=0,preceding_initializer_peers_are_foreign=True,
  original_methods_disabled_during_native=True,runtime_mechanical_python=True,
  no_extra_commit_or_reexecution=True,ordinary_store_closed=False,whole_worker_closed=False)
 if OUT.exists():(OUT/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
 print(json.dumps(summary,sort_keys=True),flush=True)
 H.close()
if status!='PASS':raise SystemExit(1)
