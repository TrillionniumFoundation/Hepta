"""Native decision stages against the unchanged BackgroundOptimizer methods.

Only the documented pure continuation boundary is stopped. Candidate source
validation is fresh original verification; actual native validation is owned by
the full coordinator. This is not a whole-BG or runtime-publication claim.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes as C,json,math,random,struct,sys,threading
from types import SimpleNamespace
from unittest.mock import patch
W=Path(__file__).resolve().parents[1];sys.path.insert(0,str(W))
import hepta.hia_background_optimizer as bg
from hepta.hia_program import _verify_program_reference
from tools.qualify_hia_background_optimizer_admission import source
from tools.qualify_hia_background_optimizer_structure import Flat
from tools.qualify_hia_background_optimizer_json_capture import Capture,encode,unpack_tree
from tools.generate_hia_background_optimizer_decision import LABELS,ERRORS
NONE=(1<<64)-1
MAX=(1<<63)-1
class Stop(BaseException):pass
def stop(*a,**k):raise Stop()
def error(e):return {'type':type(e).__name__,'message':str(e)}
def pack(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(x):return sha256(pack(x)).hexdigest()
def original(owner,job,inputs,report,wall,mode):
 count=0
 def p(x):
  nonlocal count
  count+=1
  if mode==0 and count==2:raise Stop()
  return pack(x)
 try:
  with patch.object(bg,'_pack',side_effect=p),patch.object(bg,'verify_program',side_effect=stop if mode==1 else _verify_program_reference):
   result=owner._decision(job,inputs,report,wall)
  return {'kind':0 if result[0]is None else 3,'actual':result[1],'total':result[2]}
 except Stop:return {'kind':1 if mode==0 else 2}
 except Exception as e:return {'error':error(e)}
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--capture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
 D=args.output;D.mkdir(exist_ok=False);flat=Flat(args.directory/'background_optimizer_decision.flat');cap=Capture(args.capture)
 base=_verify_program_reference(source());candidate=_verify_program_reference(source(name='candidate'))
 owner=object.__new__(bg.BackgroundOptimizer);owner._function='calculate';owner._baseline=base
 owner._condition=threading.Condition();owner._same_snapshot=lambda job:True;owner._last_program=base
 job=SimpleNamespace(baseline=base,epoch=0,generation=0,number=1,submitted_ns=0,submit_work_ns=10,enqueued_ns=20,cancellation=SimpleNamespace(cancelled=lambda:False))
 def good():
  inputs={'candidates':[{'id':'fast','program':candidate.as_dict()}],
   'observations':{'abstain':{'search_ns':7,'program_sha256':base.sha256,'runtime_ns':1000,'uncertainty_ns':5},'fast':{'search_ns':11,'program_sha256':candidate.sha256,'runtime_ns':10,'uncertainty_ns':2}},
   'objective':{'target':bg.TARGET,'expected_calls':100,'resource_cap_ns':1000000}}
  report={'schema':bg.RANK_SCHEMA,'before_sha256':base.sha256,'before_input_sha256':base.input_sha256,'function':'calculate','generation':1,
   'observations_sha256':digest(inputs['observations']),'objective':copy.deepcopy(inputs['objective']),
   'objective_sha256':digest({'schema':bg.RANK_SCHEMA,'objective':inputs['objective'],'function':'calculate','before_sha256':base.sha256,'before_input_sha256':base.input_sha256}),
   'selected_id':'fast','admitted':True,'costs':{'actual_adapter_ns':20,'supplied_search_ns':18,'total_search_ns':38},
   'selected_program':candidate.as_dict(),'net_margin_ns':(995-12)*100-38}
  return inputs,report
 def rebind(inputs,report):
  report['observations_sha256']=digest(inputs['observations'])
  report['objective']=copy.deepcopy(inputs['objective'])
  report['objective_sha256']=digest({'schema':bg.RANK_SCHEMA,'objective':inputs['objective'],'function':owner._function,'before_sha256':base.sha256,'before_input_sha256':base.input_sha256})
 def frame(mode,inputs,report,wall=1000,candidatehash=None,rankedhash=None,clocks=None):
  ir=encode(inputs);rc,ia,_,_=cap.decode(ir);assert rc==0
  rr=encode(report);rc,ra,_,_=cap.decode(rr);assert rc==0
  fn=owner._function.encode('utf-8','surrogatepass');gen=encode(job.epoch+1)
  ro=pack(report.get('objective'))if mode else b''
  io=pack(inputs['objective'])if mode else b''
  h=bytearray(512);h[:8]=b'HIABDC01';struct.pack_into('<10Q',h,8,mode,len(ir),len(ia),len(rr),len(ra),len(fn),len(gen),len(ro),len(io),wall)
  h[96:128]=bytes.fromhex(base.sha256);h[128:160]=bytes.fromhex(base.input_sha256);h[160:192]=bytes.fromhex(digest(inputs['observations']))
  objective={'schema':bg.RANK_SCHEMA,'objective':inputs['objective'],'function':owner._function,'before_sha256':base.sha256,'before_input_sha256':base.input_sha256}
  h[192:224]=bytes.fromhex(digest(objective));h[224:256]=bytes.fromhex(candidatehash or candidate.sha256);h[256:288]=bytes.fromhex(rankedhash or candidate.sha256)
  if clocks:struct.pack_into('<3Q',h,288,*clocks)
  return bytes(h)+ir+ia+rr+ra+fn+gen+ro+io,ir,ia,rr,ra
 def native(raw,ia,ra):
  wn=max(131072,struct.unpack_from('<Q',ia,8)[0],struct.unpack_from('<Q',ra,8)[0])
  s=C.create_string_buffer(raw);o=C.create_string_buffer(288);w=C.create_string_buffer(wn+32)
  C.memset(o,0xdb,len(o));C.memset(w,0xa5,len(w))
  rc=flat.entry(s,len(raw),C.addressof(o)+16,256,C.addressof(w)+16,wn)
  assert s.raw==raw+b'\0'and o.raw[:16]+o.raw[-16:]==b'\xdb'*32 and w.raw[:16]+w.raw[-16:]==b'\xa5'*32
  out=o.raw[16:272]
  if rc:return rc,None,out
  words=struct.unpack('<8s31Q',out);assert words[0]==b'HIABDR01'
  return 0,words,out
 def decode_error(words,ir,ia,rr,ra):
  ident=words[3]
  if ident in ERRORS:
   typ,message=ERRORS[ident];return {'type':typ,'message':message}
  if 200<=ident<299:return error(KeyError(LABELS[ident-200]))
  if ident==299:
   which,node=words[4],words[5]
   _,values=unpack_tree(rr if which else ir,ra if which else ia)
   return error(KeyError(values[node]))
  raise AssertionError(('unknown error',ident))
 rows=[];counts={};reportout={'passed':False,'whole_background_qualified':False,'scope':__doc__,'flat_sha256':flat.sha,'capture_sha256':cap.flat.sha,'cases':rows,'counts':counts}
 def save():(D/'qualification.json').write_text(json.dumps(reportout,indent=2)+'\n')
 def run(name,mode,inputs,report,wall=1000,expected=None,**kw):
  expected=original(owner,job,inputs,report,wall,mode)if expected is None else expected
  raw,ir,ia,rr,ra=frame(mode,inputs,report,wall=wall,**kw);rc,head,out=native(raw,ia,ra)
  actual=None
  try:
   assert rc==0,(rc,name)
   if head[1]:actual={'error':decode_error(head,ir,ia,rr,ra)}
   else:
    actual={'kind':head[8]}
    if head[8]in(0,3):actual.update(actual=head[9],total=head[10])
   assert actual==expected,(name,actual,expected)
  except BaseException:
   (D/'failure.input').write_bytes(raw);(D/'failure.output').write_bytes(out)
   (D/'failure.json').write_text(json.dumps({'case':name,'mode':mode,'rc':rc,'actual':actual,'expected':expected,'head':head,'completed':len(rows)},default=lambda x:x.decode()if type(x)is bytes else repr(x),indent=2)+'\n');raise
  rows.append({'case':name,'stage':mode,'input_sha256':sha256(raw).hexdigest(),'result':actual,'passed':True});counts[str(mode)]=counts.get(str(mode),0)+1
  if len(rows)%100==0:save();print('BG_DECISION_CASE',len(rows),name,flush=True)
  return head
 inputs,rep=good();run('good-binding',0,inputs,rep);run('good-cost-selection',1,inputs,rep);run('good-selected-source',2,inputs,rep)
 values=[None,False,True,-1,0,1,2,MAX,MAX+1,1<<64,10**100,0.0,-0.0,1.0,1.5,1e300,math.inf,-math.inf,math.nan,'','fast','abstain','calculate',[],{},[1]]
 for key in ['schema','before_sha256','before_input_sha256','function','generation','observations_sha256']:
  for i,v in enumerate(values):
   x,r=good();r[key]=v;run('binding-'+key+'-'+str(i),0,x,r)
 for n in [0,1,2,2**53-1,2**53,2**53+1,2**64-1,2**64,2**100,2**1023,10**10000]:
  job.epoch=n-1
  for i,v in enumerate([n,n+1,float(n)if n.bit_length()<1024 else math.inf,False,True]):
   x,r=good();r['generation']=v;run('generation-'+str(n.bit_length())+'-'+str(i),0,x,r)
 job.epoch=0
 for key in ['admitted','selected_id','costs','net_margin_ns']:
  for i,v in enumerate(values):
   x,r=good();r[key]=v
   if key=='net_margin_ns':r['admitted']=False;r['selected_id']='abstain'
   run('fields-'+key+'-'+str(i),1,x,r)
 for key in ['actual_adapter_ns','total_search_ns','supplied_search_ns']:
  for i,v in enumerate(values):
   x,r=good();r['costs'][key]=v;run('cost-'+key+'-'+str(i),1,x,r)
 for i,v in enumerate(values):
  if type(v)is float and not math.isfinite(v):continue
  x,r=good();x['observations']['extra']=v;rebind(x,r);run('observation-row-'+str(i),1,x,r)
 for key in ['search_ns']:
  for i,v in enumerate(values):
   if type(v)is float and not math.isfinite(v):continue
   x,r=good();x['observations']['fast'][key]=v;rebind(x,r);run('observation-cost-'+str(i),1,x,r)
 for i,obs in enumerate([{'abstain':{'search_ns':MAX},'fast':{'search_ns':MAX}},{'abstain':{'search_ns':MAX},'fast':{'search_ns':MAX},'later':{}},{'abstain':{'search_ns':MAX},'fast':{'search_ns':MAX},'later':{'search_ns':False}}]):
  x,r=good();x['observations']=obs;rebind(x,r);run('complete-supplied-sum-'+str(i),1,x,r)
 for i,v in enumerate(values):
  x,r=good();x['candidates']=v;run('candidate-sequence-'+str(i),1,x,r)
 for i,v in enumerate(values):
  x,r=good();x['candidates']=[{'id':'fast','program':candidate.as_dict()},v];run('candidate-row-'+str(i),1,x,r)
 for i,v in enumerate(values):
  x,r=good();x['candidates'].append({'id':v,'program':base.as_dict()});run('candidate-key-'+str(i),1,x,r)
 x,r=good();x['candidates'].append({'id':'fast'});run('candidate-last-duplicate',1,x,r)
 x,r=good();r['admitted']=False;r['selected_id']='abstain';r['net_margin_ns']=0;run('valid-abstain',1,x,r)
 rng=random.Random(0xB6DEC151)
 for i in range(160):
  x,r=good()
  for _ in range(rng.randrange(1,5)):
   path=rng.choice([('admitted',),('selected_id',),('costs',),('costs','actual_adapter_ns'),('costs','total_search_ns'),('costs','supplied_search_ns')])
   if len(path)==1:r[path[0]]=rng.choice(values)
   elif type(r.get(path[0]))is dict:r[path[0]][path[1]]=rng.choice(values)
  run('cost-order-'+str(i),1,x,r)
 x,r=good();r['selected_program']=base.as_dict();run('source-diff',2,x,r,rankedhash=base.sha256)
 for i,sel in enumerate(['fast','empty',"a'b",'\ud800','😀','\n','z'*10000]):
  x,r=good();r['selected_id']=sel;x['candidates'][0]['id']=sel
  if sel=='fast':
   x['observations'].pop('fast');r['costs'].update(supplied_search_ns=7,total_search_ns=27)
  rebind(x,r)
  run('missing-observation-'+str(i),2,x,r)
 for field in ['program_sha256']:
  for key in ['fast','abstain']:
   for i,v in enumerate(values):
    if type(v)is float and not math.isfinite(v):continue
    x,r=good();x['observations'][key][field]=v;rebind(x,r);run('source-binding-'+key+'-'+str(i),2,x,r)
 for label,row,field in [('calls','objective','expected_calls'),('cap','objective','resource_cap_ns'),('ir','abstain','runtime_ns'),('iu','abstain','uncertainty_ns'),('cr','fast','runtime_ns'),('cu','fast','uncertainty_ns')]:
  for i,v in enumerate(values):
   if type(v)is float and not math.isfinite(v):continue
   x,r=good()
   if row=='objective':x['objective'][field]=v
   else:x['observations'][row][field]=v
   rebind(x,r);run('margin-'+label+'-'+str(i),2,x,r)
 for i,v in enumerate(values):
  x,r=good();r['net_margin_ns']=v;run('reported-margin-'+str(i),2,x,r)
 for i in range(300):
  x,r=good()
  ir=rng.randrange(0,MAX+1);iu=rng.randrange(0,MAX+1);cr=rng.randrange(0,MAX+1);cu=rng.randrange(0,MAX+1);calls=rng.randrange(1,MAX+1)
  if i%3==0:ir=MAX;iu=0;cr=0;cu=0
  x['observations']['abstain'].update(runtime_ns=ir,uncertainty_ns=iu);x['observations']['fast'].update(runtime_ns=cr,uncertainty_ns=cu);x['objective']['expected_calls']=calls
  r['net_margin_ns']=(max(0,ir-iu)-(cr+cu))*calls-r['costs']['total_search_ns']
  if i%7==0:r['net_margin_ns']+=1
  rebind(x,r);h=run('wide-margin-'+str(i),2,x,r)
  if not h[1]:assert h[12]+(h[13]<<64)==r['net_margin_ns']
 # Actual original _execute is driven with fixed clock observations only.
 # Providers below observe arguments at the pure budget boundary; they do not
 # constitute a native runtime or a production publication.
 def execute_budget(x,r,submit,started,handoff,wall):
  owner._bridge={};owner._timeout=2000;owner._bridge_timeout=10.0
  actual=r['costs']['actual_adapter_ns'];total=r['costs']['total_search_ns']
  owner._decision=lambda job,inputs,ranking,rankwall:(candidate,actual,total)
  published=[]
  def publish(*a,**kw):published.append(kw);return {'prepare_ns':0}
  owner._runtime=SimpleNamespace(publish_if_current=publish)
  job.submit_work_ns=submit;job.payload=pack(x);job.enqueued_ns=started;job.report=None
  times=iter([started,started,handoff if handoff-started==wall else started+wall,handoff,handoff,handoff])
  with patch.object(bg,'rank_candidates',return_value=r),patch.object(bg.time,'perf_counter_ns',side_effect=lambda:next(times)):
   out=owner._execute(job)
  del owner._decision
  return out,published
 for i in range(120):
  x,r=good();r['net_margin_ns']=max(0,x['observations']['abstain']['runtime_ns']-5)-12
  x['objective']['expected_calls']=1;r['net_margin_ns']-=38;rebind(x,r)
  submit=rng.choice([0,1,10,500,MAX,(1<<64)-1]);started=100000;delta=rng.choice([20,21,100,500,1000])
  handoff=started+delta
  expected={'kind':3,'actual':20,'total':38}
  out,pub=execute_budget(x,r,submit,started,handoff,delta)
  h=run('prepare-budget-'+str(i),3,x,r,wall=delta,expected=expected,clocks=(submit,started,handoff))
  assert h[20]+(h[21]<<64)==out['costs']['coordinator_before_publish_ns']
  assert h[25]==out['costs']['publication_budget_ns']
  assert bool(pub)==(h[25]>0)
 # Poisoned-work repeat and malformed/short-output atomic controls.
 x,r=good();raw,ir,ia,rr,ra=frame(0,x,r);guards=[]
 for at in [0,8,88,312,320,504,16,24,32,40,48,56,64,72]:
  bad=bytearray(raw);struct.pack_into('<Q',bad,at,NONE)
  rc,h,out=native(bytes(bad),ia,ra);assert rc==4294967293 and out==b'\xdb'*256,(at,rc)
  guards.append({'offset':at,'rc':rc,'atomic':True})
 s=C.create_string_buffer(raw);o=C.create_string_buffer(255);w=C.create_string_buffer(131072)
 C.memset(o,0xdb,len(o));rc=flat.call(raw,o,w);assert rc==4294967294 and o.raw==b'\xdb'*255
 guards.append({'short_output':255,'rc':rc,'atomic':True})
 reportout.update(passed=True,total=len(rows),guards=guards,guard_count=len(guards),actual_capture_calls=cap.calls)
 save();print('BG_DECISION_QUALIFIED',len(rows),len(guards),flat.sha,flush=True)
if __name__=='__main__':main()
