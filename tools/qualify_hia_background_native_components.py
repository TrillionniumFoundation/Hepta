"""Fresh native Background components and detached snapshot lifecycle checks.

These tests bind actual native owners. Python supplies input values and the
unchanged Python snapshot method as an oracle; it does not run product policy.
"""
from pathlib import Path
import argparse,collections,ctypes as C,hashlib,importlib,json,os,struct,subprocess,threading,types
from tools.qualify_hia_multiversion_components import Image
from tools.qualify_hia_future_retirement import Public
from tools.qualify_hia_result_value_records import Values,NativeEngine
from tools.qualify_hia_multiversion_background_jobs import Jobs
from tools.qualify_hia_multiversion_background_queue import Queue
from tools.qualify_hia_multiversion_background_payload import Owner as Payload
from tools.qualify_hia_multiversion_values import Owner as Decimal
from tools.qualify_hia_multiversion_background_ledger import Ledger,STATUSES
from hepta import hia_background_optimizer as original

ROOT=Path(__file__).resolve().parents[1]
COMPILER_SHA='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
SIX=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
COMPONENTS={
 'multiversion_future':['multiversion_future'],
 'multiversion_values':['multiversion_values','unsigned_decimal_values'],
 'multiversion_background_payload':['multiversion_background_payload'],
 'multiversion_background_jobs':['multiversion_background_jobs'],
 'multiversion_background_job_refs':['multiversion_background_job_refs'],
 'multiversion_background_queue':['multiversion_background_queue'],
 'multiversion_background_ledger':['multiversion_background_ledger'],
 'multiversion_background_worker':['multiversion_background_worker'],
 'background_optimizer_snapshot':['background_optimizer_snapshot'],
 'background_optimizer_business_worker':['background_optimizer_business_worker','background_optimizer_business_worker_failure'],
}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def u(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def cap(raw,at):return struct.unpack_from('<3Q',raw,at)
def addr(f):return C.cast(f,C.c_void_p).value
def put(buf,at,*values):struct.pack_into('<'+'Q'*len(values),buf,at,*values)
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def build(compiler,out,future):
 compiler=Path(compiler);assert pin(compiler.read_bytes())==dict(bytes=813129,sha256=COMPILER_SHA)
 modules=[];flats={};products={};sources={}
 need=list(dict.fromkeys([n for name,roles in COMPONENTS.items()for n in roles+[name+'_packer']]))
 for name in need:
  path=ROOT/'examples/hia_bootstrap'/(name+'.hepta');raw=path.read_bytes();source=str(path.relative_to(ROOT))
  rounds=[subprocess.run([str(compiler),'compile'],input=raw,capture_output=True,timeout=30)for _ in range(2)]
  assert all(p.returncode==0 and p.stdout and not p.stderr for p in rounds),(name,[(p.returncode,p.stderr)for p in rounds])
  assert rounds[0].stdout==rounds[1].stdout,name
  flat=rounds[0].stdout;flats[name]=flat;(out/(name+'.flat')).write_bytes(flat);sources[source]=sha(raw)
  modules.append(dict(source_path=source,source_bytes=len(raw),source_sha256=sha(raw),flat_bytes=len(flat),flat_sha256=sha(flat),double_compile_identical=True))
  print('BG_NATIVE_COMPILE',name,len(flat),flush=True)
 for name,roles in COMPONENTS.items():
  packer=importlib.import_module('tools.generate_hia_'+name+'_packer');parts=[flats[n]for n in roles]
  assert len(parts)==len(packer.ROLES)
  wire=struct.pack('<'+'Q'*(2+len(parts)),packer.MAGIC,len(parts),*map(len,parts))+b''.join(parts)
  expected=packer.reference_object(parts);image=Image(out/(name+'_packer.flat'))
  ob=C.create_string_buffer(len(expected));wb=C.create_string_buffer(1<<20);rc=image(wire,ob,wb)
  assert rc==len(expected)and ob.raw==expected,(name,rc,len(expected))
  op=out/(name+'.o');op.write_bytes(ob.raw)
  so=out/(name+'.so')
  p=subprocess.run(['/usr/bin/cc','-shared','-Wl,-z,defs','-Wl,-z,noexecstack','-o',str(so),str(op),'-pthread'],capture_output=True,timeout=30)
  assert p.returncode==0,(name,p.stderr)
  products[name]={'native_object':pin(ob.raw),'platform_resolved_test_image':pin(so.read_bytes()),'roles':roles,'independent_reference_equal':True,'imports':list(packer.RELOCATIONS)}
  sources['tools/generate_hia_'+name+'_packer.py']=sha((ROOT/'tools'/('generate_hia_'+name+'_packer.py')).read_bytes())
  print('BG_NATIVE_PACK',name,len(ob.raw),flush=True)
 fr=json.loads((future/'build.json').read_text())
 for row in fr['modules']:
  assert row['double_compile_identical'] and sha((ROOT/row['source_path']).read_bytes())==row['source_sha256']
 for name in ('hia-future-public.core.bin','hia-result-value.core.bin'):
  raw=(future/name).read_bytes();assert pin(raw)==fr['products'][name];(out/name).write_bytes(raw)
 for path in ('tools/generate_hia_background_optimizer_snapshot.py','tools/hia_background_retirement_source.py','tools/qualify_hia_background_native_components.py','hepta/hia_background_optimizer.py'):
  sources[path]=sha((ROOT/path).read_bytes())
 result=dict(schema='hepta.hia.background-native-components-build.v1',compiler=pin(compiler.read_bytes()),modules=modules,products=products,
             future_build={'path':str(future/'build.json'),'sha256':sha((future/'build.json').read_bytes()),'products':fr['products']},
             sources=sources,native_compile_and_pack=True,platform_linker_used_only_for_component_execution=True,whole_background_qualified=False)
 save(out/'build.json',result);return result

class NativeComponents:
 def __init__(self,out):self.out=out;self.libs={}
 def entry(self,name,symbol):
  if name not in self.libs:self.libs[name]=C.CDLL(str(self.out/(name+'.so')))
  f=getattr(self.libs[name],symbol);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32;return f
class ExternalJobs(Jobs):
 def __init__(self,native,p,fac):
  self.image=native.out/'multiversion_background_jobs.so';self.f=native.entry('multiversion_background_jobs','hia_mv_background_jobs')
  self.ff=native.entry('multiversion_future','hia_mv_future');self.payload=Payload(native.out/'multiversion_background_payload.so')
  self.w=C.create_string_buffer(256);self.calls=0;self.lock=threading.Lock();self.keep=[]
  r=p.call(17,*fac);self.cellfn=SIX(u(r,72));self.cellctx=u(r,80);assert u(r,88)==256
  raw=bytearray(128);raw[:8]=b'HIABJO03';put(raw,8,13);put(raw,24,addr(self.ff),addr(self.payload.f),C.addressof(self.payload.w),256,addr(self.cellfn),self.cellctx,256)
  self.retirement(raw,consumed=0)
 def retirement(self,raw,consumed):
  src=C.create_string_buffer(bytes(raw),128);out=C.create_string_buffer(2048);rc=self.f(src,128,out,2048,self.w,256);r=out.raw
  assert rc==0 and r[:8]==b'HIABJOR2'and u(r,8)==0,(rc,r[:160].hex())
  assert (u(r,128),u(r,136),u(r,144))==(consumed,1,0),r[:160].hex()
  return r
 def drop(self,owned):
  raw=bytearray(128);raw[:8]=b'HIABJO03';put(raw,8,11);put(raw,24,*owned);return self.retirement(raw,1)
class ActualQueue(Queue):
 def __init__(self,native,jobs,maximum):
  self.values=jobs;self.f=native.entry('multiversion_background_queue','hia_mv_background_queue')
  self.w=C.create_string_buffer(4096);self.calls=0;self.mutex=threading.Lock();self.errors=[]
  self.ref=native.entry('multiversion_background_job_refs','hia_mv_background_job_refs')
  self.refctx=C.create_string_buffer(64);self.refctx[:8]=b'HIABJRC1';put(self.refctx,8,addr(jobs.f),C.addressof(jobs.w),256)
  self.run(0,{16:maximum,64:addr(self.ref),80:C.addressof(self.refctx),88:64})
 def add(self,j):
  future=self.values.view(j)[0]
  return self.run(1,{24:j[0],32:j[1],40:j[2],48:future,56:512})

def snapshot_cases(out):
 native=NativeComponents(out);v=Values(NativeEngine(out/'hia-result-value.core.bin'))
 public=Public(v,Image(out/'hia-future-public.core.bin'));fac=public.factory();jobs=ExternalJobs(native,public,fac);queue=ActualQueue(native,jobs,3)
 decimal=Decimal(out/'multiversion_values.so');ledger=Ledger(out/'multiversion_background_ledger.so',jobs,decimal)
 worker=native.entry('multiversion_background_worker','hia_mv_background_worker');ww=C.create_string_buffer(512)
 business=native.entry('background_optimizer_business_worker','hia_background_business_worker');bw=C.create_string_buffer(1064960)
 def worker_call(op,fields=None):
  raw=bytearray(128);raw[:8]=b'HIABGW02'if op==0 else b'HIABGW01';put(raw,8,op)
  for at,x in (fields or {}).items():put(raw,at,x)
  src=C.create_string_buffer(bytes(raw),128);reply=C.create_string_buffer(8192)
  rc=worker(src,128,reply,8192,ww,512);assert rc==0 and reply.raw[:8]==b'HIABGWO1'and u(reply.raw,8)==0,(op,rc,reply.raw[:128].hex());return reply.raw
 worker_call(0,{16:addr(queue.f),24:C.addressof(queue.w),32:4096,40:addr(business),48:C.addressof(bw),56:len(bw)})
 submission=C.create_string_buffer(8192);submission[:8]=b'HIABSSC1';put(submission,8,addr(v.engine.image.entry),C.addressof(v.engine.context),256);put(submission,32,addr(queue.f),C.addressof(queue.w),4096)
 sw=C.create_string_buffer(8192);sw[:8]=b'HIABSPC1'
 triples=[(v.engine.image.entry,v.engine.context),(queue.f,queue.w),(ledger.f,ledger.w),(worker,ww),(jobs.f,jobs.w),(decimal.f,decimal.w),(jobs.payload.f,jobs.payload.w)]
 for at,(f,w)in zip(range(8,153,24),triples):put(sw,at,addr(f),C.addressof(w),len(w))
 put(sw,176,C.addressof(submission),8192,C.addressof(bw),len(bw),os.getpid())
 snap=native.entry('background_optimizer_snapshot','hia_background_snapshot');rows=[];saved=[];queued=[];recent=collections.deque(maxlen=64);outcomes={};settled=0;cost=0;failure=None;active=None;closed=False
 def oracle():
  ob=object.__new__(original.BackgroundOptimizer);ob._condition=threading.Condition();ob._closed=closed;ob._max_pending=3
  ob._pending={i:None for i in range(len(queued))};ob._queue=collections.deque([None]*sum(x['queued']for x in queued))
  ob._active=active
  ob._worker=types.SimpleNamespace(is_alive=lambda:False);ob._settled_jobs=settled;ob._observed_work_ns=cost;ob._outcomes=outcomes.copy();ob._recent_jobs=recent.copy();ob._worker_failure=failure
  return ob.snapshot()
 def call(label,retain=False):
  before=u(v.raw(47),48);raw=b'HIABSPQ1'+bytes(120);src=C.create_string_buffer(raw,128);ob=C.create_string_buffer(b'\xa5'*(262144+32),262144+32)
  rc=snap(src,128,ob,262144,sw,8192);r=ob.raw[:262144]
  assert rc==0 and r[:8]==b'HIABSPR1' and u(r,8)==0 and u(r,16)==1 and u(r,48)==0,(label,rc,r[:128].hex())
  assert src.raw==raw and ob.raw[262144:]==b'\xa5'*32 and u(sw.raw,216)==0 and u(queue.w.raw,128)&0xffffffff==0
  owned=v.keep(r,24);answer=v.python_value(owned);expected=oracle();assert answer==expected,(label,answer,expected)
  if not retain:
   v.drop(owned);assert u(v.raw(47),48)==before,(label,before,u(v.raw(47),48))
  rows.append(dict(case=label,passed=True,settled=settled,recent=len(recent),outstanding=len(queued),queued=sum(x['queued']for x in queued),active=active))
  print('BG_SNAPSHOT_CASE',label,flush=True);return (answer,owned)if retain else answer
 call('empty-original-fields')
 queue.run(7)
 for number in (17,18):
  j=jobs.create(b'captured input');r=queue.add(j);slot=u(r,16);meta=v.dictionary([('job',number)])
  put(submission,1024+slot*128,*j,*meta)
  queued.append(dict(job=j,meta=meta,slot=slot,number=number,queued=True))
 call('queued-original-fields')
 take=queue.run(2);held=queue.refs(take)[0];queued[0]['queued']=False;active=17
 call('active-job-is-real-retained-metadata')
 for i in range(80):
  j=jobs.create(str(i).encode());status=(i*5)%6;amount=10**100+i;receipt={'job':i,'status':STATUSES[status],'costs':{'value':amount},'nested':[i,{'text':'λ'}]}
  raw=json.dumps(receipt,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
  ledger.record(j,raw,amount,status);jobs.drop(j);settled+=1;cost+=amount;outcomes[STATUSES[status]]=outcomes.get(STATUSES[status],0)+1;recent.append(raw)
 call('eighty-settlements-exact-bigint-and-last-sixty-four')
 failure={'class':'KeyboardInterrupt','message':'x'*2047+'🌍','pending':2};f=v.keep(v.raw(1,tail=json.dumps(failure,ensure_ascii=False).encode()));put(bw,512,*f)
 held_before=set(v.held);first,owned=call('worker-failure-detached-fields',True)
 def field(obj,key):return v.keep(v.raw(9,a=obj,b=v.scalar(key)))
 failure_copy=field(owned,'worker_failure');v.raw(10,a=failure_copy,b=v.scalar('message'),c=v.scalar('mutated'))
 receipts=field(field(owned,'cost_accounting'),'recent_jobs');receipt=v.keep(v.raw(12,a=receipts,b=v.scalar(0)))
 nested=field(receipt,'nested');item=v.keep(v.raw(12,a=nested,b=v.scalar(1)));v.raw(10,a=item,b=v.scalar('text'),c=v.scalar('changed'))
 assert v.python_value(owned)['worker_failure']['message']=='mutated'
 assert v.python_value(owned)['cost_accounting']['recent_jobs'][0]['nested'][1]['text']=='changed'
 call('returned-native-dictionaries-do-not-alias-owner-ledger')
 for c in list(v.held):
  if c not in held_before:v.drop(c)
 for current in list(queued):
  if active is None:take=queue.run(2);held=queue.refs(take)[0];active=current['number'];current['queued']=False
  released=queue.settle(take);queue.release_refs(released);v.drop(current['meta']);C.memset(C.addressof(submission)+1024+128*current['slot'],0,128);queued.remove(current);active=None
 queue.run(4);closed=True;queue.run(8)
 call('closed-drained-snapshot-and-retained-history')
 worker_call(5);ledger.destroy();decimal.run(9);queue.destroy();jobs.destroy()
 public.typed(27,fac[0],fac[1]);public.typed(29);v.finish()
 assert u(jobs.w.raw,16)==u(decimal.w.raw,16)==u(jobs.payload.w.raw,16)==0
 rows.append(dict(case='all-native-reference-registries-empty-after-last-close',passed=True))
 return rows

def main():
 p=argparse.ArgumentParser();p.add_argument('--compiler',type=Path,required=True);p.add_argument('--future-build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--reuse-build',action='store_true');a=p.parse_args()
 if a.reuse_build:
  report=json.loads((a.output/'build.json').read_text())
  for name,digest in report['sources'].items():assert sha((ROOT/name).read_bytes())==digest,name
 else:
  a.output.mkdir(parents=True,exist_ok=False);report=build(a.compiler,a.output,a.future_build)
 rows=snapshot_cases(a.output)
 result=dict(schema='hepta.hia.background-snapshot-native-retirement.v1',component_qualified=True,whole_background_qualified=False,whole_native_runtime_qualified=False,
             passed=len(rows),failed=0,cases=rows,build=pin((a.output/'build.json').read_bytes()),original_source_sha256=sha((ROOT/'hepta/hia_background_optimizer.py').read_bytes()),
             notes=['Native HIA compile and native HIA pack; only the component test loader resolves declared malloc/free/pthread platform imports.',
                    'Queue and ledger have actual native ownership; public BackgroundOptimizer construction and worker business remain separate integration gates.'])
 save(a.output/'results.json',result);print('BG_SNAPSHOT_NATIVE_QUALIFIED',len(rows),flush=True)
if __name__=='__main__':main()
