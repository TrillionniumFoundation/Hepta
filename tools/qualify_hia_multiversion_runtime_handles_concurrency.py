from pathlib import Path
import sys,os,json,runpy,ctypes as C,threading,concurrent.futures,time,argparse,hashlib
B=Path("/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z");x=runpy.run_path(str(B/'qualify-runtime-handles-smoke-v2.py'));Carrier=x['Carrier'];inner=x['inner'];scalar_program=x['scalar_program'];rawdoc=x['rawdoc'];get=x['get'];sealed=x['sealed']
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--component',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();D=a.output;D.mkdir(exist_ok=False)
 paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];cases=[];allrows=[]
 def begin(name):
  p=D/name;p.mkdir(mode=0o700);rows=[];r=Carrier(a.component,rows);r.q(0);before=set(os.listdir('/proc/self/fd'));cap=r.create(files,p,scalar_program(None));return r,cap,p,rows,before
 def finish(name,r,p,rows,before,**extra):
  assert get(r.w,16)==get(r.w,40)==get(r.w,64)==0,[get(r.w,i) for i in (16,40,64)]
  assert not list(p.iterdir()),list(p.iterdir());assert set(os.listdir('/proc/self/fd'))==before
  r.q(5);cases.append(dict(name=name,actual_calls=len(rows),**extra));allrows.extend(rows)
  (D/'progress.json').write_text(json.dumps(dict(cases=cases,calls=allrows),indent=2)+'\n');print('HANDLES_CONCURRENT_PASS',name,len(rows),flush=True)
 def obj(cap):return get(C.string_at(cap[0],96),8)
 r,cap,p,rows,before=begin('independent-retains');lease=r.lease(cap);barrier=threading.Barrier(8)
 def work(k):
  barrier.wait()
  for i in range(100):
   c=r.q(2,lease)['cap'];r.call(c,k*1000+i);r.q(3,c)
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(work,range(8)))
 node=obj(lease);rawlease=get(C.string_at(node,192),80);ret=C.string_at(rawlease+96,64);assert get(ret,40)==1
 r.q(3,lease);r.q(3,cap);finish('independent-retains',r,p,rows,before,threads=8,calls=800)
 r,cap,p,rows,before=begin('same-node-double-drop');target=r.q(2,cap)['cap'];barrier=threading.Barrier(16)
 def drop(k):barrier.wait();return r.q(3,target,want=None)['row']['status']
 with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:statuses=list(pool.map(drop,range(16)))
 assert statuses.count(0)==1 and statuses.count(1)==15,statuses
 r.q(3,cap);finish('same-node-double-drop',r,p,rows,before,statuses=statuses)
 r,cap,p,rows,before=begin('last-lease-reference-during-call');lease=r.lease(cap);target=obj(lease);r.q(3,cap)
 payload=inner(4,fn=b'calculate',args=b'['+b' '*(6<<20)+b'17]');entered=threading.Event()
 def long_call():entered.set();return r.q(4,lease,payload,child=0)
 with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
  f=pool.submit(long_call);entered.wait();deadline=time.monotonic()+10
  while get(C.string_at(target+56,8),0)==0:
   assert not f.done(),'call completed before pin observation';assert time.monotonic()<deadline;time.sleep(0.0001)
  r.q(3,lease);assert get(r.w,64)!=0 and not f.done(),'last reference did not overlap a native call'
  r.q(5,want=5);result=f.result(timeout=30)
 assert result['value']==b'17' and result['row']['finalizer']==0,result
 finish('last-lease-reference-during-call',r,p,rows,before,accepted_raw_argument_bytes=(6<<20)+4,actual_return='17')
 r,cap,p,rows,before=begin('last-runtime-reference-during-publication');target=obj(cap)
 def publish():return r.q(4,cap,inner(1,raw=rawdoc(scalar_program('bit.xor'))),child=0)
 with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
  f=pool.submit(publish);deadline=time.monotonic()+10
  while get(C.string_at(target+56,8),0)==0:
   assert not f.done(),'publication completed before pin observation';assert time.monotonic()<deadline;time.sleep(0.0001)
  r.q(3,cap);assert get(r.w,64)!=0 and not f.done()
  r.q(5,want=5);result=f.result(timeout=60)
 assert result['row']['finalizer']==0 and result['row']['retained']==0,result
 finish('last-runtime-reference-during-publication',r,p,rows,before,child_status=result['row']['child_status'])
 r,cap,p,rows,before=begin('stale-foreign-fork');r.q(6,(1,0,0),want=1);r.q(6,(cap[0],cap[1]^1,cap[2]),want=1)
 foreign=Carrier(a.component,[]);foreign.q(0);foreign.q(6,cap,want=1);foreign.q(5)
 pid=os.fork()
 if pid==0:
  try:r.q(6,cap,want=5)
  except BaseException:os._exit(97)
  os._exit(0)
 assert os.waitpid(pid,0)[1]==0
 old=[]
 for i in range(200):
  c=r.q(2,cap)['cap']
  for stale in old[-3:]:r.q(6,stale,want=1)
  old.append(c);r.q(3,c)
 r.q(3,cap);finish('stale-foreign-fork',r,p,rows,before,retains=200,distinct_nodes=len({c[0] for c in old}))
 p=D/'invalid-constructor';p.mkdir(mode=0o700);rows=[];r=Carrier(a.component,rows);r.q(0);before=set(os.listdir('/proc/self/fd'))
 bad=r.q(1,payload=inner(0,files=files,parent=os.fsencode(p),raw=b'{'),child=10);assert bad['cap'][0]==0
 cap=r.create(files,p,scalar_program(None));r.q(3,cap);finish('invalid-constructor',r,p,rows,before)
 for fd,b in files:os.close(fd)
 report=dict(schema='hepta.hia.multiversion-runtime-handles-concurrency.v1',whole_native_runtime=False,passed=len(cases),failed=0,actual_calls=len(allrows),image_sha256=hashlib.sha256(a.component.read_bytes()).hexdigest(),cases=cases,calls=allrows)
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('HANDLES_CONCURRENCY_COMPLETE',len(cases),len(allrows),flush=True)
if __name__=='__main__':main()
