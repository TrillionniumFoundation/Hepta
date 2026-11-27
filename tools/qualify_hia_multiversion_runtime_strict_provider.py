from pathlib import Path
import os,sys,struct,json,ctypes as C,time,hashlib,threading,runpy,argparse
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.hia_multiversion_strict_qualification_support import inner,scalar_program,rawdoc,sealed,NONE,get,Token
sha=lambda b:hashlib.sha256(b).hexdigest()
def control(op,data=b''):
 q=bytearray(128);struct.pack_into('<8sQ',q,0,b'HIAMVBC1',op);struct.pack_into('<Q',q,72,len(data));return bytes(q)+data
def request(op,cap=(0,0,0),*,reply=(0,0,0),token=0,gen=b'',epoch=b'',raw=b'',measurement=b'',budget=20_000_000_000,handoff=NONE):
 q=bytearray(128);struct.pack_into('<8sQ',q,0,b'HIAMVBQ1',op);struct.pack_into('<3Q',q,16,*cap)
 if op==2:
  struct.pack_into('<2Q',q,40,token,512);struct.pack_into('<7Q',q,56,len(gen),len(epoch),len(raw),len(measurement),budget,handoff,int(bool(measurement)))
  return bytes(q)+gen+epoch+raw+measurement
 if op==5:struct.pack_into('<3Q',q,40,*reply)
 return bytes(q)
class Provider:
 def __init__(self,path,rows):
  self.lib=C.CDLL(str(path));self.f=self.lib.hia_mv_background_runtime;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
  self.w=C.create_string_buffer(1024);self.rows=rows;self.lock=threading.Lock()
 def call(self,raw,want=0):
  s=C.create_string_buffer(raw);out=C.create_string_buffer(128);start=time.monotonic_ns();rc=self.f(s,len(raw),out,len(out),self.w,len(self.w));ns=time.monotonic_ns()-start
  assert rc==0,(rc,out.raw.hex())
  z=out.raw;assert z[:8]==b'HIAMVBO1';status=get(z,8);cap=tuple(get(z,a) for a in (40,48,56));p,n=get(z,24),get(z,32);payload=C.string_at(p,n) if p else b''
  assert bool(p)==bool(n) and (not p or cap[0]) and s.raw==raw+b'\0'
  row=dict(op=get(raw,8),control=raw[:8]==b'HIAMVBC1',status=status,kind=get(z,16),committed=get(z,64),payload_bytes=n,payload_sha256=sha(payload),elapsed_ns=ns,cap=bool(cap[0]))
  with self.lock:self.rows.append(row)
  print('PROVIDER_CALL',row,flush=True)
  if want is not None:assert status==want,row
  return dict(cap=cap,payload=payload,pointer=p,header=z,row=row)
 def q(self,op,cap=(0,0,0),want=0,**kw):return self.call(request(op,cap,**kw),want)
 def drop_reply(self,r):return self.q(5,reply=r['cap'])
 def create(self,files,parent,program):
  raw=bytearray(inner(0,files=files,parent=os.fsencode(parent),raw=rawdoc(program)))
  raw[:8]=b'HIAMVEX5';struct.pack_into('<Q',raw,240,sys.get_int_max_str_digits())
  frame=bytearray(control(1,bytes(raw)));frame[:8]=b'HIAMVBC2'
  return self.call(bytes(frame))['cap']
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--component',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);[ap.add_argument('--'+name,type=Path,required=True) for name in ('normalizer','proof','builder','future')];a=ap.parse_args();D=a.output;D.mkdir(exist_ok=False);parent=D/'native';parent.mkdir(mode=0o700)
 paths=[a.normalizer,a.proof,a.builder]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];rows=[];checks=[];r=Provider(a.component,rows);r.call(control(0));before=set(os.listdir('/proc/self/fd'))
 def mark(name,**kw):
  checks.append(dict(name=name,**kw));(D/'calls.json').write_text(json.dumps(rows,indent=2)+'\n');(D/'checks.json').write_text(json.dumps(checks,indent=2)+'\n');print('PROVIDER_GATE',name,flush=True)
 cap=r.create(files,parent,scalar_program(None));assert cap[0];mark('actual-constructor-normalize-proof-build-load')
 snap=r.q(1,cap);z=snap['payload'];assert z[:8]==b'HIAMVBS1' and get(z,16)==6 and z[256:]==b'00';assert get(z,24)==get(z,32)==1;mark('actual-lock-consistent-snapshot')
 clone=r.q(3,cap)['cap'];assert clone!=cap and clone[0];r.q(4,cap);r.q(1,cap,want=3)
 assert C.string_at(snap['pointer'],len(z))==z;mark('independent-strong-reference-and-stale-cap')
 future=C.CDLL(str(a.future));token=Token(future)
 pub=r.q(2,clone,token=token.address,gen=b'0',epoch=b'0',raw=rawdoc(scalar_program('bit.xor')))
 assert get(pub['header'],64)==1 and get(token.w,64)==2
 doc=json.loads(pub['payload']);assert doc['generation']['generation']==1 and doc['selection_epoch']==1,doc
 mark('actual-same-token-conditional-publication',result=doc)
 stale=r.q(2,clone,want=1,token=token.address,gen=b'0',epoch=b'0',raw=rawdoc(scalar_program(None)))
 assert json.loads(stale['payload'])=={'type':'MultiversionRejected','message':'E_HIA_MULTIVERSION: stale generation or selection epoch'}
 mark('exact-stale-before-token-order')
 cancelled=Token(future);cancelled.q(1)
 no=r.q(2,clone,want=1,token=cancelled.address,gen=b'1',epoch=b'1',raw=rawdoc(scalar_program(None)))
 assert json.loads(no['payload'])=={'type':'MultiversionRejected','message':'E_HIA_MULTIVERSION: publication cancelled before selection'}
 mark('actual-future-cancel-no-publication')
 latest=r.q(1,clone);assert latest['payload'][256:]==b'11'
 r.q(4,clone);assert not list(parent.iterdir());r.call(control(2),want=3)
 for item in (snap,pub,stale,no,latest):
  assert C.string_at(item['pointer'],len(item['payload']))==item['payload'];r.drop_reply(item);r.drop_reply(item) if False else None
 mark('reply-outlives-last-runtime-and-blocks-context-destroy')
 r.call(control(2));assert get(r.w,32)==get(r.w,256+16)==get(r.w,256+40)==get(r.w,256+64)==get(r.w,512+16)==0
 token.q(10);cancelled.q(10)
 assert set(os.listdir('/proc/self/fd'))==before
 for fd,_ in files:os.close(fd)
 mark('actual-finalizer-fd-and-context-lifetimes')
 report=dict(schema='hepta.hia.multiversion-background-runtime-strict-smoke.v1',whole_native_runtime=False,passed=len(checks),failed=0,image_sha256=sha(a.component.read_bytes()),actual_calls=len(rows),checks=checks,calls=rows)
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PROVIDER_SMOKE_PASS',len(checks),len(rows),flush=True)
if __name__=='__main__':main()
