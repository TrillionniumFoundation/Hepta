"""Private process request/descriptor/extent controls on the actual product."""
from pathlib import Path
import argparse,ctypes as C,fcntl,hashlib,json,os,struct,time
from tools.qualify_hia_multiversion_prepare_process import Process,sealed,NONE
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory
 proc=Process(D/'process-component.so');fd=sealed((D/'child-fixture').read_bytes());rows=[]
 data=struct.pack('<4Q',0,0,0,0)+b'guards'
 def request(role=1,path=b'',body=data):
  return struct.pack('<8s15Q',b'HIAMVPS1',role,fd,time.monotonic_ns()+10_000_000_000,len(body),67108864,67108864,len(path),0,*([0]*7))+body+path
 base=request();variants=[('magic',b'INVALID!'+base[8:]),('empty',b''),('short-header',base[:127]),('short-body',base[:-1]),('tail',base+b' ')]
 for at,vals in [(8,[0,5,NONE]),(16,[0,1,2,2147483648,NONE]),(24,[0]),(32,[8388609,NONE]),(40,[67108865,NONE]),(48,[67108865,NONE]),(56,[1,4096,NONE]),(64,[1,3])]+[(n,[1]) for n in range(72,128,8)]:
  for value in vals:
   raw=bytearray(base);struct.pack_into('<Q',raw,at,value);variants.append(('field-'+str(at)+'-'+str(value),bytes(raw)))
 variants += [('path-empty',request(3)),('path-relative',request(3,b'relative')),('path-NUL',request(3,b'/tmp/bad\0tail')),('path-other-role',request(1,b'/tmp/x'))]
 w=C.create_string_buffer(20<<20);o=C.create_string_buffer(b'G'*512);baseline=set(os.listdir('/proc/self/fd'))
 for label,raw in variants:
  s=C.create_string_buffer(raw);C.memset(o,71,512);rc=proc.f(s,len(raw),o,128,w,len(w));assert rc==0xfffffffd and o.raw[:512]==b'G'*512,(label,rc)
  assert s.raw==raw+b'\0' and set(os.listdir('/proc/self/fd'))==baseline
  rows.append({'case':label,'status':rc,'output_unchanged':True})
 s=C.create_string_buffer(base)
 for label,oc,wc in [('short-output',127,len(w)),('zero-output',0,len(w)),('short-work',128,len(w)-1),('zero-work',128,0)]:
  C.memset(o,71,512);rc=proc.f(s,len(base),o,oc,w,wc);assert rc==0xfffffffd and o.raw[:512]==b'G'*512,(label,rc)
  rows.append({'case':label,'status':rc,'output_unchanged':True})
 for role,n in [(1,8<<20),(2,(16<<20)+192)]:
  body=struct.pack('<4Q',0,0,0,0)+b'x'*(n-32);r=proc.run(fd,body,role=role,budget=10);assert r['status']==0 and r['stdout']==body[32:]
  rows.append({'case':'exact-input-'+str(role),'status':0,'input_bytes':n,'output_sha256':hashlib.sha256(r['stdout']).hexdigest()})
 r=proc.run(fd,struct.pack('<4Q',0,0,0,0),outcap=0,errcap=0);assert r['status']==0 and not r['stdout'] and not r['stderr']
 rows.append({'case':'zero-stream-cap-empty-actual-stream','status':0})
 path=b'/'+b'x'*4094;r=proc.run(fd,struct.pack('<4Q',4,0,0,0),role=3,path=path)
 assert r['status']==0 and r['stdout']==b'hia-build-shared\0'+path+b'\0'
 rows.append({'case':'exact-build-argument-4095','status':0})
 # Every owned descriptor is normalized above standard streams; restore only our saved originals.
 for closed in [(0,),(1,),(2,),(0,1,2)]:
  saved={n:fcntl.fcntl(n,fcntl.F_DUPFD_CLOEXEC,3) for n in closed}
  try:
   for n in closed:os.close(n)
   r=proc.run(fd,struct.pack('<4Q',1,31,19,0));assert r['status']==0 and len(r['stdout'])==31 and len(r['stderr'])==19
  finally:
   for n,copy in saved.items():os.dup2(copy,n);os.close(copy)
  rows.append({'case':'closed-standard-'+','.join(map(str,closed)),'status':0})
 cancel=C.c_uint64(2);r=proc.run(fd,struct.pack('<4Q',0,0,0,0),cancel=cancel);assert r['status']==0
 rows.append({'case':'committed-token-is-not-cancelled','status':0})
 for label,other in [('directory',os.open(D,os.O_RDONLY|os.O_DIRECTORY)),('regular',os.open(D/'child-fixture',os.O_RDONLY))]:
  before=os.fstat(other);r=proc.run(other,data);after=os.fstat(other);assert r['status']==3 and before.st_ino==after.st_ino;os.close(other)
  rows.append({'case':label+'-unsealed-refusal','status':3})
 read,write=os.pipe()
 try:r=proc.run(read,data);assert r['status']==3
 finally:os.close(read);os.close(write)
 rows.append({'case':'pipe-executable-refusal','status':3})
 os.close(fd)
 report={'schema':'hepta.hia.multiversion-prepare-process.guards.v1','passed':len(rows),'failed':0,'whole_native_runtime':False,'image_sha256':hashlib.sha256((D/'process-component.so').read_bytes()).hexdigest(),'cases':rows}
 (D/'guards-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PROCESS_GUARDS_PASS',len(rows),flush=True)
if __name__=='__main__':main()

