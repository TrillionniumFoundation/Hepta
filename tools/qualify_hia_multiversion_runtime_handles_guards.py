from pathlib import Path
import os,sys,ctypes as C,struct,mmap,json,hashlib,runpy
B=Path("/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z");D=B/'native-multiversion-runtime-handles-guards-v2';D.mkdir(exist_ok=False)
image=B/'native-multiversion-runtime-handles-v3/runtime-handles.so';x=runpy.run_path(str(B/'qualify-runtime-handles-smoke-v2.py'));Carrier=x['Carrier'];inner=x['inner'];rawdoc=x['rawdoc'];scalar_program=x['scalar_program'];sealed=x['sealed'];get=x['get']
rows=[];r=Carrier(image,rows);mem=mmap.mmap(-1,96<<20);out=(C.c_char*(96<<20)).from_buffer(mem);guards=[]
def header(op=0,payload=b'',cap=(0,0,0)):
 h=bytearray(128);struct.pack_into('<8sQ',h,0,b'HIAMVHQ1',op);struct.pack_into('<3Q',h,24,*cap);struct.pack_into('<Q',h,72,len(payload));return bytes(h)+payload
def patch(b,i,n):
 b=bytearray(b);struct.pack_into('<Q',b,i,n);return bytes(b)
def reject(name,b,on=96<<20,wn=256):
 s=C.create_string_buffer(b);C.memset(out,0xa5,8192);C.memset(C.addressof(out)+len(out)-4096,0xa5,4096)
 if on>=96<<20 and wn>=256:struct.pack_into('<Q',out,128,0)
 pre=bytes(out[:8192]);wpre=r.w.raw
 rc=r.f(s,len(b),out,on,r.w,wn)
 assert rc==0xfffffffd and bytes(out[:8192])==pre and bytes(out[-4096:])==b'\xa5'*4096 and r.w.raw==wpre and s.raw==b+b'\0',(name,rc)
 guards.append(dict(name=name,bytes=len(b),rc=rc,source_sha256=hashlib.sha256(b).hexdigest()))
b=header();child0=struct.pack('<8sQ',b'HIAMVEX1',0)+b'\0'*240
for n in [0,1,7,8,15,16,63,64,127]:reject('short-'+str(n),b[:n])
reject('badmagic',b'X'+b[1:])
for n in [8,9,2**32,2**64-1]:reject('unknown-op-'+str(n),patch(b,8,n))
for i in range(16,128,8):
 if i!=72:reject('init-reserved-'+str(i),patch(b,i,1))
for n in [1,256,20<<20,(20<<20)+1,2**64-1]:reject('extent-'+str(n),patch(b,72,n))
reject('trailing',b+b'X')
for op in [0,2,3,5,6,7]:reject('forbidden-payload-'+str(op),header(op,b'X'))
for op in [1,4]:
 for n in [0,1,255]:reject('short-inner-'+str(op)+'-'+str(n),header(op,b'X'*n))
for i in (16,24,32,40,48,56,64,80,88,96,104,112,120):reject('create-reserved-'+str(i),patch(header(1,child0),i,1))
reject('create-wrong-inner-magic',header(1,b'X'+child0[1:]))
reject('create-wrong-inner-op',header(1,inner(1)))
for op in (2,3,4,6):
 base=header(op,inner(3) if op==4 else b'',(1,2,3))
 for i in (16,48,56,64,80,88,96,104,112,120):reject('cap-reserved-'+str(op)+'-'+str(i),patch(base,i,1))
for n in (0,1,(96<<20)-1):reject('short-output-'+str(n),b,on=n)
for n in (0,1,255):reject('short-context-'+str(n),b,wn=n)
del out;mem.close()
r.q(6,(1,2,3),want=5);r.q(0);r.q(6,(1,2,3),want=1);r.q(5);r.q(7,want=5)
print('GUARDS_PASS',len(guards),flush=True)
paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths]
p=D/'parent';p.mkdir(mode=0o700);r=Carrier(image,rows);r.q(0);before=set(os.listdir('/proc/self/fd'));cap=r.create(files,p,scalar_program(None))
artifacts=list(p.rglob('*.so'));assert len(artifacts)==1 and artifacts[0].name=='generation-0.so',[str(x) for x in artifacts]
pub=r.q(4,cap,inner(1,raw=rawdoc(scalar_program(None))),child=0)
assert sorted(x.name for x in p.rglob('*.so'))==['generation-0.so','generation-1.so']
rootdir=artifacts[0].parent
foreign=rootdir/'private-qa-blocker';foreign.write_bytes(b'owned QA obstacle; no production input')
drop=r.q(3,cap,want=9)
assert get(drop['header'],72)==1 and get(r.w,40)!=0 and get(r.w,64)!=0,drop
r.q(5,want=5);r.q(6,cap,want=1)
foreign.rename(D/'preserved-blocker')
retry=r.q(7)
assert get(r.w,16)==get(r.w,40)==get(r.w,64)==0 and not list(p.iterdir()),[get(r.w,k) for k in (16,40,64)]
r.q(5);assert set(os.listdir('/proc/self/fd'))==before
for fd,_ in files:os.close(fd)
report=dict(schema='hepta.hia.multiversion-runtime-handles-guards.v1',whole_native_runtime=False,passed=len(guards)+5,failed=0,private_guards=guards,lifecycle_calls=rows,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),actual_retained_retry=True,exact_generation_filenames=True)
(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('HANDLES_GUARDS_PASS',report['passed'],flush=True)
