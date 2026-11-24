"""Qualify the closed independent VM backend and linker without a target compiler."""
from pathlib import Path
import argparse,ctypes,hashlib,json,mmap,os,struct,subprocess,time,traceback
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--build',type=Path,required=True);p.add_argument('--original',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();D=a.output;D.mkdir(mode=0o700)
sha=lambda raw:hashlib.sha256(raw).hexdigest()
report={'status':'running','target_compiler_used':False,'build':str(a.build),'cases':[]}
def save():(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
def checked(name,fn):
 rd,wr=os.pipe();pid=os.fork()
 if pid==0:
  os.close(rd)
  try:result=fn();payload={'passed':True,'detail':result}
  except BaseException:payload={'passed':False,'error':traceback.format_exc()}
  blob=json.dumps(payload).encode()
  while blob:
   n=os.write(wr,blob);blob=blob[n:]
  os.close(wr);os._exit(0)
 os.close(wr);chunks=[]
 while True:
  part=os.read(rd,65536)
  if not part:break
  chunks.append(part)
 os.close(rd);_,status=os.waitpid(pid,0);raw=b''.join(chunks)
 row={'case':name,'wait_status':status}
 if status==0 and raw:row.update(json.loads(raw))
 else:row.update(passed=False,output_hex=raw.hex())
 report['cases'].append(row);save()
 if not row['passed']:raise AssertionError(row)
 if len(report['cases'])%50==0:print('GUARDS',len(report['cases']),'PASS',flush=True)
def mapped(raw,offset=0,restype=ctypes.c_uint32,args=None):
 memory=mmap.mmap(-1,len(raw),prot=7);memory.write(raw);address=ctypes.addressof(ctypes.c_ubyte.from_buffer(memory))+offset
 if args is None:args=(ctypes.c_void_p,ctypes.c_size_t)*3
 return memory,ctypes.CFUNCTYPE(restype,*args)(address)
mseed,fseed=mapped((a.build/'seed_vm_backend.flat').read_bytes())
mlink,flink=mapped((a.build/'cold_reference_kernel_linker.flat').read_bytes())
def invoke(fn,raw,on=1<<20,wn=1<<20):
 sb=ctypes.create_string_buffer(raw,max(1,len(raw)));ob=ctypes.create_string_buffer(b'\xa5'*on,max(1,on));wb=ctypes.create_string_buffer(wn or 1)
 ret=fn(sb,len(raw),ob,on,wb,wn)
 assert bytes(sb)[:len(raw)]==raw,'input changed'
 return ret,bytes(ob)[:on]
def negative(fn,raw,expect,on=1<<20,wn=1<<20):
 ret,out=invoke(fn,raw,on,wn);assert ret==expect,(hex(ret),hex(expect));assert out==b'\xa5'*on,'partial output on refusal'
 return {'input_sha256':sha(raw),'return':ret,'output_unchanged':True}
def positive(fn,raw,expected):
 ret,out=invoke(fn,raw);assert ret==len(expected) and out[:ret]==expected and out[ret:]==b'\xa5'*(len(out)-ret)
 return {'input_sha256':sha(raw),'output_sha256':sha(expected),'bytes':ret}
requests={}
for role in ('owned_reference','cold_export_reference_vm'):
 for entry,mode in (('f0',3),('f3',7)):
  key=role+'-'+entry
  raw=(a.build/(key+'-native-object.input')).read_bytes();obj=(a.build/(key+'.o')).read_bytes();requests[key]=raw
  checked('backend-positive-'+key,lambda raw=raw,obj=obj:positive(fseed,raw,obj))
  frame=b'HIAVLK01'+struct.pack('<2Q',mode,len(obj))+obj
  expected=(a.build/(key+'.flat')).read_bytes()
  checked('linker-positive-'+key,lambda frame=frame,expected=expected:positive(flink,frame,expected))
# Exact input-domain boundaries and reserved fields; all failures must precede output.
base=requests['owned_reference-f0']
for offset,values in ((0,[0,1]),(8,[0,2,2049,(1<<64)-1]),(16,[0,65,(1<<64)-1]),(24,[0,64,73,len(base),len(base)+8,(1<<64)-1]),(32,[0,2,(1<<64)-1]),(40,[0,2,(1<<64)-1]),(48,[1,(1<<64)-1]),(56,[0,1,2,4,6,8,(1<<64)-1]),(64,[0,64,73,len(base),(1<<64)-1])):
 for value in values:
  raw=bytearray(base);struct.pack_into('<Q',raw,offset,value)
  checked('backend-header-'+str(offset)+'-'+str(value),lambda raw=bytes(raw):negative(fseed,raw,0xffffffff))
for size in (0,1,7,63,79):
 checked('backend-short-'+str(size),lambda raw=base[:size]:negative(fseed,raw,0xfffffffd))
for raw,name in ((base+b'\0','trailing'),(base[:-1],'truncated')):
 checked('backend-'+name,lambda raw=raw:negative(fseed,raw,0xffffffff))
checked('backend-over-input',lambda:negative(fseed,b'\0'*((1<<20)+1),0xfffffffd))
for on,wn,name in ((0,1<<20,'zero-output'),((1<<20)-1,1<<20,'short-output'),((1<<20)+1,1<<20,'large-output'),(1<<20,0,'zero-work'),(1<<20,(1<<20)-1,'short-work')):
 checked('backend-abi-'+name,lambda on=on,wn=wn:negative(fseed,base,0xfffffffd,on,wn))
end=struct.unpack_from('<Q',base,24)[0]
for kind in (0,1,7,9,11,12,(1<<64)-1):
 raw=bytearray(base);struct.pack_into('<Q',raw,end,kind)
 checked('backend-return-type-'+str(kind),lambda raw=bytes(raw):negative(fseed,raw,0xffffffff))
start=struct.unpack_from('<Q',base,64)[0]
for op in (4,5,6,11,26,28,31,39,(1<<64)-1):
 raw=bytearray(base);struct.pack_into('<Q',raw,start,op)
 checked('backend-unsupported-op-'+str(op),lambda raw=bytes(raw):negative(fseed,raw,0xffffffff))
# Explicit new division remains unsigned; the old seed remains unchanged.
run=requests['owned_reference-f3'];start=struct.unpack_from('<Q',run,64)[0];end=struct.unpack_from('<Q',run,24)[0]
division=next(i for i in range(start,end-63,64) if struct.unpack_from('<Q',run,i)[0] in (7,8))
for width,kind in ((8,2),(16,3),(32,4),(64,5),(64,10)):
 raw=bytearray(run);struct.pack_into('<Q',raw,division+40,width);struct.pack_into('<Q',raw,division+56,kind)
 checked('backend-signed-division-'+str(kind),lambda raw=bytes(raw):negative(fseed,raw,0xffffffff))
resource=next(i for i in range(start,end-63,64) if struct.unpack_from('<Q',run,i)[0]==38)
site=struct.unpack_from('<Q',run,resource+8)[0]
for op in (0,1,2,6,8,10,11,13,15,16,17,18,19,20,21,22,23,28):
 raw=bytearray(run);struct.pack_into('<Q',raw,site,op)
 checked('backend-resource-'+str(op),lambda raw=bytes(raw):negative(fseed,raw,0xffffffff))
for kind in (0,1,2,5,(1<<64)-1):
 raw=bytearray(run);struct.pack_into('<Q',raw,site+8,kind)
 checked('backend-resource-kind-'+str(kind),lambda raw=bytes(raw):negative(fseed,raw,0xffffffff))
for entry,mode in (('f0',3),('f3',7)):
 obj=(a.build/('owned_reference-'+entry+'.o')).read_bytes();frame=b'HIAVLK01'+struct.pack('<2Q',mode,len(obj))+obj
 sh=struct.unpack_from('<Q',obj,40)[0]
 def flip(name,at):
  raw=bytearray(frame);raw[at]^=1
  checked('linker-'+entry+'-'+name,lambda raw=bytes(raw):negative(flink,raw,0,wn=0))
 for at in range(24):flip('frame-byte-'+str(at),at)
 for at in list(range(0,40))+list(range(48,64)):flip('elf-header-byte-'+str(at),24+at)
 for section in range(7):
  for field in range(0,64,8):flip('section-'+str(section)+'-field-'+str(field),24+sh+section*64+field)
 rela=struct.unpack_from('<Q',obj,sh+128+24)[0];rn=struct.unpack_from('<Q',obj,sh+128+32)[0]
 sym=struct.unpack_from('<Q',obj,sh+192+24)[0];strings=struct.unpack_from('<Q',obj,sh+256+24)[0];sn=struct.unpack_from('<Q',obj,sh+256+32)[0]
 names=struct.unpack_from('<Q',obj,sh+320+24)[0];nn=struct.unpack_from('<Q',obj,sh+320+32)[0]
 for at in range(240):flip('symbol-byte-'+str(at),24+sym+at)
 for at in range(sn):flip('string-byte-'+str(at),24+strings+at)
 for at in range(nn):flip('name-byte-'+str(at),24+names+at)
 for at in range(97 if mode==3 else 69):flip('public-byte-'+str(at),24+64+at)
 for index in range(min(3,rn//24)):
  rec=rela+index*24;location=struct.unpack_from('<Q',obj,rec)[0]
  for field,value in ((0,0),(0,(1<<64)-1),(8,(4<<32)|4),(8,(3<<32)|1),(16,0)):
   raw=bytearray(frame);struct.pack_into('<Q',raw,24+rec+field,value)
   checked('linker-'+entry+'-relocation-'+str(index)+'-'+str(field)+'-'+str(value),lambda raw=bytes(raw):negative(flink,raw,0,wn=0))
  flip('call-opcode-'+str(index),24+64+location-1)
  flip('relocation-hole-'+str(index),24+64+location)
 for on in (0,len((a.build/('owned_reference-'+entry+'.flat')).read_bytes())-1):
  checked('linker-'+entry+'-short-output-'+str(on),lambda on=on,frame=frame:negative(flink,frame,0,on,0))
 for size in (0,23,535,len(frame)-1):
  checked('linker-'+entry+'-truncated-'+str(size),lambda raw=frame[:size]:negative(flink,raw,0,wn=0))
 checked('linker-'+entry+'-trailing',lambda raw=frame+b'\0':negative(flink,raw,0,wn=0))
# Compare link results with the standard linker in external QA only.
def command(argv):
 r=subprocess.run([str(x) for x in argv],capture_output=True)
 assert r.returncode==0,(argv,r.returncode,r.stderr)
 return r.stdout
primitive=D/'primitives.o';command(['as','--64',a.source/'tools/hia_cold_reference_primitives.S','-o',primitive])
for role in ('owned_reference','cold_export_reference_vm'):
 for entry in ('f0','f3'):
  key=role+'-'+entry;obj=a.build/(key+'.o');elf=D/(key+'.elf');flat=D/(key+'.flat');script=D/(key+'.ld')
  script.write_text('SECTIONS { . = 0x10000; .text : { '+str(primitive)+'(.text) '+str(obj)+'(.text) } /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) } }\n')
  command(['ld','-m','elf_x86_64','--no-undefined','--build-id=none','-z','noexecstack','-T',script,'-o',elf,primitive,obj]);command(['objcopy','-O','binary','--only-section=.text',elf,flat])
  expected=(a.build/(key+'.flat')).read_bytes()
  checked('gnu-linker-byte-parity-'+key,lambda flat=flat,expected=expected:({'sha256':sha(expected)} if flat.read_bytes()==expected else (_ for _ in ()).throw(AssertionError('linker mismatch'))))
# Actual private f3 ABI receives fourteen words and writes exactly one result word.
packet=next((a.original/'qualification').glob('scalar-*-vm.input')).read_bytes()
oldraw=(a.original/'owned-reference-independent.flat').read_bytes();oldoff=json.loads((a.original/'native-packing.json').read_text())['entry_offset']
def abi(which):
 if which=='old':
  mp,plan=mapped(oldraw);mr,run=mapped(oldraw,oldoff,None,(ctypes.c_void_p,ctypes.c_void_p))
 else:
  mp,plan=mapped((a.build/'owned_reference-f0.flat').read_bytes());mr,run=mapped((a.build/'owned_reference-f3.flat').read_bytes(),0,None,(ctypes.c_void_p,ctypes.c_void_p))
 sb=ctypes.create_string_buffer(packet,len(packet));pb=ctypes.create_string_buffer(96);dummy=ctypes.create_string_buffer(1)
 assert plan(sb,len(packet),pb,96,dummy,0)==96
 sizes=struct.unpack_from('<6Q',pb.raw,48);buffers=[ctypes.create_string_buffer(max(1,n)) for n in sizes]
 args=(ctypes.c_uint64*14)(ctypes.addressof(sb),len(packet),*[x for buf,n in zip(buffers,sizes) for x in (ctypes.addressof(buf),n)])
 guards=(ctypes.c_uint64*3)(0x1111222233334444,0,0x5555666677778888)
 run(args,ctypes.byref(guards,8))
 assert guards[0]==0x1111222233334444 and guards[2]==0x5555666677778888,'private result touched neighbouring word'
 assert guards[1]>=144 and guards[1]<=sizes[0]
 assert bytes(sb)==packet
 return {'result':guards[1],'output_sha256':sha(buffers[0].raw[:guards[1]]),'plan_hex':pb.raw.hex(),'left_guard':guards[0],'right_guard':guards[2]}
checked('private-single-word-result-old',lambda:abi('old'))
checked('private-single-word-result-new',lambda:abi('new'))
assert report['cases'][-1]['detail']==report['cases'][-2]['detail']
report.update(status='passed',case_count=len(report['cases']),products={p.name:{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in a.build.glob('hia-*')});save();print('VM BACKEND/LINKER/ABI PASS',len(report['cases']),flush=True)
