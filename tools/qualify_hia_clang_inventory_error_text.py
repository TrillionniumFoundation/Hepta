"""Native inventory refusal text from actual HIA inventory replies.

Python constructs byte fixtures and runs the retained original parser as a QA
oracle. Production error construction uses only the fixed native components.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,random,shutil,struct,subprocess,traceback
from tools.qualify_hia_generation_lease_owner import old
from tools.qualify_hia_clang_object_inventory import synthetic,ALLOWED
from hepta.elf_shared_abi import _reference_owned_shared_symbols,ELFSharedABIRejected
from hepta.object_symbols import inspect_object_symbols,ObjectSymbolsRejected
from hepta.hia_program_llvm import HIAProgramLLVMRejected

def u(raw,at,n=8):return int.from_bytes(raw[at:at+n],'little')
def alter(raw,*items):
 out=bytearray(raw)
 for at,n,v in items:out[at:at+n]=int(v).to_bytes(n,'little')
 return bytes(out)
def tail(names):return b''.join(struct.pack('<Q',len(n.encode('ascii')))+n.encode('ascii')for n in names)
def shared(entries):
 names=bytearray(b'\0');symbols=bytearray(bytes(24))
 code=232
 for entry in entries:
  name=entry[0];info=entry[1]if len(entry)>1 else 0x12;section=entry[2]if len(entry)>2 else 1
  value=entry[3]if len(entry)>3 else 0x1000+code;extent=entry[4]if len(entry)>4 else 1
  at=len(names);names.extend(name+b'\0');symbols.extend(struct.pack('<IBBHQQ',at,info,0,section,value,extent))
 raw=bytearray(bytes(code));raw.append(0xc3);raw.extend(bytes((-len(raw))%8))
 sym=len(raw);raw.extend(symbols);strings=len(raw);raw.extend(names);raw.extend(bytes((-len(raw))%8))
 dyn=len(raw);tags=[(5,0x1000+strings),(6,0x1000+sym),(10,len(names)),(11,24),(21,0),(21,0),(0,0)]
 raw.extend(b''.join(struct.pack('<2Q',*r)for r in tags));sh=len(raw)
 rows=[bytes(64),struct.pack('<IIQQQQIIQQ',0,1,6,0x1000+code,code,1,0,0,1,0),struct.pack('<IIQQQQIIQQ',0,11,2,0x1000+sym,sym,len(symbols),3,1,8,24),struct.pack('<IIQQQQIIQQ',0,3,2,0x1000+strings,strings,len(names),0,0,1,0)]
 raw.extend(b''.join(rows))
 raw[:64]=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),3,62,1,0,64,sh,0,64,56,3,64,4,0)
 raw[64:232]=b''.join([struct.pack('<IIQQQQQQ',1,5,0,0x1000,0x1000,len(raw),len(raw),4096),struct.pack('<IIQQQQQQ',2,6,dyn,0x1000+dyn,0x1000+dyn,len(tags)*16,len(tags)*16,8),struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16)])
 return bytes(raw)

class Inventory:
 def __init__(self,base):
  self.images=[old.Image((base/'shared.component').read_bytes()),old.Image((base/'object.component').read_bytes())]
  self.out=C.create_string_buffer(2<<20);self.work=C.create_string_buffer(2<<20)
 def run(self,kind,raw,expected,machine):
  C.memset(self.work,0,len(self.work))
  if kind==0:
   wire=raw
   struct.pack_into('<Q',self.work,0,int.from_bytes(b'HIAELFA2','little'))
   struct.pack_into('<Q',self.work,1572880,len(expected))
   for i,name in enumerate(expected):
    b=name.encode('ascii');assert len(b)<=512
    struct.pack_into('<Q',self.work,1572888+i*520,len(b));C.memmove(C.addressof(self.work)+1572896+i*520,b,len(b))
   wn=1639448
  else:
   wire=b'HIAOEL01'+struct.pack('<7Q',machine,len(raw),len(expected),0,0,0,0)+raw+tail(expected);wn=len(self.work)
  src=C.create_string_buffer(wire);n=self.images[kind].entry(src,len(wire),self.out,len(self.out),self.work,wn)
  assert 64<=n<=len(self.out),(kind,len(raw),hex(n))
  return bytes(self.out[:n])

def original(kind,raw,expected,machine):
 try:
  if kind==0:
   if not 64<=len(raw)<=67108864:raise ELFSharedABIRejected('E_LLVM_OWNED_DYNSYM: invalid artifact or source export list')
   exports,_=_reference_owned_shared_symbols(raw)
   if exports!=set(expected):raise ELFSharedABIRejected('E_LLVM_OWNED_DYNSYM: public ABI symbols differ from source: expected '+repr(expected)+', observed '+repr(tuple(sorted(exports))))
  else:
   result=inspect_object_symbols(raw,'ELF64',machine)
   if machine==243 and u(raw,48,4)!=5:raise HIAProgramLLVMRejected('E_HIA_PROGRAM_LLVM: RISC-V object requires the reviewed RV64GC LP64D ELF flags')
   if result['defined']!=frozenset(expected)or not result['undefined']<=ALLOWED:raise HIAProgramLLVMRejected('E_HIA_PROGRAM_LLVM: object import/export inventory differs from the closed core ABI')
 except (ELFSharedABIRejected,ObjectSymbolsRejected,HIAProgramLLVMRejected)as exc:return exc
 return None

def main():
 p=argparse.ArgumentParser();p.add_argument('--flat',type=Path,required=True);p.add_argument('--components',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700)
 image=old.Image(a.flat.read_bytes());inventory=Inventory(a.components)
 out=mmap.mmap(-1,40<<20);work=mmap.mmap(-1,1048704);op=C.addressof(C.c_char.from_buffer(out));wp=C.addressof(C.c_char.from_buffer(work))
 rows=[];codes={'shared':{},'object':{}};details=set();controls=0
 report={'schema':'hia.clang-inventory-error-text.qualification.v1','passed':False,'whole_public_runtime_qualified':False,'cases':rows,'codes':codes,'product':{'path':str(a.flat),'bytes':a.flat.stat().st_size,'sha256':hashlib.sha256(a.flat.read_bytes()).hexdigest()}}
 def invoke(wire,capacity,wn=1048704):
  src=C.create_string_buffer(wire);return image.entry(src,len(wire),op,capacity,wp,wn)
 def check(label,kind,raw,expected=('calculate',),machine=62):
  nonlocal controls
  refusal=original(kind,raw,expected,machine);reply=inventory.run(kind,raw,expected,machine)
  code=u(reply,0 if kind==0 else 8);failed=code!=0 or kind==0 and u(reply,16)==2
  assert failed==(refusal is not None),(label,code,repr(refusal))
  key='shared'if kind==0 else'object';codes[key][str(code)]=codes[key].get(str(code),0)+1
  if refusal is None:return
  expected_bytes=tail(expected);wire=b'HIACIER1'+struct.pack('<5Q',kind,len(raw),len(reply),len(expected),len(expected_bytes))+bytes(80)+raw+reply+expected_bytes
  want=str(refusal).encode('ascii');needed=128+len(want);assert needed+16<len(out)
  out[:needed+16]=b'\xa5'*(needed+16)
  n=invoke(wire,len(out));assert n==needed,(label,n,needed,repr(refusal),reply[:64].hex())
  assert out[:8]==b'HIACIRS1'and u(out,16)==len(want)and bytes(out[128:n])==want,(label,bytes(out[128:n]),want)
  cls=51 if isinstance(refusal,ELFSharedABIRejected)else 52 if isinstance(refusal,ObjectSymbolsRejected)else 45
  assert u(out,8)==cls and u(out,56)==needed and not any(out[64:128])and out[n:n+16]==b'\xa5'*16,(label,'header/canary')
  cause=refusal.__cause__
  if cause is None:assert u(out,24)==0,(label,'unexpected cause')
  else:
   assert isinstance(cause,UnicodeDecodeError)and cause.encoding=='ascii'
   at,size,pos=struct.unpack_from('<3Q',out,32)
   assert u(out,24)==1 and raw[at:at+size]==cause.object and pos==cause.start and pos+1==cause.end and cause.reason=='ordinal not in range(128)',(label,'Unicode cause',at,size,pos,repr(cause))
  mark=(kind,code,cls,str(refusal)if code==2 else '')
  if mark not in details:
   details.add(mark)
   out[:needed+16]=b'\xa5'*(needed+16);assert invoke(wire,needed)==needed and out[needed:needed+16]==b'\xa5'*16
   out[:needed+16]=b'\xa5'*(needed+16);assert invoke(wire,needed-1)==0xfffffffe and u(work,56)==needed and out[:needed+16]==b'\xa5'*(needed+16)
   controls+=2
  rows.append({'label':label,'kind':kind,'artifact_bytes':len(raw),'code':code,'class':cls,'message_bytes':len(want),'unicode_cause':cause is not None,'passed':True})
 try:
  compiler=shutil.which('clang');assert compiler
  version=subprocess.check_output([compiler,'--version'],text=True,timeout=30);assert 'clang version 21.1.8'in version,version
  report['actual_clang']={'path':compiler,'version':version.splitlines()[0]}
  llvm=b'declare void @abort()\ndefine i64 @calculate(i64 %a) {\nentry:\n %z = icmp eq i64 %a, 0\n br i1 %z, label %bad, label %good\nbad:\n call void @abort()\n unreachable\ngood:\n %v = add i64 %a, 7\n ret i64 %v\n}\n'
  actual=[]
  for kind in (0,1):
   path=a.output/('actual.so'if kind==0 else'actual.o')
   command=[compiler,'-x','ir','-O3','-fPIC','-shared'if kind==0 else'-c','-o',str(path),'-']
   cp=subprocess.run(command,input=llvm,capture_output=True,timeout=30);assert cp.returncode==0,cp.stderr
   raw=path.read_bytes();actual.append(raw);check('actual-clang-success',kind,raw);check('actual-clang-source-mismatch',kind,raw,('other',))
  raw=shared([(b'calculate',)]);check('synthetic-shared-valid',0,raw)
  sh=u(raw,40);sym=u(raw,sh+128+24);names=u(raw,sh+192+24);names_n=u(raw,sh+192+32);dyn=u(raw,120+8)
  mutations=[
   ('identity',[(16,2,1)]),('sections',[(58,2,1)]),('section-range',[(sh+64+24,8,len(raw)+1)]),
   ('headers',[(54,2,1)]),('tls',[(64,4,7)]),('stack-permissions',[(176+4,4,7)]),
   ('dynamic-bounds',[(120+32,8,3)]),('load-permissions',[(64+4,4,7)]),('load-range',[(64+8,8,len(raw)+1)]),
   ('stack-missing',[(176,4,0)]),('exec-missing',[(64+4,4,4)]),('dynamic-missing',[(120,4,0)]),
   ('symbols-missing',[(sh+128+4,4,1)]),('symbols-shape',[(sh+128+56,8,1)]),
   ('loader-redirection',[(dyn,8,15)]),('loader-flags',[(dyn+64,8,30),(dyn+72,8,1)]),
   ('loader-flags1',[(dyn+64,8,0x6ffffffb),(dyn+72,8,0x10)]),('loader-duplicate',[(dyn+16,8,5)]),
   ('loader-authority',[(dyn+40,8,names_n+1)]),('needed-bounds',[(dyn+64,8,1),(dyn+72,8,names_n)]),
   ('needed-name',[(dyn+64,8,1),(dyn+72,8,0)]),('name-offset',[(sym+24,4,names_n)]),
   ('name-unclosed',[(names+names_n-1,1,65)]),('name-unicode',[(names+1,1,255)]),('name-spelling',[(names+1,1,63)]),
   ('binding',[(sym+24+4,1,0x32)]),('public-kind',[(sym+24+4,1,0x11)]),('public-extent',[(sym+24+8,8,1)])]
  for label,changes in mutations:check(label,0,alter(raw,*changes))
  expanded=raw+bytes(16*4097);check('dynamic-unbounded',0,alter(expanded,(120+8,8,len(raw)),(120+32,8,16*4097)))
  check('duplicate-identity',0,shared([(b'calculate',),(b'calculate',0x10,0,0,0)]))
  check('unreviewed-import',0,shared([(b'calculate',),(b'evil',0x10,0,0,0)]))
  check('empty-observed',0,shared([]))
  check('sorted-multiple-exports',0,shared([(b'zeta',),(b'beta',),(b'alpha',)]))
  for n in [1,5,16,63]:check('short-shared-'+str(n),0,actual[0][:n])
  entries=[('fn_'+str(i).zfill(5)).encode()for i in range(65535)]
  check('full-original-symbol-bound',0,shared([(name,)for name in reversed(entries)]))
  object_cases=[
   ('one',[(b'calculate',)]),('weak',[(b'calculate',0x22,1)]),('binding',[(b'calculate',0xa2,1)]),
   ('global-data',[(b'calculate',),(b'data',0x11,1)]),('defined-duplicate',[(b'calculate',),(b'calculate',)]),
   ('export-import',[(b'calculate',),(b'calculate',0x10,0,0,0)]),('import-export',[(b'calculate',0x10,0,0,0),(b'calculate',)]),
   ('nonascii',[(b'calculate',),(b'bad\xff\xfe',0x10,0,0,0)]),('long-nonascii',[(b'calculate',),(b'a'*4096+b'\xfftail',0x10,0,0,0)]),
   ('outside',[(b'calculate',0x12,1,1,1)]),('zero-size',[(b'calculate',0x12,1,0,0)]),
   ('bad-section',[(b'calculate',0x12,0xff,0,1)]),('no-export',[(b'abort',0x10,0,0,0)]),
   ('nonidentifier',[(b'\ncalculate',)]),('long-name',[(b'c'*65537,)])]
  for label,entries in object_cases:check('object-'+label,1,synthetic(entries))
  ob=synthetic([(b'calculate',)]);osh=u(ob,40);sym=u(ob,osh+128+24);names=u(ob,osh+192+24);names_n=u(ob,osh+192+32)
  changes=[('table-invalid',[(osh+128+56,8,1)]),('strings-missing',[(osh+128+40,4,1)]),('table-missing',[(osh+128+4,4,1)]),('name-bad',[(sym+24,4,names_n)]),('name-unclosed',[(names+names_n-1,1,65)]),('strings-outside-empty',[(osh+192+24,8,len(ob)+1),(osh+192+32,8,0)])]
  for label,items in changes:check('object-'+label,1,alter(ob,*items))
  check('riscv-flags',1,alter(synthetic([(b'calculate',)],243),(48,4,0)),machine=243)
  for kind,raw in enumerate(actual):
   offsets=set(range(64));sh=u(raw,40);sn=u(raw,60,2);offsets.update(range(sh,sh+sn*64))
   if kind==0:
    ph=u(raw,32);pn=u(raw,56,2);offsets.update(range(ph,ph+pn*56))
   for at in sorted(offsets):
    for value in (0,255):
     if raw[at]!=value:check('actual-mutation-'+str(at)+'-'+str(value),kind,alter(raw,(at,1,value)))
  # Malformed codec frames contain no native capabilities or owner authority.
  valid_reply=inventory.run(0,actual[0],('other',),62);t=tail(('other',));wire=b'HIACIER1'+struct.pack('<5Q',0,len(actual[0]),len(valid_reply),1,len(t))+bytes(80)+actual[0]+valid_reply+t
  bad=[b'',wire[:127],b'BADMAGIC'+wire[8:],alter(wire,(8,8,2)),alter(wire,(16,8,0)),alter(wire,(24,8,63)),alter(wire,(32,8,129)),alter(wire,(40,8,len(t)+1))]
  for at in range(48,128,8):bad.append(alter(wire,(at,8,1)))
  for item in bad:
   out[:512]=b'\xa5'*512;assert invoke(item,len(out))==0xfffffffd and out[:512]==b'\xa5'*512;controls+=1
  out[:512]=b'\xa5'*512;assert invoke(wire,len(out),1048703)==0xfffffffe and out[:512]==b'\xa5'*512;controls+=1
  assert set(map(int,codes['shared']))>=set(range(32)),codes
  assert set(map(int,codes['object']))>=set(range(14)),codes
  report.update(passed=True,actual_native_inventory_replies=True,original_exception_messages_and_ascii_causes_equal=True,original_symbol_bound_65536_preserved=True,native_refusals=len(rows),bounds_and_malformed_controls=controls)
  print('INVENTORY_ERROR_TEXT_ACTUAL_PASS',len(rows),controls,codes,flush=True)
 except BaseException as e:report.update(failure=repr(e),traceback=traceback.format_exc());raise
 finally:(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');out.close();work.close()
if __name__=='__main__':main()
