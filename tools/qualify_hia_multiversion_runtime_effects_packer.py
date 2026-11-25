from pathlib import Path
import sys,ctypes as C,struct,json,hashlib
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');V=B/'native-multiversion-source';sys.path.insert(0,str(V))
from tools import generate_hia_multiversion_runtime_effects_packer as p
from tools.qualify_hia_multiversion_components import Image
D=B/'native-multiversion-runtime-effects-pack-v1';D.mkdir(exist_ok=False)
R=B/'native-multiversion-runtime-effects-v7';old=B/'native-multiversion-runtime-effects-v1'
report=json.loads((R/'build.json').read_text());parts=[Path(x['path']).read_bytes() for x in report['roles']]
pack=Image(old/'multiversion_runtime_effects_packer.flat');link=Image(old/'multiversion_runtime_linker.flat')
rows=[]
def packet(parts):return struct.pack('<8sQ',b'HIAMVEK1',len(parts))+b''.join(struct.pack('<Q',len(x)) for x in parts)+b''.join(parts)
def run(name,tool,raw,expected=None,output=128,work=2048):
 out=C.create_string_buffer(b'\xa5'*output,output);w=C.create_string_buffer(work);rc=tool(raw,out,w)
 if expected is None:assert rc>=0xfffffff0 and out.raw==b'\xa5'*output,(name,rc)
 else:assert rc==len(expected) and out.raw[:rc]==expected and out.raw[rc:]==b'\xa5'*(output-rc),(name,rc,len(expected))
 rows.append(dict(name=name,rc=rc,input_bytes=len(raw),input_sha256=hashlib.sha256(raw).hexdigest(),output_bytes=output,workspace_bytes=work))
def patch(raw,at,value,width=8):
 b=bytearray(raw);b[at:at+width]=value.to_bytes(width,'little');return bytes(b)
tiny=[bytes([i]) for i in range(len(p.ROLES))];frame=packet(tiny);expect=p.reference_object(tiny);head=16+8*len(tiny)
run('all43-smallest',pack,frame,expect,len(expect)+17)
for n in [0,7,8,15,head-1,len(frame)-1]:run('truncated-'+str(n),pack,frame[:n])
for n in [0,42,44,(1<<64)-1]:run('wrong-count-'+str(n),pack,patch(frame,8,n))
run('wrong-magic',pack,b'X'+frame[1:]);run('trailing',pack,frame+b'X')
for i,name in enumerate(p.ROLES):
 for n in [0,4194305]:run('role-'+name+'-extent-'+str(n),pack,patch(frame,16+i*8,n))
run('short-work',pack,frame,work=2047)
for n in [0,1,len(expect)-1]:run('short-output-'+str(n),pack,frame,output=n)
large=list(tiny);large[0]=b'K'*4194304;expected=p.reference_object(large);run('actual-role-four-MiB',pack,packet(large),expected,len(expected)+1)
edge=list(tiny)
for i in range(3):edge[i]=b'B'*4194304
base=len(p.reference_object(edge));obj=p.reference_object(edge);sh=struct.unpack_from('<Q',obj,40)[0];textsize=struct.unpack_from('<Q',obj,sh+96)[0]
edge[-1]=b'Z'*(16777216-textsize+1);expected=p.reference_object(edge)
sh=struct.unpack_from('<Q',expected,40)[0];assert struct.unpack_from('<Q',expected,sh+96)[0]==16777216
run('actual-total-sixteen-MiB',pack,packet(edge),expected,len(expected)+1)
edge[-1]+=b'Z';run('total-sixteen-MiB-plus-one',pack,packet(edge))
actual=packet(parts);expected=p.reference_object(parts);run('all43-actual-byte-exact',pack,actual,expected,len(expected)+9)
linked=(R/'runtime-effects.so').read_bytes();run('five-import-actual-link-byte-exact',link,expected,linked,len(linked)+17,1<<20)
for n in [0,1,len(linked)-1]:run('link-short-output-'+str(n),link,expected,output=n,work=1<<20)
for name,at,value,width in [('elf-magic',0,0,1),('class',4,1,1),('machine',18,3,2),('type',16,2,2),('section-count',60,6,2),('section-offset',40,(1<<64)-1,8)]:
 run('link-'+name,link,patch(expected,at,value,width),work=1<<20)
sh=struct.unpack_from('<Q',expected,40)[0]
for name,at,value,width in [('text-kind',sh+68,8,4),('text-flags',sh+72,7,8),('stack-flags',sh+6*64+8,4,8),('symbol-link',sh+3*64+40,1,4),('reloc-info',sh+2*64+44,2,4)]:
 run('link-'+name,link,patch(expected,at,value,width),work=1<<20)
strings=struct.unpack_from('<Q',expected,sh+4*64+24)[0];size=struct.unpack_from('<Q',expected,sh+4*64+32)[0]
for oldname,newname in [(b'malloc\0',b'calloc\0'),(b'free\0',b'exit\0'),(b'dlopen\0',b'Dlopen\0')]:
 at=expected.index(oldname,strings,strings+size);raw=expected[:at]+newname+expected[at+len(oldname):];run('link-forbidden-'+newname[:-1].decode(),link,raw,work=1<<20)
result=dict(schema='hepta.hia.multiversion-runtime-effects-package.v1',whole_native_runtime=False,passed=len(rows),failed=0,packer=pack.pin,linker=link.pin,image_sha256=report['image_sha256'],cases=rows)
(D/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('EFFECTS_PACKAGE_PASS',len(rows),flush=True)
