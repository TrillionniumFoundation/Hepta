from pathlib import Path
import ctypes as C,mmap,struct,sys,json,hashlib,argparse
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);D=p.parse_args().directory
from tools import hia_multiversion_strict_qualification_support as _client
h=vars(_client);rows=[]
base=bytearray(h['inner'](0,files=[(0,b'')]*3,parent=b'/tmp/no-private-guard-effects',raw=h['rawdoc'](h['scalar_program'](None))))
base[:8]=b'HIAMVEX5';struct.pack_into('<Q',base,240,4300)
cases=[]
def edit(raw,at,value):q=bytearray(raw);struct.pack_into('<Q',q,at,value);return bytes(q)
for digit in [1,639,2147483648,(1<<64)-1]:cases.append(('strict-digits-'+str(digit),edit(base,240,digit)))
cases += [('strict-reserved248',edit(base,248,1)),('strict-nonconstructor',edit(base,8,1)),('legacy-cannot-carry-digits',b'HIAMVEX3'+bytes(base[8:]))]
p=bytearray(128);struct.pack_into('<8sQ',p,0,b'HIAMVBC2',1);struct.pack_into('<Q',p,72,len(base));p.extend(base)
providers=[('new-control-old-effects',bytes(p[:128])+b'HIAMVEX3'+bytes(p[136:])),('old-control-new-effects',b'HIAMVBC1'+bytes(p[8:])),('strict-control-init',struct.pack('<8s15Q',b'HIAMVBC2',0,*([0]*14))),('strict-control-destroy',struct.pack('<8s15Q',b'HIAMVBC2',2,*([0]*14))),('strict-control-pad',edit(p,120,1))]
for image,symbol,wn,on,items in [(D/'runtime-effects.so','hia_mv_runtime_effects',131072,40<<20,cases),(D/'runtime-provider.so','hia_mv_background_runtime',1024,128,providers)]:
 lib=C.CDLL(str(image));f=getattr(lib,symbol);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32
 m=mmap.mmap(-1,on);o=(C.c_char*on).from_buffer(m)
 for name,raw in items:
  w=C.create_string_buffer(wn);s=C.create_string_buffer(raw);rc=f(s,len(raw),o,on,w,wn)
  row=dict(name=name,rc=rc,workspace_unchanged=w.raw==bytes(wn),source_unchanged=s.raw==raw+b'\0',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest());rows.append(row)
  assert rc==0xfffffffd and row['workspace_unchanged'] and row['source_unchanged'],row
  print('STRICT_RUNTIME_GUARD',name,flush=True)
 del o;m.close()
report=dict(schema='hepta.hia.multiversion-strict-runtime-private.v1',whole_native_runtime=False,passed=len(rows),failed=0,cases=rows)
(D/'strict-wrapper-guards.json').write_text(json.dumps(report,indent=2)+'\n');print('STRICT_WRAPPER_GUARDS_PASS',len(rows),flush=True)
