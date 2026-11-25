from pathlib import Path
from hashlib import sha256
import argparse,ast,ctypes as C,json,mmap,os,struct,sys,time,resource
W=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(W))
from tools.generate_hia_background_optimizer_json_capture import source_program
from tools.generate_hia_multiversion_future import document
from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_source_build import _run_captured,_named_source_request,_compiled_sources
from tools.qualify_hia_background_optimizer_structure import Flat
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--compiler',type=Path,required=True);args=p.parse_args()
D=args.output;D.mkdir(exist_ok=False)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
probe="def capture_offset_probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    if length(s)<40 or length(o)<1024 or length(w)<128:\n        return 4294967293\n    op=probe_read(s,0)\n    a=probe_read(s,8)\n    b=probe_read(s,16)\n    c=probe_read(s,24)\n    d=probe_read(s,32)\n    if op==0:\n        put(o,512,decoded(s,w,a))\n        put(o,520,get(w,112))\n        put(o,528,get(w,120))\n    elif op==1:\n        put(o,512,wire_atom(s,a))\n    elif op==2:\n        put(o,512,same_key(s,w,a,b))\n    elif op==3:\n        put(w,40,d)\n        put(o,512,insert_key(s,o,w,a,b,c))\n    elif op==4:\n        put(w,0,a)\n        put(w,72,b)\n        put(o,512,decode_string(s,o,w))\n        put(o,520,get(w,0))\n        put(o,528,get(w,88))\n    elif op==5:\n        if capture_same_key(w,a,b):\n            put(o,512,1)\n        else:\n            put(o,512,0)\n    elif op==6:\n        put(o,512,capture_copy(w,o,a,b,c))\n    elif op==7:\n        put(o,512,capture_insert(w,a))\n    else:\n        return 4294967293\n    return 0\n\ndef probe_read(s:readbuf,at:u64) -> u64:\n    value=0\n    i=0\n    while i<8:\n        value=value|(byte(s,at+i)<<(i*8))\n        i=i+1\n    return value\n"
raw=render_assembly(document(probe+'\n'+source_program(),'background_optimizer_json_capture_offset_probe')).encode()
(D/'probe.hepta').write_bytes(raw)
seed=args.compiler.read_bytes()
assert sha256(seed).hexdigest()=='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
CD=D/'compile';CD.mkdir();r=_run_captured(seed,'sources',_named_source_request({'probe.hepta':raw}),CD)
(CD/'stdout').write_bytes(r.stdout);(CD/'stderr').write_bytes(r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr[:500])
flat=_compiled_sources(r.stdout,{'probe.hepta':raw})['probe.hepta'];(D/'probe.flat').write_bytes(flat)
f=Flat(D/'probe.flat')
high=1<<32;n=high+16384
src=mmap.mmap(-1,n,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,prot=mmap.PROT_READ|mmap.PROT_WRITE)
wide=mmap.mmap(-1,n,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,prot=mmap.PROT_READ|mmap.PROT_WRITE)
sp=C.addressof(C.c_char.from_buffer(src));wp=C.addressof(C.c_char.from_buffer(wide))
out=C.create_string_buffer(1024);work=C.create_string_buffer(8192);rows=[]
def invoke(name,op,a=0,b=0,c=0,d=0,use_wide=False):
 struct.pack_into('<5Q',src,0,op,a,b,c,d)
 rc=f.entry(sp,n,C.addressof(out),len(out),wp if use_wide else C.addressof(work),n if use_wide else len(work))
 assert rc==0,(name,rc)
 result=struct.unpack_from('<3Q',out,512)
 rows.append({'case':name,'result':list(result),'passed':True})
 return result
def source(at,raw):src[at:at+len(raw)]=raw
for k,token,cp,advance in [
 ('ascii',b'a',97,1),('unicode2','é'.encode(),233,2),('unicode3','中'.encode(),20013,3),
 ('unicode4','😀'.encode(),128512,4),('high-surrogate',b'\\ud800',0xd800,6),('low-surrogate',b'\\udfff',0xdfff,6),
 ('pair',b'\\ud83d\\ude00',128512,12),('wtf-high',b'\xed\xa0\x80',0xd800,3),('wtf-low',b'\xed\xbf\xbf',0xdfff,3),
 ('end',b'"',1114112,1)]:
 for at in [high-1,high+257]:
  source(at,token+b'"')
  got=invoke(k+'-'+str(at),0,at)
  assert got[:2]==(cp,at+advance),(k,got,at)
for i,token in enumerate([b'0',b'-1',b'123456789012345678901234567890',b'1e99',b'NaN',b'Infinity',b'-Infinity']):
 at=high+512;source(at,token+b' ')
 got=invoke('atom-'+str(i),1,at);assert got[0]==at+len(token),(token,got)
for i,(a,b,want) in enumerate([(b'a"',b'a"',1),(b'\\ud800"',b'\xed\xa0\x80"',1),(b'\\ud83d\\ude00"','😀"'.encode(),1),(b'a"',b'b"',0),(b'\\ud800"',b'\\udfff"',0)]):
 source(high+1024,a);source(high+2048,b)
 assert invoke('same-key-'+str(i),2,high+1024,high+2048)[0]==want
out=C.create_string_buffer(1024)
source(high+1024,b'a"');source(high+2048,b'a"')
for scope,at in [(1,high+1024),(high+1,high+2048),(1,high+2048)]:
 assert invoke('hash-scope-'+str(scope)+'-'+str(at),3,16,scope,at,0x1234)[0]==0
entries=[struct.unpack_from('<2Q',out,i*16)for i in range(16)]
assert sorted((sc,at)for at,sc in entries if at)==[(1,high+1024),(high+1,high+2048)],entries
for i,token,value in [(0,b'"\\ud800"','\ud800'),(1,b'"\\ud800\\ud800"','\ud800\ud800'),(2,b'"\\ud83d\\ude00"','😀')]:
 out=C.create_string_buffer(1024);at=high-2;source(at,token)
 got=invoke('decode-string-'+str(i),4,at,64);expected=value.encode('utf-8','surrogatepass')
 assert got[1:]==(at+len(token),len(expected)) and out.raw[64:64+len(expected)]==expected,got
for i,(a,b,want) in enumerate([(b'xyz',b'xyz',1),(b'\xed\xa0\x80',b'\xed\xa0\x80',1),(b'xyz',b'xyZ',0)]):
 wide[high+128:high+128+len(a)]=a;wide[high+512:high+512+len(b)]=b
 struct.pack_into('<2Q',wide,64+40,high+128,len(a));struct.pack_into('<2Q',wide,136+40,high+512,len(b))
 assert invoke('owned-key-'+str(i),5,0,1,use_wide=True)[0]==want
wide[high+1024:high+1056]=bytes(range(32))
invoke('owned-copy-high-source',6,high+1024,64,32,use_wide=True)
assert out.raw[64:96]==bytes(range(32))
ctx=n-512;table=1024;maps=2048;first=2112
struct.pack_into('<8Q',wide,ctx,4,512,maps,first,2200,2400,table,8)
for i in range(4):struct.pack_into('<Q',wide,maps+8*i,i);struct.pack_into('<Q',wide,first+8*i,i)
for i,parent in [(1,1),(2,high+1),(3,1)]:
 struct.pack_into('<Q',wide,64+72*i+8,parent)
 struct.pack_into('<2Q',wide,64+72*i+40,high+1024,3)
 invoke('owned-hash-scope-'+str(i),7,i,use_wide=True)
entries=[struct.unpack_from('<4Q',wide,table+i*32)for i in range(8)]
assert sorted((row[0],row[1])for row in entries if row[0])==[(2,1),(3,high+1)],entries
assert struct.unpack_from('<Q',wide,maps+8)[0]==3 and struct.unpack_from('<Q',wide,first+24)[0]==1
report={'passed':True,'whole_background_qualified':False,'scope':'Actual compiled owned-capture helpers with sparse source/work views spanning 2^32. It checks full-width scalar offsets, WTF-8 decoding, key scope equality and new duplicate-compaction source offsets; it does not claim a 4 GiB whole JSON document was scanned.','count':len(rows),'cases':rows,'virtual_source_bytes':n,'virtual_workspace_bytes':n,'probe_source_sha256':sha256(raw).hexdigest(),'probe_flat_bytes':len(flat),'probe_flat_sha256':sha256(flat).hexdigest(),'production_source_sha256':sha256((W/'examples/hia_bootstrap/background_optimizer_json_capture.hepta').read_bytes()).hexdigest()}
(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
print('BG_CAPTURE_OFFSETS_QUALIFIED',len(rows),sha256(flat).hexdigest(),flush=True)
