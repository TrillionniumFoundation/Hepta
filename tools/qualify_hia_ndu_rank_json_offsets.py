from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,os,resource,struct
import argparse,sys
cli=argparse.ArgumentParser(description='Probe production JSON helpers across 2^32 offset and scope.')
cli.add_argument('--probe');cli.add_argument('--output');cli.add_argument('--emit-probe-source')
args=cli.parse_args()
PROBE='\ndef json_offset_probe(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    if length(o)<256 or length(w)<128:\n        return 4294967293\n    mode=get(w,0)\n    if mode==0:\n        cp=decoded(s,w,get(w,8))\n        put(o,0,cp)\n        put(o,8,get(w,112))\n        put(o,16,get(w,120))\n        return 0\n    if mode==1:\n        return same_key(s,w,get(w,8),get(w,16))\n    if mode==2:\n        return insert_key(s,o,w,8,get(w,24),get(w,32))\n    return 4294967293\n'
if args.emit_probe_source:
 sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
 from tools.generate_hia_ndu_rank_json import source_program
 from tools.generate_hia_system_jobctl_request import document
 from hepta.hia_agent_assembly import render_assembly
 Path(args.emit_probe_source).write_text(render_assembly(document(PROBE+source_program(),'ndu_rank_json_offset_probe')))
 sys.exit(0)
if not args.probe or not args.output:
 cli.error('--probe and --output are required for qualification')
D=Path(args.output);D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
r={'role': 'ndu_rank_json_offset_probe', 'source_sha256': '702e3ecfadbc6117f48dfd932eee0b6d42aa65f5810e0ff1c769423664c67607', 'profile': {'functions': 21, 'blocks': 387, 'ops': 1708, 'max_block_params': 15}, 'flat_bytes': 152029, 'flat_sha256': '2b23d43e797167698471801c1629c32945a64cfb6862c949479ed1ca694963cc'}
raw=Path(args.probe).read_bytes();assert sha256(raw).hexdigest()==r['flat_sha256']
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
fd=os.memfd_create('wide-json-actual-helper-probe',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value)
entry=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
extent=(1<<32)+8192;source=lib.mmap(None,extent,3,0x22|0x4000,-1,0);assert source not in(None,C.c_void_p(-1).value)
out=C.create_string_buffer(288);work=C.create_string_buffer(160);rows=[]
def start(mode,left=0,right=0,scope=0,at=0,hash=0):
 C.memset(work,0,160);C.memset(work,0xa5,16);C.memset(C.addressof(work)+144,0xa5,16)
 struct.pack_into('<6Q',work,16,mode,left,right,scope,at,hash)
def invoke(label,expected):
 result=entry(source,extent,C.addressof(out)+16,256,C.addressof(work)+16,128)
 assert result==expected,(label,result,expected)
 assert work.raw[:16]+work.raw[-16:]==b'\xa5'*32 and out.raw[:16]+out.raw[-16:]==b'\xdb'*32
 rows.append({'case':label,'passed':True,'return':result})
C.memset(out,0xdb,len(out))
for offset in (0,(1<<32)-2,(1<<32)+2):
 for text,cp,advance in [(b'a"',97,1),(b'\\uD83D\\uDE00"',128512,12),('😀"'.encode(),128512,4),(b'"',1114112,1),(b'\\u0000"',0,6),(b'\xff',1114113,None)]:
  C.memmove(source+offset,text,len(text));start(0,offset);invoke('decoded-'+str(offset)+'-'+str(cp)+'-'+str(advance),0);actual,next,reason=struct.unpack_from('<3Q',out,16);assert actual==cp
  if advance is not None:assert next==offset+advance,(offset,cp,next)
  else:assert reason==20
  assert C.string_at(source+offset,len(text))==text
left=128;right=(1<<32)+128
for a,b,wanted in [(b'alpha"',b'alpha"',1),(b'\\u0061lpha"',b'alpha"',1),('é"'.encode(),b'\\u00e9"',1),(b'alpha"',b'alphb"',0)]:
 C.memmove(source+left,a,len(a));C.memmove(source+right,b,len(b));start(1,left,right);invoke('same-key-'+str(len(rows)),wanted)
text=b'alpha"';C.memmove(source+left,text,len(text));C.memmove(source+right,text,len(text))
value=14695981039346656037
for cp in 'alpha':value=((value^ord(cp))*1099511628211)&((1<<64)-1)
C.memset(C.addressof(out)+16,0,256)
for scope,position,expected in [(0,left,0),(1<<32,right,0),(0,right,4),(1<<32,left,4)]:
 start(2,scope=scope,at=position,hash=value);invoke('full-width-scope-'+str(scope)+'-'+str(position),expected)
table=[struct.unpack_from('<2Q',out,16+i*16) for i in range(8)];assert (left,0) in table and (right,1<<32) in table,table
report={'passed':True,'count':len(rows),'scope':'Actual compiled production decoder/helper source with a probe entry, using a sparse anonymous source view spanning the 2^32 boundary. Only touched source pages are committed. This tests offset/scope width; it is not a claim that a 4GiB entire JSON document was scanned.','probe':r,'rows':rows,'virtual_input_bytes':extent}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('NDU_JSON_U64_OFFSET_ALL_PASS',len(rows),flush=True)
