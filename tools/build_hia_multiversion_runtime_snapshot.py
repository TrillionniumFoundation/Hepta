from pathlib import Path
import ctypes,fcntl,hashlib,json,mmap,os,subprocess,sys,time
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
S=Path(__file__).resolve().parents[1];Q=Path(os.environ.get('HIA_MV_SNAPSHOT_QA_ROOT',str(T/'multiversion-runtime-snapshot-qa')));Q.mkdir(parents=True,exist_ok=True);D=Q/'native-v4';D.mkdir()
sys.path.insert(0,str(S))
from tools.build_hia_source_build import _named_source_request,_compiled_sources
from tools.generate_hia_multiversion_runtime_snapshot_packer import PREFIX
sha=lambda x:hashlib.sha256(x).hexdigest()
compiler=Path(os.environ.get('HIA_MV_SNAPSHOT_COMPILER',str(T/'production-p3/post-bootstrap/hia-source-build')));raw=compiler.read_bytes();assert sha(raw)=='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
fd=os.memfd_create('snapshot-compiler',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
names=['multiversion_runtime_snapshot','multiversion_runtime_snapshot_packer']
sources={n+'.hepta':(S/'examples/hia_bootstrap'/(n+'.hepta')).read_bytes()for n in names}
packet=_named_source_request(sources);compiles=[];elapsed=[]
for i in range(2):
 start=time.monotonic_ns();r=subprocess.run([f'/proc/self/fd/{fd}','sources'],input=packet,capture_output=True,pass_fds=(fd,),timeout=120,env={'PATH':''});elapsed.append(time.monotonic_ns()-start)
 (D/f'compiler-{i}.stdout').write_bytes(r.stdout);(D/f'compiler-{i}.stderr').write_bytes(r.stderr)
 assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr)
 compiles.append(_compiled_sources(r.stdout,sources))
assert compiles[0]==compiles[1]
flats=compiles[0];body=flats[names[0]+'.hepta'];packer=flats[names[1]+'.hepta']
(D/'snapshot-policy.flat').write_bytes(body);(D/'snapshot-packer.flat').write_bytes(packer)
mm=mmap.mmap(-1,len(packer),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);mm.write(packer)
FN=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)
fn=FN(ctypes.addressof(ctypes.c_char.from_buffer(mm)))
wire=b'HIAMVSPK'+len(body).to_bytes(8,'little')+bytes(16)+body
s=ctypes.create_string_buffer(wire);o=ctypes.create_string_buffer(len(body)+len(PREFIX));w=ctypes.create_string_buffer(64)
assert fn(s,len(wire),o,len(o),w,len(w))==0
actual=o.raw;assert actual==PREFIX+body
if (Q/'snapshot-bridge.bin').exists():assert (Q/'snapshot-bridge.bin').read_bytes()==PREFIX
(D/'snapshot.flat').write_bytes(actual)
rows=[]
for n in names:
 source=sources[n+'.hepta'];flat=flats[n+'.hepta']
 assert (S/'examples/hia_bootstrap'/(n+'.hepta')).read_bytes()==source
 rows.append({'name':n,'source_sha256':sha(source),'source_bytes':len(source),'flat_sha256':sha(flat),'flat_bytes':len(flat)})
report={'status':'DOUBLE_NATIVE_BUILD_AND_NATIVE_PACK_PASS','roles':rows,'compiler_sha256':sha(raw),'compiler_seals':fcntl.fcntl(fd,fcntl.F_GET_SEALS),'elapsed_ns':elapsed,'bridge_sha256':sha(PREFIX),'bridge_bytes':len(PREFIX),'flat_sha256':sha(actual),'flat_bytes':len(actual),'whole_runtime_qualified':False}
(D/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
