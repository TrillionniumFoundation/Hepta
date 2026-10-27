import copy,ctypes,hashlib,json,mmap,os,pathlib,resource,subprocess,sys,tempfile
import argparse
parser=argparse.ArgumentParser(description="Independent C record-view audit replay; use the exact commit in the review manifest.")
parser.add_argument("--repo", required=True)
parser.add_argument("--clang", required=True)
parser.add_argument("--rustc", required=True)
parser.add_argument("--output", required=True)
args=parser.parse_args()
if pathlib.Path(args.output).exists():
 raise SystemExit("Refusing to overwrite existing evidence")
ROOT=pathlib.Path(args.repo).resolve();sys.path.insert(0,str(ROOT))
from hepta.c_migrate import migrate_c_project
from tools.qualify_c_ring_buffer import capture_fixture,FIXTURE
CLANG=args.clang;RUSTC=args.rustc
work=pathlib.Path(tempfile.mkdtemp(prefix='hepta-record-alias-audit-'));database=capture_fixture(work)
r=migrate_c_project(database,work/'translated',contracts=json.loads((FIXTURE/'contracts.json').read_text()),clang=CLANG,rustc=RUSTC,verify_native=True)
assert r['ok'],r['diagnostics']
class Ring(ctypes.Structure):_fields_=[('data',ctypes.POINTER(ctypes.c_ubyte)),('mask',ctypes.c_size_t),('tail',ctypes.c_size_t),('head',ctypes.c_size_t)]
lib=ctypes.CDLL(str(work/'translated/libtranslated.so'));rec=ctypes.POINTER(Ring);ptr=ctypes.POINTER(ctypes.c_ubyte)
lib.ring_buffer_init.argtypes=[rec,ptr,ctypes.c_size_t];lib.ring_buffer_queue.argtypes=[rec,ctypes.c_ubyte];lib.ring_buffer_queue_arr.argtypes=[rec,ptr,ctypes.c_size_t];lib.ring_buffer_dequeue.argtypes=[rec,ptr]
rows=[]
for case in ['record_buffer_overlap','buffer_input_overlap','buffer_output_overlap','record_output_overlap']:
 shared=mmap.mmap(-1,4096,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
 ring=Ring.from_buffer(shared);buf=(ctypes.c_ubyte*8).from_buffer(shared,64)
 lib.ring_buffer_init(ctypes.byref(ring),buf,8);lib.ring_buffer_queue(ctypes.byref(ring),173)
 if case=='record_buffer_overlap':ring.data=ctypes.cast(ctypes.byref(ring),ptr)
 before=hashlib.sha256(shared[:]).hexdigest()
 child=os.fork()
 if child==0:
  resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  if case=='record_buffer_overlap':lib.ring_buffer_queue(ctypes.byref(ring),42)
  elif case=='buffer_input_overlap':lib.ring_buffer_queue_arr(ctypes.byref(ring),buf,1)
  elif case=='buffer_output_overlap':lib.ring_buffer_dequeue(ctypes.byref(ring),buf)
  else:lib.ring_buffer_dequeue(ctypes.byref(ring),ctypes.cast(ctypes.byref(ring),ptr))
  os._exit(0)
 _,status=os.waitpid(child,0);after=hashlib.sha256(shared[:]).hexdigest()
 rows.append({'case':case,'exit_code':os.waitstatus_to_exitcode(status),'shared_record_and_storage_unchanged':before==after,'before_sha256':before,'after_sha256':after})
 assert rows[-1]['exit_code']==-6 and before==after,rows[-1]
 del ring,buf;shared.close()
# A read/read alias is permitted, and observes the same original bytes.
source='#include <stddef.h>\nstruct State{unsigned char*data;size_t n;}; int probe(struct State*r,const unsigned char*input,size_t n){return r->data[0]+input[0];}\n'
contracts={'schema':'hepta.c-record-views.v1','records':{'State':{'buffers':{'data':{'length_field':'n','add':0}}}},'functions':{'probe':{'records':{'r':{'access':'read'}},'slices':{'input':{'access':'read','length':'n'}}}}}
casework=work/'read_alias';casework.mkdir();(casework/'input.c').write_text(source);(casework/'compile_commands.json').write_text(json.dumps([{'directory':str(casework),'file':'input.c','arguments':['clang','-std=c11','-c','input.c']}]))
q=migrate_c_project(casework/'compile_commands.json',casework/'translated',contracts=contracts,clang=CLANG,rustc=RUSTC,verify_native=True);assert q['ok'],q['diagnostics']
subprocess.run(['gcc','-shared','-fPIC',str(casework/'input.c'),'-o',str(casework/'original.so')],check=True)
class State(ctypes.Structure):_fields_=[('data',ptr),('n',ctypes.c_size_t)]
data=(ctypes.c_ubyte*4)(13,23,37,41);state=State(data,4);values={}
for label,path in [('C',casework/'original.so'),('Hepta',casework/'translated/libtranslated.so')]:
 read=ctypes.CDLL(str(path)).probe;read.argtypes=[ctypes.POINTER(State),ptr,ctypes.c_size_t];read.restype=ctypes.c_int;values[label]=read(ctypes.byref(state),data,4)
assert values=={'C':26,'Hepta':26},values
report={'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'implementation_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'hepta/c_record_views.py',ROOT/'hepta/c_translation.py']},'preborrow_rejections':rows,'read_read_alias':values,'artifacts':str(work),'claims':{'atomic_rollback_after_algorithm_mutation':False,'pointer_provenance_proved':False}}
pathlib.Path(args.output).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
