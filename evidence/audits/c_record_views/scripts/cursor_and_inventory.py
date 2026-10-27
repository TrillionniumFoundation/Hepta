import copy,ctypes,hashlib,json,os,pathlib,subprocess,sys,tempfile
import argparse
parser=argparse.ArgumentParser(description="Independent C record-view audit replay; use the exact commit in the review manifest.")
parser.add_argument("--repo", required=True)
parser.add_argument("--clang", required=True)
parser.add_argument("--rustc", required=True)
parser.add_argument("--output", required=True)
args=parser.parse_args()
if pathlib.Path(args.output).exists():
 raise SystemExit("Refusing to overwrite existing evidence")
ROOT=pathlib.Path(args.repo).resolve()
sys.path.insert(0,str(ROOT))
from hepta.c_migrate import migrate_c_project
from tests.test_c_record_views import SOURCE, CONTRACT
CLANG=args.clang
RUSTC=args.rustc
BASE=pathlib.Path(tempfile.mkdtemp(prefix='hepta-record-independent-'))
rows=[]
def run_case(name,source,contract=None,invoke=None):
 work=BASE/name;work.mkdir();(work/'input.c').write_text(source)
 db=work/'compile_commands.json';db.write_text(json.dumps([{'directory':str(work),'file':'input.c','arguments':['clang','-std=c11','-c','input.c']}]))
 r=migrate_c_project(db,work/'translated',contracts=copy.deepcopy(CONTRACT if contract is None else contract),clang=CLANG,rustc=RUSTC,verify_native=True)
 row={'case':name,'ok':r['ok'],'diagnostics':r['diagnostics'],'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'coverage':r.get('coverage')}
 if r['ok'] and invoke:
  c=subprocess.run(['gcc','-std=c11','-O2','-fPIC','-shared',str(work/'input.c'),'-o',str(work/'original.so')],capture_output=True,text=True)
  assert c.returncode==0,c.stderr
  for mode,path in [('original',work/'original.so'),('translated',work/'translated/libtranslated.so')]:
   p=subprocess.run([sys.executable,'-c',invoke,str(path)],capture_output=True,text=True,timeout=15)
   row[mode]={'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
 rows.append(row);print(json.dumps(row),flush=True)
INVOKE='''import ctypes,sys
class State(ctypes.Structure):_fields_=[('data',ctypes.POINTER(ctypes.c_ubyte)),('n',ctypes.c_size_t),('head',ctypes.c_uint)]
lib=ctypes.CDLL(sys.argv[1]);lib.start.argtypes=[ctypes.POINTER(State),ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t];lib.read_at.argtypes=[ctypes.POINTER(State),ctypes.c_size_t];lib.read_at.restype=ctypes.c_uint
buf=(ctypes.c_ubyte*4)(13,23,37,41);state=State();lib.start(ctypes.byref(state),buf,4)
print(lib.read_at(ctypes.byref(state),0),flush=True)
'''
run_case('signed_negative_cursor_index',SOURCE.replace('return ctx->data[i];','unsigned char *p=ctx->data; ++p; return p[-1];'),invoke=INVOKE)
run_case('signed_negative_cursor_variable',SOURCE.replace('return ctx->data[i];','unsigned char *p=ctx->data; ++p; int back=-1; return p[back];'),invoke=INVOKE)
run_case('one_past_then_back',SOURCE.replace('return ctx->data[i];','unsigned char *p=ctx->data; for (size_t j=0;j<ctx->n;++j) ++p; return p[-1];'),invoke=INVOKE)
# Complete initialization into previously poisoned storage, no old-field reads.
run_case('valid_original_module',SOURCE,invoke=INVOKE.replace('state=State();','state=State();ctypes.memset(ctypes.byref(state),255,ctypes.sizeof(state));'))
# Defined wrapping operation through C's real usual-arithmetic conversions.
run_case('unsigned_head_wrap',SOURCE.replace('return ctx->data[i];','return (ctx->head + 1u);'),invoke=INVOKE.replace('print(lib.read_at','state.head=0xffffffff\nprint(lib.read_at'))
# Unused active declarations remain a module rejection.
run_case('unused_union',SOURCE+'\nunion Hidden {unsigned char *p;unsigned int n;};\n')
run_case('unused_global',SOURCE+'\nunsigned int unused_global;\n')
run_case('initializer_postincrement',SOURCE.replace('ctx->data = data;','ctx->data = data++;'))
run_case('initializer_partial_zero',SOURCE.replace('ctx->head = 0;','if (n) ctx->head = 0;'))
run_case('extent_reassignment',SOURCE.replace('return ctx->data[i];','ctx->n=1;return 0;'))
report={'base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'implementation_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'hepta/c_record_views.py',ROOT/'hepta/c_translation.py']},'rows':rows,'artifacts':str(BASE)}
out=pathlib.Path(args.output);out.write_text(json.dumps(report,indent=2)+'\n');print(out,flush=True)
