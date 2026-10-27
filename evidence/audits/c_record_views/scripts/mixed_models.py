import ctypes,hashlib,json,pathlib,subprocess,sys,tempfile
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
work=pathlib.Path(tempfile.mkdtemp(prefix='hepta-record-mixed-model-'))
configs=[];contracts={'schema':'hepta.c-record-views.v1','records':{},'functions':{}}
for tag,flag in [('A','-funsigned-char'),('B','-fsigned-char')]:
 source=f'#include <stddef.h>\nstruct {tag} {{char *data;size_t n;}};\nint read_{tag}(struct {tag} *r){{return r->data[0];}}\n'
 (work/(tag+'.c')).write_text(source)
 configs.append({'directory':str(work),'file':tag+'.c','arguments':['clang','-std=c11',flag,'-c',tag+'.c']})
 contracts['records'][tag]={'buffers':{'data':{'length_field':'n','add':0}}}
 contracts['functions']['read_'+tag]={'records':{'r':{'access':'read'}},'slices':{}}
 subprocess.run(['gcc','-std=c11',flag,'-fPIC','-c',str(work/(tag+'.c')),'-o',str(work/(tag+'.o'))],check=True)
subprocess.run(['gcc','-shared',str(work/'A.o'),str(work/'B.o'),'-o',str(work/'original.so')],check=True)
(work/'compile_commands.json').write_text(json.dumps(configs))
r=migrate_c_project(work/'compile_commands.json',work/'translated',contracts=contracts,clang=args.clang,rustc=args.rustc,verify_native=True)
report={'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'migration_ok':r['ok'],'diagnostics':r['diagnostics'],'coverage':r.get('coverage'),'declaration_inventory_complete':r['declaration_inventory_complete'],'models':[c['model'] for c in r['build']['configurations']],'artifacts':str(work),'implementation_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'hepta/c_record_views.py',ROOT/'hepta/c_translation.py',ROOT/'hepta/c_project.py']},'values':{}}
if r['ok']:
 class Record(ctypes.Structure):_fields_=[('data',ctypes.POINTER(ctypes.c_ubyte)),('n',ctypes.c_size_t)]
 data=(ctypes.c_ubyte*1)(255);record=Record(data,1)
 for impl,path in [('original',work/'original.so'),('translated',work/'translated/libtranslated.so')]:
  lib=ctypes.CDLL(str(path));report['values'][impl]={}
  for tag in ['A','B']:
   f=getattr(lib,'read_'+tag);f.argtypes=[ctypes.POINTER(Record)];f.restype=ctypes.c_int
   report['values'][impl][tag]=f(ctypes.byref(record))
print(json.dumps(report,indent=2))
pathlib.Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
