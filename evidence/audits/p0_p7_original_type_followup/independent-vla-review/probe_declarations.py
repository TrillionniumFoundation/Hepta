#!/usr/bin/env python3
"""Small declaration/coverage probes for the original-type admission integration."""
import ctypes
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).parent
REPO = Path('/workspace/scratch/4bc91e0ee48c/hepta-vla-original-type')
CLANG = '/usr/lib/llvm-20/bin/clang'
sys.path.insert(0,str(REPO))
from hepta.c_migrate import migrate_c_project

CASES = {
 'pointer_prototype_vla_definition': ('unsigned probe(unsigned n, const unsigned *other);\nunsigned probe(unsigned n, const unsigned data[++n]) { return n; }\n', None),
 'vla_definition_pointer_redeclaration': ('unsigned probe(unsigned n, const unsigned data[++n]) { return n; }\nunsigned probe(unsigned n, const unsigned *other);\n', None),
 'vla_prototype_pointer_definition': ('unsigned probe(unsigned n, const unsigned other[++n]);\nunsigned probe(unsigned n, const unsigned *data) { return n; }\n', None),
 'fixed_prototype_pointer_definition': ('unsigned probe(unsigned n, const unsigned other[8]);\nunsigned probe(unsigned n, const unsigned *data) { return n; }\n', None),
 'header_vla_definition': ('#include "local.h"\n', 'unsigned probe(unsigned n, const unsigned data[++n]) { return n; }\n'),
 'local_typedef_vla': ('unsigned probe(unsigned n, const unsigned *data) { typedef unsigned Row[++n]; return n; }\n', None),
 'nested_vla_prototype': ('unsigned probe(unsigned n, const unsigned *data) { unsigned nested(unsigned m, const unsigned a[++m]); return n; }\n', None),
}
rows=[]
for name,(source,header) in CASES.items():
 directory=ROOT/name;directory.mkdir()
 (directory/'input.c').write_text(source)
 if header is not None:(directory/'local.h').write_text(header)
 argv=[CLANG,'-std=c11','-O0','-Werror','-shared','-fPIC','input.c','-o','original.so']
 compiled=subprocess.run(argv,cwd=directory,capture_output=True,text=True,timeout=15)
 (directory/'compile.stdout').write_text(compiled.stdout);(directory/'compile.stderr').write_text(compiled.stderr)
 row={'case':name,'source':source,'header':header,'compile_argv':argv,'compile_returncode':compiled.returncode}
 if compiled.returncode==0:
  library=ctypes.CDLL(str(directory/'original.so'));library.probe.argtypes=[ctypes.c_uint,ctypes.POINTER(ctypes.c_uint)];library.probe.restype=ctypes.c_uint
  data=(ctypes.c_uint*64)(*range(64));row['original_result_n7']=int(library.probe(7,data))
  database=directory/'compile_commands.json'
  database.write_text(json.dumps([{'directory':str(directory),'file':'input.c','arguments':[CLANG,'-std=c11','-O0','-c','input.c','-o','input.o']}]))
  contracts={'schema':'hepta.c-contracts.v1','functions':{'probe':{'slices':{'1':{'length':'n','access':'read'}}}}}
  report=migrate_c_project(database,directory/'migrated',contracts=contracts,clang=CLANG)
  (directory/'migration.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
  row.update(migration_ok=report['ok'],diagnostics=report['diagnostics'],declarations=report['declarations'],original_type_receipts=report.get('source_type_admission',[]))
 rows.append(row)
 print(json.dumps({k:v for k,v in row.items() if k not in {'compile_argv','declarations','original_type_receipts'}},ensure_ascii=False),flush=True)
(ROOT/'declaration-results.json').write_text(json.dumps({'schema':'hepta.audit.vla-independent-declarations.v1','git_commit':subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),'cases':rows},indent=2,sort_keys=True)+'\n')
