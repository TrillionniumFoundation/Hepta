#!/usr/bin/python3
"""Execute one identical ABI admission candidate against a selected source tree."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root, out = map(Path, sys.argv[1:])
out.mkdir()
sys.path.insert(0, str(root))
from hepta.c_migrate import migrate_c, migrate_c_project
from tools.release_check import snapshot

clang = '/usr/lib/llvm-20/bin/clang'
os.environ['PATH'] = '/usr/lib/llvm-20/bin:/tmp/hepta-toolchains/rust-1.90.0/bin:' + os.environ['PATH']
os.environ['RUSTC'] = '/tmp/hepta-toolchains/rust-1.90.0/bin/rustc'
os.chdir(root)
start = time.monotonic()
before = snapshot()
head = subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip()
source = '__attribute__((ms_abi)) unsigned int probe(unsigned int x) { return x + 2u; }\n'
caller = '#include <stdio.h>\n__attribute__((ms_abi)) unsigned int probe(unsigned int);\nint main(void) { unsigned int r=probe(7u); printf("%u\\n",r); return r==9u ? 0 : 1; }\n'
(out/'input.c').write_text(source)
(out/'caller.c').write_text(caller)
commands=[]
def run(argv):
    r=subprocess.run(argv,cwd=out,capture_output=True,text=True,timeout=60)
    commands.append({'argv':argv,'cwd':str(out),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
    if r.returncode: raise RuntimeError('reference command failed')
    return r
run([clang,'-std=c11','-O0','input.c','caller.c','-o',str(out/'original')])
reference=run([str(out/'original')])
(out/'compile_commands.json').write_text(json.dumps([{'directory':str(out),'file':'input.c','arguments':['clang','-std=c11','-O0','-c','input.c','-o','input.o']}]))
project=migrate_c_project(out/'compile_commands.json',out/'converted',clang=clang)
strict=migrate_c(out/'input.c',out/'strict.hepta',clang=clang)
for name, report in [('project',project),('strict',strict)]:
    (out/(name+'.json')).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
after=snapshot()
result={'schema':'hepta.abi-admission-before-after.v1','git_commit':head,'source_root':str(root),'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_snapshot_before':before,'source_snapshot_after':after,'source_unchanged':before==after,'duration_seconds':time.monotonic()-start,
        'reference_commands':commands,'reference_value':reference.stdout.strip(),
        'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'caller_sha256':hashlib.sha256(caller.encode()).hexdigest(),
        'clang_resolved':str(Path(clang).resolve()),'clang_sha256':hashlib.file_digest(Path(clang).resolve().open('rb'),'sha256').hexdigest(),
        'project_ok':project['ok'],'project_output_exists':(out/'converted').exists(),'project_codes':[x['code'] for x in project.get('diagnostics',[])],
        'strict_ok':strict['ok'],'strict_output_exists':(out/'strict.hepta').exists(),'strict_codes':[x['code'] for x in strict.get('rejected',[])],
        'generated_wrong_abi_executed':False,'scope':'Original caller preserves ms_abi; compare migration admission, not an undefined mismatched-ABI native call'}
(out/'report.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('source_snapshot_before','source_snapshot_after','reference_commands')},sort_keys=True))
