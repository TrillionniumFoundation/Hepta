import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path('/workspace/scratch/4bc91e0ee48c/hepta-vla-original-type')
sys.path.insert(0,str(ROOT))
from hepta.c_migrate import migrate_c_project
from tools.qualify_hia_unified import snapshot

root=Path('/tmp/hepta-vla-original-type-20261027')
before=root/'before'
out=root/'after'
out.mkdir()
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
source_before=snapshot()
identities={name:hashlib.sha256((before/name).read_bytes()).hexdigest()
            for name in ('input.c','compile_commands.json','contracts.json','original.so')}
library=ctypes.CDLL(str(before/'original.so'))
library.probe.argtypes=[ctypes.c_uint,ctypes.POINTER(ctypes.c_uint)]
library.probe.restype=ctypes.c_uint
native_result=int(library.probe(7,(ctypes.c_uint*8)(*range(8))))
migration=migrate_c_project(before/'compile_commands.json',out/'must-not-publish',
    contracts=json.loads((before/'contracts.json').read_text()),
    clang='/usr/lib/llvm-20/bin/clang')
(out/'migration.json').write_text(json.dumps(migration,indent=2,sort_keys=True)+'\n')
source_after=snapshot()
identities_after={name:hashlib.sha256((before/name).read_bytes()).hexdigest() for name in identities}
report={'schema':'hepta.audit.vla-refusal.v1','git_commit':head,
        'before_execution_commit':json.loads((before/'report.json').read_text())['git_commit'],
        'source_snapshot_before':source_before['sha256'],
        'source_snapshot_after':source_after['sha256'],
        'source_unchanged':source_before==source_after,
        'same_counterexample_artifacts':identities==identities_after,
        'inputs_and_original_native':identities,
        'reference_native_result':native_result,'input':{'n':7,'initialized_array_elements':8},
        'migration_ok':migration['ok'],'diagnostics':migration['diagnostics'],
        'publication_absent':not (out/'must-not-publish').exists(),
        'captured_inputs_same_as_before':migration['build']['sha256']==json.loads((before/'migration.json').read_text())['build']['sha256'],
        'finished_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
report['passed']=not report['migration_ok'] and report['publication_absent'] and native_result==8 and report['source_unchanged'] and report['same_counterexample_artifacts'] and report['captured_inputs_same_as_before'] and [d['code'] for d in report['diagnostics']]==['E_C_VLA_PARAMETER']
(out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(report))
