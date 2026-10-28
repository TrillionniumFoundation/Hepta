import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT=Path('/workspace/scratch/4bc91e0ee48c/hepta-vla-original-type')
sys.path.insert(0,str(ROOT))
from tools.qualify_hia_unified import snapshot

head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
out=Path('/tmp/hepta-vla-original-type-20261027')/('validation-'+head[:8])
out.mkdir()
def write(name,value):
    (out/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
before=snapshot()
write('source-before.json',before)
argv=['/usr/bin/python3','-m','unittest',
      'tests.test_c_parameter_types','tests.test_c_project',
      'tests.test_c_record_views','tests.test_c_project_matrix',
      'tests.test_c_project_source_arguments','tests.test_c_project_semantic_flags','-v']
environment=os.environ.copy()
environment['PATH']='/usr/lib/llvm-20/bin:/tmp/hepta-toolchains/rust-1.90.0/bin:/usr/bin:/bin'
environment['RUSTC']='/tmp/hepta-toolchains/rust-1.90.0/bin/rustc'
tool_paths={'clang':'/usr/lib/llvm-20/bin/clang',
            'rustc':environment['RUSTC'],
            'libclang':'/usr/lib/x86_64-linux-gnu/libclang-20.so.20',
            'python':'/usr/bin/python3'}
tools={name:{'path':path,'sha256':hashlib.sha256(Path(path).read_bytes()).hexdigest()}
       for name,path in tool_paths.items()}
plan={'schema':'hepta.audit.vla-validation.v1','git_commit':head,
      'source_snapshot_before':before['sha256'],'argv':argv,'cwd':str(ROOT),
      'tools':tools,'timeout_seconds':1500,
      'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
write('plan.json',plan)
started=time.monotonic()
with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
    process=subprocess.Popen(argv,cwd=ROOT,env=environment,stdout=stdout,stderr=stderr,start_new_session=True)
    write('process.json',{'pid':process.pid,'argv':argv,'started_utc':plan['started_utc']})
    timed_out=False
    try:
        code=process.wait(timeout=1500)
    except subprocess.TimeoutExpired:
        timed_out=True
        os.killpg(process.pid,signal.SIGKILL)
        code=process.wait()
    finally:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
elapsed=time.monotonic()-started
after=snapshot()
write('source-after.json',after)
log=(out/'stderr.log').read_text(errors='replace')
match=re.search(r'Ran (\d+) tests? in ([0-9.]+)s',log)
after_tools={name:hashlib.sha256(Path(path).read_bytes()).hexdigest() for name,path in tool_paths.items()}
result={**plan,'returncode':code,'timed_out':timed_out,'seconds':elapsed,
        'source_snapshot_after':after['sha256'],
        'source_unchanged':before==after,'tools_unchanged':all(v['sha256']==after_tools[n] for n,v in tools.items()),
        'tests_run':int(match.group(1)) if match else None,
        'unittest_seconds':float(match.group(2)) if match else None,
        'unittest_footer':log[match.start():].strip() if match else None,
        'finished_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
result['passed']=code==0 and not timed_out and result['source_unchanged'] and result['tools_unchanged'] and bool(match) and log[match.end():].strip()=='OK'
write('report.json',result)
print(json.dumps({k:result[k] for k in ('git_commit','returncode','passed','tests_run','seconds','source_unchanged','tools_unchanged')}))
