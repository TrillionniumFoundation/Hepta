#!/usr/bin/env python3
"""Execute exact local tests, record identities and conservatively qualify the slice."""
from __future__ import annotations
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path
from economic_probe import comparison
from test_economic_probe import study

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'evidence'
FILES=('README.md','P0_P7_STATUS.md','hia_probe.py','economic_probe.py',
       'test_probe.py','test_traps.py','test_cpp_bridge.py','test_economic_probe.py',
       'cpp_bridge_fixture.cpp','cpp_c_consumer.c','qualify.py')

def sha(path:Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def cmd(argv:list[str], timeout:int=120) -> dict:
    try:
        r=subprocess.run(argv,cwd=ROOT,text=True,capture_output=True,timeout=timeout,check=False)
        return {'command':argv,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
    except (subprocess.TimeoutExpired,OSError) as e:
        return {'command':argv,'returncode':-1,'stdout':'','stderr':str(e)}

def main() -> int:
    OUT.mkdir(exist_ok=True)
    result=cmd([sys.executable,'-m','unittest','discover','-p','test_*.py','-v'],timeout=90)
    (OUT/'tests.stdout.log').write_text(result['stdout'])
    (OUT/'tests.stderr.log').write_text(result['stderr'])
    full=result['stdout']+'\n'+result['stderr']
    match=re.search(r'Ran (\d+) tests? in ',full)
    count=int(match.group(1)) if match else 0
    skipped=bool(re.search(r'\bskipped=\d+|\bSKIP\b|\.\.\. skipped',full,re.I))
    passes=result['returncode']==0 and count>=1 and not skipped and '\nOK' in full
    versions={c:cmd([c,'--version'],10)['stdout'].splitlines()[:1] for c in ('clang','gcc','clang++','g++')}
    files={name:sha(ROOT/name) for name in FILES}
    plan=comparison(study())
    (OUT/'synthetic_planner.json').write_text(json.dumps(plan,sort_keys=True,indent=2)+'\n')
    report={
       'schema':'hepta.audit.offline-qualification.v1',
       'profile':'independent_bounded_research_only',
       'authority':'DENY_ALL', 'production_activation_allowed':False,
       'all_p0_p7_blockers_closed':False,
       'qualification_of_local_slice':bool(passes),
       'test_count':count,'test_skips_detected':skipped,'test_exit_code':result['returncode'],
       'machine':{'platform':platform.platform(),'machine':platform.machine(),
                  'python':platform.python_version(),'compilers':versions},
       'source_identities':files,
       'logs':{'stdout_sha256':sha(OUT/'tests.stdout.log'),
               'stderr_sha256':sha(OUT/'tests.stderr.log')},
       'planner':{'dataset_kind':'synthetic','report_sha256':sha(OUT/'synthetic_planner.json'),
                  'native_ndu_executed':False,'application_net_benefit_proved':False},
       'github':{'read_write_status':'BLOCKED_403_ACCOUNT_SUSPENDED',
                  'remote_push_performed':False,'remote_pr_created':False},
       'scope_exclusions':['canonical Hepta verification','independent Rust backend',
            'whole-program safety','actual C/C++ project migration','ARM64 ABI','Agent hidden evaluation',
            'physical hardware','measured NDU advantage','production cutover']}
    (OUT/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    (OUT/'SOURCE_MANIFEST.json').write_text(json.dumps(files,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'local_pass':passes,'tests':count,'skips':skipped,
                      'report':str(OUT/'REPORT.json'), 'remote_status':'BLOCKED_403'},sort_keys=True))
    return 0 if passes else 1

if __name__=='__main__':sys.exit(main())
