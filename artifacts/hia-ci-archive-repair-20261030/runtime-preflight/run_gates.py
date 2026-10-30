#!/usr/bin/env python3
"""Replay exactly the six requested CI qualification commands in isolation."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

OUT=Path(__file__).resolve().parent
SETUP=json.loads((OUT/'SETUP.json').read_bytes())
SOURCE=Path(SETUP['isolated_checkout'])
EVIDENCE=Path(SETUP['output_root'])
CLANG='/usr/lib/llvm-20/bin/clang'


def validate():
    assert subprocess.check_output(['git','--no-replace-objects','rev-parse','HEAD'],cwd=SOURCE,text=True).strip()==SETUP['head']
    assert not subprocess.check_output(['git','--no-replace-objects','status','--porcelain','--untracked-files=all'],cwd=SOURCE).strip()
    assert all(sha256((SOURCE/name).read_bytes()).hexdigest()==entry['sha256'] for name,entry in SETUP['source_files'].items())
    assert sha256(Path(SETUP['recursive_bridge']).read_bytes()).hexdigest()==SETUP['recursive_binary_sha256']
    assert sha256(Path(SETUP['recursive_manifest']).read_bytes()).hexdigest()==SETUP['recursive_manifest_sha256']


def main():
    validate()
    EVIDENCE.mkdir(exist_ok=False)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(SOURCE)+':/workspace/scratch/cd43ab608057/hia-python-deps',
             CLANG=CLANG,HEPTA_CLANG=CLANG,HEPTA_RECURSIVE_NDU_IDENTITY=SETUP['recursive_manifest'],
             HEPTA_RECURSIVE_NDU_BRIDGE=SETUP['recursive_bridge'])
    specs=[
        ('ndu-loop',['tools/qualify_hia_ndu_loop.py','--identity',SETUP['recursive_manifest'],'--bridge',SETUP['recursive_bridge'],'--clang',CLANG,'--output',str(EVIDENCE/'ndu-loop')]),
        ('adaptive',['tools/qualify_hia_adaptive.py','--workdir',str(EVIDENCE/'adaptive'),'--clang',CLANG]),
        ('owned-state',['tools/qualify_hia_stateful.py','--workdir',str(EVIDENCE/'owned-state'),'--clang',CLANG]),
        ('narrowing',['tools/qualify_hia_narrowing.py','--out',str(EVIDENCE/'narrowing'),'--clang',CLANG]),
        ('owned-continuation',['tools/qualify_hia_continuation.py','--workdir',str(EVIDENCE/'owned-continuation'),'--clang',CLANG]),
        ('agent-assembly',['tools/qualify_hia_agent_assembly.py','--out',str(EVIDENCE/'agent-assembly'),'--clang',CLANG]),
    ]
    report={'schema':'hepta.hia.step21-isolated-ci-replay.v1','head':SETUP['head'],'checkout':str(SOURCE),
            'source_files':SETUP['source_files'],'recursive_source_pin':SETUP['recursive_identity_observed']['source_commit'],
            'recursive_binary_sha256':SETUP['recursive_binary_sha256'],'clang':CLANG,
            'scope':'Six existing workflow qualification commands; independent gates continue after any failure to expose later defects. Output location changes only. No formal NDU/Agent/Ring study is modified or repeated.',
            'gates':[],'main_source_files_written':0,'main_git_metadata_written':0,'source_unchanged':False}
    for name,arguments in specs:
        validate()
        command=[sys.executable,*arguments]
        row={'name':name,'command':command,'status':'running','cwd':str(SOURCE)}
        report['gates'].append(row)
        (OUT/'RUN.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print(json.dumps({'gate':name,'status':'running'}),flush=True)
        start=time.monotonic_ns()
        log=OUT/(name+'.log')
        with log.open('wb') as sink:
            result=subprocess.run(command,cwd=SOURCE,env=env,stdout=sink,stderr=subprocess.STDOUT)
        row.update(returncode=result.returncode,wall_ns=time.monotonic_ns()-start,
                   status='passed' if result.returncode==0 else 'failed',log=str(log),
                   log_sha256=sha256(log.read_bytes()).hexdigest(),output=str(EVIDENCE/name))
        validate()
        print(json.dumps({k:row[k] for k in ('name','status','returncode','wall_ns')}),flush=True)
        (OUT/'RUN.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    validate()
    report['source_unchanged']=True
    report['all_six_passed']=all(row['returncode']==0 for row in report['gates'])
    (OUT/'RUN.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'all_six_passed':report['all_six_passed'],'source_unchanged':True}),flush=True)
    return 0 if report['all_six_passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
