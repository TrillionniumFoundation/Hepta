"""One explicit 180/3 owner per stage; eight complete classes remain eight stages."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

from common import *

def main():
    p=argparse.ArgumentParser();p.add_argument('--phase',required=True);a=p.parse_args()
    require(a.phase in ('derive','caps',*[f'class-{i}' for i in range(8)]),'unknown fixed stage')
    require(a.phase!='derive', 'derivation already executed; do not replay')
    require(json.loads((HERE/'DERIVATION-ADMISSION.json').read_bytes())['status']=='DERIVATION_ORIGINALS_ACCEPTED','derived closure not admitted')
    if a.phase.startswith('class-'):
        require(json.loads((HERE/'actual-caps/ACCEPTANCE.json').read_bytes())['status']=='PASS','caps not accepted')
    out=HERE/('actual-'+a.phase);out.mkdir(mode=0o700,exist_ok=False)
    guard=out/'guard';guard.mkdir(mode=0o700)
    stage=out/'stage';stage.mkdir(mode=0o700)
    report={'schema':'hia.v81.source-stage-acceptance.v1','phase':a.phase,'status':'HOLD',
            'original_qualification_seconds':180,'cleanup_seconds':3,'native_or_full_run':False}
    before=snapshot();save(out/'source-before.json',wire(before))
    frozen=json.loads((HERE/'CONTROL-PINS.json').read_bytes())
    for name,row in frozen.items(): require(file_record(HERE/name)==row,'frozen control changed: '+name)
    declared=json.loads((SOURCE/SUPPORT).read_bytes())['source_identity']['files']
    names=set(declared)|{SUPPORT}
    if a.phase=='derive': names-=MUTABLE
    identities={str(SOURCE/name):before[name]['sha256'] for name in sorted(names)}
    identities.update({str(HERE/name):row['sha256'] for name,row in frozen.items()})
    identities[str(HERE/'CONTROL-PINS.json')]=sha256((HERE/'CONTROL-PINS.json').read_bytes()).hexdigest()
    request={'schema':'hia-external-guardian-request.v1','controller_seconds':180,
             'command':[str(Path(sys.executable).resolve()),'-I','-S','-B',str(HERE/'worker.py'),'--phase',a.phase,'--output',str(stage)],
             'cwd':str(SOURCE),'source_identities':identities}
    raw=(json.dumps(request,sort_keys=True,separators=(',',':'))+'\n').encode();require(len(raw)<=262144,'original request cap exceeded')
    save(guard/'request.json',raw)
    command=[str(Path(sys.executable).resolve()),'-I','-S','-B',str(HERE/'controls/guardian.py'),
             '--config',str(guard/'request.json'),'--config-sha256',sha256(raw).hexdigest(),
             '--implementation',str(HERE/'controls/process_owner_impl.py')]
    report.update(command=command,request_sha256=sha256(raw).hexdigest(),request_bytes=len(raw),input_count=len(identities))
    save(out/'INTENT.json',wire(report))
    start=time.monotonic_ns()
    try:
        with (out/'supervisor.stdout.log').open('xb') as stdout,(out/'supervisor.stderr.log').open('xb') as stderr:
            proc=subprocess.run(command,cwd=SOURCE,stdout=stdout,stderr=stderr,check=False)
        report['supervisor_returncode']=proc.returncode
        guardian=json.loads((guard/'guardian.json').read_bytes());natural_guardian(guardian,request)
        require(proc.returncode==0,'guardian supervisor failed')
        child=json.loads((stage/'report.json').read_bytes())
        require(child['phase']==a.phase and child['status']=='PASS','worker did not pass')
        for path,digest in guardian['logs'].items(): require(sha256(Path(path).read_bytes()).hexdigest()==digest,'guardian log bytes differ')
        report.update(status='PASS',worker_report=file_record(stage/'report.json'),guardian=file_record(guard/'guardian.json'),
                      natural_cleanup=True,child_elapsed_ns=child['elapsed_ns'])
    except BaseException as error:
        report['status']='HOLD';report['error']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
        traceback.print_exc()
    finally:
        try:
            after=snapshot();save(out/'source-after.json',wire(after))
            changed=[name for name in before if before[name]!=after.get(name)]
            require(set(before)==set(after),'tracked namespace drift')
            require(set(changed)<=MUTABLE if a.phase=='derive' else not changed,'unapproved source bytes or mode change')
            report.update(source_changes=changed,source_preserved_except_declared_derivation=True)
        except BaseException as error:
            report['status']='HOLD';report['preservation_error']={'type':type(error).__name__,'message':str(error)}
        report['driver_elapsed_ns']=time.monotonic_ns()-start
        save(out/'ACCEPTANCE.json',wire(report))
    print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__': raise SystemExit(main())
