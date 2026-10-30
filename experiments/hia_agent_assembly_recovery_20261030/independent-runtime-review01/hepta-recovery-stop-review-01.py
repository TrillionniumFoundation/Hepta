from __future__ import annotations
import hashlib, importlib.util, json, os, pathlib, signal, subprocess, tempfile, time
from unittest import mock
ROOT=pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work')
SOURCE=ROOT/'experiments/hia_agent_assembly_recovery_20261030/run_recovery.py'
source_bytes=SOURCE.read_bytes()
spec=importlib.util.spec_from_file_location('reviewed_recovery',SOURCE)
module=importlib.util.module_from_spec(spec)
exec(compile(source_bytes,str(SOURCE),'exec'),module.__dict__)
rows=[]
class FakeProcess:
    pid=49173
    def __init__(self,mode): self.mode=mode;self.returncode=None;self.reaped=False;self.wait_count=0;self.events=[]
    def wait(self,timeout=None):
        self.wait_count+=1;self.events.append({'action':'wait','timeout':timeout,'already_reaped':self.reaped})
        if self.mode=='timeout' and self.wait_count==1: raise subprocess.TimeoutExpired(['fake-child'],timeout)
        self.returncode=0 if self.mode=='success' else 1
        self.reaped=True
        return self.returncode
    def poll(self):
        self.events.append({'action':'poll','already_reaped':self.reaped})
        return self.returncode
for mode in ('success','failure','timeout'):
    process=FakeProcess(mode)
    def killpg(group,value): process.events.append({'action':'killpg','group':group,'signal':int(value),'owner_already_reaped':process.reaped})
    with tempfile.TemporaryDirectory(prefix='hepta-pure-stop-review-') as folder:
        with mock.patch.object(module.subprocess,'Popen',return_value=process) as spawn,mock.patch.object(module.os,'killpg',side_effect=killpg):
            error=None
            try: module.run_command(pathlib.Path(folder),'fake',['fake-child'],timeout=0.25)
            except BaseException as caught: error={'type':type(caught).__name__,'message':str(caught)}
        receipt=json.loads((pathlib.Path(folder)/'fake.command.json').read_text())
        signals=[event for event in process.events if event['action']=='killpg']
        expected_error=None if mode=='success' else ('RuntimeError' if mode=='failure' else 'TimeoutExpired')
        rows.append({'name':mode,'passed':bool(signals) and all(not event['owner_already_reaped'] for event in signals) and all(event['group']==process.pid for event in signals) and process.reaped and (error['type'] if error else None)==expected_error,
          'requires_group_cleanup_before_reap_on_every_exit':True,'start_new_session':spawn.call_args.kwargs.get('start_new_session'),'events':process.events,'observed_error':error,'command_receipt':receipt})
report={'schema':'hepta.independent.pure-recovery-stop-review.v1','source':{'path':str(SOURCE.relative_to(ROOT)),'sha256':hashlib.sha256(source_bytes).hexdigest()},'source_unchanged':SOURCE.read_bytes()==source_bytes,'cases':rows,'count':len(rows),'passed':sum(row['passed'] for row in rows),'real_subprocesses':0,'real_signals':0,'model_completions':0,'native_executions':0,'interpretation':'Original reviewed failure preserved; mocked child identity/order only, not an OS containment qualification'}
path=pathlib.Path('/tmp/hepta-recovery-stop-review-01.json')
with path.open('x') as stream: json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
print(json.dumps({'path':str(path),'count':report['count'],'passed':report['passed'],'source_sha256':report['source']['sha256'],'source_unchanged':report['source_unchanged']}))
