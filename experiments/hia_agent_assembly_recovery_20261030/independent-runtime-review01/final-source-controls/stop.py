from __future__ import annotations
import hashlib, importlib.util, json, pathlib, signal, subprocess, tempfile, types
from contextlib import ExitStack
from unittest import mock
ROOT=pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work')
SOURCE=ROOT/'experiments/hia_agent_assembly_recovery_20261030/run_recovery.py'
source_bytes=SOURCE.read_bytes()
spec=importlib.util.spec_from_file_location('reviewed_stop_recovery',SOURCE)
module=importlib.util.module_from_spec(spec)
exec(compile(source_bytes,str(SOURCE),'exec'),module.__dict__)
rows=[]
class FakeProcess:
    pid=49173
    def __init__(self,mode): self.mode=mode;self.returncode=None;self.reaped=False;self.wait_count=0;self.events=[]
    def wait(self,timeout=None):
        self.wait_count+=1;self.events.append({'action':'wait','timeout':timeout,'already_reaped':self.reaped})
        if self.mode=='reap_timeout': raise subprocess.TimeoutExpired(['fake-child'],timeout)
        self.returncode=7 if self.mode=='failure' else (-9 if self.mode in {'timeout','timeout_signal_error','interrupt'} else 0)
        self.reaped=True
        return self.returncode
    def poll(self): raise AssertionError('poll would reap the anchored owner before group cleanup')
CASES=[('success',None),('failure','RuntimeError'),('timeout','TimeoutExpired'),('interrupt','KeyboardInterrupt'),('external_reap','ChildProcessError'),('timeout_signal_error','TimeoutExpired'),('signal_error','RuntimeError'),('reap_timeout','RuntimeError'),('owner_record_error','OSError'),('spawn_error','OSError'),('outer_budget',None)]
for mode,expected_error in CASES:
    process=FakeProcess(mode)
    def waitid(which,pid,flags):
        process.events.append({'action':'waitid','which':which,'pid':pid,'flags':flags,'already_reaped':process.reaped})
        if mode=='external_reap': process.reaped=True;raise ChildProcessError('mock: another observer reaped the child')
        if mode=='interrupt': raise KeyboardInterrupt('mock cancellation')
        if mode in {'timeout','timeout_signal_error'}: return None
        return types.SimpleNamespace(si_pid=pid,si_code=1,si_status=7 if mode=='failure' else 0)
    def killpg(group,value):
        process.events.append({'action':'killpg','group':group,'signal':int(value),'owner_already_reaped':process.reaped})
        if mode in {'signal_error','timeout_signal_error'}: raise PermissionError('mock cleanup denied')
    actual_save=module.save
    def save(path,value):
        if mode=='owner_record_error' and str(path).endswith('.owner.json'): raise OSError('mock owner receipt write failed')
        return actual_save(path,value)
    with tempfile.TemporaryDirectory(prefix='hepta-pure-stop-review2-') as folder:
        with ExitStack() as stack:
            spawn=stack.enter_context(mock.patch.object(module.subprocess,'Popen',side_effect=OSError('mock spawn failed') if mode=='spawn_error' else None,return_value=process))
            stack.enter_context(mock.patch.object(module.os,'waitid',side_effect=waitid))
            stack.enter_context(mock.patch.object(module.os,'killpg',side_effect=killpg))
            stack.enter_context(mock.patch.object(module,'save',side_effect=save))
            if mode=='outer_budget': stack.enter_context(mock.patch.object(module,'remaining_time',return_value=.05))
            error=None
            try: module.run_command(pathlib.Path(folder),'fake',['fake-child'],timeout=0 if mode in {'timeout','timeout_signal_error'} else 10)
            except BaseException as caught: error={'type':type(caught).__name__,'message':str(caught)}
        receipt=json.loads((pathlib.Path(folder)/'fake.command.json').read_text())
        signals=[event for event in process.events if event['action']=='killpg']
        expected_signals=0 if mode in {'external_reap','spawn_error'} else 1
        signal_ok=len(signals)==expected_signals and all(not event['owner_already_reaped'] and event['group']==process.pid and event['signal']==int(signal.SIGKILL) for event in signals)
        status_observations=[event for event in process.events if event['action']=='waitid']
        waitid_ok=all(event['flags'] & module.os.WNOWAIT and event['pid']==process.pid for event in status_observations)
        cleanup=receipt.get('owned_group_cleanup',{})
        diagnostics_ok=(mode not in {'signal_error','timeout_signal_error','reap_timeout','external_reap'} or bool(cleanup.get('errors')))
        unknown_ok=mode=='spawn_error' or cleanup.get('all_engine_shutdown_receipts','absent') is None
        budget_ok=mode!='outer_budget' or receipt['effective_outer_timeout_seconds']==.05
        expected_waits=0 if mode=='spawn_error' else 1
        rows.append({'name':mode,'passed':signal_ok and waitid_ok and process.wait_count==expected_waits and diagnostics_ok and unknown_ok and budget_ok and (error['type'] if error else None)==expected_error,
          'start_new_session':spawn.call_args.kwargs.get('start_new_session') if spawn.call_args else None,'events':process.events,'observed_error':error,'expected_error':expected_error,'command_receipt':receipt})
report={'schema':'hepta.independent.pure-recovery-stop-review.v2','source':{'path':str(SOURCE.relative_to(ROOT)),'sha256':hashlib.sha256(source_bytes).hexdigest()},'source_unchanged':SOURCE.read_bytes()==source_bytes,'cases':rows,'count':len(rows),'passed':sum(row['passed'] for row in rows),'real_subprocesses':0,'real_signals':0,'model_completions':0,'native_executions':0,'earlier_failure_evidence':'/tmp/hepta-recovery-stop-review-01.json','scope':'Mocked owner identity/cleanup order and failure accounting, not real OS process-group isolation','limits':['Internal frozen HIA Clang capture opens its own session; outer group cleanup does not prove those descendants exited.','Unknown engine close receipts stay null; forced outer termination is not qualified complete coverage.','Fresh hosted VM teardown is the final containment boundary after an outer infrastructure failure.']}
path=pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_agent_assembly_recovery_20261030/independent-runtime-review01/final-source-controls/stop.json')
with path.open('x') as stream: json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
print(json.dumps({'path':str(path),'count':report['count'],'passed':report['passed'],'source_sha256':report['source']['sha256'],'source_unchanged':report['source_unchanged'],'failed':[row['name'] for row in rows if not row['passed']]}))
