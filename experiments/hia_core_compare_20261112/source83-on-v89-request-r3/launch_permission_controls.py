"""One synthetic permission-controller check; no project or native execution."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'control'))
from common import pin, require, save, runtime

def main():
    policy=json.loads((HERE/'PERMISSION-CONTROLS-REQUEST.json').read_bytes())
    runtime(policy['runtime'])
    for expected in policy['input_pins']:
        require(pin(expected['path'])==expected,'permission-control frozen input differs')
    folder=Path(policy['evidence_root'])
    require(not folder.exists(),'preserve existing permission-control output')
    folder.mkdir(mode=0o700)
    final={'schema':'hepta.source83-permission-controller-final.v1','status':'HOLD',
           'closed_owner_confirmed':False,'child_originals_read':False,
           'synthetic_only':True,'real_negative_commands_executed':False,
           'source83_executed':False,'generator_executed':False,'native_executed':False,
           'command':policy['command'],'request':pin(HERE/'PERMISSION-CONTROLS-REQUEST.json')}
    parent=[]
    closed=False
    try:
        owner_pin=policy['process_owner']
        require(pin(owner_pin['path'])==owner_pin,'original process owner changed')
        spec=importlib.util.spec_from_file_location('source83_permission_original_owner',owner_pin['path'])
        owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
        environment={name:os.environ[name] for name in ('PATH','LANG','LC_ALL','LC_CTYPE','TMPDIR','TZ') if name in os.environ}
        environment['PYTHONDONTWRITEBYTECODE']='1'
        environment['PYTHONPYCACHEPREFIX']=str(folder/'unused-pycache')
        returned=owner.run_owned(policy['command'],cwd=HERE,env=environment,
            stdout_path=folder/'child.stdout.log',stderr_path=folder/'child.stderr.log',
            receipt_path=folder/'lifecycle.json',qualification_seconds=20,cleanup_seconds=3)
        save(folder/'wrapper.json',returned);parent.append(pin(folder/'wrapper.json'))
        cleanup=returned.get('cleanup',{})
        require(type(returned.get('supervisor_returncode')) is int
                and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
                and cleanup.get('leader_reaped') is True and cleanup.get('deadline_exceeded') is False
                and cleanup.get('remaining_direct_children')==[] and cleanup.get('errors')==[],
                'permission-control owner closure is unknown')
        life_pin=pin(folder/'lifecycle.json');life_raw=(folder/'lifecycle.json').read_bytes()
        owner_request_pin=pin(folder/'lifecycle.json.request.json')
        request_raw=(folder/'lifecycle.json.request.json').read_bytes()
        require(sha256(life_raw).hexdigest()==life_pin['sha256']
                and pin(folder/'lifecycle.json')==life_pin
                and sha256(request_raw).hexdigest()==owner_request_pin['sha256']
                and pin(folder/'lifecycle.json.request.json')==owner_request_pin,
                'permission-control owner raw bytes changed')
        life=json.loads(life_raw);request=json.loads(request_raw)
        require(returned['receipt_sha256']==sha256(life_raw).hexdigest()
                and {k:v for k,v in returned.items() if k not in ('receipt_sha256','supervisor_returncode')}==life
                and life['request_sha256']==sha256(request_raw).hexdigest()
                and life['schema']==request['schema']=='hepta.hia.selfhost-process-owner.v1'
                and life['implementation_sha256']==request['implementation_sha256']==owner_pin['sha256']
                and request['command']==policy['command'] and request['cwd']==str(HERE)
                and request['env']==environment
                and request['stdout_path']==str(folder/'child.stdout.log')
                and request['stderr_path']==str(folder/'child.stderr.log')
                and request['receipt_path']==str(folder/'lifecycle.json')
                and life['qualification_seconds']==request['qualification_seconds']==20
                and life['cleanup_seconds']==request['cleanup_seconds']==3
                and type(request['started_ns']) is int and type(request['deadline_ns']) is int
                and request['deadline_ns']-request['started_ns']==20_000_000_000,
                'permission-control owner is not bound to this request')
        cleanup=life['cleanup']
        require(life['subreaper_enabled'] is True and cleanup['attempted'] is True
                and cleanup['complete'] is True and cleanup['observed_echild'] is True
                and cleanup['leader_reaped'] is True and cleanup['deadline_exceeded'] is False
                and cleanup['remaining_direct_children']==[] and cleanup['errors']==[],
                'permission-control bound ECHILD closure missing')
        closed=True
        final['owner']={'lifecycle':life_pin,'request':owner_request_pin,
                        'status':life['status'],'returncode':life['returncode']}
        require(returned['supervisor_returncode']==0 and life['returncode']==0
                and life['status']=='OWNED_PROCESS_COMPLETED' and life.get('timed_out') is False
                and life['qualification_started'] is True and life['exit_observed_before_deadline'] is True
                and life['event_overflow'] is False and life['interrupted_signals']==[]
                and life.get('owner_error') is None
                and [r['kind'] for r in life['events']]==[
                  'qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'],
                'permission-control source owner did not pass naturally')
        report=json.loads((folder/'evidence/report.json').read_bytes())
        require(report['status']=='SYNTHETIC_CONTROLLER_CONTROLS_PASS'
                and report['expected_ids']==report['loaded_ids']==report['executed_ids']==policy['expected_ids']
                and type(report['tests_run']) is int and report['tests_run']==4
                and all(report[k]==[] for k in ('loader_errors','errors','failures','skipped',
                  'expectedFailures','unexpectedSuccesses','real_subprocess_attempts','project_modules_loaded')),
                'full four synthetic permission controls did not pass')
        for expected in policy['input_pins']:
            require(pin(expected['path'])==expected,'permission-control input changed')
        final['status']='SYNTHETIC_PERMISSION_CONTROLS_PASS'
    except BaseException:
        final['status']='HOLD';final['error']=traceback.format_exc()
    finally:
        final['closed_owner_confirmed']=closed;final['child_originals_read']=closed
        if closed:
            final['actual_originals']=[pin(p) for p in sorted(folder.rglob('*')) if p.is_file()]
        else:
            final['actual_originals']=[]
            save(folder/'PARENT-OBSERVATIONS.json',{'files':parent,'child_originals_read':False})
        save(folder/'FINAL.json',final)
    print(json.dumps({k:final[k] for k in ('status','closed_owner_confirmed','source83_executed')}))
    return 0 if final['status']=='SYNTHETIC_PERMISSION_CONTROLS_PASS' else 1
if __name__=='__main__':raise SystemExit(main())

