from pathlib import Path
from hashlib import sha256
import json, os, sys, time
root=Path(__file__).resolve().parent
source=root/'source'; sys.path.insert(0,str(source))
from tools.hia_selfhost_process_owner import run_owned
folder=root/'source-controls-review-r2'; folder.mkdir(mode=0o700)
inner=folder/'inner'
command=[sys.executable,'-B',str(root/'run-review-source-controls-r2.py')]
started=time.monotonic()
life=run_owned(command,cwd=source,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},stdout_path=folder/'child.stdout',stderr_path=folder/'child.stderr',receipt_path=folder/'lifecycle.json',qualification_seconds=180)
clean=life.get('cleanup',{})
okay=(life.get('status')=='OWNED_PROCESS_COMPLETED' and life.get('returncode')==0 and life.get('exit_observed_before_deadline') is True and life.get('timed_out') is False and not life.get('interrupted_signals') and not life.get('event_overflow') and not life.get('owner_error') and clean.get('complete') is True and clean.get('observed_echild') is True and clean.get('leader_reaped') is True and not clean.get('errors') and not clean.get('remaining_direct_children') and all(e.get('kind')!='owned_child_sigkill' for e in life.get('events',[])))
report=json.loads((inner/'report.json').read_bytes()) if (inner/'report.json').exists() else None
record={'schema':'hia.store-page-owned-source-controls.v1','command':command,'scope':'SOURCE_ONLY_NOT_COLD_OR_NATIVE_OR_FULL','qualification_seconds':180,'status':'PASS' if okay and report and report['status']=='PASS' else 'HOLD','lifecycle_pass':okay,'lifecycle':life,'inner_status':report['status'] if report else None,'inner_report_sha256':sha256((inner/'report.json').read_bytes()).hexdigest() if report else None,'python':sys.version,'executable':sys.executable,'wall_seconds':time.monotonic()-started}
(folder/'control.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':record['status'],'inner':record['inner_status'],'lifecycle':okay,'seconds':record['wall_seconds']},indent=2),flush=True)
raise SystemExit(0 if record['status']=='PASS' else 1)
