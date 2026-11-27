from pathlib import Path
import json,os,sys
TOOLS=Path(__file__).resolve().parent
sys.path.insert(0,str(TOOLS))
from bounded_support import ROOT, SOURCE
sys.path.insert(0,str(SOURCE))
from tools.hia_selfhost_process_owner import run_owned
name,script=sys.argv[1:3];out=ROOT/'evidence'/name;out.mkdir(exist_ok=False)
env=dict(os.environ)
for key in list(env):
    if key.startswith('HEPTA_') or key in ('PYTHONPATH','PYTHONHOME'):env.pop(key)
env['PYTHONDONTWRITEBYTECODE']='1'
result=run_owned([sys.executable,'-B',str(TOOLS/script),*sys.argv[3:]],cwd=str(ROOT),env=env,stdout_path=out/'stdout.log',stderr_path=out/'stderr.log',receipt_path=out/'owner.json',qualification_seconds=180,cleanup_seconds=3)
(out/'RETURNED.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({key:result.get(key) for key in ('status','returncode','cleanup','qualification_seconds','cleanup_seconds')}))
raise SystemExit(0 if result.get('status')=='OWNED_PROCESS_COMPLETED' and type(result.get('returncode')) is int and result['returncode']==0 and result.get('cleanup',{}).get('complete') is True else 1)
