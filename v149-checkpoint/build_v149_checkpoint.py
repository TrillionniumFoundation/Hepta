from pathlib import Path
import copy,hashlib,json
ROOT=Path('/tmp/hia-progress-v149-20261114-dda7')
OLD=Path('/tmp/hia-progress-v148-20261114-dda7')
oldraw=(OLD/'STATE.json').read_bytes();prior=json.loads(oldraw)
update=json.loads((ROOT/'V149-UPDATE.json').read_bytes())
state=copy.deepcopy(prior)
state['retained_prior_top_at_v149']={k:copy.deepcopy(prior[k]) for k in ('schema','frozen_at_utc','prior_commit','snapshot_label','next')}
state.update(schema='hepta.hia-native-progress.v149',snapshot_label='v149',frozen_at_utc=update['frozen_at_utc'],prior_commit=update['prior_commit'],whole_native=False,production_legacy_retired=False,current_environment_qualification=False)
state['current_v149']=update;state['next']=update['next']
for k in set(prior)-{'schema','frozen_at_utc','prior_commit','snapshot_label','next'}:assert state[k]==prior[k],k
raw=(json.dumps(state,sort_keys=False,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
with (ROOT/'STATE.json').open('xb') as f:f.write(raw)
oldreadme=(OLD/'README.md').read_bytes()
prefix=(ROOT/'README-v149-PREFIX.md').read_bytes()
readme=prefix+oldreadme
assert readme.endswith(oldreadme)
with (ROOT/'README.md').open('xb') as f:f.write(readme)
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
print(json.dumps({'STATE':pin(raw),'README':pin(readme),'prior_state_fields_preserved':True,'prior_README_exact_suffix_preserved':True,'whole_native':False},sort_keys=True))
