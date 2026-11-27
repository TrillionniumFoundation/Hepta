from pathlib import Path
from hashlib import sha256
from datetime import datetime,timezone
import json,os,subprocess,sys,time,signal,traceback,shutil
R=Path('/home/qian-qi/hia-native-cold-edge-6f7d-20261127-2ac5');S=R/'source';H='6f7dfb2defd8852d2fe58e02ff8c5cf78c5e7807'
assert json.loads((R/'source-materialization-v2.json').read_text())['passed'] is True
assert not (R/'campaign.json').exists()
os.chdir(S);sys.path.insert(0,str(S))
from tools.hia_native_cold_chain import regular,read_json
from tools.hia_native_cold_preseed import ROOT_NAMES
from tools.hia_release_contract import validate_release_contract,source_domain
def pin(raw):return {'bytes':len(raw),'sha256':sha256(raw).hexdigest()}
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',GIT_OPTIONAL_LOCKS='0')
env.pop('PYTHONHOME',None);env.pop('PYTHONPATH',None)
q={'schema':'hepta.hia.native-cold-development-campaign.v1','source_head':H,'source':str(S),'started_utc':datetime.now(timezone.utc).isoformat(),'passed':False,'calls':[],'whole_native_delivery_qualified':False,'whole_stack_rewritten_in_hia':False,'qualification_wall_limit_seconds':180,'cleanup_wall_limit_seconds':3,'continue_post_install_rebuild':True}
def save():(R/'campaign.json').write_text(json.dumps(q,indent=2,sort_keys=True)+'\n')
def git(*args):return subprocess.check_output(['/usr/bin/git',*args],cwd=S,env=env,text=True,timeout=30).strip()
def invoke(label,script,args,timeout):
 command=[sys.executable,'-I','-B',str(S/'tools'/script),*map(str,args)]
 row={'label':label,'argv':command,'script':pin(regular(S/'tools'/script))};q['calls'].append(row);save()
 print('EXACT_NATIVE_STAGE_BEGIN',label,datetime.now(timezone.utc).isoformat(),flush=True)
 t=time.monotonic_ns()
 with (R/(label+'.stdout')).open('xb') as out,(R/(label+'.stderr')).open('xb') as err:
  p=subprocess.Popen(command,cwd=S,env=env,stdout=out,stderr=err,start_new_session=True)
  row['pid']=p.pid;save()
  try:p.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=10);row['external_observer_timeout']=True
 row.update(returncode=p.returncode,wall_elapsed_ns=time.monotonic_ns()-t,stdout=pin((R/(label+'.stdout')).read_bytes()),stderr=pin((R/(label+'.stderr')).read_bytes()));save()
 print('EXACT_NATIVE_STAGE_TERMINAL',label,p.returncode,row['wall_elapsed_ns'],flush=True)
 assert p.returncode==0,(label,(R/(label+'.stderr')).read_text()[-3000:])
try:
 assert git('rev-parse','HEAD')==H
 assert git('status','--porcelain','--untracked-files=no')==''
 preflight={'utc':datetime.now(timezone.utc).isoformat(),'loadavg':Path('/proc/loadavg').read_text(),'meminfo':Path('/proc/meminfo').read_text(),'disk':dict(zip(('total','used','free'),shutil.disk_usage(R))),'logical_cpus':os.cpu_count(),'processes':subprocess.check_output(['/usr/bin/ps','-eo','pid,ppid,pcpu,pmem,comm','--sort=-pcpu'],text=True).splitlines()[:25]}
 assert preflight['disk']['free']>12*1024**3
 (R/'campaign-preflight.json').write_text(json.dumps(preflight,indent=2)+'\n')
 contract=validate_release_contract(S);assert source_domain(contract)=='native'
 dist=S/'native/bootstrap/linux-x86_64';mr=regular(dist/'manifest.json');m=read_json(mr)
 assert m['schema']=='hepta.hia.native-bootstrap-distribution.v1' and m['target']=='linux-x86_64'
 assert set(m['executables'])=={*ROOT_NAMES,'hia-cold-build'}
 rows=[]
 for name in ROOT_NAMES:
  d=m['executables'][name];assert d['path']=='bin/'+name
  p=dist/d['path'];raw=regular(p);assert raw[:4]==b'\x7fELF' and pin(raw)=={k:d[k] for k in ('bytes','sha256')}
  rows.append(dict(name=name,path=str(p),**pin(raw)))
 receipt=R/'bootstrap-inputs.json';receipt.write_text(json.dumps({'schema':'hepta.hia.native-cold-bootstrap-inputs.v1','distribution_manifest':{'path':str(dist/'manifest.json'),**pin(mr)},'historical_source':m['source'],'historical_qualification_reused':False,'bootstrap':rows},indent=2,sort_keys=True)+'\n')
 preseed=R/'preseed';prep=R/'preparation';build=R/'build';export=R/'export';chain=R/'chain'
 invoke('preseed','hia_native_cold_preseed.py',['--source',S,'--output',preseed,'--root-receipt',receipt],300)
 invoke('prepare','hia_native_cold_prepare.py',['--source',S,'--base',H,'--preseed',preseed,'--output',prep],300)
 prepared=read_json(regular(prep/'report.json'));assert prepared['passed'] and prepared['changed_sources']==[]
 assert git('diff','--exit-code','HEAD','--')==''
 invoke('construct','hia_native_cold_construct.py',['--source',S,'--head',H,'--preparation',prep,'--preseed',preseed,'--output',build],600)
 invoke('export','hia_native_cold_export.py',['--source',S,'--build',build,'--preparation',prep,'--output',export],600)
 invoke('full-chain','hia_native_cold_chain.py',['--source',S,'--head',H,'--preparation',prep,'--build',build,'--export',export,'--output',chain],4500)
 result=read_json(regular(chain/'qualification.json'));assert result['passed'] is True and result['whole_cold_qualified'] is True
 assert git('rev-parse','HEAD')==H and git('diff','--exit-code','HEAD','--')==''
 q.update(passed=True,chain={'path':str(chain/'qualification.json'),**pin(regular(chain/'qualification.json'))},whole_native_delivery_qualified=result['whole_native_delivery_qualified'])
 save();print('EXACT_NATIVE_FULL_CHAIN_PASS',H,flush=True)
except BaseException:
 q['error']=traceback.format_exc();save();raise
