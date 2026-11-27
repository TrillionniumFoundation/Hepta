import hashlib,json,os,pathlib,subprocess,time
base=pathlib.Path('/home/qian-qi/hia-slot15-cold-selection-20261127-2ac5');src=base/'source';tmp=base/'tmp';e=base/'evidence';g=['/usr/bin/git','-C',str(src)]
assert subprocess.check_output(g+['rev-parse','HEAD'],text=True).strip()=='991052b888d06a10f2748fddb1e69bd9455861d5'
assert subprocess.check_output(g+['status','--porcelain'],text=True)==''
python='/home/qian-qi/hia-native-caller-selection-20261127-2ac5/original-ci-python-prerequisites-v1/bin/python'
inputs=json.loads((e/'inputs.json').read_bytes())
assert all(hashlib.sha256(pathlib.Path(v['path']).read_bytes()).hexdigest()==v['sha256'] for v in [inputs['cold_report'],inputs['generation_index'],*inputs['generations']])
report=pathlib.Path(inputs['cold_report']['path'])
bundle=base/'slot15-selection-and-context-v3.bundle';raw=bundle.read_bytes()
assert len(raw)==7857 and hashlib.sha256(raw).hexdigest()=='5b63ce595098e8ad0da3f9a9430223689e5c159d4fe1b5a5a0f8c4fcbf7a0336'
new='95fbdddbcd9b5feadb4f3a906896aa4908111ec6'
with (e/'context-successor-checkout.stdout').open('wb') as so,(e/'context-successor-checkout.stderr').open('wb') as se:
 subprocess.run(g+['fetch','--no-tags',str(bundle),'HEAD'],stdout=so,stderr=se,check=True)
 subprocess.run(g+['merge','--ff-only',new],stdout=so,stderr=se,check=True)
env=dict(os.environ);env['TMPDIR']=str(tmp);env['PYTHONDONTWRITEBYTECODE']='1'
def run(label,command,timeout):
 out=e/label;out.mkdir(mode=0o700)
 head=subprocess.check_output(g+['rev-parse','HEAD'],text=True).strip()
 assert subprocess.check_output(g+['status','--porcelain'],text=True)==''
 (out/'intent.json').write_text(json.dumps({'source_head':head,'command':command,'timeout_seconds':timeout,'TMPDIR':str(tmp),'cold_inputs':inputs},indent=2)+'\n')
 beg=time.monotonic();result={}
 try:
  with (out/'stdout').open('wb') as so,(out/'stderr').open('wb') as se:result['returncode']=subprocess.run(command,cwd=src,env=env,stdout=so,stderr=se,timeout=timeout).returncode
 except subprocess.TimeoutExpired:result['terminal']='timeout'
 result['elapsed_seconds']=time.monotonic()-beg;result['source_head_after']=subprocess.check_output(g+['rev-parse','HEAD'],text=True).strip();result['worktree_status_after']=subprocess.check_output(g+['status','--porcelain'],text=True)
 for filename in ('stdout','stderr'):
  raw=(out/filename).read_bytes();result[filename]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 result['passed']=type(result.get('returncode')) is int and result['returncode']==0 and result['source_head_after']==head and result['worktree_status_after']==''
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(label,json.dumps(result),flush=True)
 print((out/'stdout').read_text(errors='replace')[-3000:],flush=True);print((out/'stderr').read_text(errors='replace')[-5000:],flush=True)
 return result,out
controls,_=run('source-history-controls-v2',[python,'-B','-m','unittest','-v','tests.test_hia_slot_cold_selection_history'],120);assert controls['passed'] is True
command=[python,'-B','-m','tools.qualify_hia_slot_operations_callers','--cold-report',str(report),'--evidence',str(base/'slot15-caller-v2')]
after,out=run('matching-slot15-v2',command,1800)
summary={'source_head':new,'source_controls':controls,'actual_slot15':after,'native_source_changed':False,'whole_native_delivery_qualified':False}
gate=base/'slot15-caller-v2/report.json'
if gate.exists():summary['caller_report']=json.loads(gate.read_bytes())
summary['cold_inputs_stable']=all(hashlib.sha256(pathlib.Path(v['path']).read_bytes()).hexdigest()==v['sha256'] for v in [inputs['cold_report'],inputs['generation_index'],*inputs['generations']])
summary['passed']=after['passed'] is True and summary['cold_inputs_stable'] is True and summary.get('caller_report',{}).get('status')=='PASS'
(e/'qualification-v2.json').write_text(json.dumps(summary,indent=2)+'\n');print('FINAL',json.dumps({k:summary[k] for k in ('source_head','passed','cold_inputs_stable')}),flush=True)
raise SystemExit(0 if summary['passed'] else 1)
