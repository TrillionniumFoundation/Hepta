import hashlib,json,os,pathlib,subprocess,time
base=pathlib.Path('/home/qian-qi/hia-slot15-cold-selection-20261127-2ac5');base.mkdir(mode=0o700)
src=base/'source';src.mkdir(mode=0o700);tmp=base/'tmp';tmp.mkdir(mode=0o700);e=base/'evidence';e.mkdir(mode=0o700)
python='/home/qian-qi/hia-native-caller-selection-20261127-2ac5/original-ci-python-prerequisites-v1/bin/python'
report=pathlib.Path('/home/qian-qi/hia-native-final-2b154-20261127-2ac5/qualified-cold-handoff-v1/qualified-cold.json');index=report.with_suffix('.generations.json')
inputs={}
for name,path,expected_size,expected_hash in [('cold_report',report,184450,'becd051e3a5771d0059d6f5b1880c56e4234d5167b19969fb2ed98fb343e2b95'),('generation_index',index,1275,'2e80577e47a4a070664318891f37ad63794c7e41163b21fd51517310f7c1b297')]:
 raw=path.read_bytes();assert len(raw)==expected_size and hashlib.sha256(raw).hexdigest()==expected_hash
 inputs[name]={'path':str(path),'bytes':len(raw),'sha256':expected_hash};(e/(name+'.original.json')).write_bytes(raw)
rows=json.loads(index.read_bytes())['generations'];assert len(rows)==3
inputs['generations']=[]
for row in rows:
 p=pathlib.Path(row['produced_image']);raw=p.read_bytes();digest=hashlib.sha256(raw).hexdigest()
 assert len(raw)==641344 and digest=='acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9'
 inputs['generations'].append({'path':str(p),'bytes':len(raw),'sha256':digest})
(e/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
borrow=pathlib.Path('/home/qian-qi/hia-component-wheel-custody-20261127-2ac5/source/.git');g=['/usr/bin/git','-C',str(src)]
subprocess.run(g+['init','-q'],check=True)
objects=[];seen=set()
def collect(path):
 path=path.resolve()
 if path in seen:return
 assert path.is_dir();seen.add(path);objects.append(str(path))
 f=path/'info/alternates'
 if f.is_file():
  for value in f.read_text().splitlines():
   p=pathlib.Path(value);collect(p if p.is_absolute() else path/p)
collect(borrow/'objects')
(src/'.git/objects/info/alternates').write_text('\n'.join(objects)+'\n')
(src/'.git/shallow').write_text((borrow/'shallow').read_text())
branch='codex/hia-slot15-native-cold-selection-20261127-2ac5';old='f765709ba3dc5e95878ec25ffd5e8d9c4b3675d1';new='991052b888d06a10f2748fddb1e69bd9455861d5'
subprocess.run(g+['update-ref','refs/heads/'+branch,old],check=True)
subprocess.run(g+['symbolic-ref','HEAD','refs/heads/'+branch],check=True)
with (e/'checkout.stdout').open('wb') as so,(e/'checkout.stderr').open('wb') as se:
 subprocess.run(g+['checkout','-f',branch],stdout=so,stderr=se,check=True)
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
original_cmd=[python,'-B','-m','tools.qualify_hia_slot_operations_callers','--cold-report',str(report),'--evidence',str(base/'original-slot15-caller-v1')]
before,original_out=run('original-rejection-v1',original_cmd,1800)
assert type(before.get('returncode')) is int and before['returncode']!=0
assert "KeyError: 'nested_report'" in (original_out/'stderr').read_text(),(original_out/'stderr').read_text()
bundle=pathlib.Path('/home/qian-qi/hia-component-wheel-custody-20261127-2ac5/slot15-native-cold-selection-v1.bundle');raw=bundle.read_bytes()
assert len(raw)==9517 and hashlib.sha256(raw).hexdigest()=='15e01e3c5cf0383cb6c1883416c1a5a4e939f5466e360cc5d92c36474b514925'
with (e/'successor-checkout.stdout').open('wb') as so,(e/'successor-checkout.stderr').open('wb') as se:
 subprocess.run(g+['fetch','--no-tags',str(bundle),'HEAD'],stdout=so,stderr=se,check=True)
 subprocess.run(g+['merge','--ff-only',new],stdout=so,stderr=se,check=True)
controls,_=run('source-history-controls-v1',[python,'-B','-m','unittest','-v','tests.test_hia_slot_cold_selection_history'],120);assert controls['passed'] is True
command=[python,'-B','-m','tools.qualify_hia_slot_operations_callers','--cold-report',str(report),'--evidence',str(base/'slot15-caller-v1')]
after,out=run('matching-slot15-v1',command,1800)
summary={'source_head':new,'original_rejection':before,'source_controls':controls,'actual_slot15':after,'native_source_changed':False,'whole_native_delivery_qualified':False}
gate=base/'slot15-caller-v1/report.json'
if gate.exists():summary['caller_report']=json.loads(gate.read_bytes())
summary['cold_inputs_stable']=all(hashlib.sha256(pathlib.Path(v['path']).read_bytes()).hexdigest()==v['sha256'] for v in [inputs['cold_report'],inputs['generation_index'],*inputs['generations']])
summary['passed']=after['passed'] is True and summary['cold_inputs_stable'] is True and summary.get('caller_report',{}).get('status')=='PASS'
(e/'qualification.json').write_text(json.dumps(summary,indent=2)+'\n');print('FINAL',json.dumps({k:summary[k] for k in ('source_head','passed','cold_inputs_stable')}),flush=True)
raise SystemExit(0 if summary['passed'] else 1)
