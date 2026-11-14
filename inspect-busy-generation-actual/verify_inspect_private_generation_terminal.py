import ast,hashlib,json,os,stat
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35');S=R/'v132-inspect-machine-entry-r1/successor-r2';G=S/'generation-stage-r1';E=S/'generation-attempt-r1';O=R/'v95-audit-mount-r1/v140-progress'
ns={};t=ast.parse((R/'v95-audit-mount-r1/v139-progress/verify_inspect_r3_terminal.py').read_text())
exec(compile(ast.Module(body=[n for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom)) or isinstance(n,ast.FunctionDef) and n.name=='pin'],type_ignores=[]),'<root-pin>','exec'),ns)
pin=ns['pin']
def load(p):return json.loads(p.read_bytes())
def bound(row):
 p=Path(row['path']);assert pin(p)[0]==row['pin'];return load(p)
def stats(p):
 q=p.lstat();return {'device':q.st_dev,'inode':q.st_ino,'bytes':q.st_size,'mode':stat.S_IMODE(q.st_mode),'nlink':q.st_nlink,'mtime_ns':q.st_mtime_ns,'ctime_ns':q.st_ctime_ns}
def tree(rows):
 root={}
 for name,row in rows.items():
  d=root;parts=name.split('/')
  for part in parts[:-1]:d=d.setdefault(part,{})
  d[parts[-1]]=(row['mode'],row['git_blob'])
 def finish(d):
  raw=b''
  for n,x in sorted(d.items(),key=lambda it:(it[0]+('/' if isinstance(it[1],dict) else '')).encode()):
   mode,digest=('40000',finish(x)) if isinstance(x,dict) else x
   raw+=mode.encode()+b' '+n.encode()+b'\0'+bytes.fromhex(digest)
  return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
 return finish(root)
p=load(G/'PLAN.json');res=load(E/'RESULT.json');install=load(E/'INSTALLATION.json');outer=load(S/'generation-outer-r1/OUTER.json')
assert pin(G/'PLAN.json')[0]['git_blob']=='04d6db7d206317a564c582d1e757737fee642b4d'
assert pin(G/'run_generation.py')[0]['git_blob']=='80b3c87b4ca7c1ff90ff902e4b56f9ca28ea6abd'
assert (E/'PLAN-USED.json').read_bytes()==(G/'PLAN.json').read_bytes()
assert outer['returncode']==0 and outer['only_generation_stage'] and outer['no_followup_started']
assert res['status']=='GENERATION_ONLY_PASS' and (res['generation_invocations'],res['check_invocations'],res['owner_launch_attempts'])==(2,1,3)
assert all(res[k]==0 for k in ['native_compilations','product_tests','vm_frames','source_copies','new_hardlinks'])
assert all(res[k] is False for k in ['matching_current_cold','cli_operation10_connected','default_activated','whole_cli_native'])
assert res['source_final_tree']==install['source_tree']=='741fa64dadb37f98ab9b195f1ee7b67fe683fc70'
assert res['plan_pin']==pin(G/'PLAN.json')[0]
for row in p['inputs'].values():assert pin(Path(row['path']))==(row['pin'],row['posix_mode'])
initial=load(Path(p['inputs']['source_capture']['path']));base=bound(res['final_base_capture']);final=bound(res['final_source_capture']);mapping=bound(install['complete_map'])
assert base==load(Path(p['inputs']['base_capture']['path'])) and final['files']==mapping and tree(mapping)==res['source_final_tree']
assert set(initial['files'])==set(mapping) and len(mapping)==3188 and len(base['files'])==3187
generated=set(p['generated_paths'])
for n in mapping:
 if n not in generated:assert mapping[n]==initial['files'][n] and final['stat'][n]==initial['stat'][n]
for q in E.glob('GUARD-*.json'):
 d=load(q);assert d['all_bytes_read'] and d['all_seven_stat_fields_checked'];assert bound(d['base'])==base
 assert bound(d['source'])==(final if d['label']=='install-after' else initial),q.name
inodes={}
for role,root,capture in [('base',Path(p['base']),base),('source',Path(p['source']),final)]:
 assert not capture['errors'];seen=set();inodes[role]=set()
 for folder,dirs,names in os.walk(root,followlinks=False):
  for n in dirs:assert stat.S_ISDIR((Path(folder)/n).lstat().st_mode)
  for n in names:seen.add((Path(folder)/n).relative_to(root).as_posix())
 assert seen==set(capture['files'])
 for n,expected in capture['files'].items():
  f=root/n;assert pin(f)[0]==expected and stats(f)==capture['stat'][n],role+'/'+n
  st=stats(f);inodes[role].add((st['device'],st['inode']))
  if role=='source':assert st['nlink']==1
assert len(inodes['source'])==3188 and not inodes['source']&inodes['base']
for row in install['generated']:
 n=row['path'];assert row['before']==initial['files'][n] and row['before_stat']==initial['stat'][n]
 assert row['after']==mapping[n] and row['after_stat']==final['stat'][n]
 assert (row['before_stat']['device'],row['before_stat']['inode'])!=(row['after_stat']['device'],row['after_stat']['inode'])
for n in p['generated_paths'][:2]:assert (Path(p['source'])/n).read_bytes()==(Path(p['base'])/n).read_bytes()
assert mapping[p['generated_paths'][2]]!=initial['files'][p['generated_paths'][2]]
actual_fields={}
for n in ast.parse((Path(p['source'])/p['generated_paths'][2]).read_bytes()).body:
 if isinstance(n,ast.Expr):assert isinstance(n.value,ast.Constant) and isinstance(n.value.value,str);continue
 assert isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)
 key=n.targets[0].id;assert key not in actual_fields;actual_fields[key]=ast.literal_eval(n.value)
assert set(actual_fields)=={'SOURCE_BYTES','SOURCE_SHA256','HOST_SOURCE_SHA256'} and len(actual_fields['HOST_SOURCE_SHA256'])==13
assert actual_fields['SOURCE_BYTES']==98544 and actual_fields['SOURCE_SHA256']==mapping[p['generated_paths'][0]]['sha256']
for name,digest in actual_fields['HOST_SOURCE_SHA256'].items():assert pin(Path(p['source'])/'hepta'/name)[0]['sha256']==digest
assert actual_fields['HOST_SOURCE_SHA256']['hia_inspect_program_native.py']=='8db7befea61305e52d08abe874ddc252d5cec0072b92e44e55be50a9c439f89d'
runtime=load(E/'RUNTIME.json');assert runtime==p['runtime']
stages=[]
for i,stage in enumerate(res['stages']):
 assert stage['label']==p['stage_order'][i] and stage['status']=='PASS' and stage['source_guard_pass']
 directory=Path(stage['directory']);request=load(directory/'REQUEST.json');command=load(directory/'COMMAND.json');child=load(directory/'CHILD-RESULT.json')
 assert stage['child_result_pin']==pin(directory/'CHILD-RESULT.json')[0] and child['request_pin']==pin(directory/'REQUEST.json')[0]
 assert child['status']=='PASS' and child['tests']==child['native_compilations']==child['vm_frames']==0
 assert child['generator_argv']==request['generator_argv']==command['generator_argv'] and child['runtime_context']==runtime
 argv=child['generator_argv'];assert ('--check' in argv)==(i==2)
 assert request['kind']==stage['label'] and request['plan_sha256']==pin(G/'PLAN.json')[0]['sha256']
 assert command['argv'][0:3]==[runtime['launch_executable'],'-I','-B'] and command['argv'][-1]==child['request_pin']['sha256']
 owner=load(directory/'OWNER.json');returned=load(directory/'OWNER-RETURNED.json');oreq=load(directory/'OWNER.json.request.json')
 assert returned==stage['owner_returned'] and returned['receipt_sha256']==hashlib.sha256((directory/'OWNER.json').read_bytes()).hexdigest()
 assert {k:v for k,v in returned.items() if k not in ['receipt_sha256','supervisor_returncode']}==owner and returned['supervisor_returncode']==0
 assert owner['request_sha256']==hashlib.sha256((directory/'OWNER.json.request.json').read_bytes()).hexdigest()
 assert oreq['command']==command['argv'] and oreq['env']==command['environment'] and oreq['cwd']==p['source']
 for obj in (owner,oreq,command):assert obj['qualification_seconds']==180 and obj['cleanup_seconds']==3
 assert owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==0 and not owner['timed_out']
 assert owner['exit_observed_before_deadline'] and not owner['event_overflow'] and not owner['interrupted_signals']
 clean=owner['cleanup'];assert clean['complete'] and clean['observed_echild'] and clean['leader_reaped'] and not clean['deadline_exceeded'] and not clean['errors'] and not clean['remaining_direct_children']
 assert clean['elapsed_ns']<=3000000000
 assert stage['generated_identity']['actual_generated_fields']==actual_fields
 output=stage['outputs'];assert not output['errors']
 for name,row in output['files'].items():
  f=Path(request['output_directory'])/name;assert pin(f)[0]==row['pin'] and stats(f)==row['stat']
  assert f.read_bytes()==(Path(p['source'])/next(n for n in generated if Path(n).name==name)).read_bytes()
 stages.append({'label':stage['label'],'owner':pin(directory/'OWNER.json')[0],'child':pin(directory/'CHILD-RESULT.json')[0],'returncode':0,'cleanup_elapsed_ns':clean['elapsed_ns'],'final_ECHILD':True,'historical_descendant_inventory_complete':owner['historical_descendant_inventory_complete']})
assert res['stages'][1]['outputs']==res['stages'][2]['outputs']
for n in generated:assert (E/'results/1'/Path(n).name).read_bytes()==(E/'results/2'/Path(n).name).read_bytes()
for role in ('executable','library'):
 v=runtime[role];f=Path(v['path']);i,mode=pin(f);s=stats(f);assert i['bytes']==v['bytes'] and i['sha256']==v['sha256'] and mode==v['mode']
 assert all(s[k]==v[k] for k in ['device','inode','mtime_ns','ctime_ns'])
report={'schema':'hepta.root-inspect-private-generation-terminal.v1','status':'PASS_INDEPENDENT_TERMINAL_AND_CURRENT_SOURCE_READBACK','result':pin(E/'RESULT.json')[0],'installation':pin(E/'INSTALLATION.json')[0],'outer':pin(S/'generation-outer-r1/OUTER.json')[0],'stages':stages,'actual_generation_invocations':2,'actual_check_invocations':1,'base_files':3187,'source_files':3188,'source_tree':res['source_final_tree'],'base_all_bytes_modes_seven_stats_unchanged':True,'nongenerated_3185_private_files_all_bytes_modes_seven_stats_unchanged':True,'all_current_private_inodes_unique_nlink1_disjoint_from_base':True,'three_per_path_new_file_replacements':True,'inode_numbers_may_be_reused_after_prior_private_unlink':True,'both_generated_sets_and_installed_full_bytes_equal':True,'check_preserved_second_outputs_full_bytes_and_stats':True,'HIA_and_ports_unchanged':True,'actual_identity_binds_13_host_sources_and_new_runtime':True,'runtime_full_files_stats_rechecked':True,'new_products_by_this_reader':0,'Source10_Source8_Native17_VM12_on_this_source_not_executed':True,'whole_native':False}
out=O/'ROOT-INSPECT-PRIVATE-GENERATION-TERMINAL.json'
with out.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'report':str(out),'identity':pin(out)[0]}))
