"""Read-only Root full review of actual independent CLI R4 binding."""
import ast,hashlib,json,os,stat,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');B=Path('/tmp/hia-inspect-cli-controls-r4-dda7');R=Path('/dev/shm/hia-inspect-cli-controls-r4-dda7');O=Path('/tmp/hia-root-inspect-cli-r4-preparation-dda7')
started=time.monotonic_ns();seen={}
helper=(D/'verify_op10_r3_sharded_preflight.py').read_bytes()
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'[reviewed read-only Root primitives]','exec'),globals())
def data(path):return json.loads(read(path))
braw=read(R/'BINDING-RESULT.json',0o600);b=json.loads(braw)
praw=fixed(b['plan']);p=json.loads(praw);request=data(B/'PREPARATION-PLAN.json')
assert praw==fixed(request['proposed_plan']) and pin(praw)['git_blob']=='c5f94b6680777297d98b69f24f0eb3c7111341bc'
assert b['status']=='BOUND_NOT_EXECUTED' and b['product_execution'] is False and b['copied_paths']==b['source_files']==3191
assert b['predecessor_rows']==61683 and b['historical_failure_rows']==133 and b['original_61550_rows_exact_prefix']
assert b['source_tree']==p['source_tree']=='fa3d74c64f7dfc6bb13a712dfd9e466676ec5665' and b['source']==p['source']==str(R/'source')
assert data(R/'PREPARATION-REQUEST.json')==request
old=json.loads(fixed(b['original_failed_plan']))
before=data(R/'BASE-SOURCE-BEFORE.json');after=data(R/'BASE-SOURCE-AFTER.json')
assert before==after and before['root']==old['source']
capture=json.loads(fixed(b['source_capture']));m=json.loads(fixed(b['source_manifest']));modes=json.loads(fixed(b['source_modes']))
assert b['source_manifest']==p['source_manifest'] and b['source_modes']==p['source_modes']
assert len(m)==len(modes)==3191 and tree(m)==p['source_tree']
assert capture['root']==str(R/'source') and capture['source_files']==3191 and capture['tree']==p['source_tree']
def check_capture(c):
 root=Path(c['root']);names=set();directories={};inodes=set();total=0
 for folder,dirs,files in os.walk(root,followlinks=False):
  relative=Path(folder).relative_to(root).as_posix();relative='' if relative=='.' else relative
  directories[relative]=seven(Path(folder).lstat())
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:names.add((Path(folder)/name).relative_to(root).as_posix())
 assert names==set(c['files']) and directories==c['directories']
 for name,row in c['files'].items():
  path=root/name;raw=read(path,row['posix_mode']);s=path.lstat()
  q=pin(raw);q['mode']='100755' if s.st_mode&0o111 else '100644'
  assert q==row['pin'] and seven(s)==row['seven_stats'] and s.st_nlink==1 and (s.st_dev,s.st_ino) not in inodes
  inodes.add((s.st_dev,s.st_ino));total+=len(raw)
 return inodes,total
oi,ob=check_capture(before);ni,nb=check_capture(capture)
assert ni.isdisjoint(oi) and len(ni)==len(oi)==3191
assert {name:row['pin'] for name,row in capture['files'].items()}==m
assert {name:row['posix_mode'] for name,row in capture['files'].items()}==modes
assert {name:row['pin'] for name,row in before['files'].items()}==json.loads(fixed(old['source_manifest']))
copies=[json.loads(line) for line in read(R/'COPY.jsonl',0o600).splitlines()]
assert len(copies)==3191 and [x['path'] for x in copies]==list(before['files'])
for row in copies:
 name=row['path'];assert row['before']==before['files'][name] and row['after']==capture['files'][name] and row['records_context_substitution']==(name=='hepta/hia_inspect_cli_records.py')
 assert row['before']['posix_mode']==row['after']['posix_mode']
 if not row['records_context_substitution']:assert row['before']['pin']==row['after']['pin']
assert nb-ob==12
assert fixed(request['records_after'])==read(R/'source/hepta/hia_inspect_cli_records.py')
for row in p['controls'].values():fixed(row)
for row in p['retained_authorities'].values():fixed(row)
fixed(p['compiler']);fixed(p['predecessor_inspect_image'])
for row in request['author_files'].values():fixed(row)
fixed(request['failure_terminal']);inv=json.loads(fixed(request['failure_inventory']))
for row in inv.values():
 fixed(row);assert seven(Path(row['path']).lstat())==row['seven_stats']
for key in ('executable','library'):
 row=p['runtime'][key];path=Path(row['path']).resolve();raw=read(path,row['mode']);s=path.stat()
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 assert [s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns]==[row['device'],row['inode'],row['mtime_ns'],row['ctime_ns']]
outer=data(O/'OUTER.json');assert outer['status']=='EXITED' and outer['returncode']==0 and outer['preparation_attempts']==1 and outer['product_executions']==0 and not outer['automatic_retry']
assert outer['authorization']['git_blob']=='e21aff5130cbafbb9a2d8ffb43ac04a965f15a70'
assert read(O/'stdout.raw')==read(O/'stderr.raw')==b''
assert b['argv']==[p['runtime']['launch_executable'],'-I','-B',str(B/'run_inspect_cli_controls.py'),'--execute',str(R/'EXECUTION-PLAN.json'),'--plan-sha256',pin(praw)['sha256']]
assert not os.path.lexists(p['attempt'])
evidence={}
for root,label in ((R,'binding'),(O,'root-outer')):
 for folder,dirs,files in os.walk(root,followlinks=False):
  if Path(folder)==R:dirs[:]=[x for x in dirs if x!='source']
  for name in files:
   path=Path(folder)/name;raw=read(path)
   evidence[label+'/'+path.relative_to(root).as_posix()]={'path':str(path),'pin':pin(raw),'posix_mode':stat.S_IMODE(path.lstat().st_mode),'seven_stats':seven(path.lstat())}
for path,previous in seen.items():assert seven(Path(path).lstat())==previous,path
iraw=enc(evidence)
with (D/'inspect-cli-r4-binding-root-inventory.json').open('xb') as f:f.write(iraw)
proof={'schema':'hepta.root.inspect-cli-r4-binding-terminal.v1','status':'PASS_ACTUAL_BOUND_NOT_PRODUCT_EXECUTED','session':74619,'outer_exit':0,'outer_elapsed_ns':outer['elapsed_ns'],'binding_result':pin(braw),'actual_plan':pin(praw),'actual_source_files':3191,'actual_source_bytes':nb,'actual_source_tree':tree(m),'actual_source_capture':b['source_capture'],'actual_copy_journal_rows':3191,'all_before_after_journal_bytes_modes_seven_stats_verified':True,'all_old_and_new_full_current_bytes_modes_pathsets_directories_and_seven_stats':True,'all_new_inodes_distinct_single_link_and_disjoint_from_old':True,'records_only_12byte_change':True,'original_failure_131raw_fullbytes_modes_seven_stats_retained':True,'controls':16,'actual_raw_files':len(evidence),'actual_raw_bytes':sum(row['pin']['bytes'] for row in evidence.values()),'inventory':pin(iraw),'all_unique_final_stat_checks':len(seen),'products_executed':0,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-started}
raw=enc(proof);out=D/'inspect-cli-r4-binding-root-terminal.json'
with out.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(out),'pin':pin(raw),'elapsed_seconds':proof['elapsed_ns']/1e9},sort_keys=True))
