import ast,hashlib,json,os,stat,sys,time
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35')
A=Path('/tmp/hia-inspect-source18-evidence-r2-dda7')
O=Path('/tmp/hia-root-v141-dda7/ROOT-NATIVE-PROPOSAL.json')
helper=R/'v95-audit-mount-r1/v140-progress/verify_source18_proposal.py'
raw=helper.read_bytes()
assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()=='c932413d529442b855043d13afb3e4d6aefa0973'
t=ast.parse(raw);ns={}
exec(compile(ast.Module(body=[n for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'<root-read-only-helpers>','exec'),ns)
read,obj,tree=ns['read'],ns['obj'],ns['tree']
assert sys.version_info[:3]==(3,14,4)
old=obj(A/'SOURCE-PLAN.json');p=obj(A/'NATIVE-PLAN.json');launch=obj(A/'NATIVE-LAUNCH.json');priorlaunch=obj(A/'SOURCE-LAUNCH.json')
assert read(A/'SOURCE-PLAN.json')[1]['git_blob']=='87a5b6de865ddaec23807db2b9614a66cff457e1'
assert read(A/'NATIVE-PLAN.json')[1]['git_blob']=='46a1c86949e63a242a4ead2bc14a73739e509b6b'
assert read(A/'NATIVE-LAUNCH.json')[1]['git_blob']=='22320f77741c35a3f47b485794d54d8409ffc0f7'
assert read(A/'run_inspect_stages.py')[1]==p['runner']==old['runner'] and p['runner']['git_blob']=='dbd07c1c815641a0a55c4c2fcefef5d41034e369'
delta={'active_phase','attempt','authorized_proposal_counts','contract','expected_new_evidence_bytes_upper_estimate','generation_evidence','qualification','source_predecessor'}
assert set(p)==set(old) and {k for k in p if p[k]!=old[k]}==delta
inverse=dict(p)
for k in delta:inverse[k]=old[k]
assert inverse==old
assert p['active_phase']=='native-vm' and p['expected_new_evidence_bytes_upper_estimate'] is None
assert p['authorized_proposal_counts']==dict(CLI43=0,Native=17,VM=12,compile=1,original3=0,owners=10,source10=0,source8=0,source_subtests=0)
assert p['qualification']==dict(CLI_op10_connected=False,current_Native=0,current_VM=0,current_compile=0,current_product_execution=0,current_source_tests=18,matching_current_cold=False,whole_native=False)
assert p['limits']==dict(cleanup_seconds=3,minimum_free_bytes=1073741824,qualification_seconds=180)
assert not p['automatic_retry'] and p['first_failed_group_or_guard_or_incomplete_cleanup_stops']
assert len(old['generation_evidence'])==60 and p['generation_evidence'][:60]==old['generation_evidence']
extra=p['generation_evidence'][60:]
assert len(extra)==52 and len({x['path'] for x in p['generation_evidence']})==112
source_attempt=Path(p['source_predecessor']['path']).parent
source_outer=source_attempt.parent/'source-controls-outer-r1'
expected={str(x) for root in (source_attempt,source_outer) for x in root.rglob('*') if x.is_file()}
assert expected=={x['path'] for x in extra} and len(expected)==52
descriptors=[]
def fixed(row):
 raw,got,st=read(row['path']);assert got==row['pin'] and st['mode']==row['posix_mode'],row['path']
 descriptors.append(row['path']);return raw
for row in p['generation_evidence']:fixed(row)
for row in p['inputs'].values():fixed(row)
for row in (p['generation_runner'],p['old_source10_runner'],p['contract'],p['source_predecessor']):fixed(row)
assert fixed(p['contract']).endswith((A/'CONTRACT.md').read_bytes())
r=json.loads(fixed(p['source_predecessor']))
assert p['source_predecessor']['pin']['git_blob']=='cecd5958bda4f9138af4714c955c0b3b02891f99' and p['source_predecessor']['posix_mode']==0o600
assert r['status']=='SOURCE_CONTROLS_PASS' and r['owner_launch_attempts']==2 and r['complete_source_guard_pass']
proof=O.parent/'ROOT-SOURCE18-TERMINAL.json'
assert read(proof)[1]['git_blob']=='19e7b5395189d352d58fc4c15b754e22d74abe9e'
assert obj(proof)['result']==p['source_predecessor']['pin']
assert obj(source_outer/'OUTER.json')['returncode']==0
spec=obj(p['inputs']['kit_spec']['path'])
assert p['native_group_order']==spec['native_group_order'] and p['vm_group_order']==spec['vm_group_order']
assert len(p['native_group_order'])==7 and len(p['vm_group_order'])==2
for label in p['native_group_order']+p['vm_group_order']:assert p['groups'][label]['ids']==spec['groups'][label]
assert sum(len(p['groups'][x]['ids']) for x in p['native_group_order'])==17
assert sum(len(p['groups'][x]['ids']) for x in p['vm_group_order'])==12
assert p['product_limits']==spec['limits'] and p['compiler']==spec['compiler']
assert p['product_limits']==dict(cleanup_seconds=3,compile_wall_seconds=20,compiler_author_blocks=1536,compiler_author_functions=128,compiler_author_operations=8192,image_capacity=1048576,qualification_seconds=180,source_capacity=1048576,vm_call_depth=128,vm_heap_bytes=8388608,vm_steps_per_frame=10000000,workspace_capacity=1048576)
c=p['compiler'];cr,cp,cs=read(c['path'])
assert (cp['bytes'],cp['git_blob'],cp['sha256'],cs['mode'])==(c['bytes'],c['git_blob'],c['sha256'],c['mode'])
inodes={}
for role,key in [('base','base_final'),('source','source_final')]:
 root=Path(p[role]['path']);capture=obj(p['inputs'][key]['path']);assert not capture['errors']
 assert tree(capture['files'])==p[role]['tree'] and len(capture['files'])==p[role]['files']
 seen=set();inodes[role]=set()
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:assert stat.S_ISDIR((Path(folder)/name).lstat().st_mode)
  for name in files:seen.add((Path(folder)/name).relative_to(root).as_posix())
 assert seen==set(capture['files'])
 for name,expected_pin in capture['files'].items():
  raw,got,st=read(root/name);assert got==expected_pin and st==capture['stat'][name],role+'/'+name
  inodes[role].add((st['device'],st['inode']))
  if role=='source':assert st['nlink']==1
assert len(inodes['source'])==3188 and not inodes['source']&inodes['base']
for key in ('executable','library'):
 x=p['runtime'][key];raw,got,st=read(x['path']);assert got['bytes']==x['bytes'] and got['sha256']==x['sha256']
 for f in ('device','inode','mode','mtime_ns','ctime_ns'):assert st[f]==x[f]
assert launch['plan']['pin']==read(A/'NATIVE-PLAN.json')[1] and launch['runner']['pin']==p['runner']
assert launch['actual_Source18_result']==p['source_predecessor']
assert launch['evidence_authority']==p['evidence_authority']
assert launch['cwd']==priorlaunch['cwd']
argv=launch['argv'];i=argv.index(p['runtime']['launch_executable'])
assert argv[:i]==['/usr/bin/env','-i','PATH=/usr/local/bin:/usr/bin:/bin','HOME='+p['attempt'],'LANG=C.UTF-8','LC_ALL=C.UTF-8','PYTHONDONTWRITEBYTECODE=1','TMPDIR=/dev/shm/hia-inspect-stages-dda7/startup-tmp','LD_LIBRARY_PATH='+p['runtime']['library_directory']]
assert argv[i:]==[p['runtime']['launch_executable'],'-I','-B',str(A/'run_inspect_stages.py'),'--execute-stage','native-vm','--plan',str(A/'NATIVE-PLAN.json'),'--plan-sha256',launch['plan']['pin']['sha256'],'--attempt',p['attempt']]
ea=p['evidence_authority'];ep=Path(ea['path']);assert ep.resolve(strict=True)==ep
fd=os.open(ep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 st=os.fstat(fd);named=ep.lstat();assert st==named and stat.S_ISDIR(st.st_mode)
 assert ea==dict(schema='hepta.hia.inspect-fixed-evidence-filesystem.v1',path=str(ep),device=st.st_dev,inode=st.st_ino,mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid)
 v=os.fstatvfs(fd);free=v.f_bavail*v.f_frsize;assert not(v.f_flag&os.ST_NOEXEC) and free>=1073741824
finally:os.close(fd)
assert Path(p['attempt']).parent==ep and not Path(p['attempt']).exists()
assert Path(launch['outer_directory'])==ep/'native-vm-outer-r1' and not Path(launch['outer_directory']).exists()
report=dict(schema='hepta.root-native17-vm12-proposal-readback.v1',status='PASS_STATIC_CURRENT_SOURCE_AND_ACTUAL_SOURCE18',observed_ns=time.time_ns(),plan=read(A/'NATIVE-PLAN.json')[1],launch=read(A/'NATIVE-LAUNCH.json')[1],runner=p['runner'],complete_plan_inverse=True,changed_fields=sorted(delta),original_generation_prefix=60,actual_Source18_appended_complete_files=52,descriptors_full_bytes_modes_checked=len(descriptors),actual_Source18_result=p['source_predecessor'],root_Source18_proof=read(proof)[1],base_files=3187,source_files=3188,source_tree=p['source']['tree'],all_current_bytes_modes_seven_stats_exact=True,private_inodes_unique_nlink1_disjoint=True,original_compiler_and_runtime_full_bytes_stats=True,original_native_ids=17,original_vm_ids=12,original_owners=10,product_limits=p['product_limits'],evidence_authority=ea,available_output_bytes=free,attempt_outer_absent=True,compile_Native_VM_by_this_reader=0,whole_native=False,matching_current_cold=False)
with O.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(dict(status=report['status'],report=str(O),pin=read(O)[1],free=free)))
