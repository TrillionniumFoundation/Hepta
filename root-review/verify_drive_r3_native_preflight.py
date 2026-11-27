"""Root complete-input Native17/VM12 preflight; no product import or bootstrap."""
import ast,hashlib,json,os,stat,sys,time
from pathlib import Path
helper=Path('/tmp/hia-root-v141-dda7/verify_drive_r3_generation_plan.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(helper)).encode()+b'\0'+helper).hexdigest()=='db1de0e35a29c6fc84ea0e59938d7f8170429959'
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'[Root pure read-only helper definitions]','exec'),globals())
D=Path('/tmp/hia-inspect-drive-source18-r3-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/ROOT-DRIVE-R3-NATIVE-PREFLIGHT.json')
started=time.monotonic_ns()
assert sys.version_info[:3]==(3,14,4)
oldraw=(D/'SOURCE-PLAN.json').read_bytes()
assert pin(oldraw)['git_blob']=='ec2ce52faca4281d43151be0242186450e4acfd9'
old=json.loads(oldraw)
raw=(D/'NATIVE-PLAN.json').read_bytes()
check(raw,{'bytes':74027,'git_blob':'9cb9a6a75238a000a3a723841b478db4424b441d','sha256':'74eae79fa8d26b5f6d9e0959adab97303568f415a9071cd44cbbf0c7eef62772'})
p=json.loads(raw)
delta={'active_phase','attempt','authorized_proposal_counts','contract','expected_new_evidence_bytes_upper_estimate','generation_evidence','qualification','source_predecessor'}
assert set(p)==set(old) and {k for k in p if p[k]!=old[k]}==delta
inverse=dict(p)
for k in delta:inverse[k]=old[k]
assert inverse==old
runner,_=read_checked(D/'run_inspect_stages.py',p['runner'],0o644)
assert p['runner']==old['runner'] and pin(runner)['git_blob']=='cd9cecf3321a0b7a1e1a8717e08962deeca487e6'
assert p['active_phase']=='native-vm' and p['expected_new_evidence_bytes_upper_estimate'] is None
assert p['authorized_proposal_counts']==dict(CLI43=0,Native=17,VM=12,compile=1,original3=0,owners=10,source10=0,source8=0,source_subtests=0)
assert p['qualification']==dict(CLI_op10_connected=False,current_Native=0,current_VM=0,current_compile=0,current_product_execution=0,current_source_tests=18,matching_current_cold=False,whole_native=False)
assert p['limits']==dict(cleanup_seconds=3,minimum_free_bytes=1073741824,qualification_seconds=180)
assert not p['automatic_retry'] and p['first_failed_group_or_guard_or_incomplete_cleanup_stops']
assert len(old['generation_evidence'])==81 and p['generation_evidence'][:81]==old['generation_evidence']
extra=p['generation_evidence'][81:]
assert len(extra)==55 and sum(x['pin']['bytes'] for x in extra)==14606934
assert len({x['path'] for x in p['generation_evidence']})==136
source_attempt=Path(p['source_predecessor']['path']).parent
source_outer=source_attempt.parent/'source-controls-outer-r1'
expected=set()
for root in (source_attempt,source_outer):
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        expected.update(str(Path(directory)/name) for name in files)
assert expected=={x['path'] for x in extra} and len(expected)==55
descriptors=[*p['generation_evidence'],*p['inputs'].values(),p['generation_runner'],p['old_source10_runner'],p['contract'],p['source_predecessor']]
for row in descriptors:read_checked(row['path'],row['pin'],row['posix_mode'])
assert Path(p['contract']['path']).read_bytes().endswith((D/'CONTRACT.md').read_bytes())
assert p['source_predecessor']['pin']['git_blob']=='66a7fcb126e87224d171b6869be08e28e2d1cec6' and p['source_predecessor']['posix_mode']==0o600
r=json.loads(Path(p['source_predecessor']['path']).read_bytes())
assert r['status']=='SOURCE_CONTROLS_PASS' and r['owner_launch_attempts']==2 and r['complete_source_guard_pass']
proofpath=OUT.parent/'ROOT-DRIVE-R3-SOURCE18-TERMINAL.json'
proofraw=proofpath.read_bytes();assert pin(proofraw)['git_blob']=='90693fc0507ff4278e38dbda6a8b069a42d298bb'
proof=json.loads(proofraw)
assert proof['result']==p['source_predecessor']['pin']
assert (proof['methods'],proof['events'],proof['subtests'])==(18,36,21)
assert proof['status']=='PASS_ALL_ACTUAL_SOURCE18_AND_CURRENT_SOURCE_READBACK'
assert json.loads((source_outer/'OUTER.json').read_bytes())['returncode']==0
spec=json.loads(Path(p['inputs']['kit_spec']['path']).read_bytes())
assert p['native_group_order']==spec['native_group_order'] and p['vm_group_order']==spec['vm_group_order']
assert len(p['native_group_order'])==7 and len(p['vm_group_order'])==2
for label in p['native_group_order']+p['vm_group_order']:assert p['groups'][label]['ids']==spec['groups'][label]
assert sum(len(p['groups'][x]['ids']) for x in p['native_group_order'])==17
assert sum(len(p['groups'][x]['ids']) for x in p['vm_group_order'])==12
assert p['product_limits']==spec['limits'] and p['compiler']==spec['compiler']
assert p['product_limits']==dict(cleanup_seconds=3,compile_wall_seconds=20,compiler_author_blocks=1536,compiler_author_functions=128,compiler_author_operations=8192,image_capacity=1048576,qualification_seconds=180,source_capacity=1048576,vm_call_depth=128,vm_heap_bytes=8388608,vm_steps_per_frame=10000000,workspace_capacity=1048576)
read_checked(p['compiler']['path'],p['compiler'],p['compiler']['mode'])
captures={k:json.loads(Path(p['inputs'][k+'_final']['path']).read_bytes()) for k in ('source','base','predecessor')}
inodes={}
for role,capture in captures.items():
    assert tree(capture['files'])==p[role]['tree'] and len(capture['files'])==p[role]['files']
    inodes[role]=source_capture(Path(p[role]['path']),capture)
assert p['source']['tree']=='b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96'
assert len(inodes['source'])==3188 and inodes['source'].isdisjoint(inodes['base']|inodes['predecessor'])
assert all(s['nlink']==1 for s in captures['source']['stat'].values())
for key in ('executable','library'):
    row=p['runtime'][key];data=Path(row['path']).read_bytes()
    assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
    got=seven(Path(row['path']).stat())
    assert all(got[k]==row[k] for k in ('device','inode','mode','bytes','mtime_ns','ctime_ns'))
launchraw=(D/'NATIVE-LAUNCH.json').read_bytes()
assert pin(launchraw)['git_blob']=='c3f27425d75ecb1fbb46312ef13ada3ed6030cc3'
launch=json.loads(launchraw);priorlaunch=json.loads((D/'SOURCE-LAUNCH.json').read_bytes())
assert launch['plan']['pin']==dict(pin(raw),mode='100644') and launch['runner']['pin']==p['runner']
assert launch['actual_Source18_result']==p['source_predecessor']
assert launch['evidence_authority']==p['evidence_authority'] and launch['cwd']==priorlaunch['cwd']
argv=launch['argv'];i=argv.index(p['runtime']['launch_executable'])
assert argv[:i]==['/usr/bin/env','-i','PATH=/usr/local/bin:/usr/bin:/bin','HOME='+p['attempt'],'LANG=C.UTF-8','LC_ALL=C.UTF-8','PYTHONDONTWRITEBYTECODE=1','TMPDIR=/dev/shm/hia-inspect-drive-r3-dda7/startup-tmp','LD_LIBRARY_PATH='+p['runtime']['library_directory']]
assert argv[i:]==[p['runtime']['launch_executable'],'-I','-B',str(D/'run_inspect_stages.py'),'--execute-stage','native-vm','--plan',str(D/'NATIVE-PLAN.json'),'--plan-sha256',pin(raw)['sha256'],'--attempt',p['attempt']]
assert (launch['compile_declared'],launch['Native_declared'],launch['VM_declared'],launch['owner_count'],launch['Source_old3_CLI43_generation_declared'])==(1,17,12,10,0)
outerraw=(D/'launch_native_once.py').read_bytes()
assert pin(outerraw)['git_blob']=='81a93095a71ca4a24f63277e21ae841ee13d9916'
inverse=json.loads((D/'NATIVE-OUTER-BYTE-INVERSE.json').read_bytes())
restored=outerraw.decode()
assert len(inverse['changes'])==13
for change in reversed(inverse['changes']):
    assert restored.count(change['after'])==1
    restored=restored.replace(change['after'],change['before'],1)
oldouter=(D/'launch_source18_once.py').read_bytes()
assert restored.encode()==oldouter and pin(oldouter)['git_blob']=='7fea202fa64cd66890ace93d39bb066c6b0e74c1'
ea=p['evidence_authority'];ep=Path(ea['path']);assert ep.resolve(strict=True)==ep
fd=os.open(ep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    st=os.fstat(fd);named=ep.lstat();assert st==named and stat.S_ISDIR(st.st_mode)
    assert ea==dict(schema='hepta.hia.inspect-fixed-evidence-filesystem.v1',path=str(ep),device=st.st_dev,inode=st.st_ino,mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid)
    v=os.fstatvfs(fd);free=v.f_bavail*v.f_frsize;assert not(v.f_flag&os.ST_NOEXEC) and free>=1073741824
finally:os.close(fd)
assert Path(p['attempt'])==ep/'native-vm-attempt-r1' and not Path(p['attempt']).exists()
assert Path(launch['outer_directory'])==ep/'native-vm-outer-r1' and not Path(launch['outer_directory']).exists()
report=dict(schema='hepta.root-drive-r3-native17-vm12-proposal-readback.v1',status='PASS_STATIC_CURRENT_THREE_SOURCE_TREES_AND_ACTUAL_SOURCE18',observed_ns=time.time_ns(),plan=pin(raw),launch=pin(launchraw),runner=p['runner'],outer_recorder=pin(outerraw),complete_plan_inverse=True,changed_fields=sorted(delta),complete_outer_inverse=True,outer_replacements=13,original_generation_prefix=81,actual_Source18_appended_complete_files=55,actual_Source18_appended_bytes=14606934,descriptors_full_bytes_modes_checked=len(descriptors),actual_Source18_result=p['source_predecessor'],root_Source18_proof=pin(proofraw),base_files=3187,predecessor_files=3188,source_files=3188,source_tree=p['source']['tree'],all_current_three_trees_bytes_modes_seven_stats_pathsets_exact=True,private_inodes_unique_nlink1_disjoint=True,original_compiler_and_runtime_full_bytes_stats=True,original_native_ids=17,original_vm_ids=12,original_owners=10,product_limits=p['product_limits'],evidence_authority=ea,available_output_bytes=free,attempt_outer_absent=True,compile_Native_VM_by_this_reader=0,whole_native=False,matching_current_cold=False,production_legacy_retired=False,elapsed_ns=time.monotonic_ns()-started)
with OUT.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
