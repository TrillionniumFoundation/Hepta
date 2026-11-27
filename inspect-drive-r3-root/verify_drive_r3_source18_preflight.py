"""Root static/full-input preflight for actual R3 Source18; no bootstrap or product call."""
import ast,hashlib,json,os,stat,time
from pathlib import Path
helper=Path('/tmp/hia-root-v141-dda7/verify_drive_r3_generation_plan.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(helper)).encode()+b'\0'+helper).hexdigest()=='db1de0e35a29c6fc84ea0e59938d7f8170429959'
exec(compile(ast.Module(body=[n for n in ast.parse(helper).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'[Root owned read-only helper definitions]','exec'),globals())
D=Path('/tmp/hia-inspect-drive-source18-r3-dda7')
OLD=Path('/tmp/hia-inspect-source18-evidence-r2-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/ROOT-DRIVE-R3-SOURCE18-PREFLIGHT.json')
started=time.monotonic_ns()
raw=(D/'SOURCE-PLAN.json').read_bytes()
check(raw,{'bytes':52888,'git_blob':'ec2ce52faca4281d43151be0242186450e4acfd9','sha256':'83f26d2c723ca31183807a3bc5eb08adc962f4709785e3f69e729d4e25ee8099'})
p=json.loads(raw);old_raw=(OLD/'SOURCE-PLAN.json').read_bytes()
assert pin(old_raw)['git_blob']=='87a5b6de865ddaec23807db2b9614a66cff457e1'
old=json.loads(old_raw)
changed={k for k in set(p)|set(old) if p.get(k)!=old.get(k)}
assert changed=={'attempt','contract','evidence_authority','generation_evidence','generation_plan_sha256','generation_runner','inputs','predecessor','runner','source'},changed
runner,_=read_checked(D/'run_inspect_stages.py',p['runner'],0o644)
old_runner=(OLD/'run_inspect_stages.py').read_bytes()
assert pin(old_runner)['git_blob']=='dbd07c1c815641a0a55c4c2fcefef5d41034e369'
inverse=json.loads((D/'RUNNER-BYTE-INVERSE.json').read_bytes())
restored=runner.decode()
for row in reversed(inverse['replacements_in_forward_order']):
    assert restored.count(row['after'])==1
    restored=restored.replace(row['after'],row['before'],1)
assert restored.encode()==old_runner
def functions(b):
    s=b.decode();return {n.name:ast.get_source_segment(s,n) for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)}
of,nf=functions(old_runner),functions(runner)
assert set(of)==set(nf)
changed_functions={n for n in of if of[n]!=nf[n]}
assert changed_functions=={'bootstrap','full_guard','protected_source_fence','child'}
assert len(of)-len(changed_functions)==12
descriptors=[*p['inputs'].values(),*p['generation_evidence'],p['generation_runner'],p['old_source10_runner'],p['contract']]
for row in descriptors:read_checked(row['path'],row['pin'],row['posix_mode'])
assert len(p['generation_evidence'])==81 and sum(r['pin']['bytes'] for r in p['generation_evidence'])==16827810
paths={r['path'] for r in p['generation_evidence']};assert len(paths)==81
scope=Path(p['evidence_authority']['path'])
actual=set()
for rootname in ('materialization-attempt-r1','generation-attempt-r1','generation-outer-r1'):
    root=scope/rootname
    for directory,dirs,files in os.walk(root,followlinks=False):
        if Path(directory)==scope/'materialization-attempt-r1':dirs[:]=[n for n in dirs if n!='source']
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        actual.update(str(Path(directory)/name) for name in files)
assert actual==paths
captures={n:json.loads(Path(row['path']).read_bytes()) for n,row in p['inputs'].items()}
source,base,predecessor=(captures[k] for k in ('source_final','base_final','predecessor_final'))
assert captures['source_map']==source['files'] and len(source['files'])==3188
assert tree(source['files'])==p['source']['tree']=='b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96'
assert tree(base['files'])==p['base']['tree']=='7df49dd24bbba4ba3210168e639d6ea35a76a475'
assert tree(predecessor['files'])==p['predecessor']['tree']=='741fa64dadb37f98ab9b195f1ee7b67fe683fc70'
si=source_capture(Path(p['source']['path']),source);bi=source_capture(Path(p['base']['path']),base);pi=source_capture(Path(p['predecessor']['path']),predecessor)
assert len(si)==3188 and si.isdisjoint(bi|pi) and all(x['nlink']==1 for x in source['stat'].values())
rootproof=captures['root_generation_readback']
assert rootproof['status']=='PASS_ACTUAL_MATERIALIZATION_AND_DOUBLE_GENERATION_CHECK_ONLY'
assert p['inputs']['root_generation_readback']['pin']['git_blob']=='fd4f5cc07567550030820a6588b4c34331d1a7a0'
assert rootproof['source_map']==p['inputs']['source_map']['pin'] and rootproof['source_capture']==p['inputs']['source_final']['pin']
assert rootproof['result']=={k:p['inputs']['generation_result']['pin'][k] for k in ('bytes','sha256','git_blob')}
assert captures['generation_result']['status']=='GENERATION_ONLY_PASS' and captures['generation_result']['source_final_tree']==p['source']['tree']
assert p['active_phase']=='source-controls' and p['source_predecessor'] is None
assert p['limits']=={'qualification_seconds':180,'cleanup_seconds':3,'minimum_free_bytes':1073741824}
assert p['groups']==old['groups'] and p['test_source_pins']==old['test_source_pins']
assert p['source_group_order']==['source10','source8-physical-lease']
assert sum(len(p['groups'][g]['ids']) for g in p['source_group_order'])==18
assert sum(p['groups'][g]['expected_subtests'] for g in p['source_group_order'])==21
for name,want in p['test_source_pins'].items():assert source['files'][name]==want
read_checked(p['compiler']['path'],p['compiler'],p['compiler']['mode'])
for key in ('executable','library'):
    row=p['runtime'][key];data=Path(row['path']).read_bytes()
    assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
    observed=seven(Path(row['path']).stat())
    assert all(observed[k]==row[k] for k in ('device','inode','mode','bytes','mtime_ns','ctime_ns'))
launch_raw=(D/'SOURCE-LAUNCH.json').read_bytes()
assert pin(launch_raw)['git_blob']=='a28fe3d2ed35c9eca64e95ba6b9e5ff15c72b71f'
launch=json.loads(launch_raw);outer_raw=(D/'launch_source18_once.py').read_bytes()
assert pin(outer_raw)['git_blob']=='7fea202fa64cd66890ace93d39bb066c6b0e74c1'
assert launch['plan']['pin']==dict(pin(raw),mode='100644') and launch['runner']['pin']==p['runner']
assert launch['argv'][launch['argv'].index('--execute-stage')+1]=='source-controls'
assert launch['argv'][launch['argv'].index('--plan-sha256')+1]==pin(raw)['sha256']
assert launch['Source_declared']==18 and launch['owner_count']==2 and launch['expected_subtests']==21
assert not Path(p['attempt']).exists() and not Path(launch['outer_directory']).exists()
assert not Path('/workspace/scratch/dda74a4fae35/v132-inspect-machine-entry-r1/successor-r2/source-controls-attempt-r1').exists()
s=scope.lstat();assert not scope.is_symlink() and stat.S_ISDIR(s.st_mode)
authority={'schema':p['evidence_authority']['schema'],'path':str(scope),'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}
assert authority==p['evidence_authority']==launch['evidence_authority']
space=os.statvfs(scope);assert not space.f_flag&os.ST_NOEXEC and space.f_bavail*space.f_frsize>=1073741824
report={'schema':'hepta.hia.root-drive-r3-source18-preflight.v1','status':'PASS_EXACT_MINIMAL_RUNNER_AND_ALL_ACTUAL_INPUTS_NO_PRODUCTS',
 'runner':pin(runner),'plan':pin(raw),'launch':pin(launch_raw),'outer_recorder':pin(outer_raw),
 'complete_runner_inverse':True,'changed_functions':sorted(changed_functions),'unchanged_functions':12,
 'changed_plan_fields':sorted(changed),'all_complete_descriptors':len(descriptors),
 'actual_generation_evidence_files':81,'actual_generation_evidence_bytes':16827810,'actual_evidence_pathsets_equal':True,
 'all_three_source_trees_current_bytes_modes_seven_stats_and_pathsets':True,'all3188_new_inodes_unique_nlink1_and_disjoint':True,
 'original_groups_full_equal':True,'Source_methods':18,'Source_events':36,'Source_subtests':21,'owner_count':2,
 'limits':p['limits'],'actual_scope_authority':authority,'fresh_available_bytes':space.f_bavail*space.f_frsize,
 'Source_executed':0,'Native_compile':0,'Native_tests':0,'VM':0,'bootstrap_executed':False,
 'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-started}
with OUT.open('x',encoding='utf-8') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
