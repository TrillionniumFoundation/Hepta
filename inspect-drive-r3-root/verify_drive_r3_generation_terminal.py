"""Read-only complete actual Inspect drive R3 materialization/generation terminal."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import time
helper=Path('/tmp/hia-root-v141-dda7/verify_drive_r3_generation_plan.py').read_bytes()
assert hashlib.sha1(b'blob '+str(len(helper)).encode()+b'\0'+helper).hexdigest()=='db1de0e35a29c6fc84ea0e59938d7f8170429959'
module=ast.parse(helper)
exec(compile(ast.Module(body=[n for n in module.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'[Root reviewed read-only helpers]','exec'),globals())

D=Path('/tmp/hia-inspect-drive-generation-r3-dda7')
S=Path('/dev/shm/hia-inspect-drive-r3-dda7')
G=S/'generation-attempt-r1'
M=S/'materialization-attempt-r1'
O=S/'generation-outer-r1'
OUT=Path('/tmp/hia-root-v141-dda7/ROOT-DRIVE-R3-GENERATION-TERMINAL.json')
started=time.monotonic_ns()
evidence={}
def read(path,expected=None):
    path=Path(path);before=seven(path.lstat());assert stat.S_ISREG(path.lstat().st_mode)
    raw=path.read_bytes();assert seven(path.lstat())==before
    if expected is not None:check(raw,expected)
    if path.is_relative_to(S):
        evidence[path.relative_to(S).as_posix()]={'pin':pin(raw),'mode':before['mode'],'stat':before}
    return raw
def data(path,expected=None):return json.loads(read(path,expected))
def descriptor(row):
    p=Path(row['path']);assert p.parent==G/'maps' or p.parent==M/'maps'
    assert p.name==row['pin']['sha256']+'.json'
    return data(p,row['pin'])
plan=data(D/'PLAN.json');launch=data(D/'LAUNCH.json')
result_raw=read(G/'RESULT.json')
assert pin(result_raw)['git_blob']=='eea5d55ab81fb102edfc1b0c4e6067943ada6af1'
result=json.loads(result_raw);outer=data(O/'OUTER.json')
assert result['status']=='GENERATION_ONLY_PASS' and result['generation_invocations']==2 and result['check_invocations']==1
assert result['owner_launch_attempts']==3 and result['product_tests']==result['native_compilations']==result['vm_frames']==0
assert result['source_files']==3188 and result['generated_metadata_current'] is True
assert result['source_final_tree']=='b7a3881a4d9f6d5a725d6e8d560fa492f6b26d96'
assert outer['status']=='PASS' and outer['returncode']==0 and outer['product_attempts']==1
assert outer['argv']==launch['argv'] and outer['cwd']==launch['cwd']
assert outer['authorization']['git_blob']=='fa987dba2506ffaca389d42ff7622a3e787695a5'
for key in ('Source_tests','Native_tests','compiles','VM'):assert outer[key]==0
check(read(D/'run_generation.py'),outer['runner']);check(read(D/'PLAN.json'),outer['plan']);check(read(D/'LAUNCH.json'),outer['launch'])
material=data(M/'RESULT.json',result['materialization_result'])
assert material['status']=='PRIVATE_SOURCE_MATERIALIZATION_PASS' and material['source_files']==3188
assert material['source_tree']==plan['derived_materialized_tree']=='292de63f31f2634043f6b02559d3e6fa6253c4f1'
assert material['source_copies']==1 and material['new_hardlinks']==0
assert material['all_old_bytes_modes_seven_stats_unchanged'] is material['all_private_inodes_unique'] is material['no_base_inode_reused'] is True
for key in ('generation','product_execution','Source','Native','compile','VM'):assert material[key]==0
initial=data(M/'SOURCE-CAPTURE.json',material['source_capture'])
assert data(M/'SOURCE-MAP.json',material['source_map'])==initial['files']
assert descriptor(material['complete_current_source_capture'])==initial
base=data(plan['inputs']['source_capture']['path'],plan['inputs']['source_capture']['pin'])
legacy=data(plan['inputs']['base_capture']['path'],plan['inputs']['base_capture']['pin'])
copy=[json.loads(line) for line in read(M/'COPY.jsonl').splitlines()]
assert len(copy)==3188 and [r['path'] for r in copy]==sorted(base['files'])
for row in copy:
    name=row['path'];assert row['before']==base['files'][name] and row['old_stat']==base['stat'][name]
    assert row['after']==initial['files'][name] and row['new_stat']==initial['stat'][name]
final=descriptor(result['final_source_capture'])
assert descriptor(result['final_base_capture'])==base and descriptor(result['final_legacy_capture'])==legacy
assert tree(final['files'])==result['source_final_tree']
bi=source_capture(Path(plan['base']),base);li=source_capture(Path(plan['legacy']),legacy);ni=source_capture(Path(plan['source']),final)
assert len(ni)==3188 and ni.isdisjoint(bi|li) and all(s['nlink']==1 for s in final['stat'].values())
installation=data(G/'INSTALLATION.json')
assert installation['status']=='THREE_NEW_INODES_AFTER_REAL_DOUBLE_GENERATION_AND_CHECK'
assert descriptor(installation['complete_map'])==final['files'] and installation['source_tree']==result['source_final_tree']
assert [r['path'] for r in installation['generated']]==plan['generated_paths']
for row in installation['generated']:
    name=row['path'];assert row['before']==initial['files'][name] and row['before_stat']==initial['stat'][name]
    assert row['after']==final['files'][name] and row['after_stat']==final['stat'][name]
    assert (row['before_stat']['device'],row['before_stat']['inode'])!=(row['after_stat']['device'],row['after_stat']['inode'])
for name in set(initial['files'])-set(plan['generated_paths']):
    assert initial['files'][name]==final['files'][name] and initial['stat'][name]==final['stat'][name]
assert {n for n in base['files'] if base['files'][n]!=final['files'][n]}=={'hepta/hia_inspect_program_native.py','hepta/hia_inspect_program_data.py'}
guards=sorted(G.glob('GUARD-*.json'));assert len(guards)==9
for path in guards:
    guard=data(path);assert descriptor(guard['legacy'])==legacy and descriptor(guard['base'])==base
    assert descriptor(guard['source'])==(final if path.name=='GUARD-install-after.json' else initial)
assert [r['label'] for r in result['stages']]==plan['stage_order']
owners=[]
for number,row in enumerate(result['stages'],1):
    directory=G/('%02d-%s'%(number,row['label']));assert Path(row['directory'])==directory
    assert row['status']=='PASS' and row['source_guard_pass'] is True and row['outputs']==row['actual_partial_outputs']
    assert data(directory/'STAGE.json')==row
    owner_raw=read(directory/'OWNER.json');owner=json.loads(owner_raw);returned=data(directory/'OWNER-RETURNED.json')
    assert returned==row['owner_returned']==dict(owner,receipt_sha256=hashlib.sha256(owner_raw).hexdigest(),supervisor_returncode=0)
    assert owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==0 and owner['qualification_seconds']==180 and owner['cleanup_seconds']==3
    assert owner['timed_out'] is False and owner['exit_observed_before_deadline'] is True
    cleanup=owner['cleanup'];assert cleanup['complete'] and cleanup['observed_echild'] and cleanup['leader_reaped']
    assert not cleanup['errors'] and not cleanup['remaining_direct_children'] and cleanup['elapsed_ns']<=3000000000
    assert owner['historical_descendant_inventory_complete'] is False
    owner_request_raw=read(directory/'OWNER.json.request.json')
    assert hashlib.sha256(owner_request_raw).hexdigest()==owner['request_sha256']
    owner_request=json.loads(owner_request_raw);command=data(directory/'COMMAND.json');request_raw=read(directory/'REQUEST.json');request=json.loads(request_raw)
    assert owner_request['command']==command['argv'] and owner_request['cwd']==command['cwd']==plan['source']
    assert owner_request['env']==command['environment']==command['supervisor_environment']
    assert command['qualification_seconds']==owner_request['qualification_seconds']==180
    assert command['cleanup_seconds']==owner_request['cleanup_seconds']==3
    assert owner_request['deadline_ns']-owner_request['started_ns']==180000000000
    assert command['argv'][-1]==hashlib.sha256(request_raw).hexdigest()
    assert command['generator_argv']==request['generator_argv']
    assert ('--check' in request['generator_argv'])==(number==3)
    assert request['source']==plan['source'] and request['runtime_context']==plan['runtime']
    child=data(directory/'CHILD-RESULT.json',row['child_result_pin'])
    assert child['status']=='PASS' and child['runtime_context']==plan['runtime'] and child['generator_argv']==request['generator_argv']
    check(request_raw,child['request_pin'])
    assert child['tests']==child['native_compilations']==child['vm_frames']==0
    assert child['write_fence']=='EXACT_PYTHON_WRITES_ONLY_NOT_A_NATIVE_SANDBOX'
    output=G/'results'/('1' if number==1 else '2')
    assert sorted(p.name for p in output.iterdir())==row['outputs']['actual_names']
    for name,item in row['outputs']['files'].items():
        raw=read(output/name,item['pin']);assert seven((output/name).lstat())==item['stat']
        final_path={'inspect_program.hepta':'examples/hia_bootstrap/inspect_program.hepta','hia_inspect_program_ports.py':'hepta/hia_inspect_program_ports.py','hia_inspect_program_data.py':'hepta/hia_inspect_program_data.py'}[name]
        assert raw==Path(plan['source'],final_path).read_bytes()
    owners.append({'label':row['label'],'qualification_seconds':180,'cleanup_seconds':3,'returncode':0,'observed_echild':True,'cleanup_ns':cleanup['elapsed_ns']})
assert result['stages'][1]['outputs']==result['stages'][2]['outputs']
identity_raw=Path(plan['source'],'hepta/hia_inspect_program_data.py').read_bytes()
fields={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(identity_raw).body if isinstance(n,ast.Assign)}
assert len(fields['HOST_SOURCE_SHA256'])==13
for name,sha in fields['HOST_SOURCE_SHA256'].items():assert final['files']['hepta/'+name]['sha256']==sha
assert fields['SOURCE_BYTES']==98544 and fields['SOURCE_SHA256']==final['files']['examples/hia_bootstrap/inspect_program.hepta']['sha256']
assert fields['HOST_SOURCE_SHA256']['hia_inspect_program_native.py']=='8bdc0f48ba8a48dc79afec36e62cad09d2f85ee6ae0c53bf640ba5b5058e5ed3'
for root in (G,O,M):
    for directory,dirs,files in os.walk(root,followlinks=False):
        if Path(directory)==M:dirs[:]=[n for n in dirs if n!='source']
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        for name in files:read(Path(directory)/name)
report={'schema':'hepta.hia.root-drive-r3-generation-terminal.v1','status':'PASS_ACTUAL_MATERIALIZATION_AND_DOUBLE_GENERATION_CHECK_ONLY',
 'actual_session':85625,'outer_exit_code':0,'outer_elapsed_ns':outer['elapsed_ns'],'result':pin(result_raw),
 'actual_source_files':3188,'actual_source_tree':tree(final['files']),'source_map':installation['complete_map']['pin'],
 'source_capture':result['final_source_capture']['pin'],'materialization':result['materialization_result'],
 'all_three_trees_full_current_bytes_modes_seven_stats_and_pathsets':True,'all3188_actual_copy_rows_verified':True,
 'all9_generation_guards_complete_actual_captures_equal':True,'actual_owners':owners,
 'generation_invocations':2,'check_invocations':1,'complete_HIA_and_ports_unchanged':True,'actual_new13_host_identity':pin(identity_raw),
 'all_three_per_path_generated_inodes_replaced':True,'all3185_nongenerated_bytes_modes_seven_stats_unchanged':True,
 'complete_evidence_files':len(evidence),'complete_evidence_bytes':sum(r['pin']['bytes'] for r in evidence.values()),
 'full_evidence_manifest_sha256':hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
 'new_products_by_reader':0,'Source_tests':0,'Native_compile':0,'Native_tests':0,'VM':0,
 'historical_descendant_inventory_complete':False,'whole_native':False,'production_legacy_retired':False,'elapsed_ns':time.monotonic_ns()-started}
with OUT.open('x',encoding='utf-8') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
