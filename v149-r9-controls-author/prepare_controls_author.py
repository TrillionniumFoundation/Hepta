"""Metadata-only R9 projection of the eight frozen groups; no project import."""
from pathlib import Path
import argparse,ast,base64,copy,hashlib,json,os,stat

ROOT=Path(__file__).resolve().parent
OLD=Path('/tmp/hia-u32-r8-post-reset-r4-dda7')
PREFIX=Path('/hia-r8-r9-execution-20261114-dda7')
OUTPUT=Path('/hia-r8-r9-controls-20261114-dda7')
AUTHOR=Path('/tmp/hia-r8-r9-execution-author-r1-dda7')
CANDIDATE=Path('/tmp/hia-r8-fuel-successor-analysis-r1-dda7/candidate-r2/overlay/tools/generate_hia_file_render_checker_word64.py')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def encode(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b,m=None):
    p={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if m is not None:p.update(mode=m,git_mode='100755' if m&0o111 else '100644')
    return p
def read(p):
    p=Path(p)
    for parent in reversed(p.parents):assert stat.S_ISDIR(parent.lstat().st_mode),parent
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1,p
    stamp=[getattr(s,k) for k in FIELDS]
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        assert [getattr(os.fstat(fd),k) for k in FIELDS]==stamp
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(s.st_size+1)
        assert len(b)==s.st_size and [getattr(os.fstat(fd),k) for k in FIELDS]==stamp==[getattr(p.lstat(),k) for k in FIELDS]
    finally:os.close(fd)
    return b,stat.S_IMODE(s.st_mode),stamp
def identity(p):
    b,m,s=read(p);return {'path':str(p),'identity':pin(b,m),'seven_stats':s}
def origin(p):
    r=identity(p);return {'path':r['path'],'identity':r['identity'],'stat':dict(zip(FIELDS,r['seven_stats'],strict=True))}
def write(n,b,m=0o644):
    p=ROOT/n;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(m);assert read(p)[:2]==(b,m)
def functions(b):
    lines=b.decode().splitlines(True)
    return {n.name:''.join(lines[n.lineno-1:n.end_lineno]).encode() for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
def check_owner(folder):
    raw=read(folder/'OWNER.json')[0];ret=json.loads(read(folder/'OWNER-RETURNED.json')[0]);r=json.loads(raw)
    r.update(supervisor_returncode=ret['supervisor_returncode'],receipt_sha256=pin(raw)['sha256']);assert r==ret
    assert r['status']=='OWNED_PROCESS_COMPLETED' and r['returncode']==r['supervisor_returncode']==0
    assert r['qualification_seconds']==180 and r['cleanup_seconds']==3 and not r['timed_out']
    assert r['exit_observed_before_deadline'] and r['cleanup']['complete'] and r['cleanup']['observed_echild']
    return r

def main(root_proof,root_proof_git):
    assert not OUTPUT.exists() and not OUTPUT.is_symlink()
    root_proof=identity(root_proof);assert root_proof['identity']['git_blob']==root_proof_git
    root_result=json.loads(read(root_proof['path'])[0])
    assert root_result['status']=='PASS_INDEPENDENT_R9_PREFIX_TERMINAL_ONLY'
    assert (root_result['generation'],root_result['compile'],root_result['pack'],root_result['original_product_owners'])==(2,1,1,3)
    assert root_result['semantic_Native']==root_result['semantic_VM']==root_result['ELF_execution']==0
    assert root_result['all_before_after_source_runtime_maps_equal'] and root_result['all_test_limits_unchanged']
    assert root_result['original_frame_ELF_checks_full'] and root_result['full_logical_buffers']==12 and root_result['physical_canary_spans']==6
    assert (root_result['fresh_domain_files'],root_result['fresh_domain_bytes'],root_result['source_files'],root_result['runtime_files'])==(6777,948620735,3180,2496)
    old_raw=read(OLD/'EXECUTION-PLAN.json')[0];old=json.loads(old_raw)
    assert len(old['fixed_inputs'])==948 and len(old['phases'])==8
    before={n:read(OLD/n) for n in old['controls']}
    assert all(pin(b,m)==old['controls'][n] for n,(b,m,_) in before.items())
    prefix=json.loads(read(PREFIX/'RESULT.json')[0]);generated=json.loads(read(PREFIX/'GENERATED-BINDING.json')[0])
    assert prefix['status']=='PASS_PRIVATE_R9_GENERATION_AND_SIZE_PACK_ONLY' and prefix['finalization_errors']==[]
    assert prefix['generation_owner_launches']==2 and prefix['size_driver_attempts']==1
    assert prefix['compile_calls_attempted']==prefix['pack_calls_attempted']==1
    assert prefix['VM_calls']==prefix['semantic_Native_cases']==prefix['aggregate_cases']==prefix['ELF_exec_calls']==0
    assert prefix['not_started']==[] and [r['stage'] for r in prefix['stages']]==['generate','check','size-pack']
    assert all(r['status']=='PASS' for r in prefix['stages'])
    for row in generated['files'].values():assert identity(row['path'])==row
    first=read(PREFIX/'generation/generate/report.json')[0];assert first==read(PREFIX/'generation/check/report.json')[0]
    report=json.loads(first);counts=report['generated'];p=counts['word64_projection']
    assert set(counts)=={'functions','blocks','ops','word64_projection'}
    assert {k:counts[k] for k in ('functions','blocks','ops')}=={'functions':107,'blocks':1456,'ops':6347}
    assert p['whole_inverse_equal'] and p['complete_original_Core_verifier_returned'] and len(p['removed_identity_casts'])==317
    for stage in ('generate','check'):check_owner(PREFIX/'generation'/stage)
    size=PREFIX/'size-pack';check_owner(size)
    actual=json.loads(read(size/'RESULT.json')[0]);outer=json.loads(read(size/'OUTER.json')[0])
    assert actual['status']==outer['status']=='PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY'
    assert actual['compile_calls_attempted']==actual['pack_calls_attempted']==1 and actual['finalization_errors']==[]
    assert actual==outer['actual_child_result'] and outer['finalization_errors']==[]
    source=identity(PREFIX/'generated/file_render_checker_word64.hepta')
    image=identity(size/'R8.u32.image.bin');elf=identity(size/'R8.private-nonexecuted.elf.bin')
    assert source==prefix['actual_generated_source']==generated['files']['source']
    assert {k:image['identity'][k] for k in ('bytes','sha256','git_blob')}==actual['image']==prefix['actual_image']
    assert {k:elf['identity'][k] for k in ('bytes','sha256','git_blob')}==actual['ELF']==prefix['actual_ELF']
    for name,observed in (('source',source),('image',image),('ELF',elf)):
        assert {k:observed['identity'][k] for k in ('bytes','sha256','git_blob')}==root_result[name]
    assert source['identity']['sha256']==report['source_sha256'] and source['identity']['bytes']==report['source_bytes']
    assert source['identity']['mode']==image['identity']['mode']==elf['identity']['mode']==0o644
    assert actual['size']['frame_admitted'] and actual['size']['ELF_admitted'] and image['identity']['bytes']<=557376 and elf['identity']['bytes']<=1048576
    candidate=identity(CANDIDATE);assert candidate['identity']['git_blob']=='8dde3a64f7388f81f8996888c97d43def2b336db'
    candidate_raw=read(CANDIDATE)[0]
    assert functions(candidate_raw)['source_program']==functions(before['inputs/R8-GENERATOR.py'][0])['source_program']
    edits={};after={n:(b,m) for n,(b,m,_) in before.items()}
    def replace(n,a,b,count):
        raw,m=after[n];assert raw.count(a.encode())==count,(n,a,raw.count(a.encode()))
        changed=raw.replace(a.encode(),b.encode())
        assert changed.count(b.encode())==count and changed.replace(b.encode(),a.encode())==raw
        edits.setdefault(n,[]).append({'before':a,'after':b,'count':count});after[n]=(changed,m)
    for role,count in [('R8-source',2),('R8-image',2),('R8-elf',1),('R8-result',1),('R8-generator',1)]:
        replace('r8_common.py',repr(role),repr(role.replace('R8-','R9-')),count)
    for name,count in [('R8-GENERATOR.py',2),('R8-OWNER.json',1),('R8-RESULT.json',1)]:
        replace('r8_common.py',repr('inputs/'+name),repr('inputs/'+name.replace('R8-','R9-')),count)
    replace('r8_private_reference.py',old['fixed_inputs']['R8-source']['identity']['sha256'],source['identity']['sha256'],1)
    replace('r8_private_reference.py',"PROFILE = 'hepta.test-only.u32-r8-roundtrip-reference.v1'","PROFILE = 'hepta.test-only.u32-r9-word64-roundtrip-reference.v1'",1)
    for n,suffix in [('semantic/authoring/support.py','semantic'),('aggregate/successor-r2/authoring/support.py','aggregate/successor-r2'),('aggregate/successor-r3/authoring/support.py','aggregate/successor-r3')]:
        replace(n,repr(str(Path(old['output'])/suffix)),repr(str(OUTPUT/suffix)),1)
    fixture=json.loads(before['fixtures/REPORT.json'][0])
    fixture['build']['executable']=str(OUTPUT/'aggregate/successor-r2/evidence/build-r2/built/private-R8.elf')
    fixture['build']['elf_inspection']=actual['elf_inspection'];fixture['image']=actual['image']
    fixture['images']['semantic']={k:actual['image'][k] for k in ('bytes','sha256')}
    fixture['input_sha256']=source['identity']['sha256'];fixture['origin']=origin(size/'RESULT.json')
    fixture['status_meaning']='fixed input projection of actual completed R9 generation/size/pack only; no semantic result'
    fixture_raw=encode(fixture);after['fixtures/REPORT.json']=(fixture_raw,before['fixtures/REPORT.json'][1])
    fixture_outer=json.loads(before['fixtures/OUTER.json'][0])
    fixture_outer.update(actual_outer=origin(size/'OUTER.json'),actual_owner=origin(size/'OWNER.json'),
        status_meaning='admitted actual R9 size owner/input view; no new semantic owner execution')
    after['fixtures/OUTER.json']=(encode(fixture_outer),before['fixtures/OUTER.json'][1])
    old_elf=old['fixed_inputs']['R8-elf']['identity'];new_elf=elf['identity']
    kernel='aggregate/successor-r2/authoring/run_kernel_130_r1.py';observer='aggregate/successor-r3/authoring/run_observer_build.py';pipeline='aggregate/successor-r3/authoring/run_pipeline_vm_r1.py'
    replace(kernel,old_elf['sha256'],new_elf['sha256'],1)
    # The retained method contains this original literal. The later R4 input
    # fixture has a different path-bound hash; R4 never reached kernel130.
    # Preserve both facts and invert this exact method literal, not an assumed
    # equality between its historical literal and the current R4 fixture.
    replace(kernel,repr('232b616bebcd49dd129725aeee83460813fd47ad94eaa5a60d5939d5c20d0ea8'),repr(pin(fixture_raw)['sha256']),1)
    replace(kernel,'len(elf) == '+str(old_elf['bytes']),'len(elf) == '+str(new_elf['bytes']),1)
    replace(observer,old_elf['sha256'],new_elf['sha256'],1)
    replace(observer,'assert len(original_elf) == '+str(old_elf['bytes'])+' and','assert len(original_elf) == '+str(new_elf['bytes'])+' and',1)
    replace(observer,'len(elf) == len(original_elf) == '+str(old_elf['bytes']),'len(elf) == len(original_elf) == '+str(new_elf['bytes']),1)
    replace(pipeline,'len(elf) == '+str(old_elf['bytes']),'len(elf) == '+str(new_elf['bytes']),1)
    plan=copy.deepcopy(old);plan['output']=str(OUTPUT);plan['runtime']['environment']['HOME']=str(OUTPUT)
    paths={'R9-source':Path(source['path']),'R9-image':Path(image['path']),'R9-elf':Path(elf['path']),
        'R9-generator':CANDIDATE,'R9-owner':size/'OWNER.json','R9-result':size/'RESULT.json','R9-outer':size/'OUTER.json',
        'R9-root-proof':Path(root_proof['path']),'R9-prefix-result':PREFIX/'RESULT.json','R9-generated-binding':PREFIX/'GENERATED-BINDING.json',
        'R9-generate-report':PREFIX/'generation/generate/report.json','R9-check-report':PREFIX/'generation/check/report.json',
        'R9-generate-owner':PREFIX/'generation/generate/OWNER-RETURNED.json','R9-check-owner':PREFIX/'generation/check/OWNER-RETURNED.json'}
    active={n:identity(p) for n,p in paths.items()}
    for n,row in active.items():
        assert n not in plan['fixed_inputs'];plan['fixed_inputs'][n]={'path':row['path'],'identity':row['identity'],'phases':['*']}
    for n,filename in [('R9-generator','R9-GENERATOR.py'),('R9-owner','R9-OWNER.json'),('R9-result','R9-RESULT.json')]:
        b,m,_=read(active[n]['path']);after['inputs/'+filename]=(b,m)
    plan['R9_explicit_successor']={'schema':'hia.R9.actual-input-projection.v1','private_candidate_only':True,
        'prefix_result':identity(PREFIX/'RESULT.json'),'prefix_plan':identity(AUTHOR/'PREFIX-PLAN.json'),
        'root_prefix_proof':root_proof,'actual_candidate_roles':active,'old948_retained_exact':True,
        'old_R4_semantics_qualification':'FAIL_VM_FUEL_RETAINED','original_ORACLE_RESTORE_PLAN_unchanged':True,
        'new_oracle_owner_executions':0,'ordinary_B3_and_profile_compiler_unchanged':True,
        'original_SIZE_history_unchanged':True,'old_R8_labels_are_legacy_role_names_only':True,
        'new_source_image_and_ELF_from_actual_prefix':True,'product_executions_before_Root_authorization':0}
    changes=[]
    for n,(b,m) in after.items():
        if n in before:
            prior,prior_mode,_=before[n];assert m==prior_mode
            if n in edits:
                back=b
                for e in reversed(edits[n]):
                    assert back.count(e['after'].encode())==e['count'];back=back.replace(e['after'].encode(),e['before'].encode())
                assert back==prior,(n,'whole inverse')
            elif n not in ('fixtures/REPORT.json','fixtures/OUTER.json'):assert b==prior,(n,'unapproved byte change')
            if b!=prior:changes.append({'path':n,'before':pin(prior,m),'after':pin(b,m),
                'before_base64':base64.b64encode(prior).decode(),'after_base64':base64.b64encode(b).decode(),
                'literal_replacements':edits.get(n),'explicit_fixture_JSON_projection':n.startswith('fixtures/')})
        if n.endswith('.py'):ast.parse(b,filename=n)
        write(n,b,m)
    for n in ('_checked_components','execute_linux_file_roundtrip','execute_program'):
        assert functions(after['r8_private_reference.py'][0])[n]==functions(before['r8_private_reference.py'][0])[n]
    assert after['run_controls.py'][0]==before['run_controls.py'][0]
    assert after['ORACLE-RESTORE-PLAN.json']==before['ORACLE-RESTORE-PLAN.json'][:2]
    protected=('phases','budgets','maximum_actual_calls','minimum_free_bytes','fail_stop','automatic_retry',
        'original_kernel130_order','original_native162_order','original_semantic_six_order','original_observation_paths',
        'public_component_pins','source','requires_prior_original_oracle_restore','native_guard_hex')
    assert all(plan[k]==old[k] for k in protected)
    assert {k:plan['fixed_inputs'][k] for k in old['fixed_inputs']}==old['fixed_inputs']
    plan['controls']={n:pin(b,m) for n,(b,m) in after.items()}
    inverse={'schema':'hia.R9.eight-group-exact-inverse.v1','status':'PASS_AUTHORING_ONLY',
        'original_plan':identity(OLD/'EXECUTION-PLAN.json'),'original_control_count':len(before),
        'changed_existing_files':changes,'new_control_files':['inputs/R9-GENERATOR.py','inputs/R9-OWNER.json','inputs/R9-RESULT.json'],
        'old948_fixed_inputs_full_exact_projection':True,'new_R9_roles':list(active),
        'old_original_role_count':948,'new_total_role_count':len(plan['fixed_inputs']),
        'original_phase_budgets_case_order_and_assert_operators_preserved':True,
        'private_three_functions_whole_bytes_unchanged':True,'run_controls_whole_bytes_unchanged':True,
        'ORACLE_RESTORE_PLAN_fullbytes_unchanged':True,'root_proof':root_proof,'product_executions':0,
        'retained_kernel_fixture_binding':{'original_method_literal':'232b616bebcd49dd129725aeee83460813fd47ad94eaa5a60d5939d5c20d0ea8',
            'current_R4_fixture_sha256':pin(before['fixtures/REPORT.json'][0])['sha256'],
            'R4_kernel_group_executed':False,'R9_actual_fixture_sha256':pin(fixture_raw)['sha256'],
            'original_assert_operator_and_whole_inverse_preserved':True}}
    write('R9-EXACT-INVERSE.json',encode(inverse));plan['controls']['R9-EXACT-INVERSE.json']=pin(encode(inverse),0o644)
    plan.pop('authorization_pin');plan['authorization_pin']=pin(encode(plan))['sha256']
    reverse=copy.deepcopy(plan);reverse.pop('R9_explicit_successor');reverse['authorization_pin']=old['authorization_pin']
    reverse['output']=old['output'];reverse['runtime']=old['runtime']
    for n in active:reverse['fixed_inputs'].pop(n)
    reverse['controls']=old['controls'];assert encode(reverse)==old_raw,'whole old plan inverse'
    write('EXECUTION-PLAN.json',encode(plan))
    launch={'schema':'hia.R9.eight-groups.launch-author.v1','status':'AUTHORING_ONLY','cwd':old['source']['path'],
        'argv':['/usr/bin/env','-i']+[k+'='+v for k,v in sorted(plan['runtime']['environment'].items())]
            +[plan['runtime']['executable']['path'],'-B',str(ROOT/'run_controls.py'),'--plan-sha256',plan['authorization_pin']],
        'outer_root':'/tmp/hia-r9-controls-outer-r1-dda7','outer_seconds':1800,'outer_cleanup_seconds':3,
        'outer_is_watchdog_not_run_owned_180_limit':True,'each_product_owner_seconds':180,'each_cleanup_seconds':3,
        'output':str(OUTPUT),'plan':identity(ROOT/'EXECUTION-PLAN.json'),'products':0,'no_stage_retries':True}
    write('PRODUCT-LAUNCH.json',encode(launch))
    result={'schema':'hia.R9.eight-group-authoring-result.v1','status':'PASS_AUTHORING_ONLY',
        'plan':identity(ROOT/'EXECUTION-PLAN.json'),'launch':identity(ROOT/'PRODUCT-LAUNCH.json'),
        'inverse':identity(ROOT/'R9-EXACT-INVERSE.json'),'old_controls':len(before),'new_controls':len(plan['controls']),
        'old_roles':948,'new_roles':len(active),'new_total_roles':len(plan['fixed_inputs']),
        'phase_count':8,'full_original_methods_except_listed_actual_length_hash_literals':True,
        'source_tree':old['source']['tree'],'source_files':3180,'actual_prefix':identity(PREFIX/'RESULT.json'),
        'scope':str(ROOT),'output_exists':OUTPUT.exists(),'binders_or_products_executed':0}
    write('R9-AUTHORING-RESULT.json',encode(result));print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root-prefix-proof',type=Path,required=True);p.add_argument('--root-prefix-proof-git',required=True)
    a=p.parse_args();main(a.root_prefix_proof,a.root_prefix_proof_git)
