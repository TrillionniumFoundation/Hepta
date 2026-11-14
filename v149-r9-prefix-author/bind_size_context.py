"""Bind one completed R9 generation to the retained size/pack controls; no product execution."""
from pathlib import Path
import copy,json
import prefix_support as S

def bind(binding):
    root=S.EXEC/'size-context'
    S.require(not root.exists(),'size binding already exists')
    S.mkdir(root);originals=S.EXEC/'input-authority';S.mkdir(originals)
    capsule=S.capsule()
    old_inputs_raw=capsule['INPUTS.json'][0];old_inputs=json.loads(old_inputs_raw)
    S.require(S.encode(old_inputs)==old_inputs_raw and len(old_inputs['files'])==36,'original size input preimage differs')
    inputs=copy.deepcopy(old_inputs);changes=[];copied=0;inodes=set()
    for row in inputs['files']:
        member=row['captured'];raw,identity=capsule[member]
        S.require(identity==row['captured_identity']==row['origin_identity'],'original captured/origin identity differs')
        origin=originals/member;target=root/member
        S.write(origin,raw,identity['mode']);S.write(target,raw,identity['mode'])
        _,_,stamp=S.read(origin)
        for p in (origin,target):
            s=p.lstat();key=(s.st_dev,s.st_ino);S.require(key not in inodes and s.st_nlink==1,'new input alias');inodes.add(key)
        old_path=row['origin'];old_stat=row['origin_stat']
        row['origin']=str(origin);row['origin_stat']=dict(zip(S.FIELDS,stamp,strict=True))
        changes.append({'member':member,'origin_before':old_path,'origin_after':row['origin'],'stat_before':old_stat,'stat_after':row['origin_stat']})
        copied+=len(raw)
    S.require(copied==7579451,'original 36 input bytes differ')
    reverted=copy.deepcopy(inputs)
    for row,change in zip(reverted['files'],changes,strict=True):
        S.require(row['captured']==change['member'],'input order changed')
        row['origin']=change['origin_before'];row['origin_stat']=change['stat_before']
    S.require(S.encode(reverted)==old_inputs_raw,'complete size input inverse differs')
    S.dump(root/'INPUTS.json',inputs)
    preserved=('ACTUAL-INPUT-MANIFEST.json','EXTRACTION-RESULT.json','RETAINED-SUPPORT.json','CONTRACT.md','FROZEN-3180-SOURCE.json',
        'retained_buffer_child.py','retained_buffer_observer.py','retained_pack_contract.py')
    for name in preserved:
        raw,identity=capsule[name];S.write(root/name,raw,identity['mode'])
    original_runner=capsule['run_size_pack.py'][0]
    original_support=capsule['size_support.py'][0]
    runner=S.read(S.AUTHOR/'size-runner.py')[0]
    support=S.read(S.AUTHOR/'size-support.py')[0]
    old=b"source = S.input_bytes('R8.hepta')"
    new=b"source = S.candidate_source_bytes()"
    S.require(original_runner.count(old)==runner.count(new)==1 and runner.replace(new,old)==original_runner,'one compile-input full inverse differs')
    extension=S.read(S.AUTHOR/'candidate_size_source.py.txt')[0]
    S.require(support==original_support+extension,'support append-only inverse differs')
    S.write(root/'run_size_pack.py',runner);S.write(root/'size_support.py',support)
    projection_raw=capsule['PROJECTION.json'][0];projection=json.loads(projection_raw)
    S.require(S.encode(projection)==projection_raw,'original projection canonical bytes differ')
    original_projection=copy.deepcopy(projection)
    projection['original_builder']=str(S.SOURCE/'tools/build_hia_linux_file_roundtrip_program.py')
    for name,row in projection['unchanged_loader_files'].items():
        row['origin']=str(S.AUTHOR/'predecessor-size'/name)
    reverted_projection=copy.deepcopy(projection)
    reverted_projection['original_builder']=original_projection['original_builder']
    for name,row in reverted_projection['unchanged_loader_files'].items():
        row['origin']=original_projection['unchanged_loader_files'][name]['origin']
    S.require(S.encode(reverted_projection)==projection_raw,'whole pack projection inverse differs')
    S.dump(root/'PROJECTION.json',projection)
    S.dump(root/'CANDIDATE-BINDING.json',binding)
    inverse={'schema':'hia.R9.size-input-and-source-whole-inverse.v1','original_input_capsule':S.PLAN['size_author_capsule'],
        'original36_count':36,'original36_bytes':copied,'every_old_input_bytes_and_mode_preserved':True,
        'all72_materialized_files_distinct_inodes':len(inodes)==72,'new_original_provenance':True,'old_seven_stats_inherited':False,
        'input_changes':changes,'complete_inputs_inverse_equal':True,
        'runner_unique_before':old.decode(),'runner_unique_after':new.decode(),'runner_whole_inverse_equal':True,
        'support_original_full_prefix_exact':True,'one_appended_helper':'candidate_source_bytes',
        'original_projection':original_projection,'new_projection':projection,'whole_projection_inverse_equal':True,
        'old_budgets_and_capacity_assertions_unchanged':True,'ordinary_SOURCE_rebound':False,'product_executions_by_binder':0}
    S.dump(root/'BINDING-INVERSE.json',inverse)
    old_plan_raw=capsule['EXECUTION-PLAN.json'][0];old_plan=json.loads(old_plan_raw)
    S.require(S.encode(old_plan)==old_plan_raw,'old size plan canonical bytes differ')
    plan=copy.deepcopy(old_plan)
    plan['root']=str(root);plan['output']=str(S.EXEC/'size-pack')
    plan['source']['path']=str(S.SOURCE)
    plan['ordinary_SOURCE_path']=str(S.SOURCE/'examples/hia_bootstrap/selfhost.hepta')
    plan['environment']=copy.deepcopy(S.PLAN['environment'])
    plan['runtime']=copy.deepcopy(S.PLAN['runtime'])
    for name,row in plan['controls'].items():
        if name.startswith('author:'):
            row['path']=str(root/name.removeprefix('author:'))
        else:
            replacements={
                'owner_source':S.SOURCE/'tools/hia_selfhost_process_owner.py',
                'retained_builder':S.SOURCE/'tools/build_hia_linux_file_roundtrip_program.py',
                'retained_R8_driver':S.AUTHOR/'predecessor-size/retained_R8_driver.py',
                'retained_entry_support':S.AUTHOR/'predecessor-size/retained_entry_support.py'}
            S.require(name in replacements,'unknown retained external control')
            row['path']=str(replacements[name])
        actual=S.identity(row['path'])['identity']
        if name not in ('author:INPUTS.json','author:PROJECTION.json','author:run_size_pack.py','author:size_support.py'):
            S.require(actual==row['identity'],'unapproved retained control byte change: '+name)
        row['identity']=actual
    for name,path in [('CANDIDATE-BINDING.json',root/'CANDIDATE-BINDING.json'),('BINDING-INVERSE.json',root/'BINDING-INVERSE.json')]:
        plan['controls']['author:'+name]={'path':str(path),'identity':S.identity(path)['identity']}
    plan['R9_explicit_successor']={
        'generation_binding':S.identity(root/'CANDIDATE-BINDING.json'),
        'retained_runner_names_are_historical':True,'single_explicit_compile_source_change':True,
        'original_R8_hepta_and_size_history_still_required':True,'new_current_cold':False,'public_R5_profile_unchanged':True,
        'all_runtime_and_source_bytes_new_provenance_bound_separately':True,
        'prefix_authorization_pin':S.PLAN['authorization_pin']}
    S.require(plan['execution']==old_plan['execution'] and plan['capacity']==old_plan['capacity'] and plan['storage']==old_plan['storage'],
        'original size budget/capacity/storage changed')
    expected_control_changes={'author:INPUTS.json','author:PROJECTION.json','author:run_size_pack.py','author:size_support.py'}
    reverse=copy.deepcopy(plan);reverse.pop('R9_explicit_successor')
    for field in ('root','output','source','ordinary_SOURCE_path','environment','runtime'):reverse[field]=copy.deepcopy(old_plan[field])
    for field in ('author:CANDIDATE-BINDING.json','author:BINDING-INVERSE.json'):reverse['controls'].pop(field)
    for name,row in reverse['controls'].items():
        row['path']=old_plan['controls'][name]['path']
        if name in expected_control_changes:row['identity']=copy.deepcopy(old_plan['controls'][name]['identity'])
    S.require(S.encode(reverse)==old_plan_raw,'whole original size plan inverse differs')
    S.dump(root/'EXECUTION-PLAN.json',plan)
    inverse_result={'schema':'hia.R9.size-plan-complete-inverse.v1','complete_old_plan_byte_inverse':True,
        'retained_old_control_keys':list(old_plan['controls']),'explicitly_changed_old_control_identities':sorted(expected_control_changes),
        'added_control_keys':['author:CANDIDATE-BINDING.json','author:BINDING-INVERSE.json'],
        'old_plan':S.pin(old_plan_raw),'new_plan':S.identity(root/'EXECUTION-PLAN.json'),
        'raw_source':binding['files']['source'],'old36_inputs_unchanged':True,'new_compile_or_pack':0}
    S.dump(root/'PLAN-INVERSE-RESULT.json',inverse_result)
    return {'context':str(root),'plan':S.identity(root/'EXECUTION-PLAN.json'),'runner':S.identity(root/'run_size_pack.py'),
        'binding':S.identity(root/'CANDIDATE-BINDING.json'),'inverse':S.identity(root/'PLAN-INVERSE-RESULT.json'),
        'product_executions_by_binder':0}
