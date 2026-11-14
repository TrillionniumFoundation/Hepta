"""Static complete-byte reviewer. Imports no project, performs no product call."""
from pathlib import Path
import ast
import hashlib
import json
import os
import stat

ROOT=Path('/tmp/hia-u32-r8-controls-r2-dda7')
OUT=Path(__file__).resolve().parent


def pin(raw,mode=0o644):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
        'mode':mode,'git_mode':'100755' if mode&0o111 else '100644'}


def load(name):return json.loads((ROOT/name).read_bytes())


def function(raw,name):
    text=raw.decode();lines=text.splitlines(keepends=True)
    n=next(x for x in ast.parse(text).body if isinstance(x,ast.FunctionDef) and x.name==name)
    return ''.join(lines[n.lineno-1:n.end_lineno]).encode()


def assignment(raw,name):
    n=next(x for x in ast.parse(raw).body if isinstance(x,ast.Assign)
           and len(x.targets)==1 and isinstance(x.targets[0],ast.Name) and x.targets[0].id==name)
    return ast.literal_eval(n.value)


def dump(name,value):
    with (OUT/name).open('x') as f:
        json.dump(value,f,sort_keys=True,indent=2,allow_nan=False);f.write('\n')


def main():
    p=load('EXECUTION-PLAN.json');o=load('ORACLE-RESTORE-PLAN.json')
    for v in (p,o):
        fixed=dict(v);expected=fixed.pop('authorization_pin')
        assert hashlib.sha256((json.dumps(fixed,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()).hexdigest()==expected
    assert len(p['controls'])==61 and len(p['fixed_inputs'])==948
    for name,row in p['controls'].items():
        path=ROOT/name;s=path.lstat();assert stat.S_ISREG(s.st_mode)
        raw=path.read_bytes();assert pin(raw,stat.S_IMODE(s.st_mode))==row
        if name.endswith('.py'):ast.parse(raw)
    scripts=[]
    for row in load('PROJECTIONS.json'):
        raw=(ROOT/row['path']).read_bytes();assert pin(raw)==row['after']
        inverse=raw.decode()
        for change in reversed(row['replacements']):
            assert inverse.count(change['after'])==change['count']
            inverse=inverse.replace(change['after'],change['before'])
        old=(ROOT/'retained'/row['path']).read_bytes()
        assert inverse.encode()==old==Path(row['original']['path']).read_bytes()
        assert pin(old)==row['original']['identity']
        scripts.append({'path':row['path'],'before':pin(old),'after':pin(raw),'inverse_full_bytes':True})
    assert len(scripts)==7
    for row in load('SUPPORT-PROJECTIONS.json'):
        raw=(ROOT/row['path']).read_bytes();assert pin(raw)==row['after']
        inverse=raw.decode()
        for change in reversed(row['replacements']):
            assert inverse.count(change['after'])==1
            inverse=inverse.replace(change['after'],change['before'])
        old=(ROOT/'retained'/row['path']).read_bytes()
        assert inverse.encode()==old==Path(row['origin']).read_bytes()
        for n in ast.parse(old).body:
            if isinstance(n,ast.FunctionDef):assert function(raw,n.name)==function(old,n.name)
    source=Path(p['source']['path']);assert len(load('FROZEN-3180-SOURCE.json'))==3180
    original=(ROOT/'retained/hia_linux_file_roundtrip.py').read_bytes()
    assert original==(source/'hepta/hia_linux_file_roundtrip.py').read_bytes()
    private=(ROOT/'r8_private_reference.py').read_bytes()
    for name in ('_checked_components','execute_linux_file_roundtrip'):
        assert function(private,name)==function(original,name)
    old_pins=assignment(original,'COMPONENT_PINS');new_pins=assignment(private,'COMPONENT_PINS')
    assert list(old_pins)==list(new_pins)==['linux.roundtrip.representation','linux.roundtrip.semantic']
    assert new_pins=={**old_pins,'linux.roundtrip.semantic':p['fixed_inputs']['R8-source']['identity']['sha256']}
    assert old_pins==p['public_component_pins']
    assert assignment(private,'PROFILE')=='hepta.test-only.u32-r8-roundtrip-reference.v1'
    assert not any(isinstance(n,ast.FunctionDef) and n.name=='_execute' for n in ast.parse(private).body)
    observation=load('PRIVATE-WRAPPER-OBSERVATION-DIFF.json')
    assert pin(private)==observation['after']
    inv=private.decode().replace(observation['after_text'],observation['before_text'])
    assert inv.encode()==(ROOT/'author-history/private-reference-before-frame-observer.py').read_bytes()
    child=(ROOT/'hia_selfhost_child_frames.py').read_bytes();proj=load('LOADER-PROJECTION.json')
    assert pin(child)==proj['projected'];inverse=bytearray(child)
    for add in reversed(proj['only_insertions']):
        assert child[add['new_start']:add['new_end']]==add['bytes'].encode()
        del inverse[add['new_start']:add['new_end']]
    assert bytes(inverse)==(ROOT/'retained/hia_selfhost_child.py').read_bytes()==(source/'tools/hia_selfhost_child.py').read_bytes()
    six=assignment((ROOT/'semantic/authoring/run_compact_vm_remaining_r1.py').read_bytes(),'SELECTED')
    assert six==assignment((ROOT/'retained/semantic/authoring/run_compact_vm_remaining_r1.py').read_bytes(),'SELECTED')
    assert six==tuple(tuple(x) for x in p['original_semantic_six_order'])
    seven=assignment((ROOT/'aggregate/successor-r3/authoring/run_pipeline_vm_r1.py').read_bytes(),'ROWS')
    assert seven==assignment((ROOT/'retained/aggregate/successor-r3/authoring/run_pipeline_vm_r1.py').read_bytes(),'ROWS') and len(seven)==7
    assert [x['name'] for x in p['phases']]==['public-R5-refusal','native162','semantic-edge-vm',
        'semantic-remaining-vm','kernel130','observer-build','pipeline7','tail2']
    assert sum(x['compile_calls'] for x in p['phases'])==6
    assert sum(x['standalone_native_calls'] for x in p['phases'])==163
    assert sum(x['new_VM_calls'] for x in p['phases'])==15
    assert sum(x['direct_kernel_calls'] for x in p['phases'])==138
    assert p['budgets']['each_owner_seconds']==180 and p['budgets']['each_owner_cleanup_seconds']==3
    assert p['budgets']['each_native_seconds']==20 and p['budgets']['each_native_cpu_seconds']==10
    assert p['budgets']['each_VM_steps']==10000000 and p['minimum_free_bytes']==3*(1<<30)
    manifest=load('inputs/ORIGINAL-CAS-MANIFEST.json')
    assert len(o['required'])==496 and len(o['restore_order'])==136
    assert sum(v['identity']['bytes'] for v in o['required'].values())==704110777
    assert sum(o['required'][n]['identity']['bytes'] for n in o['restore_order'])==578353224
    for name,row in o['required'].items():
        old=manifest['files'][name]
        assert row['identity']=={**{k:old[k] for k in ('bytes','sha256','git_blob','git_mode')},'mode':old['mode_bits']}
        assert any(x['path']==row['path'] and x['identity']==row['identity'] for x in p['fixed_inputs'].values())
    assert p['original_observation_paths']==o['original_observation_paths'] and len(p['original_observation_paths'])==162
    assert p['requires_prior_original_oracle_restore']==o['authorization_pin']
    assert not Path(o['destination']).exists() and not Path(p['output']).exists()
    fixed_env=load('inputs/SIZE-EXECUTION-PLAN.json')['environment']
    assert p['runtime']['environment']=={**fixed_env,'HOME':p['output']}
    page=os.statvfs(Path(o['destination']).parent).f_frsize
    allocated=sum((o['required'][n]['identity']['bytes']+page-1)//page*page for n in o['restore_order'])
    free={name:os.statvfs(name).f_bavail*os.statvfs(name).f_frsize for name in ('/tmp','/dev/shm','/workspace/scratch/dda74a4fae35')}
    storage={'oracle_logical_bytes':578353224,'oracle_allocated_file_bound':allocated,
        'oracle_fixed_root':o['destination'],'oracle_metadata_allowance':o['allocation_metadata_allowance_bytes'],
        'oracle_filesystem_required_free':allocated+o['allocation_metadata_allowance_bytes']+o['additional_reserved_bytes'],
        'unchanged_product_entry_floor':3*(1<<30),
        'product_filesystem_required_before_restore':3*(1<<30)+o['additional_product_reserved_bytes'],
        'observed_free_bytes':free,
        'successful_native162_body_minimum':sum(x['successful_native_body_minimum_bytes'] for x in o['estimated_successful_native_body_storage']),
        'planning_success_shaped_total_new_product_evidence_bytes':2*(1<<30),
        'estimate_is_not_a_truncation_or_product_limit':True,
        'complete_failures_and_partial_writes_remain_in_place':True,
        'no_new_full_source_or_archive_copy':True}
    dump('STORAGE.json',storage)
    dump('WHOLE-INVERSE.json',{'scripts':scripts,'seven_retained_script_full_bytes_restored':True,
        'three_support_helper_bodies_full_bytes':True,'two_private_admission_functions_full_bytes':True,
        'original_native_child_full_bytes_after_removing_capture_insertions':True,
        'original_162_six_130_seven_two_bodies_assertions_and_limits_preserved':True,
        'only_control_projections':'fixed input pins/paths and explicit private-reference import',
        'public_production_source_changed':False})
    dump('REPORT.json',{'status':'STATIC_AUTHOR_READBACK_PASS_NOT_EXECUTED',
        'controls':61,'fixed_inputs':948,'original_source_files':3180,'source_tree':p['source']['tree'],
        'restoration_execution':False,'project_imports':0,'HIA_generation':0,'compile_calls':0,
        'Native_calls':0,'VM_calls':0,'CI_runs':0,
        'public_R5_refusal':'concrete original-entry control authored; not executed',
        'private_R8_reference':'retained admission/execute bodies; old report.profile tag grants no public qualification',
        'full_source_fresh_readback':'deferred to authorized original180+3 execution owners',
        'original_R5_six_result':'5PASS/1fuelFAIL historical only; no result transfer',
        'required_prior_nonproduct_restore':'136 exact old observations, no replacement oracle',
        'plan_identity':pin((ROOT/'EXECUTION-PLAN.json').read_bytes()),
        'restore_plan_identity':pin((ROOT/'ORACLE-RESTORE-PLAN.json').read_bytes())})


if __name__=='__main__':main()
